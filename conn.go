package desync

import (
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Options selects what happens to the first complete TLS ClientHello of a
// connection. Everything after it is passed through untouched, and a
// connection that does not start with a ClientHello is never modified.
type Options struct {
	// ClientHello bounds incomplete assembly. Nil/zero fields use defaults.
	ClientHello *ClientHelloOptions
	// Fake selects a platform-specific low-TTL first transmission.
	Fake *FakeOptions
	// TLSRec splits the ClientHello into separate TLS records at these
	// positions (ByeDPI --tlsrec).
	TLSRec []Pos
	// Split sends the (possibly record-split) ClientHello in separate TCP
	// writes, cut at these positions of the original record (ByeDPI --split).
	Split []Pos
	// SplitDelay is a pause between the TCP pieces; 0 sends them back to back.
	SplitDelay time.Duration
	// SplitWait waits, before each further TCP piece, until the kernel
	// reports the previous bytes as sent or acknowledged. Unsupported modes
	// fail Validate and the first Write; see PlatformCapabilities.
	SplitWait SplitWait
	// SplitWaitTimeout bounds each SplitWait wait (default 2 s, max 1 min).
	SplitWaitTimeout time.Duration
	// Random adds bounded random record/write cuts; nil keeps the strategy
	// deterministic. Include Key() in a strategy ID so it is never reused for
	// a different randomization policy or seed.
	Random *RandomOptions
	// Disorder sends the first TCP piece with hop limit 1, so it expires at
	// the first router, then restores the hop limit and sends the rest; TCP
	// retransmits the first piece with the normal hop limit (ByeDPI
	// --disorder). It needs Split or Random.Split positions. The hop limit is
	// restored once the kernel reports the piece as transmitted (bounded by
	// SplitWaitTimeout); see PlatformCapabilities().Disorder.
	Disorder bool
	// OOB sends one urgent (MSG_OOB) byte right after the first TCP piece
	// (ByeDPI --oob; with Disorder, --disoob). It needs Split or Random.Split
	// positions.
	OOB *OOBOptions
}

// Enabled reports whether the options change anything.
func (o Options) Enabled() bool {
	return o.Fake != nil || len(o.TLSRec) > 0 || len(o.Split) > 0 || o.Random.enabled() ||
		o.Disorder || o.OOB != nil
}

// splits reports whether the hello can be sent in more than one TCP write.
func (o Options) splits() bool {
	return len(o.Split) > 0 || (o.Random != nil && len(o.Random.Split) > 0)
}

// Conn applies Options to the first ClientHello written to an underlying conn.
type Conn struct {
	net.Conn
	opts Options

	mu              sync.Mutex
	pending         *helloAssembly // guarded by mu; only while input is incomplete
	err             error          // terminal configuration or first-write failure
	closed          chan struct{}
	closeOnce       sync.Once
	done            bool // guarded by mu; ClientHello handled (or not a hello)
	deadlineMu      sync.Mutex
	writeDeadline   time.Time
	deadlineChanged chan struct{}
	watch           *helloWatch // guarded by deadlineMu

	usedTTL atomic.Int32 // the fake's TTL, see FakeTTL

	obs ackObserver // guarded by mu; the socket observer of sendHello, see observer
}

// WrapConn returns c with the options applied, or c itself when they are
// empty.
func WrapConn(c net.Conn, opts Options) net.Conn {
	if !opts.Enabled() {
		return c
	}
	opts.TLSRec = append([]Pos(nil), opts.TLSRec...)
	opts.Split = append([]Pos(nil), opts.Split...)
	opts.Random = opts.Random.clone()
	if opts.ClientHello != nil {
		limits := *opts.ClientHello
		opts.ClientHello = &limits
	}
	if opts.Fake != nil {
		fake := *opts.Fake
		fake.Payload = append([]byte(nil), fake.Payload...)
		if fake.AutoTTL != nil {
			auto := *fake.AutoTTL
			fake.AutoTTL = &auto
		}
		fake.SNI = append([]string(nil), fake.SNI...)
		opts.Fake = &fake
	}
	if opts.OOB != nil {
		oob := *opts.OOB
		opts.OOB = &oob
	}
	w := &Conn{Conn: c, opts: opts, closed: make(chan struct{}), err: opts.Validate()}
	if opts.Fake != nil || opts.splits() && (opts.SplitDelay > 0 || opts.SplitWait != SplitWaitNone || opts.Disorder) {
		w.deadlineChanged = make(chan struct{})
	}
	return w
}

// NetConn returns the wrapped connection.
func (c *Conn) NetConn() net.Conn { return c.Conn }

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.deadlineMu.Lock()
		if c.closed != nil {
			close(c.closed)
		}
		c.stopHelloAssemblyLocked()
		c.deadlineMu.Unlock()
	})
	return c.Conn.Close()
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetDeadline(t); err != nil {
		return err
	}
	c.updateWriteDeadline(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.updateWriteDeadline(t)
	return nil
}

// updateWriteDeadline is called with deadlineMu held. Signal every successful
// change, including clearing/extending a deadline while a split wait is active.
func (c *Conn) updateWriteDeadline(t time.Time) {
	c.writeDeadline = t
	if c.deadlineChanged != nil {
		close(c.deadlineChanged)
		c.deadlineChanged = make(chan struct{})
	}
}

func (c *Conn) writeState() (time.Time, <-chan struct{}, error) {
	c.deadlineMu.Lock()
	deadline, changed := c.writeDeadline, c.deadlineChanged
	var assemblyErr error
	if c.watch != nil {
		assemblyErr = c.watch.err
	}
	c.deadlineMu.Unlock()
	if assemblyErr != nil {
		return deadline, changed, assemblyErr
	}
	select {
	case <-c.closed:
		return time.Time{}, nil, net.ErrClosed
	default:
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return deadline, changed, os.ErrDeadlineExceeded
	}
	return deadline, changed, nil
}

// waitWriteDelay implements only the configured pause. It does not observe
// ACKs or guarantee TCP segment boundaries. Deadline changes and Close wake it.
func (c *Conn) waitWriteDelay(delay time.Duration) error {
	end := time.Now().Add(delay)
	for {
		deadline, changed, err := c.writeState()
		if err != nil {
			return err
		}
		until := end
		if !deadline.IsZero() && deadline.Before(until) {
			until = deadline
		}
		remaining := time.Until(until)
		if remaining <= 0 {
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return os.ErrDeadlineExceeded
			}
			return nil
		}
		timer := time.NewTimer(remaining)
		select {
		case <-c.closed:
			timer.Stop()
			return net.ErrClosed
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// Write holds a ClientHello until its whole handshake is complete, then sends it
// desynchronised; every other write goes straight through.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.pending = nil
		c.mu.Unlock()
		_ = c.Close()
		return 0, err
	}
	if c.done {
		c.mu.Unlock()
		return c.Conn.Write(p)
	}
	defer c.mu.Unlock()
	if _, _, err := c.writeState(); err != nil {
		if c.helloAssemblyError() != nil {
			c.pending = nil
		}
		return 0, err
	}
	data, tail, frame, buffered, inspectErr := c.inspectHello(p)
	if inspectErr == errShort {
		if err := c.beginHelloAssembly(); err != nil {
			c.pending = nil
			c.err = err
			_ = c.Close()
			return 0, err
		}
		return len(p), nil
	}
	if err := c.stopHelloAssembly(); err != nil {
		c.pending = nil
		c.err = err
		_ = c.Close()
		return 0, err
	}
	c.pending = nil
	c.done = true
	if inspectErr != nil && inspectErr != ErrNotClientHello {
		c.err = inspectErr
		_ = c.Close()
		return 0, inspectErr
	}
	var n int
	var err error
	if inspectErr == ErrNotClientHello {
		n, err = writeAllCount(c.Conn, data)
	} else {
		n, err = c.sendHello(data, frame)
	}
	if err != nil {
		c.err = err
		_ = c.Close()
		return currentWriteCount(n, buffered, len(p)), err
	}
	if len(tail) > 0 {
		tailN, tailErr := writeAllCount(c.Conn, tail)
		n += tailN
		if tailErr != nil {
			c.err = tailErr
			_ = c.Close()
			return currentWriteCount(n, buffered, len(p)), tailErr
		}
	}
	return len(p), nil
}

// sendHello transforms only positions inside the logical ClientHello, while
// retaining existing input record headers and any coalesced tail payload.
func (c *Conn) sendHello(rec []byte, frame helloFrame) (int, error) {
	out := rec
	var recCuts, splitCuts []int
	if r := c.opts.Random; r.enabled() {
		// Draw record ranges first, then write ranges, so a seed reproduces.
		// One bounded allocation holds both cut lists.
		rng := c.newCutRand()
		nRec := len(c.opts.TLSRec) + randomCutCapacity(r.TLSRec)
		buf := make([]int, 0, nRec+len(c.opts.Split)+randomCutCapacity(r.Split))
		recCuts = frame.randomCuts(frame.positionCuts(buf[:0:nRec], c.opts.TLSRec), r.TLSRec, &rng)
		recCuts = frame.normalizeCuts(recCuts, true)
		splitCuts = frame.randomCuts(frame.positionCuts(buf[nRec:nRec], c.opts.Split), r.Split, &rng)
		splitCuts = frame.normalizeCuts(splitCuts, false)
	} else {
		recCuts = frame.cuts(c.opts.TLSRec, true)
	}
	if len(recCuts) > 0 {
		out = fragmentHello(rec, frame, recCuts)
	}
	if !c.opts.Random.enabled() {
		splitCuts = frame.cuts(c.opts.Split, false)
	}
	s := pieceSender{c: c, out: out, ends: mapCuts(splitCuts, recCuts), fakeEnd: -1}
	if c.opts.Fake != nil {
		// The fake prefix end is one more cut; the fake piece ends there.
		prefix, err := fakePrefixLength(len(out), c.opts.Fake.Prefix)
		if err != nil {
			return 0, err
		}
		s.fakeEnd = prefix
	}
	if len(s.ends) > 0 {
		var err error
		if s.ack, err = c.splitObserver(); err != nil {
			return 0, err
		}
		if s.first, err = c.prepareFirstPiece(s.ack); err != nil {
			return 0, err
		}
	}
	if s.fakeEnd >= 0 {
		// Before the first piece: a fake that cannot run on this socket
		// fails while nothing has been written.
		if err := prepareFakeFunc(c); err != nil {
			return 0, err
		}
		firstEnd := s.fakeEnd
		if len(s.ends) > 0 && s.ends[0] < firstEnd {
			firstEnd = s.ends[0]
		}
		if firstEnd == s.fakeEnd && s.first != nil {
			return 0, ErrFakeFirstPiece
		}
		s.ends = insertCut(s.ends, s.fakeEnd)
		decoy, err := c.fakeDecoy(rec, frame)
		if err != nil {
			return 0, err
		}
		s.decoy = decoy
	}
	s.ends = append(s.ends, len(out))
	if err := s.send(0, 0); err != nil {
		if s.fakeStarted {
			// A failed native asynchronous send has no reliable count: report
			// only the pieces before the fake piece and terminate; never
			// replay this stream.
			return originalWriteCount(s.beforeFake, recCuts), err
		}
		return originalWriteCount(s.written, recCuts), err
	}
	return len(rec), nil
}

// pieceSender writes the TCP pieces of one transformed ClientHello.
type pieceSender struct {
	c     *Conn
	out   []byte
	ends  []int // piece ends in out, ascending, the last is len(out)
	ack   ackObserver
	first *firstPiece
	// fakeEnd is the end of the fake piece, -1 without Fake; decoy is the
	// connection's decoy bytes.
	fakeEnd int
	decoy   []byte
	// written counts bytes of out; extra counts urgent bytes, which are on
	// the socket but not part of the stream the server reads. beforeFake is
	// written when the fake piece started.
	written, extra, beforeFake int
	fakeStarted                bool
}

// send writes the pieces from index i on, the first of them starting at
// start. The fake piece hands the pieces after it to the native backend,
// which writes them as soon as the low-hop transmission allows.
func (s *pieceSender) send(i, start int) error {
	c := s.c
	for ; i < len(s.ends); i++ {
		end := s.ends[i]
		if end <= start || end > len(s.out) {
			continue
		}
		if i > 0 && s.ack != nil {
			if err := c.waitSplit(s.ack, int64(s.written+s.extra)); err != nil {
				return err
			}
		}
		if i > 0 && c.opts.SplitDelay > 0 {
			if err := c.waitWriteDelay(c.opts.SplitDelay); err != nil {
				return err
			}
		}
		piece := s.out[start:end]
		if end == s.fakeEnd {
			s.fakeStarted, s.beforeFake = true, s.written
			next := i + 1
			payload := fakeBytes(s.decoy, c.opts.Fake.Offset, len(piece))
			return sendFakePieceFunc(c, piece, payload, start > 0, func() error {
				s.written += len(piece)
				return s.send(next, end)
			})
		}
		var n, urgent int
		var err error
		if i == 0 && s.first != nil {
			n, urgent, err = s.first.send(c, piece)
		} else {
			n, err = writeAllCount(c.Conn, piece)
		}
		s.written += n
		s.extra += urgent
		if err != nil {
			return err
		}
		start = end
	}
	return nil
}

// sendFakePieceFunc is replaced by tests to observe the fake piece.
var sendFakePieceFunc = (*Conn).sendFakePiece

// prepareFakeFunc is replaced by tests together with sendFakePieceFunc.
var prepareFakeFunc = (*Conn).prepareFake

// insertCut adds at to the ascending cuts unless it is already there.
func insertCut(cuts []int, at int) []int {
	i := sort.SearchInts(cuts, at)
	if i < len(cuts) && cuts[i] == at {
		return cuts
	}
	cuts = append(cuts, 0)
	copy(cuts[i+1:], cuts[i:])
	cuts[i] = at
	return cuts
}

func writeAll(w io.Writer, p []byte) error {
	_, err := writeAllCount(w, p)
	return err
}

func writeAllCount(w io.Writer, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return written, io.ErrShortWrite
		}
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// currentWriteCount excludes bytes already accepted by an earlier buffered
// Write. Socket progress can include those bytes, but they cannot be counted
// twice in the result of the current call.
func currentWriteCount(written, buffered, input int) int {
	n := written - buffered
	if n < 0 {
		return 0
	}
	if n > input {
		return input
	}
	return n
}

// originalWriteCount removes generated TLS headers from a wire-prefix count.
// A failure inside an inserted header accepts no additional caller bytes.
func originalWriteCount(wire int, recordCuts []int) int {
	n := wire
	for i, cut := range recordCuts {
		inserted := wire - (cut + i*recordHeaderLen)
		if inserted <= 0 {
			break
		}
		if inserted > recordHeaderLen {
			inserted = recordHeaderLen
		}
		n -= inserted
	}
	return n
}

// mapCuts moves offsets of the original record to the same bytes in the
// record-split output, where every record cut before them added a header. A
// TCP cut at a record cut lands before the new header, so each record starts
// its own segment.
func mapCuts(cuts, recCuts []int) []int {
	out := make([]int, 0, len(cuts))
	for _, c := range cuts {
		shift := 0
		for _, r := range recCuts {
			if r < c {
				shift += recordHeaderLen
			}
		}
		out = append(out, c+shift)
	}
	return out
}
