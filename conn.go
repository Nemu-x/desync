package desync

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Options selects what happens to the first TLS record (the ClientHello) of a
// connection. Everything after it is passed through untouched, and a
// connection that does not start with a ClientHello is never modified.
type Options struct {
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
}

// Enabled reports whether the options change anything.
func (o Options) Enabled() bool { return o.Fake != nil || len(o.TLSRec) > 0 || len(o.Split) > 0 }

// Conn applies Options to the first record written to an underlying conn.
type Conn struct {
	net.Conn
	opts Options

	mu              sync.Mutex
	buf             []byte // a ClientHello written in pieces, until it is complete
	err             error  // terminal configuration or first-write failure
	closed          chan struct{}
	closeOnce       sync.Once
	done            bool // guarded by mu; first record handled (or not a hello)
	deadlineMu      sync.Mutex
	writeDeadline   time.Time
	deadlineChanged chan struct{}
}

// WrapConn returns c with the options applied, or c itself when they are
// empty.
func WrapConn(c net.Conn, opts Options) net.Conn {
	if !opts.Enabled() {
		return c
	}
	opts.TLSRec = append([]Pos(nil), opts.TLSRec...)
	opts.Split = append([]Pos(nil), opts.Split...)
	if opts.Fake != nil {
		fake := *opts.Fake
		fake.Payload = append([]byte(nil), fake.Payload...)
		opts.Fake = &fake
	}
	w := &Conn{Conn: c, opts: opts, closed: make(chan struct{}), err: opts.Validate()}
	if len(opts.Split) > 0 && opts.SplitDelay > 0 {
		w.deadlineChanged = make(chan struct{})
	}
	return w
}

// NetConn returns the wrapped connection.
func (c *Conn) NetConn() net.Conn { return c.Conn }

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
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
	select {
	case <-c.closed:
		return time.Time{}, nil, net.ErrClosed
	default:
	}
	c.deadlineMu.Lock()
	deadline, changed := c.writeDeadline, c.deadlineChanged
	c.deadlineMu.Unlock()
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

// Write holds a ClientHello until its first record is complete, then sends it
// desynchronised; every other write goes straight through.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
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
		return 0, err
	}

	data := p
	buffered := len(c.buf)
	if len(c.buf) > 0 {
		data = append(c.buf, p...)
		c.buf = nil
	} else if !looksLikeHello(p) {
		c.done = true
		return c.Conn.Write(p)
	}

	rl, err := recordLen(data)
	switch {
	case err == errShort || (err == nil && len(data) < rl):
		// Wait for the rest of the record (a TLS client always sends the
		// whole hello before it reads).
		// Copy: p belongs to the caller and may be reused once we return.
		c.buf = append([]byte(nil), data...)
		return len(p), nil
	case err != nil:
		c.done = true
		c.buf = nil
		n, werr := writeAllCount(c.Conn, data)
		if werr != nil {
			c.err = werr
			_ = c.Close()
		}
		return currentWriteCount(n, buffered, len(p)), werr
	}

	c.done = true
	c.buf = nil
	n, err := c.sendFirst(data[:rl])
	if err != nil {
		c.err = err
		_ = c.Close()
		return currentWriteCount(n, buffered, len(p)), err
	}
	if len(data) > rl {
		tailN, tailErr := writeAllCount(c.Conn, data[rl:])
		n += tailN
		if tailErr != nil {
			c.err = tailErr
			_ = c.Close()
			return currentWriteCount(n, buffered, len(p)), tailErr
		}
	}
	return len(p), nil
}

// sendFirst writes the first record with the options applied.
func (c *Conn) sendFirst(rec []byte) (int, error) {
	h, err := ParseHello(rec)
	if err != nil {
		return writeAllCount(c.Conn, rec)
	}
	out := rec
	recCuts := resolve(c.opts.TLSRec, h, recordHeaderLen, len(rec))
	if len(recCuts) > 0 {
		out = FragmentRecord(rec, recCuts)
	}
	start := 0
	if c.opts.Fake != nil {
		prefix, err := fakePrefixLength(len(out), c.opts.Fake.Prefix)
		if err != nil {
			return 0, err
		}
		// Submit the normal tail before waiting for the native prefix. A
		// low-TTL prefix can still be pending when this tail reaches the peer.
		if err := c.sendFake(out[:prefix], fakePayload(c.opts.Fake.Payload, prefix), out[prefix:]); err != nil {
			// A failed native asynchronous send has no reliable prefix count.
			// Report zero conservatively and terminate; never replay this stream.
			return 0, err
		}
		return len(rec), nil
	}
	tcpCuts := mapCuts(resolve(c.opts.Split, h, 0, len(rec)), recCuts)
	written := 0
	for i, end := range append(tcpCuts, len(out)) {
		if end <= start || end > len(out) {
			continue
		}
		if i > 0 && c.opts.SplitDelay > 0 {
			if err := c.waitWriteDelay(c.opts.SplitDelay); err != nil {
				return originalWriteCount(written, recCuts), err
			}
		}
		n, err := writeAllCount(c.Conn, out[start:end])
		written += n
		if err != nil {
			return originalWriteCount(written, recCuts), err
		}
		start = end
	}
	return len(rec), nil
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
