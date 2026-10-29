package desync

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"syscall"
)

var (
	// ErrDisorderUnsupported reports that Options.Disorder is not implemented
	// on this platform.
	ErrDisorderUnsupported = errors.New("desync: disorder is not implemented on this platform")
	// ErrOOBUnsupported reports that Options.OOB is not implemented on this
	// platform.
	ErrOOBUnsupported = errors.New("desync: out-of-band data is not implemented on this platform")
	// ErrSocketMethodRequiresTCP reports that Disorder or OOB was requested on
	// a connection that does not expose a TCP socket through SyscallConn.
	ErrSocketMethodRequiresTCP = errors.New("desync: disorder and OOB require a TCP connection exposing SyscallConn")
)

// disorderHopLimit makes the first transmission of the piece expire at the
// first router (ByeDPI --disorder uses the same value).
const disorderHopLimit = 1

// DefaultOOBByte is the out-of-band byte sent when OOBOptions.Byte is zero.
const DefaultOOBByte = 'a'

// OOBOptions sends one byte of TCP urgent data (MSG_OOB) right after the
// first TCP piece (ByeDPI --oob). A receiver without SO_OOBINLINE removes the
// urgent byte from the stream, so the server reads the original bytes; an
// inspecting device that ignores the urgent pointer sees one extra byte.
type OOBOptions struct {
	// Byte is the urgent byte; zero selects DefaultOOBByte ('a').
	Byte byte
}

func (o *OOBOptions) urgentByte() byte {
	if o.Byte == 0 {
		return DefaultOOBByte
	}
	return o.Byte
}

// DisorderCapability describes Options.Disorder on this OS.
type DisorderCapability struct {
	// Supported reports that Options.Disorder is implemented.
	Supported bool
	// Mechanism names the socket query used around the low-hop piece.
	Mechanism string
	// Observed is true when the hop limit is restored only after the kernel
	// reported the low-hop piece as transmitted. When false (macOS), the
	// piece is written once the send buffer is empty, so the kernel builds
	// its segment inside the send call; this is inferred, not observed.
	Observed bool
	// Reliable is true when the observation reads the kernel's queue state
	// rather than counters (see AckCapability.Reliable).
	Reliable bool
}

func (o Options) validateSocketMethods() error {
	if !o.Disorder && o.OOB == nil {
		return nil
	}
	if !o.splits() {
		return fmt.Errorf("desync: disorder and OOB require Split or Random.Split positions")
	}
	if o.Disorder && o.SplitWait == SplitWaitAcked {
		// The low-hop piece is acknowledged only after its retransmission,
		// so an acknowledged wait would undo the reordering.
		return fmt.Errorf("desync: disorder cannot be combined with SplitWaitAcked")
	}
	if o.Disorder && !platformDisorder.Supported {
		return fmt.Errorf("%w (%s)", ErrDisorderUnsupported, runtime.GOOS)
	}
	if o.OOB != nil && !supportsOOB {
		return fmt.Errorf("%w (%s)", ErrOOBUnsupported, runtime.GOOS)
	}
	return nil
}

// firstPiece sends the first TCP piece of a split ClientHello with the
// configured socket methods. It is prepared before anything is written, so
// a connection without a usable socket fails before transmission.
type firstPiece struct {
	raw syscall.RawConn
	obs ackObserver // disorder only
}

func (c *Conn) prepareFirstPiece(splitObs ackObserver) (*firstPiece, error) {
	if !c.opts.Disorder && c.opts.OOB == nil {
		return nil, nil
	}
	raw, err := socketOf(c.Conn)
	if err != nil {
		return nil, ErrSocketMethodRequiresTCP
	}
	p := &firstPiece{raw: raw, obs: splitObs}
	if c.opts.Disorder && p.obs == nil {
		if p.obs, err = newAckObserver(raw); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDisorderUnsupported, err)
		}
	}
	return p, nil
}

// send writes piece and returns how many of its bytes were written and how
// many extra (urgent) bytes went to the socket. With Disorder the piece goes
// out with hop limit 1; the limit is restored before send returns, also on
// every error, and the restore error is reported.
func (p *firstPiece) send(c *Conn, piece []byte) (n, extra int, err error) {
	if !c.opts.Disorder {
		return p.write(c, piece)
	}
	timeout := c.opts.SplitWaitTimeout
	if timeout == 0 {
		timeout = defaultSplitWaitTimeout
	}
	if !platformDisorder.Observed {
		// Every earlier byte acknowledged: the send queue is empty, so the
		// kernel transmits the piece within the send call.
		if err := c.poll(timeout, ErrSplitWaitTimeout, "disorder", func() (bool, error) {
			return p.obs.reached(SplitWaitAcked, 0)
		}); err != nil {
			return 0, 0, err
		}
	}
	saved, err := lowerHop(p.raw, disorderHopLimit)
	if err != nil {
		return 0, 0, fmt.Errorf("desync: disorder: %w", err)
	}
	defer func() {
		if restoreErr := restoreHop(p.raw, saved); restoreErr != nil {
			err = errors.Join(err, restoreErr)
		}
	}()
	if n, extra, err = p.write(c, piece); err != nil {
		return n, extra, err
	}
	if platformDisorder.Observed {
		// Restore only after the low-hop segment left the socket. A restore
		// before it would send the piece with the normal hop limit.
		written := int64(n + extra)
		err = c.poll(timeout, ErrSplitWaitTimeout, "disorder", func() (bool, error) {
			return p.obs.reached(SplitWaitSent, written)
		})
	}
	return n, extra, err
}

func (p *firstPiece) write(c *Conn, piece []byte) (int, int, error) {
	if c.opts.OOB == nil {
		n, err := writeAllCount(c.Conn, piece)
		return n, 0, err
	}
	buf := make([]byte, len(piece)+1)
	copy(buf, piece)
	buf[len(piece)] = c.opts.OOB.urgentByte()
	n, err := sendOOBFunc(p.raw, buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if n >= len(buf) {
		return len(piece), 1, err
	}
	return n, 0, err
}

// sendOOBFunc is replaced by tests to observe the socket at the send.
var sendOOBFunc = sendOOB
