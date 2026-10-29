package desync

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"
)

var (
	// ErrSplitWaitUnsupported reports that the requested SplitWait mode cannot
	// be observed on this platform or socket. The wrapper never replaces it
	// with a timed pause; use SplitDelay for an explicit delay.
	ErrSplitWaitUnsupported = errors.New("desync: split wait is not supported on this platform")
	// ErrSplitWaitRequiresTCP reports a connection that does not expose a
	// TCP socket through SyscallConn, so its send queue cannot be observed.
	ErrSplitWaitRequiresTCP = errors.New("desync: split wait requires a TCP connection exposing SyscallConn")
	// ErrSplitWaitTimeout reports that the previous piece was not observed as
	// sent or acknowledged within SplitWaitTimeout. The connection is closed.
	ErrSplitWaitTimeout = errors.New("desync: split wait timed out")
)

// SplitWait selects what the wrapper observes on the socket before it writes
// the next TCP piece of a split ClientHello. It is not a delay: the wait ends
// as soon as the kernel reports the condition, and fails with an error when
// it cannot be observed. The OS still decides how bytes become segments.
type SplitWait uint8

const (
	// SplitWaitNone writes the pieces back to back (plus SplitDelay).
	SplitWaitNone SplitWait = iota
	// SplitWaitSent waits until every byte written so far has been
	// transmitted at least once (it left the socket's unsent queue).
	SplitWaitSent
	// SplitWaitAcked waits until every byte written so far has been
	// acknowledged by the peer.
	SplitWaitAcked
)

const (
	defaultSplitWaitTimeout = 2 * time.Second
	maxSplitWaitTimeout     = time.Minute
)

func (w SplitWait) String() string {
	switch w {
	case SplitWaitNone:
		return "none"
	case SplitWaitSent:
		return "sent"
	case SplitWaitAcked:
		return "acked"
	}
	return fmt.Sprintf("SplitWait(%d)", uint8(w))
}

// ParseSplitWait parses "none", "sent" or "acked".
func ParseSplitWait(s string) (SplitWait, error) {
	switch s {
	case "", "none":
		return SplitWaitNone, nil
	case "sent":
		return SplitWaitSent, nil
	case "acked":
		return SplitWaitAcked, nil
	}
	return SplitWaitNone, fmt.Errorf("desync: unknown split wait %q", s)
}

// Capabilities describes what this build of the package implements on the
// current operating system. It reports availability, not effectiveness on a
// particular network. ProbeConn checks an actual socket.
type Capabilities struct {
	// OS is runtime.GOOS.
	OS string
	// FakeTCP reports Options.Fake support (same as SupportsFake).
	FakeTCP bool
	// FakeUDP reports WrapPacketConn support (same as SupportsUDPFake).
	FakeUDP bool
	// TTLControl reports that the package changes and restores a socket's
	// TTL or hop limit on this OS (used by Fake, Disorder and the UDP burst).
	TTLControl bool
	// Disorder describes Options.Disorder support.
	Disorder DisorderCapability
	// OOB reports Options.OOB support.
	OOB bool
	// Ack describes send-queue / acknowledgement observation for SplitWait.
	Ack AckCapability
	// Unsupported explains, keyed by method ("fake-tcp", "fake-udp",
	// "disorder", "oob"), why a method is not implemented on this OS.
	Unsupported map[string]string
}

// AckCapability describes how SplitWait observes a socket on this OS.
type AckCapability struct {
	// Mechanism names the kernel interface, empty when there is none.
	Mechanism string
	// Sent and Acked report which SplitWait modes are implemented.
	Sent, Acked bool
	// Reliable is true when the decision reads the kernel's own per-socket
	// send-queue state. It is false when it is inferred from cumulative
	// counters that can run ahead of the queue, so the wait may end early
	// (see docs/connection-io.md).
	Reliable bool
}

// Supports reports whether mode can be honored. SplitWaitNone always can.
func (a AckCapability) Supports(mode SplitWait) bool {
	switch mode {
	case SplitWaitNone:
		return true
	case SplitWaitSent:
		return a.Sent
	case SplitWaitAcked:
		return a.Acked
	}
	return false
}

// PlatformCapabilities reports what the package implements on this OS.
func PlatformCapabilities() Capabilities {
	c := Capabilities{
		OS:          runtime.GOOS,
		FakeTCP:     supportsFake,
		FakeUDP:     supportsUDPFake,
		TTLControl:  supportsFake || supportsUDPFake || platformDisorder.Supported,
		Disorder:    platformDisorder,
		OOB:         supportsOOB,
		Ack:         platformAck,
		Unsupported: map[string]string{},
	}
	if !supportsFake {
		c.Unsupported["fake-tcp"] = "not implemented on " + runtime.GOOS
	}
	if !supportsUDPFake {
		c.Unsupported["fake-udp"] = "not implemented on " + runtime.GOOS
	}
	if !platformDisorder.Supported {
		c.Unsupported["disorder"] = "not implemented on " + runtime.GOOS
	}
	if !supportsOOB {
		c.Unsupported["oob"] = "not implemented on " + runtime.GOOS
	}
	return c
}

// AckState is a snapshot of a socket's send queue. Values that the platform
// cannot observe are -1.
type AckState struct {
	// Unacked counts written bytes not yet acknowledged, sent or not.
	Unacked int64
	// Unsent counts written bytes not yet transmitted once.
	Unsent int64
	// InFlight counts transmitted bytes not yet acknowledged.
	InFlight int64
	// Sent is the cumulative number of distinct bytes transmitted on the
	// connection (counter-based platforms only).
	Sent int64
}

// ConnCapabilities is the result of probing an actual connection.
type ConnCapabilities struct {
	// TTL is the socket's current TTL (IPv4 peer) or unicast hop limit (IPv6
	// peer), or -1 when it cannot be read; TTLErr explains why.
	TTL    int
	TTLErr error
	// Ack lists the SplitWait modes this socket can honor; AckErr explains a
	// failed probe, in which case no mode is available.
	Ack    AckCapability
	AckErr error
	// State is the send-queue snapshot taken by the probe.
	State AckState
}

// ProbeConn queries the socket under c (unwrapping *Conn and other wrappers
// with a NetConn method) without changing it. It returns an error only when no
// socket is reachable; per-feature failures are reported in the result.
func ProbeConn(c net.Conn) (ConnCapabilities, error) {
	out := ConnCapabilities{TTL: -1, State: unknownAckState()}
	raw, err := socketOf(c)
	if err != nil {
		return out, err
	}
	ipv6 := false
	if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok && addr.IP.To4() == nil {
		ipv6 = true
	}
	controlErr := raw.Control(func(fd uintptr) {
		ttl, ttlErr := readSocketTTL(fd, ipv6)
		if ttlErr != nil {
			out.TTLErr = ttlErr
		} else {
			out.TTL = ttl
		}
	})
	if controlErr != nil {
		return out, controlErr
	}
	if !platformAck.Acked && !platformAck.Sent {
		out.AckErr = ErrSplitWaitUnsupported
		return out, nil
	}
	obs, err := newAckObserver(raw)
	if err == nil {
		out.State, err = obs.state()
	}
	if err != nil {
		out.AckErr = fmt.Errorf("%w: %v", ErrSplitWaitUnsupported, err)
		out.State = unknownAckState()
		return out, nil
	}
	out.Ack = platformAck
	return out, nil
}

func unknownAckState() AckState { return AckState{Unacked: -1, Unsent: -1, InFlight: -1, Sent: -1} }

// socketOf finds a SyscallConn below c, following NetConn wrappers.
func socketOf(c net.Conn) (syscall.RawConn, error) {
	for i := 0; i < 8 && c != nil; i++ {
		if s, ok := c.(syscall.Conn); ok {
			if _, tcp := c.LocalAddr().(*net.TCPAddr); !tcp {
				return nil, ErrSplitWaitRequiresTCP
			}
			return s.SyscallConn()
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		c = u.NetConn()
	}
	return nil, ErrSplitWaitRequiresTCP
}

// ackObserver samples one socket's send queue. reached reports whether mode
// holds for every byte written so far; written counts the bytes this wrapper
// wrote since the observer was created (counter-based platforms need it).
type ackObserver interface {
	reached(mode SplitWait, written int64) (bool, error)
	state() (AckState, error)
}

func (o Options) validateSplitWait() error {
	if o.SplitWaitTimeout < 0 || o.SplitWaitTimeout > maxSplitWaitTimeout {
		return fmt.Errorf("desync: split wait timeout must be between 0 and %v", maxSplitWaitTimeout)
	}
	if o.SplitWait == SplitWaitNone {
		return nil
	}
	if o.SplitWait > SplitWaitAcked {
		return fmt.Errorf("desync: unknown split wait %d", o.SplitWait)
	}
	if !o.splits() {
		return fmt.Errorf("desync: split wait requires Split or Random.Split positions")
	}
	if !platformAck.Supports(o.SplitWait) {
		return fmt.Errorf("%w (%s on %s)", ErrSplitWaitUnsupported, o.SplitWait, runtime.GOOS)
	}
	return nil
}

// splitObserver prepares observation before the first piece is written, so
// an unsupported socket fails before anything is transmitted.
func (c *Conn) splitObserver() (ackObserver, error) {
	if c.opts.SplitWait == SplitWaitNone {
		return nil, nil
	}
	raw, err := socketOf(c.Conn)
	if err != nil {
		return nil, err
	}
	obs, err := newAckObserver(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSplitWaitUnsupported, err)
	}
	return obs, nil
}

const (
	splitWaitSpins       = 16
	splitWaitMinInterval = 50 * time.Microsecond
	splitWaitMaxInterval = time.Millisecond
)

// waitSplit polls obs until the configured condition holds for the written
// bytes, bounded by SplitWaitTimeout.
func (c *Conn) waitSplit(obs ackObserver, written int64) error {
	timeout := c.opts.SplitWaitTimeout
	if timeout == 0 {
		timeout = defaultSplitWaitTimeout
	}
	return c.poll(timeout, ErrSplitWaitTimeout, "split wait", func() (bool, error) {
		return obs.reached(c.opts.SplitWait, written)
	})
}

// poll calls cond until it reports true. The poll interval starts with a few
// scheduler yields, then grows from 50 microseconds to 1 ms. Close, the write
// deadline (including changes to it) and timeout bound the wait; timeoutErr is
// returned when timeout expires. A cond error is wrapped with what.
func (c *Conn) poll(timeout time.Duration, timeoutErr error, what string, cond func() (bool, error)) error {
	end := time.Now().Add(timeout)
	interval := time.Duration(0)
	for polls := 0; ; polls++ {
		deadline, changed, err := c.writeState()
		if err != nil {
			return err
		}
		ok, err := cond()
		if err != nil {
			select {
			case <-c.closed:
				return net.ErrClosed
			default:
			}
			return fmt.Errorf("desync: %s: %w", what, err)
		}
		if ok {
			return nil
		}
		now := time.Now()
		if !now.Before(end) {
			return timeoutErr
		}
		if polls < splitWaitSpins {
			runtime.Gosched()
			continue
		}
		if interval == 0 {
			interval = splitWaitMinInterval
		} else if interval < splitWaitMaxInterval {
			interval *= 2
			if interval > splitWaitMaxInterval {
				interval = splitWaitMaxInterval
			}
		}
		sleep := interval
		if d := end.Sub(now); d < sleep {
			sleep = d
		}
		if !deadline.IsZero() {
			if d := deadline.Sub(now); d < sleep {
				sleep = d
			}
		}
		timer := time.NewTimer(sleep)
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
