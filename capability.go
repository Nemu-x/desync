package desync

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
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
// particular network. A method is reported only when it works on every
// socket of this OS; ProbeConn and ProbeCapabilities check an actual socket.
type Capabilities struct {
	// OS is runtime.GOOS.
	OS string
	// FakeTCP reports Options.Fake support. It equals SupportsFake except on
	// Android, where the fake is listed in Conditional instead.
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
	// AutoTTL describes observing the server's TTL for FakeOptions.AutoTTL.
	AutoTTL AutoTTLCapability
	// Unsupported explains, keyed by method ("fake-tcp", "fake-udp",
	// "disorder", "oob", "auto-ttl-ipv4", "auto-ttl-ipv6"), why a method is
	// not implemented on this OS, or (for the methods in Conditional) why it
	// is not guaranteed.
	Unsupported map[string]string
	// Conditional lists, keyed like Unsupported ("split-wait-sent",
	// "fake-tcp", "disorder"), methods this build implements but whose
	// availability depends on the socket and kernel, with the reason. They
	// are reported as unavailable above (and in Unsupported); Validate
	// accepts them, and a socket that cannot provide them fails the first
	// Write before any byte is sent. ProbeCapabilities resolves them on a
	// live connection. Only Android has conditional methods.
	Conditional map[string]string
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
		AutoTTL:     platformAutoTTL,
		Unsupported: map[string]string{},
	}
	if !platformAutoTTL.IPv4 {
		c.Unsupported["auto-ttl-ipv4"] = autoTTLIPv4Reason
	}
	if !platformAutoTTL.IPv6 {
		c.Unsupported["auto-ttl-ipv6"] = autoTTLIPv6Reason
	}
	if !supportsFake {
		c.Unsupported["fake-tcp"] = fakeUnsupportedReason
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
	if sentPerSocket {
		c.lowerSentMethods(sentPerSocketReason, true)
	}
	return c
}

// lowerSentMethods reports the methods that need a socket's unsent-byte
// count (SplitWaitSent, the Linux fake, observed disorder) as unavailable
// with reason, and also as Conditional when conditional is set.
func (c *Capabilities) lowerSentMethods(reason string, conditional bool) {
	if c.Unsupported == nil {
		c.Unsupported = map[string]string{}
	}
	if conditional && c.Conditional == nil {
		c.Conditional = map[string]string{}
	}
	lower := func(key string) {
		c.Unsupported[key] = reason
		if conditional {
			c.Conditional[key] = reason
		}
	}
	if c.Ack.Sent {
		c.Ack.Sent = false
		if i := strings.IndexByte(c.Ack.Mechanism, '/'); i >= 0 {
			// "SIOCOUTQ/SIOCOUTQNSD": only the first query remains
			c.Ack.Mechanism = c.Ack.Mechanism[:i]
		}
		lower("split-wait-sent")
	}
	if c.FakeTCP && fakeObservesSent {
		c.FakeTCP = false
		lower("fake-tcp")
	}
	if c.Disorder.Supported && c.Disorder.Observed {
		c.Disorder = DisorderCapability{}
		lower("disorder")
	}
}

// ProbeCapabilities returns PlatformCapabilities adjusted to the socket under
// c (found like ProbeConn finds it): the SplitWait modes, the TCP fake and
// disorder are reported as this socket can honor them, and Conditional is
// resolved (empty). On Android, probe a connection before choosing
// strategies; a loopback one is enough, because the restriction belongs to
// the app's SELinux domain and the kernel. The error is ProbeConn's.
func ProbeCapabilities(c net.Conn) (Capabilities, error) {
	caps := PlatformCapabilities()
	conn, err := ProbeConn(c)
	if err != nil {
		return caps, err
	}
	return caps.withConn(conn), nil
}

// withConn applies a probe of one socket to the platform capabilities.
func (c Capabilities) withConn(conn ConnCapabilities) Capabilities {
	out := c
	out.Unsupported = make(map[string]string, len(c.Unsupported))
	for k, v := range c.Unsupported {
		if _, conditional := c.Conditional[k]; !conditional {
			out.Unsupported[k] = v
		}
	}
	out.Conditional = nil
	// Start from what the build implements, then lower what this socket
	// cannot do.
	out.Ack, out.FakeTCP, out.Disorder = platformAck, supportsFake, platformDisorder
	switch {
	case conn.AckErr != nil:
		reason := conn.AckErr.Error()
		if out.Ack.Acked {
			out.Unsupported["split-wait-acked"] = reason
		}
		out.lowerSentMethods(reason, false)
		out.Ack = AckCapability{}
		if out.Disorder.Supported {
			// unobserved disorder (macOS) still needs the acknowledged count
			out.Disorder = DisorderCapability{}
			out.Unsupported["disorder"] = reason
		}
	case !conn.Ack.Sent:
		reason := "unsent bytes cannot be observed on this socket"
		if conn.SentErr != nil {
			reason = conn.SentErr.Error()
		}
		out.lowerSentMethods(reason, false)
		out.Ack = conn.Ack
	default:
		out.Ack = conn.Ack
		if i := strings.IndexByte(conn.Ack.Mechanism, '/'); i >= 0 && out.Disorder.Observed {
			// disorder reads the same unsent-byte source as SplitWaitSent
			out.Disorder.Mechanism = conn.Ack.Mechanism[i+1:]
		}
	}
	return out
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
	// Ack lists the SplitWait modes this socket can honor, with the
	// mechanism it uses (on Linux "SIOCOUTQ/SIOCOUTQNSD", "SIOCOUTQ/TCP_INFO"
	// where SIOCOUTQNSD is denied, as on Android, or "SIOCOUTQ" when neither
	// reports unsent bytes); AckErr explains a failed probe, in which case no
	// mode is available.
	Ack    AckCapability
	AckErr error
	// SentErr explains why Ack.Sent is false on a socket whose acknowledged
	// bytes can be observed (for example SIOCOUTQNSD denied and a kernel
	// without tcpi_notsent_bytes). The methods that need unsent bytes
	// (SplitWaitSent, the Linux fake, disorder) fail on this socket before
	// sending.
	SentErr error
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
	out.Ack, out.SentErr = obs.capability()
	if out.Ack.Sent || !platformAck.Sent {
		out.SentErr = nil
	}
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
// capability reports the modes this socket can honor and, when Sent is
// false, why.
type ackObserver interface {
	reached(mode SplitWait, written int64) (bool, error)
	state() (AckState, error)
	capability() (AckCapability, error)
}

// observer returns the send-queue observer of the socket raw, created once
// per connection: sendHello runs once, under c.mu, and its split wait,
// disorder and fake share it, so a denied query is attempted only once.
func (c *Conn) observer(raw syscall.RawConn) (ackObserver, error) {
	if c.obs != nil {
		return c.obs, nil
	}
	obs, err := newAckObserver(raw)
	if err != nil {
		return nil, err
	}
	c.obs = obs
	return obs, nil
}

// requireSent fails when obs cannot report unsent bytes; base is the
// method's sentinel error.
func requireSent(obs ackObserver, base error) error {
	ack, why := obs.capability()
	if ack.Sent {
		return nil
	}
	if why == nil {
		why = errors.New("unsent bytes cannot be observed on this socket")
	}
	return fmt.Errorf("%w: %w", base, why)
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
	obs, err := c.observer(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSplitWaitUnsupported, err)
	}
	if c.opts.SplitWait == SplitWaitSent {
		if err := requireSent(obs, ErrSplitWaitUnsupported); err != nil {
			return nil, err
		}
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
