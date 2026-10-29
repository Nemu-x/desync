package desync

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrUDPFakeUnsupported = errors.New("desync: UDP fake is not implemented on this platform")
var ErrUDPFakeRequiresSocket = errors.New("desync: UDP fake requires an unconnected UDP socket exposing SyscallConn")

// UDPOptions inserts a bounded burst of low-TTL datagrams before the first
// few application datagrams to each peer. The original payload is unchanged.
// TTL must expire beyond the inspecting device and before the actual peer;
// effectiveness and a suitable TTL must be established on the user's network.
type UDPOptions struct {
	TTL int
	// Repeats defaults to 6, and must be between 1 and 16.
	Repeats int
	// Packets defaults to 3 initial application datagrams per peer (1-8).
	Packets int
	// Payload defaults to 64 zero bytes. Custom payloads may contain 1-1200 bytes.
	Payload []byte

	// QUIC decoys. Template generates the decoy instead of Payload (which
	// must then be empty); SNI is the server name in the QUIC Initial
	// template's ClientHello (default DefaultQUICSNI, wildcards as in
	// FakeOptions.SNI); QUICOnly limits the burst to datagrams that look like
	// a QUIC client Initial (long header, version 1, a draft or 2, Initial
	// type, at least 1200 bytes), so other UDP traffic passes untouched and
	// does not count towards Packets.
	Template UDPTemplate
	SNI      string
	QUICOnly bool

	// Counters can be shared by sockets belonging to one outbound. Do not copy
	// or reset a counters value after it has been used.
	Counters *UDPCounters
}

// UDPCounters is a concurrency-safe, optional aggregate; its zero value is ready.
type UDPCounters struct {
	packets atomic.Uint64
	fakes   atomic.Uint64
	errors  atomic.Uint64
	peers   atomic.Uint64
}

type UDPSnapshot struct {
	Packets     uint64 `json:"packets"`
	FakePackets uint64 `json:"fakePackets"`
	FakeErrors  uint64 `json:"fakeErrors"`
	Peers       uint64 `json:"peers"`
}

func (c *UDPCounters) Snapshot() UDPSnapshot {
	if c == nil {
		return UDPSnapshot{}
	}
	return UDPSnapshot{Packets: c.packets.Load(), FakePackets: c.fakes.Load(), FakeErrors: c.errors.Load(), Peers: c.peers.Load()}
}

func SupportsUDPFake() bool { return supportsUDPFake }

func (o UDPOptions) Validate() error {
	if o.TTL < 1 || o.TTL > 255 {
		return fmt.Errorf("desync: UDP fake TTL must be between 1 and 255")
	}
	if o.Repeats < 0 || o.Repeats > 16 {
		return fmt.Errorf("desync: UDP repeats must be between 1 and 16 (or zero for default)")
	}
	if o.Packets < 0 || o.Packets > 8 {
		return fmt.Errorf("desync: UDP initial packets must be between 1 and 8 (or zero for default)")
	}
	if len(o.Payload) > 1200 {
		return fmt.Errorf("desync: UDP fake payload exceeds 1200 bytes")
	}
	if o.Template != UDPTemplateZero && o.Template != UDPTemplateQUICInitial {
		return fmt.Errorf("desync: unknown UDP template %d", int(o.Template))
	}
	if o.Template != UDPTemplateZero && len(o.Payload) > 0 {
		return fmt.Errorf("desync: UDP Template and Payload are mutually exclusive")
	}
	if o.SNI != "" {
		if o.Template != UDPTemplateQUICInitial {
			return fmt.Errorf("desync: UDP SNI needs Template UDPTemplateQUICInitial")
		}
		if err := validFakeSNI(o.SNI); err != nil {
			return err
		}
	}
	if !SupportsUDPFake() {
		return ErrUDPFakeUnsupported
	}
	return nil
}

type udpPeer struct {
	attempts int
	last     time.Time
}

// PacketConn owns writes to its UDP socket. Do not write to the underlying
// socket separately: its TTL is changed temporarily during injection. ReadFrom,
// deadlines and Close retain net.PacketConn semantics. No raw socket or packet
// driver is required. Peers are bounded to 64 per socket and expire after idle.
type PacketConn struct {
	net.PacketConn
	opts   UDPOptions
	raw    syscall.RawConn
	mu     sync.Mutex
	peers  map[netip.AddrPort]udpPeer
	closed atomic.Bool
}

func WrapPacketConn(pc net.PacketConn, opts UDPOptions) (*PacketConn, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if pc == nil || pc.LocalAddr() == nil || !strings.HasPrefix(pc.LocalAddr().Network(), "udp") {
		return nil, ErrUDPFakeRequiresSocket
	}
	if connected, ok := pc.(interface{ RemoteAddr() net.Addr }); ok && connected.RemoteAddr() != nil {
		return nil, ErrUDPFakeRequiresSocket
	}
	socket, ok := pc.(syscall.Conn)
	if !ok {
		return nil, ErrUDPFakeRequiresSocket
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return nil, err
	}
	if err := configureUDPFake(raw); err != nil {
		return nil, err
	}
	if opts.Repeats == 0 {
		opts.Repeats = 6
	}
	if opts.Packets == 0 {
		opts.Packets = 3
	}
	if opts.Template == UDPTemplateQUICInitial {
		if opts.SNI == "" {
			opts.SNI = DefaultQUICSNI
		}
	} else if len(opts.Payload) == 0 {
		opts.Payload = make([]byte, 64)
	} else {
		opts.Payload = append([]byte(nil), opts.Payload...)
	}
	if opts.Counters == nil {
		opts.Counters = &UDPCounters{}
	}
	return &PacketConn{PacketConn: pc, opts: opts, raw: raw, peers: make(map[netip.AddrPort]udpPeer)}, nil
}

func (c *PacketConn) Counters() UDPSnapshot { return c.opts.Counters.Snapshot() }

func (c *PacketConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

func (c *PacketConn) shouldInject(addr net.Addr) bool {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp == nil {
		return false
	}
	peer := udp.AddrPort()
	if !peer.IsValid() {
		return false
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	now := time.Now()
	state, exists := c.peers[peer]
	if exists && now.Sub(state.last) > 2*time.Minute {
		delete(c.peers, peer)
		state, exists = udpPeer{}, false
	}
	if !exists {
		if len(c.peers) >= 64 {
			for key, value := range c.peers {
				if now.Sub(value.last) > 2*time.Minute {
					delete(c.peers, key)
				}
			}
			if len(c.peers) >= 64 {
				return false
			}
		}
		c.opts.Counters.peers.Add(1)
	}
	inject := state.attempts < c.opts.Packets
	if inject {
		state.attempts++
	}
	state.last = now
	c.peers[peer] = state
	return inject
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > 0 && (!c.opts.QUICOnly || looksLikeQUICInitial(p)) && c.shouldInject(addr) {
		opts := c.opts
		if opts.Template == UDPTemplateQUICInitial {
			payload, err := quicInitial(opts.SNI)
			if err != nil {
				c.opts.Counters.errors.Add(1)
				return 0, err
			}
			opts.Payload = payload
		}
		unsafeTTL, err := sendUDPFake(c.PacketConn, c.raw, opts, addr)
		if err != nil {
			c.opts.Counters.errors.Add(1)
			if unsafeTTL {
				_ = c.Close()
			}
			return 0, err
		}
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err == nil {
		c.opts.Counters.packets.Add(1)
	}
	return n, err
}
