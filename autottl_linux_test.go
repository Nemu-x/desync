//go:build linux

package desync

import (
	"bytes"
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// hopLimitListener listens on IPv6 loopback with hop limit hl, which the
// SYN-ACK (sent by the listener) and the accepted socket inherit, so a
// loopback path looks like 64/128/255 - hl hops to the client.
func hopLimitListener(t *testing.T, hl int) net.Listener {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, hl)
		})
		if err != nil {
			return err
		}
		return opErr
	}}
	ln, err := lc.Listen(context.Background(), "tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func dialAutoTTL(t *testing.T, ln net.Listener, control bool) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	if control {
		d.Control = ControlAutoTTL
	}
	client, err := d.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

// The client reads the hop limit of the server's SYN-ACK right after
// connect, before it sent anything, without privileges.
func TestLinuxObserveHopsSynAck(t *testing.T) {
	for _, tc := range []struct{ hl, hops int }{{120, 8}, {61, 3}, {250, 5}, {64, 0}} {
		ln := hopLimitListener(t, tc.hl)
		client, _ := dialAutoTTL(t, ln, true)
		got, err := ObserveHops(WrapConn(client, Options{TLSRec: []Pos{{Offset: 1}}}))
		if err != nil || got.TTL != tc.hl || got.Hops != tc.hops {
			t.Fatalf("hop limit %d: %+v %v, want TTL %d hops %d", tc.hl, got, err, tc.hl, tc.hops)
		}
	}
	// Ambiguous values are reported, not guessed.
	ln := hopLimitListener(t, 80)
	client, _ := dialAutoTTL(t, ln, true)
	if got, err := ObserveHops(client); !errors.Is(err, ErrAutoTTLUnobserved) || got.TTL != 80 {
		t.Fatalf("hop limit 80: %+v %v", got, err)
	}
}

// The recorded value follows the last in-order segment, here data sent with
// a different hop limit after the handshake.
func TestLinuxObserveHopsFollowsData(t *testing.T) {
	ln := hopLimitListener(t, 120)
	client, server := dialAutoTTL(t, ln, true)
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, 100)
	}); err != nil || opErr != nil {
		t.Fatal(err, opErr)
	}
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if got, err := ObserveHops(client); err != nil || got.TTL != 100 || got.Hops != 28 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestLinuxObserveHopsNeedsControl(t *testing.T) {
	ln := hopLimitListener(t, 120)
	client, _ := dialAutoTTL(t, ln, false)
	if _, err := ObserveHops(client); !errors.Is(err, ErrAutoTTLUnobserved) {
		t.Fatalf("without ControlAutoTTL: %v", err)
	}
	// IPv4 stays unobservable even when prepared.
	ln4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln4.Close()
	c4, err := (&net.Dialer{Control: ControlAutoTTL}).Dial("tcp4", ln4.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c4.Close()
	if _, err := ObserveHops(c4); !errors.Is(err, ErrAutoTTLUnsupported) {
		t.Fatalf("IPv4: %v", err)
	}
}

// End to end: the fake is sent with the TTL derived from the SYN-ACK (hop
// limit 120: 8 hops, TTL 7). The server drops segments below hop limit 8,
// like the router before it would, so the stream is intact only if the fake
// used the derived TTL and TCP retransmitted the original bytes.
func TestLinuxFakeAutoTTLRoundTrip(t *testing.T) {
	ln := hopLimitListener(t, 120)
	client, server := dialAutoTTL(t, ln, true)
	dropLowHop(t, server, true)
	hello := captureHello(t, "example.test")
	tail := []byte("after the hello")
	before := tcpHop(t, client)
	w := WrapConn(client, Options{Fake: &FakeOptions{AutoTTL: &AutoTTL{}, Payload: bytes.Repeat([]byte{'X'}, 600)}}).(*Conn)
	_ = w.SetWriteDeadline(time.Now().Add(10 * time.Second))
	read := readUntil(server, tail)
	input := append(append([]byte(nil), hello...), tail...)
	if n, err := w.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write: %d %v", n, err)
	}
	if got := <-read; !bytes.Equal(got, input) {
		t.Fatalf("server stream changed: got %d bytes %q", len(got), got)
	}
	if ttl, auto := w.FakeTTL(); ttl != 7 || !auto {
		t.Fatalf("FakeTTL: %d %v, want 7 derived", ttl, auto)
	}
	if after := tcpHop(t, client); after != before {
		t.Fatalf("hop limit not restored: %d -> %d", before, after)
	}
	if n, ok := tcpRetransmits(t, client); ok && n == 0 {
		t.Fatal("the fake was not dropped and retransmitted")
	}
	// The wrapper stopped the per-segment recording after reading it.
	raw, _ := client.SyscallConn()
	var on int
	_ = raw.Control(func(fd uintptr) { on, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvHopLimit) })
	if on != 0 {
		t.Fatal("IPV6_RECVHOPLIMIT still enabled")
	}
}

// The reason IPv4 is unsupported, observed: with IP_RECVTTL enabled before
// connect, IP_PKTOPTIONS on the client reports the multicast TTL (1), not the
// TTL 120 of the server's SYN-ACK and data.
func TestLinuxIPv4TCPRecordsNoTTL(t *testing.T) {
	const ipPktOptions, ipRecvTTL, ipTTL = 9, 12, 2 // linux/in.h
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 120) })
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipRecvTTL, 1) })
	}}
	client, err := d.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	raw, _ := client.(*net.TCPConn).SyscallConn()
	buf := make([]byte, 256)
	var n int
	var opErr error
	_ = raw.Control(func(fd uintptr) { n, opErr = getsockoptBytes(fd, syscall.IPPROTO_IP, ipPktOptions, buf) })
	if opErr != nil {
		t.Fatal(opErr)
	}
	msgs, err := syscall.ParseSocketControlMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == ipTTL && len(m.Data) >= 4 {
			v := int(m.Data[0]) | int(m.Data[1])<<8 | int(m.Data[2])<<16 | int(m.Data[3])<<24
			if v == 120 {
				t.Fatalf("the kernel now reports the received TTL on IPv4 TCP; auto TTL could support IPv4")
			}
			t.Logf("IP_PKTOPTIONS IP_TTL: %d (not the received 120)", v)
			return
		}
	}
	t.Logf("IP_PKTOPTIONS returned no IP_TTL message (%d bytes)", n)
}

// Both header layouts are parsed: a 32-bit process on a 64-bit kernel gets
// 64-bit headers from IPV6_2292PKTOPTIONS.
func TestLinuxCmsgIntLayouts(t *testing.T) {
	// 64-bit: IPV6_PKTINFO (len 36, padded to 40) then IPV6_HOPLIMIT 120.
	b64 := make([]byte, 64)
	put := func(b []byte, off int, v uint32) {
		b[off], b[off+1], b[off+2], b[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	}
	little := func() bool { x := uint16(1); return *(*byte)(unsafe.Pointer(&x)) == 1 }()
	if !little {
		t.Skip("layout fixture is little-endian")
	}
	put(b64, 0, 36)
	put(b64, 8, syscall.IPPROTO_IPV6)
	put(b64, 12, 50) // IPV6_PKTINFO
	put(b64, 40, 20)
	put(b64, 48, syscall.IPPROTO_IPV6)
	put(b64, 52, ipv6HopLimit)
	put(b64, 56, 120)
	if v, ok := cmsgInt(b64[:60], 16, 8, syscall.IPPROTO_IPV6, ipv6HopLimit); !ok || v != 120 {
		t.Fatalf("64-bit: %d %v", v, ok)
	}
	if _, ok := cmsgInt(b64[:60], 12, 4, syscall.IPPROTO_IPV6, ipv6HopLimit); ok {
		t.Fatal("64-bit headers misread as 32-bit")
	}
	b32 := make([]byte, 16)
	put(b32, 0, 16)
	put(b32, 4, syscall.IPPROTO_IPV6)
	put(b32, 8, ipv6HopLimit)
	put(b32, 12, 61)
	if v, ok := cmsgInt(b32, 12, 4, syscall.IPPROTO_IPV6, ipv6HopLimit); !ok || v != 61 {
		t.Fatalf("32-bit: %d %v", v, ok)
	}
	for _, b := range [][]byte{nil, make([]byte, 16), {200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, ok := cmsgInt(b, 16, 8, syscall.IPPROTO_IPV6, ipv6HopLimit); ok {
			t.Fatalf("garbage %x parsed", b)
		}
	}
}
