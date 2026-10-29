//go:build windows

package desync

import (
	"net"
	"syscall"
	"testing"
)

// syscall.GetsockoptInt returns EWINDOWS before Go 1.21; the fake backends
// read options through getsockoptInt so they work on the module's minimum Go.
func TestGetsockoptIntRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var kind, before, after int
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		s := syscall.Handle(fd)
		if kind, opErr = getsockoptInt(s, syscall.SOL_SOCKET, 0x1008); opErr != nil { // SO_TYPE
			return
		}
		if before, opErr = getsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL); opErr != nil {
			return
		}
		if opErr = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, 33); opErr != nil {
			return
		}
		after, opErr = getsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL)
	}); err != nil {
		t.Fatal(err)
	}
	if opErr != nil {
		t.Fatal(opErr)
	}
	if kind != syscall.SOCK_STREAM || before < 1 || before > 255 || after != 33 {
		t.Fatalf("SO_TYPE %d, TTL %d -> %d", kind, before, after)
	}
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip(err)
	}
	defer udp.Close()
	hops, err := udpSocketTTLFor(udp, net.IPv6loopback)
	if err != nil || hops < 1 || hops > 255 {
		t.Fatalf("IPv6 hop limit: %d %v", hops, err)
	}
}

func setOOBInline(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, 0x0100, 1) // SO_OOBINLINE
}
