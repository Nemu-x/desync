//go:build linux || darwin

package desync

import (
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// closedUDPPort returns a loopback address nothing listens on, so a datagram
// to it draws an ICMP port-unreachable reply.
func closedUDPPort(t *testing.T) *net.UDPAddr {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().(*net.UDPAddr)
	c.Close()
	return addr
}

func setRecvErr(t *testing.T, c *net.UDPConn, on int) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 0xb, on) // IP_RECVERR
	}); err != nil || opErr != nil {
		t.Fatal(err, opErr)
	}
}

// readAfterICMP sends one datagram to a closed port and reports what the next
// ReadFrom returns.
func readAfterICMP(t *testing.T, pc net.PacketConn, to net.Addr) error {
	t.Helper()
	if _, err := pc.WriteTo([]byte("probe"), to); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err := pc.ReadFrom(make([]byte, 64))
	return err
}

// ICMP errors caused by the burst must not surface on the owned socket. A
// port-unreachable reply on loopback takes the same path as a time-exceeded
// reply on a real route (udp_err / udp_ctlinput).
func TestUDPFakeSuppressesICMPErrors(t *testing.T) {
	to := closedUDPPort(t)
	if runtime.GOOS == "linux" {
		// Control: with IP_RECVERR on, the error reaches ReadFrom.
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		setRecvErr(t, c, 1)
		err = readAfterICMP(t, c, to)
		c.Close()
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("control without suppression: %v, want ECONNREFUSED", err)
		}
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	setRecvErr(t, c, 1)
	wrapped, err := WrapPacketConn(c, UDPOptions{TTL: 4, Repeats: 2})
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	defer wrapped.Close()
	if err := readAfterICMP(t, wrapped, to); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom after ICMP error: %v, want a timeout", err)
	}
	if runtime.GOOS == "linux" {
		raw, _ := c.SyscallConn()
		var v int
		var opErr error
		_ = raw.Control(func(fd uintptr) { v, opErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, 0xb) })
		if opErr != nil || v != 0 {
			t.Fatalf("IP_RECVERR after wrap: %d %v", v, opErr)
		}
	}
}
