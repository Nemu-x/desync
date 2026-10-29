//go:build windows

package desync

import (
	"net"
	"os"
	"syscall"
)

// Windows: select the option by the destination family. Reading IP_TTL can
// succeed on an IPv6-only socket although setting it fails, and an
// IPv4-mapped destination on a dual-stack socket uses IP_TTL.
func hopFor(fd uintptr, dst net.IP) (savedHop, error) {
	h := savedHop{level: syscall.IPPROTO_IP, option: syscall.IP_TTL}
	if dst.To4() == nil {
		h.level, h.option = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	v, err := getsockoptInt(syscall.Handle(fd), h.level, h.option)
	if err != nil {
		return h, os.NewSyscallError("getsockopt hop limit", err)
	}
	h.restore = v
	return h, nil
}

func setHop(fd uintptr, h savedHop, value int) error {
	return os.NewSyscallError("setsockopt hop limit", syscall.SetsockoptInt(syscall.Handle(fd), h.level, h.option, value))
}

func socketPeer(fd uintptr) (net.IP, error) {
	sa, err := syscall.Getpeername(syscall.Handle(fd))
	if err != nil {
		return nil, os.NewSyscallError("getpeername", err)
	}
	return sockaddrIP(sa)
}

// Disorder waits until SIO_TCP_INFO counts the low-hop piece as sent; the
// counters are not reliable (see AckCapability.Reliable).
var platformDisorder = DisorderCapability{Supported: true, Mechanism: "SIO_TCP_INFO", Observed: true}
