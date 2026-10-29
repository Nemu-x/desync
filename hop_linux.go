//go:build linux

package desync

import (
	"net"
	"os"
	"syscall"
)

// Linux and Android: an IPv4 or IPv4-mapped destination uses IP_TTL (also on
// an AF_INET6 socket, where the kernel sends mapped traffic through IPv4), an
// IPv6 destination IPV6_UNICAST_HOPS. getsockopt returns the effective value,
// including the system default.
func hopFor(fd uintptr, dst net.IP) (savedHop, error) {
	h := savedHop{level: syscall.IPPROTO_IP, option: syscall.IP_TTL}
	if dst.To4() == nil {
		h.level, h.option = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	v, err := syscall.GetsockoptInt(int(fd), h.level, h.option)
	if err != nil {
		return h, os.NewSyscallError("getsockopt hop limit", err)
	}
	h.restore = v
	return h, nil
}

func setHop(fd uintptr, h savedHop, value int) error {
	return os.NewSyscallError("setsockopt hop limit", syscall.SetsockoptInt(int(fd), h.level, h.option, value))
}

func socketPeer(fd uintptr) (net.IP, error) {
	sa, err := syscall.Getpeername(int(fd))
	if err != nil {
		return nil, os.NewSyscallError("getpeername", err)
	}
	return sockaddrIP(sa)
}

// Disorder waits until SIOCOUTQNSD reports no unsent bytes, so the low-hop
// piece was transmitted before the hop limit is restored.
var platformDisorder = DisorderCapability{Supported: true, Mechanism: "SIOCOUTQNSD", Observed: true, Reliable: true}
