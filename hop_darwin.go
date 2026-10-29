//go:build darwin

package desync

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// macOS/iOS: an AF_INET socket uses IP_TTL. An AF_INET6 socket rejects
// IPPROTO_IP options (xnu ip6_ctloutput), and IPV6_UNICAST_HOPS sets both its
// IPv6 hop limit and, on a dual-stack socket, the TTL of IPv4-mapped traffic
// (in6p_hops and inp_ip_ttl). Its value -1 means the system default; restoring
// -1 on a dual-stack socket would also set the IPv4 TTL to 255 (the kernel
// casts it to uint8), so there the default is restored as the explicit
// value, and only when both defaults (net.inet6.ip6.hlim, net.inet.ip.ttl)
// are equal.
func hopFor(fd uintptr, _ net.IP) (savedHop, error) {
	sa, err := syscall.Getsockname(int(fd))
	if err != nil {
		return savedHop{}, os.NewSyscallError("getsockname", err)
	}
	h := savedHop{level: syscall.IPPROTO_IP, option: syscall.IP_TTL}
	if _, ok := sa.(*syscall.SockaddrInet6); ok {
		h.level, h.option = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	v, err := syscall.GetsockoptInt(int(fd), h.level, h.option)
	if err != nil {
		return h, os.NewSyscallError("getsockopt hop limit", err)
	}
	h.restore = v
	if v >= 0 || h.level != syscall.IPPROTO_IPV6 {
		return h, nil
	}
	only, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
	if err != nil {
		return h, os.NewSyscallError("getsockopt IPV6_V6ONLY", err)
	}
	if only != 0 {
		return h, nil
	}
	hlim, err := syscall.SysctlUint32("net.inet6.ip6.hlim")
	if err != nil {
		return h, os.NewSyscallError("sysctl net.inet6.ip6.hlim", err)
	}
	ttl, err := syscall.SysctlUint32("net.inet.ip.ttl")
	if err != nil {
		return h, os.NewSyscallError("sysctl net.inet.ip.ttl", err)
	}
	if hlim != ttl || hlim < 1 || hlim > 255 {
		return h, fmt.Errorf("desync: cannot restore the hop limits of a dual-stack socket: default IPv6 hop limit %d differs from default TTL %d", hlim, ttl)
	}
	h.restore = int(hlim)
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

// Disorder cannot observe unsent bytes here. It writes the low-hop piece only
// once SO_NWRITE reports an empty send buffer, so the kernel builds the
// segment within the send call; that transmission is inferred, not observed.
var platformDisorder = DisorderCapability{Supported: true, Mechanism: "SO_NWRITE"}
