//go:build linux

package desync

import (
	"os"
	"syscall"
)

// suppressUDPErrors keeps the ICMP time-exceeded replies to the low-TTL
// datagrams from surfacing on this owned socket. Linux reports ICMP errors on
// an unconnected UDP socket only with IP_RECVERR/IPV6_RECVERR enabled (see
// __udp4_lib_err/__udp6_lib_err: without it, a soft error such as time
// exceeded is dropped, and a hard one is reported only on a connected
// socket). Both are off by default; if the caller enabled them, they are
// turned off, otherwise a time-exceeded reply would fail the next ReadFrom
// with EHOSTUNREACH and be queued on the error queue.
func suppressUDPErrors(fd uintptr) error {
	options := [][2]int{{syscall.IPPROTO_IP, syscall.IP_RECVERR}}
	if sa, err := syscall.Getsockname(int(fd)); err == nil {
		if _, ok := sa.(*syscall.SockaddrInet6); ok {
			options = append(options, [2]int{syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR})
		}
	}
	for _, o := range options {
		v, err := syscall.GetsockoptInt(int(fd), o[0], o[1])
		if err != nil {
			return os.NewSyscallError("getsockopt RECVERR", err)
		}
		if v != 0 {
			if err := syscall.SetsockoptInt(int(fd), o[0], o[1], 0); err != nil {
				return os.NewSyscallError("setsockopt RECVERR", err)
			}
		}
	}
	return nil
}
