//go:build linux

package desync

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Linux (and Android) record the hop limit of IPv6 TCP segments when
// IPV6_RECVHOPLIMIT is enabled: tcp_v6_do_rcv clones each segment and, at
// ipv6_pktoptions, stores the hop limit of the last in-order one (including
// the SYN-ACK that completes connect) in np->mcast_hops. getsockopt
// IPV6_2292PKTOPTIONS returns it as an IPV6_HOPLIMIT control message on a
// stream socket. The option must be enabled before connect to see the SYN-ACK:
// after it nothing arrives before the ClientHello is sent.
//
// IPv4 has no counterpart: tcp_v4_do_rcv records nothing, and IP_PKTOPTIONS
// reports inet->mc_ttl, which only tcp_v4_syn_recv_sock (an accepted, passive
// socket) sets from a received packet. IPv4-mapped peers of an IPv6 socket
// take the IPv4 path too. Datagram ancillary data (IP_RECVTTL) is not
// delivered for TCP.
var platformAutoTTL = AutoTTLCapability{Mechanism: "IPV6_RECVHOPLIMIT/IPV6_2292PKTOPTIONS", IPv6: true}

const autoTTLIPv4Reason = "Linux records no received TTL for an outgoing IPv4 TCP connection: IP_RECVTTL control data is datagram-only, and IP_PKTOPTIONS reports the multicast TTL, which only an accepted socket sets from the handshake"
const autoTTLIPv6Reason = ""

// in6.h values, identical on every Linux architecture.
const (
	ipv6RecvHopLimit   = 0x33 // IPV6_RECVHOPLIMIT
	ipv6HopLimit       = 0x34 // IPV6_HOPLIMIT
	ipv62292PktOptions = 0x6  // IPV6_2292PKTOPTIONS
)

func prepareTTLObservation(fd uintptr, network string) error {
	if !strings.HasPrefix(network, "tcp") {
		return nil
	}
	sa, err := syscall.Getsockname(int(fd))
	if err != nil {
		return os.NewSyscallError("getsockname", err)
	}
	if _, ok := sa.(*syscall.SockaddrInet6); !ok || network == "tcp4" {
		return nil
	}
	// A dual-stack socket may still connect to an IPv4-mapped address, which
	// this cannot observe; enabling it there is harmless.
	return os.NewSyscallError("setsockopt IPV6_RECVHOPLIMIT", syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvHopLimit, 1))
}

// observeTTL reads the recorded hop limit. stop disables the recording
// afterwards, so the kernel no longer clones every received segment.
func observeTTL(fd uintptr, stop bool) (int, error) {
	peer, err := socketPeer(fd)
	if err != nil {
		return 0, err
	}
	if peer.To4() != nil {
		return 0, fmt.Errorf("%w: %s", ErrAutoTTLUnsupported, autoTTLIPv4Reason)
	}
	on, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvHopLimit)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt IPV6_RECVHOPLIMIT", err)
	}
	if on == 0 {
		return 0, fmt.Errorf("%w: IPV6_RECVHOPLIMIT was not enabled before connect (dial with ControlAutoTTL)", ErrAutoTTLUnobserved)
	}
	buf := make([]byte, 256)
	n, err := getsockoptBytes(fd, syscall.IPPROTO_IPV6, ipv62292PktOptions, buf)
	if stop {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvHopLimit, 0)
	}
	if err != nil {
		return 0, os.NewSyscallError("getsockopt IPV6_2292PKTOPTIONS", err)
	}
	// A 32-bit process on a 64-bit kernel still receives 64-bit control
	// message headers here: do_ipv6_getsockopt does not set MSG_CMSG_COMPAT
	// for IPV6_2292PKTOPTIONS (do_ip_getsockopt does for IP_PKTOPTIONS).
	for _, layout := range [...][2]int{{int(unsafe.Sizeof(syscall.Cmsghdr{})), int(unsafe.Sizeof(uintptr(0)))}, {16, 8}} {
		if v, ok := cmsgInt(buf[:n], layout[0], layout[1], syscall.IPPROTO_IPV6, ipv6HopLimit); ok {
			// mcast_hops starts at 1 (IPV6_DEFAULT_MCASTHOPS) and the
			// caller may set -1: neither was received.
			if v < 1 || v > 255 {
				break
			}
			return v, nil
		}
	}
	return 0, fmt.Errorf("%w: the kernel reported no received hop limit", ErrAutoTTLUnobserved)
}

// cmsgInt finds the int-valued control message level/typ in b, laid out with
// headers of hdr bytes (length word, level, type) and the given alignment.
func cmsgInt(b []byte, hdr, align, level, typ int) (int, bool) {
	for len(b) >= hdr {
		var length int
		if hdr == 16 {
			length = int(*(*uint64)(unsafe.Pointer(&b[0])))
		} else {
			length = int(*(*uint32)(unsafe.Pointer(&b[0])))
		}
		if length < hdr || length > len(b) {
			return 0, false
		}
		lv := int(*(*int32)(unsafe.Pointer(&b[hdr-8])))
		ty := int(*(*int32)(unsafe.Pointer(&b[hdr-4])))
		if lv == level && ty == typ && length >= hdr+4 {
			return int(*(*int32)(unsafe.Pointer(&b[hdr]))), true
		}
		next := (length + align - 1) &^ (align - 1)
		if next > len(b) {
			return 0, false
		}
		b = b[next:]
	}
	return 0, false
}
