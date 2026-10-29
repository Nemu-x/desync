//go:build darwin

package desync

import (
	"os"
	"syscall"
)

// macOS/iOS: SO_NWRITE returns so_snd.sb_cc, the bytes in the socket send
// buffer. TCP keeps data there until it is acknowledged (tcp_input sbdrop on
// ACK), so zero means everything written was acknowledged. This is the same
// value as tcpi_snd_sbbytes of the public TCP_CONNECTION_INFO ("bytes in send
// socket buffer, including in-flight data"); SO_NWRITE is read through
// libSystem's getsockopt, which the standard syscall package exposes only for
// integers. The public interfaces do not separate unsent from in-flight bytes
// (the struct with snd_una/txunacked is private), so SplitWaitSent is not
// offered.
var platformAck = AckCapability{Mechanism: "SO_NWRITE", Acked: true, Reliable: true}

type darwinAck struct{ raw syscall.RawConn }

func newAckObserver(raw syscall.RawConn) (ackObserver, error) {
	o := &darwinAck{raw: raw}
	if _, err := o.state(); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *darwinAck) state() (AckState, error) {
	s := unknownAckState()
	var opErr error
	err := o.raw.Control(func(fd uintptr) {
		v, e := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_NWRITE)
		if e != nil {
			opErr = os.NewSyscallError("getsockopt SO_NWRITE", e)
			return
		}
		s.Unacked = int64(v)
	})
	if err == nil {
		err = opErr
	}
	if err != nil {
		return unknownAckState(), err
	}
	return s, nil
}

func (o *darwinAck) reached(mode SplitWait, _ int64) (bool, error) {
	if mode != SplitWaitAcked {
		return false, ErrSplitWaitUnsupported
	}
	s, err := o.state()
	if err != nil {
		return false, err
	}
	return s.Unacked == 0, nil
}

func readSocketTTL(fd uintptr, ipv6 bool) (int, error) {
	if !ipv6 {
		return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
	}
	hops, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
	if err != nil || hops >= 0 {
		return hops, err
	}
	// -1: the socket uses the system default (RFC 3493), which BSD kernels
	// report as is instead of resolving it like Linux does
	def, err := syscall.SysctlUint32("net.inet6.ip6.hlim")
	if err != nil {
		return -1, os.NewSyscallError("sysctl net.inet6.ip6.hlim", err)
	}
	return int(def), nil
}
