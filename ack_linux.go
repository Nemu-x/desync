//go:build linux

package desync

import (
	"os"
	"syscall"
	"unsafe"
)

// Linux (and Android) report a TCP socket's queues through ioctl, see
// tcp(7): SIOCOUTQ is write_seq - snd_una (written, not yet acknowledged) and
// SIOCOUTQNSD is write_seq - snd_nxt (written, not yet transmitted). Both are
// read from the socket's own state on every call, on every kernel since
// 2.6.38, with arch-independent semantics.
var platformAck = AckCapability{Mechanism: "SIOCOUTQ/SIOCOUTQNSD", Sent: true, Acked: true, Reliable: true}

const siocOUTQNSD = 0x894B // linux/sockios.h

type linuxAck struct{ raw syscall.RawConn }

func newAckObserver(raw syscall.RawConn) (ackObserver, error) {
	o := &linuxAck{raw: raw}
	if _, err := o.state(); err != nil {
		return nil, err
	}
	return o, nil
}

func socketQueue(fd uintptr, req uintptr) (int64, error) {
	var v int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(&v))); errno != 0 {
		return 0, errno
	}
	return int64(v), nil
}

func (o *linuxAck) state() (AckState, error) {
	s := unknownAckState()
	var opErr error
	err := o.raw.Control(func(fd uintptr) {
		if s.Unacked, opErr = socketQueue(fd, syscall.TIOCOUTQ); opErr != nil {
			opErr = os.NewSyscallError("ioctl SIOCOUTQ", opErr)
			return
		}
		if s.Unsent, opErr = socketQueue(fd, siocOUTQNSD); opErr != nil {
			opErr = os.NewSyscallError("ioctl SIOCOUTQNSD", opErr)
		}
	})
	if err == nil {
		err = opErr
	}
	if err != nil {
		return unknownAckState(), err
	}
	s.InFlight = s.Unacked - s.Unsent
	return s, nil
}

func (o *linuxAck) reached(mode SplitWait, _ int64) (bool, error) {
	s, err := o.state()
	if err != nil {
		return false, err
	}
	if mode == SplitWaitSent {
		return s.Unsent == 0, nil
	}
	return s.Unacked == 0, nil
}

func readSocketTTL(fd uintptr, ipv6 bool) (int, error) {
	if ipv6 {
		return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
	}
	return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
}
