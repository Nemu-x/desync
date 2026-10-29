//go:build linux

package desync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux (and Android) report a TCP socket's queues through ioctl, see
// tcp(7): SIOCOUTQ is write_seq - snd_una (written, not yet acknowledged) and
// SIOCOUTQNSD is write_seq - snd_nxt (written, not yet transmitted). Both are
// read from the socket's own state on every call, on every kernel since
// 2.6.38, with arch-independent semantics.
//
// Android's SELinux policy lets untrusted apps issue SIOCOUTQ (it is
// TIOCOUTQ, in unpriv_tty_ioctls) but not SIOCOUTQNSD (priv_sock_ioctls), so
// there the second ioctl fails with EACCES. When it is denied (EACCES or
// EPERM), the unsent count is read from getsockopt(TCP_INFO)
// tcpi_notsent_bytes instead, which the kernel fills from the same
// write_seq - snd_nxt (Linux 4.6 and later). A kernel whose TCP_INFO ends
// before that field leaves the socket without SplitWaitSent; the decision is
// made per socket, when the observer is created.
//
// platformAck is what this build implements; PlatformCapabilities lowers it
// on Android, where unsent bytes are observable only per socket.
var platformAck = AckCapability{Mechanism: ackMechanismOUTQNSD, Sent: true, Acked: true, Reliable: true}

const (
	siocOUTQNSD = 0x894B // linux/sockios.h

	ackMechanismOUTQNSD = "SIOCOUTQ/SIOCOUTQNSD"
	ackMechanismTCPInfo = "SIOCOUTQ/TCP_INFO"
	ackMechanismAcked   = "SIOCOUTQ"
)

// sockQuery is the kernel interface linuxAck reads. Tests replace
// linuxSockQuery to reproduce Android's denial of SIOCOUTQNSD and old kernels.
type sockQuery struct {
	ioctl      func(fd, req uintptr) (int64, error)
	getsockopt func(fd uintptr, level, option int, buf []byte) (int, error)
}

var linuxSockQuery = sockQuery{ioctl: socketQueue, getsockopt: getsockoptBytes}

// sentSource is how one socket reports its unsent bytes.
type sentSource uint8

const (
	sentOUTQNSD sentSource = iota // ioctl SIOCOUTQNSD
	sentTCPInfo                   // getsockopt TCP_INFO tcpi_notsent_bytes
	sentNone                      // not observable; why says why
)

type linuxAck struct {
	raw  syscall.RawConn
	q    sockQuery
	sent sentSource
	why  error
}

func newAckObserver(raw syscall.RawConn) (ackObserver, error) {
	o := &linuxAck{raw: raw, q: linuxSockQuery}
	var opErr error
	if err := raw.Control(func(fd uintptr) { opErr = o.detect(fd) }); err != nil {
		return nil, err
	}
	if opErr != nil {
		return nil, opErr
	}
	return o, nil
}

// detect checks that SIOCOUTQ works and picks the source of unsent bytes:
// SIOCOUTQNSD, else (when it is denied) TCP_INFO, else none.
func (o *linuxAck) detect(fd uintptr) error {
	if _, err := o.q.ioctl(fd, syscall.TIOCOUTQ); err != nil {
		return os.NewSyscallError("ioctl SIOCOUTQ", err)
	}
	_, err := o.q.ioctl(fd, siocOUTQNSD)
	if err == nil {
		o.sent = sentOUTQNSD
		return nil
	}
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		return os.NewSyscallError("ioctl SIOCOUTQNSD", err)
	}
	denied := os.NewSyscallError("ioctl SIOCOUTQNSD", err)
	_, ok, infoErr := o.notsent(fd)
	switch {
	case infoErr != nil:
		o.sent, o.why = sentNone, fmt.Errorf("%w; %w", denied, infoErr)
	case !ok:
		o.sent, o.why = sentNone, fmt.Errorf("%w; %w", denied, errNoNotsentBytes)
	default:
		o.sent = sentTCPInfo
	}
	return nil
}

var errNoNotsentBytes = errors.New("TCP_INFO has no tcpi_notsent_bytes (Linux before 4.6)")

// notsent reads tcpi_notsent_bytes; ok is false when the kernel's tcp_info
// ends before it.
func (o *linuxAck) notsent(fd uintptr) (v int64, ok bool, err error) {
	var buf [tcpInfoNotsentEnd]byte
	n, err := o.q.getsockopt(fd, syscall.IPPROTO_TCP, syscall.TCP_INFO, buf[:])
	if err != nil {
		return 0, false, os.NewSyscallError("getsockopt TCP_INFO", err)
	}
	if n < 0 || n > len(buf) {
		n = len(buf)
	}
	v, ok = parseTCPInfoNotsent(buf[:n], nativeEndian)
	return v, ok, nil
}

func socketQueue(fd uintptr, req uintptr) (int64, error) {
	var v int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(&v))); errno != 0 {
		return 0, errno
	}
	return int64(v), nil
}

// read samples the requested counts; the others stay -1.
func (o *linuxAck) read(unacked, unsent bool) (AckState, error) {
	s := unknownAckState()
	if unsent && o.sent == sentNone {
		return s, fmt.Errorf("%w: %w", ErrSplitWaitUnsupported, o.why)
	}
	var opErr error
	err := o.raw.Control(func(fd uintptr) {
		if unacked {
			if s.Unacked, opErr = o.q.ioctl(fd, syscall.TIOCOUTQ); opErr != nil {
				opErr = os.NewSyscallError("ioctl SIOCOUTQ", opErr)
				return
			}
		}
		if !unsent {
			return
		}
		if o.sent == sentOUTQNSD {
			if s.Unsent, opErr = o.q.ioctl(fd, siocOUTQNSD); opErr != nil {
				opErr = os.NewSyscallError("ioctl SIOCOUTQNSD", opErr)
			}
			return
		}
		v, ok, e := o.notsent(fd)
		switch {
		case e != nil:
			opErr = e
		case !ok:
			opErr = errNoNotsentBytes
		default:
			s.Unsent = v
		}
	})
	if err == nil {
		err = opErr
	}
	if err != nil {
		return unknownAckState(), err
	}
	return s, nil
}

func (o *linuxAck) state() (AckState, error) {
	s, err := o.read(true, o.sent != sentNone)
	if err != nil {
		return s, err
	}
	if s.Unsent >= 0 {
		s.InFlight = s.Unacked - s.Unsent
	}
	return s, nil
}

func (o *linuxAck) reached(mode SplitWait, _ int64) (bool, error) {
	if mode == SplitWaitSent {
		s, err := o.read(false, true)
		return err == nil && s.Unsent == 0, err
	}
	s, err := o.read(true, false)
	return err == nil && s.Unacked == 0, err
}

func (o *linuxAck) capability() (AckCapability, error) {
	switch o.sent {
	case sentOUTQNSD:
		return platformAck, nil
	case sentTCPInfo:
		return AckCapability{Mechanism: ackMechanismTCPInfo, Sent: true, Acked: true, Reliable: true}, nil
	}
	return AckCapability{Mechanism: ackMechanismAcked, Acked: true, Reliable: true}, o.why
}

// nativeEndian is the byte order of the kernel's structures.
var nativeEndian = func() binary.ByteOrder {
	x := uint16(1)
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

func readSocketTTL(fd uintptr, ipv6 bool) (int, error) {
	if ipv6 {
		return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
	}
	return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
}
