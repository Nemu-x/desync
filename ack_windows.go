//go:build windows

package desync

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"
)

// Windows 10 1703+ / Server 2016+: SIO_TCP_INFO returns TCP_INFO_v0 for the
// socket without elevation. It has BytesInFlight ("sent bytes that are
// unacknowledged"), BytesOut ("total number of bytes sent") and BytesRetrans,
// but no count of written-but-unsent bytes. The wrapper therefore samples a
// baseline before its first piece and waits until the distinct transmitted
// bytes (BytesOut - BytesRetrans) grew by what it wrote and, for
// SplitWaitAcked, BytesInFlight is zero.
//
// This is not reliable: BytesOut is a counter, not queue state. On loopback
// it matched small writes exactly but exceeded the written bytes for writes
// of about 100 KB and more, and under a zero receive window (window probes),
// without a matching BytesRetrans. An inflated counter can end the wait
// before every byte was sent. Bytes written to the socket before wrapping
// that were still unsent at the baseline would also be counted as ours.
var platformAck = AckCapability{Mechanism: "SIO_TCP_INFO", Sent: true, Acked: true, Reliable: false}

const (
	sioTCPInfo      = 0xD8000027 // _WSAIORW(IOC_VENDOR, 39)
	tcpInfoV0Size   = 88
	tcpInfoInFlight = 28
	tcpInfoOut      = 48
	tcpInfoRetrans  = 68
)

type tcpInfoV0 struct {
	inFlight uint32
	out      uint64
	retrans  uint32
}

func (t tcpInfoV0) distinctOut() int64 {
	if uint64(t.retrans) > t.out {
		return 0
	}
	return int64(t.out - uint64(t.retrans))
}

func parseTCPInfoV0(b []byte) tcpInfoV0 {
	return tcpInfoV0{
		inFlight: binary.LittleEndian.Uint32(b[tcpInfoInFlight:]),
		out:      binary.LittleEndian.Uint64(b[tcpInfoOut:]),
		retrans:  binary.LittleEndian.Uint32(b[tcpInfoRetrans:]),
	}
}

func queryTCPInfo(socket syscall.Handle) (tcpInfoV0, error) {
	var version uint32
	var buf [tcpInfoV0Size]byte
	var returned uint32
	err := syscall.WSAIoctl(socket, sioTCPInfo, (*byte)(unsafe.Pointer(&version)), 4,
		&buf[0], uint32(len(buf)), &returned, nil, 0)
	if err != nil {
		return tcpInfoV0{}, os.NewSyscallError("WSAIoctl SIO_TCP_INFO", err)
	}
	if returned < tcpInfoRetrans+4 {
		return tcpInfoV0{}, os.NewSyscallError("WSAIoctl SIO_TCP_INFO", syscall.EINVAL)
	}
	return parseTCPInfoV0(buf[:]), nil
}

type windowsAck struct {
	raw  syscall.RawConn
	base int64
}

func newAckObserver(raw syscall.RawConn) (ackObserver, error) {
	o := &windowsAck{raw: raw}
	info, err := o.query()
	if err != nil {
		return nil, err
	}
	o.base = info.distinctOut()
	return o, nil
}

func (o *windowsAck) query() (tcpInfoV0, error) {
	var info tcpInfoV0
	var opErr error
	err := o.raw.Control(func(fd uintptr) { info, opErr = queryTCPInfo(syscall.Handle(fd)) })
	if err == nil {
		err = opErr
	}
	return info, err
}

func (o *windowsAck) state() (AckState, error) {
	info, err := o.query()
	if err != nil {
		return unknownAckState(), err
	}
	s := unknownAckState()
	s.InFlight = int64(info.inFlight)
	s.Sent = info.distinctOut()
	return s, nil
}

func (o *windowsAck) reached(mode SplitWait, written int64) (bool, error) {
	info, err := o.query()
	if err != nil {
		return false, err
	}
	if info.distinctOut()-o.base < written {
		return false, nil
	}
	return mode == SplitWaitSent || info.inFlight == 0, nil
}

func readSocketTTL(fd uintptr, ipv6 bool) (int, error) {
	if ipv6 {
		return getsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
	}
	return getsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
}

func (o *windowsAck) capability() (AckCapability, error) { return platformAck, nil }
