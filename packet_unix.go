//go:build linux || darwin

package desync

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
)

const supportsUDPFake = true

func configureUDPFake(raw syscall.RawConn) error {
	var opErr error
	err := raw.Control(func(fd uintptr) {
		kind, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil || kind != syscall.SOCK_DGRAM {
			opErr = ErrUDPFakeRequiresSocket
			return
		}
		opErr = suppressUDPErrors(fd)
	})
	return errors.Join(err, opErr)
}

func sendUDPFake(pc net.PacketConn, raw syscall.RawConn, opts UDPOptions, addr net.Addr) (unsafeTTL bool, err error) {
	var dst net.IP
	if udp, ok := addr.(*net.UDPAddr); ok {
		dst = udp.IP
	}
	var opErr error
	controlErr := raw.Control(func(fd uintptr) {
		// The option follows the destination family (see hopFor), so an
		// IPv4 peer on a dual-stack socket gets the IPv4 TTL changed.
		saved, getErr := hopFor(fd, dst)
		if getErr != nil {
			opErr = fmt.Errorf("desync: read UDP hop limit: %w", getErr)
			return
		}
		if setErr := setHop(fd, saved, opts.TTL); setErr != nil {
			opErr = fmt.Errorf("desync: set UDP fake hop limit: %w", setErr)
			unsafeTTL = true
			return
		}
		for i := 0; i < opts.Repeats; i++ {
			n, sendErr := pc.WriteTo(opts.Payload, addr)
			if sendErr == nil && n != len(opts.Payload) {
				sendErr = io.ErrShortWrite
			}
			if sendErr != nil {
				opErr = sendErr
				break
			}
			opts.Counters.fakes.Add(1)
		}
		if restoreErr := setHop(fd, saved, saved.restore); restoreErr != nil {
			unsafeTTL = true
			opErr = errors.Join(opErr, fmt.Errorf("desync: restore UDP hop limit: %w", restoreErr))
		}
	})
	return unsafeTTL, errors.Join(controlErr, opErr)
}
