//go:build !windows

package desync

import (
	"net"
	"syscall"
)

const supportsUDPFake = false

func configureUDPFake(syscall.RawConn) error { return ErrUDPFakeUnsupported }
func sendUDPFake(net.PacketConn, syscall.RawConn, UDPOptions, net.Addr) (bool, error) {
	return false, ErrUDPFakeUnsupported
}
