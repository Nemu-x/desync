//go:build linux && !386

package desync

import (
	"net"
	"syscall"
	"testing"
	"unsafe"
)

// tcpRetransmits returns tcpi_total_retrans of the connection.
func tcpRetransmits(t testing.TB, c *net.TCPConn) (uint32, bool) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var info syscall.TCPInfo
	size := uint32(syscall.SizeofTCPInfo)
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)), 0)
	}); err != nil {
		t.Fatal(err)
	}
	if errno != 0 {
		t.Fatal(errno)
	}
	return info.Total_retrans, true
}
