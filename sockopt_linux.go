//go:build linux && !386

package desync

import (
	"syscall"
	"unsafe"
)

// getsockoptBytes reads a socket option into buf and returns its length.
func getsockoptBytes(fd uintptr, level, option int, buf []byte) (int, error) {
	size := uint32(len(buf))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(option),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(size), nil
}
