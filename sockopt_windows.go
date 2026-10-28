//go:build windows

package desync

import (
	"syscall"
	"unsafe"
)

// getsockoptInt reads an integer socket option. syscall.GetsockoptInt is a
// stub returning EWINDOWS before Go 1.21; syscall.Getsockopt calls ws2_32
// getsockopt on every supported Go version.
func getsockoptInt(socket syscall.Handle, level, option int) (int, error) {
	var value int32
	size := int32(unsafe.Sizeof(value))
	if err := syscall.Getsockopt(socket, int32(level), int32(option), (*byte)(unsafe.Pointer(&value)), &size); err != nil {
		return -1, err
	}
	return int(value), nil
}
