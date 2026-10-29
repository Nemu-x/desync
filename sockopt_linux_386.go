//go:build linux && 386

package desync

import (
	"syscall"
	"unsafe"
)

const socketcallGetsockopt = 15 // linux/net.h SYS_GETSOCKOPT

// getsockoptBytes reads a socket option into buf and returns its length.
// linux/386 reaches getsockopt through socketcall, whose arguments are passed
// in memory, out of reach of the rule that keeps syscall arguments in place.
// The value and its length therefore live in one buffer of non-constant
// size, which the compiler allocates on the (non-moving) heap.
func getsockoptBytes(fd uintptr, level, option int, buf []byte) (int, error) {
	mem := make([]byte, 4+len(buf))
	size := (*uint32)(unsafe.Pointer(&mem[0]))
	*size = uint32(len(buf))
	args := [5]uintptr{fd, uintptr(level), uintptr(option), uintptr(unsafe.Pointer(&mem[4])), uintptr(unsafe.Pointer(size))}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, socketcallGetsockopt, uintptr(unsafe.Pointer(&args)), 0)
	if errno != 0 {
		return 0, errno
	}
	n := int(*size)
	if n > len(buf) {
		n = len(buf)
	}
	copy(buf, mem[4:4+n])
	return n, nil
}
