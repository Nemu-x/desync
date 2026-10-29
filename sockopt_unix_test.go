//go:build linux || darwin

package desync

import "syscall"

func setOOBInline(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_OOBINLINE, 1)
}
