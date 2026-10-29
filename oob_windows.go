//go:build windows

package desync

import (
	"os"
	"syscall"
)

const supportsOOB = true

const msgOOB = 0x1 // winsock2.h MSG_OOB

// sendOOB writes p with MSG_OOB, which marks its last byte as urgent data. The
// send is synchronous (no OVERLAPPED), so Go's completion port never sees it.
func sendOOB(raw syscall.RawConn, p []byte) (int, error) {
	var sent uint32
	var opErr error
	err := raw.Control(func(fd uintptr) {
		buf := syscall.WSABuf{Len: uint32(len(p)), Buf: &p[0]}
		opErr = syscall.WSASend(syscall.Handle(fd), &buf, 1, &sent, msgOOB, nil, nil)
	})
	if err == nil && opErr != nil {
		err = os.NewSyscallError("WSASend MSG_OOB", opErr)
	}
	return int(sent), err
}
