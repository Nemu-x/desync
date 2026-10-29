//go:build linux || darwin

package desync

import (
	"os"
	"syscall"
)

const supportsOOB = true

// sendOOB writes p with MSG_OOB, which marks its last byte as urgent data.
// It waits for socket space through the runtime poller, so the underlying
// connection's write deadline and Close bound it.
func sendOOB(raw syscall.RawConn, p []byte) (int, error) {
	var n int
	var opErr error
	err := raw.Write(func(fd uintptr) bool {
		n, opErr = syscall.SendmsgN(int(fd), p, nil, nil, syscall.MSG_OOB)
		return opErr != syscall.EAGAIN && opErr != syscall.EINTR
	})
	if n < 0 {
		n = 0
	}
	if err == nil && opErr != nil {
		err = os.NewSyscallError("sendmsg MSG_OOB", opErr)
	}
	return n, err
}
