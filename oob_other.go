//go:build !linux && !darwin && !windows

package desync

import "syscall"

const supportsOOB = false

func sendOOB(syscall.RawConn, []byte) (int, error) { return 0, ErrOOBUnsupported }
