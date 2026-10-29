//go:build !linux && !darwin && !windows

package desync

import (
	"errors"
	"syscall"
)

var platformAck = AckCapability{}

func newAckObserver(syscall.RawConn) (ackObserver, error) { return nil, ErrSplitWaitUnsupported }

func readSocketTTL(uintptr, bool) (int, error) { return 0, errTTLUnsupported }

var errTTLUnsupported = errors.New("desync: reading the socket TTL is not implemented on this platform")
