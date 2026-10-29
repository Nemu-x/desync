//go:build windows

package desync

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	qpc     = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
	qpcFreq = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")
)

// preciseClock uses QueryPerformanceCounter: Go's monotonic clock on Windows
// advances in steps of about 0.5 ms, too coarse for these measurements.
func preciseClock() func() time.Duration {
	var freq int64
	qpcFreq.Call(uintptr(unsafe.Pointer(&freq)))
	var start int64
	qpc.Call(uintptr(unsafe.Pointer(&start)))
	return func() time.Duration {
		var now int64
		qpc.Call(uintptr(unsafe.Pointer(&now)))
		return time.Duration((now - start) * int64(time.Second) / freq)
	}
}
