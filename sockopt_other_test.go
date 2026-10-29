//go:build !linux && !darwin && !windows

package desync

func setOOBInline(uintptr) error { return ErrOOBUnsupported }
