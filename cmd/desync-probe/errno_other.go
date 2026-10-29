//go:build !windows

package main

import "syscall"

var (
	resetErrnos       = []syscall.Errno{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE}
	refusedErrnos     = []syscall.Errno{syscall.ECONNREFUSED}
	unreachableErrnos = []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN}
	timeoutErrnos     = []syscall.Errno{syscall.ETIMEDOUT}
)
