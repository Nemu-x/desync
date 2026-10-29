package main

import "syscall"

// Winsock and Win32 error codes; syscall.ECONNRESET and friends are invented
// values on Windows and never match a real socket error.
var (
	resetErrnos = []syscall.Errno{
		10053, // WSAECONNABORTED
		10054, // WSAECONNRESET
		64,    // ERROR_NETNAME_DELETED (reset seen through overlapped I/O)
		1236,  // ERROR_CONNECTION_ABORTED
	}
	refusedErrnos     = []syscall.Errno{10061, 1225} // WSAECONNREFUSED, ERROR_CONNECTION_REFUSED
	unreachableErrnos = []syscall.Errno{
		10050, // WSAENETDOWN
		10051, // WSAENETUNREACH
		10065, // WSAEHOSTUNREACH
		1231,  // ERROR_NETWORK_UNREACHABLE
		1232,  // ERROR_HOST_UNREACHABLE
	}
	timeoutErrnos = []syscall.Errno{10060, 121} // WSAETIMEDOUT, ERROR_SEM_TIMEOUT
)
