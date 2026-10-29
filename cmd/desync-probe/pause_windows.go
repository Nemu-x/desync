package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// waitIfOwnConsole keeps the window open when the program was started by a
// double click: Windows then creates a console that only this process uses,
// and closes it as soon as the process exits.
func waitIfOwnConsole() {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return
	}
	var ids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	if n != 1 {
		return
	}
	fmt.Fprint(os.Stderr, "\nPress Enter to close this window.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
