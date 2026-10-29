//go:build !windows

package main

// waitIfOwnConsole is needed only on Windows, where a double-clicked
// console program's window closes when it exits.
func waitIfOwnConsole() {}
