//go:build !plan9 && !windows

package main

import "syscall"

// errConnReset is the errno of a reset connection's read (plan9 has none;
// Windows reports WSAECONNRESET).
var errConnReset error = syscall.ECONNRESET
