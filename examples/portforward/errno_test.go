//go:build !plan9

package main

import "syscall"

// errConnReset is the reset errno TestPortForwardExampleSignalExit
// compares with (plan9 has none).
var errConnReset error = syscall.ECONNRESET
