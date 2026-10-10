//go:build !plan9

package main

import "syscall"

// The errnos the tests compare with or inject (plan9 has none of them).
var (
	errConnReset    error = syscall.ECONNRESET
	errTooManyFiles error = syscall.EMFILE
)
