package main

import "syscall"

// errConnReset is the errno of a reset connection's read.
var errConnReset error = syscall.WSAECONNRESET
