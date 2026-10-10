package main

import "errors"

// plan9 has no errnos: a reset never matches, and an Accept failure is a
// plain error (the front end backs off on any error but net.ErrClosed).
var (
	errConnReset    = errors.New("connection reset (no errno on plan9)")
	errTooManyFiles = errors.New("too many open files")
)
