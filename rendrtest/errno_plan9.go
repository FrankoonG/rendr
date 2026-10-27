//go:build plan9

package rendrtest

import "syscall"

// errWSAEMSGSIZE stands in for Windows' WSAEMSGSIZE on Plan 9, which has no
// numeric errnos: the package builds there, and a Windows-style truncation
// reads as an error of that name.
const errWSAEMSGSIZE = syscall.ErrorString("WSAEMSGSIZE")

// errConnReset stands in for ECONNRESET on Plan 9, which has no numeric
// errnos (ErrReset matches it with errors.Is).
var errConnReset error = syscall.ErrorString("connection reset by peer")

// errMsgSize stands in for EMSGSIZE (ErrMsgSize) on Plan 9, which has no
// numeric errnos.
var errMsgSize error = errWSAEMSGSIZE

// The errors of ScriptedDial's failures on Plan 9, which has no numeric
// errnos.
var (
	errConnRefused error = syscall.ErrorString("connection refused")
	errNetUnreach  error = syscall.ErrorString("network is unreachable")
	errHostUnreach error = syscall.ErrorString("no route to host")
)
