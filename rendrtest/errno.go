//go:build !plan9

package rendrtest

import (
	"runtime"
	"syscall"
)

// errWSAEMSGSIZE is Windows' WSAEMSGSIZE, which rendr classifies by number
// on every OS (M2 design Revision 1, R1-28).
const errWSAEMSGSIZE = syscall.Errno(10040)

// errConnReset is what a TargetConn's reset matches with errors.Is (M4
// design §A2.4: ErrReset matches syscall.ECONNRESET).
var errConnReset error = syscall.ECONNRESET

// errMsgSize is ErrMsgSize: the number the net package returns on Windows
// (WSAEMSGSIZE), this OS's EMSGSIZE elsewhere.
var errMsgSize = dialErrno(10040, syscall.EMSGSIZE)

// The errnos of ScriptedDial's failures: the numbers the net package
// returns on Windows (WSAECONNREFUSED, WSAENETUNREACH, WSAEHOSTUNREACH),
// this OS's symbols elsewhere.
var (
	errConnRefused = dialErrno(10061, syscall.ECONNREFUSED)
	errNetUnreach  = dialErrno(10051, syscall.ENETUNREACH)
	errHostUnreach = dialErrno(10065, syscall.EHOSTUNREACH)
)

func dialErrno(windows, sym syscall.Errno) error {
	if runtime.GOOS == "windows" {
		return windows
	}
	return sym
}
