//go:build !plan9

package l4

import (
	"errors"
	"syscall"
)

// errnoCode maps the syscall.Errno inside err, if any (M4 design §A8.1,
// R1-12): this OS's symbols first (symCode: the Unix table; none on
// Windows, js and wasip1), then the Windows numbers (wsaCode), which hold
// on every OS but plan9 because a Windows errno is compared by its number.
func errnoCode(err error) (RejectCode, bool) {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return 0, false
	}
	if c, ok := symCode(e); ok {
		return c, true
	}
	return wsaCode(e)
}

// wsaCode maps a Windows socket error number (WSAECONNREFUSED,
// WSAENETUNREACH, WSAEHOSTUNREACH, WSAETIMEDOUT, WSAEACCES, WSAEMFILE,
// WSAENOBUFS, WSAEADDRNOTAVAIL, …) to its code.
func wsaCode(e syscall.Errno) (RejectCode, bool) {
	return 0, false // M4 WP2: the Windows-number table
}
