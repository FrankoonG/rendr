//go:build unix

package l4

import "syscall"

// symCode maps this OS's errno symbols to their codes (M4 design §A8.1).
func symCode(e syscall.Errno) (RejectCode, bool) {
	switch e {
	case syscall.ECONNREFUSED:
		return CodeRefused, true
	case syscall.ENETUNREACH, syscall.ENETDOWN:
		return CodeNetUnreachable, true
	case syscall.EHOSTUNREACH, syscall.EHOSTDOWN:
		return CodeHostUnreachable, true
	case syscall.ETIMEDOUT:
		return CodeTimeout, true
	case syscall.EADDRNOTAVAIL, syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM:
		return CodeCapacity, true
	case syscall.EACCES, syscall.EPERM:
		return CodeNotAllowed, true
	}
	return 0, false
}
