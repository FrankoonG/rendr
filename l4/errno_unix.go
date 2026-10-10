//go:build unix

package l4

import "syscall"

// symCode maps this OS's errno symbols (ECONNREFUSED, ENETUNREACH,
// EHOSTUNREACH, ETIMEDOUT, EACCES, EPERM, EMFILE, ENFILE, ENOBUFS,
// EADDRNOTAVAIL, …) to their codes.
func symCode(e syscall.Errno) (RejectCode, bool) {
	return 0, false // M4 WP2: the symbol table
}
