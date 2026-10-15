//go:build !plan9

package udpsocket

import "syscall"

// The errnos the batch calls and the fd −1 probe report (M5-D15, R1-3);
// plan9 has no such errno (errno_plan9.go).
var (
	errAgain error = syscall.EAGAIN
	errNoSys error = syscall.ENOSYS
	errBadF  error = syscall.EBADF
)

// sysErrno returns err as an errno, if it is one.
func sysErrno(err error) (error, bool) {
	errno, ok := err.(syscall.Errno)
	return errno, ok
}
