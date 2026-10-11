package udpsocket

import "errors"

// plan9's syscall package has no errnos: a Conn there is always plain (no
// batch call, no probe), so these values are never returned to the code
// that compares them; they keep conn.go portable (the l4 build of M4's
// C-1 reaches this package through the root).
var (
	errAgain = errors.New("udpsocket: EAGAIN")
	errNoSys = errors.New("udpsocket: ENOSYS")
	errBadF  = errors.New("udpsocket: EBADF")
)

// sysErrno reports no errno on plan9.
func sysErrno(err error) (error, bool) { return nil, false }
