//go:build plan9

package l4

// errnoCode maps nothing on plan9, which has no syscall.Errno: its dial
// errors fall through to CodeDialFailed.
func errnoCode(error) (RejectCode, bool) { return 0, false }

// errnoClass finds no syscall.Errno on plan9: every error of an l4 socket
// but io.ErrShortBuffer is fatal there (errClass; m4:R3-34).
func errnoClass(error) (localClass, bool) { return 0, false }
