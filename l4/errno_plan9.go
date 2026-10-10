//go:build plan9

package l4

// errnoCode maps nothing on plan9, which has no syscall.Errno: its dial
// errors fall through to CodeDialFailed.
func errnoCode(error) (RejectCode, bool) { return 0, false }
