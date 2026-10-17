//go:build plan9

package l4

// pfErrno is a named errno of the l4 socket rows.
type pfErrno struct {
	name string
	err  error
}

// pfFatalErrnos: plan9 has no syscall.Errno.
func pfFatalErrnos() []pfErrno { return nil }
