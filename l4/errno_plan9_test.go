//go:build plan9

package l4

// errnoRows: plan9 has no syscall.Errno; its dial errors are CodeDialFailed.
func errnoRows() []classifyRow { return nil }
