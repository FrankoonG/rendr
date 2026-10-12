//go:build !unix && !plan9

package l4

import "syscall"

// symCode has no symbols here (Windows, js, wasip1): a Windows errno is
// mapped by its number (wsaCode); js and wasip1 have no socket errnos to
// classify.
func symCode(syscall.Errno) (RejectCode, bool) { return 0, false }
