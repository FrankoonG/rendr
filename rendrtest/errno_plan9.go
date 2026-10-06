//go:build plan9

package rendrtest

import "syscall"

// errWSAEMSGSIZE stands in for Windows' WSAEMSGSIZE on Plan 9, which has no
// numeric errnos: the package builds there, and a Windows-style truncation
// reads as an error of that name.
const errWSAEMSGSIZE = syscall.ErrorString("WSAEMSGSIZE")
