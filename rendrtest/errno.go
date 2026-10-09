//go:build !plan9

package rendrtest

import "syscall"

// errWSAEMSGSIZE is Windows' WSAEMSGSIZE, which rendr classifies by number
// on every OS (M2 design Revision 1, R1-28).
const errWSAEMSGSIZE = syscall.Errno(10040)
