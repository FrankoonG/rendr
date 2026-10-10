//go:build unix

package l4

import (
	"os"
	"syscall"
)

// symRows are this OS's errno symbols (M4 design §A8.1), bare and wrapped
// as the net package returns them.
func symRows() []classifyRow {
	rows := []classifyRow{
		{"ECONNREFUSED", syscall.ECONNREFUSED, CodeRefused},
		{"ENETUNREACH", syscall.ENETUNREACH, CodeNetUnreachable},
		{"ENETDOWN", syscall.ENETDOWN, CodeNetUnreachable},
		{"EHOSTUNREACH", syscall.EHOSTUNREACH, CodeHostUnreachable},
		{"EHOSTDOWN", syscall.EHOSTDOWN, CodeHostUnreachable},
		{"ETIMEDOUT", syscall.ETIMEDOUT, CodeTimeout},
		{"EADDRNOTAVAIL", syscall.EADDRNOTAVAIL, CodeCapacity},
		{"EMFILE", syscall.EMFILE, CodeCapacity},
		{"ENFILE", syscall.ENFILE, CodeCapacity},
		{"ENOBUFS", syscall.ENOBUFS, CodeCapacity},
		{"ENOMEM", syscall.ENOMEM, CodeCapacity},
		{"EACCES", syscall.EACCES, CodeNotAllowed},
		{"EPERM", syscall.EPERM, CodeNotAllowed},
		{"ECONNRESET (not in the table)", syscall.ECONNRESET, CodeDialFailed},
		{"EINVAL (not in the table)", syscall.EINVAL, CodeDialFailed},
	}
	for _, r := range rows[:len(rows):len(rows)] {
		rows = append(rows, classifyRow{r.name + " in OpError", opErr(os.NewSyscallError("connect", r.err)), r.want})
	}
	return rows
}
