//go:build !plan9

package l4

import (
	"os"
	"syscall"
)

// wsaErrno is the syscall.Errno numbered n (a Windows socket error number,
// compared by number on every OS but plan9); on plan9, which has no
// syscall.Errno, it is nil and the callers leave the row out.
func wsaErrno(n uintptr) error { return syscall.Errno(n) }

// errnoRows are TestClassify's errno rows: the Windows numbers, compared by
// number on every OS but plan9 (bare, and wrapped as the net package
// returns them), then this OS's symbols (symRows).
func errnoRows() []classifyRow {
	rows := []classifyRow{
		{"WSAECONNREFUSED", syscall.Errno(10061), CodeRefused},
		{"WSAENETUNREACH", syscall.Errno(10051), CodeNetUnreachable},
		{"WSAENETDOWN", syscall.Errno(10050), CodeNetUnreachable},
		{"WSAEHOSTUNREACH", syscall.Errno(10065), CodeHostUnreachable},
		{"WSAEHOSTDOWN", syscall.Errno(10064), CodeHostUnreachable},
		{"WSAETIMEDOUT", syscall.Errno(10060), CodeTimeout},
		{"WSAEADDRNOTAVAIL", syscall.Errno(10049), CodeCapacity},
		{"WSAEMFILE", syscall.Errno(10024), CodeCapacity},
		{"WSAENOBUFS", syscall.Errno(10055), CodeCapacity},
		{"WSAEACCES", syscall.Errno(10013), CodeNotAllowed},
		{"WSAECONNRESET (not in the table)", syscall.Errno(10054), CodeDialFailed},
		{"WSAEADDRINUSE (not in the table)", syscall.Errno(10048), CodeDialFailed},
	}
	for _, r := range rows[:len(rows):len(rows)] {
		rows = append(rows, classifyRow{r.name + " in OpError", opErr(os.NewSyscallError("connectex", r.err)), r.want})
	}
	return append(rows, symRows()...)
}
