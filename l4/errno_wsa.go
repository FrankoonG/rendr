//go:build !plan9

package l4

import (
	"errors"
	"syscall"
)

// errnoCode maps the syscall.Errno inside err, if any (M4 design §A8.1,
// R1-12): this OS's symbols first (symCode: the Unix table; none on
// Windows, js and wasip1), then the Windows numbers (wsaCode), which hold
// on every OS but plan9 because a Windows errno is compared by its number.
func errnoCode(err error) (RejectCode, bool) {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return 0, false
	}
	if c, ok := symCode(e); ok {
		return c, true
	}
	return wsaCode(e)
}

// The Windows socket error numbers of the table (winsock2.h). They are
// compared by number because on Windows syscall.ECONNREFUSED and its kin
// are not the values the net package returns.
const (
	wsaEACCES        = syscall.Errno(10013)
	wsaEMFILE        = syscall.Errno(10024)
	wsaEADDRNOTAVAIL = syscall.Errno(10049)
	wsaENETDOWN      = syscall.Errno(10050)
	wsaENETUNREACH   = syscall.Errno(10051)
	wsaENOBUFS       = syscall.Errno(10055)
	wsaETIMEDOUT     = syscall.Errno(10060)
	wsaECONNREFUSED  = syscall.Errno(10061)
	wsaEHOSTDOWN     = syscall.Errno(10064)
	wsaEHOSTUNREACH  = syscall.Errno(10065)
)

// wsaCode maps a Windows socket error number to its code.
func wsaCode(e syscall.Errno) (RejectCode, bool) {
	switch e {
	case wsaECONNREFUSED:
		return CodeRefused, true
	case wsaENETUNREACH, wsaENETDOWN:
		return CodeNetUnreachable, true
	case wsaEHOSTUNREACH, wsaEHOSTDOWN:
		return CodeHostUnreachable, true
	case wsaETIMEDOUT:
		return CodeTimeout, true
	case wsaEADDRNOTAVAIL, wsaEMFILE, wsaENOBUFS:
		return CodeCapacity, true
	case wsaEACCES:
		return CodeNotAllowed, true
	}
	return 0, false
}

// errnoClass classifies the syscall.Errno inside err, if any, for the l4
// sockets (M6-D15, R1-2): this OS's symbols of the size class and the
// fatal set first (symLocal), then the Windows numbers (wsaLocal), which
// hold on every OS but plan9; every other errno is noise. ok is false when
// err holds no syscall.Errno.
func errnoClass(err error) (c localClass, ok bool) {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return 0, false
	}
	if c, ok := symLocal(e); ok {
		return c, true
	}
	if c, ok := wsaLocal(e); ok {
		return c, true
	}
	return classNoise, true
}

// The Windows socket error numbers of the l4 sockets' size class and fatal
// set (winsock2.h; M6-D15, R1-2).
const (
	wsaEBADF        = syscall.Errno(10009)
	wsaEFAULT       = syscall.Errno(10014)
	wsaEINVAL       = syscall.Errno(10022)
	wsaENOTSOCK     = syscall.Errno(10038)
	wsaEDESTADDRREQ = syscall.Errno(10039)
	wsaEMSGSIZE     = syscall.Errno(10040)
	wsaEOPNOTSUPP   = syscall.Errno(10045)
	wsaEISCONN      = syscall.Errno(10056)
	wsaENOTCONN     = syscall.Errno(10057)
	wsaESHUTDOWN    = syscall.Errno(10058)
)

// wsaLocal maps a Windows socket error number of the size class
// (WSAEMSGSIZE: a datagram above the read buffer, the buffer filled) or of
// the fatal set (a closed, invalid, wrong-kind or unconnected socket, and
// EISCONN's twin). WSAECONNRESET, WSAENETRESET, WSAENOBUFS,
// WSAEHOSTUNREACH, WSAENETUNREACH, WSAENETDOWN, WSAEACCES and the rest are
// noise.
func wsaLocal(e syscall.Errno) (localClass, bool) {
	switch e {
	case wsaEMSGSIZE:
		return classSize, true
	case wsaEBADF, wsaEFAULT, wsaEINVAL, wsaENOTSOCK, wsaEDESTADDRREQ, wsaEOPNOTSUPP, wsaEISCONN, wsaENOTCONN, wsaESHUTDOWN:
		return classFatal, true
	}
	return 0, false
}
