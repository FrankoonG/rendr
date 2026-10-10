package l4

import (
	"errors"
	"fmt"

	"github.com/FrankoonG/rendr/v2"
)

// RejectCode is the code of an l4 Server's refusal (rendr.RejectError.Code),
// in the l4 range 0x4C34_00nn ("L4"); application codes are at least 256.
type RejectCode uint32

// Reject codes.
const (
	CodeBadRequest      RejectCode = 0x4C340001 // not L4 metadata, truncated, or trailing garbage
	CodeBadVersion      RejectCode = 0x4C340002 // an unknown metadata version
	CodeBadCommand      RejectCode = 0x4C340003 // an unknown command
	CodeBadAddress      RejectCode = 0x4C340004 // a malformed or non-canonical destination
	CodeNotAllowed      RejectCode = 0x4C340005 // the Dial hook denied it (ErrDenied), or a local firewall (EACCES, EPERM)
	CodeRefused         RejectCode = 0x4C340006 // the target refused (RST to the SYN)
	CodeNetUnreachable  RejectCode = 0x4C340007
	CodeHostUnreachable RejectCode = 0x4C340008
	CodeTimeout         RejectCode = 0x4C340009 // the connect timed out (DialTimeout or the pending deadline)
	CodeDNSNotFound     RejectCode = 0x4C34000A // the name does not exist
	CodeDNSFailure      RejectCode = 0x4C34000B // resolution failed or timed out
	CodeCapacity        RejectCode = 0x4C34000C // the Server's MaxConns or abandoned cap; the host's fds or ports
	CodeDialFailed      RejectCode = 0x4C34000D // anything else
)

// String returns the code's fixed class text, which is also the Reject
// message a Server sends.
func (c RejectCode) String() string {
	return fmt.Sprintf("l4 code %#08x", uint32(c)) // M4 WP2: the fixed class texts
}

// CodeOf returns the l4 code of err (a Dial error, or the first Read or
// Write error after EarlyReturn); ok is false when err is not an l4
// Server's refusal.
func CodeOf(err error) (code RejectCode, ok bool) {
	return 0, false // M4 WP2
}

// Abort codes of a forwarded session (rendr.Conn.Abort).
const (
	AbortReset    rendr.AbortCode = 0x4C340101 // the forwarded socket was reset or failed
	AbortShutdown rendr.AbortCode = 0x4C340102 // Forward's ctx ended (a Server stopping)
)

// ErrDenied is what a Server's Dial hook wraps to refuse a target by policy
// (answered CodeNotAllowed).
var ErrDenied = errors.New("l4: target not allowed")
