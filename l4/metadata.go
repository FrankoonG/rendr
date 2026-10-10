package l4

import (
	"errors"
	"fmt"
)

// CmdConnect is Request.Cmd for a TCP connection, the only command of
// metadata version 1.
const CmdConnect = 1

// Request is what an OPEN's L4 metadata carries.
type Request struct {
	Cmd  uint8  // CmdConnect
	Addr string // "host:port"; an IPv6 host in brackets; a host name is resolved by the passive
	App  []byte // the application's own metadata (aliases the decoded input)
}

// ErrBadAddress reports a malformed or non-canonical target address.
var ErrBadAddress = errors.New("l4: bad target address")

// AppendMetadata appends the canonical L4 metadata (version 1) of r to dst.
// Errors wrap ErrBadAddress.
func AppendMetadata(dst []byte, r Request) ([]byte, error) {
	return dst, errors.ErrUnsupported // M4 WP2
}

// ParseMetadata decodes L4 metadata strictly. The error is a
// *MetadataError whose Code is CodeBadRequest, CodeBadVersion,
// CodeBadCommand or CodeBadAddress.
func ParseMetadata(md []byte) (Request, error) {
	return Request{}, &MetadataError{Code: CodeBadRequest, Msg: errors.ErrUnsupported.Error()} // M4 WP2
}

// Match reports whether md starts with the L4 magic.
func Match(md []byte) bool {
	return false // M4 WP2
}

// MetadataError is ParseMetadata's error: the Reject code a Server answers
// the malformed metadata with, and what was wrong.
type MetadataError struct {
	Code RejectCode
	Msg  string
}

// Error implements error.
func (e *MetadataError) Error() string {
	return fmt.Sprintf("l4: metadata: %s: %s", e.Code, e.Msg)
}
