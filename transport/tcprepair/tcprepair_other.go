//go:build !linux

package tcprepair

import (
	"errors"
	"net"
)

// State is the same shape as the Linux file so non-Linux builds
// compile. All operations error out.
type State struct {
	LocalAddr  *net.TCPAddr
	RemoteAddr *net.TCPAddr
	SendSeq    uint32
	RecvSeq    uint32
	Timestamp  uint32
	RecvQueue  []byte
	SendQueue  []byte
}

// Snapshot returns an error on non-Linux; TCP_REPAIR is Linux-only.
func Snapshot(_ *net.TCPConn) (*State, error) {
	return nil, errors.New("tcprepair: TCP_REPAIR only supported on Linux, use gvisor fallback")
}

// Restore returns an error on non-Linux; TCP_REPAIR is Linux-only.
func Restore(_ *State) (int, error) {
	return -1, errors.New("tcprepair: TCP_REPAIR only supported on Linux, use gvisor fallback")
}
