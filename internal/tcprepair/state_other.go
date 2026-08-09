//go:build !linux || !amd64

package tcprepair

import (
	"context"
	"net"
)

func Inspect(*net.TCPConn) (Inspection, error) {
	return Inspection{}, ErrUnsupported
}

func Capture(*net.TCPConn) (*CaptureLease, error) {
	return nil, ErrUnsupported
}

func (*CaptureLease) Resume() error { return ErrUnsupported }

func (*CaptureLease) Close() error { return ErrUnsupported }

func Resume(*net.TCPConn) error {
	return ErrUnsupported
}

func Enter(*net.TCPConn) error {
	return ErrUnsupported
}

func Restore(context.Context, *Snapshot) (*net.TCPConn, error) {
	return nil, ErrUnsupported
}
