//go:build !windows

package realsock

import (
	"errors"
	"net"
)

// l4uConnResetOn is Windows only (l4u_windows_test.go): SIO_UDP_CONNRESET
// is a Winsock switch.
func l4uConnResetOn(*net.UDPConn) error {
	return errors.New("SIO_UDP_CONNRESET is a Winsock switch")
}
