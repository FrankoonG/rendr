//go:build !unix && !windows

package carrier

import (
	"net"
	"testing"
)

// The per-OS halves of the WP5 token tests on the platforms without an
// errno table (owned_udp_other.go; compile-only, M2 design §A6.1).

// wp5ErrnoCases: no errno rows; the deadline, closed, Temporary() and count
// rows of TestOwnedUDPErrorClasses remain.
func wp5ErrnoCases() wp5Errnos { return wp5Errnos{} }

// wp5CheckOSTruncation: no truncation flag or error is read here; a
// datagram longer than the read buffer must fill it, which the max+1 rule
// alone detects.
func wp5CheckOSTruncation(t *testing.T, n, bufLen, flags int, err error) {
	t.Helper()
	if err != nil || n != bufLen {
		t.Fatalf("truncated read: n %d of %d, flags %#x, %v; want the buffer filled, no error", n, bufLen, flags, err)
	}
}

// wp5ReportICMP returns nil: no ICMP-derived errors here.
func wp5ReportICMP(*testing.T, *net.UDPConn) error { return nil }
