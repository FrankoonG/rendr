package smoke

import (
	"fmt"
	"net"
	"strconv"
)

// portFromAddr parses "ip:port" / "[ip6]:port" and returns the port.
// Used by the iptables harness to target a specific path by its
// transport-layer source port.
func portFromAddr(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("split %q: %w", addr, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", p, err)
	}
	return port, nil
}
