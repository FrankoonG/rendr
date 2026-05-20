//go:build linux

package smoke

import (
	"fmt"
	"os/exec"
	"strconv"
)

// iptablesDropSrcPort installs an OUTPUT-chain rule that drops every
// TCP segment whose source port matches port. Returns a cleanup
// function that removes the same rule; caller MUST defer it (a leaked
// rule would silently break subsequent regress runs).
//
// Linux-only by build tag. The container running regress must have
// CAP_NET_ADMIN (docker --cap-add=NET_ADMIN, set by scripts/regress.sh).
func iptablesDropSrcPort(port int) (cleanup func() error, err error) {
	addArgs := []string{"-A", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "DROP"}
	delArgs := []string{"-D", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "DROP"}
	cmd := exec.Command("iptables", addArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables -A sport %d: %w (%s)", port, err, out)
	}
	cleanup = func() error {
		c := exec.Command("iptables", delArgs...)
		o, e := c.CombinedOutput()
		if e != nil {
			return fmt.Errorf("iptables -D sport %d: %w (%s)", port, e, o)
		}
		return nil
	}
	return cleanup, nil
}

