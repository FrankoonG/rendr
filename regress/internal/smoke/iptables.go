//go:build linux

package smoke

import (
	"fmt"
	"os/exec"
	"strconv"
)

// iptablesDropSrcPort installs an OUTPUT-chain rule that REJECTs
// every TCP segment whose source port matches port via tcp-reset,
// causing the LOCAL socket to receive ECONNRESET. This matches the
// semantics of the older ForceKillPathForTest engine backdoor:
// PathConn.Read() returns an error, readerLoop exits, engine's
// onPathDeath triggers prime-mode failover.
//
// A plain `-j DROP` would silently drop the outbound packet — no
// FIN/RST reaches the local socket, PathConn.Read blocks indefinitely,
// engine never sees the path die. RTO would fire eventually (minutes),
// missing the 5 s G4 failover budget.
//
// Returns a cleanup function that removes the same rule; caller MUST
// defer it (a leaked rule silently breaks subsequent regress runs).
//
// Linux-only by build tag. The container running regress must have
// CAP_NET_ADMIN (docker --cap-add=NET_ADMIN, set by scripts/regress.sh).
func iptablesDropSrcPort(port int) (cleanup func() error, err error) {
	addArgs := []string{"-A", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "REJECT", "--reject-with", "tcp-reset"}
	delArgs := []string{"-D", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "REJECT", "--reject-with", "tcp-reset"}
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

