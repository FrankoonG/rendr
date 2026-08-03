//go:build linux

package smoke

import (
	"bytes"
	"os"
)

func readG3HostUDPStats() (g3HostUDPStats, bool, error) {
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return g3HostUDPStats{}, true, err
	}
	stats, err := parseG3HostUDPStats(bytes.NewReader(data))
	return stats, true, err
}
