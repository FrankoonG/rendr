//go:build linux

package smoke

import (
	"bytes"
	"os"
)

func readG3HostUDPStats() (g3HostUDPStats, string, error) {
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return g3HostUDPStats{}, g3UDPStatsReadError, err
	}
	stats, err := parseG3HostUDPStats(bytes.NewReader(data))
	if err != nil {
		return g3HostUDPStats{}, g3UDPStatsParseError, err
	}
	return stats, g3UDPStatsOK, nil
}
