//go:build !linux

package smoke

func readG3HostUDPStats() (g3HostUDPStats, string, error) {
	return g3HostUDPStats{}, g3UDPStatsUnsupported, nil
}
