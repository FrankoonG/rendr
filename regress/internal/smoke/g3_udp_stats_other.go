//go:build !linux

package smoke

func readG3HostUDPStats() (g3HostUDPStats, bool, error) {
	return g3HostUDPStats{}, false, nil
}
