package rendrtest

import "os"

// openFDs counts this process's open file descriptors.
func openFDs() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}
