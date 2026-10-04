//go:build !linux

package rendrtest

// openFDs is not counted on this platform (design §11.2: fds on Linux).
func openFDs() int { return -1 }
