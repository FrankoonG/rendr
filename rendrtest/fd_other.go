//go:build !linux

package rendrtest

// openFDs is not observed on this platform (design §11.2: fds on Linux).
func openFDs() map[string]bool { return nil }
