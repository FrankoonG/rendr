//go:build linux

package tcpquarantine

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func currentNamespaceScope() (namespaceScope, error) {
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return namespaceScope{}, fmt.Errorf("open network namespace: %w", err)
	}
	defer unix.Close(fd)
	var state unix.Stat_t
	if err := unix.Fstat(fd, &state); err != nil {
		return namespaceScope{}, fmt.Errorf("stat network namespace: %w", err)
	}
	return namespaceScope{platform: "linux", device: uint64(state.Dev), inode: state.Ino}, nil
}
