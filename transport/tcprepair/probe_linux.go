//go:build linux

package tcprepair

import (
	"errors"
	"fmt"
	"syscall"
)

// Available actively probes whether this process can use the TCP_REPAIR
// primitives required by the owned-leaf planner. It does not select a
// mobility implementation or imply that a live kernel TCP connection can be
// converted to another backend.
func Available() error {
	if err := requireTCPRepairWindowKernel(); err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("tcprepair: probe socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := setInt(fd, tcpRepair, 1); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("tcprepair: CAP_NET_ADMIN required: %w", err)
		}
		return fmt.Errorf("tcprepair: enable TCP_REPAIR: %w", err)
	}
	_ = setInt(fd, tcpRepair, 0)
	return nil
}
