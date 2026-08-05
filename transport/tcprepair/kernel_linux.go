//go:build linux

package tcprepair

import (
	"fmt"
	"syscall"
)

func requireTCPRepairWindowKernel() error {
	release, ok := currentKernelRelease()
	if !ok {
		return nil
	}
	version, ok := parseLinuxKernelRelease(release)
	if !ok {
		return nil
	}
	if version.lessThan(4, 5) {
		return fmt.Errorf("tcprepair: TCP_REPAIR_WINDOW requires Linux >= 4.5 (kernel %s)", release)
	}
	return nil
}

func currentKernelRelease() (string, bool) {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "", false
	}
	buf := make([]byte, 0, len(uts.Release))
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	if len(buf) == 0 {
		return "", false
	}
	return string(buf), true
}
