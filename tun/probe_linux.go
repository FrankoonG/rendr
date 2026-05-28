//go:build linux

package tun

import (
	"errors"
	"os"
	"syscall"

	"github.com/FrankoonG/rendr/virtualif"
)

const devNetTun = "/dev/net/tun"

// Probe reports whether a Linux TUN device can be opened by this
// process. It does not create an interface; later setup performs the
// TUNSETIFF step after config validation.
func Probe() virtualif.Capability {
	f, err := os.OpenFile(devNetTun, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err == nil {
		_ = f.Close()
		return virtualif.Capability{Available: true}
	}
	reason := virtualif.ReasonTUNUnavailable
	if errors.Is(err, os.ErrPermission) {
		reason = virtualif.ReasonTUNPermissionDenied
	}
	return virtualif.Capability{
		Available: false,
		Reason:    reason,
		Err: &virtualif.Error{
			Op:     "tun probe",
			Reason: reason,
			Err:    err,
		},
	}
}
