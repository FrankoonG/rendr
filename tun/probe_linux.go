//go:build linux

package tun

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"github.com/FrankoonG/rendr/virtualif"
)

const devNetTun = "/dev/net/tun"

// Probe reports whether this process can create a Linux TUN interface.
// The temporary interface disappears when the probe fd is closed.
func Probe() virtualif.Capability {
	f, err := os.OpenFile(devNetTun, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
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
	defer f.Close()
	req, err := newIfReq("rendrp%d")
	if err != nil {
		return virtualif.Capability{Available: false, Reason: virtualif.ReasonTUNUnavailable, Err: err}
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(linuxTunSetIFF), uintptr(unsafe.Pointer(req))); errno != 0 {
		probeErr := probeOpenError("tun probe", errno)
		reason := virtualif.ReasonTUNUnavailable
		var verr *virtualif.Error
		if errors.As(probeErr, &verr) {
			reason = verr.Reason
		}
		return virtualif.Capability{Available: false, Reason: reason, Err: probeErr}
	}
	return virtualif.Capability{Available: true}
}
