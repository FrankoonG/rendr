//go:build !linux

package tun

import "github.com/FrankoonG/rendr/virtualif"

// Probe reports unavailable on non-Linux platforms for the first TUN
// milestone. Windows/macOS backends can fill this in later.
func Probe() virtualif.Capability {
	err := &virtualif.Error{
		Op:     "tun probe",
		Reason: virtualif.ReasonTUNUnavailable,
	}
	return virtualif.Capability{
		Available: false,
		Reason:    virtualif.ReasonTUNUnavailable,
		Err:       err,
	}
}
