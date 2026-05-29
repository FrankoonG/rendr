//go:build !linux

package tun

import (
	"errors"

	"github.com/FrankoonG/rendr/virtualif"
)

// Device is only implemented on Linux in this milestone.
type Device struct{}

func Open(Config) (*Device, error) {
	return nil, &virtualif.Error{
		Op:     "tun open",
		Reason: virtualif.ReasonTUNUnavailable,
		Err:    errors.New("non-linux TUN backend not implemented"),
	}
}
