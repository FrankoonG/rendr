// Package virtualif holds common virtual-interface contracts shared by
// TUN and future TAP frontends.
package virtualif

import "io"

// Device is the minimal raw-packet interface required by l3 ingress.
type Device interface {
	io.ReadWriteCloser
	Name() string
	MTU() int
}

// Capability describes whether a virtual-interface backend can run in
// the current process and environment.
type Capability struct {
	Available bool
	Reason    ErrorReason
	Err       error
}
