// Package virtualif holds common virtual-interface contracts shared by
// TUN and future TAP frontends.
package virtualif

import (
	"context"
	"io"
)

// Device is the minimal raw-packet interface required by l3 ingress. Each
// successful Read or Write represents exactly one complete packet; backends
// must return an error instead of silently truncating or short-writing it. A
// Read that returns io.ErrShortBuffer must retain the packet so the caller can
// retry with a larger buffer without loss.
type Device interface {
	io.ReadWriteCloser
	Name() string
	MTU() int
}

// ContextReader is implemented by devices that can cancel a blocked packet
// read without closing the interface. Callers should fall back to Device.Read
// when a backend does not provide it.
type ContextReader interface {
	ReadContext(context.Context, []byte) (int, error)
}

// CancellableDevice is the packet source contract required by long-running
// pumps. Relays that only write replies can continue to accept Device.
type CancellableDevice interface {
	Device
	ContextReader
}

// Capability describes whether a virtual-interface backend can run in
// the current process and environment.
type Capability struct {
	Available bool
	Reason    ErrorReason
	Err       error
}
