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

// ContextWriter is implemented by devices that can cancel a blocked packet
// write without closing the interface. It preserves Device's packet-atomic
// contract: success means exactly one complete packet was written, while a
// context that is already done must prevent the packet from being submitted.
// Cancellation racing with a completed write may still return success. The
// context must be non-nil. Callers should fall back to Device.Write when a
// backend does not provide it.
type ContextWriter interface {
	WriteContext(context.Context, []byte) (int, error)
}

// CancellableWriterDevice is the output-side contract for long-running relay
// loops. Their shutdown must not depend on the virtual interface becoming
// writable after the relay context has been canceled.
type CancellableWriterDevice interface {
	Device
	ContextWriter
}

// CancellableDevice is the packet source contract required by long-running
// pumps. Relays that only write replies can continue to accept Device.
type CancellableDevice interface {
	Device
	ContextReader
}

// FullDuplexCancellableDevice is required by adapters that continuously move
// packets in both directions. Their shutdown must not depend on a future read
// or on a blocked backend write eventually becoming writable.
type FullDuplexCancellableDevice interface {
	CancellableDevice
	CancellableWriterDevice
}

// Capability describes whether a virtual-interface backend can run in
// the current process and environment.
type Capability struct {
	Available bool
	Reason    ErrorReason
	Err       error
}
