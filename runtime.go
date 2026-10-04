package rendr

// Runtime is one rendr instance: it owns its InstanceID, admission tables
// (handshake slots, session table and tombstones, sessionless carriers),
// the memory budget, the buffer pool, the abandoned-call pool, the event
// queue, its Listeners and Peers. All methods are safe for concurrent use.
type Runtime struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewRuntime normalizes cfg (see Config) and draws the InstanceID from
// crypto/rand. It fails only if crypto/rand fails; out-of-range values are
// clamped, never rejected. It starts no goroutine unless cfg.OnEvent is set
// (the event worker).
func NewRuntime(cfg Config) (*Runtime, error) {
	panic("unimplemented: M1b")
}

// InstanceID returns this Runtime's InstanceID.
func (rt *Runtime) InstanceID() InstanceID {
	panic("unimplemented: M1b")
}

// NewPeer validates and deep-copies cfg: 1–16 carriers, every Name non-empty
// and unique, every Dial non-nil. A Peer with two or more carriers runs the
// health layer (probe carriers) while it is in use.
func (rt *Runtime) NewPeer(cfg PeerConfig) (*Peer, error) {
	panic("unimplemented: M1b")
}

// Listen creates a Listener over cfg.Sources (one accept goroutine per
// pull source). cfg is normalized like Config; adjustments are appended to
// Status.ConfigAdjustments with the prefix "Listen[i].".
func (rt *Runtime) Listen(cfg ListenConfig) (*Listener, error) {
	panic("unimplemented: M1b")
}

// Status returns the Runtime counters. Counters are read individually;
// consistency across them is not claimed.
func (rt *Runtime) Status() Status {
	panic("unimplemented: M1b")
}

// Close shuts the Runtime down (idempotent, bounded): new handshakes are
// answered PREFACE_ACK(GOING_AWAY); every Listener closes (pending sessions
// answered GOING_AWAY); every session sends RST(AbortGoingAway) and GOAWAY
// and ends locally with net.ErrClosed; every Peer stops probing; sessionless
// carriers get GOAWAY; then every goroutine is joined within about 2 s,
// stragglers stuck in embedder code are counted in Status.Abandoned. Later
// calls on the Runtime and its objects return net.ErrClosed.
func (rt *Runtime) Close() error {
	panic("unimplemented: M1b")
}
