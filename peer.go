package rendr

import (
	"context"
	"net"
	"time"
)

// Carrier is a carrier factory. The set is closed: M1 has StreamCarrier;
// M2 adds DatagramCarrier.
type Carrier interface{ isCarrier() }

// StreamCarrier is a factory of ordered, reliable byte-stream carriers to
// the Peer's rendr instance (an L7 tunnel, a TLS connection, a raw TCP
// connection from carrier/tcp, ...). rendr treats it and every conn it
// returns as untrusted (L51): calls are bounded by DialTimeout even when
// ctx is ignored, panics and Goexit are contained, (nil, nil) is an error,
// a conn returned late is closed exactly once, byte counts are validated,
// and conns are only ever used through the net.Conn interface.
type StreamCarrier struct {
	// Name identifies the factory in Status, PeerStatus and ranking ties;
	// unique and non-empty within a Peer.
	Name string
	// Dial opens one carrier. Required.
	Dial func(ctx context.Context) (net.Conn, error)
	// DialEarly, if set, is used instead of Dial: first holds the PREFACE and
	// the first frame (OPEN or JOIN) and must be sent before anything else
	// inside the embedder's own open request, saving one round trip. The
	// returned conn must not deliver first again.
	DialEarly func(ctx context.Context, first []byte) (net.Conn, error)
}

func (StreamCarrier) isCarrier() {}

// PeerConfig lists a Peer's carrier factories in preference order (the
// order breaks ranking ties). Every session snapshots it at Dial; a later
// change of the Peer does not affect existing sessions (L20).
type PeerConfig struct {
	Carriers []Carrier
}

// DialOptions configure one session.
type DialOptions struct {
	// Mode is fixed for the session's lifetime; 0 selects ModeSelector.
	Mode Mode
	// Metadata is opaque bytes delivered to the passive application with the
	// OPEN (≤ Handshake.MaxMetadata, else ErrMetadataTooLarge).
	Metadata []byte
	// NoPathGrace overrides Config.NoPathGrace for this session (clamped to
	// 3 s–300 s; 0 keeps the Runtime value).
	NoPathGrace time.Duration
}

// Peer is one destination rendr instance (the same-instance contract,
// plan §1.4) reachable through a set of carrier factories. It does not pin
// the InstanceID: every new session learns the instance it reaches.
type Peer struct {
	_ struct{} // unexported state is defined by the implementation
}

// Dial opens a session (design §6.6): with two or more factories it first
// waits for the first probe samples — only while probing is cold-starting
// and never longer than Probe.DialWait — then races OPEN over the ranked
// factories with JoinStagger and returns on the first OPEN_ACK(OK).
// Errors (plan §6): *RejectError (ErrRejected), ErrCapacity, ErrVersion,
// ErrProtocol, ErrMetadataTooLarge, ErrSessionLost, ErrNoPath (no OPEN within
// NoPathGrace, wrapping the last carrier error), ctx.Err() wrapping the last
// carrier error (returned within 100 ms of cancellation; the session then
// withdraws in the background), net.ErrClosed after Peer.Close or
// Runtime.Close.
func (p *Peer) Dial(ctx context.Context, o DialOptions) (*Conn, error) {
	panic("unimplemented: M1b")
}

// Status returns the per-factory probe evidence.
func (p *Peer) Status() PeerStatus {
	panic("unimplemented: M1b")
}

// Close stops probing; later Dials return net.ErrClosed. Sessions already
// dialled keep running on their factory snapshot. Idempotent.
func (p *Peer) Close() error {
	panic("unimplemented: M1b")
}

// PeerStatus is the health layer's view of a Peer.
type PeerStatus struct {
	Probing   bool            // probe carriers are maintained (≥ 2 factories, in use)
	Factories []FactoryStatus // in configuration order
}

// FactoryStatus is one factory's probe state (plan §3.9, design §8).
type FactoryStatus struct {
	Name          string
	Evidence      Evidence      // at the time of the call
	RTT           time.Duration // aggregated probe RTT (fresh or held), else 0
	Samples       uint64        // unloaded probe samples accepted
	LoadedSamples uint64        // samples excluded by the self-load guard
	Failed        bool          // ranking demotion mark; never blocks a dial
	FailReason    string        // last failure: "transport_error", "capacity", "ping_timeout", ...
	ProbeCarrier  CarrierID     // the current probe carrier (0 when none)
	Attempts      uint64        // probe dial attempts
}
