package rendr

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Carrier is a carrier factory. The set is closed: StreamCarrier and
// DatagramCarrier (each as a value or a non-nil pointer). Stream sessions
// (Dial) use a Peer's stream factories only; packet sessions (DialPacket)
// use both kinds, datagram factories first.
type Carrier interface{ isCarrier() }

// StreamCarrier is a factory of ordered, reliable byte-stream carriers to
// the Peer's rendr instance (an L7 tunnel, a TLS connection, a raw TCP
// connection from carrier/tcp, ...). rendr treats it and every conn it
// returns as untrusted: calls are bounded by DialTimeout even when
// ctx is ignored, panics and Goexit are contained, (nil, nil) is an error,
// a conn returned late is closed exactly once, byte counts are validated,
// and conns are only ever used through the net.Conn interface, except the
// connections package carrier/tcp creates (see that package).
type StreamCarrier struct {
	// Name identifies the factory in Status, PeerStatus and ranking ties;
	// unique and non-empty within a Peer.
	Name string
	// Dial opens one carrier. Required.
	Dial func(ctx context.Context) (net.Conn, error)
	// DialEarly, if set, is used instead of Dial: first holds the PREFACE and
	// the first frame — an OPEN or JOIN for a session carrier, a PING for a
	// probe carrier (Peers with two or more factories) — and must be sent
	// before anything else inside the embedder's own open request, saving
	// one round trip. The returned conn must not deliver first again.
	DialEarly func(ctx context.Context, first []byte) (net.Conn, error)
}

func (StreamCarrier) isCarrier() {}

// PeerConfig lists a Peer's carrier factories in preference order (the
// order breaks ranking ties). Every session snapshots it at Dial; a later
// change of the Peer does not affect existing sessions.
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

// Peer is one destination rendr instance reachable through a set of
// carrier factories; every factory must reach that same instance (the
// embedding contract in the package documentation). It does not pin the
// InstanceID: every new session learns the instance it reaches.
type Peer struct {
	rt        *Runtime
	factories []carrier.Factory // the snapshot every session dials with (L20); never modified
	streams   uint16            // DialSpec.Eligible bits of the stream factories (M2-D46)
	names     []string          // factory names in configuration order (PeerStatus)
	health    *carrier.Health   // nil for a single factory (no probing, design §7.8)
	env       session.Env       // the Env template of this Peer's sessions; each Dial adds its own Registry (dialReg)

	mu     sync.Mutex // a leaf (design §3.2)
	closed bool
	gone   [][16]byte // instances that sent GOAWAY or answered GOING_AWAY, oldest first (LRU, D21)
}

// goneAwayLimit bounds a Peer's gone-away instance set (D21).
const goneAwayLimit = 64

// newPeer validates cfg and builds the Peer's factory snapshot (L20): the
// carriers are copied, so a later change of cfg has no effect.
func newPeer(rt *Runtime, cfg PeerConfig) (*Peer, error) {
	n := len(cfg.Carriers)
	if n < 1 || n > maxFactories {
		return nil, fmt.Errorf("rendr: NewPeer: %d carriers, want 1 to %d", n, maxFactories)
	}
	p := &Peer{
		rt:        rt,
		factories: make([]carrier.Factory, n),
		names:     make([]string, n),
	}
	seen := make(map[string]struct{}, n)
	for i, c := range cfg.Carriers {
		f, err := factoryOf(i, c)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[f.Name]; dup {
			return nil, fmt.Errorf("rendr: NewPeer: carrier name %q is used twice", f.Name)
		}
		seen[f.Name] = struct{}{}
		p.factories[i] = f
		p.names[i] = f.Name
		if f.Kind == wire.KindStream {
			p.streams |= 1 << i
		}
	}
	p.env = session.Env{
		Carrier: &rt.cenv,
		Events:  rt.ev, // a nil *eventQueue discards every event
		Rand:    rt.eff.rand,
		Hooks:   rt.eff.hooks,
	}
	if n >= 2 {
		p.health = carrier.NewHealth(&rt.cenv, p.factories, rt.eff.health)
	}
	return p, nil
}

// factoryOf validates the i-th carrier factory of a PeerConfig and converts
// it (M2 design §A2.1, §A5.14): a StreamCarrier needs a Name and a Dial; a
// DatagramCarrier a Name, a Dial and an MTU of 537–65,507 bytes (M2-D51).
// Every factory gets its Kind (R1-32).
func factoryOf(i int, c Carrier) (carrier.Factory, error) {
	switch v := c.(type) {
	case *StreamCarrier:
		if v == nil {
			return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %d is a nil *StreamCarrier", i)
		}
		return factoryOf(i, *v)
	case *DatagramCarrier:
		if v == nil {
			return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %d is a nil *DatagramCarrier", i)
		}
		return factoryOf(i, *v)
	case StreamCarrier:
		switch {
		case v.Name == "":
			return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %d has no Name", i)
		case v.Dial == nil:
			return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %q has no Dial", v.Name)
		}
		return carrier.Factory{Index: i, Name: v.Name, Kind: wire.KindStream, Dial: v.Dial, DialEarly: v.DialEarly}, nil
	case DatagramCarrier:
		switch {
		case v.Name == "":
			return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %d has no Name", i)
		case v.Dial == nil:
			return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %q has no Dial", v.Name)
		case v.MTU < wire.MinFrameBudget || v.MTU > wire.MaxDatagram:
			return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %q has MTU %d, want %d to %d", v.Name, v.MTU, wire.MinFrameBudget, wire.MaxDatagram)
		}
		return carrier.Factory{Index: i, Name: v.Name, Kind: wire.KindDatagram, DialPacket: v.Dial, MTU: v.MTU}, nil
	}
	return carrier.Factory{}, fmt.Errorf("rendr: NewPeer: carrier %d is %T, want StreamCarrier or DatagramCarrier", i, c)
}

// Status returns the per-factory probe evidence.
func (p *Peer) Status() PeerStatus {
	var snap *carrier.Snapshot
	if p.health != nil {
		snap = p.health.Snapshot()
	}
	return peerStatusFrom(snap, p.names, time.Now())
}

// Close stops probing; later Dials return net.ErrClosed. Sessions already
// dialled keep running on their factory snapshot. Idempotent.
func (p *Peer) Close() error {
	p.shutdown()
	p.rt.mu.Lock()
	delete(p.rt.peers, p)
	p.rt.mu.Unlock()
	return nil
}

// shutdown marks the Peer closed and stops its health layer (bounded;
// Health.Close is idempotent).
func (p *Peer) shutdown() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	if p.health != nil {
		p.health.Close()
	}
}

func (p *Peer) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// goneAway reports whether inst sent GOAWAY to (or answered GOING_AWAY
// for) this Peer: no OPEN is sent to it again (design §6.6, D21).
func (p *Peer) goneAway(inst [16]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, g := range p.gone {
		if g == inst {
			return true
		}
	}
	return false
}

// noteGoAway records inst in the gone-away set as the most recent entry,
// evicting the least recently noted instance beyond goneAwayLimit.
func (p *Peer) noteGoAway(inst [16]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, g := range p.gone {
		if g == inst {
			copy(p.gone[i:], p.gone[i+1:])
			p.gone[len(p.gone)-1] = inst
			return
		}
	}
	if len(p.gone) == goneAwayLimit {
		copy(p.gone, p.gone[1:])
		p.gone = p.gone[:len(p.gone)-1]
	}
	p.gone = append(p.gone, inst)
}

// PeerStatus is the health layer's view of a Peer.
type PeerStatus struct {
	Probing   bool            // probe carriers are maintained (≥ 2 factories, in use)
	Factories []FactoryStatus // in configuration order
}

// FactoryStatus is one factory's probe state (see ProbePolicy, Evidence
// and SelectorPolicy).
type FactoryStatus struct {
	Name          string
	Evidence      Evidence      // at the time of the call
	RTT           time.Duration // aggregated probe RTT (fresh or held), else 0
	Samples       uint64        // probe samples accepted, loaded ones included
	LoadedSamples uint64        // samples excluded by the self-load guard
	Failed        bool          // ranking demotion mark; never blocks a dial
	FailReason    string        // last failure: "transport_error", "capacity", "ping_timeout", ...
	ProbeCarrier  CarrierID     // the current probe carrier (0 when none)
	Attempts      uint64        // probe dial attempts
}
