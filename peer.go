package rendr

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
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
	rt        *Runtime
	factories []carrier.Factory // the snapshot every session dials with (L20); never modified
	names     []string          // factory names in configuration order (PeerStatus)
	health    *carrier.Health   // nil for a single factory (no probing, design §7.8)
	env       session.Env       // the Env of this Peer's sessions (Registry: peerRegistry)

	mu     sync.Mutex // a leaf (design §3.2)
	closed bool
	gone   [][16]byte           // instances that sent GOAWAY or answered GOING_AWAY, oldest first (LRU, D21)
	holds  map[SessionID]func() // Health holds of this Peer's sessions (released at their end)
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
		holds:     make(map[SessionID]func()),
	}
	seen := make(map[string]struct{}, n)
	for i, c := range cfg.Carriers {
		var sc StreamCarrier
		switch v := c.(type) {
		case StreamCarrier:
			sc = v
		case *StreamCarrier:
			if v == nil {
				return nil, fmt.Errorf("rendr: NewPeer: carrier %d is a nil *StreamCarrier", i)
			}
			sc = *v
		default:
			return nil, fmt.Errorf("rendr: NewPeer: carrier %d is %T, want StreamCarrier", i, c)
		}
		switch _, dup := seen[sc.Name]; {
		case sc.Name == "":
			return nil, fmt.Errorf("rendr: NewPeer: carrier %d has no Name", i)
		case dup:
			return nil, fmt.Errorf("rendr: NewPeer: carrier name %q is used twice", sc.Name)
		case sc.Dial == nil:
			return nil, fmt.Errorf("rendr: NewPeer: carrier %q has no Dial", sc.Name)
		}
		seen[sc.Name] = struct{}{}
		p.factories[i] = carrier.Factory{Index: i, Name: sc.Name, Dial: sc.Dial, DialEarly: sc.DialEarly}
		p.names[i] = sc.Name
	}
	p.env = session.Env{
		Carrier:  &rt.cenv,
		Events:   rt.ev, // a nil *eventQueue discards every event
		Registry: peerRegistry{p},
		Rand:     rt.eff.rand,
		Hooks:    rt.eff.hooks,
	}
	if n >= 2 {
		p.health = carrier.NewHealth(&rt.cenv, p.factories, rt.eff.health)
	}
	return p, nil
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

// hold keeps the Peer's probing alive for session sid (design §7.8: a Peer
// is in use while it has a live session). It is taken before the session
// exists, so the session's end always finds it, and released by unhold at a
// Dial failure or at the session's end, whichever comes first.
func (p *Peer) hold(sid SessionID) {
	if p.health == nil {
		return
	}
	release := p.health.Hold()
	p.mu.Lock()
	p.holds[sid] = release
	p.mu.Unlock()
}

// unhold releases the hold of session sid (idempotent).
func (p *Peer) unhold(sid SessionID) {
	if p.health == nil {
		return
	}
	p.mu.Lock()
	release := p.holds[sid]
	delete(p.holds, sid)
	p.mu.Unlock()
	if release != nil {
		release()
	}
}

// peerRegistry is the session.Registry of a Peer's (dialer) sessions: it
// keeps their table entries (MaxSessions units, the Lingering count) and
// releases the Peer's health hold at their end.
type peerRegistry struct{ p *Peer }

var _ session.Registry = peerRegistry{}

// Opened is a passive-side transition: a dialer session is attached by
// Peer.Dial when Dial returns.
func (peerRegistry) Opened(*session.Session) {}

// Lingering moves the session into (or out of) the Lingering count.
func (r peerRegistry) Lingering(s *session.Session, on bool) {
	r.p.rt.table.setLingering(dialerKey(SessionID(s.ID())), s, on)
}

// Orphaned counts only passive sessions (SessionCounts.Orphaned).
func (peerRegistry) Orphaned(*session.Session, bool) {}

// Ended removes the dialer entry (releasing its MaxSessions unit unless
// Peer.Dial's failure path already did), releases the Peer's health hold
// and remembers the session until its Done closes, for Runtime.Close.
func (r peerRegistry) Ended(s *session.Session, _ session.Verdict) {
	sid := SessionID(s.ID())
	rt := r.p.rt
	rt.table.ended(dialerKey(sid), s, session.Verdict{}, time.Now())
	r.p.unhold(sid)
	rt.noteEnded(s)
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
