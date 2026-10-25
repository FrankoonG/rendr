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
//
// Limitation: probe round trips are measured from a PING's write commit,
// so a conn whose Write returns only after the far end read the bytes (a
// net.Pipe-like conn, such as an in-process tunnel) may yield no probe
// evidence at GOMAXPROCS=1. Its factory then stays EvidenceUnknown: a
// cold-start Dial waits the whole Probe.DialWait, and ranking falls back to
// the configured order.
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
	// Props describe the factory to the scheduler: fate group, cheap
	// subflows, head-of-line coupling. The zero value shares the factory's
	// carriers between the Peer's sessions in a fate group of its own.
	Props Props
}

func (StreamCarrier) isCarrier() {}

// PeerConfig lists a Peer's carrier factories in preference order (the
// order breaks ranking ties). Every session snapshots it at Dial; a later
// change of the Peer does not affect existing sessions.
type PeerConfig struct {
	Carriers []Carrier // 1–16 StreamCarrier and DatagramCarrier factories
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

	// EarlyReturn makes Dial return as soon as its local checks passed,
	// before any network I/O (TCP Fast Open semantics; stream sessions only).
	// The session opens with the first Write, Read or CloseWrite: the first
	// Write's bytes, up to Handshake.EarlyDataMax, travel with the OPEN in the
	// same carrier write when the session dials a carrier of its own, so a
	// protocol whose client speaks first saves one round trip. Until the
	// peer answers, Write accepts at most EarlyDataMax bytes in all and then
	// waits for the answer (deadlines apply). Every outcome Dial would have
	// returned arrives later instead: the next Read and Write return it
	// (*RejectError, ErrCapacity, ErrVersion, ErrProtocol, ErrMetadataTooLarge,
	// ErrSessionLost, ErrNoPath); the bytes written early are then discarded
	// on both sides and Done is closed. Close keeps its meaning: what was
	// written is delivered once the peer accepts, within Linger; Abort
	// withdraws. A Close before the first Write, Read or CloseWrite sends
	// nothing; neither does an idle limit (Config.IdleTimeout,
	// Conn.SetIdleTimeout) that expires before them, counted from Dial: the
	// session then ends with ErrIdleTimeout. The cold-start wait for probe
	// samples is skipped. PeerInstance and RemoteAddr report the zero
	// InstanceID until the peer accepted. A session that opens on a carrier
	// it shares with other sessions (rendr mux) sends its bytes after the
	// answer, which costs the same as early data on a carrier of its own. Do
	// not use it when the peer's answer must precede your first byte (a
	// SOCKS5 reply, for example). Write before you Read: a Read that comes
	// first opens the session without early bytes. DialPacket refuses it
	// with ErrProtocol. SessionStatus.EarlyBytes reports how many bytes
	// travelled as early data.
	EarlyReturn bool
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
	props     peerProps         // the factories' interned Props
	pool      *carrier.Pool     // the Peer's shared carriers (rendr mux); nil while no factory is mux-eligible

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
	props, err := newPeerProps(cfg.Carriers, p.names)
	if err != nil {
		return nil, err
	}
	p.props = props
	// rendr mux is the default (M3-D2, plan:135): a factory whose carriers
	// are not cheap subflows shares them between the Peer's sessions.
	props.muxFactories(p.factories)
	p.env = session.Env{
		Carrier: &rt.cenv,
		Events:  rt.ev, // a nil *eventQueue discards every event
		Rand:    rt.eff.rand,
		Hooks:   rt.eff.hooks,
		Closing: &rt.closing,
	}
	if n >= 2 {
		p.health = carrier.NewHealth(&rt.cenv, p.factories, rt.eff.health)
	}
	for i := range p.factories {
		if p.factories[i].Mux {
			// The Peer's pool (M3-D16): every attempt of the Peer's sessions
			// goes through it. Its datagram factories read the per-Dial
			// hints from the attempt's context (poolFactories).
			p.pool = carrier.NewPool(&rt.cenv, poolFactories(p.factories))
			rt.addPool(p.pool)
			break
		}
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
// dialled keep running on their factory snapshot — also on the carriers
// they share (rendr mux): each closes at its last session, and
// Runtime.Close joins them. Idempotent.
func (p *Peer) Close() error {
	p.shutdown()
	p.rt.mu.Lock()
	delete(p.rt.peers, p)
	p.rt.prunePoolsLocked()
	p.rt.mu.Unlock()
	return nil
}

// shutdown marks the Peer closed and stops its health layer (bounded;
// Health.Close is idempotent). The Peer's pool keeps serving the sessions
// that survive (their redials and JOINs) until its trunks drained
// (Pool.Close only lets Runtime.Close's join return).
func (p *Peer) shutdown() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	if p.health != nil {
		p.health.Close()
	}
	if p.pool != nil {
		p.pool.Close()
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
	Name          string        // the factory's Name
	Evidence      Evidence      // at the time of the call
	RTT           time.Duration // aggregated probe RTT (fresh or held), else 0
	Samples       uint64        // probe samples accepted, loaded ones included
	LoadedSamples uint64        // samples excluded by the self-load guard
	Failed        bool          // ranking demotion mark; never blocks a dial
	FailReason    string        // last failure: "transport_error", "capacity", "ping_timeout", ...
	ProbeCarrier  CarrierID     // the current probe carrier (0 when none)
	Attempts      uint64        // probe dial attempts
}

// Props describe a carrier factory to the scheduler (plan §3.2). The zero
// value is a factory of its own fate group whose carriers the Peer's
// sessions share (rendr mux).
//
// NewPeer validates the Props of every factory: a FateGroup of at most 64
// bytes; HoLCoupled only with a FateGroup; the factories of one FateGroup
// agree on HoLCoupled. The error names the factory.
type Props struct {
	// FateGroup names factories whose carriers fail together (a shared first
	// hop, relay or transport connection). Bond and race keep at most one
	// member per group; selector failover tries other groups first. "" puts
	// the factory in a group of its own. At most 64 bytes; compared within
	// one Peer only.
	FateGroup string
	// CheapSubflow: opening a carrier of this factory is cheap (a native
	// subflow such as a new stream of an existing connection), so every
	// session dials its own carriers of it. When false (the default) the
	// sessions of one Peer share the live carriers of this factory, a
	// carrier carrying sessions of one kind (stream or packet): a new
	// session or a failover JOIN uses a live carrier of its kind instead of
	// dialling, sessions on one carrier share its head-of-line blocking and
	// its fate, and the carrier closes when its last session ends.
	CheapSubflow bool
	// HoLCoupled: the carriers of this factory's FateGroup share one
	// in-order pipe (for example streams of one TCP or TLS connection), so a
	// stall of one stalls all. A scheduling hint: rendr never moves a
	// write-blocked carrier's acknowledgement or scheduling duty onto a
	// coupled carrier while another exists. Requires FateGroup.
	HoLCoupled bool
}

// maxFateGroup bounds Props.FateGroup in bytes (M3-D36).
const maxFateGroup = 64

// validateProps checks the Props of a PeerConfig's factories, named by
// names in the same order (M3-D36): FateGroup at most maxFateGroup bytes,
// HoLCoupled only with a FateGroup, and the factories of one FateGroup
// agreeing on HoLCoupled. The error names the first offending factory.
func validateProps(names []string, props []Props) error {
	for i, pr := range props {
		switch {
		case len(pr.FateGroup) > maxFateGroup:
			return fmt.Errorf("rendr: NewPeer: carrier %q: Props.FateGroup is %d bytes, at most %d", names[i], len(pr.FateGroup), maxFateGroup)
		case pr.HoLCoupled && pr.FateGroup == "":
			return fmt.Errorf("rendr: NewPeer: carrier %q: Props.HoLCoupled requires a Props.FateGroup", names[i])
		}
		for j := range i {
			if q := props[j]; q.FateGroup == pr.FateGroup && q.HoLCoupled != pr.HoLCoupled {
				return fmt.Errorf("rendr: NewPeer: carrier %q: Props.HoLCoupled %v disagrees with carrier %q of fate group %q", names[i], pr.HoLCoupled, names[j], pr.FateGroup)
			}
		}
	}
	return nil
}

// internGroups gives every factory a fate-group index (M3-D36, §A7.1):
// factories with equal non-empty FateGroups share one index from 1 up, a
// factory with an empty FateGroup gets index 0, which the scheduler reads
// as a group of its own (session.DialSpec.Groups), and coupled has bit i
// set when factory i's group is HoLCoupled.
//
// props holds at most maxFactories entries (NewPeer's limit) and has been
// validated (validateProps), so the factories of one group agree on
// HoLCoupled.
func internGroups(props []Props) (groups [maxFactories]uint8, coupled uint16) {
	next := uint8(1)
	for i, pr := range props {
		if pr.FateGroup == "" {
			continue // a group of its own: index 0, never coupled
		}
		g := next
		for j := range i {
			if props[j].FateGroup == pr.FateGroup {
				g = groups[j]
				break
			}
		}
		if g == next {
			next++
		}
		groups[i] = g
		if pr.HoLCoupled {
			coupled |= 1 << i
		}
	}
	return groups, coupled
}

// The Props half of a Peer (M3 design §A7.1): what NewPeer derives from its
// factories' Props and every dialer session snapshots at Dial.

// peerProps is a Peer's interned Props, immutable after NewPeer.
type peerProps struct {
	groups  [maxFactories]uint8 // fate-group index per factory (internGroups; 0: a group of its own)
	coupled uint16              // bit i: factory i's group is HoLCoupled
	names   []string            // Props.FateGroup per factory (CarrierStatus.FateGroup on the dialer)
	cheap   uint16              // bit i: factory i is CheapSubflow (carrier.Factory.Mux is its complement)
	factory []string            // factory names in configuration order (the session snapshot's lane names)
}

// newPeerProps validates the Props of a PeerConfig's carriers, whose
// factory names (validated and unique) are names in the same order, and
// interns them (M3-D36). The error names the first offending factory.
func newPeerProps(carriers []Carrier, names []string) (peerProps, error) {
	props := make([]Props, len(carriers))
	for i, c := range carriers {
		props[i] = propsOf(c)
	}
	if err := validateProps(names, props); err != nil {
		return peerProps{}, err
	}
	pp := peerProps{names: make([]string, len(props)), factory: names}
	pp.groups, pp.coupled = internGroups(props)
	for i, pr := range props {
		pp.names[i] = pr.FateGroup
		if pr.CheapSubflow {
			pp.cheap |= 1 << i
		}
	}
	return pp, nil
}

// propsOf returns the Props of a PeerConfig carrier: a StreamCarrier or a
// DatagramCarrier, as a value or a non-nil pointer.
func propsOf(c Carrier) Props {
	switch v := c.(type) {
	case StreamCarrier:
		return v.Props
	case *StreamCarrier:
		if v != nil {
			return v.Props
		}
	case DatagramCarrier:
		return v.Props
	case *DatagramCarrier:
		if v != nil {
			return v.Props
		}
	}
	return Props{}
}

// dialProps fills the fate-group fields of a dialer session's spec from
// the Peer's interned Props (M3-D36, M3-D37, M3-D39): DialSpec.Groups and
// DialSpec.Coupled.
func (pp *peerProps) dialProps(spec *session.DialSpec) {
	spec.Groups = pp.groups
	spec.Coupled = pp.coupled
}

// fateGroup returns the Props.FateGroup of factory i ("" when it has none).
func (pp *peerProps) fateGroup(i int) string {
	if i < 0 || i >= len(pp.names) {
		return ""
	}
	return pp.names[i]
}

// muxFactories sets carrier.Factory.Mux on every factory of fs (the Peer's
// snapshot, in configuration order) that is not CheapSubflow (M3-D2): its
// session carriers negotiate rendr mux and go through the Peer's pool.
// Called by NewPeer once the pool exists (WP10).
func (pp *peerProps) muxFactories(fs []carrier.Factory) {
	for i := range fs {
		fs[i].Mux = pp.cheap&(1<<i) == 0
	}
}

// status converts a session snapshot (sessionStatusFrom) and, for a
// dialer session of this Peer (pp non-nil), reports each carrier's
// Props.FateGroup by its factory name (CarrierStatus.FateGroup, M3-D49).
// A nil pp (the passive side) leaves FateGroup empty.
func (pp *peerProps) status(st session.Status) SessionStatus {
	out := sessionStatusFrom(st)
	if pp == nil {
		return out
	}
	for i := range out.Carriers {
		c := &out.Carriers[i]
		for j, n := range pp.factory {
			if n == c.Name {
				c.FateGroup = pp.fateGroup(j)
				break
			}
		}
	}
	return out
}
