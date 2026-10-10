package session

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// DialSpec is everything a dialer session needs, snapshotted at Dial (L20).
type DialSpec struct {
	SID        [16]byte
	Params     Params
	Factories  []carrier.Factory        // the Peer's factory snapshot
	Health     *carrier.Health          // the Peer's health layer; nil = inert (no evidence, no marks, no waiting)
	Metadata   []byte                   // copied by Dial
	GoneAway   func(inst [16]byte) bool // instances that sent GOAWAY to this Peer: never OPEN to them
	NoteGoAway func(inst [16]byte)      // record an instance that answered GOING_AWAY or sent GOAWAY
	// Eligible is the set of factories this session may dial (M2-D46): bit
	// i for Factories[i]; 0 means all (every M1 session). Stream sessions
	// get the stream factories only; packet sessions all of them, ranked
	// by kind class (M2-D47). Health keeps every factory under its Peer
	// index, so a factory outside Eligible is kept out of every scheduling
	// input (integration 1): never ranked (no race, bond or redial slot)
	// and marked failed for the selector's Evaluate, so that it never
	// becomes a quality target.
	Eligible uint16

	// Pool is the Peer's carrier pool (M3-D16): with a pool every attempt
	// goes through Pool.Attempt — a mux-eligible factory's
	// (carrier.Factory.Mux) takes a live trunk, waits for the factory's
	// dial in flight or dials with wire.OptMux; any other factory's is
	// Establish. Pool.Attempt dials with the pool's own factory snapshot,
	// which must be the Peer's (Factories differ from it only in wrappers
	// that AttemptContext stands for). nil: every attempt runs Establish
	// on Factories (M2).
	Pool *carrier.Pool
	// AttemptContext, when set, derives every attempt's base context
	// (attempts outlive the Dial's context): package rendr attaches its
	// per-Dial factory hints there, which the Pool's factories read, so a
	// dial made through the pool keeps them (W4 L3-1).
	AttemptContext func(context.Context) context.Context
	// Groups is the fate-group index of every factory (M3-D36, M3-D37):
	// factories with the same non-empty Props.FateGroup share an index from
	// 1 up; index 0 is a group of its own (an empty FateGroup), so a zero
	// Groups keeps every factory independent.
	Groups [16]uint8
	// Coupled has bit i set when factory i's fate group is HoLCoupled
	// (M3-D39).
	Coupled uint16

	// EarlyReturn (M4-D9 … M4-D12; stream sessions only, M4-D14): Dial
	// returns the session at once, before any attempt, in StatePending;
	// the opening starts at the first Write, Read or CloseWrite
	// (triggerOpen), the first attempt fixes the early span [0, min(end,
	// Params.EarlyDataMax)) that every fresh-carrier attempt carries
	// (R1-2), and the opening's terminal outcome ends the session with
	// Dial's error (early_dial.go).
	EarlyReturn bool
}

// Dial creates a dialer session and runs its opening phase (design §6.6):
// an OPEN race over the ranked factories with JoinStagger and the per-factory
// redial cadence (at most Params.MaxCarriers attempts outstanding), bounded
// by Params.Grace from the call. It returns on the first OPEN_ACK(OK) — the
// session is then open, bound to that carrier's peer instance, with that
// carrier active (selector) or a member (bond); a later OPEN_ACK(OK) is kept
// only if it comes from the bound instance — or on a terminal outcome:
// *RejectError, ErrCapacity, ErrVersion, ErrProtocol, ErrMetadataTooLarge,
// ErrSessionLost, ErrNoPath (wrapping the last carrier error). OPEN_ACK
// CAPACITY with wire.CodeCarriers refuses one carrier of a pending session,
// not the session: that attempt backs off and the race continues. When ctx ends
// first it returns ctx.Err() wrapping the last carrier error within 100 ms.
// After any terminal outcome or cancellation the session withdraws in the
// background (outstanding attempts cancelled with carrier.ErrWithdrawn, so
// Establish sends RST(withdrawn) where an OPEN was written; a late
// OPEN_ACK(OK) gets RST(AbortWithdrawn); every carrier closed once; L49).
// An OPEN_ACK(OK) from an instance other than the bound one also gets
// RST(AbortWithdrawn) (that instance opened a session of its own); a
// selector race loser on the bound instance is retired with CLOSE instead.
// A success that raced the cancellation wins (one CAS decides).
// spec.Health may be nil (inert).
//
// With spec.EarlyReturn (M4 design §A4) Dial returns the session at once,
// before any I/O and before any attempt, in StatePending: the opening
// above starts at the session's first Write, Read or CloseWrite, with
// openBy = that instant + Grace, and every terminal outcome after the
// return — or a Close followed by Linger before the verdict — ends the
// session with that error instead (Read and Write return it, Done closes,
// EventSessionEnd carries it). Before the verdict Write admits at most
// Params.EarlyDataMax bytes in all; a Close keeps its linger meaning and
// an Abort withdraws (early_dial.go). ctx is not used after the return. A
// packet session with EarlyReturn fails at once with ErrProtocol.
//
// A packet session (Params.Kind == wire.KindDatagram, M2 design §A5.4,
// §A5.12) sends OPEN with its MaxPayload offer (Params.Packet.MaxPayload)
// and returns once the first OPEN_ACK(OK) fixed MaxPayload; every carrier's
// OPEN_ACK and JOIN_ACK values are checked per carrier (§A3.5) and fix its
// frame budget. It dials only the factories in spec.Eligible, ranks its
// datagram factories first (M2-D47) and skips in its opening race the
// datagram factories that cannot carry its OPEN (M2-D52). Dial fails at
// once with ErrNoPath when no factory is eligible.
//
// Further contracts of this implementation: Params.Role is set to
// RoleDialer and a zero Params.Mode to ModeSelector. With a health layer
// the session subscribes to its snapshots and holds it (Health.Hold) until
// the session ends; Peer.Dial still calls Use and WaitFirst before Dial.
//
// Registry: Dial returns at once, without creating a session and without
// any Registry call, when ctx is already done or spec has no factory; the
// caller releases what it reserved for the Dial itself. Every session it
// creates calls Ended exactly once, also when Dial fails, with
// Verdict{Opened: true} once it opened — at the end decision, on the
// actor goroutine after the session lock was released, in the same step
// that retires the lanes and withdraws the attempts, not after they were
// joined (Session.Done reports that) — and Lingering(on) after Close,
// Lingering(off) at the end; Opened and Orphaned are passive-only. Events
// are emitted only for a session whose Dial succeeded.
func Dial(ctx context.Context, env *Env, spec DialSpec) (*Session, error) {
	var h healthSource
	if spec.Health != nil { // a nil *Health in the interface would not be nil
		h = spec.Health
	}
	return dial(ctx, env, spec, h)
}

// dial is Dial with the health layer as an interface (tests pass a fake).
func dial(ctx context.Context, env *Env, spec DialSpec, h healthSource) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(spec.Factories) == 0 || !spec.anyEligible() {
		return nil, fmt.Errorf("%w: no carrier factory", ErrNoPath)
	}
	if spec.EarlyReturn && spec.Params.Kind == wire.KindDatagram {
		return nil, fmt.Errorf("%w: EarlyReturn is for stream sessions", ErrProtocol)
	}
	p := spec.Params
	p.Role = RoleDialer
	if p.Mode == 0 {
		p.Mode = ModeSelector
	}
	spec.Params = p
	s := &Session{env: env, p: p, id: spec.SID, meta: bytes.Clone(spec.Metadata)}
	s.done = make(chan struct{})
	s.mb.init()
	a := newActor(s)
	d := newDialer(spec, h)
	a.d = d
	s.mu.Lock()
	s.initStreamLocked()
	win := s.openWindowLocked() // the window of OPEN
	s.ctl.state = StatePending
	s.ctl.epoch = p.FirstEpoch - 1 // the first publication is FirstEpoch
	s.ctl.echoed = p.FirstEpoch - 1
	s.ctl.rescuedBase = ^uint64(0)
	s.initialSnapLocked()
	if spec.EarlyReturn {
		// M4-D12: Close and Abort close s.closing, so a Read or CloseWrite
		// after them sees it closed and triggers nothing (triggerOpen).
		s.closing = make(chan struct{})
		d.closed = s.closing
	}
	s.mu.Unlock()
	d.open = openPayload(s, win)
	if h != nil {
		d.gauges = h.Gauges()
		d.release = h.Hold()
		d.unsub = h.Subscribe(&s.mb)
	}
	if spec.EarlyReturn {
		// M4-D9: no attempt before the trigger; the actor runs at the
		// first ring (a trigger's startOpen, Close, a health snapshot).
		d.deferred.Store(true)
		s.mb.actor.Store(a)
		return s, nil
	}
	d.started = true
	d.openBy = time.Now().Add(orDefault(p.Grace, defGrace))
	s.mb.actor.Store(a) // rings kick the actor from now on (R1-7)
	a.kick()
	select {
	case err := <-d.result:
		return dialReturn(s, err)
	case <-ctx.Done():
	}
	if d.state.CompareAndSwap(dialWaiting, dialWithdrawn) {
		s.mb.post(&withdraw{})
		return nil, wrapLast(ctx.Err(), d.lastErr())
	}
	return dialReturn(s, <-d.result) // the actor decided first: its result is on the way
}

// eligible reports whether the session may dial factory i (M2-D46): bit i
// of Eligible, every factory when Eligible is 0.
func (spec *DialSpec) eligible(i int) bool {
	return spec.Eligible == 0 || (i < 16 && spec.Eligible&(1<<i) != 0)
}

// anyEligible reports whether the session may dial any of its factories.
func (spec *DialSpec) anyEligible() bool {
	for i := range spec.Factories {
		if spec.eligible(i) {
			return true
		}
	}
	return false
}

// kindClass is factory f's kind class for a session of kind k (M2-D47): a
// packet session ranks its datagram factories (class 0) before its stream
// factories (class 1); a stream session's factories are all class 0.
func kindClass(k wire.CarrierKind, f *carrier.Factory) uint8 {
	if k == wire.KindDatagram && f.Kind != wire.KindDatagram {
		return 1
	}
	return 0
}

func dialReturn(s *Session, err error) (*Session, error) {
	if err != nil {
		return nil, err
	}
	return s, nil
}
