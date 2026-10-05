package session

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
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
	// index.
	Eligible uint16
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
	if len(spec.Factories) == 0 {
		return nil, fmt.Errorf("%w: no carrier factory", ErrNoPath)
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
	s.mu.Unlock()
	d.open = openPayload(s, win)
	d.openBy = time.Now().Add(orDefault(p.Grace, defGrace))
	if h != nil {
		d.gauges = h.Gauges()
		d.release = h.Hold()
		d.unsub = h.Subscribe(&s.mb)
	}
	go a.run()
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

func dialReturn(s *Session, err error) (*Session, error) {
	if err != nil {
		return nil, err
	}
	return s, nil
}
