package rendr

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
)

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
//
// ctx bounds only the Dial: cancelling it after Dial returned does not
// affect the session.
func (p *Peer) Dial(ctx context.Context, o DialOptions) (*Conn, error) {
	rt := p.rt
	switch m := rt.eff.cfg.Handshake.MaxMetadata; {
	case p.isClosed() || rt.closing.Load():
		return nil, net.ErrClosed
	case o.Mode > ModeBond:
		return nil, fmt.Errorf("rendr: Dial: unknown %v: %w", o.Mode, ErrProtocol)
	case len(o.Metadata) > m:
		return nil, fmt.Errorf("rendr: Dial: %d bytes of metadata, limit %d: %w", len(o.Metadata), m, ErrMetadataTooLarge)
	case rt.abandon.Full():
		return nil, fmt.Errorf("%w: %w", ErrCapacity, carrier.ErrAbandonFull)
	}
	sid, err := newSessionID(rand.Reader)
	if err != nil {
		return nil, err
	}
	if !rt.table.placeDialer(sid) {
		return nil, fmt.Errorf("rendr: Dial: local MaxSessions %d reached: %w", rt.eff.cfg.MaxSessions, ErrCapacity)
	}
	if h := rt.eff.hooks; h != nil && h.DialBegin != nil {
		h.DialBegin()
	}
	if !rt.beginDial() {
		rt.table.ended(dialerKey(sid), nil, session.Verdict{}, time.Now())
		return nil, net.ErrClosed
	}
	reg := &dialReg{rt: rt, sid: sid}
	s, created, err := p.open(ctx, sid, o, reg)
	if err != nil {
		// The placeholder's MaxSessions unit is free at once; the session's
		// own Ended, if it comes later, finds nothing to release.
		rt.table.ended(dialerKey(sid), nil, session.Verdict{}, time.Now())
		if !created || !reg.handOver() {
			rt.dial.done(nil)
		}
		if rt.closing.Load() && ctx.Err() == nil {
			return nil, net.ErrClosed // the Runtime closed during the Dial
		}
		return nil, err
	}
	// The attach and the closing check run before rt.dial.done: Runtime.Close
	// either finds the session live in the table after setting closing, or
	// this check sees closing and shuts the session down itself.
	rt.table.attach(sid, s) // false: the session already ended; its Conn reports the end error
	if rt.closing.Load() {
		s.Shutdown()
		rt.dial.done(nil)
		return nil, net.ErrClosed
	}
	rt.dial.done(nil)
	return newConn(rt, s), nil
}

// open runs the opening phase of session sid (design §6.6): the cold-start
// wait for probe evidence (Health.Use, WaitFirst) and session.Dial, under a
// context that also ends when the Runtime closes. session.Dial holds the
// Peer's health layer itself for the session's lifetime. created reports
// whether session.Dial created a session — then that session calls reg's
// Ended exactly once, also when Dial failed (it withdraws in the
// background).
func (p *Peer) open(ctx context.Context, sid SessionID, o DialOptions, reg *dialReg) (s *session.Session, created bool, err error) {
	rt := p.rt
	dctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stop := context.AfterFunc(rt.ctx, func() { cancel(net.ErrClosed) })
	defer stop()
	if p.health != nil {
		p.health.Use()
		p.health.WaitFirst(dctx)
	}
	env := p.env
	env.Registry = reg
	ec := &entryCtx{Context: dctx}
	spec := p.spec(sid, o)
	s, err = session.Dial(ec, &env, spec)
	// session.Dial's documented contract: it creates no session (and makes
	// no Registry call) when ctx is done at its entry check — its first Err
	// call — or when spec has no factory (never here: NewPeer requires
	// one). TestSessionDialEntryContract pins both, so that a change on the
	// session side fails visibly instead of leaving a Dial membership that
	// no Registry.Ended ever releases.
	return s, ec.live.Load() && len(spec.Factories) > 0, err
}

// spec is the frozen DialSpec of session sid (L20): the Peer's factory
// snapshot and the per-Dial Params (design §10.4 step 4).
func (p *Peer) spec(sid SessionID, o DialOptions) session.DialSpec {
	return session.DialSpec{
		SID:        sid,
		Params:     p.rt.eff.dialerParams(o.Mode, o.NoPathGrace),
		Factories:  p.factories,
		Health:     p.health,
		Metadata:   o.Metadata,
		GoneAway:   p.goneAway,
		NoteGoAway: p.noteGoAway,
	}
}

// beginDial counts one more Dial inside session.Dial unless the Runtime is
// closing (then Close no longer waits for new members).
func (rt *Runtime) beginDial() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closing.Load() {
		return false
	}
	rt.dial.add()
	return true
}

// entryCtx is the context Peer.Dial hands to session.Dial. session.Dial
// creates a session — which then calls Registry.Ended exactly once, also
// when Dial fails — unless ctx was already done at its entry check, its
// first call of Err (its contract: no session and no Registry call then).
// entryCtx records that first result, so that a failed Dial knows whether
// a session withdraws in the background that Runtime.Close must join.
type entryCtx struct {
	context.Context
	once sync.Once
	live atomic.Bool // the first Err call returned nil
}

func (c *entryCtx) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { c.live.Store(err == nil) })
	return err
}

// dialReg is the session.Registry of one dialer session (design §6.6): it
// keeps the session's table entry (the MaxSessions unit, the Lingering
// count) and records the session for Runtime.Close until its Done closes.
// When the Dial failed after session.Dial had created the session, that
// session withdraws in the background and reports Ended later: the Dial
// then stays a member of the Runtime's in-flight Dial group until that
// Ended (handOver), so Runtime.Close joins the withdrawing session too.
type dialReg struct {
	rt  *Runtime
	sid SessionID

	mu    sync.Mutex
	ended bool // Ended ran
	owed  bool // the failed Dial left its group membership to Ended
}

var _ session.Registry = (*dialReg)(nil)

// Opened is a passive-side transition: Peer.Dial attaches a dialer session
// to its table placeholder when Dial returns.
func (*dialReg) Opened(*session.Session) {}

// Orphaned counts only passive sessions (SessionCounts.Orphaned).
func (*dialReg) Orphaned(*session.Session, bool) {}

// Lingering moves the session into (or out of) the Lingering count.
func (r *dialReg) Lingering(s *session.Session, on bool) {
	r.rt.table.setLingering(dialerKey(r.sid), s, on)
}

// Ended records the session for Runtime.Close, then removes its table entry
// (releasing its MaxSessions unit unless Peer.Dial's failure path already
// did) and, for a failed Dial that handed its membership over, ends it.
func (r *dialReg) Ended(s *session.Session, _ session.Verdict) {
	rt := r.rt
	rt.noteEnded(s)
	rt.table.ended(dialerKey(r.sid), s, session.Verdict{}, time.Now())
	r.mu.Lock()
	r.ended = true
	owed := r.owed
	r.mu.Unlock()
	if owed {
		rt.dial.done(nil)
	}
}

// handOver leaves the failed Dial's membership of rt.dial to Ended. It
// returns false when Ended already ran: the caller ends the membership.
func (r *dialReg) handOver() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return false
	}
	r.owed = true
	return true
}
