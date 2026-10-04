package rendr

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
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
	if !rt.beginDial() {
		rt.table.ended(dialerKey(sid), nil, session.Verdict{}, time.Now())
		return nil, net.ErrClosed
	}
	defer rt.dial.done(nil)
	s, err := p.open(ctx, sid, o)
	if err != nil {
		return nil, err
	}
	// The attach and the closing check run before rt.dial.done: Runtime.Close
	// either finds the session live in the table after setting closing, or
	// this check sees closing and shuts the session down itself.
	rt.table.attach(sid, s) // false: the session already ended; its Conn reports the end error
	if rt.closing.Load() {
		s.Shutdown()
		return nil, net.ErrClosed
	}
	return newConn(rt, s), nil
}

// open runs the opening phase of session sid (design §6.6): the Peer's
// health hold, the cold-start wait for probe evidence and session.Dial, all
// under a context that also ends when the Runtime closes. On failure the
// dialer placeholder (MaxSessions unit) and the hold are released here; the
// session's own Registry.Ended, if it comes later, finds nothing to release.
func (p *Peer) open(ctx context.Context, sid SessionID, o DialOptions) (*session.Session, error) {
	rt := p.rt
	dctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stop := context.AfterFunc(rt.ctx, func() { cancel(net.ErrClosed) })
	defer stop()
	p.hold(sid)
	if p.health != nil {
		p.health.Use()
		p.health.WaitFirst(dctx)
	}
	var s *session.Session
	err := dctx.Err()
	if err == nil {
		s, err = session.Dial(dctx, &p.env, p.spec(sid, o))
	}
	if err == nil {
		return s, nil
	}
	p.unhold(sid)
	rt.table.ended(dialerKey(sid), nil, session.Verdict{}, time.Now())
	if rt.closing.Load() && ctx.Err() == nil {
		return nil, net.ErrClosed // the Runtime closed during the Dial
	}
	return nil, err
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
