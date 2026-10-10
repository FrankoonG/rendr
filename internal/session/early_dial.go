package session

import (
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// EarlyReturn on the dialer (M4 design §A4.1 … §A4.3; WP9a): the deferred
// opening and its trigger, the pre-verdict admission cap, the session's one
// early span, the winning lane's in-flight span, and Close and Abort
// before the verdict.
//
// States (§A4.1). A session that Dial returned with DialSpec.EarlyReturn is
// deferred (dialer.deferred set, StatePending) until its first Write, Read
// or CloseWrite (triggerOpen), opening (dialer.started, StatePending) until
// its first OPEN_ACK(OK) or a terminal outcome, then open as any dialer.
// Every terminal outcome of the opening ends the session with Dial's error
// (failOpeningLocked), which the next Read and Write return.
//
// The early span (R1-2): at the first OPEN attempt after the trigger the
// actor fixes k0 = min(end, EarlyDataMax) (the committed bytes, never
// sNext) and takes a reference on the send chunks holding [0, k0); the
// first attempt goroutine copies them once into the session's span and
// drops the references (earlySpan.bytes), outside every lock. Every OPEN
// attempt carries exactly that span (a fresh carrier sends it with
// wire.OpenFlagEarly; a fast-path or coalesced view sends nothing early).
// At the first OPEN_ACK(OK) sNext moves to k0, the winner's kw =
// Established.Early bytes are in flight on its lane and [kw, k0) is
// requeued (earlyVerdictLocked).

// triggerOpen starts the opening of a session that Dial returned with
// EarlyReturn: the first caller to clear dialer.deferred posts startOpen
// (M4-D9). After Close or Abort (dialer.closed is closed) it does nothing,
// so a Read or CloseWrite that follows them opens nothing (M4-D12). Read
// and CloseWrite call it first; Write calls it right after a
// round's bytes were committed, so the first attempt's early span
// includes them (R1-15), and earlyCapLocked calls it when the cap holds a
// Write back. It never blocks and takes only the mailbox's leaf lock, so
// callers may hold s.mu. A no-op for every other session (one immutable
// field compare on the passive, one atomic load on an opened dialer).
func (s *Session) triggerOpen() {
	if s.p.Role != RoleDialer {
		return
	}
	a := s.mb.actor.Load()
	if a == nil || a.d == nil {
		return
	}
	d := a.d
	if !d.deferred.Load() {
		return
	}
	select {
	case <-d.closed:
		// Close or Abort came first: the session ends locally and sends
		// nothing (M4-D12); earlyCloseLocked claims deferred.
		return
	default:
	}
	if d.deferred.CompareAndSwap(true, false) {
		s.mb.post(&startOpen{}) // false only after the actor exited: nothing to open
	}
}

// earlyCapLocked bounds Write's reservation while a dialer session is
// pending (M4-D10, R1-2): room is what the window leaves; the result keeps
// resEnd ≤ FirstOffset + EarlyDataMax until the verdict (0: the Write
// waits for it on wwake, which the verdict rings: earlyVerdictLocked, or
// the end). A Write held back by the cap triggers the opening itself, so
// a session whose cap admits nothing (EarlyDataMax 0) still opens at its
// first Write. It returns room unchanged for every session that is not a
// pending dialer.
func (s *Session) earlyCapLocked(room int64) int64 {
	if s.p.Role != RoleDialer || s.ctl.state != StatePending {
		return room
	}
	lim := s.p.FirstOffset + uint64(earlyMax(&s.p))
	if s.st.resEnd >= lim {
		s.triggerOpen()
		return 0
	}
	return min(room, int64(lim-s.st.resEnd))
}

// earlyMax is Params.EarlyDataMax clamped to [0, wire.EarlyWindow] (M4-D16;
// package rendr normalizes it, the clamp keeps the session safe on its own).
func earlyMax(p *Params) int {
	return min(max(p.EarlyDataMax, 0), wire.EarlyWindow)
}

// earlyCloseLocked is terminationLocked's branch for a dialer still in its
// opening phase (M4-D12, M4-D20, AM-8). Nothing applies until the
// application closed (Close or Abort):
//   - never triggered (dialer.deferred still set): the session ends
//     locally with net.ErrClosed — nothing was sent, nothing is;
//   - triggered but startOpen not handled yet (a Write committed its
//     bytes, or a Read or CloseWrite ran, and Close followed before this
//     step): the opening starts now, so those bytes keep Close's meaning
//     (a trigger after the Close is none: triggerOpen);
//   - Abort: the opening is withdrawn at once (RST(AbortWithdrawn) where
//     an OPEN was written: the end withdraws every attempt, C25);
//   - Close: Linger counts from the Close; at closeAt + Linger the
//     opening is withdrawn (Status().Err net.ErrClosed), until then the
//     deadline is armed and the opening continues; on OPEN_ACK(OK) the
//     open session keeps the linger from the same instant (st.closedAt).
func (a *actor) earlyCloseLocked(now time.Time) {
	d, st := a.d, &a.s.st
	if !st.closed {
		return
	}
	if d.deferred.Load() && d.deferred.CompareAndSwap(true, false) {
		a.earlyEndLocked(now, net.ErrClosed)
		return
	}
	if !d.started {
		a.onStartOpenLocked(now) // the trigger's startOpen is still on its way
	}
	if st.abortReq != nil {
		a.earlyEndLocked(now, net.ErrClosed)
		return
	}
	if d.closeAt.IsZero() {
		d.closeAt = st.closedAt
	}
	by := d.closeAt.Add(orDefault(a.s.p.Linger, defLinger))
	if !now.Before(by) {
		a.earlyEndLocked(now, net.ErrClosed)
		return
	}
	a.want(by)
}

// onStartOpenLocked handles startOpen: the deferred opening starts — the
// opening race and cadence that Dial runs (dialActLocked, in this step),
// openBy = now + Grace. The early span is fixed by the first OPEN attempt
// (earlySpanLocked). A session that ended, or whose opening already
// started (earlyCloseLocked started it), ignores it.
func (a *actor) onStartOpenLocked(now time.Time) {
	d := a.d
	if d == nil || d.started || a.ending {
		return
	}
	d.started = true
	d.openBy = now.Add(orDefault(a.s.p.Grace, defGrace))
}

// earlyEndLocked ends an EarlyReturn session before its verdict (a Close
// or Abort, the Linger after a Close) with err: the end procedure
// withdraws every attempt. failOpeningLocked emits the event the same way.
func (a *actor) earlyEndLocked(now time.Time, err error) {
	if a.ending {
		return
	}
	a.terminateLocked(now, err, nil, false)
	a.earlyEndEventLocked(now, err)
}

// earlyEndEventLocked emits EventSessionEnd for an EarlyReturn session
// that ends before its verdict: the application holds its Conn, so the end
// is reported (§A4.4), unlike a classic Dial's failure, which returns no
// session (actor.event emits nothing for an unopened dialer).
func (a *actor) earlyEndEventLocked(now time.Time, err error) {
	if d := a.d; d == nil || !d.spec.EarlyReturn || a.s.env.Events == nil {
		return
	}
	a.events = append(a.events, Event{Kind: EventSessionEnd, Session: a.s.id, Err: err, Time: now})
	a.worked = true
}

// earlySpan is the session's one early span [FirstOffset, FirstOffset+k)
// (R1-2). The actor fixes k and references the chunks under s.mu
// (earlySpanLocked); the first attempt goroutine that needs the bytes
// copies them into b — the one allocation per session — and drops the
// references (bytes). b is read-only afterwards and shared by every
// attempt. The span is fixed with the first OPEN attempt, which runs bytes
// first thing on its own goroutine, so the references are always dropped.
type earlySpan struct {
	once  sync.Once
	k     int
	pos   int             // the span's first byte in src[0]
	src   [2]*carrier.Buf // the chunks holding the span, referenced until the copy
	b     []byte          // the copy
	fixed bool            // (A) the span was fixed (k may be 0)
}

// bytes returns the span, copying it on the first call. nil-safe (no span).
func (e *earlySpan) bytes() []byte {
	if e == nil {
		return nil
	}
	e.once.Do(e.copyOut)
	return e.b
}

// copyOut copies the span out of its chunks and drops their references.
func (e *earlySpan) copyOut() {
	b := make([]byte, e.k)
	n := copy(b, e.src[0].B[e.pos:])
	if n < e.k {
		copy(b[n:], e.src[1].B)
	}
	for i, c := range e.src {
		c.Release() // nil-safe
		e.src[i] = nil
	}
	e.b = b
}

// earlySpanLocked returns the session's early span for an OPEN attempt,
// fixing it at the first call (R1-2): k0 = min(end, EarlyDataMax) of the
// committed bytes, the chunks referenced for the copy. nil when the session
// carries no early bytes: not an EarlyReturn session, a packet session
// (M4-D14), k0 == 0, or a non-zero Params.FirstOffset (a test preset: the
// carrier writes the early DATA frame at wire offset 0).
func (a *actor) earlySpanLocked() *earlySpan {
	d, s := a.d, a.s
	e := &d.early
	if !e.fixed {
		e.fixed = true
		st := &s.st
		if d.spec.EarlyReturn && s.pk == nil && s.p.FirstOffset == 0 {
			e.k = int(min(st.end-s.p.FirstOffset, uint64(earlyMax(&s.p))))
		}
		if e.k > 0 {
			off := s.p.FirstOffset
			c, pos := st.chunkFor(off)
			c.Ref()
			e.src[0], e.pos = c, pos
			if first := chunkSize - pos; first < e.k {
				c2, _ := st.chunkFor(off + uint64(first))
				c2.Ref()
				e.src[1] = c2
			}
		}
	}
	if e.k == 0 {
		return nil
	}
	return e
}

// earlyVerdictLocked applies the early span at the first OPEN_ACK(OK) on
// the winner's lane l (M4-D7, R1-2, M4-D18): EarlyBytes = kw, the
// winner's Established.Early (k0, or 0 for a fast-path or coalesced
// view); if k0 > 0, sNext = max(sNext, k0) — any byte below k0 may have
// reached the passive on some carrier, so its ACKs and JOIN_ACK rxNext up
// to k0 are legal —, [0, kw) is in flight on l (resent only if l dies, L10)
// and, in selector and bond, [kw, k0) is requeued (duplicates are dropped
// by offset at the passive, L47). A race winner's cursor starts at kw and
// every other member sends its own copies (M3-D30): no retx entry.
func (a *actor) earlyVerdictLocked(now time.Time, l *lane, kw int) {
	s := a.s
	st := &s.st
	e := &a.d.early
	st.earlyBytes = uint64(kw)
	k0 := uint64(e.k)
	if k0 == 0 {
		return
	}
	base := s.p.FirstOffset
	st.sNext = max(st.sNext, base+k0)
	l.infl.add(base, uint64(kw))
	if s.p.Mode == ModeRace {
		l.rnext = base + uint64(kw)
	} else if uint64(kw) < k0 {
		st.retx.add(base+uint64(kw), k0-uint64(kw))
	}
	s.wakeDataLocked(now)
}

// PeerBound reports whether the session is bound to its peer instance:
// always for a passive session; for a dialer once its first OPEN_ACK(OK)
// was accepted (before Dial returns, except with EarlyReturn: M4-D15).
// PeerInstance is final once it reports true.
func (s *Session) PeerBound() bool {
	return s.p.Role == RolePassive || s.bound.Load()
}
