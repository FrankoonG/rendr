package rendr

import (
	"errors"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// admitOpen admits an OPEN carrier (design §6.2), in this order:
// metadata over the limit and malformed OPENs are refused BAD_REQUEST before
// any state exists (L44, L48); an existing entry routes the carrier
// (tombstone: its verdict, §6.5; live session: AttachOpen, L47); then a
// closing Runtime answers GOING_AWAY, a closed Listener (whose Runtime runs
// on) CAPACITY(CodeBacklog), MaxSessions and the Listener's backlog answer
// CAPACITY; otherwise both reservations are taken, the pending session is
// created unstarted outside every admission lock and inserted with
// insert-or-get (D28): the winner starts it and queues it for Accept; a
// loser releases both reservations and routes its carrier to the entry that
// won. It reports whether it refused the carrier itself (an answer written
// with WriteAndClose, which the handshake goroutine then awaits).
func (rt *Runtime) admitOpen(ln *Listener, h *carrier.Hello, deadline time.Time) (refused bool) {
	c := h.Conn
	if h.MetaTooLarge {
		answerOpen(c, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize}, deadline)
		return true
	}
	o, err := wire.ParseOpen(h.Payload, rt.eff.cfg.Handshake.MaxMetadata)
	if code, bad := openBadRequest(h.Payload, &o, err); bad {
		answerOpen(c, wire.OpenAck{Status: wire.StatusBadRequest, Code: code}, deadline)
		return true
	}
	key := passiveKey(InstanceID(h.Preface.Instance), SessionID(o.SID))
	if r := rt.table.lookup(key, time.Now()); r.found {
		return routeOpen(r, c, deadline)
	}
	if st, code := ln.refusal(); st != wire.StatusOK {
		answerOpen(c, wire.OpenAck{Status: st, Code: code}, deadline)
		return true
	}
	if !rt.table.reserve() {
		answerOpen(c, wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeMaxSessions}, deadline)
		return true
	}
	switch ln.reserve() {
	case reserveClosed:
		rt.table.unreserve()
		st, code := ln.refusal()
		answerOpen(c, wire.OpenAck{Status: st, Code: code}, deadline)
		return true
	case reserveFull:
		rt.table.unreserve()
		answerOpen(c, wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog}, deadline)
		return true
	}
	spec := session.PassiveSpec{
		SID:            o.SID,
		Params:         rt.eff.passiveParams(Mode(o.Mode), o.RetainMs, ln.cfg.AcceptTimeout),
		DialerInstance: h.Preface.Instance,
		PeerWindow:     o.Window,
		Metadata:       o.Metadata,
	}
	s := session.NewPending(&ln.env, spec, c)
	r, inserted := rt.table.insertOrGet(key, s, spec.Params.TombstoneTTL, time.Now())
	if !inserted {
		// Never started: s owns no goroutine and no Budget charge, and its
		// carrier goes to the entry that won (D28).
		ln.unreserve()
		rt.table.unreserve()
		return routeOpen(r, c, deadline)
	}
	ln.bind(s)
	s.Start()
	if rt.closing.Load() {
		// Runtime.Close may have taken its session snapshot before this
		// insert; the session is shut down here instead (GOING_AWAY).
		s.Shutdown()
	}
	ln.enqueue(s)
	return false
}

// openBadRequest decides whether an OPEN is answered BAD_REQUEST and with
// which reason code (design §5.3, §6.2): a parse error is CodeBadKind or
// CodeBadMode when the kind or mode byte is outside the format's range,
// else CodeBadValue (reserved flags or PMTU, zero SID, inconsistent
// lengths); a well-formed OPEN of another kind than stream (M2) is
// CodeBadKind, mode race (M3) CodeBadMode.
func openBadRequest(payload []byte, o *wire.Open, err error) (code uint32, bad bool) {
	if err != nil {
		if errors.Is(err, wire.ErrValue) && len(payload) >= wire.OpenFixedLen {
			if k := wire.CarrierKind(payload[16]); k != wire.KindStream && k != wire.KindDatagram {
				return wire.CodeBadKind, true
			}
			return wire.CodeBadMode, true
		}
		return wire.CodeBadValue, true
	}
	switch {
	case o.Kind != wire.KindStream:
		return wire.CodeBadKind, true
	case Mode(o.Mode) != ModeSelector && Mode(o.Mode) != ModeBond:
		return wire.CodeBadMode, true
	}
	return 0, false
}

// routeOpen routes an OPEN carrier to an existing entry (design §6.2,
// §6.5): a tombstone repeats its verdict (L47: REJECTED, CAPACITY or
// GOING_AWAY for a session that never opened, UNKNOWN_SESSION for one that
// did or was withdrawn); a live session takes it with AttachOpen (pending:
// parked until the verdict; open: adopted with OPEN_ACK(OK)) or returns the
// verdict to answer (CAPACITY CodeCarriers, an ended session's verdict). It
// reports whether it answered the carrier itself.
func routeOpen(r lookupResult[*session.Session], c *carrier.Conn, deadline time.Time) (refused bool) {
	switch {
	case r.tomb:
		answerOpen(c, r.verdict.OpenAck(), deadline)
	case r.sess == nil: // a passive key never holds a dialer placeholder
		answerOpen(c, wire.OpenAck{Status: wire.StatusUnknownSession}, deadline)
	default:
		taken, v := r.sess.AttachOpen(c)
		if taken {
			return false
		}
		answerOpen(c, v.OpenAck(), deadline)
	}
	return true
}

// admitJoin routes a JOIN carrier (design §6.3; L48: no OPEN capacity,
// backlog or MaxSessions check applies). The Runtime answers only what the
// table decides: no entry or a tombstone is UNKNOWN_SESSION (a JOIN from
// another dialer instance cannot find the key, plan §3.4). A live session
// decides everything else under its own lock (pending: BAD_REQUEST; ended:
// UNKNOWN_SESSION; mode; carrier limit; rxNext), and the root writes the
// status of a JOIN it did not take. It reports whether it answered the
// carrier itself.
func (rt *Runtime) admitJoin(h *carrier.Hello, deadline time.Time) (refused bool) {
	c := h.Conn
	j, err := wire.ParseJoin(h.Payload)
	if err != nil {
		answerJoin(c, wire.StatusBadRequest, deadline)
		return true
	}
	r := rt.table.lookup(passiveKey(InstanceID(h.Preface.Instance), SessionID(j.SID)), time.Now())
	if !r.found || r.tomb || r.sess == nil {
		answerJoin(c, wire.StatusUnknownSession, deadline)
		return true
	}
	taken, st := r.sess.Join(c, &j)
	if taken {
		return false
	}
	answerJoin(c, st, deadline)
	return true
}

// lnRegistry is the session.Registry of the passive sessions a Listener
// admitted: it moves their table entries between the SessionCounts
// categories, turns an ended entry into a tombstone answering the verdict
// (design §6.5), frees the session's backlog slot when it leaves
// StatePending, and remembers an ended session until its Done closes, for
// Runtime.Close. Sessions call it without holding their lock.
type lnRegistry struct{ ln *Listener }

var _ session.Registry = lnRegistry{}

func passiveKeyOf(s *session.Session) tableKey {
	return passiveKey(InstanceID(s.PeerInstance()), SessionID(s.ID()))
}

// Opened: Confirm opened the session; its backlog slot is free.
func (r lnRegistry) Opened(s *session.Session) {
	r.ln.rt.table.opened(passiveKeyOf(s), s)
	r.ln.leavePending(s)
}

// Lingering moves the session into (or out of) the Lingering count.
func (r lnRegistry) Lingering(s *session.Session, on bool) {
	r.ln.rt.table.setLingering(passiveKeyOf(s), s, on)
}

// Orphaned moves the session into (or out of) the Orphaned count.
func (r lnRegistry) Orphaned(s *session.Session, on bool) {
	r.ln.rt.table.setOrphaned(passiveKeyOf(s), s, on)
}

// Ended replaces the entry by a tombstone answering v for the session's
// TombstoneTTL and releases its MaxSessions unit and backlog slot. The
// session is recorded for Runtime.Close first (noteEnded), so that Close's
// snapshot finds it in the table or in its draining list.
func (r lnRegistry) Ended(s *session.Session, v session.Verdict) {
	rt := r.ln.rt
	rt.noteEnded(s)
	rt.table.ended(passiveKeyOf(s), s, v, time.Now())
	r.ln.leavePending(s)
}
