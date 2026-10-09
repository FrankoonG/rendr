package rendr

import (
	"errors"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// admitOpen admits an OPEN carrier (design §6.2), in this order:
// metadata over the limit and malformed OPENs are refused BAD_REQUEST before
// any state exists (L44, L48), as are OPENs whose kind does not fit the
// carrier (M2 design §A3.5); a packet OPEN on a datagram carrier fixes the
// carrier's frame budget, cmtu_acc = min(the dialer's offer, the
// transport's limit), before anything else uses the carrier (M2-D50, R1-5);
// an existing entry routes the carrier (tombstone: its verdict, §6.5; a
// live session of the other kind: BAD_REQUEST CodeBadKind; live session:
// AttachOpen, L47); then a closing Runtime answers GOING_AWAY, a
// closed Listener (whose Runtime runs on) CAPACITY(CodeBacklog), MaxSessions
// and the Listener's backlog of the OPEN's session kind answer CAPACITY;
// otherwise both reservations are taken, the pending session is created
// unstarted outside every admission lock and inserted with insert-or-get
// (D28): the winner starts it and queues it for Accept or AcceptPacket; a
// loser releases both reservations and routes its carrier to the entry that
// won. limit is the transport limit of a datagram carrier (0 on a stream
// carrier) and fl its raw-UDP flow, if any, which leaves its source's
// admitting quota once a positive verdict is written for it (M2-D59) — or
// earlier, once its dialer answered the address check of H2 (the carrier's
// reader, carrier.SourceChecker). It
// reports whether it refused the carrier itself (an answer written with
// WriteAndClose, which the handshake goroutine then awaits).
//
// The same path admits an OPEN for a new handle on a live passive MUX trunk
// (admitView, M3-D21): c is then the new view (handle above 1), ln the
// Listener that accepted the trunk, its refusals go through the trunk's
// refusal ring (answerOpen; R1-4), a closed Listener answers CAPACITY
// CodeListenerClosed instead of CodeBacklog (R1-10: never GOING_AWAY, which
// would make the dialer's Peer give up the instance), and a packet OPEN
// keeps the trunk's budget (no SetBudget after Start, M3-D24). The OPEN
// carrier of a new MUX trunk (handle 1) enters the Runtime trunk set before
// its session starts it (addTrunk).
func (rt *Runtime) admitOpen(ln *Listener, h *carrier.Hello, deadline time.Time, limit int, fl *udpflow.Flow) (refused bool) {
	c := h.Conn
	view := isView(c)
	if c.Mux() && !view {
		rt.addTrunk(c, ln)
	}
	if h.MetaTooLarge {
		answerOpen(c, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize}, deadline)
		return true
	}
	o, err := wire.ParseOpen(h.Payload, rt.eff.cfg.Handshake.MaxMetadata)
	if code, bad := openBadRequest(h.Payload, &o, err, c.Kind()); bad {
		answerOpen(c, wire.OpenAck{Status: wire.StatusBadRequest, Code: code}, deadline)
		return true
	}
	packet := o.Kind == wire.KindDatagram
	var maxPayload int
	if packet {
		var cmtu int
		cmtu, maxPayload = packetAccept(&o, limit, rt.eff.cfg.Packet.MaxPayload)
		if !view {
			c.SetBudget(cmtu) // a no-op on a stream carrier
		}
	}
	key := passiveKey(InstanceID(h.Preface.Instance), SessionID(o.SID))
	if view {
		// §A5.6 step 5: on a live trunk the closed Listener answers first.
		if st, code := ln.viewRefusal(true); st != wire.StatusOK {
			answerOpen(c, wire.OpenAck{Status: st, Code: code}, deadline)
			return true
		}
	}
	if r := rt.table.lookup(key, time.Now()); r.found {
		return rt.routeOpen(r, c, fl, o.Kind, deadline)
	}
	if st, code := ln.viewRefusal(view); st != wire.StatusOK {
		answerOpen(c, wire.OpenAck{Status: st, Code: code}, deadline)
		return true
	}
	if !rt.table.reserve() {
		answerOpen(c, wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeMaxSessions}, deadline)
		return true
	}
	k := kindIdx(o.Kind)
	switch ln.reserve(k) {
	case reserveClosed:
		rt.table.unreserve()
		st, code := ln.viewRefusal(view)
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
	if packet {
		spec.Params = rt.eff.packetParams(spec.Params, maxPayload)
		spec.MaxPayload = maxPayload
	}
	s := session.NewPending(&ln.env, spec, c)
	if packet {
		rt.trackFlows(s, fl) // before the session is visible: every later carrier finds its record
	}
	r, inserted := rt.table.insertOrGet(key, s, spec.Params.TombstoneTTL, time.Now())
	if !inserted {
		// Never started: s owns no goroutine and no Budget charge, and its
		// carrier goes to the entry that won (D28).
		rt.untrackFlows(s)
		ln.unreserve(k)
		rt.table.unreserve()
		return rt.routeOpen(r, c, fl, o.Kind, deadline)
	}
	ln.bind(s, k)
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
// which reason code (design §5.3, §6.2; M2 design §A3.5): a parse error is
// CodeBadKind or CodeBadMode when the kind or mode byte is outside the
// format's range, else CodeBadValue (reserved flags or PMTU, zero SID,
// inconsistent lengths, a packet OPEN's pmtu or window out of range); a
// stream OPEN on a datagram carrier is CodeBadKind; a packet OPEN whose
// window (the carrier's cmtu offer) is non-zero on a stream carrier or zero
// on a datagram carrier is CodeBadValue. Modes 1 to 3 (selector, bond and
// race, M3-D28) are admitted.
func openBadRequest(payload []byte, o *wire.Open, err error, carrierKind wire.CarrierKind) (code uint32, bad bool) {
	if err != nil {
		if errors.Is(err, wire.ErrValue) && len(payload) >= wire.OpenFixedLen {
			if k := wire.CarrierKind(payload[16]); k != wire.KindStream && k != wire.KindDatagram {
				return wire.CodeBadKind, true
			}
			if m := payload[17]; m < 1 || m > 3 {
				return wire.CodeBadMode, true
			}
		}
		return wire.CodeBadValue, true
	}
	dgCarrier := carrierKind == wire.KindDatagram
	switch {
	case o.Kind == wire.KindStream && dgCarrier:
		return wire.CodeBadKind, true
	case o.Kind == wire.KindDatagram && (o.Window == 0) == dgCarrier:
		return wire.CodeBadValue, true
	case Mode(o.Mode) < ModeSelector || Mode(o.Mode) > ModeRace:
		return wire.CodeBadMode, true
	}
	return 0, false
}

// packetAccept computes a packet OPEN's accepted values (M2-D49, M2-D50,
// M2 design §A5.4): on a datagram carrier whose transport receives at most
// limit bytes (limit 0: a stream carrier) the frame budget cmtu_acc =
// min(the dialer's offer OPEN.window, limit); the session's MaxPayload
// pmtu_acc = min(OPEN.pmtu, own Packet.MaxPayload), and at most
// cmtu_acc − 25 when the OPEN came on a datagram carrier and the dialer's
// own offer fit its datagram budget (pmtu ≤ window − 25: it meant datagram
// carriers to carry everything).
func packetAccept(o *wire.Open, limit, ownMax int) (cmtu, maxPayload int) {
	maxPayload = min(int(o.PMTU), ownMax)
	if limit == 0 {
		return 0, maxPayload
	}
	cmtu = min(int(o.Window), limit)
	if int(o.PMTU) <= int(o.Window)-wire.DgramOverhead {
		maxPayload = min(maxPayload, cmtu-wire.DgramOverhead)
	}
	return cmtu, maxPayload
}

// routeOpen routes an OPEN carrier to an existing entry (design §6.2,
// §6.5): a tombstone repeats its verdict (L47: REJECTED, CAPACITY or
// GOING_AWAY for a session that never opened, UNKNOWN_SESSION for one that
// did or was withdrawn); an OPEN of kind other than the live session's is
// BAD_REQUEST CodeBadKind (M2 design §A3.5: a datagram carrier on a stream
// session, or a stream-kind OPEN on a packet session, is a protocol
// violation of that carrier, never the session's); a live session takes it with AttachOpen (pending:
// parked until the verdict; open: adopted with OPEN_ACK(OK)) or returns the
// verdict to answer (CAPACITY CodeCarriers, BAD_REQUEST for a carrier ID it
// already attached, an ended session's verdict). A datagram carrier's
// budget was set by admitOpen before (R1-5). It reports whether it answered
// the carrier itself.
func (rt *Runtime) routeOpen(r lookupResult[*session.Session], c *carrier.Conn, fl *udpflow.Flow, kind wire.CarrierKind, deadline time.Time) (refused bool) {
	switch {
	case r.tomb:
		answerOpen(c, r.verdict.OpenAck(), deadline)
	case r.sess == nil: // a passive key never holds a dialer placeholder
		answerOpen(c, wire.OpenAck{Status: wire.StatusUnknownSession}, deadline)
	case rt.sessionKind(r.sess) != kind:
		answerOpen(c, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadKind}, deadline)
	default:
		taken, v := r.sess.AttachOpen(c)
		if taken {
			rt.holdFlow(r.sess, fl)
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
// UNKNOWN_SESSION; mode; the carrier's kind and a packet session's cmtu
// offer, M2 design §A3.5; carrier limit; rxNext), and the root writes the
// status of a JOIN it did not take. A datagram carrier's cmtu offer is
// first bounded by its transport's limit (joinOffer), so the session fixes
// cmtu_acc = min(rxNext, limit) as for an OPEN (M2 design §A5.4, M2-D50).
// An accepted JOIN's raw-UDP flow leaves its source's admitting quota
// (M2-D59). It reports whether it answered the carrier itself.
//
// ln is the Listener that accepted the carrier: the JOIN carrier of a new
// MUX trunk enters the Runtime trunk set with it (addTrunk), so OPENs that
// later arrive on that trunk are admitted to its queues. A JOIN for a new
// handle on a live trunk (admitView) takes the same path; its refusals go
// through the trunk's refusal ring (answerJoin).
func (rt *Runtime) admitJoin(ln *Listener, h *carrier.Hello, deadline time.Time, limit int, fl *udpflow.Flow) (refused bool) {
	c := h.Conn
	if c.Mux() && !isView(c) {
		rt.addTrunk(c, ln)
	}
	j, err := wire.ParseJoin(h.Payload)
	if err != nil {
		answerJoin(c, wire.StatusBadRequest, deadline)
		return true
	}
	j.RxNext = joinOffer(j.RxNext, c.Kind(), limit)
	r := rt.table.lookup(passiveKey(InstanceID(h.Preface.Instance), SessionID(j.SID)), time.Now())
	if !r.found || r.tomb || r.sess == nil {
		answerJoin(c, wire.StatusUnknownSession, deadline)
		return true
	}
	taken, st := r.sess.Join(c, &j)
	if taken {
		if fl != nil {
			fl.Admitted()
		}
		return false
	}
	answerJoin(c, st, deadline)
	return true
}

// admitView is the Runtime's carrier.Env.Admit (M3-D21, §A5.6): an OPEN or
// JOIN for a new handle on a started passive MUX trunk, on the trunk's
// reader. v is the new view (pending or joining, shim endpoint), already
// counted against the trunk's view cap; the carrier checked the cap, the
// payload decode and our GOAWAY. The rest is the handshake admission's path
// (admitOpen, admitJoin) with v as the carrier: JOINs never wait behind
// OPENs (they take no backlog or MaxSessions check, L48), the OPEN pools
// are the trunk's Listener's, and every refusal decided here is an answer
// in the trunk's refusal ring (R1-4). It never blocks: table lookups,
// leaf-lock sections, a session's NewPending/Start, and posts to a
// session's mailbox. p is valid only during the call: what outlives it is
// copied (the session copies its metadata and JOIN).
func (rt *Runtime) admitView(v *carrier.Conn, hdr wire.Header, p []byte) {
	rec, _ := v.OwnerTag().(*trunkRec)
	if rec == nil {
		// Not in the trunk set (cannot happen: a MUX trunk is registered
		// before its session starts it): refuse without a penalty.
		v.Refuse(v.Handle(), carrier.Answer{Type: respType(hdr.Type), Status: wire.StatusCapacity, Code: wire.CodeMuxFull})
		return
	}
	rec.viewAdded()
	h := &carrier.Hello{Conn: v, First: hdr, Payload: p}
	h.Preface.Instance = v.PeerInstance()
	h.Preface.CarrierID = v.ID()
	switch hdr.Type {
	case wire.TypeOpen:
		if o, err := wire.ParseOpen(p, wire.MaxMetadata); err == nil && len(o.Metadata) > rt.eff.cfg.Handshake.MaxMetadata {
			h.MetaTooLarge = true
		}
		rt.admitOpen(rec.ln, h, time.Time{}, v.MTU(), nil)
	case wire.TypeJoin:
		rt.admitJoin(rec.ln, h, time.Time{}, v.MTU(), nil)
	default:
		v.Refuse(v.Handle(), carrier.Answer{Type: respType(hdr.Type), Status: wire.StatusBadRequest, Code: wire.CodeBadValue})
	}
}

// isView reports whether c is a view admitted on a started MUX trunk (a
// handle above 1) rather than the first carrier of a handshake.
func isView(c *carrier.Conn) bool { return c.Handle() != wire.SessionHandle }

// respType is the response type of a first frame type.
func respType(t wire.Type) wire.Type {
	if t == wire.TypeJoin {
		return wire.TypeJoinAck
	}
	return wire.TypeOpenAck
}

// joinOffer bounds a JOIN's cmtu offer by the transport limit of the
// datagram carrier it came on (M2 design §A5.4: the passive's cmtu_acc =
// min(rxNext, io.Limit())). A stream carrier's rxNext (a stream session's
// delivered offset, or a packet session's 0) and an offer outside
// [MinFrameBudget, MaxDatagram], which the session refuses as it is, are
// returned unchanged.
func joinOffer(rxNext uint64, k wire.CarrierKind, limit int) uint64 {
	if k != wire.KindDatagram || limit <= 0 || rxNext < wire.MinFrameBudget || rxNext > wire.MaxDatagram {
		return rxNext
	}
	return min(rxNext, uint64(limit))
}

// lnRegistry is the session.Registry of the passive sessions a Listener
// admitted: it moves their table entries between the SessionCounts
// categories, turns an ended entry into a tombstone answering the verdict
// (design §6.5), frees the session's backlog slot when it leaves
// StatePending, releases the admitting quota of a packet session's flows
// once it opened, and remembers an ended session until its Done closes, for
// Runtime.Close. Sessions call it without holding their lock.
type lnRegistry struct{ ln *Listener }

var _ session.Registry = lnRegistry{}

func passiveKeyOf(s *session.Session) tableKey {
	return passiveKey(InstanceID(s.PeerInstance()), SessionID(s.ID()))
}

// Opened: Confirm opened the session; its backlog slot is free, and the
// OPEN_ACK(OK) it writes is the positive verdict of its flows.
func (r lnRegistry) Opened(s *session.Session) {
	r.ln.rt.table.opened(passiveKeyOf(s), s)
	r.ln.leavePending(s)
	r.ln.rt.flowsOpened(s)
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
	rt.untrackFlows(s)
}
