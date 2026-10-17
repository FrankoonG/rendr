package rendr

import (
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The passive handshake (design §6.1, plan §3.5, L44, L48):
//
//	source (accept loop | Handle) → startHandshake: a slot; full → evict the
//	    oldest unfinished handshake (its conn closed), never refuse the new one
//	handshake goroutine: carrier.ReadHello under accept + Handshake.Timeout
//	    (PREFACE validated, PREFACE_ACK written, first frame read) → slot
//	    released → OPEN: admitOpen; JOIN: admitJoin; PING: sessionless →
//	    a carrier the admission refused is awaited until it is done
//
// The slot covers the network reads and ReadHello's own PREFACE_ACK
// refusals (VERSION, FEATURE, the gate's CAPACITY or GOING_AWAY), which are
// written and closed inline, bounded by the handshake deadline (the drain
// by at most 1 s of it); on a conn that ignores its deadlines the conn is
// closed as the last resort 1 s + AbandonWait after that deadline (design
// §0.8 V2, §0.9 X5). It is released right after the first frame, never
// held while waiting for the application or for an admission refusal to be
// written.

// startHandshake runs the handshake of nc, accepted at at, on its own
// goroutine; the caller already counted it in rt.hsg. It never blocks on
// nc: an evicted handshake's conn is closed on a goroutine of its own.
// Once Runtime.Close drained the handshake slots no handshake starts: nc is
// closed instead, on the membership the caller took for it, so the drain
// is final and Close's join covers that close too.
func (rt *Runtime) startHandshake(ln *Listener, nc net.Conn, at time.Time) {
	if _, owned := nc.(*carrier.OwnedTCP); !owned {
		nc = &onceConn{Conn: nc}
	}
	slot, evicted := rt.hs.admit(nc, rt.hsg) // an eviction adds its closer to rt.hsg
	if evicted != nil {
		rt.closeWatched(evicted) // SetDeadline(now) + Close: its ReadHello fails at once
	}
	if slot == nil {
		rt.closeWatched(nc) // drained by Runtime.Close
		return
	}
	go rt.handshake(ln, slot, nc, at)
}

// closeWatched closes the conn of an unfinished handshake (eviction,
// Runtime.Close's drain, a handshake refused by that drain, a refusal cut
// by Runtime.Close): SetDeadline(now) and Close each run on a goroutine
// that holds a membership of rt.hsg — the caller added the first, this
// adds the second while that one is held — so the handshake goroutine's
// own call fails at once, and Runtime.Close's bounded join covers both
// closers like the handshake itself. SetDeadline is started first (L52),
// and the Close does not wait for it (design §0.14 B3): a conn whose
// deadline setters wait for a Read in progress — a websocket adapter that
// honours gorilla's one-reader rule — is closed at once, which ends that
// Read and then the SetDeadline. Every call of an unfinished handshake
// runs under a deadline set before it (the handshake deadline, set first
// by ReadHello, or a refusal's write and drain bounds), so a Close that
// happens to run before its SetDeadline leaves no call unbounded. A
// SetDeadline or Close the embedder never returns from is counted in
// Status.Abandoned AbandonWait after it started, by its own watch outside
// Runtime.Close and at the latest by Close's join before it returns (L52),
// exactly as a handshake stuck in a Read.
func (rt *Runtime) closeWatched(nc hsIO) {
	wait := rt.eff.timing.AbandonWait
	rt.hsg.add() // the Close's membership, added while the caller's is held
	rt.hsg.goWatched(rt.abandon, wait, func() { setDeadlineNow(nc) })
	rt.hsg.goWatched(rt.abandon, wait, func() { closeConn(nc) })
}

// setDeadlineNow calls nc.SetDeadline(time.Now()); a panic is contained
// (L51; a runtime.Goexit ends only its own closer goroutine, which
// goWatched settles).
func setDeadlineNow(nc hsIO) {
	defer func() { _ = recover() }()
	_ = nc.SetDeadline(time.Now())
}

// closeConn calls nc.Close(); a panic is contained (L51). nc is an onceConn,
// rendr's own OwnedTCP or a carrier.PacketIO (whose Close is idempotent), so
// the embedder's Close runs once however many closers a handshake's conn
// meets.
func closeConn(nc hsIO) {
	defer func() { _ = recover() }()
	_ = nc.Close()
}

// handshake is one handshake goroutine. Every path closes nc exactly once:
// ReadHello closes it on failure (also on a runtime.Goexit inside a conn
// call); afterwards the carrier owns it (verdicts close it after writing).
// A carrier the admission refused (an answer written with WriteAndClose)
// is awaited before the goroutine leaves rt.hsg, so Runtime.Close joins
// refusals too (awaitRefusal).
func (rt *Runtime) handshake(ln *Listener, slot *hsSlot, nc net.Conn, at time.Time) {
	held, member := true, true
	defer func() {
		if held {
			rt.hs.release(slot) // a runtime.Goexit inside ReadHello
		}
		if member {
			rt.hsg.done(rt.abandon)
		}
	}()
	deadline := at.Add(rt.eff.cfg.Handshake.Timeout)
	h, err := carrier.ReadHello(&rt.cenv, nc, deadline, rt.eff.cfg.Handshake.MaxMetadata, rt.gateFn)
	held = false
	if !rt.hs.release(slot) {
		// Evicted (or drained by Runtime.Close): its conn is being closed.
		if err == nil {
			h.Conn.Kill(carrier.CauseLocalClose, "handshake slot evicted")
			rt.awaitRefusal(h.Conn, nc)
		}
		return
	}
	if err != nil {
		return
	}
	refused := true
	switch h.First.Type {
	case wire.TypeOpen:
		refused = rt.admitOpen(ln, h, deadline, 0, nil)
	case wire.TypeJoin:
		refused = rt.admitJoin(ln, h, deadline, 0, nil)
	case wire.TypePing:
		c, inst, ok := rt.admitSessionless(h, deadline)
		if !ok {
			break
		}
		// This goroutine now watches the sessionless carrier (rt.slg); it
		// leaves the handshake group, whose join bound is shorter.
		refused, member = false, false
		rt.hsg.done(rt.abandon)
		rt.watchSessionless(c, inst)
	default: // ReadHello returns only OPEN, JOIN and PING
		h.Conn.Kill(carrier.CauseProtocolViolation, "unexpected first frame "+h.First.Type.String())
	}
	if refused {
		rt.awaitRefusal(h.Conn, nc)
	}
}

// awaitRefusal holds the handshake goroutine, a member of rt.hsg, until the
// carrier c that the admission refused (or killed) is done: its answer
// written, the conn drained and closed in the L05 order, bounded by the
// handshake deadline and the 1 s drain (the carrier abandons a call that
// ignores them by itself). When the Runtime closes first, the refusal gets
// the close bound — min(1 s, DeadMax) after Close's last shutdown step,
// like a CLOSE frame — and is then cut: nc (the same conn the carrier owns)
// is closed on watched members of rt.hsg (closeWatched), so the write and
// the drain fail at once, and Close joins the end of the carrier (design
// §6.8, L52). Every close of nc goes through its once wrapper (or is a
// second close of rendr's own OwnedTCP), so the embedder's Close still
// runs once (L51).
func (rt *Runtime) awaitRefusal(c *carrier.Conn, nc hsIO) {
	select {
	case <-c.Done():
		return
	case <-rt.cut:
	}
	rt.hsg.add() // the closer's membership, added by a member that still runs (group)
	rt.closeWatched(nc)
	<-c.Done() // this goroutine stands for the carrier's closer in Close's join
}

// onceConn makes Close idempotent for an embedder conn during its
// handshake: eviction and Runtime.Close close the conn of an unfinished
// handshake (SetDeadline(now) + Close, so that even a conn that ignores
// deadlines is released) while that handshake's ReadHello closes it too when
// its read fails. The embedder's Close still runs exactly once (L51), and a
// later Close returns at once instead of waiting for a first one stuck in
// the embedder (no lock is held across an embedder call, design §3.2, §3.8).
// rendr's own *carrier.OwnedTCP is never wrapped: it is the ownership
// token of the vectored-write and CloseWrite paths (L57), and a second Close
// of its *net.TCPConn only returns an error.
type onceConn struct {
	net.Conn
	closed atomic.Bool
}

// Close closes the embedder conn on the first call; later calls return
// net.ErrClosed.
func (c *onceConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return c.Conn.Close()
}

// answerOpen writes one OPEN_ACK refusal as c's first frame and closes c in
// the L05 order, bounded by the handshake deadline (design §6.1). On a view
// admitted on a live MUX trunk the refusal is queued in the trunk's refusal
// ring instead (R1-4): the handle never becomes a session's, and the trunk
// lives (a fixed-size answer: a REJECTED message is not repeated there).
func answerOpen(c *carrier.Conn, a wire.OpenAck, deadline time.Time) {
	if isView(c) {
		c.Refuse(c.Handle(), carrier.Answer{Type: wire.TypeOpenAck, Status: a.Status, Code: a.Code, Window: a.Window})
		return
	}
	if len(a.Msg) > wire.MaxMsg {
		a.Msg = a.Msg[:wire.MaxMsg]
	}
	var b [wire.OpenAckFixedLen + wire.MaxMsg]byte
	n := wire.PutOpenAck(b[:], &a)
	c.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, b[:n], deadline)
}

// answerJoin writes one JOIN_ACK refusal as c's first frame and closes c
// (on a view of a live MUX trunk: an answer in the trunk's refusal ring,
// R1-4). A non-zero code is an UNKNOWN_SESSION's end code, only for a
// carrier that negotiated wire.OptEndCode (admitJoin): its RxNext field
// carries it (PutJoinAckMux's layout, a view's refusal code); 0 writes the
// canonical JOIN_ACK.
func answerJoin(c *carrier.Conn, st wire.AckStatus, code uint32, deadline time.Time) {
	if isView(c) {
		c.Refuse(c.Handle(), carrier.Answer{Type: wire.TypeJoinAck, Status: st, Code: code})
		return
	}
	var b [wire.JoinAckLen]byte
	n := wire.PutJoinAckMux(b[:], &wire.JoinAck{Status: st}, code)
	c.WriteAndClose(wire.TypeJoinAck, 0, wire.SessionHandle, b[:n], deadline)
}

// The passive handshake of a datagram carrier (M2 design §A5.10, §A5.14):
//
//	source (a FromPacketConn flow | HandlePacket) → startHandshakeDatagram:
//	    a slot of the same LRU as stream handshakes (full → evict the
//	    oldest, its transport closed), never refuse the new one
//	handshake goroutine: carrier.ReadHelloDatagram under accept +
//	    Handshake.Timeout (a complete valid H1, H2 written) → slot released →
//	    OPEN: admitOpen; JOIN: admitJoin; PING: sessionless → a carrier the
//	    admission refused (its verdict a reliable REL) is awaited until done
//
// The slot covers the reads up to the first datagram's verdict-free part,
// as for stream carriers; it is never held while waiting for the
// application. The transport is closed exactly once: by ReadHelloDatagram
// on a failure, afterwards by the carrier that owns it.

// startHandshakeDatagram runs the handshake of the datagram transport io,
// accepted at at, on its own goroutine; the caller already counted it in
// rt.hsg (beginHandshake). It never blocks on io: an evicted handshake's
// transport is closed on goroutines of its own. Once Runtime.Close drained
// the handshake slots no handshake starts: io is closed instead, on the
// membership the caller took for it.
func (rt *Runtime) startHandshakeDatagram(ln *Listener, io carrier.PacketIO, at time.Time) {
	slot, evicted := rt.hs.admit(io, rt.hsg) // an eviction adds its closer to rt.hsg
	if evicted != nil {
		rt.closeWatched(evicted) // SetDeadline(now) + Close: its ReadHelloDatagram fails at once
	}
	if slot == nil {
		rt.closeWatched(io) // drained by Runtime.Close
		return
	}
	go rt.handshakeDatagram(ln, slot, io, at)
}

// handshakeDatagram is one datagram handshake goroutine (handshake's
// counterpart). A flow's admitting quota is released when a positive
// verdict was written for it: an accepted JOIN, a started sessionless
// carrier, or the Confirm of its OPEN's session (admitOpen, holdFlow); an
// OPEN flow's also when its dialer answered the address check of H2 (the
// carrier's reader, carrier.SourceChecker), so a pending session holds its
// backlog slot and not its address's quota; otherwise the flow leaves it
// when it is removed (M2-D59). Every exit
// returns the inbox buffer the reader may still hold (Release), so a flow
// leaves nothing charged to the Budget.
func (rt *Runtime) handshakeDatagram(ln *Listener, slot *hsSlot, io carrier.PacketIO, at time.Time) {
	held, member := true, true
	defer func() {
		if held {
			io.Release()        // a runtime.Goexit inside ReadHelloDatagram
			rt.hs.release(slot) // its io is closed by ReadHelloDatagram's own guard
		}
		if member {
			rt.hsg.done(rt.abandon)
		}
	}()
	deadline := at.Add(rt.eff.cfg.Handshake.Timeout)
	h, err := carrier.ReadHelloDatagram(&rt.cenv, io, deadline, rt.eff.cfg.Handshake.MaxMetadata, rt.gateFn)
	held = false
	if err != nil {
		io.Release()
	}
	if !rt.hs.release(slot) {
		// Evicted (or drained by Runtime.Close): its transport is being closed.
		if err == nil {
			h.Conn.Kill(carrier.CauseLocalClose, "handshake slot evicted")
			rt.awaitRefusal(h.Conn, io)
		}
		return
	}
	if err != nil {
		return
	}
	fl := flowOf(io)
	refused := true
	switch h.First.Type {
	case wire.TypeOpen:
		refused = rt.admitOpen(ln, h, deadline, io.Limit(), fl)
	case wire.TypeJoin:
		refused = rt.admitJoin(ln, h, deadline, io.Limit(), fl)
	case wire.TypePing:
		c, inst, ok := rt.admitSessionless(h, deadline)
		if !ok {
			break
		}
		if fl != nil {
			fl.Admitted() // the probe carrier started: its PONG was H2's
		}
		refused, member = false, false
		rt.hsg.done(rt.abandon)
		rt.watchSessionless(c, inst)
	default: // ReadHelloDatagram returns only OPEN, JOIN and PING
		h.Conn.Kill(carrier.CauseProtocolViolation, "unexpected first frame "+h.First.Type.String())
	}
	if refused {
		rt.awaitRefusal(h.Conn, io)
	}
}

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
	early := o.Flags&wire.OpenFlagEarly != 0 // M4-D5: a duplicate OPEN's lane records it
	if r := rt.table.lookup(key, time.Now()); r.found {
		return rt.routeOpen(r, c, fl, o.Kind, early, deadline)
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
		Early:          o.Flags&wire.OpenFlagEarly != 0, // M4-D5: its early DATA may follow before the verdict
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
		return rt.routeOpen(r, c, fl, o.Kind, early, deadline)
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
func (rt *Runtime) routeOpen(r lookupResult[*session.Session], c *carrier.Conn, fl *udpflow.Flow, kind wire.CarrierKind, early bool, deadline time.Time) (refused bool) {
	switch {
	case r.tomb:
		answerOpen(c, r.verdict.OpenAck(), deadline)
	case r.sess == nil: // a passive key never holds a dialer placeholder
		answerOpen(c, wire.OpenAck{Status: wire.StatusUnknownSession}, deadline)
	case rt.sessionKind(r.sess) != kind:
		answerOpen(c, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadKind}, deadline)
	default:
		taken, v := r.sess.AttachOpenEarly(c, early)
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
// another dialer instance cannot find the key, plan §3.4) — on a carrier
// that negotiated wire.OptEndCode (any of its views), an opened session's
// tombstone adds the RST code that session decided (WP13 B-1, L47; 0 for
// none). A live session
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
		answerJoin(c, wire.StatusBadRequest, 0, deadline)
		return true
	}
	j.RxNext = joinOffer(j.RxNext, c.Kind(), limit)
	r := rt.table.lookup(passiveKey(InstanceID(h.Preface.Instance), SessionID(j.SID)), time.Now())
	if !r.found || r.tomb || r.sess == nil {
		var code uint32
		if r.tomb && r.verdict.Opened && c.EndCodes() {
			code = r.verdict.Code // the ended session's own RST (WP13 B-1, L47)
		}
		answerJoin(c, wire.StatusUnknownSession, code, deadline)
		return true
	}
	taken, st := r.sess.Join(c, &j)
	if taken {
		if fl != nil {
			fl.Admitted()
		}
		return false
	}
	var code uint32
	if st == wire.StatusUnknownSession && c.EndCodes() {
		// Ended before Registry.Ended made it a tombstone: the same code
		// (WP13 B-1, L47).
		code = r.sess.EndCode()
	}
	answerJoin(c, st, code, deadline)
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
// handle above 1) rather than the first carrier of a handshake (handle 1;
// a bare Conn's 0 is no view either: it has no trunk to refuse through).
func isView(c *carrier.Conn) bool { return c.Handle() > wire.SessionHandle }

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

// Sessionless (probe) carriers (design §6.4, plan §3.5): a carrier whose
// first frame is a PING belongs to no session. The passive answers that
// PING (recorded by ReadHello) as its first frame, answers later PINGs,
// never PINGs itself and closes after Sessionless.Idle without a PING or
// on the dialer's CLOSE (the carrier does this itself). At most
// Sessionless.PerInstance such carriers per dialer instance and
// Sessionless.Total per Runtime are held; beyond either cap the new one
// gets CLOSE(capacity) and existing ones are never evicted.

// admitSessionless starts h's carrier as a sessionless carrier and counts
// it, or refuses it: CLOSE(capacity) at either cap, GOAWAY when the Runtime
// is closing (its Close may already have taken its snapshot of these
// carriers); the handshake goroutine then awaits the refusal
// (awaitRefusal). On success the caller watches the carrier
// (watchSessionless) on the handshake goroutine, now a member of rt.slg.
func (rt *Runtime) admitSessionless(h *carrier.Hello, deadline time.Time) (*carrier.Conn, InstanceID, bool) {
	c, inst := h.Conn, InstanceID(h.Preface.Instance)
	rt.mu.Lock()
	switch {
	case rt.closing.Load():
		rt.mu.Unlock()
		c.WriteAndClose(wire.TypeGoAway, 0, 0, []byte{byte(wire.GoAwayShutdown)}, deadline)
		return nil, inst, false
	case !rt.slt.acquire(inst):
		rt.mu.Unlock()
		c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, deadline)
		return nil, inst, false
	}
	rt.sl[c] = struct{}{}
	rt.slg.add()
	rt.mu.Unlock()
	c.Start(nil, nil, carrier.StartOptions{Sessionless: true})
	return c, inst, true
}

// watchSessionless waits for the sessionless carrier's end and only then
// frees its place in the caps (design §6.4: the entry is removed at Done,
// so a carrier that is still closing keeps counting).
func (rt *Runtime) watchSessionless(c *carrier.Conn, inst InstanceID) {
	defer rt.slg.done(nil)
	<-c.Done()
	rt.mu.Lock()
	delete(rt.sl, c)
	rt.mu.Unlock()
	rt.slt.release(inst)
}
