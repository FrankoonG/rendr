package rendr

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
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
func (rt *Runtime) closeWatched(nc net.Conn) {
	wait := rt.eff.timing.AbandonWait
	rt.hsg.add() // the Close's membership, added while the caller's is held
	rt.hsg.goWatched(rt.abandon, wait, func() { setDeadlineNow(nc) })
	rt.hsg.goWatched(rt.abandon, wait, func() { closeConn(nc) })
}

// setDeadlineNow calls nc.SetDeadline(time.Now()); a panic is contained
// (L51; a runtime.Goexit ends only its own closer goroutine, which
// goWatched settles).
func setDeadlineNow(nc net.Conn) {
	defer func() { _ = recover() }()
	_ = nc.SetDeadline(time.Now())
}

// closeConn calls nc.Close(); a panic is contained (L51). nc is an onceConn
// or rendr's own OwnedTCP, so the embedder's Close runs once however many
// closers a handshake's conn meets.
func closeConn(nc net.Conn) {
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
		refused = rt.admitOpen(ln, h, deadline)
	case wire.TypeJoin:
		refused = rt.admitJoin(h, deadline)
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
func (rt *Runtime) awaitRefusal(c *carrier.Conn, nc net.Conn) {
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
// the L05 order, bounded by the handshake deadline (design §6.1).
func answerOpen(c *carrier.Conn, a wire.OpenAck, deadline time.Time) {
	if len(a.Msg) > wire.MaxMsg {
		a.Msg = a.Msg[:wire.MaxMsg]
	}
	var b [wire.OpenAckFixedLen + wire.MaxMsg]byte
	n := wire.PutOpenAck(b[:], &a)
	c.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, b[:n], deadline)
}

// answerJoin writes one JOIN_ACK refusal as c's first frame and closes c.
func answerJoin(c *carrier.Conn, st wire.AckStatus, deadline time.Time) {
	var b [wire.JoinAckLen]byte
	n := wire.PutJoinAck(b[:], &wire.JoinAck{Status: st})
	c.WriteAndClose(wire.TypeJoinAck, 0, wire.SessionHandle, b[:n], deadline)
}
