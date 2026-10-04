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
//	    released → OPEN: admitOpen; JOIN: admitJoin; PING: sessionless
//
// The slot covers only the network reads: it is released right after the
// first frame, never held while waiting for the application.

// startHandshake runs the handshake of nc, accepted at at, on its own
// goroutine; the caller already counted it in rt.hsg. It never blocks on
// nc: an evicted handshake's conn is closed on a guarded goroutine.
func (rt *Runtime) startHandshake(ln *Listener, nc net.Conn, at time.Time) {
	if _, owned := nc.(*carrier.OwnedTCP); !owned {
		nc = &onceConn{Conn: nc}
	}
	slot, evicted := rt.hs.admit(nc)
	if evicted != nil {
		carrier.CloseConn(&rt.cenv, evicted) // SetDeadline(now) + Close: its ReadHello fails at once
	}
	go rt.handshake(ln, slot, nc, at)
}

// handshake is one handshake goroutine. Every path closes nc exactly once:
// ReadHello closes it on failure (also on a runtime.Goexit inside a conn
// call); afterwards the carrier owns it (verdicts close it after writing).
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
		}
		return
	}
	if err != nil {
		return
	}
	switch h.First.Type {
	case wire.TypeOpen:
		rt.admitOpen(ln, h, deadline)
	case wire.TypeJoin:
		rt.admitJoin(h, deadline)
	case wire.TypePing:
		c, inst, ok := rt.admitSessionless(h, deadline)
		if !ok {
			return
		}
		// This goroutine now watches the sessionless carrier (rt.slg); it
		// leaves the handshake group, whose join bound is shorter.
		member = false
		rt.hsg.done(rt.abandon)
		rt.watchSessionless(c, inst)
	default: // ReadHello returns only OPEN, JOIN and PING
		h.Conn.Kill(carrier.CauseProtocolViolation, "unexpected first frame "+h.First.Type.String())
	}
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
