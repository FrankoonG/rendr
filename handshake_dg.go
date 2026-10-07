package rendr

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

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
// carrier, or the Confirm of its OPEN's session (admitOpen, holdFlow);
// otherwise the flow leaves it when it is removed (M2-D59). Every exit
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
		refused = rt.admitJoin(h, deadline, io.Limit(), fl)
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
