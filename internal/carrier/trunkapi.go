package carrier

import (
	"encoding/binary"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The owner's handle on a trunk (M3 design §A4.5, §A4.6, §A5.6; M3-D22,
// M3-D26): package rendr keeps the passive MUX trunks in its Runtime trunk
// set, records the Listener that accepted each of them, closes a passive
// trunk that stays without views and joins every trunk at Runtime.Close.
// It reaches the trunk through the handshake's view 1 (or any view of it).
// These methods are no-ops (or zero) on a bare Conn without a trunk.

// TrunkDone is closed when every goroutine of the physical carrier finished
// or was abandoned (the trunk's own Done; on a dedicated carrier it is
// Done). A nil channel on a bare Conn.
func (c *Conn) TrunkDone() <-chan struct{} {
	if c.trunk == nil {
		return nil
	}
	return c.tdone
}

// Views returns the views of the trunk that are not gone (§A5.4: opening,
// awaiting, attached-pending, live and retiring on the dialer; pending,
// joining, held, live and retiring on the passive) — the count the close
// at the last view reads (M3-D20, M3-D22). A dedicated carrier reports 1
// until its end.
func (c *Conn) Views() int {
	if c.trunk == nil {
		return 0
	}
	return c.viewCount()
}

// SetOwnerTag records the owner's record of the trunk (package rendr: the
// Runtime trunk set's entry, with the Listener that accepted the trunk,
// §A5.6); OwnerTag returns it (nil until set).
func (c *Conn) SetOwnerTag(x any) {
	if c.trunk == nil {
		return
	}
	c.mx.Lock()
	c.listener = x
	c.mx.Unlock()
}

// OwnerTag returns the record SetOwnerTag stored (nil when none).
func (c *Conn) OwnerTag() any {
	if c.trunk == nil {
		return nil
	}
	c.mx.Lock()
	defer c.mx.Unlock()
	return c.listener
}

// OnViewEnd registers f, called once for every view of the trunk whose
// Done closed, on a goroutine of its own (the passive owner's view-count
// transition, M3-D22; the dialer's pool registers its own hook). Only a
// MUX trunk's views have their own Done; one hook per trunk.
func (c *Conn) OnViewEnd(f func(*Conn)) {
	if c.trunk == nil {
		return
	}
	c.onViewDone(f)
}

// RetireTrunk seals the trunk (no new view) and retires the physical
// carrier with CLOSE(r) (M2's Retire): the close of a passive MUX trunk
// without views (M3-D22) and of a dedicated carrier. Idempotent.
func (c *Conn) RetireTrunk(r wire.CloseReason) {
	if c.trunk == nil {
		return
	}
	c.seal()
	c.retireTrunk(r)
}

// GoAwayTrunk seals the trunk and queues GOAWAY(shutdown) once ahead of
// any further frame, then retires it (Runtime.Close on a trunk without
// views, M3-D26). Idempotent.
func (c *Conn) GoAwayTrunk() {
	if c.trunk == nil {
		return
	}
	c.seal()
	t := c.trunk
	t.mu.Lock()
	t.st.goAway = true
	if !t.st.retiring {
		t.st.retiring, t.st.reason = true, wire.CloseRetire
	}
	t.mu.Unlock()
	t.wakeWriter()
}

// TrunkDying reports that the physical carrier recorded its death (every
// view then ends with it).
func (c *Conn) TrunkDying() bool { return c.trunk != nil && c.death.Load() != nil }

// TrunkCloseSent reports that the physical carrier wrote its CLOSE (handle
// 0): its retirement drains (L05) and needs no kill at a close bound. A
// view's CloseSent also reports the view's own DETACH.
func (c *Conn) TrunkCloseSent() bool { return c.trunk != nil && c.closeSent.Load() }

// nearFull reports a batch that may refuse an endpoint's control frame
// although it is not Full: fewer than two frames left, or less control
// arena than the largest session control frame (an RST or OPEN_ACK with
// its message, a SCHED) needs. The MUX writer keeps a view whose call
// placed nothing in such a batch ready for the next round (drrRound).
func (b *Batch) nearFull() bool {
	return b.n >= MaxBatchFrames-2 || b.ctl > ControlArena-(wire.RstFixedLen+wire.MaxMsg+wire.HeaderLen)
}

// patchViewOffer writes a datagram trunk's current send budget into the
// first frame of a view opened on it (§A3.3, M3-D24): a packet OPEN
// offers it in OPEN.window, a JOIN in JOIN.rxNext, as buildH1 does for
// handle 1; the passive answers within it. p is the view's own copy.
func patchViewOffer(kind wire.Type, p []byte, budget int) {
	switch {
	case kind == wire.TypeOpen && len(p) >= wire.OpenFixedLen:
		binary.BigEndian.PutUint32(p[24:28], uint32(budget))
	case kind == wire.TypeJoin && len(p) >= 25:
		binary.BigEndian.PutUint64(p[17:25], uint64(budget))
	}
}

// rstWithdrawnPayload is the RST(AbortWithdrawn) payload a withdrawn OPEN
// view places before its DETACH (R1-5 rule 1).
var rstWithdrawnPayload = func() []byte {
	var p [wire.RstFixedLen]byte
	return p[:wire.PutRst(p[:], &wire.Rst{Code: wire.RstWithdrawn})]
}()
