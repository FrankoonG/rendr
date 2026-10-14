package carrier

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The writer of a datagram carrier (M2-D12, M2-D25, M2-D29; M2 design §A5.8
// and Revision 1, R1-2, R1-4, R1-8). writeRound stays the shared loop and
// hands a datagram carrier's rounds to dgWriteRound.

// dgWriteRound runs one round of a datagram carrier: death checks; under
// Conn.mu the datagram mode (budget, REL room), the H2 repeat and the
// rebind challenge (datagrams of their own), and the carrier control —
// RACK, PONG, the challenge PONG, the REL retransmission, a due PING (none
// while held), GOAWAY; Fill (held, R1-8: the first response releases the
// hold in this round and the first PING may follow it); CLOSE last when
// retiring. After our CLOSE the rounds place only RACKs and REL
// retransmissions (M2-D31). It returns false when the writer must exit:
// the carrier ended.
func (c *Conn) dgWriteRound(w *writer) bool {
	if c.death.Load() != nil {
		return false
	}
	now := time.Now()
	if c.checkDeadlines(now) {
		return false
	}
	dg := c.dg
	b := w.b
	b.Reset(now)
	w.ping, w.pingJudged, w.pingAtEnd, w.pingEnd, w.close = false, false, false, false, false
	w.probe, w.retx, w.rack, w.pingAt, w.rackAt = false, false, false, -1, -1
	closing := c.closeSent.Load()

	c.mu.Lock()
	st := &c.st
	room := dg.rel.room()
	if closing {
		room = 0 // nothing new follows our CLOSE
	}
	b.SetDatagram(int(dg.budget.Load()), room)
	h2 := dg.hs.repeatH2
	dg.hs.repeatH2 = false
	chal, cand, nonce := c.chalSendLocked(now)
	kill := c.dgControlLocked(w, b, now, closing)
	retiring, reason := st.retiring, st.reason
	c.mu.Unlock()
	if kill {
		c.killCarrier(CausePingTimeout, "mtu probe")
		return false
	}

	if !closing {
		n := b.Len()
		c.fillRound(b) // the endpoint frames (nothing on a carrier without a session)
		epFrames := b.Len() > n
		if w.held && epFrames {
			// The first response released the hold (R1-8); the first
			// PING may follow it (the dialer keeps the response
			// datagram's tail, R1-1).
			w.held = false
			dg.held.Store(false)
			if !retiring {
				c.mu.Lock()
				kill = c.dgPingLocked(w, b, now)
				c.mu.Unlock()
				if kill {
					b.ReleaseRefs()
					c.killCarrier(CausePingTimeout, "mtu probe")
					return false
				}
			}
		}
		if retiring && !epFrames && b.addClose(reason) {
			w.close = true // REL{CLOSE}: the last frame we place
		}
	}
	if b.relCount() > 0 || b.relRefused() {
		c.mu.Lock()
		c.relSealLocked(b)
		if b.relRefused() {
			// A reliable frame found no REL room: a RACK with progress wakes
			// the writer (§A5.9); room freed since SetDatagram wakes it now.
			if dg.rel.room() > 0 {
				c.wakeWriter()
			} else {
				dg.rel.blocked = true
			}
		}
		c.mu.Unlock()
	}
	if b.Len() == 0 && !h2 && !chal {
		return c.dgSleep(w, now)
	}
	if b.Len() > 0 {
		w.fseq = b.seal(w.fseq)
	}
	return c.dgWriteBatch(w, b, now, h2, chal, cand, nonce)
}

// dgControlLocked appends the round's carrier control (§A5.8): the RACK
// when one is due (latest state wins); in closing rounds only the REL
// retransmission besides it; otherwise the PONG (its pad clamped to this
// side's budget, M2-D24), the challenge PONG, the REL retransmission, a due
// PING (never while held or retiring) and GOAWAY. kill reports a fourth
// unanswered MTU probe.
func (c *Conn) dgControlLocked(w *writer, b *Batch, now time.Time, closing bool) (kill bool) {
	dg := c.dg
	st := &c.st
	if r := &dg.rel; r.rackDue {
		rk := r.rackLocked()
		if b.addRack(&rk) {
			r.rackDue = false
			w.rack, w.rackCum, w.rackAt = true, rk.CumAck, b.Len()-1
		}
	}
	if closing {
		c.dgRetxLocked(w, b, now)
		return false
	}
	if st.pongDue {
		p := st.pong
		p.Pad = min(p.Pad, max(int(dg.budget.Load())-wire.FrameOverhead-wire.PingFixedLen, 0))
		if b.addPong(&p) {
			st.pongDue = false
		}
	}
	if ch := &dg.chal; ch.pongDue && b.addPong(&ch.pong) {
		ch.pongDue = false
	}
	c.dgRetxLocked(w, b, now)
	if !st.retiring && !w.held {
		kill = c.dgPingLocked(w, b, now)
	}
	if st.goAway && !st.goAwaySent && b.addGoAway(wire.GoAwayShutdown) {
		st.goAwaySent = true
	}
	return kill
}

// dgRetxLocked appends the retransmission of una when its timer expired:
// a new outer frame around the byte-identical REL payload (PA-21); one per
// round, single flight (M2-D16).
func (c *Conn) dgRetxLocked(w *writer, b *Batch, now time.Time) {
	r := &c.dg.rel
	if !c.relRetxDueLocked(now) {
		return
	}
	s := &r.slot[r.una%wire.RelWindow]
	if b.addRelRetx(s.b[:s.n]) {
		w.retx, w.retxCseq = true, r.una
	}
}

// dgPingLocked appends a due PING (cadence, retry or MTU probe); kill
// reports a fourth unanswered MTU probe.
func (c *Conn) dgPingLocked(w *writer, b *Batch, now time.Time) (kill bool) {
	k, _ := c.dgPingDueLocked(now)
	if k == pingNone {
		return false
	}
	kill = c.dgEncodePingLocked(w, b, now, k)
	if w.ping {
		w.pingAt = b.Len() - 1
	}
	return kill
}

// dgWriteBatch writes the round's datagrams (§A5.8): the stored H2 first and
// alone, the challenge alone to its candidate, then the sealed frames packed
// into datagrams under the budget (M2-D12) — through the transport's
// BatchIO in flushes of up to MaxBatch datagrams (dgWriteFlushes, M5 design
// §A4.3), or, on a transport without one, each built once in the writer's
// scratch after Headroom() bytes and handed to WriteDatagram, with
// Hooks.BeforeWrite before it (M2-D29). One stall window and one
// SetWriteDeadline cover the round. Per datagram: written; refused as too
// large — the budget shrinks (M2-D25), its DGRAM counts Refused and its
// PING record goes; lost to noise — Dropped; any other error ends the
// carrier (an invalid count included: never retried, L42), and so does a
// death record found before a write: nothing more is written, and the
// DGRAMs of the datagrams no write carried go back to their sessions
// after the death (dgReturnUnsent). After an invalid count none of the
// datagrams the misreporting call was given goes back — which of them
// left is unknown — but the round's later ones, which no call was given,
// do. The PING is committed when the write that carried it returns (L23);
// the rest of the commit follows under Conn.mu: the REL timer per R1-2,
// the CLOSE and the retirement checks (R1-4).
func (c *Conn) dgWriteBatch(w *writer, b *Batch, now time.Time, h2, chal bool, cand PeerKey, nonce uint64) bool {
	dg := c.dg
	io := dg.io
	c.mu.Lock()
	srtt := c.st.srtt
	check := dg.chal.check
	c.mu.Unlock()
	// One arm per round, as in M2 (M5 design A4.3 item 5 as decided at
	// R3-21): the stall window and the write deadline cover the whole
	// round's bytes (wireLen), however many WriteDatagrams calls its
	// flushes take. The watchdog guards against a stalled socket, not
	// against latency, and a round's bytes are bounded by the queue budget.
	stall := sched.StallWindow(srtt, b.wireLen(), 0, c.tm.WriteStall, c.tm.DeadMax)
	gen := c.wstate.Load() >> 1
	c.armWatchdog(gen, now, stall)
	_ = io.SetWriteDeadline(now.Add(stall)) // a transport without deadlines still has the watchdog's stage 2
	hr := io.Headroom()
	hook := c.env.Hooks
	rs := dgRound{budget: int(dg.budget.Load()), pinged: w.ping, unsent: -1}
	if h2 {
		d := append(w.dscratch.B[:hr], dg.hs.h2()...)
		if check != 0 {
			// The address check is still unanswered (its PONG may have been
			// lost): the repeat carries it at a fresh fseq instead of the
			// first one, so the dialer's window takes it and Establish
			// answers it again. Same size, still one datagram per duplicate
			// H1: no amplification (SourceChecker).
			var pp [wire.PingFixedLen]byte
			wire.PutPing(pp[:], &wire.Ping{Nonce: check})
			d = wire.AppendFrame(d[:len(d)-wire.FrameOverhead-wire.PingFixedLen], wire.Header{Type: wire.TypePing, Fseq: w.fseq}, pp[:])
			w.fseq++
		}
		if hook != nil && hook.BeforeWrite != nil {
			hook.BeforeWrite(c.id, 1, len(d))
		}
		rs.fatal = c.dgControlWritten(io.WriteDatagram(d))
	}
	if rs.fatal == nil && chal {
		var pp [wire.PingFixedLen]byte
		wire.PutPing(pp[:], &wire.Ping{ID: 0, TS: uint64(now.Sub(c.base)), Nonce: nonce})
		d := wire.AppendFrame(w.dscratch.B[:hr], wire.Header{Type: wire.TypePing, Fseq: w.fseq}, pp[:])
		w.fseq++
		if hook != nil && hook.BeforeWrite != nil {
			hook.BeforeWrite(c.id, 1, len(d))
		}
		rs.fatal = c.dgControlWritten(io.WriteDatagramTo(d, cand))
	}
	if rs.fatal != nil {
		rs.unsent = 0 // none of the round's frames was written
	}
	if w.bio != nil {
		c.dgWriteFlushes(w, b, &rs, now)
	} else {
		for i := 0; rs.fatal == nil && i < b.Len(); {
			end, _ := b.nextDatagram(i, rs.budget)
			d := b.appendDatagram(w.dscratch.B[:hr], i, end)
			if hook != nil && hook.BeforeWrite != nil {
				hook.BeforeWrite(c.id, end-i, len(d))
			}
			if c.death.Load() != nil {
				rs.fatal, rs.unsent = errWriteDead, i // nothing more is written on a dead carrier
				break
			}
			err := io.WriteDatagram(d)
			c.dgOutcome(w, b, &rs, i, end, end, err, now, time.Now()) // the call carried this datagram alone
			i = end
		}
	}
	end := time.Now()
	c.disarmWatchdog(gen)
	if fatal := rs.fatal; fatal != nil {
		c.dgWriteFailed(fatal)
		c.dgReturnUnsent(b, rs.unsent) // after the death: the session re-routes them
		b.ReleaseRefs()
		return false
	}
	b.ReleaseRefs() // the writes returned: the chunk references go
	if w.close {
		c.closeSent.Store(true) // attempted: REL{CLOSE} is retransmitted until RACKed
	}
	c.mu.Lock()
	c.commitLocked(w, b, end, end) // w.ping is false here: the PING was committed with its datagram
	c.st.txBytes += rs.txb
	c.relAttemptedLocked(w.retx, w.retxCseq, end)
	if rs.rackWritten && dg.peerCloseSeen && !wire.SeqLess(w.rackCum, dg.peerCloseCseq) {
		dg.peerCloseRacked = true
	}
	finish := c.dgRetireDoneLocked()
	c.mu.Unlock()
	if w.retx {
		dg.ctr.retransmits.Add(1)
		if hook != nil && hook.RelRetransmit != nil {
			hook.RelRetransmit(c.id, w.retxCseq)
		}
	}
	if rs.pinged {
		if o := c.opts.Observer; o != nil {
			o.PingCommitted(c, w.pingID, rs.pingT)
		}
	}
	if finish {
		c.finishRetire("retired: CLOSE exchange complete")
		return false
	}
	if w.close {
		c.dgCloseWritten()
	}
	return c.death.Load() == nil
}

// dgWriteFailed ends the carrier after a fatal outcome of its round: a
// budget below the control floor and any other write error kill it
// (write_stall for a deadline, else transport_error), unless the peer's
// CLOSE already arrived (the retirement completes). On a carrier that is
// already dead (errWriteDead) it changes nothing: the first death record
// stays.
func (c *Conn) dgWriteFailed(fatal error) {
	if fatal == errBudgetFloor {
		c.killCarrier(CauseTransportError, fatal.Error())
		return
	}
	if c.endIfPeerClosed("write ended (" + fatal.Error() + ")") {
		return
	}
	cause := CauseTransportError
	if errors.Is(fatal, os.ErrDeadlineExceeded) {
		cause = CauseWriteStall
	}
	c.killCarrier(cause, "write: "+fatal.Error())
}

// DgramReturner is implemented by a PacketEndpoint that takes back the
// DGRAMs its datagram carrier placed and never wrote (M5 pktloss; L39:
// only data in flight on a dead carrier may be lost). The writer of a
// round that ends the carrier hands back every DGRAM of the round's
// unwritten datagrams: after a fatal write error, the datagram the
// transport refused that way and every later one (never given to it);
// after a death record found before a write, that write's and every later
// one. It does so after the carrier's death record is set, so the session
// places them again on a live carrier (or counts them where its queue
// would): a datagram rendr knows never left is neither lost uncounted nor
// sent twice. A write that returned an invalid count (L42: an error
// matching ErrWriteCount or udpsocket.ErrInvalidCount, or a batched count
// of a shape it cannot have) is the exception: which of the datagrams that
// call was given left is unknown — a transport that misreports its count
// may have sent them — so none of them goes back, while the round's
// datagrams after that call, which no call was given, do.
type DgramReturner interface {
	// Unsent hands back the DGRAM of session seq seq: p aliases buf.B and
	// the reference on buf moves to the endpoint (kept or released). It is
	// called on the carrier's writer goroutine, in seq order per endpoint,
	// with no carrier lock held, and must not block.
	Unsent(c *Conn, seq uint64, p []byte, buf *Buf)
}

// dgReturnUnsent hands the DGRAMs of the round's sealed frames [from,
// b.Len()) back to their views' endpoints (DgramReturner), each with a
// reference of its own on its chunk, before ReleaseRefs drops the batch's
// (from < 0: nothing). A DGRAM without a chunk (component tests), of a
// handle no view holds any more, or of an endpoint that takes nothing back
// is dropped as before.
func (c *Conn) dgReturnUnsent(b *Batch, from int) {
	if from < 0 {
		return
	}
	for k := from; k < b.n; k++ {
		f := &b.frames[k]
		if f.hdr.Type != wire.TypeDgram || f.chunk == nil {
			continue
		}
		v := c.trunk.route(f.hdr.Handle)
		if v == nil {
			continue
		}
		r, ok := v.pep.(DgramReturner)
		if !ok {
			continue
		}
		f.chunk.Ref()
		r.Unsent(v, f.off, f.body, f.chunk)
	}
}

// errWriteDead: the round found the carrier's death record before a write
// (another goroutine killed it while the round was built or written):
// nothing more is written on it.
var errWriteDead = errors.New("rendr/carrier: carrier died during the write round")

// ErrWriteCount is the identity of an invalid write count (L42, PA-19): a
// datagram write that reported another count than the datagram's length,
// or a batched write whose count has a shape it cannot have. errors.Is
// matches it for every such error of the datagram transports — the
// embedder adapter's (a *countError of a WriteTo), rendr's own sockets'
// (errUDPWriteCount), a batched write's (errBatchCount) and udpflow's
// foreign-conn writes — and the batch calls' own udpsocket.ErrInvalidCount
// stands beside it (isWriteCount). The carrier dies, and the writer hands
// back none of the datagrams the misreporting call was given: the count
// lied, so they may have left (dgOutcome, DgramReturner).
var ErrWriteCount = errors.New("rendr/carrier: datagram write returned an invalid count")

// isWriteCount reports whether err is an invalid write count (L42):
// ErrWriteCount, or udpsocket.ErrInvalidCount from a batch call.
func isWriteCount(err error) bool {
	return errors.Is(err, ErrWriteCount) || errors.Is(err, udpsocket.ErrInvalidCount)
}

// dgRound is what a round's datagram writes build up for its commit.
type dgRound struct {
	budget      int       // the send budget the round packs under (lowered by a refusal)
	txb         uint64    // DGRAM bytes written (Stats.TxBytes)
	rackWritten bool      // a written datagram carried the round's RACK
	pinged      bool      // the round's PING left: PingCommitted is reported
	pingT       time.Time // its commit time
	fatal       error     // the error that ends the carrier
	unsent      int       // with fatal: the first sealed frame whose DGRAM goes back (dgReturnUnsent; -1: none)
}

// dgOutcome applies the result err of the write of the datagram of sealed
// frames [i, end), which returned at ret, to the round (§A5.8): the PING
// it carried is committed at ret, written or lost to noise (L23);
// written — counted, the DGRAM's bytes and the RACK mark; too large —
// Refused, the PING record goes, the budget shrinks (M2-D25); noise —
// Dropped; else the error ends the carrier: this datagram and the round's
// rest never left — unless err is an invalid count (isWriteCount, L42):
// then which of the datagrams of the call that carried this one left is
// unknown, and only those after that call, from callEnd (the first sealed
// frame after it: its flush's end, or end for a call of this datagram
// alone), go back. It reports whether the budget changed: the datagrams
// packed after this one under the old budget are then packed again.
func (c *Conn) dgOutcome(w *writer, b *Batch, rs *dgRound, i, end, callEnd int, err error, now, ret time.Time) (shrank bool) {
	dg := c.dg
	n, hasDgram := b.datagramDgram(end)
	ping := w.ping && w.pingAt >= i && w.pingAt < end
	if ping && (err == nil || errors.Is(err, ErrNoise)) {
		// The PING is committed at the return of the write that carried it
		// (L23), not at the end of the round: the rest of the round's
		// writes neither stretch its RTT sample nor let its PONG arrive
		// before the commit.
		rs.pingT = ret
		c.mu.Lock()
		c.commitPingLocked(w, ret)
		c.mu.Unlock()
		w.ping = false
	}
	switch {
	case err == nil:
		dg.ctr.datagrams.Add(1)
		if hasDgram {
			dg.lastDgram.Store(c.dgSince(now))
			rs.txb += uint64(n)
		}
		if w.rackAt >= i && w.rackAt < end {
			rs.rackWritten = true
		}
	case errors.Is(err, wire.ErrDatagramTooLarge):
		if hasDgram {
			dg.ctr.refused.Add(1)
		}
		if ping {
			c.mu.Lock()
			c.dgUnsentPingLocked(w) // it never left; a probe counts unanswered
			c.mu.Unlock()
			rs.pinged = false
		}
		if c.dgShrink(err) {
			rs.fatal, rs.unsent = errBudgetFloor, end // this one counted Refused; the rest never left
			return false
		}
		before := rs.budget
		rs.budget = int(dg.budget.Load())
		return rs.budget != before
	case errors.Is(err, ErrNoise):
		c.dgDropped(1) // this datagram is lost; the carrier lives
	case isWriteCount(err):
		// L42: the call that carried this datagram misreported its count —
		// a transport that sent a datagram and returned (len+1, nil) or
		// (0, nil), a sendmmsg count beyond its call — so its datagrams may
		// have left, and one handed back would be sent twice. Those after
		// the call were given to no call.
		rs.fatal, rs.unsent = err, callEnd
	default:
		rs.fatal, rs.unsent = err, i // this datagram and the round's rest never left
	}
	return false
}

// dgArenaSize is the size requested for a round's arena: the 64 KiB class
// of DBufs, which holds the largest datagram (wire.MaxDatagram with its
// flow header) (M5-D11).
const dgArenaSize = 64 << 10

// dgWriteFlushes writes the round's sealed frames through the transport's
// BatchIO (M5 design §A4.3; L55, L23, M2-D25, M2-D29): the datagrams are
// packed in order into the round's arena (one DBufs buffer of the 64 KiB
// class, charged to the stage account, taken here and released at the
// end; it holds copies, never a chunk reference) and flushed with one
// WriteDatagrams call when the flush holds MaxBatch datagrams, the arena
// cannot hold the next one, the datagram carrying the round's PING was
// just added — so that PING commits at the return of the call that wrote
// it (L23) — or the round's frames are exhausted: batching never waits for
// frames (L55). Hooks.BeforeWrite runs for each datagram, in order, before
// the call that carries it. The result is mapped datagram by datagram
// (dgOutcome): ds[:n] written; ds[n] refused — the rest of the round is
// packed again from the frame after it if the budget shrank, else the
// flush goes on with ds[n+1:] — lost to noise (the flush goes on with
// ds[n+1:]) or fatal (the round's unsent datagrams are never written:
// dgReturnUnsent hands their DGRAMs back). A death record found before a
// call is fatal for that call's datagrams. A count outside [0, len], a
// short count without an error, or a full count with one, is fatal
// (errBatchCount, L42), and so is an invalid count the transport reports
// as ds[n]'s error (isWriteCount): which of the call's datagrams left is
// unknown, so none of ds[n:] goes back — only the datagrams of the flushes
// after it, which no call was given. Counters move only for the written
// indexes, at the call's return (L55).
func (c *Conn) dgWriteFlushes(w *writer, b *Batch, rs *dgRound, now time.Time) {
	if b.Len() == 0 {
		return
	}
	bio := w.bio
	hr := c.dg.io.Headroom()
	hook := c.env.Hooks
	maxB := min(max(bio.MaxBatch(), 1), MaxBatchFrames)
	w.arena = c.dbufs().Get(dgArenaSize, c.env.stageBudget())
	var ends [MaxBatchFrames]int // the frame end of each datagram of the flush
	for i := 0; rs.fatal == nil && i < b.Len(); {
		first := i
		arena := w.arena.B[:0]
		var ds [][]byte
		nd := 0
		for i < b.Len() && nd < maxB {
			end, n := b.nextDatagram(i, rs.budget)
			if nd > 0 && len(arena)+hr+n > cap(arena) {
				break // the arena is full: flush, then go on
			}
			var ln int
			ds, ln = b.appendDatagramArena(i, end, arena[:len(arena)+hr])
			arena = arena[:ln]
			if hook != nil && hook.BeforeWrite != nil {
				hook.BeforeWrite(c.id, end-i, len(ds[nd]))
			}
			ends[nd] = end
			nd++
			ping := w.ping && w.pingAt >= i && w.pingAt < end
			i = end
			if ping {
				break // the PING's datagram ends its flush (L23)
			}
		}
		for sent := 0; sent < nd && rs.fatal == nil; {
			if c.death.Load() != nil {
				rs.fatal, rs.unsent = errWriteDead, dgStart(first, ends[:], sent) // nothing more is written on a dead carrier
				break
			}
			k, err := bio.WriteDatagrams(ds[sent:nd])
			ret := time.Now()
			if k < 0 || k > nd-sent || (err == nil) != (k == nd-sent) {
				// Out of range, short without an error, or an error for a
				// datagram past the last (L42): which of the call's
				// datagrams left is unknown, so none of them is handed
				// back; the flushes after it were given to no call.
				rs.fatal, rs.unsent = errBatchCount, ends[nd-1]
				break
			}
			for j := sent; j < sent+k; j++ {
				c.dgOutcome(w, b, rs, dgStart(first, ends[:], j), ends[j], ends[nd-1], nil, now, ret)
			}
			sent += k
			if err == nil {
				break
			}
			j := sent
			sent++
			if c.dgOutcome(w, b, rs, dgStart(first, ends[:], j), ends[j], ends[nd-1], err, now, ret) && sent < nd {
				i = ends[j] // packed under the old budget: pack the rest again
				break
			}
		}
		b.resetFlush()
	}
	w.arena.Release()
	w.arena = nil
}

// dgStart returns the first sealed frame of the flush's j-th datagram: the
// end of the one before it, or first.
func dgStart(first int, ends []int, j int) int {
	if j == 0 {
		return first
	}
	return ends[j-1]
}

// errBatchCount: a batched write reported a count outside the datagrams it
// was given, fewer without an error, or all of them with an error (L42:
// the carrier dies, never retried). It matches ErrWriteCount.
var errBatchCount = fmt.Errorf("%w (a batched write's count of a shape it cannot have)", ErrWriteCount)

// errBudgetFloor: a refusal lowered the budget below wire.ControlFloor.
var errBudgetFloor = errors.New("datagram budget below the control floor")

// dgControlWritten classifies the result of a datagram the writer sends
// outside the batch (the H2 repeat, a rebind challenge): too large, noise
// and a transport that cannot rebind lose that datagram only; any other
// error ends the carrier.
func (c *Conn) dgControlWritten(err error) error {
	switch {
	case err == nil:
		c.dg.ctr.datagrams.Add(1)
		return nil
	case errors.Is(err, wire.ErrDatagramTooLarge), errors.Is(err, ErrNoise), errors.Is(err, ErrNoRebind):
		c.dgDropped(1)
		return nil
	}
	return err
}

// dgShrink applies a size refusal (M2-D25): DatagramTooLargeError{Max} with
// 0 < Max < budget lowers the budget to Max (never raised); Max 0 lowers
// nothing (the MTU probe decides). It reports a budget below
// wire.ControlFloor (the carrier dies).
func (c *Conn) dgShrink(err error) bool {
	var te *wire.DatagramTooLargeError
	if !errors.As(err, &te) || te.Max <= 0 {
		return false
	}
	b := &c.dg.budget
	for {
		cur := b.Load()
		if int32(te.Max) >= cur || b.CompareAndSwap(cur, int32(te.Max)) {
			break
		}
	}
	return int(b.Load()) < wire.ControlFloor
}

// dgCloseWritten runs after the round that placed our CLOSE (M2-D31, R1-4):
// the retirement completes when the CLOSE exchange does (dgRetireDoneLocked)
// or at min(max(2·srtt + 100 ms, 3·RTO), 2 s) from now.
func (c *Conn) dgCloseWritten() {
	c.mu.Lock()
	bound := min(max(2*c.st.srtt+100*time.Millisecond, 3*c.relRTOLocked()), dgRetireMax)
	c.mu.Unlock()
	c.jmu.Lock()
	if !c.join.doneClosed {
		c.join.drain = time.AfterFunc(bound, func() { c.finishRetire("retired: drain bound after CLOSE") })
	}
	c.jmu.Unlock()
}

// dgRetireMax caps the datagram retirement after our CLOSE (M2-D31).
const dgRetireMax = 2 * time.Second

// dgRetireDoneLocked reports whether the datagram retirement is complete
// (R1-4): our CLOSE was RACKed (it is our last REL, so nothing is
// outstanding), the peer's CLOSE was dispatched and a written datagram
// carried a RACK covering it.
func (c *Conn) dgRetireDoneLocked() bool {
	dg := c.dg
	return c.closeSent.Load() && !dg.rel.outstanding() && dg.peerCloseSeen && dg.peerCloseRacked
}

// dgSleep waits for a wake, the carrier's death or the earliest timed event
// (dgNextWakeLocked, the endpoint's WakeAt) and returns true. A timer that
// fires for an event that went away meanwhile — a REL timeout the RACK
// cleared (R1-2) — starts no round: the sleep re-checks what is due and
// goes on sleeping, so a carrier with nothing outstanding neither writes
// nor wakes its endpoint (M2-D65).
func (c *Conn) dgSleep(w *writer, now time.Time) bool {
	wt := w.b.WakeTime()
	if !wt.After(now) {
		wt = time.Time{} // a WakeAt at or before the round's own time was served by Fill
	}
	for {
		if !wt.IsZero() && !now.Before(wt) {
			return true
		}
		c.mu.Lock()
		at := c.dgNextWakeLocked(now, w)
		c.mu.Unlock()
		if !at.IsZero() && !at.After(now) {
			return true
		}
		if !wt.IsZero() && (at.IsZero() || wt.Before(at)) {
			at = wt
		}
		if at.IsZero() {
			select {
			case <-c.wake:
			case <-c.dying:
			}
			return true
		}
		w.timer.Reset(at.Sub(now))
		select {
		case <-c.wake:
			w.timer.Stop()
			return true
		case <-c.dying:
			w.timer.Stop()
			return true
		case <-w.timer.C:
		}
		now = time.Now()
	}
}

// dgNextWakeLocked returns the earliest timed event of a datagram carrier
// (zero: none): the next PING or PING retry (not while held, retiring or
// closing), the death deadline of the oldest PING, the sessionless idle
// limit, the REL retransmission (only while a REL is outstanding: M2-D65)
// and the rebind challenge.
func (c *Conn) dgNextWakeLocked(now time.Time, w *writer) time.Time {
	st := &c.st
	var at time.Time
	earliest := func(t time.Time) {
		if !t.IsZero() && (at.IsZero() || t.Before(at)) {
			at = t
		}
	}
	if !st.retiring && !w.held && !c.closeSent.Load() {
		k, t := c.dgPingDueLocked(now)
		if k != pingNone {
			return now
		}
		earliest(t)
	}
	_, t, _ := c.deathDueLocked(now)
	earliest(t)
	if c.opts.Sessionless && !st.retiring {
		earliest(st.lastPingRx.Add(c.tm.SessionlessIdle))
	}
	earliest(c.relWakeLocked())
	earliest(c.chalWakeLocked(now))
	return at
}
