package carrier

import (
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// writer is the writer goroutine's own state (design §4.8). Nothing here is
// shared: other goroutines reach the writer only through Conn.mu state, the
// atomics and the wake/dying channels.
type writer struct {
	b     *Batch
	fseq  uint32 // next tx fseq (the handshake set it past the first frame)
	held  bool   // StartOptions.Hold: nothing is written before the endpoint's first frame
	timer *time.Timer
	vec   net.Buffers // OwnedTCP: the reused iovec backing array
	vv    net.Buffers // the vector handed to WriteBuffers; a field, so taking its address allocates nothing
	// scratch is the coalescing copy of the batch while its Write runs
	// (every conn but an OwnedTCP): pooled and charged to the Budget,
	// released only after the Write returned or unwound (§4.1).
	scratch *Buf

	// The current round.
	ping       bool // the batch carries a PING
	pingID     uint32
	pingJudged bool // the PING judged a backlog interval (≥ 5 ms): its commit starts the next one (X4)
	close      bool // the batch carries our CLOSE, its last frame

	// Backlog accounting (D15): busy time in the current backlog interval
	// (since the commit of the latest PING that judged one, X4) = durations
	// of writes that carried DATA plus time spent cap-blocked (from
	// MarkCapBlocked until the next Fill that pulled DATA or found nothing
	// waiting).
	busyAcc       time.Duration
	capSince      time.Time // start of the open cap-blocked period; zero: none
	dataSincePing bool      // DATA was written after the latest PING was encoded

	// Physical writes by shape (tests and diagnostics).
	vectored, coalesced uint64
}

// backlogged reports whether the writer was busy for at least 25% of the
// interval [since, now] (D15).
func (w *writer) backlogged(now, since time.Time) bool {
	busy := w.busyAcc
	if !w.capSince.IsZero() {
		from := w.capSince
		if from.Before(since) {
			from = since
		}
		busy += now.Sub(from)
	}
	elapsed := now.Sub(since)
	return elapsed > 0 && 4*busy >= elapsed
}

// noteRound closes or opens the cap-blocked period after a Fill.
func (w *writer) noteRound(b *Batch, now time.Time) {
	if !w.capSince.IsZero() && (b.dataBytes() > 0 || !b.CapBlocked()) {
		w.busyAcc += now.Sub(w.capSince)
		w.capSince = time.Time{}
	}
	if b.CapBlocked() && w.capSince.IsZero() {
		w.capSince = now
	}
}

// writerInit prepares the writer's batch, timers and (on an OwnedTCP) the
// iovec array. Everything a round needs afterwards is reused.
func (c *Conn) writerInit() {
	w := &c.wr
	w.b = NewBatch(c.tm.BatchBudget)
	w.timer = time.NewTimer(time.Hour)
	w.timer.Stop()
	c.wd1 = time.AfterFunc(time.Hour, c.watchStage1)
	c.wd1.Stop()
	c.wd2 = time.AfterFunc(time.Hour, c.watchStage2)
	c.wd2.Stop()
	if c.owned != nil {
		w.vec = make(net.Buffers, 0, 2*MaxBatchFrames+1)
	}
}

// writeLoop is the carrier's writer goroutine: one batch per round, rounds
// until the carrier dies or its CLOSE was written (design §4.8).
func (c *Conn) writeLoop() {
	normal := false
	defer func() {
		if !normal { // runtime.Goexit inside an embedder call (L51)
			c.Kill(CauseTransportError, "conn Write called runtime.Goexit")
		}
		w := &c.wr
		// The embedder call returned or unwound: release the chunk
		// references and the coalescing scratch (only this goroutine pools
		// its buffers, §4.1).
		if w.b != nil {
			w.b.Reset(time.Time{})
		}
		if w.scratch != nil {
			w.scratch.Release()
			w.scratch = nil
		}
		if w.timer != nil {
			w.timer.Stop()
		}
		if c.wd1 != nil {
			c.wd1.Stop()
			c.wd2.Stop()
		}
		c.partDone(partWriter)
	}()
	c.writerInit()
	for c.writeRound(&c.wr) {
	}
	normal = true
}

// writeRound runs one round: death checks, carrier control and Fill into a
// fresh batch, then either one physical write or a sleep. It returns false
// when the writer must exit: the carrier is dead (never Fill after a death
// it saw or caused, C1) or our CLOSE was written.
func (c *Conn) writeRound(w *writer) bool {
	if c.death.Load() != nil {
		return false
	}
	now := time.Now()
	if c.checkDeadlines(now) {
		return false
	}
	b := w.b
	b.Reset(now)
	w.ping, w.pingJudged, w.close = false, false, false
	// The cap-blocked flag is published before Fill and corrected after it
	// (§3.5: set the waiting flag, then evaluate). A PONG that frees
	// capacity while Fill decides at the cap therefore always sees it set
	// and wakes the writer, so a round that ends cap-blocked with nothing to
	// write never sleeps past the capacity that PONG proved (C5, R13). A
	// PONG during a round that is not cap-blocked costs one extra round.
	c.capBlocked.Store(true)
	epFrames := false
	var retiring bool
	var reason wire.CloseReason
	if w.held {
		// The first frame on the wire is the endpoint's first response
		// (OPEN_ACK or JOIN_ACK); PONGs and PINGs follow it.
		if c.ep != nil {
			c.ep.Fill(c, b)
		}
		if b.Len() > 0 {
			w.held, epFrames = false, true
		} else if !c.isRetiring() {
			c.capBlocked.Store(b.CapBlocked())
			return c.sleep(w, now)
		}
		retiring, reason = c.appendCarrierControl(w, b, now)
	} else {
		retiring, reason = c.appendCarrierControl(w, b, now)
		if c.ep != nil {
			n := b.Len()
			c.ep.Fill(c, b)
			epFrames = b.Len() > n
		}
	}
	c.capBlocked.Store(b.CapBlocked())
	w.noteRound(b, now)
	if b.CapBlocked() && w.dataSincePing && !w.ping {
		c.mu.Lock()
		c.st.pingReq = true // a cap-hit PING: in-flight is released only by PONGs
		c.mu.Unlock()
	}
	if retiring && !epFrames && b.addClose(reason) {
		w.close = true // nothing follows it
	}
	if b.Len() == 0 {
		return c.sleep(w, now)
	}
	return c.writeBatch(w, b, now)
}

func (c *Conn) isRetiring() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.retiring
}

// checkDeadlines kills the carrier when its oldest committed PING passed
// the death deadline (L25) — after the peer's CLOSE, which no PONG follows,
// that ends the retirement instead — and retires a sessionless carrier that
// saw no PING for SessionlessIdle (§6.4). It reports an end (the writer
// exits).
func (c *Conn) checkDeadlines(now time.Time) bool {
	c.mu.Lock()
	dead, _, waited := c.deathDueLocked(now)
	st := &c.st
	if !dead && c.opts.Sessionless && !st.retiring && !now.Before(st.lastPingRx.Add(c.tm.SessionlessIdle)) {
		st.retiring, st.reason = true, wire.CloseRetire
	}
	c.mu.Unlock()
	if dead {
		if !c.endIfPeerClosed("no PONG") {
			c.Kill(CausePingTimeout, "no PONG for "+waited.String())
		}
		return true
	}
	return false
}

// appendCarrierControl appends carrier-level frames under Conn.mu: the
// pending PONG (latest wins), a due PING (none once retiring) and GOAWAY.
// It returns the retirement state read in the same section.
func (c *Conn) appendCarrierControl(w *writer, b *Batch, now time.Time) (retiring bool, reason wire.CloseReason) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := &c.st
	if st.pongDue && b.addPong(&st.pong) {
		st.pongDue = false
	}
	if !st.retiring {
		if due, _ := c.pingDueLocked(now, w); due {
			c.encodePingLocked(w, b, now)
		}
	}
	if st.goAway && !st.goAwaySent && b.addGoAway(wire.GoAwayShutdown) {
		st.goAwaySent = true
	}
	return st.retiring, st.reason
}

// sleep waits for a wake, the death of the carrier, or the earliest timed
// event: the next PING, the death deadline of the oldest PING, the
// endpoint's WakeAt and the sessionless idle limit. It returns true (the
// caller runs the next round, which re-checks everything).
func (c *Conn) sleep(w *writer, now time.Time) bool {
	c.mu.Lock()
	at := c.nextWakeLocked(now, w)
	c.mu.Unlock()
	if wt := w.b.WakeTime(); wt.After(now) && (at.IsZero() || wt.Before(at)) {
		at = wt // a WakeAt at or before the round's own time was already served by Fill
	}
	if at.IsZero() {
		select {
		case <-c.wake:
		case <-c.dying:
		}
		return true
	}
	d := at.Sub(now)
	if d <= 0 {
		return true
	}
	w.timer.Reset(d)
	select {
	case <-c.wake:
	case <-c.dying:
	case <-w.timer.C:
	}
	w.timer.Stop()
	return true
}

func (c *Conn) nextWakeLocked(now time.Time, w *writer) time.Time {
	st := &c.st
	var at time.Time
	if !st.retiring && !w.held {
		due, t := c.pingDueLocked(now, w)
		if due {
			return now
		}
		at = t
	}
	if _, t, _ := c.deathDueLocked(now); !t.IsZero() && (at.IsZero() || t.Before(at)) {
		at = t
	}
	if c.opts.Sessionless && !st.retiring {
		if t := st.lastPingRx.Add(c.tm.SessionlessIdle); at.IsZero() || t.Before(at) {
			at = t
		}
	}
	return at
}

// writeBatch seals the batch and writes it: one stall window per batch
// (plan §3.6, C23), the two-stage generation-checked watchdog (C6), one
// SetWriteDeadline, Hooks.BeforeWrite, then the vectored write on an
// OwnedTCP or one coalesced Write on every other conn (P2, L41, L57), with
// count checks (L42). It returns false when the writer must exit.
func (c *Conn) writeBatch(w *writer, b *Batch, now time.Time) bool {
	w.fseq = b.seal(w.fseq)
	total := b.wireLen()
	c.mu.Lock()
	srtt, rate := c.st.srtt, c.st.rate
	c.mu.Unlock()
	stall := sched.StallWindow(srtt, total, rate, c.tm.WriteStall, c.tm.DeadMax)
	gen := c.wstate.Load() >> 1
	c.armWatchdog(gen, now, stall)
	if err := callSetWriteDeadline(c.nc, now.Add(stall)); err != nil {
		if _, ok := err.(*panicError); ok {
			c.disarmWatchdog(gen)
			b.ReleaseRefs()
			c.Kill(CauseTransportError, err.Error())
			return false
		}
		// A conn without write deadlines still has the watchdog's stage 2.
	}
	if h := c.env.Hooks; h != nil && h.BeforeWrite != nil {
		h.BeforeWrite(c.id, b.Len(), total)
	}
	start := time.Now()
	err := c.physWrite(w, b, total)
	end := time.Now()
	c.disarmWatchdog(gen)
	b.ReleaseRefs() // the write returned: its chunk references go (L17, L43)
	if err != nil {
		if c.endIfPeerClosed("write ended (" + err.Error() + ")") {
			return false
		}
		cause := CauseTransportError
		if isTimeout(err) {
			cause = CauseWriteStall
		}
		c.Kill(cause, "write: "+err.Error()) // a no-op if stage 2 already killed it as write_stall
		return false
	}
	if w.close {
		c.closeSent.Store(true) // on the wire, whatever happens next
	}
	if c.death.Load() != nil {
		return false // killed (or the retirement completed) while the write was in progress
	}
	if n := b.dataBytes(); n > 0 {
		w.busyAcc += end.Sub(start)
		w.dataSincePing = true
		if g := c.opts.Gauge; g != nil {
			g.AddTx(n, end) // the self-load volume (§8.2), counted with st.txBytes
		}
	}
	c.mu.Lock()
	c.commitLocked(w, b, end)
	c.mu.Unlock()
	if w.ping {
		if w.pingJudged {
			// The next backlog interval starts at this commit. A PING that
			// could not judge one (< 5 ms) leaves it running (X4).
			w.busyAcc = 0
			if !w.capSince.IsZero() {
				w.capSince = end
			}
		}
		if o := c.opts.Observer; o != nil {
			o.PingCommitted(c, w.pingID, end)
		}
	}
	if w.close {
		c.closeWritten()
		return false
	}
	return true
}

// physWrite performs the batch's physical write. An OwnedTCP gets one
// vectored write that references the send chunks (D3); every other conn
// gets the batch copied into a pooled scratch and exactly one Write call
// unless it writes short with progress, in which case the remainder follows
// inside the same stall window (C23, L42). The scratch is charged to the
// Budget like every other buffer (§4.1, plan §3.7: it shows in
// BufferedBytes and in the window's memory-pressure feedback) and released
// only after the Write returned (abandoned-call rule): a writer stuck in an
// embedder Write keeps it, and its charge, until that Write returns. Its
// class is the smallest that holds the batch; a full batch (256 KiB of DATA
// plus framing) takes the 512 KiB class for the duration of the Write.
func (c *Conn) physWrite(w *writer, b *Batch, total int) error {
	if c.owned != nil {
		w.vectored++
		w.vv = b.appendBuffers(w.vec[:0])
		remaining := int64(total)
		for remaining > 0 {
			n, err := callWriteBuffers(c.owned, &w.vv)
			if n < 0 || n > remaining {
				return &countError{"Write", int(n), int(remaining)}
			}
			remaining -= n
			if err != nil {
				return err
			}
			if remaining > 0 && n == 0 {
				return errZeroWrite
			}
		}
		return nil
	}
	w.coalesced++
	if total > MaxClass+ClassSlack { // only with a test BatchBudget beyond 1 MiB
		return writeFull(c.nc, b.appendTo(make([]byte, 0, total)))
	}
	w.scratch = c.env.Bufs.Get(total, c.env.Budget)
	err := writeFull(c.nc, b.appendTo(w.scratch.B[:0]))
	w.scratch.Release()
	w.scratch = nil
	return err
}
