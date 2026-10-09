package carrier

import "time"

// The two-stage write watchdog (design §4.8, C6). Each batch write has a
// generation g, packed with the WriteBlocked flag into Conn.wstate as
// g<<1 | blocked. Before the write the writer arms both stages for g:
//
//   - stage 1 at PingBusy (only if PingBusy is shorter than the stall
//     window): CAS(wstate, g<<1|0 → g<<1|1); only a successful CAS reports
//     ep.WriteBlocked, so duties move off a carrier whose write is blocked
//     (L08, D5);
//   - stage 2 at the stall window: if wstate still holds generation g, the
//     write stalled: Kill(write_stall) (L24), or, after the peer's CLOSE,
//     the end of that retirement (endIfPeerClosed).
//
// When the write returns, one store sets generation g+1 with the flag
// clear. time.AfterFunc's Stop cannot stop a callback that already started,
// and the timers are reused for every batch, so a callback checks both the
// generation and that its stage is actually due: a late callback of an
// earlier write can neither set the flag on an idle carrier nor act early
// on a newer write. One stall window covers the whole batch: a short write
// with progress continues inside it (C23).

// armWatchdog arms both stages for write generation gen started at now.
func (c *Conn) armWatchdog(gen uint64, now time.Time, stall time.Duration) {
	at := now.Sub(c.base)
	if pb := c.tm.PingBusy; pb < stall {
		c.wd1At.Store(int64(at + pb)) // the due time first: a callback that sees gen sees it
		c.wd1Gen.Store(gen)
		c.wd1.Reset(pb)
	}
	c.wd2At.Store(int64(at + stall))
	c.wd2Gen.Store(gen)
	c.wd2.Reset(stall)
}

// disarmWatchdog completes write generation gen: the next generation with
// WriteBlocked clear, in one store, then both stages are stopped.
func (c *Conn) disarmWatchdog(gen uint64) {
	c.wstate.Store((gen + 1) << 1)
	c.wd1.Stop()
	c.wd2.Stop()
}

// watchStage1 is stage 1's timer callback.
func (c *Conn) watchStage1() {
	gen := c.wd1Gen.Load()
	if int64(time.Since(c.base)) < c.wd1At.Load() {
		return // a late callback of an earlier write; the newer write's own stage is still pending
	}
	if c.wstate.CompareAndSwap(gen<<1, gen<<1|1) {
		if c.mux {
			c.writeBlockedAll() // every view's endpoint (M3-D14; mux.go)
		} else if c.ep != nil {
			c.ep.WriteBlocked(c)
		}
	}
}

// watchStage2 is stage 2's timer callback.
func (c *Conn) watchStage2() {
	gen := c.wd2Gen.Load()
	if int64(time.Since(c.base)) < c.wd2At.Load() {
		return
	}
	if c.wstate.Load()>>1 == gen && !c.endIfPeerClosed("write stalled") {
		c.killCarrier(CauseWriteStall, "batch write exceeded its stall window")
	}
}
