package carrier

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Estimator constants (plan §4 internal constants, design §4.10).
const (
	// pingRingSize bounds the PING records of one carrier. While it is
	// full no new PING is encoded: the oldest record alone decides death,
	// and the next PONG frees records (FIFO).
	pingRingSize = 16
	// minRateSample is the shortest interval a rate sample may span.
	minRateSample = 5 * time.Millisecond
	// rateDecayStep: the decaying-max rate filters lose 5% per 50 ms.
	rateDecayStep = 50 * time.Millisecond
)

// pingRecord is one PING of this incarnation (design §4.10, D14).
type pingRecord struct {
	id          uint32
	nonce       uint64    // salt ^ id: binds a PONG to this incarnation (L21, L23)
	mark        uint64    // submitted before the batch carrying the PING (PINGs precede DATA)
	committedAt time.Time // when the write carrying the PING returned; zero until then
	busy        bool      // the BUSY flag the PING carried (this side backlogged before it)
	early       bool      // a matching PONG raced the PING's own write: liveness proven, no sample (L23)
}

// carrierState is everything guarded by Conn.mu.
type carrierState struct {
	// Estimator.
	srtt, minRTT               time.Duration
	rttSeen                    bool
	rate                       float64 // bytes/s: decaying max of backlogged PONG-watermark samples
	submitted, pongMark        uint64  // DATA payload bytes written / proven by PONG watermarks
	rateMark                   uint64  // pongMark at the start of the current rate interval
	rateAt                     time.Time
	rateCommitAt               time.Time // commit of the PING whose PONG started the interval
	rxRate                     float64   // bytes/s: decaying max of received DATA payload
	rxMark                     uint64
	rxAt                       time.Time
	txBytes, retxBytes, frames uint64

	// PING records: a FIFO ring, oldest at head.
	ring          [pingRingSize]pingRecord
	head, n       int
	nextPingID    uint32
	pingSent      bool      // a PING was encoded on this incarnation
	pingReq       bool      // RequestPing or a cap-hit PING
	lastCommit    time.Time // commit of the latest PING (cadence)
	intervalStart time.Time // start of the current backlog interval: the latest PING commit, or Start
	lastBusy      bool      // the BUSY flag of the latest PING sent (Stats.Backlogged)
	peerBusy      bool      // the BUSY flag of the latest PING received (Stats.PeerBusy)

	// Carrier-level control.
	pong       wire.Ping // latest PING received: answered by the next PONG (latest wins, L08)
	pongDue    bool
	lastPingRx time.Time // sessionless idle clock
	retiring   bool
	reason     wire.CloseReason
	goAway     bool
	goAwaySent bool

	// Self-load gauge contribution (design §4.10, §8.2).
	gauge    *Gauge
	gContrib int64
	gBacklog bool
	gEnded   bool
}

func (st *carrierState) inflight() int64 { return int64(st.submitted - st.pongMark) }

func (st *carrierState) record(i int) *pingRecord {
	return &st.ring[(st.head+i)%pingRingSize]
}

func (st *carrierState) push(r pingRecord) {
	st.ring[(st.head+st.n)%pingRingSize] = r
	st.n++
}

// dropThrough removes records 0..i (a PONG answers its PING and, on a FIFO
// stream, every older one).
func (st *carrierState) dropThrough(i int) {
	st.head = (st.head + i + 1) % pingRingSize
	st.n -= i + 1
}

func (st *carrierState) find(id uint32) int {
	for i := range st.n {
		if st.record(i).id == id {
			return i
		}
	}
	return -1
}

// decay returns the decaying-max filter factor for an interval dt.
func decay(dt time.Duration) float64 {
	return math.Pow(0.95, float64(dt)/float64(rateDecayStep))
}

// encodePingLocked appends this carrier's next PING to b (design §4.10):
// id from the counter (serial arithmetic, L14), nonce = salt ^ id (D14),
// BUSY when the writer was backlogged for ≥ 25% of the interval since the
// previous PING commit (D15); an interval shorter than 5 ms (a cap-hit PING
// right behind the previous one) carries the previous state on. Its record
// is uncommitted until the write returns.
func (c *Conn) encodePingLocked(w *writer, b *Batch, now time.Time) {
	st := &c.st
	id := st.nextPingID
	busy := st.lastBusy // an interval too short to judge (a cap-hit PING right after a commit) keeps the state
	if now.Sub(st.intervalStart) >= minRateSample {
		busy = w.backlogged(now, st.intervalStart)
	}
	p := wire.Ping{ID: id, TS: uint64(now.Sub(c.base)), Nonce: c.salt ^ uint64(id)}
	if !b.addPing(busy, &p) {
		return
	}
	st.nextPingID++
	st.push(pingRecord{id: id, nonce: p.Nonce, mark: st.submitted, busy: busy})
	st.pingSent, st.pingReq = true, false
	st.lastBusy = busy
	c.rxData.Store(false)
	w.ping, w.pingID = true, id
	w.dataSincePing = false
	c.gaugeUpdateLocked()
}

// commitLocked accounts a batch whose write returned at at: DATA becomes
// submitted, and the batch's PING is committed (RTT counts from here, L23;
// a new backlog interval starts). A batch that ended cap-blocked after
// writing DATA asks for a cap-hit PING, so the cap is released one RTT
// later rather than at the next PING timer (msess, R13).
func (c *Conn) commitLocked(w *writer, b *Batch, at time.Time) {
	st := &c.st
	data := uint64(b.dataBytes())
	st.submitted += data
	st.txBytes += data
	st.retxBytes += uint64(b.retxBytes())
	st.frames += uint64(b.Len())
	if w.ping {
		if i := st.find(w.pingID); i >= 0 {
			st.record(i).committedAt = at
		}
		st.lastCommit, st.intervalStart = at, at
	}
	if data > 0 && b.CapBlocked() {
		st.pingReq = true
	}
	c.gaugeUpdateLocked()
}

// onPongLocked applies a PONG received at now (design §4.10). A PONG that
// matches no record of this incarnation by id and nonce is ignored; one
// that matches a PING whose write has not returned yet marks it and
// advances the PONG watermark (liveness and delivery, no sample). A match
// yields the RTT from the PING's commit (L23), drops that record and every
// older one, updates srtt, minRTT, the PONG watermark, the rate (only for a
// backlogged interval: D15, P4) and the receive rate. wake reports that the
// watermark advanced while the writer's last round was cap-blocked (C5), or
// that the PONG freed records of a full ring.
func (c *Conn) onPongLocked(p *wire.Ping, now time.Time) (matched bool, rtt time.Duration, wake bool) {
	st := &c.st
	i := st.find(p.ID)
	if i < 0 {
		return false, 0, false
	}
	r := st.record(i)
	if r.nonce != p.Nonce {
		return false, 0, false
	}
	if r.committedAt.IsZero() {
		// The PONG raced its PING's own write (the bytes left before the
		// Write call returned): it is no evidence (L23) — no RTT and no
		// rate sample — but it proves liveness, and that the peer read
		// every DATA byte submitted before the PING. So the watermark
		// advances and a cap-blocked writer is woken (C5): a carrier whose
		// every PONG races its commit (a synchronous conn at GOMAXPROCS=1)
		// must not stay capped at its capacity for good. The record stays
		// for a genuine match; the older records were answered before it on
		// this FIFO stream, so they go (waking a writer that waits on a
		// full ring), and early records never accumulate in the ring.
		r.early = true
		full := st.n == pingRingSize
		advanced := r.mark > st.pongMark
		if advanced {
			st.pongMark = r.mark
			c.gaugeUpdateLocked()
		}
		if i > 0 {
			st.dropThrough(i - 1)
		}
		return false, 0, (advanced && c.capBlocked.Load()) || (full && i > 0)
	}
	rec := *r
	full := st.n == pingRingSize
	st.dropThrough(i)
	rtt = now.Sub(rec.committedAt)
	if !st.rttSeen {
		st.srtt, st.minRTT, st.rttSeen = rtt, rtt, true
	} else {
		st.srtt = (7*st.srtt + rtt) / 8
		st.minRTT = min(st.minRTT, rtt)
	}
	advanced := rec.mark > st.pongMark
	if advanced {
		st.pongMark = rec.mark
	}
	switch {
	case !advanced:
		// Nothing new was proven: idle is not slowness. The next interval
		// starts here.
		st.rateMark, st.rateAt, st.rateCommitAt = st.pongMark, now, rec.committedAt
	case now.Sub(st.rateAt) >= minRateSample:
		dt := now.Sub(st.rateAt)
		st.rate *= decay(dt)
		if rec.busy {
			// The proven bytes were submitted over the commit span of the two
			// PINGs; a burst of PONGs released together (a delayed return
			// path) spans far less on arrival. Dividing by the longer of the
			// two keeps the sample within the drain rate (L32).
			span := dt
			if dc := rec.committedAt.Sub(st.rateCommitAt); dc > span {
				span = dc
			}
			if s := float64(st.pongMark-st.rateMark) / span.Seconds(); s > st.rate {
				st.rate = s
			}
		}
		st.rateMark, st.rateAt, st.rateCommitAt = st.pongMark, now, rec.committedAt
	}
	rx := c.rxBytes.Load()
	if dt := now.Sub(st.rxAt); dt >= minRateSample {
		st.rxRate *= decay(dt)
		if s := float64(rx-st.rxMark) / dt.Seconds(); s > st.rxRate {
			st.rxRate = s
		}
		st.rxMark, st.rxAt = rx, now
	}
	c.gaugeUpdateLocked()
	// A full record ring deferred the next PING (a cap-hit one included):
	// the freed records let the writer send it.
	return true, rtt, (advanced && c.capBlocked.Load()) || full
}

// onPing records a PING received at now: the next PONG answers it (latest
// wins: a flood of PINGs behind a blocked write collapses into one PONG,
// L08), its BUSY flag becomes Stats.PeerBusy, and it restarts the
// sessionless idle clock.
func (c *Conn) onPing(busy bool, p *wire.Ping, now time.Time) {
	c.mu.Lock()
	st := &c.st
	st.pong, st.pongDue = *p, true
	st.lastPingRx = now
	if st.peerBusy != busy {
		st.peerBusy = busy
		c.gaugeUpdateLocked()
	}
	c.mu.Unlock()
	c.Wake()
}

// deathDueLocked reports whether the oldest committed, unanswered PING has
// reached the death deadline D = sched.DeathDeadline(srtt, inflight, rate,
// DeadMin, DeadMax) (L25), when it will (zero if no PING is outstanding),
// and how long it has waited.
func (c *Conn) deathDueLocked(now time.Time) (due bool, at time.Time, waited time.Duration) {
	st := &c.st
	for i := range st.n {
		r := st.record(i)
		if r.committedAt.IsZero() || r.early {
			continue
		}
		d := sched.DeathDeadline(st.srtt, st.inflight(), st.rate, c.tm.DeadMin, c.tm.DeadMax)
		at = r.committedAt.Add(d)
		return !now.Before(at), at, now.Sub(r.committedAt)
	}
	return false, time.Time{}, 0
}

// pingDueLocked reports whether a PING is due at now and otherwise when the
// next one becomes due (zero: none scheduled). The first PING goes out at
// once (L23); a requested one as soon as possible; then probe carriers PING
// every ProbeInterval and other carriers every PingBusy while busy (P12)
// and PingIdle otherwise. Sessionless carriers never PING; a full record
// ring defers the PING until a PONG frees a record. Application silence
// never triggers anything (L30).
func (c *Conn) pingDueLocked(now time.Time, w *writer) (bool, time.Time) {
	st := &c.st
	if c.opts.Sessionless || st.n == pingRingSize {
		return false, time.Time{}
	}
	if !st.pingSent || st.pingReq {
		return true, now
	}
	iv := c.tm.PingIdle
	switch {
	case c.opts.Probe:
		iv = c.tm.ProbeInterval
	case c.busyCadenceLocked(now, w):
		iv = c.tm.PingBusy
	}
	at := st.lastCommit.Add(iv)
	return !now.Before(at), at
}

// busyCadenceLocked: PING every PingBusy while this side has unproven DATA
// in flight, waits at the capacity cap, sent BUSY in its last PING, received
// DATA since its previous PING (a pure receiver must detect a silent drop
// within the G4 budget, F12/P12), or its backlog state flipped since the
// last PING (the peer learns it within an RTT).
func (c *Conn) busyCadenceLocked(now time.Time, w *writer) bool {
	st := &c.st
	return st.inflight() > 0 || !w.capSince.IsZero() || st.lastBusy || c.rxData.Load() ||
		w.backlogged(now, st.intervalStart) != st.lastBusy
}

// gaugeUpdateLocked refreshes this carrier's self-load contribution:
// forward bytes not proven by a PONG watermark plus the reverse bound
// rxRate·srtt, and the backlog state (local BUSY or the peer's) (§8.2).
func (c *Conn) gaugeUpdateLocked() {
	st := &c.st
	if st.gauge == nil || st.gEnded {
		return
	}
	contrib := st.inflight() + int64(st.rxRate*st.srtt.Seconds())
	if d := contrib - st.gContrib; d != 0 {
		st.gauge.AddInflight(d)
		st.gContrib = contrib
	}
	if on := st.lastBusy || st.peerBusy; on != st.gBacklog {
		st.gauge.SetBacklog(on)
		st.gBacklog = on
	}
}

// endGaugeLocked withdraws the whole contribution when the carrier ends.
// It marks the end even while no gauge is installed yet: a Kill that races
// Start runs before Start installs the gauge, and the reader may still
// account frames until the closer's Close, so nothing may be contributed
// afterwards.
func (c *Conn) endGaugeLocked() {
	st := &c.st
	if st.gEnded {
		return
	}
	st.gEnded = true
	if st.gauge == nil {
		return
	}
	if st.gContrib != 0 {
		st.gauge.AddInflight(-st.gContrib)
		st.gContrib = 0
	}
	if st.gBacklog {
		st.gauge.SetBacklog(false)
		st.gBacklog = false
	}
}
