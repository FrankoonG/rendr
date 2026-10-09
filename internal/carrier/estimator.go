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
	pingRingSize = 32
	// pingCadenceMax bounds the records the PING cadence may fill: a PING
	// due only by its timer waits while this many are outstanding (on a
	// path whose round trip spans more cadence intervals; the oldest record
	// decides death either way). The first PING, requested (cap-hit) PINGs
	// and byte-clocked PINGs may use the rest of the ring, so the PINGs that
	// release capacity never wait behind cadence PINGs that prove nothing
	// new (design §0.13 A7b). It also sizes the health layer's probe
	// records: a probe carrier sends only its first and cadence PINGs.
	pingCadenceMax = 16
	// minRateSample is the shortest interval a rate sample may span (and a
	// backlog interval a PING may judge); rateSpan lengthens the rate's.
	minRateSample = 5 * time.Millisecond
	// rateDecayStep: the decaying-max rate filters lose 5% per 50 ms.
	rateDecayStep = 50 * time.Millisecond
	// clockStepMin and clockStepDiv set the byte clock's step (design §0.13
	// A7b): max(clockStepMin, capacity/clockStepDiv) of DATA between two
	// PINGs of a burst (endPing).
	clockStepMin = 64 << 10
	clockStepDiv = 8
)

// pingRecord is one PING of this incarnation (design §4.10, D14).
type pingRecord struct {
	id          uint32
	nonce       uint64    // salt ^ id: binds a PONG to this incarnation (L21, L23)
	mark        uint64    // DATA submitted before the PING on the wire: before its batch, or through it (a PING that ends its batch, endPing)
	committedAt time.Time // when the write carrying the PING returned; zero until then
	busy        bool      // the BUSY flag the PING carried (this side backlogged before it)
	early       bool      // a matching PONG raced the PING's own write: liveness proven, no sample (L23)
}

// carrierState is everything guarded by trunk.mu (M2's Conn.mu).
type carrierState struct {
	// Estimator.
	srtt, minRTT               time.Duration
	rttvar                     time.Duration // RFC 6298 RTT variation (sched.RTTVar): only the REL timeout uses it (M2-D16)
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
	ring       [pingRingSize]pingRecord
	head, n    int
	nextPingID uint32
	pingSent   bool      // a PING was encoded on this incarnation
	pingReq    bool      // RequestPing or a cap-hit PING
	lastCommit time.Time // commit of the latest PING (cadence)
	// intervalStart is the start of the current backlog interval: the
	// commit of the latest PING that judged one (an interval of at least
	// minRateSample, X4), or Start.
	intervalStart time.Time
	lastBusy      bool // the latest judged backlog state, carried by every PING sent since (Stats.Backlogged)
	peerBusy      bool // the BUSY flag of the latest PING received (Stats.PeerBusy)

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
// and BUSY when the writer was backlogged for ≥ 25% of the current backlog
// interval (D15). An interval shorter than 5 ms cannot be judged: such a
// PING carries the latest judged state on, and its commit does not restart
// the interval, whose busy time keeps accumulating until a PING judges it
// (X4). In a cap-limited flow every PING is a cap-hit PING one RTT after
// the previous commit; restarting the interval at each of them would never
// judge one below a 5 ms RTT, so BUSY, the rate samples it gates and the
// capacity they raise would stay off for good. Its record is uncommitted
// until the write returns. A PING appended before Fill (atEnd false: the
// first PING, and every PING while the byte clock is off) precedes every
// DATA byte of its batch, and its mark is what was submitted before the
// batch; one appended after Fill (atEnd, endPing) follows every DATA byte
// of its batch, and its mark includes them.
func (t *trunk) encodePingLocked(w *writer, b *Batch, now time.Time, atEnd bool) {
	t.encodePingPadLocked(w, b, now, atEnd, 0)
}

// encodePingPadLocked is encodePingLocked with pad zero bytes of padding
// (an MTU probe of a datagram carrier, M2-D24). On a datagram carrier
// PING ids skip 0 when the counter wraps: id 0 is the rebind challenge
// (M2-D27, L14); stream carriers keep M1's plain wrap.
func (t *trunk) encodePingPadLocked(w *writer, b *Batch, now time.Time, atEnd bool, pad int) {
	st := &t.st
	id := st.nextPingID
	if id == 0 && t.dg != nil {
		id = 1
	}
	busy, judged := st.lastBusy, now.Sub(st.intervalStart) >= minRateSample
	if judged {
		busy = w.backlogged(now, st.intervalStart)
	}
	p := wire.Ping{ID: id, TS: uint64(now.Sub(t.base)), Nonce: t.salt ^ uint64(id), Pad: pad}
	if !b.addPing(busy, &p) {
		return
	}
	mark := st.submitted
	if atEnd {
		mark += uint64(b.dataBytes())
	}
	st.nextPingID = id + 1
	st.push(pingRecord{id: id, nonce: p.Nonce, mark: mark, busy: busy})
	st.pingSent, st.pingReq = true, false
	st.lastBusy = busy
	t.rxData.Store(false)
	w.ping, w.pingID, w.pingJudged, w.pingAtEnd = true, id, judged, atEnd
	w.dataSincePing, w.clock, w.pingFirst = false, 0, false
	t.gaugeUpdateLocked()
}

// endPing appends, after the DATA Fill placed in b, the PING that ends the
// batch (design §0.13 A7b): the cadence or requested PING that
// appendCarrierControl left to it while the byte clock runs (pingEnd), or
// else a byte-clocked PING.
//
// The byte clock: a cap-limited writer whose conn takes its whole capacity
// C at once (a socket buffer, a deep router queue) proved such a burst only
// with its cap-hit PING, queued behind all of it, and got the capacity
// back one round trip after the burst drained, every burst: a path of rate
// R and round-trip time RTT ran at R·C/(C + R·RTT) (12.7 of 16 MiB/s at
// 100 ms with an 8 MiB window; about 57 % in M1c's window-100ms case). The
// byte clock puts a PING into the burst after every step = max(64 KiB, C/8)
// of DATA written since the latest PING, so the PONGs come back while the
// burst drains, each releasing a step of capacity; the bytes in flight stay
// near C, and the path stays busy once C exceeds R·RTT by more than a step.
// Where the window binds instead (Window/RTT below R), the in-flight count
// lags the path by up to a step of delivered but unproven bytes, so the
// flow reaches about (Window − step)/RTT.
//
// The clock runs only while the path's bandwidth-delay product, rate ×
// minRTT, reaches one step (clockStepLocked): only then does the cycle cost
// the path a ninth or more (R·RTT ≥ C/8 gives R·C/(C + R·RTT) ≤ 8/9 R).
// Below it a burst of C spans many round trips and drains with little loss,
// and PINGs inside it would only keep the capacity's whole headroom,
// 2·rate·(minRTT + PingBusy + 50 ms) — over twenty round trips at a 10 ms
// RTT — standing in the path's queue, inflating every RTT measured through
// it (a bond orders its members by srtt, L34). Once the capacity is clamped
// at the window the gate reads rate·minRTT ≥ Window/8, which a fast short
// path can reach too (128 MiB/s at 10 ms with an 8 MiB window): the clock
// then removes the cycle there as well, at the cost of keeping up to the
// window's headroom (Window − rate·minRTT) queued in the path. Before the
// first rate sample the clock is off; bursts at the 128 KiB floor are single
// batches anyway.
//
// Every PING placed here ends its batch: it follows the DATA it proves, so
// it reaches the peer together with the last of those bytes, and its PONG's
// arrival matches its mark. A PING at the front of a batch arrives only with
// the bytes behind it in the same unit of the path — a TSO or GRO segment,
// a store-and-forward link quantum — later than the position it proves: a
// rate interval started at its PONG loses a unit of drain time, which the
// short samples of a clocked flow (a clock step, a refill of a batch or
// two) cannot absorb: they read a 16 MiB/s link as 24 MiB/s (clock PINGs in
// front), a 4 MiB/s one as 6 MiB/s (cadence PINGs in front of refills) and,
// behind a blocked write whose PONGs freed capacity, as 7.8 MiB/s (the
// cap-hit PING requested at its end, in front of the next round's DATA).
// So while the clock runs, cadence and requested PINGs end their batch as
// well (one that does not fit in a full batch goes first in the next round,
// pingFirst); the first PING precedes its batch, the clock being off then.
//
// A byte-clocked PING goes only into a batch whose DATA budget Fill
// exhausted (more DATA was waiting) and that is not the first of its burst:
// the batch that ends a burst, because the capacity, the window or the
// application stopped Fill, is proven by the cap-hit or the next cadence
// PING as before, so a writer that stops with DATA unproven keeps the
// PingBusy cadence, whose PINGs draw the PONG that reveals a lost reverse
// path (L11, P12). A burst whose only full batches are partly
// retransmissions (segments that do not fill the budget exactly) or many
// small frames gets no clock PING: it is proven as before the byte clock.
// At most one PING per batch; none once retiring; its record may use the
// ring past the cadence's share. The step was computed with the round's
// carrier control (w.step), so the decision takes no lock and reads no
// clock; the lock is taken only to encode the PING.
func (t *trunk) endPing(w *writer, b *Batch, now time.Time) {
	due := w.pingEnd
	w.pingEnd = false
	if !due {
		n := int64(b.dataBytes())
		if w.ping || n == 0 || w.burst == 0 || w.step == 0 || w.clock+n < w.step || b.Room() > 0 {
			return
		}
	}
	if !b.pingFits() {
		if due {
			w.pingFirst = true // still due: the next round's carrier control places it first
		}
		return
	}
	t.mu.Lock()
	if !t.st.retiring && t.st.n < pingRingSize {
		t.encodePingLocked(w, b, now, true)
	}
	t.mu.Unlock()
}

// clockStepLocked returns the byte clock's step, max(64 KiB, capacity/8),
// or 0 while the clock is off: the path's bandwidth-delay product
// (rate·minRTT) is below one step.
func (t *trunk) clockStepLocked() int64 {
	st := &t.st
	step := max(clockStepMin, t.capacityLocked()/clockStepDiv)
	if st.rate*st.minRTT.Seconds() < float64(step) {
		return 0
	}
	return step
}

// commitLocked accounts a batch whose write returned at at: DATA becomes
// submitted, and the batch's PING is committed (RTT counts from here, L23;
// a new backlog interval starts when the PING judged the previous one,
// X4). A batch that ended cap-blocked after writing DATA asks for a cap-hit
// PING, so the cap is released one RTT later rather than at the next PING
// timer (msess, R13), unless a PING ended the batch (endPing) and so proves
// all of its DATA already. A PONG that raced this write proved the bytes
// before its PING; those of the batch itself count from here, now that
// they are submitted (onPongLocked).
func (t *trunk) commitLocked(w *writer, b *Batch, at time.Time) {
	st := &t.st
	data := uint64(b.dataBytes())
	st.submitted += data
	st.txBytes += data
	st.retxBytes += uint64(b.retxBytes())
	st.frames += uint64(b.Len())
	if w.ping {
		t.commitPingLocked(w, at)
	}
	if data > 0 && b.CapBlocked() && !w.pingAtEnd {
		st.pingReq = true
	}
	t.gaugeUpdateLocked()
}

// commitPingLocked commits the writer's PING at at, the return of the
// write that carried it (L23): RTT counts from here; an early mark applies
// its PONG watermark; a judged PING starts the next backlog interval.
func (t *trunk) commitPingLocked(w *writer, at time.Time) {
	st := &t.st
	if i := st.find(w.pingID); i >= 0 {
		r := st.record(i)
		r.committedAt = at
		if r.early && r.mark > st.pongMark {
			st.pongMark = r.mark
		}
	}
	st.lastCommit = at
	if w.pingJudged {
		st.intervalStart = at
	}
}

// onPongLocked applies a PONG received at now (design §4.10). A PONG that
// matches no record of this incarnation by id and nonce is ignored; one
// that matches a PING whose write has not returned yet marks it and
// advances the PONG watermark (liveness and delivery, no sample). A match
// yields the RTT from the PING's commit (L23), drops that record and every
// older one, updates srtt, minRTT, the PONG watermark, the rate (only for a
// backlogged interval: D15, P4; a PONG that proves nothing new restarts the
// interval only while the interval itself has proven nothing yet, §0.13 A1;
// a sample spans at least rateSpan) and the receive rate. wake reports that
// the watermark advanced while the writer's last round was cap-blocked
// (C5), or that the PONG freed the records a waiting PING needs
// (ringFreed).
func (t *trunk) onPongLocked(p *wire.Ping, now time.Time) (matched bool, rtt time.Duration, wake bool) {
	st := &t.st
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
		// must not stay capped at its capacity for good. The watermark never
		// passes what was submitted: the mark of a PING that ends its batch
		// (endPing) counts that batch's DATA, which is submitted only at the
		// commit, so the rest of the mark is applied there (commitLocked)
		// and the bytes in flight never read negative. The record stays
		// for a genuine match; the older records were answered before it on
		// this FIFO stream, so they go (waking a writer that waits on a
		// full ring), and early records never accumulate in the ring.
		r.early = true
		n0 := st.n
		m := min(r.mark, st.submitted)
		advanced := m > st.pongMark
		if advanced {
			st.pongMark = m
			t.gaugeUpdateLocked()
		}
		if i > 0 {
			st.dropThrough(i - 1)
		}
		return false, 0, (advanced && t.capBlocked.Load()) || ringFreed(n0, st.n)
	}
	rec := *r
	n0 := st.n
	st.dropThrough(i)
	rtt = now.Sub(rec.committedAt)
	st.rttvar = sched.RTTVar(st.rttvar, st.srtt, rtt, !st.rttSeen) // before srtt (RFC 6298 §2.3)
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
	case !advanced && st.pongMark == st.rateMark:
		// Nothing new was proven since the interval began: idle is not
		// slowness. The next interval starts here.
		st.rateMark, st.rateAt, st.rateCommitAt = st.pongMark, now, rec.committedAt
	case !advanced:
		// Nothing new was proven by this PONG, but the interval holds bytes
		// an earlier PONG proved too soon after its start to be sampled
		// (< rateSpan). Restarting here would throw that proof away:
		// on a path whose RTT is at least PingBusy, a busy PING that went
		// out just before a burst returns just before the PONG proving the
		// burst, and when the two arrive less than minRateSample apart
		// (RTT mod PingBusy < 5 ms) the round trips lost their samples — the
		// rate stayed at or near 0 and the capacity at CapFloor, 128 KiB per
		// RTT whatever the window (design §0.13 A1). The interval runs on to
		// the next PONG that proves more. Its start still precedes every
		// byte it counts on the wire (each PING precedes the DATA submitted
		// after its mark), so the sample stays within the drain rate.
	case now.Sub(st.rateAt) >= st.rateSpan():
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
			s := float64(st.pongMark-st.rateMark) / span.Seconds()
			if span < st.srtt/2 && t.capacityLocked() > t.tm.CapFloor {
				// A sample shorter than half an RTT can be a cluster of
				// PONGs released together: once the capacity left its
				// floor, it may at most double the estimate (rateSpan).
				s = min(s, 2*st.rate)
			}
			if s > st.rate {
				st.rate = s
			}
		}
		st.rateMark, st.rateAt, st.rateCommitAt = st.pongMark, now, rec.committedAt
	}
	rx := t.rxBytes.Load()
	if dt := now.Sub(st.rxAt); dt >= minRateSample {
		st.rxRate *= decay(dt)
		if s := float64(rx-st.rxMark) / dt.Seconds(); s > st.rxRate {
			st.rxRate = s
		}
		st.rxMark, st.rxAt = rx, now
	}
	t.gaugeUpdateLocked()
	// A full ring, or the cadence's full share of it, deferred the next
	// PING: the freed records let the writer send it.
	return true, rtt, (advanced && t.capBlocked.Load()) || ringFreed(n0, st.n)
}

// ringFreed reports whether dropping records took the ring from n0 to n
// records out of the full ring or below the cadence's share: a PING may
// have been waiting for the room.
func ringFreed(n0, n int) bool {
	return (n0 == pingRingSize && n < n0) || (n0 >= pingCadenceMax && n < pingCadenceMax)
}

// rateSpan returns the shortest interval a rate sample may span: 5 ms
// (minRateSample), and half the smoothed RTT while the peer reports BUSY.
//
// With byte-clocked PINGs (design §0.13 A7b) a PONG proves new bytes every
// clock step instead of once per burst, so samples over a few
// milliseconds of PONG arrivals become common, and such arrivals carry
// timing noise. A backlogged peer queues our PONGs behind its own DATA, and
// they leave that queue together (ACK compression): over 5 ms such
// clusters read a 16 MiB/s link at a 100 ms RTT as 72 MiB/s, and an 8
// MiB/s one at 400 ms as 55 MiB/s (design §0.13 A1 bounds a sample with
// bulk both ways at 4×; the estimate before the byte clock peaked at 3.6×).
// Half the smoothed RTT, which holds the queueing delay of both
// directions, averages a cluster with the gap behind it (2× and 1.7×
// there). Such a sample measures what the path carried for this side
// while both directions were loaded — its achieved rate, not the drain rate
// of a saturated path — so with bulk both ways the estimate follows the
// achieved rate (far below the link rate where a window limits the flow;
// the capacity is then clamped at the window anyway). Without the peer's
// BUSY its writer has no standing queue, and the 5 ms floor keeps the
// drain-rate samples inside one burst that raise a capacity from the floor
// within one round trip (L32, L33; an echo whose path degrades, L29).
//
// The peer's BUSY flag tells of its writer, not of the queue its last
// burst left behind: our PONGs queued there leave together after its BUSY
// cleared (a 16 MiB/s link then read as 118 MiB/s), and a peer whose
// backlog comes and goes is not BUSY all the time. So a sample over less
// than half the smoothed RTT may at most double the estimate (onPongLocked)
// unless the capacity still sits at its floor: before the first evidence
// any sample may set it, and a real rise takes a few PONGs, not one.
func (st *carrierState) rateSpan() time.Duration {
	if st.peerBusy {
		return max(minRateSample, st.srtt/2)
	}
	return minRateSample
}

// onPing records a PING received at now: the next PONG answers it (latest
// wins: a flood of PINGs behind a blocked write collapses into one PONG,
// L08), its BUSY flag becomes Stats.PeerBusy, and it restarts the
// sessionless idle clock.
func (t *trunk) onPing(busy bool, p *wire.Ping, now time.Time) {
	t.mu.Lock()
	st := &t.st
	st.pong, st.pongDue = *p, true
	st.lastPingRx = now
	if st.peerBusy != busy {
		st.peerBusy = busy
		t.gaugeUpdateLocked()
	}
	t.mu.Unlock()
	t.wakeWriter()
}

// deathDueLocked reports whether the oldest committed, unanswered PING has
// reached the death deadline D = sched.DeathDeadline(srtt, inflight, rate,
// DeadMin, DeadMax) (L25), when it will (zero if no PING is outstanding),
// and how long it has waited.
func (t *trunk) deathDueLocked(now time.Time) (due bool, at time.Time, waited time.Duration) {
	st := &t.st
	for i := range st.n {
		r := st.record(i)
		if r.committedAt.IsZero() || r.early {
			continue
		}
		d := sched.DeathDeadline(st.srtt, st.inflight(), st.rate, t.tm.DeadMin, t.tm.DeadMax)
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
// ring defers the PING until a PONG frees a record, and the cadence's full
// share of it (pingCadenceMax) defers a cadence PING. Byte-clocked PINGs
// are not scheduled here: they end batches that carry DATA (endPing).
// Application silence never triggers anything (L30).
func (t *trunk) pingDueLocked(now time.Time, w *writer) (bool, time.Time) {
	st := &t.st
	if t.opts.Sessionless || st.n == pingRingSize {
		return false, time.Time{}
	}
	if !st.pingSent || st.pingReq {
		return true, now
	}
	if st.n >= pingCadenceMax {
		return false, time.Time{}
	}
	iv := t.tm.PingIdle
	switch {
	case t.opts.Probe:
		iv = t.tm.ProbeInterval
	case t.busyCadenceLocked(now, w):
		iv = t.tm.PingBusy
	}
	at := st.lastCommit.Add(iv)
	return !now.Before(at), at
}

// busyCadenceLocked: PING every PingBusy while this side has unproven DATA
// in flight, waits at the capacity cap, sent BUSY in its last PING, received
// DATA since its previous PING (a pure receiver must detect a silent drop
// within the G4 budget, F12/P12), or the current backlog interval disagrees
// with the latest judged state (the peer learns a flip within PingBusy and
// an RTT).
func (t *trunk) busyCadenceLocked(now time.Time, w *writer) bool {
	st := &t.st
	return st.inflight() > 0 || !w.capSince.IsZero() || st.lastBusy || t.rxData.Load() ||
		w.backlogged(now, st.intervalStart) != st.lastBusy
}

// gaugeUpdateLocked refreshes this carrier's self-load contribution:
// forward bytes not proven by a PONG watermark plus the reverse bound
// rxRate·srtt, and the backlog state (local BUSY or the peer's) (§8.2).
// While the peer reports BUSY the reverse bound is at least CapFloor: a
// send-backlogged peer sits at its capacity cap, never below the floor, or
// has writes in progress that cover a quarter of its time (§0.13 A5). On a
// path whose bandwidth-delay product is below the floor, rxRate·srtt alone
// hovered around LoadThreshold while the peer was saturated, and a probe
// sample carrying the download's own queueing counted as unloaded.
func (t *trunk) gaugeUpdateLocked() {
	st := &t.st
	if st.gauge == nil || st.gEnded {
		return
	}
	rev := int64(st.rxRate * st.srtt.Seconds())
	if st.peerBusy {
		rev = max(rev, t.tm.CapFloor)
	}
	contrib := st.inflight() + rev
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
func (t *trunk) endGaugeLocked() {
	st := &t.st
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
