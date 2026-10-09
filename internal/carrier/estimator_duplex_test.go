package carrier

import (
	"fmt"
	"math"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// duplexCase is one carrier-level run of bulk both ways (duplexRun): the
// dialer and the passive each send as fast as their capacity lets them,
// over a Link shaped to rate per direction with a buffer of buf per
// direction, Window 8 MiB on both ends.
type duplexCase struct {
	rtt  time.Duration
	rate float64
	buf  int
	// warm and span: the judged window [warm, warm+span) after Start.
	warm, span time.Duration
	// pingTS, if set, rewrites the TS of every PING the passive sends;
	// since is the virtual time since the run began, before the handshake
	// (a peer clock that drifts or steps against the dialer's).
	pingTS func(ts uint64, since time.Duration) uint64
}

// duplexResult is what duplexRun measured over the judged window.
type duplexResult struct {
	shares  [2]float64       // dialer → passive, passive → dialer: share of the link
	peak    [2]float64       // the largest rate estimate of each side
	srttMax [2]time.Duration // the largest srtt each side reported
	minRTT  [2]time.Duration // each side's minRTT at the window's end
	// lift: the largest distance, from Start to the window's end, by which
	// each side's one-way floor (owdBase) lay above the true one: the
	// Link's one-way delay plus the offset of the two carriers' clocks
	// plus pingTS's clock error. drop: the largest distance, over the
	// window, by which it lay below the true one, which reads as reverse
	// queue that is not there.
	lift, drop [2]time.Duration
}

// latencyBound is the round trip that bulk both ways settles below
// without a clock error (the M3 estimator amendment's price; the
// sched.CapacityDuplex comment derives it): each side's in-flight cap
// 2·rate·(minRTT + PingBusy + 50 ms) plus the reverse queue holds a
// standing queue of 2·k·(minRTT + PingBusy + 50 ms) − minRTT in its own
// direction, k its rate estimate over the link rate, so the round trip is
// 2·(k₁ + k₂)·(minRTT + PingBusy + 50 ms) − minRTT, plus at most one
// chunk's serialization each way (a PING waits behind the chunk being
// written). k is each side's largest estimate over the window; with an
// exact estimate (k = 1) this is 3·minRTT + 4·PingBusy + 200 ms.
func latencyBound(r duplexResult, i int, rate float64) time.Duration {
	k := (r.peak[0] + r.peak[1]) / rate
	m := r.minRTT[i]
	chunks := time.Duration(2 * float64(ChunkSize) / rate * float64(time.Second))
	return time.Duration(2*k*float64(m+hTiming().PingBusy+50*time.Millisecond)) - m + chunks
}

// duplexRun runs c and returns its window's measurements once both flows
// completed intact and in order and neither carrier died (it fails the
// test otherwise). Each flow carries rate × (warm + span + 1 s), so neither
// ends inside the window. Samples are taken every 10 ms.
func duplexRun(t *testing.T, c duplexCase) duplexResult {
	total := uint64(c.rate * (c.warm + c.span + time.Second).Seconds())
	envD, envP := phEnvs()
	envD.Timing.Window, envP.Timing.Window = 8<<20, 8<<20
	began := time.Now() // set before any carrier goroutine reads it
	if c.pingTS != nil {
		envP.Hooks = &testhooks.Hooks{PingTS: func(_ uint32, ts uint64) uint64 { return c.pingTS(ts, time.Since(began)) }}
	}
	sink := newLtSink(total)
	back := newSource(envP, ChunkSize, true)
	defer back.chunk.Release()
	back.offer(total)
	dc, pc := lrLinkPair(t, envD, envP, c.rate, c.rtt/2, c.buf, &lrDuplex{ltSink: sink, src: back})
	src := newSource(envD, ChunkSize, true)
	defer src.chunk.Release()
	src.offer(total)
	start := time.Now()
	dc.Start(src, &hBell{}, StartOptions{})

	var r duplexResult
	// clockErr is how much later than the truth the PINGs x receives read
	// now: pingTS's error, on the dialer's side only.
	clockErr := func(x, peer *Conn) time.Duration {
		if c.pingTS == nil || x != dc {
			return 0
		}
		ts := uint64(time.Since(peer.trunk.base))
		return time.Duration(int64(ts) - int64(c.pingTS(ts, time.Since(began))))
	}
	floorOff := func(x, peer *Conn) time.Duration {
		x.mu.Lock()
		defer x.mu.Unlock()
		if !x.st.owdSeen {
			return 0
		}
		return x.st.owdBase - (c.rtt/2 + peer.trunk.base.Sub(x.trunk.base) + clockErr(x, peer))
	}
	var fwd0 uint64
	var back0 int64
	for at := start.Add(10 * time.Millisecond); at.Before(start.Add(c.warm + c.span)); at = at.Add(10 * time.Millisecond) {
		time.Sleep(time.Until(at))
		var off [2]time.Duration
		for i, x := range [2][2]*Conn{{dc, pc}, {pc, dc}} {
			off[i] = floorOff(x[0], x[1])
			r.lift[i] = max(r.lift[i], off[i])
		}
		if at.Before(start.Add(c.warm)) {
			continue
		}
		r.drop[0], r.drop[1] = max(r.drop[0], -off[0]), max(r.drop[1], -off[1])
		if at.Equal(start.Add(c.warm)) {
			fwd0, _, _ = sink.result()
			back0 = src.rxBytes.Load()
		}
		for i, x := range []*Conn{dc, pc} {
			s := x.Stats()
			r.peak[i], r.srttMax[i] = max(r.peak[i], s.Rate), max(r.srttMax[i], s.SRTT)
		}
	}
	time.Sleep(time.Until(start.Add(c.warm + c.span)))
	fwd1, _, _ := sink.result()
	back1 := src.rxBytes.Load()
	r.shares = [2]float64{float64(fwd1-fwd0) / (c.rate * c.span.Seconds()), float64(back1-back0) / (c.rate * c.span.Seconds())}
	ds, ps := dc.Stats(), pc.Stats()
	r.minRTT = [2]time.Duration{ds.MinRTT, ps.MinRTT}
	t.Logf("dialer → passive %.3f, passive → dialer %.3f of the link; rate peaks %.1f and %.1f MiB/s; srtt max %v and %v (minRTT %v and %v); cap %d and %d KiB; floor lift %v and %v, drop %v and %v",
		r.shares[0], r.shares[1], r.peak[0]/(1<<20), r.peak[1]/(1<<20), r.srttMax[0].Round(time.Millisecond), r.srttMax[1].Round(time.Millisecond),
		ds.MinRTT.Round(time.Millisecond), ps.MinRTT.Round(time.Millisecond), ds.Cap>>10, ps.Cap>>10, r.lift[0].Round(time.Millisecond), r.lift[1].Round(time.Millisecond),
		r.drop[0].Round(time.Millisecond), r.drop[1].Round(time.Millisecond))

	for limit := time.After(time.Minute); ; {
		next, bad, doneAt := sink.result()
		if bad != "" {
			t.Fatalf("the dialer's flow: %s", bad)
		}
		if !doneAt.IsZero() && uint64(src.rxBytes.Load()) >= total {
			break
		}
		select {
		case <-limit:
			t.Fatalf("stalled: %d and %d of %d bytes", next, src.rxBytes.Load(), total)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := uint64(src.rxBytes.Load()); got != total {
		t.Fatalf("the passive's flow: %d of %d bytes", got, total)
	}
	for _, x := range []*Conn{dc, pc} {
		if dead, cause, detail, _ := x.Death(); dead {
			t.Fatalf("carrier %d died: %v %s", x.ID(), cause, detail)
		}
	}
	return r
}

// requireShares fails the test unless each direction of r carried at least
// 0.85 of the link.
func requireShares(t *testing.T, r duplexResult) {
	t.Helper()
	for i, who := range []string{"dialer → passive", "passive → dialer"} {
		if r.shares[i] < 0.85 {
			t.Errorf("%s carried %.3f of the link with bulk both ways, want ≥ 0.85", who, r.shares[i])
		}
	}
}

// TestDuplexKeepsBothDirections_L15 (M3 estimator amendment; L15, plan §4
// capacity): bulk both ways over one carrier (duplexRun). Each side's
// PONGs travel behind the other side's DATA, so its proofs come a reverse
// queue later than its own round trip: with a capacity sized from minRTT
// alone (2·rate·(minRTT + PingBusy + 50 ms)) the side whose PONGs wait
// longer is cap-limited below the link, its rate samples (span ≥ srtt/2
// while the peer is BUSY) measure what it achieved, and the estimate
// settles near CapFloor/srtt. Before the fix (m3 8a9b989) the passive's
// flow carried 0.15 of a 4 MiB/s link at a 20 ms RTT with a 2-MiB link
// buffer and 0.17 of a 16 MiB/s link at 100 ms (the second is the path
// TestByteClockDuplexRateBounded_L32 logs, not judges). The 2 MiB/s row
// with a 128-KiB buffer is a guard, not a failing-first row: it passed
// there too (0.88; the same Link fails only with the mux suite's load,
// TestMuxBulkBothWaysKeepsTheLink) and keeps the short queue covered. The
// capacity now adds the reverse queue measured one way
// (sched.CapacityDuplex, noteOWD).
//
// The long rows run 60 s after the warm-up on deep Links (a buffer of half
// a second or more per direction) at 1–8 MiB/s: the standing queues the
// allowance leaves keep growing for tens of seconds while the rate
// estimates climb, so a 6-s window understates them (the previous bound,
// 1.5 × (3·minRTT + 4·PingBusy + 200 ms), held over 6 s and fails on all
// four 60-s rows: srtt up to 2.25 × the exact-estimate figure).
//
// Under -race (R1-23 lever 1, I3: the rows took 43 s of the Linux race
// lane's carrier package) the three 6-s rows and the cheapest 60-s row
// (1 MiB/s) run, with the same criteria; the non-race lanes run all seven.
//
// PASS: over the window after the warm-up, while both flows run, each
// direction carries ≥ 0.85 of the link; the price of the allowance is
// bounded: neither side's srtt exceeds latencyBound (the amendment's
// standing-queue bound, 2·(k₁ + k₂)·(minRTT + PingBusy + 50 ms) − minRTT
// plus a chunk each way, k the rate overestimate measured in the run); and
// with no clock error neither side's one-way floor rises more than one
// 64-KiB chunk's serialization plus 50 ms above the true one (noteOWD may
// lift it only for an excess its own round trip does not show; a bound
// from srtt alone, which lags the queues' ramp, lifted it by 50–180 ms on
// the two deep Links and read the reverse queue that much short). Both
// flows then complete intact and in order, and neither carrier dies.
func TestDuplexKeepsBothDirections_L15(t *testing.T) {
	for _, tc := range []struct {
		rtt  time.Duration
		rate float64
		buf  int // the link's buffer per direction
		span time.Duration
		race bool // runs under -race too
	}{
		{20 * time.Millisecond, 4 << 20, 2 << 20, 6 * time.Second, true},
		{20 * time.Millisecond, 2 << 20, (2 << 20) / 16, 6 * time.Second, true},
		{100 * time.Millisecond, 16 << 20, 64 << 20, 6 * time.Second, true},
		{20 * time.Millisecond, 4 << 20, 2 << 20, time.Minute, false},
		{20 * time.Millisecond, 2 << 20, 2 << 20, time.Minute, false},
		{20 * time.Millisecond, 1 << 20, 1 << 20, time.Minute, true},
		{20 * time.Millisecond, 8 << 20, 8 << 20, time.Minute, false},
	} {
		if carrierRace && !tc.race {
			continue
		}
		t.Run(fmt.Sprintf("rtt%v/%gMiBps/buf%dKiB/%v", tc.rtt, tc.rate/(1<<20), tc.buf>>10, tc.span), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := duplexRun(t, duplexCase{rtt: tc.rtt, rate: tc.rate, buf: tc.buf, warm: 2 * time.Second, span: tc.span})
				requireShares(t, r)
				for i, who := range []string{"dialer", "passive"} {
					if bound := latencyBound(r, i, tc.rate); r.srttMax[i] > bound {
						t.Errorf("%s: srtt reached %v with bulk both ways, want ≤ %v (2·(k₁ + k₂)·(minRTT + PingBusy + 50 ms) − minRTT + 2 chunks, k₁ + k₂ = %.2f)",
							who, r.srttMax[i], bound, (r.peak[0]+r.peak[1])/tc.rate)
					}
					if bound := time.Duration(float64(ChunkSize)/tc.rate*float64(time.Second)) + 50*time.Millisecond; r.lift[i] > bound {
						t.Errorf("%s: the one-way floor rose %v above the true one without a clock error, want ≤ %v", who, r.lift[i], bound)
					}
				}
			})
		})
	}
}

// TestDuplexPeerClockSkew_L15 (M3 estimator review; noteOWD's floor): bulk
// both ways (duplexRun, 20 ms RTT, 2-MiB link buffer) for 150 virtual
// seconds while the passive's PING TS — its monotonic clock — runs slow
// against the dialer's or steps back. Each such PING's apparent one-way
// delay grows by the clock error, and while the passive stays BUSY nothing
// re-anchored the dialer's floor, which only fell to a smaller delay or
// crept up on non-BUSY PINGs: the error read as a reverse queue, the
// dialer's allowance sat at its srtt − minRTT clamp (which holds its own
// forward queue as well), the dialer's queue grew and the passive's flow
// fell back towards DEFECT 2. The floor now also rises by a quarter of any
// excess beyond the queueing the dialer's own round trip shows, at once
// beyond it by more than DeadMax. Without that rule (7917493's floor) the
// passive → dialer share over the last 50 s is 0.71 (drift 0.5 %,
// 2 MiB/s), 0.61 (drift 1 %, 4 MiB/s), about 0.4 with the flow stalled at
// the end (a 1-s step, 2 MiB/s) and 0.76 (a 6-s step, 4 MiB/s), the same
// at GOMAXPROCS 1 and 4; with it 0.90, 0.90–0.91, 0.93 and 0.94. A 0.5 % drift is
// 10 times NTP's largest slew (500 ppm); over the run it accumulates
// 0.75 s, what 100 ppm accumulates in about two hours. A peer clock that
// runs fast is harmless (the floor follows a smaller delay at once). The
// 0.05 % row is NTP's largest slew.
//
// The latency price under a clock error: what the floor reads short of
// the truth reads as reverse queue, so the dialer's allowance and its
// standing queue grow by it (at most its forward queue, noteOWD's bound).
// Steps, a 0.05 % drift and a 1 % drift at 4 MiB/s stay within the
// no-error bound (latencyBound); a 0.5 % drift at 2 MiB/s exceeds it by
// about a quarter (srtt 1.28 s against 1.02 s, the floor 0.21 s short).
//
// Under -race (R1-23 lever 1, I3: the rows took 90 s of the Linux race
// lane's carrier package) the 0.5 % drift and the 1-s step run, both at
// 2 MiB/s and with the same criteria; the non-race lanes run all five.
//
// PASS: over the last 50 s each direction carries ≥ 0.85 of the link and
// neither side's srtt exceeds latencyBound times the row's slack (1, or
// 1.5 for the 0.5 % drift); both flows complete intact and in order;
// neither carrier dies.
func TestDuplexPeerClockSkew_L15(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rate  float64
		drift float64       // the passive's clock runs slow by this fraction
		step  time.Duration // and steps back by this much 10 s into the run
		slack float64       // the srtt bound: latencyBound × slack
		race  bool          // runs under -race too
	}{
		{"drift0.05%/2MiBps", 2 << 20, 0.0005, 0, 1, false},
		{"drift0.5%/2MiBps", 2 << 20, 0.005, 0, 1.5, true},
		{"drift1%/4MiBps", 4 << 20, 0.01, 0, 1, false},
		{"step1s/2MiBps", 2 << 20, 0, time.Second, 1, true},
		{"step6s/4MiBps", 4 << 20, 0, 6 * time.Second, 1, false}, // beyond DeadMax: the floor moves at once
	} {
		if carrierRace && !tc.race {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				skew := func(ts uint64, since time.Duration) uint64 {
					v := float64(ts) * (1 - tc.drift)
					if since >= 10*time.Second {
						v -= float64(tc.step)
					}
					return uint64(max(0, v))
				}
				r := duplexRun(t, duplexCase{rtt: 20 * time.Millisecond, rate: tc.rate, buf: 2 << 20,
					warm: 100 * time.Second, span: 50 * time.Second, pingTS: skew})
				requireShares(t, r)
				for i, who := range []string{"dialer", "passive"} {
					if bound := time.Duration(tc.slack * float64(latencyBound(r, i, tc.rate))); r.srttMax[i] > bound {
						t.Errorf("%s: srtt reached %v under the clock error, want ≤ %v (latencyBound × %g)", who, r.srttMax[i], bound, tc.slack)
					}
				}
			})
		})
	}
}

// TestReverseQueueAllowance (M3 estimator amendment; sched.CapacityDuplex):
// the reverse-path allowance a carrier adds to its capacity, driven through
// onPing with chosen TS values (one-way delays) and BUSY flags.
//
//   - The floor of the one-way delay is its smallest value; a PING's excess
//     over it is the reverse queue, followed at once when it rises and with
//     gain 1/8 when it falls.
//   - The allowance applies only while the peer reports BUSY and only after
//     an RTT was measured; it adds min(delivered, rate)·revQ and never more
//     than srtt − minRTT of it.
//   - A PING without BUSY moves the floor up by 1/16 of its excess (a peer
//     clock that runs slow); a BUSY PING whose excess is within srtt −
//     minRTT does not (beyond it: TestReverseQueueFloorBound); a smaller
//     delay resets the floor at once.
func TestReverseQueueAllowance(t *testing.T) {
	const rate = 4 << 20
	t0 := time.Unix(1000, 0)
	tr := &trunk{tm: hTiming(), base: t0}
	st := &tr.st
	st.rate, st.dlvRate = rate, rate
	st.srtt, st.minRTT, st.rttvar = 600*time.Millisecond, 20*time.Millisecond, 0
	plain := sched.Capacity(rate, st.minRTT, tr.tm.PingBusy, tr.tm.CapFloor, tr.tm.Window)
	allow := func(d time.Duration, r float64) int64 { // the formula's own rows are sched's
		return sched.CapacityDuplex(rate, st.minRTT, tr.tm.PingBusy, r, d, tr.tm.CapFloor, tr.tm.Window)
	}
	// ping delivers a PING sent at the peer's clock 5 s + at (an offset of
	// 5 s against ours) that took oneWay to arrive.
	ping := func(at, oneWay time.Duration, busy bool) {
		tr.onPing(busy, &wire.Ping{ID: 1, TS: uint64(5*time.Second + at)}, t0.Add(at+oneWay))
	}
	capNow := func() int64 {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return tr.capacityLocked()
	}

	// No RTT yet: nothing, whatever the PINGs say.
	ping(time.Second, 10*time.Millisecond, false)
	ping(2*time.Second, 310*time.Millisecond, true)
	st.rttSeen = false
	if got := capNow(); got != plain {
		t.Fatalf("before the first RTT: capacity %d, want the plain %d", got, plain)
	}
	st.rttSeen = true
	if st.revQ != 300*time.Millisecond {
		t.Fatalf("a rising excess is taken at once: revQ %v, want 300ms", st.revQ)
	}
	if got, want := capNow(), allow(300*time.Millisecond, rate); got != want {
		t.Fatalf("peer BUSY, 300 ms reverse queue: capacity %d, want %d", got, want)
	}

	// The delivered rate, not the (decaying-max) estimate, prices it when
	// it is lower; the estimate bounds it when it is higher.
	st.dlvRate = rate / 2
	if got, want := capNow(), allow(300*time.Millisecond, rate/2); got != want {
		t.Fatalf("delivered rate/2: capacity %d, want %d", got, want)
	}
	st.dlvRate = 3 * rate
	if got, want := capNow(), allow(300*time.Millisecond, rate); got != want {
		t.Fatalf("delivered 3× the estimate: capacity %d, want %d", got, want)
	}
	st.dlvRate = rate

	// Bounded by srtt − minRTT: the reverse queue is part of the round trip.
	st.srtt = 120 * time.Millisecond
	if got, want := capNow(), allow(100*time.Millisecond, rate); got != want {
		t.Fatalf("srtt 120 ms: capacity %d, want %d (allowance clamped at srtt − minRTT)", got, want)
	}
	st.srtt = 600 * time.Millisecond

	// A falling excess moves revQ by 1/8 per PING (as srtt).
	ping(3*time.Second, 110*time.Millisecond, true)
	if want := 300*time.Millisecond - 200*time.Millisecond/owdGain; st.revQ != want {
		t.Fatalf("a falling excess: revQ %v, want %v", st.revQ, want)
	}

	// Without BUSY: no allowance, and the floor creeps up by 1/16 of the
	// excess; with BUSY (an excess within srtt − minRTT) it holds.
	ping(4*time.Second, 170*time.Millisecond, false)
	if got := capNow(); got != plain {
		t.Fatalf("peer not BUSY: capacity %d, want the plain %d", got, plain)
	}
	base := st.owdBase
	ping(5*time.Second, 170*time.Millisecond, false)
	if want := base + (170*time.Millisecond-5*time.Second-base)/owdCreep; st.owdBase != want {
		t.Fatalf("a non-BUSY PING: floor %v, want %v", st.owdBase, want)
	}
	base = st.owdBase
	ping(6*time.Second, 400*time.Millisecond, true)
	if st.owdBase != base {
		t.Fatalf("a BUSY PING moved the floor: %v, want %v", st.owdBase, base)
	}
	// A smaller one-way delay is the new floor at once.
	ping(7*time.Second, 5*time.Millisecond, true)
	if want := 5*time.Millisecond - 5*time.Second; st.owdBase != want {
		t.Fatalf("a smaller delay: floor %v, want %v", st.owdBase, want)
	}

	// A wrong TS (a lying or drifting peer) adds at most srtt − minRTT.
	tr.onPing(true, &wire.Ping{ID: 2, TS: 0}, t0.Add(8*time.Second+time.Hour))
	if got, want := capNow(), allow(st.srtt-st.minRTT, rate); got != want {
		t.Fatalf("a TS an hour off: capacity %d, want %d", got, want)
	}
	st.revQ = 10 * time.Hour
	if got := capNow(); got > tr.tm.Window {
		t.Fatalf("capacity %d beyond the window %d", got, tr.tm.Window)
	}
}

// TestReverseQueueFloorBound (M3 estimator review; noteOWD, owdOf): the
// floor of the one-way delay checked against the round trip, and PING TS
// values that no clock produces, driven through onPing.
//
//   - No reverse queue exceeds rt − minRTT, the queueing our own round
//     trip shows in both directions together, where rt is the largest of
//     srtt, the latest RTT sample and the wait of the oldest unanswered
//     PING (so it does not lag a growing queue). An excess beyond it
//     raises the floor by a quarter of the part beyond, BUSY or not; an
//     excess within it leaves a BUSY PING's floor alone; an excess beyond
//     it by more than DeadMax moves the floor at once, so that the excess
//     is rt − minRTT. Before the first RTT the rule does not apply.
//   - The rule applies to a PING without BUSY as well, after the
//     sixteenth such a PING moves the floor by: beyond the bound by more
//     than DeadMax, at once; otherwise by a quarter of what is left beyond
//     it.
//   - A smaller delay brings the floor down at once after such a move.
//   - A TS at or above 2^63 ns is no monotonic clock's: the PING is still
//     answered (it is the PONG's echo) and leaves the floor and revQ alone.
//   - A TS far ahead (MaxInt64 ns) is clamped, so the floor arithmetic
//     never overflows: the next ordinary PING re-anchors the floor within
//     rt − minRTT of its delay, and as the round trip falls the floor
//     follows it, so a single wrong TS does not hold the allowance at its
//     clamp for the carrier's life.
func TestReverseQueueFloorBound(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := &trunk{tm: hTiming(), base: t0}
	st := &tr.st
	const off = 5 * time.Second // the peer's clock against ours
	// ping delivers PING id sent at our time at (the peer's clock reads
	// off + at) that took oneWay to arrive.
	ping := func(id uint32, at, oneWay time.Duration, busy bool) {
		tr.onPing(busy, &wire.Ping{ID: id, TS: uint64(off + at)}, t0.Add(at+oneWay))
	}
	floor := 10*time.Millisecond - off
	ping(1, time.Second, 10*time.Millisecond, true)
	if st.owdBase != floor {
		t.Fatalf("first PING: floor %v, want %v", st.owdBase, floor)
	}
	// No RTT yet: a 2-s excess is taken as it is.
	ping(2, 2*time.Second, 2*time.Second, true)
	if st.owdBase != floor || st.revQ != 1990*time.Millisecond {
		t.Fatalf("before the first RTT: floor %v revQ %v, want %v and 1.99s", st.owdBase, st.revQ, floor)
	}

	st.rttSeen, st.srtt, st.minRTT, st.revQ = true, 200*time.Millisecond, 20*time.Millisecond, 0
	const bound = 180 * time.Millisecond // srtt − minRTT
	ping(3, 3*time.Second, 160*time.Millisecond, true)
	if st.owdBase != floor || st.revQ != 150*time.Millisecond {
		t.Fatalf("an excess within srtt − minRTT: floor %v revQ %v, want %v and 150ms", st.owdBase, st.revQ, floor)
	}
	// An excess of 280 ms: 100 ms beyond the bound, a quarter of it.
	ping(4, 4*time.Second, 290*time.Millisecond, true)
	floor += 100 * time.Millisecond / owdLift
	if st.owdBase != floor || st.revQ != 280*time.Millisecond-100*time.Millisecond/owdLift {
		t.Fatalf("an excess 100 ms beyond srtt − minRTT: floor %v revQ %v, want %v and %v", st.owdBase, st.revQ, floor, 280*time.Millisecond-100*time.Millisecond/owdLift)
	}
	// The latest RTT sample widens the bound (400 ms: 380 ms of queueing),
	// and so does the wait of the oldest unanswered PING (500 ms): a queue
	// that grows faster than srtt follows is no clock error.
	excess := func(e time.Duration) time.Duration { return floor + off + e } // the one-way delay giving excess e
	st.lastRTT = 400 * time.Millisecond
	ping(40, 4100*time.Millisecond, excess(300*time.Millisecond), true)
	if st.owdBase != floor {
		t.Fatalf("an excess within the latest RTT sample's bound: floor %v, want %v", st.owdBase, floor)
	}
	st.lastRTT = 0
	at, ow := 4200*time.Millisecond, excess(400*time.Millisecond)
	st.ring[st.head], st.n = pingRecord{id: 41, committedAt: t0.Add(at + ow - 500*time.Millisecond)}, 1
	ping(41, at, ow, true)
	if st.owdBase != floor {
		t.Fatalf("an excess within the oldest unanswered PING's wait: floor %v, want %v", st.owdBase, floor)
	}
	st.n = 0
	// An excess of 10 s, beyond the bound (srtt again) by more than
	// DeadMax: at once.
	ping(5, 5*time.Second, 10*time.Second+10*time.Millisecond, true)
	if want := 10*time.Second + 10*time.Millisecond - off - bound; st.owdBase != want {
		t.Fatalf("an excess beyond srtt − minRTT + DeadMax: floor %v, want %v", st.owdBase, want)
	}
	// Ordinary PINGs again: the floor falls to the smaller delay at once.
	ping(6, 6*time.Second, 30*time.Millisecond, true)
	if want := 30*time.Millisecond - off; st.owdBase != want {
		t.Fatalf("after the outlier: floor %v, want %v", st.owdBase, want)
	}
	// The rule holds without BUSY too: a PING without BUSY whose excess is
	// beyond the bound moves the floor by its sixteenth and then by the
	// rule, here at once (10 s beyond), not by the sixteenth alone.
	ping(60, 6100*time.Millisecond, 10*time.Second+30*time.Millisecond, false)
	if want := 10*time.Second + 30*time.Millisecond - off - bound; st.owdBase != want {
		t.Fatalf("a PING without BUSY beyond srtt − minRTT + DeadMax: floor %v, want %v", st.owdBase, want)
	}
	// And by a quarter of the part beyond the bound after its sixteenth.
	floor = 30*time.Millisecond - off
	ping(61, 6200*time.Millisecond, 30*time.Millisecond, true)
	if st.owdBase != floor {
		t.Fatalf("back to the ordinary delay: floor %v, want %v", st.owdBase, floor)
	}
	ping(62, 6300*time.Millisecond, 30*time.Millisecond+500*time.Millisecond, false)
	floor += 500 * time.Millisecond / owdCreep
	floor += (500*time.Millisecond - 500*time.Millisecond/owdCreep - bound) / owdLift
	if st.owdBase != floor {
		t.Fatalf("a PING without BUSY 500 ms late: floor %v, want %v (a sixteenth, then a quarter beyond the bound)", st.owdBase, floor)
	}
	ping(63, 6400*time.Millisecond, 30*time.Millisecond, true)

	// TS values no monotonic clock reaches: answered, otherwise ignored.
	base, q := st.owdBase, st.revQ
	for i, ts := range []uint64{1 << 63, math.MaxUint64} {
		id := uint32(7 + i)
		tr.onPing(true, &wire.Ping{ID: id, TS: ts}, t0.Add(7*time.Second))
		if st.owdBase != base || st.revQ != q {
			t.Fatalf("TS %#x: floor %v revQ %v, want them unchanged (%v, %v)", ts, st.owdBase, st.revQ, base, q)
		}
		if !st.pongDue || st.pong.ID != id {
			t.Fatalf("TS %#x: the PING is not answered", ts)
		}
	}
	// A TS far ahead: clamped (no overflow), then re-anchored at once.
	tr.onPing(true, &wire.Ping{ID: 9, TS: math.MaxInt64}, t0.Add(8*time.Second))
	if st.owdBase != -owdLimit {
		t.Fatalf("TS MaxInt64: floor %v, want the clamp %v", st.owdBase, -owdLimit)
	}
	ping(10, 9*time.Second, 30*time.Millisecond, true)
	if want := 30*time.Millisecond - off - bound; st.owdBase != want {
		t.Fatalf("an ordinary PING after it: floor %v, want %v", st.owdBase, want)
	}
	// While the round trip stays loaded the floor is off by at most the
	// bound; once the round trip falls (srtt 50 ms: bound 30 ms) BUSY PINGs
	// close the gap.
	st.srtt = 50 * time.Millisecond
	for i := range 128 {
		ping(uint32(11+i), 10*time.Second+time.Duration(i)*10*time.Millisecond, 30*time.Millisecond, true)
	}
	if ex := 30*time.Millisecond - off - st.owdBase; ex > 31*time.Millisecond {
		t.Fatalf("after 128 PINGs with srtt − minRTT = 30 ms: excess %v, want ≤ 31ms", ex)
	}
}

// TestDeliveredRateWindow: noteDelivered averages the PONG watermark's
// progress over windows of at least two smoothed RTTs, so a cluster of
// PONGs that proves at once what was delivered over a longer time does not
// read as a burst of rate.
func TestDeliveredRateWindow(t *testing.T) {
	t0 := time.Unix(1000, 0)
	st := &carrierState{srtt: 100 * time.Millisecond}
	st.noteDelivered(t0) // opens the first window
	if st.dlvRate != 0 {
		t.Fatalf("no window closed yet: %v", st.dlvRate)
	}
	// 1 MiB proven 150 ms later (under two RTTs): no sample.
	st.pongMark = 1 << 20
	st.noteDelivered(t0.Add(150 * time.Millisecond))
	if st.dlvRate != 0 {
		t.Fatalf("a window shorter than 2·srtt closed: %v", st.dlvRate)
	}
	// Another MiB 50 ms later: the window spans 200 ms = 2·srtt.
	st.pongMark = 2 << 20
	st.noteDelivered(t0.Add(200 * time.Millisecond))
	if want := float64(2<<20) / 0.2; st.dlvRate != want {
		t.Fatalf("delivered rate %v, want %v", st.dlvRate, want)
	}
	// The next window starts there.
	st.pongMark = 3 << 20
	st.noteDelivered(t0.Add(600 * time.Millisecond))
	if want := float64(1<<20) / 0.4; st.dlvRate != want {
		t.Fatalf("second window: delivered rate %v, want %v", st.dlvRate, want)
	}
}
