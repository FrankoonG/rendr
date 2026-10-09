package mux

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// The tests of this file fail on m3 (f14a458 and 3bf15a2): they record
// product defects this suite found whose fixes are not WP13's (see the
// WP13 report's open items). Each states the expected behaviour; none is
// sized to pass by tolerance. Rows of the suite sized around them (to
// return to the design's sizes once they are fixed): TestMuxFairness_L15
// (8-KiB quantum; 4 MiB/s under -race), TestMuxStalledReaderIsolation_L15_L16
// (8-KiB quantum) and TestMuxRaceOnSharedTrunks (8 MiB/s under -race).

// TestMuxCapLimitedSharesFair (M3 design §A5.3, M3-D10; L15): 8 selector
// sessions share the one carrier of a one-factory Peer over a Link of
// 20 ms RTT shaped to 1 MiB/s, each sending open-ended bulk B → A, so
// every view is backlogged and the carrier runs at its capacity cap: a
// PONG frees room for about one DRR quantum (64 KiB) and a writer round
// serves one or two views.
//
// PASS: deficit round robin over backlogged views serves them in turn, so
// in any span of 8 quanta per view each view gets its 8 within ±2 (and
// never 8 in a row for the same view): in every 4-s window (≈ 64 quanta in
// all, 8 per view at 128 KiB/s) starting each second from 2 s to 14 s,
// every session receives the mean ± 2 quanta. Observed on m3 at f14a458
// and 3bf15a2: it fails at every GOMAXPROCS (1, 2, 4) and under -race,
// with different numbers per setting — windows where one view gets 3
// quanta and another 12 (mean 7.4), so a view's service is not a round
// robin; over 16 s the shares average back to 0.7–1.25 of the mean. It
// does not depend on the Link's queue: with a bottleneck queue of rate/16
// it fails the same way (quanta [4 3 11 8 4 8 11 3], mean 6.5). Under the
// race detector the same shows with four views at 2 MiB/s (see
// TestMuxRaceOnSharedTrunks).
//
// Root cause (internal/carrier/mux.go): a round starts at t.cursor % n of
// the ready ring, but the ring's order is the previous rounds' visit
// order — a PONG re-readies the cap-marked views (capList) in the order
// the last round visited them, and returnScratchLocked pushes the views
// back in scratch index order 0..n-1, although its comment and R1-1 rule 4
// say "in rotation order" — so the cursor rotates an already rotated
// list: the view served first follows cumulative sums of the cursor,
// perturbed by every control-only round and every session wake (n changes
// with them). Second, a view a round could not serve (the cap reached,
// used == 0) loses its deficit; that reset is A5.3's own pseudo-code
// (v.deficit = used > 0 ? ... : 0), so that part of the fix is an
// amendment of A5.3, not only of the code. A fix keeps the ready ring in
// round-robin order — the views a round served behind the ones it did not
// reach, the cap-marked ones re-readied unserved first — starts every
// round at the ring's head, and keeps the deficit of a view the cap
// stopped.
func TestMuxCapLimitedSharesFair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n, rate, quantum = 8, 1 << 20, 64 << 10
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, rate: rate})
		peer := w.peer("a")
		ps := w.openMany(peer, "S", n, func(int) rendr.Mode { return rendr.ModeSelector })
		requireShared(t, ps)
		b := w.startBulk(ps, openEnded, 0)
		start := time.Now()
		sleepUntil(start.Add(18 * time.Second))
		var bad []string
		for at := start.Add(2 * time.Second); !at.After(start.Add(14 * time.Second)); at = at.Add(time.Second) {
			var xs []int64
			var sum int64
			for _, r := range b.rx {
				x := r.bytesAt(at.Add(4*time.Second)) - r.bytesAt(at)
				xs = append(xs, x)
				sum += x
			}
			mean := sum / n
			var qs []string
			off := false
			for _, x := range xs {
				qs = append(qs, fmt.Sprintf("%.1f", float64(x)/quantum))
				off = off || x < mean-2*quantum || x > mean+2*quantum
			}
			t.Logf("window +%v: quanta per view %v (mean %.1f)", at.Sub(start), qs, float64(mean)/quantum)
			if off {
				bad = append(bad, fmt.Sprintf("+%v: %v (mean %.1f)", at.Sub(start), qs, float64(mean)/quantum))
			}
		}
		for _, s := range b.tx {
			s.end()
		}
		for i, r := range b.rx {
			r.waitSent(t, b.tx[i], 5*time.Minute)
		}
		for _, r := range b.up {
			r.wait(t, time.Minute)
		}
		if len(bad) > 0 {
			t.Errorf("4-s windows where a backlogged view's quanta left the mean ± 2: %v", bad)
		}
		closeAll(t, ps)
		w.noViolation()
		w.close()
	})
}

// TestMuxBulkBothWaysKeepsTheLink (L15; plan §3 estimator; found by
// TestMuxFairness_L15's bulk both ways): one selector session over a Link
// of 20 ms RTT sends open-ended bulk in both directions at once. Not
// mux-specific — the session holds its carrier alone, and a CheapSubflow
// factory behaves the same — but rendr mux makes the case common: every
// shared carrier that carries sessions sending in opposite directions is
// loaded both ways. Two Links: "deep" is 4 MiB/s per direction with
// rendrtest's default 2-MiB buffer (a 500-ms bottleneck queue); "shallow"
// is 2 MiB/s with a queue of rate/16 (62.5 ms).
//
// PASS: over 8 s after a 2-s warm-up each direction carries ≥ 0.85 of the
// link. Observed on m3 at f14a458 and 3bf15a2, at every GOMAXPROCS: deep —
// A → B 0.21 of the link, B → A 0.94; shallow — see the subtest's log
// (with 4 + 4 sessions on one shared carrier at 2 MiB/s, one direction
// falls to 0.55–0.85 of the link for every queue from 64 to 512 KiB). The
// deep form depends on the queue: at 4 MiB/s with a queue of rate/16 the
// same session carries 1.00 and 0.92 of the link and passes; at 2 MiB/s
// a short queue does not help.
//
// Root cause (internal/carrier/estimator.go, sched.Capacity): the
// capacity is 2 × the proven rate × (MinRTT + PingBusy + a slack) — about
// 160 ms of the rate here — while the bytes in flight take the smoothed
// RTT to be proven; with bulk both ways each side's PONGs queue behind the
// other side's DATA, so the smoothed RTT holds both directions' queueing
// delay (about 150–200 ms against a 20-ms minimum with the deep queue) and
// a side whose rate sample falls — the peer is BUSY, so a sample spans at
// least half the smoothed RTT (rateSpan) and measures what that side
// achieved, as the comment on rateSpan says — gets a smaller capacity,
// carries less, and samples a lower rate again: the estimate decays
// towards CapFloor / SRTT (128 KiB per ~150 ms ≈ 0.85 MiB/s, the 0.21
// above) while the other direction keeps the queue that inflates the
// smoothed RTT. At 2 MiB/s CapFloor / SRTT is a larger part of the link,
// so even a short queue lets one direction settle there.
func TestMuxBulkBothWaysKeepsTheLink(t *testing.T) {
	for _, c := range []struct {
		name   string
		rate   float64
		buffer int
	}{{"deep", 4 << 20, 0}, {"shallow", 2 << 20, (2 << 20) / 16}} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { bulkBothWays(t, c.rate, c.buffer) })
		})
	}
}

func bulkBothWays(t *testing.T, rate float64, buffer int) {
	w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, rate: rate, buffer: buffer})
	s := w.open(w.peer("a"), "S", rendr.ModeSelector)
	up := startReceiver("A → B", s.p, 1, openEnded)
	down := startReceiver("B → A", s.d, 2, openEnded)
	txUp, txDown := w.startSender(s.d, 1, openEnded, 0), w.startSender(s.p, 2, openEnded, 0)
	start := time.Now()
	from, to := start.Add(2*time.Second), start.Add(10*time.Second)
	sleepUntil(to)
	shares := [2]float64{
		float64(up.bytesAt(to)-up.bytesAt(from)) / (rate * 8),
		float64(down.bytesAt(to)-down.bytesAt(from)) / (rate * 8),
	}
	cs := liveOf(s.d.Status())
	t.Logf("A → B %.3f, B → A %.3f of the link; dialer carrier %+v", shares[0], shares[1], cs)
	txUp.end()
	txDown.end()
	up.waitSent(t, txUp, 5*time.Minute)
	down.waitSent(t, txDown, 5*time.Minute)
	for i, x := range shares {
		if x < 0.85 {
			t.Errorf("%s carried %.3f of the link with bulk both ways, want ≥ 0.85", [2]string{"A → B", "B → A"}[i], x)
		}
	}
	closeBoth(t, s)
	w.noViolation()
	w.close()
}

// TestMuxFairnessDefaultQuantum_L15 (M3 design §A11.2, §A5.3; L15,
// M3-D10): TestMuxFairness_L15 as A11.2 specifies it, at the default
// 64-KiB DRR quantum, with the same Link, load, fairness, echo (P99 ≤
// base + Cap/rate + 2·RTT) and integrity criteria, plus the round robin of
// TestMuxCapLimitedSharesFair on 1-s windows: every bulk session receives
// its direction's mean ± 2 quanta in every window (a deficit round robin
// over 4 backlogged views keeps each within 1 quantum of the others).
// Observed on m3 at 3bf15a2: it fails in 24 of 24 runs (8 at each of -cpu
// 1, 2 and 4) — windows where a session gets 10–13 quanta against a mean
// near 16. The A11.2 criteria alone fail in about half of the runs (all
// at -cpu 1, 4 of 8 at -cpu 2, 3–5 of 8 at -cpu 4): echo P99 0.38–1.45 s
// against a limit of about 0.54 s, Jain's index down to 0.88 with a
// direction at 0.61 of the link. Cause: DEFECT 1 — the carrier runs
// cap-limited, and at 16 quanta per session-second the writer's rotation,
// not DRR's quota, decides who is served; the echo's view waits for
// several rounds (SRTT 80–100 ms, Inflight 0.3–1 MB on the carrier).
func TestMuxFairnessDefaultQuantum_L15(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { fairness(t, 64<<10, true) })
}
