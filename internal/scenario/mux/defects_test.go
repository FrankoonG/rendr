package mux

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// The two tests of this file fail on m3 at f14a458: they record product
// defects this suite found whose fixes are not WP13's (see the WP13
// report's open items). Each states the expected behaviour; neither is
// sized to pass by tolerance.

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
// every session receives the mean ± 2 quanta. Observed on m3 at f14a458,
// deterministic at -cpu 1, 2 and 4: windows where one view gets 3 quanta
// and another 12 (mean 7.4), so a view's service is not a round robin;
// over 16 s the shares average back to 0.7–1.25 of the mean. Under the
// race detector the same shows with four views at 2 MiB/s (see
// TestMuxRaceOnSharedTrunks). Root cause (internal/carrier/mux.go): a
// round starts at t.cursor % n of the ready ring, but the ring's order is
// the previous rounds' visit order — a PONG re-readies the cap-marked
// views (capList) in the order the last round visited them, and
// returnScratchLocked pushes back in scratch order — so the cursor rotates
// an already rotated list: the view served first follows cumulative sums
// of the cursor, perturbed by every control-only round and every session
// wake (n changes with them); and a view a round could not serve (the cap
// reached, used == 0) also loses its deficit. A fix keeps the ready ring
// in round-robin order — the views a round served behind the ones it did
// not reach, the cap-marked ones re-readied unserved first — and starts
// every round at the ring's head.
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
// of 20 ms RTT shaped to 4 MiB/s per direction sends open-ended bulk in
// both directions at once. Not mux-specific — the session holds its
// carrier alone, and a CheapSubflow factory behaves the same — but rendr
// mux makes the case common: every shared carrier that carries sessions
// sending in opposite directions is loaded both ways.
//
// PASS: over 8 s after a 2-s warm-up each direction carries ≥ 0.85 of the
// link. Observed on m3 at f14a458: A → B 0.21 of the link, B → A 0.94,
// deterministic at -cpu 1, 2 and 4 (with 4 + 4 sessions on one shared
// carrier one direction intermittently falls to 0.55–0.70). Root cause
// (internal/carrier/estimator.go, sched.Capacity): the capacity is
// 2 × the proven rate × (MinRTT + PingBusy + a slack) — about 160 ms of
// the rate here — while the bytes in flight take the smoothed RTT to be
// proven;
// with bulk both ways each side's PONGs queue behind the other side's
// DATA, so the smoothed RTT holds both directions' queueing delay (here
// about 150–200 ms against a 20-ms minimum) and a side whose rate sample
// falls — the peer is BUSY, so a sample spans at least half the smoothed
// RTT (rateSpan) and measures what that side achieved, as the comment on
// rateSpan says — gets a smaller capacity, carries less, and samples a
// lower rate again: the estimate decays towards CapFloor / SRTT (128 KiB
// per ~150 ms ≈ 0.85 MiB/s, the 0.21 above) while the other direction
// keeps the queue that inflates the smoothed RTT.
func TestMuxBulkBothWaysKeepsTheLink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rate = 4 << 20
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, rate: rate})
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
	})
}
