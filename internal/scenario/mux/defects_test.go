package mux

import (
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
// (4 MiB/s under -race, not R1-11's 2 MiB/s). The DRR rotation defect
// this file also recorded is fixed (WP DRR); its rows,
// TestMuxCapLimitedSharesFair and the default-quantum fairness, are in
// fair_test.go.

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
