package mux

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestMuxBulkBothWaysKeepsTheLink (L15; plan §4 capacity, M3 estimator
// amendment; found by TestMuxFairness_L15's bulk both ways): one selector
// session over a Link of 20 ms RTT sends open-ended bulk in both directions
// at once. Not mux-specific — the session holds its carrier alone, and the
// carrier-level row TestDuplexKeepsBothDirections_L15 shows the same — but
// rendr mux makes the case common: every shared carrier that carries
// sessions sending in opposite directions is loaded both ways. Two Links:
// "deep" is 4 MiB/s per direction with rendrtest's default 2-MiB buffer (a
// 500-ms bottleneck queue); "shallow" is 2 MiB/s with a queue of rate/16
// (62.5 ms).
//
// PASS: over 8 s after a 2-s warm-up each direction carries ≥ 0.85 of the
// link; both flows end intact. Observed before the fix (m3 8a9b989, at
// every GOMAXPROCS): deep A → B 0.209 and B → A 0.939, shallow A → B 0.750
// and B → A 0.996; after it deep 0.96/0.93 and shallow 0.92/0.96 (with
// WP DRR merged; deep reports SRTT about 490 ms against a 41-ms MinRTT,
// the allowance's standing queues: sched.CapacityDuplex).
//
// Cause (internal/carrier/estimator.go, sched.Capacity): the capacity was
// 2·rate·(minRTT + PingBusy + 50 ms), about 160 ms of the rate here, while
// a byte is proven a forward trip, the reverse queue and the rest of the
// return trip after it is written: each side's PONGs queue behind the
// other side's DATA (and, where the conn's Write blocks, behind the peer's
// write in progress). The side whose PONGs wait longer is cap-limited
// below the link; while the peer is BUSY its rate samples span at least
// half the smoothed RTT and measure what it achieved, so the decaying-max
// estimate, and the capacity with it, fall again, towards CapFloor/srtt
// (128 KiB per ~150 ms ≈ 0.85 MiB/s, the 0.21 above). Both sides see the
// same round trip, so no capacity computed from it can tell the reverse
// queue from the forward one: the side behind never catches up. The fix
// measures the reverse queue one way — the arrival of the peer's PINGs
// against their TS, over the smallest such delay — and, while the peer is
// BUSY, adds it to the capacity at the delivered rate (sched.CapacityDuplex,
// bounded by srtt − minRTT; the floor follows a drifting or stepping peer
// clock, TestDuplexPeerClockSkew_L15).
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
