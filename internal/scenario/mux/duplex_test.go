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
// (62.5 ms). "shallow-late6ms" is the shallow Link with the A → B sender
// started 6 ms after the B → A sender (the window counts from the first).
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
//
// The shallow Link's queue is shorter than one 256-KiB batch, so both
// writers' Writes block, and in some interleavings of the race build
// (about 1 in 260 host -race runs; about one pool race-unit pass in three)
// one direction carried 0.754–0.848 (KL-20): a PING leads its batch and
// proves only the bytes before it, which stay in flight for the blocking
// Write as well as the round trip, and the side that loses the phase of
// the two blocking writers is held at its cap. The duplex allowance now
// has two parts, both applied only while the peer reports BUSY
// (duplexLocked in internal/carrier, M5-D63): the reverse queue (M3) and
// the write lag (M5; priced at the rate estimate, at most one batch). The
// deep Link, whose Writes block only once its 2-MiB queue fills, needs the
// reverse-queue part; the shallow Links need the write-lag part. Without
// the allowance: deep 0.209/0.939, shallow 0.750/0.996. Without the write
// lag: shallow-late6ms 0.859/0.820 in every run (a start 3–10 ms late
// gives that phase; the A → B start swept over 0–400 ms in 4-ms steps
// failed in 18 of 101 cells, the B → A start in 3). With both parts: 0
// failures in 2,371 host -race runs of shallow (the worst direction
// 0.910), and no sweep cell below 0.910.
func TestMuxBulkBothWaysKeepsTheLink(t *testing.T) {
	for _, c := range []struct {
		name   string
		rate   float64
		buffer int
		late   time.Duration // the A → B sender starts this much after the B → A sender
	}{
		{"deep", 4 << 20, 0, 0},
		{"shallow", 2 << 20, (2 << 20) / 16, 0},
		{"shallow-late6ms", 2 << 20, (2 << 20) / 16, 6 * time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { bulkBothWays(t, c.rate, c.buffer, c.late) })
		})
	}
}

func bulkBothWays(t *testing.T, rate float64, buffer int, late time.Duration) {
	w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, rate: rate, buffer: buffer})
	s := w.open(w.peer("a"), "S", rendr.ModeSelector)
	up := startReceiver("A → B", s.p, 1, openEnded)
	down := startReceiver("B → A", s.d, 2, openEnded)
	var txUp, txDown *sender
	var start time.Time
	if late > 0 {
		txDown = w.startSender(s.p, 2, openEnded, 0)
		start = time.Now()
		time.Sleep(late)
		txUp = w.startSender(s.d, 1, openEnded, 0)
	} else {
		txUp, txDown = w.startSender(s.d, 1, openEnded, 0), w.startSender(s.p, 2, openEnded, 0)
		start = time.Now()
	}
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
