package carrier

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestDuplexKeepsBothDirections_L15 (M3 estimator amendment; L15, plan §4
// capacity): bulk both ways over one carrier, each side sending as fast as
// its capacity lets it, over a Link shaped to the same rate per direction.
// Each side's PONGs travel behind the other side's DATA, so its proofs
// come a reverse queue later than its own round trip: with a capacity
// sized from minRTT alone (2·rate·(minRTT + PingBusy + 50 ms)) the side
// whose PONGs wait longer is cap-limited below the link, its rate samples
// (span ≥ srtt/2 while the peer is BUSY) measure what it achieved, and the
// estimate settles near CapFloor/srtt. Before the fix (m3 8a9b989) the
// passive's flow carried 0.15 of a 4 MiB/s link at a 20 ms RTT with a
// 2-MiB link buffer and 0.17 of a 16 MiB/s link at 100 ms (the second is
// the path TestByteClockDuplexRateBounded_L32 logs, not judges); the 2 MiB/s
// row with a 128-KiB buffer passed there (0.88) and fails only with the
// mux suite's load (TestMuxBulkBothWaysKeepsTheLink): it guards the short
// queue. The capacity now adds the reverse queue measured one way
// (sched.CapacityDuplex, noteOWD).
//
// PASS: over the 6 s after a 2-s warm-up, while both flows run, each
// direction carries ≥ 0.85 of the link; both flows then complete intact
// and in order, and neither carrier dies.
func TestDuplexKeepsBothDirections_L15(t *testing.T) {
	for _, tc := range []struct {
		rtt  time.Duration
		rate float64
		buf  int // the link's buffer per direction
	}{
		{20 * time.Millisecond, 4 << 20, 2 << 20},
		{20 * time.Millisecond, 2 << 20, (2 << 20) / 16},
		{100 * time.Millisecond, 16 << 20, 64 << 20},
	} {
		t.Run(fmt.Sprintf("rtt%v/%gMiBps/buf%dKiB", tc.rtt, tc.rate/(1<<20), tc.buf>>10), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const warm, span = 2 * time.Second, 6 * time.Second
				total := uint64(tc.rate * (warm + span + time.Second).Seconds()) // neither flow ends inside the window
				envD, envP := phEnvs()
				envD.Timing.Window, envP.Timing.Window = 8<<20, 8<<20
				sink := newLtSink(total)
				back := newSource(envP, ChunkSize, true)
				defer back.chunk.Release()
				back.offer(total)
				dc, pc := lrLinkPair(t, envD, envP, tc.rate, tc.rtt/2, tc.buf, &lrDuplex{ltSink: sink, src: back})
				src := newSource(envD, ChunkSize, true)
				defer src.chunk.Release()
				src.offer(total)
				start := time.Now()
				dc.Start(src, &hBell{}, StartOptions{})

				time.Sleep(warm)
				fwd0, _, _ := sink.result()
				back0 := src.rxBytes.Load()
				var peak [2]float64
				for at := start.Add(warm); at.Before(start.Add(warm + span)); at = at.Add(10 * time.Millisecond) {
					time.Sleep(time.Until(at))
					peak[0], peak[1] = max(peak[0], dc.Stats().Rate), max(peak[1], pc.Stats().Rate)
				}
				time.Sleep(time.Until(start.Add(warm + span)))
				fwd1, _, _ := sink.result()
				back1 := src.rxBytes.Load()
				shares := [2]float64{float64(fwd1-fwd0) / (tc.rate * span.Seconds()), float64(back1-back0) / (tc.rate * span.Seconds())}
				ds, ps := dc.Stats(), pc.Stats()
				t.Logf("dialer → passive %.3f, passive → dialer %.3f of the link; rate peaks %.1f and %.1f MiB/s; dialer srtt %v cap %d KiB; passive srtt %v cap %d KiB",
					shares[0], shares[1], peak[0]/(1<<20), peak[1]/(1<<20), ds.SRTT, ds.Cap>>10, ps.SRTT, ps.Cap>>10)

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
				for _, c := range []*Conn{dc, pc} {
					if dead, cause, detail, _ := c.Death(); dead {
						t.Fatalf("carrier %d died: %v %s", c.ID(), cause, detail)
					}
				}
				for i, who := range []string{"dialer → passive", "passive → dialer"} {
					if shares[i] < 0.85 {
						t.Errorf("%s carried %.3f of the link with bulk both ways, want ≥ 0.85", who, shares[i])
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
//     clock that runs slow); a BUSY PING never does; a smaller delay resets
//     the floor at once.
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
	// excess; with BUSY it holds.
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
