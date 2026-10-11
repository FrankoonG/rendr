package rendr_test

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The real-socket group of the root package (M2 design §A8.6; WP12): two
// Runtimes over carrier/udp on loopback, the passive on one listening
// socket through FromPacketConn, outside synctest bubbles. Each row is a
// leak oracle (rendrtest.AssertNoLeak, registered first so that it runs
// after every other cleanup) and uses runSmoke (integ2_smoke_test.go):
// stimulus (every kill ended a live carrier and raised a CarrierDown),
// load (≥ 90 % of the rate arrived) and integrity (every datagram's seq,
// size, CRC and body; no duplicate; losses only right after a kill or
// counted as queue drops; the §A7.2 identities on both ends), and nothing
// left after Runtime.Close.

// realLossWindows are the loss windows of a real-time smoke over
// carrier/udp: a lost datagram must have been sent in [T_k − pre,
// T_k + post] of a kill at T_k (M2 design B1.4, F8: ± 200 ms; the 50-ms
// pre-window of runSmoke's default is tighter). Under -race in real time
// the receiving reader can lag 100 ms and more, so datagrams that still
// sat unread in the killed socket were in flight on the dead carrier, and
// the passive's switch to the new carrier lags as much: both windows
// widen.
func realLossWindows() (pre, post time.Duration) {
	if loopbackRace {
		return 250 * time.Millisecond, 500 * time.Millisecond
	}
	return 0, 200 * time.Millisecond
}

// TestUDPEndToEnd: selector and bond, 10 s at 2,000 datagrams per second
// (1,000 back), one carrier closed under rendr at 5 s (an embedder-closed
// socket: transport_error at once); the session moves to a new carrier and
// keeps every datagram that was not in flight on the dead one. Under the
// race detector the timeline is 4 s with the kill at 2 s (m3 R1-23's
// first lever: 6 s with the kill at 3 s from I3 of M4 until I1 of M5,
// whose race-unit passes reached 306 s), with the same criteria; the
// non-race lanes keep 10 s.
func TestUDPEndToEnd(t *testing.T) {
	pre, post := realLossWindows()
	duration, every := 10*time.Second, 5*time.Second
	if loopbackRace {
		duration, every = 4*time.Second, 2*time.Second
	}
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			runSmoke(t, smokeUDPNet(t), smokeRun{mode: mode, duration: duration, every: every,
				rate: 2000, back: 1000, lossWin: post, preWin: pre}, rendr.Config{})
		})
	}
}

// TestPacketSmokeUDP60_CA is the 60-second real-UDP smoke of checkpoint
// C-A (integration 2, §2.4: TestPacketSmokeUDP_CA runs a shortened 10-s
// timeline): carrier/udp on loopback, selector and bond, 10,000 datagrams
// per second (2,000 under -race) and 1,000 back for 60 real seconds, a
// kill every 10 s (selector: the active carrier; bond: the members in
// turn). It is a long real-time load, so -short skips it; the pool lanes
// run it without -short.
//
// Under the race detector it runs 8 s per mode (two kills, 3 s apart: in
// bond mode each member once; 30 s with kills 10 s apart until I3 of M4,
// 12 s with kills 4 s apart until I1 of M5)
// with the same criteria: the unit suite's -race lane has a 5-minute
// wall-clock budget (plan §9.0; m3 R1-23's first lever) and a required
// test must not skip there, while the 60-s timeline at full rate stays in
// the non-race lanes.
func TestPacketSmokeUDP60_CA(t *testing.T) {
	if testing.Short() {
		t.Skip("60-s real-time smoke")
	}
	rate, duration, every := 10000, 60*time.Second, 10*time.Second
	if loopbackRace {
		rate, duration, every = 2000, 8*time.Second, 3*time.Second
	}
	pre, post := realLossWindows()
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			runSmoke(t, smokeUDPNet(t), smokeRun{mode: mode, duration: duration, every: every,
				rate: rate, back: 1000, lossWin: post, preWin: pre}, rendr.Config{})
		})
	}
}
