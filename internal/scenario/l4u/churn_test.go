package l4u

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The churn in the tombstone-eviction regime (M6 design §A12 "tombstones
// at high flow rates", §A16.2; L47).
const (
	// churnStagger is the dialer's JoinStagger: below the RTT, so every
	// OPEN also races onto the second carrier.
	churnStagger = 10 * time.Millisecond
)

// TestL4UChurnNoResurrection_L47 (§A12, §A16.2; L47): one-shot flows (a
// query that rides the OPEN, its answer) through one ingress with the DNS
// recipe's classes (Idle{10 s, 10 s}), 40 new flows per second for 5
// virtual minutes (lane.churnSpan; the race lane's in lane_test.go), over a
// Peer of two DatagramLinks u1 and u2 (selector), both Runtimes at
// MaxSessions 1,000: the passive's tombstones (TombstoneTTL = PassiveRetain
// + Linger = 64 s) want 2,560 and are capped at 2,000, so the oldest are
// evicted while their sessions' OPENs may still be retried — the
// tombstone-eviction regime of 400 flows per second at the default
// MaxSessions, at a tenth of both. The dialer's JoinStagger is 10 ms, half
// the RTT: every flow's OPEN is sent on its second carrier as well before
// the first answer can arrive (the OPEN duplicated on a second carrier).
//
// Stimulus: the passive's tombstone count reaches its cap (2,000) and
// stays there while the flows churn; OPENs cross both links (each link
// carried at least a third of the flows' OPENs, counted by captures).
//
// PASS (L47): no session is published twice — every session ID
// AcceptPacket returned is new — and the Server's UDP.Confirmed equals the
// dialer's opens (PortForward's Opened) and the target dials, exactly;
// every flow's query rode its OPEN and was written to the target once
// (FirstInOpen = Opened, FirstSent = Confirmed); every flow opened (no
// Failed, no refusal) and every query was answered at its first try;
// nothing is left at the end (close's checks).
func TestL4UChurnNoResurrection_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Both Runtimes' MaxSessions (lane.churnSessions, 1,000): the passive
		// remembers at most twice as many tombstones (plan §3.7). A tenth of
		// the default 10,000, so that the regime of 400 flows per second at
		// the default (400 × 64 s of TombstoneTTL = 25,600 wanted against
		// 20,000) is the same at a tenth of the rate (lane.churnRate, 40):
		// 2,560 against 2,000.
		maxSess, rate := lane.churnSessions, lane.churnRate
		ov := testhooks.Overrides{MaxSessions: maxSess}
		dov := ov
		dov.JoinStagger = churnStagger
		w := newWorld(t, worldOpts{dov: dov, pov: ov}, linkSpec{name: "u1"}, linkSpec{name: "u2"})
		ev := &evictionLog{}
		w.target(dnsPort, dnsTarget(ev))
		recipe := l4.FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second}
		pf := &l4.PortForward{Peer: w.peer("u1", "u2"), Idle: recipe}
		in := w.forward(pf, targetAddr(dnsPort), rendrtest.UDPSocketHubConfig{Addr: netipLoopback(5353), Queue: 64})

		var opens [2]atomic.Int64
		capDone := make(chan struct{}, 2)
		for i, name := range []string{"u1", "u2"} {
			l := w.dlink(name)
			go func() { // count the OPENs crossing each link (a lower bound: one capture is armed at a time)
				defer func() { capDone <- struct{}{} }()
				for {
					select {
					case <-l.CaptureNext(rendrtest.Up, rendrtest.FrameOpen):
						opens[i].Add(1)
					case <-w.quit:
						return
					}
				}
			}()
		}
		var maxTomb atomic.Int64
		sampDone := make(chan struct{})
		stopSamp := make(chan struct{})
		var capped atomic.Int64 // seconds the tombstones sat at the cap
		go func() {
			defer close(sampDone)
			for {
				select {
				case <-stopSamp:
					return
				case <-time.After(time.Second):
				}
				n := int64(w.p.Status().Sessions.Tombstones)
				if n > maxTomb.Load() {
					maxTomb.Store(n)
				}
				if n >= int64(2*maxSess) {
					capped.Add(1)
				}
			}
		}()

		var st dnsStats
		done := make(chan struct{}, 64)
		start := time.Now()
		flows := int(lane.churnSpan/time.Second) * rate
		step := time.Second / time.Duration(rate)
		running := 0
		for k := 0; k < flows; k++ {
			if !pace(w.quit, start.Add(time.Duration(k)*step)) {
				t.Fatal("the world shut down during the churn")
			}
			running++
			go func() {
				stub(in, clientSrc(k), uint64(k), &st)
				done <- struct{}{}
			}()
			for drained := false; !drained; {
				select {
				case <-done:
					running--
				default:
					drained = true
				}
			}
		}
		for ; running > 0; running-- {
			<-done
		}
		close(stopSamp)
		<-sampDone

		ps, ss := pf.Status().UDP, w.srv.Status().UDP
		twice, sessions := w.publishedTwice()
		t.Logf("%d flows in %v: opened %d, confirmed %d, %d target dials, %d sessions published; tombstones at most %d (cap %d, %d s at the cap); OPENs seen on u1 %d, u2 %d; answers first %d, retried %d, unanswered %d",
			flows, time.Since(start), ps.Opened, ss.Confirmed, w.dials(), sessions, maxTomb.Load(), 2*maxSess, capped.Load(),
			opens[0].Load(), opens[1].Load(), st.first.Load(), st.retried.Load(), st.unanswered.Load())
		if len(twice) != 0 {
			t.Fatalf("L47: %d sessions were published twice: %v", len(twice), twice)
		}
		if ps.Opened != uint64(flows) || ps.Failed != 0 || ss.Confirmed != ps.Opened || uint64(w.dials()) != ss.Confirmed || uint64(sessions) != ss.Confirmed {
			t.Fatalf("L47: the dialer opened %d flows (failed %d) of %d, the Server confirmed %d, %d target dials, %d sessions published: want all equal",
				ps.Opened, ps.Failed, flows, ss.Confirmed, w.dials(), sessions)
		}
		if ps.FirstInOpen != ps.Opened || ss.FirstSent != ss.Confirmed {
			t.Fatalf("L47: %d of %d flows' queries rode their OPEN and the Server wrote %d first datagrams for %d flows: want each query in its OPEN, written once",
				ps.FirstInOpen, ps.Opened, ss.FirstSent, ss.Confirmed)
		}
		if st.bad.Load() != 0 || st.unanswered.Load() != 0 || st.retried.Load() != 0 {
			t.Fatalf("queries: %d bad answers, %d unanswered, %d retried; want every one answered at its first try", st.bad.Load(), st.unanswered.Load(), st.retried.Load())
		}
		if maxTomb.Load() < int64(2*maxSess) || capped.Load() < 10 {
			t.Fatalf("stimulus: the passive's tombstones reached %d (at the cap %d s), want the cap %d for at least 10 s: not the eviction regime",
				maxTomb.Load(), capped.Load(), 2*maxSess)
		}
		for i, n := range []int64{opens[0].Load(), opens[1].Load()} {
			if n < int64(flows/3) {
				t.Fatalf("stimulus: link %d carried %d OPENs of %d flows: the OPENs were not duplicated on a second carrier", i+1, n, flows)
			}
		}
		w.noViolation()
		w.close()
		<-capDone
		<-capDone
	})
}
