package l4u

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestL4UFirstReplyUnderChurn_L12_L72 (G11-dns; m6 item rc3; L12, L72):
// at G11-dns's load the first reply of a new one-shot flow arrives one
// round trip after the direct path's (the passive's go-frame wait, M3-D8),
// also while the Peer's datagram trunks recycle their views and after its
// ranking moved every new session to a factory whose pool it must build.
//
// The world: two factories u1 and u2 (datagram links of 100 Mbit/s, 10 and
// replyU2Before each way; the Peer probes both and dials the better
// ranked) and a
// passive whose target connect takes replyDialDelay before Confirm (a
// real target's UDP connect and first write; G11-dns's B); one PortForward
// with the DNS recipe (Idle{10 s, 10 s}, MaxFlows 4,096; Server MaxFlows
// 8,192). Load: Poisson arrivals of 300 new flows per second (a seeded
// PCG), each from its own source, one 40-byte query and one 100-byte
// answer, answered by the target at once, over lane.replySpan, after one
// warm-up query and replyWarm of probing. Event: at
// lane.replyFlip u2's delay drops to replyU2After each way, a level shift
// the probe aggregator takes at its second sample (plan §4: 3σ, σ at least
// 2 ms; Probe.Interval is replyProbe), and the ranking moves every new
// session to u2, whose RTT then stays below u1's by more than the
// microseconds its own load adds to its probe samples. (In G11-dns, at the
// default 2 s, the two equal paths' probe RTTs, microseconds apart, moved
// it about once a minute without any event, each way in turn as the loaded
// path's samples rose: 20261022-015030-b8c6 at +491.9 s, 20.437 against
// 20.431 ms.) The pool fills each trunk from the next opens
// (fill-first), so a trunk takes the factory's whole open rate while it
// fills and again while it refills the views that end together 10 s later,
// and its REL window of 8 is shared by the reliable frames of every view
// on it: OPEN, SCHED and the go PACK of a new view and the RST and DETACH
// of an ending one toward the passive; OPEN_ACK, two epoch-echo PACKs and
// DETACH back. Before the fix the first frames waited behind the others
// for the next RACK: every 1-s median 47–58 ms against 40.3, p99 75 ms.
//
// PASS: every query answered at its first try, each answer the target's
// answer to its own query; the load reached (Opened = FirstInOpen = the
// queries, no DropFull, no eviction); the event happened (the flows opened
// before it ride u1, those opened from replyMoved after it u2, and u2 was
// dialled for them); over the flows first sent from 1 s on (the first
// second holds the cold Peer's Probe.DialWait, a documented cold-start
// cost) the median first reply ≤ replyExpect + 2 ms (G11-dns's median
// bound); outside the two build-up spans every 1-s window's median ≤
// replyExpect + 2 ms and the p99 ≤ replyExpect + 20 ms + 10 ms (G11-dns's
// p99 bound: one more RTT for a flow that waits for a new trunk's dial);
// inside them the p99 ≤ replyExpect + 2 × 20 ms + 10 ms (a flow that waits
// for a new trunk's dial verdict and then, with the waiters the verdict
// releases at once, for REL room on that trunk). replyExpect = 2 × 20 ms +
// replyDialDelay is the direct path's reply on u1 (one RTT and the
// target's connect) plus the go-frame RTT; u2's after the event is 0.4 ms
// less. A build-up span is the idle period after the start, and the one
// after the ranking moved (from the event to replyMoved + the idle period
// after it), while the pool fills fresh trunks one at a time at the
// factory's whole open rate: each new trunk costs its coalesced waiters a
// dial's verdict, and a new view's OPEN shares the filling trunk's REL
// window with the SCHED and go PACK of the views opened just before it
// (the designed cold-start costs, §A8.4; M3's ⌈N/8⌉ RTTs of control under
// churn); its windows are recorded. The run drains as
// TestL4UDNSChurnMiniature_L48_L72's arms do.
func TestL4UFirstReplyUnderChurn_L12_L72(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			rate     = 300
			linkRate = 100e6 / 8 // bytes per second
		)
		var dcfg rendr.Config
		dcfg.Probe.Interval = replyProbe
		w := newWorld(t, worldOpts{dcfg: dcfg, dialDelay: replyDialDelay, srv: func(s *l4.Server) { s.MaxFlows = 8192 }},
			linkSpec{name: "u1"}, linkSpec{name: "u2"})
		for _, n := range []string{"u1", "u2"} {
			for _, d := range bothDirs {
				w.dlink(n).SetRate(d, linkRate)
				if n == "u2" {
					w.dlink(n).SetDelay(d, replyU2Before, 0) // u1 ranks first until the event
				}
			}
		}
		ev := &evictionLog{}
		w.target(dnsPort, dnsTarget(ev))
		idle := l4.FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second}
		pf := &l4.PortForward{Peer: w.peer("u1", "u2"), Idle: idle, MaxFlows: 4096}
		in := w.forward(pf, targetAddr(dnsPort), rendrtest.UDPSocketHubConfig{Addr: netip.MustParseAddrPort("127.0.0.1:5353"), Queue: 256})

		span, flip := lane.replySpan, lane.replyFlip
		type rec struct {
			sent time.Time
			lat  time.Duration // 0: unanswered within 1 s
		}
		var (
			mu     sync.Mutex
			recs   []rec
			bad    int
			wg     sync.WaitGroup
			byPath [2]map[string]int // open flows by the factory of their active carrier: before the event, from replyMoved after it
		)
		// snap counts the open flows first seen from from on, by the factory
		// of their session's active carrier.
		snap := func(k int, from time.Time) {
			m := map[string]int{}
			for _, fi := range pf.Flows() {
				if fi.Since.Before(from) || fi.State != l4.FlowOpen {
					continue
				}
				if act, ok := activeOf(fi.Session); ok {
					m[act.Name]++
				}
			}
			byPath[k] = m
		}
		// One query first starts the Peer's probing (at its first Dial), so
		// that both factories have samples before the load and the event.
		warm := in.client(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 250}), 1))
		warm.Write(rendrtest.PacketPayload(nil, dnsQuerySeed, replyWarmSeq, dnsQuery, time.Unix(0, int64(replyWarmSeq))))
		warm.SetReadDeadline(time.Now().Add(time.Second))
		if buf := make([]byte, 2048); true {
			if m, err := warm.Read(buf); err != nil || !isAnswer(buf[:m], replyWarmSeq) {
				t.Fatalf("the warm-up query: %v", err)
			}
		}
		warm.Close()
		sleepUntil(time.Now().Add(replyWarm))

		start := time.Now()
		rng := rand.New(rand.NewPCG(0x7263, 0x3364))
		at, n, moved := start, 0, false
		for {
			at = at.Add(time.Duration(rng.ExpFloat64() * float64(time.Second) / rate))
			if at.Sub(start) >= span {
				break
			}
			if !moved && at.Sub(start) >= flip {
				moved = true
				if !pace(w.quit, start.Add(flip)) {
					t.Fatal("the world shut down during the load")
				}
				snap(0, start.Add(flip-5*time.Second))
				for _, d := range bothDirs {
					w.dlink("u2").SetDelay(d, replyU2After, 0)
				}
			}
			if !pace(w.quit, at) {
				t.Fatal("the world shut down during the load")
			}
			k := n
			n++
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := in.client(clientSrc(k))
				defer c.Close()
				q := rendrtest.PacketPayload(nil, dnsQuerySeed, uint64(k), dnsQuery, time.Unix(0, int64(k)))
				buf := make([]byte, 2048)
				r := rec{sent: time.Now()}
				if _, err := c.Write(q); err == nil {
					c.SetReadDeadline(r.sent.Add(time.Second))
					for {
						m, err := c.Read(buf)
						if err != nil {
							break
						}
						if isAnswer(buf[:m], uint64(k)) {
							r.lat = time.Since(r.sent)
							break
						}
						mu.Lock()
						bad++
						mu.Unlock()
					}
				}
				mu.Lock()
				recs = append(recs, r)
				mu.Unlock()
			}()
		}
		snap(1, start.Add(flip+replyMoved))
		wg.Wait()
		last := time.Now()

		// Integrity, load and the event.
		synctest.Wait()
		ps := pf.Status().UDP
		if bad != 0 {
			t.Fatalf("integrity: %d answers were not the answer to their query", bad)
		}
		if ps.Opened != uint64(n+1) || ps.FirstInOpen != ps.Opened || ps.DropFull != 0 || ps.Evicted != 0 {
			t.Fatalf("load: %d queries and the warm-up's, Opened %d, FirstInOpen %d, DropFull %d, Evicted %d; want every query its own flow, its query in the OPEN", n, ps.Opened, ps.FirstInOpen, ps.DropFull, ps.Evicted)
		}
		if byPath[0]["u1"] == 0 || byPath[0]["u2"] != 0 || byPath[1]["u2"] == 0 || byPath[1]["u1"] != 0 {
			t.Fatalf("stimulus: open flows by factory %v before the event and %v from %v after it, want u1 then u2", byPath[0], byPath[1], replyMoved)
		}
		if d := w.dlink("u2").Stats().Dials; d < 3 {
			t.Fatalf("stimulus: u2 was dialled %d times (its probe carrier included), want trunks built for the new flows", d)
		}

		// The first replies, by 1-s window of first sends.
		buildUp := func(s time.Duration) bool { return s < idle.Short || (s >= flip && s < flip+replyMoved+idle.Short) }
		var judged, steadyLat, buildLat []time.Duration
		var over, built []string
		steady := 0
		for s := time.Second; s < span; s += time.Second {
			var win []time.Duration
			for _, r := range recs {
				if d := r.sent.Sub(start); d >= s && d < s+time.Second {
					if r.lat == 0 {
						t.Fatalf("the query first sent at +%v was not answered within 1 s", d)
					}
					win = append(win, r.lat)
				}
			}
			if len(win) == 0 {
				continue
			}
			judged = append(judged, win...)
			if buildUp(s) {
				buildLat = append(buildLat, win...)
			} else {
				steadyLat = append(steadyLat, win...)
			}
			slices.Sort(win)
			p50, p90 := win[len(win)/2], win[len(win)*9/10]
			desc := fmt.Sprintf("+%v: p50 %v p90 %v (n %d)", s, p50.Round(10*time.Microsecond), p90.Round(10*time.Microsecond), len(win))
			if buildUp(s) {
				built = append(built, desc)
				continue
			}
			steady++
			if p50 > replyExpect+2*time.Millisecond {
				over = append(over, desc)
			}
		}
		q := func(xs []time.Duration, p float64) time.Duration {
			if len(xs) == 0 {
				return 0
			}
			slices.Sort(xs)
			return xs[int(p*float64(len(xs)-1))]
		}
		p50, p99 := q(judged, 0.5), q(judged, 0.99)
		s99, b50, b99 := q(steadyLat, 0.99), q(buildLat, 0.5), q(buildLat, 0.99)
		t.Logf("%d flows in %v, event at +%v: first reply over %d judged flows p50 %v, p99 %v, max %v; %d steady flows p99 %v; %d build-up flows p50 %v, p99 %v (expectation %v); flows by factory %v then %v; dials u1 %d, u2 %d; build-up windows (recorded): %v",
			n, last.Sub(start), flip, len(judged), p50, p99, q(judged, 1), len(steadyLat), s99, len(buildLat), b50, b99, replyExpect, byPath[0], byPath[1], w.dlink("u1").Stats().Dials, w.dlink("u2").Stats().Dials, built)
		if p50 > replyExpect+2*time.Millisecond {
			t.Errorf("first reply p50 %v over the judged flows, want ≤ %v", p50, replyExpect+2*time.Millisecond)
		}
		if len(over) > 0 || s99 > replyExpect+2*oneWay+10*time.Millisecond {
			t.Errorf("steady windows: %d of %d have a median above %v (%v); their p99 %v, want ≤ %v", len(over), steady, replyExpect+2*time.Millisecond, over, s99, replyExpect+2*oneWay+10*time.Millisecond)
		}
		if b99 > replyExpect+4*oneWay+10*time.Millisecond {
			t.Errorf("build-up windows: p99 %v, want ≤ %v", b99, replyExpect+4*oneWay+10*time.Millisecond)
		}

		// The drain (as dnsChurn's): every flow ends at its idle limit.
		drainBy := last.Add(idle.Short + time.Second + 2*time.Second)
		waitFor(t, time.Until(drainBy), "the drain: no flow, session or shared carrier left", func() bool { return drainedProbing(w, pf) })
		if e := ev.judge(t, time.Second+oneWay-5*time.Millisecond, idle.Short-time.Second); e != 0 {
			t.Fatalf("EvictionJudge: %d egresses closed before their idle limit", e)
		}
		w.noViolation()
		w.close()
	})
}

// drainedProbing is drained for a Peer of several factories, without the
// buffered bytes: both ends of its probe carriers hold theirs while the
// Peer probes (close checks them after the Peer's close).
func drainedProbing(w *world, pf *l4.PortForward) bool {
	if st := pf.Status().UDP; st.Flows != 0 || st.Opening != 0 || st.Held != 0 {
		return false
	}
	if st := w.srv.Status().UDP; st.Live != 0 || st.Dialing != 0 {
		return false
	}
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			return false
		}
	}
	return true
}

const (
	// replyDialDelay is the passive's target connect in
	// TestL4UFirstReplyUnderChurn_L12_L72 (worldOpts.dialDelay).
	replyDialDelay = 300 * time.Microsecond
	// replyExpect is that row's expected first reply: the direct path's
	// (one RTT and the connect) plus the go-frame RTT.
	replyExpect = 4*oneWay + replyDialDelay
	// replyProbe is the dialer's Probe.Interval (its clamp's floor, so that
	// the ranking moves soon after the event), and replyMoved when it has
	// moved: the aggregator takes the level shift at u2's second sample
	// after the event, whose PONG comes within 2 × replyProbe + one RTT.
	replyProbe = 500 * time.Millisecond
	replyMoved = 2*replyProbe + 100*time.Millisecond
	// replyU2Before and replyU2After are u2's one-way delays before and
	// after the event: 8 ms of RTT apart, a level shift beyond 3σ (6 ms),
	// and after it 0.4 ms below u1's RTT.
	replyU2Before = 14 * time.Millisecond
	replyU2After  = 9900 * time.Microsecond
	// replyWarm is how long the row probes before the load (after one
	// warm-up query, replyWarmSeq, starts the probing): the aggregator then
	// holds the 3 earlier samples a level shift needs (plan §4).
	replyWarm    = 2 * time.Second
	replyWarmSeq = 1 << 40
)
