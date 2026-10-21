package l4u

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// dnsArm is one arm of TestL4UDNSChurnMiniature_L48_L72.
type dnsArm struct {
	name     string
	queries  int
	rate     float64     // new queries per second (Poisson-free: an absolute schedule)
	idle     l4.FlowIdle // the PortForward's classes
	maxFlows int         // the PortForward's MaxFlows (0: DefaultMaxFlows)
	srvFlows int         // the Server's MaxFlows (0: DefaultMaxFlows)
	ports    int         // 0: unique sources (F87); else the sources' port space on one client address, reused no sooner than 2 s after its last use
	firstTry bool        // every query must be answered at its first try
	evicts   bool        // the table must recycle by eviction (O-1 (a)'s full table)
	reuses   bool        // queries must land on live flows (the reuse arm's stimulus)
}

// TestL4UDNSChurnMiniature_L48_L72 (§A16.2; G11-dns, R1-7, R1-23; L48,
// L72): one-shot query flows through one ingress toward a target that
// answers each query once, at once. Three arms, each a world of its own
// over one DatagramLink (one factory, so the Peer keeps no probe
// carriers), under the promotion rule in force (O-1 (a), the delegate
// decision of 2026-10-17):
//
//   - recipe: 20,000 queries at 500 per second from unique sources
//     through the DNS recipe (§A5.1: Idle{10 s, 10 s}, MaxFlows 8,192 on
//     the PortForward and the Server; ≈ 5,000 flows wanted). Both classes
//     are 10 s and the table never fills, so the arm's outcome does not
//     depend on the promotion rule (the literal rule's arm is the same
//     run). PASS: every query answered at its first try; DropFull 0, no
//     eviction; every flow's first datagram rode the OPEN and was written
//     to its target once (FirstInOpen = Opened = the queries, the Server's
//     FirstSent = Confirmed, and every egress received exactly one query:
//     the target's own count).
//   - full-table (O-1 (a)): default classes (30 s / 180 s) over a table of
//     256, 4,000 queries at 100 per second from unique sources (≈ 3,000
//     flows wanted: the table recycles twelve times over; 100 per second
//     keeps the flows younger than 1 s below half the table, so that eight
//     samples find a victim — at 500 per second every entry would be
//     younger than 1 s and nothing could be admitted). PASS: every query
//     answered within its retries; the table recycled (Evicted > 0;
//     Opened = Evicted + the other ends + the live flows); every eviction
//     was legal — the passive's egress close of every flow that ended
//     before its idle limit came at least 1 s + RTT/2 − 5 ms after the
//     flow's last datagram (EvictionJudge, R1-38), and their number equals
//     Evicted exactly; no flow ever became a stream.
//   - reuse (O-1 (a), R1-23): default classes and MaxFlows, 4,000 queries
//     at 100 per second from 4,096 ports of one client address, a port
//     reused no sooner than 2 s after its last query. PASS: every query
//     answered at its first try; queries landed on live flows (fewer opens
//     than queries, at least a tenth of the queries reused a live flow);
//     no flow ever became a stream (FlowInfo.Stream false in every 1-s
//     snapshot; with conntrack's rule without the gap reset each reused
//     flow would promote).
//
// Under the race detector the arms run 250, 300 and 300 queries (the reuse
// arm over 307 ports; lane_test.go). Every arm: answers intact (each the
// target's answer to its own query); the PortForward never failed an open
// and saw no socket noise; at the end, without stopping anything, the
// flows drain: within the longest class + PacketPing + 2 s of the last
// query the PortForward
// holds no flow, opening or held entry, the Server no flow, and both
// Runtimes no session (open, pending, lingering or orphaned), no
// handshake, no shared carrier and no buffered byte (L48, L52).
func TestL4UDNSChurnMiniature_L48_L72(t *testing.T) {
	for _, a := range dnsArms() {
		t.Run(a.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { dnsChurn(t, a) })
		})
	}
}

// dnsArms are the arms at the lane's size (lane.dnsQueries; the race lane
// runs fewer queries at the same rates, tables and bounds, and the reuse
// arm's port space scaled with them).
func dnsArms() []dnsArm {
	recipe := l4.FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second}
	return []dnsArm{
		{name: "recipe", queries: lane.dnsQueries[0], rate: 500, idle: recipe, maxFlows: 8192, srvFlows: 8192, firstTry: true},
		{name: "full-table", queries: lane.dnsQueries[1], rate: 100, maxFlows: 256, evicts: true},
		{name: "reuse", queries: lane.dnsQueries[2], rate: 100, ports: lane.dnsPorts, firstTry: true, reuses: true},
	}
}

func dnsChurn(t *testing.T, a dnsArm) {
	w := newWorld(t, worldOpts{srv: func(s *l4.Server) { s.MaxFlows = a.srvFlows }}, linkSpec{name: "u1"})
	ev := &evictionLog{}
	w.target(dnsPort, dnsTarget(ev))
	pf := &l4.PortForward{Peer: w.peer("u1"), Idle: a.idle, MaxFlows: a.maxFlows}
	in := w.forward(pf, targetAddr(dnsPort), rendrtest.UDPSocketHubConfig{Addr: netip.MustParseAddrPort("127.0.0.1:5353"), Queue: 64})

	var st dnsStats
	var stubs sync.WaitGroup
	srcs := newSourcePool(a.ports)
	var streams atomic.Int64
	stopSnap := make(chan struct{})
	snapDone := make(chan struct{})
	go func() { // 1-s snapshots: no flow may ever be a stream
		defer close(snapDone)
		for {
			select {
			case <-stopSnap:
				return
			case <-time.After(time.Second):
			}
			for _, fi := range pf.Flows() {
				if fi.Stream {
					streams.Add(1)
				}
			}
		}
	}()

	start := time.Now()
	step := time.Duration(float64(time.Second) / a.rate)
	for k := 0; k < a.queries; k++ {
		if !pace(w.quit, start.Add(time.Duration(k)*step)) {
			t.Fatal("the world shut down during the load")
		}
		src := srcs.take(time.Now())
		stubs.Add(1)
		go func() {
			defer stubs.Done()
			stub(in, src, uint64(k), &st)
			srcs.give(src, time.Now())
		}()
	}
	stubs.Wait()
	last := time.Now()
	close(stopSnap)
	<-snapDone

	// Flows keep ending at their idle limits while the counters are read,
	// and Status loads each counter on its own: a flow whose end runs
	// between the Flows and the Ended loads is in neither. The counters
	// are read once every other goroutine of the bubble is durably blocked
	// (no virtual time passes until this goroutine blocks), so that the
	// accounting below compares one instant's counters.
	synctest.Wait()
	ps := pf.Status().UDP
	t.Logf("%s: %d queries in %v: %d answered at the first try, %d after a retry (at most try %d), %d unanswered; %+v",
		a.name, a.queries, last.Sub(start), st.first.Load(), st.retried.Load(), st.maxTry.Load(), st.unanswered.Load(), plainF(ps))
	if n := st.bad.Load(); n != 0 {
		t.Fatalf("integrity: %d answers were not the answer to their query", n)
	}
	if n := st.unanswered.Load(); n != 0 {
		t.Fatalf("%d of %d queries were never answered within their retries", n, a.queries)
	}
	if a.firstTry && st.retried.Load() != 0 {
		t.Fatalf("%d of %d queries needed a retry, want every one answered at its first try", st.retried.Load(), a.queries)
	}
	if n := streams.Load(); n != 0 {
		t.Fatalf("%d flow snapshots showed a stream: a one-shot exchange was promoted", n)
	}
	switch {
	case a.evicts:
		if ps.Evicted == 0 {
			t.Fatalf("stimulus: the table of %d never recycled: Evicted %d, DropFull %d", a.maxFlows, ps.Evicted, ps.DropFull)
		}
	default:
		if ps.Evicted != 0 || ps.DropFull != 0 {
			t.Fatalf("the table was full: Evicted %d, DropFull %d, want none", ps.Evicted, ps.DropFull)
		}
	}
	if a.ports == 0 {
		// The ingress counts FirstInOpen when it hands the first datagram to
		// DialUDP (its intent); the Server's FirstSent counts the first
		// datagrams it wrote from an OPEN: both are required.
		ss := w.srv.Status().UDP
		if ps.FirstInOpen != ps.Opened || ss.FirstSent != ss.Confirmed || (a.firstTry && ps.Opened != uint64(a.queries)) {
			t.Fatalf("opens: %d flows opened, %d first datagrams rode the OPEN, the Server wrote %d first datagrams for %d flows, %d queries; want every query its own flow and its query in the OPEN",
				ps.Opened, ps.FirstInOpen, ss.FirstSent, ss.Confirmed, a.queries)
		}
		if a.firstTry {
			ev.once(t, a.queries)
		}
	}
	if a.reuses {
		reused := a.queries - int(ps.Opened)
		if reused < a.queries/10 {
			t.Fatalf("stimulus: only %d of %d queries landed on a live flow (Opened %d)", reused, a.queries, ps.Opened)
		}
		t.Logf("%d of %d queries reused a live flow", reused, a.queries)
	}
	// Opened = Evicted + the other ends + live (the accounting of A8.6).
	e := ps.Ended
	if ended := e.Idle + e.PeerIdle + e.PeerClosed + e.NoPath + e.SessionLost + e.GoingAway + e.Stopped + e.Evicted + e.Local + e.Other; ps.Opened != ended+uint64(ps.Flows) || e.Evicted != ps.Evicted {
		t.Fatalf("accounting: Opened %d, ended %d (%+v), live %d, Evicted %d", ps.Opened, ended, e, ps.Flows, ps.Evicted)
	}
	if ps.Failed != 0 || ps.ReadNoise != 0 || ps.WriteNoise != 0 {
		t.Fatalf("PortForward: Failed %d, ReadNoise %d, WriteNoise %d, want 0", ps.Failed, ps.ReadNoise, ps.WriteNoise)
	}

	// The drain: nothing is stopped; the flows end at their idle limits.
	longest := max(a.idle.Short, a.idle.Stream)
	if longest <= 0 {
		longest = l4.DefaultFlowShortIdle // every flow stays short (no stream, checked above)
	}
	drainBy := last.Add(longest + time.Second + 2*time.Second) // + PacketPing + 2 s
	waitFor(t, time.Until(drainBy), "the drain: no flow, session, hold or buffered byte left", func() bool { return drained(w, pf) })
	t.Logf("%s: drained %v after the last query", a.name, time.Since(last))

	evicted := ev.judge(t, time.Second+oneWay-5*time.Millisecond, longest-time.Second)
	if evicted != int(pf.Status().UDP.Evicted) {
		t.Fatalf("EvictionJudge: %d egress closes came before their idle limit, Evicted is %d", evicted, pf.Status().UDP.Evicted)
	}
	w.noViolation()
	w.close()
}

// drained reports whether the PortForward, the Server and both Runtimes
// hold nothing (L48, L52).
func drained(w *world, pf *l4.PortForward) bool {
	if st := pf.Status().UDP; st.Flows != 0 || st.Opening != 0 || st.Held != 0 {
		return false
	}
	if st := w.srv.Status().UDP; st.Live != 0 || st.Dialing != 0 {
		return false
	}
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.BufferedBytes != 0 || st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			return false
		}
	}
	return true
}

// sourcePool hands out client source addresses: unique ones (n 0), or a
// port of one address drawn from a space of n (a seeded PCG), each reused
// no sooner than 2 s after its last query ended (R1-23's designed reuse:
// a reuse always starts a new activity period).
type sourcePool struct {
	n    int
	next int
	rng  *rand.Rand
	mu   sync.Mutex
	busy map[int]bool
	last map[int]time.Time
}

func newSourcePool(n int) *sourcePool {
	return &sourcePool{n: n, rng: rand.New(rand.NewPCG(0x1b55, 0x2c66)), busy: map[int]bool{}, last: map[int]time.Time{}}
}

func (p *sourcePool) port(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 200}), uint16(30000+i))
}

// take returns the next source: a fresh one, or a drawn port that is idle
// and rested 2 s (the next such one after the draw).
func (p *sourcePool) take(now time.Time) netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == 0 {
		p.next++
		return clientSrc(p.next)
	}
	r := p.rng.IntN(p.n)
	for k := range p.n {
		i := (r + k) % p.n
		if at, used := p.last[i]; !p.busy[i] && (!used || now.Sub(at) >= 2*time.Second) {
			p.busy[i] = true
			return p.port(i)
		}
	}
	panic(fmt.Sprintf("sourcePool: no port of %d rested 2 s", p.n))
}

// give returns src after its query ended at now.
func (p *sourcePool) give(src netip.AddrPort, now time.Time) {
	if p.n == 0 {
		return
	}
	i := int(src.Port()) - 30000
	p.mu.Lock()
	p.busy[i] = false
	p.last[i] = now
	p.mu.Unlock()
}
