package l4u

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestMuxDgramMassRejoinAfterBlackhole_L27_L72 (G11-dns's DROP; m6 item
// rc5; L27, L72): a silent blackhole of the path that carries a Peer's
// whole DNS load ends every session on it at its death verdict; the
// sessions re-attach on the surviving path at once (L27: the fallback
// starts at the verdict), the pool keeps dialling the trunks they need,
// and the flows that arrive after the verdicts open as on a healthy path
// (L72's bounded opening stage).
//
// The world: one Peer over two datagram factories, p2 and p1 (DatagramLinks
// of 10 ms each way: RTT 20 ms; p2 is listed first, so with equal probe
// RTTs it carries every session before the DROP); the passive's Server and
// one PortForward with the DNS recipe (Idle{10 s, 10 s}; MaxFlows 8,192 and
// 4,096); a target that answers each query once, at once. Load: one-shot
// flows at lane.massRate per second, each from its own source (one 40-byte
// query, one 100-byte answer, no retry), lane.massBefore before the DROP
// (at 300 per second ≈ 2,300 sessions on p2's trunks, 64 views each: ≈ 37
// trunks) and lane.massAfter after it. The DROP: p2 blackholed both ways
// (G11-dns's nft drop), lifted only after the judgment.
//
// PASS: (a) every session whose p2 carrier died (its EventCarrierDown, the
// death verdict) re-attaches (its next EventCarrierUp) within 1 s of it,
// or ends within 1 s of it — a flow at its idle limit, ended by this side
// or by the passive, whose end then answers the JOIN UNKNOWN_SESSION; (b)
// from the first verdict to the last re-attach no gap between consecutive
// p1 trunk dials exceeds 2·RTT + RTO (RTO: the REL RTO before a sample,
// 300 ms) while a session that died before the gap began still waits at
// its start + that bound; (c) every flow whose query is sent at or after
// tDead + 1 s (tDead: the latest of the p2 trunks' earliest death records,
// G11-dns's t_dead) is answered within 1 s, so none of them was DropOpening
// or DropOpenAge; (d) from the DROP to the last re-attach (W) the dialer's
// health layer rings its subscribed sessions in at most
// ⌊W / Probe.Interval⌋ + 4 snapshots: p1's probe samples (⌊W /
// Probe.Interval⌋ + 1), p2's probe death, one failed probe redial of p2
// and the first failed mark of p2 — never one per death, nor one per view
// that died with a p2 trunk.
//
// Before rc5 (m6 f4e2381, the full lane) (a)–(c) held in the bubble —
// re-attach p50 193 ms, max 493 ms; dial gaps at most 47 ms; every late
// flow answered — because the pool's stall is CPU time, which a synctest
// clock does not see, and (d) failed: 2,327 snapshots and 6.97 M rings,
// one snapshot per death report (carrier.Health.MarkFailedAt published
// and rang every session even for a factory marked already). On the pool
// (G11-dns 20261023-004120-a110) the 2,294 death reports queued for the
// health lock ≈ 0.83 ms apart from t + 3.0 to t + 5.2 s; each death step's
// report runs before that session's next step, so three sessions that had
// dialled fresh p1 trunks started them (Conn.Start publishes a fresh
// trunk, M3-D19) 559, 768 and 448 ms after their JOIN_ACKs, every
// coalesced JOIN of the factory waiting meanwhile (the 1.8-s dial stall),
// and Peer.Dial's Health.Use and Hold — the PortForward's opening stage —
// waited until ≈ t + 5.3 s. With only the first rule (a repeated mark
// rings nobody) (d) failed at 10–20 snapshots (runs differ in the order of
// the reports): each fast-path OPEN of a p2 trunk (a race loser) cleared
// p2's mark when its trunk died, and the next death step set it again
// (EstablishError.View).
//
// Under the race detector the row runs 50 flows per second, 3.2 s before
// the DROP (≈ 160 sessions, 3 trunks) and 5.5 s after it, every rule and
// bound unchanged (lane_test.go).
func TestMuxDgramMassRejoinAfterBlackhole_L27_L72(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { massRejoin(t) })
}

const (
	massReattach = time.Second            // (a)
	massRelRTO   = 300 * time.Millisecond // the REL RTO before a sample (a fresh trunk's)
	massDialGap  = 4*oneWay + massRelRTO  // (b): 2·RTT + RTO
	massOpenWait = time.Second            // (c): a late flow's wait for its answer
	massProbe    = 2 * time.Second        // the dialer's Probe.Interval (the default)
	massIdle     = 10 * time.Second       // the DNS recipe's classes
	massWarmSeq  = 1 << 41                // the warm-up query's sequence number
	massNever    = 1000 * time.Hour       // a dead session that neither re-attached nor ended
	massDrop     = "p2"                   // the dropped path
	massLive     = "p1"                   // the surviving path
)

// massDial is one factory call of the row's dialer Peer.
type massDial struct {
	at      time.Time
	factory string
	carrier rendr.CarrierID
	probe   bool
}

// massRing is one ringing health snapshot of the dialer: its time and the
// subscribers it rang.
type massRing struct {
	at time.Time
	n  int
}

// massQuery is one client's query: its send and its answer's latency (0:
// unanswered within massOpenWait).
type massQuery struct {
	sent time.Time
	lat  time.Duration
}

// massSession is what the dialer's events say about one session after the
// DROP: its first death verdict on a p2 carrier, its first attach after it
// and its end.
type massSession struct {
	death, up, end time.Time
	err            error
}

// waited returns when the dead session stopped waiting: its re-attach, its
// end, or never.
func (s *massSession) waited() time.Time {
	switch {
	case !s.up.IsZero() && (s.end.IsZero() || s.up.Before(s.end)):
		return s.up
	case !s.end.IsZero():
		return s.end
	}
	return s.death.Add(massNever)
}

func massRejoin(t *testing.T) {
	idle := l4.FlowIdle{Short: massIdle, Stream: massIdle}
	var dcfg rendr.Config
	dcfg.Probe.Interval = massProbe
	// Every session's death, no-path, migration, up and end events fit the
	// dialer's event queue (Config.OnEvent's default is 256); (d) counts
	// the dialer's ringing health snapshots.
	var (
		rmu   sync.Mutex
		rings []massRing
	)
	dov := testhooks.Overrides{EventQueue: 1 << 17, Hooks: &testhooks.Hooks{HealthRing: func(n int) {
		rmu.Lock()
		rings = append(rings, massRing{at: time.Now(), n: n})
		rmu.Unlock()
	}}}
	w := newWorld(t, worldOpts{dcfg: dcfg, dov: dov, srv: func(s *l4.Server) { s.MaxFlows = 8192; s.UDPIdle = idle }},
		linkSpec{name: massLive}, linkSpec{name: massDrop})

	// The Peer: the kit's factories, each Dial recorded.
	var (
		dmu   sync.Mutex
		dials []massDial
	)
	var cs []rendr.Carrier
	for _, n := range []string{massDrop, massLive} {
		c := w.carrier(w.spec(n)).(rendr.DatagramCarrier)
		dial := c.Dial
		c.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			di, _ := rendr.CarrierDialInfo(ctx)
			dmu.Lock()
			dials = append(dials, massDial{at: time.Now(), factory: n, carrier: di.Carrier, probe: di.Probe})
			dmu.Unlock()
			return dial(ctx)
		}
		cs = append(cs, c)
	}
	peer, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	w.mu.Lock()
	w.peers = append(w.peers, peer)
	w.mu.Unlock()

	ev := &evictionLog{}
	w.target(dnsPort, dnsTarget(ev))
	pf := &l4.PortForward{Peer: peer, Idle: idle, MaxFlows: 4096}
	in := w.forward(pf, targetAddr(dnsPort), rendrtest.UDPSocketHubConfig{Addr: netip.MustParseAddrPort("127.0.0.1:5353"), Queue: 256})

	// One query starts the Peer's probing; two probe intervals and more give
	// both factories their samples before the load.
	warm := in.client(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 250}), 1))
	warm.Write(rendrtest.PacketPayload(nil, dnsQuerySeed, massWarmSeq, dnsQuery, time.Unix(0, int64(massWarmSeq))))
	warm.SetReadDeadline(time.Now().Add(time.Second))
	if buf := make([]byte, 2048); true {
		if m, err := warm.Read(buf); err != nil || !isAnswer(buf[:m], massWarmSeq) {
			t.Fatalf("the warm-up query: %v", err)
		}
	}
	warm.Close()
	sleepUntil(time.Now().Add(5 * time.Second))

	var (
		qmu     sync.Mutex
		queries []massQuery
		bad     int
		wg      sync.WaitGroup
	)
	send := func(k int) {
		defer wg.Done()
		c := in.client(clientSrc(k))
		defer c.Close()
		q := rendrtest.PacketPayload(nil, dnsQuerySeed, uint64(k), dnsQuery, time.Unix(0, int64(k)))
		buf := make([]byte, 2048)
		r := massQuery{sent: time.Now()}
		if _, err := c.Write(q); err == nil {
			c.SetReadDeadline(r.sent.Add(massOpenWait))
			for {
				m, err := c.Read(buf)
				if err != nil {
					break
				}
				if isAnswer(buf[:m], uint64(k)) {
					r.lat = time.Since(r.sent)
					break
				}
				qmu.Lock()
				bad++
				qmu.Unlock()
			}
		}
		qmu.Lock()
		queries = append(queries, r)
		qmu.Unlock()
	}

	// The load and the DROP.
	start := time.Now()
	drop, step := start.Add(lane.massBefore), time.Second/time.Duration(lane.massRate)
	end := drop.Add(lane.massAfter)
	dropped, onDrop := false, 0
	for k := 0; ; k++ {
		at := start.Add(time.Duration(k) * step)
		if !at.Before(end) {
			break
		}
		if !dropped && !at.Before(drop) {
			dropped = true
			if !pace(w.quit, drop) {
				t.Fatal("the world shut down during the load")
			}
			synctest.Wait()
			onDrop = massFlowsOn(pf, massDrop)
			for _, d := range bothDirs {
				w.dlink(massDrop).Blackhole(d, true)
			}
		}
		if !pace(w.quit, at) {
			t.Fatal("the world shut down during the load")
		}
		wg.Add(1)
		go send(k)
	}
	wg.Wait()
	last := time.Now()
	synctest.Wait()

	// The dialer's record of the DROP.
	dmu.Lock()
	ds := slices.Clone(dials)
	dmu.Unlock()
	factoryOf := map[rendr.CarrierID]string{}
	for _, d := range ds {
		if !d.probe {
			factoryOf[d.carrier] = d.factory
		}
	}
	ss := map[rendr.SessionID]*massSession{}
	firstDeath := map[rendr.CarrierID]time.Time{} // per p2 trunk: its earliest death record
	w.dev.mu.Lock()
	evs := slices.Clone(w.dev.evs)
	w.dev.mu.Unlock()
	for _, e := range evs {
		if e.Time.Before(drop) {
			continue
		}
		s := ss[e.Session]
		switch e.Kind {
		case rendr.EventCarrierDown:
			if factoryOf[e.Carrier] != massDrop || e.Cause == rendr.CauseRetired || e.Cause == rendr.CauseLocalClose {
				continue
			}
			if s == nil {
				ss[e.Session] = &massSession{death: e.Time}
			}
			if f, ok := firstDeath[e.Carrier]; !ok || e.Time.Before(f) {
				firstDeath[e.Carrier] = e.Time
			}
		case rendr.EventCarrierUp:
			if s != nil && s.up.IsZero() {
				s.up = e.Time
			}
		case rendr.EventSessionEnd:
			if s != nil && s.end.IsZero() {
				s.end, s.err = e.Time, e.Err
			}
		}
	}
	var tFirst, tDead, lastUp time.Time
	for _, at := range firstDeath {
		if tDead.IsZero() || at.After(tDead) {
			tDead = at
		}
		if tFirst.IsZero() || at.Before(tFirst) {
			tFirst = at
		}
	}
	if st := w.d.Status(); st.EventsDropped != 0 {
		t.Fatalf("premise: the dialer dropped %d events", st.EventsDropped)
	}
	if bad != 0 {
		t.Fatalf("integrity: %d answers were not the answer to their query", bad)
	}
	if onDrop < lane.massSessions || len(ss) < lane.massSessions/2 || len(firstDeath) < lane.massSessions/64 {
		t.Fatalf("stimulus: %d sessions on %s at the DROP (want ≥ %d), %d of them died, %d %s trunks died", onDrop, massDrop, lane.massSessions, len(ss), len(firstDeath), massDrop)
	}

	// (a) Each dead session re-attaches, or ends, within massReattach of its
	// death verdict.
	var lat []time.Duration
	var late []string
	ends := map[string]int{}
	for id, s := range ss {
		waited := s.waited()
		switch waited {
		case s.up:
			lat = append(lat, s.up.Sub(s.death))
			if s.up.After(lastUp) {
				lastUp = s.up
			}
		case s.end:
			ends[fmt.Sprint(s.err)]++
		}
		if d := waited.Sub(s.death); d > massReattach {
			late = append(late, fmt.Sprintf("%v (death at +%v, waited %v, end %v)", id, s.death.Sub(drop), d, s.err))
		}
	}
	slices.Sort(lat)

	// (b) The p1 trunk dials of the recovery, and their gaps while a dead
	// session waited.
	var p1 []time.Time
	for _, d := range ds {
		if d.factory == massLive && !d.probe && !d.at.Before(tFirst) && !d.at.After(lastUp) {
			p1 = append(p1, d.at)
		}
	}
	var gaps []string
	var maxGap time.Duration
	for i := 1; i < len(p1); i++ {
		g := p1[i].Sub(p1[i-1])
		maxGap = max(maxGap, g)
		if g <= massDialGap {
			continue
		}
		for _, s := range ss {
			if !s.death.After(p1[i-1]) && s.waited().After(p1[i-1].Add(massDialGap)) {
				gaps = append(gaps, fmt.Sprintf("+%v → +%v (%v)", p1[i-1].Sub(drop), p1[i].Sub(drop), g))
				break
			}
		}
	}

	// (c) The flows first sent from tDead + 1 s on.
	var after []time.Duration
	unanswered := 0
	for _, q := range queries {
		if q.sent.Before(tDead.Add(time.Second)) {
			continue
		}
		if q.lat == 0 {
			unanswered++
			continue
		}
		after = append(after, q.lat)
	}
	slices.Sort(after)

	// (d) The ringing health snapshots from the DROP to the last re-attach.
	rmu.Lock()
	snaps, rung := 0, 0
	for _, r := range rings {
		if !r.at.Before(drop) && !r.at.After(lastUp) {
			snaps++
			rung += r.n
		}
	}
	rmu.Unlock()
	span := lastUp.Sub(drop)
	snapLim := int(span/massProbe) + 4

	qt := func(xs []time.Duration, p float64) time.Duration {
		if len(xs) == 0 {
			return 0
		}
		return xs[int(p*float64(len(xs)-1))]
	}
	t.Logf("%d sessions on %s at the DROP, %d died; %d %s trunks died from +%v to +%v (tDead); (a) %d re-attached p50 %v, p99 %v, max %v after their verdict, %d ended first %v; (b) %d %s trunk dials from the first verdict to the last re-attach (+%v), largest gap %v; (c) %d flows from tDead + 1 s, %d unanswered, answer p50 %v, max %v; (d) %d ringing health snapshots (limit %d), %d rings; PortForward %+v",
		onDrop, massDrop, len(ss), len(firstDeath), massDrop, tFirst.Sub(drop), tDead.Sub(drop), len(lat), qt(lat, 0.5), qt(lat, 0.99), qt(lat, 1), len(ss)-len(lat), ends,
		len(p1), massLive, span, maxGap, len(after)+unanswered, unanswered, qt(after, 0.5), qt(after, 1), snaps, snapLim, rung, plainF(pf.Status().UDP))
	if len(late) > 0 {
		t.Errorf("(a) %d of %d dead sessions neither re-attached nor ended within %v of their death verdict; first: %v", len(late), len(ss), massReattach, late[:min(len(late), 5)])
	}
	if len(gaps) > 0 {
		t.Errorf("(b) %d gaps between %s trunk dials exceeded %v while a dead session waited: %v", len(gaps), massLive, massDialGap, gaps[:min(len(gaps), 5)])
	}
	if len(after)+unanswered == 0 {
		t.Fatalf("stimulus: no flow was first sent from tDead + 1 s (+%v) on", tDead.Add(time.Second).Sub(drop))
	}
	if unanswered != 0 {
		t.Errorf("(c) %d of %d flows first sent from tDead + 1 s on were not answered within %v (DropOpening or DropOpenAge)", unanswered, len(after)+unanswered, massOpenWait)
	}
	if snaps > snapLim {
		t.Errorf("(d) %d health snapshots rang the dialer's sessions (%d rings) from the DROP to the last re-attach (%v), want at most %d", snaps, rung, span, snapLim)
	}

	// Lift the blackhole; every flow ends at its idle limit.
	for _, d := range bothDirs {
		w.dlink(massDrop).Blackhole(d, false)
	}
	drainBy := last.Add(idle.Short + time.Second + 2*time.Second + massOpenWait)
	waitFor(t, time.Until(drainBy), "the drain: no flow, session or shared carrier left", func() bool { return drainedProbing(w, pf) })
	w.noViolation()
	w.close()
}

// massFlowsOn counts the PortForward's open flows whose session's active
// carrier is of factory name.
func massFlowsOn(pf *l4.PortForward, name string) int {
	n := 0
	for _, fi := range pf.Flows() {
		if act, ok := activeOf(fi.Session); ok && fi.State == l4.FlowOpen && act.Name == name {
			n++
		}
	}
	return n
}
