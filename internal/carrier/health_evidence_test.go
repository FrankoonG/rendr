package carrier

import (
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestProbeEstablishmentPongIsNotASample_L23 (D26, W12, L23): the
// establishment PONG — 300 ms late because the passive's handshake
// processing delays it — gives no sample; the probe carrier's own first
// PING, sent right after Start, does: its RTT counts from the PING's write
// commit and its timestamp is the PONG's arrival (the reader's own clock).
// Probe PINGs then follow every HealthParams.Interval (the Runtime Env's
// own ProbeInterval is not the probe cadence). A reconnect is a new
// incarnation: its evidence is Unknown again although the old samples were
// Fresh, and its first sample again comes from its first PING.
func TestProbeEstablishmentPongIsNotASample_L23(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 2, func(env *Env, p *HealthParams) {
			env.Timing.ProbeInterval = 7 * time.Second // NewHealth must apply Interval (2 s) to its probes
		})
		r.pas.setDelay(300 * time.Millisecond)
		r.h.Use()
		// Hello at 0, at the passive at 10 ms, establishment PONG written
		// at 310 ms, read at 320 ms: the probe carrier starts at 320 ms.
		r.until(330 * time.Millisecond)
		s := r.h.Snapshot()
		old := r.probe(0)
		if old == nil || s.Info[0].ProbeCarrier != old.ID() || s.Info[0].Samples != 0 || s.Evidence(0, time.Now()).State != sched.EvUnknown {
			t.Fatalf("established at 320 ms: info %+v, evidence %v", s.Info[0], s.Evidence(0, time.Now()))
		}
		// Its first PING (committed at 320 ms) is answered at 340 ms.
		r.until(340 * time.Millisecond)
		s = r.h.Snapshot()
		if sum := s.Sum[0]; s.Info[0].Samples != 1 || sum.N != 1 || sum.Mean != 20*time.Millisecond || !sum.At.Equal(r.start.Add(340*time.Millisecond)) {
			t.Fatalf("first sample: info %+v, summary %+v", s.Info[0], sum)
		}
		r.until(2340 * time.Millisecond) // the next PING: Interval after the first commit
		s = r.h.Snapshot()
		if sum := s.Sum[0]; s.Info[0].Samples != 2 || sum.N != 2 || sum.Mean != 20*time.Millisecond || !sum.At.Equal(r.start.Add(2340*time.Millisecond)) {
			t.Fatalf("second sample: info %+v, summary %+v", s.Info[0], sum)
		}
		if ev := s.Evidence(0, time.Now()); ev.State != sched.EvFresh || ev.RTT != 20*time.Millisecond {
			t.Fatalf("evidence %+v, want Fresh 20ms", ev)
		}

		// Reconnect: the path's carriers are killed at 3 s; the slot
		// redials at once (the carrier lived longer than one backoff step).
		r.until(3 * time.Second)
		if n := r.links[0].Kill(); n != 1 {
			t.Fatalf("killed %d carriers on path 0, want the probe", n)
		}
		r.until(3010 * time.Millisecond)
		if c := hCause(old); c != CauseTransportError {
			t.Fatalf("old probe ended with %v", c)
		}
		if s = r.h.Snapshot(); !s.Failed[0] || s.Info[0].FailReason != "transport_error" || s.Info[0].ProbeCarrier != 0 || s.Info[0].Attempts != 2 {
			t.Fatalf("after the death: failed %v, info %+v", s.Failed[0], s.Info[0])
		}
		r.until(3330 * time.Millisecond) // re-established at 3.32 s
		s = r.h.Snapshot()
		nc := r.probe(0)
		if nc == nil || nc == old || s.Info[0].ProbeCarrier != nc.ID() || s.Failed[0] {
			t.Fatalf("reconnect: probe %v (old %v), failed %v, info %+v", nc, old, s.Failed[0], s.Info[0])
		}
		if ev := s.Evidence(0, time.Now()); ev.State != sched.EvUnknown || s.Sum[0].N != 0 || s.Info[0].Samples != 2 {
			t.Fatalf("new incarnation: evidence %v, summary %+v, info %+v", ev, s.Sum[0], s.Info[0])
		}
		r.until(3340 * time.Millisecond)
		s = r.h.Snapshot()
		if sum := s.Sum[0]; s.Info[0].Samples != 3 || sum.N != 1 || !sum.At.Equal(r.start.Add(3340*time.Millisecond)) {
			t.Fatalf("first sample of the new incarnation: info %+v, summary %+v", s.Info[0], sum)
		}
		// The other factory was never disturbed.
		if s.Info[1].Samples != 2 || s.Failed[1] || s.Info[1].Attempts != 1 {
			t.Fatalf("factory 1: failed %v, info %+v", s.Failed[1], s.Info[1])
		}
	})
}

// TestProbeIncarnationOwnsItsPingRecords_L23_L28 (design §8.2, L23): PING
// ids restart in every probe incarnation, so commit records left by an
// incarnation that died with PINGs outstanding must never tag a sample of
// the next one. Path 0 is blackholed right after its first probe carrier
// was established: that carrier's first PING (id 2), committed while the
// factory's gauge is loaded, is never answered and the carrier dies of
// ping_timeout. The replacement's first PING has id 2 again and is
// committed while the gauge is unloaded: its sample is unloaded.
func TestProbeIncarnationOwnsItsPingRecords_L23_L28(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 2, nil)
		g := r.h.Gauges()[0]
		g.AddInflight(1 << 20)
		g.SetBacklog(true) // loaded: the first probe PING (committed at 20 ms) is recorded loaded
		r.h.Use()
		r.until(25 * time.Millisecond) // established at 20 ms; its PING 2 is in flight
		old := r.probe(0)
		r.links[0].SetBlackhole(true)
		r.until(time.Second)
		g.SetBacklog(false)
		g.AddInflight(-(1 << 20))
		r.until(2900 * time.Millisecond) // PING 3 (committed unloaded at 2.02 s) vanished too
		r.links[0].SetBlackhole(false)
		// PING 2 is DeadMin (3 s) old at 3.02 s: ping_timeout; the carrier
		// never produced a sample, so its replacement starts at once.
		r.until(3030 * time.Millisecond)
		if dead, cause, _, _ := old.Death(); !dead || cause != CausePingTimeout {
			t.Fatalf("first probe carrier: dead %v, cause %v", dead, cause)
		}
		if st := r.links[0].Stats().Probe; st.Dropped == 0 {
			t.Fatalf("stimulus: the blackhole dropped nothing: %+v", st)
		}
		r.until(3070 * time.Millisecond) // re-established at 3.04 s; PING 2 committed at 3.04 s, answered at 3.06 s
		s := r.h.Snapshot()
		if nc := r.probe(0); nc == nil || nc == old {
			t.Fatalf("no new incarnation: %v", nc)
		}
		if s.Info[0].Samples != 1 || s.Info[0].LoadedSamples != 0 || s.Sum[0].N != 1 || !s.Sum[0].At.Equal(r.start.Add(3060*time.Millisecond)) {
			t.Fatalf("first sample of the new incarnation: info %+v, summary %+v (want one unloaded sample at 3.06 s)", s.Info[0], s.Sum[0])
		}
	})
}

// TestHealthRanksFreshUnknownFailed_L28 (plan §3.9, design §7.8): the
// snapshot ranks Fresh factories by aggregated RTT, then factories without
// evidence (a dial still hanging) by configuration order, then failed ones
// (a refused path, a MarkFailed) by configuration order. MarkFailed is in
// the snapshot when it returns (the death step ranks right after it,
// §7.3); the mark is cleared by the first probe PONG whose PING was
// committed after it, never by one committed before it.
func TestHealthRanksFreshUnknownFailed_L28(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 4, nil)
		// 0: Fresh, 20 ms RTT. 1: dials hang (Unknown, not failed until
		// DialTimeout). 2: dials refused (failed). 3: Fresh, 10 ms RTT.
		r.links[1].SetDial(rendrtest.DialHang)
		r.links[2].SetRefuse(true)
		r.links[3].SetDelay(5*time.Millisecond, 0)
		bell := &hBell{}
		cancel := r.h.Subscribe(bell)
		defer cancel()
		r.h.Use()
		r.until(time.Second)
		s := r.h.Snapshot()
		if got, want := prRank(s, time.Now()), []int{3, 0, 1, 2}; !slices.Equal(got, want) {
			t.Fatalf("rank %v, want %v (evidence %v %v %v %v, failed %v)", got, want,
				s.Evidence(0, time.Now()), s.Evidence(1, time.Now()), s.Evidence(2, time.Now()), s.Evidence(3, time.Now()), s.Failed)
		}
		// Stimulus proof: each path did what the ranking claims.
		if ev := s.Evidence(3, time.Now()); ev.State != sched.EvFresh || ev.RTT != 10*time.Millisecond {
			t.Fatalf("factory 3 evidence %+v", ev)
		}
		if st := r.links[1].Stats(); st.Dials != 1 || st.DialFailures != 0 || s.Evidence(1, time.Now()).State != sched.EvUnknown || s.Failed[1] {
			t.Fatalf("hanging path: link %+v, evidence %v, failed %v", st, s.Evidence(1, time.Now()), s.Failed[1])
		}
		if st := r.links[2].Stats(); st.DialFailures < 1 || !s.Failed[2] || s.Info[2].FailReason != "transport_error" {
			t.Fatalf("refused path: link %+v, failed %v, info %+v", st, s.Failed[2], s.Info[2])
		}

		// MarkFailed demotes factory 3 below the unmeasured one at once.
		v, rings := s.Version, bell.n.Load()
		r.h.MarkFailed(3, "ping_timeout")
		s = r.h.Snapshot()
		if s.Version != v+1 || bell.n.Load() != rings+1 || !s.Failed[3] || s.Info[3].FailReason != "ping_timeout" {
			t.Fatalf("MarkFailed not published at once: version %d→%d, rings %d→%d, failed %v, info %+v", v, s.Version, rings, bell.n.Load(), s.Failed[3], s.Info[3])
		}
		if got, want := prRank(s, time.Now()), []int{0, 1, 2, 3}; !slices.Equal(got, want) {
			t.Fatalf("rank after MarkFailed %v, want %v", got, want)
		}
		// Factory 3's next PING is committed at 2.01 s (after the mark) and
		// answered at 2.02 s: the mark clears.
		r.until(2015 * time.Millisecond)
		if !r.h.Snapshot().Failed[3] {
			t.Fatal("mark cleared before a PONG")
		}
		r.until(2020 * time.Millisecond)
		s = r.h.Snapshot()
		if s.Failed[3] || s.Info[3].FailReason != "" {
			t.Fatalf("mark not cleared by the PONG of a PING committed after it: %+v", s.Info[3])
		}
		if got, want := prRank(s, time.Now()), []int{3, 0, 1, 2}; !slices.Equal(got, want) {
			t.Fatalf("rank after the PONG %v, want %v", got, want)
		}
		// A mark set between a PING's commit (4.01 s) and its PONG (4.02 s)
		// survives that PONG and clears with the next one (6.02 s).
		r.until(4015 * time.Millisecond)
		r.h.MarkFailed(3, "write_stall")
		r.until(4025 * time.Millisecond)
		if s = r.h.Snapshot(); !s.Failed[3] || s.Info[3].Samples != 3 {
			t.Fatalf("a PONG of a PING committed before the mark cleared it: failed %v, info %+v", s.Failed[3], s.Info[3])
		}
		r.until(6020 * time.Millisecond)
		if s = r.h.Snapshot(); s.Failed[3] || s.Info[3].Samples != 4 {
			t.Fatalf("mark not cleared by the next PONG: failed %v, info %+v", s.Failed[3], s.Info[3])
		}
	})
}

// TestHealthLoadedSamplesExcluded_L28_L29 (design §8.2, L28 at the carrier
// layer): probe samples are tagged loaded through the factory's real
// Gauge — loaded when the gauge was loaded at the PING's commit, or at the
// PONG's arrival, or when its epoch changed in between (a backlog episode
// shorter than the probe RTT); not loaded with in-flight bytes but no
// backlog (an application-limited flow, §8.1) nor with a backlog below
// the threshold. Loaded samples are counted and refresh LoadedAt but never
// enter the window: while this Peer's own load inflates the path's RTT
// tenfold the evidence keeps its unloaded value and turns Held, not
// worse. The guard-disabled control (the same RTT change unloaded) moves
// the evidence, which proves the stimulus (L60).
func TestHealthLoadedSamplesExcluded_L28_L29(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 2, nil)
		g := r.h.Gauges()[0]
		const thr = 64 << 10
		r.h.Use()
		r.until(time.Second) // first sample of factory 0 at 40 ms (PINGs commit at 20 ms + 2k s)
		if s := r.h.Snapshot(); s.Info[0].Samples != 1 || s.Info[0].LoadedSamples != 0 {
			t.Fatalf("baseline: %+v", s.Info[0])
		}
		// Each round k: the PING commits at c = 20 ms + 2k s and its PONG
		// arrives at c + 20 ms. Gauge steps run at offsets from c.
		type step struct {
			at       time.Duration // offset from the commit
			inflight int64         // added to the aggregate in-flight
			backlog  int           // +1 / −1: a carrier enters / leaves the backlog
		}
		rounds := []struct {
			name   string
			steps  []step
			loaded bool
		}{
			{"loaded at the commit only", []step{{-10 * time.Millisecond, thr, +1}, {10 * time.Millisecond, 0, -1}, {30 * time.Millisecond, -thr, 0}}, true},
			{"loaded at the arrival only", []step{{-10 * time.Millisecond, 0, +1}, {10 * time.Millisecond, thr, 0}, {30 * time.Millisecond, -thr, -1}}, true},
			{"epoch changed in between", []step{{-10 * time.Millisecond, thr, 0}, {5 * time.Millisecond, 0, +1}, {10 * time.Millisecond, 0, -1}, {30 * time.Millisecond, -thr, 0}}, true},
			{"in flight without a backlog", []step{{-10 * time.Millisecond, thr, 0}, {30 * time.Millisecond, -thr, 0}}, false},
			{"backlog below the threshold", []step{{-10 * time.Millisecond, thr - 1, +1}, {30 * time.Millisecond, -(thr - 1), -1}}, false},
		}
		unloaded, loaded := uint64(1), uint64(0)
		for k, rd := range rounds {
			c := 20*time.Millisecond + time.Duration(k+1)*2*time.Second
			for _, st := range rd.steps {
				r.until(c + st.at)
				g.AddInflight(st.inflight)
				switch st.backlog {
				case +1:
					g.SetBacklog(true)
				case -1:
					g.SetBacklog(false)
				}
			}
			r.until(c + 40*time.Millisecond)
			if rd.loaded {
				loaded++
			} else {
				unloaded++
			}
			s := r.h.Snapshot()
			if s.Info[0].Samples != unloaded+loaded || s.Info[0].LoadedSamples != loaded || s.Sum[0].N != int(unloaded) {
				t.Fatalf("%s: info %+v, window %d: want %d unloaded and %d loaded samples", rd.name, s.Info[0], s.Sum[0].N, unloaded, loaded)
			}
			if on, _ := g.Loaded(thr); on {
				t.Fatalf("%s: gauge left loaded", rd.name)
			}
		}
		// Self-load: from 11 s the path's RTT is 200 ms and the factory is
		// loaded (a backlogged session carrier holds ≥ the threshold).
		r.until(11 * time.Second)
		before := r.h.Snapshot()
		lastUnloaded := before.Sum[0].At
		r.links[0].SetDelay(100*time.Millisecond, 0)
		g.AddInflight(thr)
		g.SetBacklog(true)
		r.until(25 * time.Second)
		s := r.h.Snapshot()
		if s.Sum[0].Mean != 20*time.Millisecond || s.Sum[0].N != before.Sum[0].N || !s.Sum[0].At.Equal(lastUnloaded) {
			t.Fatalf("loaded samples entered the window: before %+v, after %+v", before.Sum[0], s.Sum[0])
		}
		if n := s.Info[0].LoadedSamples - before.Info[0].LoadedSamples; n != 7 || !s.Sum[0].LoadedAt.After(lastUnloaded.Add(10*time.Second)) {
			t.Fatalf("%d loaded samples, LoadedAt %v (last unloaded %v)", n, s.Sum[0].LoadedAt.Sub(r.start), lastUnloaded.Sub(r.start))
		}
		if ev := s.Evidence(0, time.Now()); ev.State != sched.EvHeld || ev.RTT != 20*time.Millisecond {
			t.Fatalf("evidence under self-load %+v, want Held at the unloaded 20ms", ev)
		}
		// Guard-disabled control: the same 200 ms path without load moves
		// the evidence (the level shift restarts the window).
		g.SetBacklog(false)
		g.AddInflight(-thr)
		r.until(31 * time.Second)
		s = r.h.Snapshot()
		if ev := s.Evidence(0, time.Now()); ev.State != sched.EvFresh || ev.RTT != 200*time.Millisecond {
			t.Fatalf("control: evidence %+v, summary %+v, want Fresh 200ms", ev, s.Sum[0])
		}
		// Factory 1's gauge was never loaded: none of its samples was.
		if s.Info[1].LoadedSamples != 0 || s.Info[1].Samples < 15 {
			t.Fatalf("factory 1: %+v", s.Info[1])
		}
	})
}

// TestHealthEvidenceAgesWithoutRepublication_L28_L29 (D25, L28): snapshots
// carry time-independent summaries, so evidence ages at the consumer's own
// now: with both paths silent (stalled, never judged dead) nothing is
// published, yet the same snapshot classifies factory 0 Fresh until its
// last unloaded sample is Probe.Fresh old, then Held (a later loaded
// sample) at the unloaded value, then Stale; factory 1 goes from Fresh to
// Stale. sched.NextChange gives every boundary.
func TestHealthEvidenceAgesWithoutRepublication_L28_L29(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 2, func(env *Env, p *HealthParams) {
			env.Timing.DeadMin, env.Timing.DeadMax = time.Hour, time.Hour // silence is not death here
		})
		g := r.h.Gauges()[0]
		r.h.Use()
		// Factory 0's samples: 40 ms, 2.04 s, 4.04 s unloaded; 6.04 s loaded.
		r.until(5990 * time.Millisecond)
		g.AddInflight(1 << 20)
		g.SetBacklog(true)
		r.until(6100 * time.Millisecond)
		g.SetBacklog(false)
		g.AddInflight(-(1 << 20))
		r.until(7 * time.Second)
		r.links[0].SetStall(true)
		r.links[1].SetStall(true)
		s := r.h.Snapshot()
		at := func(d time.Duration) time.Time { return r.start.Add(d) }
		if s.Info[0].Samples != 4 || s.Info[0].LoadedSamples != 1 || !s.Sum[0].At.Equal(at(4040*time.Millisecond)) || !s.Sum[0].LoadedAt.Equal(at(6040*time.Millisecond)) {
			t.Fatalf("factory 0 before the silence: info %+v, summary %+v", s.Info[0], s.Sum[0])
		}
		const ns = time.Nanosecond
		checks := []struct {
			t     time.Duration
			f0    sched.EvState
			f0RTT time.Duration
			f1    sched.EvState
		}{
			{8 * time.Second, sched.EvFresh, 20 * time.Millisecond, sched.EvFresh},
			{14040 * time.Millisecond, sched.EvFresh, 20 * time.Millisecond, sched.EvFresh},
			{14040*time.Millisecond + ns, sched.EvHeld, 20 * time.Millisecond, sched.EvFresh},
			{16040 * time.Millisecond, sched.EvHeld, 20 * time.Millisecond, sched.EvFresh},
			{16040*time.Millisecond + ns, sched.EvStale, 0, sched.EvStale},
			{30 * time.Second, sched.EvStale, 0, sched.EvStale},
		}
		for _, c := range checks {
			r.until(c.t)
			now := time.Now()
			if cur := r.h.Snapshot(); cur != s {
				t.Fatalf("at %v: republished (version %d → %d)", c.t, s.Version, cur.Version)
			}
			e0, e1 := s.Evidence(0, now), s.Evidence(1, now)
			if e0.State != c.f0 || e0.RTT != c.f0RTT || e1.State != c.f1 {
				t.Fatalf("at %v: evidence %+v / %+v, want %v(%v) / %v", c.t, e0, e1, c.f0, c.f0RTT, c.f1)
			}
		}
		// The boundaries a consumer would arm a timer for.
		if nc := sched.NextChange(s.Sum[0], at(8*time.Second), s.Fresh); !nc.Equal(at(14040*time.Millisecond + ns)) {
			t.Fatalf("NextChange %v", nc.Sub(r.start))
		}
		if nc := sched.NextChange(s.Sum[0], at(15*time.Second), s.Fresh); !nc.Equal(at(16040*time.Millisecond + ns)) {
			t.Fatalf("NextChange %v", nc.Sub(r.start))
		}
		r.links[0].SetStall(false)
		r.links[1].SetStall(false)
	})
}

// TestHealthIgnoresStaleIncarnation_L21_L23: the observer accepts PING
// commits and PONGs only from the factory's current probe incarnation; a
// late callback of a replaced carrier changes nothing — no sample, no
// publication, no mark cleared, and no commit record that a PING of the
// current incarnation with the same id (ids restart per incarnation) could
// match. A PONG that overtook its own PingCommitted callback (the writer
// makes a PING matchable before it reports the commit) waits for it: the
// sample is then tagged loaded when the gauge was loaded at the arrival,
// at the commit callback, or its epoch changed in between (§8.2).
func TestHealthIgnoresStaleIncarnation_L21_L23(t *testing.T) {
	env := hEnv()
	fs := []Factory{{Name: "a"}, {Name: "b"}}
	h := NewHealth(env, fs, prParams())
	defer h.Close()
	pipe := func() *Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return newConn(env, a, env.IDs.Next(), hPassiveInst, 0, "a", true)
	}
	oldC, cur := pipe(), pipe()
	h.mu.Lock()
	h.fac[0].conn = cur
	h.mu.Unlock()
	h.MarkFailed(0, "ping_timeout")
	v := h.Snapshot().Version
	g := h.Gauges()[0]
	const big = 1 << 20
	at := time.Now().Add(time.Second)
	ms := time.Millisecond

	// The replaced incarnation commits PING 7 while the gauge is loaded and
	// gets its PONG: nothing changes.
	g.AddInflight(big)
	g.SetBacklog(true)
	h.obs.PingCommitted(oldC, 7, at)
	h.obs.Pong(oldC, 7, 5*ms, at.Add(5*ms))
	if s := h.Snapshot(); s.Version != v || s.Info[0].Samples != 0 || !s.Failed[0] {
		t.Fatalf("a stale incarnation changed the evidence: version %d→%d, info %+v, failed %v", v, s.Version, s.Info[0], s.Failed[0])
	}
	// The current incarnation's own PING 7, committed and answered while
	// the gauge is unloaded (same epoch): an unloaded sample, which also
	// clears the mark (its PING was committed after it).
	g.SetBacklog(false)
	h.obs.PingCommitted(cur, 7, at)
	h.obs.Pong(cur, 7, 5*ms, at.Add(5*ms))
	s := h.Snapshot()
	if s.Version != v+1 || s.Info[0].Samples != 1 || s.Info[0].LoadedSamples != 0 || s.Failed[0] {
		t.Fatalf("current PING 7 (a stale commit record must not tag it): version %d→%d, info %+v, failed %v", v, s.Version, s.Info[0], s.Failed[0])
	}

	// PONGs that overtook their commit callback. The gauge starts each step
	// unloaded: its in-flight estimate is above the threshold (until the
	// third step) and no carrier is backlogged.
	nop := func() {}
	steps := []struct {
		name                   string
		arrival, commit, after func() // gauge changes before the PONG, before its PingCommitted, after the step
		loaded                 bool
	}{
		{"loaded at the commit only", nop, func() { g.SetBacklog(true) }, func() { g.SetBacklog(false) }, true},
		{"loaded at the arrival only", func() { g.SetBacklog(true) }, func() { g.SetBacklog(false) }, nop, true},
		{"epoch changed in between", func() { g.AddInflight(-big) }, func() { g.SetBacklog(true); g.SetBacklog(false) }, nop, true},
		{"never loaded", nop, nop, nop, false},
	}
	samples, loaded := uint64(1), uint64(0)
	for k, st := range steps {
		id := uint32(8 + k)
		pongAt := at.Add(time.Duration(k+1) * time.Second)
		st.arrival()
		ver := h.Snapshot().Version
		h.obs.Pong(cur, id, 5*ms, pongAt)
		if s := h.Snapshot(); s.Version != ver || s.Info[0].Samples != samples {
			t.Fatalf("%s: a PONG ahead of its commit callback became a sample before it: %+v", st.name, s.Info[0])
		}
		st.commit()
		h.obs.PingCommitted(cur, id, pongAt.Add(-5*ms))
		st.after()
		samples++
		stamp := func(s *Snapshot) time.Time { return s.Sum[0].At }
		if st.loaded {
			loaded++
			stamp = func(s *Snapshot) time.Time { return s.Sum[0].LoadedAt }
		}
		s := h.Snapshot()
		if s.Version != ver+1 || s.Info[0].Samples != samples || s.Info[0].LoadedSamples != loaded || !stamp(s).Equal(pongAt) {
			t.Fatalf("%s: version %d→%d, info %+v, summary %+v (want %d samples, %d loaded, stamped at the arrival)", st.name, ver, s.Version, s.Info[0], s.Sum[0], samples, loaded)
		}
	}
}
