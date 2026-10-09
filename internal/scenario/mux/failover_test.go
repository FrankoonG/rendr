package mux

import (
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// bulk is a set of sessions each moving size bytes B → A (and nothing
// A → B), with their receivers and senders.
type bulk struct {
	ps   []pair
	rx   []*receiver // B → A, read by the dialer's application
	tx   []*sender
	up   []*receiver // A → B: 0 bytes, then io.EOF
	size int64
}

// startBulk starts size bytes B → A on every session (seed 1 + index),
// paced at rate bytes/s when rate > 0.
func (w *world) startBulk(ps []pair, size int64, rate float64) *bulk {
	b := &bulk{ps: ps, size: size}
	for i, s := range ps {
		b.rx = append(b.rx, startReceiver(s.key+" B → A", s.d, uint64(1+i), size))
		b.up = append(b.up, startReceiver(s.key+" A → B", s.p, uint64(100+i), 0))
		b.tx = append(b.tx, w.startSender(s.p, uint64(1+i), size, rate))
		w.startSender(s.d, uint64(100+i), 0, 0)
	}
	return b
}

// got returns the bytes the dialer applications received in all.
func (b *bulk) got() int64 {
	var n int64
	for _, r := range b.rx {
		n += r.got.Load()
	}
	return n
}

// wait waits for every transfer's verified end.
func (b *bulk) wait(t testing.TB, within time.Duration) {
	t.Helper()
	for _, r := range b.rx {
		r.wait(t, within)
	}
	for _, r := range b.up {
		r.wait(t, within)
	}
	for _, s := range b.tx {
		s.wait(t, within)
	}
}

// sharedTarget returns the carrier the selector sessions of ps are active
// on (they must agree) and its factory name, requiring that it carries at
// least min sessions (Shared on the dialer).
func sharedTarget(t testing.TB, ps []pair, min int) (rendr.CarrierStatus, string) {
	t.Helper()
	var target rendr.CarrierStatus
	for _, s := range ps {
		if s.mode != rendr.ModeSelector {
			continue
		}
		a, ok := active(s.d.Status())
		if !ok || (target.ID != 0 && a.ID != target.ID) {
			t.Fatalf("premise: selector session %s active on %+v (found %v), the others on %d", s.key, a, ok, target.ID)
		}
		target = a
	}
	if target.Shared < min {
		t.Fatalf("premise: the selector sessions' carrier %d carries %d sessions, want ≥ %d", target.ID, target.Shared, min)
	}
	return target, target.Name
}

// TestMuxDeathRequeuesEverySession_L10 (M3 design §A5.7, §A11.2; L10,
// M3-D14; G1-mux in miniature): two factories p1 and p2 over Links of
// 20 ms RTT shaped to 16 MiB/s each (4 MiB/s under -race, R1-11) with a
// bottleneck queue of rate / 16 (62.5 ms; rendrtest's 2-MiB default
// would queue 500 ms at the race size, which alone would exceed the gap
// bound below, whatever rendr does); one Peer
// opens 2 selector and 2 bond sessions (in that order), and each sends B →
// A as fast as it can for 4 s, then half-closes — about 4 × 32 MiB in all
// (4 × 8 MiB under -race). Open-ended bulk keeps every session's sender
// backlogged on every carrier it uses, so each kill finds unacknowledged
// data of every session on the killed carrier (a sized transfer would let
// the bond sessions, with a member on each Link, finish long before the
// selector sessions' third kill).
//
// Stimulus: 1, 2 and 3 s into the transfer, the carrier the selector
// sessions are active on — shared with the bond sessions' member of that
// factory (Shared ≥ 3 asserted before every kill) — is reset (Link.Kill:
// both ends closed at once, as an RST). Every session on it records it
// dead within 1 s.
// PASS: every session's bytes verified against the PRNG with io.EOF after
// exactly what its sender wrote, and no application error; no zero-delivery
// gap above 500 ms in any session from the first kill to its end (the
// death reaches every session on the carrier at once: M3-D14's fan-out);
// each selector session counts ≥ 3 Death migrations on both ends (a bond
// session's sender counts one only when its member on the killed carrier
// held unacknowledged data, which the shared carrier's capacity rotation
// does not guarantee at the kill instant: logged, not judged); every kill is recovered with at most one session factory
// call per factory (F41) and through the pool's fast path (FastPaths grows
// at every kill: the selector sessions JOIN the other factory's live
// carrier kept by the bond members); the links stay loaded (≥ 70 % of
// their capacity over the run); a clean end and nothing left after
// Runtime.Close.
func TestMuxDeathRequeuesEverySession_L10(t *testing.T) {
	rate := float64(16 << 20)
	if raceEnabled {
		rate = 4 << 20 // R1-11
	}
	synctest.Test(t, func(t *testing.T) { deathRequeues(t, rate) })
}

func deathRequeues(t *testing.T, rate float64) {
	const oneWay, run = 10 * time.Millisecond, 4 * time.Second
	buf := int(rate / 16) // a bottleneck queue of 62.5 ms (rendrtest's 2 MiB default would hold 500 ms at the race size's rate)
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: oneWay, rate: rate, buffer: buf}, linkSpec{name: "p2", oneWay: oneWay, rate: rate, buffer: buf})
	peer := w.peer("p1", "p2")
	var ps []pair
	for i, m := range []rendr.Mode{rendr.ModeSelector, rendr.ModeSelector, rendr.ModeBond, rendr.ModeBond} {
		ps = append(ps, w.open(peer, fmt.Sprintf("S%d", i), m))
	}
	waitFor(t, 10*time.Second, "two bond members per bond session", func() bool {
		return len(liveOf(ps[2].d.Status())) == 2 && len(liveOf(ps[3].d.Status())) == 2
	})
	b := w.startBulk(ps, openEnded, 0)
	start := time.Now()

	var kills []time.Time
	for k := range 3 {
		sleepUntil(start.Add(time.Duration(k+1) * time.Second))
		target, name := sharedTarget(t, ps, 3)
		fp0 := w.d.Status().Mux.FastPaths
		l := w.link(name)
		before := l.Stats().Session.Killed
		at := time.Now()
		l.Kill()
		if l.Stats().Session.Killed == before {
			t.Fatalf("stimulus: kill %d of %s ended no session carrier", k+1, name)
		}
		kills = append(kills, at)
		hit := 0
		for _, s := range ps {
			if _, had := carrierOf(s.d.Status(), target.ID); !had {
				continue
			}
			hit++
			waitFor(t, time.Second, fmt.Sprintf("session %s to record carrier %d dead", s.key, target.ID), func() bool {
				cs, _ := carrierOf(s.d.Status(), target.ID)
				return cs.State == rendr.CarrierDead
			})
		}
		waitFor(t, 5*time.Second, "the selector sessions active on the other factory", func() bool {
			for _, s := range ps[:2] {
				if a, ok := active(s.d.Status()); !ok || a.ID == target.ID {
					return false
				}
			}
			return true
		})
		if fp := w.d.Status().Mux.FastPaths; fp <= fp0 {
			t.Fatalf("kill %d: Status.Mux.FastPaths stayed %d: no session recovered through a live carrier", k+1, fp)
		}
		t.Logf("kill %d at +%v: carrier %d of %s (Shared %d, %d sessions hit)", k+1, at.Sub(start), target.ID, name, target.Shared, hit)
	}
	sleepUntil(start.Add(run))
	for _, s := range b.tx {
		s.end()
	}
	for i, r := range b.rx {
		r.waitSent(t, b.tx[i], time.Minute)
	}
	for _, r := range b.up {
		r.wait(t, time.Minute)
	}
	end := time.Now()
	if got, capacity := b.got(), 2*rate*run.Seconds(); float64(got) < 0.7*capacity {
		t.Errorf("load: the sessions moved %d bytes in all, want ≥ 70 %% of the links' %.0f", got, capacity)
	}
	for i, r := range b.rx {
		if g, at := r.maxGap(kills[0], r.end()); g > 500*time.Millisecond {
			t.Errorf("session %s: a zero-delivery gap of %v at kill 1 +%v, want ≤ 500 ms", ps[i].key, g, at.Sub(kills[0]))
		}
	}
	bounds := append(append([]time.Time{}, kills...), end)
	for k := range kills {
		for _, f := range []string{"p1", "p2"} {
			if n := w.dialsIn(f, bounds[k], bounds[k+1]); n > 1 {
				t.Errorf("kill %d: %d session factory calls on %s, want ≤ 1 (F41)", k+1, n, f)
			}
		}
	}
	for i, s := range ps {
		ds, pss := s.d.Status(), s.p.Status()
		t.Logf("session %s (%v): %d bytes; migrations dialer %+v, passive %+v; B retransmitted %d", s.key, s.mode, b.rx[i].got.Load(), ds.Migrations, pss.Migrations, pss.RetransmittedBytes)
		if s.mode == rendr.ModeSelector && (ds.Migrations.Death < 3 || pss.Migrations.Death < 3) {
			t.Errorf("selector session %s: Death migrations %d (dialer) and %d (passive), want ≥ 3 on both ends", s.key, ds.Migrations.Death, pss.Migrations.Death)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	closeAll(t, ps)
	w.noViolation()
	w.close()
}

// TestMuxCoalescedFailover (M3 design §A5.8, §A11.2; M3-D16, M3-D18): two
// factories p1 (5 ms one way) and p2 (10 ms one way), 8 selector sessions
// all active on p1's one shared carrier (p1 ranks first); p2 carries no
// session carrier (its probe carrier never enters the pool, M3-D41). Each
// session's B → A sender writes 1 KiB every 10 ms.
//
// Stimulus: p1's carrier is reset (Link.Kill) and p1 refuses new dials
// from then on, so every session fails over to p2, which has no live
// carrier. PASS: exactly one session factory call on p2 (the first
// session's dial; the other seven wait for it and open their views on the
// published carrier: Coalesced grows by ≥ 1 and FastPaths by 7), all 8
// sessions on that one carrier (Shared 8) and each receives new bytes
// within 1 virtual second of the kill; every byte verified with io.EOF at
// the end; a clean end and nothing left after Runtime.Close.
func TestMuxCoalescedFailover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: 5 * time.Millisecond}, linkSpec{name: "p2", oneWay: 10 * time.Millisecond})
		peer := w.peer("p1", "p2")
		ps := w.openMany(peer, "S", 8, func(int) rendr.Mode { return rendr.ModeSelector })
		target, name := sharedTarget(t, ps, 8)
		if name != "p1" || w.dials("p2") != 0 {
			t.Fatalf("premise: the sessions are on %s's carrier with %d session calls on p2, want p1 and none", name, w.dials("p2"))
		}
		const rate = 100 << 10 // 1 KiB per 10-ms slot
		size := int64(4 * rate)
		b := w.startBulk(ps, size, rate)
		time.Sleep(time.Second)

		m0 := w.d.Status().Mux
		l := w.link("p1")
		l.SetRefuse(true)
		killed := time.Now()
		if l.Kill(); l.Stats().Session.Killed == 0 {
			t.Fatal("stimulus: the kill of p1 ended no session carrier")
		}
		// One deadline for all 8: every session resumes within 1 virtual s of
		// the kill (not one after the other, each within its own second).
		waitFor(t, time.Second, "every session's first bytes after the kill", func() bool {
			for _, r := range b.rx {
				if r.firstAfter(killed).IsZero() {
					return false
				}
			}
			return true
		})
		var last time.Duration
		for i, r := range b.rx {
			d := r.firstAfter(killed).Sub(killed)
			if d > time.Second {
				t.Fatalf("session %s: the first new bytes %v after the kill, want ≤ 1 s", ps[i].key, d)
			}
			last = max(last, d)
		}
		t.Logf("all 8 sessions received new bytes within %v of the kill", last)
		if got := w.dialsIn("p2", killed, time.Now()); got != 1 {
			t.Fatalf("%d session factory calls on p2 after the kill, want exactly 1 (coalesced)", got)
		}
		m := w.d.Status().Mux
		if m.Coalesced <= m0.Coalesced || m.FastPaths-m0.FastPaths != 7 {
			t.Fatalf("Status.Mux %+v → %+v: want Coalesced to grow and FastPaths to grow by 7", m0, m)
		}
		if t2, n2 := sharedTarget(t, ps, 8); n2 != "p2" || t2.ID == target.ID {
			t.Fatalf("the sessions failed over to %s carrier %d, want p2's", n2, t2.ID)
		}
		b.wait(t, time.Minute)
		closeAll(t, ps)
		w.noViolation()
		w.close()
	})
}

// TestMuxFastPathJoin (M3 design §A5.8 G4 budget, §A11.2; M3-D16, L27):
// two factories p1 and p2 over Links of 20 ms RTT. A bond session K keeps a
// member on each factory, so p2 has a live shared carrier; a selector
// session S is active on p1's carrier (with K's p1 member). S's B → A
// sender writes 1 KiB every 10 ms.
//
// Stimulus: p1's carrier is reset (Link.Kill). S's death decision is its
// dialer's EventCarrierDown of that carrier. PASS: S fails over to p2's
// live carrier with no session factory call on p2 (a JOIN on the fast
// path; FastPaths grows), and S's application receives the first new byte
// at most 3 RTT (60 ms) after the death decision (the budget: the JOIN's
// RTT, the go frame's RTT before passive-first data and half an RTT,
// §A5.8); every byte verified with io.EOF at the end; a clean end and
// nothing left after Runtime.Close.
func TestMuxFastPathJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const oneWay = 10 * time.Millisecond
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: oneWay}, linkSpec{name: "p2", oneWay: oneWay})
		peer := w.peer("p1", "p2")
		s := w.open(peer, "S", rendr.ModeSelector)
		k := w.open(peer, "K", rendr.ModeBond)
		waitFor(t, 10*time.Second, "K's two members", func() bool { return len(liveOf(k.d.Status())) == 2 })
		a, ok := active(s.d.Status())
		if !ok || a.Name != "p1" || a.Shared != 2 {
			t.Fatalf("premise: S active on %+v, want p1's carrier shared with K", a)
		}
		k2, _ := liveNamed(k.d.Status(), "p2")
		const rate = 100 << 10
		b := w.startBulk([]pair{s, k}, 4*rate, rate)
		time.Sleep(time.Second)

		fp0, calls0 := w.d.Status().Mux.FastPaths, w.dials("p2")
		if n := w.link("p1").Kill(); n == 0 {
			t.Fatal("stimulus: the kill of p1 ended no carrier")
		}
		var down rendr.Event
		waitFor(t, time.Second, "S's death decision", func() bool {
			var ok bool
			down, ok = w.dev.sessionDown(s.d.ID(), a.ID)
			return ok
		})
		var first time.Time
		waitFor(t, time.Second, "S's first new byte", func() bool {
			first = b.rx[0].firstAfter(down.Time)
			return !first.IsZero()
		})
		if got := w.dials("p2") - calls0; got != 0 {
			t.Fatalf("S's failover made %d session factory calls on p2, want 0 (a JOIN on K's live carrier)", got)
		}
		na, ok := active(s.d.Status())
		if !ok || na.ID != k2.ID {
			t.Fatalf("S is active on %+v, want K's p2 carrier %d", na, k2.ID)
		}
		if fp := w.d.Status().Mux.FastPaths; fp <= fp0 {
			t.Fatalf("Status.Mux.FastPaths stayed %d", fp)
		}
		if d := first.Sub(down.Time); d > 3*2*oneWay {
			t.Fatalf("S's first new byte came %v after the death decision, want ≤ 3 RTT (%v)", d, 3*2*oneWay)
		} else {
			t.Logf("S's first new byte %v after the death decision (%v)", d, down.Cause)
		}
		b.wait(t, time.Minute)
		closeAll(t, []pair{s, k})
		w.noViolation()
		w.close()
	})
}

// TestMuxDeathDuringRequeue_L10_L27 (M3 design §A5.7 rule 5, §A5.13 E13;
// L10, L27): two factories p1 and p2 over Links of 20 ms RTT shaped to
// 16 MiB/s each (4 MiB/s under -race, R1-11); one Peer opens 2 selector
// and 2 bond sessions, and each sends open-ended bulk both ways, so both
// ends of every session hold unacknowledged data on both shared carriers.
//
// Stimulus, twice, on the carrier selector session S0 is active on
// (shared with the bond sessions' member of that factory) and then on the
// other factory's carrier (the bond sessions' other member, where the
// first death's requeue goes):
//  1. hooked: the passive's DeathObserved hook, at the first observation
//     of the first carrier's death (before that session handles it), kills
//     the second carrier — every requeue of the first death targets a lane
//     that is already dead;
//  2. timed: the second carrier is killed 5 ms after the first, while the
//     requeued ranges are on their way over it (half an RTT).
//
// Each round must end both carriers in every session (both listed dead on
// both ends) and the hook must have fired. The sessions redial (no live
// carrier is left) and recover: no zero-delivery gap above 1 s in any
// direction of any session from the first kill on.
// PASS: every byte delivered once, in order: each direction verified
// against the PRNG with io.EOF after exactly what its sender wrote (the
// merged retransmission ranges replay from the ACK edge before new data,
// L10, independent of how many carriers the session lost, L27); a clean
// end and nothing left after Runtime.Close.
func TestMuxDeathDuringRequeue_L10_L27(t *testing.T) {
	rate := float64(16 << 20)
	if raceEnabled {
		rate = 4 << 20 // R1-11
	}
	synctest.Test(t, func(t *testing.T) { deathDuringRequeue(t, rate) })
}

func deathDuringRequeue(t *testing.T, rate float64) {
	const oneWay = 10 * time.Millisecond
	var (
		first   atomic.Uint32          // the carrier whose first death observation fires the hook (0: disarmed)
		second  atomic.Pointer[string] // the Link the hook kills
		fired   = make(chan struct{})
		firedAt atomic.Int64
	)
	var w *world
	hook := func(id uint32) {
		if id == 0 || !first.CompareAndSwap(id, 0) {
			return
		}
		firedAt.Store(time.Now().UnixNano())
		w.link(*second.Load()).Kill()
		close(fired)
	}
	buf := int(rate / 16) // a bottleneck queue of 62.5 ms, as TestMuxDeathRequeuesEverySession_L10
	w = newWorld(t, worldOpts{pov: testhooks.Overrides{Hooks: &testhooks.Hooks{DeathObserved: hook}}},
		linkSpec{name: "p1", oneWay: oneWay, rate: rate, buffer: buf}, linkSpec{name: "p2", oneWay: oneWay, rate: rate, buffer: buf})
	peer := w.peer("p1", "p2")
	var ps []pair
	for i, m := range []rendr.Mode{rendr.ModeSelector, rendr.ModeSelector, rendr.ModeBond, rendr.ModeBond} {
		ps = append(ps, w.open(peer, fmt.Sprintf("S%d", i), m))
	}
	ready := func() bool {
		if len(liveOf(ps[2].d.Status())) != 2 || len(liveOf(ps[3].d.Status())) != 2 {
			return false
		}
		_, ok0 := active(ps[0].d.Status())
		_, ok1 := active(ps[1].d.Status())
		return ok0 && ok1
	}
	waitFor(t, 10*time.Second, "two bond members per bond session and an active carrier per selector session", ready)

	var rx []*receiver
	var tx []*sender
	for i, s := range ps {
		rx = append(rx, startReceiver(s.key+" B → A", s.d, uint64(1+2*i), openEnded), startReceiver(s.key+" A → B", s.p, uint64(2+2*i), openEnded))
		tx = append(tx, w.startSender(s.p, uint64(1+2*i), openEnded, 0), w.startSender(s.d, uint64(2+2*i), openEnded, 0))
	}
	start := time.Now()
	var kills []time.Time
	for round, hooked := range []bool{true, false} {
		sleepUntil(start.Add(time.Duration(round+1) * time.Second))
		if !waitUntilOK(10*time.Second, ready) {
			for _, s := range ps {
				t.Logf("session %s (%v): dialer %+v", s.key, s.mode, liveOf(s.d.Status()))
			}
			t.Fatalf("round %d: the sessions are not back on two carriers 10 s after the last kill", round+1)
		}
		// The first carrier: S0's active one, shared with both bond
		// sessions' member of its factory (the selector sessions may sit on
		// different factories after round 1's redials); the second: the
		// other factory's, where the first death's requeue goes.
		t1, _ := active(ps[0].d.Status())
		n1 := t1.Name
		n2 := map[string]string{"p1": "p2", "p2": "p1"}[n1]
		t2, ok := liveNamed(ps[2].d.Status(), n2)
		if t1.Shared < 3 || !ok || t2.Shared < 2 {
			t.Fatalf("premise: round %d: S0's carrier %+v and the bond sessions' carrier of %s %+v (found %v), want them shared by ≥ 3 and ≥ 2 sessions", round+1, t1, n2, t2, ok)
		}
		at := time.Now()
		kills = append(kills, at)
		if hooked {
			second.Store(&n2)
			first.Store(uint32(t1.ID))
			w.link(n1).Kill()
			select {
			case <-fired:
			case <-time.After(5 * time.Second):
				t.Fatalf("stimulus: the passive never observed the death of carrier %d", t1.ID)
			}
			t.Logf("round 1: %s's carrier %d killed; %s's carrier %d killed from the hook %v later", n1, t1.ID, n2, t2.ID, time.Duration(firedAt.Load()-at.UnixNano()))
		} else {
			w.link(n1).Kill()
			time.Sleep(oneWay / 2)
			w.link(n2).Kill()
			t.Logf("round 2: %s's carrier %d killed, %s's carrier %d %v later", n1, t1.ID, n2, t2.ID, oneWay/2)
		}
		for _, s := range ps {
			for i, c := range []*rendr.Conn{s.d, s.p} {
				for _, id := range []rendr.CarrierID{t1.ID, t2.ID} {
					if _, had := carrierOf(c.Status(), id); !had {
						continue
					}
					waitFor(t, 2*time.Second, fmt.Sprintf("session %s (%s) to record carrier %d dead", s.key, side(i), id), func() bool {
						cs, _ := carrierOf(c.Status(), id)
						return cs.State == rendr.CarrierDead
					})
				}
			}
		}
	}
	sleepUntil(start.Add(3 * time.Second))
	for _, s := range tx {
		s.end()
	}
	for i, r := range rx {
		r.waitSent(t, tx[i], time.Minute)
		if g, at := r.maxGap(kills[0], r.end()); g > time.Second {
			t.Errorf("%s: a zero-delivery gap of %v at round 1 +%v, want ≤ 1 s", r.name, g, at.Sub(kills[0]))
		}
	}
	for _, s := range ps {
		ds, pss := s.d.Status(), s.p.Status()
		t.Logf("session %s (%v): migrations dialer %+v, passive %+v; retransmitted A %d, B %d; DupBytes A %d, B %d",
			s.key, s.mode, ds.Migrations, pss.Migrations, ds.RetransmittedBytes, pss.RetransmittedBytes, ds.DupBytes, pss.DupBytes)
	}
	if t.Failed() {
		t.FailNow()
	}
	closeAll(t, ps)
	w.noViolation()
	w.close()
}

// waitUntilOK polls cond every millisecond for at most within and reports
// whether it held.
func waitUntilOK(within time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(within)
	for !cond() {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}
