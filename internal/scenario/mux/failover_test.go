package mux

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
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

// TestMuxIdleFailoverCoalesces_L10_L27 (M3 design §A5.8; M3-D16,
// M3-D18 as amended by WP DIALSTORM; B0.2 item 1 — after a carrier death
// the sessions' failovers and rejoins to one factory dial at most once
// together; L10, L27; rendr-regress gold/G6-mixed-nat, defect B): two
// factories p1 and p2 over Links of 10 ms RTT, one Peer with the health
// layer's probes at their default interval. 24 sessions — 12 selector
// (active on p1's shared carrier, which ranks first) and 12 bond (a member
// on p1's and one on p2's shared carrier) — open, exchange 64 KiB each way
// and go idle until every session actor of both Runtimes is parked
// (ActorLinger). A concurrent OPEN load of 20 short selector sessions per
// second (each exchanges 4 KiB each way and closes) runs on the same Peer
// from 1 s before the stimulus to the end of the recovery.
//
// Stimulus: p1's shared carrier is reset (Link.Kill; the path stays up, as
// a NAT rebinding kills a trunk), so every session on it loses its view
// there at once: the bond sessions redial p1, the selector sessions fail
// over. Every session factory call is classified from its DialInfo: an
// OPEN (a load session's dial before its Dial returned) or a failover or
// rejoin (a JOIN of a session open at the time). Variants:
//
//   - "prompt": the passive answers handle 1 at once; the kill falls
//     halfway between two OPENs of the load, so a JOIN claims the redial.
//   - "slow-verdict": as "prompt", with host-like load — the response to
//     each long session's first frame on a new carrier reaches the dialer
//     300 ms after its PREFACE_ACK (three times the pool's least verdict
//     grace) while the PREFACE exchange itself stays prompt.
//   - "open-first": every session's verdict on a new carrier is 300 ms
//     late, and every session's handling of the death is held (Hooks.
//     DeathObserved) until a load session's OPEN made the first redial of
//     p1 and the next OPEN of the load waits for it: an OPEN claimant
//     whose verdict outlasts its verdict grace, and an OPEN waiter whose
//     grace runs out before the JOIN waiters'. The dialer's probe carriers
//     are held across the kill's instant until the shared carrier's death
//     record is set (probeHold): the kill also ends p1's probe carrier,
//     and the health publication of that death rings every session actor;
//     an actor it woke whose step missed the record in its reapDead but
//     saw it in the same step's bond slot check redialled p1 at once,
//     past the gate — a legitimate JOIN (M3-D37) that took the OPEN's
//     place as the first call (WP16-MUX-2: 1 in 90 host -race runs in
//     I3, 1 of 900 in one host -race -count=300 -cpu 1,2,4 pass; "25 of
//     24 deaths held", calls [p1 long=true +0s]).
//
// PASS: recovery — every selector session active and every bond session
// with two live members, none of them the dead carrier — within 10 s;
// from the kill to the recovery exactly one failover or rejoin dial in all
// (p1 and p2; B0.2 item 1) and, besides it, only the open-first
// claimant's OPEN (that is: one session factory call when a JOIN claims,
// two when a slow OPEN claims — the claimant and the one JOIN that dials
// in its place); Status.Mux.Carriers on the dialer at most one per factory
// (plus the OPEN claimant's in open-first) right after the recovery and
// once the load stopped; in open-first, the premise of its stimulus — the
// kill ended p1's probe carrier, and no probe carrier error after the kill
// reached the dialer before the shared carrier's death record was set
// (probeHold; without the hold, or with it released at the kill, this
// fails in most runs, where the race it closes made 1 in 900 fail); every
// long session's exchange after the recovery verified both ways; a clean
// end and nothing left after Runtime.Close. Observed before WP DIALSTORM (slow-verdict): each
// coalesced waiter whose verdict grace ran out while the claimant's JOIN
// awaited its verdict dialled its own carrier — 16 calls, 13 carriers —
// and the extra carriers stayed with their one session; after its first
// round (open-first): the OPEN waiter dialled beside the slow OPEN
// claimant before a JOIN took the claimant's place (3 calls).
func TestMuxIdleFailoverCoalesces_L10_L27(t *testing.T) {
	for _, v := range []struct {
		name      string
		slow      time.Duration
		openFirst bool
	}{{"prompt", 0, false}, {"slow-verdict", 300 * time.Millisecond, false}, {"open-first", 300 * time.Millisecond, true}} {
		t.Run(v.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { idleFailover(t, v.slow, v.openFirst) })
		})
	}
}

// prefaceAckLen is the size of a PREFACE_ACK (wire.PrefaceLen): the
// bytes a session carrier's dialer reads before its first frame's
// response.
const prefaceAckLen = 40

// slowVerdict is a dialer's session carrier conn whose bytes after the
// PREFACE_ACK — the response to its first frame and everything after it —
// reach the reader delay after the reader first asks for them (the
// passive's verdict on handle 1 delayed by host load).
type slowVerdict struct {
	net.Conn
	delay time.Duration
	read  int // bytes returned so far (Establish reads on one goroutine)
	slept bool
}

func (c *slowVerdict) Read(p []byte) (int, error) {
	if c.read < prefaceAckLen && len(p) > prefaceAckLen-c.read {
		p = p[:prefaceAckLen-c.read] // never hand out response bytes with the PREFACE_ACK
	}
	if c.read >= prefaceAckLen && !c.slept {
		c.slept = true
		time.Sleep(c.delay)
	}
	n, err := c.Conn.Read(p)
	c.read += n
	return n, err
}

// sessionDial is one session factory call: its time, factory and session.
type sessionDial struct {
	at      time.Time
	factory string
	sid     rendr.SessionID
}

// dialLog records the session factory calls of a slowPeer.
type dialLog struct {
	mu    sync.Mutex
	dials []sessionDial
}

func (l *dialLog) add(d sessionDial) {
	l.mu.Lock()
	l.dials = append(l.dials, d)
	l.mu.Unlock()
}

// in returns the calls in [from, to), in call order.
func (l *dialLog) in(from, to time.Time) []sessionDial {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []sessionDial
	for _, d := range l.dials {
		if !d.at.Before(from) && d.at.Before(to) {
			out = append(out, d)
		}
	}
	return out
}

// probeHold holds what the dialer's probe carriers read and write while it
// is engaged: every Read and Write of a probeConn returns only once the
// hold is released (at once while it is not engaged). It orders the probe
// carriers' evidence — above all the death of p1's probe carrier, which
// the stimulus's Link.Kill ends together with p1's shared carrier — after
// the death record of the shared carrier, so that the health publication
// it causes, which rings every session actor, wakes no actor before that
// record is set (WP16-MUX-2; idleFailover). It also checks that order:
// once the kill is marked (killed), every probe conn call that returns an
// error is counted (errs), and counted as early if it returned before the
// death record was marked set (recorded), so the row fails if the hold is
// lost or released before the record exists.
type probeHold struct {
	mu   sync.Mutex
	on   chan struct{} // non-nil while engaged; closed by release
	held atomic.Int64  // probe conn calls that waited

	kill, dead  atomic.Bool  // the kill happened; the death record is set
	errs, early atomic.Int64 // probe conn errors after the kill; of them before the record
}

// killed marks the kill: probe conn errors from now on are checked.
func (h *probeHold) killed() { h.kill.Store(true) }

// recorded marks the death record of the shared carrier as set; it must
// come before the release that record allows.
func (h *probeHold) recorded() { h.dead.Store(true) }

// check counts a probe conn call's error returned to the dialer.
func (h *probeHold) check(err error) {
	if err == nil || !h.kill.Load() {
		return
	}
	h.errs.Add(1)
	if !h.dead.Load() {
		h.early.Add(1)
	}
}

// engage starts holding (a no-op while engaged).
func (h *probeHold) engage() {
	h.mu.Lock()
	if h.on == nil {
		h.on = make(chan struct{})
	}
	h.mu.Unlock()
}

// release ends the hold and lets every held call return (idempotent).
func (h *probeHold) release() {
	h.mu.Lock()
	if h.on != nil {
		close(h.on)
		h.on = nil
	}
	h.mu.Unlock()
}

// wait returns once the hold is not engaged.
func (h *probeHold) wait() {
	h.mu.Lock()
	on := h.on
	h.mu.Unlock()
	if on != nil {
		h.held.Add(1)
		<-on
	}
}

// probeConn is a probe carrier's conn under a probeHold: its Read and
// Write return their result only after the hold, if engaged, is released.
type probeConn struct {
	net.Conn
	h *probeHold
}

func (c *probeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.h.wait()
	c.h.check(err)
	return n, err
}

func (c *probeConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.h.wait()
	c.h.check(err)
	return n, err
}

// slowPeer is world.peer over stream links whose session carriers of the
// sessions slow reports true for are wrapped in slowVerdict and whose
// probe carriers are wrapped in probeConn under hold (when hold is not
// nil); every session factory call is also recorded in log.
func (w *world) slowPeer(delay time.Duration, slow func(rendr.SessionID) bool, hold *probeHold, log *dialLog, names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, n := range names {
		s, l := w.spec(n), w.link(n)
		cs = append(cs, rendr.StreamCarrier{Name: n, Props: s.props, Dial: func(ctx context.Context) (net.Conn, error) {
			w.count(ctx, n)
			di, ok := rendr.CarrierDialInfo(ctx)
			if ok && !di.Probe {
				log.add(sessionDial{at: time.Now(), factory: n, sid: di.Session})
			}
			c, err := l.Dial(ctx)
			if err == nil && ok && di.Probe && hold != nil {
				return &probeConn{Conn: c, h: hold}, nil
			}
			if err == nil && ok && !di.Probe && delay > 0 && slow(di.Session) {
				return &slowVerdict{Conn: c, delay: delay}, nil
			}
			return c, err
		}})
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	w.peers = append(w.peers, p)
	return p
}

// loadOpens records when each load session's Dial returned: a factory
// call of that session before then was its OPEN, a later one a failover
// or rejoin.
type loadOpens struct {
	mu   sync.Mutex
	open map[rendr.SessionID]time.Time
}

func (o *loadOpens) add(id rendr.SessionID, at time.Time) {
	o.mu.Lock()
	o.open[id] = at
	o.mu.Unlock()
}

// isOpen reports whether factory call d was a load session's OPEN.
func (o *loadOpens) isOpen(d sessionDial) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	at, ok := o.open[d.sid]
	return ok && d.at.Before(at)
}

// openLoad opens one short selector session over p every interval (keys
// prefix0 …) until stop closes; each exchanges 4 KiB each way, verified,
// and closes. opened records when each session's Dial returned. The
// function it returns waits, once stop closed, for the loop and every
// session it started, and returns how many completed.
func (w *world) openLoad(p *rendr.Peer, prefix string, interval time.Duration, stop chan struct{}, opened *loadOpens) func() int {
	var wg sync.WaitGroup
	var done atomic.Int64
	loop := make(chan struct{})
	go func() {
		defer close(loop)
		tk := time.NewTicker(interval)
		defer tk.Stop()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			wg.Go(func() {
				s, err := w.tryOpen(p, prefix+strconv.Itoa(i), rendr.ModeSelector)
				if err != nil {
					w.t.Error(err)
					return
				}
				opened.add(s.d.ID(), time.Now())
				if err := echo(s, 4<<10, uint64(1000+2*i)); err != nil {
					w.t.Error(err)
				}
				closeAll(w.t, []pair{s})
				done.Add(1)
			})
		}
	}()
	return func() int {
		<-loop
		wg.Wait()
		return int(done.Load())
	}
}

func idleFailover(t *testing.T, slow time.Duration, openFirst bool) {
	const oneWay = 5 * time.Millisecond
	var (
		gateID atomic.Uint32 // the carrier whose death handling is held (0: none)
		gate   = make(chan struct{})
		held   atomic.Int64 // death handlings that reached the gate
		hold   probeHold    // the dialer's probe carriers across the kill (open-first)
	)
	hooks := &testhooks.Hooks{DeathObserved: func(id uint32) {
		if id != 0 && gateID.Load() == id {
			hold.recorded() // the shared carrier's death record is set
			hold.release()
			held.Add(1)
			<-gate
		}
	}}
	w := newWorld(t, worldOpts{dov: testhooks.Overrides{Hooks: hooks}},
		linkSpec{name: "p1", oneWay: oneWay}, linkSpec{name: "p2", oneWay: oneWay})
	var release sync.Once
	open := func() { release.Do(func() { hold.release(); close(gate) }) }
	t.Cleanup(open) // before the world's shutdown (LIFO): no actor stays held
	var (
		armed  atomic.Bool
		lmu    sync.Mutex
		long   = map[rendr.SessionID]bool{}
		log    = &dialLog{}
		opened = &loadOpens{open: map[rendr.SessionID]time.Time{}}
	)
	var probes *probeHold
	if openFirst {
		probes = &hold
	}
	peer := w.slowPeer(slow, func(id rendr.SessionID) bool {
		lmu.Lock()
		defer lmu.Unlock()
		return armed.Load() && (openFirst || long[id])
	}, probes, log, "p1", "p2")
	ps := w.openMany(peer, "L", 24, func(i int) rendr.Mode {
		if i%2 == 0 {
			return rendr.ModeSelector
		}
		return rendr.ModeBond
	})
	var sel, bond []pair
	lmu.Lock()
	for _, s := range ps {
		long[s.d.ID()] = true
		if s.mode == rendr.ModeSelector {
			sel = append(sel, s)
		} else {
			bond = append(bond, s)
		}
	}
	lmu.Unlock()
	waitFor(t, 10*time.Second, "two members per bond session", func() bool {
		for _, s := range bond {
			if len(liveOf(s.d.Status())) != 2 {
				return false
			}
		}
		return true
	})
	exchangeAll(t, ps, 64<<10, 1)
	target, name := sharedTarget(t, sel, len(ps))
	if name != "p1" {
		t.Fatalf("premise: the selector sessions are active on %s, want p1", name)
	}
	if m := w.d.Status().Mux; m.Carriers != 2 {
		t.Fatalf("premise: dialer Status.Mux %+v, want one carrier per factory", m)
	}
	waitFor(t, 10*time.Second, "every session actor of both Runtimes parked", func() bool {
		return testhooks.ParkedSessions.Load()-w.parked0 == int64(2*len(ps))
	})

	stop := make(chan struct{})
	w.addStop(stop)
	loadStart := time.Now()
	loadDone := w.openLoad(peer, "O", 50*time.Millisecond, stop, opened)
	// The kill falls halfway between two OPENs of the load (they start
	// every 50 ms from loadStart): without the gate the first redial is a
	// session's JOIN, as in the regress runs where 22 long sessions each
	// dialled their own carrier.
	killAt := loadStart.Add(time.Second + 25*time.Millisecond)
	if openFirst {
		// The gate holds a session only in its death step, so no session
		// actor may be running a step when the shared carrier's death is
		// recorded: one that missed the record in its reapDead but sees it
		// in the same step's bond slot check redials p1 at once, without
		// passing the gate (WP16-MUX-2), and its JOIN, not an OPEN, makes
		// the first call. The kill also ends p1's probe carrier, whose
		// death the health layer publishes to every session actor: the
		// probe carriers are held from just before the kill's instant
		// (the bubble's clock moves only when every goroutine is blocked,
		// so no step woken earlier still runs at the kill) until the first
		// death handling reached the gate, when the record is set.
		sleepUntil(killAt.Add(-time.Nanosecond))
		hold.engage()
	}
	sleepUntil(killAt)

	armed.Store(true)
	if openFirst {
		gateID.Store(uint32(target.ID))
	}
	coalesced := w.d.Status().Mux.Coalesced
	probesKilled := w.link("p1").Stats().Probe.Killed
	killed := time.Now()
	if openFirst {
		hold.killed()
	}
	if n := w.link("p1").Kill(); n == 0 {
		t.Fatal("stimulus: the kill of p1 ended no carrier")
	}
	probesKilled = w.link("p1").Stats().Probe.Killed - probesKilled
	if openFirst {
		// Every session on the dead carrier is held at its death; the
		// load's next OPEN finds no trunk of p1 and claims its redial, and
		// the OPEN after it waits for that dial. Only then do the held
		// sessions go on: that OPEN waiter's verdict grace runs out before
		// any JOIN waiter's.
		// The stimulus's three parts are reported if it does not come
		// (I3: it timed out once in 3 Linux race passes, cause unknown).
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
			var calls []string
			p1Open := false
			for _, d := range log.in(killed, time.Now().Add(time.Nanosecond)) {
				calls = append(calls, fmt.Sprintf("%s long=%v +%v", d.factory, long[d.sid], d.at.Sub(killed)))
				p1Open = p1Open || (d.factory == "p1" && !long[d.sid])
			}
			h, c := held.Load(), w.d.Status().Mux.Coalesced
			if h >= int64(len(ps)) && c > coalesced && p1Open {
				break
			}
			if !time.Now().Before(deadline) {
				t.Fatalf("timed out after 2s waiting for the death of every long session held, a new session's OPEN dialling p1 and another OPEN waiting for it: %d of %d deaths held, Coalesced %d (at the kill %d), session factory calls %v, probe carrier calls held %d",
					h, len(ps), c, coalesced, calls, hold.held.Load())
			}
		}
		open()
	}
	recovered := func() bool {
		for _, s := range ps {
			st := s.d.Status()
			live := liveOf(st)
			if s.mode == rendr.ModeBond && len(live) != 2 {
				return false
			}
			if _, ok := active(st); s.mode == rendr.ModeSelector && !ok {
				return false
			}
			for _, c := range live {
				if c.ID == target.ID {
					return false
				}
			}
		}
		return true
	}
	waitFor(t, 10*time.Second, "every long session recovered", recovered)
	at := time.Now().Add(time.Nanosecond)
	m := w.d.Status().Mux
	close(stop)
	if n := loadDone(); n < 20 {
		t.Errorf("load: %d short sessions completed, want ≥ 20", n)
	}
	after := w.d.Status().Mux

	// Every load session's Dial has returned: classify the calls.
	dials := log.in(killed, at)
	var opens, rejoins int
	var kinds []string
	for _, d := range dials {
		kind := "rejoin"
		if opened.isOpen(d) {
			kind = "open"
			opens++
		} else {
			rejoins++
		}
		kinds = append(kinds, fmt.Sprintf("%s %s +%v", d.factory, kind, d.at.Sub(killed)))
	}
	t.Logf("recovered %v after the kill: %d session factory calls %v; dialer Status.Mux %+v, %+v once the load stopped",
		at.Sub(killed), len(dials), kinds, m, after)
	wantOpens, maxCarriers := 0, 2
	if openFirst {
		wantOpens, maxCarriers = 1, 3
		if len(dials) == 0 || !opened.isOpen(dials[0]) || dials[0].factory != "p1" {
			t.Errorf("stimulus: the first call after the kill %v, want a new session's OPEN on p1", kinds)
		}
	} else if len(dials) > 0 && opened.isOpen(dials[0]) {
		t.Errorf("stimulus: the first call after the kill was an OPEN %v, want a session's JOIN", kinds)
	}
	if rejoins != 1 || opens != wantOpens {
		t.Errorf("%d failover or rejoin dials and %d OPENs from the kill to the recovery, want exactly 1 and %d (B0.2 item 1)", rejoins, opens, wantOpens)
	}
	if m.Carriers > maxCarriers || after.Carriers > maxCarriers {
		t.Errorf("dialer Status.Mux.Carriers %d right after the recovery and %d once the load stopped, want ≤ %d", m.Carriers, after.Carriers, maxCarriers)
	}
	if openFirst {
		// The premise the stimulus rests on (WP16-MUX-2): the kill ended
		// p1's probe carrier, and the dialer saw that carrier fail only
		// once the shared carrier's death record was set.
		if probesKilled == 0 || hold.errs.Load() == 0 {
			t.Errorf("stimulus: the kill ended %d probe carriers of p1 and the dialer's probe carriers returned %d errors after it, want at least one each", probesKilled, hold.errs.Load())
		}
		if e := hold.early.Load(); e != 0 {
			t.Errorf("premise: %d of %d probe carrier errors after the kill reached the dialer before the shared carrier's death record was set, want none (probeHold)", e, hold.errs.Load())
		}
	}
	exchangeAll(t, ps, 64<<10, 100)
	if t.Failed() {
		t.FailNow()
	}
	closeAll(t, ps)
	w.noViolation()
	w.close()
}
