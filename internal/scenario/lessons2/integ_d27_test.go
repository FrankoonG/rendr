package lessons2

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestSelectorFailoverRefusalsRecover_L18 (L18, L20; design D27 and §0.14
// B6, close-b integration): a selector session over a Peer with factories a
// and b runs on a toward a passive whose MaxCarriersPerSession is 1; b was
// never dialled for the session. Right after the passive's idle PING the
// dialer loses a's path locally and a stays down (its factory fails): the
// passive keeps the stale lane until its PING times out, PingIdle + DeadMin
// ≈ 13 s later, and answers every JOIN with JOIN_ACK CAPACITY until then.
// The failover race dials b without a Kick of b's slot, so the slot's
// recovery window (sched.Cadence) does not apply: only the session-side rule
// keeps such refusals at Backoff(0) — a refusal while the session has no
// live carrier must not grow the interval (B6 aims at persistent refusals
// beside a live carrier). The session must reattach on b within one
// Backoff(0) of the passive dropping the stale lane, inside the grace, and
// go on delivering. Without the rule b's refusals grew to the 4 s cap and
// the session ended with ErrNoPath at the grace for jitter 0 and 0.5 (JOINs
// at 0, 0.5, 1.5, 3.5, 7.5 and 11.5 s with jitter 0.5, none in
// [13 s, 15 s)).
func TestSelectorFailoverRefusalsRecover_L18(t *testing.T) {
	for _, j := range []struct {
		name string
		u    float64 // fixed jitter; negative: the real jitter source
	}{
		{"jitter 0", 0},
		{"jitter 0.5", 0.5},
		{"jitter 1", 1},
		{"real jitter", -1},
	} {
		t.Run(j.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { integFailoverRecovery(t, j.u) })
		})
	}
}

func integFailoverRecovery(t *testing.T, u float64) {
	const (
		grace      = 15 * time.Second // NoPathGrace (the default, set explicitly)
		backoffMax = 4 * time.Second  // RejoinBackoffMax (the default, set explicitly)
		pingIdle   = 10 * time.Second // the passive's PingIdle (the default)
		timerSlack = time.Millisecond // the actor arms no timer shorter than 1 ms
		lossDelay  = 30 * time.Millisecond
		chunk      = 64 << 10
	)
	cap := min(backoffMax, grace/2)
	maxGap := sched.Backoff(0, cap, 1) + timerSlack
	ov := &testhooks.Overrides{}
	if u >= 0 {
		ov.Rand = func() float64 { return u }
	}
	e := newEnv(t, rendr.Config{NoPathGrace: grace, RejoinBackoffMax: backoffMax}, rendr.Config{MaxCarriersPerSession: 1}, ov)
	for _, rt := range []*rendr.Runtime{e.d, e.p} {
		if adj := rt.Status().ConfigAdjustments; len(adj) != 0 {
			t.Fatalf("configuration adjusted: %v", adj)
		}
	}
	a := e.path("a", 5*time.Millisecond) // the faster path: the session opens on it
	b := e.path("b", 10*time.Millisecond)
	la, lb := &g3Lossy{p: a}, &g3Lossy{p: b}
	peer, err := e.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{la.carrier(), lb.carrier()}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	dc, pc := e.open(peer, rendr.DialOptions{})
	exchange(t, dc, pc, chunk, 2900)

	// The loss follows the passive's next idle PING on a by 30 ms.
	time.Sleep(time.Second)
	n0 := len(a.sentBack(wire.TypePing))
	waitFor(t, pingIdle+time.Second, time.Millisecond, "the passive's idle PING on a", func() bool {
		return len(a.sentBack(wire.TypePing)) > n0
	})
	pings := a.sentBack(wire.TypePing)
	time.Sleep(time.Until(pings[len(pings)-1].at.Add(lossDelay)))
	ds := dc.Status()
	if l := liveOf(ds, ""); len(l) != 1 || l[0].Name != "a" {
		t.Fatalf("before the loss: live carriers %+v, want a alone", l)
	}
	// Stimulus: b's slot never dialled for the session, so no Kick can open
	// a recovery window for it.
	if n := len(b.sessionConns(true)); n != 0 {
		t.Fatalf("stimulus: b carried %d session carriers before the loss, want none", n)
	}
	aID := liveOf(ds, "a")[0].ID
	cut := time.Now()
	a.link.SetRefuse(true)
	if n := la.lose() + lb.lose(); n != 1 {
		t.Fatalf("stimulus: the loss hit %d session carriers, want 1", n)
	}
	waitFor(t, time.Second, time.Millisecond, "the dialer saw a die", func() bool { return len(liveOf(dc.Status(), "")) == 0 })
	waitFor(t, grace+time.Second, time.Millisecond, "reattach (or the session's end)", func() bool {
		st := dc.Status()
		return st.State == rendr.StateEnded || len(liveOf(st, "")) == 1
	})
	ds = dc.Status()
	if ds.State != rendr.StateOpen || ds.NoPathEpisodes != 1 {
		t.Fatalf("after the loss: dialer %v (err %v), %d episodes; want open, 1", ds.State, ds.Err, ds.NoPathEpisodes)
	}
	if l := liveOf(ds, ""); l[0].Name != "b" {
		t.Fatalf("path a is down, yet %s attached", l[0].Name)
	}
	var stale time.Time
	for _, ev := range e.pev.of(rendr.EventCarrierDown) {
		if ev.Carrier == aID {
			stale = ev.Time
		}
	}
	if stale.IsZero() || stale.Sub(cut) < pingIdle-time.Second || !stale.Before(cut.Add(grace)) {
		t.Fatalf("stimulus: the passive dropped a's stale lane at +%v after the loss, want within [+%v, +%v)",
			stale.Sub(cut), pingIdle-time.Second, grace)
	}
	if js := g3Joins(a, cut); len(js) != 0 {
		t.Fatalf("path a is down, yet %d JOINs crossed it", len(js))
	}

	// Every JOIN of b kept the Backoff(0) cadence while the passive held the
	// stale lane, those that reached it well before it dropped the lane were
	// refused with CAPACITY, and the attaching one was written within one
	// Backoff(0) of the drop.
	js := g3Joins(b, cut)
	if len(js) == 0 {
		t.Fatal("stimulus: no JOIN on b after the loss")
	}
	var prev time.Time
	refused, attached := 0, false
	for k, c := range js {
		j, _ := c.out.first()
		st, ok := g3AckStatus(c)
		if k == 0 && j.at.Sub(cut) > 100*time.Millisecond {
			t.Fatalf("b: the failover race's first JOIN started %v after the loss, want at once", j.at.Sub(cut))
		}
		if k > 0 && prev.Before(stale) && j.at.Sub(prev) > maxGap {
			t.Fatalf("b: JOIN %d started %v after the previous one (at +%v), want at most %v while no carrier lives",
				k+1, j.at.Sub(prev), j.at.Sub(cut), maxGap)
		}
		prev = j.at
		if j.at.Before(stale.Add(-time.Second)) {
			if !ok || st != wire.StatusCapacity {
				t.Fatalf("stimulus: b: JOIN %d at +%v (stale lane held) got status %d (ok %v), want CAPACITY", k+1, j.at.Sub(cut), st, ok)
			}
			refused++
			continue
		}
		if ok && st == wire.StatusOK {
			if j.at.Before(stale.Add(-50*time.Millisecond)) || j.at.Sub(stale) > maxGap {
				t.Fatalf("b: JOIN %d attached, written %v after the stale lane died, want within (−50ms, %v]", k+1, j.at.Sub(stale), maxGap)
			}
			attached = true
			break
		}
	}
	if !attached {
		t.Fatal("b attached, but none of its JOINs after the loss was answered OK")
	}
	if lo := int((stale.Sub(cut) - time.Second) / maxGap); refused < lo {
		t.Fatalf("stimulus: %d JOINs of b refused with CAPACITY before the passive dropped the stale lane, want at least %d", refused, lo)
	}
	t.Logf("b: %d JOINs refused, attached %v after the stale lane died (+%v)", refused, prev.Sub(stale), stale.Sub(cut))

	// Load and integrity: the session delivers again, exactly.
	exchange(t, dc, pc, chunk, 2902)
	ds, ps := dc.Status(), pc.Status()
	want := uint64(2 * chunk)
	if ds.DeliveredBytes != want || ps.DeliveredBytes != want || ds.TxBytes != want || ps.TxBytes != want {
		t.Fatalf("load: dialer delivered %d sent %d, passive delivered %d sent %d; want %d each",
			ds.DeliveredBytes, ds.TxBytes, ps.DeliveredBytes, ps.TxBytes, want)
	}
	endClean(t, dc, pc)
	e.close()
}
