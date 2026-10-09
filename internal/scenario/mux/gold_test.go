package mux

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// openGoldSessions opens the mux gold cases' four sessions in order (F38):
// S1, S2 selector, S3, S4 bond, and waits until both bond sessions hold a
// member on each factory.
func openGoldSessions(w *world, peer *rendr.Peer) []pair {
	w.t.Helper()
	var ps []pair
	for i, m := range []rendr.Mode{rendr.ModeSelector, rendr.ModeSelector, rendr.ModeBond, rendr.ModeBond} {
		ps = append(ps, w.open(peer, fmt.Sprintf("S%d", i+1), m))
	}
	waitFor(w.t, 10*time.Second, "two members per bond session", func() bool {
		return len(liveOf(ps[2].d.Status())) == 2 && len(liveOf(ps[3].d.Status())) == 2
	})
	return ps
}

// verdict reports a death verdict cause (the gold's DROP causes).
func verdict(c rendr.Cause) bool { return c == rendr.CausePingTimeout || c == rendr.CauseWriteStall }

// droppedCause requires the death record of the blackholed carrier id in
// every session that listed it, on both ends (G4-mux: one death record,
// every session's lane carries it). The end whose verdict comes first
// records ping_timeout or write_stall; a rendrtest Link delivers a
// carrier's close even while it is blackholed (the close crosses the
// DROP, unlike an nft DROP), so the other end may record that close as
// transport_error, but only at or after the first verdict.
func droppedCause(t testing.TB, w *world, ps []pair, id rendr.CarrierID, drop time.Time) {
	t.Helper()
	var evs [2]rendr.Event
	for i, l := range []*eventLog{w.dev, w.pev} {
		waitFor(t, 10*time.Second, side(i)+"'s death record of the dropped carrier", func() bool {
			d := l.downOf(id)
			if len(d) > 0 {
				evs[i] = d[0]
			}
			return len(d) > 0
		})
	}
	first := 0
	if evs[1].Time.Before(evs[0].Time) || (evs[1].Time.Equal(evs[0].Time) && verdict(evs[1].Cause)) {
		first = 1
	}
	if !verdict(evs[first].Cause) {
		t.Fatalf("the %s's death record of the dropped carrier %d (the first): %+v, want ping_timeout or write_stall", side(first), id, evs[first])
	}
	if o := evs[1-first]; !verdict(o.Cause) && (o.Cause != rendr.CauseTransportError || o.Time.Before(evs[first].Time)) {
		t.Fatalf("the %s's death record of the dropped carrier %d: %+v, want ping_timeout or write_stall (or the first verdict's close)", side(1-first), id, o)
	}
	for _, s := range ps {
		for i, c := range []*rendr.Conn{s.d, s.p} {
			cs, ok := carrierOf(c.Status(), id)
			if !ok {
				continue
			}
			if cs.State != rendr.CarrierDead || cs.DeathCause != evs[i].Cause {
				t.Fatalf("session %s (%s): the dropped carrier %d is %+v, want dead with %v (the carrier's one death record)", s.key, side(i), id, cs, evs[i].Cause)
			}
		}
	}
	t.Logf("the dropped carrier %d: dialer %v at DROP +%v, passive %v at DROP +%v", id, evs[0].Cause, evs[0].Time.Sub(drop), evs[1].Cause, evs[1].Time.Sub(drop))
}

// TestMuxG4Miniature (M3 design §A11.2, B1.7; plan:746–751; L27, L10):
// gold/G4-mux at reduced scale: the zero Config on both ends, two Links p1
// and p2 of 20 ms RTT shaped to 8 MiB/s each (2 MiB/s under -race,
// R1-11), one Peer with four sessions opened in order (S1, S2 selector,
// S3, S4 bond), each sending open-ended bulk B → A (all four keep running
// through the DROP, so the bond sessions keep p2's shared carrier alive).
//
// Stimulus: 1.5 s into the transfers (the open-ended counterpart of the
// gold's "≈ 30 % of the aggregate"), the path of the F40 target — the carrier the selector
// sessions are active on, shared with the bond sessions' member of that
// factory (Shared 4) — is blackholed in both directions until the end (the
// gold's nft DROP: no RST; new dials "open" and never answer). Its
// sessions must have carried data on it and the link must drop session
// bytes. The senders half-close 6 s after the DROP.
//
// PASS per session: no application error; new bytes at the receiving
// application within 5 s of the DROP; every byte verified with io.EOF
// after exactly what its sender wrote (the data written before the DROP
// included). Case level: the dropped carrier's cause is ping_timeout or
// write_stall in every listed session's CarrierStatus on both ends (one
// death record; droppedCause's transport_error rule for the Link's close);
// at most one session factory call per factory from the DROP to the
// senders' half-close (F41: the bond members' coalesced redial of the
// dropped path; none on p2); every selector session's new active carrier is p2's; a clean end
// and nothing left after Runtime.Close.
func TestMuxG4Miniature(t *testing.T) {
	rate := float64(8 << 20)
	if raceEnabled {
		rate = 2 << 20 // R1-11
	}
	synctest.Test(t, func(t *testing.T) { g4(t, rate) })
}

func g4(t *testing.T, rate float64) {
	const oneWay, after = 10 * time.Millisecond, 6 * time.Second
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: oneWay, rate: rate}, linkSpec{name: "p2", oneWay: oneWay, rate: rate})
	peer := w.peer("p1", "p2")
	ps := openGoldSessions(w, peer)
	b := w.startBulk(ps, openEnded, 0)
	start := time.Now()

	sleepUntil(start.Add(1500 * time.Millisecond))
	target, name := sharedTarget(t, ps, 4)
	if name != "p1" {
		t.Fatalf("premise: the selector sessions are active on %s, want p1 (first in order)", name)
	}
	for _, s := range ps {
		if cs, ok := carrierOf(s.p.Status(), target.ID); !ok || cs.TxBytes == 0 {
			t.Fatalf("stimulus: session %s carried no data on the target %d before the DROP: %+v", s.key, target.ID, cs)
		}
	}
	l := w.link(name)
	dropped0 := l.Stats().Session.Dropped
	drop := time.Now()
	l.SetBlackhole(true)
	sleepUntil(drop.Add(after))
	if l.Stats().Session.Dropped == dropped0 {
		t.Fatal("stimulus: the DROP dropped no session byte")
	}
	for _, s := range ps[:2] {
		if a, ok := active(s.d.Status()); !ok || a.Name != "p2" {
			t.Errorf("selector session %s's active carrier after the DROP: %+v, want p2's", s.key, a)
		}
	}
	end := time.Now() // the senders half-close: from here the sessions end, and a claimant's end releases its waiters (R1-8)
	for _, s := range b.tx {
		s.end()
	}
	for i, r := range b.rx {
		r.waitSent(t, b.tx[i], time.Minute)
	}
	for _, r := range b.up {
		r.wait(t, time.Minute)
	}
	for i, r := range b.rx {
		first := r.firstAfter(drop)
		if first.IsZero() || first.Sub(drop) > 5*time.Second {
			t.Errorf("session %s: the first new bytes after the DROP at +%v, want ≤ 5 s", ps[i].key, first.Sub(drop))
		} else {
			t.Logf("session %s (%v): new bytes DROP +%v; %d bytes in all", ps[i].key, ps[i].mode, first.Sub(drop), r.got.Load())
		}
	}
	for _, f := range []string{"p1", "p2"} {
		if n := w.dialsIn(f, drop, end); n > 1 {
			t.Errorf("%d session factory calls on %s from the DROP to the half-close, want ≤ 1 (F41)", n, f)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	droppedCause(t, w, ps, target.ID, drop)
	t.Logf("DROP at +%v; dials from it: p1 %d, p2 %d; dialer Mux %+v", drop.Sub(start), w.dialsIn("p1", drop, end), w.dialsIn("p2", drop, end), w.d.Status().Mux)
	closeAll(t, ps)
	w.noViolation()
	w.close()
}

// G5-mux miniature bounds (as package race's G5 miniature): with
// DialTimeout = 5 s on the dialer T_gap = 5 s; G5Bound = T_gap + 3·RTT +
// S + 1 s = 5 s + 60 ms + 1 s + 1 s, S being the 1-s Status sample.
const (
	g5DialTimeout = 5 * time.Second
	g5Bound       = g5DialTimeout + 60*time.Millisecond + 2*time.Second
	g5Dropped     = 20 * time.Second
	g5Sample      = time.Second
	g5Window      = 8 << 20 // the default Window
)

// TestMuxG5Miniature_L22 (M3 design §A11.2, B1.9; plan:754–765; L22):
// gold/G5-mux at reduced scale: two Links of 20 ms RTT shaped to 25 MiB/s
// each, path B (factory b) before path A (factory a) in the Peer; the
// dialer's DialTimeout is 5 s; four sessions opened in order (S1, S2
// selector — active on b, the first factory —, S3, S4 bond), each with a
// continuous B → A transfer paced at 512 KiB/s (128 KiB/s under -race,
// R1-11; the gold paces 20 Mbit/s).
//
// Sequence (M1c's G5-sel flow for the selector sessions, G5-bond's
// criteria for the bond sessions): 5 s into the transfers path A is
// blackholed both ways for 20 s (the bond members on a must die), then
// restored (T_rm); at T_rm + G5Bound the selector sessions' shared active
// carrier on b — which also carries the bond sessions' b members — is
// reset (Link.Kill); the transfers run until 8 s after the reset.
//
// PASS per session: bond — a new member of a's factory listed within
// G5Bound of T_rm whose TxBytes on the sending side B grow in 2
// consecutive 1-s samples (L22: a rejoined member carries data); selector —
// after the reset the new active carrier is a's (the one the bond
// sessions rejoined: a fast path), the first new bytes at most 5 s after
// the reset, and at most one quality migration in [T_rm, reset]; common —
// every byte verified with io.EOF at the end (zero loss, duplicate and
// reorder), B's RetransmittedBytes grow by at most one Window from T_rm,
// no zero-delivery gap above 500 ms from T_rm to the end. Case level (F41
// at the reset, R1-19): at most one session factory call on b (the bond
// members' coalesced redial) and none on a; a clean end and nothing left
// after Runtime.Close.
func TestMuxG5Miniature_L22(t *testing.T) {
	rate := float64(512 << 10)
	if raceEnabled {
		rate = 128 << 10 // R1-11
	}
	synctest.Test(t, func(t *testing.T) { g5(t, rate) })
}

func g5(t *testing.T, rate float64) {
	const (
		oneWay = 10 * time.Millisecond
		link   = 25 << 20
		before = 5 * time.Second
		after  = 8 * time.Second
	)
	w := newWorld(t, worldOpts{dcfg: rendr.Config{DialTimeout: g5DialTimeout}},
		linkSpec{name: "b", oneWay: oneWay, rate: link}, linkSpec{name: "a", oneWay: oneWay, rate: link})
	if adj := w.d.Status().ConfigAdjustments; len(adj) != 0 {
		t.Fatalf("the dialer's Config was adjusted: %q", adj)
	}
	peer := w.peer("b", "a")
	ps := openGoldSessions(w, peer)
	b := w.startBulk(ps, openEnded, rate) // paced; the senders half-close 8 s after the reset
	start := time.Now()

	// The DROP of path A for 20 s.
	sleepUntil(start.Add(before))
	la := w.link("a")
	var victims []rendr.CarrierID
	for _, s := range ps[2:] {
		m, ok := liveNamed(s.d.Status(), "a")
		if pm, okp := carrierOf(s.p.Status(), m.ID); !ok || !okp || pm.TxBytes == 0 {
			t.Fatalf("stimulus: bond session %s's member of a carried no data before the DROP: %+v", s.key, pm)
		}
		victims = append(victims, m.ID)
	}
	dropped0 := la.Stats().Session.Dropped
	drop := time.Now()
	la.SetBlackhole(true)
	sleepUntil(drop.Add(g5Dropped))
	if la.Stats().Session.Dropped == dropped0 {
		t.Fatal("stimulus: the DROP of a dropped no session byte")
	}
	for i, s := range ps[2:] {
		if cs, ok := carrierOf(s.d.Status(), victims[i]); !ok || cs.State != rendr.CarrierDead {
			t.Fatalf("stimulus: bond session %s's member %d of a is not dead after the DROP: %+v", s.key, victims[i], cs)
		}
	}
	rm := time.Now()
	var retx0 []uint64
	var quality0 []uint64
	for _, s := range ps {
		retx0 = append(retx0, s.p.Status().RetransmittedBytes)
		quality0 = append(quality0, s.d.Status().Migrations.Quality)
	}
	la.SetBlackhole(false)

	// One loop watches both bond sessions' rejoins of a and samples each
	// rejoined member's TxBytes on B at 1 s and 2 s after it was listed, and
	// resets b at exactly T_rm + G5Bound whatever the samples' progress
	// (samples after the reset still show the member carrying data). A
	// rejoin not listed by then fails the case.
	type rejoin struct {
		id      rendr.CarrierID
		listed  time.Time
		tx      uint64
		samples int
	}
	var (
		rj      [2]rejoin
		reset   time.Time
		target  rendr.CarrierStatus
		quality []uint64
	)
	for {
		now := time.Now()
		for i, s := range ps[2:] {
			r := &rj[i]
			if r.listed.IsZero() {
				if m, ok := liveNamed(s.d.Status(), "a"); ok && m.ID != victims[i] {
					r.id, r.listed = m.ID, now
					if pm, ok := carrierOf(s.p.Status(), m.ID); ok {
						r.tx = pm.TxBytes
					}
					t.Logf("bond session %s: member %d of a listed at T_rm +%v", s.key, m.ID, now.Sub(rm))
				}
				continue
			}
			if r.samples < 2 && !now.Before(r.listed.Add(time.Duration(r.samples+1)*g5Sample)) {
				r.samples++
				pm, ok := carrierOf(s.p.Status(), r.id)
				if !ok || pm.TxBytes <= r.tx {
					t.Fatalf("bond session %s: the rejoined member %d's TxBytes on B did not grow in sample %d: %d → %+v", s.key, r.id, r.samples, r.tx, pm)
				}
				r.tx = pm.TxBytes
			}
		}
		if reset.IsZero() && !now.Before(rm.Add(g5Bound)) {
			for i, s := range ps[2:] {
				if rj[i].listed.IsZero() {
					t.Fatalf("bond session %s: no new member of a listed within G5Bound (%v) of T_rm", s.key, g5Bound)
				}
			}
			// The reset of the selector sessions' shared carrier on b.
			var name string
			target, name = sharedTarget(t, ps, 4)
			if name != "b" {
				t.Fatalf("premise: the selector sessions are active on %s at T_rm + G5Bound, want b", name)
			}
			for _, s := range ps {
				quality = append(quality, s.d.Status().Migrations.Quality)
			}
			lb := w.link("b")
			reset = time.Now()
			if lb.Kill(); lb.Stats().Session.Killed == 0 {
				t.Fatal("stimulus: the reset of b ended no session carrier")
			}
		}
		if !reset.IsZero() && rj[0].samples == 2 && rj[1].samples == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if late := reset.Sub(rm.Add(g5Bound)); late > time.Millisecond {
		t.Fatalf("premise: the reset of b came %v after T_rm + G5Bound", late)
	}

	// F41 is judged over the 5 s after the reset, while every session still
	// sends (they half-close 8 s after it; a claimant's end would release
	// its waiters to dials of their own, R1-8).
	sleepUntil(reset.Add(5 * time.Second))
	for _, r := range b.rx {
		if r.finished() {
			t.Fatalf("premise: %s ended within 5 s of the reset", r.name)
		}
	}
	if n := w.dialsIn("b", reset, time.Now()); n > 1 {
		t.Errorf("%d session factory calls on b in the 5 s after the reset, want ≤ 1 (the bond members' coalesced redial)", n)
	}
	if n := w.dialsIn("a", reset, time.Now()); n != 0 {
		t.Errorf("%d session factory calls on a in the 5 s after the reset, want 0 (the selector sessions JOIN the bond members' carrier)", n)
	}
	for _, s := range ps[:2] {
		if na, ok := active(s.d.Status()); !ok || na.Name != "a" || na.ID == target.ID {
			t.Errorf("selector session %s: the active carrier after the reset is %+v, want a's", s.key, na)
		}
	}
	sleepUntil(reset.Add(after))
	for _, s := range b.tx {
		s.end()
	}
	for i, r := range b.rx {
		r.waitSent(t, b.tx[i], 2*time.Minute)
	}
	for _, r := range b.up {
		r.wait(t, 2*time.Minute)
	}
	for i, s := range ps {
		r := b.rx[i]
		if s.mode == rendr.ModeSelector {
			if q := quality[i] - quality0[i]; q > 1 {
				t.Errorf("selector session %s: %d quality migrations in [T_rm, reset], want ≤ 1", s.key, q)
			}
			if first := r.firstAfter(reset); first.IsZero() || first.Sub(reset) > 5*time.Second {
				t.Errorf("selector session %s: the first new bytes after the reset at +%v, want ≤ 5 s", s.key, first.Sub(reset))
			} else {
				t.Logf("selector session %s: new bytes reset +%v", s.key, first.Sub(reset))
			}
		}
		if g, at := r.maxGap(rm, r.end()); g > 500*time.Millisecond {
			t.Errorf("session %s: a zero-delivery gap of %v at T_rm +%v, want ≤ 500 ms", s.key, g, at.Sub(rm))
		}
		if d := s.p.Status().RetransmittedBytes - retx0[i]; d > g5Window {
			t.Errorf("session %s: B retransmitted %d bytes from T_rm, more than one Window (%d)", s.key, d, g5Window)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	for _, s := range ps {
		ds, pss := s.d.Status(), s.p.Status()
		t.Logf("session %s (%v): migrations dialer %+v, passive %+v; Rejoins %d; B retransmitted %d", s.key, s.mode, ds.Migrations, pss.Migrations, ds.Rejoins, pss.RetransmittedBytes)
	}
	closeAll(t, ps)
	w.noViolation()
	w.close()
}
