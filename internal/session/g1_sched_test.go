package session

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// SCHED migration counts on the passive (design §0.14 B1; L45, invariants
// 4 and 6): the store bounds what a SCHED may claim by its own epoch, and
// following the counts of an applied SCHED is O(1). Every package-level
// identifier of this file starts with "g1".

// g1Counts is a SCHED's epoch and cumulative selector migration counts.
type g1Counts struct {
	epoch   uint32
	d, q, x uint64
}

func (k g1Counts) String() string {
	return fmt.Sprintf("{epoch %d: %d/%d/%d}", k.epoch, k.d, k.q, k.x)
}

// g1Sched delivers SCHED{k, ids} with cause c on lane l as its reader would
// (Control after CRC verification) and returns Control's error.
func g1Sched(l *lane, c wire.SchedCause, k g1Counts, ids ...uint32) error {
	sc := wire.Sched{Epoch: k.epoch, Death: k.d, Quality: k.q, Explicit: k.x, N: len(ids)}
	copy(sc.IDs[:], ids)
	var p [wire.SchedFixedLen + 4*wire.MaxSchedIDs]byte
	n := wire.PutSched(p[:], &sc)
	h := wire.Header{Type: wire.TypeSched, Flags: uint8(c), Len: uint32(n), Handle: wire.SessionHandle}
	return l.Control(l.c, h, p[:n])
}

// g1Stored returns the SCHED the passive s stored (zero without one) and
// takes the stream facts, reporting whether factSched was among them.
func g1Stored(s *Session) (k g1Counts, set, rang bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &s.ctl
	if c.schedInSet {
		k = g1Counts{c.schedIn.Epoch, c.schedIn.Death, c.schedIn.Quality, c.schedIn.Explicit}
	}
	return k, c.schedInSet, s.takeFactsLocked()&factSched != 0
}

// TestSchedCountsBound_L45 (§0.14 B1): the passive stores a newer SCHED
// only when its counts sum to at most the SCHEDs a dialer can have
// published up to its epoch — epoch − (FirstEpoch − 1), unwrapped past 2³²
// by the migrations the passive followed. Anything else is a violation of
// the delivering carrier (Control's error kills only it) and leaves the
// stored SCHED and the counters as they were. The bound never involves an
// earlier SCHED: a forged one within it cannot make the dialer's later
// SCHEDs fail, and a count below an earlier SCHED's is no violation. A
// SCHED that is not newer than the newest stored or applied one — before
// any, FirstEpoch − 1 — is ignored whatever its counts.
func TestSchedCountsBound_L45(t *testing.T) {
	type step struct {
		k    g1Counts
		want error    // Control's error (nil: stored, or ignored when not newer)
		kept g1Counts // the stored SCHED afterwards (the zero value: none)
	}
	none := g1Counts{}
	const w32 = 1 << 32
	cases := []struct {
		name     string
		mode     Mode
		first    uint32   // FirstEpoch
		applied  uint32   // the applied epoch (0: first − 1, as NewPending sets it)
		followed g1Counts // the passive's counters before the first SCHED (epoch unused)
		steps    []step
	}{
		{name: "beyond the epoch", first: 1, steps: []step{
			{g1Counts{1, 2, 0, 0}, errSchedCounts, none},                 // one publication counts at most one migration
			{g1Counts{1, 0, 1, 1}, errSchedCounts, none},                 // two causes, one publication
			{g1Counts{1, 1, 0, 0}, nil, g1Counts{1, 1, 0, 0}},            // within the bound
			{g1Counts{2, 3, 0, 0}, errSchedCounts, g1Counts{1, 1, 0, 0}}, // one cause beyond two publications
			{g1Counts{2, 2, 1, 0}, errSchedCounts, g1Counts{1, 1, 0, 0}}, // each cause within, the sum beyond
			{g1Counts{2, 1, 1, 1}, errSchedCounts, g1Counts{1, 1, 0, 0}}, // quality and explicit together
			{g1Counts{3, 2, 1, 0}, nil, g1Counts{3, 2, 1, 0}},
		}},
		{name: "forged", first: 1, steps: []step{
			{g1Counts{2, 1 << 62, 0, 0}, errSchedCounts, none},          // B1's reproduction
			{g1Counts{2, math.MaxUint64, 0, 0}, errSchedCounts, none},   // the largest count
			{g1Counts{2, 1 << 63, 1 << 63, 0}, errSchedCounts, none},    // counts whose 64-bit sum wraps to 0
			{g1Counts{2, 0, math.MaxUint64, 1}, errSchedCounts, none},   // wraps to 0 with the third cause
			{g1Counts{0x7FFFFFFF, 1 << 31, 0, 0}, errSchedCounts, none}, // the farthest newer epoch, one count beyond
			{g1Counts{0x7FFFFFFF, 1<<31 - 1, 0, 0}, nil, g1Counts{0x7FFFFFFF, 1<<31 - 1, 0, 0}},
		}},
		{name: "forged reference", first: 1, steps: []step{
			// A forged SCHED within the bound (two epochs ahead, two
			// explicit migrations) is stored like the dialer's own. The
			// dialer's later SCHEDs — three deaths by epoch 4, no explicit
			// migration — must still pass: the review's reference rule
			// rejected every one of them, a carrier death each, forever.
			{g1Counts{3, 0, 0, 2}, nil, g1Counts{3, 0, 0, 2}},
			{g1Counts{4, 3, 0, 0}, nil, g1Counts{4, 3, 0, 0}},
			{g1Counts{5, 4, 0, 0}, nil, g1Counts{5, 4, 0, 0}},
		}},
		{name: "lower counts", first: 1, steps: []step{
			{g1Counts{3, 1, 1, 1}, nil, g1Counts{3, 1, 1, 1}},
			{g1Counts{4, 0, 2, 1}, nil, g1Counts{4, 0, 2, 1}}, // death 1 → 0: which of the two is forged is unknowable
			{g1Counts{9, 2, 0, 3}, nil, g1Counts{9, 2, 0, 3}},
			{g1Counts{10, 0, 0, 0}, nil, g1Counts{10, 0, 0, 0}},
		}},
		{name: "lost", first: 1, steps: []step{
			{g1Counts{1, 0, 0, 0}, nil, g1Counts{1, 0, 0, 0}}, // the opening SCHED
			{g1Counts{3, 2, 0, 0}, nil, g1Counts{3, 2, 0, 0}}, // epoch 2 (death 1) was lost: a valid jump of 2
			{g1Counts{6, 2, 2, 1}, nil, g1Counts{6, 2, 2, 1}}, // two lost again, three migrations of two causes
		}},
		{name: "stale", first: 1, steps: []step{
			{g1Counts{5, 2, 0, 0}, nil, g1Counts{5, 2, 0, 0}},
			{g1Counts{4, 0, 0, 0}, nil, g1Counts{5, 2, 0, 0}},                // older, lower counts: ignored
			{g1Counts{3, 9, 9, 9}, nil, g1Counts{5, 2, 0, 0}},                // older, any counts: ignored
			{g1Counts{5, 9, 9, 9}, nil, g1Counts{5, 2, 0, 0}},                // the same epoch never replaces
			{g1Counts{0x80000005, 1 << 62, 0, 0}, nil, g1Counts{5, 2, 0, 0}}, // 2³¹ away: not newer in serial arithmetic
			{g1Counts{6, 3, 0, 0}, nil, g1Counts{6, 3, 0, 0}},
		}},
		{name: "stale before the first", first: 1, steps: []step{
			// Nothing stored yet: the reference is the initial applied
			// epoch FirstEpoch − 1 = 0.
			{g1Counts{0, 5, 0, 0}, nil, none},          // the initial epoch itself, a count beyond any bound
			{g1Counts{0x80000000, 0, 0, 0}, nil, none}, // 2³¹ away
			{g1Counts{0x80000001, 0, 0, 0}, nil, none}, // older across the wrap
			{g1Counts{0xFFFFFFF0, 1, 0, 0}, nil, none}, // just below the initial epoch
			{g1Counts{1, 0, 0, 0}, nil, g1Counts{1, 0, 0, 0}},
		}},
		{name: "applied reference", first: 1, applied: 7, followed: g1Counts{0, 3, 1, 1}, steps: []step{
			{g1Counts{7, 0, 0, 0}, nil, none},                 // the applied epoch: ignored
			{g1Counts{6, 9, 9, 9}, nil, none},                 // older than the applied epoch
			{g1Counts{8, 4, 2, 3}, errSchedCounts, none},      // 9 migrations by epoch 8
			{g1Counts{8, 4, 2, 2}, nil, g1Counts{8, 4, 2, 2}}, // 8 by epoch 8
		}},
		{name: "wraparound", first: 0xFFFFFFFE, steps: []step{
			{g1Counts{0, 4, 0, 0}, errSchedCounts, none},                 // three publications: 0xFFFFFFFE, 0xFFFFFFFF, 0
			{g1Counts{0, 3, 0, 0}, nil, g1Counts{0, 3, 0, 0}},            // the first two SCHEDs lost
			{g1Counts{0xFFFFFFFF, 1, 0, 0}, nil, g1Counts{0, 3, 0, 0}},   // older across the wrap: ignored
			{g1Counts{2, 6, 0, 0}, errSchedCounts, g1Counts{0, 3, 0, 0}}, // five publications by epoch 2
			{g1Counts{2, 4, 1, 0}, nil, g1Counts{2, 4, 1, 0}},
			{g1Counts{3, 3, 2, 0}, nil, g1Counts{3, 3, 2, 0}},
		}},
		{name: "wraparound stored", first: 0xFFFFFFFE, steps: []step{
			{g1Counts{0xFFFFFFFE, 0, 0, 0}, nil, g1Counts{0xFFFFFFFE, 0, 0, 0}},
			{g1Counts{1, 3, 0, 0}, nil, g1Counts{1, 3, 0, 0}}, // four publications by epoch 1
			{g1Counts{2, 6, 0, 0}, errSchedCounts, g1Counts{1, 3, 0, 0}},
		}},
		{name: "beyond 2^32 publications", first: 1, applied: 5, followed: g1Counts{0, w32 + 3, 1, 0}, steps: []step{
			// The dialer published 2³² + 5 SCHEDs by epoch 5 (the epoch
			// wrapped once) and the passive followed its 2³² + 4
			// migrations. The epoch alone allows 6 by epoch 6; the
			// followed migrations unwrap it to 2³² + 6.
			{g1Counts{6, w32 + 4, 1, 0}, nil, g1Counts{6, w32 + 4, 1, 0}},
			{g1Counts{7, w32 + 5, 1, 1}, nil, g1Counts{7, w32 + 5, 1, 1}},
			{g1Counts{8, w32 + 8, 1, 0}, errSchedCounts, g1Counts{7, w32 + 5, 1, 1}}, // 2³² + 9 by epoch 8
			{g1Counts{8, w32 + 7, 1, 0}, nil, g1Counts{8, w32 + 7, 1, 0}},
			{g1Counts{9, 5, 0, 0}, nil, g1Counts{9, 5, 0, 0}}, // lower counts
		}},
		{name: "followed near 2^64", first: 1, applied: 5, followed: g1Counts{0, math.MaxUint64 - 2, 0, 0}, steps: []step{
			// Only forged SCHEDs within the bound inflate the counters this
			// far; the bound would exceed 2⁶⁴ and binds nothing.
			{g1Counts{6, math.MaxUint64, 0, 0}, nil, g1Counts{6, math.MaxUint64, 0, 0}},
		}},
		{name: "followed beyond 2^64", first: 1, applied: 5, followed: g1Counts{0, math.MaxUint64, 5, 0}, steps: []step{
			{g1Counts{6, math.MaxUint64, 9, 0}, nil, g1Counts{6, math.MaxUint64, 9, 0}},
		}},
		{name: "bond", mode: ModeBond, first: 1, followed: g1Counts{0, 3, 0, 0}, steps: []step{
			// Bond sends zero; the passive's own bond deaths (3) are no
			// followed counts and do not widen the bound.
			{g1Counts{1, 0, 0, 0}, nil, g1Counts{1, 0, 0, 0}},
			{g1Counts{2, 0, 0, 0}, nil, g1Counts{2, 0, 0, 0}},
			{g1Counts{3, 4, 0, 0}, errSchedCounts, g1Counts{2, 0, 0, 0}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive, mode: tc.mode})
			defer stEnd(s, errClosed)
			l, _ := stAddLane(s, 7, false)
			s.mu.Lock()
			s.p.FirstEpoch = tc.first
			s.ctl.epoch = tc.first - 1 // as NewPending does
			if tc.applied != 0 {
				s.ctl.epoch = tc.applied
			}
			s.ctl.migDeath, s.ctl.migQuality, s.ctl.migExplicit = tc.followed.d, tc.followed.q, tc.followed.x
			s.mu.Unlock()
			g1Stored(s) // drop the facts of the setup
			prev := none
			for i, st := range tc.steps {
				err := g1Sched(l, wire.SchedDeath, st.k, 7)
				if st.want == nil && err != nil || st.want != nil && !errors.Is(err, st.want) {
					t.Fatalf("step %d: SCHED %v = %v, want %v", i, st.k, err, st.want)
				}
				var v violation
				if err != nil && !errors.As(err, &v) {
					t.Fatalf("step %d: SCHED %v = %v, which is not a carrier violation", i, st.k, err)
				}
				got, set, rang := g1Stored(s)
				if got != st.kept || set != (st.kept != none) {
					t.Fatalf("step %d: after SCHED %v the passive holds %v (set %v), want %v", i, st.k, got, set, st.kept)
				}
				if stored := st.kept != prev; rang != stored {
					t.Fatalf("step %d: SCHED %v rang the actor %v, want %v (only a stored SCHED does)", i, st.k, rang, stored)
				}
				prev = st.kept
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if have := (g1Counts{0, s.ctl.migDeath, s.ctl.migQuality, s.ctl.migExplicit}); have != tc.followed {
				t.Fatalf("the store changed the counters: %v, want %v", have, tc.followed)
			}
		})
	}
}

// g1FollowWithin applies set to the passive a's counters under s.mu on
// another goroutine (followCountsLocked) and reports whether that returned
// within d. A follow that is not O(1) never returns for counts near 2⁶⁴;
// its goroutine then keeps s.mu, so the caller must not end s.
func g1FollowWithin(s *Session, a *actor, set wire.Sched, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.ctl.set = set
		a.followCountsLocked(time.Now())
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestSchedFollowO1_L45 (§0.14 B1): the passive selector takes the counts
// of an applied SCHED in O(1). Each counter jumps to the dialer's count
// (never down), and the migrations taken are queued as Migration events
// from the carrier the previous SCHED named to the one this SCHED names:
// one per migration, at most maxFollowEvents (4) per applied SCHED, at
// least one for every cause that rose; the counters are the record. The
// last step claims counts near 2⁶⁴ in every cause (the follow itself is
// unbounded; the store is bypassed here): it returns at once, while a
// follow raising the counters one migration at a time — as before the
// bound, a jump of 2^20 then queued 2^20 events in one step — would never
// return.
func TestSchedFollowO1_L45(t *testing.T) {
	const big = 1 << 20
	const top = math.MaxUint64
	none, quality, explicit := carrier.CauseNone, carrier.CauseQuality, carrier.CauseRetired
	four := []carrier.Cause{none, none, none, none}
	steps := []struct {
		name   string
		sched  g1Counts        // the applied SCHED
		to     uint32          // the carrier it names
		have   g1Counts        // the counters afterwards (epoch unused)
		causes []carrier.Cause // its Migration events, in order
	}{
		{"no migration", g1Counts{1, 0, 0, 0}, 11, g1Counts{}, nil},
		{"one death", g1Counts{2, 1, 0, 0}, 12, g1Counts{0, 1, 0, 0}, []carrier.Cause{none}},
		{"two deaths, one SCHED lost", g1Counts{4, 3, 0, 0}, 13, g1Counts{0, 3, 0, 0}, []carrier.Cause{none, none}},
		{"one of each cause", g1Counts{7, 4, 1, 1}, 14, g1Counts{0, 4, 1, 1}, []carrier.Cause{none, quality, explicit}},
		{"four deaths", g1Counts{11, 8, 1, 1}, 15, g1Counts{0, 8, 1, 1}, four},
		{"five deaths", g1Counts{16, 13, 1, 1}, 16, g1Counts{0, 13, 1, 1}, four},
		{"three quality, two explicit", g1Counts{21, 13, 4, 3}, 17, g1Counts{0, 13, 4, 3}, []carrier.Cause{quality, quality, quality, explicit}},
		{"2^20 of every cause", g1Counts{21 + 3*big, 13 + big, 4 + big, 3 + big}, 18,
			g1Counts{0, 13 + big, 4 + big, 3 + big}, []carrier.Cause{none, none, quality, explicit}},
		{"2^20 deaths and explicit", g1Counts{21 + 5*big, 13 + 2*big, 4 + big, 3 + 2*big}, 19,
			g1Counts{0, 13 + 2*big, 4 + big, 3 + 2*big}, []carrier.Cause{none, none, none, explicit}},
		{"lower counts", g1Counts{22 + 5*big, 0, 0, 0}, 20, g1Counts{0, 13 + 2*big, 4 + big, 3 + 2*big}, nil},
		{"counts near 2^64", g1Counts{23 + 5*big, top - 2, top - 1, top}, 21,
			g1Counts{0, top - 2, top - 1, top}, []carrier.Cause{none, none, quality, explicit}},
	}
	s := stSession(stOpt{role: RolePassive})
	hung := false
	defer func() {
		if !hung {
			stEnd(s, errClosed)
		}
	}()
	s.env.Events = &acEvents{} // the actor queues events only with a sink
	a := newActor(s)
	a.named = 10 // the epoch-0 choice
	from := a.named
	for _, st := range steps {
		set := wire.Sched{Epoch: st.sched.epoch, Death: st.sched.d, Quality: st.sched.q, Explicit: st.sched.x, N: 1, IDs: [wire.MaxSchedIDs]uint32{st.to}}
		s.mu.Lock()
		a.events = a.events[:0]
		s.mu.Unlock()
		if !g1FollowWithin(s, a, set, 10*time.Second) {
			hung = true
			t.Fatalf("%s: following SCHED %v did not return within 10 s: not O(1)", st.name, st.sched)
		}
		s.mu.Lock()
		evs := append([]Event(nil), a.events...)
		have, named := g1Counts{0, s.ctl.migDeath, s.ctl.migQuality, s.ctl.migExplicit}, a.named
		s.mu.Unlock()
		if have != st.have || named != st.to {
			t.Fatalf("%s: counters %v, named %d; want %v, %d", st.name, have, named, st.have, st.to)
		}
		if len(evs) != len(st.causes) {
			t.Fatalf("%s: %d Migration events, want %d (at most %d per applied SCHED)", st.name, len(evs), len(st.causes), maxFollowEvents)
		}
		for i, ev := range evs {
			if ev.Kind != EventMigration || ev.From != from || ev.To != st.to || ev.Cause != st.causes[i] {
				t.Fatalf("%s: event %d = %+v, want a migration %d → %d with cause %v", st.name, i, ev, from, st.to, st.causes[i])
			}
		}
		from = st.to
	}
}

// TestSchedJumpApplied_L45 (§0.14 B1): a live passive selector session
// (real carriers, its actor running) receives SCHEDs as its carrier's
// reader delivers them. A valid jump of 2 — the SCHED of the first of two
// migrations was lost — counts 2 with two Migration events; a valid jump
// of 2^20 counts 2^20 with exactly 4 events; a SCHED whose death count is
// 2^62 is refused as a violation, nothing changes, and the session keeps
// delivering both ways.
func TestSchedJumpApplied_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const big = 1 << 20
		w := acNewWorld(t, nil)
		defer w.teardown()
		a, b := w.open(ModeSelector, nil, w.link("p1"))
		acWaitFor(t, time.Second, "the first SCHED applied", func() bool { return b.Status().SchedEpoch == 1 })
		b.mu.Lock()
		pl := b.lanes[0]
		b.mu.Unlock()
		migs := func() []Event { return w.b.ev.of(b.ID(), EventMigration) }
		apply := func(k g1Counts) {
			t.Helper()
			if err := g1Sched(pl, wire.SchedDeath, k, pl.id); err != nil {
				t.Fatalf("SCHED %v: %v", k, err)
			}
			acWaitFor(t, time.Second, fmt.Sprintf("SCHED %v applied", k), func() bool { return b.Status().SchedEpoch == k.epoch })
		}
		check := func(what string, death uint64, events int) {
			t.Helper()
			st, evs := b.Status(), migs()
			if st.MigDeath != death || st.MigQuality+st.MigExplicit != 0 || len(evs) != events {
				t.Fatalf("%s: passive migrations %d/%d/%d with %d events, want %d deaths and %d events",
					what, st.MigDeath, st.MigQuality, st.MigExplicit, len(evs), death, events)
			}
			for _, ev := range evs {
				if ev.From != pl.id || ev.To != pl.id || ev.Cause != carrier.CauseNone {
					t.Fatalf("%s: event %+v, want a death migration naming %d", what, ev, pl.id)
				}
			}
		}
		apply(g1Counts{3, 2, 0, 0}) // epoch 2 (death 1) was lost
		check("a valid jump of 2", 2, 2)
		apply(g1Counts{3 + big, 2 + big, 0, 0})
		check("a valid jump of 2^20", 2+big, 2+maxFollowEvents)
		forged := g1Counts{4 + big, 1 << 62, 0, 0}
		if err := g1Sched(pl, wire.SchedDeath, forged, pl.id); !errors.Is(err, errSchedCounts) {
			t.Fatalf("SCHED %v = %v, want %v", forged, err, errSchedCounts)
		}
		synctest.Wait() // the passive's actor would have run
		if e := b.Status().SchedEpoch; e != 3+big {
			t.Fatalf("applied epoch %d after the forged SCHED, want %d", e, 3+big)
		}
		check("after the forged SCHED", 2+big, 2+maxFollowEvents)
		if we, re := acTransfer(a, b, 256<<10, 91, false); we != nil || re != nil {
			t.Fatalf("dialer → passive: %v %v", we, re)
		}
		if we, re := acTransfer(b, a, 256<<10, 92, false); we != nil || re != nil {
			t.Fatalf("passive → dialer: %v %v", we, re)
		}
	})
}
