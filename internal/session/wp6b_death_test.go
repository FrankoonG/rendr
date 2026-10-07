package session

import (
	"context"
	"errors"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The actor-side packet rules around a carrier's death and attach (M2
// design §A5.1, §A5.5, §A5.6; M2-D39, M2-D52; integration 1 D6): what
// laneGoneLocked re-places on a survivor, which factories the opening race
// and Dial consider, and the reliable first echo of a new passive lane.

// wpGone is the actor's death step for l up to laneGoneLocked, without the
// SCHED or re-attach that follows it in a live session (they would mask
// what laneGoneLocked itself does).
func wpGone(s *Session, l *lane) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.state = LaneDead
	l.data = false
	if s.ctl.active == l {
		s.ctl.active = nil
	}
	s.laneGoneLocked(l)
}

// TestPacketLaneGoneBump (§A5.5 convergence, M2-D39): when a passive's
// PACK duty lane dies with FIN_DELIVERED pending, laneGoneLocked bumps the
// acknowledgement, so a survivor is woken and places the PACK with the flag
// — no SCHED and no new carrier needed.
func TestPacketLaneGoneBump(t *testing.T) {
	s := dpSession(dpOpt{role: RolePassive, mode: ModeBond})
	l1, p1 := dpAddLane(s, 1, true, true)
	l2, p2 := dpAddLane(s, 2, true, true)
	s.mu.Lock()
	s.st.ackFlags |= wire.FlagAckFinDelivered
	s.bumpNowLocked()
	duty := s.st.ackLane
	s.mu.Unlock()
	if duty == nil {
		t.Fatal("stimulus: no PACK duty lane")
	}
	dpIdle(l1)
	dpIdle(l2)
	survivor, sp := l2, p2
	if duty == l2 {
		survivor, sp = l1, p1
	}
	gen := wpLocked(s, func() uint64 { return s.st.ackGen })
	wakes := sp.wakeCount()
	wpGone(s, duty)
	if got := wpLocked(s, func() uint64 { return s.st.ackGen }); got == gen {
		t.Fatal("the death of the PACK duty lane did not bump the acknowledgement")
	}
	if sp.wakeCount() == wakes {
		t.Fatal("the idle survivor was not woken")
	}
	b := dpFill(survivor, time.Now())
	fs := dpFrames(b)
	b.ReleaseRefs()
	if !slices.ContainsFunc(fs, func(f dpFrame) bool {
		return f.typ == wire.TypePack && f.flags&wire.FlagPackFinDelivered != 0
	}) {
		t.Fatalf("the survivor placed %v, want a PACK with FIN_DELIVERED", fs)
	}
}

// TestPacketLaneGoneFinViaSurvivor (§A5.6, L40): a dialer whose FIN went
// out on a lane that dies places it again, with the same final seq, on a
// survivor that laneGoneLocked woke.
func TestPacketLaneGoneFinViaSurvivor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{mode: ModeBond})
		var ls []*lane
		var ps []*dpPort
		for i := range 3 {
			l, p := dpAddLane(s, uint32(i+1), true, true)
			ls, ps = append(ls, l), append(ps, p)
		}
		for i := range uint64(2) {
			dpWrite(t, s, i, 100)
		}
		dpClose(s)
		var final uint64
		var finLane *lane
		for _, l := range ls {
			b := dpFill(l, time.Now())
			for _, f := range dpFrames(b) {
				if f.typ == wire.TypeFin {
					final, finLane = f.fin, l
				}
			}
			b.ReleaseRefs()
			if finLane != nil {
				break
			}
		}
		if finLane == nil {
			t.Fatal("stimulus: no lane placed the FIN")
		}
		for _, l := range ls {
			dpIdle(l)
		}
		wakes := make([]int, len(ps))
		for i, p := range ps {
			wakes[i] = p.wakeCount()
		}
		wpGone(s, finLane)
		fins, woken := 0, 0
		for i, l := range ls {
			if l == finLane {
				continue
			}
			if ps[i].wakeCount() == wakes[i] {
				continue // an idle writer that is not woken never fills
			}
			woken++
			b := dpFill(l, time.Now())
			for _, f := range dpFrames(b) {
				if f.typ == wire.TypeFin {
					fins++
					if f.fin != final {
						t.Fatalf("FIN(%d) on the survivor, want the same final seq %d", f.fin, final)
					}
				}
			}
			b.ReleaseRefs()
		}
		if fins != 1 {
			t.Fatalf("%d FINs placed by the %d woken survivors, want 1", fins, woken)
		}
	})
}

// TestPacketLaneGoneRoute (§A5.2, §A5.4): laneGoneLocked recomputes the
// routing summary at once: when the last stream data lane of a mixed bond
// dies, the datagrams only a stream lane could carry (txBig, above every
// datagram lane's DgramMax) are dropped as DropTooLarge instead of waiting
// for a lane that no longer exists.
func TestPacketLaneGoneRoute(t *testing.T) {
	s := dpSession(dpOpt{mode: ModeBond, maxPayload: 4000})
	ls, _ := dpAddLane(s, 1, true, false) // stream
	dpAddLane(s, 2, true, true)           // datagram, DgramMax below 2000
	dpWrite(t, s, 1, 2000)
	if n := wpLocked(s, func() int { return s.pk.txBig.n }); n != 1 {
		t.Fatalf("stimulus: %d datagrams queued for stream lanes, want 1", n)
	}
	wpGone(s, ls)
	if c := dpCtr(s); c.DropTooLarge != 1 || wpLocked(s, func() int { return s.pk.txBig.n }) != 0 {
		t.Fatalf("after the stream lane's death: %+v; want the stream-only datagram dropped as too large", c)
	}
}

// TestPacketOpenRaceFilter (M2-D52): the opening race of a packet session
// skips a datagram factory whose MTU cannot carry the OPEN (99 bytes plus
// the metadata); once the session is open, a race (JOIN) includes it.
func TestPacketOpenRaceFilter(t *testing.T) {
	meta := make([]byte, 30) // 129 bytes of OPEN
	fs := []carrier.Factory{
		{Name: "d0", Kind: wire.KindDatagram, MTU: openOverhead + len(meta) - 1},
		{Name: "s1"},
		{Name: "d2", Kind: wire.KindDatagram, MTU: openOverhead + len(meta)},
	}
	order := func(kind wire.CarrierKind, opened bool) []int {
		spec := DialSpec{Factories: fs, Params: Params{Kind: kind}}
		s := &Session{p: spec.Params, meta: meta}
		if kind == wire.KindDatagram {
			s.pk = &packet{}
		}
		a := &actor{s: s, d: newDialer(spec, nil)}
		a.d.opened = opened
		a.startRaceLocked(time.Now())
		var got []int
		a.d.race.Next(time.Now(), 0, func(i int) (bool, time.Time) {
			got = append(got, i)
			return false, time.Time{}
		})
		slices.Sort(got)
		return got
	}
	for _, tc := range []struct {
		name   string
		kind   wire.CarrierKind
		opened bool
		want   []int
	}{
		{"packet session, opening", wire.KindDatagram, false, []int{1, 2}},
		{"packet session, open (JOIN)", wire.KindDatagram, true, []int{0, 1, 2}},
		{"stream session, opening", wire.KindStream, false, []int{0, 1, 2}},
	} {
		if got := order(tc.kind, tc.opened); !slices.Equal(got, tc.want) {
			t.Fatalf("%s: race over %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestDialNoEligibleFactory (integration 1 D6): a Dial whose Eligible
// covers none of its factories fails with ErrNoPath at once, without a
// factory call and without waiting for Grace.
func TestDialNoEligibleFactory(t *testing.T) {
	for _, kind := range []wire.CarrierKind{wire.KindStream, wire.KindDatagram} {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			l := wpLink(w, "p1", 1400)
			spec := w.spec(ModeSelector, l)
			if kind == wire.KindDatagram {
				spec = wpSpec(w, ModeSelector, 1400, l)
			}
			spec.Eligible = 1 << 1 // no factory 1
			t0 := time.Now()
			s, err := w.dial(context.Background(), spec, nil)
			if s != nil || !errors.Is(err, ErrNoPath) {
				t.Fatalf("%v: Dial = %v, %v; want ErrNoPath", kind, s, err)
			}
			if d := time.Since(t0); d != 0 {
				t.Fatalf("%v: Dial failed after %v, want at once", kind, d)
			}
			if n := l.Stats().Dials; n != 0 {
				t.Fatalf("%v: %d factory calls, want 0", kind, n)
			}
		})
	}
}

// TestPacketEchoRelAtAttach (M2-D39): a passive lane starts with echoRel
// different from the applied epoch, so the first epoch echo it places is
// reliable — also when the applied epoch is 0 (FirstEpoch 1 before the
// first SCHED, or a wrapped serial).
func TestPacketEchoRelAtAttach(t *testing.T) {
	for _, epoch := range []uint32{0, 1, 7, ^uint32(0)} {
		s := dpSession(dpOpt{role: RolePassive})
		a := &actor{s: s}
		s.mu.Lock()
		s.ctl.epoch = epoch
		l := a.newLaneLocked(time.Now(), &carrier.Conn{}, -1, 1, LaneJoining)
		s.mu.Unlock()
		if l.echoRel == epoch {
			t.Fatalf("epoch %d: a new lane's echoRel equals the applied epoch: its first echo would leave bare", epoch)
		}
	}
}
