package session

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scheduling packet sessions (M2 design §A5.12; M2-D42, M2-D46, M2-D47,
// M2-D53; integration 1 D6) and the SCHED convergence of packet sessions
// (M2-D39; L45).

// TestPacketSchedResendSkipsRel_L45 (M2-D53): the dialer's single-flight
// SCHED resend (D6) skips a packet session's datagram lanes that already
// carried the current epoch — their REL sublayer delivers it while the
// carrier lives — and keeps stream lanes and datagram lanes that have not
// carried it as candidates. A datagram lane whose Fill placed the SCHED
// (REL-wrapped) leaves the candidates; with no candidate nothing is resent.
func TestPacketSchedResendSkipsRel_L45(t *testing.T) {
	s := dpSession(dpOpt{})
	la, _ := dpAddLane(s, 1, true, true) // datagram, carried the epoch
	lb, _ := dpAddLane(s, 2, false, false)
	lc, _ := dpAddLane(s, 3, false, true) // datagram, not carried yet
	a := &actor{s: s}
	s.mu.Lock()
	s.ctl.epoch = 5
	s.ctl.set = wire.Sched{Epoch: 5, N: 1}
	s.ctl.set.IDs[0] = la.id
	la.schedSent, lb.schedSent, lc.schedSent = 5, 5, 4
	s.mu.Unlock()
	picks := func(n int) []uint32 {
		s.mu.Lock()
		defer s.mu.Unlock()
		var out []uint32
		for range n {
			if l := a.resendLaneLocked(); l != nil {
				out = append(out, l.id)
			} else {
				out = append(out, 0)
			}
		}
		return out
	}
	got := picks(6)
	if slices.Contains(got, la.id) || !slices.Contains(got, lb.id) || !slices.Contains(got, lc.id) {
		t.Fatalf("resend lanes %v: want the stream lane 2 and the uncarried datagram lane 3, never lane 1 (its REL carries the epoch)", got)
	}

	// Lane 3's Fill places the SCHED, REL-wrapped on its datagram batch:
	// from then on its REL delivers the epoch and it leaves the candidates.
	b := dpFill(lc, time.Now())
	rel := false
	for i := range b.Len() {
		if f := b.Frame(i); f.Header.Type == wire.TypeSched && f.Rel {
			rel = true
		}
	}
	b.ReleaseRefs()
	if !rel {
		t.Fatal("stimulus: lane 3's Fill placed no REL-wrapped SCHED")
	}
	if got := picks(4); slices.ContainsFunc(got, func(id uint32) bool { return id != lb.id }) {
		t.Fatalf("resend lanes %v after lane 3 carried the epoch, want only the stream lane 2", got)
	}
	s.mu.Lock()
	lb.state = LaneDead
	s.mu.Unlock()
	if got := picks(2); got[0] != 0 || got[1] != 0 {
		t.Fatalf("resend lanes %v with only carrying datagram lanes left, want none", got)
	}
}

// TestPacketDuplicateSchedReEcho_L45 (M2-D39): a packet passive answers a
// SCHED it already applied — the dialer resends one only while the echo is
// missing — with an urgent PACK that carries the echo again, so the
// exchange converges even when the first echo was lost (L45). A stream
// session would ignore it.
func TestPacketDuplicateSchedReEcho_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wpNewWorld(t, nil)
		defer w.teardown()
		l := wpLink(w, "p1", 1400)
		a, b := wpOpen(w, wpSpec(w, ModeSelector, 1400, l), nil)
		acWaitFor(t, time.Second, "the first SCHED echoed", func() bool {
			st := a.Status()
			return st.SchedEpoch > 0 && st.SchedEchoed == st.SchedEpoch
		})
		time.Sleep(2 * time.Second) // idle: no PACK is due any more
		ep, id := a.Status().SchedEpoch, acActive(a)
		gen0 := wpLocked(b, func() uint64 { return b.st.ackGen })

		packs := l.CaptureNextFrame(rendrtest.Down, rendrtest.FramePack)
		sc := wire.Sched{Epoch: ep, N: 1}
		sc.IDs[0] = id
		p := make([]byte, wire.SchedFixedLen+4)
		p = p[:wire.PutSched(p, &sc)]
		l.InjectAfterNextFrame(rendrtest.Up, rendrtest.FramePing, rendrtest.FrameSched, uint8(wire.SchedInitial), wire.SessionHandle, p)
		select {
		case raw := <-packs:
			if l.Stats().Session.FramesInjected != 1 {
				t.Fatalf("stimulus: %d frames injected, want the one duplicate SCHED", l.Stats().Session.FramesInjected)
			}
			h, err := wire.ParseHeader(raw)
			if err != nil {
				t.Fatalf("captured PACK: %v", err)
			}
			pa, err := wire.ParsePack(raw[wire.HeaderLen : wire.HeaderLen+int(h.Len)])
			if err != nil || pa.EpochEcho != ep {
				t.Fatalf("re-echo PACK %+v (%v), want the echo of epoch %d", pa, err, ep)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no PACK answered the duplicate SCHED (injected %d)", l.Stats().Session.FramesInjected)
		}
		if gen := wpLocked(b, func() uint64 { return b.st.ackGen }); gen == gen0 {
			t.Fatal("the duplicate SCHED bumped no PACK")
		}
		if st := b.Status(); st.SchedEpoch != ep || st.MigDeath+st.MigQuality+st.MigExplicit != 0 {
			t.Fatalf("passive after the duplicate: epoch %d (want %d), migrations %d/%d/%d", st.SchedEpoch, ep, st.MigDeath, st.MigQuality, st.MigExplicit)
		}
	})
}

// wpPoll advances virtual time in 1-ms steps until cond holds and returns
// the instant it did (the test fails after within).
func wpPoll(t testing.TB, within time.Duration, what string, cond func() bool) time.Time {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		synctest.Wait()
		if cond() {
			return time.Now()
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPacketPlannedSwitchRetire (M2-D42): a packet session's quality switch
// moves new datagrams to the new carrier at once and requeues nothing; the
// old carrier stays open until the passive echoed the SCHED that removed it
// — datagrams the passive sent on it before the SCHED still arrive — and
// retires 2·srtt later, well before RetireGrace; every datagram sent across
// the switch arrives exactly once.
func TestPacketPlannedSwitchRetire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wpNewWorld(t, nil)
		defer w.teardown()
		h := acNewHealth(2, w.a.p.Selector.Fresh)
		h.set(30*time.Millisecond, 0)
		l1, l2 := wpLink(w, "p1", 1400), wpLink(w, "p2", 1400)
		l2.SetDelay(100*time.Millisecond, 0) // the echo of the switch returns over p2: ≈ 100 ms
		a, b := wpOpen(w, wpSpec(w, ModeSelector, 1400, l1, l2), h)
		first := acActive(a)
		if first == 0 || a.Status().Carriers[0].Name != "p1" {
			t.Fatalf("opened on %+v, want p1", a.Status().Carriers)
		}
		up := wpStartFlow(a, b, 200, 5*time.Millisecond)
		down := wpStartFlow(b, a, 200, 5*time.Millisecond)
		defer acFreshen(h)()
		h.set(30*time.Millisecond, 10*time.Millisecond)
		old := wpLaneByID(a, first)
		tSwitch := wpPoll(t, 5*time.Second, "the quality switch", func() bool { return a.Status().MigQuality == 1 })
		removed, retiring, called := func() (uint32, bool, bool) {
			a.mu.Lock()
			defer a.mu.Unlock()
			return old.retireEpoch, old.state == LaneRetiring, old.retireCalled
		}()
		if !retiring || called || removed == 0 {
			t.Fatalf("old lane at the switch: retiring %v, retired %v, epoch %d; want retiring, not retired, the switch's epoch", retiring, called, removed)
		}
		tEcho := wpPoll(t, time.Second, "the passive echoed the switch", func() bool {
			return wpLocked(a, func() bool { return !sched.EpochNewer(removed, a.ctl.echoed) })
		})
		tRet := wpPoll(t, time.Second, "the old lane retired", func() bool {
			return wpLocked(a, func() bool { return old.retireCalled })
		})
		srtt := wpLocked(a, func() time.Duration { return old.port.SRTT() })
		t.Logf("switch → echo %v, echo → retire %v (srtt %v)", tEcho.Sub(tSwitch), tRet.Sub(tEcho), srtt)
		if tEcho.Sub(tSwitch) < 90*time.Millisecond {
			t.Fatalf("stimulus: the echo came %v after the switch, want it delayed by p2's 100 ms", tEcho.Sub(tSwitch))
		}
		if tRet.Before(tEcho) || tRet.Sub(tEcho) > 2*srtt+5*time.Millisecond {
			t.Fatalf("retired %v after the echo, want within 2·srtt (%v) after it", tRet.Sub(tEcho), 2*srtt)
		}
		if tRet.Sub(tSwitch) >= w.a.p.RetireGrace {
			t.Fatalf("retired %v after the switch, want before RetireGrace %v", tRet.Sub(tSwitch), w.a.p.RetireGrace)
		}
		up.stop()
		down.stop()
		acWaitFor(t, 2*time.Second, "every datagram arrived", func() bool {
			return up.got.Load() == up.sent.Load() && down.got.Load() == down.sent.Load()
		})
		if up.duplicates()+down.duplicates() != 0 {
			t.Fatalf("duplicates: up %d down %d", up.duplicates(), down.duplicates())
		}
		if up.sent.Load() < 100 || l2.Stats().Session.Bytes == 0 || l1.Stats().Session.Bytes == 0 {
			t.Fatalf("load: %d datagrams up; p1 %d, p2 %d session bytes", up.sent.Load(), l1.Stats().Session.Bytes, l2.Stats().Session.Bytes)
		}
		as := a.Status()
		for _, c := range as.Carriers {
			if c.ID == first && (c.State != LaneDead || c.DeathCause != carrier.CauseRetired) {
				t.Fatalf("old carrier %+v, want retired", c)
			}
		}
		if as.Packet.DropAge+as.Packet.DropNoPath+as.Packet.DropQueue != 0 {
			t.Fatalf("dialer drops across a planned switch: %+v", *as.Packet)
		}
	})
}

// TestPacketRankClass (M2-D46, M2-D47): a packet session ranks its datagram
// factories before its stream factories — failed factories last, then by
// class, then by M1's evidence order — and a session never ranks a factory
// outside DialSpec.Eligible. A stream session's factories are all class 0.
func TestPacketRankClass(t *testing.T) {
	fs := []carrier.Factory{
		{Name: "s0"}, {Name: "d1", Kind: wire.KindDatagram, MTU: 1400},
		{Name: "s2"}, {Name: "d3", Kind: wire.KindDatagram, MTU: 1400},
	}
	rank := func(kind wire.CarrierKind, eligible uint16, h *acHealth, failed int) []int {
		spec := DialSpec{Factories: fs, Eligible: eligible, Params: Params{Kind: kind}}
		var hs healthSource
		if h != nil {
			hs = h
		}
		a := &actor{s: &Session{p: spec.Params}, d: newDialer(spec, hs)}
		if failed >= 0 {
			a.d.failed[failed], a.d.failedVer[failed] = true, markPending // a local mark the snapshots do not show yet
		}
		return slices.Clone(a.rankLocked(time.Now()))
	}
	for _, tc := range []struct {
		name     string
		kind     wire.CarrierKind
		eligible uint16
		rtt      []time.Duration // nil: inert health
		failed   int
		want     []int
	}{
		{"packet, no evidence", wire.KindDatagram, 0, nil, -1, []int{1, 3, 0, 2}},
		{"packet, faster stream factories", wire.KindDatagram, 0, []time.Duration{time.Millisecond, 50 * time.Millisecond, 2 * time.Millisecond, 30 * time.Millisecond}, -1, []int{3, 1, 0, 2}},
		{"packet, a failed datagram factory", wire.KindDatagram, 0, []time.Duration{time.Millisecond, 50 * time.Millisecond, 2 * time.Millisecond, 30 * time.Millisecond}, 3, []int{1, 0, 2, 3}},
		{"stream session, stream factories only", wire.KindStream, 0b0101, []time.Duration{time.Millisecond, 50 * time.Millisecond, 2 * time.Millisecond, 30 * time.Millisecond}, -1, []int{0, 2}},
		{"stream session, the datagram factories fastest", wire.KindStream, 0b0101, []time.Duration{90 * time.Millisecond, time.Millisecond, 50 * time.Millisecond, time.Millisecond}, -1, []int{2, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h *acHealth
			if tc.rtt != nil {
				h = acNewHealth(len(fs), time.Minute)
				h.set(tc.rtt...)
			}
			if got := rank(tc.kind, tc.eligible, h, tc.failed); !slices.Equal(got, tc.want) {
				t.Fatalf("rank %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("OPEN-capable datagram factories (M2-D52)", func(t *testing.T) {
		d := &carrier.Factory{Kind: wire.KindDatagram, MTU: 1400}
		if !openFits(d, 1400-openOverhead) || openFits(d, 1400-openOverhead+1) || !openFits(&fs[0], 4096) {
			t.Fatalf("openFits: the 99-byte OPEN overhead (%d) plus metadata must fit the MTU; stream factories always fit", openOverhead)
		}
		if openOverhead != 99 {
			t.Fatalf("openOverhead %d, want 99 (M2-D52)", openOverhead)
		}
	})
}

// TestStreamSessionIgnoresDatagramFactories (integration 1 D6; M2-D46): a
// stream session on a Peer with a datagram factory 100× faster than its
// stream factory never dials it — not in the opening race, not as a bond
// member, not as the selector's quality target (it is failed for Evaluate)
// and not in the death failover race.
func TestStreamSessionIgnoresDatagramFactories(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeBond} {
		t.Run(map[Mode]string{ModeSelector: "selector", ModeBond: "bond"}[mode], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var dgDials, starts atomic.Int64
				hooks := &testhooks.Hooks{DialStart: func(i int) {
					if i == 1 {
						starts.Add(1)
					}
				}}
				w := acNewWorld(t, hooks)
				defer w.teardown()
				l1 := w.link("p1")
				fs := acFactories(l1)
				fs = append(fs, carrier.Factory{Index: 1, Name: "dg", Kind: wire.KindDatagram, MTU: 1400,
					Dial: func(context.Context) (net.Conn, error) {
						dgDials.Add(1)
						return nil, errors.New("the datagram factory was dialed")
					},
					DialPacket: func(context.Context) (net.PacketConn, net.Addr, error) {
						dgDials.Add(1)
						return nil, nil, errors.New("the datagram factory was dialed")
					},
				})
				w.sid++
				p := w.a.p
				p.Mode = mode
				spec := DialSpec{SID: [16]byte{0xD6, w.sid}, Params: p, Factories: fs, Eligible: 1 << 0}
				h := acNewHealth(2, w.a.p.Selector.Fresh)
				h.set(100*time.Millisecond, time.Millisecond) // the datagram factory 100× faster
				a, b := wpOpen(w, spec, h)
				defer acFreshen(h)()
				time.Sleep(w.a.p.Selector.Dwell + w.a.p.Selector.Cooldown + 2*time.Second)
				if l1.Kill() == 0 {
					t.Fatal("the kill hit no carrier")
				}
				acWaitFor(t, 3*time.Second, "recovered on the stream factory", func() bool {
					st := a.Status()
					return st.NoPathEpisodes == 1 && !st.InNoPath
				})
				time.Sleep(2 * time.Second)
				if n, k := dgDials.Load(), starts.Load(); n != 0 || k != 0 {
					t.Fatalf("the datagram factory was dialed %d times (%d attempts started)", n, k)
				}
				if st := a.Status(); st.MigQuality != 0 {
					t.Fatalf("%d quality migrations: a factory outside Eligible became a target", st.MigQuality)
				}
				if l1.Stats().Dials < 2 {
					t.Fatalf("stimulus: %d dials of the stream factory, want the open and the redial", l1.Stats().Dials)
				}
				if we, re := acTransfer(a, b, 1<<20, 61, false); we != nil || re != nil {
					t.Fatalf("transfer: %v %v", we, re)
				}
			})
		})
	}
}

// TestPacketSelectorClasses (M2-D48): Dial hands the selector the kind
// classes rankLocked uses (SetClasses), so a packet session that fell back
// to a stream carrier returns to a measured, fresh datagram carrier after
// Dwell even when it is slower (class-up needs no Band or Floor); a stream
// session's selector never takes a slower challenger.
func TestPacketSelectorClasses(t *testing.T) {
	fs := []carrier.Factory{{Name: "s0"}, {Name: "d1", Kind: wire.KindDatagram, MTU: 1400}}
	for _, tc := range []struct {
		name     string
		kind     wire.CarrierKind
		switches bool
	}{
		{"packet session", wire.KindDatagram, true},
		{"stream session", wire.KindStream, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := acParams(ModeSelector)
			p.Kind = tc.kind
			d := newDialer(DialSpec{Factories: fs, Params: p}, nil)
			t0 := time.Now()
			switched := false
			for at := t0; at.Before(t0.Add(3 * p.Selector.Dwell)); at = at.Add(100 * time.Millisecond) {
				sum := []sched.Summary{
					{Seen: true, Mean: 10 * time.Millisecond, N: 32, At: at},
					{Seen: true, Mean: 12 * time.Millisecond, N: 32, At: at}, // slower: no Band, no Floor
				}
				if v := d.sel.Evaluate(at, 0, sum, []bool{false, false}); v.Switch {
					if v.To != 1 || at.Sub(t0) < p.Selector.Dwell {
						t.Fatalf("switch to %d after %v, want factory 1 after Dwell %v", v.To, at.Sub(t0), p.Selector.Dwell)
					}
					switched = true
					break
				}
			}
			if switched != tc.switches {
				t.Fatalf("switched %v, want %v", switched, tc.switches)
			}
		})
	}
}
