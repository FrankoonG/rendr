package session

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// RACEACK (M3 design §A6.5 as amended; M3-D33, PA-33): a race session's
// ACK (stream) and PACK (packet) duty is the fastest live lane's, and every
// other live data lane carries a copy of each ACK or PACK, so a member
// blackholed without an error — neither write-blocked nor dead until its
// death verdict, its SRTT frozen at the fastest — never takes the ACK path
// with it (gold G4-race; TestG4RaceMiniature in internal/scenario/race).

// rcAckSides names a race sender and receiver of a stream pair with their
// lanes (lane i of one side is the peer of lane i of the other).
type rcAckSides struct {
	name     string
	snd, rcv *Session
	sl, rl   []*lane
	rp       []*stPort
}

// rcAckRows returns both directions of p: the passive receives (its ACKs
// go to the dialer) and the dialer receives.
func rcAckRows(p *stPair) []rcAckSides {
	return []rcAckSides{
		{"passive receives", p.a, p.b, p.al, p.bl, p.bp},
		{"dialer receives", p.b, p.a, p.bl, p.al, p.ap},
	}
}

// rcMove runs one Fill of from and delivers it to to unless drop; with
// keep the batch is returned undelivered (a copy in the hole that arrives
// late) and the caller releases it.
func rcMove(t *testing.T, from, to *lane, drop, keep bool) *carrier.Batch {
	t.Helper()
	_, b := stFill(from, time.Now())
	if keep {
		return b
	}
	if !drop {
		if err := stDeliver(b, to); err != nil {
			t.Fatalf("delivery on lane %d: %v", to.id, err)
		}
	}
	b.ReleaseRefs()
	return nil
}

// TestRaceAckSurvivesSilentFastest: the receiver's fastest member (5 ms,
// the ACK duty lane) goes silent towards the sender — every frame it
// places vanishes, it is neither write-blocked nor dead and its SRTT stays
// the lowest. The sender's acknowledged front keeps tracking the bytes the
// receiver read, round by round, through the slow member's ACK copies (a
// duty on the fastest lane alone froze it at the silence: the window then
// runs out before the death verdict). When the silent copies arrive late,
// after the newer ones, nothing regresses: the front, the peer's right
// edge and the unique counters stay, and no carrier is killed (L13 merge by
// max). Both roles receive.
func TestRaceAckSurvivesSilentFastest(t *testing.T) {
	p := rcPair(2, stOpt{ackEvery: 16 << 10}, stOpt{ackEvery: 16 << 10})
	for _, r := range rcAckRows(p) {
		r.rp[0].set(func(f *stPort) { f.srtt = 80 * time.Millisecond })
		r.rp[1].set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
	}
	p.pump(true)
	off := map[*Session]uint64{}
	for _, r := range rcAckRows(p) {
		r.rcv.mu.Lock()
		r.rcv.ackBumpForTest() // an ACK decision: the duty moves to the fastest
		r.rcv.mu.Unlock()
		rcMove(t, r.rl[0], r.sl[0], false, false)
		rcMove(t, r.rl[1], r.sl[1], false, false)
		if l := stLocked(r.rcv, func(st *stream) *lane { return st.ackLane }); l != r.rl[1] {
			t.Fatalf("%s: premise: the duty is on lane %d, want the 5-ms lane", r.name, l.id)
		}
		var late []*carrier.Batch
		for round := range 8 {
			rcWrite(t, r.snd, stPattern(off[r.snd], 32<<10))
			off[r.snd] += 32 << 10
			for i := range 2 {
				rcMove(t, r.sl[i], r.rl[i], false, false)
			}
			stReadN(t, r.rcv, 32<<10)
			// The fast member is silent towards the sender: its frames are
			// held (they arrive late, below) and the slow member's arrive.
			late = append(late, rcMove(t, r.rl[1], r.sl[1], false, true))
			rcMove(t, r.rl[0], r.sl[0], false, false)
			if base := rcStream(r.snd)[0]; base != off[r.snd] {
				t.Fatalf("%s round %d: the sender's acknowledged front %d, want %d (the bytes read): the ACK path died with the silent member",
					r.name, round, base, off[r.snd])
			}
		}
		before := r.snd.Status()
		edge := stLocked(r.snd, func(st *stream) uint64 { return st.peerLimit })
		for _, b := range late {
			if err := stDeliver(b, r.sl[1]); err != nil {
				t.Fatalf("%s: a late ACK copy killed its carrier: %v", r.name, err)
			}
			b.ReleaseRefs()
		}
		after := r.snd.Status()
		if after.AckedBytes != before.AckedBytes || after.AckedBytes != off[r.snd] || after.TxBytes != before.TxBytes || after.Race != before.Race {
			t.Fatalf("%s: the late copies moved the counters: %+v → %+v", r.name, before, after)
		}
		if e := stLocked(r.snd, func(st *stream) uint64 { return st.peerLimit }); e != edge {
			t.Fatalf("%s: the late copies moved the peer's right edge %d → %d", r.name, edge, e)
		}
	}
	for i, e := range p.errs {
		t.Fatalf("violation %d: %v", i, e)
	}
	p.close(t)
}

// TestRacePackSurvivesSilentFastest is the packet form: the receiver's
// fastest member is silent towards the sender; the sender's count of the
// datagrams the peer received keeps up through the slow member's PACK
// copies; the late copies, lower than what the sender holds, merge by max
// (no violation, nothing regresses). Both roles receive.
func TestRacePackSurvivesSilentFastest(t *testing.T) {
	p := dpNewPair(dpOpt{mode: ModeRace, packEvery: 4}, dpOpt{mode: ModeRace, packEvery: 4}, true, true)
	rcPktRace(p.a.s)
	rcPktRace(p.b.s)
	for _, sd := range []*dpSide{&p.a, &p.b} {
		sd.ps[0].set(func(f *dpPort) { f.srtt = 80 * time.Millisecond })
		sd.ps[1].set(func(f *dpPort) { f.srtt = 5 * time.Millisecond })
	}
	dpSettle(t, p, nil)
	for _, sd := range []*dpSide{&p.a, &p.b} {
		sd.s.mu.Lock()
		sd.s.ackBumpForTest() // a PACK decision: the duty moves to the fastest
		sd.s.mu.Unlock()
	}
	dpSettle(t, p, nil)
	for _, row := range []struct {
		name     string
		snd, rcv *dpSide
	}{{"passive receives", &p.a, &p.b}, {"dialer receives", &p.b, &p.a}} {
		if l := dpLocked(row.rcv.s, func(st *stream, _ *packet) *lane { return st.ackLane }); l != row.rcv.ls[1] {
			t.Fatalf("%s: premise: the PACK duty is on lane %d, want the 5-ms lane", row.name, l.id)
		}
		var sent uint64
		var late []*carrier.Batch
		for round := range 6 {
			for range 8 {
				sent++
				dpWrite(t, row.snd.s, sent, 100)
			}
			if _, err := dpPump(row.snd, row.rcv, nil); err != nil {
				t.Fatal(err)
			}
			if got, err := dpReadAll(t, row.rcv.s); err != nil || len(got) != 8 {
				t.Fatalf("%s round %d: read %d datagrams, %v", row.name, round, len(got), err)
			}
			late = append(late, dpFill(row.rcv.ls[1], time.Now())) // silent: arrives late
			b := dpFill(row.rcv.ls[0], time.Now())
			if err := dpDeliver(b, row.snd.ls[0], 0, nil); err != nil {
				t.Fatal(err)
			}
			b.ReleaseRefs()
			if c := dpCtr(row.snd.s); c.PeerReceived != sent {
				t.Fatalf("%s round %d: the sender's PeerReceived %d, want %d: the PACK path died with the silent member",
					row.name, round, c.PeerReceived, sent)
			}
		}
		for _, b := range late {
			if err := dpDeliver(b, row.snd.ls[1], 1, nil); err != nil {
				t.Fatalf("%s: a late PACK copy killed its carrier: %v", row.name, err)
			}
			b.ReleaseRefs()
		}
		if c := dpCtr(row.snd.s); c.PeerReceived != sent {
			t.Fatalf("%s: the late copies moved PeerReceived to %d, want %d", row.name, c.PeerReceived, sent)
		}
	}
	dpEnd(p.a.s, errClosed)
	dpEnd(p.b.s, errClosed)
}

// TestRaceAckDelayEveryMember: the delivery cadence's delayed ACK (stream)
// and PACK (packet) reach every member: arming the delay wakes each idle
// member (each arms its own writer timer, b.WakeAt), none places early,
// and once the delay passed the member that fires first bumps the ACK and
// every other member places it too — the duty lane's timer is not the only
// path. A member that is not a data lane carries no copy.
func TestRaceAckDelayEveryMember(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive, mode: ModeRace, window: 1 << 20, ackDelay: 20 * time.Millisecond})
			fast, fp := stAddLane(s, 1, true)
			slow, sp := stAddLane(s, 2, true)
			idle, ip := stAddLane(s, 3, false)
			rcRaceLanes(s)
			s.mu.Lock()
			idle.data = false // a lane that carries no data: no ACK copy
			s.mu.Unlock()
			fp.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
			sp.set(func(f *stPort) { f.srtt = 80 * time.Millisecond })
			ip.set(func(f *stPort) { f.srtt = 200 * time.Millisecond }) // the duty is the fastest lane's
			// The first DATA after an attach bumps at once: deliver it first.
			if err := stDeliverData(fast, 0, stPattern(0, 1000)); err != nil {
				t.Fatal(err)
			}
			stReadN(t, s, 1000)
			time.Sleep(20 * time.Millisecond) // and its delayed ACK
			for _, l := range []*lane{fast, slow, idle} {
				for {
					fs, b := stFill(l, time.Now())
					b.ReleaseRefs()
					if len(fs) == 0 {
						break
					}
				}
			}
			s.mu.Lock()
			fast.idle, slow.idle, idle.idle = true, true, true
			s.mu.Unlock()
			w := [3]int{stWakes(fp), stWakes(sp), stWakes(ip)}
			if err := stDeliverData(fast, 1000, stPattern(1000, 1000)); err != nil {
				t.Fatal(err)
			}
			stReadN(t, s, 1000)
			if stWakes(fp) != w[0]+1 || stWakes(sp) != w[1]+1 || stWakes(ip) != w[2] {
				t.Fatalf("arming the delay woke %d, %d, %d times; want the two members once each, the non-data lane never",
					stWakes(fp)-w[0], stWakes(sp)-w[1], stWakes(ip)-w[2])
			}
			at := stLocked(s, func(st *stream) time.Time { return st.ackDelayAt })
			for _, l := range []*lane{fast, slow} {
				fs, b := stFill(l, time.Now())
				if stCount(fs, wire.TypeAck) != 0 || !b.WakeTime().Equal(at) {
					t.Fatalf("lane %d before the delay: %v, wake at %v; want nothing and its timer at %v", l.id, fs, b.WakeTime(), at)
				}
				b.ReleaseRefs()
			}
			time.Sleep(20 * time.Millisecond)
			wf := stWakes(fp)
			for _, l := range []*lane{slow, fast} { // the slow member's timer fires first
				fs, b := stFill(l, time.Now())
				b.ReleaseRefs()
				if n := stCount(fs, wire.TypeAck); n != 1 || fs[len(fs)-1].ack.Delivered != 2000 {
					t.Fatalf("lane %d after the delay: %v; want one ACK of 2000 bytes", l.id, fs)
				}
				if l == slow && stWakes(fp) != wf+1 {
					t.Fatal("the slow member's delayed ACK did not wake the idle fast member")
				}
			}
			if fs, b := stFill(idle, time.Now()); stCount(fs, wire.TypeAck) != 0 {
				t.Fatalf("the non-data lane placed %v", fs)
			} else {
				b.ReleaseRefs()
			}
			stEnd(s, errClosed)
		})
	})
	t.Run("packet", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const pp = time.Second
			s := dpSession(dpOpt{role: RolePassive, mode: ModeRace, packetPing: pp, packEvery: 256})
			fast, fp := dpAddLane(s, 1, true, true)
			slow, sp := dpAddLane(s, 2, true, true)
			rcPktRace(s)
			fp.set(func(f *dpPort) { f.srtt = 5 * time.Millisecond })
			sp.set(func(f *dpPort) { f.srtt = 80 * time.Millisecond })
			dpIdle(fast)
			dpIdle(slow)
			w := [2]int{fp.wakeCount(), sp.wakeCount()}
			if err := dpDatagram(fast, 0, []byte("a")); err != nil {
				t.Fatal(err)
			}
			if fp.wakeCount() != w[0]+1 || sp.wakeCount() != w[1]+1 {
				t.Fatalf("arming the PACK delay woke %d and %d times; want each member once", fp.wakeCount()-w[0], sp.wakeCount()-w[1])
			}
			for _, l := range []*lane{fast, slow} {
				b := dpFill(l, time.Now())
				if dpCount(dpFrames(b), wire.TypePack) != 0 || b.WakeTime().IsZero() {
					t.Fatalf("lane %d before the delay: %v, wake %v", l.id, dpFrames(b), b.WakeTime())
				}
				b.ReleaseRefs()
			}
			time.Sleep(pp)
			wf := fp.wakeCount()
			for _, l := range []*lane{slow, fast} { // the slow member's timer fires first
				b := dpFill(l, time.Now())
				fs := dpFrames(b)
				b.ReleaseRefs()
				if dpCount(fs, wire.TypePack) != 1 || fs[len(fs)-1].pack.Received != 1 {
					t.Fatalf("lane %d after the delay: %v; want one PACK reporting 1", l.id, fs)
				}
				if l == slow && fp.wakeCount() != wf+1 {
					t.Fatal("the slow member's delayed PACK did not wake the idle fast member")
				}
			}
			dpReadAll(t, s)
			dpEnd(s, errClosed)
		})
	})
}

// TestRaceAckCopyQualifies: an ACK copy rides only a lane that could keep
// the duty — live, not leaving, not write-blocked — and a data lane: an
// urgent bump wakes the fast duty lane and the idle slow member, never a
// write-blocked member (its writer is stuck; an ACK there would wait behind
// it) or a member on which Retire was called; the retiring member's Fill
// places no copy, the slow member's does. Both session kinds.
func TestRaceAckCopyQualifies(t *testing.T) {
	type member struct {
		l     *lane
		wakes func() int
		fill  func() int // ACK or PACK frames one Fill places
	}
	check := func(t *testing.T, s *Session, fast, slow, blocked, leaving member) {
		t.Helper()
		s.mu.Lock()
		leaving.l.retireCalled = true
		for _, m := range []member{fast, slow, blocked, leaving} {
			m.l.idle = true
		}
		s.mu.Unlock()
		var w [4]int
		for i, m := range []member{fast, slow, blocked, leaving} {
			w[i] = m.wakes()
		}
		s.mu.Lock()
		s.bumpNowLocked()
		s.mu.Unlock()
		for i, want := range []int{1, 1, 0, 0} {
			m := []member{fast, slow, blocked, leaving}[i]
			if got := m.wakes() - w[i]; got != want {
				t.Fatalf("lane %d: woken %d times by the bump, want %d", m.l.id, got, want)
			}
		}
		if d := stLocked(s, func(st *stream) *lane { return st.ackLane }); d != fast.l {
			t.Fatalf("the duty is on lane %d, want the fast lane %d", d.id, fast.l.id)
		}
		if n := leaving.fill(); n != 0 {
			t.Fatalf("the retiring member placed %d ACK copies", n)
		}
		if n := slow.fill(); n != 1 {
			t.Fatalf("the slow member placed %d ACK copies, want 1", n)
		}
		if n := fast.fill(); n != 1 {
			t.Fatalf("the duty lane placed %d ACKs, want 1", n)
		}
	}
	t.Run("stream", func(t *testing.T) {
		s := stSession(stOpt{role: RolePassive, mode: ModeRace, window: 1 << 20})
		var ms []member
		for i, rtt := range []time.Duration{5, 80, 1, 2} {
			l, p := stAddLane(s, uint32(i+1), true)
			p.set(func(f *stPort) { f.srtt = rtt * time.Millisecond })
			if i == 2 {
				p.set(func(f *stPort) { f.blocked = true })
			}
			ms = append(ms, member{l, func() int { return stWakes(p) }, func() int {
				fs, b := stFill(l, time.Now())
				b.ReleaseRefs()
				return stCount(fs, wire.TypeAck)
			}})
		}
		rcRaceLanes(s)
		check(t, s, ms[0], ms[1], ms[2], ms[3])
		stEnd(s, errClosed)
	})
	t.Run("packet", func(t *testing.T) {
		s := dpSession(dpOpt{role: RolePassive, mode: ModeRace})
		var ms []member
		for i, rtt := range []time.Duration{5, 80, 1, 2} {
			l, p := dpAddLane(s, uint32(i+1), true, true)
			p.set(func(f *dpPort) { f.srtt = rtt * time.Millisecond })
			if i == 2 {
				p.set(func(f *dpPort) { f.blocked = true })
			}
			ms = append(ms, member{l, p.wakeCount, func() int {
				b := dpFill(l, time.Now())
				defer b.ReleaseRefs()
				return dpCount(dpFrames(b), wire.TypePack)
			}})
		}
		rcPktRace(s)
		check(t, s, ms[0], ms[1], ms[2], ms[3])
		dpEnd(s, errClosed)
	})
}

// TestRacePackCopyKeepsDutyOnRelFull: a reliable PACK (FIN_DELIVERED)
// that a race copy lane's datagram batch refuses for lack of REL room
// stays due on that lane and does not move the duty (R1-17 moves the duty
// only from the duty lane): the duty stays on the fastest lane, which
// places the PACK, though the srtt order the move would consult is stale
// and names another lane first.
func TestRacePackCopyKeepsDutyOnRelFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{role: RolePassive, mode: ModeRace})
		other, op := dpAddLane(s, 1, true, false)
		fast, fp := dpAddLane(s, 2, true, true)
		slow, sp := dpAddLane(s, 3, true, true)
		rcPktRace(s)
		for _, l := range []*lane{other, fast, slow} {
			dpIdle(l)
		}
		s.mu.Lock()
		s.refreshOrderLocked(time.Now(), true) // the order now: attach order
		s.mu.Unlock()
		op.set(func(f *dpPort) { f.srtt = 40 * time.Millisecond })
		fp.set(func(f *dpPort) { f.srtt = 5 * time.Millisecond })
		sp.set(func(f *dpPort) { f.srtt = 80 * time.Millisecond; f.relRoom = 0 })
		if err := dpSendFin(fast, 0); err != nil { // delivered at once: a PACK with FIN_DELIVERED is due
			t.Fatal(err)
		}
		duty := func() *lane { return dpLocked(s, func(st *stream, _ *packet) *lane { return st.ackLane }) }
		if duty() != fast {
			t.Fatalf("premise: the duty is on lane %d, want the fast lane", duty().id)
		}
		b := dpFill(slow, time.Now())
		if fs := dpFrames(b); dpCount(fs, wire.TypePack) != 0 {
			t.Fatalf("the copy lane without REL room placed %v", fs)
		}
		b.ReleaseRefs()
		if d := duty(); d != fast {
			t.Fatalf("a copy lane's refused PACK moved the duty to lane %d", d.id)
		}
		b = dpFill(fast, time.Now())
		fs := dpFrames(b)
		b.ReleaseRefs()
		if dpCount(fs, wire.TypePack) != 1 || fs[0].flags&wire.FlagPackFinDelivered == 0 {
			t.Fatalf("the duty lane placed %v; want a PACK with FIN_DELIVERED", fs)
		}
		dpEnd(s, errClosed)
	})
}

// stWakes returns f's Wake count.
func stWakes(f *stPort) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wakes
}

// TestRaceAckCopiesZeroAllocs_L41: placing an ACK (stream) or PACK
// (packet) copy on every member allocates nothing — the bump, the wake of
// every member and each member's placement.
func TestRaceAckCopiesZeroAllocs_L41(t *testing.T) {
	s, l1, l2 := rcRecv(ModeRace)
	b := carrier.NewBatch(0)
	run := func(s *Session, ls ...*lane) func() {
		return func() {
			s.mu.Lock()
			s.bumpNowLocked()
			s.mu.Unlock()
			for _, l := range ls {
				b.Reset(time.Now())
				l.Fill(nil, b)
				if b.Len() != 1 {
					panic("a race member must place its ACK copy")
				}
				b.ReleaseRefs()
			}
		}
	}
	stream := run(s, l1, l2)
	for range 16 {
		stream()
	}
	if !streamRaceEnabled {
		if a := testing.AllocsPerRun(100, stream); a != 0 {
			t.Fatalf("stream ACK copies: %v allocations per bump, want 0", a)
		}
	}
	stEnd(s, errClosed)

	ps := dpSession(dpOpt{role: RolePassive, mode: ModeRace})
	p1, _ := dpAddLane(ps, 1, true, false)
	p2, _ := dpAddLane(ps, 2, true, false)
	rcPktRace(ps)
	packet := run(ps, p1, p2)
	for range 16 {
		packet()
	}
	if !streamRaceEnabled {
		if a := testing.AllocsPerRun(100, packet); a != 0 {
			t.Fatalf("packet PACK copies: %v allocations per bump, want 0", a)
		}
	}
	dpEnd(ps, errClosed)
}
