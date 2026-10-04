package lessons3

import (
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestBondDeathRequeuesBeforeSched_L27: a bond member's death moves its
// unacknowledged data to the surviving member in the death step itself;
// the data never waits for a SCHED round trip (L27: "阻塞 SCHED 后杀 A：死亡处理
// 返回前 A 的未 ACK 区间已排到 B，对端在收到 SCHED 之前就从 B 收到数据").
//
// Bulk flows from the dialer over two rate-limited members, A and B, more
// than one member can carry. A is killed right after it committed a DATA
// batch, which is still in the link (5 ms one way behind a 2 MiB/s
// bottleneck) and dies with A: the link counts it lost. The passive's
// SCHED processing is blocked from that moment: its actor is held as it
// starts to handle A's death (Hooks.DeathObserved), so it applies no SCHED
// (and moves no ACK duty) until released. The dialer counts the bond death
// migration in A's death step — at the instant of the kill, and only
// because that step requeued A's unacknowledged spans to a live member
// (§7.6) — and B retransmits them. While the passive's applied epoch stays
// where it was, its application receives the entire stream intact up to
// io.EOF, including the batch lost with A: those bytes can only have come
// from the death step's requeue.
func TestBondDeathRequeuesBeforeSched_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newHoldGate()
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond, rate: 2 * mib}, {name: "b", delay: 10 * time.Millisecond, rate: 2 * mib}},
			pov:   &testhooks.Overrides{Hooks: &testhooks.Hooks{DeathObserved: g.hook}},
		}, g)
		a := w.link("a")
		dc, pc := w.open(w.peer(), rendr.ModeBond)
		total := int64(6 * mib)
		up := w.startFlow("up", dc, pc, 271, flowOpts{n: total})
		var memberA, memberB rendr.CarrierStatus
		waitState(t, 5*time.Second, "both members carrying data", func() (bool, string) {
			var ok bool
			memberA, memberB, ok = members(dc)
			return ok && memberA.TxBytes > 256*kib && memberB.TxBytes > 256*kib && up.recvd.Load() >= mib,
				fmt.Sprintf("members %+v / %+v, %d bytes received", memberA, memberB, up.recvd.Load())
		})
		epoch0 := pc.Status().SchedEpoch
		g.arm(func(id uint32) bool { return id == uint32(memberA.ID) })

		// Wait (in 1 ms steps) for A's next DATA commit and kill it at once:
		// the batch has not left the link yet.
		cs, _ := carrierByID(dc, memberA.ID)
		tx0, batch := cs.TxBytes, uint64(0)
		waitFor(t, 2*time.Second, "A committing a DATA batch", func() bool {
			cs, _ := carrierByID(dc, memberA.ID)
			batch = cs.TxBytes - tx0
			return batch > 0
		})
		mark := w.dev.mark()
		killedAt := time.Now()
		if a.Kill() < 1 {
			t.Fatal("no carrier of a killed")
		}
		// At most one millisecond of the bottleneck (≈ 2 KiB) has passed
		// since the commit.
		lost := a.Stats().Session.BufferLost
		if lost < int64(batch)-4*kib || lost < 16*kib {
			t.Fatalf("stimulus: %d bytes lost with A after it committed %d DATA bytes; want the batch lost in the link", lost, batch)
		}
		ev := w.dev.wait(t, mark, time.Second, "the dialer's bond death migration", isKind(rendr.EventMigration, dc.ID()))
		if ev.From != memberA.ID || !isDeathCause(ev.Cause) || !ev.Time.Equal(killedAt) {
			t.Fatalf("migration %+v (killed at %v), want A's death counted in its death step at once", ev, killedAt)
		}
		select {
		case id := <-g.held:
			if id != uint32(memberA.ID) {
				t.Fatalf("passive held at the death of %d, want A %d", id, memberA.ID)
			}
		case <-time.After(time.Second):
			t.Fatal("the passive did not observe A's death")
		}
		// The passive's actor is held: no SCHED is applied, yet the stream
		// completes over B.
		up.wait(t, 30*time.Second)
		ps := pc.Status()
		if ps.SchedEpoch != epoch0 {
			t.Fatalf("the passive applied epoch %d while held (before: %d)", ps.SchedEpoch, epoch0)
		}
		if ds := dc.Status(); ds.SchedEpoch == epoch0 || ds.RetransmittedBytes == 0 {
			t.Fatalf("dialer: epoch %d (passive's %d), %d bytes retransmitted; want a shrink SCHED published and A's spans resent", ds.SchedEpoch, epoch0, ds.RetransmittedBytes)
		}
		if cs, ok := carrierByID(dc, memberB.ID); !ok || cs.RetxBytes == 0 {
			t.Fatalf("B %+v (found %v): want A's spans retransmitted on B", cs, ok)
		}
		t.Logf("A killed after committing %d DATA bytes, %d bytes lost in the link; held passive at epoch %d received %d bytes; dialer epoch %d, %d bytes resent on B",
			batch, lost, epoch0, up.recvd.Load(), dc.Status().SchedEpoch, dc.Status().RetransmittedBytes)

		g.open()
		waitState(t, 5*time.Second, "the passive catching up with the dialer's SCHED", func() (bool, string) {
			ps, ds := pc.Status(), dc.Status()
			return ps.SchedEpoch == ds.SchedEpoch && ds.SchedEchoed == ds.SchedEpoch,
				fmt.Sprintf("passive epoch %d, dialer epoch %d echoed %d", ps.SchedEpoch, ds.SchedEpoch, ds.SchedEchoed)
		})
		wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Death: 1})
		wantMigrations(t, "passive", pc, rendr.MigrationCounts{}) // a pure receiver requeues nothing (P13)
		if s := a.Stats().Session; s.Killed < 1 || up.recvd.Load() != total {
			t.Fatalf("stimulus/load: a %+v, %d of %d bytes", s, up.recvd.Load(), total)
		}
		finishSession(t, dc, pc)
		w.finish()
	})
}

// members returns the dialer's two live bond members (a's first).
func members(dc *rendr.Conn) (a, b rendr.CarrierStatus, ok bool) {
	var na, nb int
	for _, cs := range dc.Status().Carriers {
		if cs.State != rendr.CarrierMember {
			continue
		}
		switch cs.Name {
		case "a":
			a, na = cs, na+1
		case "b":
			b, nb = cs, nb+1
		}
	}
	return a, b, na == 1 && nb == 1
}

// TestSelectorDeathRace_L27: the selector's active carrier A dies; the
// failover starts dialling at once, ignoring dwell and cooldown (1 h
// here), and races the candidates B and C with JoinStagger (L27: "杀活跃的
// A：立即开始拨号，不等 dwell 和冷却；候选 B、C 竞速，迁移计数 +1，只有胜出者收到
// 重放，落败者收到 0 个 DATA"). B, the best-ranked candidate, is dialled in
// A's death step, but the dialer's handling of B's JOIN_ACK is held
// (Hooks.DialResult), so C is dialled one JoinStagger later and wins: it
// becomes active, is counted as one death migration on both ends and
// receives the replay of A's unacknowledged data. B, released afterwards,
// attaches as a race loser and is retired with CLOSE: it carries no DATA
// in either direction. The stream arrives intact.
func TestSelectorDeathRace_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newHoldGate()
		var smu sync.Mutex
		var starts []dialStart
		dov := &testhooks.Overrides{
			SelectorDwell: time.Hour, SelectorCooldown: time.Hour,
			Hooks: &testhooks.Hooks{
				DialResult: g.hook,
				DialStart: func(f int) {
					smu.Lock()
					starts = append(starts, dialStart{f, time.Now()})
					smu.Unlock()
				},
			},
		}
		w := newWorld(t, worldConfig{
			links: []linkSpec{
				{name: "a", delay: 2 * time.Millisecond, rate: 2 * mib},
				{name: "b", delay: 5 * time.Millisecond, rate: 2 * mib},
				{name: "c", delay: 10 * time.Millisecond, rate: 2 * mib},
			},
			dov: dov, pov: &testhooks.Overrides{SelectorDwell: time.Hour, SelectorCooldown: time.Hour},
		}, g)
		a := w.link("a")
		dc, pc := w.open(w.peer(), rendr.ModeSelector)
		first := mustActive(t, dc, "dialer")
		if first.Name != "a" {
			t.Fatalf("initial active %+v, want a carrier of a", first)
		}
		total := int64(8 * mib)
		up := w.startFlow("up", dc, pc, 272, flowOpts{n: total})
		waitFor(t, 5*time.Second, "1 MiB delivered over A", func() bool { return up.recvd.Load() >= mib })

		g.arm(anyID) // the race's first attempt: B
		mark := w.dev.mark()
		smu.Lock()
		before := len(starts)
		smu.Unlock()
		killedAt := time.Now()
		if a.Kill() < 1 {
			t.Fatal("no carrier of a killed")
		}
		var bid uint32
		select {
		case bid = <-g.held:
		case <-time.After(5 * time.Second):
			t.Fatal("no race attempt after A's death")
		}
		ev := w.dev.wait(t, mark, 5*time.Second, "the race winner's migration", isKind(rendr.EventMigration, dc.ID()))
		winner := mustActive(t, dc, "dialer")
		if ev.From != first.ID || ev.To != winner.ID || winner.Name != "c" || !isDeathCause(ev.Cause) {
			t.Fatalf("migration %+v, active %+v; want A's death won by C", ev, winner)
		}
		g.open() // B's JOIN_ACK is handled now: a race loser
		waitState(t, 5*time.Second, "B retired as a race loser", func() (bool, string) {
			cs, ok := carrierByID(dc, rendr.CarrierID(bid))
			return ok && cs.State == rendr.CarrierDead && cs.DeathCause == rendr.CauseRetired, fmt.Sprintf("%+v (found %v)", cs, ok)
		})

		// The race: B in A's death step, C one JoinStagger (1 s) later.
		smu.Lock()
		race := append([]dialStart(nil), starts[before:]...)
		smu.Unlock()
		var bAt, cAt time.Time
		for _, s := range race {
			switch {
			case s.factory == 1 && bAt.IsZero():
				bAt = s.at
			case s.factory == 2 && cAt.IsZero():
				cAt = s.at
			}
		}
		if !bAt.Equal(killedAt) || cAt.Sub(killedAt) != time.Second {
			t.Fatalf("race dials: b at %v, c at %v after A's death; want b at once and c one JoinStagger later (%+v)",
				bAt.Sub(killedAt), cAt.Sub(killedAt), race)
		}

		up.wait(t, 60*time.Second)
		wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Death: 1})
		waitFor(t, time.Second, "the passive counting one death", func() bool {
			return pc.Status().Migrations == rendr.MigrationCounts{Death: 1}
		})
		// Only the winner got the replay; the loser carried no DATA.
		if cs, _ := carrierByID(dc, winner.ID); cs.TxBytes == 0 || cs.RetxBytes == 0 {
			t.Fatalf("winner C %+v: want the replay of A's data", cs)
		}
		lb, _ := carrierByID(dc, rendr.CarrierID(bid))
		pb, ok := carrierByID(pc, rendr.CarrierID(bid))
		if lb.Name != "b" || lb.TxBytes != 0 || lb.RetxBytes != 0 || !ok || pb.RxBytes != 0 || pb.TxBytes != 0 {
			t.Fatalf("loser B: dialer %+v, passive %+v (found %v); want no DATA either way", lb, pb, ok)
		}
		if s := a.Stats().Session; s.Killed < 1 || up.recvd.Load() != total {
			t.Fatalf("stimulus/load: a %+v, %d of %d bytes", s, up.recvd.Load(), total)
		}
		finishSession(t, dc, pc)
		w.finish()
	})
}

// dialStart is one Hooks.DialStart call.
type dialStart struct {
	factory int
	at      time.Time
}
