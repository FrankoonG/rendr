package race

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestRaceExactlyOnce_L39 (M3 design §A11.2, R1-35; L39 "race 下每个恰好一次，
// 重复计数约 1000"): a packet race session over two DatagramLinks u1 and u2
// (20 ms RTT, both members listed on both ends first) carries 1,000 test
// datagrams A → B, 100 per second, while the dialer's conn of a member is
// closed under rendr five times (at 1.5, 3.5, 5.5, 7.5 and 9.5 s, u1 and u2
// in turn); each death is followed by the factory's rejoin before the next
// one. The deaths are spaced so that at least 90 % of the datagrams are
// written while both members live (the single-member windows, from a
// close to its rejoin, are measured and the datagrams written in them
// counted).
//
// The passive learns of a locally closed datagram carrier only from its
// own death verdict (up to DeadMax later), so "two members on both ends"
// means: the dialer lists two live members and the passive lists both of
// them live (racing).
//
// PASS: every datagram delivered exactly once — all 1,000 seqs, intact,
// with 0 application duplicates (L39); the receiver counts Duplicates ≥
// 0.9 × 1000 (the other member's copies, deduplicated); each close one
// death of the dialer's member (its CarrierDown) and one rejoin; a clean end
// with io.EOF on both ends and nothing left after Runtime.Close.
func TestRaceExactlyOnce_L39(t *testing.T) {
	synctest.Test(t, exactlyOnce)
}

func exactlyOnce(t *testing.T) {
	const n = 1000
	w := newWorld(t, worldOpts{}, linkSpec{name: "u1", oneWay: 10 * time.Millisecond, dgram: true},
		linkSpec{name: "u2", oneWay: 10 * time.Millisecond, dgram: true})
	dc, pc := w.openPacket(w.peer("u1", "u2"), rendr.DialOptions{Mode: rendr.ModeRace})
	waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })
	up := w.startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: 100, limit: n})
	down := w.startFlow(pc, dc, flowCfg{name: "B → A", seed: 2}) // writes nothing; ends the session cleanly
	start := up.start
	rejoins0 := dc.Status().Rejoins

	type single struct{ from, to time.Time } // one member only
	var singles []single
	for k := range 5 {
		sleepUntil(start.Add(1500*time.Millisecond + time.Duration(k)*2*time.Second))
		name := [2]string{"u1", "u2"}[k%2]
		ds := dc.Status()
		if !racing(dc, pc) {
			t.Fatalf("death %d: not two members on both ends: dialer %+v, passive %+v", k, liveOf(ds), liveOf(pc.Status()))
		}
		m, _ := liveNamed(ds, name)
		at := time.Now()
		w.localClose(m.ID)
		waitFor(t, 2*time.Second, "the rejoin: two members on both ends again", func() bool {
			n, ok := liveNamed(dc.Status(), name)
			return ok && n.ID != m.ID && racing(dc, pc)
		})
		singles = append(singles, single{at, time.Now()})
		if _, ok := w.dev.downOf(m.ID); !ok {
			t.Fatalf("death %d: no CarrierDown of %s's member %d on the dialer", k, name, m.ID)
		}
	}
	waitFor(t, 30*time.Second, "every datagram written", func() bool { return up.accepted.Load() == n })
	waitFor(t, 10*time.Second, "every datagram read", func() bool { return up.read.Load() == n })

	// The premise: ≥ 90 % written while both members lived.
	up.mu.Lock()
	inSingle := 0
	for _, at := range up.wrote {
		for _, s := range singles {
			if !at.Before(s.from) && !at.After(s.to) {
				inSingle++
				break
			}
		}
	}
	up.mu.Unlock()
	if inSingle > n/10 {
		t.Fatalf("premise: %d of %d datagrams were written while one member lived, want ≤ 10 %%", inSingle, n)
	}
	if r := dc.Status().Rejoins - rejoins0; r != 5 {
		t.Fatalf("Rejoins rose by %d for 5 deaths, want 5", r)
	}

	res := up.integrity(t)
	if res.Unique != n || res.Highest != n-1 || len(res.Missing) != 0 {
		t.Fatalf("not every datagram exactly once: %+v", res)
	}
	ps := pc.Status().Packet
	if ps.Duplicates < 9*n/10 {
		t.Fatalf("the receiver counted %d Duplicates for %d datagrams, want ≥ %d (R1-35)", ps.Duplicates, n, 9*n/10)
	}
	t.Logf("%d datagrams exactly once; %d written with one member; receiver Duplicates %d, Received %d; dialer migrations %+v",
		n, inSingle, ps.Duplicates, ps.Received, dc.Status().Migrations)
	endClean(t, dc, pc, up, down)
	w.noViolation()
	w.close()
}

// racing reports that the dialer lists two live members and the passive
// lists both of them live (it may still list a carrier the dialer closed
// locally until its own death verdict).
func racing(dc, pc *rendr.PacketConn) bool {
	dl := liveOf(dc.Status())
	if len(dl) != 2 {
		return false
	}
	ps := pc.Status()
	for _, m := range dl {
		if c, ok := carrierOf(ps, m.ID); !ok || (c.State != rendr.CarrierMember && c.State != rendr.CarrierActive) {
			return false
		}
	}
	return true
}
