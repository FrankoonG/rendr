package mux

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestMuxRaceOnSharedTrunks (M3 design §A11.2, §A5.11 "race and bond on
// shared trunks"; M3-D10, M3-D30, M3-D31, M3-D35): two factories p1 and p2
// over Links of 20 ms RTT shaped to 8 MiB/s each — also under -race: at a
// quarter of that rate the four views' shares on p1 spread to [0.75, 1.28]
// under the race detector's interleavings, the writer's uneven rotation in
// cap-limited rounds that TestMuxCapLimitedSharesFair isolates, so the
// shares below would measure that defect instead of race on shared
// trunks; one Peer opens 2 selector sessions (active on p1, the first
// factory) and 2 race sessions (a member on each factory), and each sends
// open-ended bulk B → A for 6 s. So p1's shared carrier holds 4 views (the
// two selector sessions and a race member of each race session) and p2's
// holds 2 (the race sessions' other members), every view backlogged.
//
// PASS: copies — each race session's sender B places copies (Race.CopyBytes
// > 0) on both members (TxBytes grows on both of its rows on B), while its
// TxBytes counts each byte once (= what the application wrote); dedup —
// each race session's receiver A discards the copies that arrive second
// (DupBytes > 0) and its application reads every byte exactly once,
// verified against the PRNG with io.EOF after exactly what the sender
// wrote; DRR shares — over the 4 s after a 1-s warm-up, the views' byte
// shares on B's side of each shared carrier (their CarrierStatus.TxBytes
// growth) lie within [0.8, 1.25] of the carrier's mean per view (the
// race members take their fair share of each carrier and no more:
// §A5.11), and each carrier carries ≥ 0.85 of its link; a clean end and
// nothing left after Runtime.Close.
func TestMuxRaceOnSharedTrunks(t *testing.T) {
	const rate = 8 << 20
	synctest.Test(t, func(t *testing.T) {
		const oneWay, run = 10 * time.Millisecond, 6 * time.Second
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: oneWay, rate: rate}, linkSpec{name: "p2", oneWay: oneWay, rate: rate})
		peer := w.peer("p1", "p2")
		var ps []pair
		for i, m := range []rendr.Mode{rendr.ModeSelector, rendr.ModeSelector, rendr.ModeRace, rendr.ModeRace} {
			ps = append(ps, w.open(peer, fmt.Sprintf("S%d", i), m))
		}
		waitFor(t, 10*time.Second, "two race members per race session on both ends", func() bool {
			for _, s := range ps[2:] {
				if len(liveOf(s.d.Status())) != 2 || len(liveOf(s.p.Status())) != 2 {
					return false
				}
			}
			return true
		})
		t1, n1 := sharedTarget(t, ps, 4)
		if n1 != "p1" {
			t.Fatalf("premise: the selector sessions are active on %s, want p1", n1)
		}
		t2, ok := liveNamed(ps[2].d.Status(), "p2")
		if !ok || t2.Shared != 2 {
			t.Fatalf("premise: the race sessions' p2 carrier is %+v, want one shared by both", t2)
		}
		trunks := map[rendr.CarrierID]string{t1.ID: "p1", t2.ID: "p2"}
		b := w.startBulk(ps, openEnded, 0)
		start := time.Now()

		// views returns B's TxBytes of every session's row of each trunk.
		views := func() map[rendr.CarrierID][]uint64 {
			out := map[rendr.CarrierID][]uint64{}
			for _, s := range ps {
				for id := range trunks {
					if cs, ok := carrierOf(s.p.Status(), id); ok && cs.State != rendr.CarrierDead {
						out[id] = append(out[id], cs.TxBytes)
					}
				}
			}
			return out
		}
		sleepUntil(start.Add(time.Second))
		v0, at0 := views(), time.Now()
		sleepUntil(start.Add(5 * time.Second))
		v1, at1 := views(), time.Now()
		for id, name := range trunks {
			if len(v0[id]) != len(v1[id]) || len(v1[id]) != map[string]int{"p1": 4, "p2": 2}[name] {
				t.Fatalf("premise: %s's carrier %d has views %v then %v, want %d live views throughout", name, id, v0[id], v1[id], map[string]int{"p1": 4, "p2": 2}[name])
			}
			var sum float64
			var d []float64
			for i := range v1[id] {
				x := float64(v1[id][i] - v0[id][i])
				d = append(d, x)
				sum += x
			}
			mean := sum / float64(len(d))
			var shares []string
			for _, x := range d {
				shares = append(shares, fmt.Sprintf("%.3f", x/mean))
				if x < 0.8*mean || x > 1.25*mean {
					t.Errorf("%s's carrier %d: a view's share %.3f of the mean, want within [0.8, 1.25] (bytes %v)", name, id, x/mean, d)
				}
			}
			load := sum / (rate * at1.Sub(at0).Seconds())
			t.Logf("%s's carrier %d: %d views, shares of the mean %v, %.3f of the link", name, id, len(d), shares, load)
			if load < 0.85 {
				t.Errorf("load: %s's carrier carried %.3f of its link, want ≥ 0.85", name, load)
			}
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
		for i, s := range ps[2:] {
			ds, pss := s.d.Status(), s.p.Status()
			sent := uint64(b.tx[2+i].sent.Load())
			m1, _ := carrierOf(pss, t1.ID)
			m2, _ := carrierOf(pss, t2.ID)
			t.Logf("race session %s: B TxBytes %d, CopyBytes %d, member TxBytes p1 %d p2 %d; A DupBytes %d", s.key, pss.TxBytes, pss.Race.CopyBytes, m1.TxBytes, m2.TxBytes, ds.DupBytes)
			if pss.TxBytes != sent || pss.Race.CopyBytes == 0 || m1.TxBytes == 0 || m2.TxBytes == 0 {
				t.Errorf("race session %s: B's TxBytes %d (the application wrote %d), CopyBytes %d, member TxBytes %d and %d; want TxBytes = written, copies and both members carrying",
					s.key, pss.TxBytes, sent, pss.Race.CopyBytes, m1.TxBytes, m2.TxBytes)
			}
			if ds.DupBytes == 0 {
				t.Errorf("race session %s: the receiver A discarded no copy (DupBytes 0)", s.key)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
		closeAll(t, ps)
		w.noViolation()
		w.close()
	})
}
