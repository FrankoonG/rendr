package lessons6

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketBondAggregates_L32 (M3 design §A6.8, M3-D52; KL-13's guard): a
// mixed packet bond — a datagram member u (frame budget 1000, a 1 MB/s
// link) and a stream member s (a 0.5 MB/s stream link) — offered 1.5 × u's
// rate, four of five datagrams 900 bytes (u carries them) and every fifth
// 1,200 bytes (only s can), delivers at least 0.85 × the sum of its
// members' rates over a steady 10-s window. The offered load equals that
// sum, so the stream member must carry small datagrams as well as every big
// one: the headroom it keeps for the next big datagram (MaxPayload + 25
// bytes of its capacity) must not cost the aggregation. Every datagram that
// arrived is intact and arrived once.
func TestPacketBondAggregates_L32(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			small, big = 900, 1200
			ru, rs     = 1_000_000, 500_000 // the members' link rates, bytes/s
			burst      = 25
			pace       = 16 * time.Millisecond // 1,562 datagrams/s of 960 bytes on average: 1.5 MB/s
		)
		size := func(k int) int {
			if k%5 == 0 {
				return big
			}
			return small
		}
		w := newWorld(t, worldOpts{}, "u")
		lu := w.links[0]
		for _, d := range bothDirs {
			lu.SetDelay(d, 5*time.Millisecond, 0)
		}
		lu.SetRate(rendrtest.Up, ru)
		ls := w.addStreamLink("s", 1<<20)
		ls.SetDelay(5*time.Millisecond, 0)
		ls.SetRate(rs)
		dc, pc := w.open(w.peer(dgCarrier(lu, 1000), stCarrier(ls)), rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 10*time.Second, "both members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
		up := startFlow(dc, pc, flowCfg{seed: 32, burst: burst, pace: pace, size: size})
		time.Sleep(2 * time.Second) // warm-up: the estimators find the links' rates
		from := time.Now()
		time.Sleep(10 * time.Second)
		to := time.Now()
		up.halt(t, "dialer → passive")
		settle(t, dc, pc, up, nil)

		// Stimulus and load: both members carried datagrams, the offer was
		// the sum of their rates.
		sc, _ := liveNamed(dc.Status(), "s")
		uc, _ := liveNamed(dc.Status(), "u")
		if sc.TxBytes < 1000*big || uc.TxBytes < 1000*small {
			t.Fatalf("load: s carried %d bytes, u %d", sc.TxBytes, uc.TxBytes)
		}
		var offered, delivered int
		up.mu.Lock()
		for k, at := range up.wrote {
			if !at.Before(from) && at.Before(to) {
				offered += size(k)
			}
			if k < len(up.arrived) && !up.arrived[k].IsZero() && !up.arrived[k].Before(from) && up.arrived[k].Before(to) {
				delivered += size(k)
			}
		}
		bad := up.bad
		up.mu.Unlock()
		secs := to.Sub(from).Seconds()
		if o := float64(offered) / secs; o < 1.45*ru {
			t.Fatalf("load: offered %.0f B/s, want 1.5 × %d", o, ru)
		}
		if bad != nil {
			t.Fatalf("integrity: %v", bad)
		}
		// A datagram still on the link when settle returned can be counted
		// in Received an instant before the reader records it: compare the
		// two from one consistent reading (bounded).
		ds := dc.Status().Packet
		ps, arrived := pc.Status().Packet, 0
		waitFor(t, 5*time.Second, "the reader to record every received datagram", func() bool {
			ps, arrived = pc.Status().Packet, up.arrivedCount()
			return uint64(arrived) == ps.Received
		})
		if ps.Duplicates+ps.DropLate != 0 {
			t.Fatalf("counters: dialer %+v, passive %+v, arrived %d", *ds, *ps, arrived)
		}
		got := float64(delivered) / secs
		t.Logf("offered %.0f B/s, delivered %.0f B/s (%.2f of the members' %d B/s); s %d bytes, u %d bytes; dialer %+v",
			float64(offered)/secs, got, got/(ru+rs), ru+rs, sc.TxBytes, uc.TxBytes, *ds)
		if got < 0.85*(ru+rs) {
			t.Fatalf("the mixed bond delivered %.0f B/s, want ≥ 0.85 × (%d + %d) B/s; dialer %+v", got, ru, rs, *ds)
		}

		endPair(t, dc, pc, up, nil)
		w.noViolation()
		w.close()
	})
}
