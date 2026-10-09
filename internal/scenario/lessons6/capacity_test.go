package lessons6

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestPacketStreamLaneCapacity_L32: a mixed packet bond with a datagram
// member u (frame budget 1000: datagrams up to 975 bytes) and a stream
// member s (an 8 MiB/s stream link whose conn could buffer 8 MiB). Bursts
// of 100 datagrams every 20 ms: four of five are 900 bytes, which u
// carries; every fifth is 1,200 bytes, which only a stream member can carry
// (the bond's txBig, M2-D43), so s carries datagrams by construction
// (1.2 MB/s). A stream member's Fill also pulls tx after txBig (§A5.2), so
// when the writers run in parallel s takes small datagrams too, up to the
// whole 4.8 MB/s offered: its link's rate stays above that, so s is never
// saturated before the stall (on a 2 MB/s link it was at GOMAXPROCS ≥ 2,
// its capacity full, and big datagrams aged out before the stall). The
// stall starts while s has room for a big datagram, so it holds some. Then
// s's link stalls: nothing it accepted
// arrives, and its Write keeps returning while its buffer has room. On a
// stream lane DGRAM bytes are DATA (M2-D26): they are submitted against the
// carrier's in-flight capacity, so the stalled member takes at most its
// capacity of datagrams — the ones lost with it, uncounted, at its death —
// while the big datagrams it cannot take wait and age out, counted
// (DropAge, then DropTooLarge while no stream member lives); it dies of
// silence (ping_timeout or write_stall). Without the capacity gate the
// stalled member would swallow its link's buffer (thousands of
// datagrams). u carries the small datagrams throughout — also while no
// stream member lives, when a big datagram at the head of the queue is
// dropped at once instead of holding the small ones behind it until
// MaxAge; after the stall ends s is redialled and the big datagrams flow
// again. Every datagram
// that arrived is intact and arrived once.
func TestPacketStreamLaneCapacity_L32(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const small, big, burst = 900, 1200, 100
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
		ls := w.addStreamLink("s", 8<<20)
		ls.SetDelay(5*time.Millisecond, 0)
		ls.SetRate(8 << 20)
		dc, pc := w.open(w.peer(dgCarrier(lu, 1000), stCarrier(ls)), rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 10*time.Second, "both members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
		sc, ok := liveNamed(dc.Status(), "s")
		if !ok || sc.Kind != rendr.KindStream {
			t.Fatalf("no stream member: %+v", dc.Status().Carriers)
		}
		up := startFlow(dc, pc, flowCfg{seed: 21, burst: burst, pace: 20 * time.Millisecond, size: size})
		time.Sleep(5 * time.Second)
		sc, _ = carrierOf(dc.Status(), sc.ID)
		uc, _ := liveNamed(dc.Status(), "u")
		if sc.TxBytes < 1000*big || uc.TxBytes < 1000*small {
			t.Fatalf("load: both members must carry datagrams before the stall: s %d bytes, u %d bytes", sc.TxBytes, uc.TxBytes)
		}
		for _, l := range up.losses() {
			if time.Since(l.wrote) > time.Second {
				t.Fatalf("before the stall seq %d (%d bytes), written %v ago, is missing; dialer %+v; passive %+v",
					l.seq, size(l.seq), time.Since(l.wrote), *dc.Status().Packet, *pc.Status().Packet)
			}
		}

		// The stream member's link stalls while s has room for a big
		// datagram (its writer then takes datagrams the stall holds); follow
		// its capacity and in-flight bytes until it dies.
		waitFor(t, time.Second, "room on the stream member", func() bool {
			c, ok := carrierOf(dc.Status(), sc.ID)
			return ok && c.Cap-c.Inflight >= big
		})
		held0 := ls.Stats().Session.Held
		stalled := time.Now()
		ls.SetStall(true)
		maxCap, maxInflight := sc.Cap, sc.Inflight
		var died rendr.CarrierStatus
		waitFor(t, 10*time.Second, "the stalled member's death", func() bool {
			c, ok := carrierOf(dc.Status(), sc.ID)
			if !ok {
				return false
			}
			if c.State == rendr.CarrierDead {
				died = c
				return true
			}
			maxCap, maxInflight = max(maxCap, c.Cap), max(maxInflight, c.Inflight)
			return false
		})
		death := time.Now()
		// It dies of silence; or the passive found the silence first and its
		// close reached the dialer's end (the fake link delivers a close
		// through a stall), a transport_error after the passive's verdict.
		silent := func(c rendr.Cause) bool { return c == rendr.CausePingTimeout || c == rendr.CauseWriteStall }
		if !silent(died.DeathCause) {
			synctest.Wait() // the passive's CarrierDown reaches the log through its event worker
			pev, ok := w.pev.downOf(sc.ID)
			if died.DeathCause != rendr.CauseTransportError || !ok || !silent(pev.Cause) || pev.Time.After(death) {
				t.Fatalf("the stalled member died of %v (%q), want ping_timeout or write_stall (passive: %+v, %v)",
					died.DeathCause, died.DeathDetail, pev, ok)
			}
		}
		if h := ls.Stats().Session.Held; h == held0 {
			t.Fatalf("stimulus: the stall held nothing")
		}
		if maxCap <= 0 || maxInflight > maxCap {
			t.Fatalf("the stalled member's capacity %d, in flight up to %d", maxCap, maxInflight)
		}
		// u carried the small datagrams through the stall.
		if got := up.firstArrivalWrittenFrom(stalled); got.IsZero() || got.Sub(stalled) > 100*time.Millisecond {
			t.Fatalf("after the stall the first arrival came +%v", got.Sub(stalled))
		}
		if gap := up.maxArrivalGap(stalled, death); gap > 100*time.Millisecond {
			t.Fatalf("an arrival gap of %v while the stream member was stalled", gap)
		}

		// The stall ends; s is redialled and carries the big datagrams again.
		time.Sleep(3 * time.Second)
		ls.SetStall(false)
		waitFor(t, 20*time.Second, "a new stream member", func() bool {
			c, ok := liveNamed(dc.Status(), "s")
			return ok && c.ID != sc.ID
		})
		rejoin := time.Now()
		// While no stream member lived, the big datagrams nobody could
		// carry were dropped at once (DropTooLarge, M2-D45) and never held
		// up the small ones behind them.
		if gap := up.maxArrivalGap(death, rejoin); gap > 100*time.Millisecond {
			t.Fatalf("an arrival gap of %v between the stream member's death and its rejoin", gap)
		}
		time.Sleep(3 * time.Second)
		up.halt(t, "dialer → passive")
		settle(t, dc, pc, up, nil)

		ds, ps := dc.Status().Packet, pc.Status().Packet
		ls_ := up.losses()
		uncounted := ds.Sent - ps.Received
		if ps.Duplicates+ps.DropLate+ps.DropRecvQueue != 0 || uint64(up.arrivedCount()) != ps.Received || ds.DropQueue != 0 {
			t.Fatalf("counters: dialer %+v, passive %+v, arrived %d", *ds, *ps, up.arrivedCount())
		}
		if uint64(len(ls_)) != drops(ds)+uncounted {
			t.Fatalf("%d datagrams missing ≠ %d counted drops + %d lost in flight: %+v", len(ls_), drops(ds), uncounted, *ds)
		}
		if uncounted == 0 || drops(ds) == 0 {
			t.Fatalf("stimulus: the stalled member held %d datagrams and %d waited for it in vain", uncounted, drops(ds))
		}
		// The stalled member absorbed at most its capacity: the datagrams it
		// lost in flight are DGRAM payload of at least 900 bytes each.
		if int64(uncounted)*small > int64(maxCap) {
			t.Fatalf("the stalled member swallowed %d datagrams (≥ %d bytes) beyond its capacity of %d bytes",
				uncounted, int64(uncounted)*small, maxCap)
		}
		for _, l := range ls_ {
			until := death
			if size(l.seq) == big {
				until = rejoin
			}
			if l.wrote.Before(stalled.Add(-time.Second)) || l.wrote.After(until) {
				// Diagnosis: every loss outside its window, the counters and
				// the carriers at the end.
				var out []string
				for _, m := range ls_ {
					u := death
					if size(m.seq) == big {
						u = rejoin
					}
					if (m.wrote.Before(stalled.Add(-time.Second)) || m.wrote.After(u)) && len(out) < 40 {
						out = append(out, fmt.Sprintf("%d/%dB@+%v", m.seq, size(m.seq), m.wrote.Sub(stalled)))
					}
				}
				var cs []string
				for _, c := range dc.Status().Carriers {
					cs = append(cs, fmt.Sprintf("%s#%d %v %v %q cap %d infl %d tx %d", c.Name, c.ID, c.State, c.DeathCause, c.DeathDetail, c.Cap, c.Inflight, c.TxBytes))
				}
				t.Fatalf("seq %d (%d bytes) written at +%v of the stall was lost: outside [stall − 1 s, +%v]; outside (first 40): %v; death +%v; dialer %+v; passive %+v; dialer carriers %v",
					l.seq, size(l.seq), l.wrote.Sub(stalled), until.Sub(stalled), out, death.Sub(stalled), *ds, *ps, cs)
			}
		}
		if up.firstArrivalWrittenFrom(rejoin).IsZero() {
			t.Fatalf("nothing written after the rejoin arrived")
		}
		t.Logf("stall → death %v (%v %q), rejoin +%v; capacity %d bytes (in flight up to %d); %d lost in flight, drops %+v; %d accepted",
			death.Sub(stalled), died.DeathCause, died.DeathDetail, rejoin.Sub(stalled), maxCap, maxInflight, uncounted, *ds, up.accepted.Load())

		endPair(t, dc, pc, up, nil)
		w.noViolation()
		w.close()
	})
}
