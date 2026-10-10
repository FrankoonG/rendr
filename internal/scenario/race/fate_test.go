package race

import (
	"slices"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestRaceFateGroup (M3 design §A11.2, M3-D37, PA-31; plan:134 "bond / race
// 不把同组算作独立容量"): a race session over three equal Links a, b and c
// (20 ms RTT, 4 MiB/s each), a and b in fate group "g" and c alone (Peer
// order a, b, c), moves 8 MiB B → A. Race keeps at most one member per
// fate group, the best-ranked factory of each: a (b ranks after it in its
// group) and c.
//
// PASS: both ends list exactly two live members, the dialer's from a and
// c, during and after the transfer, and b's Link never carried a session
// carrier; the copies travel on those two carriers only: on the sending
// side B exactly two carriers sent data, together at least 1.5 × the bytes
// moved (each carries a copy), and A discarded duplicates; every byte
// verified and io.EOF at the end; a clean end on both ends and nothing
// left after Runtime.Close.
func TestRaceFateGroup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			size = 8 << 20
			rate = 4 << 20
		)
		g := rendr.Props{FateGroup: "g"}
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, rate: rate, props: g},
			linkSpec{name: "b", oneWay: 10 * time.Millisecond, rate: rate, props: g},
			linkSpec{name: "c", oneWay: 10 * time.Millisecond, rate: rate})
		dc, pc := w.open(w.peer("a", "b", "c"), rendr.DialOptions{Mode: rendr.ModeRace})
		waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })
		members := func(when string) {
			t.Helper()
			ds, ps := dc.Status(), pc.Status()
			var names []string
			for _, m := range liveOf(ds) {
				names = append(names, m.Name)
				if m.Name == "a" && m.FateGroup != "g" {
					t.Fatalf("%s: a's member reports FateGroup %q, want g", when, m.FateGroup)
				}
			}
			slices.Sort(names)
			if !slices.Equal(names, []string{"a", "c"}) || len(liveOf(ps)) != 2 {
				t.Fatalf("%s: the dialer's members are %v and the passive lists %d, want a and c, 2 (one member per fate group)",
					when, names, len(liveOf(ps)))
			}
		}
		members("before the transfer")
		down := startReceiver(dc, 1, size)
		up := startReceiver(pc, 2, 0)
		tx := w.startSender(pc, 1, size, 0)
		w.startSender(dc, 2, 0, 0)
		time.Sleep(time.Second) // mid-transfer
		members("during the transfer")
		down.wait(t, time.Minute)
		up.wait(t, time.Minute)
		tx.wait(t, time.Minute)
		members("after the transfer")
		for _, ci := range w.link("b").Carriers() {
			if ci.Session {
				t.Fatalf("b's Link carried a session carrier: %+v", ci)
			}
		}
		ps := pc.Status()
		var carried []rendr.CarrierStatus
		var total uint64
		for _, c := range ps.Carriers {
			if c.TxBytes > 0 {
				carried = append(carried, c)
				total += c.TxBytes
			}
		}
		if len(carried) != 2 || float64(total) < 1.5*size || dc.Status().DupBytes == 0 {
			t.Fatalf("copies: %d carriers of B sent %d bytes for %d (A discarded %d duplicate bytes), want 2 carriers, ≥ 1.5 × and > 0",
				len(carried), total, size, dc.Status().DupBytes)
		}
		t.Logf("B sent %d bytes on carriers %d and %d for %d; A discarded %d duplicate bytes",
			total, carried[0].ID, carried[1].ID, size, dc.Status().DupBytes)
		finish(t, dc, pc)
		w.noViolation()
		w.close()
	})
}
