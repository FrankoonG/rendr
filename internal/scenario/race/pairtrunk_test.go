package race

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestKillPairTrunkPremise (PA-86; prerc review): killPairTrunk, the
// premise G1 and G2 take at each Link.Kill for killedCause's relaxation,
// is true only for a MUX trunk with a surviving trunk of its pair. One
// world of three Links — p1 with a CheapSubflow factory (dedicated
// carriers), p2 and p3 shared (MUX) — and two race sessions: S1 over p1
// and p2, then S2 over p2 and p3 (another Peer of the same dialer Runtime,
// so the same pair).
//
//   - With S1 alone (the dialer counts one MUX carrier): S1's p2 member is
//     the pair's only trunk, so killing p2 leaves no trunk to carry DOWN
//     (false; without the Mux.Carriers guard it would be true, S1 having a
//     live member on p1); S1's p1 member is dedicated (false).
//   - With S2 too (at least two MUX carriers): S1's p1 member is still
//     dedicated and stays strict although the pair has trunks and S1 a
//     live member on another link (false; without the CheapSubflow guard it
//     would be true); S2's members on p2 and p3 are trunks each with the
//     other's trunk surviving (true).
//   - A second world, two Peers over one Link p1 (two trunks of the pair,
//     both on p1): no trunk survives the kill of p1 (false; without the
//     third conjunct, a live member of the session on another link, it
//     would be true).
//
// G1 and G2 meet only the true case (default factories, two links, two
// live members at each kill), so this row is the guards' test. The third
// conjunct is a conservative stand-in for "a trunk on another link
// survives": when only another session's trunk on another link survives,
// DOWN can still reach the peer and peer_down is legitimate, so the row
// does not pin that case.
func TestKillPairTrunkPremise(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{},
			linkSpec{name: "p1", oneWay: 10 * time.Millisecond, props: rendr.Props{CheapSubflow: true}},
			linkSpec{name: "p2", oneWay: 10 * time.Millisecond},
			linkSpec{name: "p3", oneWay: 10 * time.Millisecond})
		check := func(ds rendr.SessionStatus, name string, want bool, why string) {
			t.Helper()
			if got := w.killPairTrunk(ds, name); got != want {
				t.Errorf("killPairTrunk(%s) = %v, want %v: %s (dialer Mux %+v, live %+v)", name, got, want, why, w.d.Status().Mux, liveOf(ds))
			}
		}
		type session struct{ dc, pc *rendr.Conn }
		open := func(names ...string) session {
			dc, pc := w.open(w.peer(names...), rendr.DialOptions{Mode: rendr.ModeRace})
			waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })
			return session{dc, pc}
		}

		s1 := open("p1", "p2")
		if n := w.d.Status().Mux.Carriers; n != 1 {
			t.Fatalf("stimulus: the dialer counts %d MUX carriers with S1 over p1 (dedicated) and p2, want 1", n)
		}
		ds1 := s1.dc.Status()
		check(ds1, "p2", false, "the pair's only trunk")
		check(ds1, "p1", false, "a dedicated carrier")

		s2 := open("p2", "p3")
		if n := w.d.Status().Mux.Carriers; n < 2 {
			t.Fatalf("stimulus: the dialer counts %d MUX carriers with S2 over p2 and p3, want at least 2", n)
		}
		ds1, ds2 := s1.dc.Status(), s2.dc.Status()
		check(ds1, "p1", false, "a dedicated carrier, though the pair has trunks and S1 a member on p2")
		check(ds2, "p2", true, "a trunk whose pair keeps S2's trunk on p3")
		check(ds2, "p3", true, "a trunk whose pair keeps S2's trunk on p2")

		for i, s := range []session{s1, s2} {
			down, up := startReceiver(s.dc, uint64(2*i+1), 0), startReceiver(s.pc, uint64(2*i+2), 0)
			tx, rx := w.startSender(s.pc, uint64(2*i+1), 0, 0), w.startSender(s.dc, uint64(2*i+2), 0, 0) // FINs only
			down.wait(t, time.Minute)
			up.wait(t, time.Minute)
			tx.wait(t, time.Minute)
			rx.wait(t, time.Minute)
			finish(t, s.dc, s.pc)
		}
		w.noViolation()
		w.close()
	})
	// Two Peers over one Link: two trunks of the pair, both on the killed
	// Link.
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: 10 * time.Millisecond})
		dc1, pc1 := w.open(w.peer("p1"), rendr.DialOptions{})
		dc2, pc2 := w.open(w.peer("p1"), rendr.DialOptions{})
		if n := w.d.Status().Mux.Carriers; n < 2 {
			t.Fatalf("stimulus: the dialer counts %d MUX carriers with two Peers over p1, want 2", n)
		}
		if ds := dc1.Status(); w.killPairTrunk(ds, "p1") {
			t.Errorf("killPairTrunk(p1) = true, want false: every trunk of the pair is on the killed Link (dialer Mux %+v, live %+v)", w.d.Status().Mux, liveOf(ds))
		}
		for i, c := range [][2]*rendr.Conn{{dc1, pc1}, {dc2, pc2}} {
			down, up := startReceiver(c[0], uint64(2*i+1), 0), startReceiver(c[1], uint64(2*i+2), 0)
			tx, rx := w.startSender(c[1], uint64(2*i+1), 0, 0), w.startSender(c[0], uint64(2*i+2), 0, 0)
			down.wait(t, time.Minute)
			up.wait(t, time.Minute)
			tx.wait(t, time.Minute)
			rx.wait(t, time.Minute)
			finish(t, c[0], c[1])
		}
		w.noViolation()
		w.close()
	})
}
