package adversarial

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// switchSlowA is the one-way delay of link "a" from just before the relay's
// switch in TestAdvRelaySwitchLearnsByDown_PA86: the dialer's relay
// connection ends only once the fresh connection's first bytes crossed it
// and the passive's refusal came back, at least this long after the
// passive read the old upstream's end, while a DOWN crosses link "b" in
// 3 ms.
const switchSlowA = 50 * time.Millisecond

// TestAdvRelaySwitchLearnsByDown_PA86 (F-9; PA-86): the "switch" row of
// TestAdvRelaySplice_L43_L69 with the order of the two ends' learning
// fixed instead of raced. Link "a" is slowed to 50 ms one way right before
// the relay switches its upstream: the passive reads the old upstream's
// end at once (its close follows only the bytes already in the link), the
// dialer its own relay connection's end at least 50 ms later (the fresh
// connection's bytes cross the slowed link before the passive refuses
// it). A session whose other member rides a MUX trunk on link "b"
// (mux-bond, mux-race) has a surviving trunk of the pair: the passive's
// DOWN reaches the dialer within that window, and the dialer records
// peer_down, dated no earlier than the passive's transport_error — the
// death record the switch row's former "transport_error on both ends"
// rejected (2 of 3 race-unit passes, 4 of 20 worker runs) and its PA-86
// rule accepts. Without a surviving MUX trunk no DOWN exists: a dedicated
// carrier (selector, bond, race) and a selector's MUX trunk (every session
// on "a") end with transport_error on both ends, the dialer's at least
// 50 ms after the passive's. Every setup: the passive records
// transport_error first, and every session's stream arrives intact.
func TestAdvRelaySwitchLearnsByDown_PA86(t *testing.T) {
	eachSetup(t, func(t *testing.T, s setup) {
		n := rowBytes()
		w := newWorld(t, s, worldOpts{})
		xs := w.openN(w.streamPeer())
		x := xs[0]
		var fs []*sflow
		for i, y := range xs {
			fs = append(fs, startFlow(y.d, y.p, n, 4330+uint64(i)))
		}
		fs[0].reached(t, n/4, "a quarter of the transfer")
		id := target(t, s, x.d.Status())
		tm := w.tamperOf(id)
		var lname string
		for _, c := range liveOf(x.d.Status()) {
			if c.ID == id {
				lname = c.Name
			}
		}
		if lname != "a" {
			t.Fatalf("premise: the attacked carrier %d is on link %q, want a", id, lname)
		}
		survivor := false
		if s.mux {
			for _, c := range liveOf(x.d.Status()) {
				survivor = survivor || c.ID != id && c.Name == "b"
			}
		}
		if survivor != (s.mux && s.members()) {
			t.Fatalf("premise: a live member on b beside the attacked trunk: %v, want %v (%+v)", survivor, s.mux && s.members(), x.d.Status().Carriers)
		}
		l := w.link("a")
		l.SetDelay(switchSlowA, 0)
		switchAt := time.Now()
		tm.SwitchUpstream(func() (net.Conn, error) { return l.Dial(context.Background()) })
		if st := tm.Stats(); st.Switched != 1 {
			t.Fatalf("stimulus: %+v, want one upstream switch", st)
		}
		if pd := endDead(t, "passive", x.p.Status, id); pd.DeathCause != rendr.CauseTransportError {
			t.Fatalf("passive: the switched carrier died of %v %q, want transport_error", pd.DeathCause, pd.DeathDetail)
		}
		pe, de := downOf(t, w.pev, x.p.ID(), id), downOf(t, w.dev, x.d.ID(), id)
		want := rendr.CauseTransportError
		if survivor {
			want = rendr.CausePeerDown
		}
		// The dialer's own end comes at least switchSlowA after the
		// passive's; a DOWN, where one exists, within that window.
		if late := de.Time.Sub(pe.Time); pe.Cause != rendr.CauseTransportError || de.Cause != want || late < 0 || late < switchSlowA != survivor {
			t.Fatalf("the switched carrier's CarrierDown: dialer %v at +%v, passive %v at +%v; want the passive's transport_error, then the dialer's %v %s %v later",
				de.Cause, de.Time.Sub(switchAt), pe.Cause, pe.Time.Sub(switchAt), want, map[bool]string{true: "less than", false: "at least"}[survivor], switchSlowA)
		}
		if dd := endDead(t, "dialer", x.d.Status, id); dd.DeathCause != want {
			t.Fatalf("dialer: the switched carrier's row %+v, want %v", dd, want)
		}
		t.Logf("dialer %v at +%v, passive %v at +%v", de.Cause, de.Time.Sub(switchAt), pe.Cause, pe.Time.Sub(switchAt))
		l.SetDelay(2*time.Millisecond, 0)
		for i, f := range fs {
			f.wait(t, 2*time.Minute, fmt.Sprintf("session %d's transfer across the relay's switch", i))
		}
		w.noViolation()
		for _, y := range xs {
			y.endClean(t)
		}
		w.close()
	})
}
