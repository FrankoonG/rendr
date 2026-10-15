package race

import (
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestKilledCauseOnlyOnPairTrunks (PA-86; f8race review): killedCause, the
// judge of a Link.Kill's two death records in the G1 and G2 miniatures,
// accepts one end's peer_down only when the killed member is a MUX trunk
// with a surviving trunk of its pair (pairTrunk), dated no earlier than
// the other end's transport_error. A dedicated carrier (or a trunk whose
// pair has no other live trunk) has no DOWN to learn from: both ends must
// record transport_error. Without the pairTrunk guard the dedicated
// peer_down rows pass; without the dating the early peer_down row passes.
func TestKilledCauseOnlyOnPairTrunks(t *testing.T) {
	t0 := time.Unix(1000, 0)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	down := func(c rendr.Cause, ms int) rendr.Event {
		return rendr.Event{Kind: rendr.EventCarrierDown, Carrier: 7, Cause: c, Time: at(ms)}
	}
	te, pd := rendr.CauseTransportError, rendr.CausePeerDown
	for _, c := range []struct {
		name string
		evs  [2]rendr.Event // the dialer's, the passive's
		pair bool
		ok   bool
	}{
		{"dedicated: transport_error on both ends", [2]rendr.Event{down(te, 0), down(te, 1)}, false, true},
		{"pair trunk: transport_error on both ends", [2]rendr.Event{down(te, 0), down(te, 1)}, true, true},
		{"pair trunk: the dialer learns by DOWN", [2]rendr.Event{down(pd, 5), down(te, 1)}, true, true},
		{"pair trunk: the passive learns by DOWN", [2]rendr.Event{down(te, 1), down(pd, 5)}, true, true},
		{"pair trunk: peer_down at the other end's instant", [2]rendr.Event{down(pd, 1), down(te, 1)}, true, true},
		{"dedicated: the dialer records peer_down", [2]rendr.Event{down(pd, 5), down(te, 1)}, false, false},
		{"dedicated: the passive records peer_down", [2]rendr.Event{down(te, 1), down(pd, 5)}, false, false},
		{"pair trunk: peer_down before the other end's death", [2]rendr.Event{down(pd, 1), down(te, 5)}, true, false},
		{"pair trunk: peer_down on both ends", [2]rendr.Event{down(pd, 5), down(pd, 6)}, true, false},
		{"pair trunk: a silent death", [2]rendr.Event{down(rendr.CausePingTimeout, 5), down(te, 1)}, true, false},
	} {
		if bad := killedCause(c.evs, c.pair); (bad == "") != c.ok {
			t.Errorf("%s: killedCause = %q, want accepted %v", c.name, bad, c.ok)
		}
	}
}
