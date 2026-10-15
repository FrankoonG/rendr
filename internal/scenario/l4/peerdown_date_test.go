package l4

import (
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestPeerDownAfterKillDatedByPassive (PA-86; f8race review): the churn's
// rstLostByKill takes a dialer peer_down for the passive's report of a
// Link kill only when the passive's own record of the same carrier's death
// is the kill's transport_error, dated no later than the peer_down — the
// other end's primary cause, not the instant of the kill (a peer_down
// after the kill but before the passive's own death record is not its
// report). When the passive recorded no death of that carrier (DOWN is
// trunk-level: the trunk's last view may have ended before the kill), the
// peer_down is dated against the kill. The rows: the peer_down after, at
// and before the passive's transport_error; no passive record, the
// peer_down after, at or before the kill; only a record of another
// carrier; a passive record that is itself a peer_down; and a dialer
// record that is no peer_down.
func TestPeerDownAfterKillDatedByPassive(t *testing.T) {
	kill := time.Unix(1000, 0)
	at := func(ms int) time.Time { return kill.Add(time.Duration(ms) * time.Millisecond) }
	down := func(id rendr.CarrierID, c rendr.Cause, ms int) rendr.Event {
		return rendr.Event{Kind: rendr.EventCarrierDown, Carrier: id, Cause: c, Time: at(ms)}
	}
	te, pd := rendr.CauseTransportError, rendr.CausePeerDown
	for _, c := range []struct {
		name    string
		ev      rendr.Event
		passive []rendr.Event
		ok      bool
	}{
		{"after the passive's transport_error", down(5, pd, 8), []rendr.Event{down(5, te, 3)}, true},
		{"at the passive's transport_error", down(5, pd, 3), []rendr.Event{down(5, te, 3)}, true},
		{"one of several passive records", down(5, pd, 8), []rendr.Event{down(5, te, 9), down(5, te, 4)}, true},
		{"after the kill, before the passive's transport_error", down(5, pd, 2), []rendr.Event{down(5, te, 3)}, false},
		{"no passive record, after the kill", down(5, pd, 8), nil, true},
		{"no passive record, at the kill", down(5, pd, 0), nil, true},
		{"no passive record, before the kill", down(5, pd, -1), nil, false},
		{"only a passive record of another carrier", down(5, pd, 8), []rendr.Event{down(6, te, 30)}, true},
		{"the passive's record is a peer_down", down(5, pd, 8), []rendr.Event{down(5, pd, 3)}, false},
		{"the dialer's record is a transport_error", down(5, te, 8), []rendr.Event{down(5, te, 3)}, false},
		{"the dialer's record is a transport_error, no passive record", down(5, te, 8), nil, false},
	} {
		if got := peerDownAfterKill(c.ev, c.passive, kill); got != c.ok {
			t.Errorf("%s: peerDownAfterKill = %v, want %v", c.name, got, c.ok)
		}
	}
}
