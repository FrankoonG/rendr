package rendr

import "github.com/FrankoonG/rendr/v2/rendrtest"

// Dedicated carriers for the M1/M2 tests whose premise is one carrier per
// session (M3-D2: rendr mux is the default for every factory that is not a
// CheapSubflow). Those tests measure per-session carriers — their count,
// reader stages and goroutines, a session's Done joining its carriers, a
// carrier's own CLOSE drain — so they run on CheapSubflow factories, which
// keep M2's path exactly; their mux counterparts are the WP10 tests
// (TestViewGoneJoin_L52, TestStatusMuxIdentities, TestRuntimeCloseJoinsTrunks_L52,
// TestMuxOpenAfterListenerClose_L50, ...).

// dedicated returns c as a CheapSubflow factory (M2's dedicated carriers).
func dedicated(c StreamCarrier) StreamCarrier {
	c.Props.CheapSubflow = true
	return c
}

// dedicatedPeer is e.peer with every factory a CheapSubflow one.
func (e *e2ePair) dedicatedPeer(links ...*rendrtest.Link) *Peer {
	e.t.Helper()
	if len(links) == 0 {
		links = e.links
	}
	cs := make([]Carrier, len(links))
	for i, l := range links {
		cs[i] = dedicated(e2eCarrier(l))
	}
	p, err := e.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		e.t.Fatalf("NewPeer: %v", err)
	}
	return p
}
