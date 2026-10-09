package rendr

import (
	"context"
	"net"
	"testing"
)

// TestMuxFactoriesHavePool (WP7/WP9 contract, §A2.3 Established.Fresh): a
// carrier dialled with Factory.Mux offers OptMux, and a fresh MUX trunk
// needs the pool that publishes it. A Peer therefore has a pool exactly
// when one of its factories is mux-eligible, and every session attempt of
// such a Peer goes through it (session.DialSpec.Pool); a Peer whose
// factories are all CheapSubflow keeps M2's direct Establish with
// Factory.Mux false. Health probes never offer OptMux (PING first frame).
func TestMuxFactoriesHavePool(t *testing.T) {
	rt, err := NewRuntime(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	dial := func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }
	for _, tc := range []struct {
		name  string
		cheap []bool
	}{
		{"one shared", []bool{false}},
		{"one cheap", []bool{true}},
		{"mixed", []bool{true, false}},
		{"all cheap", []bool{true, true}},
		{"all shared", []bool{false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cs []Carrier
			for i, cheap := range tc.cheap {
				c := StreamCarrier{Name: string(rune('a' + i)), Dial: dial}
				c.Props.CheapSubflow = cheap
				cs = append(cs, c)
			}
			p, err := rt.NewPeer(PeerConfig{Carriers: cs})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			anyMux := false
			for i, f := range p.factories {
				if f.Mux == tc.cheap[i] {
					t.Fatalf("factory %d: Mux %v with CheapSubflow %v", i, f.Mux, tc.cheap[i])
				}
				anyMux = anyMux || f.Mux
			}
			if (p.pool != nil) != anyMux {
				t.Fatalf("pool %v with a mux-eligible factory %v", p.pool != nil, anyMux)
			}
			if spec := p.spec(SessionID{1}, DialOptions{}, false); spec.Pool != p.pool {
				t.Fatal("the Dial spec does not carry the Peer's pool")
			}
		})
	}
}
