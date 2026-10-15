package rendr

import (
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// TestCausePeerDown_PA86: the cause of a carrier the peer reported dead
// with DOWN (PA-86) is public as CausePeerDown, named "peer_down" in
// CarrierStatus.DeathCause and EventCarrierDown, numerically equal to the
// carrier package's (a plain conversion maps it), a death like a transport
// error, and one after which the carrier sends no DOWN of its own; every
// Runtime builds the trunk index the DOWN path uses.
func TestCausePeerDown_PA86(t *testing.T) {
	if CausePeerDown != 10 || CausePeerDown.String() != "peer_down" || Cause(carrier.CausePeerDown) != CausePeerDown || carrier.CausePeerDown.String() != "peer_down" {
		t.Fatalf("CausePeerDown %d %q, carrier's %d %q", CausePeerDown, CausePeerDown.String(), carrier.CausePeerDown, carrier.CausePeerDown.String())
	}
	if !carrier.CausePeerDown.Death() {
		t.Fatal("peer_down is not a death")
	}
	rt, err := NewRuntime(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if rt.cenv.Trunks == nil {
		t.Fatal("the Runtime has no trunk index: no DOWN would be sent or understood")
	}
}
