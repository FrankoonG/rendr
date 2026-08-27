//go:build linux && amd64 && !rendr_experimental_tcprepair

package tcp

import (
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestTCPImplementationProviderIsAbsentByDefault(t *testing.T) {
	for name, value := range map[string]any{
		"transport": New(),
		"listener":  &Listener{},
	} {
		if _, ok := value.(leafmobility.ImplementationProvider); ok {
			t.Fatalf("%s unexpectedly exposes the optional TCP_REPAIR implementation", name)
		}
	}

	claim := newOwnedClaim(nil, leafmobility.RoleDialer)
	facts := claim.Snapshot()
	if facts.Kind != leafmobility.KindRawTCP || facts.Role != leafmobility.RoleDialer ||
		facts.Scope != leafmobility.ScopeEndpoint || facts.Generation == 0 {
		t.Fatalf("default owned claim facts=%+v", facts)
	}
	if facts.Operations != 0 {
		t.Fatalf("default owned claim operations=%#x, want no specialized driver", facts.Operations)
	}
}
