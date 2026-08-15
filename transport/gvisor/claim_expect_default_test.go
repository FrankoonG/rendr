//go:build linux && amd64 && !rendr_experimental_gvisor

package gvisor

import (
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func expectedPacketLinkOperation() leafmobility.Operation {
	return leafmobility.OperationGVisorLinkRebind
}

func TestDefaultBuildHasProductionGVisorProvider(t *testing.T) {
	for name, value := range map[string]any{
		"dialer":   New(),
		"acceptor": &Listener{},
	} {
		provider, ok := value.(leafmobility.ImplementationProvider)
		if !ok {
			t.Fatalf("default %s %T has no production mobility provider", name, value)
		}
		capabilities, err := leafmobility.CapabilitiesForImplementationProvider(provider)
		if err != nil {
			t.Fatalf("default %s provider: %v", name, err)
		}
		if len(capabilities) != 1 || capabilities[0].Operation() != leafmobility.OperationGVisorLinkRebind {
			t.Fatalf("default %s capabilities=%v", name, capabilities)
		}
	}
}
