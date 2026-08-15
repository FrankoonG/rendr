//go:build linux && amd64

package tcp

import (
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestTCPImplementationProviderIsPresentByDefault(t *testing.T) {
	for name, value := range map[string]any{
		"transport": New(),
		"listener":  &Listener{},
	} {
		provider, ok := value.(leafmobility.ImplementationProvider)
		if !ok {
			t.Fatalf("%s does not expose the TCP_REPAIR implementation provider", name)
		}
		capabilities, err := leafmobility.CapabilitiesForImplementationProvider(provider)
		if err != nil {
			t.Fatalf("%s implementation capabilities: %v", name, err)
		}
		if len(capabilities) != 1 || capabilities[0].Operation() != leafmobility.OperationTCPRepair {
			t.Fatalf("%s implementation capabilities=%v, want TCP_REPAIR only", name, capabilities)
		}
	}
}
