//go:build linux && amd64 && !rendr_experimental_tcprepair

package tcp

import (
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestTCPImplementationProviderIsDisabledUntilQualification(t *testing.T) {
	for name, value := range map[string]any{
		"transport": New(),
		"listener":  &Listener{},
	} {
		if _, ok := value.(leafmobility.ImplementationProvider); ok {
			t.Fatalf("%s advertised unqualified TCP_REPAIR mobility", name)
		}
	}
}
