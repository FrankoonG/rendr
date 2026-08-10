//go:build !linux

package udpsocket

import (
	"context"
	"testing"

	"github.com/FrankoonG/rendr/internal/platform"
)

func TestNonLinuxNeverAllowsGSO(t *testing.T) {
	if platformGSOAllowed() {
		t.Fatal("non-Linux build allowed UDP GSO treatment")
	}
}

func TestNonLinuxPolicyForcesOrdinary(t *testing.T) {
	selected, err := detectPolicyWith(context.Background(), func(context.Context) (platform.KernelFeatures, error) {
		return platform.KernelFeatures{}, nil
	}, platformGSOAllowed())
	if err != nil {
		t.Fatal(err)
	}
	if selected.treatment != treatmentOrdinary || selected.cause != causePlatformUnsupported {
		t.Fatalf("policy=%+v", selected)
	}
}
