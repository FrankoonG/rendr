package tun

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/FrankoonG/rendr/virtualif"
)

func TestConfigNormalizeAndValidate(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/24")},
	}
	got := cfg.Normalize()
	if got.MTU != DefaultMTU {
		t.Fatalf("default MTU=%d want %d", got.MTU, DefaultMTU)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidateRejectsSmallMTU(t *testing.T) {
	err := Config{Enabled: true, MTU: MinMTU - 1}.Validate()
	var ve *virtualif.Error
	if !errors.As(err, &ve) {
		t.Fatalf("got %T %v, want virtualif.Error", err, err)
	}
	if ve.Reason != virtualif.ReasonInvalidMTU {
		t.Fatalf("reason=%s want %s", ve.Reason, virtualif.ReasonInvalidMTU)
	}
}

func TestProbeReturnsMachineReadableCapability(t *testing.T) {
	cap := Probe()
	if cap.Available {
		return
	}
	if cap.Reason == "" {
		t.Fatalf("unavailable probe missing reason: %+v", cap)
	}
	if cap.Err == nil {
		t.Fatalf("unavailable probe missing err: %+v", cap)
	}
	var ve *virtualif.Error
	if !errors.As(cap.Err, &ve) {
		t.Fatalf("probe err=%T %v, want virtualif.Error", cap.Err, cap.Err)
	}
	if ve.Reason != cap.Reason {
		t.Fatalf("probe reason mismatch: cap=%s err=%s", cap.Reason, ve.Reason)
	}
}
