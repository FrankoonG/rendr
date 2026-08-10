package tun

import (
	"errors"
	"testing"

	"github.com/FrankoonG/rendr/virtualif"
)

func TestConfigNormalizeAndValidate(t *testing.T) {
	cfg := Config{Enabled: true}
	got := cfg.Normalize()
	if got.MTU != DefaultMTU {
		t.Fatalf("default MTU=%d want %d", got.MTU, DefaultMTU)
	}
	if got.Queues != DefaultQueues {
		t.Fatalf("default queues=%d want %d", got.Queues, DefaultQueues)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidateRejectsInvalidQueueCount(t *testing.T) {
	for _, queues := range []int{-1, MaxQueues + 1} {
		err := Config{Enabled: true, Queues: queues}.Validate()
		var ve *virtualif.Error
		if !errors.As(err, &ve) || ve.Reason != virtualif.ReasonInvalidQueueCount {
			t.Fatalf("queues=%d error=%T %v", queues, err, err)
		}
	}
}

func TestConfigValidateRejectsSmallMTU(t *testing.T) {
	for _, mtu := range []int{MinMTU - 1, MaxMTU + 1} {
		err := Config{Enabled: true, MTU: mtu}.Validate()
		var ve *virtualif.Error
		if !errors.As(err, &ve) {
			t.Fatalf("mtu=%d got %T %v, want virtualif.Error", mtu, err, err)
		}
		if ve.Reason != virtualif.ReasonInvalidMTU {
			t.Fatalf("mtu=%d reason=%s want %s", mtu, ve.Reason, virtualif.ReasonInvalidMTU)
		}
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
