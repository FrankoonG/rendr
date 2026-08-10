//go:build linux

package tun

import (
	"errors"
	"syscall"
	"testing"

	"github.com/FrankoonG/rendr/virtualif"
)

type fakeProbeDevice struct {
	name       string
	mtu        int
	queues     int
	closeErr   error
	closeCalls int
}

func (device *fakeProbeDevice) Close() error {
	device.closeCalls++
	return device.closeErr
}

func (device *fakeProbeDevice) Name() string    { return device.name }
func (device *fakeProbeDevice) MTU() int        { return device.mtu }
func (device *fakeProbeDevice) QueueCount() int { return device.queues }

func TestProbeConfigUsesNormalizedOpenSemantics(t *testing.T) {
	device := &fakeProbeDevice{name: "rendrp7", mtu: DefaultMTU, queues: DefaultQueues}
	var opened Config
	capability := probeConfig(Config{Enabled: true, Name: "rendrp%d"}, func(cfg Config) (probeDevice, error) {
		opened = cfg
		return device, nil
	})
	if !capability.Available || capability.Reason != "" || capability.Err != nil {
		t.Fatalf("capability=%+v want available", capability)
	}
	if opened.Enabled != true || opened.Name != "rendrp%d" || opened.MTU != 0 || opened.Queues != 0 {
		t.Fatalf("open config=%+v want caller config unchanged", opened)
	}
	if device.closeCalls != 1 {
		t.Fatalf("close calls=%d want 1", device.closeCalls)
	}
}

func TestProbeConfigHonorsRequestedMTUAndMultiQueue(t *testing.T) {
	cfg := Config{Enabled: true, Name: "rendrmq%d", MTU: 1400, Queues: 3}
	device := &fakeProbeDevice{name: "rendrmq9", mtu: cfg.MTU, queues: cfg.Queues}
	capability := probeConfig(cfg, func(got Config) (probeDevice, error) {
		if got != cfg {
			t.Fatalf("open config=%+v want %+v", got, cfg)
		}
		return device, nil
	})
	if !capability.Available {
		t.Fatalf("capability=%+v want available", capability)
	}
	if device.closeCalls != 1 {
		t.Fatalf("close calls=%d want 1", device.closeCalls)
	}
}

func TestProbeConfigClassifiesOpenBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason virtualif.ErrorReason
	}{
		{name: "setiff-permission", err: probeOpenError("tun setiff", syscall.EPERM), reason: virtualif.ReasonTUNPermissionDenied},
		{name: "setiff-unsupported", err: probeOpenError("tun setiff", syscall.ENOTTY), reason: virtualif.ReasonTUNUnavailable},
		{name: "multiqueue-unsupported", err: probeOpenError("tun setiff multiqueue", syscall.EINVAL), reason: virtualif.ReasonTUNUnavailable},
		{name: "mtu-rejected", err: classifyMTUError(syscall.EINVAL), reason: virtualif.ReasonInvalidMTU},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capability := probeConfig(Config{Enabled: true, MTU: 1400, Queues: 2}, func(Config) (probeDevice, error) {
				return nil, test.err
			})
			assertFailedProbe(t, capability, test.reason, test.err)
		})
	}
}

func TestProbeConfigRejectsSemanticMismatchAndCleanupFailure(t *testing.T) {
	tests := []struct {
		name   string
		device *fakeProbeDevice
	}{
		{name: "empty-name", device: &fakeProbeDevice{mtu: 1400, queues: 2}},
		{name: "mtu-mismatch", device: &fakeProbeDevice{name: "rendrp1", mtu: 1399, queues: 2}},
		{name: "queue-mismatch", device: &fakeProbeDevice{name: "rendrp1", mtu: 1400, queues: 1}},
		{name: "cleanup-failure", device: &fakeProbeDevice{name: "rendrp1", mtu: 1400, queues: 2, closeErr: syscall.EIO}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capability := probeConfig(Config{Enabled: true, MTU: 1400, Queues: 2}, func(Config) (probeDevice, error) {
				return test.device, nil
			})
			assertFailedProbe(t, capability, virtualif.ReasonTUNUnavailable, nil)
			if test.device.closeCalls != 1 {
				t.Fatalf("close calls=%d want 1", test.device.closeCalls)
			}
		})
	}
}

func TestProbeConfigRejectsNilDependencies(t *testing.T) {
	for _, test := range []struct {
		name string
		open probeOpenFunc
	}{
		{name: "nil-opener"},
		{name: "nil-device", open: func(Config) (probeDevice, error) { return nil, nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertFailedProbe(t, probeConfig(Config{Enabled: true}, test.open), virtualif.ReasonTUNUnavailable, nil)
		})
	}
}

func TestProbeConfigRejectsInvalidConfigBeforeOpen(t *testing.T) {
	for _, test := range []struct {
		name   string
		cfg    Config
		reason virtualif.ErrorReason
	}{
		{name: "disabled", cfg: Config{}, reason: virtualif.ReasonTUNUnavailable},
		{name: "invalid-mtu", cfg: Config{Enabled: true, MTU: MinMTU - 1}, reason: virtualif.ReasonInvalidMTU},
		{name: "invalid-queues", cfg: Config{Enabled: true, Queues: MaxQueues + 1}, reason: virtualif.ReasonInvalidQueueCount},
	} {
		t.Run(test.name, func(t *testing.T) {
			opened := false
			capability := probeConfig(test.cfg, func(Config) (probeDevice, error) {
				opened = true
				return nil, nil
			})
			assertFailedProbe(t, capability, test.reason, nil)
			if opened {
				t.Fatal("invalid probe configuration reached the OS opener")
			}
		})
	}
}

func assertFailedProbe(t testing.TB, capability virtualif.Capability, reason virtualif.ErrorReason, cause error) {
	t.Helper()
	if capability.Available || capability.Reason != reason || capability.Err == nil {
		t.Fatalf("capability=%+v want unavailable reason=%s with error", capability, reason)
	}
	var typed *virtualif.Error
	if !errors.As(capability.Err, &typed) || typed.Reason != reason {
		t.Fatalf("error=%T %v want virtualif.Error reason=%s", capability.Err, capability.Err, reason)
	}
	if cause != nil && !errors.Is(capability.Err, cause) {
		t.Fatalf("error=%v does not preserve cause %v", capability.Err, cause)
	}
}
