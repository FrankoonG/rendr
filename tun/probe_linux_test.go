//go:build linux

package tun

import (
	"errors"
	"net"
	"sort"
	"strings"
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

var probeRemoved = func(string) (bool, error) { return true, nil }

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
	capability := probeConfigWithVerifier(Config{Enabled: true, Name: "rendrp%d"}, func(cfg Config) (probeDevice, error) {
		opened = cfg
		return device, nil
	}, probeRemoved)
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
	capability := probeConfigWithVerifier(cfg, func(got Config) (probeDevice, error) {
		if got != cfg {
			t.Fatalf("open config=%+v want %+v", got, cfg)
		}
		return device, nil
	}, probeRemoved)
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
			capability := probeConfigWithVerifier(Config{Enabled: true, MTU: 1400, Queues: 2}, func(Config) (probeDevice, error) {
				return nil, test.err
			}, probeRemoved)
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
			capability := probeConfigWithVerifier(Config{Enabled: true, MTU: 1400, Queues: 2}, func(Config) (probeDevice, error) {
				return test.device, nil
			}, probeRemoved)
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
			assertFailedProbe(t, probeConfigWithVerifier(Config{Enabled: true}, test.open, probeRemoved), virtualif.ReasonTUNUnavailable, nil)
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
			capability := probeConfigWithVerifier(test.cfg, func(Config) (probeDevice, error) {
				opened = true
				return nil, nil
			}, probeRemoved)
			assertFailedProbe(t, capability, test.reason, nil)
			if opened {
				t.Fatal("invalid probe configuration reached the OS opener")
			}
		})
	}
}

func TestProbeConfigClosesPartialDeviceReturnedWithError(t *testing.T) {
	device := &fakeProbeDevice{name: "rendrp-partial", mtu: DefaultMTU, queues: DefaultQueues}
	openErr := syscall.EIO
	capability := probeConfigWithVerifier(Config{Enabled: true}, func(Config) (probeDevice, error) {
		return device, openErr
	}, probeRemoved)
	assertFailedProbe(t, capability, virtualif.ReasonTUNUnavailable, openErr)
	if device.closeCalls != 1 {
		t.Fatalf("partial device close calls=%d want 1", device.closeCalls)
	}
}

func TestProbeConfigRequiresConfirmedInterfaceRemoval(t *testing.T) {
	for _, test := range []struct {
		name string
		gone probeGoneFunc
		want error
	}{
		{name: "interface remains", gone: func(string) (bool, error) { return false, nil }},
		{name: "verification fails", gone: func(string) (bool, error) { return false, syscall.EIO }, want: syscall.EIO},
		{name: "nil verifier"},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := &fakeProbeDevice{name: "rendrp-cleanup", mtu: DefaultMTU, queues: DefaultQueues}
			capability := probeConfigWithVerifier(Config{Enabled: true}, func(Config) (probeDevice, error) {
				return device, nil
			}, test.gone)
			assertFailedProbe(t, capability, virtualif.ReasonTUNUnavailable, test.want)
			if test.gone != nil && device.closeCalls != 1 {
				t.Fatalf("device close calls=%d want 1", device.closeCalls)
			}
		})
	}
}

func TestProbeLeavesNoTemporaryInterfaceWhenAvailable(t *testing.T) {
	before := probeInterfaceNames(t, "rendrp")
	capability := Probe()
	if !capability.Available {
		if capability.Err == nil || capability.Reason == "" {
			t.Fatalf("unavailable capability lacks typed evidence: %+v", capability)
		}
		return
	}
	after := probeInterfaceNames(t, "rendrp")
	if strings.Join(after, "\x00") != strings.Join(before, "\x00") {
		t.Fatalf("Probe leaked a temporary interface: before=%v after=%v", before, after)
	}
}

func probeInterfaceNames(t *testing.T, prefix string) []string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, prefix) {
			names = append(names, iface.Name)
		}
	}
	sort.Strings(names)
	return names
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
