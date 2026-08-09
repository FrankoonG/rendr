//go:build linux

package platform

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLinuxKernelMajor(t *testing.T) {
	tests := []struct {
		release string
		major   int
		ok      bool
	}{
		{release: "5.0.0", major: 5, ok: true},
		{release: "6.8.0-111-generic", major: 6, ok: true},
		{release: "10.1-custom", major: 10, ok: true},
		{release: "", ok: false},
		{release: "linux-6.8", ok: false},
		{release: "6", ok: false},
		{release: "1001.0", ok: false},
	}
	for _, test := range tests {
		t.Run(test.release, func(t *testing.T) {
			major, ok := linuxKernelMajor(test.release)
			if major != test.major || ok != test.ok {
				t.Fatalf("linuxKernelMajor(%q)=(%d,%v), want (%d,%v)", test.release, major, ok, test.major, test.ok)
			}
		})
	}
}

func TestSystemDetectorTUNResourceSlope(t *testing.T) {
	if os.Getenv("RENDR_EXPECT_TUN") != "available" {
		t.Skip("privileged TUN expectation is unset")
	}
	detector, err := newSystemDetector()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := detector.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	baseFDs := countProcessFDs(t)
	baseGoroutines := runtime.NumGoroutine()
	for range 200 {
		if err := detector.Invalidate(FeatureTUNOpen); err != nil {
			t.Fatal(err)
		}
		if _, err := detector.Current(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	if got := countProcessFDs(t); got > baseFDs+2 {
		t.Fatalf("fd slope: before=%d after=%d", baseFDs, got)
	}
	if got := runtime.NumGoroutine(); got > baseGoroutines+1 {
		t.Fatalf("goroutine slope: before=%d after=%d", baseGoroutines, got)
	}
	interfaces, err := netInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range interfaces {
		if strings.HasPrefix(name, "rndr") {
			t.Fatalf("temporary interface leaked: %s", name)
		}
	}
}

func countProcessFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func netInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names, nil
}

func TestSystemDetectorTUNExpectation(t *testing.T) {
	expectation := os.Getenv("RENDR_EXPECT_TUN")
	if expectation == "" {
		t.Skip("RENDR_EXPECT_TUN is unset")
	}
	detector, err := newSystemDetector()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	open := requireFeature(t, snapshot, FeatureTUNOpen)
	setIFF := requireFeature(t, snapshot, FeatureTUNSetIFF)
	single := requireFeature(t, snapshot, FeatureTUNSingleQueue)
	multi := requireFeature(t, snapshot, FeatureTUNMultiQueue)
	switch expectation {
	case "available":
		for _, evidence := range []FeatureEvidence{open, setIFF, single, multi} {
			if evidence.State != FeatureAvailable {
				t.Fatalf("%s=%s/%s, want available", evidence.ID, evidence.State, evidence.Reason)
			}
		}
	case "permission_denied":
		if open.State != FeatureAvailable {
			t.Fatalf("TUN open=%s/%s, want available character device", open.State, open.Reason)
		}
		if setIFF.State != FeaturePermissionDenied {
			t.Fatalf("TUNSETIFF=%s/%s, want permission_denied", setIFF.State, setIFF.Reason)
		}
		if single.State == FeatureAvailable || multi.State == FeatureAvailable {
			t.Fatalf("unprivileged queue evidence single=%s multi=%s", single.State, multi.State)
		}
	default:
		t.Fatalf("unknown RENDR_EXPECT_TUN value %q", expectation)
	}
}

func TestSystemDetectorTCPRepairExpectation(t *testing.T) {
	expectation := os.Getenv("RENDR_EXPECT_TCPREPAIR")
	if expectation == "" {
		t.Skip("RENDR_EXPECT_TCPREPAIR is unset")
	}
	detector, err := newSystemDetector()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	permission := requireFeature(t, snapshot, FeatureTCPRepairPermission)
	base := requireFeature(t, snapshot, FeatureTCPRepairBase)
	queue := requireFeature(t, snapshot, FeatureTCPRepairQueueSeq)
	window := requireFeature(t, snapshot, FeatureTCPRepairWindow)
	options := requireFeature(t, snapshot, FeatureTCPRepairOptions)
	switch expectation {
	case "available":
		for _, evidence := range []FeatureEvidence{permission, base, queue, window, options} {
			if evidence.State != FeatureAvailable {
				t.Fatalf("%s=%s/%s, want available", evidence.ID, evidence.State, evidence.Reason)
			}
		}
	case "permission_denied":
		for _, evidence := range []FeatureEvidence{permission, base} {
			if evidence.State != FeaturePermissionDenied {
				t.Fatalf("%s=%s/%s, want permission_denied", evidence.ID, evidence.State, evidence.Reason)
			}
		}
		for _, evidence := range []FeatureEvidence{queue, window, options} {
			if evidence.State != FeatureUnprobed {
				t.Fatalf("dependent %s=%s/%s, want unprobed", evidence.ID, evidence.State, evidence.Reason)
			}
		}
	default:
		t.Fatalf("unknown RENDR_EXPECT_TCPREPAIR value %q", expectation)
	}
}

func TestSystemDetectorTransparentBindExpectation(t *testing.T) {
	expectation := os.Getenv("RENDR_EXPECT_TRANSPARENT_BIND")
	if expectation == "" {
		t.Skip("RENDR_EXPECT_TRANSPARENT_BIND is unset")
	}
	detector, err := newSystemDetector()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v4 := requireFeature(t, snapshot, FeatureTransparentBindV4)
	v6 := requireFeature(t, snapshot, FeatureTransparentBindV6)
	switch expectation {
	case "available":
		for _, evidence := range []FeatureEvidence{v4, v6} {
			if evidence.State != FeatureAvailable {
				t.Fatalf("%s=%s/%s, want available", evidence.ID, evidence.State, evidence.Reason)
			}
		}
	case "permission_denied":
		for _, evidence := range []FeatureEvidence{v4, v6} {
			if evidence.State != FeaturePermissionDenied {
				t.Fatalf("%s=%s/%s, want permission_denied", evidence.ID, evidence.State, evidence.Reason)
			}
		}
	default:
		t.Fatalf("unknown RENDR_EXPECT_TRANSPARENT_BIND value %q", expectation)
	}
}

func TestSystemDetectorUDPOffloadExpectation(t *testing.T) {
	if os.Getenv("RENDR_EXPECT_UDP_OFFLOAD") != "available" {
		t.Skip("UDP offload expectation is unset")
	}
	detector, err := newSystemDetector()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []FeatureID{FeatureUDPGSO, FeatureUDPGRO} {
		evidence := requireFeature(t, snapshot, id)
		if evidence.State != FeatureAvailable || evidence.Source != SourceRuntimeRoundTrip {
			t.Fatalf("%s=%s/%s source=%s, want active available", id, evidence.State, evidence.Reason, evidence.Source)
		}
	}
}

func TestAcquireExecutionContextIncludesSecurityBoundary(t *testing.T) {
	unlock := lockExecutionThread()
	defer unlock()
	lease, err := acquireExecutionContext()
	if err != nil {
		t.Fatal(err)
	}
	identity := lease.Identity
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := identity.validate(); err != nil {
		t.Fatal(err)
	}
	if digestExecutionContext(identity) == ([32]byte{}) {
		t.Fatal("execution-context digest is zero")
	}
}

func requireFeature(t *testing.T, snapshot KernelFeatures, id FeatureID) FeatureEvidence {
	t.Helper()
	evidence, ok := snapshot.Feature(id)
	if !ok {
		t.Fatalf("snapshot has no %s evidence", id)
	}
	return evidence
}

func TestSystemProberRejectsKernelBelowFiveWithoutActiveProbe(t *testing.T) {
	identity := testExecutionContext("caps")
	identity.Kernel.Release = "4.19.0"
	at := time.Unix(100, 0).UTC()
	evidence, err := (systemProber{}).Probe(context.Background(), identity, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != len(knownFeatureIDs) {
		t.Fatalf("evidence count=%d", len(evidence))
	}
	for _, result := range evidence {
		if result.State != FeatureUnsupported || result.Reason != ReasonKernelBelowMinimum || result.Source != SourcePlatformBoundary {
			t.Fatalf("below-floor evidence=%+v", result)
		}
	}
}
