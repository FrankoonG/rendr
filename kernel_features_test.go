package rendr

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
)

func TestProbeLocalPublishesTypedKernelSnapshotWithoutOptionalCaps(t *testing.T) {
	status, err := ProbeLocal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Kernel.Generation == 0 || status.Kernel.ProbeRevision == 0 || status.Kernel.ProbedAt.IsZero() || status.Kernel.ExpiresAt.IsZero() {
		t.Fatalf("incomplete kernel snapshot: %+v", status.Kernel)
	}
	for _, id := range []KernelFeatureID{
		KernelFeatureTCPRepairPermission,
		KernelFeatureTCPRepairBase,
		KernelFeatureTCPRepairQueueSeq,
		KernelFeatureTCPRepairWindow,
		KernelFeatureTCPRepairOptions,
		KernelFeatureTransparentBindV4,
		KernelFeatureTransparentBindV6,
		KernelFeatureTUNOpen,
		KernelFeatureTUNSetIFF,
		KernelFeatureTUNSingleQueue,
		KernelFeatureTUNMultiQueue,
		KernelFeatureUDPGSO,
		KernelFeatureUDPGRO,
	} {
		feature, ok := status.Kernel.Lookup(id)
		if !ok || feature.State == "" || feature.Reason == "" || feature.Source == "" || feature.ProbedAt.IsZero() {
			t.Fatalf("feature %q is incomplete: %+v", id, feature)
		}
	}
}

func TestKernelFeatureExpiryAtomicallyRemovesAvailability(t *testing.T) {
	features := KernelFeatures{
		Generation:    1,
		ProbeRevision: 1,
		ProbedAt:      time.Unix(10, 0),
		ExpiresAt:     time.Unix(20, 0),
		Features: []KernelFeatureStatus{
			{ID: KernelFeatureTUNOpen, State: KernelFeatureAvailable, Reason: "confirmed", Source: "runtime_syscall", ProbedAt: time.Unix(10, 0)},
			{ID: KernelFeatureUDPGSO, State: KernelFeatureUnsupported, Reason: "primitive_unsupported", Source: "runtime_syscall", ProbedAt: time.Unix(10, 0)},
		},
	}
	snapshot := features.snapshot(time.Unix(21, 0))
	for _, feature := range snapshot.Features {
		if feature.State != KernelFeatureUnprobed || feature.Reason != KernelFeatureReasonExpired || feature.Source != KernelEvidenceCacheExpiry {
			t.Fatalf("expired snapshot retained evidence: %+v", feature)
		}
	}
	if features.Features[0].State != KernelFeatureAvailable {
		t.Fatal("snapshot mutation escaped defensive copy")
	}
}

func TestRuntimeLocalStatusIsDefensiveAndStatusDoesNotReprobe(t *testing.T) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	first := runtime.LocalStatus()
	if len(first.Caps) == 0 || len(first.Kernel.Features) == 0 {
		t.Fatalf("runtime local status is incomplete: %+v", first)
	}
	originalState := first.Kernel.Features[0].State
	first.Caps[0] = "mutated"
	first.Kernel.Features[0].State = KernelFeatureAvailable
	second := runtime.LocalStatus()
	if second.Caps[0] == "mutated" || second.Kernel.Features[0].State != originalState {
		t.Fatalf("caller mutation escaped into Runtime: first=%+v second=%+v", first, second)
	}
	if first.Kernel.Generation != second.Kernel.Generation || !first.Kernel.ProbedAt.Equal(second.Kernel.ProbedAt) {
		t.Fatal("LocalStatus unexpectedly ran another active probe")
	}
}

func TestPublicKernelStatusDoesNotExposeExecutionIdentityOrErrno(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(KernelFeatures{}), reflect.TypeOf(KernelFeatureStatus{})} {
		for _, forbidden := range []string{
			"Errno", "RawErrno", "BootID", "Kernel", "UserNamespace", "NetworkNamespace",
			"MountNamespace", "EffectiveCapabilities", "EffectiveUID", "FilesystemUID", "ContextDigest",
		} {
			if _, ok := typ.FieldByName(forbidden); ok {
				t.Fatalf("public %s exposes internal field %s", typ.Name(), forbidden)
			}
		}
	}
}

func TestRuntimeFallsBackToGenericStatusWhenOptionalProbeFails(t *testing.T) {
	probeErr := errors.New("injected context probe failure")
	runtime, err := newRuntimeContextWithProbe(context.Background(), RuntimeConfig{}, func(context.Context, ...CapabilityID) (LocalStatus, error) {
		return LocalStatus{}, probeErr
	})
	if err != nil {
		t.Fatalf("optional probe prevented generic Runtime: %v", err)
	}
	status := runtime.LocalStatus()
	if !status.Caps.Has(CapRendr) || !status.Caps.Has(CapL7) || !status.Caps.Has(CapPacketMode) {
		t.Fatalf("generic capabilities missing after probe failure: %v", status.Caps)
	}
	for _, feature := range status.Kernel.Features {
		if feature.State != KernelFeatureProbeFailed || feature.Reason != KernelFeatureReasonContextProbeFailed {
			t.Fatalf("optional failure became false green: %+v", feature)
		}
	}
}

func TestRuntimeStatusFailsClosedAcrossExecutionContext(t *testing.T) {
	contextDigest := [32]byte{1}
	runtime := &Runtime{
		contextDigest: contextDigest,
		localStatus: LocalStatus{
			Caps: coreLocalStatus().Caps,
			Kernel: KernelFeatures{
				Generation: 1, ProbeRevision: 1, ProbedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
				contextDigest: contextDigest, invalidationGeneration: platform.InvalidationGeneration(),
				Features: []KernelFeatureStatus{{
					ID: KernelFeatureTUNOpen, State: KernelFeatureAvailable, Reason: "confirmed", Source: "runtime_syscall", ProbedAt: time.Now(),
				}},
			},
		},
	}
	status := runtime.LocalStatus()
	feature, ok := status.Kernel.Lookup(KernelFeatureTUNOpen)
	if !ok || feature.State != KernelFeatureUnprobed || feature.Reason != KernelFeatureReasonContextChanged {
		t.Fatalf("cross-context status=%+v", feature)
	}
}

func TestRuntimeNeverPublishesThreadScopedSeccompEvidence(t *testing.T) {
	contextDigest, err := platform.CurrentRuntimeContextDigest()
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		contextDigest: contextDigest,
		localStatus: LocalStatus{
			Caps: coreLocalStatus().Caps,
			Kernel: KernelFeatures{
				Generation: 1, ProbeRevision: 1, ProbedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
				contextDigest: contextDigest, invalidationGeneration: platform.InvalidationGeneration(), threadScoped: true,
				Features: []KernelFeatureStatus{{
					ID: KernelFeatureTUNOpen, State: KernelFeatureAvailable, Reason: "confirmed", Source: "runtime_syscall", ProbedAt: time.Now(),
				}},
			},
		},
	}
	status := runtime.LocalStatus()
	feature, ok := status.Kernel.Lookup(KernelFeatureTUNOpen)
	if !ok || feature.State != KernelFeatureUnprobed || feature.Reason != KernelFeatureReasonThreadScoped {
		t.Fatalf("seccomp thread-scoped status=%+v", feature)
	}
}

func TestRuntimeInvalidationImmediatelyRevokesPublishedEvidence(t *testing.T) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.invalidateKernelFeature(KernelFeatureTUNOpen); err != nil {
		t.Fatal(err)
	}
	for _, status := range []LocalStatus{runtime.LocalStatus(), other.LocalStatus()} {
		for _, feature := range status.Kernel.Features {
			if feature.State != KernelFeatureUnprobed || feature.Reason != KernelFeatureReasonInvalidated {
				t.Fatalf("invalidation retained evidence: %+v", feature)
			}
		}
	}
}

func TestRuntimeRefreshRetainsContextAndMonotonicGeneration(t *testing.T) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	before := runtime.LocalStatus()
	after, err := runtime.RefreshLocalStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.Kernel.Generation < before.Kernel.Generation {
		t.Fatalf("refresh regressed generation %d -> %d", before.Kernel.Generation, after.Kernel.Generation)
	}
	if runtime.contextDigest != after.Kernel.contextDigest {
		t.Fatal("refresh changed Runtime execution-context binding")
	}
}
