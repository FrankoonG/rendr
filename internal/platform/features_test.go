package platform

import (
	"syscall"
	"testing"
	"time"
)

func TestKernelFeaturesDefaultsMissingObservationsToUnprobed(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	identity := testExecutionContext("caps-a")
	available, err := NewEvidence(FeatureUDPGSO, FeatureAvailable, ReasonConfirmed, at, SourceRuntimeRoundTrip, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := newKernelFeatures(identity, at, time.Minute, 1, 0, []FeatureEvidence{available})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := snapshot.Feature(FeatureUDPGSO); !ok || got.State != FeatureAvailable {
		t.Fatalf("GSO evidence=%+v", got)
	}
	if got, ok := snapshot.Feature(FeatureTCPRepairBase); !ok || got.State != FeatureUnprobed || got.Reason != ReasonNotProbed {
		t.Fatalf("missing evidence=%+v, want unprobed", got)
	}
	if got := len(snapshot.All()); got != len(knownFeatureIDs) {
		t.Fatalf("feature count=%d want %d", got, len(knownFeatureIDs))
	}
	if snapshot.ContextDigest == ([32]byte{}) || snapshot.ProbeRevision != ProbeRevision {
		t.Fatalf("snapshot lacks context identity: %+v", snapshot)
	}
}

func TestAvailableEvidenceRequiresActiveConfirmation(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	tests := []struct {
		name      string
		reason    FeatureReason
		source    EvidenceSource
		errno     syscall.Errno
		retryable bool
	}{
		{name: "wrong reason", reason: ReasonSyscallFailed, source: SourceRuntimeSyscall},
		{name: "version metadata", reason: ReasonConfirmed, source: SourcePlatformBoundary},
		{name: "latent errno", reason: ReasonConfirmed, source: SourceRuntimeSyscall, errno: syscall.EPERM},
		{name: "retryable success", reason: ReasonConfirmed, source: SourceRuntimeSyscall, retryable: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewEvidence(FeatureTCPRepairBase, FeatureAvailable, test.reason, at, test.source, test.errno, test.retryable); err == nil {
				t.Fatal("contradictory available evidence accepted")
			}
		})
	}
}

func TestSnapshotRejectsDuplicateEvidence(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	evidence, err := NewEvidence(FeatureTUNOpen, FeatureUnsupported, ReasonPlatformUnsupported, at, SourcePlatformBoundary, syscall.ENODEV, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newKernelFeatures(testExecutionContext("caps-a"), at, time.Minute, 1, 0, []FeatureEvidence{evidence, evidence}); err == nil {
		t.Fatal("duplicate evidence accepted")
	}
}

func TestRuntimeContextDigestIgnoresThreadShardButNotSecurityBoundary(t *testing.T) {
	base := testExecutionContext("caps-a")
	otherThread := base
	otherThread.ThreadID = "99"
	otherThread.ThreadStartTime = "12345"
	if digestExecutionContext(base) == digestExecutionContext(otherThread) {
		t.Fatal("cache digest ignored seccomp thread shard")
	}
	if digestRuntimeExecutionContext(base) != digestRuntimeExecutionContext(otherThread) {
		t.Fatal("Runtime digest was bound to scheduler thread")
	}
	otherNamespace := base
	otherNamespace.NetworkNamespace = "net:other"
	if digestRuntimeExecutionContext(base) == digestRuntimeExecutionContext(otherNamespace) {
		t.Fatal("Runtime digest ignored network namespace")
	}
}

func testExecutionContext(capabilities string) ExecutionContext {
	return ExecutionContext{
		OS:                    "linux",
		Arch:                  "amd64",
		BootID:                "boot-a",
		Kernel:                KernelIdentity{System: "Linux", Release: "6.8.0", Version: "test", Machine: "x86_64"},
		UserNamespace:         "user:1",
		NetworkNamespace:      "net:2",
		MountNamespace:        "mnt:3",
		EffectiveCapabilities: capabilities,
		EffectiveUID:          "0",
		FilesystemUID:         "0",
		EffectiveGID:          "0",
		FilesystemGID:         "0",
		Groups:                "0",
		NoNewPrivileges:       "0",
		SeccompMode:           "0",
		SeccompFilters:        "0",
		ThreadID:              "process",
		ThreadStartTime:       "process",
		SecurityLabel:         "unconfined",
		ProbeRevision:         ProbeRevision,
	}
}
