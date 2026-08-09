// Package platform records actively observed operating-system capabilities.
// Process-wide evidence here never substitutes for per-endpoint eligibility.
package platform

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"
)

// ProbeRevision invalidates cached evidence when probe semantics change.
const ProbeRevision uint32 = 1

// FeatureID is a stable internal identity for one independently probed
// platform primitive.
type FeatureID string

const (
	FeatureTCPRepairPermission FeatureID = "tcp_repair_permission"
	FeatureTCPRepairBase       FeatureID = "tcp_repair_base"
	FeatureTCPRepairQueueSeq   FeatureID = "tcp_repair_queue_seq"
	FeatureTCPRepairWindow     FeatureID = "tcp_repair_window"
	FeatureTCPRepairOptions    FeatureID = "tcp_repair_options"
	FeatureTransparentBindV4   FeatureID = "transparent_bind_v4"
	FeatureTransparentBindV6   FeatureID = "transparent_bind_v6"
	FeatureTUNOpen             FeatureID = "tun_open"
	FeatureTUNSetIFF           FeatureID = "tun_set_iff"
	FeatureTUNSingleQueue      FeatureID = "tun_single_queue"
	FeatureTUNMultiQueue       FeatureID = "tun_multi_queue"
	FeatureUDPGSO              FeatureID = "udp_gso"
	FeatureUDPGRO              FeatureID = "udp_gro"
)

var knownFeatureIDs = [...]FeatureID{
	FeatureTCPRepairPermission,
	FeatureTCPRepairBase,
	FeatureTCPRepairQueueSeq,
	FeatureTCPRepairWindow,
	FeatureTCPRepairOptions,
	FeatureTransparentBindV4,
	FeatureTransparentBindV6,
	FeatureTUNOpen,
	FeatureTUNSetIFF,
	FeatureTUNSingleQueue,
	FeatureTUNMultiQueue,
	FeatureUDPGSO,
	FeatureUDPGRO,
}

func (id FeatureID) valid() bool {
	for _, known := range knownFeatureIDs {
		if id == known {
			return true
		}
	}
	return false
}

// FeatureState distinguishes confirmed support from every form of missing or
// incomplete evidence. Unknown and failed probes are never treated as support.
type FeatureState string

const (
	FeatureAvailable        FeatureState = "available"
	FeatureUnsupported      FeatureState = "unsupported"
	FeaturePermissionDenied FeatureState = "permission_denied"
	FeatureUnprobed         FeatureState = "unprobed"
	FeatureProbeFailed      FeatureState = "probe_failed"
)

func (state FeatureState) valid() bool {
	switch state {
	case FeatureAvailable, FeatureUnsupported, FeaturePermissionDenied, FeatureUnprobed, FeatureProbeFailed:
		return true
	default:
		return false
	}
}

// FeatureReason is stable enough for planning and regression assertions. Raw
// errno remains diagnostic evidence rather than policy.
type FeatureReason string

const (
	ReasonConfirmed            FeatureReason = "confirmed"
	ReasonNotProbed            FeatureReason = "not_probed"
	ReasonPlatformUnsupported  FeatureReason = "platform_unsupported"
	ReasonKernelBelowMinimum   FeatureReason = "kernel_below_minimum"
	ReasonPermissionDenied     FeatureReason = "permission_denied"
	ReasonPrimitiveUnsupported FeatureReason = "primitive_unsupported"
	ReasonDeviceUnavailable    FeatureReason = "device_unavailable"
	ReasonResourceExhausted    FeatureReason = "resource_exhausted"
	ReasonSyscallFailed        FeatureReason = "syscall_failed"
	ReasonSemanticMismatch     FeatureReason = "semantic_mismatch"
)

// EvidenceSource identifies how a fact was established. Version metadata is
// intentionally not a source of positive feature evidence.
type EvidenceSource string

const (
	SourceNotRun           EvidenceSource = "not_run"
	SourcePlatformBoundary EvidenceSource = "platform_boundary"
	SourceRuntimeSyscall   EvidenceSource = "runtime_syscall"
	SourceRuntimeRoundTrip EvidenceSource = "runtime_round_trip"
)

// FeatureEvidence is one immutable observation. errno is intentionally
// private; policy must branch on State and Reason, not OS-specific numbers.
type FeatureEvidence struct {
	ID        FeatureID
	State     FeatureState
	Reason    FeatureReason
	ProbedAt  time.Time
	Source    EvidenceSource
	Retryable bool
	errno     syscall.Errno
}

// NewEvidence constructs validated feature evidence for a platform prober.
func NewEvidence(id FeatureID, state FeatureState, reason FeatureReason, at time.Time, source EvidenceSource, errno syscall.Errno, retryable bool) (FeatureEvidence, error) {
	evidence := FeatureEvidence{
		ID:        id,
		State:     state,
		Reason:    reason,
		ProbedAt:  at,
		Source:    source,
		Retryable: retryable,
		errno:     errno,
	}
	if err := evidence.validate(); err != nil {
		return FeatureEvidence{}, err
	}
	return evidence, nil
}

// RawErrno returns internal diagnostic evidence. It must not be serialized
// into public status or used as a policy identity.
func (e FeatureEvidence) RawErrno() syscall.Errno { return e.errno }

func (e FeatureEvidence) validate() error {
	if !e.ID.valid() {
		return fmt.Errorf("platform: unknown feature %q", e.ID)
	}
	if !e.State.valid() {
		return fmt.Errorf("platform: feature %q has invalid state %q", e.ID, e.State)
	}
	if e.Reason == "" {
		return fmt.Errorf("platform: feature %q has no stable reason", e.ID)
	}
	if e.ProbedAt.IsZero() {
		return fmt.Errorf("platform: feature %q has no observation time", e.ID)
	}
	if e.Source == "" {
		return fmt.Errorf("platform: feature %q has no evidence source", e.ID)
	}
	if e.State == FeatureAvailable {
		if e.Reason != ReasonConfirmed {
			return fmt.Errorf("platform: available feature %q is not confirmed", e.ID)
		}
		if e.Source != SourceRuntimeSyscall && e.Source != SourceRuntimeRoundTrip {
			return fmt.Errorf("platform: available feature %q lacks active evidence", e.ID)
		}
		if e.errno != 0 || e.Retryable {
			return fmt.Errorf("platform: available feature %q carries contradictory failure evidence", e.ID)
		}
	}
	if e.State == FeaturePermissionDenied && e.Reason != ReasonPermissionDenied {
		return fmt.Errorf("platform: denied feature %q has reason %q", e.ID, e.Reason)
	}
	if e.State == FeaturePermissionDenied && e.errno != syscall.EPERM && e.errno != syscall.EACCES {
		return fmt.Errorf("platform: denied feature %q lacks permission errno", e.ID)
	}
	if e.State == FeatureUnsupported {
		switch e.Reason {
		case ReasonPlatformUnsupported, ReasonKernelBelowMinimum, ReasonPrimitiveUnsupported, ReasonDeviceUnavailable:
		default:
			return fmt.Errorf("platform: unsupported feature %q has reason %q", e.ID, e.Reason)
		}
	}
	if e.State == FeatureUnprobed && (e.Reason != ReasonNotProbed || e.Source != SourceNotRun || e.errno != 0 || e.Retryable) {
		return fmt.Errorf("platform: unprobed feature %q has contradictory evidence", e.ID)
	}
	if e.State == FeatureProbeFailed {
		switch e.Reason {
		case ReasonSyscallFailed, ReasonSemanticMismatch, ReasonResourceExhausted:
		default:
			return fmt.Errorf("platform: failed feature %q has reason %q", e.ID, e.Reason)
		}
		if e.Reason == ReasonResourceExhausted && !e.Retryable {
			return fmt.Errorf("platform: exhausted feature %q is not retryable", e.ID)
		}
	}
	return nil
}

// KernelIdentity is diagnostic and cache identity only. It never grants a
// feature by version lookup.
type KernelIdentity struct {
	System  string
	Release string
	Version string
	Machine string
}

// ExecutionContext is the complete cache identity for permission-sensitive
// probes. Namespace, credentials, sandbox, boot, or probe revisions miss cache.
type ExecutionContext struct {
	OS                    string
	Arch                  string
	BootID                string
	Kernel                KernelIdentity
	UserNamespace         string
	NetworkNamespace      string
	MountNamespace        string
	EffectiveCapabilities string
	EffectiveUID          string
	FilesystemUID         string
	EffectiveGID          string
	FilesystemGID         string
	Groups                string
	NoNewPrivileges       string
	SeccompMode           string
	SeccompFilters        string
	ThreadID              string
	ThreadStartTime       string
	SecurityLabel         string
	ProbeRevision         uint32
}

func (identity ExecutionContext) validate() error {
	if identity.OS == "" || identity.Arch == "" || identity.ProbeRevision == 0 {
		return fmt.Errorf("platform: incomplete operating-system identity")
	}
	if identity.OS == "linux" {
		if identity.BootID == "" || identity.Kernel.Release == "" || identity.UserNamespace == "" ||
			identity.NetworkNamespace == "" || identity.MountNamespace == "" || identity.EffectiveCapabilities == "" ||
			identity.EffectiveUID == "" || identity.FilesystemUID == "" || identity.EffectiveGID == "" ||
			identity.FilesystemGID == "" || identity.Groups == "" || identity.NoNewPrivileges == "" ||
			identity.SeccompMode == "" || identity.SeccompFilters == "" || identity.ThreadID == "" ||
			identity.ThreadStartTime == "" || identity.SecurityLabel == "" {
			return fmt.Errorf("platform: incomplete Linux execution context")
		}
	}
	return nil
}

// KernelFeatures is an immutable active-probe snapshot for one exact
// ExecutionContext.
type KernelFeatures struct {
	Identity               ExecutionContext
	ContextDigest          [32]byte
	RuntimeContextDigest   [32]byte
	Generation             uint64
	InvalidationGeneration uint64
	ProbeRevision          uint32
	ProbedAt               time.Time
	ExpiresAt              time.Time
	probedClock            time.Time
	expiresClock           time.Time
	features               map[FeatureID]FeatureEvidence
}

func newKernelFeatures(identity ExecutionContext, at time.Time, ttl time.Duration, generation, invalidationGeneration uint64, observations []FeatureEvidence) (KernelFeatures, error) {
	if err := identity.validate(); err != nil {
		return KernelFeatures{}, err
	}
	if at.IsZero() {
		return KernelFeatures{}, fmt.Errorf("platform: zero snapshot time")
	}
	if ttl <= 0 {
		return KernelFeatures{}, fmt.Errorf("platform: snapshot expiry does not follow probe time")
	}
	if generation == 0 {
		return KernelFeatures{}, fmt.Errorf("platform: zero snapshot generation")
	}
	features := make(map[FeatureID]FeatureEvidence, len(knownFeatureIDs))
	for _, id := range knownFeatureIDs {
		evidence, err := NewEvidence(id, FeatureUnprobed, ReasonNotProbed, at, SourceNotRun, 0, false)
		if err != nil {
			return KernelFeatures{}, err
		}
		features[id] = evidence
	}
	seen := make(map[FeatureID]bool, len(observations))
	for _, evidence := range observations {
		if err := evidence.validate(); err != nil {
			return KernelFeatures{}, err
		}
		if evidence.ProbedAt.Before(at) {
			return KernelFeatures{}, fmt.Errorf("platform: feature %q predates its snapshot", evidence.ID)
		}
		if seen[evidence.ID] {
			return KernelFeatures{}, fmt.Errorf("platform: duplicate observation for %q", evidence.ID)
		}
		seen[evidence.ID] = true
		features[evidence.ID] = evidence
	}
	return KernelFeatures{
		Identity:               identity,
		ContextDigest:          digestExecutionContext(identity),
		RuntimeContextDigest:   digestRuntimeExecutionContext(identity),
		Generation:             generation,
		InvalidationGeneration: invalidationGeneration,
		ProbeRevision:          identity.ProbeRevision,
		ProbedAt:               at,
		ExpiresAt:              at.Add(ttl),
		probedClock:            at,
		expiresClock:           at.Add(ttl),
		features:               features,
	}, nil
}

// Feature returns a factual observation without inventing unknown IDs.
func (snapshot KernelFeatures) Feature(id FeatureID) (FeatureEvidence, bool) {
	evidence, ok := snapshot.features[id]
	return evidence, ok
}

// All returns a deterministic defensive copy of every known feature.
func (snapshot KernelFeatures) All() []FeatureEvidence {
	out := make([]FeatureEvidence, 0, len(knownFeatureIDs))
	for _, id := range knownFeatureIDs {
		if evidence, ok := snapshot.Feature(id); ok {
			out = append(out, evidence)
		}
	}
	return out
}

func (snapshot KernelFeatures) clone() KernelFeatures {
	copyFeatures := make(map[FeatureID]FeatureEvidence, len(snapshot.features))
	for id, evidence := range snapshot.features {
		copyFeatures[id] = evidence
	}
	snapshot.features = copyFeatures
	return snapshot
}

func digestExecutionContext(identity ExecutionContext) [32]byte {
	values := []string{
		identity.OS, identity.Arch, identity.BootID,
		identity.Kernel.System, identity.Kernel.Release, identity.Kernel.Version, identity.Kernel.Machine,
		identity.UserNamespace, identity.NetworkNamespace, identity.MountNamespace,
		identity.EffectiveCapabilities, identity.EffectiveUID, identity.FilesystemUID,
		identity.EffectiveGID, identity.FilesystemGID, identity.Groups,
		identity.NoNewPrivileges, identity.SeccompMode, identity.SeccompFilters,
		identity.ThreadID, identity.ThreadStartTime, identity.SecurityLabel,
	}
	return digestContextValues(values, identity.ProbeRevision)
}

func digestRuntimeExecutionContext(identity ExecutionContext) [32]byte {
	values := []string{
		identity.OS, identity.Arch, identity.BootID,
		identity.Kernel.System, identity.Kernel.Release, identity.Kernel.Version, identity.Kernel.Machine,
		identity.UserNamespace, identity.NetworkNamespace, identity.MountNamespace,
		identity.EffectiveCapabilities, identity.EffectiveUID, identity.FilesystemUID,
		identity.EffectiveGID, identity.FilesystemGID, identity.Groups,
		identity.NoNewPrivileges, identity.SeccompMode, identity.SeccompFilters, identity.SecurityLabel,
	}
	return digestContextValues(values, identity.ProbeRevision)
}

func digestContextValues(values []string, probeRevision uint32) [32]byte {
	hash := sha256.New()
	for _, value := range values {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	var revision [4]byte
	binary.BigEndian.PutUint32(revision[:], probeRevision)
	_, _ = hash.Write(revision[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}
