package rendr

import (
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
)

type KernelFeatureID string

const (
	KernelFeatureTCPRepairPermission KernelFeatureID = "tcp_repair_permission"
	KernelFeatureTCPRepairBase       KernelFeatureID = "tcp_repair_base"
	KernelFeatureTCPRepairQueueSeq   KernelFeatureID = "tcp_repair_queue_seq"
	KernelFeatureTCPRepairWindow     KernelFeatureID = "tcp_repair_window"
	KernelFeatureTCPRepairOptions    KernelFeatureID = "tcp_repair_options"
	KernelFeatureTransparentBindV4   KernelFeatureID = "transparent_bind_v4"
	KernelFeatureTransparentBindV6   KernelFeatureID = "transparent_bind_v6"
	KernelFeatureTUNOpen             KernelFeatureID = "tun_open"
	KernelFeatureTUNSetIFF           KernelFeatureID = "tun_set_iff"
	KernelFeatureTUNSingleQueue      KernelFeatureID = "tun_single_queue"
	KernelFeatureTUNMultiQueue       KernelFeatureID = "tun_multi_queue"
	KernelFeatureUDPGSO              KernelFeatureID = "udp_gso"
	KernelFeatureUDPGRO              KernelFeatureID = "udp_gro"
)

type KernelFeatureState string

const (
	KernelFeatureAvailable        KernelFeatureState = "available"
	KernelFeatureUnsupported      KernelFeatureState = "unsupported"
	KernelFeaturePermissionDenied KernelFeatureState = "permission_denied"
	KernelFeatureUnprobed         KernelFeatureState = "unprobed"
	KernelFeatureProbeFailed      KernelFeatureState = "probe_failed"
)

type KernelFeatureReason string
type KernelEvidenceSource string

const (
	KernelFeatureReasonExpired            KernelFeatureReason  = "evidence_expired"
	KernelFeatureReasonContextChanged     KernelFeatureReason  = "execution_context_changed"
	KernelFeatureReasonContextProbeFailed KernelFeatureReason  = "execution_context_probe_failed"
	KernelFeatureReasonInvalidated        KernelFeatureReason  = "evidence_invalidated"
	KernelFeatureReasonThreadScoped       KernelFeatureReason  = "thread_scoped_evidence"
	KernelEvidenceCacheExpiry             KernelEvidenceSource = "cache_expiry"
	KernelEvidenceContextCheck            KernelEvidenceSource = "execution_context_check"
	KernelEvidenceRuntimeProbe            KernelEvidenceSource = "runtime_probe"
	KernelEvidenceRuntimeInvalidation     KernelEvidenceSource = "runtime_invalidation"
)

// KernelFeatureStatus is the stable public view of one active observation.
// Raw errno and execution-context identity intentionally remain internal.
type KernelFeatureStatus struct {
	ID       KernelFeatureID
	State    KernelFeatureState
	Reason   KernelFeatureReason
	Source   KernelEvidenceSource
	ProbedAt time.Time
}

// KernelFeatures is one atomic snapshot. ExpiresAt prevents a stale positive
// observation from remaining green indefinitely; Lookup downgrades the whole
// snapshot to unprobed after expiry.
type KernelFeatures struct {
	Generation             uint64
	ProbeRevision          uint32
	ProbedAt               time.Time
	ExpiresAt              time.Time
	Features               []KernelFeatureStatus
	contextDigest          [32]byte
	invalidationGeneration uint64
	threadScoped           bool
}

func (features KernelFeatures) Lookup(id KernelFeatureID) (KernelFeatureStatus, bool) {
	now := time.Now()
	expired := (!features.ProbedAt.IsZero() && now.Before(features.ProbedAt)) ||
		(!features.ExpiresAt.IsZero() && !now.Before(features.ExpiresAt))
	for _, feature := range features.Features {
		if feature.ID != id {
			continue
		}
		if expired {
			feature.State = KernelFeatureUnprobed
			feature.Reason = KernelFeatureReasonExpired
			feature.Source = KernelEvidenceCacheExpiry
		}
		return feature, true
	}
	return KernelFeatureStatus{}, false
}

func (features KernelFeatures) Available(id KernelFeatureID) bool {
	feature, ok := features.Lookup(id)
	return ok && feature.State == KernelFeatureAvailable
}

func (features KernelFeatures) snapshot(now time.Time) KernelFeatures {
	copyFeatures := append([]KernelFeatureStatus(nil), features.Features...)
	features.Features = copyFeatures
	if (features.ProbedAt.IsZero() || !now.Before(features.ProbedAt)) &&
		(features.ExpiresAt.IsZero() || now.Before(features.ExpiresAt)) {
		return features
	}
	return features.unprobed(KernelFeatureReasonExpired, KernelEvidenceCacheExpiry)
}

func (features KernelFeatures) unprobed(reason KernelFeatureReason, source KernelEvidenceSource) KernelFeatures {
	features.Features = append([]KernelFeatureStatus(nil), features.Features...)
	for index := range features.Features {
		features.Features[index].State = KernelFeatureUnprobed
		features.Features[index].Reason = reason
		features.Features[index].Source = source
	}
	return features
}

func failedKernelFeatures(at time.Time) KernelFeatures {
	features := KernelFeatures{
		ProbedAt: at,
		Features: make([]KernelFeatureStatus, 0, len(allKernelFeatureIDs)),
	}
	for _, id := range allKernelFeatureIDs {
		features.Features = append(features.Features, KernelFeatureStatus{
			ID: id, State: KernelFeatureProbeFailed,
			Reason: KernelFeatureReasonContextProbeFailed, Source: KernelEvidenceRuntimeProbe, ProbedAt: at,
		})
	}
	return features
}

var allKernelFeatureIDs = [...]KernelFeatureID{
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
}

func kernelFeaturesFromPlatform(snapshot platform.KernelFeatures) KernelFeatures {
	features := KernelFeatures{
		Generation:             snapshot.Generation,
		ProbeRevision:          snapshot.ProbeRevision,
		ProbedAt:               snapshot.ProbedAt,
		ExpiresAt:              snapshot.ExpiresAt,
		contextDigest:          snapshot.RuntimeContextDigest,
		invalidationGeneration: snapshot.InvalidationGeneration,
		threadScoped:           snapshot.Identity.OS == "linux" && snapshot.Identity.SeccompMode != "0",
		Features:               make([]KernelFeatureStatus, 0, len(snapshot.All())),
	}
	for _, evidence := range snapshot.All() {
		features.Features = append(features.Features, KernelFeatureStatus{
			ID:       KernelFeatureID(evidence.ID),
			State:    KernelFeatureState(evidence.State),
			Reason:   KernelFeatureReason(evidence.Reason),
			Source:   KernelEvidenceSource(evidence.Source),
			ProbedAt: evidence.ProbedAt,
		})
	}
	return features
}
