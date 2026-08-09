//go:build linux

package platform

import (
	"context"
	"fmt"
	"syscall"
	"time"
)

type systemProber struct{}

func (systemProber) Probe(ctx context.Context, identity ExecutionContext, at time.Time) ([]FeatureEvidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	major, ok := linuxKernelMajor(identity.Kernel.Release)
	if !ok {
		return uniformLinuxEvidence(FeatureProbeFailed, ReasonSyscallFailed, SourcePlatformBoundary, 0, false, at)
	}
	if major < 5 {
		return uniformLinuxEvidence(FeatureUnsupported, ReasonKernelBelowMinimum, SourcePlatformBoundary, syscall.ENOSYS, false, at)
	}
	return probeTUN(ctx, at, defaultTUNProbeOps())
}

func uniformLinuxEvidence(state FeatureState, reason FeatureReason, source EvidenceSource, errno syscall.Errno, retryable bool, at time.Time) ([]FeatureEvidence, error) {
	out := make([]FeatureEvidence, 0, len(knownFeatureIDs))
	for _, id := range knownFeatureIDs {
		evidence, err := NewEvidence(id, state, reason, at, source, errno, retryable)
		if err != nil {
			return nil, err
		}
		out = append(out, evidence)
	}
	return out, nil
}

func linuxKernelMajor(release string) (int, bool) {
	if release == "" || release[0] < '0' || release[0] > '9' {
		return 0, false
	}
	major := 0
	index := 0
	for index < len(release) && release[index] >= '0' && release[index] <= '9' {
		major = major*10 + int(release[index]-'0')
		index++
	}
	if index == len(release) || release[index] != '.' {
		return 0, false
	}
	if major > 1_000 {
		return 0, false
	}
	return major, true
}

func mustEvidence(id FeatureID, state FeatureState, reason FeatureReason, at time.Time, source EvidenceSource, errno syscall.Errno, retryable bool) FeatureEvidence {
	evidence, err := NewEvidence(id, state, reason, at, source, errno, retryable)
	if err != nil {
		panic(fmt.Sprintf("platform: internal evidence invariant: %v", err))
	}
	return evidence
}
