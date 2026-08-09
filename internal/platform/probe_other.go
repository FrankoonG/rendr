//go:build !linux

package platform

import (
	"context"
	"syscall"
	"time"
)

type systemProber struct{}

func (systemProber) Probe(ctx context.Context, _ ExecutionContext, at time.Time) ([]FeatureEvidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]FeatureEvidence, 0, len(knownFeatureIDs))
	for _, id := range knownFeatureIDs {
		evidence, err := NewEvidence(id, FeatureUnsupported, ReasonPlatformUnsupported, at, SourcePlatformBoundary, syscall.ENOSYS, false)
		if err != nil {
			return nil, err
		}
		out = append(out, evidence)
	}
	return out, nil
}
