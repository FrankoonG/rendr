package platform

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrExecutionContextChanged = errors.New("platform: execution context changed during probe")

const (
	defaultSnapshotTTL = 30 * time.Second
	maxCachedContexts  = 8
	maxContextRetries  = 3
)

// prober actively observes the supplied execution context. It must not infer
// positive support from kernel version or adapter names.
type prober interface {
	Probe(context.Context, ExecutionContext, time.Time) ([]FeatureEvidence, error)
}

// probeFunc adapts a function to prober in package-local tests.
type probeFunc func(context.Context, ExecutionContext, time.Time) ([]FeatureEvidence, error)

func (f probeFunc) Probe(ctx context.Context, identity ExecutionContext, at time.Time) ([]FeatureEvidence, error) {
	return f(ctx, identity, at)
}

// detector serializes probes so concurrent callers reuse one complete result.
// The gate is context-aware; canceled waiters do not cancel another caller's
// probe. Results are sharded by complete execution context and bounded.
type detector struct {
	prober         prober
	acquireContext func() (*executionContextLease, error)
	now            func() time.Time
	ttl            time.Duration
	gate           chan struct{}

	mu                     sync.RWMutex
	generation             uint64
	invalidationGeneration uint64
	cached                 map[ExecutionContext]KernelFeatures
}

func newDetector(prober prober) (*detector, error) {
	if prober == nil {
		return nil, fmt.Errorf("platform: nil prober")
	}
	return &detector{
		prober:         prober,
		acquireContext: acquireExecutionContext,
		now:            time.Now,
		ttl:            defaultSnapshotTTL,
		gate:           make(chan struct{}, 1),
		cached:         make(map[ExecutionContext]KernelFeatures),
	}, nil
}

// Current returns a defensive immutable snapshot. On Linux, key acquisition,
// probing, cleanup, and identity verification run on one locked OS thread.
func (d *detector) Current(ctx context.Context) (KernelFeatures, error) {
	if d == nil {
		return KernelFeatures{}, fmt.Errorf("platform: nil detector")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case d.gate <- struct{}{}:
		defer func() { <-d.gate }()
	case <-ctx.Done():
		return KernelFeatures{}, ctx.Err()
	}

	unlock := lockExecutionThread()
	defer unlock()
	for attempt := 0; attempt < maxContextRetries; attempt++ {
		snapshot, retry, err := d.currentOnce(ctx)
		if !retry {
			return snapshot, err
		}
	}
	return KernelFeatures{}, ErrExecutionContextChanged
}

func (d *detector) currentOnce(ctx context.Context) (KernelFeatures, bool, error) {
	if err := ctx.Err(); err != nil {
		return KernelFeatures{}, false, err
	}
	lease, err := d.acquireContext()
	if err != nil {
		return KernelFeatures{}, false, fmt.Errorf("platform: acquire execution context: %w", err)
	}
	identity := lease.Identity
	if err := identity.validate(); err != nil {
		return KernelFeatures{}, false, errors.Join(err, lease.Close())
	}

	now := d.now()
	d.mu.RLock()
	cached, ok := d.cached[identity]
	cacheGeneration := d.generation
	d.mu.RUnlock()
	if ok && !now.Before(cached.probedClock) && now.Before(cached.expiresClock) {
		if err := lease.Close(); err != nil {
			return KernelFeatures{}, false, fmt.Errorf("platform: close execution context: %w", err)
		}
		return cached.clone(), false, nil
	}

	observations, probeErr := invokeProber(d.prober, ctx, identity, now)
	if probeErr != nil {
		return KernelFeatures{}, false, errors.Join(probeErr, lease.Close())
	}
	if err := ctx.Err(); err != nil {
		return KernelFeatures{}, false, errors.Join(err, lease.Close())
	}
	verify, err := d.acquireContext()
	if err != nil {
		return KernelFeatures{}, false, errors.Join(fmt.Errorf("platform: re-acquire execution context: %w", err), lease.Close())
	}
	current := verify.Identity
	if cleanupErr := errors.Join(verify.Close(), lease.Close()); cleanupErr != nil {
		return KernelFeatures{}, false, fmt.Errorf("platform: release execution context: %w", cleanupErr)
	}
	if current != identity {
		return KernelFeatures{}, true, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.generation != cacheGeneration {
		return KernelFeatures{}, true, nil
	}
	d.generation++
	ttl := d.ttl
	if identity.SeccompMode != "0" && identity.SeccompFilters == "unreported" {
		ttl = time.Nanosecond
	}
	snapshot, err := newKernelFeatures(identity, now, ttl, d.generation, d.invalidationGeneration, observations)
	if err != nil {
		return KernelFeatures{}, false, err
	}
	if len(d.cached) >= maxCachedContexts {
		d.evictOldestLocked()
	}
	d.cached[identity] = snapshot.clone()
	return snapshot.clone(), false, nil
}

func invokeProber(prober prober, ctx context.Context, identity ExecutionContext, at time.Time) (observations []FeatureEvidence, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			observations = nil
			err = fmt.Errorf("platform: active probe panic: %v", recovered)
		}
	}()
	return prober.Probe(ctx, identity, at)
}

// Invalidate records contradictory runtime evidence by ensuring the next
// Current call performs a fresh active probe.
func (d *detector) Invalidate(feature FeatureID) error {
	if d == nil {
		return fmt.Errorf("platform: nil detector")
	}
	if !feature.valid() {
		return fmt.Errorf("platform: unknown feature %q", feature)
	}
	d.mu.Lock()
	d.generation++
	d.invalidationGeneration++
	d.cached = make(map[ExecutionContext]KernelFeatures)
	d.mu.Unlock()
	return nil
}

func (d *detector) invalidationVersion() uint64 {
	if d == nil {
		return 0
	}
	d.mu.RLock()
	version := d.invalidationGeneration
	d.mu.RUnlock()
	return version
}

func (d *detector) evictOldestLocked() {
	var oldestIdentity ExecutionContext
	var oldestTime time.Time
	found := false
	for identity, snapshot := range d.cached {
		if !found || snapshot.ProbedAt.Before(oldestTime) {
			oldestIdentity = identity
			oldestTime = snapshot.ProbedAt
			found = true
		}
	}
	if found {
		delete(d.cached, oldestIdentity)
	}
}
