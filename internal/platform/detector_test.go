package platform

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDetectorCachesOnlyExactExecutionContext(t *testing.T) {
	var calls atomic.Int32
	identity := testExecutionContext("caps-a")
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, at time.Time) ([]FeatureEvidence, error) {
		calls.Add(1)
		evidence, err := NewEvidence(FeatureTCPRepairBase, FeaturePermissionDenied, ReasonPermissionDenied, at, SourceRuntimeSyscall, syscall.EPERM, false)
		return []FeatureEvidence{evidence}, err
	}))

	first, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || first.Identity != second.Identity {
		t.Fatalf("same-context calls=%d first=%+v second=%+v", calls.Load(), first.Identity, second.Identity)
	}

	identity.EffectiveCapabilities = "caps-b"
	third, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || third.Identity.EffectiveCapabilities != "caps-b" {
		t.Fatalf("changed-context calls=%d identity=%+v", calls.Load(), third.Identity)
	}
}

func TestDetectorRefreshesCacheThatCannotCoverRequestedValidity(t *testing.T) {
	var calls atomic.Int32
	identity := testExecutionContext("caps-a")
	now := time.Unix(100, 0).UTC()
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, _ time.Time) ([]FeatureEvidence, error) {
		calls.Add(1)
		return nil, nil
	}))
	detector.ttl = 10 * time.Second
	detector.now = func() time.Time { return now }

	first, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(9500 * time.Millisecond)
	if cached, err := detector.Current(context.Background()); err != nil || cached.Generation != first.Generation {
		t.Fatalf("ordinary lookup snapshot/error=%d/%v want cached generation %d", cached.Generation, err, first.Generation)
	}
	refreshed, err := detector.CurrentFresh(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || refreshed.Generation == first.Generation || refreshed.ExpiresAt.Sub(now) != detector.ttl {
		t.Fatalf("fresh lookup calls=%d generations=%d/%d remaining=%s",
			calls.Load(), first.Generation, refreshed.Generation, refreshed.ExpiresAt.Sub(now))
	}
	if _, err := detector.CurrentFresh(context.Background(), -time.Nanosecond); err == nil {
		t.Fatal("negative minimum validity was accepted")
	}
}

func TestDetectorSerializesConcurrentSameContextProbe(t *testing.T) {
	identity := testExecutionContext("caps-a")
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, _ time.Time) ([]FeatureEvidence, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil, nil
	}))

	const goroutines = 100
	errs := make(chan error, goroutines)
	var wait sync.WaitGroup
	wait.Add(goroutines)
	for range goroutines {
		go func() {
			defer wait.Done()
			_, err := detector.Current(context.Background())
			errs <- err
		}()
	}
	<-started
	close(release)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls=%d want 1", got)
	}
}

func TestDetectorInvalidationCannotBeOverwrittenByInFlightProbe(t *testing.T) {
	identity := testExecutionContext("caps-a")
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, at time.Time) ([]FeatureEvidence, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		evidence, err := NewEvidence(FeatureUDPGSO, FeatureAvailable, ReasonConfirmed, at, SourceRuntimeRoundTrip, 0, false)
		return []FeatureEvidence{evidence}, err
	}))

	done := make(chan error, 1)
	go func() {
		_, err := detector.Current(context.Background())
		done <- err
	}()
	<-started
	if err := detector.Invalidate(FeatureUDPGSO); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("probe calls=%d want stale result discarded and retried", got)
	}
}

func TestDetectorRejectsRepeatedContextDrift(t *testing.T) {
	identityA := testExecutionContext("caps-a")
	identityB := testExecutionContext("caps-b")
	var reads atomic.Int32
	detector, err := newDetector(probeFunc(func(_ context.Context, _ ExecutionContext, _ time.Time) ([]FeatureEvidence, error) {
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	detector.acquireContext = func() (*executionContextLease, error) {
		if reads.Add(1)%2 == 1 {
			return &executionContextLease{Identity: identityA}, nil
		}
		return &executionContextLease{Identity: identityB}, nil
	}
	if _, err := detector.Current(context.Background()); !errors.Is(err, ErrExecutionContextChanged) {
		t.Fatalf("Current error=%v want %v", err, ErrExecutionContextChanged)
	}
}

func TestDetectorHonorsCancelledContextWithoutProbe(t *testing.T) {
	identity := testExecutionContext("caps-a")
	var calls atomic.Int32
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, _ time.Time) ([]FeatureEvidence, error) {
		calls.Add(1)
		return nil, nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := detector.Current(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Current error=%v want canceled", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("cancelled probe ran %d times", calls.Load())
	}
}

func TestDetectorRecoversProbePanicAndReleasesGate(t *testing.T) {
	identity := testExecutionContext("caps-a")
	var calls atomic.Int32
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, _ time.Time) ([]FeatureEvidence, error) {
		if calls.Add(1) == 1 {
			panic("injected")
		}
		return nil, nil
	}))
	if _, err := detector.Current(context.Background()); err == nil {
		t.Fatal("probe panic was not reported")
	}
	if _, err := detector.Current(context.Background()); err != nil {
		t.Fatalf("gate remained poisoned after panic: %v", err)
	}
}

func TestDetectorWallClockRollbackInvalidatesCache(t *testing.T) {
	identity := testExecutionContext("caps-a")
	var calls atomic.Int32
	times := []time.Time{time.Unix(100, 0), time.Unix(50, 0)}
	var clock atomic.Int32
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, _ time.Time) ([]FeatureEvidence, error) {
		calls.Add(1)
		return nil, nil
	}))
	detector.now = func() time.Time {
		index := int(clock.Add(1)) - 1
		if index >= len(times) {
			return times[len(times)-1]
		}
		return times[index]
	}
	if _, err := detector.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := detector.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("clock rollback reused positive cache: calls=%d", calls.Load())
	}
}

func TestDetectorInvalidationGenerationIsSnapshotBound(t *testing.T) {
	identity := testExecutionContext("caps-a")
	detector := testDetector(t, &identity, probeFunc(func(_ context.Context, _ ExecutionContext, _ time.Time) ([]FeatureEvidence, error) {
		return nil, nil
	}))
	first, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := detector.Invalidate(FeatureTUNOpen); err != nil {
		t.Fatal(err)
	}
	second, err := detector.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.InvalidationGeneration <= first.InvalidationGeneration || detector.invalidationVersion() != second.InvalidationGeneration {
		t.Fatalf("invalidation generations first=%d second=%d current=%d", first.InvalidationGeneration, second.InvalidationGeneration, detector.invalidationVersion())
	}
}

func testDetector(t *testing.T, identity *ExecutionContext, prober prober) *detector {
	t.Helper()
	detector, err := newDetector(prober)
	if err != nil {
		t.Fatal(err)
	}
	detector.acquireContext = func() (*executionContextLease, error) {
		return &executionContextLease{Identity: *identity}, nil
	}
	detector.now = func() time.Time { return time.Unix(100, 0).UTC() }
	return detector
}
