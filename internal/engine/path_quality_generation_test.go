package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type routeEpochQualityPath struct {
	transport.PathConn

	mu      sync.Mutex
	quality transport.PathQuality
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type failedQualityPath struct{ transport.PathConn }

func (p *failedQualityPath) QualityContext(context.Context) (transport.PathQuality, error) {
	return transport.PathQuality{}, errors.New("quality unavailable")
}

type panickingQualityPath struct{ transport.PathConn }

func (p *panickingQualityPath) QualityContext(context.Context) (transport.PathQuality, error) {
	panic("quality callback panic")
}

func (p *routeEpochQualityPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	if p.entered != nil {
		p.once.Do(func() { close(p.entered) })
		select {
		case <-p.release:
		case <-ctx.Done():
			return transport.PathQuality{}, ctx.Err()
		}
	}
	p.mu.Lock()
	quality := p.quality
	p.mu.Unlock()
	return quality, nil
}

func (p *routeEpochQualityPath) setQuality(quality transport.PathQuality) {
	p.mu.Lock()
	p.quality = quality
	p.mu.Unlock()
}

func TestQualityObserverRetiresLegacyCacheAfterRouteChange(t *testing.T) {
	base, peer := newMemoryPathPair()
	path := &routeEpochQualityPath{PathConn: base}
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	initial := transport.PathQuality{RTT: 7 * time.Millisecond, LossPP: 3, At: time.Now()}
	path.setQuality(initial)
	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != initial {
		t.Fatalf("initial quality=%+v, want %+v", got, initial)
	}

	slot.retireLegacyQualityEvidence()
	slot.peerMobilityEpoch.Add(1)
	if got := observePathQualities([]*pathSlot{slot}, 75*time.Millisecond)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("predecessor cached quality crossed peer route epoch: %+v", got)
	}

	// PathQualityReader has no route-generation argument. A timestamp after the
	// commit therefore cannot prove that this sample belongs to the successor.
	fresh := transport.PathQuality{RTT: 13 * time.Millisecond, LossPP: 5, At: time.Now().Add(time.Hour)}
	path.setQuality(fresh)
	if got := observePathQualities([]*pathSlot{slot}, 75*time.Millisecond)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("unscoped adapter quality regained authority after mobility: %+v", got)
	}
}

func TestUntimestampedInitialQualityOnlyBootstrapsProbeTimeout(t *testing.T) {
	base, peer := newMemoryPathPair()
	path := &routeEpochQualityPath{PathConn: base}
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	initial := transport.PathQuality{RTT: 17 * time.Millisecond, Jitter: 3 * time.Millisecond}
	path.setQuality(initial)
	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != initial {
		t.Fatalf("initial untimestamped quality=%+v, want %+v", got, initial)
	}
	if got := slot.latestSchedulingQuality(time.Now(), time.Second); got != (transport.PathQuality{}) {
		t.Fatalf("untimestamped adapter quality entered scheduling: %+v", got)
	}

	slot.retireLegacyQualityEvidence()
	slot.peerMobilityEpoch.Add(1)
	if got := observePathQualities([]*pathSlot{slot}, 75*time.Millisecond)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("untimestamped predecessor quality crossed route epoch: %+v", got)
	}
}

func TestCurrentGenerationProbeRestoresSchedulingAfterLegacyRetirement(t *testing.T) {
	base, peer := newMemoryPathPair()
	path := &routeEpochQualityPath{PathConn: base}
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	slot.retireLegacyQualityEvidence()
	slot.peerMobilityEpoch.Add(1)
	now := time.Now()
	probe := transport.PathQuality{RTT: 23 * time.Millisecond, Jitter: 2 * time.Millisecond, At: now}
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: pathProbeGenerationForSlot(slot), firstIssued: now, lastIssued: now,
		lastSuccess: now, lastTransition: now, quality: probe, issued: 1, succeeded: 1,
	})
	if got := slot.latestSchedulingQuality(now.Add(time.Millisecond), time.Second); got != probe {
		t.Fatalf("current-generation probe quality=%+v, want %+v", got, probe)
	}

	// Even a newer adapter timestamp cannot override a generation-bound probe.
	path.setQuality(transport.PathQuality{RTT: time.Millisecond, At: now.Add(time.Hour)})
	if got := slot.latestSchedulingQuality(now.Add(2*time.Millisecond), time.Second); got != probe {
		t.Fatalf("retired adapter overrode current probe: %+v", got)
	}
}

func TestSchedulingQualityRejectsStaleAndFutureAdapterSamples(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name string
		want bool
		at   time.Time
	}{
		{name: "fresh", want: true, at: now.Add(-time.Millisecond)},
		{name: "stale", at: now.Add(-maximumSelectorProbeFreshFor - time.Second)},
		{name: "future", at: now.Add(time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, peer := newMemoryPathPair()
			path := &routeEpochQualityPath{PathConn: base}
			slot := newRouteEpochQualitySlot(t, path)
			t.Cleanup(func() {
				slot.stopQualityObserver()
				slot.waitQualityObserver()
				_ = peer.Close()
			})

			sample := transport.PathQuality{RTT: 9 * time.Millisecond, At: test.at}
			path.setQuality(sample)
			if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != sample {
				t.Fatalf("raw adapter observation=%+v, want %+v", got, sample)
			}
			got := slot.latestSchedulingQuality(now, time.Second)
			if test.want && got != sample {
				t.Fatalf("fresh scheduling quality=%+v, want %+v", got, sample)
			}
			if !test.want && got != (transport.PathQuality{}) {
				t.Fatalf("%s adapter quality entered scheduling: %+v", test.name, got)
			}
		})
	}
}

func TestSchedulingQualityFreshnessUsesHalfOpenBoundary(t *testing.T) {
	now := time.Unix(500, 0)
	quality := transport.PathQuality{RTT: 9 * time.Millisecond, At: now}
	freshFor := selectorProbeFreshFor(time.Second, quality)
	if !schedulingQualityFresh(quality, now.Add(freshFor-time.Nanosecond), time.Second) {
		t.Fatal("quality expired before the freshness boundary")
	}
	if schedulingQualityFresh(quality, now.Add(freshFor), time.Second) {
		t.Fatal("quality remained fresh at the exclusive boundary")
	}
}

func TestProbeTimingQualityRejectsUntrustedAdapterAndPrefersCurrentProbe(t *testing.T) {
	base, peer := newMemoryPathPair()
	slot := newRouteEpochQualitySlot(t, base)
	t.Cleanup(func() { _ = peer.Close() })
	now := time.Now()
	freshProbe := transport.PathQuality{RTT: 30 * time.Millisecond, At: now.Add(-time.Millisecond)}
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: pathProbeGenerationForSlot(slot), firstIssued: now, lastIssued: now,
		lastSuccess: now, quality: freshProbe, issued: 1, succeeded: 1,
	})
	freshAdapter := transport.PathQuality{RTT: time.Millisecond, At: now}
	if got := slot.probeTimingQuality(freshAdapter, now, time.Second); got != freshProbe {
		t.Fatalf("fresh adapter overrode current probe timing=%+v, want %+v", got, freshProbe)
	}

	for name, adapter := range map[string]transport.PathQuality{
		"future": {RTT: time.Second, At: now.Add(time.Hour)},
		"stale":  {RTT: time.Second, At: now.Add(-maximumSelectorProbeFreshFor - time.Second)},
	} {
		slot.probeEvidence.Store(nil)
		if got := slot.probeTimingQuality(adapter, now, time.Second); got != (transport.PathQuality{}) {
			t.Fatalf("%s adapter became probe timing evidence: %+v", name, got)
		}
	}

	bootstrap := transport.PathQuality{RTT: 40 * time.Millisecond}
	if got := slot.probeTimingQuality(bootstrap, now, time.Second); got != bootstrap {
		t.Fatalf("initial untimestamped bootstrap=%+v, want %+v", got, bootstrap)
	}
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: pathProbeGenerationForSlot(slot), firstIssued: now, lastIssued: now,
		lastWireTimeout: now, issued: 1, timedOut: 1,
	})
	if got := slot.probeTimingQuality(bootstrap, now, time.Second); got != (transport.PathQuality{}) {
		t.Fatalf("untimestamped adapter remained authoritative after probe evidence: %+v", got)
	}
}

func TestIssuePathProbeFiltersFutureAdapterTiming(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	path := &routeEpochQualityPath{PathConn: base}
	slot := startProbeTestWriter(t, e, &pathSlot{id: 51, owner: 510, conn: path})
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})
	path.setQuality(transport.PathQuality{RTT: 900 * time.Millisecond, At: time.Now().Add(time.Hour)})

	e.issuePathProbe(slot)
	e.probeMu.Lock()
	defer e.probeMu.Unlock()
	for _, observation := range e.probeOutstanding {
		if observation.slot != slot {
			continue
		}
		if observation.quality != (transport.PathQuality{}) {
			t.Fatalf("future adapter timing entered probe deadline evidence: %+v", observation.quality)
		}
		return
	}
	t.Fatal("probe observation was not reserved")
}

func TestPublicPathQualityUsesOnlyFreshTimestampedEvidence(t *testing.T) {
	now := time.Unix(9_000, 0)
	interval := time.Second
	slot := &pathSlot{id: 52, owner: 520}
	invalid := []struct {
		name    string
		quality transport.PathQuality
	}{
		{name: "untimestamped", quality: transport.PathQuality{RTT: time.Millisecond}},
		{name: "future", quality: transport.PathQuality{RTT: time.Millisecond, At: now.Add(time.Second)}},
		{name: "stale", quality: transport.PathQuality{RTT: time.Millisecond, At: now.Add(-maximumSelectorProbeFreshFor - time.Second)}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if got := publicPathQuality(slot, test.quality, now, interval); got != (transport.PathQuality{}) {
				t.Fatalf("invalid adapter quality became public: %+v", got)
			}
		})
	}

	freshAdapter := transport.PathQuality{RTT: 19 * time.Millisecond, LossPP: 7, At: now.Add(-time.Millisecond)}
	if got := publicPathQuality(slot, freshAdapter, now, interval); got != freshAdapter {
		t.Fatalf("fresh adapter quality=%+v, want %+v", got, freshAdapter)
	}
	freshProbe := transport.PathQuality{RTT: 23 * time.Millisecond, Jitter: 2 * time.Millisecond, At: now}
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: pathProbeGenerationForSlot(slot), firstIssued: now, lastIssued: now,
		lastSuccess: now, quality: freshProbe, issued: 1, succeeded: 1,
	})
	if got := publicPathQuality(slot, invalid[1].quality, now, interval); got != freshProbe {
		t.Fatalf("future adapter displaced fresh public probe quality: %+v, want %+v", got, freshProbe)
	}
}

func TestSchedulingQualityPrefersFreshProbeOverInvalidAdapter(t *testing.T) {
	now := time.Now()
	probe := transport.PathQuality{RTT: 21 * time.Millisecond, Jitter: 2 * time.Millisecond, At: now}
	for _, test := range []struct {
		name    string
		adapter transport.PathQuality
	}{
		{
			name:    "future adapter",
			adapter: transport.PathQuality{RTT: time.Millisecond, At: now.Add(time.Hour)},
		},
		{
			name: "stale adapter",
			adapter: transport.PathQuality{
				RTT: time.Millisecond,
				At:  now.Add(-maximumSelectorProbeFreshFor - time.Second),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mergeSchedulingQuality(test.adapter, probe, now, time.Second); got != probe {
				t.Fatalf("merged quality=%+v, want current probe %+v", got, probe)
			}
		})
	}
}

func TestSchedulingQualityKeepsLossOnItsIndependentFreshnessWindow(t *testing.T) {
	now := time.Unix(7_500, 0)
	probe := transport.PathQuality{RTT: 21 * time.Millisecond, Jitter: 2 * time.Millisecond, At: now}
	lossOnly := transport.PathQuality{
		RTT: 10 * time.Millisecond, LossPP: 500,
		At: now.Add(-selectorEvidenceFreshFor + time.Nanosecond),
	}
	got := mergeSchedulingQuality(lossOnly, probe, now, time.Second)
	want := probe
	want.LossPP = lossOnly.LossPP
	if got != want {
		t.Fatalf("independently fresh loss merge=%+v, want %+v", got, want)
	}

	expired := lossOnly
	expired.At = now.Add(-selectorEvidenceFreshFor - time.Nanosecond)
	if got := mergeSchedulingQuality(expired, probe, now, time.Second); got != probe {
		t.Fatalf("expired loss crossed its freshness window: %+v", got)
	}
	future := lossOnly
	future.At = now.Add(time.Nanosecond)
	if got := mergeSchedulingQuality(future, probe, now, time.Second); got != probe {
		t.Fatalf("future loss became scheduling evidence: %+v", got)
	}
}

func TestExecutionStallWindowUsesOnlyFreshCurrentGenerationQuality(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	path := &routeEpochQualityPath{PathConn: base}
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	now := time.Now()
	path.setQuality(transport.PathQuality{
		RTT: 900 * time.Millisecond,
		At:  now.Add(time.Hour),
	})
	_ = observePathQualities([]*pathSlot{slot}, time.Second)
	if got := e.executionStallWindowForSlot(slot); got != minimumDispatchStallWindow {
		t.Fatalf("future adapter widened dispatch stall window to %v", got)
	}

	slot.retireLegacyQualityEvidence()
	slot.peerMobilityEpoch.Add(1)
	probeAt := time.Now()
	probe := transport.PathQuality{RTT: 80 * time.Millisecond, Jitter: 10 * time.Millisecond, At: probeAt}
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: pathProbeGenerationForSlot(slot), firstIssued: probeAt, lastIssued: probeAt,
		lastSuccess: probeAt, lastTransition: probeAt, quality: probe, issued: 1, succeeded: 1,
	})
	const want = 340 * time.Millisecond
	if got := e.executionStallWindowForSlot(slot); got != want {
		t.Fatalf("current probe dispatch stall window=%v, want %v", got, want)
	}

	staleAt := time.Now().Add(-maximumSelectorProbeFreshFor - time.Second)
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: pathProbeGenerationForSlot(slot), firstIssued: staleAt, lastIssued: staleAt,
		lastSuccess: staleAt, lastTransition: staleAt,
		quality: transport.PathQuality{RTT: time.Second, At: staleAt}, issued: 1, succeeded: 1,
	})
	if got := e.executionStallWindowForSlot(slot); got != minimumDispatchStallWindow {
		t.Fatalf("stale current-generation probe widened dispatch stall window to %v", got)
	}
}

func TestQualityObserverEmptyMeasurementCompletesWithoutBudgetStarvation(t *testing.T) {
	base, peer := newMemoryPathPair()
	slot := newRouteEpochQualitySlot(t, &routeEpochQualityPath{PathConn: base})
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	started := time.Now()
	if got := observePathQualities([]*pathSlot{slot}, 500*time.Millisecond)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("empty transport quality became evidence: %+v", got)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("empty quality observation consumed the full budget: %v", elapsed)
	}
}

func TestQualityObserverErrorCompletesWithoutBudgetStarvation(t *testing.T) {
	base, peer := newMemoryPathPair()
	slot := newRouteEpochQualitySlot(t, &failedQualityPath{PathConn: base})
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	started := time.Now()
	if got := observePathQualities([]*pathSlot{slot}, 500*time.Millisecond)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("failed transport quality became evidence: %+v", got)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("failed quality observation consumed the full budget: %v", elapsed)
	}
}

func TestQualityObserverPanicIsContainedWithoutBudgetStarvation(t *testing.T) {
	base, peer := newMemoryPathPair()
	slot := newRouteEpochQualitySlot(t, &panickingQualityPath{PathConn: base})
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	started := time.Now()
	if got := observePathQualities([]*pathSlot{slot}, 500*time.Millisecond)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("panicking transport quality became evidence: %+v", got)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("panicking quality observation consumed the full budget: %v", elapsed)
	}
}

func TestQualityObserverDiscardsReadCrossingPeerRouteEpoch(t *testing.T) {
	base, peer := newMemoryPathPair()
	path := &routeEpochQualityPath{
		PathConn: base,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		select {
		case <-path.release:
		default:
			close(path.release)
		}
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	result := make(chan map[*pathSlot]transport.PathQuality, 1)
	go func() { result <- observePathQualities([]*pathSlot{slot}, 75*time.Millisecond) }()
	select {
	case <-path.entered:
	case <-time.After(time.Second):
		t.Fatal("quality observer did not enter predecessor read")
	}
	slot.retireLegacyQualityEvidence()
	slot.peerMobilityEpoch.Add(1)
	fresh := transport.PathQuality{RTT: 11 * time.Millisecond, At: time.Now().Add(time.Hour)}
	path.setQuality(fresh)
	close(path.release)
	if got := <-result; got[slot] != (transport.PathQuality{}) {
		t.Fatalf("quality read crossing route epoch was published: %+v", got[slot])
	}
	if got := observePathQualities([]*pathSlot{slot}, 75*time.Millisecond)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("delayed predecessor adapter regained authority after retry: %+v", got)
	}
}

func newRouteEpochQualitySlot(t *testing.T, path transport.PathConn) *pathSlot {
	t.Helper()
	return &pathSlot{id: 1, owner: 1, conn: path}
}

func TestPredecessorProbeInvalidationPreservesSuccessorEvidence(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 7, owner: 9}
	predecessor := pathProbeGenerationForSlot(slot)
	slot.peerMobilityEpoch.Add(1)
	successor := pathProbeGenerationForSlot(slot)
	now := time.Now()
	const predecessorID, successorID = uint64(41), uint64(42)
	e.probeOutstanding[predecessorID] = pathProbeObservation{slot: slot, generation: predecessor}
	e.probeOutstanding[successorID] = pathProbeObservation{slot: slot, generation: successor}
	successorEvidence := &pathProbeEvidence{
		generation: successor, firstIssued: now, lastIssued: now, lastSuccess: now,
		quality: transport.PathQuality{RTT: time.Millisecond, At: now}, issued: 1, succeeded: 1,
	}
	slot.probeEvidence.Store(successorEvidence)

	e.invalidatePredecessorPathProbeEvidence(slot)
	if _, exists := e.probeOutstanding[predecessorID]; exists {
		t.Fatal("predecessor probe observation survived route commit")
	}
	if got, exists := e.probeOutstanding[successorID]; !exists || got.generation != successor {
		t.Fatalf("successor probe observation was removed: %+v/%t", got, exists)
	}
	if got := slot.probeEvidence.Load(); got != successorEvidence {
		t.Fatalf("successor probe evidence was removed: %p, want %p", got, successorEvidence)
	}
}
