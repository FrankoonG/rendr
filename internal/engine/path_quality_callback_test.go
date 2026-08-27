package engine

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type panickingQualityErrorStringer struct{}

func (panickingQualityErrorStringer) String() string {
	panic("String must not be called")
}

type qualityCallbackStep uint8

const (
	qualityCallbackReturn qualityCallbackStep = iota
	qualityCallbackError
	qualityCallbackPanic
	qualityCallbackGoexit
	qualityCallbackContextError
)

type sequencedQualityCallbackPath struct {
	transport.PathConn

	mu        sync.Mutex
	steps     []qualityCallbackStep
	qualities []transport.PathQuality
	calls     int
	panicVal  any
}

type blockingQualityCallbackPath struct {
	transport.PathConn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

type constantQualityCallbackPath struct {
	transport.PathConn
	quality transport.PathQuality
	calls   atomic.Int32
}

func (p *constantQualityCallbackPath) QualityContext(context.Context) (transport.PathQuality, error) {
	p.calls.Add(1)
	return p.quality, nil
}

type qualityThenBlockCallbackPath struct {
	transport.PathConn
	quality transport.PathQuality
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (p *qualityThenBlockCallbackPath) QualityContext(context.Context) (transport.PathQuality, error) {
	if p.calls.Add(1) == 1 {
		return p.quality, nil
	}
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return p.quality, nil
}

func (p *blockingQualityCallbackPath) QualityContext(context.Context) (transport.PathQuality, error) {
	p.calls.Add(1)
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return transport.PathQuality{RTT: time.Millisecond, At: time.Now()}, nil
}

func TestReadPathQualityForeverBlockRetainsOneBoundedLease(t *testing.T) {
	base, peer := newMemoryPathPair()
	defer base.Close()
	defer peer.Close()
	path := &blockingQualityCallbackPath{
		PathConn: base,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(path.release) }) }
	t.Cleanup(release)

	started := time.Now()
	quality, err := readPathQuality(context.Background(), path)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("forever-blocking quality callback escaped after %s", elapsed)
	}
	if quality != (transport.PathQuality{}) {
		t.Fatalf("blocked quality=%+v, want fail-closed zero", quality)
	}
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(err, &deadlineErr) || deadlineErr.operation != pathQualityCallbackOperation {
		t.Fatalf("blocked quality error=%v, want typed callback deadline", err)
	}
	select {
	case <-path.entered:
	default:
		t.Fatal("quality callback did not enter")
	}
	if !externalPathCallbackInFlight(pathQualityCallbackOperation, path) {
		t.Fatal("abandoned quality callback did not retain its lease")
	}

	for attempt := 0; attempt < 128; attempt++ {
		quality, err = readPathQuality(context.Background(), path)
		var busyErr *pathDispatchCallbackBusyError
		if quality != (transport.PathQuality{}) || !errors.As(err, &busyErr) {
			t.Fatalf("repeat %d quality/error=%+v/%v, want zero/typed busy", attempt, quality, err)
		}
	}
	if got := path.calls.Load(); got != 1 {
		t.Fatalf("blocked callback invocations=%d, want exactly one", got)
	}

	release()
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight(pathQualityCallbackOperation, path)
	})
	quality, err = readPathQuality(context.Background(), path)
	if err != nil || quality.RTT <= 0 || path.calls.Load() != 2 {
		t.Fatalf("quality callback did not recover: quality=%+v err=%v calls=%d", quality, err, path.calls.Load())
	}
}

func TestReadPathQualityCapacitySaturationFailsClosedAndRecovers(t *testing.T) {
	eventuallyEngine(t, time.Second, func() bool {
		externalPathCallbacks.Lock()
		defer externalPathCallbacks.Unlock()
		return externalPathCallbacks.classInflight[externalPathCallbackOptional] == 0
	})
	leases := reserveOptionalCallbackClass(t, "QualityCallbackSaturationReservation")
	defer releaseOptionalCallbackClass(leases)

	base, peer := newMemoryPathPair()
	defer base.Close()
	defer peer.Close()
	path := &constantQualityCallbackPath{
		PathConn: base,
		quality:  transport.PathQuality{RTT: 3 * time.Millisecond, At: time.Now()},
	}
	quality, err := readPathQuality(context.Background(), path)
	var capacityErr *pathDispatchCallbackCapacityError
	if quality != (transport.PathQuality{}) || !errors.As(err, &capacityErr) {
		t.Fatalf("capacity quality/error=%+v/%v, want zero/typed capacity", quality, err)
	}
	if got := path.calls.Load(); got != 0 {
		t.Fatalf("capacity-exhausted quality callback ran %d times", got)
	}

	releaseOptionalCallbackClass(leases)
	eventuallyEngine(t, time.Second, func() bool {
		externalPathCallbacks.Lock()
		defer externalPathCallbacks.Unlock()
		return externalPathCallbacks.classInflight[externalPathCallbackOptional] == 0
	})
	quality, err = readPathQuality(context.Background(), path)
	if err != nil || quality != path.quality || path.calls.Load() != 1 {
		t.Fatalf("capacity recovery quality/error/calls=%+v/%v/%d", quality, err, path.calls.Load())
	}
}

func TestQualityCallbackBlockDoesNotDelayHealthySiblingRemoveOrClose(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	targets := configureLeafSelectorRuntime(t, e, "quality-blocked", "quality-healthy")
	badBase, badPeer := newMemoryPathPair()
	goodBase, goodPeer := newMemoryPathPair()
	bad := &blockingQualityCallbackPath{
		PathConn: badBase,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	good := &constantQualityCallbackPath{
		PathConn: goodBase,
		quality:  transport.PathQuality{RTT: 2 * time.Millisecond, At: time.Now()},
	}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(bad.release) }) }
	t.Cleanup(func() {
		unblock()
		_ = e.Close()
		_ = badPeer.Close()
		_ = goodPeer.Close()
	})
	badID, err := e.AttachPathBound(
		bad,
		transport.PathSpec{Transport: "quality-callback", Address: "blocked"},
		PathBinding{
			LocalTXTargetID: targets["quality-blocked"],
			PeerTXTargetID:  targets["quality-blocked"],
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	goodID, err := e.AttachPathBound(
		good,
		transport.PathSpec{Transport: "quality-callback", Address: "healthy"},
		PathBinding{
			LocalTXTargetID: targets["quality-healthy"],
			PeerTXTargetID:  targets["quality-healthy"],
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	badSlot, goodSlot := e.paths[badID], e.paths[goodID]
	e.pathsMu.RUnlock()
	if badSlot == nil || goodSlot == nil {
		t.Fatal("attached quality callback slots are missing")
	}

	started := time.Now()
	qualities := observePathQualities([]*pathSlot{goodSlot, badSlot}, 75*time.Millisecond)
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("blocked sibling delayed quality scheduling for %s", elapsed)
	}
	if got := qualities[goodSlot]; got != good.quality {
		t.Fatalf("healthy sibling quality=%+v, want %+v", got, good.quality)
	}
	select {
	case <-bad.entered:
	default:
		t.Fatal("blocked quality callback did not enter")
	}
	if !externalPathCallbackInFlight(pathQualityCallbackOperation, bad) {
		t.Fatal("blocked quality callback did not retain its process lease")
	}

	removeDone := make(chan error, 1)
	go func() { removeDone <- e.RemovePath(badID) }()
	select {
	case err := <-removeDone:
		if err != nil {
			t.Fatalf("RemovePath with blocked quality callback: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked quality callback prevented RemovePath")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close with blocked quality callback: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked quality callback prevented Engine.Close")
	}
	if !externalPathCallbackInFlight(pathQualityCallbackOperation, bad) {
		t.Fatal("Engine.Close released a callback lease before the callback exited")
	}
	unblock()
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight(pathQualityCallbackOperation, bad)
	})
}

func TestQualityObserverTimeoutDoesNotReusePriorSample(t *testing.T) {
	base, peer := newMemoryPathPair()
	defer peer.Close()
	want := transport.PathQuality{RTT: 4 * time.Millisecond, At: time.Now()}
	path := &qualityThenBlockCallbackPath{
		PathConn: base,
		quality:  want,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(path.release) }) }
	t.Cleanup(release)
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = base.Close()
	})

	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != want {
		t.Fatalf("initial quality=%+v, want %+v", got, want)
	}
	started := time.Now()
	if got := observePathQualities([]*pathSlot{slot}, selectorQualityObservationBudget)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("timed-out observation reused prior quality: %+v", got)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("timed-out observation returned after %s", elapsed)
	}
	select {
	case <-path.entered:
	default:
		t.Fatal("second quality callback did not block")
	}
	if got := path.calls.Load(); got != 2 {
		t.Fatalf("quality callback calls=%d, want 2", got)
	}

	release()
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight(pathQualityCallbackOperation, path)
	})
}

func (p *sequencedQualityCallbackPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	p.mu.Lock()
	index := p.calls
	p.calls++
	step := p.steps[index]
	quality := p.qualities[index]
	panicVal := p.panicVal
	p.mu.Unlock()

	switch step {
	case qualityCallbackError:
		return transport.PathQuality{}, errors.New("quality unavailable")
	case qualityCallbackPanic:
		panic(panicVal)
	case qualityCallbackGoexit:
		runtime.Goexit()
	case qualityCallbackContextError:
		<-ctx.Done()
		return transport.PathQuality{}, ctx.Err()
	}
	return quality, nil
}

func TestReadPathQualityReportsAbnormalCallbackExit(t *testing.T) {
	for _, test := range []struct {
		name  string
		step  qualityCallbackStep
		check func(*testing.T, error)
	}{
		{
			name: "panic",
			step: qualityCallbackPanic,
			check: func(t *testing.T, err error) {
				var panicErr *pathQualityCallbackPanicError
				if !errors.As(err, &panicErr) {
					t.Fatalf("error=%v, want typed quality callback panic", err)
				}
				if panicErr.panicType != "string" {
					t.Fatalf("panic type=%q, want string", panicErr.panicType)
				}
			},
		},
		{
			name: "goexit",
			step: qualityCallbackGoexit,
			check: func(t *testing.T, err error) {
				var goexitErr *pathQualityCallbackGoexitError
				if !errors.As(err, &goexitErr) {
					t.Fatalf("error=%v, want typed quality callback Goexit", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, peer := newMemoryPathPair()
			defer base.Close()
			defer peer.Close()
			path := &sequencedQualityCallbackPath{
				PathConn:  base,
				steps:     []qualityCallbackStep{test.step},
				qualities: []transport.PathQuality{{}},
				panicVal:  "quality panic",
			}
			quality, err := readPathQuality(context.Background(), path)
			if quality != (transport.PathQuality{}) {
				t.Fatalf("quality=%+v, want zero after abnormal callback", quality)
			}
			test.check(t, err)
		})
	}
}

func TestReadPathQualityPanicDiagnosticDoesNotInvokeRecoveredStringer(t *testing.T) {
	base, peer := newMemoryPathPair()
	defer base.Close()
	defer peer.Close()
	path := &sequencedQualityCallbackPath{
		PathConn:  base,
		steps:     []qualityCallbackStep{qualityCallbackPanic},
		qualities: []transport.PathQuality{{}},
		panicVal:  panickingQualityErrorStringer{},
	}

	_, err := readPathQuality(context.Background(), path)
	var panicErr *pathQualityCallbackPanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("error=%v, want typed quality callback panic", err)
	}
	if panicErr.panicType != "engine.panickingQualityErrorStringer" {
		t.Fatalf("panic type=%q, want engine.panickingQualityErrorStringer", panicErr.panicType)
	}
	if got := panicErr.Error(); got == "" {
		t.Fatal("panic diagnostic is empty")
	}
}

func TestQualityObserverAbnormalExitInvalidatesSampleAndContinues(t *testing.T) {
	for _, test := range []struct {
		name string
		step qualityCallbackStep
	}{
		{name: "panic", step: qualityCallbackPanic},
		{name: "goexit", step: qualityCallbackGoexit},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, peer := newMemoryPathPair()
			initial := transport.PathQuality{RTT: 7 * time.Millisecond, At: time.Now()}
			recovered := transport.PathQuality{RTT: 13 * time.Millisecond, At: time.Now().Add(time.Millisecond)}
			path := &sequencedQualityCallbackPath{
				PathConn:  base,
				steps:     []qualityCallbackStep{qualityCallbackReturn, test.step, qualityCallbackReturn},
				qualities: []transport.PathQuality{initial, {}, recovered},
				panicVal:  "quality panic",
			}
			slot := newRouteEpochQualitySlot(t, path)
			t.Cleanup(func() {
				slot.stopQualityObserver()
				slot.waitQualityObserver()
				_ = peer.Close()
			})

			if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != initial {
				t.Fatalf("initial quality=%+v, want %+v", got, initial)
			}
			if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != (transport.PathQuality{}) {
				t.Fatalf("stale positive quality survived abnormal callback: %+v", got)
			}
			slot.qualityObserverMu.Lock()
			sampled := slot.qualityObserverSampled
			cached := slot.qualityObserverSample
			slot.qualityObserverMu.Unlock()
			if sampled || cached != (transport.PathQuality{}) {
				t.Fatalf("abnormal callback left cache eligible: sampled=%t quality=%+v", sampled, cached)
			}
			if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != recovered {
				t.Fatalf("observer did not recover after abnormal callback: got %+v, want %+v", got, recovered)
			}
		})
	}
}

func TestQualityObserverOrdinaryErrorRetainsLastSample(t *testing.T) {
	base, peer := newMemoryPathPair()
	initial := transport.PathQuality{RTT: 11 * time.Millisecond, At: time.Now()}
	recovered := transport.PathQuality{RTT: 17 * time.Millisecond, At: time.Now().Add(time.Millisecond)}
	path := &sequencedQualityCallbackPath{
		PathConn:  base,
		steps:     []qualityCallbackStep{qualityCallbackReturn, qualityCallbackError, qualityCallbackReturn},
		qualities: []transport.PathQuality{initial, {}, recovered},
	}
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = peer.Close()
	})

	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != initial {
		t.Fatalf("initial quality=%+v, want %+v", got, initial)
	}
	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != initial {
		t.Fatalf("ordinary error discarded prior quality: got %+v, want %+v", got, initial)
	}
	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != recovered {
		t.Fatalf("quality did not recover after ordinary error: got %+v, want %+v", got, recovered)
	}
}

func TestQualityObserverContextDeadlineInvalidatesPriorSample(t *testing.T) {
	base, peer := newMemoryPathPair()
	initial := transport.PathQuality{RTT: 11 * time.Millisecond, At: time.Now()}
	path := &sequencedQualityCallbackPath{
		PathConn: base,
		steps: []qualityCallbackStep{
			qualityCallbackReturn,
			qualityCallbackContextError,
		},
		qualities: []transport.PathQuality{initial, {}},
	}
	slot := newRouteEpochQualitySlot(t, path)
	t.Cleanup(func() {
		slot.stopQualityObserver()
		slot.waitQualityObserver()
		_ = base.Close()
		_ = peer.Close()
	})

	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != initial {
		t.Fatalf("initial quality=%+v, want %+v", got, initial)
	}
	if got := observePathQualities([]*pathSlot{slot}, time.Second)[slot]; got != (transport.PathQuality{}) {
		t.Fatalf("context deadline retained stale quality: %+v", got)
	}
	slot.qualityObserverMu.Lock()
	sampled := slot.qualityObserverSampled
	cached := slot.qualityObserverSample
	slot.qualityObserverMu.Unlock()
	if sampled || cached != (transport.PathQuality{}) {
		t.Fatalf("context deadline left cache eligible: sampled=%t quality=%+v", sampled, cached)
	}
}
