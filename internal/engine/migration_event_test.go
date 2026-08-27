package engine

import (
	"errors"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func commitMigrationEventForTest(t *testing.T, e *Engine, oldID, newID uint32, cause string) migrationEventDispatch {
	t.Helper()
	e.pathsMu.Lock()
	dispatch := e.recordMigrationLocked(oldID, newID, cause, e.routeMigrationEvidenceLocked())
	count := e.migrationCount
	e.pathsMu.Unlock()
	if dispatch.event.Ordinal != count {
		t.Fatalf("event ordinal=%d, committed migration count=%d", dispatch.event.Ordinal, count)
	}
	return dispatch
}

func receiveMigrationEvent(t *testing.T, events <-chan MigrationEvent) MigrationEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for migration event")
		return MigrationEvent{}
	}
}

func TestMigrationEventSubscriberSerializesCallbacks(t *testing.T) {
	e := &Engine{}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	arrivals := make(chan MigrationEvent, 2)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) {
		if event.Ordinal == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		arrivals <- event
	})
	defer subscription.Cancel()
	if subscription.AfterOrdinal() != 0 {
		t.Fatalf("initial subscription baseline=%d, want 0", subscription.AfterOrdinal())
	}

	first := commitMigrationEventForTest(t, e, 10, 20, "first")
	e.deliverMigrationEvent(first)
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first callback did not start")
	}

	second := commitMigrationEventForTest(t, e, 20, 30, "second")
	e.deliverMigrationEvent(second)
	select {
	case got := <-arrivals:
		t.Fatalf("second callback ran concurrently with blocked first callback: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	if got := receiveMigrationEvent(t, arrivals); got.Ordinal != 1 {
		t.Fatalf("first callback ordinal=%d, want 1", got.Ordinal)
	}
	if got := receiveMigrationEvent(t, arrivals); got.Ordinal != 2 {
		t.Fatalf("second callback ordinal=%d, want 2", got.Ordinal)
	}

	committed := []MigrationEvent{first.event, second.event}
	sort.Slice(committed, func(i, j int) bool { return committed[i].Ordinal < committed[j].Ordinal })
	for i, event := range committed {
		wantOrdinal := uint64(i + 1)
		if event.Ordinal != wantOrdinal {
			t.Fatalf("commit[%d] ordinal=%d, want %d", i, event.Ordinal, wantOrdinal)
		}
		if event.CommittedAt.IsZero() {
			t.Fatalf("commit[%d] has zero timestamp", i)
		}
	}
	if !committed[1].CommittedAt.After(committed[0].CommittedAt) {
		t.Fatalf("commit timestamps are not monotonic: first=%s second=%s",
			committed[0].CommittedAt, committed[1].CommittedAt)
	}
	if got := e.MigrationCount(); got != uint64(len(committed)) {
		t.Fatalf("MigrationCount=%d, want %d", got, len(committed))
	}
	if first.event.OldPathID != 10 || first.event.NewPathID != 20 || first.event.Cause != "first" {
		t.Fatalf("first event facts changed: %+v", first.event)
	}
}

func TestMigrationEventCancellationBoundary(t *testing.T) {
	e := &Engine{}
	events := make(chan MigrationEvent, 2)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	if subscription.AfterOrdinal() != 0 {
		t.Fatalf("initial subscription baseline=%d, want 0", subscription.AfterOrdinal())
	}

	committedBeforeCancel := commitMigrationEventForTest(t, e, 1, 2, "before-cancel")
	subscription.Cancel()
	e.deliverMigrationEvent(committedBeforeCancel)
	committedAfterCancel := commitMigrationEventForTest(t, e, 2, 3, "after-cancel")
	e.deliverMigrationEvent(committedAfterCancel)
	if got := receiveMigrationEvent(t, events); got.Ordinal != committedBeforeCancel.event.Ordinal {
		t.Fatalf("cancel suppressed already committed event: got=%+v want=%+v", got, committedBeforeCancel.event)
	}
	select {
	case got := <-events:
		t.Fatalf("received event after cancellation: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}

	// Cancellation is idempotent.
	subscription.Cancel()
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("canceled subscription worker did not drain")
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("normal cancellation error=%v", err)
	}

	t.Run("out-of-order suffix preserves the committed prefix", func(t *testing.T) {
		e := &Engine{}
		for index := 0; index < migrationEventQueueCapacity-1; index++ {
			_ = commitMigrationEventForTest(t, e, 1, 2, "baseline")
		}
		events := make(chan MigrationEvent, 2)
		subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
		if got, want := subscription.AfterOrdinal(), uint64(migrationEventQueueCapacity-1); got != want {
			t.Fatalf("AfterOrdinal=%d, want %d", got, want)
		}
		first := commitMigrationEventForTest(t, e, 2, 3, "ring-prefix")
		second := commitMigrationEventForTest(t, e, 3, 4, "ring-suffix")
		e.deliverMigrationEvent(second)
		subscription.Cancel()
		select {
		case <-subscription.Done():
			t.Fatal("cancellation discarded an out-of-order committed suffix")
		default:
		}
		e.deliverMigrationEvent(first)
		for index, want := range []uint64{first.event.Ordinal, second.event.Ordinal} {
			if got := receiveMigrationEvent(t, events); got.Ordinal != want {
				t.Fatalf("callback[%d] ordinal=%d, want %d", index, got.Ordinal, want)
			}
		}
		select {
		case <-subscription.Done():
		case <-time.After(time.Second):
			t.Fatal("canceled subscription did not drain its out-of-order prefix")
		}
	})
}

func TestMigrationEventReservationsShareFixedPendingBudget(t *testing.T) {
	e := &Engine{}
	var mu sync.Mutex
	received := make([]uint64, 0, migrationEventQueueCapacity)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) {
		mu.Lock()
		received = append(received, event.Ordinal)
		mu.Unlock()
	})

	dispatches := make([]migrationEventDispatch, 0, migrationEventQueueCapacity)
	for index := 0; index < migrationEventQueueCapacity; index++ {
		dispatch := commitMigrationEventForTest(t, e, 1, 2, "reserved")
		if len(dispatch.subscribers) != 1 {
			t.Fatalf("reservation[%d] subscribers=%d, want 1", index, len(dispatch.subscribers))
		}
		dispatches = append(dispatches, dispatch)
	}
	overflow := commitMigrationEventForTest(t, e, 2, 3, "overflow")
	if len(overflow.subscribers) != 0 {
		t.Fatalf("overflow reserved beyond fixed pending budget: subscribers=%d", len(overflow.subscribers))
	}
	if !errors.Is(subscription.Err(), ErrMigrationObserverLagged) {
		t.Fatalf("overflow error=%v, want %v", subscription.Err(), ErrMigrationObserverLagged)
	}

	subscription.mu.Lock()
	queued, reservations := subscription.queueLen, subscription.reservations
	subscription.mu.Unlock()
	if queued != 0 || reservations != migrationEventQueueCapacity {
		t.Fatalf("pre-delivery queue/reservations=%d/%d, want 0/%d",
			queued, reservations, migrationEventQueueCapacity)
	}
	for _, dispatch := range dispatches {
		e.deliverMigrationEvent(dispatch)
	}
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("lagged subscription did not drain its reserved prefix")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != migrationEventQueueCapacity {
		t.Fatalf("reserved callback count=%d, want %d", len(received), migrationEventQueueCapacity)
	}
	for index, ordinal := range received {
		if ordinal != uint64(index+1) {
			t.Fatalf("reserved callback[%d] ordinal=%d, want %d", index, ordinal, index+1)
		}
	}
}

func TestMigrationEventSlowSubscriberIsBoundedAndReportsLag(t *testing.T) {
	e := &Engine{}
	entered := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	var first sync.Once
	var calls atomic.Int32
	var active atomic.Int32
	var maximumActive atomic.Int32
	subscription := e.OnMigrationEvent(func(MigrationEvent) {
		current := active.Add(1)
		for {
			maximum := maximumActive.Load()
			if current <= maximum || maximumActive.CompareAndSwap(maximum, current) {
				break
			}
		}
		defer active.Add(-1)
		calls.Add(1)
		first.Do(func() {
			close(entered)
			<-release
		})
	})

	firstDispatch := commitMigrationEventForTest(t, e, 1, 2, "blocked-first")
	e.deliverMigrationEvent(firstDispatch)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("subscriber callback did not block")
	}
	for index := 0; index < migrationEventQueueCapacity; index++ {
		dispatch := commitMigrationEventForTest(t, e, 2, 3, "queued")
		e.deliverMigrationEvent(dispatch)
	}
	overflow := commitMigrationEventForTest(t, e, 3, 4, "overflow")
	e.deliverMigrationEvent(overflow)
	eventuallyEngine(t, time.Second, func() bool {
		return errors.Is(subscription.Err(), ErrMigrationObserverLagged)
	})

	e.pathsMu.RLock()
	_, stillRegistered := e.migrationEventSubscribers[subscription.id]
	e.pathsMu.RUnlock()
	if stillRegistered {
		t.Fatal("lagged subscriber remained registered for future commits")
	}
	subscription.mu.Lock()
	queued, reservations, accepting := subscription.queueLen, subscription.reservations, subscription.accepting
	subscription.mu.Unlock()
	if queued != migrationEventQueueCapacity || reservations != 0 || accepting {
		t.Fatalf("lagged subscription queue/reservations/accepting=%d/%d/%t",
			queued, reservations, accepting)
	}

	close(release)
	released = true
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("lagged subscription did not drain its bounded prefix")
	}
	if got := calls.Load(); got != migrationEventQueueCapacity+1 {
		t.Fatalf("callback count=%d, want blocked event plus %d queued events", got, migrationEventQueueCapacity)
	}
	if got := maximumActive.Load(); got != 1 {
		t.Fatalf("concurrent callbacks=%d, want one worker per subscription", got)
	}
	subscription.Cancel()
}

func TestMigrationEventPostCommitSubscriptionDoesNotSeeHistory(t *testing.T) {
	e := &Engine{}
	committed := commitMigrationEventForTest(t, e, 1, 2, "before-subscription")
	events := make(chan MigrationEvent, 1)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	if subscription.AfterOrdinal() != committed.event.Ordinal {
		t.Fatalf("post-commit subscription baseline=%d, want %d", subscription.AfterOrdinal(), committed.event.Ordinal)
	}
	e.deliverMigrationEvent(committed)
	select {
	case got := <-events:
		t.Fatalf("post-commit subscriber received historical event: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMigrationEventNilCallbackReturnsQuiescedSubscription(t *testing.T) {
	e := &Engine{}
	committed := commitMigrationEventForTest(t, e, 1, 2, "baseline")
	subscription := e.OnMigrationEvent(nil)
	if subscription.AfterOrdinal() != committed.event.Ordinal {
		t.Fatalf("inactive subscription baseline=%d, want %d", subscription.AfterOrdinal(), committed.event.Ordinal)
	}
	select {
	case <-subscription.Done():
	default:
		t.Fatal("nil callback subscription is not already quiesced")
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("nil callback subscription error=%v", err)
	}
	subscription.Cancel()
}

func TestMigrationEventSubscriberCountIsBoundedAndReusable(t *testing.T) {
	t.Run("per connection", func(t *testing.T) {
		baseline := runtime.NumGoroutine()
		e := &Engine{}
		if size := unsafe.Sizeof(migrationEventSubscriber{}); size > 512 {
			t.Fatalf("idle subscriber structure=%d bytes, want <=512", size)
		}
		subscriptions := make([]*migrationEventSubscriber, 0, migrationEventSubscriberCapacity)
		for index := 0; index < migrationEventSubscriberCapacity; index++ {
			subscription := e.OnMigrationEvent(func(MigrationEvent) {})
			if err := subscription.Err(); err != nil {
				t.Fatalf("subscription[%d] error=%v", index, err)
			}
			if subscription.queue != nil {
				t.Fatalf("idle subscription[%d] allocated a pending-event ring", index)
			}
			subscriptions = append(subscriptions, subscription)
		}
		if got := len(migrationEventProcessCallbackSlots); got != 0 {
			t.Fatalf("idle subscriptions own %d process callback slots", got)
		}
		if growth := runtime.NumGoroutine() - baseline; growth > 4 {
			t.Fatalf("idle subscription goroutine growth=%d, want <=4", growth)
		}

		rejected := e.OnMigrationEvent(func(MigrationEvent) {})
		if !errors.Is(rejected.Err(), ErrMigrationObserverLimit) {
			t.Fatalf("excess subscription error=%v, want %v", rejected.Err(), ErrMigrationObserverLimit)
		}
		select {
		case <-rejected.Done():
		default:
			t.Fatal("excess subscription is not immediately quiescent")
		}

		subscriptions[0].Cancel()
		select {
		case <-subscriptions[0].Done():
		case <-time.After(time.Second):
			t.Fatal("canceled idle subscription did not quiesce")
		}
		replacement := e.OnMigrationEvent(func(MigrationEvent) {})
		if err := replacement.Err(); err != nil {
			t.Fatalf("replacement subscription error=%v", err)
		}
		select {
		case <-replacement.Done():
			t.Fatal("replacement subscription was returned inactive")
		default:
		}

		for _, subscription := range subscriptions[1:] {
			subscription.Cancel()
		}
		replacement.Cancel()
		for _, subscription := range append(subscriptions[1:], replacement) {
			select {
			case <-subscription.Done():
			case <-time.After(time.Second):
				t.Fatal("subscription worker did not quiesce after cancellation")
			}
		}
	})

	t.Run("out-of-order delivery remains ordered", func(t *testing.T) {
		e := &Engine{}
		events := make(chan MigrationEvent, 2)
		subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
		first := commitMigrationEventForTest(t, e, 1, 2, "first")
		second := commitMigrationEventForTest(t, e, 2, 3, "second")

		e.deliverMigrationEvent(second)
		select {
		case event := <-events:
			t.Fatalf("later ordinal ran before missing prefix: %+v", event)
		case <-time.After(20 * time.Millisecond):
		}
		if got := len(migrationEventProcessCallbackSlots); got != 0 {
			t.Fatalf("non-runnable suffix owns %d callback slots", got)
		}

		e.deliverMigrationEvent(first)
		for index, want := range []uint64{first.event.Ordinal, second.event.Ordinal} {
			if got := receiveMigrationEvent(t, events); got.Ordinal != want {
				t.Fatalf("callback[%d] ordinal=%d, want %d", index, got.Ordinal, want)
			}
		}
		subscription.Cancel()
		select {
		case <-subscription.Done():
		case <-time.After(time.Second):
			t.Fatal("ordered subscription did not quiesce")
		}
	})

	t.Run("idle process population", func(t *testing.T) {
		baseline := runtime.NumGoroutine()
		count := migrationEventProcessCallbackCapacity + 1
		engines := make([]*Engine, 0, 1+count/migrationEventSubscriberCapacity)
		subscriptions := make([]*migrationEventSubscriber, 0, count)
		for index := 0; index < count; index++ {
			if index%migrationEventSubscriberCapacity == 0 {
				engines = append(engines, &Engine{})
			}
			subscription := engines[len(engines)-1].OnMigrationEvent(func(MigrationEvent) {})
			if err := subscription.Err(); err != nil {
				t.Fatalf("process subscription[%d] error=%v", index, err)
			}
			subscriptions = append(subscriptions, subscription)
		}
		if got := len(migrationEventProcessCallbackSlots); got != 0 {
			t.Fatalf("idle process population owns %d callback slots", got)
		}
		if growth := runtime.NumGoroutine() - baseline; growth > 4 {
			t.Fatalf("idle process population goroutine growth=%d, want <=4", growth)
		}

		for _, subscription := range subscriptions {
			subscription.Cancel()
		}
		for _, subscription := range subscriptions {
			select {
			case <-subscription.Done():
			case <-time.After(time.Second):
				t.Fatal("idle process subscription did not quiesce after cancellation")
			}
		}
	})

	t.Run("active process capacity and reuse", func(t *testing.T) {
		if got := len(migrationEventProcessCallbackSlots); got != 0 {
			t.Fatalf("callback slots before test=%d, want 0", got)
		}
		baseline := runtime.NumGoroutine()
		engines := make([]*Engine, 0, migrationEventProcessCallbackCapacity)
		subscriptions := make([]*migrationEventSubscriber, 0, migrationEventProcessCallbackCapacity)
		entered := make([]chan struct{}, migrationEventProcessCallbackCapacity)
		release := make([]chan struct{}, migrationEventProcessCallbackCapacity)
		released := make([]atomic.Bool, migrationEventProcessCallbackCapacity)
		releaseOne := func(index int) {
			if released[index].CompareAndSwap(false, true) {
				close(release[index])
			}
		}
		t.Cleanup(func() {
			for index, subscription := range subscriptions {
				subscription.Cancel()
				releaseOne(index)
			}
		})

		for index := 0; index < migrationEventProcessCallbackCapacity; index++ {
			engine := &Engine{}
			engines = append(engines, engine)
			entered[index] = make(chan struct{})
			release[index] = make(chan struct{})
			callbackIndex := index
			subscription := engine.OnMigrationEvent(func(MigrationEvent) {
				close(entered[callbackIndex])
				<-release[callbackIndex]
			})
			if err := subscription.Err(); err != nil {
				t.Fatalf("active subscription[%d] error=%v", index, err)
			}
			subscriptions = append(subscriptions, subscription)
			dispatch := commitMigrationEventForTest(t, engine, 1, 2, "block")
			engine.deliverMigrationEvent(dispatch)
			select {
			case <-entered[index]:
			case <-time.After(time.Second):
				t.Fatalf("active callback[%d] did not start", index)
			}
		}
		if got := len(migrationEventProcessCallbackSlots); got != migrationEventProcessCallbackCapacity {
			t.Fatalf("active callback slots=%d, want %d", got, migrationEventProcessCallbackCapacity)
		}
		if growth := runtime.NumGoroutine() - baseline; growth > migrationEventProcessCallbackCapacity+8 {
			t.Fatalf("blocked callback goroutine growth=%d exceeds bound", growth)
		}

		var excessCalls atomic.Int32
		excessEngine := &Engine{}
		excess := excessEngine.OnMigrationEvent(func(MigrationEvent) { excessCalls.Add(1) })
		if err := excess.Err(); err != nil {
			t.Fatalf("idle excess subscription was rejected early: %v", err)
		}
		excessDispatch := commitMigrationEventForTest(t, excessEngine, 1, 2, "capacity")
		excessEngine.deliverMigrationEvent(excessDispatch)
		if !errors.Is(excess.Err(), ErrMigrationObserverLimit) {
			t.Fatalf("active capacity error=%v, want %v", excess.Err(), ErrMigrationObserverLimit)
		}
		select {
		case <-excess.Done():
		default:
			t.Fatal("capacity-rejected callback subscription is not immediately quiescent")
		}
		if got := excessCalls.Load(); got != 0 {
			t.Fatalf("capacity-rejected callback calls=%d, want 0", got)
		}

		lagEngine := &Engine{}
		var lagCalls atomic.Int32
		lagged := lagEngine.OnMigrationEvent(func(MigrationEvent) { lagCalls.Add(1) })
		lagDispatches := make([]migrationEventDispatch, 0, migrationEventQueueCapacity)
		for index := 0; index < migrationEventQueueCapacity; index++ {
			lagDispatches = append(lagDispatches,
				commitMigrationEventForTest(t, lagEngine, 1, 2, "reserved-lag-prefix"))
		}
		if dispatch := commitMigrationEventForTest(t, lagEngine, 2, 3, "lag-overflow"); len(dispatch.subscribers) != 0 {
			t.Fatalf("lag overflow retained %d subscribers", len(dispatch.subscribers))
		}
		if !errors.Is(lagged.Err(), ErrMigrationObserverLagged) {
			t.Fatalf("pre-delivery lag error=%v, want %v", lagged.Err(), ErrMigrationObserverLagged)
		}
		for _, dispatch := range lagDispatches {
			lagEngine.deliverMigrationEvent(dispatch)
		}
		select {
		case <-lagged.Done():
		default:
			t.Fatal("capacity-rejected lagged subscription is not quiescent")
		}
		if !errors.Is(lagged.Err(), ErrMigrationObserverLagged) {
			t.Fatalf("capacity rejection replaced stable lag error with %v", lagged.Err())
		}
		if got := lagCalls.Load(); got != 0 {
			t.Fatalf("capacity-rejected lagged callback calls=%d, want 0", got)
		}

		subscriptions[0].Cancel()
		select {
		case <-subscriptions[0].Done():
			t.Fatal("cancellation reclaimed a slot while its callback was still active")
		default:
		}
		if got := len(migrationEventProcessCallbackSlots); got != migrationEventProcessCallbackCapacity {
			t.Fatalf("callback slots after cancellation=%d, want %d", got, migrationEventProcessCallbackCapacity)
		}
		releaseOne(0)
		select {
		case <-subscriptions[0].Done():
		case <-time.After(time.Second):
			t.Fatal("released canceled callback did not quiesce")
		}

		goexitEngine := &Engine{}
		goexit := goexitEngine.OnMigrationEvent(func(MigrationEvent) { runtime.Goexit() })
		goexitDispatch := commitMigrationEventForTest(t, goexitEngine, 1, 2, "goexit")
		goexitEngine.deliverMigrationEvent(goexitDispatch)
		select {
		case <-goexit.Done():
		case <-time.After(time.Second):
			t.Fatal("Goexit callback did not release process capacity")
		}
		if !errors.Is(goexit.Err(), ErrMigrationObserverCallbackFailed) {
			t.Fatalf("Goexit callback error=%v, want %v", goexit.Err(), ErrMigrationObserverCallbackFailed)
		}

		run := make(chan struct{})
		replacementEngine := &Engine{}
		replacement := replacementEngine.OnMigrationEvent(func(MigrationEvent) { close(run) })
		replacementDispatch := commitMigrationEventForTest(t, replacementEngine, 1, 2, "replacement")
		replacementEngine.deliverMigrationEvent(replacementDispatch)
		select {
		case <-run:
		case <-time.After(time.Second):
			t.Fatal("replacement callback did not reuse process capacity")
		}
		replacement.Cancel()
		select {
		case <-replacement.Done():
		case <-time.After(time.Second):
			t.Fatal("replacement subscription did not quiesce")
		}

		for index := 1; index < len(subscriptions); index++ {
			subscriptions[index].Cancel()
			releaseOne(index)
		}
		for index := 1; index < len(subscriptions); index++ {
			select {
			case <-subscriptions[index].Done():
			case <-time.After(time.Second):
				t.Fatalf("active subscription[%d] did not quiesce", index)
			}
		}
		if got := len(migrationEventProcessCallbackSlots); got != 0 {
			t.Fatalf("process callback slots after cleanup=%d, want 0", got)
		}
		eventuallyEngine(t, time.Second, func() bool {
			return runtime.NumGoroutine()-baseline <= 8
		})
	})
}

func TestMigrationEventEvidenceIsSortedFrozenAndSubscriberIsolated(t *testing.T) {
	e := &Engine{}
	e.pathTopologyEpoch.Store(17)
	commit := selectorEvidenceCommit{
		topologyEpoch: 17,
		healthEpoch:   23,
		capturedAt:    time.Now(),
		validUntil:    time.Now().Add(time.Second),
		generations: []selectorPathGenerationBinding{
			{
				pathID: 9, owner: 90, slotGeneration: 900,
				probeGeneration: pathProbeGeneration{
					routeGeneration: 91, endpointGeneration: 92, peerMobilityEpoch: 93,
				},
				healthRevision: 94,
			},
			{
				pathID: 3, owner: 30, slotGeneration: 300,
				probeGeneration: pathProbeGeneration{
					routeGeneration: 31, endpointGeneration: 32, peerMobilityEpoch: 33,
				},
				healthRevision: 34,
			},
		},
	}

	mutated := make(chan struct{})
	good := make(chan MigrationEvent, 1)
	mutatorSubscription := e.OnMigrationEvent(func(event MigrationEvent) {
		event.Evidence.ProbeGenerations[0].PathID = 999
		close(mutated)
		panic("injected observer panic")
	})
	defer mutatorSubscription.Cancel()
	goodSubscription := e.OnMigrationEvent(func(event MigrationEvent) { good <- event })
	defer goodSubscription.Cancel()

	e.pathsMu.Lock()
	evidence := e.selectorMigrationEvidenceLocked(commit)
	dispatch := e.recordMigrationLocked(3, 9, "quality", evidence)
	e.pathsMu.Unlock()
	evidence.ProbeGenerations[0].PathID = 777
	e.deliverMigrationEvent(dispatch)

	select {
	case <-mutated:
	case <-time.After(time.Second):
		t.Fatal("mutating observer did not run")
	}
	event := receiveMigrationEvent(t, good)
	if event.Evidence.Kind != MigrationEvidenceSelector || event.Evidence.TopologyEpoch != 17 ||
		event.Evidence.HealthEpoch != 23 ||
		len(event.Evidence.ProbeGenerations) != 2 {
		t.Fatalf("selector evidence=%+v", event.Evidence)
	}
	first, second := event.Evidence.ProbeGenerations[0], event.Evidence.ProbeGenerations[1]
	if first != (MigrationProbeGeneration{
		PathID: 3, PathOwner: 30, PathGeneration: 300,
		RouteGeneration: 31, EndpointGeneration: 32, PeerMobilityEpoch: 33, HealthRevision: 34,
	}) || second != (MigrationProbeGeneration{
		PathID: 9, PathOwner: 90, PathGeneration: 900,
		RouteGeneration: 91, EndpointGeneration: 92, PeerMobilityEpoch: 93, HealthRevision: 94,
	}) {
		t.Fatalf("selector generation vector=%+v", event.Evidence.ProbeGenerations)
	}
	if dispatch.event.Evidence.ProbeGenerations[0].PathID != 3 {
		t.Fatalf("subscriber mutated committed event=%+v", dispatch.event.Evidence.ProbeGenerations)
	}
}

func TestMigrationEventCallbackMayReenterObserverAPI(t *testing.T) {
	e := &Engine{}
	done := make(chan uint64, 1)
	subscription := e.OnMigrationEvent(func(MigrationEvent) {
		nested := e.OnMigrationEvent(func(MigrationEvent) {})
		nested.Cancel()
		done <- nested.AfterOrdinal()
	})
	defer subscription.Cancel()
	dispatch := commitMigrationEventForTest(t, e, 1, 2, "reentrant")
	e.deliverMigrationEvent(dispatch)
	select {
	case baseline := <-done:
		if baseline != dispatch.event.Ordinal {
			t.Fatalf("reentrant subscription baseline=%d, want %d", baseline, dispatch.event.Ordinal)
		}
	case <-time.After(time.Second):
		t.Fatal("migration callback could not reenter observer API")
	}
}

func TestMigrationEventCallbackPanicTerminatesSubscription(t *testing.T) {
	e := &Engine{}
	var calls atomic.Int32
	subscription := e.OnMigrationEvent(func(MigrationEvent) {
		calls.Add(1)
		panic("injected observer panic")
	})

	first := commitMigrationEventForTest(t, e, 1, 2, "panic")
	second := commitMigrationEventForTest(t, e, 2, 3, "reserved-before-panic")
	if len(second.subscribers) != 1 {
		t.Fatalf("second event was not reserved before callback panic: subscribers=%d", len(second.subscribers))
	}
	e.deliverMigrationEvent(first)
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("panicked callback did not terminate its subscription")
	}
	if !errors.Is(subscription.Err(), ErrMigrationObserverCallbackFailed) {
		t.Fatalf("panicked callback error=%v, want %v", subscription.Err(), ErrMigrationObserverCallbackFailed)
	}
	e.deliverMigrationEvent(second)
	subscription.mu.Lock()
	queued, reservations := subscription.queueLen, subscription.reservations
	subscription.mu.Unlock()
	if queued != 0 || reservations != 0 {
		t.Fatalf("panicked subscription retained queue/reservations=%d/%d", queued, reservations)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback calls=%d, want only the panicked event", got)
	}
}

func TestMigrationEventCallbackGoexitTerminatesSubscription(t *testing.T) {
	e := &Engine{}
	entered := make(chan struct{})
	subscription := e.OnMigrationEvent(func(MigrationEvent) {
		close(entered)
		runtime.Goexit()
	})
	dispatch := commitMigrationEventForTest(t, e, 1, 2, "goexit")
	e.deliverMigrationEvent(dispatch)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Goexit callback did not start")
	}
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("Goexit callback left its subscription worker registered")
	}
	if !errors.Is(subscription.Err(), ErrMigrationObserverCallbackFailed) {
		t.Fatalf("Goexit callback error=%v, want %v", subscription.Err(), ErrMigrationObserverCallbackFailed)
	}
	e.pathsMu.RLock()
	_, registered := e.migrationEventSubscribers[subscription.id]
	e.pathsMu.RUnlock()
	if registered {
		t.Fatal("Goexit callback subscription remained registered")
	}
}

func TestMigrationEventCallbackMayCancelItself(t *testing.T) {
	e := &Engine{}
	returned := make(chan struct{})
	var subscription *migrationEventSubscriber
	subscription = e.OnMigrationEvent(func(MigrationEvent) {
		subscription.Cancel()
		close(returned)
	})
	dispatch := commitMigrationEventForTest(t, e, 1, 2, "self-cancel")
	e.deliverMigrationEvent(dispatch)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("self-cancel callback did not return")
	}
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("self-canceled subscription did not quiesce")
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("self-cancel error=%v", err)
	}
}

func TestMigrationEventCallbackMayCloseEngine(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	closed := make(chan error, 1)
	subscription := e.OnMigrationEvent(func(MigrationEvent) { closed <- e.Close() })
	dispatch := commitMigrationEventForTest(t, e, 1, 2, "callback-close")
	e.deliverMigrationEvent(dispatch)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("callback engine close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("callback could not close engine")
	}
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("engine-close subscription did not quiesce")
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("callback close changed subscription error: %v", err)
	}
}

func TestMigrationEventBlockedCallbackDoesNotBlockEngineClose(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	entered := make(chan struct{})
	release := make(chan struct{})
	subscription := e.OnMigrationEvent(func(MigrationEvent) {
		close(entered)
		<-release
	})
	dispatch := commitMigrationEventForTest(t, e, 1, 2, "blocked-close")
	e.deliverMigrationEvent(dispatch)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("observer callback did not block")
	}

	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("engine close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("engine close waited for external observer callback")
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("engine close changed subscription error: %v", err)
	}
	close(release)
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("subscription worker did not exit after callback release")
	}
}

func TestMigrationEventEngineClosePreservesReservedPrefix(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	events := make(chan MigrationEvent, 2)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	first := commitMigrationEventForTest(t, e, 1, 2, "before-close-1")
	second := commitMigrationEventForTest(t, e, 2, 3, "before-close-2")
	if err := e.Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}
	select {
	case <-subscription.Done():
		t.Fatal("subscription quiesced before committed reservations were delivered")
	default:
	}
	e.deliverMigrationEvent(first)
	e.deliverMigrationEvent(second)
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("closed-engine subscription did not drain committed prefix")
	}
	for index, want := range []uint64{first.event.Ordinal, second.event.Ordinal} {
		select {
		case event := <-events:
			if event.Ordinal != want {
				t.Fatalf("event[%d] ordinal=%d, want %d", index, event.Ordinal, want)
			}
		default:
			t.Fatalf("missing callback[%d] after subscription quiescence", index)
		}
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("engine close changed subscription error: %v", err)
	}

	t.Run("out-of-order suffix survives close across the ring boundary", func(t *testing.T) {
		e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
		for index := 0; index < migrationEventQueueCapacity-1; index++ {
			_ = commitMigrationEventForTest(t, e, 1, 2, "baseline")
		}
		events := make(chan MigrationEvent, 2)
		subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
		first := commitMigrationEventForTest(t, e, 2, 3, "close-ring-prefix")
		second := commitMigrationEventForTest(t, e, 3, 4, "close-ring-suffix")
		e.deliverMigrationEvent(second)
		if err := e.Close(); err != nil {
			t.Fatalf("engine close: %v", err)
		}
		select {
		case <-subscription.Done():
			t.Fatal("engine close discarded an out-of-order committed suffix")
		default:
		}
		e.deliverMigrationEvent(first)
		for index, want := range []uint64{first.event.Ordinal, second.event.Ordinal} {
			if got := receiveMigrationEvent(t, events); got.Ordinal != want {
				t.Fatalf("callback[%d] ordinal=%d, want %d", index, got.Ordinal, want)
			}
		}
		select {
		case <-subscription.Done():
		case <-time.After(time.Second):
			t.Fatal("closed-engine subscription did not drain its out-of-order prefix")
		}
		if err := subscription.Err(); err != nil {
			t.Fatalf("engine close changed subscription error: %v", err)
		}
	})
}

func TestNonRetainingStagedActivationPreservesSourceMigrationBinding(t *testing.T) {
	e, pathBinding := newAdmissionAdversarialEngine(t, SideClient)
	predecessor, predecessorPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = predecessorPeer.Close() })
	predecessorID, err := e.AttachPathBound(
		predecessor, transport.PathSpec{Transport: "memory"}, pathBinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	successor, successorPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = successorPeer.Close() })
	successorID, _ := prepareBoundAdmission(t, e, successor, pathBinding, 0xa7)
	if err := e.StagePathAttach(successorID); err != nil {
		t.Fatal(err)
	}

	e.pathsMu.RLock()
	wantSource := e.migrationPathBindingLocked(predecessorID)
	e.pathsMu.RUnlock()
	events := make(chan MigrationEvent, 1)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	if err := e.ActivateStagedPath(successorID, false); err != nil {
		t.Fatal(err)
	}
	event := receiveMigrationEvent(t, events)
	e.pathsMu.RLock()
	wantResult := e.migrationPathBindingLocked(successorID)
	e.pathsMu.RUnlock()
	if event.OldPathID != predecessorID || event.NewPathID != successorID || event.Cause != "recovery" {
		t.Fatalf("activation event=%+v", event)
	}
	if event.Evidence.Source != wantSource || event.Evidence.Result != wantResult {
		t.Fatalf("activation bindings source=%+v result=%+v, want source=%+v result=%+v",
			event.Evidence.Source, event.Evidence.Result, wantSource, wantResult)
	}
	if event.Evidence.Source.PathOwner == 0 || event.Evidence.Source.PathGeneration == 0 ||
		event.Evidence.Source.LocalTargetID == ([16]byte{}) || event.Evidence.Source.PeerTargetID == ([16]byte{}) {
		t.Fatalf("activation source is not physically bound: %+v", event.Evidence.Source)
	}
}

func TestCompositeLeafReplacementEmitsExactMigrationBinding(t *testing.T) {
	for _, group := range []struct {
		name string
		kind proto.GraphNodeKind
	}{
		{name: "bond", kind: proto.GraphNodeKindBond},
		{name: "race", kind: proto.GraphNodeKindRace},
	} {
		t.Run(group.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				topologyName := "root"
				if nested {
					topologyName = "nested"
				}
				t.Run(topologyName, func(t *testing.T) {
					for _, replaceRepresentative := range []bool{false, true} {
						roleName := "non-representative"
						if replaceRepresentative {
							roleName = "representative"
						}
						t.Run(roleName, func(t *testing.T) {
							for _, retain := range []bool{false, true} {
								retainName := "retire-predecessor"
								if retain {
									retainName = "retain-predecessor"
								}
								t.Run(retainName, func(t *testing.T) {
									testCompositeLeafReplacementMigrationBinding(
										t, group.kind, nested, replaceRepresentative, retain,
									)
								})
							}
						})
					}
				})
			}
		})
	}
	t.Run("zombie-accounting-and-late-predecessor-death", testCompositeLeafReplacementZombieAccounting)
	t.Run("inactive-selector-leaf-does-not-charge-zombie", testInactiveSelectorLeafReplacementZombieAccounting)
}

func testInactiveSelectorLeafReplacementZombieAccounting(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{
		MigrationBudget: time.Second, ZombieMaxMigrations: 2,
		ZombieCooldown: time.Hour, ProbeInterval: time.Hour,
	}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	bindings := map[string]PathBinding{
		"a": {LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]},
		"b": {LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"]},
	}
	pathA := newLifecycleHealthyPath()
	aID, err := e.AttachPathBound(pathA,
		transport.PathSpec{Transport: "memory", Address: "a"}, bindings["a"])
	if err != nil {
		t.Fatal(err)
	}
	pathB := newLifecycleHealthyPath()
	bID, err := e.AttachPathBound(pathB,
		transport.PathSpec{Transport: "memory", Address: "b"}, bindings["b"])
	if err != nil {
		t.Fatal(err)
	}
	if e.ActivePath() != aID {
		t.Fatalf("initial active path=%d want=%d", e.ActivePath(), aID)
	}

	pathA.die(transport.CauseTransportError, errors.New("selected path failed"))
	eventuallyEngine(t, time.Second, func() bool { return e.ActivePath() == bID })
	eventuallyEngine(t, time.Second, func() bool {
		e.policyStateMu.Lock()
		selected := e.policySelections[ids["root"]]
		e.policyStateMu.Unlock()
		return selected == ids["b"]
	})
	if got := e.MigrationCount(); got != 1 {
		t.Fatalf("selected-path failover migrations=%d want=1", got)
	}
	if got := policyTxZombieLeft(e); got != 1 {
		t.Fatalf("selected-path failover zombie budget=%d want=1", got)
	}

	recoveredA := newLifecycleHealthyPath()
	if _, err := e.AttachPathBound(recoveredA,
		transport.PathSpec{Transport: "memory", Address: "a-recovered"}, bindings["a"]); err != nil {
		t.Fatal(err)
	}
	if e.ActivePath() != bID {
		t.Fatalf("inactive leaf recovery changed active path to %d want=%d", e.ActivePath(), bID)
	}

	replacementA := newLifecycleHealthyPath()
	replacementID, err := e.AttachPathBound(replacementA,
		transport.PathSpec{Transport: "memory", Address: "a-replacement"}, bindings["a"])
	if err != nil {
		t.Fatal(err)
	}
	if replacementID == 0 || e.ActivePath() != bID {
		t.Fatalf("inactive replacement path/active=%d/%d want nonzero/%d", replacementID, e.ActivePath(), bID)
	}
	if got := e.MigrationCount(); got != 2 {
		t.Fatalf("inactive replacement migrations=%d want=2", got)
	}
	if got := policyTxZombieLeft(e); got != 1 {
		t.Fatalf("inactive replacement charged zombie budget: got=%d want=1", got)
	}
	if err := e.CloseErr(); err != nil {
		t.Fatalf("inactive replacement closed healthy session: %v", err)
	}
}

type lateDeathClaimedPath struct {
	*claimedMemoryPath

	mu        sync.Mutex
	death     func(transport.DeathCause, error)
	closeOnce sync.Once
	closed    chan struct{}
	fire      chan struct{}
	fired     chan struct{}
}

func (path *lateDeathClaimedPath) OnDeath(fn func(transport.DeathCause, error)) {
	path.mu.Lock()
	path.death = fn
	path.mu.Unlock()
}

func (path *lateDeathClaimedPath) Close() error {
	var closeErr error
	path.closeOnce.Do(func() {
		closeErr = path.claimedMemoryPath.Close()
		close(path.closed)
		go func() {
			<-path.fire
			path.mu.Lock()
			death := path.death
			path.mu.Unlock()
			if death != nil {
				death(transport.CauseTransportError, errors.New("late retired predecessor death"))
			}
			close(path.fired)
		}()
	})
	return closeErr
}

func testCompositeLeafReplacementZombieAccounting(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindBond, "aggregate", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{
		MigrationBudget: time.Second, ZombieMaxMigrations: 2,
		ZombieCooldown: time.Hour, ProbeInterval: time.Hour,
	}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	bindings := map[string]PathBinding{
		"a": {LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]},
		"b": {LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"]},
	}
	a, aPeer := newClaimedMigrationEventPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	if _, err := e.AttachPathBound(a,
		transport.PathSpec{Transport: "memory", Address: "a"}, bindings["a"]); err != nil {
		t.Fatal(err)
	}
	bBase, bPeer := newClaimedMigrationEventPathPair()
	t.Cleanup(func() { _ = bPeer.Close() })
	bClaimed := bBase.(*claimedMemoryPath)
	b := &lateDeathClaimedPath{
		claimedMemoryPath: bClaimed,
		closed:            make(chan struct{}),
		fire:              make(chan struct{}),
		fired:             make(chan struct{}),
	}
	if _, err := e.AttachPathBound(b,
		transport.PathSpec{Transport: "memory", Address: "b"}, bindings["b"]); err != nil {
		t.Fatal(err)
	}

	events := make(chan MigrationEvent, 4)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	replaceB := func(tag byte) uint32 {
		t.Helper()
		successor, peer := newClaimedMigrationEventPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		id, _ := prepareBoundAdmission(t, e, successor, bindings["b"], tag)
		if err := e.StagePathAttach(id); err != nil {
			t.Fatal(err)
		}
		if err := e.ActivateStagedPath(id, false); err != nil {
			t.Fatal(err)
		}
		return id
	}

	firstID := replaceB(0xc1)
	first := receiveMigrationEvent(t, events)
	if first.NewPathID != firstID || first.Ordinal != 1 {
		t.Fatalf("first composite replacement event=%+v", first)
	}
	select {
	case <-b.closed:
	case <-time.After(time.Second):
		t.Fatal("first predecessor did not retire")
	}
	close(b.fire)
	select {
	case <-b.fired:
	case <-time.After(time.Second):
		t.Fatal("late predecessor death did not fire")
	}
	time.Sleep(20 * time.Millisecond)
	if got := e.MigrationCount(); got != 1 {
		t.Fatalf("late predecessor death changed migration count to %d", got)
	}
	e.zombieMu.Lock()
	leftAfterFirst := e.zombieLeft
	e.zombieMu.Unlock()
	if leftAfterFirst != 1 || errors.Is(e.CloseErr(), ErrZombie) {
		t.Fatalf("first replacement zombie state left/error=%d/%v", leftAfterFirst, e.CloseErr())
	}
	select {
	case duplicate := <-events:
		t.Fatalf("late predecessor death emitted duplicate event: %+v", duplicate)
	default:
	}

	secondID := replaceB(0xc2)
	second := receiveMigrationEvent(t, events)
	if second.NewPathID != secondID || second.Ordinal != 2 {
		t.Fatalf("second composite replacement event=%+v", second)
	}
	eventuallyEngine(t, time.Second, func() bool { return errors.Is(e.CloseErr(), ErrZombie) })
	if got := e.MigrationCount(); got != 2 {
		t.Fatalf("two composite replacements migration count=%d want 2", got)
	}
	select {
	case duplicate := <-events:
		t.Fatalf("zombie close emitted duplicate migration event: %+v", duplicate)
	case <-time.After(20 * time.Millisecond):
	}
}

func testCompositeLeafReplacementMigrationBinding(
	t *testing.T,
	groupKind proto.GraphNodeKind,
	nested bool,
	replaceRepresentative bool,
	retain bool,
) {
	t.Helper()
	groupName := "aggregate"
	if groupKind == proto.GraphNodeKindRace {
		groupName = "redundant"
	}
	groupNode := runtimeNode(groupKind, groupName, "a", "b")
	nodes := []proto.GraphNode{groupNode, runtimeNode(proto.GraphNodeKindPath, "a"), runtimeNode(proto.GraphNodeKindPath, "b")}
	if nested {
		nodes = append([]proto.GraphNode{runtimeNode(proto.GraphNodeKindSelector, "root", groupName)}, nodes...)
	}
	manifest, ids := runtimeGraph(t, nodes...)
	e := New(SideClient, NewClientFlowID(), Limits{
		MigrationBudget: time.Second, ZombieMaxMigrations: 32, ProbeInterval: time.Hour,
	}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	bindings := map[string]PathBinding{
		"a": {LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]},
		"b": {LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"]},
	}
	pathIDs := make(map[string]uint32, 2)
	for _, name := range []string{"a", "b"} {
		path, peer := newClaimedMigrationEventPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		pathID, err := e.AttachPathBound(path,
			transport.PathSpec{Transport: "memory", Address: name}, bindings[name])
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		pathIDs[name] = pathID
	}
	if got := e.MigrationCount(); got != 0 {
		t.Fatalf("initial composite activation emitted %d migration events", got)
	}
	if got := e.ActivePath(); got != pathIDs["a"] {
		t.Fatalf("initial representative=%d, want a=%d", got, pathIDs["a"])
	}

	replacedName := "b"
	if replaceRepresentative {
		replacedName = "a"
	}
	predecessorID := pathIDs[replacedName]
	e.pathsMu.RLock()
	wantSource := e.migrationPathBindingLocked(predecessorID)
	e.pathsMu.RUnlock()
	if wantSource.EndpointGeneration == 0 {
		t.Fatalf("predecessor endpoint generation is zero: %+v", wantSource)
	}

	successor, successorPeer := newClaimedMigrationEventPathPair()
	t.Cleanup(func() { _ = successorPeer.Close() })
	successorID, _ := prepareBoundAdmission(t, e, successor, bindings[replacedName], byte(0xb0+predecessorID))
	if err := e.StagePathAttach(successorID); err != nil {
		t.Fatal(err)
	}
	events := make(chan MigrationEvent, 2)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	if err := e.ActivateStagedPath(successorID, retain); err != nil {
		t.Fatal(err)
	}
	event := receiveMigrationEvent(t, events)
	e.pathsMu.RLock()
	wantResult := e.migrationPathBindingLocked(successorID)
	e.pathsMu.RUnlock()
	if event.OldPathID != predecessorID || event.NewPathID != successorID || event.Cause != "recovery" {
		t.Fatalf("leaf replacement event=%+v, want %d->%d recovery", event, predecessorID, successorID)
	}
	if event.Evidence.Source != wantSource || event.Evidence.Result != wantResult {
		t.Fatalf("leaf replacement bindings source=%+v result=%+v, want source=%+v result=%+v",
			event.Evidence.Source, event.Evidence.Result, wantSource, wantResult)
	}
	if event.Evidence.Source.EndpointGeneration == 0 || event.Evidence.Result.EndpointGeneration == 0 {
		t.Fatalf("leaf replacement cleared endpoint generation: %+v", event.Evidence)
	}
	if got := e.MigrationCount(); got != 1 || event.Ordinal != got {
		t.Fatalf("leaf replacement count/event=%d/%d, want 1", got, event.Ordinal)
	}
	select {
	case duplicate := <-events:
		t.Fatalf("one leaf replacement emitted duplicate event: %+v", duplicate)
	case <-time.After(20 * time.Millisecond):
	}
}

func newClaimedMigrationEventPathPair() (transport.PathConn, transport.PathConn) {
	path, peer := newMemoryPathPair()
	claim := leafmobility.MustNewClaim(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Scope: leafmobility.ScopeEndpoint, Session: leafmobility.SessionStream,
		Generation: leafmobility.NextGeneration(),
	})
	return &claimedMemoryPath{PathConn: path, claim: claim}, peer
}

func TestPathDeathMigrationEventPrecedesSerialLifecycleHook(t *testing.T) {
	tests := []struct {
		name       string
		hook       func(entered chan<- struct{}, release <-chan struct{})
		wantReturn bool
		wantPanic  bool
	}{
		{
			name: "blocked",
			hook: func(entered chan<- struct{}, release <-chan struct{}) {
				close(entered)
				<-release
			},
			wantReturn: true,
		},
		{
			name: "panic",
			hook: func(chan<- struct{}, <-chan struct{}) {
				panic("injected serial path-death hook panic")
			},
			wantPanic: true,
		},
		{
			name: "goexit",
			hook: func(chan<- struct{}, <-chan struct{}) {
				runtime.Goexit()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			targets := configureLeafSelectorRuntime(t, e, "primary", "successor")
			primary := newTxAdversarialPath()
			successor := newTxAdversarialPath()
			primaryID := attachFixturePath(t, e, primary,
				transport.PathSpec{Transport: "adversarial", Address: "primary"}, targets["primary"])
			successorID := attachFixturePath(t, e, successor,
				transport.PathSpec{Transport: "adversarial", Address: "successor"}, targets["successor"])
			primaryRef, ok := e.PathRef(primaryID)
			if !ok {
				t.Fatal("primary path ref is unavailable")
			}
			e.pathsMu.RLock()
			primarySlot := e.paths[primaryID]
			e.pathsMu.RUnlock()
			if primarySlot == nil {
				t.Fatal("primary slot is unavailable")
			}

			events := make(chan MigrationEvent, 1)
			subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
			defer subscription.Cancel()
			entered := make(chan struct{})
			release := make(chan struct{})
			cancelHook := e.OnPathDeathSerial(func(PathDeathEvent) { test.hook(entered, release) })
			defer cancelHook()
			type outcome struct {
				returned  bool
				recovered any
			}
			finished := make(chan outcome, 1)
			go func() {
				returned := false
				defer func() { finished <- outcome{returned: returned, recovered: recover()} }()
				e.onPathDeath(primaryID, primaryRef.Owner, transport.CauseTransportError,
					errors.New("injected primary path death"))
				returned = true
			}()

			if test.name == "blocked" {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("serial lifecycle hook did not block")
				}
			}
			event := receiveMigrationEvent(t, events)
			if event.OldPathID != primaryID || event.NewPathID != successorID || event.Cause != "death" {
				t.Fatalf("path-death migration event=%+v", event)
			}
			if test.name == "blocked" {
				select {
				case result := <-finished:
					t.Fatalf("departure returned before blocked hook release: %+v", result)
				default:
				}
				close(release)
			}
			var result outcome
			select {
			case result = <-finished:
			case <-time.After(time.Second):
				t.Fatal("path departure did not reach its terminal callback outcome")
			}
			if result.returned != test.wantReturn || (result.recovered != nil) != test.wantPanic {
				t.Fatalf("hook outcome returned=%t panic=%v, want returned=%t panic=%t",
					result.returned, result.recovered, test.wantReturn, test.wantPanic)
			}
			// Panic and Goexit terminate the trusted serial continuation before it
			// starts normal retirement. Complete the already-tracked physical
			// cleanup so this negative-control subtest leaves no process residue.
			e.retirePathAsync(primarySlot)
			subscription.Cancel()
			select {
			case <-subscription.Done():
			case <-time.After(time.Second):
				t.Fatal("path-death event reservation did not quiesce")
			}
		})
	}
}

func TestLegacyOnMigrateWrapsOrderedEvent(t *testing.T) {
	e := &Engine{}
	type legacyEvent struct {
		oldID uint32
		newID uint32
		cause string
	}
	events := make(chan legacyEvent, 1)
	cancel := e.OnMigrate(func(oldID, newID uint32, cause string) {
		events <- legacyEvent{oldID: oldID, newID: newID, cause: cause}
	})
	defer cancel()

	dispatch := commitMigrationEventForTest(t, e, 7, 7, "leaf-mobility")
	e.deliverMigrationEvent(dispatch)
	select {
	case got := <-events:
		if got != (legacyEvent{oldID: 7, newID: 7, cause: "leaf-mobility"}) {
			t.Fatalf("legacy callback=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy callback did not fire")
	}
}

func TestPathAdmissionTransferFailureDoesNotCommitMigrationEvent(t *testing.T) {
	e, pathBinding := newAdmissionAdversarialEngine(t, SideClient)
	predecessor, predecessorPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = predecessorPeer.Close() })
	predecessorID, err := e.AttachPathBound(predecessor, transport.PathSpec{Transport: "memory"}, pathBinding)
	if err != nil {
		t.Fatal(err)
	}
	predecessorRef, ok := e.PathRef(predecessorID)
	if !ok {
		t.Fatal("predecessor path ref is unavailable")
	}

	successor, successorPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = successorPeer.Close() })
	successorID, binding := prepareBoundAdmission(t, e, successor, pathBinding, 0x91)
	if err := e.StagePathAttach(successorID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(successorID, true); err != nil {
		t.Fatal(err)
	}
	baselineCount := e.MigrationCount()
	if e.ActivePath() != successorID {
		t.Fatalf("active path=%d, want successor %d", e.ActivePath(), successorID)
	}

	e.pathsMu.Lock()
	admissionKey, indexed := e.pathAdmissionByPath[successorID]
	if !indexed {
		e.pathsMu.Unlock()
		t.Fatal("successor admission index is missing before injection")
	}
	delete(e.pathAdmissionByPath, successorID)
	e.pathsMu.Unlock()

	events := make(chan MigrationEvent, 2)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	err = e.promotePathAdmissionRoute(binding, predecessorRef)
	if err == nil || !strings.Contains(err.Error(), "did not follow predecessor") {
		t.Fatalf("corrupt transfer error=%v", err)
	}
	if got := e.MigrationCount(); got != baselineCount {
		t.Fatalf("failed transfer changed MigrationCount=%d, want %d", got, baselineCount)
	}
	if got := e.ActivePath(); got != successorID {
		t.Fatalf("failed transfer changed active path=%d, want %d", got, successorID)
	}
	e.pathsMu.RLock()
	activeSuccessor := e.paths[successorID]
	retainedPredecessor := e.retainedPaths[predecessorID]
	e.pathsMu.RUnlock()
	if activeSuccessor == nil || retainedPredecessor == nil {
		t.Fatalf("failed transfer mutated topology: active successor=%t retained predecessor=%t",
			activeSuccessor != nil, retainedPredecessor != nil)
	}
	select {
	case event := <-events:
		t.Fatalf("failed transfer emitted migration event: %+v", event)
	case <-time.After(50 * time.Millisecond):
	}

	e.pathsMu.Lock()
	e.pathAdmissionByPath[successorID] = admissionKey
	e.pathsMu.Unlock()
	if err := e.promotePathAdmissionRoute(binding, predecessorRef); err != nil {
		t.Fatalf("promote after restoring invariant: %v", err)
	}
	event := receiveMigrationEvent(t, events)
	if got := e.MigrationCount(); got != baselineCount+1 || event.Ordinal != got {
		t.Fatalf("successful transfer count/event=%d/%d, want %d", got, event.Ordinal, baselineCount+1)
	}
	if event.OldPathID != successorID || event.NewPathID != predecessorID || event.Cause != "admission-terminal-route" {
		t.Fatalf("successful transfer event=%+v", event)
	}
	if event.Evidence.Kind != MigrationEvidenceRoute || event.Evidence.TopologyEpoch == 0 ||
		len(event.Evidence.ProbeGenerations) != 0 || event.Evidence.TransactionID != ([16]byte{}) {
		t.Fatalf("successful transfer route evidence=%+v", event.Evidence)
	}
	if event.Evidence.Source.PathID != successorID || event.Evidence.Result.PathID != predecessorID ||
		event.Evidence.Source.PathOwner == 0 || event.Evidence.Result.PathOwner == 0 ||
		event.Evidence.Source.PathGeneration == 0 || event.Evidence.Result.PathGeneration == 0 ||
		event.Evidence.Source.LocalTargetID == ([16]byte{}) || event.Evidence.Result.LocalTargetID == ([16]byte{}) ||
		event.Evidence.Selector != (MigrationSelectorBinding{}) || event.Evidence.Leaf != (MigrationLeafBinding{}) {
		t.Fatalf("successful transfer route bindings=%+v/%+v selector=%+v leaf=%+v",
			event.Evidence.Source, event.Evidence.Result, event.Evidence.Selector, event.Evidence.Leaf)
	}
}

func TestSelectorReplayErrorStillDeliversCommittedMigrationEvent(t *testing.T) {
	e := New(SideClient, [16]byte{0x92}, Limits{ProbeInterval: time.Hour}.Clamp())
	defer e.Close()
	targets := configureLeafSelectorRuntime(t, e, "primary", "successor")
	primary := newTxAdversarialPath()
	successor := newTxAdversarialPath()
	primaryID := attachFixturePath(t, e, primary,
		transport.PathSpec{Transport: "adversarial", Address: "primary"}, targets["primary"])
	successorID := attachFixturePath(t, e, successor,
		transport.PathSpec{Transport: "adversarial", Address: "successor"}, targets["successor"])
	if e.ActivePath() != primaryID {
		t.Fatalf("active path=%d, want primary %d", e.ActivePath(), primaryID)
	}
	if _, err := e.SendData([]byte("unacknowledged-before-cutover")); err != nil {
		t.Fatalf("publish replay prefix: %v", err)
	}

	events := make(chan MigrationEvent, 2)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	savedRuntime := e.localExecutionRuntime()
	var removeRuntime sync.Once
	e.boundedReplayAfterSnapshot = func() {
		removeRuntime.Do(func() {
			e.graphMu.Lock()
			e.localExec = nil
			e.graphMu.Unlock()
		})
	}
	err := e.SelectExplicitTarget(targets["root"], targets["successor"], "forced-replay-error")
	e.graphMu.Lock()
	e.localExec = savedRuntime
	e.graphMu.Unlock()
	e.boundedReplayAfterSnapshot = nil
	if !errors.Is(err, ErrPolicyOutcomeUnknown) || !strings.Contains(err.Error(), errExecutionRuntimeNotConfigured.Error()) {
		t.Fatalf("selector replay error=%v, want outcome-unknown wrapping %v", err, errExecutionRuntimeNotConfigured)
	}
	if got := e.ActivePath(); got != successorID {
		t.Fatalf("committed selector active path=%d, want %d", got, successorID)
	}
	event := receiveMigrationEvent(t, events)
	if got := e.MigrationCount(); got != 1 || event.Ordinal != got {
		t.Fatalf("committed selector count/event=%d/%d, want 1", got, event.Ordinal)
	}
	if event.OldPathID != primaryID || event.NewPathID != successorID || event.Cause != "forced-replay-error" {
		t.Fatalf("committed selector event=%+v", event)
	}
	if event.Evidence.Kind != MigrationEvidenceSelector || event.Evidence.TopologyEpoch == 0 ||
		len(event.Evidence.ProbeGenerations) != 0 || event.Evidence.TransactionID != ([16]byte{}) ||
		event.Evidence.RefreshEvidenceGeneration != 0 || event.Evidence.SourceEndpointGeneration != 0 ||
		event.Evidence.ResultEndpointGeneration != 0 {
		t.Fatalf("explicit selector evidence=%+v", event.Evidence)
	}
	select {
	case duplicate := <-events:
		t.Fatalf("one selector commit emitted duplicate event: %+v", duplicate)
	case <-time.After(50 * time.Millisecond):
	}
}
