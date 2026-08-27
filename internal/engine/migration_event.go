package engine

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

const (
	migrationEventQueueCapacity           = 64
	migrationEventSubscriberCapacity      = 64
	migrationEventProcessCallbackCapacity = 2 * migrationEventSubscriberCapacity
)

var migrationEventProcessCallbackSlots = make(
	chan struct{},
	migrationEventProcessCallbackCapacity,
)

var (
	// ErrMigrationObserverLagged reports that a subscriber callback did not
	// drain its fixed pending budget quickly enough. The subscription is
	// removed from future commits and Err remains stable after the already
	// committed prefix drains.
	ErrMigrationObserverLagged = errors.New("engine: migration observer lagged")
	// ErrMigrationObserverCallbackFailed reports that callback execution did
	// not return normally. The subscription is detached because continuing
	// would create an unobservable ordinal gap.
	ErrMigrationObserverCallbackFailed = errors.New("engine: migration observer callback failed")
	// ErrMigrationObserverLimit reports that either one connection already owns
	// the maximum number of subscriptions or the process cannot grant an
	// immediate callback execution slot. The rejected or terminated
	// subscription is quiescent and can be inspected through Err and Done.
	ErrMigrationObserverLimit = errors.New("engine: migration observer limit reached")
)

type MigrationEvidenceKind uint8

const (
	MigrationEvidenceRoute MigrationEvidenceKind = iota + 1
	MigrationEvidenceSelector
	MigrationEvidenceLeafMobility
)

type MigrationProbeGeneration struct {
	PathID             uint32
	PathOwner          uint64
	PathGeneration     uint64
	RouteGeneration    uint64
	EndpointGeneration uint64
	PeerMobilityEpoch  uint64
	HealthRevision     uint64
}

type MigrationEvidence struct {
	Kind                      MigrationEvidenceKind
	TransactionID             [16]byte
	RefreshEvidenceGeneration uint64
	SourceEndpointGeneration  uint64
	ResultEndpointGeneration  uint64
	TopologyEpoch             uint64
	HealthEpoch               uint64
	Source                    MigrationPathBinding
	Result                    MigrationPathBinding
	Selector                  MigrationSelectorBinding
	Leaf                      MigrationLeafBinding
	ProbeGenerations          []MigrationProbeGeneration
}

type MigrationPathBinding struct {
	PathID             uint32
	PathOwner          uint64
	PathGeneration     uint64
	RouteGeneration    uint64
	EndpointGeneration uint64
	PeerMobilityEpoch  uint64
	HealthRevision     uint64
	LocalTargetID      [16]byte
	PeerTargetID       [16]byte
}

type MigrationSelectorBinding struct {
	SelectorID        [16]byte
	TargetID          [16]byte
	Origin            string
	CutoverGeneration uint64
	CapturedAt        time.Time
	ValidUntil        time.Time
}

type MigrationLeafBinding struct {
	RefreshReason           string
	RefreshObservedAt       time.Time
	RefreshSourceGeneration uint64
	RefreshSourceUsable     bool
	RefreshIncarnation      uint64
}

// MigrationEvent is an immutable observation of one committed migration.
// Ordinal is connection-local, starts at one, and equals MigrationCount after
// this commit. Each subscription observes callbacks in Ordinal order;
// different subscriptions may progress independently.
type MigrationEvent struct {
	OldPathID   uint32
	NewPathID   uint32
	Cause       string
	Ordinal     uint64
	CommittedAt time.Time
	Evidence    MigrationEvidence
}

type migrationEventDispatch struct {
	event       MigrationEvent
	subscribers []*migrationEventSubscriber
}

type migrationEventSubscriber struct {
	engine       *Engine
	id           uint64
	afterOrdinal uint64
	hook         func(MigrationEvent)
	done         chan struct{}

	mu            sync.Mutex
	doneOnce      sync.Once
	queue         []MigrationEvent
	queueLen      int
	reservations  uint64
	nextOrdinal   uint64
	accepting     bool
	canceled      bool
	discardQueue  bool
	workerRunning bool
	err           error
}

// recordMigrationLocked freezes migration accounting and its observer event
// in one critical section. Callers hold pathsMu for writing.
func (e *Engine) recordMigrationLocked(
	oldID, newID uint32,
	cause string,
	evidence MigrationEvidence,
) migrationEventDispatch {
	return e.recordMigrationAtLocked(oldID, newID, cause, evidence, time.Now())
}

func (e *Engine) recordMigrationAtLocked(
	oldID, newID uint32,
	cause string,
	evidence MigrationEvidence,
	committedAt time.Time,
) migrationEventDispatch {
	e.migrationCount++
	e.migrationEpoch.Add(1)
	evidence.ProbeGenerations = append([]MigrationProbeGeneration(nil), evidence.ProbeGenerations...)

	committedAt = e.nextMigrationCommittedAtLocked(committedAt)
	e.lastMigrationCommittedAt = committedAt
	if evidence.Source == (MigrationPathBinding{}) && oldID != 0 {
		evidence.Source = e.migrationPathBindingLocked(oldID)
	}
	if evidence.Result == (MigrationPathBinding{}) && newID != 0 {
		evidence.Result = e.migrationPathBindingLocked(newID)
	}
	event := MigrationEvent{
		OldPathID:   oldID,
		NewPathID:   newID,
		Cause:       cause,
		Ordinal:     e.migrationCount,
		CommittedAt: committedAt,
		Evidence:    evidence,
	}

	dispatch := migrationEventDispatch{event: event}
	if len(e.migrationEventSubscribers) != 0 {
		dispatch.subscribers = make([]*migrationEventSubscriber, 0, len(e.migrationEventSubscribers))
		for id, subscriber := range e.migrationEventSubscribers {
			reserved, lagged := subscriber.reserve()
			if lagged {
				delete(e.migrationEventSubscribers, id)
			}
			if reserved {
				dispatch.subscribers = append(dispatch.subscribers, subscriber)
			}
		}
	}
	return dispatch
}

func (e *Engine) nextMigrationCommittedAtLocked(candidate time.Time) time.Time {
	if candidate.IsZero() {
		candidate = time.Now()
	}
	if !e.lastMigrationCommittedAt.IsZero() && candidate.UnixNano() <= e.lastMigrationCommittedAt.UnixNano() {
		return e.lastMigrationCommittedAt.Add(time.Nanosecond)
	}
	return candidate
}

func (e *Engine) migrationPathBindingLocked(pathID uint32) MigrationPathBinding {
	if e == nil || pathID == 0 {
		return MigrationPathBinding{}
	}
	slot := e.paths[pathID]
	if slot == nil {
		slot = e.retainedPaths[pathID]
	}
	if slot == nil {
		slot = e.stagedPaths[pathID]
	}
	if slot == nil {
		slot = e.pendingPaths[pathID]
	}
	return migrationPathBindingForSlot(slot)
}

func migrationPathBindingForSlot(slot *pathSlot) MigrationPathBinding {
	if slot == nil {
		return MigrationPathBinding{}
	}
	generation := pathProbeGenerationForSlot(slot)
	healthRevision, _, _ := slot.healthEvidenceSnapshot()
	return MigrationPathBinding{
		PathID:             slot.id,
		PathOwner:          slot.owner,
		PathGeneration:     slot.gen,
		RouteGeneration:    generation.routeGeneration,
		EndpointGeneration: generation.endpointGeneration,
		PeerMobilityEpoch:  generation.peerMobilityEpoch,
		HealthRevision:     healthRevision,
		LocalTargetID:      [16]byte(slot.localTXTargetID),
		PeerTargetID:       [16]byte(slot.peerTXTargetID),
	}
}

func migrationSelectorOriginName(origin policySelectionOrigin) string {
	switch origin {
	case policySelectionExternal:
		return "external"
	case policySelectionExplicit:
		return "explicit"
	case policySelectionQuality:
		return "quality"
	case policySelectionPathDeath:
		return "path_death"
	case policySelectionPathDeathReplayed:
		return "path_death_replayed"
	case policySelectionProbeFailure:
		return "probe_failure"
	case policySelectionProbeStarvedData:
		return "probe_starved_data"
	case policySelectionWriteStalled:
		return "write_stalled"
	case policySelectionPeakPromote:
		return "peak_promote"
	case policySelectionPeakReturn:
		return "peak_return"
	default:
		return ""
	}
}

func migrationRefreshReasonName(reason leafmobility.RefreshReason) string {
	switch reason {
	case leafmobility.RefreshReasonRouteSourceChanged:
		return "route_source_changed"
	case leafmobility.RefreshReasonRouteSourceUnavailable:
		return "route_source_unavailable"
	case leafmobility.RefreshReasonRouteSourceRestored:
		return "route_source_restored"
	case leafmobility.RefreshReasonLinkUnresponsive:
		return "link_unresponsive"
	case leafmobility.RefreshReasonLocalReadFailure:
		return "local_read_failure"
	case leafmobility.RefreshReasonLocalWriteFailure:
		return "local_write_failure"
	case leafmobility.RefreshReasonOuterMTUFailure:
		return "outer_mtu_failure"
	case leafmobility.RefreshReasonReplayStalled:
		return "replay_stalled"
	case leafmobility.RefreshReasonReplayFailure:
		return "replay_failure"
	case leafmobility.RefreshReasonLivenessProbeFailure:
		return "liveness_probe_failure"
	default:
		return ""
	}
}

// routeMigrationEvidenceLocked records one physical routing transition. The
// caller holds pathsMu, which is also the mutation lock for topology epochs.
func (e *Engine) routeMigrationEvidenceLocked() MigrationEvidence {
	return MigrationEvidence{
		Kind:          MigrationEvidenceRoute,
		TopologyEpoch: e.currentPathTopologyEpoch(),
	}
}

// selectorMigrationEvidenceLocked freezes the full generation vector that was
// validated immediately before a selector commit. Explicit selections have no
// probe vector and bind only the topology epoch current at their commit.
func (e *Engine) selectorMigrationEvidenceLocked(commit selectorEvidenceCommit) MigrationEvidence {
	evidence := MigrationEvidence{
		Kind:          MigrationEvidenceSelector,
		TopologyEpoch: commit.topologyEpoch,
		HealthEpoch:   commit.healthEpoch,
	}
	if evidence.TopologyEpoch == 0 {
		evidence.TopologyEpoch = e.currentPathTopologyEpoch()
	}
	if evidence.HealthEpoch == 0 {
		evidence.HealthEpoch = e.healthEvidenceEpoch.Load()
	}
	if !commit.physicallyBound() {
		return evidence
	}
	evidence.ProbeGenerations = make([]MigrationProbeGeneration, 0, len(commit.generations))
	for _, generation := range commit.generations {
		evidence.ProbeGenerations = append(evidence.ProbeGenerations, MigrationProbeGeneration{
			PathID:             generation.pathID,
			PathOwner:          generation.owner,
			PathGeneration:     generation.slotGeneration,
			RouteGeneration:    generation.probeGeneration.routeGeneration,
			EndpointGeneration: generation.probeGeneration.endpointGeneration,
			PeerMobilityEpoch:  generation.probeGeneration.peerMobilityEpoch,
			HealthRevision:     generation.healthRevision,
		})
	}
	sort.Slice(evidence.ProbeGenerations, func(i, j int) bool {
		left, right := evidence.ProbeGenerations[i], evidence.ProbeGenerations[j]
		if left.PathID != right.PathID {
			return left.PathID < right.PathID
		}
		if left.PathOwner != right.PathOwner {
			return left.PathOwner < right.PathOwner
		}
		return left.PathGeneration < right.PathGeneration
	})
	return evidence
}

// OnMigrationEvent registers one bounded asynchronous subscriber. Registration
// and AfterOrdinal are linearized with migration accounting. Cancel removes the
// subscriber from future commits while preserving every event already reserved
// by a commit. A callback that falls behind is detached with
// ErrMigrationObserverLagged rather than creating unbounded goroutines. Idle
// subscribers do not own process callback slots; a slot is acquired only when
// the next ordered event is ready to execute.
func (e *Engine) OnMigrationEvent(fn func(MigrationEvent)) *migrationEventSubscriber {
	e.pathsMu.Lock()
	afterOrdinal := e.migrationCount
	if fn == nil || e.closing.Load() || e.isClosed() {
		e.pathsMu.Unlock()
		return newInactiveMigrationEventSubscriber(afterOrdinal, nil)
	}
	if e.migrationEventSubscribers == nil {
		e.migrationEventSubscribers = make(map[uint64]*migrationEventSubscriber)
	}
	if len(e.migrationEventSubscribers) >= migrationEventSubscriberCapacity ||
		e.migrationEventSubscriberID == ^uint64(0) {
		e.pathsMu.Unlock()
		return newInactiveMigrationEventSubscriber(
			afterOrdinal, ErrMigrationObserverLimit,
		)
	}
	e.migrationEventSubscriberID++
	subscriber := newMigrationEventSubscriber(e, e.migrationEventSubscriberID, afterOrdinal, fn)
	e.migrationEventSubscribers[subscriber.id] = subscriber
	e.pathsMu.Unlock()
	return subscriber
}

// OnMigrate preserves the best-effort callback shape as a wrapper around the
// ordered event API. It intentionally cannot expose a terminal subscriber
// error; callers that require complete evidence use OnMigrationEvent.
func (e *Engine) OnMigrate(fn func(oldID, newID uint32, cause string)) (cancel func()) {
	if fn == nil {
		return func() {}
	}
	subscription := e.OnMigrationEvent(func(event MigrationEvent) {
		fn(event.OldPathID, event.NewPathID, event.Cause)
	})
	return subscription.Cancel
}

// deliverMigrationEvent enqueues the subscriber reservations frozen by the
// commit. Registration or cancellation after that commit affects only later
// events. Caller must not hold pathsMu.
func (e *Engine) deliverMigrationEvent(dispatch migrationEventDispatch) {
	for _, subscriber := range dispatch.subscribers {
		subscriber.enqueueReserved(cloneMigrationEvent(dispatch.event))
	}
}

func newMigrationEventSubscriber(
	engine *Engine,
	id uint64,
	afterOrdinal uint64,
	hook func(MigrationEvent),
) *migrationEventSubscriber {
	subscriber := &migrationEventSubscriber{
		engine:       engine,
		id:           id,
		afterOrdinal: afterOrdinal,
		hook:         hook,
		done:         make(chan struct{}),
		nextOrdinal:  afterOrdinal + 1,
		accepting:    true,
	}
	return subscriber
}

func newInactiveMigrationEventSubscriber(
	afterOrdinal uint64,
	terminalErr error,
) *migrationEventSubscriber {
	subscriber := &migrationEventSubscriber{
		afterOrdinal: afterOrdinal,
		done:         make(chan struct{}),
		canceled:     true,
		err:          terminalErr,
	}
	subscriber.finish()
	return subscriber
}

// AfterOrdinal is the last committed ordinal observed atomically before this
// subscriber was installed.
func (s *migrationEventSubscriber) AfterOrdinal() uint64 {
	if s == nil {
		return 0
	}
	return s.afterOrdinal
}

// Err returns the stable terminal diagnostic for this subscriber. Normal
// cancellation and engine close leave Err nil.
func (s *migrationEventSubscriber) Err() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Done closes after this subscription can no longer invoke its callback.
// Cancel and Engine.Close do not wait for an external callback that is
// currently running; callers that need a quiescence boundary can wait here.
func (s *migrationEventSubscriber) Done() <-chan struct{} {
	if s == nil {
		return closedMigrationEventSubscriptionDone
	}
	return s.done
}

// Cancel removes the subscriber from future commit snapshots. Events already
// reserved at their commit boundary remain deliverable.
func (s *migrationEventSubscriber) Cancel() {
	if s == nil {
		return
	}
	if s.engine == nil {
		s.stopAccepting()
		return
	}
	s.engine.cancelMigrationEventSubscriber(s)
}

// reserve freezes one future delivery at the commit boundary. queueLen and
// reservations share one fixed budget so goroutines paused between commit and
// enqueue cannot create a hidden backlog outside the queue capacity.
func (s *migrationEventSubscriber) reserve() (reserved, lagged bool) {
	if s == nil {
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.accepting {
		return false, false
	}
	if s.reservations >= uint64(migrationEventQueueCapacity-s.queueLen) {
		s.err = ErrMigrationObserverLagged
		s.accepting = false
		s.canceled = true
		return false, true
	}
	if s.reservations == ^uint64(0) {
		panic("engine: migration event reservation exhausted")
	}
	s.reservations++
	return true, false
}

func (s *migrationEventSubscriber) enqueueReserved(event MigrationEvent) {
	if s == nil {
		panic("engine: migration event delivered to nil subscriber")
	}
	var startWorker, removeSubscriber, finish bool
	s.mu.Lock()
	if s.reservations == 0 {
		s.mu.Unlock()
		panic("engine: migration event delivered without reservation")
	}
	s.reservations--
	if !s.discardQueue {
		if s.queueLen == migrationEventQueueCapacity {
			s.mu.Unlock()
			panic("engine: migration event pending budget invariant violated")
		}
		if s.queue == nil {
			s.queue = make([]MigrationEvent, migrationEventQueueCapacity)
		}
		if event.Ordinal < s.nextOrdinal {
			s.mu.Unlock()
			panic("engine: duplicate migration event delivery")
		}
		index := int(event.Ordinal % uint64(migrationEventQueueCapacity))
		if s.queue[index].Ordinal != 0 {
			s.mu.Unlock()
			panic("engine: migration event queue ordinal collision")
		}
		s.queue[index] = event
		s.queueLen++
		if s.nextEventReadyLocked() && !s.workerRunning {
			select {
			case migrationEventProcessCallbackSlots <- struct{}{}:
				s.workerRunning = true
				startWorker = true
			default:
				if s.err == nil {
					s.err = ErrMigrationObserverLimit
				}
				s.accepting = false
				s.canceled = true
				s.discardQueue = true
				s.clearQueueLocked()
				removeSubscriber = true
			}
		}
	}
	finish = s.shouldFinishLocked()
	s.mu.Unlock()
	if removeSubscriber && s.engine != nil {
		s.engine.removeMigrationEventSubscriber(s)
	}
	if startWorker {
		go s.run()
	}
	if finish {
		s.finish()
	}
}

func (s *migrationEventSubscriber) stopAccepting() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.accepting = false
	s.canceled = true
	finish := s.shouldFinishLocked()
	s.mu.Unlock()
	if finish {
		s.finish()
	}
}

func (s *migrationEventSubscriber) run() {
	callbackActive := false
	workerOwned := true
	defer func() {
		if callbackActive {
			// runtime.Goexit cannot be recovered, but it does run defers.
			s.failCallback()
		}
		if workerOwned {
			s.releaseWorker()
		}
	}()
	for {
		s.mu.Lock()
		event, ready := s.popNextEventLocked()
		if !ready {
			s.releaseWorkerLocked()
			workerOwned = false
			finish := s.shouldFinishLocked()
			s.mu.Unlock()
			if finish {
				s.finish()
			}
			return
		}
		s.mu.Unlock()
		callbackActive = true
		returned := invokeMigrationHook(s.hook, event)
		callbackActive = false
		if !returned {
			s.failCallback()
			return
		}
	}
}

func (e *Engine) cancelMigrationEventSubscriber(subscriber *migrationEventSubscriber) {
	e.pathsMu.Lock()
	if e.migrationEventSubscribers[subscriber.id] == subscriber {
		delete(e.migrationEventSubscribers, subscriber.id)
	}
	subscriber.stopAccepting()
	e.pathsMu.Unlock()
}

func (e *Engine) removeMigrationEventSubscriber(subscriber *migrationEventSubscriber) {
	e.pathsMu.Lock()
	if e.migrationEventSubscribers[subscriber.id] == subscriber {
		delete(e.migrationEventSubscribers, subscriber.id)
	}
	e.pathsMu.Unlock()
}

func (s *migrationEventSubscriber) failCallback() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = ErrMigrationObserverCallbackFailed
	}
	s.accepting = false
	s.canceled = true
	s.discardQueue = true
	s.clearQueueLocked()
	s.mu.Unlock()
	if s.engine != nil {
		s.engine.removeMigrationEventSubscriber(s)
	}
}

func (s *migrationEventSubscriber) nextEventReadyLocked() bool {
	if s.queueLen == 0 {
		return false
	}
	index := int(s.nextOrdinal % uint64(migrationEventQueueCapacity))
	return s.queue[index].Ordinal == s.nextOrdinal
}

func (s *migrationEventSubscriber) popNextEventLocked() (MigrationEvent, bool) {
	if !s.nextEventReadyLocked() {
		return MigrationEvent{}, false
	}
	index := int(s.nextOrdinal % uint64(migrationEventQueueCapacity))
	event := s.queue[index]
	s.queue[index] = MigrationEvent{}
	s.queueLen--
	s.nextOrdinal++
	if s.queueLen == 0 {
		s.queue = nil
	}
	return event, true
}

func (s *migrationEventSubscriber) clearQueueLocked() {
	s.queue = nil
	s.queueLen = 0
}

func (s *migrationEventSubscriber) shouldFinishLocked() bool {
	return s.canceled && !s.workerRunning &&
		(s.discardQueue || (s.reservations == 0 && s.queueLen == 0))
}

func (s *migrationEventSubscriber) releaseWorker() {
	s.mu.Lock()
	s.releaseWorkerLocked()
	finish := s.shouldFinishLocked()
	s.mu.Unlock()
	if finish {
		s.finish()
	}
}

func (s *migrationEventSubscriber) releaseWorkerLocked() {
	if !s.workerRunning {
		panic("engine: migration event worker released without ownership")
	}
	select {
	case <-migrationEventProcessCallbackSlots:
	default:
		panic("engine: migration event callback slot ownership lost")
	}
	s.workerRunning = false
}

func (s *migrationEventSubscriber) finish() {
	s.doneOnce.Do(func() { close(s.done) })
}

func cloneMigrationEvent(event MigrationEvent) MigrationEvent {
	event.Evidence.ProbeGenerations = append(
		[]MigrationProbeGeneration(nil), event.Evidence.ProbeGenerations...,
	)
	return event
}

func invokeMigrationHook(hook func(MigrationEvent), event MigrationEvent) (returned bool) {
	returned = true
	defer func() {
		if recover() != nil {
			returned = false
		}
	}()
	hook(event)
	return returned
}

var closedMigrationEventSubscriptionDone = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()
