package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

const (
	leafMobilityInitiatorRetryMin = 10 * time.Millisecond
	leafMobilityInitiatorRetryMax = time.Second
)

// LeafMobilityInitiatorPhase is diagnostic state for the engine-owned
// automatic initiator. It never selects or authorizes a mobility backend.
type LeafMobilityInitiatorPhase uint8

const (
	LeafMobilityInitiatorIdle                    LeafMobilityInitiatorPhase = 0
	LeafMobilityInitiatorPending                 LeafMobilityInitiatorPhase = 1
	LeafMobilityInitiatorPlanning                LeafMobilityInitiatorPhase = 2
	LeafMobilityInitiatorBaseline                LeafMobilityInitiatorPhase = 3
	LeafMobilityInitiatorNegotiating             LeafMobilityInitiatorPhase = 4
	LeafMobilityInitiatorExecuting               LeafMobilityInitiatorPhase = 5
	LeafMobilityInitiatorCommitted               LeafMobilityInitiatorPhase = 6
	LeafMobilityInitiatorRolledBack              LeafMobilityInitiatorPhase = 7
	LeafMobilityInitiatorRejected                LeafMobilityInitiatorPhase = 8
	LeafMobilityInitiatorFailed                  LeafMobilityInitiatorPhase = 9
	LeafMobilityInitiatorSuperseded              LeafMobilityInitiatorPhase = 10
	LeafMobilityInitiatorDeferred                LeafMobilityInitiatorPhase = 11
	LeafMobilityInitiatorExpired                 LeafMobilityInitiatorPhase = 12
	LeafMobilityInitiatorSubscriptionUnavailable LeafMobilityInitiatorPhase = 13
	LeafMobilityInitiatorFailClosed              LeafMobilityInitiatorPhase = 14
)

// LeafMobilityInitiatorSnapshot is a non-authorizing, copy-safe diagnostic.
type LeafMobilityInitiatorSnapshot struct {
	Ref                      PathRef
	EvidenceGeneration       uint64
	SourceEndpointGeneration uint64
	ResultEndpointGeneration uint64
	EvidenceReason           leafmobility.RefreshReason
	ObservedAt               time.Time
	UpdatedAt                time.Time
	Phase                    LeafMobilityInitiatorPhase
	Operation                leafmobility.Operation
	Fallback                 leafmobility.Fallback
	PlanStage                leafmobility.Stage
	PlanReason               leafmobility.Reason
	TransactionID            leafmobility.TransactionID
	Deadline                 time.Time
	Error                    string
}

type leafMobilityRefreshEvent struct {
	ref      PathRef
	claim    *leafmobility.Claim
	evidence leafmobility.RefreshEvidence
	snapshot leafmobility.RefreshSnapshot
	deadline time.Time
}

type leafMobilityRefreshBudget struct {
	endpointGeneration uint64
	incarnation        uint64
	sourceGeneration   uint64
	deadline           time.Time
}

// LeafMobilityInitiatorStatus returns the newest event state for an exact
// current path generation.
func (e *Engine) LeafMobilityInitiatorStatus(ref PathRef) (LeafMobilityInitiatorSnapshot, bool) {
	if e == nil || ref.ID == 0 || ref.Owner == 0 {
		return LeafMobilityInitiatorSnapshot{}, false
	}
	e.leafRefreshMu.Lock()
	snapshot, ok := e.leafRefreshStatus[ref]
	e.leafRefreshMu.Unlock()
	return snapshot, ok
}

func (e *Engine) registerLeafMobilityRefresh(slot *pathSlot) {
	if e == nil || slot == nil || slot.mobilityClaim == nil || !e.leafMobilityRefreshNegotiated(slot.mobilityFacts) {
		return
	}
	source, ok := slot.conn.(leafmobility.RefreshSource)
	if !ok {
		e.recordLeafMobilityInitiator(LeafMobilityInitiatorSnapshot{
			Ref:                      PathRef{ID: slot.id, Owner: slot.owner},
			SourceEndpointGeneration: slot.mobilityFacts.Generation,
			Phase:                    LeafMobilityInitiatorSubscriptionUnavailable,
			UpdatedAt:                time.Now(),
		})
		return
	}
	ref := PathRef{ID: slot.id, Owner: slot.owner}
	claim := slot.mobilityClaim
	subscriptionCtx, cancelSubscription := context.WithCancel(context.Background())
	subscriptionDone := make(chan struct{})
	go func() {
		select {
		case <-e.closed:
			cancelSubscription()
		case <-subscriptionDone:
		}
	}()
	cancel, err := source.SubscribeLeafMobilityRefresh(subscriptionCtx, func(evidence leafmobility.RefreshEvidence) {
		e.enqueueLeafMobilityRefresh(ref, claim, evidence)
	})
	if err != nil {
		close(subscriptionDone)
		cancelSubscription()
		e.recordLeafMobilityInitiator(LeafMobilityInitiatorSnapshot{
			Ref: ref, SourceEndpointGeneration: slot.mobilityFacts.Generation,
			Phase: LeafMobilityInitiatorSubscriptionUnavailable, UpdatedAt: time.Now(), Error: err.Error(),
		})
		return
	}
	if cancel == nil {
		cancel = func() {}
	}
	var once sync.Once
	slot.installMobilityRefreshCancel(func() {
		once.Do(func() {
			close(subscriptionDone)
			cancelSubscription()
			cancel()
			e.forgetLeafMobilityRefresh(ref)
		})
	})
	e.recordLeafMobilityInitiator(LeafMobilityInitiatorSnapshot{
		Ref: ref, SourceEndpointGeneration: slot.mobilityFacts.Generation,
		Phase: LeafMobilityInitiatorIdle, UpdatedAt: time.Now(),
	})
}

func (e *Engine) leafMobilityRefreshNegotiated(facts leafmobility.Facts) bool {
	if facts.Operations == 0 {
		return false
	}
	e.graphMu.RLock()
	local, localSet := e.localNegotiation, e.localNegotiationSet
	peer, peerSet := e.peerNegotiation, e.peerNegotiationSet
	e.graphMu.RUnlock()
	if !localSet || !peerSet {
		return false
	}
	localSupport := leafmobility.KnownOperationSetFromProtocol(local.MobilitySupported)
	peerSupport := leafmobility.KnownOperationSetFromProtocol(peer.MobilitySupported)
	return localSupport.Has(facts.Operations) && peerSupport.Has(facts.Operations)
}

func (s *pathSlot) installMobilityRefreshCancel(cancel func()) {
	if s == nil || cancel == nil {
		return
	}
	s.mobilityRefreshMu.Lock()
	if s.mobilityRefreshClosed {
		s.mobilityRefreshMu.Unlock()
		cancel()
		return
	}
	previous := s.mobilityRefreshCancel
	s.mobilityRefreshCancel = cancel
	s.mobilityRefreshMu.Unlock()
	if previous != nil {
		previous()
	}
}

func (s *pathSlot) cancelMobilityRefresh() {
	if s == nil {
		return
	}
	s.mobilityRefreshMu.Lock()
	s.mobilityRefreshClosed = true
	cancel := s.mobilityRefreshCancel
	s.mobilityRefreshCancel = nil
	s.mobilityRefreshMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *Engine) enqueueLeafMobilityRefresh(ref PathRef, claim *leafmobility.Claim, evidence leafmobility.RefreshEvidence) {
	if e == nil || claim == nil || e.closing.Load() {
		return
	}
	e.pathsMu.RLock()
	current := e.leafMobilityRefreshClaimPresentLocked(ref, claim)
	e.pathsMu.RUnlock()
	if !current {
		return
	}

	e.leafRefreshMu.Lock()
	after := e.leafRefreshSeen[ref]
	snapshot, err := evidence.ValidateFor(claim, after)
	if err != nil {
		e.leafRefreshMu.Unlock()
		return
	}
	budget := e.leafRefreshBudget[ref]
	if budget.endpointGeneration == snapshot.EndpointGeneration && budget.incarnation == snapshot.Incarnation &&
		budget.sourceGeneration == snapshot.SourceGeneration && !budget.deadline.IsZero() {
		e.leafRefreshMu.Unlock()
		return
	}
	e.leafRefreshSeen[ref] = snapshot.Generation
	if budget.endpointGeneration != snapshot.EndpointGeneration || budget.incarnation != snapshot.Incarnation || budget.deadline.IsZero() {
		budget = leafMobilityRefreshBudget{
			endpointGeneration: snapshot.EndpointGeneration,
			incarnation:        snapshot.Incarnation,
			sourceGeneration:   snapshot.SourceGeneration,
			deadline:           snapshot.ObservedAt.Add(e.limits.MigrationBudget),
		}
		e.leafRefreshBudget[ref] = budget
	} else {
		budget.sourceGeneration = snapshot.SourceGeneration
		e.leafRefreshBudget[ref] = budget
	}
	e.leafRefreshPending[ref] = leafMobilityRefreshEvent{
		ref: ref, claim: claim, evidence: evidence, snapshot: snapshot, deadline: budget.deadline,
	}
	e.leafRefreshStatus[ref] = LeafMobilityInitiatorSnapshot{
		Ref: ref, EvidenceGeneration: snapshot.Generation,
		SourceEndpointGeneration: snapshot.EndpointGeneration, EvidenceReason: snapshot.Reason,
		ObservedAt: snapshot.ObservedAt, UpdatedAt: time.Now(), Phase: LeafMobilityInitiatorPending,
		Deadline: budget.deadline,
	}
	e.leafRefreshMu.Unlock()
	select {
	case e.leafRefreshWake <- struct{}{}:
	default:
	}
	e.signalLeafMobilityRetry()
}

func (e *Engine) leafMobilityInitiatorLoop() {
	for {
		select {
		case <-e.closed:
			return
		case <-e.leafRefreshWake:
		}
		for {
			event, workerCtx, ok := e.popLeafMobilityRefresh()
			if !ok {
				break
			}
			e.coreWG.Add(1)
			go func() {
				defer e.coreWG.Done()
				defer e.finishLeafMobilityRefreshWorker(event.ref)
				e.executeLeafMobilityRefresh(workerCtx, event)
			}()
		}
	}
}

func (e *Engine) popLeafMobilityRefresh() (leafMobilityRefreshEvent, context.Context, bool) {
	e.leafRefreshMu.Lock()
	defer e.leafRefreshMu.Unlock()
	for ref, event := range e.leafRefreshPending {
		if _, running := e.leafRefreshRunning[ref]; running {
			continue
		}
		delete(e.leafRefreshPending, ref)
		e.leafRefreshRunning[ref] = struct{}{}
		workerCtx, cancel := context.WithCancelCause(context.Background())
		e.leafRefreshCancel[ref] = cancel
		return event, workerCtx, true
	}
	return leafMobilityRefreshEvent{}, nil, false
}

func (e *Engine) finishLeafMobilityRefreshWorker(ref PathRef) {
	e.leafRefreshMu.Lock()
	delete(e.leafRefreshRunning, ref)
	cancel := e.leafRefreshCancel[ref]
	delete(e.leafRefreshCancel, ref)
	_, pending := e.leafRefreshPending[ref]
	e.leafRefreshMu.Unlock()
	if cancel != nil {
		cancel(context.Canceled)
	}
	if pending {
		select {
		case e.leafRefreshWake <- struct{}{}:
		default:
		}
	}
}

func (e *Engine) executeLeafMobilityRefresh(parent context.Context, event leafMobilityRefreshEvent) {
	if event.snapshot.Reason == leafmobility.RefreshReasonRouteSourceRestored {
		if err := e.validateLeafMobilityRefreshEvent(event); err != nil {
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorSuperseded, leafmobility.Plan{}, leafmobility.TransactionID{}, err)
			return
		}
		e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorBaseline, leafmobility.Plan{}, leafmobility.TransactionID{}, nil)
		return
	}
	if event.deadline.IsZero() || !event.deadline.After(time.Now()) {
		e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorExpired, leafmobility.Plan{}, leafmobility.TransactionID{}, context.DeadlineExceeded)
		return
	}
	ctx, cancel := context.WithDeadline(parent, event.deadline)
	closed := make(chan struct{})
	go func() {
		select {
		case <-e.closed:
			cancel()
		case <-closed:
		}
	}()
	defer func() {
		close(closed)
		cancel()
	}()
	retryDelay := leafMobilityInitiatorRetryMin

	for {
		retryWake := e.leafMobilityRetryChannel()
		if err := e.validateLeafMobilityRefreshEvent(event); err != nil {
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorSuperseded, leafmobility.Plan{}, leafmobility.TransactionID{}, err)
			return
		}
		ready, stale, readinessErr := e.leafMobilityRefreshReady(event)
		if stale {
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorSuperseded, leafmobility.Plan{}, leafmobility.TransactionID{}, leafmobility.ErrRefreshEvidenceStale)
			return
		}
		if !ready {
			e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorDeferred, leafmobility.Plan{}, leafmobility.TransactionID{}, readinessErr)
			if !e.waitLeafMobilityRetry(ctx, retryWake) {
				e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorExpired, leafmobility.Plan{}, leafmobility.TransactionID{}, context.Cause(ctx))
				return
			}
			continue
		}

		transactionID, err := newLeafMobilityTransactionID()
		if err != nil {
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorFailed, leafmobility.Plan{}, transactionID, err)
			return
		}
		e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorPlanning, leafmobility.Plan{}, transactionID, nil)
		plan, err := e.planLeafMobilityCandidateUntil(ctx, event.ref, transactionID, senderDirection(e.side), event.deadline)
		if err != nil {
			if errors.Is(err, ErrLeafMobilityControlRouteUnavailable) {
				e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorDeferred, plan, transactionID, err)
				if e.waitLeafMobilityRetry(ctx, retryWake) {
					continue
				}
				e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorExpired, plan, transactionID, context.Cause(ctx))
				return
			}
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorFailed, plan, transactionID, err)
			return
		}
		if plan.Operation == 0 {
			if plan.Retryable {
				e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorDeferred, plan, transactionID, nil)
				if e.waitLeafMobilityBackoff(ctx, retryDelay) {
					retryDelay = nextLeafMobilityBackoff(retryDelay)
					continue
				}
				e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorExpired, plan, transactionID, context.Cause(ctx))
				return
			}
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorBaseline, plan, transactionID, nil)
			return
		}
		if err := e.validateLeafMobilityRefreshEvent(event); err != nil {
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorSuperseded, plan, transactionID, err)
			return
		}
		select {
		case e.leafTx.sendGate <- struct{}{}:
		default:
			e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorDeferred, plan, transactionID, ErrLeafMobilityAuthorityBusy)
			select {
			case e.leafTx.sendGate <- struct{}{}:
			case <-ctx.Done():
				e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorExpired, plan, transactionID, context.Cause(ctx))
				return
			case <-e.closed:
				return
			}
		}
		if err := e.validateLeafMobilityRefreshEvent(event); err != nil {
			e.releaseLeafMobilitySendGate()
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorSuperseded, plan, transactionID, err)
			return
		}
		e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorNegotiating, plan, transactionID, nil)
		authority, err := e.negotiateLeafMobilityAuthority(ctx, event.ref, plan, true)
		if err != nil {
			if leafMobilityInitiatorRetryable(err) {
				e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorDeferred, plan, transactionID, err)
				if e.waitLeafMobilityBackoff(ctx, retryDelay) {
					retryDelay = nextLeafMobilityBackoff(retryDelay)
					continue
				}
				e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorExpired, plan, transactionID, context.Cause(ctx))
				return
			}
			phase := LeafMobilityInitiatorFailed
			if errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
				phase = LeafMobilityInitiatorFailClosed
			} else if errors.Is(err, ErrLeafMobilityRejected) {
				phase = LeafMobilityInitiatorRejected
			}
			e.finishLeafMobilityRefresh(event, phase, plan, transactionID, err)
			return
		}
		permit, err := authority.Consume()
		if err != nil {
			rollbackErr := authority.Rollback(context.WithoutCancel(ctx))
			if leafMobilityInitiatorRetryable(err) && (rollbackErr == nil || errors.Is(rollbackErr, leafmobility.ErrAuthorityStale)) {
				e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorDeferred, plan, transactionID, err)
				if e.waitLeafMobilityBackoff(ctx, retryDelay) {
					retryDelay = nextLeafMobilityBackoff(retryDelay)
					continue
				}
			}
			phase := LeafMobilityInitiatorRolledBack
			if rollbackErr != nil && !errors.Is(rollbackErr, leafmobility.ErrAuthorityStale) {
				phase = LeafMobilityInitiatorFailed
			}
			if authority.State() == leafmobility.ResourceTransactionOutcomeUnknown || errors.Is(rollbackErr, ErrLeafMobilityOutcomeUnknown) {
				phase = LeafMobilityInitiatorFailClosed
			}
			e.finishLeafMobilityRefresh(event, phase, plan, transactionID, errors.Join(err, rollbackErr))
			return
		}
		e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorExecuting, plan, transactionID, nil)
		err = permit.Execute(ctx)
		if err == nil {
			commitErr := e.recordCommittedLeafMobility(event)
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorCommitted, plan, transactionID, commitErr)
			return
		}
		phase := LeafMobilityInitiatorFailed
		switch permit.State() {
		case leafmobility.ResourceTransactionRolledBack, leafmobility.ResourceTransactionAborted:
			phase = LeafMobilityInitiatorRolledBack
		case leafmobility.ResourceTransactionCompleted:
			phase = LeafMobilityInitiatorCommitted
		}
		if permit.State() == leafmobility.ResourceTransactionOutcomeUnknown ||
			permit.ExecutionState() == leafmobility.ExecutionFailClosedRequired ||
			permit.ExecutionState() == leafmobility.ExecutionFailedClosed {
			phase = LeafMobilityInitiatorFailClosed
		}
		e.finishLeafMobilityRefresh(event, phase, plan, transactionID, err)
		return
	}
}

func (e *Engine) validateLeafMobilityRefreshEvent(event leafMobilityRefreshEvent) error {
	if _, err := event.evidence.ValidateFor(event.claim, 0); err != nil {
		return err
	}
	e.leafRefreshMu.Lock()
	newer := e.leafRefreshSeen[event.ref] > event.snapshot.Generation
	e.leafRefreshMu.Unlock()
	if newer {
		return leafmobility.ErrRefreshEvidenceStale
	}
	return nil
}

func (e *Engine) leafMobilityRefreshReady(event leafMobilityRefreshEvent) (ready, stale bool, err error) {
	e.pathsMu.RLock()
	active := e.paths[event.ref.ID]
	if active != nil && active.owner == event.ref.Owner && active.mobilityClaim == event.claim {
		e.pathsMu.RUnlock()
		if !event.snapshot.SourceUsable {
			return false, false, leafmobility.ErrRefreshSourceUnavailable
		}
		if _, routeErr := e.leafMobilityControlRoutes(event.ref); routeErr != nil {
			return false, false, routeErr
		}
		return true, false, nil
	}
	present := e.leafMobilityRefreshClaimPresentLocked(event.ref, event.claim)
	e.pathsMu.RUnlock()
	if present {
		return false, false, ErrPathAttachInProgress
	}
	return false, true, ErrStalePathRef
}

func (e *Engine) waitLeafMobilityRetry(ctx context.Context, wake <-chan struct{}) bool {
	select {
	case <-wake:
		return true
	case <-ctx.Done():
		return false
	case <-e.closed:
		return false
	}
}

func (e *Engine) waitLeafMobilityBackoff(ctx context.Context, delay time.Duration) bool {
	if delay < leafMobilityInitiatorRetryMin {
		delay = leafMobilityInitiatorRetryMin
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	case <-e.closed:
		return false
	}
}

func nextLeafMobilityBackoff(current time.Duration) time.Duration {
	if current < leafMobilityInitiatorRetryMin {
		return leafMobilityInitiatorRetryMin
	}
	if current >= leafMobilityInitiatorRetryMax/2 {
		return leafMobilityInitiatorRetryMax
	}
	return current * 2
}

func leafMobilityInitiatorRetryable(err error) bool {
	return errors.Is(err, ErrLeafMobilityAuthorityBusy) || errors.Is(err, ErrLeafMobilityPeerBusy) ||
		errors.Is(err, ErrLeafMobilityAdmissionBusy) || errors.Is(err, leafmobility.ErrAuthorityActive) ||
		errors.Is(err, leafmobility.ErrAuthorityStale) || errors.Is(err, leafmobility.ErrStalePlan)
}

func (e *Engine) recordCommittedLeafMobility(event leafMobilityRefreshEvent) error {
	e.pathsMu.Lock()
	slot := e.paths[event.ref.ID]
	if slot == nil || slot.owner != event.ref.Owner || slot.mobilityClaim != event.claim {
		e.pathsMu.Unlock()
		return ErrStalePathRef
	}
	slot.mobilityFacts = event.claim.Snapshot()
	committer, _ := slot.conn.(leafmobility.RefreshCommitter)
	e.migrationCount++
	ticket := e.accountMigration()
	e.pathsMu.Unlock()
	var commitErr error
	if committer != nil {
		commitErr = committer.CommitLeafMobilityRefresh(event.evidence)
	}
	e.fireMigrateHooks(event.ref.ID, event.ref.ID, "leaf-mobility")
	e.tripZombie(ticket)
	return commitErr
}

func (e *Engine) updateLeafMobilityRefresh(
	event leafMobilityRefreshEvent,
	phase LeafMobilityInitiatorPhase,
	plan leafmobility.Plan,
	transactionID leafmobility.TransactionID,
	err error,
) {
	snapshot := LeafMobilityInitiatorSnapshot{
		Ref: event.ref, EvidenceGeneration: event.snapshot.Generation,
		SourceEndpointGeneration: event.snapshot.EndpointGeneration, EvidenceReason: event.snapshot.Reason,
		ObservedAt: event.snapshot.ObservedAt, UpdatedAt: time.Now(), Phase: phase,
		Operation: plan.Operation, Fallback: plan.Fallback, PlanStage: plan.Stage, PlanReason: plan.Reason,
		TransactionID: transactionID, Deadline: event.deadline,
	}
	if phase == LeafMobilityInitiatorBaseline && event.snapshot.Reason == leafmobility.RefreshReasonRouteSourceRestored {
		snapshot.Deadline = time.Time{}
	}
	switch phase {
	case LeafMobilityInitiatorCommitted, LeafMobilityInitiatorRolledBack, LeafMobilityInitiatorFailClosed:
		snapshot.ResultEndpointGeneration = event.claim.Snapshot().Generation
	}
	if err != nil {
		snapshot.Error = err.Error()
	}
	e.recordLeafMobilityInitiator(snapshot)
}

func (e *Engine) finishLeafMobilityRefresh(
	event leafMobilityRefreshEvent,
	phase LeafMobilityInitiatorPhase,
	plan leafmobility.Plan,
	transactionID leafmobility.TransactionID,
	err error,
) {
	e.updateLeafMobilityRefresh(event, phase, plan, transactionID, err)
	if phase == LeafMobilityInitiatorBaseline && event.snapshot.Reason == leafmobility.RefreshReasonRouteSourceRestored {
		e.clearLeafMobilityRefreshBudget(event)
	}
}

func (e *Engine) clearLeafMobilityRefreshBudget(event leafMobilityRefreshEvent) {
	e.leafRefreshMu.Lock()
	budget := e.leafRefreshBudget[event.ref]
	if budget.endpointGeneration == event.snapshot.EndpointGeneration && budget.incarnation == event.snapshot.Incarnation &&
		budget.sourceGeneration == event.snapshot.SourceGeneration {
		delete(e.leafRefreshBudget, event.ref)
	}
	e.leafRefreshMu.Unlock()
}

func (e *Engine) recordLeafMobilityInitiator(snapshot LeafMobilityInitiatorSnapshot) {
	if e == nil || snapshot.Ref.ID == 0 || snapshot.Ref.Owner == 0 {
		return
	}
	e.pathsMu.RLock()
	current := e.leafMobilityRefreshRefPresentLocked(snapshot.Ref)
	e.pathsMu.RUnlock()
	if !current {
		return
	}
	e.leafRefreshMu.Lock()
	previous, ok := e.leafRefreshStatus[snapshot.Ref]
	if !ok || previous.EvidenceGeneration <= snapshot.EvidenceGeneration {
		e.leafRefreshStatus[snapshot.Ref] = snapshot
	}
	e.leafRefreshMu.Unlock()
}

func (e *Engine) leafMobilityRefreshCurrent(ref PathRef, claim *leafmobility.Claim) bool {
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	current := slot != nil && slot.owner == ref.Owner && slot.mobilityClaim == claim && !e.isClosed()
	e.pathsMu.RUnlock()
	return current
}

func (e *Engine) forgetLeafMobilityRefresh(ref PathRef) {
	e.leafRefreshMu.Lock()
	if cancel := e.leafRefreshCancel[ref]; cancel != nil {
		cancel(ErrStalePathRef)
	}
	delete(e.leafRefreshPending, ref)
	delete(e.leafRefreshSeen, ref)
	delete(e.leafRefreshBudget, ref)
	delete(e.leafRefreshStatus, ref)
	e.leafRefreshMu.Unlock()
}

func (e *Engine) leafMobilityRefreshClaimPresentLocked(ref PathRef, claim *leafmobility.Claim) bool {
	for _, paths := range []map[uint32]*pathSlot{e.paths, e.pendingPaths, e.stagedPaths} {
		if slot := paths[ref.ID]; slot != nil && slot.owner == ref.Owner && slot.mobilityClaim == claim {
			return true
		}
	}
	return false
}

func (e *Engine) leafMobilityRefreshRefPresentLocked(ref PathRef) bool {
	for _, paths := range []map[uint32]*pathSlot{e.paths, e.pendingPaths, e.stagedPaths} {
		if slot := paths[ref.ID]; slot != nil && slot.owner == ref.Owner {
			return true
		}
	}
	return false
}

func (e *Engine) signalLeafMobilityRetry() {
	if e == nil {
		return
	}
	e.leafRefreshRetryMu.Lock()
	close(e.leafRefreshRetryWait)
	e.leafRefreshRetryWait = make(chan struct{})
	e.leafRefreshRetryMu.Unlock()
}

func (e *Engine) leafMobilityRetryChannel() <-chan struct{} {
	e.leafRefreshRetryMu.Lock()
	wake := e.leafRefreshRetryWait
	e.leafRefreshRetryMu.Unlock()
	return wake
}

func newLeafMobilityTransactionID() (leafmobility.TransactionID, error) {
	var id leafmobility.TransactionID
	if _, err := rand.Read(id[:]); err != nil {
		return leafmobility.TransactionID{}, err
	}
	if id == (leafmobility.TransactionID{}) {
		return leafmobility.TransactionID{}, net.ErrClosed
	}
	return id, nil
}
