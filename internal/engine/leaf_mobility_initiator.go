package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

const (
	leafMobilityInitiatorRetryMin  = 10 * time.Millisecond
	leafMobilityInitiatorRetryMax  = time.Second
	leafMobilityRefreshSubscribeOp = "RefreshSource.SubscribeLeafMobilityRefresh"
	leafMobilityRefreshEventOp     = "RefreshSource callback"
	leafMobilityRefreshCommitOp    = "RefreshCommitter.CommitLeafMobilityRefresh"
	leafMobilityRefreshCancelOp    = "RefreshSource cancellation"
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
	ref           PathRef
	claim         *leafmobility.Claim
	evidence      leafmobility.RefreshEvidence
	snapshot      leafmobility.RefreshSnapshot
	sourceBinding MigrationPathBinding
	deadline      time.Time
	policyHold    *leafMobilityPolicyHold
	finishWorker  *sync.Once
}

func (event leafMobilityRefreshEvent) releasePolicyHold() {
	if event.policyHold != nil {
		event.policyHold.Release()
	}
}

type leafMobilityRefreshBudget struct {
	endpointGeneration uint64
	incarnation        uint64
	sourceGeneration   uint64
	deadline           time.Time
}

type leafMobilityRefreshSubscriptionResult struct {
	cancel func()
	err    error
}

type leafMobilityRefreshCancellation struct {
	owner       *leafMobilityRefreshSubscriptionOwner
	cancelSetup context.CancelCauseFunc
	cancel      func()
	reservation *externalPathDurableCallbackReservation
	once        sync.Once
	startErr    error
	callback    bool
}

func (cancellation *leafMobilityRefreshCancellation) start() error {
	if cancellation == nil {
		return nil
	}
	cancellation.once.Do(func() {
		if cancellation.owner != nil {
			cancellation.owner.revoke()
		}
		if cancellation.cancelSetup != nil {
			cancellation.cancelSetup(context.Canceled)
		}
		if cancellation.cancel == nil {
			cancellation.startErr = cancellation.reservation.releaseReservation()
			return
		}
		cancellation.callback = true
		cancellation.startErr = cancellation.reservation.start(func() error {
			cancellation.cancel()
			return nil
		})
	})
	return cancellation.startErr

}

func (cancellation *leafMobilityRefreshCancellation) run(ctx context.Context) error {
	if err := cancellation.start(); err != nil || cancellation == nil || !cancellation.callback {
		return err
	}
	return cancellation.reservation.wait(ctx)
}

func (cancellation *leafMobilityRefreshCancellation) completion() <-chan struct{} {
	if cancellation == nil {
		return (*externalPathDurableCallbackReservation)(nil).completion()
	}
	return cancellation.reservation.completion()
}

type leafMobilityRefreshSubscriptionOwner struct {
	mu                  sync.Mutex
	callback            func(leafmobility.RefreshEvidence)
	validateEvidence    func(leafmobility.RefreshEvidence) (leafmobility.RefreshSnapshot, error)
	beforeAdmission     func(leafmobility.RefreshSnapshot)
	callbackAuthority   *externalPathCallbackOwner
	deliveryReservation *externalPathDurableCallbackReservation
	deliveryRunning     *externalPathDurableCallbackReservation
	pendingEvidence     leafmobility.RefreshEvidence
	pendingEvidenceSet  bool
	sourceLineage       leafmobility.RefreshSourceLineage
	latestGeneration    uint64
	trackCompletion     func(*externalPathDurableCallbackReservation)
	recordTeardown      func(error)
	completionTrackOnce sync.Once
	active              bool
}

type leafMobilityRefreshDeliveryTarget struct {
	owner *leafMobilityRefreshSubscriptionOwner
}

func (owner *leafMobilityRefreshSubscriptionOwner) setCompletionTracker(
	track func(*externalPathDurableCallbackReservation),
	record func(error),
) {
	if owner == nil {
		return
	}
	owner.mu.Lock()
	owner.trackCompletion = track
	owner.recordTeardown = record
	owner.mu.Unlock()
}

func (owner *leafMobilityRefreshSubscriptionOwner) track(
	reservation *externalPathDurableCallbackReservation,
) {
	if owner == nil || reservation == nil {
		return
	}
	owner.completionTrackOnce.Do(func() {
		owner.mu.Lock()
		track := owner.trackCompletion
		owner.mu.Unlock()
		if track != nil {
			track(reservation)
		}
	})

}

func (owner *leafMobilityRefreshSubscriptionOwner) recordWaitError(err error) {
	if owner == nil || err == nil {
		return
	}
	var deadlineErr *pathDispatchCallbackDeadlineError
	var stateErr *externalPathDurableCallbackStateError
	if !errors.As(err, &deadlineErr) && !errors.As(err, &stateErr) {
		return
	}
	owner.mu.Lock()
	record := owner.recordTeardown
	owner.mu.Unlock()
	if record != nil {
		record(err)
	}
}

func newLeafMobilityRefreshSubscriptionOwner(
	claim *leafmobility.Claim,
	callback func(leafmobility.RefreshEvidence),
) *leafMobilityRefreshSubscriptionOwner {
	owner := &leafMobilityRefreshSubscriptionOwner{callback: callback, active: true}
	if claim != nil {
		owner.validateEvidence = func(evidence leafmobility.RefreshEvidence) (leafmobility.RefreshSnapshot, error) {
			return evidence.ValidateFor(claim, 0)
		}
	}
	return owner
}

func (owner *leafMobilityRefreshSubscriptionOwner) bindCallbackAuthority(
	authority *externalPathCallbackOwner,
) error {
	if owner == nil || authority == nil {
		return errors.New("engine: nil leaf mobility refresh callback authority")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.callbackAuthority != nil && owner.callbackAuthority != authority {
		return errors.New("engine: leaf mobility refresh callback authority already bound")
	}
	if !owner.active {
		return errors.New("engine: leaf mobility refresh subscription owner is revoked")
	}
	if owner.deliveryReservation != nil || owner.deliveryRunning != nil {
		return errors.New("engine: leaf mobility refresh delivery authority already bound")
	}
	owner.callbackAuthority = authority
	reservation, err := owner.reserveDelivery(authority)
	if err != nil {
		owner.callbackAuthority = nil
		return err
	}
	owner.deliveryReservation = reservation
	return nil
}

func (owner *leafMobilityRefreshSubscriptionOwner) reserveDelivery(
	authority *externalPathCallbackOwner,
) (*externalPathDurableCallbackReservation, error) {
	reservation, err := reserveExternalPathDurableCallbackTargetAuthority(
		leafMobilityRefreshEventOp,
		&leafMobilityRefreshDeliveryTarget{owner: owner},
		authority,
	)
	if err != nil {
		return nil, err
	}
	if err := reservation.onCompletion(func(completion externalPathDurableCallbackCompletion) {
		owner.completeDelivery(reservation, completion)
	}); err != nil {
		_ = reservation.releaseReservation()
		return nil, err
	}
	return reservation, nil
}

func (owner *leafMobilityRefreshSubscriptionOwner) publish(evidence leafmobility.RefreshEvidence) {
	if owner == nil {
		return
	}
	if owner.validateEvidence == nil {
		return
	}
	snapshot, err := owner.validateEvidence(evidence)
	if err != nil || snapshot.Generation == 0 {
		return
	}
	if owner.beforeAdmission != nil {
		owner.beforeAdmission(snapshot)
	}
	owner.mu.Lock()
	if !owner.active || owner.callback == nil || owner.callbackAuthority == nil {
		owner.mu.Unlock()
		return
	}
	if snapshot.SourceLineage != (leafmobility.RefreshSourceLineage{}) {
		if owner.sourceLineage == (leafmobility.RefreshSourceLineage{}) {
			owner.sourceLineage = snapshot.SourceLineage
		} else if owner.sourceLineage != snapshot.SourceLineage {
			owner.mu.Unlock()
			return
		}
	}
	// Within one exact source lineage, retaining the highest validated
	// process-wide generation prevents a delayed callback from replacing newer
	// factual evidence merely because it acquired this mutex later.
	if snapshot.Generation <= owner.latestGeneration {
		owner.mu.Unlock()
		return
	}
	owner.latestGeneration = snapshot.Generation
	owner.pendingEvidence = evidence
	owner.pendingEvidenceSet = true
	if owner.deliveryRunning != nil {
		owner.mu.Unlock()
		return
	}
	reservation := owner.deliveryReservation
	if reservation == nil {
		owner.active = false
		owner.callback = nil
		owner.pendingEvidence = leafmobility.RefreshEvidence{}
		owner.pendingEvidenceSet = false
		record := owner.recordTeardown
		owner.mu.Unlock()
		if record != nil {
			record(&externalPathDurableCallbackStateError{
				operation: leafMobilityRefreshEventOp,
				action:    "publish without reserved delivery authority",
				state:     externalPathDurableCallbackReleased,
			})
		}
		return
	}
	owner.deliveryReservation = nil
	owner.deliveryRunning = reservation
	owner.mu.Unlock()
	if err := reservation.start(owner.runDelivery); err != nil {
		return
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), externalPathValueCallbackTimeout)
	defer cancel()
	// A timed-out wait does not abandon the event. The durable worker and exact
	// generation authority remain live until delivery and handoff complete.
	_ = reservation.wait(waitCtx)
}

func (owner *leafMobilityRefreshSubscriptionOwner) runDelivery() (retErr error) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			retErr = newPathDispatchCallbackPanicError(leafMobilityRefreshEventOp, recovered)
		} else if !returned {
			retErr = &pathDispatchCallbackGoexitError{operation: leafMobilityRefreshEventOp}
		}
		retErr = errors.Join(retErr, owner.prepareDeliveryHandoff())
	}()
	owner.mu.Lock()
	if !owner.active || owner.callback == nil || !owner.pendingEvidenceSet {
		owner.mu.Unlock()
		returned = true
		return nil
	}
	evidence := owner.pendingEvidence
	owner.pendingEvidence = leafmobility.RefreshEvidence{}
	owner.pendingEvidenceSet = false
	callback := owner.callback
	owner.mu.Unlock()
	// One reservation delivers one coalesced snapshot. Any event admitted while
	// this callback runs is handed off through the executor queue, preventing a
	// noisy source from monopolizing one of the bounded durable workers.
	callback(evidence)
	returned = true
	return nil
}

func (owner *leafMobilityRefreshSubscriptionOwner) prepareDeliveryHandoff() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	active := owner.active
	authority := owner.callbackAuthority
	owner.mu.Unlock()
	if !active || authority == nil {
		return nil
	}
	reservation, err := owner.reserveDelivery(authority)
	owner.mu.Lock()
	if !owner.active || owner.callbackAuthority != authority {
		owner.mu.Unlock()
		if reservation != nil {
			_ = reservation.releaseReservation()
		}
		return nil
	}
	if err != nil {
		var stateErr *externalPathDurableCallbackStateError
		if errors.As(err, &stateErr) && stateErr.action == "invoke after exact-generation retirement" {
			owner.active = false
			owner.callback = nil
			owner.pendingEvidence = leafmobility.RefreshEvidence{}
			owner.pendingEvidenceSet = false
			owner.mu.Unlock()
			return nil
		}
	}
	if err == nil {
		owner.deliveryReservation = reservation
	}
	owner.mu.Unlock()
	return err
}

func (owner *leafMobilityRefreshSubscriptionOwner) completeDelivery(
	reservation *externalPathDurableCallbackReservation,
	completion externalPathDurableCallbackCompletion,
) {
	if owner == nil {
		return
	}
	var next *externalPathDurableCallbackReservation
	var release *externalPathDurableCallbackReservation
	owner.mu.Lock()
	if owner.deliveryRunning != reservation {
		record := owner.recordTeardown
		owner.mu.Unlock()
		if completion.Terminal != nil && record != nil {
			record(completion.Terminal)
		}
		return
	}
	owner.deliveryRunning = nil
	if completion.Terminal != nil {
		owner.active = false
		owner.callback = nil
		owner.pendingEvidence = leafmobility.RefreshEvidence{}
		owner.pendingEvidenceSet = false
		release = owner.deliveryReservation
		owner.deliveryReservation = nil
	} else if owner.active && owner.pendingEvidenceSet && owner.deliveryReservation != nil {
		next = owner.deliveryReservation
		owner.deliveryReservation = nil
		owner.deliveryRunning = next
	}
	record := owner.recordTeardown
	owner.mu.Unlock()
	if release != nil {
		_ = release.releaseReservation()
	}
	if completion.Terminal != nil && record != nil {
		record(completion.Terminal)
	}
	if next != nil {
		_ = next.start(owner.runDelivery)
	}
}

func (owner *leafMobilityRefreshSubscriptionOwner) revoke() {
	if owner == nil {
		return
	}
	owner.mu.Lock()
	owner.active = false
	owner.callback = nil
	owner.pendingEvidence = leafmobility.RefreshEvidence{}
	owner.pendingEvidenceSet = false
	reservation := owner.deliveryReservation
	owner.deliveryReservation = nil
	owner.mu.Unlock()
	if reservation != nil {
		_ = reservation.releaseReservation()
	}
}

func (owner *leafMobilityRefreshSubscriptionOwner) activeNow() bool {
	if owner == nil {
		return false
	}
	owner.mu.Lock()
	active := owner.active
	owner.mu.Unlock()
	return active
}

func (owner *leafMobilityRefreshSubscriptionOwner) lockPublication() bool {
	if owner == nil {
		return false
	}
	owner.mu.Lock()
	if !owner.active {
		owner.mu.Unlock()
		return false
	}
	return true
}

func (owner *leafMobilityRefreshSubscriptionOwner) unlockPublication() {
	owner.mu.Unlock()
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
	var subscriptionOwner *leafMobilityRefreshSubscriptionOwner
	subscriptionOwner = newLeafMobilityRefreshSubscriptionOwner(claim, func(evidence leafmobility.RefreshEvidence) {
		e.enqueueLeafMobilityRefresh(ref, slot, claim, subscriptionOwner, evidence)
	})
	subscriptionOwner.setCompletionTracker(e.trackLeafRefreshRegistrationCompletion, e.recordTeardownErr)
	cancellation, err := invokeLeafMobilityRefreshSubscribeOwned(
		source, subscriptionCtx, subscriptionOwner, slot.callbackAuthority,
	)
	if err != nil {
		close(subscriptionDone)
		cancelSubscription()
		e.recordLeafMobilityInitiator(LeafMobilityInitiatorSnapshot{
			Ref: ref, SourceEndpointGeneration: slot.mobilityFacts.Generation,
			Phase: LeafMobilityInitiatorSubscriptionUnavailable, UpdatedAt: time.Now(), Error: err.Error(),
		})
		return
	}
	var once sync.Once
	e.recordLeafMobilityInitiator(LeafMobilityInitiatorSnapshot{
		Ref: ref, SourceEndpointGeneration: slot.mobilityFacts.Generation,
		Phase: LeafMobilityInitiatorIdle, UpdatedAt: time.Now(),
	})
	slot.installMobilityRefreshCancel(func() {
		once.Do(func() {
			// Publication authority is revoked synchronously. Only the untrusted
			// transport cancellation callback is deferred to the tracked worker.
			subscriptionOwner.revoke()
			close(subscriptionDone)
			cancelSubscription()
			// Revoke every pending or running factual decision before entering
			// transport-owned teardown. A malformed cancel callback therefore
			// cannot retain a policy hold or specialized execution authority.
			e.forgetLeafMobilityRefresh(ref)
			e.startLeafMobilityRefreshCancel(cancellation)
		})
	})
}

func invokeLeafMobilityRefreshSubscribeOwned(
	source leafmobility.RefreshSource,
	ctx context.Context,
	owner *leafMobilityRefreshSubscriptionOwner,
	callbackAuthority *externalPathCallbackOwner,
) (*leafMobilityRefreshCancellation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if owner == nil {
		return nil, errors.New("engine: nil leaf mobility refresh subscription owner")
	}
	if err := ctx.Err(); err != nil {
		return nil, &pathDispatchCallbackDeadlineError{operation: leafMobilityRefreshSubscribeOp, cause: err}
	}
	if err := owner.bindCallbackAuthority(callbackAuthority); err != nil {
		return nil, err
	}
	cancelReservation, err := reserveExternalPathDurableCallbackAuthority(
		leafMobilityRefreshCancelOp, callbackAuthority,
	)
	if err != nil {
		owner.revoke()
		return nil, err
	}
	lease, err := acquireExternalPathCallbackLeaseTargetAuthority(
		leafMobilityRefreshSubscribeOp, source, callbackAuthority,
	)
	if err != nil {
		cancelReservation.releaseReservation()
		owner.revoke()
		return nil, err
	}
	setupCtx, cancelSetup := context.WithCancelCause(ctx)
	timer := time.AfterFunc(externalPathValueCallbackTimeout, func() {
		cancelSetup(context.DeadlineExceeded)
	})
	result := make(chan leafMobilityRefreshSubscriptionResult)
	abandoned := make(chan struct{})
	go func() {
		var subscription leafMobilityRefreshSubscriptionResult
		returned := false
		defer func() {
			if recovered := recover(); recovered != nil {
				subscription.err = newPathDispatchCallbackPanicError(leafMobilityRefreshSubscribeOp, recovered)
			} else if !returned {
				subscription.err = &pathDispatchCallbackGoexitError{operation: leafMobilityRefreshSubscribeOp}
			}
			select {
			case result <- subscription:
			case <-abandoned:
				owner.revoke()
				cancelSetup(context.Canceled)
				cleanupLeafMobilityRefreshSubscription(
					owner, cancelSetup, subscription.cancel, cancelReservation,
				)
			}
			lease.release()
		}()
		subscription.cancel, subscription.err = source.SubscribeLeafMobilityRefresh(setupCtx, owner.publish)
		returned = true
	}()
	select {
	case subscription := <-result:
		timer.Stop()
		if cause := context.Cause(setupCtx); cause != nil {
			owner.revoke()
			cancelSetup(cause)
			cleanupLeafMobilityRefreshSubscription(
				owner, cancelSetup, subscription.cancel, cancelReservation,
			)
			return nil, &pathDispatchCallbackDeadlineError{
				operation: leafMobilityRefreshSubscribeOp,
				cause:     cause,
			}
		}
		if subscription.err != nil {
			owner.revoke()
			cancelSetup(subscription.err)
			cleanupLeafMobilityRefreshSubscription(
				owner, cancelSetup, subscription.cancel, cancelReservation,
			)
			return nil, subscription.err
		}
		return &leafMobilityRefreshCancellation{
			owner: owner, cancelSetup: cancelSetup, cancel: subscription.cancel,
			reservation: cancelReservation,
		}, nil
	case <-setupCtx.Done():
		timer.Stop()
		owner.revoke()
		owner.track(cancelReservation)
		close(abandoned)
		return nil, &pathDispatchCallbackDeadlineError{
			operation: leafMobilityRefreshSubscribeOp,
			cause:     context.Cause(setupCtx),
		}
	}
}

func cleanupLeafMobilityRefreshSubscription(
	owner *leafMobilityRefreshSubscriptionOwner,
	cancelSetup context.CancelCauseFunc,
	cancel func(),
	reservation *externalPathDurableCallbackReservation,
) {
	ctx, stop := context.WithTimeout(context.Background(), externalPathValueCallbackTimeout)
	defer stop()
	cancellation := &leafMobilityRefreshCancellation{
		owner: owner, cancelSetup: cancelSetup, cancel: cancel, reservation: reservation,
	}
	owner.track(reservation)
	owner.recordWaitError(cancellation.run(ctx))
}

func invokeLeafMobilityRefreshCancel(ctx context.Context, owner any, cancel func()) error {
	if cancel == nil {
		return nil
	}
	var reservation *externalPathDurableCallbackReservation
	var err error
	if callbackAuthority, ok := owner.(*externalPathCallbackOwner); ok {
		reservation, err = reserveExternalPathDurableCallbackAuthority(
			leafMobilityRefreshCancelOp, callbackAuthority,
		)
	} else {
		reservation, err = reserveExternalPathDurableCallback(leafMobilityRefreshCancelOp, owner)
	}
	if err != nil {
		return err
	}
	return reservation.invoke(ctx, func() error {
		cancel()
		return nil
	})
}

func (e *Engine) startLeafMobilityRefreshCancel(cancellation *leafMobilityRefreshCancellation) {
	if e == nil || cancellation == nil {
		return
	}
	e.leafRefreshCancelWG.Add(1)
	if err := cancellation.reservation.onCompletion(func(completion externalPathDurableCallbackCompletion) {
		e.recordTeardownErr(completion.Terminal)
		e.leafRefreshCancelWG.Done()
	}); err != nil {
		e.recordTeardownErr(err)
		e.leafRefreshCancelWG.Done()
		return
	}
	if err := cancellation.start(); err != nil {
		e.recordTeardownErr(err)
		return
	}
	if cancellation.callback {
		if err := externalPathDurableCallbackDeadlines.schedule(
			cancellation.reservation, externalPathValueCallbackTimeout, e.recordTeardownErr,
		); err != nil {
			e.recordTeardownErr(err)
		}
	}
}

// trackLeafRefreshRegistrationCompletion is called only while an existing
// registration ticket is live. Each late setup/cancel worker transfers that
// ticket before its predecessor returns, so Close never races a zero-to-one
// WaitGroup Add.
func (e *Engine) trackLeafRefreshRegistrationCompletion(
	reservation *externalPathDurableCallbackReservation,
) {
	if e == nil || reservation == nil {
		return
	}
	e.leafRefreshRegistrationWG.Add(1)
	if err := reservation.onCompletion(func(completion externalPathDurableCallbackCompletion) {
		e.recordTeardownErr(completion.Terminal)
		e.leafRefreshRegistrationWG.Done()
	}); err != nil {
		e.recordTeardownErr(err)
		e.leafRefreshRegistrationWG.Done()
	}
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

func (e *Engine) enqueueLeafMobilityRefresh(
	ref PathRef,
	sourceSlot *pathSlot,
	claim *leafmobility.Claim,
	owner *leafMobilityRefreshSubscriptionOwner,
	evidence leafmobility.RefreshEvidence,
) {
	if e == nil || claim == nil || !owner.activeNow() || e.closing.Load() {
		return
	}
	initial, err := evidence.ValidateFor(claim, 0)
	if err != nil {
		return
	}
	var policyHold *leafMobilityPolicyHold
	if leafMobilityRefreshRequiresPolicyHold(initial.Reason) && initial.SourceUsable {
		policyHold = e.acquireSelectedLeafMobilityPolicyHold(
			sourceSlot, leafMobilityRefreshIsLeafFault(initial.Reason),
		)
	}
	accepted := false
	defer func() {
		if !accepted && policyHold != nil {
			policyHold.Release()
		}
	}()
	if hook := e.leafRefreshBeforePublish; hook != nil {
		hook()
	}
	e.pathsMu.RLock()
	current := e.leafMobilityRefreshClaimPresentLocked(ref, claim)
	if !current {
		e.pathsMu.RUnlock()
		return
	}
	e.leafRefreshMu.Lock()
	if e.closing.Load() {
		e.leafRefreshMu.Unlock()
		e.pathsMu.RUnlock()
		return
	}
	after := e.leafRefreshSeen[ref]
	snapshot, err := evidence.ValidateFor(claim, after)
	if err != nil {
		e.leafRefreshMu.Unlock()
		e.pathsMu.RUnlock()
		return
	}
	budget := e.leafRefreshBudget[ref]
	if budget.endpointGeneration == snapshot.EndpointGeneration && budget.incarnation == snapshot.Incarnation &&
		budget.sourceGeneration == snapshot.SourceGeneration && !budget.deadline.IsZero() {
		e.leafRefreshMu.Unlock()
		e.pathsMu.RUnlock()
		return
	}
	// Cancellation revokes this owner synchronously before clearing pending
	// state. Holding the owner gate over the final map mutation gives exactly
	// one order: either this publication commits and cancellation removes it,
	// or cancellation wins and this callback cannot recreate it.
	if !owner.lockPublication() {
		e.leafRefreshMu.Unlock()
		e.pathsMu.RUnlock()
		return
	}
	// A selector may have activated this leaf after the callback first sampled
	// it but before the event became visible in leafRefreshPending. Recheck the
	// effective projection while pathsMu and leafRefreshMu form the same lock
	// order used by selector promotion. The selector either observes this event
	// in the queue or this callback observes the committed selector state.
	if policyHold != nil && e.pathSlotInEffectiveProjectionLocked(e.localExecutionRuntime(), sourceSlot) {
		policyHold.Promote()
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
	previous := e.leafRefreshPending[ref]
	e.leafRefreshPending[ref] = leafMobilityRefreshEvent{
		ref: ref, claim: claim, evidence: evidence, snapshot: snapshot, deadline: budget.deadline, policyHold: policyHold,
	}
	e.leafRefreshStatus[ref] = LeafMobilityInitiatorSnapshot{
		Ref: ref, EvidenceGeneration: snapshot.Generation,
		SourceEndpointGeneration: snapshot.EndpointGeneration, EvidenceReason: snapshot.Reason,
		ObservedAt: snapshot.ObservedAt, UpdatedAt: time.Now(), Phase: LeafMobilityInitiatorPending,
		Deadline: budget.deadline,
	}
	owner.unlockPublication()
	e.leafRefreshMu.Unlock()
	e.pathsMu.RUnlock()
	accepted = true
	previous.releasePolicyHold()
	select {
	case e.leafRefreshWake <- struct{}{}:
	default:
	}
	e.signalLeafMobilityRetry()
}

func leafMobilityRefreshRequiresPolicyHold(reason leafmobility.RefreshReason) bool {
	switch reason {
	case leafmobility.RefreshReasonRouteSourceChanged,
		leafmobility.RefreshReasonLinkUnresponsive,
		leafmobility.RefreshReasonLocalReadFailure,
		leafmobility.RefreshReasonLocalWriteFailure,
		leafmobility.RefreshReasonOuterMTUFailure,
		leafmobility.RefreshReasonReplayStalled,
		leafmobility.RefreshReasonReplayFailure,
		leafmobility.RefreshReasonLivenessProbeFailure:
		return true
	default:
		return false
	}
}

func leafMobilityRefreshIsLeafFault(reason leafmobility.RefreshReason) bool {
	switch reason {
	case leafmobility.RefreshReasonLinkUnresponsive,
		leafmobility.RefreshReasonLocalReadFailure,
		leafmobility.RefreshReasonLocalWriteFailure,
		leafmobility.RefreshReasonReplayStalled,
		leafmobility.RefreshReasonReplayFailure,
		leafmobility.RefreshReasonLivenessProbeFailure:
		return true
	default:
		return false
	}
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
				defer e.finishLeafMobilityRefreshWorker(event)
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
		event.finishWorker = &sync.Once{}
		e.leafRefreshRunning[ref] = event.policyHold
		workerCtx, cancel := context.WithCancelCause(context.Background())
		e.leafRefreshCancel[ref] = cancel
		return event, workerCtx, true
	}
	return leafMobilityRefreshEvent{}, nil, false
}

func (e *Engine) finishLeafMobilityRefreshWorker(event leafMobilityRefreshEvent) {
	if event.finishWorker == nil {
		return
	}
	event.finishWorker.Do(func() {
		// The policy hold belongs to this exact worker. Release it before
		// removing the running marker so a terminal status can never imply that
		// selector policy is still fenced by a worker that has already ended.
		event.releasePolicyHold()
		e.leafRefreshMu.Lock()
		delete(e.leafRefreshRunning, event.ref)
		cancel := e.leafRefreshCancel[event.ref]
		delete(e.leafRefreshCancel, event.ref)
		_, pending := e.leafRefreshPending[event.ref]
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
	})
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
		if err := e.leafMobilityRefreshCommitterBusy(event); err != nil {
			e.updateLeafMobilityRefresh(event, LeafMobilityInitiatorDeferred, leafmobility.Plan{}, leafmobility.TransactionID{}, err)
			if e.waitLeafMobilityBackoff(ctx, retryDelay) {
				retryDelay = nextLeafMobilityBackoff(retryDelay)
				continue
			}
			e.finishLeafMobilityRefresh(event, LeafMobilityInitiatorExpired, leafmobility.Plan{}, leafmobility.TransactionID{}, context.Cause(ctx))
			return
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
		if err := e.validateLeafMobilityRefreshEvent(event); err != nil {
			rollbackErr := authority.Rollback(context.WithoutCancel(ctx))
			phase := LeafMobilityInitiatorSuperseded
			if rollbackErr != nil && !errors.Is(rollbackErr, leafmobility.ErrAuthorityStale) {
				phase = LeafMobilityInitiatorFailed
			}
			if authority.State() == leafmobility.ResourceTransactionOutcomeUnknown ||
				errors.Is(rollbackErr, ErrLeafMobilityOutcomeUnknown) {
				phase = LeafMobilityInitiatorFailClosed
			}
			e.finishLeafMobilityRefresh(event, phase, plan, transactionID, errors.Join(err, rollbackErr))
			return
		}
		event.sourceBinding = e.leafMobilitySourceBinding(event)
		if !validLeafMobilitySourceBinding(event, event.sourceBinding) {
			bindingErr := fmt.Errorf("%w: leaf mobility source binding is unavailable", ErrStalePathRef)
			rollbackErr := authority.Rollback(context.WithoutCancel(ctx))
			phase := LeafMobilityInitiatorSuperseded
			if rollbackErr != nil && !errors.Is(rollbackErr, leafmobility.ErrAuthorityStale) {
				phase = LeafMobilityInitiatorFailed
			}
			if authority.State() == leafmobility.ResourceTransactionOutcomeUnknown ||
				errors.Is(rollbackErr, ErrLeafMobilityOutcomeUnknown) {
				phase = LeafMobilityInitiatorFailClosed
			}
			e.finishLeafMobilityRefresh(event, phase, plan, transactionID, errors.Join(bindingErr, rollbackErr))
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
			commitErr, _ := e.recordCommittedLeafMobility(ctx, event, transactionID)
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

func validLeafMobilitySourceBinding(event leafMobilityRefreshEvent, binding MigrationPathBinding) bool {
	return binding.PathID == event.ref.ID && binding.PathOwner == event.ref.Owner &&
		binding.PathGeneration != 0 && binding.RouteGeneration != 0 && binding.EndpointGeneration != 0 &&
		binding.EndpointGeneration == event.snapshot.EndpointGeneration &&
		binding.LocalTargetID != ([16]byte{}) && binding.PeerTargetID != ([16]byte{})
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

func (e *Engine) leafMobilitySourceBinding(event leafMobilityRefreshEvent) MigrationPathBinding {
	if e == nil {
		return MigrationPathBinding{}
	}
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	slot := e.paths[event.ref.ID]
	if slot == nil || slot.owner != event.ref.Owner || slot.mobilityClaim != event.claim {
		return MigrationPathBinding{}
	}
	return migrationPathBindingForSlot(slot)
}

func (e *Engine) leafMobilityRefreshCommitterBusy(event leafMobilityRefreshEvent) error {
	if e == nil {
		return nil
	}
	e.pathsMu.RLock()
	slot := e.paths[event.ref.ID]
	if slot == nil || slot.owner != event.ref.Owner || slot.mobilityClaim != event.claim {
		e.pathsMu.RUnlock()
		return ErrStalePathRef
	}
	committer, _ := slot.conn.(leafmobility.RefreshCommitter)
	authority := slot.callbackAuthority
	e.pathsMu.RUnlock()
	if committer != nil && authority == nil {
		return &externalPathDurableCallbackStateError{
			operation: leafMobilityRefreshCommitOp,
			action:    "check without exact-generation callback authority",
			state:     externalPathDurableCallbackReleased,
		}
	}
	if committer != nil && externalPathCallbackInFlight(leafMobilityRefreshCommitOp, authority) {
		return &pathDispatchCallbackBusyError{operation: leafMobilityRefreshCommitOp}
	}
	return nil
}

func (e *Engine) recordCommittedLeafMobility(
	ctx context.Context,
	event leafMobilityRefreshEvent,
	transactionID leafmobility.TransactionID,
) (error, bool) {
	e.pathsMu.Lock()
	slot := e.paths[event.ref.ID]
	if slot == nil || slot.owner != event.ref.Owner || slot.mobilityClaim != event.claim {
		e.pathsMu.Unlock()
		return ErrStalePathRef, false
	}
	sourceBinding := event.sourceBinding
	sourceBinding.EndpointGeneration = event.snapshot.EndpointGeneration
	e.syncPathMobilityFactsLocked(slot, event.claim)
	committer, _ := slot.conn.(leafmobility.RefreshCommitter)
	authority := slot.callbackAuthority
	resultBinding := migrationPathBindingForSlot(slot)
	migrationEvent := e.recordMigrationLocked(event.ref.ID, event.ref.ID, "leaf-mobility", MigrationEvidence{
		Kind:                      MigrationEvidenceLeafMobility,
		TransactionID:             [16]byte(transactionID),
		RefreshEvidenceGeneration: event.snapshot.Generation,
		SourceEndpointGeneration:  event.snapshot.EndpointGeneration,
		ResultEndpointGeneration:  slot.mobilityFacts.Generation,
		TopologyEpoch:             e.currentPathTopologyEpoch(),
		Source:                    sourceBinding,
		Result:                    resultBinding,
		Leaf: MigrationLeafBinding{
			RefreshReason:           migrationRefreshReasonName(event.snapshot.Reason),
			RefreshObservedAt:       event.snapshot.ObservedAt,
			RefreshSourceGeneration: event.snapshot.SourceGeneration,
			RefreshSourceUsable:     event.snapshot.SourceUsable,
			RefreshIncarnation:      event.snapshot.Incarnation,
		},
	})
	ticket := e.accountMigration()
	e.pathsMu.Unlock()

	// The migration is factual once accounting and its immutable event have
	// committed under pathsMu. A transport-owned baseline callback must not
	// delay observation or zombie accounting after that boundary.
	e.deliverMigrationEvent(migrationEvent)
	e.tripZombie(ticket)

	var commitErr error
	if committer != nil {
		commitErr = invokeLeafMobilityRefreshCommitter(ctx, authority, committer, event.evidence)
	}
	return commitErr, true
}

func invokeLeafMobilityRefreshCommitter(
	ctx context.Context,
	authority *externalPathCallbackOwner,
	committer leafmobility.RefreshCommitter,
	evidence leafmobility.RefreshEvidence,
) error {
	if committer == nil {
		return nil
	}
	return invokeExternalPathErrorCallbackAuthority(ctx, leafMobilityRefreshCommitOp, authority, func() error {
		return committer.CommitLeafMobilityRefresh(evidence)
	})
}

func (e *Engine) syncLeafMobilityPathBeforeUnfence(outgoing *outgoingLeafMobilityTransaction, slot *pathSlot) {
	if e == nil || outgoing == nil || slot == nil || outgoing.claim == nil {
		return
	}
	e.pathsMu.Lock()
	current := e.paths[outgoing.source.ID]
	if current == slot && current.owner == outgoing.source.Owner && current.mobilityClaim == outgoing.claim {
		e.syncPathMobilityFactsLocked(current, outgoing.claim)
	}
	e.pathsMu.Unlock()
}

// syncPathMobilityFactsLocked updates physical-generation evidence before TX
// can reopen. Caller holds pathsMu. It is intentionally idempotent because the
// automatic initiator records migration accounting after authority completion.
func (e *Engine) syncPathMobilityFactsLocked(slot *pathSlot, claim *leafmobility.Claim) {
	if slot == nil || claim == nil {
		return
	}
	facts := claim.Snapshot()
	changed := slot.probeEndpointGen.Load() != facts.Generation
	slot.mobilityFacts = facts
	if changed {
		slot.retireLegacyQualityEvidence()
		slot.probeEndpointGen.Store(facts.Generation)
		e.invalidatePredecessorPathProbeEvidence(slot)
		e.advancePathTopologyEpochLocked()
	}
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
	if phase == LeafMobilityInitiatorBaseline && event.snapshot.Reason == leafmobility.RefreshReasonRouteSourceRestored {
		e.clearLeafMobilityRefreshBudget(event)
	}
	// A terminal status is an externally observable ownership boundary. Clear
	// this event's initiator worker, cancellation and policy hold first. The
	// per-event once also makes the goroutine's deferred cleanup harmless and
	// prevents it from deleting a newer worker admitted for the same PathRef.
	e.finishLeafMobilityRefreshWorker(event)
	e.updateLeafMobilityRefresh(event, phase, plan, transactionID, err)
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
	if !current {
		e.pathsMu.RUnlock()
		return
	}
	if hook := e.leafRefreshStatusBeforeWrite; hook != nil {
		hook()
	}
	e.leafRefreshMu.Lock()
	previous, ok := e.leafRefreshStatus[snapshot.Ref]
	if !ok || previous.EvidenceGeneration <= snapshot.EvidenceGeneration {
		e.leafRefreshStatus[snapshot.Ref] = snapshot
	}
	e.leafRefreshMu.Unlock()
	e.pathsMu.RUnlock()
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
	pending := e.leafRefreshPending[ref]
	delete(e.leafRefreshPending, ref)
	delete(e.leafRefreshSeen, ref)
	delete(e.leafRefreshBudget, ref)
	delete(e.leafRefreshStatus, ref)
	e.leafRefreshMu.Unlock()
	pending.releasePolicyHold()
}

func (e *Engine) closeLeafMobilityRefreshQueue() {
	e.leafRefreshMu.Lock()
	pending := make([]leafMobilityRefreshEvent, 0, len(e.leafRefreshPending))
	for _, event := range e.leafRefreshPending {
		pending = append(pending, event)
	}
	for _, cancel := range e.leafRefreshCancel {
		cancel(net.ErrClosed)
	}
	e.leafRefreshPending = make(map[PathRef]leafMobilityRefreshEvent)
	e.leafRefreshSeen = make(map[PathRef]uint64)
	e.leafRefreshBudget = make(map[PathRef]leafMobilityRefreshBudget)
	e.leafRefreshStatus = make(map[PathRef]LeafMobilityInitiatorSnapshot)
	e.leafRefreshMu.Unlock()
	for _, event := range pending {
		event.releasePolicyHold()
	}
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
