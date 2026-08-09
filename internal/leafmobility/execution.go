package leafmobility

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	goruntime "runtime"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

// ExecutionState is the local driver-attempt state. Peer resolution is a
// separate engine transaction and must not be inferred from this value.
type ExecutionState uint8

const (
	ExecutionInvalid ExecutionState = iota
	ExecutionAuthorized
	ExecutionPrepared
	ExecutionStaged
	ExecutionPublishAuthorized
	ExecutionPublished
	ExecutionActivationRequired
	ExecutionActivated
	ExecutionRollbackRequired
	// ExecutionFailClosedRequired means Publish may have crossed its owner-swap
	// boundary without a complete, trustworthy outcome. Rollback is forbidden;
	// only destructive fail-closed cleanup can release the execution lease.
	ExecutionFailClosedRequired
	ExecutionRolledBack
	ExecutionFailedClosed
)

// FinalAcceptanceDisposition is the only result of atomically consuming a
// correlated FINAL acceptance. RollbackOnly records the peer decision and
// consumes its generation, but never grants the driver a Publish right.
type FinalAcceptanceDisposition uint8

const (
	FinalAcceptanceInvalid FinalAcceptanceDisposition = iota
	FinalAcceptancePublishAllowed
	FinalAcceptanceRollbackOnly
)

var (
	ErrExecutionState       = errors.New("leafmobility: invalid driver execution state")
	ErrExecutionBusy        = errors.New("leafmobility: driver execution is busy")
	ErrExecutionDriver      = errors.New("leafmobility: driver execution failed")
	ErrExecutionDriverPanic = errors.New("leafmobility: driver execution panicked")
)

// PeerAgreement is the correlated FINAL evidence supplied by the engine that
// owns the Claim's issuer. A ResourceTransaction state alone cannot mint it.
type PeerAgreement struct {
	Binding                 proto.LeafMobilityPeerPlanBinding
	Generation              uint64
	ActorEndpointGeneration uint64
	PeerEndpointGeneration  uint64
	ActorPlanDigest         proto.LeafMobilityPlanDigest
	ProposalDigest          proto.LeafMobilityProposalDigest
	PeerPlanDigest          proto.LeafMobilityPeerDigest
	AgreementDigest         proto.LeafMobilityAgreementDigest
	ReservationID           proto.LeafMobilityReservationID
}

// ExecutionRequest binds the exact preflight attempt to the immutable local
// plan and the peer agreement that authorized destructive work.
type ExecutionRequest struct {
	Plan      Plan
	Facts     Facts
	Agreement PeerAgreement
}

type AttemptEvidence struct {
	Digest          EvidenceDigest
	ProbeReferences ProbeReferences
}

// PublicationEvidence is sealed driver evidence for the private successor
// built by Stage. It is opaque on the wire; the engine hashes it with the
// bilateral agreement so COMMIT_INTENT cannot be minted before staging.
type PublicationEvidence struct {
	Digest EvidenceDigest
}

// DriverAttempt is created by one non-destructive Preflight call. It is kept
// private inside Plan and invoked only by an engine-bound Execution. Every
// failing forward stage must preserve enough state for Rollback.
type DriverAttempt interface {
	Evidence() AttemptEvidence
	Prepare(context.Context, ExecutionRequest) error
	// Stage creates and validates a private successor. It must not change the
	// endpoint owner's visible incarnation or release packet quarantine.
	Stage(context.Context, ExecutionRequest) (PublicationEvidence, error)
	// Publish performs only the endpoint-owner swap. Activate owns every
	// post-publication step that may need retrying. Implementations must check
	// the context while holding the owner lock immediately before swapping.
	Publish(context.Context, ExecutionRequest) error
	Activate(context.Context, ExecutionRequest) error
	Rollback(context.Context, ExecutionRequest) error
	// FailClosed terminates every driver-owned endpoint and removes every
	// destructive side effect. It is idempotent and retryable beyond the
	// bilateral plan deadline; protocol expiry never transfers cleanup
	// ownership away from the attempt.
	FailClosed(context.Context, ExecutionRequest) error
	// EndpointGenerationChanged is sampled only after a successful Rollback.
	// Commit always creates a new generation. A rollback reports true when it
	// had to reconstruct or rebind the physical endpoint instead of resuming
	// the original incarnation.
	EndpointGenerationChanged() bool
}

func readAttemptEvidence(attempt DriverAttempt) (evidence AttemptEvidence, err error) {
	if interfaceIsNil(attempt) {
		return AttemptEvidence{}, ErrInvalidDriver
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			evidence = AttemptEvidence{}
			err = fmt.Errorf("%w: attempt evidence panicked: %v", ErrInvalidDriver, recovered)
		}
	}()
	return attempt.Evidence(), nil
}

// Execution is a copy-safe, single-use wrapper around one exact preflight
// attempt. Copies share the same token and cannot execute a stage twice.
type Execution struct {
	token *executionToken
}

type executionToken struct {
	mu                 sync.Mutex
	request            ExecutionRequest
	attempt            DriverAttempt
	claim              *Claim
	issuer             *authorityIssuerToken
	transaction        *resourceTransactionToken
	deadline           time.Time
	forwardDeadline    time.Time
	state              ExecutionState
	busy               bool
	leaseHeld          bool
	incarnationBefore  uint64
	incarnationTracked bool
	publication        PublicationEvidence
	stageCancel        context.CancelFunc
}

func newExecution(
	attempt DriverAttempt,
	request ExecutionRequest,
	claim *Claim,
	issuer *authorityIssuerToken,
	token *resourceTransactionToken,
) *Execution {
	deadline := request.Plan.Deadline
	if request.Plan.attempt != nil && !request.Plan.attempt.deadline.IsZero() {
		deadline = request.Plan.attempt.deadline
	}
	incarnationBefore, incarnationTracked := claim.endpointIncarnation()
	return &Execution{token: &executionToken{
		attempt: attempt, request: request, claim: claim, issuer: issuer, transaction: token,
		deadline: deadline, forwardDeadline: executionForwardDeadline(deadline), state: ExecutionAuthorized,
		incarnationBefore: incarnationBefore, incarnationTracked: incarnationTracked,
	}}
}

const (
	minRollbackReserve = 100 * time.Millisecond
	maxRollbackReserve = 5 * time.Second
)

func executionForwardDeadline(deadline time.Time) time.Time {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return deadline
	}
	reserve := remaining / 4
	if reserve < minRollbackReserve {
		reserve = remaining / 2
	}
	if reserve > maxRollbackReserve {
		reserve = maxRollbackReserve
	}
	return deadline.Add(-reserve)
}

func (e *Execution) State() ExecutionState {
	if e == nil || e.token == nil {
		return ExecutionInvalid
	}
	e.token.mu.Lock()
	state := e.token.state
	e.token.mu.Unlock()
	return state
}

// ForwardDeadline is the immutable end of destructive forward work. The
// interval until the plan deadline is reserved for rollback and peer cleanup.
func (e *Execution) ForwardDeadline() time.Time {
	if e == nil || e.token == nil {
		return time.Time{}
	}
	e.token.mu.Lock()
	deadline := e.token.forwardDeadline
	e.token.mu.Unlock()
	return deadline
}

// Deadline is the monotonic local execution deadline corresponding to the
// canonical wall-clock deadline carried by the bilateral plan.
func (e *Execution) Deadline() time.Time {
	if e == nil || e.token == nil {
		return time.Time{}
	}
	e.token.mu.Lock()
	deadline := e.token.deadline
	e.token.mu.Unlock()
	return deadline
}

func (e *Execution) Prepare(ctx context.Context) error {
	return e.runForwardStep(ctx, ExecutionAuthorized, ExecutionPrepared, "prepare", func(attempt DriverAttempt, ctx context.Context, request ExecutionRequest) error {
		return attempt.Prepare(ctx, request)
	})
}

func (e *Execution) Stage(ctx context.Context) error {
	var publication PublicationEvidence
	err := e.runForwardStep(ctx, ExecutionPrepared, ExecutionStaged, "stage", func(attempt DriverAttempt, ctx context.Context, request ExecutionRequest) error {
		var stageErr error
		publication, stageErr = attempt.Stage(ctx, request)
		if stageErr == nil && publication.Digest == (EvidenceDigest{}) {
			return fmt.Errorf("%w: stage returned zero publication evidence", ErrExecutionDriver)
		}
		if stageErr == nil {
			e.token.mu.Lock()
			e.token.publication = publication
			e.token.mu.Unlock()
		}
		return stageErr
	})
	if err != nil {
		return err
	}
	return nil
}

// PublicationDigest binds the private successor evidence to the exact peer
// agreement. Peers echo this opaque value through FINAL and terminal receipts.
func (e *Execution) PublicationDigest() (proto.LeafMobilityPublicationDigest, error) {
	if e == nil || e.token == nil {
		return proto.LeafMobilityPublicationDigest{}, ErrExecutionState
	}
	e.token.mu.Lock()
	state := e.token.state
	publication := e.token.publication
	agreement := e.token.request.Agreement.AgreementDigest
	e.token.mu.Unlock()
	if state != ExecutionStaged && state != ExecutionPublishAuthorized && state != ExecutionPublished &&
		state != ExecutionActivationRequired && state != ExecutionActivated {
		return proto.LeafMobilityPublicationDigest{}, ErrExecutionState
	}
	if publication.Digest == (EvidenceDigest{}) || agreement == (proto.LeafMobilityAgreementDigest{}) {
		return proto.LeafMobilityPublicationDigest{}, ErrExecutionState
	}
	h := sha256.New()
	h.Write([]byte("rendr-leaf-mobility-publication-v1\x00"))
	h.Write(agreement[:])
	h.Write(publication.Digest[:])
	var digest proto.LeafMobilityPublicationDigest
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// ResolveFinalAcceptance atomically consumes the correlated FINAL state and
// advances both the resource transaction and this exact Execution. Recovery
// passes allowPublish=false because an abandoned COMMIT can only converge by
// rolling back its private successor. No driver method is invoked here.
func (e *Execution) ResolveFinalAcceptance(allowPublish bool) (FinalAcceptanceDisposition, error) {
	if e == nil || e.token == nil {
		return FinalAcceptanceInvalid, ErrExecutionState
	}
	token := e.token
	token.mu.Lock()
	if token.busy {
		token.mu.Unlock()
		return FinalAcceptanceInvalid, ErrExecutionBusy
	}
	stateBefore := token.state
	if stateBefore != ExecutionStaged && stateBefore != ExecutionRollbackRequired && stateBefore != ExecutionRolledBack {
		token.mu.Unlock()
		return FinalAcceptanceInvalid, ErrExecutionState
	}
	if (stateBefore != ExecutionRolledBack && !token.leaseHeld) || token.claim == nil || token.transaction == nil {
		token.mu.Unlock()
		return FinalAcceptanceInvalid, ErrExecutionState
	}
	if stateBefore != ExecutionStaged {
		allowPublish = false
	}
	token.busy = true
	request := token.request
	token.mu.Unlock()

	factualCurrent := request.Plan.attempt != nil && request.Plan.attempt.evidenceCurrent() &&
		request.Plan.ProbeReferences.matchesCurrentExecutionContext() &&
		request.Plan.ProbeReferences.matchesCurrentPlatform(context.Background())
	now := time.Now()
	factualCurrent = factualCurrent && request.Plan.ProbeReferences.validFor(
		request.Plan.Operation, request.Plan.EndpointGeneration,
		now.UnixNano(), request.Plan.Deadline.UnixNano(), true,
	)

	token.mu.Lock()
	if token.state != stateBefore || !token.busy {
		token.busy = false
		token.mu.Unlock()
		return FinalAcceptanceInvalid, ErrExecutionState
	}
	claim := token.claim
	claim.mu.Lock()
	resource := claim.resource
	if resource == nil {
		claim.mu.Unlock()
		token.busy = false
		if stateBefore != ExecutionRolledBack {
			token.state = ExecutionRollbackRequired
		}
		token.mu.Unlock()
		return FinalAcceptanceInvalid, ErrAuthorityStale
	}
	resource.mu.Lock()
	transaction := token.transaction
	linearizedAt := time.Now()
	factualCurrent = factualCurrent && request.Plan.ProbeReferences.validFor(
		request.Plan.Operation, request.Plan.EndpointGeneration,
		linearizedAt.UnixNano(), request.Plan.Deadline.UnixNano(), true,
	)
	identityCurrent := claim.issuer == token.issuer && claim.activeTransaction == transaction &&
		transaction.claim == claim && transaction.resource == resource && transaction.activeLocked() &&
		transaction.executionIssued && transaction.plan == request.Plan
	if !identityCurrent {
		resource.mu.Unlock()
		claim.mu.Unlock()
		token.busy = false
		if stateBefore != ExecutionRolledBack {
			token.state = ExecutionRollbackRequired
		}
		token.mu.Unlock()
		return FinalAcceptanceInvalid, ErrAuthorityStale
	}

	late := false
	switch transaction.state {
	case ResourceTransactionCommitPublished:
		late = !transaction.deadline.After(linearizedAt)
	case ResourceTransactionOutcomeUnknown:
		if transaction.unknownFrom != ResourceTransactionCommitPublished {
			resource.mu.Unlock()
			claim.mu.Unlock()
			token.busy = false
			if stateBefore != ExecutionRolledBack {
				token.state = ExecutionRollbackRequired
			}
			token.mu.Unlock()
			return FinalAcceptanceInvalid, ErrTransactionOutcomeUnknown
		}
		late = true
	default:
		resource.mu.Unlock()
		claim.mu.Unlock()
		token.busy = false
		if stateBefore != ExecutionRolledBack {
			token.state = ExecutionRollbackRequired
		}
		token.mu.Unlock()
		return FinalAcceptanceInvalid, ErrResourceTransactionState
	}
	if err := transaction.consumeGenerationLocked(); err != nil {
		resource.mu.Unlock()
		claim.mu.Unlock()
		token.busy = false
		if stateBefore != ExecutionRolledBack {
			token.state = ExecutionRollbackRequired
		}
		token.mu.Unlock()
		return FinalAcceptanceInvalid, err
	}
	if transaction.expiry != nil {
		transaction.expiry.Stop()
		transaction.expiry = nil
	}
	publishAllowed := allowPublish && !late && factualCurrent && token.forwardDeadline.After(linearizedAt) &&
		claim.currentForPlanLocked(request.Plan)
	if publishAllowed {
		transaction.unknownFrom = ResourceTransactionInvalid
		transaction.state = ResourceTransactionPublishAuthorized
		token.state = ExecutionPublishAuthorized
	} else {
		transaction.unknownFrom = ResourceTransactionPublishAuthorized
		transaction.state = ResourceTransactionOutcomeUnknown
		if stateBefore != ExecutionRolledBack {
			token.state = ExecutionRollbackRequired
		}
	}
	resource.mu.Unlock()
	claim.mu.Unlock()
	token.busy = false
	token.mu.Unlock()
	if publishAllowed {
		return FinalAcceptancePublishAllowed, nil
	}
	return FinalAcceptanceRollbackOnly, nil
}

func (e *Execution) runForwardStep(
	ctx context.Context,
	want, next ExecutionState,
	name string,
	step func(DriverAttempt, context.Context, ExecutionRequest) error,
) error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	token := e.token
	if ctx == nil {
		ctx = context.Background()
	}
	token.mu.Lock()
	if token.busy {
		token.mu.Unlock()
		return ErrExecutionBusy
	}
	if token.state != want || interfaceIsNil(token.attempt) {
		token.mu.Unlock()
		return ErrExecutionState
	}
	token.busy = true
	attempt := token.attempt
	request := token.request
	token.mu.Unlock()
	if want == ExecutionAuthorized {
		if !token.claim.acquireExecutionLease() {
			token.mu.Lock()
			token.busy = false
			token.state = ExecutionRolledBack
			token.mu.Unlock()
			return ErrAuthorityStale
		}
		token.mu.Lock()
		token.leaseHeld = true
		token.mu.Unlock()
	} else {
		token.mu.Lock()
		leaseHeld := token.leaseHeld
		token.mu.Unlock()
		if !leaseHeld {
			token.mu.Lock()
			token.busy = false
			token.state = ExecutionRollbackRequired
			token.mu.Unlock()
			return ErrExecutionState
		}
	}

	if err := e.validateAuthorityCurrent(ResourceTransactionExecutionStaged); err != nil {
		token.mu.Lock()
		token.busy = false
		if want == ExecutionAuthorized {
			token.state = ExecutionRolledBack
		} else {
			token.state = ExecutionRollbackRequired
		}
		token.mu.Unlock()
		if want == ExecutionAuthorized {
			e.releaseLease()
		}
		return err
	}
	if !token.forwardDeadline.After(time.Now()) {
		token.mu.Lock()
		token.busy = false
		if want == ExecutionAuthorized {
			token.state = ExecutionRolledBack
		} else {
			token.state = ExecutionRollbackRequired
		}
		token.mu.Unlock()
		if want == ExecutionAuthorized {
			e.releaseLease()
		}
		return ErrPlanExpired
	}
	stageCtx, cancel := context.WithDeadline(ctx, token.forwardDeadline)
	if err := stageCtx.Err(); err != nil {
		cancel()
		token.mu.Lock()
		token.busy = false
		if want == ExecutionAuthorized {
			token.state = ExecutionRolledBack
		} else {
			token.state = ExecutionRollbackRequired
		}
		token.mu.Unlock()
		if want == ExecutionAuthorized {
			e.releaseLease()
		}
		return err
	}
	token.mu.Lock()
	token.stageCancel = cancel
	token.mu.Unlock()
	expectedContext, _ := request.Plan.ProbeReferences.contextDigest()
	expectedPlatform, _ := request.Plan.ProbeReferences.platformReference()
	err := invokeDriverStep(name, expectedContext, expectedPlatform, true, true, func() error {
		return step(attempt, stageCtx, request)
	})
	stageContextErr := stageCtx.Err()
	token.mu.Lock()
	token.stageCancel = nil
	token.mu.Unlock()
	cancel()
	if err == nil && stageContextErr != nil {
		err = fmt.Errorf("%w: %s deadline: %w", ErrExecutionDriver, name, stageContextErr)
	}
	if err == nil {
		err = e.validateAuthorityCurrent(ResourceTransactionExecutionStaged)
	}
	token.mu.Lock()
	token.busy = false
	if err != nil {
		token.state = ExecutionRollbackRequired
	} else {
		token.state = next
	}
	token.mu.Unlock()
	return err
}

// Publish crosses the only local owner-swap boundary. A driver error with an
// unchanged sealed incarnation is rollback-capable; every changed or
// contradictory outcome requires fail-closed cleanup.
func (e *Execution) Publish(ctx context.Context) error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	token := e.token
	if ctx == nil {
		ctx = context.Background()
	}
	token.mu.Lock()
	if token.busy || token.state != ExecutionPublishAuthorized || interfaceIsNil(token.attempt) || !token.leaseHeld {
		token.mu.Unlock()
		return ErrExecutionState
	}
	token.busy = true
	attempt, request := token.attempt, token.request
	token.mu.Unlock()
	if err := e.validateAuthorityCurrent(ResourceTransactionPublishAuthorized); err != nil {
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionRollbackRequired
		token.mu.Unlock()
		return err
	}
	if !token.forwardDeadline.After(time.Now()) {
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionRollbackRequired
		token.mu.Unlock()
		return ErrPlanExpired
	}
	stageCtx, cancel := context.WithDeadline(ctx, token.forwardDeadline)
	token.mu.Lock()
	token.stageCancel = cancel
	token.mu.Unlock()
	expectedContext, _ := request.Plan.ProbeReferences.contextDigest()
	expectedPlatform, _ := request.Plan.ProbeReferences.platformReference()
	err := invokeDriverStep("publish", expectedContext, expectedPlatform, true, false, func() error {
		return attempt.Publish(stageCtx, request)
	})
	token.mu.Lock()
	token.stageCancel = nil
	token.mu.Unlock()
	cancel()
	after, proven := token.claim.endpointIncarnation()
	unchanged := token.incarnationTracked && proven && after == token.incarnationBefore
	changed := token.incarnationTracked && proven && after != token.incarnationBefore
	if changed {
		token.claim.advanceEndpointGeneration()
	}
	if err != nil {
		token.mu.Lock()
		token.busy = false
		if unchanged {
			token.state = ExecutionRollbackRequired
		} else {
			token.state = ExecutionFailClosedRequired
		}
		token.mu.Unlock()
		return err
	}
	if !changed {
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionFailClosedRequired
		token.mu.Unlock()
		return fmt.Errorf("%w: publish: %w", ErrExecutionDriver, ErrIncarnationUnproven)
	}
	if err := token.transaction.markPublished(); err != nil {
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionFailClosedRequired
		token.mu.Unlock()
		return fmt.Errorf("%w: publish transaction: %w", ErrExecutionDriver, err)
	}
	token.mu.Lock()
	token.busy = false
	token.state = ExecutionPublished
	token.mu.Unlock()
	return nil
}

// Activate retries post-publication work without reopening rollback. It may
// resume the endpoint, release quarantine, and close namespace executors.
func (e *Execution) Activate(ctx context.Context) error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	token := e.token
	if ctx == nil {
		ctx = context.Background()
	}
	token.mu.Lock()
	if token.busy || (token.state != ExecutionPublished && token.state != ExecutionActivationRequired) ||
		interfaceIsNil(token.attempt) || !token.leaseHeld {
		token.mu.Unlock()
		return ErrExecutionState
	}
	token.busy = true
	attempt, request := token.attempt, token.request
	token.mu.Unlock()
	if err := e.validatePublishedCurrent(); err != nil {
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionFailClosedRequired
		token.mu.Unlock()
		return err
	}
	stageCtx, cancel := context.WithDeadline(ctx, token.deadline)
	expectedContext, _ := request.Plan.ProbeReferences.contextDigest()
	expectedPlatform, _ := request.Plan.ProbeReferences.platformReference()
	err := invokeDriverStep("activate", expectedContext, expectedPlatform, true, true, func() error {
		return attempt.Activate(stageCtx, request)
	})
	cancel()
	token.mu.Lock()
	token.busy = false
	if err == nil {
		token.state = ExecutionActivated
	} else {
		token.state = ExecutionActivationRequired
	}
	token.mu.Unlock()
	return err
}

// FinalizePublished releases carrier ownership only after activation and peer
// terminal resolution have both completed.
func (e *Execution) FinalizePublished() error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	e.token.mu.Lock()
	if e.token.state != ExecutionActivated || e.token.busy {
		e.token.mu.Unlock()
		return ErrExecutionState
	}
	e.token.mu.Unlock()
	e.releaseLease()
	return nil
}

// CancelForward asks the currently running driver stage to stop. Driver
// implementations must honor the supplied context before its deadline.
func (e *Execution) CancelForward() {
	if e == nil || e.token == nil {
		return
	}
	e.token.mu.Lock()
	cancel := e.token.stageCancel
	e.token.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *Execution) releaseLease() {
	if e == nil || e.token == nil {
		return
	}
	token := e.token
	token.mu.Lock()
	if !token.leaseHeld {
		token.mu.Unlock()
		return
	}
	token.leaseHeld = false
	claim := token.claim
	token.mu.Unlock()
	claim.releaseExecutionLease()
}

func (e *Execution) validateAuthorityCurrent(want ResourceTransactionState) error {
	if e == nil || e.token == nil {
		return ErrAuthorityStale
	}
	execution := e.token
	if execution.claim == nil || execution.issuer == nil || execution.transaction == nil {
		return ErrAuthorityStale
	}
	if execution.request.Plan.attempt == nil || !execution.request.Plan.attempt.evidenceCurrent() {
		return ErrAuthorityStale
	}
	nowNano := time.Now().UnixNano()
	if !execution.request.Plan.ProbeReferences.validFor(
		execution.request.Plan.Operation, execution.request.Plan.EndpointGeneration,
		nowNano, execution.request.Plan.Deadline.UnixNano(), true,
	) || !execution.request.Plan.ProbeReferences.matchesCurrentExecutionContext() {
		return ErrAuthorityStale
	}
	if !execution.request.Plan.ProbeReferences.matchesCurrentPlatform(context.Background()) {
		return ErrAuthorityStale
	}
	claim := execution.claim
	claim.mu.Lock()
	resource := claim.resource
	if resource == nil {
		claim.mu.Unlock()
		return ErrAuthorityStale
	}
	resource.mu.Lock()
	transaction := execution.transaction
	current := claim.issuer == execution.issuer && claim.activeTransaction == transaction &&
		transaction.claim == claim && transaction.resource == resource && transaction.activeLocked() &&
		transaction.state == want && transaction.executionIssued &&
		transaction.plan == execution.request.Plan && transaction.deadline.After(time.Now()) &&
		claim.currentForPlanLocked(execution.request.Plan)
	resource.mu.Unlock()
	claim.mu.Unlock()
	if !current {
		return ErrAuthorityStale
	}
	return nil
}

func (e *Execution) validatePublishedCurrent() error {
	if e == nil || e.token == nil || e.token.claim == nil || e.token.transaction == nil {
		return ErrAuthorityStale
	}
	token := e.token
	claim := token.claim
	claim.mu.Lock()
	resource := claim.resource
	if resource == nil {
		claim.mu.Unlock()
		return ErrAuthorityStale
	}
	resource.mu.Lock()
	current := token.transaction.claim == claim && token.transaction.resource == resource &&
		token.transaction.activeLocked() && token.transaction.state == ResourceTransactionPublished &&
		token.transaction.executionIssued
	resource.mu.Unlock()
	claim.mu.Unlock()
	if !current {
		return ErrAuthorityStale
	}
	return nil
}

// Rollback restores driver-local endpoint ownership before peer ROLLED_BACK
// may be published. Failed rollback remains retryable and fail-closed.
func (e *Execution) Rollback(ctx context.Context) error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	token := e.token
	token.mu.Lock()
	if token.busy {
		token.mu.Unlock()
		return ErrExecutionBusy
	}
	switch token.state {
	case ExecutionAuthorized:
		// No driver method has run, so abandoning the exact attempt is a
		// proven local no-op.
		token.state = ExecutionRolledBack
		token.mu.Unlock()
		return nil
	case ExecutionRolledBack:
		token.mu.Unlock()
		return nil
	case ExecutionPrepared, ExecutionStaged, ExecutionPublishAuthorized, ExecutionRollbackRequired:
		if interfaceIsNil(token.attempt) {
			token.mu.Unlock()
			return ErrExecutionState
		}
	case ExecutionPublished, ExecutionActivationRequired, ExecutionActivated,
		ExecutionFailClosedRequired, ExecutionFailedClosed, ExecutionInvalid:
		token.mu.Unlock()
		return ErrExecutionState
	default:
		token.mu.Unlock()
		return ErrExecutionState
	}
	if !token.deadline.After(time.Now()) {
		token.state = ExecutionRollbackRequired
		token.mu.Unlock()
		return ErrPlanExpired
	}
	token.busy = true
	attempt := token.attempt
	request := token.request
	token.mu.Unlock()

	rollbackParent := context.Background()
	if ctx != nil {
		rollbackParent = context.WithoutCancel(ctx)
	}
	rollbackCtx, cancel := context.WithDeadline(rollbackParent, token.deadline)
	generationChanged := false
	err := invokeDriverStep("rollback", ContextDigest{}, ProbeReference{}, false, false, func() error {
		if err := attempt.Rollback(rollbackCtx, request); err != nil {
			return err
		}
		if token.incarnationTracked {
			after, ok := token.claim.endpointIncarnation()
			if !ok {
				return ErrIncarnationUnproven
			}
			generationChanged = after != token.incarnationBefore
		} else {
			generationChanged = attempt.EndpointGenerationChanged()
		}
		return nil
	})
	cancel()
	if err == nil && generationChanged {
		token.claim.advanceEndpointGeneration()
	}
	token.mu.Lock()
	token.busy = false
	if err == nil {
		token.state = ExecutionRolledBack
	} else {
		token.state = ExecutionRollbackRequired
	}
	token.mu.Unlock()
	if err == nil {
		return nil
	}
	return err
}

// FinalizeRolledBack releases carrier ownership only after the engine has
// published, or definitively abandoned, the peer rollback outcome.
func (e *Execution) FinalizeRolledBack() error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	e.token.mu.Lock()
	if e.token.state != ExecutionRolledBack || e.token.busy {
		e.token.mu.Unlock()
		return ErrExecutionState
	}
	e.token.mu.Unlock()
	e.releaseLease()
	return nil
}

// FailClosed asks the driver to terminate all endpoint and quarantine state
// after rollback can no longer be claimed. Cleanup remains retryable and the
// Claim lease remains held until the driver proves completion.
func (e *Execution) FailClosed(ctx context.Context) error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	if ctx == nil {
		ctx = context.Background()
	}
	token := e.token
	token.mu.Lock()
	if token.busy {
		token.mu.Unlock()
		return ErrExecutionBusy
	}
	stateBefore := token.state
	switch stateBefore {
	case ExecutionAuthorized:
		token.state = ExecutionFailedClosed
		token.mu.Unlock()
		e.releaseLease()
		return nil
	case ExecutionPrepared, ExecutionStaged, ExecutionPublishAuthorized,
		ExecutionPublished, ExecutionActivationRequired, ExecutionRollbackRequired,
		ExecutionFailClosedRequired:
		if interfaceIsNil(token.attempt) {
			token.mu.Unlock()
			return ErrExecutionState
		}
	case ExecutionFailedClosed:
		token.mu.Unlock()
		return nil
	default:
		token.mu.Unlock()
		return ErrExecutionState
	}
	token.busy = true
	attempt := token.attempt
	request := token.request
	token.mu.Unlock()

	err := invokeDriverStep("fail-closed", ContextDigest{}, ProbeReference{}, false, false, func() error {
		return attempt.FailClosed(ctx, request)
	})
	token.mu.Lock()
	token.busy = false
	if err == nil {
		token.state = ExecutionFailedClosed
	} else {
		// Once the driver has entered FailClosed, cleanup may already have
		// terminated the physical endpoint. Failure can only be retried through
		// FailClosed; Rollback must never be reopened.
		token.state = ExecutionFailClosedRequired
	}
	token.mu.Unlock()
	if err != nil {
		return err
	}
	e.releaseLease()
	return nil
}

func invokeDriverStep(
	name string,
	expectedContext ContextDigest,
	expectedPlatform ProbeReference,
	verifyBefore bool,
	verifyAfter bool,
	step func() error,
) (err error) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: %s: %v", ErrExecutionDriverPanic, name, recovered)
		}
	}()
	if verifyBefore {
		current, contextErr := currentExecutionContextDigest()
		if contextErr != nil || current != expectedContext {
			return fmt.Errorf("%w: %s execution context changed", ErrExecutionDriver, name)
		}
		if expectedPlatform != (ProbeReference{}) {
			if !platformReferenceMatchesCurrent(context.Background(), expectedPlatform) {
				return fmt.Errorf("%w: %s platform evidence changed", ErrExecutionDriver, name)
			}
		}
	}
	if err := step(); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrExecutionDriver, name, err)
	}
	if verifyAfter {
		current, contextErr := currentExecutionContextDigest()
		if contextErr != nil || current != expectedContext {
			return fmt.Errorf("%w: %s execution context changed", ErrExecutionDriver, name)
		}
		if expectedPlatform != (ProbeReference{}) {
			if !platformReferenceMatchesCurrent(context.Background(), expectedPlatform) {
				return fmt.Errorf("%w: %s platform evidence changed", ErrExecutionDriver, name)
			}
		}
	}
	return nil
}
