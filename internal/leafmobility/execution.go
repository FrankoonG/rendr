package leafmobility

import (
	"context"
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
	ExecutionCutover
	ExecutionCommitted
	ExecutionRollbackRequired
	// ExecutionFailClosedRequired means Commit returned nil, but the Claim's
	// physical endpoint reporter did not prove a new incarnation. Commit may
	// already be irreversible, so rollback is forbidden and only destructive
	// fail-closed cleanup can release the execution lease.
	ExecutionFailClosedRequired
	ExecutionRolledBack
	ExecutionFailedClosed
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

// DriverAttempt is created by one non-destructive Preflight call. It is kept
// private inside Plan and invoked only by an engine-bound Execution. Every
// failing forward stage must preserve enough state for Rollback.
type DriverAttempt interface {
	Evidence() AttemptEvidence
	Prepare(context.Context, ExecutionRequest) error
	Cutover(context.Context, ExecutionRequest) error
	Commit(context.Context, ExecutionRequest) error
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

func (e *Execution) Cutover(ctx context.Context) error {
	return e.runForwardStep(ctx, ExecutionPrepared, ExecutionCutover, "cutover", func(attempt DriverAttempt, ctx context.Context, request ExecutionRequest) error {
		return attempt.Cutover(ctx, request)
	})
}

func (e *Execution) Commit(ctx context.Context) error {
	return e.runForwardStep(ctx, ExecutionCutover, ExecutionCommitted, "commit", func(attempt DriverAttempt, ctx context.Context, request ExecutionRequest) error {
		return attempt.Commit(ctx, request)
	})
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

	if err := e.validateAuthorityCurrent(); err != nil {
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
	err := invokeDriverStep(name, expectedContext, expectedPlatform, true, next != ExecutionCommitted, func() error {
		return step(attempt, stageCtx, request)
	})
	stageContextErr := stageCtx.Err()
	token.mu.Lock()
	token.stageCancel = nil
	token.mu.Unlock()
	cancel()
	// A nil Commit return is the irreversible local linearization point.
	// Cancellation or topology changes observed afterward cannot make a
	// committed endpoint rollback-capable again.
	if err == nil && next == ExecutionCommitted {
		after, proven := token.claim.endpointIncarnation()
		if !token.incarnationTracked || !proven || after == token.incarnationBefore {
			token.mu.Lock()
			token.busy = false
			token.state = ExecutionFailClosedRequired
			token.mu.Unlock()
			return fmt.Errorf("%w: commit: %w", ErrExecutionDriver, ErrIncarnationUnproven)
		}
		token.claim.advanceEndpointGeneration()
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionCommitted
		token.mu.Unlock()
		return nil
	}
	if err == nil && stageContextErr != nil {
		err = fmt.Errorf("%w: %s deadline: %w", ErrExecutionDriver, name, stageContextErr)
	}
	if err == nil {
		err = e.validateAuthorityCurrent()
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

// FinalizeCommitted releases carrier ownership only after the engine has
// resolved, or definitively failed to resolve, the peer terminal outcome.
func (e *Execution) FinalizeCommitted() error {
	if e == nil || e.token == nil {
		return ErrExecutionState
	}
	e.token.mu.Lock()
	if e.token.state != ExecutionCommitted || e.token.busy {
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

func (e *Execution) validateAuthorityCurrent() error {
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
		transaction.state == ResourceTransactionConsumed && transaction.executionIssued &&
		transaction.plan == execution.request.Plan && transaction.deadline.After(time.Now()) &&
		claim.currentForPlanLocked(execution.request.Plan)
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
	case ExecutionPrepared, ExecutionCutover, ExecutionRollbackRequired:
		if interfaceIsNil(token.attempt) {
			token.mu.Unlock()
			return ErrExecutionState
		}
	case ExecutionCommitted, ExecutionFailClosedRequired, ExecutionFailedClosed, ExecutionInvalid:
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
	switch token.state {
	case ExecutionAuthorized:
		token.state = ExecutionFailedClosed
		token.mu.Unlock()
		e.releaseLease()
		return nil
	case ExecutionPrepared, ExecutionCutover, ExecutionRollbackRequired, ExecutionFailClosedRequired:
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
	} else if token.state == ExecutionFailClosedRequired {
		// An unproven nil Commit remains beyond the rollback boundary even when
		// cleanup needs another attempt.
		token.state = ExecutionFailClosedRequired
	} else {
		token.state = ExecutionRollbackRequired
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
