package leafmobility

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	goruntime "runtime"
	"sync"
	"sync/atomic"
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
	ErrExecutionState        = errors.New("leafmobility: invalid driver execution state")
	ErrExecutionBusy         = errors.New("leafmobility: driver execution is busy")
	ErrExecutionDriver       = errors.New("leafmobility: driver execution failed")
	ErrExecutionDriverPanic  = errors.New("leafmobility: driver execution panicked")
	ErrExecutionDriverGoexit = errors.New("leafmobility: driver execution called runtime.Goexit")
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

type driverEvidenceOutcome struct {
	evidence AttemptEvidence
	err      error
}

type driverEvidenceCall struct {
	done    chan struct{}
	outcome driverEvidenceOutcome
}

var driverEvidenceRegistry = struct {
	sync.Mutex
	active map[driverAttemptKey]*driverEvidenceCall
}{active: make(map[driverAttemptKey]*driverEvidenceCall)}

func readAttemptEvidence(attempt DriverAttempt) (AttemptEvidence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), driverEvidenceCallbackTimeout)
	defer cancel()
	return invokeDriverEvidence(ctx, attempt)
}

func invokeDriverEvidence(ctx context.Context, attempt DriverAttempt) (AttemptEvidence, error) {
	if interfaceIsNil(attempt) {
		return AttemptEvidence{}, ErrInvalidDriver
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AttemptEvidence{}, errors.Join(ErrInvalidDriver, err)
	}
	ptr, ok := interfaceIdentity(attempt)
	if !ok {
		return AttemptEvidence{}, ErrInvalidDriver
	}
	key := driverAttemptKey{typeOf: reflect.TypeOf(attempt), ptr: ptr}
	call := &driverEvidenceCall{done: make(chan struct{})}
	driverEvidenceRegistry.Lock()
	if active := driverEvidenceRegistry.active[key]; active != nil {
		driverEvidenceRegistry.Unlock()
		return AttemptEvidence{}, errors.Join(ErrInvalidDriver, ErrDriverEvidenceBusy)
	}
	if !acquireDriverCallbackPermit() {
		driverEvidenceRegistry.Unlock()
		return AttemptEvidence{}, errors.Join(ErrInvalidDriver, ErrDriverCallbackCapacity)
	}
	driverEvidenceRegistry.active[key] = call
	driverEvidenceRegistry.Unlock()

	go func() {
		returned := false
		defer func() {
			if recovered := recover(); recovered != nil {
				call.outcome = driverEvidenceOutcome{err: errors.Join(ErrInvalidDriver, ErrDriverEvidencePanic)}
			} else if !returned {
				call.outcome = driverEvidenceOutcome{err: errors.Join(ErrInvalidDriver, ErrDriverEvidenceGoexit)}
			}
			releaseDriverCallbackPermit()
			driverEvidenceRegistry.Lock()
			if driverEvidenceRegistry.active[key] == call {
				delete(driverEvidenceRegistry.active, key)
			}
			driverEvidenceRegistry.Unlock()
			close(call.done)
		}()
		call.outcome.evidence = attempt.Evidence()
		returned = true
	}()

	select {
	case <-call.done:
		return call.outcome.evidence, call.outcome.err
	case <-ctx.Done():
		select {
		case <-call.done:
			return call.outcome.evidence, call.outcome.err
		default:
			return AttemptEvidence{}, errors.Join(ErrInvalidDriver, ctx.Err())
		}
	}
}

type driverCallbackError struct {
	kind   error
	cause  error
	step   string
	detail string
}

func (e *driverCallbackError) Error() string {
	if e == nil {
		return "leafmobility: driver callback failed"
	}
	message := "leafmobility: driver callback failed"
	if e.kind != nil {
		message = e.kind.Error()
	}
	if e.step != "" {
		message += ": " + e.step
	}
	if e.detail != "" {
		message += ": " + e.detail
	}
	return message
}

func (e *driverCallbackError) Unwrap() []error {
	if e == nil {
		return nil
	}
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}

func newDriverCallbackError(kind error, step string, cause error) error {
	return &driverCallbackError{
		kind: kind, cause: cause, step: step,
		detail: trustedDriverCallbackCause(cause),
	}
}

// trustedDriverCallbackCause preserves factual infrastructure diagnostics
// without invoking Error or Is on an arbitrary driver-owned value. Driver
// causes remain available through errors.Is/errors.As via Unwrap.
func trustedDriverCallbackCause(cause error) string {
	return trustedDriverCallbackCauseAtDepth(cause, 0)
}

func trustedDriverCallbackCauseAtDepth(cause error, depth int) string {
	const maxTrustedDriverCallbackCauseDepth = 16
	if cause == nil {
		return ""
	}
	if depth >= maxTrustedDriverCallbackCauseDepth {
		return ""
	}
	typeOf := reflect.TypeOf(cause)
	if typeOf == nil {
		return ""
	}
	if typeOf.Comparable() {
		switch cause {
		case context.Canceled:
			return context.Canceled.Error()
		case context.DeadlineExceeded:
			return context.DeadlineExceeded.Error()
		case os.ErrDeadlineExceeded:
			return os.ErrDeadlineExceeded.Error()
		case ErrDriverCallbackCapacity:
			return ErrDriverCallbackCapacity.Error()
		case ErrIncarnationUnproven:
			return ErrIncarnationUnproven.Error()
		case ErrPlanExpired:
			return ErrPlanExpired.Error()
		}
	}
	switch typed := cause.(type) {
	case *net.OpError:
		return trustedDriverCallbackCauseAtDepth(typed.Err, depth+1)
	case *os.PathError:
		return trustedDriverCallbackCauseAtDepth(typed.Err, depth+1)
	case *os.SyscallError:
		return trustedDriverCallbackCauseAtDepth(typed.Err, depth+1)
	}
	base := typeOf
	if base.Kind() == reflect.Pointer {
		base = base.Elem()
	}
	if base.PkgPath() == "fmt" && base.Name() == "wrapError" {
		if wrapped, ok := cause.(interface{ Unwrap() error }); ok {
			return trustedDriverCallbackCauseAtDepth(wrapped.Unwrap(), depth+1)
		}
	}
	if (base.PkgPath() == "fmt" && base.Name() == "wrapErrors") ||
		(base.PkgPath() == "errors" && base.Name() == "joinError") {
		if wrapped, ok := cause.(interface{ Unwrap() []error }); ok {
			for _, child := range wrapped.Unwrap() {
				if detail := trustedDriverCallbackCauseAtDepth(child, depth+1); detail != "" {
					return detail
				}
			}
		}
	}
	return ""
}

type driverStepResult struct {
	publication PublicationEvidence
	err         error
}

type driverStepCall struct {
	done chan struct{}

	mu             sync.Mutex
	completed      bool
	result         driverStepResult
	reconciliation driverCallReconciliation
	generation     *atomic.Bool
	onDone         func()
}

type driverCallReconciliation uint8

const (
	driverCallReconcileNone driverCallReconciliation = iota
	driverCallReconcileRollback
	driverCallReconcileFailClosed
)

func (call *driverStepCall) complete(result driverStepResult) {
	call.mu.Lock()
	call.result = result
	call.completed = true
	onDone := call.onDone
	call.mu.Unlock()
	if onDone != nil {
		onDone()
	}
	close(call.done)
}

func (call *driverStepCall) installReconciliation(
	reconciliation driverCallReconciliation,
	generation *atomic.Bool,
	onDone func(),
) bool {
	call.mu.Lock()
	defer call.mu.Unlock()
	call.reconciliation = reconciliation
	call.generation = generation
	if call.completed {
		return true
	}
	call.onDone = onDone
	return false
}

func (call *driverStepCall) reconciliationResult() (driverCallReconciliation, *atomic.Bool, error) {
	call.mu.Lock()
	defer call.mu.Unlock()
	return call.reconciliation, call.generation, call.result.err
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
	driverCall         *driverStepCall
	cleanupPermitHeld  bool
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
	minRollbackReserve            = 100 * time.Millisecond
	maxRollbackReserve            = 5 * time.Second
	driverCallbackLimit           = 64
	driverCleanupCallbackLimit    = 64
	driverEvidenceCallbackTimeout = 100 * time.Millisecond
	driverCanceledCallbackGrace   = 100 * time.Millisecond
)

var driverCallbackPermits = make(chan struct{}, driverCallbackLimit)
var driverCleanupCallbackPermits = make(chan struct{}, driverCleanupCallbackLimit)

func acquireDriverCallbackPermit() bool {
	select {
	case driverCallbackPermits <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseDriverCallbackPermit() {
	select {
	case <-driverCallbackPermits:
	default:
		panic("leafmobility: driver callback permit released without ownership")
	}
}

func acquireDriverCleanupCallbackPermit() bool {
	select {
	case driverCleanupCallbackPermits <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseDriverCleanupCallbackPermit() {
	select {
	case <-driverCleanupCallbackPermits:
	default:
		panic("leafmobility: driver cleanup callback permit released without ownership")
	}
}

type driverCallbackClass uint8

const (
	driverCallbackNormal driverCallbackClass = iota
	driverCallbackCleanup
)

func driverStepCallbackPermits(class driverCallbackClass) (acquire func() bool, release func()) {
	if class == driverCallbackCleanup {
		// Every issued Execution reserves this capacity before destructive work.
		// Cleanup keeps that reservation until terminal ownership is released.
		return func() bool { return true }, func() {}
	}
	return acquireDriverCallbackPermit, releaseDriverCallbackPermit
}

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
	e.token.reapDriverCallLocked()
	state := e.token.state
	e.token.mu.Unlock()
	return state
}

func (token *executionToken) reapDriverCallLocked() {
	if token == nil || token.driverCall == nil {
		return
	}
	select {
	case <-token.driverCall.done:
		token.driverCall = nil
		token.busy = false
	default:
	}
}

func (token *executionToken) retainDriverCallLocked(
	call *driverStepCall,
	reconciliation driverCallReconciliation,
	generation *atomic.Bool,
) bool {
	if token == nil {
		return false
	}
	if call == nil {
		token.driverCall = nil
		token.busy = false
		return false
	}
	token.driverCall = call
	token.busy = true
	completed := call.installReconciliation(reconciliation, generation, func() {
		token.reconcileDriverCall(call)
	})
	if completed {
		return token.reconcileDriverCallLocked(call)
	}
	return false
}

func (token *executionToken) reconcileDriverCall(call *driverStepCall) {
	if token == nil || call == nil {
		return
	}
	token.mu.Lock()
	releaseLease := token.reconcileDriverCallLocked(call)
	token.mu.Unlock()
	if releaseLease {
		releaseExecutionTokenLease(token)
	}
}

func (token *executionToken) reconcileDriverCallLocked(call *driverStepCall) bool {
	if token == nil || call == nil || token.driverCall != call {
		return false
	}
	reconciliation, generation, err := call.reconciliationResult()
	token.driverCall = nil
	token.busy = false
	switch reconciliation {
	case driverCallReconcileRollback:
		if err == nil {
			if generation != nil && generation.Load() {
				token.claim.advanceEndpointGeneration()
			}
			token.state = ExecutionRolledBack
		} else {
			token.state = ExecutionRollbackRequired
		}
	case driverCallReconcileFailClosed:
		if err == nil {
			token.state = ExecutionFailedClosed
			return true
		}
		token.state = ExecutionFailClosedRequired
	}
	return false
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
	_, err := e.runForwardStep(
		ctx, ExecutionAuthorized, ExecutionPrepared, "prepare",
		func(attempt DriverAttempt, ctx context.Context, request ExecutionRequest) (PublicationEvidence, error) {
			return PublicationEvidence{}, attempt.Prepare(ctx, request)
		}, nil,
	)
	return err
}

func (e *Execution) Stage(ctx context.Context) error {
	_, err := e.runForwardStep(
		ctx, ExecutionPrepared, ExecutionStaged, "stage",
		func(attempt DriverAttempt, ctx context.Context, request ExecutionRequest) (PublicationEvidence, error) {
			publication, stageErr := attempt.Stage(ctx, request)
			if stageErr == nil && publication.Digest == (EvidenceDigest{}) {
				return PublicationEvidence{}, fmt.Errorf("%w: stage returned zero publication evidence", ErrExecutionDriver)
			}
			return publication, stageErr
		}, func(token *executionToken, publication PublicationEvidence) {
			token.publication = publication
		},
	)
	return err
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
	token.reapDriverCallLocked()
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
	step func(DriverAttempt, context.Context, ExecutionRequest) (PublicationEvidence, error),
	commit func(*executionToken, PublicationEvidence),
) (PublicationEvidence, error) {
	if e == nil || e.token == nil {
		return PublicationEvidence{}, ErrExecutionState
	}
	token := e.token
	if ctx == nil {
		ctx = context.Background()
	}
	token.mu.Lock()
	token.reapDriverCallLocked()
	if token.busy {
		token.mu.Unlock()
		return PublicationEvidence{}, ErrExecutionBusy
	}
	if token.state != want || interfaceIsNil(token.attempt) {
		token.mu.Unlock()
		return PublicationEvidence{}, ErrExecutionState
	}
	token.busy = true
	attempt := token.attempt
	request := token.request
	token.mu.Unlock()
	if want == ExecutionAuthorized {
		if !acquireDriverCleanupCallbackPermit() {
			token.mu.Lock()
			token.busy = false
			token.mu.Unlock()
			return PublicationEvidence{}, newDriverCallbackError(
				ErrExecutionDriver, name, ErrDriverCallbackCapacity,
			)
		}
		token.mu.Lock()
		token.cleanupPermitHeld = true
		token.mu.Unlock()
		if !token.claim.acquireExecutionLease() {
			token.mu.Lock()
			token.busy = false
			token.state = ExecutionRolledBack
			token.mu.Unlock()
			e.releaseLease()
			return PublicationEvidence{}, ErrAuthorityStale
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
			return PublicationEvidence{}, ErrExecutionState
		}
	}

	authorityErr := e.validateAuthorityCurrent(ResourceTransactionExecutionStaged)
	if authorityErr != nil {
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
		return PublicationEvidence{}, authorityErr
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
		return PublicationEvidence{}, ErrPlanExpired
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
		return PublicationEvidence{}, err
	}
	token.mu.Lock()
	token.stageCancel = cancel
	token.mu.Unlock()
	expectedContext, _ := request.Plan.ProbeReferences.contextDigest()
	expectedPlatform, _ := request.Plan.ProbeReferences.platformReference()
	publication, call, err := invokeDriverStep(stageCtx, name, expectedContext, expectedPlatform, true, true, driverCallbackNormal, false, func() (PublicationEvidence, error) {
		return step(attempt, stageCtx, request)
	})
	token.mu.Lock()
	token.stageCancel = nil
	token.mu.Unlock()
	stageContextErr := stageCtx.Err()
	if err == nil && stageContextErr != nil {
		err = newDriverCallbackError(ErrExecutionDriver, name, stageContextErr)
	}
	if err == nil {
		err = e.validateAuthorityCurrent(ResourceTransactionExecutionStaged)
	}
	cancel()
	if err == nil && !token.forwardDeadline.After(time.Now()) {
		err = ErrPlanExpired
	}
	token.mu.Lock()
	if err != nil {
		token.state = ExecutionRollbackRequired
		token.retainDriverCallLocked(call, driverCallReconcileNone, nil)
	} else {
		token.busy = false
		token.driverCall = nil
		if commit != nil {
			commit(token, publication)
		}
		token.state = next
	}
	token.mu.Unlock()
	if err != nil {
		return PublicationEvidence{}, err
	}
	return publication, nil
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
	token.reapDriverCallLocked()
	if token.busy || token.state != ExecutionPublishAuthorized || interfaceIsNil(token.attempt) || !token.leaseHeld {
		token.mu.Unlock()
		return ErrExecutionState
	}
	token.busy = true
	attempt, request := token.attempt, token.request
	token.mu.Unlock()
	authorityErr := e.validateAuthorityCurrent(ResourceTransactionPublishAuthorized)
	if authorityErr != nil {
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionRollbackRequired
		token.mu.Unlock()
		return authorityErr
	}
	if !token.forwardDeadline.After(time.Now()) {
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionRollbackRequired
		token.mu.Unlock()
		return ErrPlanExpired
	}
	stageCtx, cancel := context.WithDeadline(ctx, token.forwardDeadline)
	if err := stageCtx.Err(); err != nil {
		cancel()
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionRollbackRequired
		token.mu.Unlock()
		return err
	}
	token.mu.Lock()
	token.stageCancel = cancel
	token.mu.Unlock()
	expectedContext, _ := request.Plan.ProbeReferences.contextDigest()
	expectedPlatform, _ := request.Plan.ProbeReferences.platformReference()
	_, call, err := invokeDriverStep(stageCtx, "publish", expectedContext, expectedPlatform, true, false, driverCallbackNormal, false, func() (PublicationEvidence, error) {
		return PublicationEvidence{}, attempt.Publish(stageCtx, request)
	})
	token.mu.Lock()
	token.stageCancel = nil
	token.mu.Unlock()
	stageContextErr := stageCtx.Err()
	cancel()
	if err == nil && stageContextErr != nil {
		err = newDriverCallbackError(ErrExecutionDriver, "publish", stageContextErr)
	}
	uncertain := call != nil
	after, proven := token.claim.endpointIncarnation()
	unchanged := token.incarnationTracked && proven && after == token.incarnationBefore
	changed := token.incarnationTracked && proven && after != token.incarnationBefore
	if changed || uncertain {
		token.claim.advanceEndpointGeneration()
	}
	if err != nil {
		token.mu.Lock()
		if unchanged && !uncertain {
			token.state = ExecutionRollbackRequired
		} else {
			token.state = ExecutionFailClosedRequired
		}
		token.retainDriverCallLocked(call, driverCallReconcileNone, nil)
		token.mu.Unlock()
		return err
	}
	if !changed {
		token.mu.Lock()
		token.busy = false
		token.driverCall = nil
		token.state = ExecutionFailClosedRequired
		token.mu.Unlock()
		return fmt.Errorf("%w: publish: %w", ErrExecutionDriver, ErrIncarnationUnproven)
	}
	if err := token.transaction.markPublished(); err != nil {
		token.mu.Lock()
		token.busy = false
		token.driverCall = nil
		token.state = ExecutionFailClosedRequired
		token.mu.Unlock()
		return fmt.Errorf("%w: publish transaction: %w", ErrExecutionDriver, err)
	}
	token.mu.Lock()
	token.busy = false
	token.driverCall = nil
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
	token.reapDriverCallLocked()
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
	if err := stageCtx.Err(); err != nil {
		cancel()
		token.mu.Lock()
		token.busy = false
		token.state = ExecutionActivationRequired
		token.mu.Unlock()
		return err
	}
	token.mu.Lock()
	token.stageCancel = cancel
	token.mu.Unlock()
	expectedContext, _ := request.Plan.ProbeReferences.contextDigest()
	expectedPlatform, _ := request.Plan.ProbeReferences.platformReference()
	_, call, err := invokeDriverStep(stageCtx, "activate", expectedContext, expectedPlatform, true, true, driverCallbackNormal, false, func() (PublicationEvidence, error) {
		return PublicationEvidence{}, attempt.Activate(stageCtx, request)
	})
	token.mu.Lock()
	token.stageCancel = nil
	token.mu.Unlock()
	stageContextErr := stageCtx.Err()
	cancel()
	if err == nil && stageContextErr != nil {
		err = newDriverCallbackError(ErrExecutionDriver, "activate", stageContextErr)
	}
	token.mu.Lock()
	if err == nil {
		token.busy = false
		token.driverCall = nil
		token.state = ExecutionActivated
	} else {
		token.state = ExecutionActivationRequired
		token.retainDriverCallLocked(call, driverCallReconcileNone, nil)
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
	e.token.reapDriverCallLocked()
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
	e.token.reapDriverCallLocked()
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
	releaseExecutionTokenLease(e.token)
}

func releaseExecutionTokenLease(token *executionToken) {
	if token == nil {
		return
	}
	token.mu.Lock()
	leaseHeld := token.leaseHeld
	cleanupPermitHeld := token.cleanupPermitHeld
	token.leaseHeld = false
	token.cleanupPermitHeld = false
	claim := token.claim
	token.mu.Unlock()
	if leaseHeld {
		claim.releaseExecutionLease()
	}
	if cleanupPermitHeld {
		releaseDriverCleanupCallbackPermit()
	}
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
	token.reapDriverCallLocked()
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

	rollbackDeadline := token.deadline
	if ctx != nil {
		if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(rollbackDeadline) {
			rollbackDeadline = callerDeadline
		}
	}
	// Local ownership cleanup ignores a caller's explicit cancellation but
	// preserves its earlier deadline. Claim retirement remains an independent
	// authoritative cancellation boundary below.
	rollbackCtx, cancel := context.WithDeadline(context.Background(), rollbackDeadline)
	retirementCtx := token.claim.executionRetirementContext()
	stopRetirementCancel := context.AfterFunc(retirementCtx, cancel)
	if retirementCtx.Err() != nil {
		cancel()
	}
	var generationChanged atomic.Bool
	_, call, err := invokeDriverStep(rollbackCtx, "rollback", ContextDigest{}, ProbeReference{}, false, false, driverCallbackCleanup, true, func() (PublicationEvidence, error) {
		if err := attempt.Rollback(rollbackCtx, request); err != nil {
			return PublicationEvidence{}, err
		}
		if token.incarnationTracked {
			after, ok := token.claim.endpointIncarnation()
			if !ok {
				return PublicationEvidence{}, ErrIncarnationUnproven
			}
			generationChanged.Store(after != token.incarnationBefore)
		} else {
			generationChanged.Store(attempt.EndpointGenerationChanged())
		}
		return PublicationEvidence{}, nil
	})
	stopRetirementCancel()
	cancel()
	token.mu.Lock()
	releaseLease := false
	if err == nil {
		if generationChanged.Load() {
			token.claim.advanceEndpointGeneration()
		}
		token.busy = false
		token.driverCall = nil
		token.state = ExecutionRolledBack
	} else {
		token.state = ExecutionRollbackRequired
		releaseLease = token.retainDriverCallLocked(
			call, driverCallReconcileRollback, &generationChanged,
		)
	}
	token.mu.Unlock()
	if releaseLease {
		releaseExecutionTokenLease(token)
	}
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
	e.token.reapDriverCallLocked()
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
	token.reapDriverCallLocked()
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

	cleanupCtx := ctx
	cancel := func() {}
	if deadline, ok := cleanupCtx.Deadline(); !ok || time.Until(deadline) > maxRollbackReserve {
		cleanupCtx, cancel = context.WithTimeout(cleanupCtx, maxRollbackReserve)
	}
	_, call, err := invokeDriverStep(cleanupCtx, "fail-closed", ContextDigest{}, ProbeReference{}, false, false, driverCallbackCleanup, true, func() (PublicationEvidence, error) {
		return PublicationEvidence{}, attempt.FailClosed(cleanupCtx, request)
	})
	cancel()
	token.mu.Lock()
	releaseLease := false
	if err == nil {
		token.busy = false
		token.driverCall = nil
		token.state = ExecutionFailedClosed
	} else {
		// Once the driver has entered FailClosed, cleanup may already have
		// terminated the physical endpoint. Failure can only be retried through
		// FailClosed; Rollback must never be reopened.
		token.state = ExecutionFailClosedRequired
		releaseLease = token.retainDriverCallLocked(
			call, driverCallReconcileFailClosed, nil,
		)
	}
	token.mu.Unlock()
	if releaseLease {
		releaseExecutionTokenLease(token)
	}
	if err != nil {
		return err
	}
	e.releaseLease()
	return nil
}

func invokeDriverStep(
	ctx context.Context,
	name string,
	expectedContext ContextDigest,
	expectedPlatform ProbeReference,
	verifyBefore bool,
	verifyAfter bool,
	class driverCallbackClass,
	allowCanceledStart bool,
	step func() (PublicationEvidence, error),
) (PublicationEvidence, *driverStepCall, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	initialErr := ctx.Err()
	if initialErr != nil && !allowCanceledStart {
		return PublicationEvidence{}, nil, newDriverCallbackError(ErrExecutionDriver, name, initialErr)
	}
	acquirePermit, releasePermit := driverStepCallbackPermits(class)
	if !acquirePermit() {
		return PublicationEvidence{}, nil, newDriverCallbackError(ErrExecutionDriver, name, ErrDriverCallbackCapacity)
	}
	call := &driverStepCall{done: make(chan struct{})}
	go func() {
		defer releasePermit()
		returned := false
		var result driverStepResult
		defer func() {
			if !returned {
				result = driverStepResult{err: newDriverCallbackError(ErrExecutionDriverGoexit, name, nil)}
			}
			call.complete(result)
		}()
		result = invokeDriverStepLocked(
			name, expectedContext, expectedPlatform, verifyBefore, verifyAfter, step,
		)
		returned = true
	}()
	select {
	case <-call.done:
		return call.result.publication, nil, call.result.err
	case <-ctx.Done():
		timer := time.NewTimer(driverCanceledCallbackGrace)
		defer timer.Stop()
		select {
		case <-call.done:
			return call.result.publication, nil, call.result.err
		case <-timer.C:
			return PublicationEvidence{}, call, newDriverCallbackError(ErrExecutionDriver, name, ctx.Err())
		}
	}
}

func invokeDriverStepLocked(
	name string,
	expectedContext ContextDigest,
	expectedPlatform ProbeReference,
	verifyBefore bool,
	verifyAfter bool,
	step func() (PublicationEvidence, error),
) (result driverStepResult) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	defer func() {
		if recovered := recover(); recovered != nil {
			result = driverStepResult{err: newDriverCallbackError(ErrExecutionDriverPanic, name, nil)}
		}
	}()
	if verifyBefore {
		current, contextErr := currentExecutionContextDigest()
		if contextErr != nil || current != expectedContext {
			return driverStepResult{err: newDriverCallbackError(ErrExecutionDriver, name, errors.New("execution context changed"))}
		}
		if expectedPlatform != (ProbeReference{}) {
			if !platformReferenceMatchesCurrent(context.Background(), expectedPlatform) {
				return driverStepResult{err: newDriverCallbackError(ErrExecutionDriver, name, errors.New("platform evidence changed"))}
			}
		}
	}
	publication, err := step()
	if err != nil {
		return driverStepResult{err: newDriverCallbackError(ErrExecutionDriver, name, err)}
	}
	if verifyAfter {
		current, contextErr := currentExecutionContextDigest()
		if contextErr != nil || current != expectedContext {
			return driverStepResult{err: newDriverCallbackError(ErrExecutionDriver, name, errors.New("execution context changed"))}
		}
		if expectedPlatform != (ProbeReference{}) {
			if !platformReferenceMatchesCurrent(context.Background(), expectedPlatform) {
				return driverStepResult{err: newDriverCallbackError(ErrExecutionDriver, name, errors.New("platform evidence changed"))}
			}
		}
	}
	return driverStepResult{publication: publication}
}
