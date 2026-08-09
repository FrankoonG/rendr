package leafmobility

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"sort"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/proto"
)

// ClaimState is a coherent ownership observation used by the planner.
type ClaimState struct {
	Facts          Facts
	Binding        Binding
	BaseGeneration uint64
	Bound          bool
	Retired        bool
	HasDriver      bool
}

type TransactionID [16]byte
type EvidenceDigest [32]byte
type LocalPlanDigest [32]byte

type ProbeID uint8

const (
	ProbePlatformSnapshot  ProbeID = 1
	ProbeEndpointState     ProbeID = 2
	ProbeTuple             ProbeID = 3
	ProbeQuarantineSchema  ProbeID = 4
	ProbeRollbackReadiness ProbeID = 5
	maxProbeReferences             = 5
	MaxProbeObservationAge         = 30 * time.Second
	MaxProbeLifetime               = 30 * time.Second
)

type ContextDigest [32]byte

// ProbeReference identifies immutable evidence used by one preflight. It is a
// reference, not raw kernel diagnostics; private errno and socket state remain
// inside the owning driver.
type ProbeReference struct {
	ID                 ProbeID
	Revision           uint32
	Generation         uint64
	EndpointGeneration uint64
	ObservedNano       int64
	ExpiresNano        int64
	ContextDigest      ContextDigest
	Digest             EvidenceDigest
}

// ProbeReferences is a canonical, fixed-capacity value so Plan remains
// immutable, comparable, and safe to include in the bilateral digest.
type ProbeReferences struct {
	count uint8
	items [maxProbeReferences]ProbeReference
}

func NewProbeReferences(references ...ProbeReference) (ProbeReferences, error) {
	if len(references) == 0 || len(references) > maxProbeReferences {
		return ProbeReferences{}, fmt.Errorf("%w: probe reference count %d", ErrInvalidDriver, len(references))
	}
	canonical := append([]ProbeReference(nil), references...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].ID < canonical[j].ID })
	var result ProbeReferences
	result.count = uint8(len(canonical))
	for index, reference := range canonical {
		if !reference.valid() || (index > 0 && canonical[index-1].ID == reference.ID) {
			return ProbeReferences{}, fmt.Errorf("%w: invalid or duplicate probe reference %d", ErrInvalidDriver, reference.ID)
		}
		result.items[index] = reference
	}
	return result, nil
}

func (r ProbeReferences) All() []ProbeReference {
	count := int(r.count)
	if count > len(r.items) {
		return nil
	}
	return append([]ProbeReference(nil), r.items[:count]...)
}

func (r ProbeReferences) valid(required bool) bool {
	if int(r.count) > len(r.items) || (required && r.count == 0) {
		return false
	}
	for index := 0; index < int(r.count); index++ {
		if !r.items[index].valid() || (index > 0 && r.items[index-1].ID >= r.items[index].ID) {
			return false
		}
	}
	for index := int(r.count); index < len(r.items); index++ {
		if r.items[index] != (ProbeReference{}) {
			return false
		}
	}
	return true
}

func (r ProbeReference) valid() bool {
	return r.ID >= ProbePlatformSnapshot && r.ID <= ProbeRollbackReadiness &&
		r.Revision != 0 && r.Generation != 0 && r.ObservedNano > 0 && r.ExpiresNano > r.ObservedNano &&
		r.ContextDigest != (ContextDigest{}) && r.Digest != (EvidenceDigest{}) &&
		((r.ID == ProbePlatformSnapshot && r.EndpointGeneration == 0) ||
			(r.ID != ProbePlatformSnapshot && r.EndpointGeneration != 0))
}

func (r ProbeReferences) validFor(
	operation Operation,
	endpointGeneration uint64,
	nowNano int64,
	deadlineNano int64,
	requireComplete bool,
) bool {
	if !r.valid(requireComplete) {
		return false
	}
	var (
		seen    uint8
		context ContextDigest
	)
	for _, reference := range r.All() {
		if (nowNano > 0 && (reference.ObservedNano > nowNano || reference.ExpiresNano <= nowNano)) ||
			(nowNano > 0 && nowNano-reference.ObservedNano > int64(MaxProbeObservationAge)) ||
			reference.ExpiresNano-reference.ObservedNano > int64(MaxProbeLifetime) ||
			deadlineNano > reference.ExpiresNano {
			return false
		}
		if context == (ContextDigest{}) {
			context = reference.ContextDigest
		} else if context != reference.ContextDigest {
			return false
		}
		if reference.ID != ProbePlatformSnapshot && reference.EndpointGeneration != endpointGeneration {
			return false
		}
		seen |= 1 << (reference.ID - 1)
	}
	if !requireComplete {
		return true
	}
	mandatory := mandatoryProbeMask(operation)
	return mandatory != 0 && seen&mandatory == mandatory
}

func (r ProbeReferences) contextDigest() (ContextDigest, bool) {
	if !r.valid(true) {
		return ContextDigest{}, false
	}
	context := r.items[0].ContextDigest
	for index := 1; index < int(r.count); index++ {
		if r.items[index].ContextDigest != context {
			return ContextDigest{}, false
		}
	}
	return context, true
}

func (r ProbeReferences) matchesContext(expected ContextDigest) bool {
	context, ok := r.contextDigest()
	return ok && expected != (ContextDigest{}) && context == expected
}

func currentExecutionContextDigest() (ContextDigest, error) {
	digest, err := platform.CurrentRuntimeContextDigest()
	return ContextDigest(digest), err
}

func (r ProbeReferences) matchesCurrentExecutionContext() bool {
	current, err := currentExecutionContextDigest()
	return err == nil && r.matchesContext(current)
}

func (r ProbeReferences) platformReference() (ProbeReference, bool) {
	for _, reference := range r.All() {
		if reference.ID == ProbePlatformSnapshot {
			return reference, true
		}
	}
	return ProbeReference{}, false
}

func (r ProbeReferences) matchesPlatformReference(expected ProbeReference) bool {
	reference, ok := r.platformReference()
	return !ok || (expected != (ProbeReference{}) && reference == expected)
}

func (r ProbeReferences) matchesCurrentPlatform(ctx context.Context) bool {
	reference, ok := r.platformReference()
	if !ok {
		return true
	}
	return platformReferenceMatchesCurrent(ctx, reference)
}

func platformReferenceMatchesCurrent(ctx context.Context, reference ProbeReference) bool {
	current, err := currentPlatformReference(ctx)
	now := time.Now().UnixNano()
	return err == nil && current.ObservedNano <= now && current.ExpiresNano > now &&
		reference.ID == current.ID && reference.Revision == current.Revision &&
		reference.Generation == current.Generation && reference.ContextDigest == current.ContextDigest &&
		reference.Digest == current.Digest
}

func currentPlatformReference(ctx context.Context) (ProbeReference, error) {
	snapshot, err := platform.Detect(ctx)
	if err != nil {
		return ProbeReference{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("RPF1"))
	var scalar [8]byte
	binary.BigEndian.PutUint32(scalar[:4], snapshot.ProbeRevision)
	_, _ = hash.Write(scalar[:4])
	binary.BigEndian.PutUint64(scalar[:], snapshot.InvalidationGeneration)
	_, _ = hash.Write(scalar[:])
	_, _ = hash.Write(snapshot.RuntimeContextDigest[:])
	writeString := func(value string) {
		binary.BigEndian.PutUint32(scalar[:4], uint32(len(value)))
		_, _ = hash.Write(scalar[:4])
		_, _ = hash.Write([]byte(value))
	}
	for _, evidence := range snapshot.All() {
		writeString(string(evidence.ID))
		writeString(string(evidence.State))
		writeString(string(evidence.Reason))
		writeString(string(evidence.Source))
		if evidence.Retryable {
			_, _ = hash.Write([]byte{1})
		} else {
			_, _ = hash.Write([]byte{0})
		}
	}
	var digest EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	generation := snapshot.InvalidationGeneration + 1
	if generation == 0 {
		return ProbeReference{}, fmt.Errorf("%w: platform invalidation generation exhausted", ErrInvalidDriver)
	}
	return ProbeReference{
		ID: ProbePlatformSnapshot, Revision: snapshot.ProbeRevision, Generation: generation,
		ObservedNano: snapshot.ProbedAt.UnixNano(), ExpiresNano: snapshot.ExpiresAt.UnixNano(),
		ContextDigest: ContextDigest(snapshot.RuntimeContextDigest), Digest: digest,
	}, nil
}

func (r ProbeReferences) earliestExpiry() int64 {
	var earliest int64
	for _, reference := range r.All() {
		if earliest == 0 || reference.ExpiresNano < earliest {
			earliest = reference.ExpiresNano
		}
	}
	return earliest
}

func mandatoryProbeMask(operation Operation) uint8 {
	const (
		platform   = 1 << (ProbePlatformSnapshot - 1)
		endpoint   = 1 << (ProbeEndpointState - 1)
		tuple      = 1 << (ProbeTuple - 1)
		quarantine = 1 << (ProbeQuarantineSchema - 1)
		rollback   = 1 << (ProbeRollbackReadiness - 1)
	)
	switch operation {
	case OperationTCPRepair:
		return platform | endpoint | tuple | quarantine | rollback
	case OperationQUICCIDRebind, OperationUDPFlowRebind:
		return endpoint | tuple | rollback
	case OperationGVisorLinkRebind:
		return platform | endpoint | tuple | rollback
	default:
		return 0
	}
}

func (r ProbeReferences) containsMask(required uint8) bool {
	if required == 0 {
		return false
	}
	var seen uint8
	for _, reference := range r.All() {
		seen |= 1 << (reference.ID - 1)
	}
	return seen&required == required
}

func decisionProbeMask(stage Stage) uint8 {
	const (
		platform   = 1 << (ProbePlatformSnapshot - 1)
		endpoint   = 1 << (ProbeEndpointState - 1)
		tuple      = 1 << (ProbeTuple - 1)
		quarantine = 1 << (ProbeQuarantineSchema - 1)
		rollback   = 1 << (ProbeRollbackReadiness - 1)
	)
	switch stage {
	case StageEndpoint, StageResourceBudget:
		return endpoint
	case StagePlatform:
		return platform
	case StagePreflight:
		return platform | endpoint
	case StageTuple:
		return tuple
	case StageQuiesce:
		return endpoint | rollback
	case StageQuarantine:
		return quarantine
	case StageSnapshot:
		return endpoint | tuple
	case StageRollback:
		return rollback
	default:
		return 0
	}
}

// Fallback identifies the already-negotiated non-specialized recovery path.
type Fallback uint8

const (
	FallbackInvalid      Fallback = 0
	FallbackRedialAttach Fallback = 1
)

// Reason is stable planner output. It is intentionally coarser than a driver
// error string so status and regressions can compare it across kernels.
type Reason uint16

const (
	ReasonNone                       Reason = 0
	ReasonEndpointNotOwned           Reason = 1
	ReasonEndpointRetired            Reason = 2
	ReasonBindingNotActive           Reason = 3
	ReasonBindingMismatch            Reason = 4
	ReasonSessionMismatch            Reason = 5
	ReasonOperationNotQualified      Reason = 6
	ReasonLocalUnsupported           Reason = 7
	ReasonPeerUnsupported            Reason = 8
	ReasonDeadlineExpired            Reason = 9
	ReasonPreflightRejected          Reason = 10
	ReasonPreflightFailed            Reason = 11
	ReasonStaleGeneration            Reason = 12
	ReasonNotRawTCP                  Reason = 13
	ReasonTCPStateIneligible         Reason = 14
	ReasonKernelUnsupported          Reason = 15
	ReasonPermissionDenied           Reason = 16
	ReasonStateAPIIncomplete         Reason = 17
	ReasonTupleNotPreservable        Reason = 18
	ReasonTransparentBindUnavailable Reason = 19
	ReasonQuiesceFailed              Reason = 20
	ReasonSnapshotIncomplete         Reason = 21
	ReasonQuarantineUnavailable      Reason = 22
	ReasonQuarantineUnverified       Reason = 23
	ReasonPlanMismatch               Reason = 24
	ReasonRollbackUnavailable        Reason = 25
	ReasonResourceBudgetExceeded     Reason = 26
)

func (r Reason) String() string {
	switch r {
	case ReasonNone:
		return ""
	case ReasonEndpointNotOwned:
		return "endpoint_not_owned"
	case ReasonEndpointRetired:
		return "endpoint_retired"
	case ReasonBindingNotActive:
		return "binding_not_active"
	case ReasonBindingMismatch:
		return "binding_mismatch"
	case ReasonSessionMismatch:
		return "session_mismatch"
	case ReasonOperationNotQualified:
		return "owned_operation_not_qualified"
	case ReasonLocalUnsupported:
		return "local_unsupported"
	case ReasonPeerUnsupported:
		return "peer_unsupported"
	case ReasonDeadlineExpired:
		return "deadline_expired"
	case ReasonPreflightRejected:
		return "preflight_rejected"
	case ReasonPreflightFailed:
		return "preflight_failed"
	case ReasonStaleGeneration:
		return "stale_generation"
	case ReasonNotRawTCP:
		return "not_raw_tcp"
	case ReasonTCPStateIneligible:
		return "tcp_state_ineligible"
	case ReasonKernelUnsupported:
		return "kernel_unsupported"
	case ReasonPermissionDenied:
		return "permission_denied"
	case ReasonStateAPIIncomplete:
		return "state_api_incomplete"
	case ReasonTupleNotPreservable:
		return "tuple_not_preservable"
	case ReasonTransparentBindUnavailable:
		return "transparent_bind_unavailable"
	case ReasonQuiesceFailed:
		return "quiesce_failed"
	case ReasonSnapshotIncomplete:
		return "snapshot_incomplete"
	case ReasonQuarantineUnavailable:
		return "quarantine_unavailable"
	case ReasonQuarantineUnverified:
		return "quarantine_unverified"
	case ReasonPlanMismatch:
		return "plan_mismatch"
	case ReasonRollbackUnavailable:
		return "rollback_unavailable"
	case ReasonResourceBudgetExceeded:
		return "resource_budget_exceeded"
	default:
		return fmt.Sprintf("reason_%d", r)
	}
}

// Stage identifies the factual eligibility boundary that produced a decision.
// It is stable planner/status evidence, not a driver log message.
type Stage uint8

const (
	StageNone              Stage = 0
	StageEndpoint          Stage = 1
	StageBinding           Stage = 2
	StageSession           Stage = 3
	StagePlatform          Stage = 4
	StageTuple             Stage = 5
	StagePreflight         Stage = 6
	StageQuiesce           Stage = 7
	StageQuarantine        Stage = 8
	StageSnapshot          Stage = 9
	StagePeerPlan          Stage = 10
	StageRollback          Stage = 11
	StageResourceBudget    Stage = 12
	StagePreflightComplete Stage = 13
)

func (s Stage) String() string {
	switch s {
	case StageNone:
		return ""
	case StageEndpoint:
		return "endpoint"
	case StageBinding:
		return "binding"
	case StageSession:
		return "session"
	case StagePlatform:
		return "platform"
	case StageTuple:
		return "tuple"
	case StagePreflight:
		return "preflight"
	case StageQuiesce:
		return "quiesce"
	case StageQuarantine:
		return "quarantine"
	case StageSnapshot:
		return "snapshot"
	case StagePeerPlan:
		return "peer_plan"
	case StageRollback:
		return "rollback"
	case StageResourceBudget:
		return "resource_budget"
	case StagePreflightComplete:
		return "preflight_complete"
	default:
		return fmt.Sprintf("stage_%d", s)
	}
}

// Driver is implementable only by packages inside this module because this
// package lives under internal/. Preflight is non-destructive and returns the
// exact inert attempt that produced its evidence. The attempt is sealed into
// Plan and remains unreachable until the Claim's engine-bound issuer consumes
// a correlated peer agreement.
type Driver interface {
	Operation() Operation
	Preflight(context.Context, PreflightRequest) (DriverAttempt, PreflightResult, error)
}

// Capability is sealed session-level evidence that a real in-module driver
// exists. It is still not endpoint eligibility or peer authorization.
type Capability struct {
	operation Operation
}

func CapabilityForDriver(driver Driver) (Capability, error) {
	if interfaceIsNil(driver) {
		return Capability{}, fmt.Errorf("%w: nil driver", ErrInvalidDriver)
	}
	if _, ok := interfaceIdentity(driver); !ok {
		return Capability{}, fmt.Errorf("%w: driver must have stable pointer identity", ErrInvalidDriver)
	}
	operation := driver.Operation()
	if !operation.single() {
		return Capability{}, fmt.Errorf("%w: operation %#x is not one known operation", ErrInvalidDriver, operation)
	}
	return Capability{operation: operation}, nil
}

func (c Capability) Operation() Operation { return c.operation }

type PlanRequest struct {
	TransactionID TransactionID
	Binding       Binding
	Direction     proto.SenderDirection
	Session       Session
	Deadline      time.Time
	LocalSupport  Operation
	PeerSupport   Operation
}

type PreflightRequest struct {
	PlanRequest
	Facts         Facts
	ContextDigest ContextDigest
	PlatformProbe ProbeReference
}

type PreflightResult struct {
	Eligible        bool
	Stage           Stage
	Reason          Reason
	Retryable       bool
	EvidenceDigest  EvidenceDigest
	ProbeReferences ProbeReferences
}

// KnownOperationSetFromProtocol maps known optional wire capabilities without
// relying on enum casts. Unknown supported bits are intentionally ignored;
// negotiation decode already rejects unknown required bits.
func KnownOperationSetFromProtocol(set proto.LeafMobilitySet) Operation {
	var operations Operation
	if set.Has(proto.LeafMobilityTCPRepair) {
		operations |= OperationTCPRepair
	}
	if set.Has(proto.LeafMobilityQUICCIDRebind) {
		operations |= OperationQUICCIDRebind
	}
	if set.Has(proto.LeafMobilityUDPFlowRebind) {
		operations |= OperationUDPFlowRebind
	}
	if set.Has(proto.LeafMobilityGVisorLinkRebind) {
		operations |= OperationGVisorLinkRebind
	}
	return operations
}

// ProtocolSet converts internal operations to their stable wire identities.
func (o Operation) ProtocolSet() (proto.LeafMobilitySet, error) {
	if o&^knownOperations != 0 {
		return 0, fmt.Errorf("%w: unknown internal operation %#x", ErrInvalidPlanRequest, o)
	}
	var set proto.LeafMobilitySet
	if o.Has(OperationTCPRepair) {
		set |= proto.LeafMobilityTCPRepair
	}
	if o.Has(OperationQUICCIDRebind) {
		set |= proto.LeafMobilityQUICCIDRebind
	}
	if o.Has(OperationUDPFlowRebind) {
		set |= proto.LeafMobilityUDPFlowRebind
	}
	if o.Has(OperationGVisorLinkRebind) {
		set |= proto.LeafMobilityGVisorLinkRebind
	}
	return set, nil
}

// Plan is an immutable local factual candidate for exactly one transaction
// and endpoint generation. This package currently exposes no execution path.
// Operation zero means the redial/attach fallback was selected.
type Plan struct {
	TransactionID      TransactionID
	Binding            Binding
	EndpointGeneration uint64
	BaseGeneration     uint64
	Direction          proto.SenderDirection
	Session            Session
	Operation          Operation
	Fallback           Fallback
	Reason             Reason
	Stage              Stage
	Retryable          bool
	Deadline           time.Time
	LocalSupport       Operation
	PeerSupport        Operation
	Kind               Kind
	Role               Role
	Scope              Scope
	ResourceID         ResourceID
	EvidenceDigest     EvidenceDigest
	ProbeReferences    ProbeReferences
	LocalDigest        LocalPlanDigest
	attempt            *driverAttemptBinding
}

type driverAttemptBinding struct {
	driver    Driver
	attempt   DriverAttempt
	request   PreflightRequest
	evidence  EvidenceDigest
	probes    ProbeReferences
	operation Operation
	deadline  time.Time
}

type driverAttemptKey struct {
	typeOf reflect.Type
	ptr    uintptr
}

type driverAttemptRecord struct {
	deadline time.Time
	attempt  DriverAttempt
}

var driverAttemptRegistry = struct {
	sync.Mutex
	active map[driverAttemptKey]driverAttemptRecord
}{active: make(map[driverAttemptKey]driverAttemptRecord)}

var (
	ErrInvalidPlanRequest = errors.New("leafmobility: invalid plan request")
	ErrInvalidPlan        = errors.New("leafmobility: invalid plan")
	ErrStalePlan          = errors.New("leafmobility: stale plan")
	ErrPlanExpired        = errors.New("leafmobility: plan deadline expired")
	ErrBaselinePlan       = errors.New("leafmobility: baseline plan has no specialized transaction")
)

const MaxPlanHorizon = 90 * time.Second

// PlanCandidate performs only non-destructive checks. A specialized local
// candidate is returned only after exact ownership, session capability and
// fresh driver preflight agree; peer transaction agreement is still required
// before execution. Every other factual outcome selects redial/attach.
func PlanCandidate(ctx context.Context, claim *Claim, request PlanRequest) (Plan, error) {
	request.Deadline = canonicalTime(request.Deadline)
	if err := validatePlanRequest(request); err != nil {
		return Plan{}, err
	}
	now := time.Now()
	base := Plan{
		TransactionID: request.TransactionID,
		Binding:       request.Binding,
		Direction:     request.Direction,
		Session:       request.Session,
		Fallback:      FallbackRedialAttach,
		Deadline:      request.Deadline,
		LocalSupport:  request.LocalSupport,
		PeerSupport:   request.PeerSupport,
	}
	if !request.Deadline.After(now) {
		return finalizePlan(base, StagePeerPlan, ReasonDeadlineExpired, false), nil
	}
	if request.Deadline.Sub(now) > MaxPlanHorizon {
		return Plan{}, fmt.Errorf("%w: deadline exceeds %s", ErrInvalidPlanRequest, MaxPlanHorizon)
	}
	if claim == nil {
		return finalizePlan(base, StageEndpoint, ReasonEndpointNotOwned, false), nil
	}
	state, driver := claim.stateWithDriver()
	base.EndpointGeneration = state.Facts.Generation
	base.BaseGeneration = state.BaseGeneration
	base.Kind = state.Facts.Kind
	base.Role = state.Facts.Role
	base.Scope = state.Facts.Scope
	base.ResourceID = state.Facts.ResourceID
	if state.Retired {
		return finalizePlan(base, StageEndpoint, ReasonEndpointRetired, false), nil
	}
	if !state.Bound {
		return finalizePlan(base, StageBinding, ReasonBindingNotActive, false), nil
	}
	if state.Binding != request.Binding {
		return finalizePlan(base, StageBinding, ReasonBindingMismatch, false), nil
	}
	if state.Facts.Session != SessionAny && state.Facts.Session != request.Session {
		return finalizePlan(base, StageSession, ReasonSessionMismatch, false), nil
	}
	operation := operationForKind(state.Facts.Kind)
	if operation == 0 || !state.Facts.Operations.Has(operation) || driver == nil {
		return finalizePlan(base, StageEndpoint, ReasonOperationNotQualified, false), nil
	}
	if !request.LocalSupport.Has(operation) {
		return finalizePlan(base, StagePlatform, ReasonLocalUnsupported, false), nil
	}
	if !request.PeerSupport.Has(operation) {
		return finalizePlan(base, StagePeerPlan, ReasonPeerUnsupported, false), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return finalizePlan(base, StagePreflight, ReasonPreflightFailed, false), nil
	}
	preflightCtx, cancel := context.WithDeadline(ctx, request.Deadline)
	preflightRequest, attempt, result, err := invokeDriverPreflight(preflightCtx, driver, request, state.Facts)
	contextErr := preflightCtx.Err()
	cancel()
	if request.Deadline.UnixNano() <= time.Now().UnixNano() {
		return finalizePlan(base, StagePeerPlan, ReasonDeadlineExpired, false), nil
	}
	if err != nil || contextErr != nil {
		return finalizePlan(base, StagePreflight, ReasonPreflightFailed, false), nil
	}
	executionContext := preflightRequest.ContextDigest
	evidenceDeadline := result.ProbeReferences.earliestExpiry()
	if evidenceDeadline != 0 && evidenceDeadline < base.Deadline.UnixNano() {
		base.Deadline = canonicalUnixTime(evidenceDeadline)
	}
	if err := validatePreflightResult(
		operation, state.Facts.Generation, executionContext, preflightRequest.PlatformProbe,
		base.Deadline.UnixNano(), time.Now().UnixNano(), attempt, result,
	); err != nil {
		return Plan{}, err
	}
	current, _ := claim.stateWithDriver()
	if current.Retired {
		return finalizePlan(base, StageEndpoint, ReasonEndpointRetired, false), nil
	}
	if !current.Bound || current.Binding != state.Binding || current.Facts != state.Facts {
		return finalizePlan(base, StageBinding, ReasonBindingMismatch, false), nil
	}
	if current.BaseGeneration != state.BaseGeneration {
		return finalizePlan(base, StagePeerPlan, ReasonStaleGeneration, false), nil
	}
	if !result.Eligible {
		base.ProbeReferences = result.ProbeReferences
		return finalizePlan(base, result.Stage, result.Reason, result.Retryable), nil
	}
	attemptDeadline, ok := registerDriverAttempt(attempt, base.Deadline)
	if !ok {
		return Plan{}, fmt.Errorf("%w: driver attempt identity is not unique", ErrInvalidDriver)
	}
	base.Operation = operation
	base.Stage = StagePreflightComplete
	base.EvidenceDigest = result.EvidenceDigest
	base.ProbeReferences = result.ProbeReferences
	base.attempt = &driverAttemptBinding{
		driver: driver, attempt: attempt, request: preflightRequest,
		evidence: result.EvidenceDigest, probes: result.ProbeReferences, operation: operation, deadline: attemptDeadline,
	}
	base.LocalDigest = digestPlan(base)
	return base, nil
}

func registerDriverAttempt(attempt DriverAttempt, deadline time.Time) (time.Time, bool) {
	ptr, ok := interfaceIdentity(attempt)
	now := time.Now()
	remaining := deadline.Sub(now)
	if !ok || remaining <= 0 {
		return time.Time{}, false
	}
	monotonicDeadline := now.Add(remaining)
	key := driverAttemptKey{typeOf: reflect.TypeOf(attempt), ptr: ptr}
	driverAttemptRegistry.Lock()
	for candidate, record := range driverAttemptRegistry.active {
		if !record.deadline.After(now) {
			delete(driverAttemptRegistry.active, candidate)
		}
	}
	if record, exists := driverAttemptRegistry.active[key]; exists && record.deadline.After(now) {
		driverAttemptRegistry.Unlock()
		return time.Time{}, false
	}
	driverAttemptRegistry.active[key] = driverAttemptRecord{deadline: monotonicDeadline, attempt: attempt}
	driverAttemptRegistry.Unlock()
	return monotonicDeadline, true
}

func invokeDriverPreflight(
	ctx context.Context,
	driver Driver,
	request PlanRequest,
	facts Facts,
) (preflight PreflightRequest, attempt DriverAttempt, result PreflightResult, err error) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	defer func() {
		if recovered := recover(); recovered != nil {
			preflight = PreflightRequest{}
			attempt = nil
			result = PreflightResult{}
			err = fmt.Errorf("%w: preflight panicked: %v", ErrInvalidDriver, recovered)
		}
	}()
	contextDigest, err := currentExecutionContextDigest()
	if err != nil || contextDigest == (ContextDigest{}) {
		return PreflightRequest{}, nil, PreflightResult{}, fmt.Errorf("%w: execution context unavailable: %v", ErrInvalidDriver, err)
	}
	preflight = PreflightRequest{PlanRequest: request, Facts: facts, ContextDigest: contextDigest}
	platformProbe, platformErr := currentPlatformReference(ctx)
	if platformErr != nil || platformProbe.ContextDigest != contextDigest {
		return PreflightRequest{}, nil, PreflightResult{}, fmt.Errorf("%w: platform evidence unavailable: %v", ErrInvalidDriver, platformErr)
	}
	preflight.PlatformProbe = platformProbe
	attempt, result, err = driver.Preflight(ctx, preflight)
	if err != nil {
		return preflight, attempt, result, err
	}
	current, contextErr := currentExecutionContextDigest()
	if contextErr != nil || current != contextDigest {
		return preflight, nil, PreflightResult{}, fmt.Errorf("%w: execution context changed during preflight", ErrInvalidDriver)
	}
	return preflight, attempt, result, nil
}

// ValidatePlanCurrent revalidates a published local candidate against the
// exact claim. It does not expose the driver or start a transaction.
func (c *Claim) ValidatePlanCurrent(plan Plan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Operation == 0 {
		return ErrBaselinePlan
	}
	nowNano := time.Now().UnixNano()
	if plan.Deadline.UnixNano() <= nowNano {
		return ErrPlanExpired
	}
	if !plan.ProbeReferences.validFor(plan.Operation, plan.EndpointGeneration, nowNano, plan.Deadline.UnixNano(), true) ||
		!plan.ProbeReferences.matchesCurrentExecutionContext() ||
		!plan.ProbeReferences.matchesCurrentPlatform(context.Background()) {
		return ErrStalePlan
	}
	state, driver := c.stateWithDriver()
	if state.Retired || !state.Bound || state.Binding != plan.Binding ||
		state.Facts.Generation != plan.EndpointGeneration || state.Facts.Kind != plan.Kind ||
		state.Facts.Role != plan.Role || state.Facts.Scope != plan.Scope || state.Facts.ResourceID != plan.ResourceID || driver == nil ||
		state.BaseGeneration != plan.BaseGeneration || !state.Facts.Operations.Has(plan.Operation) ||
		plan.attempt == nil || !plan.attempt.validFor(plan, driver, state.Facts, PlanRequest{
		TransactionID: plan.TransactionID, Binding: plan.Binding, Direction: plan.Direction,
		Session: plan.Session, Deadline: plan.Deadline, LocalSupport: plan.LocalSupport, PeerSupport: plan.PeerSupport,
	}) {
		return ErrStalePlan
	}
	return nil
}

func (p Plan) Validate() error {
	request := PlanRequest{
		TransactionID: p.TransactionID,
		Binding:       p.Binding,
		Direction:     p.Direction,
		Session:       p.Session,
		Deadline:      p.Deadline,
		LocalSupport:  p.LocalSupport,
		PeerSupport:   p.PeerSupport,
	}
	if err := validatePlanRequest(request); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	if p.Deadline != canonicalTime(p.Deadline) {
		return fmt.Errorf("%w: non-canonical deadline", ErrInvalidPlan)
	}
	if p.Fallback != FallbackRedialAttach {
		return fmt.Errorf("%w: unsupported fallback %d", ErrInvalidPlan, p.Fallback)
	}
	if !p.ProbeReferences.valid(false) {
		return fmt.Errorf("%w: invalid probe references", ErrInvalidPlan)
	}
	if p.Operation == 0 {
		intent := operationForKind(p.Kind)
		if !p.Stage.valid() || p.Stage == StageNone || p.Stage == StagePreflightComplete ||
			!p.Reason.valid() || p.Reason == ReasonNone || p.EvidenceDigest != (EvidenceDigest{}) || p.attempt != nil {
			return fmt.Errorf("%w: invalid baseline decision", ErrInvalidPlan)
		}
		if !validDecision(intent, p.Stage, p.Reason, p.Retryable) ||
			!p.ProbeReferences.validFor(intent, p.EndpointGeneration, 0, p.Deadline.UnixNano(), false) {
			return fmt.Errorf("%w: contradictory baseline decision", ErrInvalidPlan)
		}
	} else {
		facts := Facts{
			Kind: p.Kind, Role: p.Role, Scope: p.Scope, Session: p.Session,
			Operations: p.Operation, Generation: p.EndpointGeneration, ResourceID: p.ResourceID,
		}
		if p.attempt != nil && p.attempt.request.Facts.Session == SessionAny {
			facts.Session = SessionAny
		}
		if !p.Operation.single() || p.Stage != StagePreflightComplete || p.Reason != ReasonNone || p.Retryable || p.EndpointGeneration == 0 ||
			operationForKind(p.Kind) != p.Operation || p.Role == RoleUnknown || p.Scope == ScopeUnknown ||
			p.ResourceID == (ResourceID{}) ||
			!p.LocalSupport.Has(p.Operation) || !p.PeerSupport.Has(p.Operation) ||
			p.EvidenceDigest == (EvidenceDigest{}) || p.attempt == nil ||
			!p.ProbeReferences.validFor(p.Operation, p.EndpointGeneration, 0, p.Deadline.UnixNano(), true) ||
			!p.attempt.validFor(p, p.attempt.driver, facts, request) {
			return fmt.Errorf("%w: invalid specialized decision", ErrInvalidPlan)
		}
	}
	if p.LocalDigest == (LocalPlanDigest{}) || p.LocalDigest != digestPlan(p) {
		return fmt.Errorf("%w: plan digest mismatch", ErrInvalidPlan)
	}
	return nil
}

func (a *driverAttemptBinding) validFor(plan Plan, driver Driver, facts Facts, request PlanRequest) bool {
	return a != nil && sameInterfaceIdentity(a.driver, driver) && !interfaceIsNil(a.attempt) &&
		a.operation == plan.Operation && a.evidence == plan.EvidenceDigest && a.probes == plan.ProbeReferences &&
		sameBoundedPlanRequest(a.request.PlanRequest, request) && a.request.Facts == facts &&
		a.probes.matchesContext(a.request.ContextDigest) && a.probes.matchesPlatformReference(a.request.PlatformProbe) &&
		a.deadline.After(time.Now())
}

func (a *driverAttemptBinding) evidenceCurrent() bool {
	if a == nil || interfaceIsNil(a.attempt) {
		return false
	}
	evidence, err := readAttemptEvidence(a.attempt)
	return err == nil && evidence.Digest == a.evidence && evidence.ProbeReferences == a.probes
}

func sameBoundedPlanRequest(preflight, plan PlanRequest) bool {
	return preflight.TransactionID == plan.TransactionID && preflight.Binding == plan.Binding &&
		preflight.Direction == plan.Direction && preflight.Session == plan.Session &&
		preflight.Deadline.UnixNano() >= plan.Deadline.UnixNano() &&
		preflight.LocalSupport == plan.LocalSupport && preflight.PeerSupport == plan.PeerSupport
}

func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return canonicalUnixTime(value.UnixNano())
}

func canonicalUnixTime(nano int64) time.Time {
	return time.Unix(0, nano).UTC()
}

func validatePlanRequest(request PlanRequest) error {
	if request.TransactionID == (TransactionID{}) {
		return fmt.Errorf("%w: zero transaction id", ErrInvalidPlanRequest)
	}
	if err := validateBinding(request.Binding); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPlanRequest, err)
	}
	if !request.Direction.Valid() {
		return fmt.Errorf("%w: invalid direction %d", ErrInvalidPlanRequest, request.Direction)
	}
	if request.Session != SessionStream && request.Session != SessionPacket {
		return fmt.Errorf("%w: invalid session %d", ErrInvalidPlanRequest, request.Session)
	}
	if request.Deadline.IsZero() {
		return fmt.Errorf("%w: zero deadline", ErrInvalidPlanRequest)
	}
	if request.LocalSupport&^knownOperations != 0 || request.PeerSupport&^knownOperations != 0 {
		return fmt.Errorf("%w: unknown capability bit", ErrInvalidPlanRequest)
	}
	return nil
}

func validatePreflightResult(
	operation Operation,
	endpointGeneration uint64,
	expectedContext ContextDigest,
	expectedPlatform ProbeReference,
	deadlineNano int64,
	nowNano int64,
	attempt DriverAttempt,
	result PreflightResult,
) error {
	if result.Eligible {
		if result.Stage != StagePreflightComplete || result.Reason != ReasonNone || result.Retryable ||
			result.EvidenceDigest == (EvidenceDigest{}) ||
			!result.ProbeReferences.validFor(operation, endpointGeneration, nowNano, deadlineNano, true) ||
			!result.ProbeReferences.matchesContext(expectedContext) ||
			!result.ProbeReferences.matchesPlatformReference(expectedPlatform) ||
			interfaceIsNil(attempt) {
			return fmt.Errorf("%w: eligible preflight lacks canonical evidence", ErrInvalidDriver)
		}
		if _, ok := interfaceIdentity(attempt); !ok {
			return fmt.Errorf("%w: preflight attempt must have stable pointer identity", ErrInvalidDriver)
		}
		evidence, err := readAttemptEvidence(attempt)
		if err != nil || evidence.Digest != result.EvidenceDigest || evidence.ProbeReferences != result.ProbeReferences {
			return fmt.Errorf("%w: preflight attempt evidence mismatch", ErrInvalidDriver)
		}
		return nil
	}
	if !interfaceIsNil(attempt) {
		return fmt.Errorf("%w: ineligible preflight retained an executable attempt", ErrInvalidDriver)
	}
	if !validDecision(operation, result.Stage, result.Reason, result.Retryable) {
		return fmt.Errorf("%w: ineligible preflight lacks a reason", ErrInvalidDriver)
	}
	if result.EvidenceDigest != (EvidenceDigest{}) {
		return fmt.Errorf("%w: ineligible preflight supplied success evidence", ErrInvalidDriver)
	}
	if result.ProbeReferences.count == 0 ||
		!result.ProbeReferences.validFor(operation, endpointGeneration, nowNano, deadlineNano, false) ||
		!result.ProbeReferences.matchesContext(expectedContext) ||
		!result.ProbeReferences.matchesPlatformReference(expectedPlatform) ||
		!result.ProbeReferences.containsMask(decisionProbeMask(result.Stage)) {
		return fmt.Errorf("%w: ineligible preflight lacks probe references", ErrInvalidDriver)
	}
	return nil
}

func (r Reason) valid() bool {
	return r <= ReasonResourceBudgetExceeded
}

func (s Stage) valid() bool {
	return s <= StagePreflightComplete
}

func validDecision(operation Operation, stage Stage, reason Reason, retryable bool) bool {
	if !stage.valid() || !reason.valid() || stage == StageNone || reason == ReasonNone {
		return false
	}
	wantStage := StageNone
	switch reason {
	case ReasonEndpointNotOwned, ReasonEndpointRetired, ReasonOperationNotQualified,
		ReasonNotRawTCP, ReasonTCPStateIneligible:
		wantStage = StageEndpoint
	case ReasonBindingNotActive, ReasonBindingMismatch:
		wantStage = StageBinding
	case ReasonSessionMismatch:
		wantStage = StageSession
	case ReasonLocalUnsupported, ReasonKernelUnsupported, ReasonPermissionDenied, ReasonStateAPIIncomplete:
		wantStage = StagePlatform
	case ReasonTupleNotPreservable, ReasonTransparentBindUnavailable:
		wantStage = StageTuple
	case ReasonPreflightRejected, ReasonPreflightFailed:
		wantStage = StagePreflight
	case ReasonQuiesceFailed:
		wantStage = StageQuiesce
	case ReasonQuarantineUnavailable, ReasonQuarantineUnverified:
		wantStage = StageQuarantine
	case ReasonSnapshotIncomplete:
		wantStage = StageSnapshot
	case ReasonPeerUnsupported, ReasonDeadlineExpired, ReasonStaleGeneration, ReasonPlanMismatch:
		wantStage = StagePeerPlan
	case ReasonRollbackUnavailable:
		wantStage = StageRollback
	case ReasonResourceBudgetExceeded:
		wantStage = StageResourceBudget
	}
	if stage != wantStage {
		return false
	}
	if retryable {
		switch reason {
		case ReasonPreflightRejected, ReasonPreflightFailed, ReasonQuarantineUnavailable,
			ReasonResourceBudgetExceeded:
		default:
			return false
		}
	}
	switch reason {
	case ReasonNotRawTCP, ReasonTCPStateIneligible, ReasonTransparentBindUnavailable,
		ReasonQuiesceFailed, ReasonSnapshotIncomplete, ReasonQuarantineUnavailable,
		ReasonQuarantineUnverified:
		return operation == OperationTCPRepair
	default:
		return true
	}
}

func finalizePlan(plan Plan, stage Stage, reason Reason, retryable bool) Plan {
	plan.Operation = 0
	plan.Stage = stage
	plan.Reason = reason
	plan.Retryable = retryable
	plan.EvidenceDigest = EvidenceDigest{}
	plan.attempt = nil
	plan.LocalDigest = digestPlan(plan)
	return plan
}

const planCanonicalSize = 696

func digestPlan(plan Plan) LocalPlanDigest {
	wire := make([]byte, planCanonicalSize)
	copy(wire[0:4], "RLM2")
	wire[4] = 2
	wire[5] = byte(plan.Direction)
	wire[6] = byte(plan.Session)
	wire[7] = byte(plan.Operation)
	wire[8] = byte(plan.Fallback)
	if plan.Retryable {
		wire[9] = 1
	}
	binary.BigEndian.PutUint16(wire[10:12], uint16(plan.Reason))
	wire[12] = byte(plan.LocalSupport)
	wire[13] = byte(plan.PeerSupport)
	wire[14] = byte(plan.Kind)
	wire[15] = byte(plan.Role)
	wire[16] = byte(plan.Scope)
	wire[17] = byte(plan.Stage)
	copy(wire[20:36], plan.TransactionID[:])
	copy(wire[36:52], plan.Binding.FlowID[:])
	copy(wire[52:68], plan.Binding.LocalTargetID[:])
	copy(wire[68:84], plan.Binding.PeerTargetID[:])
	binary.BigEndian.PutUint32(wire[84:88], plan.Binding.PathID)
	binary.BigEndian.PutUint64(wire[88:96], plan.Binding.Owner)
	binary.BigEndian.PutUint64(wire[96:104], plan.EndpointGeneration)
	binary.BigEndian.PutUint64(wire[104:112], plan.BaseGeneration)
	binary.BigEndian.PutUint64(wire[112:120], uint64(plan.Deadline.UnixNano()))
	copy(wire[120:136], plan.ResourceID[:])
	copy(wire[136:168], plan.EvidenceDigest[:])
	wire[168] = plan.ProbeReferences.count
	for index := 0; index < maxProbeReferences; index++ {
		reference := plan.ProbeReferences.items[index]
		offset := 176 + index*104
		wire[offset] = byte(reference.ID)
		binary.BigEndian.PutUint32(wire[offset+4:offset+8], reference.Revision)
		binary.BigEndian.PutUint64(wire[offset+8:offset+16], reference.Generation)
		binary.BigEndian.PutUint64(wire[offset+16:offset+24], reference.EndpointGeneration)
		binary.BigEndian.PutUint64(wire[offset+24:offset+32], uint64(reference.ObservedNano))
		binary.BigEndian.PutUint64(wire[offset+32:offset+40], uint64(reference.ExpiresNano))
		copy(wire[offset+40:offset+72], reference.ContextDigest[:])
		copy(wire[offset+72:offset+104], reference.Digest[:])
	}
	return sha256.Sum256(wire)
}

func (c *Claim) stateWithDriver() (ClaimState, Driver) {
	if c == nil {
		return ClaimState{Retired: true}, nil
	}
	c.mu.RLock()
	state := ClaimState{
		Facts:     c.facts,
		Binding:   c.binding,
		Bound:     c.bound,
		Retired:   c.retired,
		HasDriver: c.driver != nil,
	}
	driver := c.driver
	if c.resource != nil {
		state.BaseGeneration = c.resource.currentGeneration()
	}
	c.mu.RUnlock()
	return state, driver
}
