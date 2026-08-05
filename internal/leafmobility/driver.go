package leafmobility

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

// ClaimState is a coherent ownership observation used by the planner.
type ClaimState struct {
	Facts     Facts
	Binding   Binding
	Bound     bool
	Retired   bool
	HasDriver bool
}

type TransactionID [16]byte
type EvidenceDigest [32]byte
type LocalPlanDigest [32]byte

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
	ReasonNone Reason = iota
	ReasonEndpointNotOwned
	ReasonEndpointRetired
	ReasonBindingNotActive
	ReasonBindingMismatch
	ReasonSessionMismatch
	ReasonOperationNotQualified
	ReasonLocalUnsupported
	ReasonPeerUnsupported
	ReasonDeadlineExpired
	ReasonPreflightRejected
	ReasonPreflightFailed
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
	default:
		return fmt.Sprintf("reason_%d", r)
	}
}

// Driver is implementable only by packages inside this module because this
// package lives under internal/. This checkpoint permits only non-destructive
// factual preflight. The peer-plan transaction will introduce a separate,
// single-use execution authority rather than exposing mutation here early.
type Driver interface {
	Operation() Operation
	Preflight(context.Context, PreflightRequest) (PreflightResult, error)
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
	Facts Facts
}

type PreflightResult struct {
	Eligible       bool
	Reason         Reason
	Retryable      bool
	EvidenceDigest EvidenceDigest
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
	Direction          proto.SenderDirection
	Session            Session
	Operation          Operation
	Fallback           Fallback
	Reason             Reason
	Retryable          bool
	Deadline           time.Time
	LocalSupport       Operation
	PeerSupport        Operation
	Kind               Kind
	Role               Role
	Scope              Scope
	EvidenceDigest     EvidenceDigest
	LocalDigest        LocalPlanDigest
}

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
		return finalizePlan(base, ReasonDeadlineExpired, false), nil
	}
	if request.Deadline.Sub(now) > MaxPlanHorizon {
		return Plan{}, fmt.Errorf("%w: deadline exceeds %s", ErrInvalidPlanRequest, MaxPlanHorizon)
	}
	if claim == nil {
		return finalizePlan(base, ReasonEndpointNotOwned, false), nil
	}
	state, driver := claim.stateWithDriver()
	base.EndpointGeneration = state.Facts.Generation
	base.Kind = state.Facts.Kind
	base.Role = state.Facts.Role
	base.Scope = state.Facts.Scope
	if state.Retired {
		return finalizePlan(base, ReasonEndpointRetired, false), nil
	}
	if !state.Bound {
		return finalizePlan(base, ReasonBindingNotActive, false), nil
	}
	if state.Binding != request.Binding {
		return finalizePlan(base, ReasonBindingMismatch, false), nil
	}
	if state.Facts.Session != SessionAny && state.Facts.Session != request.Session {
		return finalizePlan(base, ReasonSessionMismatch, false), nil
	}
	operation := operationForKind(state.Facts.Kind)
	if operation == 0 || !state.Facts.Operations.Has(operation) || driver == nil {
		return finalizePlan(base, ReasonOperationNotQualified, false), nil
	}
	if !request.LocalSupport.Has(operation) {
		return finalizePlan(base, ReasonLocalUnsupported, false), nil
	}
	if !request.PeerSupport.Has(operation) {
		return finalizePlan(base, ReasonPeerUnsupported, false), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return finalizePlan(base, ReasonPreflightFailed, false), nil
	}
	preflightCtx, cancel := context.WithDeadline(ctx, request.Deadline)
	result, err := driver.Preflight(preflightCtx, PreflightRequest{PlanRequest: request, Facts: state.Facts})
	contextErr := preflightCtx.Err()
	cancel()
	if !request.Deadline.After(time.Now()) {
		return finalizePlan(base, ReasonDeadlineExpired, false), nil
	}
	if err != nil || contextErr != nil {
		return finalizePlan(base, ReasonPreflightFailed, false), nil
	}
	if err := validatePreflightResult(result); err != nil {
		return Plan{}, err
	}
	current, _ := claim.stateWithDriver()
	if current.Retired {
		return finalizePlan(base, ReasonEndpointRetired, false), nil
	}
	if !current.Bound || current.Binding != state.Binding || current.Facts != state.Facts {
		return finalizePlan(base, ReasonBindingMismatch, false), nil
	}
	if !result.Eligible {
		return finalizePlan(base, result.Reason, result.Retryable), nil
	}
	base.Operation = operation
	base.EvidenceDigest = result.EvidenceDigest
	base.LocalDigest = digestPlan(base)
	return base, nil
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
	if !plan.Deadline.After(time.Now()) {
		return ErrPlanExpired
	}
	state, driver := c.stateWithDriver()
	if state.Retired || !state.Bound || state.Binding != plan.Binding ||
		state.Facts.Generation != plan.EndpointGeneration || state.Facts.Kind != plan.Kind ||
		state.Facts.Role != plan.Role || state.Facts.Scope != plan.Scope || driver == nil ||
		!state.Facts.Operations.Has(plan.Operation) {
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
	if p.Fallback != FallbackRedialAttach {
		return fmt.Errorf("%w: unsupported fallback %d", ErrInvalidPlan, p.Fallback)
	}
	if p.Operation == 0 {
		if !p.Reason.valid() || p.Reason == ReasonNone || p.EvidenceDigest != (EvidenceDigest{}) {
			return fmt.Errorf("%w: invalid baseline decision", ErrInvalidPlan)
		}
	} else {
		if !p.Operation.single() || p.Reason != ReasonNone || p.EndpointGeneration == 0 ||
			operationForKind(p.Kind) != p.Operation || p.Role == RoleUnknown || p.Scope == ScopeUnknown ||
			!p.LocalSupport.Has(p.Operation) || !p.PeerSupport.Has(p.Operation) ||
			p.EvidenceDigest == (EvidenceDigest{}) {
			return fmt.Errorf("%w: invalid specialized decision", ErrInvalidPlan)
		}
	}
	if p.LocalDigest == (LocalPlanDigest{}) || p.LocalDigest != digestPlan(p) {
		return fmt.Errorf("%w: plan digest mismatch", ErrInvalidPlan)
	}
	return nil
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

func validatePreflightResult(result PreflightResult) error {
	if result.Eligible {
		if result.Reason != ReasonNone || result.Retryable || result.EvidenceDigest == (EvidenceDigest{}) {
			return fmt.Errorf("%w: eligible preflight lacks canonical evidence", ErrInvalidDriver)
		}
		return nil
	}
	if !result.Reason.valid() || result.Reason == ReasonNone {
		return fmt.Errorf("%w: ineligible preflight lacks a reason", ErrInvalidDriver)
	}
	if result.EvidenceDigest != (EvidenceDigest{}) {
		return fmt.Errorf("%w: ineligible preflight supplied success evidence", ErrInvalidDriver)
	}
	return nil
}

func (r Reason) valid() bool {
	return r <= ReasonPreflightFailed
}

func finalizePlan(plan Plan, reason Reason, retryable bool) Plan {
	plan.Operation = 0
	plan.Reason = reason
	plan.Retryable = retryable
	plan.EvidenceDigest = EvidenceDigest{}
	plan.LocalDigest = digestPlan(plan)
	return plan
}

const planCanonicalSize = 144

func digestPlan(plan Plan) LocalPlanDigest {
	wire := make([]byte, planCanonicalSize)
	copy(wire[0:4], "RLM1")
	wire[4] = 1
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
	copy(wire[20:36], plan.TransactionID[:])
	copy(wire[36:52], plan.Binding.FlowID[:])
	copy(wire[52:68], plan.Binding.LocalTargetID[:])
	copy(wire[68:84], plan.Binding.PeerTargetID[:])
	binary.BigEndian.PutUint32(wire[84:88], plan.Binding.PathID)
	binary.BigEndian.PutUint64(wire[88:96], plan.Binding.Owner)
	binary.BigEndian.PutUint64(wire[96:104], plan.EndpointGeneration)
	binary.BigEndian.PutUint64(wire[104:112], uint64(plan.Deadline.UnixNano()))
	copy(wire[112:144], plan.EvidenceDigest[:])
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
	c.mu.RUnlock()
	return state, driver
}
