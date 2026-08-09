package leafmobility

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

var (
	ErrAuthorityIssuerRequired = errors.New("leafmobility: driven claim requires an authority issuer")
	ErrAuthorityIssuerMismatch = errors.New("leafmobility: authority issuer mismatch")
	ErrInvalidPeerAgreement    = errors.New("leafmobility: invalid peer agreement")
)

// AuthorityIssuer is an opaque per-engine authority domain. A sibling package
// can create a different issuer, but it cannot execute a Claim already bound
// to this issuer. Engine keeps the matching pointer private.
type AuthorityIssuer struct {
	token *authorityIssuerToken
}

type authorityIssuerToken struct {
	id uint64
}

var authorityIssuerCounter atomic.Uint64

func NewAuthorityIssuer() *AuthorityIssuer {
	for {
		if id := authorityIssuerCounter.Add(1); id != 0 {
			return &AuthorityIssuer{token: &authorityIssuerToken{id: id}}
		}
	}
}

// BindClaim is the engine-owned counterpart to Claim.Bind. Driven claims must
// enter topology through this method; plain claims may use either path.
func (i *AuthorityIssuer) BindClaim(claim *Claim, binding Binding) error {
	if i == nil || i.token == nil {
		return ErrAuthorityIssuerMismatch
	}
	if claim == nil {
		return ErrInvalidBinding
	}
	return claim.bind(binding, i.token)
}

// ConsumeExecution atomically binds a correlated PREPARED reservation to the
// exact claim, resource transaction, plan, issuer domain, driver and preflight
// attempt. It authorizes private staging only. Execution.Publish remains
// impossible until the engine later records correlated FINAL authorization.
func (i *AuthorityIssuer) ConsumeExecution(
	claim *Claim,
	transaction *ResourceTransaction,
	plan Plan,
	agreement PeerAgreement,
) (*Execution, error) {
	if i == nil || i.token == nil || claim == nil || transaction == nil || transaction.token == nil {
		return nil, ErrAuthorityIssuerMismatch
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if plan.Operation == 0 {
		return nil, ErrBaselinePlan
	}
	nowNano := time.Now().UnixNano()
	if plan.Deadline.UnixNano() <= nowNano {
		return nil, ErrPlanExpired
	}
	if !plan.ProbeReferences.validFor(plan.Operation, plan.EndpointGeneration, nowNano, plan.Deadline.UnixNano(), true) ||
		!plan.ProbeReferences.matchesCurrentExecutionContext() ||
		!plan.ProbeReferences.matchesCurrentPlatform(context.Background()) {
		return nil, ErrAuthorityStale
	}
	if err := validatePeerAgreement(plan, agreement); err != nil {
		return nil, err
	}
	if plan.attempt == nil || !plan.attempt.evidenceCurrent() {
		return nil, ErrAuthorityStale
	}

	claim.mu.Lock()
	resource := claim.resource
	if resource == nil {
		claim.mu.Unlock()
		return nil, ErrAuthorityStale
	}
	resource.mu.Lock()
	token := transaction.token
	if claim.issuer != i.token {
		resource.mu.Unlock()
		claim.mu.Unlock()
		return nil, ErrAuthorityIssuerMismatch
	}
	if token != claim.activeTransaction || token.claim != claim || token.resource != resource ||
		token.plan != plan || !token.activeLocked() {
		resource.mu.Unlock()
		claim.mu.Unlock()
		return nil, ErrAuthorityStale
	}
	if token.executionIssued {
		resource.mu.Unlock()
		claim.mu.Unlock()
		return nil, ErrAuthorityConsumed
	}
	if agreement.Generation != token.generation || agreement.Generation != plan.BaseGeneration+1 {
		resource.mu.Unlock()
		claim.mu.Unlock()
		return nil, fmt.Errorf("%w: generation %d does not match transaction generation %d", ErrInvalidPeerAgreement, agreement.Generation, token.generation)
	}
	if !claim.currentForPlanLocked(plan) || plan.attempt == nil ||
		!sameInterfaceIdentity(plan.attempt.driver, claim.driver) || interfaceIsNil(plan.attempt.attempt) {
		resource.mu.Unlock()
		claim.mu.Unlock()
		return nil, ErrAuthorityStale
	}
	if err := token.stageExecutionLocked(); err != nil {
		resource.mu.Unlock()
		claim.mu.Unlock()
		return nil, err
	}
	token.executionIssued = true
	request := ExecutionRequest{Plan: plan, Facts: claim.facts, Agreement: agreement}
	attempt := plan.attempt.attempt
	resource.mu.Unlock()
	claim.mu.Unlock()
	return newExecution(attempt, request, claim, i.token, token), nil
}

func validatePeerAgreement(plan Plan, agreement PeerAgreement) error {
	binding := agreement.Binding
	if err := binding.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPeerAgreement, err)
	}
	if agreement.Generation != plan.BaseGeneration+1 || agreement.ActorEndpointGeneration != plan.EndpointGeneration ||
		agreement.PeerEndpointGeneration == 0 || agreement.ActorPlanDigest != proto.LeafMobilityPlanDigest(plan.LocalDigest) ||
		agreement.ProposalDigest == (proto.LeafMobilityProposalDigest{}) ||
		agreement.PeerPlanDigest == (proto.LeafMobilityPeerDigest{}) ||
		agreement.AgreementDigest == (proto.LeafMobilityAgreementDigest{}) ||
		agreement.ReservationID == (proto.LeafMobilityReservationID{}) {
		return ErrInvalidPeerAgreement
	}
	if binding.Direction != plan.Direction || binding.SessionKind != protocolSession(plan.Session) ||
		binding.Operation != protocolOperation(plan.Operation) || binding.Fallback != proto.LeafMobilityFallbackRedialAttach ||
		binding.SessionEpoch != proto.SessionEpoch(plan.Binding.FlowID) || binding.TransactionID != [16]byte(plan.TransactionID) ||
		binding.BaseGeneration != plan.BaseGeneration || binding.ResourceScope != protocolScope(plan.Scope) ||
		binding.ResourceID != proto.LeafMobilityResourceID(plan.ResourceID) {
		return ErrInvalidPeerAgreement
	}
	clientTarget, serverTarget := proto.TargetID(plan.Binding.LocalTargetID), proto.TargetID(plan.Binding.PeerTargetID)
	if binding.ActorSide == proto.LeafMobilityActorServer {
		clientTarget, serverTarget = serverTarget, clientTarget
	}
	if binding.SubjectClientTargetID != clientTarget || binding.SubjectServerTargetID != serverTarget {
		return ErrInvalidPeerAgreement
	}
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     agreement.ActorEndpointGeneration,
		ActorPlanDigest:             agreement.ActorPlanDigest,
	}
	proposal, err := prepare.ProposalDigest()
	if err != nil || proposal != agreement.ProposalDigest {
		return ErrInvalidPeerAgreement
	}
	digest, err := proto.ComputeLeafMobilityAgreementDigest(
		binding, agreement.Generation, agreement.ActorEndpointGeneration,
		agreement.PeerEndpointGeneration, agreement.ProposalDigest, agreement.PeerPlanDigest,
		agreement.ReservationID,
	)
	if err != nil || digest != agreement.AgreementDigest {
		return ErrInvalidPeerAgreement
	}
	return nil
}

func protocolSession(session Session) proto.LeafMobilitySessionKind {
	switch session {
	case SessionStream:
		return proto.LeafMobilitySessionStream
	case SessionPacket:
		return proto.LeafMobilitySessionPacket
	default:
		return proto.LeafMobilitySessionInvalid
	}
}

func protocolOperation(operation Operation) proto.LeafMobilityOperation {
	switch operation {
	case OperationTCPRepair:
		return proto.LeafMobilityOperationTCPRepair
	case OperationQUICCIDRebind:
		return proto.LeafMobilityOperationQUICCIDRebind
	case OperationUDPFlowRebind:
		return proto.LeafMobilityOperationUDPFlowRebind
	case OperationGVisorLinkRebind:
		return proto.LeafMobilityOperationGVisorLinkRebind
	default:
		return proto.LeafMobilityOperationInvalid
	}
}

func protocolScope(scope Scope) proto.LeafMobilityResourceScope {
	switch scope {
	case ScopeEndpoint:
		return proto.LeafMobilityResourceEndpoint
	case ScopeSharedLink:
		return proto.LeafMobilityResourceSharedLink
	case ScopeProcessLocal:
		return proto.LeafMobilityResourceProcessLocal
	default:
		return proto.LeafMobilityResourceInvalid
	}
}
