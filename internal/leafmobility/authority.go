package leafmobility

import (
	"errors"
	"fmt"
	"time"
)

type ResourceTransactionState uint8

const (
	ResourceTransactionInvalid         ResourceTransactionState = 0
	ResourceTransactionProposed        ResourceTransactionState = 1
	ResourceTransactionPrepared        ResourceTransactionState = 2
	ResourceTransactionCommitPublished ResourceTransactionState = 3
	ResourceTransactionFinalAccepted   ResourceTransactionState = 4
	ResourceTransactionFinalRejected   ResourceTransactionState = 5
	ResourceTransactionConsumed        ResourceTransactionState = 6
	ResourceTransactionResolving       ResourceTransactionState = 7
	ResourceTransactionCompleted       ResourceTransactionState = 8
	ResourceTransactionRolledBack      ResourceTransactionState = 9
	ResourceTransactionAborted         ResourceTransactionState = 10
	ResourceTransactionExpired         ResourceTransactionState = 11
	ResourceTransactionOutcomeUnknown  ResourceTransactionState = 12
	ResourceTransactionRevoked         ResourceTransactionState = 13
)

type Resolution uint8

const (
	ResolutionInvalid    Resolution = 0
	ResolutionComplete   Resolution = 1
	ResolutionRolledBack Resolution = 2
)

var (
	ErrAuthorityActive           = errors.New("leafmobility: resource transaction already active")
	ErrAuthorityStale            = errors.New("leafmobility: resource transaction is stale")
	ErrAuthorityRevoked          = errors.New("leafmobility: resource transaction is revoked")
	ErrAuthorityExpired          = errors.New("leafmobility: resource transaction expired")
	ErrAuthorityConsumed         = errors.New("leafmobility: resource transaction already consumed")
	ErrResourceTransactionState  = errors.New("leafmobility: invalid resource transaction state")
	ErrTransactionOutcomeUnknown = errors.New("leafmobility: resource transaction outcome is unknown")
	ErrPeerAgreementRejected     = errors.New("leafmobility: peer rejected resource transaction")
)

// ResourceTransaction is a copy-safe resource exclusion and state token. It is
// not execution authority and must never be accepted by a specialized driver.
// The engine owns peer evidence and may record validated wire transitions here;
// only the engine may mint its own route-ledger-bound execution capability.
type ResourceTransaction struct {
	token *resourceTransactionToken
}

type resourceTransactionToken struct {
	claim             *Claim
	resource          *resourceState
	plan              Plan
	deadline          time.Time
	generation        uint64
	resolution        Resolution
	unknownFrom       ResourceTransactionState
	state             ResourceTransactionState
	proposalPublished bool
	executionIssued   bool
	expiry            *time.Timer
}

type ResourceTransactionSnapshot struct {
	State       ResourceTransactionState
	Plan        Plan
	Deadline    time.Time
	Generation  uint64
	Resolution  Resolution
	UnknownFrom ResourceTransactionState
}

// MarkProposalPublished records the conservative point after which the peer
// may have observed PREPARE. Every such attempt consumes one resource
// generation, including abort and expiry, so delayed transactions cannot
// reuse an old base generation.
func (t *ResourceTransaction) MarkProposalPublished() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if token.state != ResourceTransactionProposed || !token.activeLocked() {
		return ErrResourceTransactionState
	}
	token.proposalPublished = true
	return nil
}

// ReserveResourceTransaction creates the local, pre-wire exclusivity token.
// Holding it before PREPARE prevents two engines sharing one physical resource
// from advertising reservations they cannot both honor.
func (c *Claim) ReserveResourceTransaction(plan Plan) (*ResourceTransaction, error) {
	if c == nil {
		return nil, ErrAuthorityStale
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if plan.Operation == 0 {
		return nil, ErrBaselinePlan
	}
	now := time.Now()
	if !plan.Deadline.After(now) {
		return nil, ErrPlanExpired
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentForPlanLocked(plan) {
		return nil, ErrAuthorityStale
	}
	resource := c.resource
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.poisoned {
		return nil, ErrResourceOutcomeUnknown
	}
	if c.activeTransaction != nil || resource.transaction != nil {
		return nil, ErrAuthorityActive
	}
	if resource.admission != nil {
		return nil, ErrResourceAdmissionActive
	}
	if plan.BaseGeneration != resource.generation || resource.generation == ^uint64(0) {
		return nil, fmt.Errorf("%w: plan generation %d does not match resource generation %d", ErrAuthorityStale, plan.BaseGeneration, resource.generation)
	}
	token := &resourceTransactionToken{
		claim: c, resource: resource, plan: plan, deadline: plan.Deadline,
		state: ResourceTransactionProposed,
	}
	c.activeTransaction = token
	resource.transaction = token
	token.expiry = time.AfterFunc(time.Until(plan.Deadline), token.expire)
	return &ResourceTransaction{token: token}, nil
}

func (t *ResourceTransaction) State() ResourceTransactionState {
	if t == nil || t.token == nil {
		return ResourceTransactionInvalid
	}
	token := t.token
	token.claim.mu.Lock()
	token.resource.mu.Lock()
	if !token.deadline.After(time.Now()) {
		token.expireLocked()
	}
	state := token.state
	token.resource.mu.Unlock()
	token.claim.mu.Unlock()
	return state
}

func (t *ResourceTransaction) Snapshot() ResourceTransactionSnapshot {
	if t == nil || t.token == nil {
		return ResourceTransactionSnapshot{}
	}
	token := t.token
	token.claim.mu.Lock()
	token.resource.mu.Lock()
	if !token.deadline.After(time.Now()) {
		token.expireLocked()
	}
	snapshot := ResourceTransactionSnapshot{
		State: token.state, Plan: token.plan, Deadline: token.deadline,
		Generation: token.generation, Resolution: token.resolution,
		UnknownFrom: token.unknownFrom,
	}
	token.resource.mu.Unlock()
	token.claim.mu.Unlock()
	return snapshot
}

// MarkPrepared records a route-ledger-validated PREPARED receipt. deadline is
// the immutable minimum of the local plan and the first peer lease observation.
func (t *ResourceTransaction) MarkPrepared(generation uint64, deadline time.Time) error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if token.state != ResourceTransactionProposed || !token.activeLocked() {
		return ErrResourceTransactionState
	}
	if generation != token.plan.BaseGeneration+1 || !deadline.After(time.Now()) || deadline.After(token.plan.Deadline) {
		return ErrAuthorityStale
	}
	token.generation = generation
	token.deadline = deadline
	if token.expiry != nil {
		token.expiry.Stop()
	}
	token.expiry = time.AfterFunc(time.Until(deadline), token.expire)
	token.state = ResourceTransactionPrepared
	return nil
}

// MarkCommitPublished records the replay-ledger publication linearization
// point. It does not establish peer agreement or authorize driver execution.
func (t *ResourceTransaction) MarkCommitPublished() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if !token.deadline.After(time.Now()) {
		token.expireLocked()
		return ErrPlanExpired
	}
	if token.state != ResourceTransactionPrepared || !token.activeLocked() {
		return ErrResourceTransactionState
	}
	token.state = ResourceTransactionCommitPublished
	return nil
}

// MarkFinalAccepted records a correlated FINAL acceptance. This advances the
// resource generation but intentionally returns no execution capability.
func (t *ResourceTransaction) MarkFinalAccepted() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if token.state != ResourceTransactionCommitPublished || !token.activeLocked() {
		return ErrResourceTransactionState
	}
	if err := token.consumeGenerationLocked(); err != nil {
		return err
	}
	token.state = ResourceTransactionFinalAccepted
	return nil
}

// MarkFinalRejected records a correlated FINAL rejection and releases the
// resource. A published generation is consumed even when the peer rejects it.
func (t *ResourceTransaction) MarkFinalRejected() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if token.state != ResourceTransactionCommitPublished || !token.activeLocked() {
		return ErrResourceTransactionState
	}
	if err := token.consumeGenerationLocked(); err != nil {
		return err
	}
	token.clearLocked(ResourceTransactionFinalRejected)
	return nil
}

// ReconcileFinalAccepted records a late, correlated FINAL acceptance after the
// COMMIT outcome became unknown. The transaction stays held and cannot be
// consumed after its immutable deadline; the engine must resolve it without
// execution.
func (t *ResourceTransaction) ReconcileFinalAccepted() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if token.state != ResourceTransactionOutcomeUnknown ||
		token.unknownFrom != ResourceTransactionCommitPublished || !token.activeLocked() {
		return ErrResourceTransactionState
	}
	if err := token.consumeGenerationLocked(); err != nil {
		return err
	}
	token.unknownFrom = ResourceTransactionInvalid
	token.state = ResourceTransactionFinalAccepted
	return nil
}

// ReconcileFinalRejected releases a fail-closed transaction when a late,
// correlated FINAL rejection proves that the peer issued no execution right.
func (t *ResourceTransaction) ReconcileFinalRejected() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if token.state != ResourceTransactionOutcomeUnknown ||
		token.unknownFrom != ResourceTransactionCommitPublished || !token.activeLocked() {
		return ErrResourceTransactionState
	}
	if err := token.consumeGenerationLocked(); err != nil {
		return err
	}
	token.clearLocked(ResourceTransactionFinalRejected)
	return nil
}

// consumeWithoutExecution exists only for package-local resource-state tests.
// Production crosses this boundary through AuthorityIssuer.ConsumeExecution,
// which additionally binds exact peer and driver evidence.
func (t *ResourceTransaction) consumeWithoutExecution() error {
	if t == nil || t.token == nil {
		return ErrAuthorityStale
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	return token.consumeLocked()
}

func (t *resourceTransactionToken) consumeLocked() error {
	switch t.state {
	case ResourceTransactionConsumed:
		return ErrAuthorityConsumed
	case ResourceTransactionOutcomeUnknown:
		return ErrTransactionOutcomeUnknown
	case ResourceTransactionFinalAccepted:
		if !t.activeLocked() || !t.claim.currentForPlanLocked(t.plan) {
			_ = t.markOutcomeUnknownLocked()
			return ErrAuthorityStale
		}
		if !t.deadline.After(time.Now()) {
			_ = t.markOutcomeUnknownLocked()
			return ErrAuthorityExpired
		}
		t.state = ResourceTransactionConsumed
		return nil
	default:
		return ErrAuthorityStale
	}
}

// BeginResolution records the engine's selected terminal driver outcome.
// FinalAccepted may only enter a no-execution rollback. A consumed transaction
// may complete or roll back. Deterministic cleanup may also resume from the
// corresponding fail-closed state after the immutable deadline.
func (t *ResourceTransaction) BeginResolution(resolution Resolution) error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	if resolution != ResolutionComplete && resolution != ResolutionRolledBack {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if !token.activeLocked() {
		return ErrResourceTransactionState
	}
	switch token.state {
	case ResourceTransactionFinalAccepted:
		if resolution != ResolutionRolledBack {
			return ErrResourceTransactionState
		}
	case ResourceTransactionConsumed:
	case ResourceTransactionOutcomeUnknown:
		switch token.unknownFrom {
		case ResourceTransactionFinalAccepted:
			if resolution != ResolutionRolledBack {
				return ErrTransactionOutcomeUnknown
			}
		case ResourceTransactionConsumed:
		case ResourceTransactionResolving:
			if token.resolution == resolution {
				return nil
			}
			return ErrTransactionOutcomeUnknown
		default:
			return ErrTransactionOutcomeUnknown
		}
	default:
		return ErrResourceTransactionState
	}
	token.resolution = resolution
	token.unknownFrom = ResourceTransactionInvalid
	token.state = ResourceTransactionResolving
	return nil
}

// FinishResolution records a correlated RELEASED receipt and releases the
// resource. It can reconcile a late receipt after resolving became uncertain.
func (t *ResourceTransaction) FinishResolution(resolution Resolution) error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	if resolution != ResolutionComplete && resolution != ResolutionRolledBack {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	if !token.activeLocked() || token.resolution != resolution {
		return ErrResourceTransactionState
	}
	if token.state != ResourceTransactionResolving &&
		(token.state != ResourceTransactionOutcomeUnknown || token.unknownFrom != ResourceTransactionResolving) {
		return ErrResourceTransactionState
	}
	state := ResourceTransactionCompleted
	if resolution == ResolutionRolledBack {
		state = ResourceTransactionRolledBack
	}
	token.clearLocked(state)
	return nil
}

// Abort is safe only before COMMIT publication. Once publication is possible,
// the resource remains fail-closed until correlated terminal evidence arrives.
func (t *ResourceTransaction) Abort() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	switch token.state {
	case ResourceTransactionAborted:
		return nil
	case ResourceTransactionProposed, ResourceTransactionPrepared:
		if token.proposalPublished {
			if err := token.consumeGenerationLocked(); err != nil {
				return err
			}
		}
		token.clearLocked(ResourceTransactionAborted)
		return nil
	case ResourceTransactionCommitPublished, ResourceTransactionFinalAccepted,
		ResourceTransactionConsumed, ResourceTransactionResolving, ResourceTransactionOutcomeUnknown:
		return ErrTransactionOutcomeUnknown
	default:
		return ErrResourceTransactionState
	}
}

func (t *ResourceTransaction) MarkOutcomeUnknown() error {
	if t == nil || t.token == nil {
		return ErrResourceTransactionState
	}
	token := t.token
	token.claim.mu.Lock()
	defer token.claim.mu.Unlock()
	token.resource.mu.Lock()
	defer token.resource.mu.Unlock()
	return token.markOutcomeUnknownLocked()
}

func (t *resourceTransactionToken) markOutcomeUnknownLocked() error {
	switch t.state {
	case ResourceTransactionOutcomeUnknown:
		return nil
	case ResourceTransactionCommitPublished, ResourceTransactionFinalAccepted,
		ResourceTransactionConsumed, ResourceTransactionResolving:
		if err := t.consumeGenerationLocked(); err != nil {
			return err
		}
		if t.expiry != nil {
			t.expiry.Stop()
		}
		t.unknownFrom = t.state
		t.state = ResourceTransactionOutcomeUnknown
		return nil
	default:
		return ErrResourceTransactionState
	}
}

func (t *resourceTransactionToken) expire() {
	if t == nil || t.claim == nil || t.resource == nil {
		return
	}
	t.claim.mu.Lock()
	t.resource.mu.Lock()
	if !t.deadline.After(time.Now()) {
		t.expireLocked()
	}
	t.resource.mu.Unlock()
	t.claim.mu.Unlock()
}

func (t *resourceTransactionToken) expireLocked() {
	switch t.state {
	case ResourceTransactionProposed, ResourceTransactionPrepared:
		if t.proposalPublished {
			if err := t.consumeGenerationLocked(); err != nil {
				_ = t.markOutcomeUnknownLocked()
				return
			}
		}
		t.clearLocked(ResourceTransactionExpired)
	case ResourceTransactionCommitPublished, ResourceTransactionFinalAccepted,
		ResourceTransactionConsumed, ResourceTransactionResolving:
		_ = t.markOutcomeUnknownLocked()
	}
}

func (t *resourceTransactionToken) consumeGenerationLocked() error {
	want := t.generation
	if want == 0 {
		want = t.plan.BaseGeneration + 1
	}
	switch t.resource.generation {
	case t.plan.BaseGeneration:
		t.resource.generation = want
		return nil
	case want:
		return nil
	default:
		return fmt.Errorf("%w: resource generation changed from %d to %d", ErrAuthorityStale, t.plan.BaseGeneration, t.resource.generation)
	}
}

func (t *resourceTransactionToken) activeLocked() bool {
	return t.claim.activeTransaction == t && t.resource.transaction == t
}

func (t *resourceTransactionToken) clearLocked(state ResourceTransactionState) {
	if t.claim.activeTransaction == t {
		t.claim.activeTransaction = nil
	}
	if t.resource.transaction == t {
		t.resource.transaction = nil
	}
	if t.expiry != nil {
		t.expiry.Stop()
	}
	t.unknownFrom = ResourceTransactionInvalid
	t.state = state
}

func (c *Claim) currentForPlanLocked(plan Plan) bool {
	return !c.retired && c.bound && c.binding == plan.Binding && c.driver != nil && c.resource != nil &&
		c.facts.Generation == plan.EndpointGeneration && c.facts.Kind == plan.Kind &&
		c.facts.Role == plan.Role && c.facts.Scope == plan.Scope && c.facts.ResourceID == plan.ResourceID &&
		c.facts.Operations.Has(plan.Operation)
}

func (c *Claim) revokeResourceTransactionLocked() {
	if c.resource == nil || c.activeTransaction == nil {
		return
	}
	c.resource.mu.Lock()
	transaction := c.activeTransaction
	switch transaction.state {
	case ResourceTransactionProposed, ResourceTransactionPrepared:
		if transaction.proposalPublished {
			if err := transaction.consumeGenerationLocked(); err != nil {
				transaction.resource.poisoned = true
			}
		}
		transaction.clearLocked(ResourceTransactionRevoked)
	case ResourceTransactionCommitPublished, ResourceTransactionFinalAccepted,
		ResourceTransactionConsumed, ResourceTransactionResolving:
		_ = transaction.markOutcomeUnknownLocked()
	}
	c.resource.mu.Unlock()
}
