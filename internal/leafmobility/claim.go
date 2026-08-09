package leafmobility

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)

// Kind identifies the implementation that owns a leaf.
type Kind uint8

const (
	KindUnknown Kind = 0
	KindRawTCP  Kind = 1
	KindUDPFlow Kind = 2
	KindQUIC    Kind = 3
	KindGVisor  Kind = 4
)

// Role identifies which side created the owned leaf.
type Role uint8

const (
	RoleUnknown  Role = 0
	RoleDialer   Role = 1
	RoleAcceptor Role = 2
)

// Scope identifies the resource covered by a claim.
type Scope uint8

const (
	ScopeUnknown      Scope = 0
	ScopeEndpoint     Scope = 1
	ScopeSharedLink   Scope = 2
	ScopeProcessLocal Scope = 3
)

// Session identifies the application contract supported by a leaf.
type Session uint8

const (
	SessionAny    Session = 0
	SessionStream Session = 1
	SessionPacket Session = 2
)

// Operation is a set of specialized operations an owner can provide.
type Operation uint8

const (
	OperationTCPRepair        Operation = 1 << 0
	OperationQUICCIDRebind    Operation = 1 << 1
	OperationUDPFlowRebind    Operation = 1 << 2
	OperationGVisorLinkRebind Operation = 1 << 3
	knownOperations                     = OperationTCPRepair | OperationUDPFlowRebind | OperationQUICCIDRebind | OperationGVisorLinkRebind
)

// Has reports whether all requested non-zero operations are present.
func (o Operation) Has(requested Operation) bool {
	return requested != 0 && o&requested == requested
}

// SupportsSession reports whether one specialized operation can preserve the
// requested application contract. SessionAny is ownership metadata, not a
// negotiable wire session, and is therefore never accepted here.
func (o Operation) SupportsSession(session Session) bool {
	if !o.single() {
		return false
	}
	switch o {
	case OperationTCPRepair, OperationGVisorLinkRebind:
		return session == SessionStream
	case OperationUDPFlowRebind:
		return session == SessionPacket
	case OperationQUICCIDRebind:
		return session == SessionStream || session == SessionPacket
	default:
		return false
	}
}

type ResourceID [16]byte

// Facts is an immutable-by-convention ownership snapshot.
type Facts struct {
	Kind       Kind
	Role       Role
	Scope      Scope
	Session    Session
	Operations Operation
	Generation uint64
	ResourceID ResourceID
}

// Binding ties a claim to one physical path generation.
type Binding struct {
	FlowID        [16]byte
	LocalTargetID [16]byte
	PeerTargetID  [16]byte
	PathID        uint32
	Owner         uint64
}

var (
	ErrInvalidFacts        = errors.New("leafmobility: invalid facts")
	ErrInvalidBinding      = errors.New("leafmobility: invalid binding")
	ErrAlreadyBound        = errors.New("leafmobility: claim already bound")
	ErrNotBound            = errors.New("leafmobility: claim is not bound")
	ErrBindingMismatch     = errors.New("leafmobility: binding mismatch")
	ErrRetired             = errors.New("leafmobility: claim is retired")
	ErrDriverRequired      = errors.New("leafmobility: specialized operation requires a driver")
	ErrInvalidDriver       = errors.New("leafmobility: invalid driver")
	ErrIncarnationUnproven = errors.New("leafmobility: physical endpoint incarnation was not proven")
)

var generationCounter atomic.Uint64

// NextGeneration returns a non-zero process-local endpoint generation. The
// session binding supplies restart uniqueness; this counter distinguishes
// replacements inside one process.
func NextGeneration() uint64 {
	for {
		if generation := generationCounter.Add(1); generation != 0 {
			return generation
		}
	}
}

// Provider exposes a sealed claim to other packages in this module.
type Provider interface {
	LeafMobilityClaim() *Claim
}

// IncarnationReporter is held by a driven Claim, not by one attempt. It lets
// execution compare the physical endpoint owner before and after a driver
// transition instead of trusting driver-local bookkeeping.
type IncarnationReporter interface {
	LeafMobilityIncarnation() uint64
}

// Claim is a pointer-owned, single-bind ownership claim.
type Claim struct {
	noCopy      noCopy
	facts       Facts
	driver      Driver
	incarnation IncarnationReporter
	resource    *resourceState
	issuer      *authorityIssuerToken

	executionMu       sync.Mutex
	executionActive   bool
	executionRetiring bool
	executionDone     chan struct{}

	mu                sync.RWMutex
	binding           Binding
	bound             bool
	retired           bool
	activeTransaction *resourceTransactionToken
}

// NewClaim validates facts and returns a new unbound claim.
func NewClaim(facts Facts) (*Claim, error) {
	if err := validateFacts(facts); err != nil {
		return nil, err
	}
	if facts.Operations != 0 {
		return nil, fmt.Errorf("%w: operations %#x", ErrDriverRequired, facts.Operations)
	}
	return &Claim{facts: facts}, nil
}

// NewDrivenClaim creates a claim whose specialized operation is backed by a
// concrete in-module driver. The operation comes from the driver rather than
// caller-supplied facts, so a descriptor cannot manufacture capability.
func NewDrivenClaim(facts Facts, driver Driver, resource Resource) (*Claim, error) {
	return newDrivenClaim(facts, driver, resource, nil)
}

// NewDrivenClaimWithIncarnation additionally binds the claim to the physical
// endpoint owner's monotonic incarnation reporter.
func NewDrivenClaimWithIncarnation(
	facts Facts,
	driver Driver,
	resource Resource,
	incarnation IncarnationReporter,
) (*Claim, error) {
	if interfaceIsNil(incarnation) {
		return nil, fmt.Errorf("%w: nil incarnation reporter", ErrInvalidDriver)
	}
	if _, ok := interfaceIdentity(incarnation); !ok {
		return nil, fmt.Errorf("%w: incarnation reporter must have stable pointer identity", ErrInvalidDriver)
	}
	if _, ok := readIncarnation(incarnation); !ok {
		return nil, ErrIncarnationUnproven
	}
	return newDrivenClaim(facts, driver, resource, incarnation)
}

func newDrivenClaim(facts Facts, driver Driver, resource Resource, incarnation IncarnationReporter) (*Claim, error) {
	if facts.Operations != 0 {
		return nil, fmt.Errorf("%w: facts must not predeclare operations %#x", ErrInvalidDriver, facts.Operations)
	}
	if facts.Scope != ScopeUnknown || facts.ResourceID != (ResourceID{}) {
		return nil, fmt.Errorf("%w: driven claim must derive resource facts from its owner", ErrInvalidDriver)
	}
	if resource.state == nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDriver, ErrInvalidResource)
	}
	facts.Scope = resource.state.scope
	facts.ResourceID = resource.state.id
	if err := validateFacts(facts); err != nil {
		return nil, err
	}
	if interfaceIsNil(driver) {
		return nil, fmt.Errorf("%w: nil driver", ErrInvalidDriver)
	}
	if _, ok := interfaceIdentity(driver); !ok {
		return nil, fmt.Errorf("%w: driver must have stable pointer identity", ErrInvalidDriver)
	}
	operation := driver.Operation()
	if !operation.single() {
		return nil, fmt.Errorf("%w: operation %#x is not one known operation", ErrInvalidDriver, operation)
	}
	if want := operationForKind(facts.Kind); operation != want {
		return nil, fmt.Errorf("%w: kind %d requires operation %#x, got %#x", ErrInvalidDriver, facts.Kind, want, operation)
	}
	facts.Operations = operation
	return &Claim{facts: facts, driver: driver, incarnation: incarnation, resource: resource.state}, nil
}

// MustNewClaim is NewClaim for adapter facts that cannot be invalid at runtime.
func MustNewClaim(facts Facts) *Claim {
	claim, err := NewClaim(facts)
	if err != nil {
		panic(err)
	}
	return claim
}

// MustNewDrivenClaim is NewDrivenClaim for adapter wiring that is fixed at
// construction time.
func MustNewDrivenClaim(facts Facts, driver Driver, resource Resource) *Claim {
	claim, err := NewDrivenClaim(facts, driver, resource)
	if err != nil {
		panic(err)
	}
	return claim
}

func MustNewDrivenClaimWithIncarnation(
	facts Facts,
	driver Driver,
	resource Resource,
	incarnation IncarnationReporter,
) *Claim {
	claim, err := NewDrivenClaimWithIncarnation(facts, driver, resource, incarnation)
	if err != nil {
		panic(err)
	}
	return claim
}

func readIncarnation(reporter IncarnationReporter) (value uint64, ok bool) {
	if interfaceIsNil(reporter) {
		return 0, false
	}
	defer func() {
		if recover() != nil {
			value, ok = 0, false
		}
	}()
	value = reporter.LeafMobilityIncarnation()
	return value, value != 0
}

func (c *Claim) endpointIncarnation() (uint64, bool) {
	if c == nil {
		return 0, false
	}
	c.mu.RLock()
	reporter := c.incarnation
	c.mu.RUnlock()
	return readIncarnation(reporter)
}

// Snapshot returns a value copy of the claimed facts.
func (c *Claim) Snapshot() Facts {
	if c == nil {
		return Facts{}
	}
	c.mu.RLock()
	facts := c.facts
	c.mu.RUnlock()
	return facts
}

// advanceEndpointGeneration records the physical incarnation created by one
// successful specialized commit. The bilateral transaction keeps its old
// generation as immutable evidence; only future plans observe this value.
func (c *Claim) advanceEndpointGeneration() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	current := c.facts.Generation
	generation := NextGeneration()
	for generation == current {
		generation = NextGeneration()
	}
	c.facts.Generation = generation
	c.mu.Unlock()
	return generation
}

// State returns one coherent ownership snapshot. Driver identity is exposed
// only as a boolean; this checkpoint exposes local candidate planning but no
// executable driver operation.
func (c *Claim) State() ClaimState {
	if c == nil {
		return ClaimState{Retired: true}
	}
	c.mu.RLock()
	state := ClaimState{
		Facts:     c.facts,
		Binding:   c.binding,
		Bound:     c.bound,
		Retired:   c.retired,
		HasDriver: c.driver != nil,
	}
	if c.resource != nil {
		state.BaseGeneration = c.resource.currentGeneration()
	}
	c.mu.RUnlock()
	return state
}

// Bind binds the claim exactly once.
func (c *Claim) Bind(binding Binding) error {
	if c != nil && c.driver != nil {
		return ErrAuthorityIssuerRequired
	}
	return c.bind(binding, nil)
}

func (c *Claim) bind(binding Binding, issuer *authorityIssuerToken) error {
	if err := validateBinding(binding); err != nil {
		return err
	}
	if c == nil {
		return ErrInvalidBinding
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retired {
		return ErrRetired
	}
	if c.bound {
		return ErrAlreadyBound
	}
	c.binding = binding
	c.bound = true
	c.issuer = issuer
	return nil
}

// Retire invalidates the claim only for its exact bound owner. Repeating the
// same retirement is idempotent; a stale or copied binding cannot retire a
// newer owner.
func (c *Claim) Retire(binding Binding) error {
	if err := c.RequestRetire(binding); err != nil {
		return err
	}
	c.waitExecutionQuiesced()
	return nil
}

// RequestRetire commits logical retirement without waiting for an in-flight
// driver attempt. It is safe under an engine topology lock: new executions
// are rejected immediately, while physical carrier cleanup must call Retire
// outside that lock to wait for rollback or commit.
func (c *Claim) RequestRetire(binding Binding) error {
	_, err := c.RequestRetireState(binding)
	return err
}

// RequestRetireState additionally reports whether carrier cleanup must wait
// for an active execution to publish or abandon its terminal outcome.
func (c *Claim) RequestRetireState(binding Binding) (bool, error) {
	if err := validateBinding(binding); err != nil {
		return false, err
	}
	if c == nil {
		return false, ErrInvalidBinding
	}
	c.executionMu.Lock()
	defer c.executionMu.Unlock()
	c.mu.Lock()
	if !c.bound {
		c.mu.Unlock()
		return false, ErrNotBound
	}
	if c.binding != binding {
		c.mu.Unlock()
		return false, ErrBindingMismatch
	}
	c.executionRetiring = true
	c.retired = true
	c.revokeResourceTransactionLocked()
	c.mu.Unlock()
	return c.executionActive, nil
}

// RetireUnbound invalidates a path that never entered engine ownership. It
// cannot retire a bound claim, so adapter cleanup cannot revoke another slot
// through a copied wrapper.
func (c *Claim) RetireUnbound() bool {
	if c == nil {
		return false
	}
	c.executionMu.Lock()
	c.mu.Lock()
	if c.bound {
		c.mu.Unlock()
		c.executionMu.Unlock()
		return false
	}
	c.executionRetiring = true
	c.retired = true
	c.revokeResourceTransactionLocked()
	c.mu.Unlock()
	done := c.executionDone
	c.executionMu.Unlock()
	if done != nil {
		<-done
	}
	return true
}

func (c *Claim) acquireExecutionLease() bool {
	if c == nil {
		return false
	}
	c.executionMu.Lock()
	defer c.executionMu.Unlock()
	if c.executionRetiring || c.executionActive {
		return false
	}
	c.executionActive = true
	c.executionDone = make(chan struct{})
	return true
}

func (c *Claim) releaseExecutionLease() {
	if c == nil {
		return
	}
	c.executionMu.Lock()
	if c.executionActive {
		c.executionActive = false
		close(c.executionDone)
		c.executionDone = nil
	}
	c.executionMu.Unlock()
}

func (c *Claim) waitExecutionQuiesced() {
	if c == nil {
		return
	}
	c.executionMu.Lock()
	done := c.executionDone
	c.executionMu.Unlock()
	if done != nil {
		<-done
	}
}

// Retired reports whether the bound endpoint has left engine ownership.
func (c *Claim) Retired() bool {
	if c == nil {
		return true
	}
	c.mu.RLock()
	retired := c.retired
	c.mu.RUnlock()
	return retired
}

// Binding returns a value copy of the binding when one has been installed.
func (c *Claim) Binding() (Binding, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binding, c.bound
}

// ExecutionGeneration is the last terminal peer-agreement generation of the
// claimed resource. Claims that share a link observe one generation.
func (c *Claim) ExecutionGeneration() uint64 {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	resource := c.resource
	c.mu.RUnlock()
	return resource.currentGeneration()
}

func validateFacts(facts Facts) error {
	switch facts.Kind {
	case KindRawTCP, KindUDPFlow, KindQUIC, KindGVisor:
	default:
		return fmt.Errorf("%w: kind %d", ErrInvalidFacts, facts.Kind)
	}
	switch facts.Role {
	case RoleDialer, RoleAcceptor:
	default:
		return fmt.Errorf("%w: role %d", ErrInvalidFacts, facts.Role)
	}
	switch facts.Scope {
	case ScopeEndpoint, ScopeSharedLink, ScopeProcessLocal:
	default:
		return fmt.Errorf("%w: scope %d", ErrInvalidFacts, facts.Scope)
	}
	switch facts.Session {
	case SessionAny, SessionStream, SessionPacket:
	default:
		return fmt.Errorf("%w: session %d", ErrInvalidFacts, facts.Session)
	}
	if facts.Operations&^knownOperations != 0 {
		return fmt.Errorf("%w: operations %#x", ErrInvalidFacts, facts.Operations)
	}
	if facts.Generation == 0 {
		return fmt.Errorf("%w: generation is zero", ErrInvalidFacts)
	}
	return nil
}

func (o Operation) single() bool {
	return o != 0 && o&^knownOperations == 0 && o&(o-1) == 0
}

func operationForKind(kind Kind) Operation {
	switch kind {
	case KindRawTCP:
		return OperationTCPRepair
	case KindUDPFlow:
		return OperationUDPFlowRebind
	case KindQUIC:
		return OperationQUICCIDRebind
	case KindGVisor:
		return OperationGVisorLinkRebind
	default:
		return 0
	}
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func interfaceIdentity(value any) (uintptr, bool) {
	if value == nil {
		return 0, false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Pointer || reflected.IsNil() {
		return 0, false
	}
	return reflected.Pointer(), true
}

func sameInterfaceIdentity(left, right any) bool {
	leftID, leftOK := interfaceIdentity(left)
	rightID, rightOK := interfaceIdentity(right)
	return leftOK && rightOK && leftID == rightID && reflect.TypeOf(left) == reflect.TypeOf(right)
}

func validateBinding(binding Binding) error {
	switch {
	case isZeroID(binding.FlowID):
		return fmt.Errorf("%w: FlowID is zero", ErrInvalidBinding)
	case isZeroID(binding.LocalTargetID):
		return fmt.Errorf("%w: LocalTargetID is zero", ErrInvalidBinding)
	case isZeroID(binding.PeerTargetID):
		return fmt.Errorf("%w: PeerTargetID is zero", ErrInvalidBinding)
	case binding.PathID == 0:
		return fmt.Errorf("%w: PathID is zero", ErrInvalidBinding)
	case binding.Owner == 0:
		return fmt.Errorf("%w: Owner is zero", ErrInvalidBinding)
	default:
		return nil
	}
}

func isZeroID(id [16]byte) bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
