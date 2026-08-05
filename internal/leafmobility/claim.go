package leafmobility

import (
	"errors"
	"fmt"
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
	OperationUDPFlowRebind    Operation = 1 << 1
	OperationQUICCIDRebind    Operation = 1 << 2
	OperationGVisorLinkRebind Operation = 1 << 3
	knownOperations                     = OperationTCPRepair | OperationUDPFlowRebind | OperationQUICCIDRebind | OperationGVisorLinkRebind
)

// Has reports whether all requested non-zero operations are present.
func (o Operation) Has(requested Operation) bool {
	return requested != 0 && o&requested == requested
}

// Facts is an immutable-by-convention ownership snapshot.
type Facts struct {
	Kind       Kind
	Role       Role
	Scope      Scope
	Session    Session
	Operations Operation
	Generation uint64
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
	ErrInvalidFacts    = errors.New("leafmobility: invalid facts")
	ErrInvalidBinding  = errors.New("leafmobility: invalid binding")
	ErrAlreadyBound    = errors.New("leafmobility: claim already bound")
	ErrNotBound        = errors.New("leafmobility: claim is not bound")
	ErrBindingMismatch = errors.New("leafmobility: binding mismatch")
	ErrRetired         = errors.New("leafmobility: claim is retired")
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

// Claim is a pointer-owned, single-bind ownership claim.
type Claim struct {
	noCopy noCopy
	facts  Facts

	mu      sync.RWMutex
	binding Binding
	bound   bool
	retired bool
}

// NewClaim validates facts and returns a new unbound claim.
func NewClaim(facts Facts) (*Claim, error) {
	if err := validateFacts(facts); err != nil {
		return nil, err
	}
	return &Claim{facts: facts}, nil
}

// MustNewClaim is NewClaim for adapter facts that cannot be invalid at runtime.
func MustNewClaim(facts Facts) *Claim {
	claim, err := NewClaim(facts)
	if err != nil {
		panic(err)
	}
	return claim
}

// Snapshot returns a value copy of the claimed facts.
func (c *Claim) Snapshot() Facts {
	return c.facts
}

// Bind binds the claim exactly once.
func (c *Claim) Bind(binding Binding) error {
	if err := validateBinding(binding); err != nil {
		return err
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
	return nil
}

// Retire invalidates the claim only for its exact bound owner. Repeating the
// same retirement is idempotent; a stale or copied binding cannot retire a
// newer owner.
func (c *Claim) Retire(binding Binding) error {
	if err := validateBinding(binding); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.bound {
		return ErrNotBound
	}
	if c.binding != binding {
		return ErrBindingMismatch
	}
	c.retired = true
	return nil
}

// RetireUnbound invalidates a path that never entered engine ownership. It
// cannot retire a bound claim, so adapter cleanup cannot revoke another slot
// through a copied wrapper.
func (c *Claim) RetireUnbound() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bound {
		return false
	}
	c.retired = true
	return true
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
