package leafmobility

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

var (
	ErrInvalidResource         = errors.New("leafmobility: invalid resource handle")
	ErrResourceAdmissionActive = errors.New("leafmobility: resource admission already active")
	ErrResourceOutcomeUnknown  = errors.New("leafmobility: resource outcome is unknown")
)

// Resource is a sealed, copy-safe handle owned by the implementation that
// actually controls an endpoint, shared link, or process-local stack. Claims
// for the same physical resource must receive copies of this handle; callers
// cannot choose or reuse its identity.
type Resource struct {
	state *resourceState
}

type ResourceSnapshot struct {
	Scope      Scope
	ID         ResourceID
	Generation uint64
	Poisoned   bool
}

func NewResource(scope Scope) (Resource, error) {
	if scope != ScopeEndpoint && scope != ScopeSharedLink && scope != ScopeProcessLocal {
		return Resource{}, fmt.Errorf("%w: scope %d", ErrInvalidResource, scope)
	}
	var id ResourceID
	if _, err := rand.Read(id[:]); err != nil {
		return Resource{}, fmt.Errorf("%w: generate identity: %v", ErrInvalidResource, err)
	}
	if id == (ResourceID{}) {
		return Resource{}, fmt.Errorf("%w: generated zero identity", ErrInvalidResource)
	}
	return Resource{state: &resourceState{scope: scope, id: id}}, nil
}

func MustNewResource(scope Scope) Resource {
	resource, err := NewResource(scope)
	if err != nil {
		panic(err)
	}
	return resource
}

func (r Resource) Snapshot() ResourceSnapshot {
	if r.state == nil {
		return ResourceSnapshot{}
	}
	r.state.mu.Lock()
	poisoned := r.state.poisoned
	if transaction := r.state.transaction; transaction != nil &&
		transaction.state == ResourceTransactionOutcomeUnknown {
		poisoned = true
	}
	snapshot := ResourceSnapshot{
		Scope: r.state.scope, ID: r.state.id, Generation: r.state.generation, Poisoned: poisoned,
	}
	r.state.mu.Unlock()
	return snapshot
}

type resourceState struct {
	mu          sync.Mutex
	scope       Scope
	id          ResourceID
	generation  uint64
	transaction *resourceTransactionToken
	admission   *resourceAdmissionToken
	poisoned    bool
	poisonedBy  *resourceAdmissionToken
}

func (r *resourceState) currentGeneration() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	generation := r.generation
	r.mu.Unlock()
	return generation
}

type AdmissionReservation struct {
	token *resourceAdmissionToken
}

type resourceAdmissionToken struct {
	resources []*resourceState
	state     atomic.Uint32
}

const (
	resourceAdmissionIssued   uint32 = 1
	resourceAdmissionDone     uint32 = 2
	resourceAdmissionPoisoned uint32 = 3
)

// ReserveAdmissions atomically excludes specialized transactions on every
// resource touched by a path admission. Duplicate claims/resources collapse to
// one lock domain; resources are locked by immutable ID to avoid lock cycles.
func ReserveAdmissions(claims ...*Claim) (*AdmissionReservation, error) {
	resources := make([]*resourceState, 0, len(claims))
	seen := make(map[*resourceState]struct{}, len(claims))
	for _, claim := range claims {
		if claim == nil {
			continue
		}
		claim.mu.RLock()
		resource := claim.resource
		retired := claim.retired
		claim.mu.RUnlock()
		if retired {
			return nil, ErrAuthorityStale
		}
		if resource == nil {
			continue
		}
		if _, exists := seen[resource]; exists {
			continue
		}
		seen[resource] = struct{}{}
		resources = append(resources, resource)
	}
	if len(resources) == 0 {
		return nil, nil
	}
	sort.Slice(resources, func(i, j int) bool { return bytes.Compare(resources[i].id[:], resources[j].id[:]) < 0 })
	lockResources(resources)
	defer unlockResources(resources)
	for _, resource := range resources {
		if resource.poisoned {
			return nil, ErrResourceOutcomeUnknown
		}
		if resource.transaction != nil {
			return nil, ErrAuthorityActive
		}
		if resource.admission != nil {
			return nil, ErrResourceAdmissionActive
		}
	}
	token := &resourceAdmissionToken{resources: resources}
	token.state.Store(resourceAdmissionIssued)
	for _, resource := range resources {
		resource.admission = token
	}
	return &AdmissionReservation{token: token}, nil
}

func (r *AdmissionReservation) Active() bool {
	return r != nil && r.token != nil && r.token.state.Load() == resourceAdmissionIssued
}

func (r *AdmissionReservation) Release() {
	if r == nil || r.token == nil || r.token.state.Load() != resourceAdmissionIssued {
		return
	}
	token := r.token
	lockResources(token.resources)
	if token.state.CompareAndSwap(resourceAdmissionIssued, resourceAdmissionDone) {
		for _, resource := range token.resources {
			if resource.admission == token {
				resource.admission = nil
			}
		}
	}
	unlockResources(token.resources)
}

// Poison converts an unresolved peer execution guard into a persistent
// fail-closed resource state. It is used only after the peer may have obtained
// execution authority and no correlated RELEASED resolution was observed.
func (r *AdmissionReservation) Poison() {
	if r == nil || r.token == nil || r.token.state.Load() != resourceAdmissionIssued {
		return
	}
	token := r.token
	lockResources(token.resources)
	if token.state.CompareAndSwap(resourceAdmissionIssued, resourceAdmissionPoisoned) {
		for _, resource := range token.resources {
			if resource.admission == token {
				resource.admission = nil
				resource.poisoned = true
				resource.poisonedBy = token
			}
		}
	}
	unlockResources(token.resources)
}

// ReconcilePoison clears only the fail-closed state installed by this exact
// reservation. It is valid after correlated terminal evidence resolves an
// outcome that was unknown when the reservation deadline expired.
func (r *AdmissionReservation) ReconcilePoison() bool {
	if r == nil || r.token == nil || r.token.state.Load() != resourceAdmissionPoisoned {
		return false
	}
	token := r.token
	lockResources(token.resources)
	reconciled := token.state.CompareAndSwap(resourceAdmissionPoisoned, resourceAdmissionDone)
	if reconciled {
		for _, resource := range token.resources {
			if resource.poisonedBy == token {
				resource.poisoned = false
				resource.poisonedBy = nil
			}
		}
	}
	unlockResources(token.resources)
	return reconciled
}

func lockResources(resources []*resourceState) {
	for _, resource := range resources {
		resource.mu.Lock()
	}
}

func unlockResources(resources []*resourceState) {
	for i := len(resources) - 1; i >= 0; i-- {
		resources[i].mu.Unlock()
	}
}
