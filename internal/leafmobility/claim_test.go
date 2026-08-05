package leafmobility

import (
	"errors"
	"fmt"
	"testing"
)

func TestEnumValuesStable(t *testing.T) {
	tests := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"KindUnknown", uint64(KindUnknown), 0},
		{"KindRawTCP", uint64(KindRawTCP), 1},
		{"KindUDPFlow", uint64(KindUDPFlow), 2},
		{"KindQUIC", uint64(KindQUIC), 3},
		{"KindGVisor", uint64(KindGVisor), 4},
		{"RoleUnknown", uint64(RoleUnknown), 0},
		{"RoleDialer", uint64(RoleDialer), 1},
		{"RoleAcceptor", uint64(RoleAcceptor), 2},
		{"ScopeUnknown", uint64(ScopeUnknown), 0},
		{"ScopeEndpoint", uint64(ScopeEndpoint), 1},
		{"ScopeSharedLink", uint64(ScopeSharedLink), 2},
		{"ScopeProcessLocal", uint64(ScopeProcessLocal), 3},
		{"SessionAny", uint64(SessionAny), 0},
		{"SessionStream", uint64(SessionStream), 1},
		{"SessionPacket", uint64(SessionPacket), 2},
		{"OperationTCPRepair", uint64(OperationTCPRepair), 1},
		{"OperationQUICCIDRebind", uint64(OperationQUICCIDRebind), 2},
		{"OperationUDPFlowRebind", uint64(OperationUDPFlowRebind), 4},
		{"OperationGVisorLinkRebind", uint64(OperationGVisorLinkRebind), 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("value = %d, want %d", test.got, test.want)
			}
		})
	}
}

func TestOperationHas(t *testing.T) {
	operations := OperationTCPRepair | OperationQUICCIDRebind
	if !operations.Has(OperationTCPRepair) {
		t.Fatal("TCP repair operation not found")
	}
	if !operations.Has(OperationTCPRepair | OperationQUICCIDRebind) {
		t.Fatal("combined operation set not found")
	}
	if operations.Has(OperationUDPFlowRebind) {
		t.Fatal("unexpected UDP flow operation")
	}
	if operations.Has(0) {
		t.Fatal("zero must not be treated as an operation")
	}
}

func TestNewClaimRejectsInvalidFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Facts)
	}{
		{"unknown kind", func(f *Facts) { f.Kind = KindUnknown }},
		{"invalid kind", func(f *Facts) { f.Kind = Kind(255) }},
		{"unknown role", func(f *Facts) { f.Role = RoleUnknown }},
		{"invalid role", func(f *Facts) { f.Role = Role(255) }},
		{"unknown scope", func(f *Facts) { f.Scope = ScopeUnknown }},
		{"invalid scope", func(f *Facts) { f.Scope = Scope(255) }},
		{"invalid session", func(f *Facts) { f.Session = Session(255) }},
		{"unknown operation bit", func(f *Facts) { f.Operations |= Operation(1 << 7) }},
		{"zero generation", func(f *Facts) { f.Generation = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := testFacts()
			test.mutate(&facts)
			claim, err := NewClaim(facts)
			if !errors.Is(err, ErrInvalidFacts) {
				t.Fatalf("error = %v, want ErrInvalidFacts", err)
			}
			if claim != nil {
				t.Fatal("invalid facts returned a claim")
			}
		})
	}
}

func TestNewClaimAcceptsAnySessionAndNoOperations(t *testing.T) {
	facts := testFacts()
	facts.Session = SessionAny
	facts.Operations = 0
	if _, err := NewClaim(facts); err != nil {
		t.Fatalf("NewClaim() error = %v", err)
	}
}

func TestNewClaimRejectsOperationWithoutDriver(t *testing.T) {
	facts := testFacts()
	facts.Operations = OperationTCPRepair
	claim, err := NewClaim(facts)
	if !errors.Is(err, ErrDriverRequired) {
		t.Fatalf("NewClaim error=%v want=%v", err, ErrDriverRequired)
	}
	if claim != nil {
		t.Fatal("unbacked operation returned a claim")
	}
}

func TestMustNewClaim(t *testing.T) {
	claim := MustNewClaim(testFacts())
	if claim == nil {
		t.Fatal("MustNewClaim returned nil")
	}

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("MustNewClaim did not panic for invalid facts")
		} else if err, ok := recovered.(error); !ok || !errors.Is(err, ErrInvalidFacts) {
			t.Fatalf("panic = %v, want ErrInvalidFacts", recovered)
		}
	}()
	invalid := testFacts()
	invalid.Generation = 0
	MustNewClaim(invalid)
}

func TestClaimFactsAreDefensiveValues(t *testing.T) {
	facts := testFacts()
	want := facts
	claim, err := NewClaim(facts)
	if err != nil {
		t.Fatalf("NewClaim() error = %v", err)
	}

	facts.Kind = KindGVisor
	facts.Generation++
	if got := claim.Snapshot(); got != want {
		t.Fatalf("Snapshot() = %+v, want %+v", got, want)
	}

	snapshot := claim.Snapshot()
	snapshot.Role = RoleAcceptor
	snapshot.Generation++
	if got := claim.Snapshot(); got != want {
		t.Fatalf("Snapshot() after mutation = %+v, want %+v", got, want)
	}
}

func TestClaimBindOnce(t *testing.T) {
	claim := MustNewClaim(testFacts())
	if binding, ok := claim.Binding(); ok || binding != (Binding{}) {
		t.Fatalf("Binding() before bind = (%+v, %t), want zero, false", binding, ok)
	}

	binding := testBinding(1)
	want := binding
	if err := claim.Bind(binding); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	binding.FlowID[0]++
	binding.Owner++

	got, ok := claim.Binding()
	if !ok || got != want {
		t.Fatalf("Binding() = (%+v, %t), want (%+v, true)", got, ok, want)
	}
	got.LocalTargetID[0]++
	got, ok = claim.Binding()
	if !ok || got != want {
		t.Fatalf("Binding() after mutation = (%+v, %t), want (%+v, true)", got, ok, want)
	}

	if err := claim.Bind(want); !errors.Is(err, ErrAlreadyBound) {
		t.Fatalf("repeated Bind() error = %v, want ErrAlreadyBound", err)
	}
	if err := claim.Bind(testBinding(2)); !errors.Is(err, ErrAlreadyBound) {
		t.Fatalf("different Bind() error = %v, want ErrAlreadyBound", err)
	}
}

func TestClaimRejectsZeroBindingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"FlowID", func(b *Binding) { b.FlowID = [16]byte{} }},
		{"LocalTargetID", func(b *Binding) { b.LocalTargetID = [16]byte{} }},
		{"PeerTargetID", func(b *Binding) { b.PeerTargetID = [16]byte{} }},
		{"PathID", func(b *Binding) { b.PathID = 0 }},
		{"Owner", func(b *Binding) { b.Owner = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := MustNewClaim(testFacts())
			binding := testBinding(1)
			test.mutate(&binding)
			if err := claim.Bind(binding); !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("Bind() error = %v, want ErrInvalidBinding", err)
			}
			if binding, ok := claim.Binding(); ok || binding != (Binding{}) {
				t.Fatalf("invalid Bind changed state to (%+v, %t)", binding, ok)
			}
		})
	}
}

func TestClaimConcurrentBindHasOneWinner(t *testing.T) {
	claim := MustNewClaim(testFacts())
	const workers = 64

	start := make(chan struct{})
	results := make(chan error, workers)
	candidates := make(map[Binding]struct{}, workers)
	for i := 0; i < workers; i++ {
		binding := testBinding(byte(i + 1))
		candidates[binding] = struct{}{}
		go func() {
			<-start
			results <- claim.Bind(binding)
		}()
	}
	close(start)

	successes := 0
	for i := 0; i < workers; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAlreadyBound):
		default:
			t.Fatalf("Bind() error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful binds = %d, want 1", successes)
	}
	winner, ok := claim.Binding()
	if !ok {
		t.Fatal("claim is not bound")
	}
	if _, exists := candidates[winner]; !exists {
		t.Fatalf("binding winner %+v was not a candidate", winner)
	}
}

func TestNextGenerationIsNonZeroAndMonotonic(t *testing.T) {
	first := NextGeneration()
	second := NextGeneration()
	if first == 0 || second == 0 || second <= first {
		t.Fatalf("generations=%d,%d want non-zero increasing values", first, second)
	}
}

func TestClaimRetirementRequiresExactBinding(t *testing.T) {
	claim := MustNewClaim(testFacts())
	binding := testBinding(1)
	if err := claim.Retire(binding); !errors.Is(err, ErrNotBound) {
		t.Fatalf("unbound Retire error=%v want=%v", err, ErrNotBound)
	}
	if err := claim.Bind(binding); err != nil {
		t.Fatal(err)
	}
	stale := binding
	stale.Owner++
	if err := claim.Retire(stale); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("stale Retire error=%v want=%v", err, ErrBindingMismatch)
	}
	if claim.Retired() {
		t.Fatal("stale binding retired claim")
	}
	if err := claim.Retire(binding); err != nil {
		t.Fatal(err)
	}
	if err := claim.Retire(binding); err != nil {
		t.Fatalf("idempotent Retire error=%v", err)
	}
	if !claim.Retired() {
		t.Fatal("claim did not report retired")
	}
}

func TestRetiredClaimCannotBind(t *testing.T) {
	claim := MustNewClaim(testFacts())
	binding := testBinding(1)
	if err := claim.Bind(binding); err != nil {
		t.Fatal(err)
	}
	if err := claim.Retire(binding); err != nil {
		t.Fatal(err)
	}
	if err := claim.Bind(testBinding(2)); !errors.Is(err, ErrRetired) {
		t.Fatalf("Bind after Retire error=%v want=%v", err, ErrRetired)
	}
}

func TestRetireUnboundCannotRevokeBoundOwner(t *testing.T) {
	unbound := MustNewClaim(testFacts())
	if !unbound.RetireUnbound() || !unbound.Retired() {
		t.Fatal("unbound claim was not retired")
	}
	if err := unbound.Bind(testBinding(1)); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired unbound claim Bind error=%v want=%v", err, ErrRetired)
	}

	bound := MustNewClaim(testFacts())
	if err := bound.Bind(testBinding(2)); err != nil {
		t.Fatal(err)
	}
	if bound.RetireUnbound() || bound.Retired() {
		t.Fatal("RetireUnbound revoked a bound owner")
	}
}

func testFacts() Facts {
	return Facts{
		Kind:       KindRawTCP,
		Role:       RoleDialer,
		Scope:      ScopeEndpoint,
		Session:    SessionStream,
		Generation: 7,
	}
}

func testBinding(id byte) Binding {
	return Binding{
		FlowID:        [16]byte{id},
		LocalTargetID: [16]byte{id, 1},
		PeerTargetID:  [16]byte{id, 2},
		PathID:        uint32(id),
		Owner:         uint64(id),
	}
}

type testProvider struct {
	claim *Claim
}

func (p *testProvider) LeafMobilityClaim() *Claim {
	return p.claim
}

var _ Provider = (*testProvider)(nil)

func ExampleProvider() {
	provider := &testProvider{claim: MustNewClaim(testFacts())}
	fmt.Println(provider.LeafMobilityClaim().Snapshot().Kind)
	// Output: 1
}
