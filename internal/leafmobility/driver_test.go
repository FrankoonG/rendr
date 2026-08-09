package leafmobility

import (
	"context"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type fakeDriver struct {
	operation      Operation
	result         PreflightResult
	preErr         error
	waitForContext bool

	preflightCalls atomic.Int32
	lastPreflight  PreflightRequest
}

func (d *fakeDriver) Operation() Operation { return d.operation }

func (d *fakeDriver) Preflight(ctx context.Context, request PreflightRequest) (PreflightResult, error) {
	d.preflightCalls.Add(1)
	d.lastPreflight = request
	if d.waitForContext {
		<-ctx.Done()
	}
	return d.result, d.preErr
}

func TestNewDrivenClaimDerivesOperationFromDriver(t *testing.T) {
	tests := []struct {
		kind      Kind
		operation Operation
	}{
		{KindRawTCP, OperationTCPRepair},
		{KindQUIC, OperationQUICCIDRebind},
		{KindUDPFlow, OperationUDPFlowRebind},
		{KindGVisor, OperationGVisorLinkRebind},
	}
	for _, test := range tests {
		facts := testDrivenFacts()
		facts.Kind = test.kind
		driver := &fakeDriver{operation: test.operation}
		claim, err := NewDrivenClaim(facts, driver, MustNewResource(ScopeEndpoint))
		if err != nil {
			t.Fatalf("kind=%d operation=%#x: %v", test.kind, test.operation, err)
		}
		state := claim.State()
		if state.Facts.Operations != test.operation || !state.HasDriver {
			t.Fatalf("state=%+v want operation=%#x and driver", state, test.operation)
		}
	}
}

func TestProtocolOperationMappingIsExplicitAndStable(t *testing.T) {
	tests := []struct {
		wire      proto.LeafMobilitySet
		operation Operation
	}{
		{proto.LeafMobilityTCPRepair, OperationTCPRepair},
		{proto.LeafMobilityQUICCIDRebind, OperationQUICCIDRebind},
		{proto.LeafMobilityUDPFlowRebind, OperationUDPFlowRebind},
		{proto.LeafMobilityGVisorLinkRebind, OperationGVisorLinkRebind},
	}
	for _, test := range tests {
		if got := KnownOperationSetFromProtocol(test.wire | 1<<15); got != test.operation {
			t.Errorf("wire=%#x operation=%#x want=%#x", test.wire, got, test.operation)
		}
		gotWire, err := test.operation.ProtocolSet()
		if err != nil {
			t.Fatal(err)
		}
		if gotWire != test.wire {
			t.Errorf("operation=%#x wire=%#x want=%#x", test.operation, gotWire, test.wire)
		}
	}
	if _, err := Operation(1 << 7).ProtocolSet(); !errors.Is(err, ErrInvalidPlanRequest) {
		t.Fatalf("unknown operation error=%v want=%v", err, ErrInvalidPlanRequest)
	}
}

func TestCapabilityRequiresConcreteDriver(t *testing.T) {
	driver := &fakeDriver{operation: OperationTCPRepair}
	capability, err := CapabilityForDriver(driver)
	if err != nil || capability.Operation() != OperationTCPRepair {
		t.Fatalf("capability=%+v err=%v", capability, err)
	}
	var typedNil *fakeDriver
	if _, err := CapabilityForDriver(typedNil); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("typed nil capability error=%v want=%v", err, ErrInvalidDriver)
	}
}

func TestNewDrivenClaimRejectsForgedOrMismatchedDriver(t *testing.T) {
	facts := testDrivenFacts()
	resource := MustNewResource(ScopeEndpoint)
	var typedNil *fakeDriver
	tests := []struct {
		name     string
		facts    Facts
		driver   Driver
		resource Resource
	}{
		{name: "nil", facts: facts, resource: resource},
		{name: "typed nil", facts: facts, driver: typedNil, resource: resource},
		{name: "zero operation", facts: facts, driver: &fakeDriver{}, resource: resource},
		{name: "multiple operations", facts: facts, driver: &fakeDriver{operation: OperationTCPRepair | OperationQUICCIDRebind}, resource: resource},
		{name: "wrong kind", facts: facts, driver: &fakeDriver{operation: OperationQUICCIDRebind}, resource: resource},
		{name: "predeclared facts", facts: func() Facts {
			f := facts
			f.Operations = OperationTCPRepair
			return f
		}(), driver: &fakeDriver{operation: OperationTCPRepair}, resource: resource},
		{name: "predeclared resource", facts: func() Facts {
			f := facts
			f.Scope = ScopeEndpoint
			return f
		}(), driver: &fakeDriver{operation: OperationTCPRepair}, resource: resource},
		{name: "zero resource", facts: facts, driver: &fakeDriver{operation: OperationTCPRepair}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim, err := NewDrivenClaim(test.facts, test.driver, test.resource)
			if !errors.Is(err, ErrInvalidDriver) {
				t.Fatalf("error=%v want=%v", err, ErrInvalidDriver)
			}
			if claim != nil {
				t.Fatal("invalid driver returned a claim")
			}
		})
	}
}

func TestPlanCandidateRequiresExactSessionAndEndpointEvidence(t *testing.T) {
	evidence := EvidenceDigest{0xaa, 0xbb}
	driver := &fakeDriver{
		operation: OperationTCPRepair,
		result:    PreflightResult{Eligible: true, EvidenceDigest: evidence},
	}
	facts := testDrivenFacts()
	claim := MustNewDrivenClaim(facts, driver, MustNewResource(ScopeEndpoint))
	binding := testBinding(7)
	if err := claim.Bind(binding); err != nil {
		t.Fatal(err)
	}
	request := fixedPlanRequest(binding)
	plan, err := PlanCandidate(context.Background(), claim, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != OperationTCPRepair || plan.Fallback != FallbackRedialAttach ||
		plan.Reason != ReasonNone || plan.EndpointGeneration != facts.Generation ||
		plan.Kind != KindRawTCP || plan.Role != RoleDialer || plan.Scope != ScopeEndpoint ||
		plan.ResourceID == (ResourceID{}) ||
		plan.EvidenceDigest != evidence || plan.LocalDigest == (LocalPlanDigest{}) {
		t.Fatalf("specialized plan=%+v", plan)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if driver.preflightCalls.Load() != 1 || driver.lastPreflight.PlanRequest != request || driver.lastPreflight.Facts != claim.Snapshot() {
		t.Fatalf("preflight calls=%d request=%+v", driver.preflightCalls.Load(), driver.lastPreflight)
	}
	if err := claim.ValidatePlanCurrent(plan); err != nil {
		t.Fatalf("current plan: %v", err)
	}

	mutated := plan
	mutated.Binding.Owner++
	if err := mutated.Validate(); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("mutated plan error=%v want=%v", err, ErrInvalidPlan)
	}
	if err := claim.Retire(binding); err != nil {
		t.Fatal(err)
	}
	if err := claim.ValidatePlanCurrent(plan); !errors.Is(err, ErrStalePlan) {
		t.Fatalf("retired plan error=%v want=%v", err, ErrStalePlan)
	}
}

func TestPlanCandidateFallbacksDoNotCallDriverPrematurely(t *testing.T) {
	binding := testBinding(8)
	request := fixedPlanRequest(binding)
	evidence := EvidenceDigest{1}

	t.Run("unowned", func(t *testing.T) {
		plan, err := PlanCandidate(context.Background(), nil, request)
		assertFallbackPlan(t, plan, err, ReasonEndpointNotOwned, false)
	})

	t.Run("operation not qualified", func(t *testing.T) {
		claim := MustNewClaim(testFacts())
		if err := claim.Bind(binding); err != nil {
			t.Fatal(err)
		}
		plan, err := PlanCandidate(context.Background(), claim, request)
		assertFallbackPlan(t, plan, err, ReasonOperationNotQualified, false)
	})

	tests := []struct {
		name      string
		mutate    func(*PlanRequest)
		result    PreflightResult
		preErr    error
		want      Reason
		retryable bool
		wantCalls int32
	}{
		{name: "local unsupported", mutate: func(r *PlanRequest) { r.LocalSupport = 0 }, want: ReasonLocalUnsupported},
		{name: "peer unsupported", mutate: func(r *PlanRequest) { r.PeerSupport = 0 }, want: ReasonPeerUnsupported},
		{name: "session mismatch", mutate: func(r *PlanRequest) { r.Session = SessionPacket }, want: ReasonSessionMismatch},
		{name: "deadline expired", mutate: func(r *PlanRequest) { r.Deadline = time.Unix(1, 0) }, want: ReasonDeadlineExpired},
		{name: "preflight rejected", result: PreflightResult{Reason: ReasonPreflightRejected, Retryable: true}, want: ReasonPreflightRejected, retryable: true, wantCalls: 1},
		{name: "preflight failed", preErr: errors.New("probe failed"), want: ReasonPreflightFailed, wantCalls: 1},
		{name: "eligible", result: PreflightResult{Eligible: true, EvidenceDigest: evidence}, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := &fakeDriver{operation: OperationTCPRepair, result: test.result, preErr: test.preErr}
			claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
			if err := claim.Bind(binding); err != nil {
				t.Fatal(err)
			}
			candidate := request
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			plan, err := PlanCandidate(context.Background(), claim, candidate)
			if test.name == "eligible" {
				if err != nil || plan.Operation != OperationTCPRepair || plan.Reason != ReasonNone {
					t.Fatalf("eligible plan=%+v err=%v", plan, err)
				}
			} else {
				assertFallbackPlan(t, plan, err, test.want, test.retryable)
			}
			if got := driver.preflightCalls.Load(); got != test.wantCalls {
				t.Fatalf("preflight calls=%d want=%d", got, test.wantCalls)
			}
		})
	}
}

func TestPlanCandidateBoundsAndRechecksDeadline(t *testing.T) {
	binding := testBinding(11)
	request := fixedPlanRequest(binding)
	request.Deadline = time.Now().Add(MaxPlanHorizon + time.Second)
	if _, err := PlanCandidate(context.Background(), nil, request); !errors.Is(err, ErrInvalidPlanRequest) {
		t.Fatalf("oversized horizon error=%v want=%v", err, ErrInvalidPlanRequest)
	}

	driver := &fakeDriver{
		operation:      OperationTCPRepair,
		result:         PreflightResult{Eligible: true, EvidenceDigest: EvidenceDigest{1}},
		waitForContext: true,
	}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	if err := claim.Bind(binding); err != nil {
		t.Fatal(err)
	}
	request = fixedPlanRequest(binding)
	request.Deadline = time.Now().Add(5 * time.Millisecond)
	plan, err := PlanCandidate(context.Background(), claim, request)
	assertFallbackPlan(t, plan, err, ReasonDeadlineExpired, false)
}

func TestPlanCandidateHonorsParentCancellation(t *testing.T) {
	binding := testBinding(12)
	driver := &fakeDriver{
		operation: OperationTCPRepair,
		result:    PreflightResult{Eligible: true, EvidenceDigest: EvidenceDigest{1}},
	}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	if err := claim.Bind(binding); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan, err := PlanCandidate(ctx, claim, fixedPlanRequest(binding))
	assertFallbackPlan(t, plan, err, ReasonPreflightFailed, false)
	if driver.preflightCalls.Load() != 0 {
		t.Fatalf("preflight calls=%d want=0 for pre-canceled context", driver.preflightCalls.Load())
	}

	driver.waitForContext = true
	ctx, cancel = context.WithCancel(context.Background())
	result := make(chan Plan, 1)
	errs := make(chan error, 1)
	go func() {
		candidate, planErr := PlanCandidate(ctx, claim, fixedPlanRequest(binding))
		result <- candidate
		errs <- planErr
	}()
	deadline := time.Now().Add(time.Second)
	for driver.preflightCalls.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("preflight did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	plan = <-result
	err = <-errs
	assertFallbackPlan(t, plan, err, ReasonPreflightFailed, false)
}

func TestPlanDigestCanonicalGolden(t *testing.T) {
	binding := testBinding(9)
	plan := Plan{
		TransactionID:      TransactionID{0x41, 0x42},
		Binding:            binding,
		EndpointGeneration: 7,
		Direction:          proto.SenderDirectionClientToServer,
		Session:            SessionStream,
		Operation:          OperationTCPRepair,
		Fallback:           FallbackRedialAttach,
		Deadline:           time.Unix(2_000_000_000, 123_456_789),
		LocalSupport:       OperationTCPRepair,
		PeerSupport:        OperationTCPRepair,
		Kind:               KindRawTCP,
		Role:               RoleDialer,
		Scope:              ScopeEndpoint,
		ResourceID:         ResourceID{0x31, 0x32},
		EvidenceDigest:     EvidenceDigest{0xde, 0xad, 0xbe, 0xef},
	}
	plan.LocalDigest = digestPlan(plan)
	const want = "c88c384811a5af0eb71fef7c62d87bdb0f703d38be1dd67b8cf3d2ef4e496207"
	if got := hex.EncodeToString(plan.LocalDigest[:]); got != want {
		t.Fatalf("plan digest=%s want=%s", got, want)
	}
	nextGeneration := plan
	nextGeneration.BaseGeneration++
	if digestPlan(nextGeneration) == plan.LocalDigest {
		t.Fatal("resource base generation did not enter plan digest")
	}
}

func TestInvalidPreflightEvidenceFailsClosed(t *testing.T) {
	binding := testBinding(10)
	request := fixedPlanRequest(binding)
	tests := []PreflightResult{
		{Eligible: true},
		{Eligible: true, Reason: ReasonPreflightRejected, EvidenceDigest: EvidenceDigest{1}},
		{Eligible: true, Retryable: true, EvidenceDigest: EvidenceDigest{1}},
		{},
		{Reason: ReasonPreflightRejected, EvidenceDigest: EvidenceDigest{1}},
		{Reason: Reason(0xffff)},
	}
	for i, result := range tests {
		driver := &fakeDriver{operation: OperationTCPRepair, result: result}
		claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
		if err := claim.Bind(binding); err != nil {
			t.Fatal(err)
		}
		if _, err := PlanCandidate(context.Background(), claim, request); !errors.Is(err, ErrInvalidDriver) {
			t.Errorf("case %d error=%v want=%v", i, err, ErrInvalidDriver)
		}
	}
}

func fixedPlanRequest(binding Binding) PlanRequest {
	return PlanRequest{
		TransactionID: TransactionID{0x41, 0x42},
		Binding:       binding,
		Direction:     proto.SenderDirectionClientToServer,
		Session:       SessionStream,
		Deadline:      time.Now().Add(time.Minute),
		LocalSupport:  OperationTCPRepair,
		PeerSupport:   OperationTCPRepair,
	}
}

func assertFallbackPlan(t *testing.T, plan Plan, err error, reason Reason, retryable bool) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != 0 || plan.Fallback != FallbackRedialAttach || plan.Reason != reason || plan.Retryable != retryable {
		t.Fatalf("fallback plan=%+v want reason=%s retryable=%t", plan, reason, retryable)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("fallback Validate: %v", err)
	}
	if plan.LocalDigest == (LocalPlanDigest{}) {
		t.Fatal("fallback plan has zero digest")
	}
}
