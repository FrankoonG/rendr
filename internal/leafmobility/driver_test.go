package leafmobility

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/proto"
)

type fakeDriver struct {
	operation       Operation
	result          PreflightResult
	preErr          error
	waitForContext  bool
	preserveContext bool
	attempt         DriverAttempt
	mutateResult    func(PreflightRequest, *PreflightResult)

	preflightCalls atomic.Int32
	lastPreflight  PreflightRequest
}

func (d *fakeDriver) Operation() Operation { return d.operation }

func (d *fakeDriver) Preflight(ctx context.Context, request PreflightRequest) (DriverAttempt, PreflightResult, error) {
	d.preflightCalls.Add(1)
	d.lastPreflight = request
	if d.waitForContext {
		<-ctx.Done()
	}
	result := d.result
	if !d.preserveContext && result.ProbeReferences.count != 0 {
		result.ProbeReferences = testProbeReferencesForRequest(result.ProbeReferences, request)
	}
	if d.mutateResult != nil {
		d.mutateResult(request, &result)
	}
	if result.Eligible && d.preErr == nil {
		attempt := d.attempt
		if attempt == nil {
			attempt = &fakeDriverTransaction{evidence: AttemptEvidence{
				Digest: result.EvidenceDigest, ProbeReferences: result.ProbeReferences,
			}}
		} else if fixed, ok := attempt.(*fakeDriverTransaction); ok {
			fixed.evidence = AttemptEvidence{Digest: result.EvidenceDigest, ProbeReferences: result.ProbeReferences}
		}
		return attempt, result, nil
	}
	return nil, result, d.preErr
}

type fakeDriverTransaction struct {
	evidence AttemptEvidence
}

func (t *fakeDriverTransaction) Evidence() AttemptEvidence { return t.evidence }

func (*fakeDriverTransaction) Prepare(context.Context, ExecutionRequest) error { return nil }
func (*fakeDriverTransaction) Stage(context.Context, ExecutionRequest) (PublicationEvidence, error) {
	return PublicationEvidence{Digest: EvidenceDigest{0x51}}, nil
}
func (*fakeDriverTransaction) Publish(context.Context, ExecutionRequest) error  { return nil }
func (*fakeDriverTransaction) Activate(context.Context, ExecutionRequest) error { return nil }
func (*fakeDriverTransaction) Rollback(context.Context, ExecutionRequest) error { return nil }
func (*fakeDriverTransaction) FailClosed(context.Context, ExecutionRequest) error {
	return nil
}
func (*fakeDriverTransaction) EndpointGenerationChanged() bool { return false }

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

func TestDrivenClaimCannotBindWithoutEngineIssuer(t *testing.T) {
	driver := &fakeDriver{operation: OperationTCPRepair}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	binding := testBinding(33)
	if err := claim.Bind(binding); !errors.Is(err, ErrAuthorityIssuerRequired) {
		t.Fatalf("direct driven Bind=%v want=%v", err, ErrAuthorityIssuerRequired)
	}
	issuer := NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	if err := NewAuthorityIssuer().BindClaim(claim, binding); !errors.Is(err, ErrAlreadyBound) {
		t.Fatalf("second issuer BindClaim=%v want=%v", err, ErrAlreadyBound)
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

func TestTCPRepairEligibilityReasonsAndStagesAreStable(t *testing.T) {
	reasons := map[Reason]string{
		ReasonEndpointNotOwned:           "endpoint_not_owned",
		ReasonNotRawTCP:                  "not_raw_tcp",
		ReasonTCPStateIneligible:         "tcp_state_ineligible",
		ReasonKernelUnsupported:          "kernel_unsupported",
		ReasonPermissionDenied:           "permission_denied",
		ReasonStateAPIIncomplete:         "state_api_incomplete",
		ReasonTupleNotPreservable:        "tuple_not_preservable",
		ReasonTransparentBindUnavailable: "transparent_bind_unavailable",
		ReasonQuiesceFailed:              "quiesce_failed",
		ReasonSnapshotIncomplete:         "snapshot_incomplete",
		ReasonQuarantineUnavailable:      "quarantine_unavailable",
		ReasonQuarantineUnverified:       "quarantine_unverified",
		ReasonPeerUnsupported:            "peer_unsupported",
		ReasonPlanMismatch:               "plan_mismatch",
		ReasonStaleGeneration:            "stale_generation",
		ReasonRollbackUnavailable:        "rollback_unavailable",
		ReasonResourceBudgetExceeded:     "resource_budget_exceeded",
	}
	for reason, want := range reasons {
		if !reason.valid() || reason.String() != want {
			t.Errorf("reason=%d valid=%t string=%q want=%q", reason, reason.valid(), reason.String(), want)
		}
	}
	reasonOrder := []Reason{
		ReasonNone, ReasonEndpointNotOwned, ReasonEndpointRetired, ReasonBindingNotActive,
		ReasonBindingMismatch, ReasonSessionMismatch, ReasonOperationNotQualified,
		ReasonLocalUnsupported, ReasonPeerUnsupported, ReasonDeadlineExpired,
		ReasonPreflightRejected, ReasonPreflightFailed, ReasonStaleGeneration,
		ReasonNotRawTCP, ReasonTCPStateIneligible, ReasonKernelUnsupported,
		ReasonPermissionDenied, ReasonStateAPIIncomplete, ReasonTupleNotPreservable,
		ReasonTransparentBindUnavailable, ReasonQuiesceFailed, ReasonSnapshotIncomplete,
		ReasonQuarantineUnavailable, ReasonQuarantineUnverified, ReasonPlanMismatch,
		ReasonRollbackUnavailable, ReasonResourceBudgetExceeded,
	}
	for value, reason := range reasonOrder {
		if uint16(reason) != uint16(value) {
			t.Errorf("reason numeric drift: %s=%d want=%d", reason, reason, value)
		}
	}
	stageOrder := []Stage{
		StageNone, StageEndpoint, StageBinding, StageSession, StagePlatform, StageTuple,
		StagePreflight, StageQuiesce, StageQuarantine, StageSnapshot, StagePeerPlan,
		StageRollback, StageResourceBudget, StagePreflightComplete,
	}
	for value, stage := range stageOrder {
		if uint8(stage) != uint8(value) {
			t.Errorf("stage numeric drift: %s=%d want=%d", stage, stage, value)
		}
	}
	probeOrder := []ProbeID{
		ProbePlatformSnapshot, ProbeEndpointState, ProbeTuple, ProbeQuarantineSchema, ProbeRollbackReadiness,
	}
	for index, probe := range probeOrder {
		if uint8(probe) != uint8(index+1) {
			t.Errorf("probe numeric drift: %d want=%d", probe, index+1)
		}
	}
	for stage := StageEndpoint; stage <= StagePreflightComplete; stage++ {
		if !stage.valid() || stage.String() == "" {
			t.Errorf("stage=%d valid=%t string=%q", stage, stage.valid(), stage.String())
		}
	}
	binding := testBinding(34)
	plan := finalizePlan(Plan{
		TransactionID: TransactionID{1}, Binding: binding,
		Direction: proto.SenderDirectionClientToServer, Session: SessionStream,
		Fallback: FallbackRedialAttach, Deadline: canonicalTime(time.Now().Add(time.Minute)),
		LocalSupport: OperationTCPRepair, PeerSupport: OperationTCPRepair,
	}, StagePeerPlan, ReasonStaleGeneration, false)
	if err := plan.Validate(); err != nil {
		t.Fatalf("stale-generation fallback failed its own validation: %v", err)
	}
}

func TestProbeReferencesAreCanonicalAndImmutable(t *testing.T) {
	first := ProbeReference{
		ID: ProbeEndpointState, Revision: 2, Generation: 3, EndpointGeneration: 7,
		ObservedNano: 4, ExpiresNano: 40, ContextDigest: ContextDigest{1}, Digest: EvidenceDigest{5},
	}
	second := ProbeReference{
		ID: ProbePlatformSnapshot, Revision: 6, Generation: 7,
		ObservedNano: 8, ExpiresNano: 80, ContextDigest: ContextDigest{1}, Digest: EvidenceDigest{9},
	}
	references, err := NewProbeReferences(first, second)
	if err != nil {
		t.Fatal(err)
	}
	all := references.All()
	if len(all) != 2 || all[0] != second || all[1] != first || !references.valid(true) {
		t.Fatalf("canonical references=%+v", all)
	}
	all[0].Digest[0] ^= 0xff
	if references.All()[0] != second {
		t.Fatal("ProbeReferences.All exposed mutable storage")
	}
	if _, err := NewProbeReferences(first, first); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("duplicate reference error=%v want=%v", err, ErrInvalidDriver)
	}
	invalid := first
	invalid.ObservedNano = 0
	if _, err := NewProbeReferences(invalid); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("invalid reference error=%v want=%v", err, ErrInvalidDriver)
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

func TestCapabilityForClaimRequiresTheSealedDriver(t *testing.T) {
	driver := &fakeDriver{operation: OperationTCPRepair}
	driven := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	capability, ok := CapabilityForClaim(driven)
	if !ok || capability.Operation() != OperationTCPRepair {
		t.Fatalf("CapabilityForClaim(driven) = (%v, %t)", capability.Operation(), ok)
	}
	baselineFacts := testDrivenFacts()
	baselineFacts.Scope = ScopeEndpoint
	baseline := MustNewClaim(baselineFacts)
	if capability, ok := CapabilityForClaim(baseline); ok || capability.Operation() != 0 {
		t.Fatalf("CapabilityForClaim(baseline) = (%v, %t)", capability.Operation(), ok)
	}
	if capability, ok := CapabilityForClaim(nil); ok || capability.Operation() != 0 {
		t.Fatalf("CapabilityForClaim(nil) = (%v, %t)", capability.Operation(), ok)
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
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: evidence, ProbeReferences: testProbeReferences(1),
		},
	}
	facts := testDrivenFacts()
	claim := MustNewDrivenClaim(facts, driver, MustNewResource(ScopeEndpoint))
	binding := testBinding(7)
	bindDrivenClaim(t, claim, binding)
	request := fixedPlanRequest(binding)
	plan, err := PlanCandidate(context.Background(), claim, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != OperationTCPRepair || plan.Fallback != FallbackRedialAttach ||
		plan.Stage != StagePreflightComplete || plan.Reason != ReasonNone || plan.EndpointGeneration != facts.Generation ||
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
		assertFallbackPlan(t, plan, err, StageEndpoint, ReasonEndpointNotOwned, false)
	})

	t.Run("operation not qualified", func(t *testing.T) {
		claim := MustNewClaim(testFacts())
		if err := claim.Bind(binding); err != nil {
			t.Fatal(err)
		}
		plan, err := PlanCandidate(context.Background(), claim, request)
		assertFallbackPlan(t, plan, err, StageEndpoint, ReasonOperationNotQualified, false)
	})

	t.Run("operation incompatible with packet session", func(t *testing.T) {
		driver := &fakeDriver{operation: OperationTCPRepair}
		facts := testDrivenFacts()
		facts.Session = SessionAny
		claim := MustNewDrivenClaim(facts, driver, MustNewResource(ScopeEndpoint))
		bindDrivenClaim(t, claim, binding)
		candidate := request
		candidate.Session = SessionPacket
		plan, err := PlanCandidate(context.Background(), claim, candidate)
		assertFallbackPlan(t, plan, err, StageSession, ReasonSessionMismatch, false)
		if got := driver.preflightCalls.Load(); got != 0 {
			t.Fatalf("preflight calls=%d want=0", got)
		}
	})

	tests := []struct {
		name      string
		mutate    func(*PlanRequest)
		result    PreflightResult
		preErr    error
		stage     Stage
		want      Reason
		retryable bool
		wantCalls int32
	}{
		{name: "local unsupported", mutate: func(r *PlanRequest) { r.LocalSupport = 0 }, stage: StagePlatform, want: ReasonLocalUnsupported},
		{name: "peer unsupported", mutate: func(r *PlanRequest) { r.PeerSupport = 0 }, stage: StagePeerPlan, want: ReasonPeerUnsupported},
		{name: "session mismatch", mutate: func(r *PlanRequest) { r.Session = SessionPacket }, stage: StageSession, want: ReasonSessionMismatch},
		{name: "deadline expired", mutate: func(r *PlanRequest) { r.Deadline = time.Unix(1, 0) }, stage: StagePeerPlan, want: ReasonDeadlineExpired},
		{name: "preflight rejected", result: PreflightResult{Stage: StagePreflight, Reason: ReasonPreflightRejected, Retryable: true, ProbeReferences: testProbeReferences(2)}, stage: StagePreflight, want: ReasonPreflightRejected, retryable: true, wantCalls: 1},
		{name: "preflight failed", preErr: errors.New("probe failed"), stage: StagePreflight, want: ReasonPreflightFailed, wantCalls: 1},
		{name: "eligible", result: PreflightResult{Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: evidence, ProbeReferences: testProbeReferences(3)}, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := &fakeDriver{operation: OperationTCPRepair, result: test.result, preErr: test.preErr}
			claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
			bindDrivenClaim(t, claim, binding)
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
				assertFallbackPlan(t, plan, err, test.stage, test.want, test.retryable)
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
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{1}, ProbeReferences: testProbeReferences(4),
		},
		waitForContext: true,
	}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	bindDrivenClaim(t, claim, binding)
	request = fixedPlanRequest(binding)
	request.Deadline = time.Now().Add(5 * time.Millisecond)
	plan, err := PlanCandidate(context.Background(), claim, request)
	assertFallbackPlan(t, plan, err, StagePeerPlan, ReasonDeadlineExpired, false)
}

func TestPlanCandidateHonorsParentCancellation(t *testing.T) {
	binding := testBinding(12)
	driver := &fakeDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{1}, ProbeReferences: testProbeReferences(5),
		},
	}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	bindDrivenClaim(t, claim, binding)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan, err := PlanCandidate(ctx, claim, fixedPlanRequest(binding))
	assertFallbackPlan(t, plan, err, StagePreflight, ReasonPreflightFailed, false)
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
	assertFallbackPlan(t, plan, err, StagePreflight, ReasonPreflightFailed, false)
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
		Stage:              StagePreflightComplete,
		Fallback:           FallbackRedialAttach,
		Deadline:           time.Unix(2_000_000_000, 123_456_789).UTC(),
		LocalSupport:       OperationTCPRepair,
		PeerSupport:        OperationTCPRepair,
		Kind:               KindRawTCP,
		Role:               RoleDialer,
		Scope:              ScopeEndpoint,
		ResourceID:         ResourceID{0x31, 0x32},
		EvidenceDigest:     EvidenceDigest{0xde, 0xad, 0xbe, 0xef},
		ProbeReferences: testProbeReferencesAt(
			6, 7, time.Unix(2_000_000_000, 0).Add(-10*time.Second).UnixNano(),
			time.Unix(2_000_000_000, 0).Add(20*time.Second).UnixNano(),
		),
	}
	plan.LocalDigest = digestPlan(plan)
	const want = "de97881035019034826f77bbce98e69d29bfc0692ba55dc20e3d7ab1bd00282e"
	if got := hex.EncodeToString(plan.LocalDigest[:]); got != want {
		t.Fatalf("plan digest=%s want=%s", got, want)
	}
	nextGeneration := plan
	nextGeneration.BaseGeneration++
	if digestPlan(nextGeneration) == plan.LocalDigest {
		t.Fatal("resource base generation did not enter plan digest")
	}
	mutateReference := func(index int, mutate func(*ProbeReference)) Plan {
		candidate := plan
		items := candidate.ProbeReferences.All()
		mutate(&items[index])
		updated, err := NewProbeReferences(items...)
		if err != nil {
			t.Fatal(err)
		}
		candidate.ProbeReferences = updated
		return candidate
	}
	mutations := map[string]func() Plan{
		"transaction id":       func() Plan { candidate := plan; candidate.TransactionID[0] ^= 0xff; return candidate },
		"binding flow":         func() Plan { candidate := plan; candidate.Binding.FlowID[0] ^= 0xff; return candidate },
		"binding local target": func() Plan { candidate := plan; candidate.Binding.LocalTargetID[0] ^= 0xff; return candidate },
		"binding peer target":  func() Plan { candidate := plan; candidate.Binding.PeerTargetID[0] ^= 0xff; return candidate },
		"binding path":         func() Plan { candidate := plan; candidate.Binding.PathID++; return candidate },
		"binding owner":        func() Plan { candidate := plan; candidate.Binding.Owner++; return candidate },
		"endpoint generation":  func() Plan { candidate := plan; candidate.EndpointGeneration++; return candidate },
		"base generation":      func() Plan { candidate := plan; candidate.BaseGeneration++; return candidate },
		"direction": func() Plan {
			candidate := plan
			candidate.Direction = proto.SenderDirectionServerToClient
			return candidate
		},
		"session":   func() Plan { candidate := plan; candidate.Session = SessionPacket; return candidate },
		"operation": func() Plan { candidate := plan; candidate.Operation = OperationQUICCIDRebind; return candidate },
		"fallback":  func() Plan { candidate := plan; candidate.Fallback = FallbackInvalid; return candidate },
		"stage":     func() Plan { candidate := plan; candidate.Stage = StageSnapshot; return candidate },
		"reason":    func() Plan { candidate := plan; candidate.Reason = ReasonSnapshotIncomplete; return candidate },
		"retryable": func() Plan { candidate := plan; candidate.Retryable = true; return candidate },
		"deadline": func() Plan {
			candidate := plan
			candidate.Deadline = candidate.Deadline.Add(time.Nanosecond)
			return candidate
		},
		"local support":    func() Plan { candidate := plan; candidate.LocalSupport |= OperationQUICCIDRebind; return candidate },
		"peer support":     func() Plan { candidate := plan; candidate.PeerSupport |= OperationQUICCIDRebind; return candidate },
		"kind":             func() Plan { candidate := plan; candidate.Kind = KindQUIC; return candidate },
		"role":             func() Plan { candidate := plan; candidate.Role = RoleAcceptor; return candidate },
		"scope":            func() Plan { candidate := plan; candidate.Scope = ScopeSharedLink; return candidate },
		"resource id":      func() Plan { candidate := plan; candidate.ResourceID[0] ^= 0xff; return candidate },
		"plan evidence":    func() Plan { candidate := plan; candidate.EvidenceDigest[0] ^= 0xff; return candidate },
		"probe revision":   func() Plan { return mutateReference(0, func(reference *ProbeReference) { reference.Revision++ }) },
		"probe generation": func() Plan { return mutateReference(0, func(reference *ProbeReference) { reference.Generation++ }) },
		"probe endpoint generation": func() Plan {
			return mutateReference(1, func(reference *ProbeReference) { reference.EndpointGeneration++ })
		},
		"observed time": func() Plan { return mutateReference(0, func(reference *ProbeReference) { reference.ObservedNano++ }) },
		"expiry time":   func() Plan { return mutateReference(0, func(reference *ProbeReference) { reference.ExpiresNano++ }) },
		"context digest": func() Plan {
			return mutateReference(0, func(reference *ProbeReference) { reference.ContextDigest[0] ^= 0xff })
		},
		"evidence digest": func() Plan {
			return mutateReference(0, func(reference *ProbeReference) { reference.Digest[0] ^= 0xff })
		},
		"probe count":     func() Plan { candidate := plan; candidate.ProbeReferences.count--; return candidate },
		"probe id":        func() Plan { candidate := plan; candidate.ProbeReferences.items[0].ID = 0; return candidate },
		"last probe slot": func() Plan { candidate := plan; candidate.ProbeReferences.items[4].Digest[1] ^= 0xff; return candidate },
	}
	for name, mutate := range mutations {
		if digestPlan(mutate()) == plan.LocalDigest {
			t.Errorf("%s did not enter plan digest", name)
		}
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
		bindDrivenClaim(t, claim, binding)
		if _, err := PlanCandidate(context.Background(), claim, request); !errors.Is(err, ErrInvalidDriver) {
			t.Errorf("case %d error=%v want=%v", i, err, ErrInvalidDriver)
		}
	}
}

func TestTCPRepairEligiblePreflightRequiresFreshCompleteEvidence(t *testing.T) {
	binding := testBinding(35)
	request := fixedPlanRequest(binding)
	base := testProbeReferencesFor(0x35, 7)
	mutations := []struct {
		name   string
		mutate func([]ProbeReference) []ProbeReference
	}{
		{name: "missing endpoint state", mutate: func(items []ProbeReference) []ProbeReference {
			return append(items[:1:1], items[2:]...)
		}},
		{name: "wrong endpoint generation", mutate: func(items []ProbeReference) []ProbeReference {
			items[1].EndpointGeneration++
			return items
		}},
		{name: "expired", mutate: func(items []ProbeReference) []ProbeReference {
			for index := range items {
				items[index].ExpiresNano = time.Now().Add(-time.Millisecond).UnixNano()
				items[index].ObservedNano = items[index].ExpiresNano - int64(time.Second)
			}
			return items
		}},
		{name: "future observation", mutate: func(items []ProbeReference) []ProbeReference {
			for index := range items {
				items[index].ObservedNano = time.Now().Add(time.Minute).UnixNano()
				items[index].ExpiresNano = items[index].ObservedNano + int64(time.Minute)
			}
			return items
		}},
		{name: "stale observation with future expiry", mutate: func(items []ProbeReference) []ProbeReference {
			for index := range items {
				items[index].ObservedNano = time.Now().Add(-2 * time.Minute).UnixNano()
				items[index].ExpiresNano = time.Now().Add(time.Second).UnixNano()
			}
			return items
		}},
		{name: "context drift", mutate: func(items []ProbeReference) []ProbeReference {
			items[len(items)-1].ContextDigest[0] ^= 0xff
			return items
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			items := test.mutate(base.All())
			references, err := NewProbeReferences(items...)
			if err != nil {
				t.Fatal(err)
			}
			driver := &fakeDriver{operation: OperationTCPRepair, preserveContext: test.name == "context drift", result: PreflightResult{
				Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x35}, ProbeReferences: references,
			}}
			claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
			bindDrivenClaim(t, claim, binding)
			if _, err := PlanCandidate(context.Background(), claim, request); !errors.Is(err, ErrInvalidDriver) {
				t.Fatalf("PlanCandidate error=%v want=%v", err, ErrInvalidDriver)
			}
		})
	}
}

func TestPlanCandidateRejectsConsistentWrongRuntimeContext(t *testing.T) {
	binding := testBinding(38)
	references := testProbeReferencesFor(0x38, 7)
	driver := &fakeDriver{operation: OperationTCPRepair, preserveContext: true, result: PreflightResult{
		Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x38}, ProbeReferences: references,
	}}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	bindDrivenClaim(t, claim, binding)
	if _, err := PlanCandidate(context.Background(), claim, fixedPlanRequest(binding)); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("consistent foreign context error=%v want=%v", err, ErrInvalidDriver)
	}
}

func TestPlanCandidateRejectsReusedDriverAttemptIdentity(t *testing.T) {
	binding := testBinding(39)
	references := testProbeReferencesFor(0x3b, 7)
	attempt := &fakeDriverTransaction{evidence: AttemptEvidence{
		Digest: EvidenceDigest{0x3b}, ProbeReferences: references,
	}}
	driver := &fakeDriver{operation: OperationTCPRepair, attempt: attempt, result: PreflightResult{
		Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x3b}, ProbeReferences: references,
	}}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	bindDrivenClaim(t, claim, binding)
	first := fixedPlanRequest(binding)
	if _, err := PlanCandidate(context.Background(), claim, first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.TransactionID[0] ^= 0xff
	if _, err := PlanCandidate(context.Background(), claim, second); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("reused attempt error=%v want=%v", err, ErrInvalidDriver)
	}
}

func TestPlanCandidateRejectsForgedPlatformProbeProvenance(t *testing.T) {
	binding := testBinding(40)
	driver := &fakeDriver{operation: OperationTCPRepair, result: PreflightResult{
		Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x3c},
		ProbeReferences: testProbeReferencesFor(0x3c, 7),
	}, mutateResult: func(_ PreflightRequest, result *PreflightResult) {
		items := result.ProbeReferences.All()
		items[0].Generation++
		result.ProbeReferences, _ = NewProbeReferences(items...)
	}}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	bindDrivenClaim(t, claim, binding)
	if _, err := PlanCandidate(context.Background(), claim, fixedPlanRequest(binding)); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("forged platform provenance error=%v want=%v", err, ErrInvalidDriver)
	}
}

func TestPlatformInvalidationRevokesPublishedPlanImmediately(t *testing.T) {
	binding := testBinding(41)
	driver := &fakeDriver{operation: OperationTCPRepair, result: PreflightResult{
		Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x3e},
		ProbeReferences: testProbeReferencesFor(0x3e, 7),
	}}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	bindDrivenClaim(t, claim, binding)
	plan, err := PlanCandidate(context.Background(), claim, fixedPlanRequest(binding))
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.Invalidate(platform.FeatureTCPRepairBase); err != nil {
		t.Fatal(err)
	}
	if err := claim.ValidatePlanCurrent(plan); !errors.Is(err, ErrStalePlan) {
		t.Fatalf("invalidated platform plan=%v want=%v", err, ErrStalePlan)
	}
}

func TestEveryOperationRequiresItsCompleteEvidenceSet(t *testing.T) {
	now := time.Now()
	base := testProbeReferencesFor(0x39, 7)
	tests := []struct {
		operation Operation
		required  []ProbeID
	}{
		{OperationTCPRepair, []ProbeID{ProbePlatformSnapshot, ProbeEndpointState, ProbeTuple, ProbeQuarantineSchema, ProbeRollbackReadiness}},
		{OperationQUICCIDRebind, []ProbeID{ProbeEndpointState, ProbeTuple, ProbeRollbackReadiness}},
		{OperationUDPFlowRebind, []ProbeID{ProbeEndpointState, ProbeTuple, ProbeRollbackReadiness}},
		{OperationGVisorLinkRebind, []ProbeID{ProbePlatformSnapshot, ProbeEndpointState, ProbeTuple, ProbeRollbackReadiness}},
	}
	for _, test := range tests {
		for _, missing := range test.required {
			t.Run(fmt.Sprintf("operation_%d_without_probe_%d", test.operation, missing), func(t *testing.T) {
				items := base.All()
				filtered := items[:0]
				for _, item := range items {
					if item.ID != missing {
						filtered = append(filtered, item)
					}
				}
				references, err := NewProbeReferences(filtered...)
				if err != nil {
					t.Fatal(err)
				}
				result := PreflightResult{
					Eligible: true, Stage: StagePreflightComplete,
					EvidenceDigest: EvidenceDigest{0x39}, ProbeReferences: references,
				}
				attempt := &fakeDriverTransaction{evidence: AttemptEvidence{Digest: result.EvidenceDigest, ProbeReferences: references}}
				if err := validatePreflightResult(
					test.operation, 7, testProbeContext(references), testPlatformProbe(references),
					now.Add(time.Minute).UnixNano(), now.UnixNano(), attempt, result,
				); !errors.Is(err, ErrInvalidDriver) {
					t.Fatalf("validation error=%v want=%v", err, ErrInvalidDriver)
				}
			})
		}
	}
}

func TestIneligibleDecisionRequiresStageSpecificEvidence(t *testing.T) {
	now := time.Now()
	base := testProbeReferencesFor(0x3a, 7)
	platformOnly, err := NewProbeReferences(base.All()[0])
	if err != nil {
		t.Fatal(err)
	}
	result := PreflightResult{
		Stage: StageQuarantine, Reason: ReasonQuarantineUnverified,
		ProbeReferences: platformOnly,
	}
	if err := validatePreflightResult(
		OperationTCPRepair, 7, testProbeContext(platformOnly), testPlatformProbe(platformOnly),
		now.Add(time.Minute).UnixNano(), now.UnixNano(), nil, result,
	); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("unrelated evidence error=%v want=%v", err, ErrInvalidDriver)
	}
}

func TestEveryIneligibleStageRequiresItsMinimumEvidence(t *testing.T) {
	now := time.Now()
	base := testProbeReferencesFor(0x3d, 7)
	tests := []struct {
		stage     Stage
		reason    Reason
		retryable bool
		required  []ProbeID
	}{
		{StageEndpoint, ReasonTCPStateIneligible, false, []ProbeID{ProbeEndpointState}},
		{StagePlatform, ReasonKernelUnsupported, false, []ProbeID{ProbePlatformSnapshot}},
		{StageTuple, ReasonTupleNotPreservable, false, []ProbeID{ProbeTuple}},
		{StagePreflight, ReasonPreflightRejected, true, []ProbeID{ProbePlatformSnapshot, ProbeEndpointState}},
		{StageQuiesce, ReasonQuiesceFailed, false, []ProbeID{ProbeEndpointState, ProbeRollbackReadiness}},
		{StageQuarantine, ReasonQuarantineUnverified, false, []ProbeID{ProbeQuarantineSchema}},
		{StageSnapshot, ReasonSnapshotIncomplete, false, []ProbeID{ProbeEndpointState, ProbeTuple}},
		{StageRollback, ReasonRollbackUnavailable, false, []ProbeID{ProbeRollbackReadiness}},
		{StageResourceBudget, ReasonResourceBudgetExceeded, true, []ProbeID{ProbeEndpointState}},
	}
	for _, test := range tests {
		for _, missing := range test.required {
			t.Run(fmt.Sprintf("stage_%d_without_probe_%d", test.stage, missing), func(t *testing.T) {
				items := base.All()
				filtered := items[:0]
				for _, item := range items {
					if item.ID != missing {
						filtered = append(filtered, item)
					}
				}
				references, err := NewProbeReferences(filtered...)
				if err != nil {
					t.Fatal(err)
				}
				result := PreflightResult{
					Stage: test.stage, Reason: test.reason, Retryable: test.retryable, ProbeReferences: references,
				}
				if err := validatePreflightResult(
					OperationTCPRepair, 7, testProbeContext(references), testPlatformProbe(references),
					now.Add(time.Minute).UnixNano(), now.UnixNano(), nil, result,
				); !errors.Is(err, ErrInvalidDriver) {
					t.Fatalf("validation error=%v want=%v", err, ErrInvalidDriver)
				}
			})
		}
	}
}

func TestPlanDeadlineIsBoundedByEarliestEvidenceExpiry(t *testing.T) {
	binding := testBinding(36)
	request := fixedPlanRequest(binding)
	expiry := canonicalTime(time.Now().Add(10 * time.Second))
	references := testProbeReferencesAt(
		0x36, 7, time.Now().Add(-time.Second).UnixNano(), expiry.UnixNano(),
	)
	driver := &fakeDriver{operation: OperationTCPRepair, result: PreflightResult{
		Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x36}, ProbeReferences: references,
	}}
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	bindDrivenClaim(t, claim, binding)
	plan, err := PlanCandidate(context.Background(), claim, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Deadline != expiry || driver.lastPreflight.Deadline.UnixNano() != request.Deadline.UnixNano() ||
		plan.attempt.request != driver.lastPreflight {
		t.Fatalf("deadlines plan=%v driver=%v attempt=%v expiry=%v", plan.Deadline, driver.lastPreflight.Deadline, plan.attempt.request.Deadline, expiry)
	}
}

func TestPreflightRejectsContradictoryStageReasonAndOperation(t *testing.T) {
	now := time.Now()
	references := testProbeReferencesFor(0x37, 7)
	tests := []struct {
		name      string
		operation Operation
		result    PreflightResult
	}{
		{name: "wrong stage", operation: OperationTCPRepair, result: PreflightResult{
			Stage: StageTuple, Reason: ReasonQuarantineUnverified, ProbeReferences: references,
		}},
		{name: "tcp reason on quic", operation: OperationQUICCIDRebind, result: PreflightResult{
			Stage: StageEndpoint, Reason: ReasonNotRawTCP, ProbeReferences: references,
		}},
		{name: "nonretryable reason marked retryable", operation: OperationTCPRepair, result: PreflightResult{
			Stage: StageTuple, Reason: ReasonTupleNotPreservable, Retryable: true, ProbeReferences: references,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePreflightResult(
				test.operation, 7, testProbeContext(test.result.ProbeReferences), testPlatformProbe(test.result.ProbeReferences),
				now.Add(time.Minute).UnixNano(), now.UnixNano(), nil, test.result,
			); !errors.Is(err, ErrInvalidDriver) {
				t.Fatalf("validation error=%v want=%v", err, ErrInvalidDriver)
			}
		})
	}
}

func fixedPlanRequest(binding Binding) PlanRequest {
	return PlanRequest{
		TransactionID: TransactionID{0x41, 0x42},
		Binding:       binding,
		Direction:     proto.SenderDirectionClientToServer,
		Session:       SessionStream,
		Deadline:      canonicalTime(time.Now().Add(time.Minute)),
		LocalSupport:  OperationTCPRepair,
		PeerSupport:   OperationTCPRepair,
	}
}

func assertFallbackPlan(t *testing.T, plan Plan, err error, stage Stage, reason Reason, retryable bool) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != 0 || plan.Fallback != FallbackRedialAttach || plan.Stage != stage || plan.Reason != reason || plan.Retryable != retryable {
		t.Fatalf("fallback plan=%+v want stage=%s reason=%s retryable=%t", plan, stage, reason, retryable)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("fallback Validate: %v", err)
	}
	if plan.LocalDigest == (LocalPlanDigest{}) {
		t.Fatal("fallback plan has zero digest")
	}
}

func bindDrivenClaim(t testing.TB, claim *Claim, binding Binding) *AuthorityIssuer {
	t.Helper()
	issuer := NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	return issuer
}

func testProbeReferences(seed byte) ProbeReferences {
	now := time.Now()
	return testProbeReferencesAt(seed, 7, now.Add(-time.Second).UnixNano(), now.Add(20*time.Second).UnixNano())
}

func testProbeReferencesFor(seed byte, endpointGeneration uint64) ProbeReferences {
	now := time.Now()
	return testProbeReferencesAt(seed, endpointGeneration, now.Add(-time.Second).UnixNano(), now.Add(20*time.Second).UnixNano())
}

func testProbeReferencesAt(seed byte, endpointGeneration uint64, observedNano, expiresNano int64) ProbeReferences {
	contextDigest := ContextDigest{seed, 0xc1}
	references, err := NewProbeReferences(
		ProbeReference{
			ID: ProbePlatformSnapshot, Revision: 1, Generation: uint64(seed) + 1,
			ObservedNano: observedNano, ExpiresNano: expiresNano, ContextDigest: contextDigest,
			Digest: EvidenceDigest{seed, 1},
		},
		ProbeReference{
			ID: ProbeEndpointState, Revision: 1, Generation: uint64(seed) + 2, EndpointGeneration: endpointGeneration,
			ObservedNano: observedNano, ExpiresNano: expiresNano, ContextDigest: contextDigest,
			Digest: EvidenceDigest{seed, 2},
		},
		ProbeReference{
			ID: ProbeTuple, Revision: 1, Generation: uint64(seed) + 3, EndpointGeneration: endpointGeneration,
			ObservedNano: observedNano, ExpiresNano: expiresNano, ContextDigest: contextDigest,
			Digest: EvidenceDigest{seed, 3},
		},
		ProbeReference{
			ID: ProbeQuarantineSchema, Revision: 1, Generation: uint64(seed) + 4, EndpointGeneration: endpointGeneration,
			ObservedNano: observedNano, ExpiresNano: expiresNano, ContextDigest: contextDigest,
			Digest: EvidenceDigest{seed, 4},
		},
		ProbeReference{
			ID: ProbeRollbackReadiness, Revision: 1, Generation: uint64(seed) + 5, EndpointGeneration: endpointGeneration,
			ObservedNano: observedNano, ExpiresNano: expiresNano, ContextDigest: contextDigest,
			Digest: EvidenceDigest{seed, 5},
		},
	)
	if err != nil {
		panic(err)
	}
	return references
}

func testProbeReferencesForRequest(references ProbeReferences, request PreflightRequest) ProbeReferences {
	items := references.All()
	for index := range items {
		items[index].ContextDigest = request.ContextDigest
		if items[index].ID == ProbePlatformSnapshot {
			items[index] = request.PlatformProbe
		}
	}
	updated, err := NewProbeReferences(items...)
	if err != nil {
		panic(err)
	}
	return updated
}

func testProbeContext(references ProbeReferences) ContextDigest {
	contextDigest, _ := references.contextDigest()
	return contextDigest
}

func testPlatformProbe(references ProbeReferences) ProbeReference {
	reference, _ := references.platformReference()
	return reference
}
