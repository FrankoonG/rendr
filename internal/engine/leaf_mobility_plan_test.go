package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type enginePlanDriver struct {
	operation             leafmobility.Operation
	calls                 atomic.Int32
	evidence              leafmobility.EvidenceDigest
	entered               chan struct{}
	release               chan struct{}
	rollbackEntered       chan struct{}
	rollbackRelease       chan struct{}
	rollbackIgnoreContext bool
	stageEntered          chan struct{}
	stageRelease          chan struct{}
	commitEntered         chan struct{}
	commitRelease         chan struct{}
	prepareCalls          atomic.Int32
	cutoverCalls          atomic.Int32
	commitCalls           atomic.Int32
	activateCalls         atomic.Int32
	activateErr           error
	rollbackCalls         atomic.Int32
	failClosedCalls       atomic.Int32
	retryableFailures     atomic.Int32
	evidenceEntered       chan struct{}
	evidenceRelease       chan struct{}
	evidenceOnce          sync.Once
}

func (d *enginePlanDriver) Operation() leafmobility.Operation { return d.operation }

func (d *enginePlanDriver) Preflight(_ context.Context, request leafmobility.PreflightRequest) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	d.calls.Add(1)
	if d.entered != nil {
		close(d.entered)
	}
	if d.release != nil {
		<-d.release
	}
	now := time.Now()
	observed, expires := now.Add(-time.Second).UnixNano(), now.Add(20*time.Second).UnixNano()
	contextDigest := request.ContextDigest
	endpointGeneration := request.Facts.Generation
	references, err := leafmobility.NewProbeReferences(
		request.PlatformProbe,
		leafmobility.ProbeReference{
			ID: leafmobility.ProbeEndpointState, Revision: 1, Generation: 2, EndpointGeneration: endpointGeneration,
			ObservedNano: observed, ExpiresNano: expires, ContextDigest: contextDigest, Digest: leafmobility.EvidenceDigest{2},
		},
		leafmobility.ProbeReference{
			ID: leafmobility.ProbeTuple, Revision: 1, Generation: 3, EndpointGeneration: endpointGeneration,
			ObservedNano: observed, ExpiresNano: expires, ContextDigest: contextDigest, Digest: leafmobility.EvidenceDigest{3},
		},
		leafmobility.ProbeReference{
			ID: leafmobility.ProbeQuarantineSchema, Revision: 1, Generation: 4, EndpointGeneration: endpointGeneration,
			ObservedNano: observed, ExpiresNano: expires, ContextDigest: contextDigest, Digest: leafmobility.EvidenceDigest{4},
		},
		leafmobility.ProbeReference{
			ID: leafmobility.ProbeRollbackReadiness, Revision: 1, Generation: 5, EndpointGeneration: endpointGeneration,
			ObservedNano: observed, ExpiresNano: expires, ContextDigest: contextDigest, Digest: leafmobility.EvidenceDigest{5},
		},
	)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	for {
		remaining := d.retryableFailures.Load()
		if remaining <= 0 {
			break
		}
		if d.retryableFailures.CompareAndSwap(remaining, remaining-1) {
			return nil, leafmobility.PreflightResult{
				Stage: leafmobility.StagePreflight, Reason: leafmobility.ReasonPreflightRejected,
				Retryable: true, ProbeReferences: references,
			}, nil
		}
	}
	result := leafmobility.PreflightResult{
		Eligible: true, Stage: leafmobility.StagePreflightComplete, EvidenceDigest: d.evidence, ProbeReferences: references,
	}
	return &enginePlanDriverTransaction{driver: d, evidence: leafmobility.AttemptEvidence{
		Digest: result.EvidenceDigest, ProbeReferences: result.ProbeReferences,
	}}, result, nil
}

type enginePlanDriverTransaction struct {
	driver   *enginePlanDriver
	evidence leafmobility.AttemptEvidence
}

func (t *enginePlanDriverTransaction) Evidence() leafmobility.AttemptEvidence {
	if t.driver.evidenceEntered != nil {
		t.driver.evidenceOnce.Do(func() { close(t.driver.evidenceEntered) })
	}
	if t.driver.evidenceRelease != nil {
		<-t.driver.evidenceRelease
	}
	return t.evidence
}

func (t *enginePlanDriverTransaction) Prepare(context.Context, leafmobility.ExecutionRequest) error {
	t.driver.prepareCalls.Add(1)
	return nil
}
func (t *enginePlanDriverTransaction) Stage(ctx context.Context, _ leafmobility.ExecutionRequest) (leafmobility.PublicationEvidence, error) {
	t.driver.cutoverCalls.Add(1)
	if t.driver.stageEntered != nil {
		select {
		case <-t.driver.stageEntered:
		default:
			close(t.driver.stageEntered)
		}
	}
	if t.driver.stageRelease != nil {
		select {
		case <-t.driver.stageRelease:
		case <-ctx.Done():
			return leafmobility.PublicationEvidence{}, context.Cause(ctx)
		}
	}
	return leafmobility.PublicationEvidence{Digest: leafmobility.EvidenceDigest{0x71}}, nil
}
func (t *enginePlanDriverTransaction) Publish(ctx context.Context, _ leafmobility.ExecutionRequest) error {
	t.driver.commitCalls.Add(1)
	if t.driver.commitEntered != nil {
		select {
		case <-t.driver.commitEntered:
		default:
			close(t.driver.commitEntered)
		}
	}
	if t.driver.commitRelease != nil {
		select {
		case <-t.driver.commitRelease:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return nil
}
func (t *enginePlanDriverTransaction) Activate(context.Context, leafmobility.ExecutionRequest) error {
	t.driver.activateCalls.Add(1)
	return t.driver.activateErr
}
func (t *enginePlanDriverTransaction) Rollback(ctx context.Context, _ leafmobility.ExecutionRequest) error {
	t.driver.rollbackCalls.Add(1)
	if t.driver.rollbackEntered != nil {
		select {
		case <-t.driver.rollbackEntered:
		default:
			close(t.driver.rollbackEntered)
		}
	}
	if t.driver.rollbackRelease != nil {
		if t.driver.rollbackIgnoreContext {
			<-t.driver.rollbackRelease
			return nil
		}
		select {
		case <-t.driver.rollbackRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (t *enginePlanDriverTransaction) FailClosed(context.Context, leafmobility.ExecutionRequest) error {
	t.driver.failClosedCalls.Add(1)
	return nil
}

func (*enginePlanDriverTransaction) EndpointGenerationChanged() bool { return false }

func TestEnginePlansSpecializedMobilityFromExactFrozenEvidence(t *testing.T) {
	driver := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0x51}}
	claim := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Session:    leafmobility.SessionStream,
		Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint))
	capability := mustEngineCapability(t, driver)
	e, ref := engineWithPlannableLeaf(t, claim, capability, proto.LeafMobilityTCPRepair)
	started := time.Now()
	plan, err := e.PlanLeafMobilityCandidate(context.Background(), ref, leafmobility.TransactionID{1}, proto.SenderDirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != leafmobility.OperationTCPRepair || plan.EndpointGeneration != claim.Snapshot().Generation ||
		plan.Binding.PathID != ref.ID || plan.Binding.Owner != ref.Owner || plan.Direction != proto.SenderDirectionClientToServer {
		t.Fatalf("plan=%+v ref=%+v", plan, ref)
	}
	if driver.calls.Load() != 1 {
		t.Fatalf("preflight calls=%d want=1", driver.calls.Load())
	}
	if !plan.Deadline.After(started) || plan.Deadline.After(started.Add(e.limits.MigrationBudget+time.Second)) {
		t.Fatalf("candidate deadline=%v start=%v budget=%v", plan.Deadline, started, e.limits.MigrationBudget)
	}
}

func TestEnginePlannerCannotPromoteOwnershipWithoutPeerSupport(t *testing.T) {
	driver := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0x52}}
	claim := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Session:    leafmobility.SessionStream,
		Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint))
	e, ref := engineWithPlannableLeaf(t, claim, mustEngineCapability(t, driver), 0)
	plan, err := e.PlanLeafMobilityCandidate(context.Background(), ref, leafmobility.TransactionID{2}, proto.SenderDirectionServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != 0 || plan.Reason != leafmobility.ReasonPeerUnsupported {
		t.Fatalf("plan=%+v want peer-unsupported baseline", plan)
	}
	if driver.calls.Load() != 0 {
		t.Fatalf("preflight ran %d time(s) before peer agreement", driver.calls.Load())
	}
}

func TestEnginePlannerRejectsUnnegotiatedAndStalePath(t *testing.T) {
	e, binding := admissionTestEngine(t)
	path, peer := newMemoryPathPair()
	defer peer.Close()
	id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := e.PathRef(id)
	if !ok {
		t.Fatal("missing attached path ref")
	}
	_, err = e.PlanLeafMobilityCandidate(context.Background(), ref, leafmobility.TransactionID{3}, proto.SenderDirectionClientToServer)
	if !errors.Is(err, ErrLeafMobilityNotNegotiated) {
		t.Fatalf("unnegotiated error=%v want=%v", err, ErrLeafMobilityNotNegotiated)
	}

	negotiation := e.LocalNegotiation()
	if err := e.AcceptPeerNegotiation(negotiation, e.LocalGraphManifest()); err != nil {
		t.Fatal(err)
	}
	if err := e.RetirePath(ref, errors.New("test retirement")); err != nil {
		t.Fatal(err)
	}
	_, err = e.PlanLeafMobilityCandidate(context.Background(), ref, leafmobility.TransactionID{4}, proto.SenderDirectionClientToServer)
	if !errors.Is(err, ErrStalePathRef) {
		t.Fatalf("stale error=%v want=%v", err, ErrStalePathRef)
	}
}

func TestEnginePlannerCannotPublishAfterConcurrentPathRetirement(t *testing.T) {
	driver := &enginePlanDriver{
		operation: leafmobility.OperationTCPRepair,
		evidence:  leafmobility.EvidenceDigest{0x53},
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	claim := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Session:    leafmobility.SessionStream,
		Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint))
	e, ref := engineWithPlannableLeaf(t, claim, mustEngineCapability(t, driver), proto.LeafMobilityTCPRepair)
	result := make(chan error, 1)
	go func() {
		_, err := e.PlanLeafMobilityCandidate(context.Background(), ref, leafmobility.TransactionID{5}, proto.SenderDirectionClientToServer)
		result <- err
	}()
	select {
	case <-driver.entered:
	case <-time.After(time.Second):
		t.Fatal("planner did not enter preflight")
	}
	if err := e.RetirePath(ref, errors.New("concurrent retirement")); err != nil {
		t.Fatal(err)
	}
	close(driver.release)
	select {
	case err := <-result:
		if !errors.Is(err, ErrStalePathRef) {
			t.Fatalf("planning error=%v want=%v", err, ErrStalePathRef)
		}
	case <-time.After(time.Second):
		t.Fatal("planner did not finish after preflight release")
	}
}

func TestLogicalPathDepartureInvalidatesPublishedCandidateBeforeCleanup(t *testing.T) {
	driver := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0x54}}
	claim := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Session:    leafmobility.SessionStream,
		Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint))
	e, ref := engineWithPlannableLeaf(t, claim, mustEngineCapability(t, driver), proto.LeafMobilityTCPRepair)
	plan, err := e.PlanLeafMobilityCandidate(context.Background(), ref, leafmobility.TransactionID{6}, proto.SenderDirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	e.pathsMu.Lock()
	slot := e.paths[ref.ID]
	departure := e.detachPathLocked(slot, e.localExec, transport.CauseCleanClose, errors.New("logical departure"), true)
	if err := claim.ValidatePlanCurrent(plan); !errors.Is(err, leafmobility.ErrStalePlan) {
		e.pathsMu.Unlock()
		t.Fatalf("candidate remained current after topology departure: %v", err)
	}
	e.pathsMu.Unlock()
	e.finishPathDeparture(departure)
}

func engineWithPlannableLeaf(t *testing.T, claim *leafmobility.Claim, local leafmobility.Capability, peer proto.LeafMobilitySet) (*Engine, PathRef) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "control"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "control"),
	)
	flow := NewClientFlowID()
	e := New(SideClient, flow, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalMobilityCapabilities(local); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	peerNegotiation := proto.NewNegotiation(proto.SessionEpoch(flow))
	peerNegotiation.MobilitySupported = peer
	peerNegotiation.GraphDigest, _ = manifest.Digest()
	if err := e.AcceptPeerNegotiation(peerNegotiation, manifest); err != nil {
		t.Fatal(err)
	}
	path, remote := newMemoryPathPair()
	t.Cleanup(func() { _ = remote.Close() })
	id, err := e.AttachPathBound(&claimedMemoryPath{PathConn: path, claim: claim}, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := e.PathRef(id)
	if !ok {
		t.Fatal("missing path ref")
	}
	control, controlRemote := newMemoryPathPair()
	t.Cleanup(func() { _ = controlRemote.Close() })
	if _, err := e.AttachPathBound(control, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["control"], PeerTXTargetID: ids["control"],
	}); err != nil {
		t.Fatal(err)
	}
	return e, ref
}

func mustEngineCapability(t *testing.T, driver leafmobility.Driver) leafmobility.Capability {
	t.Helper()
	capability, err := leafmobility.CapabilityForDriver(driver)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}
