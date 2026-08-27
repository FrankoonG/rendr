package leafmobility

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type refreshTestReporter struct{ incarnation atomic.Uint64 }

func (r *refreshTestReporter) LeafMobilityIncarnation() uint64 {
	return r.incarnation.Load()
}

func TestRefreshEvidenceBindsClaimGenerationAndIncarnation(t *testing.T) {
	claim, reporter := newRefreshTestClaim(t, 1)
	emitter, err := NewRefreshEmitter(claim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := evidence.ValidateFor(claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation == 0 || snapshot.EndpointGeneration != claim.Snapshot().Generation ||
		snapshot.Incarnation != 1 || snapshot.Reason != RefreshReasonRouteSourceChanged || snapshot.ObservedAt.IsZero() {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if _, err := evidence.ValidateFor(claim, snapshot.Generation); !errors.Is(err, ErrInvalidRefreshEvidence) {
		t.Fatalf("replayed evidence error=%v", err)
	}

	reporter.incarnation.Add(1)
	if _, err := evidence.ValidateFor(claim, 0); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("old incarnation error=%v", err)
	}
}

func TestRefreshEvidenceRejectsForeignAndRetiredClaims(t *testing.T) {
	claim, _ := newRefreshTestClaim(t, 1)
	foreign, _ := newRefreshTestClaim(t, 1)
	emitter, err := NewRefreshEmitter(claim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.ValidateFor(foreign, 0); !errors.Is(err, ErrInvalidRefreshEvidence) {
		t.Fatalf("foreign claim error=%v", err)
	}
	binding, ok := claim.Binding()
	if !ok {
		t.Fatal("claim is not bound")
	}
	if err := claim.Retire(binding); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.ValidateFor(claim, 0); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("retired claim error=%v", err)
	}
	if _, err := emitter.Observe(RefreshReasonRouteSourceChanged); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("observe retired claim error=%v", err)
	}
}

func TestRefreshEmitterRequiresDrivenIncarnation(t *testing.T) {
	plain := MustNewClaim(Facts{
		Kind: KindRawTCP, Role: RoleDialer, Scope: ScopeEndpoint,
		Session: SessionStream, Generation: NextGeneration(),
	})
	if _, err := NewRefreshEmitter(plain); !errors.Is(err, ErrInvalidRefreshEvidence) {
		t.Fatalf("plain claim emitter error=%v", err)
	}
}

func TestRefreshEvidenceTracksAdapterSourceGeneration(t *testing.T) {
	claim, _ := newRefreshTestClaim(t, 1)
	state := NewRefreshSourceState()
	first, err := state.Update([32]byte{0x41})
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := NewRefreshEmitterWithSourceState(claim, state)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(RefreshReasonRouteSourceChanged, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.ValidateFor(claim, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Update([32]byte{0x42}); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.ValidateFor(claim, 0); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("replaced source generation error=%v", err)
	}
	current, err := emitter.Observe(RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	state.Invalidate()
	if _, err := current.ValidateFor(claim, 0); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("invalidated source generation error=%v", err)
	}
	if _, err := emitter.Observe(RefreshReasonRouteSourceChanged); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("observe invalid source error=%v", err)
	}
}

func TestRefreshEvidenceExposesOpaqueSourceLineage(t *testing.T) {
	claim, _ := newRefreshTestClaim(t, 1)
	firstState := NewRefreshSourceState()
	firstSnapshot, err := firstState.Update([32]byte{0x31})
	if err != nil {
		t.Fatal(err)
	}
	firstEmitter, err := NewRefreshEmitterWithSourceState(claim, firstState)
	if err != nil {
		t.Fatal(err)
	}
	firstEvidence, err := firstEmitter.Observe(RefreshReasonRouteSourceChanged, firstSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstEvidence.ValidateFor(claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	repeatedEvidence, err := firstEmitter.Observe(RefreshReasonRouteSourceChanged, firstSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := repeatedEvidence.ValidateFor(claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	secondState := NewRefreshSourceState()
	secondSnapshot, err := secondState.Update([32]byte{0x32})
	if err != nil {
		t.Fatal(err)
	}
	secondEmitter, err := NewRefreshEmitterWithSourceState(claim, secondState)
	if err != nil {
		t.Fatal(err)
	}
	secondEvidence, err := secondEmitter.Observe(RefreshReasonRouteSourceChanged, secondSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondEvidence.ValidateFor(claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceLineage == (RefreshSourceLineage{}) ||
		first.SourceLineage != repeated.SourceLineage ||
		first.SourceLineage == second.SourceLineage {
		t.Fatalf("source lineages first=%+v repeated=%+v second=%+v", first, repeated, second)
	}
}

func TestRefreshEvidenceCarriesUnavailableAndRestoredSourceFacts(t *testing.T) {
	claim, _ := newRefreshTestClaim(t, 1)
	state := NewRefreshSourceState()
	baseline, err := state.Update([32]byte{0x51})
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := NewRefreshEmitterWithSourceState(claim, state)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := emitter.Observe(RefreshReasonRouteSourceChanged, baseline)
	if err != nil {
		t.Fatal(err)
	}

	unavailable, changed, err := state.MarkUnavailable()
	if err != nil || !changed {
		t.Fatalf("mark unavailable changed=%t err=%v", changed, err)
	}
	if _, err := prior.ValidateFor(claim, 0); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("superseded usable evidence error=%v", err)
	}
	evidence, err := emitter.Observe(RefreshReasonRouteSourceUnavailable, unavailable)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := evidence.ValidateFor(claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SourceUsable || snapshot.Reason != RefreshReasonRouteSourceUnavailable {
		t.Fatalf("unavailable snapshot=%+v", snapshot)
	}
	if _, err := state.DigestForCommit(evidence); !errors.Is(err, ErrRefreshSourceUnavailable) {
		t.Fatalf("unavailable commit digest error=%v", err)
	}
	if _, repeated, err := state.MarkUnavailable(); err != nil || repeated {
		t.Fatalf("repeated unavailable changed=%t err=%v", repeated, err)
	}
	if _, err := emitter.Observe(RefreshReasonRouteSourceChanged, unavailable); !errors.Is(err, ErrInvalidRefreshEvidence) {
		t.Fatalf("unavailable source with changed reason error=%v", err)
	}

	restored, err := state.Update([32]byte{0x51})
	if err != nil {
		t.Fatal(err)
	}
	restoredEvidence, err := emitter.Observe(RefreshReasonRouteSourceRestored, restored)
	if err != nil {
		t.Fatal(err)
	}
	restoredSnapshot, err := restoredEvidence.ValidateFor(claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !restoredSnapshot.SourceUsable || restoredSnapshot.Reason != RefreshReasonRouteSourceRestored ||
		restoredSnapshot.SourceGeneration == snapshot.SourceGeneration {
		t.Fatalf("restored snapshot=%+v unavailable=%+v", restoredSnapshot, snapshot)
	}
	testRefreshEvidenceCarriesTypedUsableFaultWithoutChangingSource(t)
}

func testRefreshEvidenceCarriesTypedUsableFaultWithoutChangingSource(t *testing.T) {
	reasons := []RefreshReason{
		RefreshReasonLinkUnresponsive,
		RefreshReasonLocalReadFailure,
		RefreshReasonLocalWriteFailure,
		RefreshReasonOuterMTUFailure,
		RefreshReasonReplayStalled,
		RefreshReasonReplayFailure,
		RefreshReasonLivenessProbeFailure,
	}
	for _, reason := range reasons {
		t.Run(fmt.Sprint(reason), func(t *testing.T) {
			claim, _ := newRefreshTestClaim(t, 1)
			state := NewRefreshSourceState()
			baseline, err := state.Update([32]byte{0x61})
			if err != nil {
				t.Fatal(err)
			}
			emitter, err := NewRefreshEmitterWithSourceState(claim, state)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := emitter.Observe(reason, baseline)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := evidence.ValidateFor(claim, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !snapshot.SourceUsable || snapshot.Reason != reason {
				t.Fatalf("typed fault snapshot=%+v want reason=%d", snapshot, reason)
			}
			if _, err := state.DigestForCommit(evidence); err != nil {
				t.Fatalf("unchanged usable source cannot commit: %v", err)
			}
		})
	}
}

func TestRefreshCommitLinearizesAgainstNewSourceGeneration(t *testing.T) {
	claim, _ := newRefreshTestClaim(t, 1)
	state := NewRefreshSourceState()
	current, err := state.Update([32]byte{0x81})
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := NewRefreshEmitterWithSourceState(claim, state)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(RefreshReasonRouteSourceChanged, current)
	if err != nil {
		t.Fatal(err)
	}
	commitEntered := make(chan struct{})
	commitRelease := make(chan struct{})
	commitDone := make(chan error, 1)
	go func() {
		commitDone <- state.CommitCurrent(evidence, func(digest [32]byte) {
			if digest != ([32]byte{0x81}) {
				panic("unexpected commit digest")
			}
			close(commitEntered)
			<-commitRelease
		})
	}()
	select {
	case <-commitEntered:
	case <-time.After(time.Second):
		t.Fatal("commit did not enter")
	}

	updateDone := make(chan error, 1)
	go func() {
		_, updateErr := state.Update([32]byte{0x82})
		updateDone <- updateErr
	}()
	select {
	case err := <-updateDone:
		t.Fatalf("source update crossed an active commit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(commitRelease)
	if err := <-commitDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("source update did not resume after commit")
	}
	if _, err := evidence.ValidateFor(claim, 0); !errors.Is(err, ErrRefreshEvidenceStale) {
		t.Fatalf("committed evidence remained current after source update: %v", err)
	}
}

func newRefreshTestClaim(t testing.TB, incarnation uint64) (*Claim, *refreshTestReporter) {
	t.Helper()
	reporter := &refreshTestReporter{}
	reporter.incarnation.Store(incarnation)
	driver := &fakeDriver{operation: OperationTCPRepair}
	claim := MustNewDrivenClaimWithIncarnation(Facts{
		Kind: KindRawTCP, Role: RoleDialer, Session: SessionStream,
		Generation: NextGeneration(),
	}, driver, MustNewResource(ScopeEndpoint), reporter)
	issuer := NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, testBinding(91)); err != nil {
		t.Fatal(err)
	}
	return claim, reporter
}
