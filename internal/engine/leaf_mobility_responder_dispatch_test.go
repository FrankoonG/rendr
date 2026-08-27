package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// peerCompleteDelayedDATAPath models a repaired carrier that has accepted the
// predecessor DATA frame while its original PathConn.Write call still owns
// dispatcher completion. Later writes therefore remain serialized behind it.
type peerCompleteDelayedDATAPath struct {
	transport.PathConn
	repair      <-chan struct{}
	returnWrite <-chan struct{}
	started     chan struct{}
	accepted    chan struct{}
	firstDATA   atomic.Bool
	startedOnce sync.Once
	acceptOnce  sync.Once
}

func (p *peerCompleteDelayedDATAPath) Write(frame []byte) (int, error) {
	if len(frame) < proto.HeaderSize {
		return p.PathConn.Write(frame)
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameData || !p.firstDATA.CompareAndSwap(false, true) {
		return p.PathConn.Write(frame)
	}
	p.startedOnce.Do(func() { close(p.started) })
	<-p.repair
	n, writeErr := p.PathConn.Write(frame)
	p.acceptOnce.Do(func() { close(p.accepted) })
	<-p.returnWrite
	return n, writeErr
}

type peerCompleteMigrationEvent struct {
	oldID uint32
	newID uint32
	cause string
}

func TestPeerLeafCompleteRetiresResponderStallBeforeSelectorReprojection(t *testing.T) {
	repair := make(chan struct{})
	returnWrite := make(chan struct{})
	var repairOnce, returnOnce sync.Once
	releaseRepair := func() { repairOnce.Do(func() { close(repair) }) }
	releaseWrite := func() { returnOnce.Do(func() { close(returnWrite) }) }
	t.Cleanup(func() {
		releaseRepair()
		releaseWrite()
	})

	stallPath := &peerCompleteDelayedDATAPath{
		repair: repair, returnWrite: returnWrite,
		started: make(chan struct{}), accepted: make(chan struct{}),
	}
	serverLimits := Limits{}.Clamp()
	serverLimits.ProbeInterval = time.Second
	serverLimits.SelectorDwell = time.Hour
	serverLimits.SelectorCooldown = time.Hour
	var subjectWire *memoryPathConn
	fixture := newLeafMobilityEngineFixtureWithAllWrappersAndLimits(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		nil,
		func(path *memoryPathConn) transport.PathConn {
			subjectWire = path
			stallPath.PathConn = path
			return stallPath
		},
		nil, nil,
		Limits{}, serverLimits,
	)
	if subjectWire == nil {
		t.Fatal("missing responder subject wire")
	}
	fixture.server.tailReplayInitialDelay = time.Hour
	fixture.server.tailReplayMaxBackoff = time.Hour
	fixture.server.pathsMu.RLock()
	subjectSlot := fixture.server.paths[fixture.serverRef.ID]
	siblingSlot := fixture.server.paths[fixture.serverControlRef.ID]
	fixture.server.pathsMu.RUnlock()
	if subjectSlot == nil || siblingSlot == nil {
		t.Fatal("missing responder selector leaves")
	}
	now := time.Now()
	seedPathProbeSuccess(fixture.server, subjectSlot, now, 10*time.Millisecond)
	seedPathProbeSuccess(fixture.server, siblingSlot, now, 20*time.Millisecond)

	var migrationMu sync.Mutex
	var migrations []peerCompleteMigrationEvent
	cancelMigration := fixture.server.OnMigrate(func(oldID, newID uint32, cause string) {
		migrationMu.Lock()
		migrations = append(migrations, peerCompleteMigrationEvent{oldID: oldID, newID: newID, cause: cause})
		migrationMu.Unlock()
	})
	defer cancelMigration()

	oldPayload := []byte("predecessor-data")
	oldWrite := make(chan error, 1)
	go func() {
		n, err := fixture.server.SendData(oldPayload)
		if err == nil && n != len(oldPayload) {
			err = io.ErrShortWrite
		}
		oldWrite <- err
	}()
	select {
	case <-stallPath.started:
	case <-time.After(time.Second):
		t.Fatal("responder subject DATA did not enter physical Write")
	}
	eventuallyEngine(t, 2*time.Second, func() bool {
		_, stalled := subjectSlot.currentDispatchStall()
		return stalled
	})
	stalledIdentity, stalled := subjectSlot.currentDispatchStall()
	if !stalled {
		t.Fatal("responder subject lost dispatch stall snapshot")
	}

	fixture.server.issuePathProbe(subjectSlot)
	eventuallyEngine(t, time.Second, func() bool {
		fixture.server.probeMu.Lock()
		defer fixture.server.probeMu.Unlock()
		for _, observation := range fixture.server.probeOutstanding {
			if observation.slot == subjectSlot && observation.lifecycle == pathProbeQueued {
				return true
			}
		}
		return false
	})
	blockedAt := time.Now()
	if status := fixture.server.pathProbeStatuses(blockedAt)[subjectSlot]; status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
		t.Fatalf("initial responder probe status=%+v", status)
	}
	starvedAt := blockedAt.Add(pathProbeDataStarvationFor(fixture.server.limits.ProbeInterval))
	if status := fixture.server.pathProbeStatuses(starvedAt)[subjectSlot]; status.lifecycle != pathProbeDataStarved || status.failure != pathProbeFailureDataStarved {
		t.Fatalf("starved responder probe status=%+v", status)
	}

	(&selector{}).evaluateRecursive(fixture.server, fixture.server.localExecutionRuntime())
	if got := fixture.server.ActivePath(); got != fixture.serverControlRef.ID {
		t.Fatalf("probe-starved selector active=%d want sibling=%d", got, fixture.serverControlRef.ID)
	}
	if got := fixture.server.MigrationCount(); got != 1 {
		t.Fatalf("probe-starved migration count=%d want 1", got)
	}
	select {
	case err := <-oldWrite:
		if err != nil {
			t.Fatalf("predecessor application write observed selector cutover: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("predecessor application write did not hand custody to selector replay")
	}
	eventuallyEngine(t, time.Second, func() bool {
		return equalPeerCompleteSequences(dataSequences(fixture.serverWire), []uint64{0})
	})
	if got := dataSequences(subjectWire); len(got) != 0 {
		t.Fatalf("subject accepted DATA before repair: %v", got)
	}
	if err := fixture.client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	oldReceived := make([]byte, len(oldPayload))
	if _, err := io.ReadFull(&Conn{E: fixture.client}, oldReceived); err != nil || !bytes.Equal(oldReceived, oldPayload) {
		t.Fatalf("predecessor application delivery=(%q,%v), want %q", oldReceived, err, oldPayload)
	}
	eventuallyEngine(t, time.Second, func() bool { return fixture.server.ReplayStats().AckNext == 1 })

	fixture.clientDriver.commitEntered = make(chan struct{})
	fixture.clientDriver.commitRelease = make(chan struct{})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd5)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	authorizeLeafMobilityPublish(t, permit)
	publishDone := make(chan error, 1)
	go func() { publishDone <- permit.PublishDriver(context.Background()) }()
	select {
	case <-fixture.clientDriver.commitEntered:
	case <-time.After(time.Second):
		t.Fatal("client mobility Publish did not reach driver")
	}

	peerEpochBefore := subjectSlot.peerMobilityEpoch.Load()
	releaseRepair()
	select {
	case <-stallPath.accepted:
	case <-time.After(time.Second):
		t.Fatal("repaired subject did not accept predecessor DATA")
	}
	if got := dataSequences(subjectWire); !equalPeerCompleteSequences(got, []uint64{0}) {
		t.Fatalf("repaired subject sequences before Write return=%v want [0]", got)
	}
	if got, ok := subjectSlot.currentDispatchStall(); !ok || got != stalledIdentity {
		t.Fatalf("accepted predecessor changed dispatch custody got=%+v present=%t want=%+v",
			got, ok, stalledIdentity)
	}
	eventuallyEngine(t, time.Second, func() bool { return fixture.client.RecvDups() == 1 })
	close(fixture.clientDriver.commitRelease)
	if err := <-publishDone; err != nil {
		t.Fatal(err)
	}
	if err := permit.ActivateDriver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Complete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if permit.State() != leafmobility.ResourceTransactionCompleted ||
		permit.ExecutionState() != leafmobility.ExecutionActivated {
		t.Fatalf("client mobility terminal state=(%d,%d)", permit.State(), permit.ExecutionState())
	}
	fixture.server.leafTx.mu.Lock()
	completed, completedOK := fixture.server.leafTx.completed[[16]byte(plan.TransactionID)]
	_, incomingStillActive := fixture.server.leafTx.incoming[[16]byte(plan.TransactionID)]
	fixture.server.leafTx.mu.Unlock()
	if !completedOK || incomingStillActive || completed.source != fixture.serverRef ||
		completed.final.Code != proto.LeafMobilityPeerPlanAckCodeAccept ||
		completed.resolution.Stage != proto.LeafMobilityPeerPlanCommitStageComplete ||
		completed.released.Phase != proto.LeafMobilityPeerPlanAckPhaseReleased ||
		completed.released.Stage != proto.LeafMobilityPeerPlanCommitStageComplete ||
		len(completed.finalFrame) == 0 || len(completed.releasedFrame) == 0 {
		t.Fatalf("responder terminal evidence completed=%t active=%t source=%+v final=%+v resolution=%+v released=%+v frames=%d/%d",
			completedOK, incomingStillActive, completed.source, completed.final,
			completed.resolution, completed.released, len(completed.finalFrame), len(completed.releasedFrame))
	}
	if got := subjectSlot.peerMobilityEpoch.Load(); got != peerEpochBefore+1 {
		t.Fatalf("responder peer mobility epoch=%d want %d", got, peerEpochBefore+1)
	}
	if got, ok := subjectSlot.currentDispatchStall(); !ok || got != stalledIdentity {
		t.Fatalf("peer COMPLETE changed predecessor custody got=%+v present=%t want=%+v",
			got, ok, stalledIdentity)
	}
	if status := fixture.server.pathProbeStatuses(time.Now())[subjectSlot]; status.failure != pathProbeFailureNone {
		t.Fatalf("peer COMPLETE retained predecessor probe authority=%+v", status)
	}

	if err := fixture.server.SelectExplicitTarget(fixture.ids["root"], fixture.ids["a"], "explicit"); err != nil {
		t.Fatal(err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverRef.ID {
		t.Fatalf("explicit repaired selection active=%d want subject=%d", got, fixture.serverRef.ID)
	}
	if got := fixture.server.MigrationCount(); got != 2 {
		t.Fatalf("explicit repaired migration count=%d want 2", got)
	}
	(&selector{}).evaluateRecursive(fixture.server, fixture.server.localExecutionRuntime())
	if got := fixture.server.ActivePath(); got != fixture.serverRef.ID {
		t.Fatalf("post-COMPLETE selector reprojected to sibling: active=%d want %d", got, fixture.serverRef.ID)
	}
	if got := fixture.server.MigrationCount(); got != 2 {
		t.Fatalf("post-COMPLETE selector added migration: %d", got)
	}

	newPayload := bytes.Repeat([]byte{0xa7}, 2*MaxPayload+17)
	newWrite := make(chan error, 1)
	go func() {
		n, err := fixture.server.SendData(newPayload)
		if err == nil && n != len(newPayload) {
			err = io.ErrShortWrite
		}
		newWrite <- err
	}()
	eventuallyEngine(t, time.Second, func() bool {
		stats := fixture.server.ReplayStats()
		return stats.PublishedNext == 2 && stats.AckNext == 1 && stats.FramesInUse == 1
	})
	select {
	case err := <-newWrite:
		t.Fatalf("new DATA bypassed predecessor Write: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	fixture.server.selectorCutoverMu.Lock()
	pendingCutover := fixture.server.selectorCutoverPending
	detached := fixture.server.detachedStreamDispatches
	unclaimed := fixture.server.dispatchTicketsUnclaimed
	fixture.server.selectorCutoverMu.Unlock()
	if pendingCutover || detached != 1 || unclaimed != 1 {
		t.Fatalf("pending DATA custody cutover/detached/unclaimed=%t/%d/%d want false/1/1",
			pendingCutover, detached, unclaimed)
	}
	if got := dataSequences(fixture.serverWire); !equalPeerCompleteSequences(got, []uint64{0}) {
		t.Fatalf("new DATA escaped to sibling while subject stalled: %v", got)
	}

	releaseWrite()
	select {
	case err := <-newWrite:
		if err != nil {
			t.Fatalf("new DATA after predecessor completion: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new DATA remained blocked after predecessor completion")
	}
	eventuallyEngine(t, time.Second, func() bool {
		return equalPeerCompleteSequences(dataSequences(subjectWire), []uint64{0, 1, 2, 3})
	})
	if got := dataSequences(fixture.serverWire); !equalPeerCompleteSequences(got, []uint64{0}) {
		t.Fatalf("post-COMPLETE DATA used sibling: %v", got)
	}

	if err := fixture.client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	newReceived := make([]byte, len(newPayload))
	if _, err := io.ReadFull(&Conn{E: fixture.client}, newReceived); err != nil || !bytes.Equal(newReceived, newPayload) {
		t.Fatalf("post-COMPLETE application delivery bytes=%d err=%v", len(newReceived), err)
	}
	eventuallyEngine(t, time.Second, func() bool {
		stats := fixture.server.ReplayStats()
		return stats.PublishedNext == 4 && stats.AckNext == 4 &&
			stats.FramesInUse == 0 && stats.BytesInUse == 0
	})
	if got := fixture.client.RecvDups(); got != 1 {
		t.Fatalf("wire duplicates=%d want exactly one retired predecessor", got)
	}
	if err := fixture.client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := fixture.client.Recv(make([]byte, 1)); n != 0 || !errors.Is(err, ErrReadDeadlineExceeded) {
		t.Fatalf("unexpected repeated application delivery=(%d,%v)", n, err)
	}
	if stall, ok := subjectSlot.currentDispatchStall(); ok {
		t.Fatalf("final subject stall=%+v", stall)
	}
	fixture.server.selectorCutoverMu.Lock()
	pendingCutover = fixture.server.selectorCutoverPending
	detached = fixture.server.detachedStreamDispatches
	unclaimed = fixture.server.dispatchTicketsUnclaimed
	fixture.server.selectorCutoverMu.Unlock()
	if pendingCutover || detached != 0 || unclaimed != 0 {
		t.Fatalf("final custody cutover/detached/unclaimed=%t/%d/%d want false/0/0",
			pendingCutover, detached, unclaimed)
	}

	eventuallyEngine(t, time.Second, func() bool {
		migrationMu.Lock()
		defer migrationMu.Unlock()
		return len(migrations) == 2
	})
	migrationMu.Lock()
	gotMigrations := append([]peerCompleteMigrationEvent(nil), migrations...)
	migrationMu.Unlock()
	wantMigrations := []peerCompleteMigrationEvent{
		{oldID: fixture.serverRef.ID, newID: fixture.serverControlRef.ID, cause: "probe-starved-data"},
		{oldID: fixture.serverControlRef.ID, newID: fixture.serverRef.ID, cause: "explicit"},
	}
	if !equalPeerCompleteMigrations(gotMigrations, wantMigrations) {
		t.Fatalf("migration events=%+v want %+v", gotMigrations, wantMigrations)
	}
}

func TestPeerMobilityCommitLinearizesDispatchGenerationBeforePublication(t *testing.T) {
	slot := &pathSlot{
		id:        17,
		gen:       23,
		owner:     23,
		dispatchQ: make(chan pathDispatchJob, 2),
	}
	engine := &Engine{paths: map[uint32]*pathSlot{slot.id: slot}}
	incoming := &incomingLeafMobilityTransaction{
		source:     pathRefForSlot(slot),
		sourceSlot: slot,
	}
	predecessor := pathProbeGenerationForSlot(slot)

	snapshotTaken := make(chan struct{})
	releasePublication := make(chan struct{})
	type submitResult struct {
		identity  pathDispatchIdentity
		submitted bool
	}
	submitDone := make(chan submitResult, 1)
	go func() {
		identity, submitted := slot.submitDispatchTracked(pathDispatchJob{
			beforePublication: func() {
				close(snapshotTaken)
				<-releasePublication
			},
		})
		submitDone <- submitResult{identity: identity, submitted: submitted}
	}()

	select {
	case <-snapshotTaken:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not stop after generation snapshot")
	}

	commitDone := make(chan struct{})
	go func() {
		engine.commitPeerLeafMobilityEpoch(incoming)
		close(commitDone)
	}()
	eventuallyEngine(t, time.Second, func() bool {
		if engine.pathsMu.TryRLock() {
			engine.pathsMu.RUnlock()
			return false
		}
		return true
	})
	if got := slot.peerMobilityEpoch.Load(); got != predecessor.peerMobilityEpoch {
		t.Fatalf("peer epoch advanced before predecessor publication: got %d want %d",
			got, predecessor.peerMobilityEpoch)
	}
	select {
	case <-commitDone:
		t.Fatal("peer mobility commit crossed blocked dispatch publication")
	default:
	}

	close(releasePublication)
	var first submitResult
	select {
	case first = <-submitDone:
	case <-time.After(time.Second):
		t.Fatal("predecessor dispatch did not publish")
	}
	if !first.submitted || first.identity.pathGeneration != predecessor {
		t.Fatalf("predecessor submission=(%+v,%t) want generation %+v",
			first.identity, first.submitted, predecessor)
	}
	select {
	case <-commitDone:
	case <-time.After(time.Second):
		t.Fatal("peer mobility commit remained blocked after publication")
	}
	published := <-slot.dispatchQ
	if published.pathGeneration != predecessor {
		t.Fatalf("published predecessor generation=%+v want %+v", published.pathGeneration, predecessor)
	}

	successor := pathProbeGenerationForSlot(slot)
	if successor.peerMobilityEpoch != predecessor.peerMobilityEpoch+1 {
		t.Fatalf("successor peer epoch=%d want %d", successor.peerMobilityEpoch, predecessor.peerMobilityEpoch+1)
	}
	second, submitted := slot.submitDispatchTracked(pathDispatchJob{})
	if !submitted || second.pathGeneration != successor {
		t.Fatalf("successor submission=(%+v,%t) want generation %+v", second, submitted, successor)
	}
	published = <-slot.dispatchQ
	if published.pathGeneration != successor {
		t.Fatalf("published successor generation=%+v want %+v", published.pathGeneration, successor)
	}
}

func dataSequences(path *memoryPathConn) []uint64 {
	if path == nil {
		return nil
	}
	headers := path.FrameHeaders()
	sequences := make([]uint64, 0, len(headers))
	for _, header := range headers {
		if header.Type == proto.FrameData {
			sequences = append(sequences, header.Seq)
		}
	}
	return sequences
}

func equalPeerCompleteSequences(got, want []uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func equalPeerCompleteMigrations(got, want []peerCompleteMigrationEvent) bool {
	if len(got) != len(want) {
		return false
	}
	matched := make([]bool, len(want))
	for _, event := range got {
		found := false
		for index, expected := range want {
			if !matched[index] && event == expected {
				matched[index] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
