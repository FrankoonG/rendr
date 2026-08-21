package engine

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestRecursiveExplicitSelectionPreemptsBlockedDataDispatch(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blocked := newCloseReleasedWritePath()
	healthy := newProbeCutoverCapturePath()
	if _, err := e.AttachPathBound(blocked, transport.PathSpec{Transport: "test"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AttachPathBound(healthy, transport.PathSpec{Transport: "test"}, PathBinding{
		LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"],
	}); err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("explicit-cutover"))
		writeDone <- err
	}()
	select {
	case <-blocked.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("selected path did not enter blocked write")
	}
	if err := e.SelectExplicitTarget(ids["root"], ids["b"], "explicit"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("handoff surfaced to application: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("explicit selection did not preempt blocked dispatch")
	}
	eventuallyEngine(t, time.Second, func() bool {
		sequences := healthy.dataSequences()
		return len(sequences) != 0 && sequences[0] == 0
	})
	if got := e.BondStuckSkips(); got != 0 {
		t.Fatalf("selector stall counted as bond skip: %d", got)
	}
}

func TestSequencedControlBypassesBlockedStreamDataAndCutoverOwnsReplay(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{MigrationBudget: time.Second}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blocked := newCloseReleasedWritePath()
	healthy := newProbeCutoverCapturePath()
	if _, err := e.AttachPathBound(blocked, transport.PathSpec{Transport: "test"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AttachPathBound(healthy, transport.PathSpec{Transport: "test"}, PathBinding{
		LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"],
	}); err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("blocked-before-control"))
		writeDone <- err
	}()
	select {
	case <-blocked.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("selected DATA did not enter blocked carrier")
	}

	controlDone := make(chan error, 1)
	go func() {
		controlDone <- e.sendFrame(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlHeartbeat), nil)
	}()
	select {
	case err := <-controlDone:
		if err != nil {
			t.Fatalf("control fallback failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("sequenced control remained behind blocked DATA")
	}

	if err := e.SelectExplicitTarget(ids["root"], ids["b"], "control-hol-cutover"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("cutover surfaced blocked DATA error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cutover did not take custody of detached stream DATA")
	}
	eventuallyEngine(t, time.Second, func() bool {
		return slices.Equal(healthy.dataSequences(), []uint64{0})
	})
	if stats := e.ReplayStats(); stats.PublishedNext != 2 {
		t.Fatalf("published frontier=%d want DATA+control", stats.PublishedNext)
	}
}

func TestFailedExplicitSelectionRetainsHandedOffReplayCustody(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "unattached"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "unattached"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{MigrationBudget: time.Second}.Clamp())
	replayOwned := make(chan struct{})
	releaseReplay := make(chan struct{})
	var releaseReplayOnce sync.Once
	releaseReplayGate := func() { releaseReplayOnce.Do(func() { close(releaseReplay) }) }
	var replayOnce atomic.Bool
	e.boundedReplayBeforeSnapshot = func() {
		if replayOnce.CompareAndSwap(false, true) {
			close(replayOwned)
		}
		<-releaseReplay
	}
	t.Cleanup(func() {
		releaseReplayGate()
		_ = e.Close()
	})
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	blocked := newCloseReleasedWritePath()
	if _, err := e.AttachPathBound(blocked, transport.PathSpec{Transport: "test"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	}); err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("retained-custody"))
		writeDone <- err
	}()
	select {
	case <-blocked.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("selected path did not enter blocked write")
	}
	selectionDone := make(chan error, 1)
	go func() {
		selectionDone <- e.SelectExplicitTarget(ids["root"], ids["unattached"], "must-fail")
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("handoff surfaced to application: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed selection did not release handed-off publisher")
	}
	select {
	case <-replayOwned:
	case <-time.After(time.Second):
		t.Fatal("failed selection did not synchronously take replay custody")
	}
	select {
	case err := <-selectionDone:
		t.Fatalf("failed selection returned before its handed-off prefix was sealed: %v", err)
	default:
	}
	if stats := e.ReplayStats(); stats.FramesInUse != 1 || stats.AckNext != 0 || stats.PublishedNext != 1 {
		t.Fatalf("failed selection lost immutable replay ownership: %+v", stats)
	}
	releaseReplayGate()
	select {
	case err := <-selectionDone:
		if err == nil {
			t.Fatal("selection of unattached target unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed selection did not finish after replay attempt was released")
	}
}

func TestSequencedSendsRejectMissingExecutionRuntimeBeforePublication(t *testing.T) {
	tests := []struct {
		name            string
		send            func(*Engine) error
		wantClosing     bool
		wantWriteClosed bool
		wantStreamFin   bool
		wantTerminal    bool
	}{
		{name: "stream-data", send: func(e *Engine) error { _, err := e.SendData([]byte("payload")); return err }},
		{name: "packet-data", send: func(e *Engine) error { return e.SendPacket(nil) }},
		{
			name: "stream-fin", send: func(e *Engine) error { return e.SendStreamFin() },
			wantWriteClosed: true, wantStreamFin: true,
		},
		{
			name: "bye", send: func(e *Engine) error { return e.SendBye(proto.ByeNormal) },
			wantClosing: true, wantTerminal: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			if err := test.send(e); !errors.Is(err, errExecutionRuntimeNotConfigured) {
				t.Fatalf("send without graph runtime error=%v", err)
			}
			stats := e.ReplayStats()
			if seq := atomic.LoadUint64(&e.sendSeq); seq != 0 {
				t.Fatalf("send sequence advanced to %d", seq)
			}
			if stats.PublishedNext != 0 || stats.FramesInUse != 0 || stats.BytesInUse != 0 {
				t.Fatalf("replay state changed: %+v", stats)
			}
			if e.sendClosing.Load() {
				t.Fatal("missing-runtime failure polluted sendClosing")
			}
			if e.sendWriteClosed.Load() {
				t.Fatal("missing-runtime failure polluted sendWriteClosed")
			}
			assertEngineSignalOpen(t, e.streamFinDone, "stream FIN once")
			assertEngineSignalOpen(t, e.terminalDone, "terminal once")

			targets := configureLeafSelectorRuntime(t, e, "path")
			path := newLifecycleHealthyPath()
			attachFixturePath(t, e, path, transport.PathSpec{Transport: "memory", Address: "runtime-recovery"}, targets["path"])
			if err := test.send(e); err != nil {
				t.Fatalf("same operation after configuring runtime: %v", err)
			}
			if writes := path.writes.Load(); writes == 0 {
				t.Fatal("recovered operation did not reach the configured path")
			}
			if got := e.sendClosing.Load(); got != test.wantClosing {
				t.Fatalf("sendClosing after recovered operation=%v want %v", got, test.wantClosing)
			}
			if got := e.sendWriteClosed.Load(); got != test.wantWriteClosed {
				t.Fatalf("sendWriteClosed after recovered operation=%v want %v", got, test.wantWriteClosed)
			}
			assertEngineSignalState(t, e.streamFinDone, test.wantStreamFin, "stream FIN once")
			assertEngineSignalState(t, e.terminalDone, test.wantTerminal, "terminal once")
			if test.wantStreamFin || test.wantTerminal {
				if err := test.send(e); err != nil {
					t.Fatalf("idempotent recovered operation: %v", err)
				}
			}
		})
	}
}

func assertEngineSignalOpen(t *testing.T, signal <-chan struct{}, label string) {
	t.Helper()
	assertEngineSignalState(t, signal, false, label)
}

func assertEngineSignalState(t *testing.T, signal <-chan struct{}, wantClosed bool, label string) {
	t.Helper()
	select {
	case <-signal:
		if !wantClosed {
			t.Fatalf("%s was consumed by the rejected operation", label)
		}
	default:
		if wantClosed {
			t.Fatalf("%s did not complete after runtime recovery", label)
		}
	}
}

func TestRuntimeLessPathsNeverPublishExecutionAuthority(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.AttachPath(newLifecycleHealthyPath(), transport.PathSpec{Transport: "memory", Address: "a"}); err != nil {
		t.Fatal(err)
	}
	_, err := e.AttachPath(newLifecycleHealthyPath(), transport.PathSpec{Transport: "memory", Address: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if active := e.ActivePath(); active != 0 {
		t.Fatalf("runtime-less paths published active route %d", active)
	}
	if state := e.State(); state == BridgeActive {
		t.Fatalf("runtime-less paths published active lifecycle state %s", state)
	}
	if migrations := e.MigrationCount(); migrations != 0 {
		t.Fatalf("runtime-less path publication counted %d migrations", migrations)
	}
}

func TestRecursiveExplicitMigrateChangesActualDataRoute(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	captures := make(map[string]*captureDispatchPath, 2)
	for _, name := range []string{"a", "b"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		id, err := e.AttachPathBound(capture, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name],
			PeerTXTargetID:  ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = id
	}

	if _, err := e.SendData([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if err := e.SelectExplicitTarget(ids["root"], ids["b"], "explicit"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendData([]byte("after")); err != nil {
		t.Fatal(err)
	}

	for _, seq := range captures["a"].dataSequences() {
		if seq >= 1 {
			t.Fatalf("post-migration DATA remained on a: a=%v b=%v", captures["a"].dataSequences(), captures["b"].dataSequences())
		}
	}
	found := false
	for _, seq := range captures["b"].dataSequences() {
		if seq == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-migration DATA did not reach b: a=%v b=%v", captures["a"].dataSequences(), captures["b"].dataSequences())
	}
}

func TestRecursiveSelectedTargetReattachRestoresDesiredIncarnation(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	attach := func(name string) (uint32, *captureDispatchPath) {
		t.Helper()
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		capture := &captureDispatchPath{PathConn: path}
		id, err := e.AttachPathBound(capture, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name], PeerTXTargetID: ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		return id, capture
	}
	aID, aCapture := attach("a")
	bID, _ := attach("b")
	if _, err := e.SendData([]byte("baseline-a")); err != nil {
		t.Fatal(err)
	}
	baselineA := aCapture.dataSequences()
	if len(baselineA) != 1 {
		t.Fatalf("baseline A DATA=%v, want exactly one sequence", baselineA)
	}
	if !closeLinearizationAckThrough(e, baselineA[0]+1) {
		t.Fatalf("could not ACK baseline A DATA sequence %d", baselineA[0])
	}
	if err := e.SelectExplicitTarget(ids["root"], ids["b"], "explicit"); err != nil {
		t.Fatal(err)
	}
	e.policyStateMu.Lock()
	selectedGeneration := e.policyGeneration
	e.policyStateMu.Unlock()
	if err := e.RemovePath(bID); err != nil {
		t.Fatal(err)
	}
	if active := e.ActivePath(); active != aID {
		t.Fatalf("death failover active=%d want a=%d", active, aID)
	}
	migrationsBeforeRecovery := e.MigrationCount()
	recoveredID, recovered := attach("b")
	if active := e.ActivePath(); active != recoveredID {
		t.Fatalf("reattach active=%d want recovered desired=%d", active, recoveredID)
	}
	if e.MigrationCount() != migrationsBeforeRecovery+1 {
		t.Fatalf("reattach migrations=%d want %d", e.MigrationCount(), migrationsBeforeRecovery+1)
	}
	migrationsBefore := e.MigrationCount()
	if err := e.SelectExplicitTarget(ids["root"], ids["b"], "explicit"); err != nil {
		t.Fatal(err)
	}
	if active := e.ActivePath(); active != recoveredID {
		t.Fatalf("same-target refresh active=%d want recovered=%d", active, recoveredID)
	}
	e.policyStateMu.Lock()
	refreshedGeneration := e.policyGeneration
	e.policyStateMu.Unlock()
	if refreshedGeneration != selectedGeneration {
		t.Fatalf("same-target physical refresh advanced policy generation=%d want %d", refreshedGeneration, selectedGeneration)
	}
	if e.MigrationCount() != migrationsBefore {
		t.Fatalf("same-target no-op migrations=%d want %d", e.MigrationCount(), migrationsBefore)
	}
	if _, err := e.SendData([]byte("recovered")); err != nil {
		t.Fatal(err)
	}
	expectedSeq := dataSequenceForPayload(t, e, []byte("recovered"))
	if !closeLinearizationAckThrough(e, expectedSeq+1) {
		t.Fatalf("could not ACK recovered DATA sequence %d", expectedSeq)
	}
	if got := aCapture.dataSequences(); !slices.Equal(got, baselineA) {
		t.Fatalf("recovered send changed old A DATA: before=%v after=%v", baselineA, got)
	}
	if got := recovered.dataSequences(); !slices.Equal(got, []uint64{expectedSeq}) {
		t.Fatalf("recovered B DATA=%v, want exactly [%d]", got, expectedSeq)
	}
	migrationsAfter := e.MigrationCount()
	if err := e.SelectExplicitTarget(ids["root"], ids["b"], "explicit"); err != nil {
		t.Fatal(err)
	}
	if e.MigrationCount() != migrationsAfter {
		t.Fatal("unchanged physical projection counted an extra migration")
	}
}

func dataSequenceForPayload(t *testing.T, e *Engine, payload []byte) uint64 {
	t.Helper()
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	var (
		sequence uint64
		matches  int
	)
	for _, entry := range e.sendHist.entries {
		if len(entry.frame) < proto.HeaderSize {
			continue
		}
		hdr, err := proto.DecodeHeader(entry.frame[:proto.HeaderSize])
		if err != nil || hdr.Type != proto.FrameData || !bytes.Equal(entry.frame[proto.HeaderSize:], payload) {
			continue
		}
		sequence = hdr.Seq
		matches++
	}
	if matches != 1 {
		t.Fatalf("replay ledger has %d DATA frames for payload %q, want exactly one", matches, payload)
	}
	return sequence
}

func TestRecursiveReplayHonorsRootSelectorInsteadOfInactiveNestedScope(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	captures := make(map[string]*captureDispatchPath, 3)
	for _, name := range []string{"a", "b", "c"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		if _, err := e.AttachPathBound(capture, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name],
			PeerTXTargetID:  ids[name],
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.SelectLocalTarget(ids["inner"], ids["c"], "inactive-nested"); err != nil {
		t.Fatal(err)
	}

	frame := executionDataFrame(t, 77, []byte("replay"))
	reservePublishedTestFrame(t, e, frame)
	if err := e.redistributeFrames([][]byte{frame}); err != nil {
		t.Fatal(err)
	}
	if got := captures["a"].dataSequences(); len(got) != 1 || got[0] != 77 {
		t.Fatalf("root-selected replay on a=%v, want [77]", got)
	}
	if got := captures["b"].dataSequences(); len(got) != 0 {
		t.Fatalf("replay leaked to inactive b: %v", got)
	}
	if got := captures["c"].dataSequences(); len(got) != 0 {
		t.Fatalf("replay leaked through inactive nested selection to c: %v", got)
	}
}

func TestInactiveNestedSelectorCannotRewriteRootActivePath(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	pathIDs := make(map[string]uint32, 3)
	for _, name := range []string{"a", "b", "c"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name], PeerTXTargetID: ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		pathIDs[name] = id
	}
	if got := e.ActivePath(); got != pathIDs["a"] {
		t.Fatalf("initial active=%d, want a=%d", got, pathIDs["a"])
	}
	if err := e.SelectLocalTarget(ids["inner"], ids["c"], "inactive-preselection"); err != nil {
		t.Fatal(err)
	}
	if got := e.ActivePath(); got != pathIDs["a"] {
		t.Fatalf("inactive nested selector rewrote active=%d, want root a=%d", got, pathIDs["a"])
	}
	if err := e.SelectLocalTarget(ids["root"], ids["inner"], "activate-inner"); err != nil {
		t.Fatal(err)
	}
	if got := e.ActivePath(); got != pathIDs["c"] {
		t.Fatalf("activated nested selector active=%d, want preselected c=%d", got, pathIDs["c"])
	}
}

func executionDataFrame(t *testing.T, seq uint64, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: seq}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}
