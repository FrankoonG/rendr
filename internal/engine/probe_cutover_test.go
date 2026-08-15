package engine

import (
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type probeCutoverCapturePath struct {
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	frames    [][]byte
	onData    func()
}

type selectorStallSuccessPath struct {
	*probeCutoverCapturePath
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *selectorStallSuccessPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData {
			p.once.Do(func() { close(p.started) })
			<-p.release
		}
	}
	return p.probeCutoverCapturePath.Write(frame)
}

func newProbeCutoverCapturePath() *probeCutoverCapturePath {
	return &probeCutoverCapturePath{closed: make(chan struct{})}
}

func (p *probeCutoverCapturePath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *probeCutoverCapturePath) Write(frame []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData && p.onData != nil {
			p.onData()
		}
	}
	p.mu.Lock()
	p.frames = append(p.frames, append([]byte(nil), frame...))
	p.mu.Unlock()
	return len(frame), nil
}

func (p *probeCutoverCapturePath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *probeCutoverCapturePath) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (p *probeCutoverCapturePath) OnDeath(func(transport.DeathCause, error)) {}
func (p *probeCutoverCapturePath) LocalAddr() string                         { return "cutover-local" }
func (p *probeCutoverCapturePath) RemoteAddr() string                        { return "cutover-remote" }

func (p *probeCutoverCapturePath) dataSequences() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	sequences := make([]uint64, 0, len(p.frames))
	for _, frame := range p.frames {
		if len(frame) < proto.HeaderSize {
			continue
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData {
			sequences = append(sequences, header.Seq)
		}
	}
	return sequences
}

func (p *probeCutoverCapturePath) frameHeaders() []proto.Header {
	p.mu.Lock()
	defer p.mu.Unlock()
	headers := make([]proto.Header, 0, len(p.frames))
	for _, frame := range p.frames {
		if len(frame) < proto.HeaderSize {
			continue
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil {
			headers = append(headers, header)
		}
	}
	return headers
}

func TestBeginSelectorCutoverRejectsGenerationExhaustionBeforeMutation(t *testing.T) {
	wake := make(chan struct{})
	e := &Engine{selectorCutoverGeneration: ^uint64(0), selectorCutoverWake: wake}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		e.beginSelectorCutover()
	}()
	if recovered == nil {
		t.Fatal("selector cutover generation exhaustion did not panic")
	}
	if e.selectorCutoverGeneration != ^uint64(0) || e.selectorCutoverPending ||
		e.selectorCutoverHandedOff || e.selectorCutoverWake != wake {
		t.Fatalf("exhausted cutover mutated state: generation=%d pending=%t handed_off=%t wake_changed=%t",
			e.selectorCutoverGeneration, e.selectorCutoverPending,
			e.selectorCutoverHandedOff, e.selectorCutoverWake != wake)
	}
	select {
	case <-wake:
		t.Fatal("exhausted cutover closed the existing wake channel")
	default:
	}
}

func TestDetachedStreamStartedDuringPendingCutoverIsHandedOff(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })

	generation := e.beginSelectorCutover()
	baseline, handedOffAtStart := e.beginDetachedStreamDispatch()
	defer e.completeDetachedStreamDispatch()
	defer e.finishSelectorCutover(generation)

	if !handedOffAtStart {
		t.Fatal("dispatch started during pending cutover did not inherit handoff")
	}
	if !e.detachedStreamDispatchHandedOff(baseline, handedOffAtStart) {
		t.Fatal("dispatch started during pending cutover escaped replay custody")
	}
}

func TestDetachedStreamPublishedDuringPendingCutoverWaitsForReplay(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newProbeCutoverCapturePath()
	attachFixturePath(t, e, path,
		transport.PathSpec{Transport: "memory", Address: "pending-cutover"},
		targets["path"],
	)

	generation := e.beginSelectorCutover()
	payload := []byte("published-during-pending-cutover")
	if n, err := e.SendData(payload); n != len(payload) || err != nil {
		t.Fatalf("SendData=(%d,%v), want (%d,nil)", n, err, len(payload))
	}
	if got := path.dataSequences(); len(got) != 0 {
		t.Fatalf("pending-cutover dispatcher wrote before replay handoff: %v", got)
	}
	e.finishSelectorCutoverWithReplay(generation)
	eventuallyEngine(t, time.Second, func() bool {
		return slices.Equal(path.dataSequences(), []uint64{0})
	})
}

func TestSelectorCutoverReplayPrecedesTerminalPublication(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newProbeCutoverCapturePath()
	attachFixturePath(t, e, path,
		transport.PathSpec{Transport: "memory", Address: "terminal-order"},
		targets["path"],
	)

	generation := e.beginSelectorCutover()
	payload := []byte("replay-before-bye")
	if n, err := e.SendData(payload); n != len(payload) || err != nil {
		t.Fatalf("SendData=(%d,%v), want (%d,nil)", n, err, len(payload))
	}
	replayEntered := make(chan struct{})
	releaseReplay := make(chan struct{})
	var enterOnce, releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseReplay) }) })
	e.boundedReplayBeforeSnapshot = func() {
		enterOnce.Do(func() { close(replayEntered) })
		<-releaseReplay
	}
	finishDone := make(chan struct{})
	go func() {
		e.finishSelectorCutoverWithReplay(generation)
		close(finishDone)
	}()
	select {
	case <-replayEntered:
	case <-time.After(time.Second):
		t.Fatal("cutover did not enter replay while holding the send sequencer")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	time.Sleep(20 * time.Millisecond)
	if got := path.frameHeaders(); len(got) != 0 {
		t.Fatalf("terminal publication overtook blocked replay: %+v", got)
	}
	releaseOnce.Do(func() { close(releaseReplay) })
	select {
	case <-finishDone:
	case <-time.After(time.Second):
		t.Fatal("cutover replay did not finish")
	}
	eventuallyEngine(t, time.Second, func() bool { return len(path.frameHeaders()) >= 2 })
	headers := path.frameHeaders()
	if headers[0].Type != proto.FrameData || headers[0].Seq != 0 ||
		headers[1].Type != proto.FrameCtrl || headers[1].Seq != 1 ||
		proto.CtrlCodeFromFlags(headers[1].Flags) != proto.CtrlBye {
		t.Fatalf("physical order=%+v, want DATA seq0 then BYE seq1", headers)
	}
	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("GracefulClose did not finish its bounded ACK wait")
	}
}

func TestRecursiveProbeStarvedDataSelectionPreemptsBlockedDataDispatch(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	limits := Limits{
		ProbeInterval:        time.Second,
		SelectorDwell:        time.Hour,
		SelectorCooldown:     time.Hour,
		SelectorHysteresis:   0.25,
		SelectorLatencyFloor: time.Millisecond,
	}.Clamp()
	e := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = e.Close() })
	e.tailReplayInitialDelay = time.Hour
	e.tailReplayMaxBackoff = time.Hour
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blocked := newCloseReleasedWritePath()
	healthy := newProbeCutoverCapturePath()
	aID, err := e.AttachPath(blocked, transport.PathSpec{Transport: "test", Address: "a", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := e.AttachPath(healthy, transport.PathSpec{Transport: "test", Address: "b", Opts: map[string]string{"name": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.ActivePath() != aID {
		t.Fatalf("initial active=%d want a=%d", e.ActivePath(), aID)
	}
	e.pathsMu.RLock()
	aSlot, bSlot := e.paths[aID], e.paths[bID]
	e.pathsMu.RUnlock()
	now := time.Now()
	seedPathProbeSuccess(e, aSlot, now, 10*time.Millisecond)
	seedPathProbeSuccess(e, bSlot, now, 20*time.Millisecond)
	bDataActive := make(chan uint32, 2)
	healthy.onData = func() {
		select {
		case bDataActive <- e.ActivePath():
		default:
		}
	}

	migrated := make(chan string, 1)
	cancelMigration := e.OnMigrate(func(_, _ uint32, cause string) { migrated <- cause })
	defer cancelMigration()
	writeResult := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("published-before-probe-cutover"))
		writeResult <- err
	}()
	select {
	case <-blocked.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("path A DATA write did not block")
	}
	eventuallyEngine(t, time.Second, func() bool { return aSlot.dispatchStalled.Load() })
	e.issuePathProbe(aSlot)
	var queuedID uint64
	var queued pathProbeObservation
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		defer e.probeMu.Unlock()
		for id, observation := range e.probeOutstanding {
			if observation.slot == aSlot && observation.lifecycle == pathProbeQueued {
				queuedID, queued = id, observation
				return true
			}
		}
		return false
	})
	blockedAt := time.Now()
	status := e.pathProbeStatuses(blockedAt)[aSlot]
	if status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
		t.Fatalf("initial queued probe status=%+v", status)
	}
	starvationFor := pathProbeDataStarvationFor(e.limits.ProbeInterval)
	if starvationFor != 2*time.Second {
		t.Fatalf("DATA-starvation threshold=%v want two measured 1s probe intervals", starvationFor)
	}
	status = e.pathProbeStatuses(blockedAt.Add(starvationFor - time.Nanosecond))[aSlot]
	if status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
		t.Fatalf("pre-threshold queued probe status=%+v", status)
	}
	(&selector{}).evaluateRecursive(e, e.localExecutionRuntime())
	if e.ActivePath() != aID || e.MigrationCount() != 0 {
		t.Fatalf("pre-threshold active/migrations=%d/%d want %d/0", e.ActivePath(), e.MigrationCount(), aID)
	}
	status = e.pathProbeStatuses(blockedAt.Add(starvationFor))[aSlot]
	if status.lifecycle != pathProbeDataStarved || status.failure != pathProbeFailureDataStarved {
		t.Fatalf("eligible queued probe status=%+v", status)
	}
	e.probeMu.Lock()
	queued = e.probeOutstanding[queuedID]
	queuedOnA := 0
	for _, observation := range e.probeOutstanding {
		if observation.slot == aSlot {
			queuedOnA++
		}
	}
	e.probeMu.Unlock()
	if queuedOnA != 1 || queued.lifecycle != pathProbeDataStarved || queued.dataStallGeneration == 0 ||
		queued.dataStallGeneration != aSlot.dispatchStallGen.Load() || !queued.deadline.IsZero() ||
		!queued.writeStartedAt.IsZero() || !queued.writeCommittedAt.IsZero() {
		t.Fatalf("factual queued observation=%+v outstanding-on-A=%d dispatch-generation=%d", queued, queuedOnA, aSlot.dispatchStallGen.Load())
	}
	select {
	case active := <-bDataActive:
		t.Fatalf("stalled selector silently dispatched on B while active=%d want A=%d", active, aID)
	case <-time.After(25 * time.Millisecond):
	}
	now = time.Now()
	seedPathProbeSuccess(e, bSlot, now, 20*time.Millisecond)
	replaySnapshotEntered := make(chan struct{})
	releaseReplaySnapshot := make(chan struct{})
	var replaySnapshotOnce sync.Once
	var releaseReplayOnce sync.Once
	e.boundedReplayBeforeSnapshot = func() {
		replaySnapshotOnce.Do(func() { close(replaySnapshotEntered) })
		<-releaseReplaySnapshot
	}
	t.Cleanup(func() { releaseReplayOnce.Do(func() { close(releaseReplaySnapshot) }) })

	evaluated := make(chan struct{})
	go func() {
		(&selector{}).evaluateRecursive(e, e.localExecutionRuntime())
		close(evaluated)
	}()
	select {
	case <-replaySnapshotEntered:
	case <-time.After(time.Second):
		t.Fatal("probe-starved-data selection did not freeze the replay prefix")
	}
	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatalf("application write observed cutover: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("application write did not hand published frame to replay")
	}
	nextWriteResult := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("published-after-probe-cutover"))
		nextWriteResult <- err
	}()
	select {
	case err := <-nextWriteResult:
		t.Fatalf("post-cutover publication overtook frozen replay: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if sequences := healthy.dataSequences(); len(sequences) != 0 {
		t.Fatalf("replacement carrier received DATA before frozen replay release: %v", sequences)
	}
	releaseReplayOnce.Do(func() { close(releaseReplaySnapshot) })
	select {
	case <-evaluated:
	case <-time.After(time.Second):
		t.Fatal("probe-starved-data selection did not finish after replay release")
	}
	select {
	case err := <-nextWriteResult:
		if err != nil {
			t.Fatalf("post-cutover publication failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-cutover publication remained blocked after replay")
	}
	if e.ActivePath() != bID || e.MigrationCount() != 1 {
		t.Fatalf("cutover active/migrations=%d/%d want %d/1", e.ActivePath(), e.MigrationCount(), bID)
	}
	for index := 0; index < 2; index++ {
		select {
		case active := <-bDataActive:
			if active != bID {
				t.Fatalf("B DATA %d started while active=%d want B=%d", index, active, bID)
			}
		case <-time.After(time.Second):
			t.Fatalf("B DATA %d did not start", index)
		}
	}
	select {
	case cause := <-migrated:
		if cause != "probe-starved-data" {
			t.Fatalf("migration cause=%q want probe-starved-data", cause)
		}
	case <-time.After(time.Second):
		t.Fatal("probe-starved-data migration hook did not fire")
	}
	deadline := time.Now().Add(time.Second)
	for len(healthy.dataSequences()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sequences := healthy.dataSequences(); len(sequences) != 2 || sequences[0] != 0 || sequences[1] != 1 {
		t.Fatalf("bounded replay/new publication sequences on B=%v want [0 1]", sequences)
	}
	if paths := e.Paths(); len(paths) != 2 {
		t.Fatalf("probe cutover detached the blackholed carrier: paths=%v", paths)
	}
	e.policyStateMu.Lock()
	generation, selected := e.policyGeneration, e.policySelections[ids["root"]]
	e.policyStateMu.Unlock()
	if generation != 1 || selected != ids["b"] {
		t.Fatalf("policy generation/selection=%d/%x want 1/%x", generation, selected, ids["b"])
	}
}

func TestRecursivePathDeathImmediatelyHandsBlockedDispatchToReplay(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{
		MigrationBudget: time.Second,
		ProbeInterval:   time.Hour,
	}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	e.tailReplayInitialDelay = time.Hour
	e.tailReplayMaxBackoff = time.Hour
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blocked := &selectorStallSuccessPath{
		probeCutoverCapturePath: newProbeCutoverCapturePath(),
		started:                 make(chan struct{}),
		release:                 make(chan struct{}),
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(blocked.release) }) })
	healthy := newProbeCutoverCapturePath()
	aID, err := e.AttachPath(blocked, transport.PathSpec{Transport: "test", Address: "a", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := e.AttachPath(healthy, transport.PathSpec{Transport: "test", Address: "b", Opts: map[string]string{"name": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.ActivePath() != aID {
		t.Fatalf("initial active=%d want a=%d", e.ActivePath(), aID)
	}

	writeResult := make(chan error, 1)
	go func() {
		_, sendErr := e.SendData([]byte("published-before-physical-death"))
		writeResult <- sendErr
	}()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("DATA did not enter the selected physical writer")
	}
	e.pathsMu.RLock()
	aSlot := e.paths[aID]
	e.pathsMu.RUnlock()
	if aSlot == nil {
		t.Fatal("selected path disappeared before injected death")
	}
	e.onPathDeath(aID, aSlot.owner, transport.CauseTransportError, net.ErrClosed)

	select {
	case sendErr := <-writeResult:
		if sendErr != nil {
			t.Fatalf("application write observed physical death: %v", sendErr)
		}
	case <-time.After(time.Second):
		t.Fatal("physical death did not hand blocked DATA to replay")
	}
	eventuallyEngine(t, time.Second, func() bool { return len(healthy.dataSequences()) > 0 })
	if sequences := healthy.dataSequences(); len(sequences) != 1 || sequences[0] != 0 {
		t.Fatalf("death replay sequences=%v want exactly [0]", sequences)
	}
	if e.ActivePath() != bID || e.MigrationCount() != 1 {
		t.Fatalf("death fallback active/migrations=%d/%d want %d/1", e.ActivePath(), e.MigrationCount(), bID)
	}
	desired, effective, ok := e.localExecutionRuntime().selectedChild(ids["root"])
	if !ok || desired != ids["b"] || effective != ids["b"] {
		t.Fatalf("death policy desired/effective=%x/%x ok=%t want b/b", desired, effective, ok)
	}
	select {
	case <-blocked.release:
		t.Fatal("test released the failed physical writer before replay completed")
	default:
	}
	releaseOnce.Do(func() { close(blocked.release) })
}

func TestRecursiveSelectorStallCompletionDoesNotRedispatchSameFrame(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	e.tailReplayInitialDelay = time.Hour
	e.tailReplayMaxBackoff = time.Hour
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	a := &selectorStallSuccessPath{
		probeCutoverCapturePath: newProbeCutoverCapturePath(),
		started:                 make(chan struct{}),
		release:                 make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseA := func() { releaseOnce.Do(func() { close(a.release) }) }
	t.Cleanup(releaseA)
	b := newProbeCutoverCapturePath()
	aID, err := e.AttachPath(a, transport.PathSpec{Transport: "test", Address: "a", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AttachPath(b, transport.PathSpec{Transport: "test", Address: "b", Opts: map[string]string{"name": "b"}}); err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	aSlot := e.paths[aID]
	e.pathsMu.RUnlock()
	result := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("single-owner-after-stall"))
		result <- err
	}()
	select {
	case <-a.started:
	case <-time.After(time.Second):
		t.Fatal("selected DATA write did not start")
	}
	eventuallyEngine(t, time.Second, func() bool { return aSlot.dispatchStalled.Load() })
	if sequences := b.dataSequences(); len(sequences) != 0 {
		t.Fatalf("stalled selector leaked DATA to B: %v", sequences)
	}
	releaseA()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("completed selected write did not return")
	}
	eventuallyEngine(t, time.Second, func() bool { return !aSlot.dispatchStalled.Load() })
	if sequences := a.dataSequences(); len(sequences) != 1 || sequences[0] != 0 {
		t.Fatalf("selected path DATA sequences=%v want [0]", sequences)
	}
	if dispatches, first := aSlot.dataDispatches.Load(), aSlot.firstDataDispatches.Load(); dispatches != 1 || first != 1 {
		t.Fatalf("selected path dispatches/first=%d/%d want 1/1", dispatches, first)
	}
	if sequences := b.dataSequences(); len(sequences) != 0 {
		t.Fatalf("healthy sibling received selector DATA without policy: %v", sequences)
	}
	if e.ActivePath() != aID || e.MigrationCount() != 0 {
		t.Fatalf("stall completion changed active/migrations=%d/%d", e.ActivePath(), e.MigrationCount())
	}
}

func TestRecursiveQualitySelectionPreemptsBlockedDataDispatch(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	limits := Limits{
		ProbeInterval:        10 * time.Millisecond,
		SelectorDwell:        time.Second,
		SelectorCooldown:     time.Hour,
		SelectorHysteresis:   0.25,
		SelectorLatencyFloor: time.Millisecond,
	}.Clamp()
	e := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = e.Close() })
	e.tailReplayInitialDelay = time.Hour
	e.tailReplayMaxBackoff = time.Hour
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blocked := newCloseReleasedWritePath()
	healthy := newProbeCutoverCapturePath()
	aID, err := e.AttachPath(blocked, transport.PathSpec{Transport: "test", Address: "a", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := e.AttachPath(healthy, transport.PathSpec{Transport: "test", Address: "b", Opts: map[string]string{"name": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	aSlot, bSlot := e.paths[aID], e.paths[bID]
	e.pathsMu.RUnlock()
	now := time.Now()
	seedPathProbeSuccess(e, aSlot, now, 100*time.Millisecond)
	seedPathProbeSuccess(e, bSlot, now, 10*time.Millisecond)
	runtime := e.localExecutionRuntime()
	selector := &selector{}
	selector.evaluateRecursive(e, runtime)
	runtime.mu.Lock()
	state := runtime.selectors[ids["root"]]
	if state == nil || state.qualityCandidate != ids["b"] {
		runtime.mu.Unlock()
		t.Fatalf("quality candidate was not staged: %+v", state)
	}
	state.qualitySince = now.Add(-time.Hour)
	runtime.mu.Unlock()

	writeResult := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("published-before-quality-cutover"))
		writeResult <- err
	}()
	select {
	case <-blocked.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("path A DATA write did not block")
	}
	evaluated := make(chan struct{})
	go func() {
		selector.evaluateRecursive(e, runtime)
		close(evaluated)
	}()
	select {
	case <-evaluated:
	case <-time.After(time.Second):
		t.Fatal("quality selection remained blocked behind DATA dispatch")
	}
	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatalf("application write observed quality cutover: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("application write did not hand published frame to quality replay")
	}
	if e.ActivePath() != bID || e.MigrationCount() != 1 {
		t.Fatalf("quality cutover active/migrations=%d/%d want %d/1", e.ActivePath(), e.MigrationCount(), bID)
	}
	deadline := time.Now().Add(time.Second)
	for len(healthy.dataSequences()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sequences := healthy.dataSequences(); len(sequences) != 1 || sequences[0] != 0 {
		t.Fatalf("quality bounded replay sequences on B=%v want [0]", sequences)
	}
}
