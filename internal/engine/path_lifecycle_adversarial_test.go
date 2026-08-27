package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestSynchronousCleanDeathCallbackDoesNotMakeCloseWaitForItsReader(t *testing.T) {
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	local, peer := net.Pipe()
	defer peer.Close()
	path := basetcp.Wrap(local)
	path.MarkByeSeen()
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "tcp", Address: "synchronous-clean-death"}); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		_ = e.Close()
		t.Fatal("clean transport death did not quiesce the engine")
	}
	if err := e.Close(); err != nil {
		t.Fatalf("clean transport callback poisoned Close result: %v", err)
	}
	if err := e.CloseErr(); !errors.Is(err, io.EOF) {
		t.Fatalf("CloseErr = %v, want io.EOF", err)
	}
}

func TestPreparedPathIsInvisibleUntilBridgeAckCommit(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	a, aPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	aCapture := &captureDispatchPath{PathConn: a}
	if _, err := e.AttachPathBound(aCapture, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = bPeer.Close() })
	bCapture := &captureDispatchPath{PathConn: b}
	pendingID, err := e.PreparePathBound(bCapture, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(e.Paths()); got != 1 {
		t.Fatalf("prepared path leaked into Paths: %d", got)
	}
	if _, err := e.SendData([]byte("before-ack")); err != nil {
		t.Fatal(err)
	}
	if got := bCapture.dataSequences(); len(got) != 0 {
		t.Fatalf("prepared path carried DATA before BRIDGE_ACK: %v", got)
	}
	if err := e.CommitPathAttach(pendingID); err != nil {
		t.Fatal(err)
	}
	if err := e.SelectLocalTarget(ids["root"], ids["b"], "after-ack"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendData([]byte("after-ack")); err != nil {
		t.Fatal(err)
	}
	if got := bCapture.dataSequences(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("committed path DATA=%v, want [1]", got)
	}
}

func TestSameLeafAdmissionIsSerializedAndRollsBackToPredecessor(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	e := New(SideServer, NewClientFlowID(), Limits{ZombieMaxMigrations: 10}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	binding := PathBinding{LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]}

	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &observedClosePath{PathConn: oldBase}
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding)
	if err != nil {
		t.Fatal(err)
	}

	winnerBase, winnerPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = winnerPeer.Close() })
	winner := &observedClosePath{PathConn: winnerBase}
	winnerID, err := e.PreparePathBound(winner, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding)
	if err != nil {
		t.Fatal(err)
	}
	concurrentBase, concurrentPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = concurrentPeer.Close() })
	concurrent := &observedClosePath{PathConn: concurrentBase}
	if _, err := e.PreparePathBound(concurrent, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding); !errors.Is(err, ErrPathAttachInProgress) {
		t.Fatalf("concurrent prepare error = %v, want %v", err, ErrPathAttachInProgress)
	}

	if paths := e.Paths(); len(paths) != 1 || paths[0].ID != oldID {
		t.Fatalf("pending replacement displaced old path before stage: %v", paths)
	}
	if err := e.StagePathAttach(winnerID); err != nil {
		t.Fatalf("stage winner: %v", err)
	}
	stagedBase, stagedPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = stagedPeer.Close() })
	stagedConcurrent := &observedClosePath{PathConn: stagedBase}
	if _, err := e.PreparePathBound(stagedConcurrent, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding); !errors.Is(err, ErrPathAttachInProgress) {
		t.Fatalf("prepare while staged error = %v, want %v", err, ErrPathAttachInProgress)
	}
	if paths := e.Paths(); len(paths) != 1 || paths[0].ID != oldID {
		t.Fatalf("staged path became TX-visible: %v", paths)
	}
	if err := e.ActivateStagedPath(winnerID, true); err != nil {
		t.Fatalf("activate winner: %v", err)
	}
	if paths := e.Paths(); len(paths) != 1 || paths[0].ID != winnerID {
		t.Fatalf("activated path set = %v, want winner only", paths)
	}
	if got := e.ActivePath(); got != winnerID {
		t.Fatalf("active path = %d, want winner %d", got, winnerID)
	}
	if old.closed.Load() {
		t.Fatal("predecessor closed before admission confirmation")
	}
	if !concurrent.closed.Load() || !stagedConcurrent.closed.Load() {
		t.Fatalf("rejected candidates closed = %t/%t, want true/true", concurrent.closed.Load(), stagedConcurrent.closed.Load())
	}
	failMemoryPath(t, e, winnerID, winnerBase, errors.New("successor transport failed"))
	deadline := time.Now().Add(time.Second)
	for e.ActivePath() != oldID && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := e.ActivePath(); got != oldID {
		t.Fatalf("active path after successor death = %d, want predecessor %d", got, oldID)
	}
	if old.closed.Load() {
		t.Fatal("rollback predecessor was closed")
	}
	if got := e.MigrationCount(); got != 2 {
		t.Fatalf("activate plus rollback migrations = %d, want 2", got)
	}
}

func TestPathSpecOptsAreOwnedAcrossEngineBoundaries(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	spec := transport.PathSpec{Transport: "memory", Address: "snapshot", Opts: map[string]string{"token": "frozen"}}
	id, err := e.AttachPath(path, spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Opts["token"] = "caller-mutated"
	first := e.Paths()
	if got := first[0].Spec.Opts["token"]; got != "frozen" {
		t.Fatalf("stored PathSpec option = %q, want frozen", got)
	}
	first[0].Spec.Opts["token"] = "snapshot-mutated"
	if got := e.Paths()[0].Spec.Opts["token"]; got != "frozen" {
		t.Fatalf("second PathSpec snapshot option = %q, want frozen", got)
	}

	mutated := make(chan struct{})
	observed := make(chan string, 1)
	e.OnPathDeath(func(event PathDeathEvent) {
		event.Spec.Opts["token"] = "hook-mutated"
		close(mutated)
	})
	e.OnPathDeath(func(event PathDeathEvent) {
		<-mutated
		observed <- event.Spec.Opts["token"]
	})
	failMemoryPath(t, e, id, path, errors.New("path transport failed"))
	select {
	case got := <-observed:
		if got != "frozen" {
			t.Fatalf("death hook PathSpec option = %q, want frozen", got)
		}
	case <-time.After(time.Second):
		t.Fatal("death hook snapshots were not delivered")
	}
}

func TestSessionPathReservationsAreBounded(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	ids := make([]uint32, 0, maxSessionPaths)
	peers := make([]transport.PathConn, 0, maxSessionPaths+1)
	for i := 0; i < maxSessionPaths; i++ {
		path, peer := newMemoryPathPair()
		peers = append(peers, peer)
		id, err := e.PreparePathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{})
		if err != nil {
			t.Fatalf("prepare path %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	extra, extraPeer := newMemoryPathPair()
	peers = append(peers, extraPeer)
	if _, err := e.PreparePathBound(extra, transport.PathSpec{Transport: "memory"}, PathBinding{}); err == nil {
		t.Fatalf("accepted more than %d simultaneous path reservations", maxSessionPaths)
	}
	for _, id := range ids {
		e.AbortPathAttach(id, nil)
	}
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func TestBridgeAttachReplayCacheIsBounded(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	flow := NewClientFlowID()
	e := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	localInstance := proto.InstanceID{1}
	peerInstance := proto.InstanceID{2}
	e.SetLocalInstanceID(localInstance)
	e.SetPeerInstanceID(peerInstance)
	binding := e.peerGraphBinding()
	var newest [16]byte
	for i := 0; i < maxSeenAttachIDs+17; i++ {
		newest = [16]byte{byte(i), byte(i >> 8), 1}
		tag := proto.BridgeTagPayload{
			BridgeID: flow, AttachID: newest, InstanceID: peerInstance,
			ExpectedPeerInstanceID: localInstance, SessionEpoch: proto.SessionEpoch(flow),
			Direction: peerSenderDirection(e.side), GraphRevision: binding.revision,
			GraphDigest: binding.digest, TargetID: ids["a"],
		}
		if err := e.ValidateBridgeBinding(tag); err != nil {
			t.Fatalf("validate attach %d: %v", i, err)
		}
	}
	e.attachMu.Lock()
	cacheLen := len(e.seenAttach)
	orderLen := len(e.seenAttachFIFO)
	e.attachMu.Unlock()
	if cacheLen != maxSeenAttachIDs || orderLen != maxSeenAttachIDs {
		t.Fatalf("attach replay cache=(%d,%d), want (%d,%d)", cacheLen, orderLen, maxSeenAttachIDs, maxSeenAttachIDs)
	}
	binding = e.peerGraphBinding()
	duplicate := proto.BridgeTagPayload{
		BridgeID: flow, AttachID: newest, InstanceID: peerInstance,
		ExpectedPeerInstanceID: localInstance, SessionEpoch: proto.SessionEpoch(flow),
		Direction: peerSenderDirection(e.side), GraphRevision: binding.revision,
		GraphDigest: binding.digest, TargetID: ids["a"],
	}
	if err := e.ValidateBridgeBinding(duplicate); err != ErrDuplicateAttach {
		t.Fatalf("newest replay error=%v, want %v", err, ErrDuplicateAttach)
	}
}

type blockingClosePath struct {
	transport.PathConn
	started chan struct{}
	release chan struct{}
	once    sync.Once
	err     error
}

func (p *blockingClosePath) Close() error {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return errors.Join(p.PathConn.Close(), p.err)
}

type observedClosePath struct {
	transport.PathConn
	closed atomic.Bool
}

type boundedRetirementClosePath struct {
	release   <-chan struct{}
	calls     atomic.Int32
	started   *atomic.Int32
	active    *atomic.Int32
	maxActive *atomic.Int32
}

func (path *boundedRetirementClosePath) Read([]byte) (int, error)    { return 0, io.EOF }
func (path *boundedRetirementClosePath) Write(p []byte) (int, error) { return len(p), nil }
func (path *boundedRetirementClosePath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}
func (path *boundedRetirementClosePath) LocalAddr() string                         { return "retirement-local" }
func (path *boundedRetirementClosePath) RemoteAddr() string                        { return "retirement-remote" }
func (path *boundedRetirementClosePath) OnDeath(func(transport.DeathCause, error)) {}

func (path *boundedRetirementClosePath) Close() error {
	path.calls.Add(1)
	now := path.active.Add(1)
	for previous := path.maxActive.Load(); now > previous; previous = path.maxActive.Load() {
		if path.maxActive.CompareAndSwap(previous, now) {
			break
		}
	}
	path.started.Add(1)
	<-path.release
	path.active.Add(-1)
	return nil
}

type preSlotBlockingPath struct {
	transport.PathConn
	frameStarted chan struct{}
	frameRelease chan struct{}
	frameOnce    sync.Once
	frameCalls   atomic.Int32
	closeStarted chan struct{}
	closeRelease chan struct{}
	closeOnce    sync.Once
}

func (path *preSlotBlockingPath) MaxFrameSize() int {
	path.frameCalls.Add(1)
	path.frameOnce.Do(func() { close(path.frameStarted) })
	<-path.frameRelease
	return 1
}

func (path *preSlotBlockingPath) Close() error {
	path.closeOnce.Do(func() { close(path.closeStarted) })
	<-path.closeRelease
	return path.PathConn.Close()
}

func (p *observedClosePath) Close() error {
	p.closed.Store(true)
	return p.PathConn.Close()
}

func TestEngineCloseCannotBePinnedByOnePathAdapter(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	blockedBase, blockedPeer := newMemoryPathPair()
	defer blockedPeer.Close()
	lateCloseErr := errors.New("late adapter close failure")
	blocked := &blockingClosePath{
		PathConn: blockedBase, started: make(chan struct{}), release: make(chan struct{}), err: lateCloseErr,
	}
	if _, err := e.AttachPath(blocked, transport.PathSpec{Transport: "memory"}); err != nil {
		t.Fatal(err)
	}
	healthyBase, healthyPeer := newMemoryPathPair()
	defer healthyPeer.Close()
	healthy := &observedClosePath{PathConn: healthyBase}
	if _, err := e.AttachPath(healthy, transport.PathSpec{Transport: "memory"}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- e.Close() }()
	select {
	case <-e.Closed():
		t.Fatal("engine reported quiescence while an owned adapter Close was still blocked")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-blocked.started:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("blocked adapter Close was not attempted")
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for !healthy.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !healthy.closed.Load() {
		t.Fatal("blocked adapter prevented healthy path Close")
	}
	var firstCloseErr error
	select {
	case firstCloseErr = <-done:
		if firstCloseErr == nil {
			t.Fatal("bounded Close did not report adapter timeout")
		}
		var teardownDeadline *engineTeardownDeadlineError
		if !errors.As(firstCloseErr, &teardownDeadline) || !errors.Is(firstCloseErr, context.DeadlineExceeded) {
			t.Fatalf("bounded Close error=%v want typed teardown deadline", firstCloseErr)
		}
	case <-time.After(pathCloseTimeout + 100*time.Millisecond):
		t.Fatal("Engine.Close exceeded path adapter timeout")
	}
	select {
	case <-e.Closed():
		t.Fatal("timed-out Close reported quiescence before blocked adapter exited")
	default:
	}
	eventuallyEngine(t, time.Second, func() bool {
		secondCloseErr := e.Close()
		closeErr := e.CloseErr()
		var repeatedDeadline, observedDeadline *pathDispatchCallbackDeadlineError
		return errors.As(secondCloseErr, &repeatedDeadline) &&
			repeatedDeadline.operation == externalPathCloseOperation &&
			errors.As(closeErr, &observedDeadline) &&
			observedDeadline.operation == externalPathCloseOperation
	})
	close(blocked.release)
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("asynchronous reaper did not publish quiescence after adapter exit")
	}
	if err := e.Close(); !errors.Is(err, lateCloseErr) {
		t.Fatalf("repeated Close error=%v did not expose late adapter failure", err)
	}
	if err := e.CloseErr(); !errors.Is(err, lateCloseErr) {
		t.Fatalf("CloseErr=%v did not expose late adapter failure", err)
	}
	t.Run("tracked retirements use bounded reapers under hostile closes", func(t *testing.T) {
		const retirementCount = externalPathRetirementWorkerLimit + 1
		engines := []*Engine{
			New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
			New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
		}
		baselineGoroutines := runtime.NumGoroutine()
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(func() {
			unblock()
			for _, engine := range engines {
				_ = engine.Close()
			}
		})
		var started, active, maxActive atomic.Int32
		paths := make([]*boundedRetirementClosePath, retirementCount)
		slots := make([]*pathSlot, retirementCount)
		for index := 0; index < retirementCount; index++ {
			path := &boundedRetirementClosePath{
				release: release, started: &started, active: &active, maxActive: &maxActive,
			}
			retirementPermit, err := externalPathRetirements.reserve()
			if err != nil {
				t.Fatalf("reserve retirement permit %d: %v", index, err)
			}
			reservation, err := reserveExternalPathCleanup(path)
			if err != nil {
				retirementPermit.release()
				t.Fatalf("reserve retirement cleanup %d: %v", index, err)
			}
			slot := &pathSlot{
				id:                 uint32(index + 1),
				owner:              uint64(index + 1),
				conn:               path,
				spec:               transport.PathSpec{Transport: "bounded-retirement"},
				cleanupReservation: reservation,
				retirementPermit:   retirementPermit,
				recvQ:              make(chan recvFrame),
				writePermit:        newPathWritePermit(),
				quit:               make(chan struct{}),
				doneR:              make(chan struct{}),
				doneW:              make(chan struct{}),
				doneP:              make(chan struct{}),
				admissionDone:      make(chan struct{}),
			}
			engine := engines[index%len(engines)]
			engine.pathsMu.Lock()
			engine.trackPathRetirementLocked(slot)
			engine.pathsMu.Unlock()
			paths[index] = path
			slots[index] = slot
			engine.retirePathAsync(slot)
		}
		eventuallyEngine(t, time.Second, func() bool {
			return started.Load() == externalPathRetirementWorkerLimit
		})
		if got := maxActive.Load(); got > externalPathDurableCallbackWorkerLimit {
			t.Fatalf("retirement close callbacks active=%d limit=%d", got, externalPathDurableCallbackWorkerLimit)
		}
		if got := len(externalPathRetirements.workerLimit); got > externalPathRetirementWorkerLimit {
			t.Fatalf("retirement workers=%d limit=%d", got, externalPathRetirementWorkerLimit)
		}
		if got := paths[retirementCount-1].calls.Load(); got != 0 {
			t.Fatalf("queued retirement close calls=%d want=0", got)
		}
		if delta := runtime.NumGoroutine() - baselineGoroutines; delta >
			2*externalPathRetirementWorkerLimit+5 {
			t.Fatalf("retirement goroutine delta=%d want<=%d",
				delta, 2*externalPathRetirementWorkerLimit+5)
		}
		eventuallyEngine(t, time.Second, func() bool {
			for _, engine := range engines {
				if strings.Contains(engine.retirementDebugSnapshot(), "stage=carrier-callback") {
					return true
				}
			}
			return false
		})
		unblock()
		eventuallyEngine(t, time.Second, func() bool {
			return started.Load() == retirementCount && active.Load() == 0
		})
		for index, path := range paths {
			if got := path.calls.Load(); got != 1 {
				t.Fatalf("retirement path %d close calls=%d want=1", index, got)
			}
			if !slots[index].retireStarted.Load() || !slots[index].retireTracked.Load() {
				t.Fatalf("retirement path %d lost lifecycle tracking", index)
			}
		}
		eventuallyEngine(t, time.Second, func() bool {
			for _, engine := range engines {
				if engine.retirementDebugSnapshot() != "none" {
					return false
				}
			}
			return true
		})
		for index, engine := range engines {
			_ = engine.Close()
			select {
			case <-engine.Closed():
			case <-time.After(time.Second):
				t.Fatalf("retirement engine %d did not quiesce", index)
			}
		}
	})
	t.Run("retirement permits survive recycled cleanup authority", func(t *testing.T) {
		executor := newExternalPathRetirementExecutor(2, 1)
		engines := []*Engine{
			New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
			New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
		}
		readerDone := []chan struct{}{make(chan struct{}), make(chan struct{})}
		var readerDoneOnce [2]sync.Once
		releaseReader := func(index int) {
			readerDoneOnce[index].Do(func() { close(readerDone[index]) })
		}
		t.Cleanup(func() {
			for index := range readerDone {
				releaseReader(index)
			}
			for _, engine := range engines {
				_ = engine.Close()
			}
			executor.shutdown()
		})

		for index, engine := range engines {
			permit, err := executor.reserve()
			if err != nil {
				t.Fatalf("reserve retirement permit %d: %v", index, err)
			}
			owner := &externalPathCallbackOwner{marker: byte(index + 1)}
			cleanup, err := reserveExternalPathDurableCallback(externalPathCloseOperation, owner)
			if err != nil {
				permit.release()
				t.Fatalf("reserve cleanup %d: %v", index, err)
			}
			if index == 0 {
				if err := cleanup.invoke(context.Background(), func() error { return nil }); err != nil {
					permit.release()
					t.Fatalf("complete cleanup reservation: %v", err)
				}
			} else if err := cleanup.releaseReservation(); err != nil {
				permit.release()
				t.Fatalf("release cleanup reservation: %v", err)
			}
			slot := &pathSlot{
				id:                 uint32(index + 1),
				owner:              uint64(index + 1),
				conn:               &boundedRetirementClosePath{},
				spec:               transport.PathSpec{Transport: "recycled-cleanup"},
				cleanupReservation: cleanup,
				retirementPermit:   permit,
				callbackAuthority:  owner,
				recvQ:              make(chan recvFrame),
				writePermit:        newPathWritePermit(),
				quit:               make(chan struct{}),
				doneR:              readerDone[index],
				doneW:              make(chan struct{}),
				doneP:              make(chan struct{}),
				admissionDone:      make(chan struct{}),
			}
			slot.cleanupOnce.Do(func() {})
			slot.readerStarted.Store(true)
			engine.pathsMu.Lock()
			engine.trackPathRetirementLocked(slot)
			engine.pathsMu.Unlock()
			started := time.Now()
			engine.retirePathAsync(slot)
			if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
				t.Fatalf("retirement enqueue %d blocked producer for %s", index, elapsed)
			}
		}

		eventuallyEngine(t, time.Second, func() bool {
			return strings.Contains(engines[0].retirementDebugSnapshot(), "stage=reader")
		})
		if got := executor.activePermits(); got != 2 {
			t.Fatalf("active retirement permits=%d want=2", got)
		}
		if permit, err := executor.reserve(); permit != nil {
			permit.release()
			t.Fatal("retirement capacity was recycled while a reader still blocked")
		} else {
			var capacityErr *pathDispatchCallbackCapacityError
			if !errors.As(err, &capacityErr) || capacityErr.operation != externalPathRetirementOperation {
				t.Fatalf("retirement overflow error=%v want typed capacity", err)
			}
		}

		releaseReader(0)
		eventuallyEngine(t, time.Second, func() bool {
			return strings.Contains(engines[1].retirementDebugSnapshot(), "stage=reader")
		})
		releaseReader(1)
		eventuallyEngine(t, time.Second, func() bool { return executor.activePermits() == 0 })
		permit, err := executor.reserve()
		if err != nil {
			t.Fatalf("retirement capacity did not recover after physical drain: %v", err)
		}
		permit.release()
	})
	t.Run("retirement shutdown rejects and releases outstanding admission", func(t *testing.T) {
		executor := newExternalPathRetirementExecutor(1, 1)
		permit, err := executor.reserve()
		if err != nil {
			t.Fatal(err)
		}
		executor.shutdown()
		if next, reserveErr := executor.reserve(); reserveErr == nil || next != nil {
			if next != nil {
				next.release()
			}
			t.Fatalf("reserve after shutdown permit/error=%v/%v", next, reserveErr)
		}

		e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
		defer e.Close()
		slot := &pathSlot{retirementPermit: permit}
		slot.retireTracked.Store(true)
		slot.retireStarted.Store(true)
		if err := executor.enqueue(e, slot); err == nil {
			t.Fatal("outstanding retirement admission entered a stopped executor")
		}
		if permit.active.Load() || executor.activePermits() != 0 {
			t.Fatalf("stopped enqueue retained permit: active=%t count=%d",
				permit.active.Load(), executor.activePermits())
		}
	})
	t.Run("retirement waits for exact-generation lifecycle callbacks", func(t *testing.T) {
		t.Run("blocked on-death registration", testRetirementWaitsForBlockedOnDeathRegistration)
		t.Run("timed-out refresh committer", testRetirementWaitsForTimedOutRefreshCommitter)
		t.Run("production refresh committer", testRetirementWaitsForProductionRefreshCommitter)
	})
	t.Run("global retirement dispatcher retires and restarts", func(t *testing.T) {
		for cycle := 0; cycle < 2; cycle++ {
			testRetirementDispatcherCycle(t, cycle)
			eventuallyEngine(t, time.Second, func() bool {
				externalPathRetirements.mu.Lock()
				idle := externalPathRetirements.queued == 0 &&
					externalPathRetirements.inflight == 0 && !externalPathRetirements.running &&
					len(externalPathRetirements.workerLimit) == 0
				externalPathRetirements.mu.Unlock()
				return idle
			})
		}
	})
	t.Run("adopted rejection remains close-tracked before slot publication", testAdoptedRejectedPathCleanupIsCloseTracked)
	t.Run("close between reservation and slot publication", testCloseBetweenReservationAndSlotPublication)
}

func testRetirementDispatcherCycle(t *testing.T, cycle int) {
	t.Helper()
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	path, peer := newMemoryPathPair()
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: fmt.Sprintf("retirement-cycle-%d", cycle)}); err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		_ = peer.Close()
		t.Fatalf("cycle %d engine close: %v", cycle, err)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("cycle %d peer close: %v", cycle, err)
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatalf("cycle %d engine did not quiesce", cycle)
	}
}

type blockedLifecyclePath struct {
	transport.PathConn
	onDeathEntered chan struct{}
	onDeathRelease chan struct{}
	commitEntered  chan struct{}
	commitRelease  chan struct{}
	closeEntered   chan struct{}
	onDeathOnce    sync.Once
	commitOnce     sync.Once
	closeOnce      sync.Once
	closeCalls     atomic.Int32
}

func (p *blockedLifecyclePath) OnDeath(fn func(transport.DeathCause, error)) {
	p.onDeathOnce.Do(func() { close(p.onDeathEntered) })
	<-p.onDeathRelease
	p.PathConn.OnDeath(fn)
}

func (p *blockedLifecyclePath) CommitLeafMobilityRefresh(leafmobility.RefreshEvidence) error {
	p.commitOnce.Do(func() { close(p.commitEntered) })
	<-p.commitRelease
	return nil
}

func (p *blockedLifecyclePath) Close() error {
	p.closeOnce.Do(func() {
		p.closeCalls.Add(1)
		close(p.closeEntered)
	})
	return p.PathConn.Close()
}

func testRetirementWaitsForBlockedOnDeathRegistration(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	base, peer := newMemoryPathPair()
	path := &blockedLifecyclePath{
		PathConn:       base,
		onDeathEntered: make(chan struct{}),
		onDeathRelease: make(chan struct{}),
		commitEntered:  make(chan struct{}),
		commitRelease:  make(chan struct{}),
		closeEntered:   make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(path.onDeathRelease) }) }
	t.Cleanup(func() {
		release()
		close(path.commitRelease)
		_ = e.Close()
		_ = peer.Close()
	})

	attached := make(chan error, 1)
	go func() {
		_, err := e.AttachPath(path, transport.PathSpec{Transport: "blocked-on-death"})
		attached <- err
	}()
	select {
	case <-path.onDeathEntered:
	case <-time.After(time.Second):
		t.Fatal("OnDeath registration did not enter")
	}
	var admissionErr error
	select {
	case admissionErr = <-attached:
	case <-time.After(pathCloseTimeout + time.Second):
		t.Fatal("OnDeath registration did not honor its callback deadline")
	}
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(admissionErr, &deadlineErr) || deadlineErr.operation != "PathConn.OnDeath" {
		t.Fatalf("AttachPath error=%v, want OnDeath callback deadline", admissionErr)
	}

	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case <-path.closeEntered:
		t.Fatal("carrier closed while exact-generation OnDeath registration was still running")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-e.Closed():
		t.Fatal("engine reported quiescence while OnDeath registration was still running")
	default:
	}
	release()
	select {
	case <-path.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("carrier close did not follow OnDeath registration completion")
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("engine did not quiesce after OnDeath registration completed")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Engine.Close did not return")
	}
	if got := path.closeCalls.Load(); got != 1 {
		t.Fatalf("carrier close calls=%d want 1", got)
	}
}

func testRetirementWaitsForTimedOutRefreshCommitter(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	base, peer := newMemoryPathPair()
	path := &blockedLifecyclePath{
		PathConn:       base,
		onDeathEntered: make(chan struct{}),
		onDeathRelease: make(chan struct{}),
		commitEntered:  make(chan struct{}),
		commitRelease:  make(chan struct{}),
		closeEntered:   make(chan struct{}),
	}
	close(path.onDeathRelease)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(path.commitRelease) }) }
	t.Cleanup(func() {
		release()
		_ = e.Close()
		_ = peer.Close()
	})
	id, err := e.AttachPath(path, transport.PathSpec{Transport: "blocked-refresh-commit"})
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	slot := e.paths[id]
	authority := slot.callbackAuthority
	e.pathsMu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	commitDone := make(chan error, 1)
	go func() {
		commitDone <- invokeLeafMobilityRefreshCommitter(
			ctx, authority, path, leafmobility.RefreshEvidence{},
		)
	}()
	select {
	case <-path.commitEntered:
	case <-time.After(time.Second):
		t.Fatal("refresh committer did not enter")
	}
	var commitErr error
	select {
	case commitErr = <-commitDone:
	case <-time.After(time.Second):
		t.Fatal("refresh committer did not honor caller deadline")
	}
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(commitErr, &deadlineErr) || deadlineErr.operation != leafMobilityRefreshCommitOp {
		t.Fatalf("refresh commit error=%v, want callback deadline", commitErr)
	}

	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case <-path.closeEntered:
		t.Fatal("carrier closed while exact-generation refresh callback was still running")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-e.Closed():
		t.Fatal("engine reported quiescence while refresh callback was still running")
	default:
	}
	release()
	select {
	case <-path.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("carrier close did not follow refresh callback completion")
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("engine did not quiesce after refresh callback completed")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Engine.Close did not return")
	}
	if got := path.closeCalls.Load(); got != 1 {
		t.Fatalf("carrier close calls=%d want 1", got)
	}
}

func testRetirementWaitsForProductionRefreshCommitter(t *testing.T) {
	var source *blockingRefreshCommitPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &blockingRefreshCommitPath{
				initiatorRefreshPath: &initiatorRefreshPath{PathConn: path},
				entered:              make(chan struct{}),
				release:              make(chan struct{}),
				closeEntered:         make(chan struct{}),
			}
			return source
		}, nil, nil, nil,
	)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(source.release) }) }
	t.Cleanup(release)
	events := make(chan MigrationEvent, 1)
	subscription := fixture.client.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if source == nil || !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	select {
	case <-source.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("production refresh committer did not enter")
	}
	event := receiveMigrationEvent(t, events)
	if event.Evidence.Kind != MigrationEvidenceLeafMobility || fixture.client.MigrationCount() != 1 {
		t.Fatalf("production commit event/count=%+v/%d", event, fixture.client.MigrationCount())
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("production refresh path is missing")
	}
	retirePathWithoutPeerNotification(
		t, fixture.client, fixture.clientRef, errors.New("retire production refresh committer"),
	)
	select {
	case <-source.closeEntered:
		release()
		t.Fatal("carrier closed while production refresh committer was still running")
	case <-time.After(2 * externalPathValueCallbackTimeout):
	}
	if !slot.retirementPermit.active.Load() {
		release()
		t.Fatal("retirement permit was released before production refresh committer completion")
	}
	release()
	select {
	case <-source.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("carrier close did not follow production refresh committer completion")
	}
	eventuallyEngine(t, time.Second, func() bool {
		return source.closeCalls.Load() == 1 && source.calls.Load() == 1 &&
			!slot.retirementPermit.active.Load()
	})
}

func testCloseBetweenReservationAndSlotPublication(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	e.SetPacketMode()
	base, peer := newMemoryPathPair()
	path := &preSlotBlockingPath{
		PathConn:     base,
		frameStarted: make(chan struct{}),
		frameRelease: make(chan struct{}),
		closeStarted: make(chan struct{}),
		closeRelease: make(chan struct{}),
	}
	var frameOnce, closeOnce sync.Once
	releaseFrame := func() { frameOnce.Do(func() { close(path.frameRelease) }) }
	releaseClose := func() { closeOnce.Do(func() { close(path.closeRelease) }) }
	t.Cleanup(func() {
		releaseFrame()
		releaseClose()
		_ = e.Close()
		_ = peer.Close()
	})
	type result struct {
		adopted bool
		err     error
	}
	prepared := make(chan result, 1)
	go func() {
		_, adopted, err := e.PreparePathBoundWithOwnership(
			path,
			transport.PathSpec{Transport: "pre-slot"},
			PathBinding{LocalReceiveFrameCapacity: 1, PeerReceiveFrameCapacity: 1},
		)
		prepared <- result{adopted: adopted, err: err}
	}()
	select {
	case <-path.frameStarted:
	case <-time.After(time.Second):
		t.Fatal("frame-limit validation did not start after cleanup reservation")
	}
	if got := path.frameCalls.Load(); got != 1 {
		t.Fatalf("MaxFrameSize stimulus calls=%d want 1", got)
	}
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case <-e.Closed():
		t.Fatal("Close crossed an in-flight pre-slot admission")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-path.closeStarted:
		t.Fatal("pre-slot carrier closed while MaxFrameSize callback was still running")
	case <-time.After(2 * externalPathValueCallbackTimeout):
	}
	releaseFrame()
	select {
	case <-path.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("pre-slot cleanup did not start after MaxFrameSize callback completion")
	}
	releaseClose()
	got := <-prepared
	if !got.adopted || got.err == nil {
		t.Fatalf("pre-slot preparation adopted/error=%t/%v want true/non-nil", got.adopted, got.err)
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("Close did not quiesce after pre-slot admission cleanup")
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close after timely pre-slot cleanup: %v", err)
	}
	if got := path.frameCalls.Load(); got != 1 {
		t.Fatalf("MaxFrameSize stimulus calls after cleanup=%d want 1", got)
	}
}

func testAdoptedRejectedPathCleanupIsCloseTracked(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	base, peer := newMemoryPathPair()
	lateCloseErr := errors.New("late rejected-admission close failure")
	blocked := &blockingClosePath{
		PathConn: base,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		err:      lateCloseErr,
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocked.release) }) }
	t.Cleanup(func() {
		_ = e.Close()
		_ = peer.Close()
	})
	t.Cleanup(release)

	type prepareResult struct {
		adopted bool
		err     error
	}
	prepared := make(chan prepareResult, 1)
	go func() {
		_, adopted, err := e.PreparePathBoundWithOwnership(
			blocked,
			transport.PathSpec{Transport: "rejected"},
			PathBinding{LocalTXTargetID: proto.TargetID{1}},
		)
		prepared <- prepareResult{adopted: adopted, err: err}
	}()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("rejected admission did not enter reserved PathConn.Close")
	}

	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	var result prepareResult
	select {
	case result = <-prepared:
	case <-time.After(pathCloseTimeout + 250*time.Millisecond):
		t.Fatal("rejected path preparation exceeded callback deadline")
	}
	if !result.adopted || result.err == nil {
		t.Fatalf("rejected preparation adopted/error=%t/%v want true/non-nil", result.adopted, result.err)
	}

	var closeErr error
	select {
	case closeErr = <-closed:
	case <-time.After(2*pathCloseTimeout + 500*time.Millisecond):
		t.Fatal("Engine.Close was pinned by pre-slot cleanup")
	}
	var callbackDeadline *pathDispatchCallbackDeadlineError
	var teardownDeadline *engineTeardownDeadlineError
	if !errors.As(closeErr, &callbackDeadline) || callbackDeadline.operation != externalPathCloseOperation ||
		!errors.As(closeErr, &teardownDeadline) {
		t.Fatalf("bounded Close error=%v want callback and engine teardown deadlines", closeErr)
	}
	select {
	case <-e.Closed():
		t.Fatal("engine published quiescence while rejected-path cleanup was alive")
	default:
	}

	release()
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("engine did not quiesce after rejected-path cleanup exited")
	}
	if err := e.Close(); !errors.Is(err, lateCloseErr) {
		t.Fatalf("repeated Close error=%v did not expose rejected-path late failure", err)
	}
	if err := e.CloseErr(); !errors.Is(err, lateCloseErr) {
		t.Fatalf("CloseErr=%v did not expose rejected-path late failure", err)
	}
}
