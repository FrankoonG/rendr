package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type synchronousDeathClosePath struct {
	closed    chan struct{}
	closeOnce sync.Once
	deathMu   sync.Mutex
	death     func(transport.DeathCause, error)
}

func newSynchronousDeathClosePath() *synchronousDeathClosePath {
	return &synchronousDeathClosePath{closed: make(chan struct{})}
}

func (p *synchronousDeathClosePath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}
func (p *synchronousDeathClosePath) Write(frame []byte) (int, error) { return len(frame), nil }
func (p *synchronousDeathClosePath) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.deathMu.Lock()
		death := p.death
		p.deathMu.Unlock()
		if death != nil {
			death(transport.CauseTransportError, net.ErrClosed)
		}
	})
	return nil
}
func (p *synchronousDeathClosePath) Quality() transport.PathQuality { return transport.PathQuality{} }
func (p *synchronousDeathClosePath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.death = fn
	p.deathMu.Unlock()
}
func (p *synchronousDeathClosePath) LocalAddr() string  { return "sync-close-local" }
func (p *synchronousDeathClosePath) RemoteAddr() string { return "sync-close-remote" }

type closeReleasedWritePath struct {
	closed       chan struct{}
	closeOnce    sync.Once
	writeStarted chan struct{}
	writeOnce    sync.Once
	deathMu      sync.Mutex
	death        func(transport.DeathCause, error)
}

func newCloseReleasedWritePath() *closeReleasedWritePath {
	return &closeReleasedWritePath{closed: make(chan struct{}), writeStarted: make(chan struct{})}
}

func (p *closeReleasedWritePath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}
func (p *closeReleasedWritePath) Write([]byte) (int, error) {
	p.writeOnce.Do(func() { close(p.writeStarted) })
	<-p.closed
	return 0, net.ErrClosed
}
func (p *closeReleasedWritePath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}
func (p *closeReleasedWritePath) Quality() transport.PathQuality { return transport.PathQuality{} }
func (p *closeReleasedWritePath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.death = fn
	p.deathMu.Unlock()
}
func (p *closeReleasedWritePath) LocalAddr() string  { return "blocked-local" }
func (p *closeReleasedWritePath) RemoteAddr() string { return "blocked-remote" }
func (p *closeReleasedWritePath) die() {
	p.deathMu.Lock()
	death := p.death
	p.deathMu.Unlock()
	if death != nil {
		death(transport.CauseTransportError, errors.New("injected path death"))
	}
}

type lifecycleHealthyPath struct {
	closed    chan struct{}
	closeOnce sync.Once
	writes    atomic.Uint64
	deathMu   sync.Mutex
	death     func(transport.DeathCause, error)
}

type qualityDeathPath struct {
	*lifecycleHealthyPath
	once sync.Once
}

func (p *qualityDeathPath) Quality() transport.PathQuality {
	p.once.Do(func() {
		p.die(transport.CauseTransportError, errors.New("quality observer detected death"))
	})
	return transport.PathQuality{}
}

func newLifecycleHealthyPath() *lifecycleHealthyPath {
	return &lifecycleHealthyPath{closed: make(chan struct{})}
}
func (p *lifecycleHealthyPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}
func (p *lifecycleHealthyPath) Write(frame []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
		p.writes.Add(1)
		return len(frame), nil
	}
}
func (p *lifecycleHealthyPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}
func (p *lifecycleHealthyPath) Quality() transport.PathQuality { return transport.PathQuality{} }
func (p *lifecycleHealthyPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.death = fn
	p.deathMu.Unlock()
}
func (p *lifecycleHealthyPath) LocalAddr() string  { return "healthy-local" }
func (p *lifecycleHealthyPath) RemoteAddr() string { return "healthy-remote" }
func (p *lifecycleHealthyPath) die(cause transport.DeathCause, err error) {
	p.deathMu.Lock()
	death := p.death
	p.deathMu.Unlock()
	if death != nil {
		death(cause, err)
	}
}

func TestEngineCloseDoesNotHoldPathsLockAcrossSynchronousDeath(t *testing.T) {
	e := New(SideClient, [16]byte{0xb1}, Limits{}.Clamp())
	path := newSynchronousDeathClosePath()
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "test", Address: "sync-close"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Engine.Close deadlocked in synchronous OnDeath callback")
	}
}

func TestRemovePathLinearizesSynchronousCloseDeathAsClean(t *testing.T) {
	e := New(SideClient, [16]byte{0xb2}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })

	healthy := newLifecycleHealthyPath()
	if _, err := e.AttachPath(healthy, transport.PathSpec{Transport: "test", Address: "healthy"}); err != nil {
		t.Fatal(err)
	}
	removed := newSynchronousDeathClosePath()
	removedID, err := e.AttachPath(removed, transport.PathSpec{Transport: "test", Address: "remove"})
	if err != nil {
		t.Fatal(err)
	}

	death := make(chan PathDeathEvent, 1)
	cancel := e.OnPathDeath(func(event PathDeathEvent) {
		if event.ID == removedID {
			death <- event
		}
	})
	defer cancel()

	if err := e.RemovePath(removedID); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-death:
		if event.Cause != transport.CauseCleanClose || event.Err != nil {
			t.Fatalf("removal death=(cause=%v err=%v), want clean close", event.Cause, event.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("clean removal did not publish a path-death event")
	}
	if paths := e.Paths(); len(paths) != 1 || paths[0].ID == removedID {
		t.Fatalf("paths after clean removal=%v", paths)
	}
}

func TestRecoveryZombieAccountingCreditsPayloadBetweenTopologies(t *testing.T) {
	tests := []struct {
		name        string
		markPayload bool
	}{
		{name: "payload", markPayload: true},
		{name: "no-payload", markPayload: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			ids := configureLeafSelectorRuntime(t, e, "recovery")
			attach := func(path transport.PathConn, address string) uint32 {
				t.Helper()
				return attachFixturePath(t, e, path, transport.PathSpec{Transport: "test", Address: address}, ids["recovery"])
			}

			initial := newLifecycleHealthyPath()
			attach(initial, "initial")
			initial.die(transport.CauseTransportError, errors.New("initial path failed"))
			if got := e.ActivePath(); got != 0 {
				t.Fatalf("active after initial path death=%d want=0", got)
			}

			firstRecovery := newLifecycleHealthyPath()
			attach(firstRecovery, "first-recovery")
			if got := e.MigrationCount(); got != 1 {
				t.Fatalf("first recovery migration count=%d want=1", got)
			}
			if got, want := policyTxZombieLeft(e), e.limits.ZombieMaxMigrations-1; got != want {
				t.Fatalf("first recovery zombie accounting=%d want=%d", got, want)
			}
			if test.markPayload {
				e.markPayload()
				if got := policyTxZombieLeft(e); got != e.limits.ZombieMaxMigrations {
					t.Fatalf("recovery payload credit=%d want=%d", got, e.limits.ZombieMaxMigrations)
				}
			}

			firstRecovery.die(transport.CauseTransportError, errors.New("first recovery failed"))
			secondRecovery := newLifecycleHealthyPath()
			secondID := attach(secondRecovery, "second-recovery")
			if got := e.MigrationCount(); got != 2 {
				t.Fatalf("second recovery migration count=%d want=2", got)
			}

			if test.markPayload {
				if got := e.ActivePath(); got != secondID {
					t.Fatalf("second recovery active=%d want=%d", got, secondID)
				}
				if got, want := policyTxZombieLeft(e), e.limits.ZombieMaxMigrations-1; got != want {
					t.Fatalf("second recovery zombie accounting=%d want=%d", got, want)
				}
				if err := e.CloseErr(); err != nil {
					t.Fatalf("second recovery closed after credited payload: %v", err)
				}
				if _, err := e.SendData([]byte("second recovery remains usable")); err != nil {
					t.Fatalf("send after second recovery: %v", err)
				}
				return
			}

			if got := policyTxZombieLeft(e); got != 0 {
				t.Fatalf("second no-payload recovery accounting=%d want=0", got)
			}
			select {
			case <-e.closed:
			case <-time.After(time.Second):
				t.Fatal("two no-payload recoveries did not close the zombie engine")
			}
			if err := e.CloseErr(); !errors.Is(err, ErrZombie) {
				t.Fatalf("two no-payload recoveries close error=%v want=%v", err, ErrZombie)
			}
		})
	}
}

func TestConcurrentRemovePathPreservesOneSurvivor(t *testing.T) {
	e := New(SideClient, [16]byte{0xb3}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	first := newLifecycleHealthyPath()
	firstID, err := e.AttachPath(first, transport.PathSpec{Transport: "test", Address: "first"})
	if err != nil {
		t.Fatal(err)
	}
	second := newLifecycleHealthyPath()
	secondID, err := e.AttachPath(second, transport.PathSpec{Transport: "test", Address: "second"})
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	firstSlot := e.paths[firstID]
	secondSlot := e.paths[secondID]
	e.pathsMu.RUnlock()

	e.sendMu.Lock()
	firstResult := make(chan error, 1)
	secondResult := make(chan error, 1)
	go func() { firstResult <- e.RemovePath(firstID) }()
	go func() { secondResult <- e.RemovePath(secondID) }()
	deadline := time.Now().Add(time.Second)
	for (firstSlot.removeWaiters.Load() == 0 || secondSlot.removeWaiters.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if firstSlot.removeWaiters.Load() == 0 || secondSlot.removeWaiters.Load() == 0 {
		e.sendMu.Unlock()
		t.Fatal("concurrent removals did not both reach the serialization gate")
	}
	e.sendMu.Unlock()
	var firstErr, secondErr error
	select {
	case firstErr = <-firstResult:
	case <-time.After(time.Second):
		t.Fatal("first concurrent removal did not finish")
	}
	select {
	case secondErr = <-secondResult:
	case <-time.After(time.Second):
		t.Fatal("second concurrent removal did not finish")
	}
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("concurrent removals errors=(%v, %v), want one success", firstErr, secondErr)
	}
	if firstErr != nil && !errors.Is(firstErr, ErrLastPath) {
		t.Fatalf("first removal error=%v, want %v", firstErr, ErrLastPath)
	}
	if secondErr != nil && !errors.Is(secondErr, ErrLastPath) {
		t.Fatalf("second removal error=%v, want %v", secondErr, ErrLastPath)
	}
	paths := e.Paths()
	wantID := firstID
	if firstErr == nil {
		wantID = secondID
	}
	if len(paths) != 1 || paths[0].ID != wantID {
		t.Fatalf("paths after concurrent removals=%v, want only %d", paths, wantID)
	}
}

func TestRemovePathAfterSurvivorFaultReturnsLastPathWithoutEOF(t *testing.T) {
	e := New(SideClient, [16]byte{0xb4}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	kept := newLifecycleHealthyPath()
	keptID, err := e.AttachPath(kept, transport.PathSpec{Transport: "test", Address: "kept"})
	if err != nil {
		t.Fatal(err)
	}
	failed := newLifecycleHealthyPath()
	if _, err := e.AttachPath(failed, transport.PathSpec{Transport: "test", Address: "failed"}); err != nil {
		t.Fatal(err)
	}
	failed.die(transport.CauseTransportError, errors.New("injected survivor fault"))
	if err := e.RemovePath(keptID); !errors.Is(err, ErrLastPath) {
		t.Fatalf("remove after survivor fault error=%v, want %v", err, ErrLastPath)
	}
	if e.IsClosed() || errors.Is(e.CloseErr(), io.EOF) {
		t.Fatalf("survivor fault plus rejected remove became clean EOF: closed=%t err=%v", e.IsClosed(), e.CloseErr())
	}
}

func TestSurvivorFaultAfterRemovePathStartsMigrationNotEOF(t *testing.T) {
	e := New(SideClient, [16]byte{0xb5}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "removed", "survivor")
	removed := newLifecycleHealthyPath()
	removedID := attachFixturePath(t, e, removed, transport.PathSpec{Transport: "test", Address: "removed"}, targets["removed"])
	survivor := newLifecycleHealthyPath()
	attachFixturePath(t, e, survivor, transport.PathSpec{Transport: "test", Address: "survivor"}, targets["survivor"])
	if err := e.RemovePath(removedID); err != nil {
		t.Fatal(err)
	}
	survivor.die(transport.CauseTransportError, errors.New("injected final carrier fault"))
	if state := e.State(); state != BridgeMigrating {
		t.Fatalf("state after final carrier fault=%s, want %s", state, BridgeMigrating)
	}
	if e.IsClosed() || errors.Is(e.CloseErr(), io.EOF) {
		t.Fatalf("administrative removal plus transport outage became clean EOF: closed=%t err=%v", e.IsClosed(), e.CloseErr())
	}
}

func TestTopologySnapshotRemainsCoherentDuringMigration(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "a", "b")
	_, err := e.AttachPathBound(newLifecycleHealthyPath(), transport.PathSpec{Transport: "snapshot", Address: "a"}, PathBinding{
		LocalTXTargetID: targets["a"], PeerTXTargetID: targets["a"],
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.AttachPathBound(newLifecycleHealthyPath(), transport.PathSpec{Transport: "snapshot", Address: "b"}, PathBinding{
		LocalTXTargetID: targets["b"], PeerTXTargetID: targets["b"],
	})
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	stop := make(chan struct{})
	migrateErr := make(chan error, 1)
	go func() {
		close(started)
		for i := 0; ; i++ {
			select {
			case <-stop:
				migrateErr <- nil
				return
			default:
			}
			targetID := targets["a"]
			if i%2 == 0 {
				targetID = targets["b"]
			}
			if err := e.SelectLocalTarget(targets["root"], targetID, "snapshot"); err != nil {
				migrateErr <- err
				return
			}
		}
	}()
	<-started

	for i := 0; i < 2000; i++ {
		snapshot := e.TopologySnapshot()
		activeFlags := 0
		activeFound := false
		for _, path := range snapshot.Paths {
			if path.Active {
				activeFlags++
			}
			if path.ID == snapshot.ActivePath {
				activeFound = path.Active
			}
		}
		if snapshot.ActivePath == 0 {
			if activeFlags != 0 {
				t.Fatalf("zero active ID with %d active path flags: %+v", activeFlags, snapshot)
			}
		} else if !activeFound || activeFlags != 1 {
			t.Fatalf("torn topology snapshot: %+v", snapshot)
		}
	}
	close(stop)
	if err := <-migrateErr; err != nil {
		t.Fatal(err)
	}
}

func TestTopologySnapshotDoesNotHoldPathLockAcrossTransportObserver(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.AttachPath(newLifecycleHealthyPath(), transport.PathSpec{Transport: "snapshot", Address: "guard"}); err != nil {
		t.Fatal(err)
	}
	path := &qualityDeathPath{lifecycleHealthyPath: newLifecycleHealthyPath()}
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "snapshot", Address: "observer"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan TopologySnapshot, 1)
	go func() { done <- e.TopologySnapshot() }()
	select {
	case snapshot := <-done:
		if len(snapshot.Paths) != 2 {
			t.Fatalf("frozen snapshot paths=%d, want 2", len(snapshot.Paths))
		}
	case <-time.After(time.Second):
		t.Fatal("TopologySnapshot deadlocked in synchronous transport observer")
	}
}

func TestPathDeathClosesBlockedWriterAndReleasesPolicyGate(t *testing.T) {
	manifest, leaves := adversarialGraphManifest("blocked-policy-root", proto.GraphNodeKindSelector, "blocked-a", "healthy-b")
	e := New(SideClient, [16]byte{0xb2}, Limits{}.Clamp())
	defer e.Close()
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	blocked := newCloseReleasedWritePath()
	healthy := newLifecycleHealthyPath()
	if _, err := e.AttachPath(blocked, transport.PathSpec{Transport: "test", Address: "blocked-a", Opts: map[string]string{"name": "blocked-a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AttachPath(healthy, transport.PathSpec{Transport: "test", Address: "healthy-b", Opts: map[string]string{"name": "healthy-b"}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- e.RequestPeerSelection(ctx, manifest.RootID, leaves[1], "blocked-write") }()
	select {
	case <-blocked.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("policy write did not block on path A")
	}
	blocked.die()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("policy result=%v want context deadline after delivered PREPARE", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dead path left policy send worker blocked")
	}
	if len(e.policySendGate) != 0 {
		t.Fatal("policy send gate remained owned after dead writer closed")
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("continues-on-b"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("sendMu remained wedged after path death")
	}
	if healthy.writes.Load() == 0 {
		t.Fatal("healthy path did not receive replay or data")
	}
}

func TestPolicyCommitBlockedBySendMuCannotMutateAfterClose(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 92, 0, fixture.selectorID, fixture.targetB)
	prepareAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	commit := policyTxUnitCommit(t, prepare, prepareAck.ack.Generation, prepareAck.ack.ReservationID)
	fixture.engine.sendMu.Lock()
	result := make(chan error, 1)
	go func() { result <- fixture.engine.handlePolicyCommit(commit) }()
	deadline := time.Now().Add(time.Second)
	for fixture.engine.policyOwnerMu.TryLock() {
		fixture.engine.policyOwnerMu.Unlock()
		if time.Now().After(deadline) {
			fixture.engine.sendMu.Unlock()
			t.Fatal("COMMIT did not reach owner linearization gate")
		}
		time.Sleep(time.Millisecond)
	}
	if err := fixture.engine.Close(); err != nil {
		fixture.engine.sendMu.Unlock()
		t.Fatal(err)
	}
	fixture.engine.sendMu.Unlock()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("COMMIT remained blocked after close")
	}
	generation, selection, _, _ := policyTxUnitState(fixture.engine, fixture.selectorID)
	if generation != 0 || selection != fixture.targetA {
		t.Fatalf("closed engine committed policy generation=%d selection=%x", generation, selection)
	}
}

func TestPolicyCommitThatWinsLifecyclePublishesWholeStateBeforeGracefulClose(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 94, 0, fixture.selectorID, fixture.targetB)
	prepareAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	commit := policyTxUnitCommit(t, prepare, prepareAck.ack.Generation, prepareAck.ack.ReservationID)

	reachedPublish := make(chan struct{})
	releasePublish := make(chan struct{})
	var reachedOnce, releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releasePublish) }) })
	fixture.engine.policyCommitAfterPublish = func() {
		reachedOnce.Do(func() { close(reachedPublish) })
		<-releasePublish
	}
	commitDone := make(chan error, 1)
	go func() { commitDone <- fixture.engine.handlePolicyCommit(commit) }()
	select {
	case <-reachedPublish:
	case <-time.After(time.Second):
		t.Fatal("COMMIT did not reach lifecycle publication point")
	}

	closeDone := make(chan struct{})
	go func() {
		fixture.engine.BeginGracefulClose()
		close(closeDone)
	}()
	waitForPolicyCloseAtLifecycle(t, fixture.engine)
	select {
	case <-closeDone:
		t.Fatal("graceful close crossed an in-flight policy publication")
	default:
	}
	releaseOnce.Do(func() { close(releasePublish) })
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("graceful close did not finish after policy publication")
	}
	var commitErr error
	select {
	case commitErr = <-commitDone:
		if commitErr != nil && !errors.Is(commitErr, net.ErrClosed) {
			t.Fatalf("COMMIT result=%v", commitErr)
		}
	case <-time.After(time.Second):
		t.Fatal("COMMIT did not finish after lifecycle publication")
	}

	desired, effective, _, ok := fixture.engine.localExecutionRuntime().selectorSelection(fixture.selectorID)
	fixture.engine.policyStateMu.Lock()
	generation := fixture.engine.policyGeneration
	selection := fixture.engine.policySelections[fixture.selectorID]
	pending := fixture.engine.policyIncoming
	completed, completedOK := fixture.engine.policyCompleted[commit.TransactionID]
	completedCount := len(fixture.engine.policyCompleted)
	fixture.engine.policyStateMu.Unlock()
	if !ok || desired != fixture.targetB || effective != fixture.targetB ||
		generation != 1 || selection != fixture.targetB || fixture.engine.ActivePath() != fixture.pathB {
		t.Fatalf("commit/close publication desired/effective=%x/%x ok=%t generation=%d selection=%x active=%d",
			desired, effective, ok, generation, selection, fixture.engine.ActivePath())
	}

	// policyIncoming is transaction custody, not part of the committed selector
	// publication. Graceful close may win after route publication but before
	// replay and FINAL bookkeeping. That terminal outcome must retain the exact
	// committed transaction; a fully finalized outcome must retain its exact ACK.
	if pending != nil {
		if !errors.Is(commitErr, net.ErrClosed) || !pending.committed ||
			pending.prepare.TransactionID != commit.TransactionID || pending.generation != commit.Generation ||
			pending.resolved != fixture.targetB || completedOK || completedCount != 0 {
			t.Fatalf("commit/close pending custody err=%v committed=%t transaction=%x generation=%d resolved=%x completed=%t/%d",
				commitErr, pending.committed, pending.prepare.TransactionID, pending.generation,
				pending.resolved, completedOK, completedCount)
		}
		return
	}
	if !completedOK || completedCount != 1 || completed.finalAck.Code != proto.PolicyAckCodeAccept ||
		completed.finalAck.Generation != commit.Generation || completed.finalAck.CurrentTargetID != fixture.targetB {
		t.Fatalf("commit/close completed custody err=%v completed=%t/%d ack=%+v",
			commitErr, completedOK, completedCount, completed.finalAck)
	}
}

func waitForPolicyCloseAtLifecycle(t *testing.T, engine *Engine) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if !engine.sessionEpochMu.TryLock() {
			return
		}
		engine.sessionEpochMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("graceful close did not reach the policy lifecycle boundary")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestQueuedPolicyWorkCannotCrossRecvTerminal(t *testing.T) {
	for _, kind := range []policyMessageKind{policyMessagePrepare, policyMessageCommit} {
		t.Run(fmt.Sprintf("kind-%d", kind), func(t *testing.T) {
			assertQueuedPolicyWorkCannotCrossTerminal(t, kind, func(engine *Engine) {
				engine.publishRecvTerminalLocked(io.EOF)
			})
		})
	}
}

func TestQueuedPolicyWorkCannotCrossPathRetireTerminal(t *testing.T) {
	for _, kind := range []policyMessageKind{policyMessagePrepare, policyMessageCommit} {
		t.Run(fmt.Sprintf("kind-%d", kind), func(t *testing.T) {
			assertQueuedPolicyWorkCannotCrossTerminal(t, kind, func(engine *Engine) {
				if engine.enqueueSequencedPathRetirementLocked([]byte{0xff}) {
					t.Fatal("malformed PATH_RETIRE unexpectedly entered receive custody")
				}
			})
		})
	}
}

func assertQueuedPolicyWorkCannotCrossTerminal(t *testing.T, kind policyMessageKind, publishTerminal func(*Engine)) {
	t.Helper()
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, byte(0xb0+kind), 0, fixture.selectorID, fixture.targetB)
	message := policyMessage{kind: kind}
	switch kind {
	case policyMessagePrepare:
		message.prepare = prepare
	case policyMessageCommit:
		prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(prepare)
		})
		message.commit = policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	}
	message.key = policyMessageKey{kind: kind, seq: uint64(0x700) + uint64(kind), frameDigest: proto.FrameDigest{byte(kind)}}
	message.done = make(chan error, 1)

	fixture.engine.policyStateMu.Lock()
	beforeGeneration := fixture.engine.policyGeneration
	beforeSelection := fixture.engine.policySelections[fixture.selectorID]
	beforePending := fixture.engine.policyIncoming
	beforeCompleted := len(fixture.engine.policyCompleted)
	beforeActive := fixture.engine.ActivePath()

	// Keep the worker blocked on policy state while proving that this exact
	// receipt has already left the FIFO. Receive terminal must remain free to
	// publish before the worker reaches its mutation boundary.
	fixture.engine.recvMu.Lock()
	if !fixture.engine.enqueuePolicyMessageLocked(message) {
		fixture.engine.recvMu.Unlock()
		fixture.engine.policyStateMu.Unlock()
		t.Fatal("failed to enqueue policy work")
	}
	fixture.engine.recvMu.Unlock()
	deadline := time.Now().Add(time.Second)
	for {
		fixture.engine.policyQueueMu.Lock()
		_, queued := fixture.engine.policyQueued[message.key]
		fixture.engine.policyQueueMu.Unlock()
		if !queued {
			break
		}
		if time.Now().After(deadline) {
			fixture.engine.policyStateMu.Unlock()
			t.Fatal("policy worker did not dequeue receipt")
		}
		time.Sleep(time.Millisecond)
	}
	fixture.engine.recvMu.Lock()
	publishTerminal(fixture.engine)
	fixture.engine.recvMu.Unlock()
	fixture.engine.policyStateMu.Unlock()

	select {
	case err := <-message.done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("queued policy result=%v want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued policy work did not leave terminal gate")
	}

	fixture.engine.policyStateMu.Lock()
	generation := fixture.engine.policyGeneration
	selection := fixture.engine.policySelections[fixture.selectorID]
	pending := fixture.engine.policyIncoming
	completed := len(fixture.engine.policyCompleted)
	fixture.engine.policyStateMu.Unlock()
	if generation != beforeGeneration || selection != beforeSelection || pending != beforePending ||
		completed != beforeCompleted || fixture.engine.ActivePath() != beforeActive {
		t.Fatalf("terminal-crossing mutation generation=%d/%d selection=%x/%x pending=%p/%p completed=%d/%d active=%d/%d",
			generation, beforeGeneration, selection, beforeSelection, pending, beforePending,
			completed, beforeCompleted, fixture.engine.ActivePath(), beforeActive)
	}
}

func TestPolicyExpiryCannotMutateAfterCloseLinearization(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0xb8, 0, fixture.selectorID, fixture.targetB)
	policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	fixture.engine.policyStateMu.Lock()
	fixture.engine.policyIncoming.expires = time.Now().Add(time.Hour)
	fixture.engine.policyStateMu.Unlock()
	if err := fixture.engine.Close(); err != nil {
		t.Fatal(err)
	}

	fixture.engine.policyStateMu.Lock()
	beforeGeneration := fixture.engine.policyGeneration
	beforeSelection := fixture.engine.policySelections[fixture.selectorID]
	beforePending := fixture.engine.policyIncoming
	beforeCompleted := len(fixture.engine.policyCompleted)
	beforeOrder := len(fixture.engine.policyCompletedOrder)
	fixture.engine.policyStateMu.Unlock()
	fixture.engine.expirePreparedPolicy(time.Now().Add(2 * time.Hour))
	fixture.engine.policyStateMu.Lock()
	defer fixture.engine.policyStateMu.Unlock()
	if fixture.engine.policyGeneration != beforeGeneration ||
		fixture.engine.policySelections[fixture.selectorID] != beforeSelection ||
		fixture.engine.policyIncoming != beforePending ||
		len(fixture.engine.policyCompleted) != beforeCompleted ||
		len(fixture.engine.policyCompletedOrder) != beforeOrder {
		t.Fatalf("expiry mutated closed policy state generation=%d/%d selection=%x/%x pending=%p/%p completed=%d/%d order=%d/%d",
			fixture.engine.policyGeneration, beforeGeneration,
			fixture.engine.policySelections[fixture.selectorID], beforeSelection,
			fixture.engine.policyIncoming, beforePending,
			len(fixture.engine.policyCompleted), beforeCompleted,
			len(fixture.engine.policyCompletedOrder), beforeOrder)
	}
}

func TestPolicyExpiryWaitsForConcurrentCloseLinearization(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0xb9, 0, fixture.selectorID, fixture.targetB)
	policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})

	fixture.engine.policyStateMu.Lock()
	beforeGeneration := fixture.engine.policyGeneration
	beforeSelection := fixture.engine.policySelections[fixture.selectorID]
	beforePending := fixture.engine.policyIncoming
	beforeCompleted := len(fixture.engine.policyCompleted)
	beforeOrder := len(fixture.engine.policyCompletedOrder)
	closeDone := make(chan error, 1)
	go func() { closeDone <- fixture.engine.Close() }()
	waitForPolicyCloseLocks(t, fixture.engine)

	expiryDone := make(chan struct{})
	go func() {
		fixture.engine.expirePreparedPolicy(time.Now().Add(2 * time.Hour))
		close(expiryDone)
	}()
	select {
	case <-expiryDone:
		fixture.engine.policyStateMu.Unlock()
		t.Fatal("expiry crossed the in-progress Close lifecycle boundary")
	case <-time.After(20 * time.Millisecond):
	}
	fixture.engine.policyStateMu.Unlock()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after state lock release")
	}
	select {
	case <-expiryDone:
	case <-time.After(time.Second):
		t.Fatal("expiry did not leave the closed lifecycle boundary")
	}

	fixture.engine.policyStateMu.Lock()
	defer fixture.engine.policyStateMu.Unlock()
	if fixture.engine.policyGeneration != beforeGeneration ||
		fixture.engine.policySelections[fixture.selectorID] != beforeSelection ||
		fixture.engine.policyIncoming != beforePending ||
		len(fixture.engine.policyCompleted) != beforeCompleted ||
		len(fixture.engine.policyCompletedOrder) != beforeOrder {
		t.Fatalf("concurrent expiry mutated closed policy state generation=%d/%d selection=%x/%x pending=%p/%p completed=%d/%d order=%d/%d",
			fixture.engine.policyGeneration, beforeGeneration,
			fixture.engine.policySelections[fixture.selectorID], beforeSelection,
			fixture.engine.policyIncoming, beforePending,
			len(fixture.engine.policyCompleted), beforeCompleted,
			len(fixture.engine.policyCompletedOrder), beforeOrder)
	}
}

func waitForPolicyCloseLocks(t *testing.T, engine *Engine) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		sessionHeld := !engine.sessionEpochMu.TryLock()
		if !sessionHeld {
			engine.sessionEpochMu.Unlock()
		}
		lifecycleHeld := !engine.policyLifecycleMu.TryLock()
		if !lifecycleHeld {
			engine.policyLifecycleMu.Unlock()
		}
		if sessionHeld && lifecycleHeld {
			return
		}
		if time.Now().After(deadline) {
			engine.policyStateMu.Unlock()
			t.Fatal("Close did not acquire session and policy lifecycle locks")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAlteredPolicyFrameCannotReuseConsumedSequence(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	first := policyTxUnitPrepare(fixture.engine, 93, 0, fixture.selectorID, fixture.targetB)
	firstPayload, err := first.Encode()
	if err != nil {
		t.Fatal(err)
	}
	header := proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Flags: proto.FlagsForCtrl(proto.CtrlPolicyPrepare), Seq: 0}
	deliver := make([][]byte, 0)
	fixture.engine.recvMu.Lock()
	fixture.engine.onFrameRecvLocked(nil, header, firstPayload, &deliver)
	fixture.engine.recvMu.Unlock()
	deadline := time.Now().Add(time.Second)
	for {
		fixture.engine.policyStateMu.Lock()
		pending := fixture.engine.policyIncoming
		fixture.engine.policyStateMu.Unlock()
		if pending != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original policy frame was not handled")
		}
		time.Sleep(time.Millisecond)
	}

	altered := first
	altered.TransactionID[1] = 1
	altered.TargetID = fixture.targetA
	alteredPayload, err := altered.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fixture.engine.recvMu.Lock()
	fixture.engine.onFrameRecvLocked(nil, header, alteredPayload, &deliver)
	terminal := fixture.engine.recvTerminal
	finalErr := fixture.engine.recvFinalErr
	fixture.engine.recvMu.Unlock()
	if !terminal || !errors.Is(finalErr, ErrPeerProtocol) {
		t.Fatalf("altered old-SEQ policy frame terminal=%v err=%v", terminal, finalErr)
	}
	fixture.engine.policyStateMu.Lock()
	pending := fixture.engine.policyIncoming
	fixture.engine.policyStateMu.Unlock()
	if pending == nil || pending.prepare.TransactionID != first.TransactionID || pending.prepare.TargetID != first.TargetID {
		t.Fatal("altered old-SEQ policy frame replaced transaction state")
	}
}

var _ transport.PathConn = (*synchronousDeathClosePath)(nil)
var _ transport.PathConn = (*closeReleasedWritePath)(nil)
var _ transport.PathConn = (*lifecycleHealthyPath)(nil)
