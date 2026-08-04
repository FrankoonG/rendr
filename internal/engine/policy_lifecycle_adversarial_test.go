package engine

import (
	"context"
	"errors"
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
	if generation != 0 || selection != (proto.TargetID{}) {
		t.Fatalf("closed engine committed policy generation=%d selection=%x", generation, selection)
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
