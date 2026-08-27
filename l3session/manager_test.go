package l3session

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestManagerStartsOneSessionPerFlow(t *testing.T) {
	ln := newTestStreamSessionListener(t, "tcp")
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptStream(ctx)
		if err != nil {
			t.Errorf("accept stream: %v", err)
			return
		}
		accepted <- c
	}()

	id := testIdentity(l3ingress.ProtocolTCP)
	ev := l3ingress.PacketEvent{
		Meta:    l3ingress.PacketMeta{Identity: id},
		Flow:    l3ingress.FlowMeta{L3Identity: id},
		Decided: true,
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
			Egress: "direct",
		},
	}
	var started atomic.Int32
	manager := &Manager{
		OnStart: func(_ context.Context, view PendingSessionView) error {
			started.Add(1)
			if got := view.Request().Identity; got != id {
				return errors.New("OnStart received the wrong identity")
			}
			return nil
		},
	}
	if err := manager.HandlePacket(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()
	if _, ok := manager.Session(id); !ok {
		t.Fatal("session was not cached")
	}
	if err := manager.HandlePacket(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("starts=%d want 1", got)
	}
	if len(ln.FlowIDs()) != 1 {
		t.Fatalf("flow ids=%d want 1", len(ln.FlowIDs()))
	}
	if err := manager.Close(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("session remained cached after Close")
	}
}

func TestManagerPropagatesPlanningErrors(t *testing.T) {
	err := (&Manager{}).HandlePacket(context.Background(), l3ingress.PacketEvent{})
	var planning *l3ingress.SessionError
	if !errors.As(err, &planning) {
		t.Fatalf("err=%v want SessionError", err)
	}
	if planning.Reason != l3ingress.ReasonSessionUndecided {
		t.Fatalf("reason=%q want %q", planning.Reason, l3ingress.ReasonSessionUndecided)
	}
}

func TestManagerClosesSessionOnFlowClose(t *testing.T) {
	id := testIdentity(l3ingress.ProtocolTCP)
	conn := &fakeConn{}
	manager := &Manager{}
	if !manager.add(id, &Session{conn: conn}) {
		t.Fatal("add failed")
	}

	manager.ObserveFlow(l3ingress.FlowSnapshot{
		Flow: l3ingress.FlowMeta{L3Identity: id},
	})
	if got := conn.closed.Load(); got != 0 {
		t.Fatalf("close count after active snapshot=%d want 0", got)
	}
	if _, ok := manager.Session(id); !ok {
		t.Fatal("session was removed by active snapshot")
	}

	manager.ObserveFlow(l3ingress.FlowSnapshot{
		Flow:        l3ingress.FlowMeta{L3Identity: id},
		Closed:      true,
		CloseReason: l3ingress.FlowCloseTCPFIN,
	})
	if got := conn.closed.Load(); got != 1 {
		t.Fatalf("close count=%d want 1", got)
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("session remained cached after closed snapshot")
	}

	manager.ObserveFlow(l3ingress.FlowSnapshot{
		Flow:        l3ingress.FlowMeta{L3Identity: id},
		Closed:      true,
		CloseReason: l3ingress.FlowCloseTCPFIN,
	})
	if got := conn.closed.Load(); got != 1 {
		t.Fatalf("close count after duplicate close=%d want 1", got)
	}
}

func TestManagerRecordsSessionPathSelectionAndMigrations(t *testing.T) {
	ln := newTestStreamSessionListener(t, "tcp")
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptStream(ctx)
		if err != nil {
			t.Errorf("accept stream: %v", err)
			return
		}
		accepted <- c
	}()

	id := testIdentity(l3ingress.ProtocolTCP)
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		rendr.Path("tcp-b", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
	})
	table := l3ingress.NewFlowTable(func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
		return l3ingress.FlowDecision{Peer: "peer-a", Root: root, Egress: "direct"}, nil
	}, l3ingress.FlowTableOptions{})
	flow := l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress}
	decision, _, snapshot, err := table.Resolve(context.Background(), flow, 40)
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{FlowTable: table}
	if err := manager.HandlePacket(context.Background(), l3ingress.PacketEvent{
		Meta:     l3ingress.PacketMeta{Identity: id},
		Flow:     snapshot.Flow,
		Ref:      snapshot.Ref,
		Decision: decision,
		Decided:  true,
	}); err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()
	defer manager.CloseAll()

	snapshot, ok := table.Snapshot(id)
	if !ok {
		t.Fatal("missing flow snapshot")
	}
	if !sameStrings(snapshot.SelectedPaths, []string{"tcp-a"}) {
		t.Fatalf("selected paths=%v want [tcp-a]", snapshot.SelectedPaths)
	}

	sess, ok := manager.Session(id)
	if !ok {
		t.Fatal("missing session")
	}
	admin := sess.Conn().(streamControl)
	_ = waitForSessionPathAttached(t, admin, "tcp-b", 3*time.Second)
	if err := admin.SelectTarget("root", "tcp-b"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot, ok = table.Snapshot(id)
		if ok && snapshot.MigrationCount == 1 && sameStrings(snapshot.SelectedPaths, []string{"tcp-b"}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("snapshot after migrate=%+v ok=%v", snapshot, ok)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestManagerStaleSessionTeardownCannotDeleteReplacement(t *testing.T) {
	id := testIdentity(l3ingress.ProtocolTCP)
	oldConn := &fakeConn{}
	newConn := &fakeConn{}
	oldSession := &Session{
		request: l3ingress.SessionRequest{
			Identity: id,
			Ref:      l3ingress.FlowRef{Identity: id, Generation: 1},
		},
		conn: oldConn,
	}
	newSession := &Session{
		request: l3ingress.SessionRequest{
			Identity: id,
			Ref:      l3ingress.FlowRef{Identity: id, Generation: 2},
		},
		conn: newConn,
	}
	manager := &Manager{sessions: map[l3ingress.L3Identity]*Session{id: newSession}}

	if err := manager.CloseSession(oldSession); err != nil {
		t.Fatal(err)
	}
	current, ok := manager.Session(id)
	if !ok || current != newSession {
		t.Fatalf("stale teardown removed replacement: current=%p ok=%v", current, ok)
	}
	if oldConn.closed.Load() != 1 || newConn.closed.Load() != 0 {
		t.Fatalf("close counts old/new=%d/%d", oldConn.closed.Load(), newConn.closed.Load())
	}
	if closed, err := manager.CloseRef(oldSession.Request().Ref); err != nil || closed {
		t.Fatalf("stale CloseRef closed=%v err=%v", closed, err)
	}
	if closed, err := manager.CloseRef(newSession.Request().Ref); err != nil || !closed {
		t.Fatalf("current CloseRef closed=%v err=%v", closed, err)
	}
	if _, ok := manager.Session(id); ok || newConn.closed.Load() != 1 {
		t.Fatalf("current session remained after CloseRef: present=%v closes=%d", ok, newConn.closed.Load())
	}
	if err := newSession.Close(); err != nil || newConn.closed.Load() != 1 {
		t.Fatalf("Session.Close was not idempotent: err=%v closes=%d", err, newConn.closed.Load())
	}
}

func TestOwnedSessionCloseWaitsForDurableSharedCompletion(t *testing.T) {
	id := testIdentity(l3ingress.ProtocolTCP)
	closeErr := errors.New("injected owned transport close result")
	started := make(chan struct{})
	release := make(chan struct{})
	conn := &delayedOwnedCloseConn{
		closeStarted: started,
		closeRelease: release,
		closeErr:     closeErr,
	}
	sess := &Session{
		request: l3ingress.SessionRequest{Identity: id},
		conn:    conn,
	}
	manager := &Manager{sessions: map[l3ingress.L3Identity]*Session{id: sess}}
	prepared := &PreparedTCP{manager: manager, session: sess}

	results := make(chan error, 2)
	go func() { results <- manager.CloseAll() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("owned transport Close did not start")
	}
	go func() { results <- prepared.Close() }()

	timer := time.NewTimer(dataPlaneCloseTimeout + 2*dataPlaneControlTimeout)
	select {
	case err := <-results:
		timer.Stop()
		t.Fatalf("owned Close returned before durable completion: %v", err)
	case <-timer.C:
	}
	close(release)
	for index := 0; index < 2; index++ {
		select {
		case err := <-results:
			if !errors.Is(err, closeErr) {
				t.Fatalf("Close result %d = %v, want shared %v", index, err, closeErr)
			}
			var callbackErr *CallbackError
			if errors.As(err, &callbackErr) && callbackErr.Reason == CallbackFailureTimeout {
				t.Fatalf("owned Close result %d was misclassified as callback timeout: %v", index, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("Close result %d did not observe durable completion", index)
		}
	}
	if got := conn.closed.Load(); got != 1 {
		t.Fatalf("owned transport Close calls = %d, want 1", got)
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("durably closed Session remained in Manager")
	}
}

func TestManagerStaleClosedSnapshotCannotDeleteReplacement(t *testing.T) {
	id := testIdentity(l3ingress.ProtocolTCP)
	oldRef := l3ingress.FlowRef{Identity: id, Generation: 1}
	newRef := l3ingress.FlowRef{Identity: id, Generation: 2}
	newConn := &fakeConn{}
	newSession := &Session{
		request: l3ingress.SessionRequest{Identity: id, Ref: newRef},
		conn:    newConn,
	}
	manager := &Manager{sessions: map[l3ingress.L3Identity]*Session{id: newSession}}

	manager.ObserveFlow(l3ingress.FlowSnapshot{
		Ref: oldRef, Flow: l3ingress.FlowMeta{L3Identity: id}, Closed: true,
		CloseReason: l3ingress.FlowCloseTCPFIN,
	})
	if current, ok := manager.Session(id); !ok || current != newSession || newConn.closed.Load() != 0 {
		t.Fatalf("stale snapshot closed replacement: current=%p ok=%v closes=%d", current, ok, newConn.closed.Load())
	}

	manager.ObserveFlow(l3ingress.FlowSnapshot{
		Ref: newRef, Flow: l3ingress.FlowMeta{L3Identity: id}, Closed: true,
		CloseReason: l3ingress.FlowCloseTCPFIN,
	})
	if _, ok := manager.Session(id); ok || newConn.closed.Load() != 1 {
		t.Fatalf("current snapshot did not close replacement: present=%v closes=%d", ok, newConn.closed.Load())
	}
}

func TestManagerOnStartFailureCannotDeleteConcurrentReplacement(t *testing.T) {
	ln := newTestStreamSessionListener(t, "tcp")
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.AcceptStream(ctx)
		if err == nil {
			accepted <- conn
		}
	}()

	id := testIdentity(l3ingress.ProtocolTCP)
	ref := l3ingress.FlowRef{Identity: id, Generation: 1}
	replacementConn := &fakeConn{}
	replacement := &Session{
		request: l3ingress.SessionRequest{
			Identity: id,
			Ref:      l3ingress.FlowRef{Identity: id, Generation: 2},
		},
		conn: replacementConn,
	}
	startErr := errors.New("injected OnStart failure")
	manager := &Manager{}
	manager.OnStart = func(_ context.Context, _ PendingSessionView) error {
		manager.mu.Lock()
		manager.sessions[id] = replacement
		manager.mu.Unlock()
		return startErr
	}
	event := l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id},
		Flow: l3ingress.FlowMeta{L3Identity: id}, Ref: ref, Decided: true,
		Decision: l3ingress.FlowDecision{
			Peer: "peer-a", Egress: "direct",
			Root: rendr.Path("tcp", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		},
	}
	if err := manager.HandlePacket(context.Background(), event); !errors.Is(err, startErr) {
		t.Fatalf("HandlePacket error=%v want %v", err, startErr)
	}
	server := <-accepted
	defer server.Close()
	if current, ok := manager.Session(id); !ok || current != replacement || replacementConn.closed.Load() != 0 {
		t.Fatalf("OnStart cleanup deleted replacement: current=%p ok=%v closes=%d", current, ok, replacementConn.closed.Load())
	}
	if err := manager.CloseAll(); err != nil || replacementConn.closed.Load() != 1 {
		t.Fatalf("CloseAll err=%v replacement closes=%d", err, replacementConn.closed.Load())
	}
}

type fakeConn struct {
	closed atomic.Int32
}

func (f *fakeConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (f *fakeConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (f *fakeConn) Close() error                     { f.closed.Add(1); return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (f *fakeConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeConn) Paths() []rendr.PathInfo          { return nil }
func (f *fakeConn) FlowID() [16]byte                 { return [16]byte{} }
func (f *fakeConn) Status() rendr.Status             { return rendr.Status{} }

type delayedOwnedCloseConn struct {
	fakeConn
	closeStarted chan struct{}
	closeRelease <-chan struct{}
	closeErr     error
	startOnce    sync.Once
}

func (c *delayedOwnedCloseConn) Close() error {
	c.closed.Add(1)
	c.startOnce.Do(func() { close(c.closeStarted) })
	<-c.closeRelease
	return c.closeErr
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
