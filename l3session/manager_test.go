package l3session

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestManagerStartsOneSessionPerFlow(t *testing.T) {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
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
		OnStart: func(_ context.Context, sess *Session) error {
			started.Add(1)
			if sess.Request.Identity != id {
				t.Fatalf("identity=%s want %s", sess.Request.Identity, id)
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
	if !manager.add(id, &Session{Conn: conn}) {
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
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
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
	admin := sess.Conn.(streamControl)
	var pathB uint32
	for _, p := range admin.Paths() {
		if p.Spec.Opts["name"] == "tcp-b" {
			pathB = p.ID
			break
		}
	}
	if pathB == 0 {
		t.Fatalf("path tcp-b not attached: %+v", admin.Paths())
	}
	if err := admin.Migrate(pathB); err != nil {
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
