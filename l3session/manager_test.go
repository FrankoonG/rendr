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
func (f *fakeConn) SetMode(rendr.Mode) error         { return nil }
func (f *fakeConn) FlowID() [16]byte                 { return [16]byte{} }
