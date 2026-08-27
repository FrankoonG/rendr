package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestLeafMobilityFinalControlRouteWriteHonorsDeadline(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	control := &deadlineControlPath{
		started:  make(chan struct{}),
		closed:   make(chan struct{}),
		returned: make(chan struct{}),
	}
	controlSlot := controlRouteTestSlot(
		2, 102, controlRouteTestTarget(2), controlRouteTestTarget(34), 2, control,
	)
	e.paths[controlSlot.id] = controlSlot

	frame := make([]byte, proto.HeaderSize)
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlLeafMobilityAck),
		Seq:     1,
	}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- e.writeLeafMobilityFrame(ctx, subjectRef, frame) }()

	select {
	case <-control.started:
	case <-time.After(time.Second):
		t.Fatal("final control route did not enter Write")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("final control write error = %v, want context deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("final control route ignored its context deadline")
	}
	select {
	case <-control.closed:
	default:
		t.Fatal("deadline did not close the blocked PathConn")
	}
	select {
	case <-control.returned:
	default:
		t.Fatal("control write returned before the blocked Write goroutine exited")
	}
	if active := e.activeLeafMobilityControlWrites(subjectRef); len(active) != 0 {
		t.Fatalf("active control writes = %d, want 0", len(active))
	}
	e.pathsMu.RLock()
	_, retained := e.paths[controlSlot.id]
	e.pathsMu.RUnlock()
	if retained {
		t.Fatal("deadline did not route the ambiguous control write through failPathControlWrite")
	}
}

type deadlineControlPath struct {
	started    chan struct{}
	closed     chan struct{}
	returned   chan struct{}
	startOnce  sync.Once
	closeOnce  sync.Once
	returnOnce sync.Once
}

func (p *deadlineControlPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *deadlineControlPath) Write([]byte) (int, error) {
	p.startOnce.Do(func() { close(p.started) })
	<-p.closed
	p.returnOnce.Do(func() { close(p.returned) })
	return 0, net.ErrClosed
}

func (p *deadlineControlPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *deadlineControlPath) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (p *deadlineControlPath) OnDeath(func(transport.DeathCause, error)) {}
func (p *deadlineControlPath) LocalAddr() string                         { return "deadline-control-local" }
func (p *deadlineControlPath) RemoteAddr() string                        { return "deadline-control-remote" }

var _ transport.PathConn = (*deadlineControlPath)(nil)
