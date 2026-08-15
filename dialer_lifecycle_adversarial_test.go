package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	transporttcp "github.com/FrankoonG/rendr/transport/tcp"
)

func testDialCanceledAfterAdmissionDoesNotWaitForDroppedTerminalAck(t *testing.T) {
	control := newCanceledAdmissionControl()
	serverRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pathListener := &droppedTerminalAckListener{
		Listener:      rawListener,
		control:       control,
		accepted:      make(chan *trackedDialLifecycleConn, 1),
		acceptEntered: make(chan struct{}),
	}
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "dropped-terminal-ack", Carrier: CarrierTCP, Listener: pathListener,
	}}})
	if err != nil {
		_ = rawListener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	clientPaths := make(chan *trackedDialLifecycleConn, 1)
	factory := &cancelAfterActivatedFactory{
		control: control,
		dialed:  clientPaths,
	}
	if err := clientRuntime.RegisterFramedFactory("dropped-terminal-ack", FramedFactory{
		Carrier: CarrierTCP, Factory: factory,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control.cancel = cancel
	acceptCtx, stopAccept := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopAccept()
	waitDialLifecycleClosed(t, pathListener.acceptEntered, time.Second, "framed source accept loop")
	baselineGoroutines := runtime.NumGoroutine()
	baselineFDs := dialLifecycleOpenFDs(t)
	type acceptResult struct {
		conn Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.AcceptStream(acceptCtx)
		if acceptErr == nil {
			control.observePeerAdmitted()
		}
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	type dialResult struct {
		conn Conn
		err  error
		at   time.Time
	}
	dialed := make(chan dialResult, 1)
	go func() {
		conn, dialErr := clientRuntime.Dial(ctx, SessionConfig{Root: Path("only", PathSpec{
			Transport: "dropped-terminal-ack",
			Address:   rawListener.Addr().String(),
		})})
		dialed <- dialResult{conn: conn, err: dialErr, at: time.Now()}
	}()

	canceledAt := waitDialLifecycleSignal(t, control.canceledAt, time.Second, "final admission cancellation")
	var result dialResult
	select {
	case result = <-dialed:
	case <-time.After(3 * time.Second):
		t.Fatal("Dial remained blocked after its context was canceled")
	}
	if result.conn != nil {
		_ = result.conn.Close()
		t.Fatal("Dial returned a connection after final admission cancellation")
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("Dial error=%v, want context.Canceled", result.err)
	}
	if elapsed := result.at.Sub(canceledAt); elapsed >= 200*time.Millisecond {
		t.Fatalf("Dial waited %s after cancellation; terminal cleanup must not block the caller", elapsed)
	}

	waitDialLifecycleClosed(t, control.byeSeen, time.Second, "peer receipt of graceful BYE")
	waitDialLifecycleClosed(t, control.terminalAckDropped, time.Second, "dropped terminal ACK")

	var peer Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("AcceptStream: %v", result.err)
		}
		peer = result.conn
	case <-time.After(time.Second):
		t.Fatal("peer did not publish the admitted session")
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, readErr := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(readErr, io.EOF) {
		t.Fatalf("peer Read after canceled Dial=(%d,%v), want (0,EOF)", n, readErr)
	}

	clientPath := waitDialLifecycleSignal(t, clientPaths, time.Second, "client carrier")
	serverPath := waitDialLifecycleSignal(t, pathListener.accepted, time.Second, "server carrier")
	waitDialLifecycleClosed(t, clientPath.closed, 3*time.Second, "client carrier cleanup")
	waitDialLifecycleClosed(t, serverPath.closed, 3*time.Second, "server carrier cleanup")
	acceptedPeer, ok := peer.(*acceptedStreamConn)
	if !ok {
		t.Fatalf("accepted connection type=%T, want *acceptedStreamConn", peer)
	}
	waitDialLifecycleClosed(t, acceptedPeer.engine.Closed(), 3*time.Second, "peer engine cleanup")
	_ = peer.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		fdsClean := baselineFDs < 0 || dialLifecycleOpenFDs(t) <= baselineFDs
		goroutinesClean := runtime.NumGoroutine() <= baselineGoroutines
		if fdsClean && goroutinesClean {
			return
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if baselineFDs >= 0 {
		if got := dialLifecycleOpenFDs(t); got > baselineFDs {
			t.Errorf("open fd count after cleanup=%d, baseline=%d", got, baselineFDs)
		}
	}
	if got := runtime.NumGoroutine(); got > baselineGoroutines {
		t.Errorf("goroutines after cleanup=%d, baseline=%d", got, baselineGoroutines)
	}
}

type canceledAdmissionControl struct {
	cancel             context.CancelFunc
	cancelOnce         sync.Once
	peerAdmittedOnce   sync.Once
	byeOnce            sync.Once
	terminalAckOnce    sync.Once
	canceledAt         chan time.Time
	peerAdmitted       chan struct{}
	byeSeen            chan struct{}
	terminalAckDropped chan struct{}
}

func newCanceledAdmissionControl() *canceledAdmissionControl {
	return &canceledAdmissionControl{
		canceledAt:         make(chan time.Time, 1),
		peerAdmitted:       make(chan struct{}),
		byeSeen:            make(chan struct{}),
		terminalAckDropped: make(chan struct{}),
	}
}

func (c *canceledAdmissionControl) observePeerAdmitted() {
	c.peerAdmittedOnce.Do(func() { close(c.peerAdmitted) })
}

func (c *canceledAdmissionControl) cancelAfterActivated() {
	c.cancelOnce.Do(func() {
		at := time.Now()
		c.cancel()
		c.canceledAt <- at
	})
}

func (c *canceledAdmissionControl) observeBye() {
	c.byeOnce.Do(func() { close(c.byeSeen) })
}

func (c *canceledAdmissionControl) dropTerminalAck() {
	c.terminalAckOnce.Do(func() { close(c.terminalAckDropped) })
}

type cancelAfterActivatedFactory struct {
	control *canceledAdmissionControl
	dialed  chan<- *trackedDialLifecycleConn
}

func (f *cancelAfterActivatedFactory) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", spec.Address)
	if err != nil {
		return nil, err
	}
	tracked := newTrackedDialLifecycleConn(raw)
	f.dialed <- tracked
	return &cancelAfterActivatedPath{PathConn: transporttcp.Wrap(tracked), control: f.control}, nil
}

func (*cancelAfterActivatedFactory) Probe(context.Context, transport.PathSpec) (transport.PathQuality, error) {
	return transport.PathQuality{}, nil
}

type cancelAfterActivatedPath struct {
	transport.PathConn
	control *canceledAdmissionControl
}

func (p *cancelAfterActivatedPath) Read(frame []byte) (int, error) {
	n, err := p.PathConn.Read(frame)
	if err == nil && isActivatedAdmissionFrame(frame[:n]) {
		<-p.control.peerAdmitted
		p.control.cancelAfterActivated()
	}
	return n, err
}

type droppedTerminalAckListener struct {
	net.Listener
	control       *canceledAdmissionControl
	accepted      chan *trackedDialLifecycleConn
	acceptEntered chan struct{}
	acceptOnce    sync.Once
}

func (l *droppedTerminalAckListener) AcceptPath(context.Context) (transport.PathConn, error) {
	l.acceptOnce.Do(func() { close(l.acceptEntered) })
	raw, err := l.Accept()
	if err != nil {
		return nil, err
	}
	tracked := newTrackedDialLifecycleConn(raw)
	l.accepted <- tracked
	return &droppedTerminalAckPath{PathConn: transporttcp.Wrap(tracked), control: l.control}, nil
}

func (*droppedTerminalAckListener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionAny
}

type droppedTerminalAckPath struct {
	transport.PathConn
	control *canceledAdmissionControl
}

func (p *droppedTerminalAckPath) Read(frame []byte) (int, error) {
	n, err := p.PathConn.Read(frame)
	if err == nil && isByeFrame(frame[:n]) {
		p.control.observeBye()
	}
	return n, err
}

func (p *droppedTerminalAckPath) Write(frame []byte) (int, error) {
	if isAckFrame(frame) && channelClosed(p.control.byeSeen) {
		p.control.dropTerminalAck()
		return len(frame), nil
	}
	return p.PathConn.Write(frame)
}

type trackedDialLifecycleConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func newTrackedDialLifecycleConn(conn net.Conn) *trackedDialLifecycleConn {
	return &trackedDialLifecycleConn{Conn: conn, closed: make(chan struct{})}
}

func (c *trackedDialLifecycleConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func isActivatedAdmissionFrame(frame []byte) bool {
	header, err := proto.DecodeHeader(frame)
	if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlPathAdmissionAck {
		return false
	}
	ack, err := proto.DecodePathAdmissionAck(frame[proto.HeaderSize:])
	return err == nil && ack.Phase == proto.PathAdmissionPhaseActivated
}

func isByeFrame(frame []byte) bool {
	header, err := proto.DecodeHeader(frame)
	return err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlBye
}

func isAckFrame(frame []byte) bool {
	header, err := proto.DecodeHeader(frame)
	if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlPathProbeReply {
		return false
	}
	_, ok := proto.DecodeAck(frame[proto.HeaderSize:])
	return ok
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func waitDialLifecycleClosed(t *testing.T, channel <-chan struct{}, timeout time.Duration, description string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitDialLifecycleSignal[T any](t *testing.T, channel <-chan T, timeout time.Duration, description string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(timeout):
		var zero T
		t.Fatalf("timed out waiting for %s", description)
		return zero
	}
}

func dialLifecycleOpenFDs(t *testing.T) int {
	t.Helper()
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}
