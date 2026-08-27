package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	transporttcp "github.com/FrankoonG/rendr/transport/tcp"
)

func testCanceledDialCleanupAuthorityIsProcessBounded(t *testing.T) {
	const (
		workerLimit   = 4
		queueCapacity = 4
	)
	executor := newCanceledDialCleanupExecutor(workerLimit, queueCapacity)

	capacity := workerLimit + queueCapacity
	if got := len(executor.queue); got != capacity {
		t.Fatalf("cleanup queue storage=%d, want complete authority capacity %d", got, capacity)
	}
	engines := make([]*engine.Engine, 0, capacity)
	reservations := make([]*canceledDialCleanupReservation, 0, capacity)
	for range capacity {
		engines = append(engines, engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}))
	}
	baselineGoroutines := runtime.NumGoroutine()
	started := make(chan struct{}, capacity)
	release := make(chan struct{})
	var cleanupCalls atomic.Int32
	for _, e := range engines {
		reservation, err := executor.reserve()
		if err != nil {
			t.Fatalf("reserve canceled Dial cleanup authority: %v", err)
		}
		reservations = append(reservations, reservation)
		cleanupCanceledDial(e, reservation, func() {
			cleanupCalls.Add(1)
			started <- struct{}{}
			<-release
			_ = e.Close()
		})
	}
	for range workerLimit {
		waitDialLifecycleSignal(t, started, time.Second, "bounded cleanup worker")
	}
	select {
	case <-started:
		t.Fatal("queued canceled Dial cleanup acquired an extra worker")
	default:
	}
	executor.mu.Lock()
	workers, queued := executor.workers, executor.queueLen
	executor.mu.Unlock()
	if workers != workerLimit || queued != queueCapacity {
		t.Fatalf("cleanup executor workers=%d queued=%d, want %d/%d", workers, queued, workerLimit, queueCapacity)
	}
	if got := runtime.NumGoroutine(); got > baselineGoroutines+workerLimit+2 {
		t.Fatalf("blocked canceled Dials grew goroutines from %d to %d", baselineGoroutines, got)
	}

	deadline := time.Now().Add(time.Second)
	for len(processCanceledDialCleanupExecutor.permits) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("prior process cleanup authorities did not quiesce: %d", len(processCanceledDialCleanupExecutor.permits))
		}
		runtime.Gosched()
	}
	processReservations := make([]*canceledDialCleanupReservation, 0, cap(processCanceledDialCleanupExecutor.permits))
	for range cap(processCanceledDialCleanupExecutor.permits) {
		reservation, err := reserveCanceledDialCleanup()
		if err != nil {
			t.Fatalf("fill process cleanup authority: %v", err)
		}
		processReservations = append(processReservations, reservation)
	}
	assertRejectedBeforeFactory := func(packet bool) {
		t.Helper()
		runtimeInstance, err := NewRuntime(DefaultRuntimeConfig())
		if err != nil {
			t.Fatal(err)
		}
		var factoryCalls atomic.Int32
		const factoryID = "cleanup-capacity"
		if packet {
			err = runtimeInstance.RegisterPacketFactory(factoryID, PacketFactory{
				Carrier: CarrierUDP,
				Dial: func(context.Context, string) (PacketEndpoint, error) {
					factoryCalls.Add(1)
					return PacketEndpoint{}, errors.New("unexpected packet factory call")
				},
			})
		} else {
			err = runtimeInstance.RegisterStreamFactory(factoryID, StreamFactory{
				Carrier: CarrierTCP,
				Dial: func(context.Context, string) (net.Conn, error) {
					factoryCalls.Add(1)
					return nil, errors.New("unexpected stream factory call")
				},
			})
		}
		if err != nil {
			t.Fatal(err)
		}
		root := Path("only", PathSpec{Transport: factoryID, Address: "127.0.0.1:1"})
		if packet {
			_, err = runtimeInstance.DialPacket(context.Background(), SessionConfig{Root: root})
		} else {
			_, err = runtimeInstance.Dial(context.Background(), SessionConfig{Root: root})
		}
		if !errors.Is(err, ErrDialCleanupCapacity) {
			t.Fatalf("over-capacity Dial packet=%t error=%v, want %v", packet, err, ErrDialCleanupCapacity)
		}
		if calls := factoryCalls.Load(); calls != 0 {
			t.Fatalf("over-capacity Dial packet=%t invoked factory %d times", packet, calls)
		}
	}
	assertRejectedBeforeFactory(false)
	assertRejectedBeforeFactory(true)
	for _, reservation := range processReservations {
		reservation.release()
	}
	if got := len(processCanceledDialCleanupExecutor.permits); got != 0 {
		t.Fatalf("released process cleanup authorities=%d, want 0", got)
	}

	close(release)
	for _, e := range engines {
		waitDialLifecycleClosed(t, e.Closed(), 3*time.Second, "canceled Dial engine cleanup")
	}
	deadline = time.Now().Add(time.Second)
	for len(executor.permits) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("cleanup authorities remained reserved: %d", len(executor.permits))
		}
		runtime.Gosched()
	}
	if calls := cleanupCalls.Load(); calls != int32(capacity) {
		t.Fatalf("cleanup calls=%d, want exactly %d", calls, capacity)
	}
	for i, reservation := range reservations {
		if state := canceledDialCleanupReservationState(reservation.state.Load()); state != canceledDialCleanupCompleted {
			t.Fatalf("cleanup reservation %d state=%d, want completed", i, state)
		}
	}

	for _, test := range []struct {
		name    string
		cleanup func()
	}{
		{name: "panic", cleanup: func() { panic("canceled Dial cleanup panic") }},
		{name: "goexit", cleanup: runtime.Goexit},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{})
			reservation, err := executor.reserve()
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			cleanupCanceledDial(e, reservation, func() {
				calls.Add(1)
				test.cleanup()
			})
			waitDialLifecycleClosed(t, e.Closed(), 3*time.Second, "abnormal canceled Dial cleanup")
			deadline := time.Now().Add(time.Second)
			for canceledDialCleanupReservationState(reservation.state.Load()) != canceledDialCleanupCompleted {
				if time.Now().After(deadline) {
					t.Fatalf("abnormal cleanup authority state=%d", reservation.state.Load())
				}
				runtime.Gosched()
			}
			if calls.Load() != 1 {
				t.Fatalf("abnormal cleanup calls=%d, want exactly 1", calls.Load())
			}
		})
	}
	reuseEngine := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{})
	reuseReservation, err := executor.reserve()
	if err != nil {
		t.Fatalf("reserve after abnormal cleanup: %v", err)
	}
	reuseCalled := make(chan struct{})
	cleanupCanceledDial(reuseEngine, reuseReservation, func() {
		close(reuseCalled)
		_ = reuseEngine.Close()
	})
	waitDialLifecycleClosed(t, reuseCalled, time.Second, "worker reuse after abnormal cleanup")
	waitDialLifecycleClosed(t, reuseEngine.Closed(), time.Second, "engine reuse after abnormal cleanup")

	serverRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "cleanup-reuse", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterStreamFactory("cleanup-reuse", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			client, server := net.Pipe()
			if err := paths.Publish(ctx, transporttcp.Wrap(server)); err != nil {
				_ = client.Close()
				_ = server.Close()
				return nil, err
			}
			return client, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	root := Path("only", PathSpec{Transport: "cleanup-reuse", Address: "peer"})
	for _, packet := range []bool{false, true} {
		accepted := make(chan interface{ Close() error }, 1)
		go func() {
			if packet {
				conn, acceptErr := listener.AcceptPacket(context.Background())
				if acceptErr == nil {
					accepted <- conn
				}
				return
			}
			conn, acceptErr := listener.AcceptStream(context.Background())
			if acceptErr == nil {
				accepted <- conn
			}
		}()
		var client interface{ Close() error }
		if packet {
			client, err = clientRuntime.DialPacket(context.Background(), SessionConfig{Root: root})
		} else {
			client, err = clientRuntime.Dial(context.Background(), SessionConfig{Root: root})
		}
		if err != nil {
			t.Fatalf("reused cleanup authority packet=%t: %v", packet, err)
		}
		if got := len(executor.permits); got != 0 {
			t.Fatalf("successful Dial packet=%t retained %d cleanup authorities", packet, got)
		}
		peer := waitDialLifecycleSignal(t, accepted, time.Second, "reused cleanup authority peer")
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close reused client packet=%t: %v", packet, err)
		}
		if err := peer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close reused peer packet=%t: %v", packet, err)
		}
	}
}

func testDialCanceledAfterAdmissionDoesNotWaitForDroppedTerminalAck(t *testing.T) {
	t.Run("process-bounded-cleanup-authority", testCanceledDialCleanupAuthorityIsProcessBounded)
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run("engine-owned-prepared-wait/"+name, func(t *testing.T) {
			testDialCanceledWhileEngineOwnsUnpublishedPath(t, packet)
		})
	}
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run("engine-owned-internal-deadline-fallback/"+name, func(t *testing.T) {
			testDialInternalAdmissionFailureRetainsCleanupAuthority(t, packet)
		})
	}
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run("engine-owned-internal-deadline-rollover-capacity/"+name, func(t *testing.T) {
			testDialInternalAdmissionFailureStopsWhenCleanupRolloverIsFull(t, packet)
		})
	}
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run("post-admission-peak-initialization/"+name, func(t *testing.T) {
			testDialPostAdmissionFailureRetainsCleanupAuthority(t, packet)
		})
	}
	t.Run("dropped-terminal-ack", testDialCanceledAfterAdmissionDropsTerminalAck)
}

func testDialPostAdmissionFailureRetainsCleanupAuthority(t *testing.T, packet bool) {
	serverRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "post-admission-peak", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	factory := &postAdmissionFailureFactory{
		paths:  paths,
		dialed: make(chan *postAdmissionFailurePath, 1),
	}
	dialer := &sessionDialer{
		Root: Selector("root", []Target{
			Path("normal", PathSpec{Transport: "post-admission-close", Address: "normal"}),
			Path("peak", PathSpec{Transport: "post-admission-close", Address: "peak"}),
		}, PeakTransfer{Targets: []string{"peak"}}),
		Primary: "peak",
	}
	if err := dialer.AddFramedPathFactory("post-admission-close", CarrierTCP, factory); err != nil {
		t.Fatal(err)
	}

	type acceptResult struct {
		conn interface{ Close() error }
		err  error
	}
	accepted := make(chan acceptResult, 1)
	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelAccept()
	go func() {
		if packet {
			conn, acceptErr := listener.AcceptPacket(acceptCtx)
			accepted <- acceptResult{conn: conn, err: acceptErr}
			return
		}
		conn, acceptErr := listener.AcceptStream(acceptCtx)
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	baselinePermits := len(processCanceledDialCleanupExecutor.permits)
	type dialResult struct {
		conn interface{ Close() error }
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() {
		if packet {
			conn, dialErr := dialer.DialPacket(context.Background())
			dialed <- dialResult{conn: conn, err: dialErr}
			return
		}
		conn, dialErr := dialer.Dial(context.Background())
		dialed <- dialResult{conn: conn, err: dialErr}
	}()

	path := waitDialLifecycleSignal(t, factory.dialed, time.Second, "post-admission client path")
	t.Cleanup(path.releaseClose)
	waitDialLifecycleClosed(t, path.closeEntered, time.Second, "post-admission physical close attempt")
	result := waitDialLifecycleSignal(t, dialed, time.Second, "post-admission Dial failure")
	if result.conn != nil {
		_ = result.conn.Close()
		t.Fatal("post-admission failure returned a connection")
	}
	if result.err == nil {
		t.Fatal("post-admission PeakTransfer initialization returned no error")
	}
	if !strings.Contains(result.err.Error(), "initialize local PeakTransfer selection") {
		t.Fatalf("post-admission Dial error=%v, want PeakTransfer initialization failure", result.err)
	}
	peer := waitDialLifecycleSignal(t, accepted, time.Second, "post-admission accepted peer")
	if peer.err != nil || peer.conn == nil {
		t.Fatalf("post-admission peer=%v error=%v", peer.conn, peer.err)
	}
	peerRead := make(chan error, 1)
	switch conn := peer.conn.(type) {
	case Conn:
		go func() {
			buffer := make([]byte, 1)
			_, readErr := conn.Read(buffer)
			peerRead <- readErr
		}()
	case PacketConn:
		go func() {
			buffer := make([]byte, 1)
			_, _, readErr := conn.ReadFrom(buffer)
			peerRead <- readErr
		}()
	default:
		t.Fatalf("post-admission peer type=%T, want rendr connection", peer.conn)
	}
	if readErr := waitDialLifecycleSignal(t, peerRead, time.Second, "post-admission peer BYE"); !errors.Is(readErr, io.EOF) {
		t.Fatalf("post-admission peer read error=%v, want normal EOF", readErr)
	}
	if got := len(processCanceledDialCleanupExecutor.permits); got != baselinePermits+1 {
		t.Fatalf("cleanup permits while post-admission Close is blocked=%d, want %d", got, baselinePermits+1)
	}

	path.releaseClose()
	waitDialLifecycleClosed(t, path.closed, time.Second, "post-admission physical close completion")
	deadline := time.Now().Add(time.Second)
	for len(processCanceledDialCleanupExecutor.permits) != baselinePermits {
		if time.Now().After(deadline) {
			t.Fatalf("post-admission cleanup authority remained: got=%d want=%d",
				len(processCanceledDialCleanupExecutor.permits), baselinePermits)
		}
		runtime.Gosched()
	}
	if got := path.closeCalls.Load(); got != 1 {
		t.Fatalf("post-admission physical close calls=%d, want exactly 1", got)
	}
	if err := peer.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close post-admission peer: %v", err)
	}
}

type postAdmissionFailureFactory struct {
	paths  *framedPipeListener
	dialed chan *postAdmissionFailurePath
}

func (f *postAdmissionFailureFactory) DialPath(
	ctx context.Context,
	spec transport.PathSpec,
) (transport.PathConn, error) {
	if spec.Address == "normal" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, server := net.Pipe()
	serverPath := transporttcp.Wrap(server)
	if err := f.paths.Publish(ctx, serverPath); err != nil {
		_ = client.Close()
		_ = serverPath.Close()
		return nil, err
	}
	path := &postAdmissionFailurePath{
		PathConn:     transporttcp.Wrap(client),
		allowClose:   make(chan struct{}),
		closeEntered: make(chan struct{}),
		closed:       make(chan struct{}),
	}
	f.dialed <- path
	return path, nil
}

func (*postAdmissionFailureFactory) Probe(
	context.Context,
	transport.PathSpec,
) (transport.PathQuality, error) {
	return transport.PathQuality{}, nil
}

type postAdmissionFailurePath struct {
	transport.PathConn
	closeOnce        sync.Once
	releaseCloseOnce sync.Once
	closeCalls       atomic.Int32
	allowClose       chan struct{}
	closeEntered     chan struct{}
	closed           chan struct{}
	closeErr         error
}

func (p *postAdmissionFailurePath) MaxFrameSize() int {
	return testPacketPathFrameSize(p.PathConn)
}

func (p *postAdmissionFailurePath) Close() error {
	p.closeOnce.Do(func() {
		p.closeCalls.Add(1)
		close(p.closeEntered)
		<-p.allowClose
		p.closeErr = p.PathConn.Close()
		close(p.closed)
	})
	return p.closeErr
}

func (p *postAdmissionFailurePath) releaseClose() {
	p.releaseCloseOnce.Do(func() { close(p.allowClose) })
}

func testDialInternalAdmissionFailureRetainsCleanupAuthority(t *testing.T, packet bool) {
	serverRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "internal-deadline", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	factory := &internalAdmissionFailureFactory{
		paths:  paths,
		failed: make(chan *internalAdmissionFailurePath, 1),
	}
	if err := clientRuntime.RegisterFramedFactory("internal-deadline", FramedFactory{
		Carrier: CarrierTCP,
		Factory: factory,
	}); err != nil {
		t.Fatal(err)
	}

	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelAccept()
	accepted := make(chan interface{ Close() error }, 1)
	acceptErr := make(chan error, 1)
	go func() {
		var (
			conn           interface{ Close() error }
			acceptErrValue error
		)
		if packet {
			conn, acceptErrValue = listener.AcceptPacket(acceptCtx)
		} else {
			conn, acceptErrValue = listener.AcceptStream(acceptCtx)
		}
		if acceptErrValue != nil {
			acceptErr <- acceptErrValue
			return
		}
		accepted <- conn
	}()

	baselinePermits := len(processCanceledDialCleanupExecutor.permits)
	started := time.Now()
	root := Selector("root", []Target{
		Path("deadline", PathSpec{Transport: "internal-deadline", Address: "deadline"}),
		Path("healthy", PathSpec{Transport: "internal-deadline", Address: "healthy"}),
	})
	var conn interface{ Close() error }
	if packet {
		conn, err = clientRuntime.DialPacket(context.Background(), SessionConfig{Root: root})
	} else {
		conn, err = clientRuntime.Dial(context.Background(), SessionConfig{Root: root})
	}
	if err != nil {
		t.Fatalf("fallback Dial failed: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		_ = conn.Close()
		t.Fatalf("fallback Dial waited %s for failed engine cleanup", elapsed)
	}
	peer := waitDialLifecycleSignal(t, accepted, time.Second, "fallback accepted connection")
	failed := waitDialLifecycleSignal(t, factory.failed, time.Second, "failed engine-owned path")
	waitDialLifecycleClosed(t, failed.closeEntered, time.Second, "failed path physical close attempt")
	if got := len(processCanceledDialCleanupExecutor.permits); got != baselinePermits+1 {
		_ = conn.Close()
		_ = peer.Close()
		t.Fatalf("cleanup permits while failed path close is blocked=%d, want %d", got, baselinePermits+1)
	}

	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close fallback client: %v", err)
	}
	if err := peer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close fallback peer: %v", err)
	}
	close(failed.allowClose)
	waitDialLifecycleClosed(t, failed.closed, time.Second, "failed path physical close completion")
	deadline := time.Now().Add(time.Second)
	for len(processCanceledDialCleanupExecutor.permits) != baselinePermits {
		if time.Now().After(deadline) {
			t.Fatalf("failed-path cleanup authority remained: got=%d want=%d",
				len(processCanceledDialCleanupExecutor.permits), baselinePermits)
		}
		runtime.Gosched()
	}
	if got := failed.closeCalls.Load(); got != 1 {
		t.Fatalf("failed path close calls=%d, want exactly 1", got)
	}
	select {
	case err := <-acceptErr:
		t.Fatalf("listener accept failed: %v", err)
	default:
	}
}

type internalAdmissionFailureFactory struct {
	paths          *framedPipeListener
	failed         chan *internalAdmissionFailurePath
	failureReady   chan struct{}
	releaseFailure chan struct{}
	healthyCalls   atomic.Int32
}

func (f *internalAdmissionFailureFactory) DialPath(
	ctx context.Context,
	spec transport.PathSpec,
) (transport.PathConn, error) {
	client, server := net.Pipe()
	if err := f.paths.Publish(ctx, transporttcp.Wrap(server)); err != nil {
		_ = client.Close()
		_ = server.Close()
		return nil, err
	}
	base := transporttcp.Wrap(client)
	if spec.Address != "deadline" {
		f.healthyCalls.Add(1)
		return base, nil
	}
	path := &internalAdmissionFailurePath{
		PathConn:       base,
		failureReady:   f.failureReady,
		releaseFailure: f.releaseFailure,
		allowClose:     make(chan struct{}),
		closeEntered:   make(chan struct{}),
		closed:         make(chan struct{}),
	}
	f.failed <- path
	return path, nil
}

func (*internalAdmissionFailureFactory) Probe(
	context.Context,
	transport.PathSpec,
) (transport.PathQuality, error) {
	return transport.PathQuality{}, nil
}

type internalAdmissionFailurePath struct {
	transport.PathConn
	helloAckSeen   atomic.Bool
	failureOnce    sync.Once
	closeOnce      sync.Once
	closeCalls     atomic.Int32
	failureReady   chan struct{}
	releaseFailure chan struct{}
	allowClose     chan struct{}
	closeEntered   chan struct{}
	closed         chan struct{}
	closeErr       error
}

func (p *internalAdmissionFailurePath) MaxFrameSize() int {
	return testPacketPathFrameSize(p.PathConn)
}

func (p *internalAdmissionFailurePath) Read(frame []byte) (int, error) {
	if p.helloAckSeen.Load() {
		if p.failureReady != nil {
			p.failureOnce.Do(func() { close(p.failureReady) })
		}
		if p.releaseFailure != nil {
			<-p.releaseFailure
		}
		return 0, context.DeadlineExceeded
	}
	n, err := p.PathConn.Read(frame)
	if err == nil && isHelloAckFrame(frame[:n]) {
		p.helloAckSeen.Store(true)
	}
	return n, err
}

func testDialInternalAdmissionFailureStopsWhenCleanupRolloverIsFull(t *testing.T, packet bool) {
	serverRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "internal-rollover-capacity", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	factory := &internalAdmissionFailureFactory{
		paths: paths, failed: make(chan *internalAdmissionFailurePath, 1),
		failureReady: make(chan struct{}), releaseFailure: make(chan struct{}),
	}
	t.Cleanup(func() {
		select {
		case <-factory.releaseFailure:
		default:
			close(factory.releaseFailure)
		}
	})
	if err := clientRuntime.RegisterFramedFactory("internal-rollover-capacity", FramedFactory{
		Carrier: CarrierTCP,
		Factory: factory,
	}); err != nil {
		t.Fatal(err)
	}

	type acceptResult struct {
		conn interface{ Close() error }
		err  error
	}
	accepted := make(chan acceptResult, 1)
	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelAccept()
	go func() {
		if packet {
			conn, acceptErr := listener.AcceptPacket(acceptCtx)
			accepted <- acceptResult{conn: conn, err: acceptErr}
			return
		}
		conn, acceptErr := listener.AcceptStream(acceptCtx)
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	baselinePermits := len(processCanceledDialCleanupExecutor.permits)
	type dialResult struct {
		conn interface{ Close() error }
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() {
		root := Selector("root", []Target{
			Path("deadline", PathSpec{Transport: "internal-rollover-capacity", Address: "deadline"}),
			Path("healthy", PathSpec{Transport: "internal-rollover-capacity", Address: "healthy"}),
		})
		if packet {
			conn, dialErr := clientRuntime.DialPacket(context.Background(), SessionConfig{Root: root})
			dialed <- dialResult{conn: conn, err: dialErr}
			return
		}
		conn, dialErr := clientRuntime.Dial(context.Background(), SessionConfig{Root: root})
		dialed <- dialResult{conn: conn, err: dialErr}
	}()

	failed := waitDialLifecycleSignal(t, factory.failed, time.Second, "rollover failed path")
	t.Cleanup(func() {
		select {
		case <-failed.allowClose:
		default:
			close(failed.allowClose)
		}
	})
	waitDialLifecycleClosed(t, factory.failureReady, time.Second, "rollover failure boundary")
	if got := len(processCanceledDialCleanupExecutor.permits); got != baselinePermits+1 {
		t.Fatalf("initial Dial cleanup permits=%d, want %d", got, baselinePermits+1)
	}
	filler := make([]*canceledDialCleanupReservation, 0, cap(processCanceledDialCleanupExecutor.permits)-len(processCanceledDialCleanupExecutor.permits))
	t.Cleanup(func() {
		for _, reservation := range filler {
			reservation.release()
		}
	})
	for len(processCanceledDialCleanupExecutor.permits) < cap(processCanceledDialCleanupExecutor.permits) {
		reservation, reserveErr := reserveCanceledDialCleanup()
		if reserveErr != nil {
			t.Fatalf("fill cleanup rollover capacity: %v", reserveErr)
		}
		filler = append(filler, reservation)
	}
	close(factory.releaseFailure)

	result := waitDialLifecycleSignal(t, dialed, time.Second, "rollover capacity Dial failure")
	if result.conn != nil {
		_ = result.conn.Close()
		t.Fatal("cleanup rollover capacity failure returned a connection")
	}
	if !errors.Is(result.err, ErrDialCleanupCapacity) || !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("cleanup rollover error=%v, want capacity and original admission errors", result.err)
	}
	if got := factory.healthyCalls.Load(); got != 0 {
		t.Fatalf("cleanup rollover invoked fallback factory %d times, want 0", got)
	}
	waitDialLifecycleClosed(t, failed.closeEntered, time.Second, "rollover failed path close")
	if got := len(processCanceledDialCleanupExecutor.permits); got != cap(processCanceledDialCleanupExecutor.permits) {
		t.Fatalf("cleanup rollover permits=%d, want saturated %d", got, cap(processCanceledDialCleanupExecutor.permits))
	}
	for _, reservation := range filler {
		reservation.release()
	}
	if got := len(processCanceledDialCleanupExecutor.permits); got != baselinePermits+1 {
		t.Fatalf("cleanup rollover released active authority: got=%d want=%d", got, baselinePermits+1)
	}
	close(failed.allowClose)
	waitDialLifecycleClosed(t, failed.closed, time.Second, "rollover failed path cleanup")
	deadline := time.Now().Add(time.Second)
	for len(processCanceledDialCleanupExecutor.permits) != baselinePermits {
		if time.Now().After(deadline) {
			t.Fatalf("rollover cleanup authority remained: got=%d want=%d",
				len(processCanceledDialCleanupExecutor.permits), baselinePermits)
		}
		runtime.Gosched()
	}
	cancelAccept()
	select {
	case peer := <-accepted:
		if peer.err == nil && peer.conn != nil {
			_ = peer.conn.Close()
		}
	case <-time.After(time.Second):
		t.Fatal("rollover listener accept did not stop")
	}
}

func (p *internalAdmissionFailurePath) Close() error {
	p.closeOnce.Do(func() {
		p.closeCalls.Add(1)
		close(p.closeEntered)
		<-p.allowClose
		p.closeErr = p.PathConn.Close()
		close(p.closed)
	})
	return p.closeErr
}

func testDialCanceledWhileEngineOwnsUnpublishedPath(t *testing.T, packet bool) {
	serverRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "cancel-prepared", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control := newCancelDuringPreparedControl(cancel)
	factory := &cancelDuringPreparedFactory{
		paths: paths, control: control, dialed: make(chan *cancelDuringPreparedPath, 1),
	}
	if err := clientRuntime.RegisterFramedFactory("cancel-prepared", FramedFactory{
		Carrier: CarrierTCP,
		Factory: factory,
	}); err != nil {
		t.Fatal(err)
	}

	baselinePermits := len(processCanceledDialCleanupExecutor.permits)
	type dialResult struct {
		conn interface{ Close() error }
		err  error
		at   time.Time
	}
	dialed := make(chan dialResult, 1)
	go func() {
		root := Path("only", PathSpec{Transport: "cancel-prepared", Address: "peer"})
		if packet {
			conn, dialErr := clientRuntime.DialPacket(ctx, SessionConfig{Root: root})
			dialed <- dialResult{conn: conn, err: dialErr, at: time.Now()}
			return
		}
		conn, dialErr := clientRuntime.Dial(ctx, SessionConfig{Root: root})
		dialed <- dialResult{conn: conn, err: dialErr, at: time.Now()}
	}()

	canceledAt := waitDialLifecycleSignal(t, control.canceledAt, time.Second, "engine-owned admission cancellation")
	result := waitDialLifecycleSignal(t, dialed, time.Second, "canceled engine-owned Dial")
	if result.conn != nil {
		_ = result.conn.Close()
		t.Fatal("Dial returned a connection after cancellation before PREPARED")
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("Dial error=%v, want context.Canceled", result.err)
	}
	if elapsed := result.at.Sub(canceledAt); elapsed >= 200*time.Millisecond {
		t.Fatalf("Dial waited %s for engine-owned path cleanup after cancellation", elapsed)
	}

	path := waitDialLifecycleSignal(t, factory.dialed, time.Second, "engine-owned client path")
	waitDialLifecycleClosed(t, path.closeEntered, time.Second, "engine-owned physical close attempt")
	if got := len(processCanceledDialCleanupExecutor.permits); got != baselinePermits+1 {
		t.Fatalf("cleanup permits while physical close is blocked=%d, want %d", got, baselinePermits+1)
	}
	close(control.allowClose)
	waitDialLifecycleClosed(t, path.closed, time.Second, "engine-owned physical close completion")
	deadline := time.Now().Add(time.Second)
	for len(processCanceledDialCleanupExecutor.permits) != baselinePermits {
		if time.Now().After(deadline) {
			t.Fatalf("cleanup authority remained after engine close: got=%d want=%d",
				len(processCanceledDialCleanupExecutor.permits), baselinePermits)
		}
		runtime.Gosched()
	}
	if got := path.closeCalls.Load(); got != 1 {
		t.Fatalf("physical path close calls=%d, want exactly 1", got)
	}
}

type cancelDuringPreparedControl struct {
	cancel     context.CancelFunc
	cancelOnce sync.Once
	canceledAt chan time.Time
	allowClose chan struct{}
}

func newCancelDuringPreparedControl(cancel context.CancelFunc) *cancelDuringPreparedControl {
	return &cancelDuringPreparedControl{
		cancel:     cancel,
		canceledAt: make(chan time.Time, 1),
		allowClose: make(chan struct{}),
	}
}

func (c *cancelDuringPreparedControl) cancelAdmission() {
	c.cancelOnce.Do(func() {
		at := time.Now()
		c.cancel()
		c.canceledAt <- at
	})
}

type cancelDuringPreparedFactory struct {
	paths   *framedPipeListener
	control *cancelDuringPreparedControl
	dialed  chan *cancelDuringPreparedPath
}

func (f *cancelDuringPreparedFactory) DialPath(ctx context.Context, _ transport.PathSpec) (transport.PathConn, error) {
	client, server := net.Pipe()
	path := &cancelDuringPreparedPath{
		PathConn:     transporttcp.Wrap(client),
		control:      f.control,
		closeEntered: make(chan struct{}),
		closed:       make(chan struct{}),
	}
	if err := f.paths.Publish(ctx, transporttcp.Wrap(server)); err != nil {
		_ = client.Close()
		_ = server.Close()
		return nil, err
	}
	f.dialed <- path
	return path, nil
}

func (*cancelDuringPreparedFactory) Probe(context.Context, transport.PathSpec) (transport.PathQuality, error) {
	return transport.PathQuality{}, nil
}

type cancelDuringPreparedPath struct {
	transport.PathConn
	control      *cancelDuringPreparedControl
	helloAckSeen atomic.Bool
	closeOnce    sync.Once
	closeCalls   atomic.Int32
	closeEntered chan struct{}
	closed       chan struct{}
	closeErr     error
}

func (p *cancelDuringPreparedPath) MaxFrameSize() int {
	return testPacketPathFrameSize(p.PathConn)
}

func (p *cancelDuringPreparedPath) Read(frame []byte) (int, error) {
	if p.helloAckSeen.Load() {
		p.control.cancelAdmission()
		return 0, context.Canceled
	}
	n, err := p.PathConn.Read(frame)
	if err == nil && isHelloAckFrame(frame[:n]) {
		p.helloAckSeen.Store(true)
	}
	return n, err
}

func (p *cancelDuringPreparedPath) Close() error {
	p.closeOnce.Do(func() {
		p.closeCalls.Add(1)
		close(p.closeEntered)
		<-p.control.allowClose
		p.closeErr = p.PathConn.Close()
		close(p.closed)
	})
	return p.closeErr
}

func testDialCanceledAfterAdmissionDropsTerminalAck(t *testing.T) {
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

	// The first physical path retirement lazily starts two process-scoped
	// engine dispatchers that intentionally outlive this session. Dial cleanup
	// itself must return every permit, which is checked independently below.
	const processDispatcherAllowance = 2
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		fdsClean := baselineFDs < 0 || dialLifecycleOpenFDs(t) <= baselineFDs
		goroutinesClean := runtime.NumGoroutine() <= baselineGoroutines+processDispatcherAllowance
		if fdsClean && goroutinesClean {
			break
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if baselineFDs >= 0 {
		if got := dialLifecycleOpenFDs(t); got > baselineFDs {
			t.Errorf("open fd count after cleanup=%d, baseline=%d", got, baselineFDs)
		}
	}
	if got := runtime.NumGoroutine(); got > baselineGoroutines+processDispatcherAllowance {
		t.Errorf("goroutines after cleanup=%d, baseline=%d allowance=%d", got, baselineGoroutines, processDispatcherAllowance)
	}
	if got := len(processCanceledDialCleanupExecutor.permits); got != 0 {
		t.Errorf("canceled Dial cleanup permits after teardown=%d, want 0", got)
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

func (p *cancelAfterActivatedPath) MaxFrameSize() int {
	return testPacketPathFrameSize(p.PathConn)
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

func (p *droppedTerminalAckPath) MaxFrameSize() int {
	return testPacketPathFrameSize(p.PathConn)
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

func isHelloAckFrame(frame []byte) bool {
	header, err := proto.DecodeHeader(frame)
	return err == nil && header.Type == proto.FrameCtrl &&
		proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlHelloAck
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
