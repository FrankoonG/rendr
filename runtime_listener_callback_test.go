package rendr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
)

type runtimeListenerCallbackAction uint8

const (
	runtimeListenerCallbackReturn runtimeListenerCallbackAction = iota
	runtimeListenerCallbackPanic
	runtimeListenerCallbackGoexit
	runtimeListenerCallbackBlock
)

type runtimeListenerCallbackPanicValue struct{}

type runtimeListenerTypedDiagnosticError struct{ cause error }

func (err *runtimeListenerTypedDiagnosticError) Error() string {
	return "typed diagnostic: " + err.cause.Error()
}
func (err *runtimeListenerTypedDiagnosticError) Unwrap() error { return err.cause }

type runtimeListenerSelfCycleError struct{}

func (*runtimeListenerSelfCycleError) Error() string     { return "self-cycle" }
func (err *runtimeListenerSelfCycleError) Unwrap() error { return err }

type runtimeListenerMultiCycleError struct{ children []error }

func (*runtimeListenerMultiCycleError) Error() string       { return "multi-cycle" }
func (err *runtimeListenerMultiCycleError) Unwrap() []error { return err.children }

type runtimeListenerPanicUnwrapOneError struct{}

func (*runtimeListenerPanicUnwrapOneError) Error() string { return "panic unwrap one" }
func (*runtimeListenerPanicUnwrapOneError) Unwrap() error { panic("unwrap one") }

type runtimeListenerPanicUnwrapManyError struct{}

func (*runtimeListenerPanicUnwrapManyError) Error() string   { return "panic unwrap many" }
func (*runtimeListenerPanicUnwrapManyError) Unwrap() []error { panic("unwrap many") }

type runtimeListenerPanicIsError struct{}

func (*runtimeListenerPanicIsError) Error() string { return "panic Is" }
func (*runtimeListenerPanicIsError) Is(error) bool { panic("Is") }

type runtimeListenerTestAddr string

func (a runtimeListenerTestAddr) Network() string { return "runtime-listener-test" }
func (a runtimeListenerTestAddr) String() string  { return string(a) }

type abnormalFramedListener struct {
	sessionKindAction runtimeListenerCallbackAction
	addrAction        runtimeListenerCallbackAction
	acceptAction      runtimeListenerCallbackAction
	closeAction       runtimeListenerCallbackAction
	closeAfterAction  runtimeListenerCallbackAction
	closeErr          error

	acceptRelease chan struct{}
	closeRelease  chan struct{}
	closeReturned chan struct{}
	closed        chan struct{}
	closeOnce     sync.Once
	returnOnce    sync.Once

	mu               sync.Mutex
	sessionKindCalls int
	addrCalls        int
	acceptCalls      int
	closeCalls       int
}

func newAbnormalFramedListener() *abnormalFramedListener {
	return &abnormalFramedListener{
		acceptRelease: make(chan struct{}),
		closeRelease:  make(chan struct{}),
		closeReturned: make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (l *abnormalFramedListener) SessionKind() transport.PathSessionKind {
	l.record(&l.sessionKindCalls)
	runRuntimeListenerCallbackAction(l.sessionKindAction, l.closeRelease)
	return transport.PathSessionStream
}

func (l *abnormalFramedListener) Addr() net.Addr {
	l.record(&l.addrCalls)
	runRuntimeListenerCallbackAction(l.addrAction, l.closeRelease)
	return runtimeListenerTestAddr("framed")
}

func (l *abnormalFramedListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	l.record(&l.acceptCalls)
	runRuntimeListenerCallbackAction(l.acceptAction, l.acceptRelease)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.acceptRelease:
		return nil, net.ErrClosed
	}
}

func (l *abnormalFramedListener) Close() error {
	l.record(&l.closeCalls)
	defer l.returnOnce.Do(func() { close(l.closeReturned) })
	runRuntimeListenerCallbackAction(l.closeAction, l.closeRelease)
	runRuntimeListenerCallbackAction(l.closeAfterAction, l.closeRelease)
	l.closeOnce.Do(func() { close(l.closed) })
	return l.closeErr
}

func (l *abnormalFramedListener) record(counter *int) {
	l.mu.Lock()
	*counter++
	l.mu.Unlock()
}

func (l *abnormalFramedListener) counts() (sessionKind, addr, accept, close int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessionKindCalls, l.addrCalls, l.acceptCalls, l.closeCalls
}

type abnormalNetListener struct {
	addrAction   runtimeListenerCallbackAction
	acceptAction runtimeListenerCallbackAction
	closeAction  runtimeListenerCallbackAction

	acceptRelease chan struct{}
	closeRelease  chan struct{}
	closed        chan struct{}
	connections   chan net.Conn
	closeOnce     sync.Once

	mu          sync.Mutex
	addrCalls   int
	acceptCalls int
	closeCalls  int
}

type lateRuntimeNetListener struct {
	conn      net.Conn
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

func (l *lateRuntimeNetListener) Accept() (net.Conn, error) {
	l.enterOnce.Do(func() { close(l.entered) })
	<-l.release
	return l.conn, nil
}

func (*lateRuntimeNetListener) Close() error   { return nil }
func (*lateRuntimeNetListener) Addr() net.Addr { return runtimeListenerTestAddr("late-stream") }

type blockedRuntimeAcceptListener struct {
	entered   chan struct{}
	closed    chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func newBlockedRuntimeAcceptListener() *blockedRuntimeAcceptListener {
	return &blockedRuntimeAcceptListener{
		entered: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (l *blockedRuntimeAcceptListener) Accept() (net.Conn, error) {
	l.enterOnce.Do(func() { close(l.entered) })
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockedRuntimeAcceptListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (*blockedRuntimeAcceptListener) Addr() net.Addr {
	return runtimeListenerTestAddr("blocked-accept")
}

type blockedRuntimeMetadataListener struct {
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

func newBlockedRuntimeMetadataListener() *blockedRuntimeMetadataListener {
	return &blockedRuntimeMetadataListener{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (*blockedRuntimeMetadataListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*blockedRuntimeMetadataListener) Close() error { return nil }

func (l *blockedRuntimeMetadataListener) Addr() net.Addr {
	l.enterOnce.Do(func() { close(l.entered) })
	<-l.release
	return runtimeListenerTestAddr("blocked-metadata")
}

type lateRuntimeFramedListener struct {
	path      transport.PathConn
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

func (*lateRuntimeFramedListener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionStream
}

func (*lateRuntimeFramedListener) Addr() net.Addr { return runtimeListenerTestAddr("late-framed") }

func (l *lateRuntimeFramedListener) AcceptPath(context.Context) (transport.PathConn, error) {
	l.enterOnce.Do(func() { close(l.entered) })
	<-l.release
	return l.path, nil
}

func (*lateRuntimeFramedListener) Close() error { return nil }

type deadlineLagRuntimeFramedListener struct {
	returnDelay time.Duration
}

func (*deadlineLagRuntimeFramedListener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionStream
}

func (*deadlineLagRuntimeFramedListener) Addr() net.Addr {
	return runtimeListenerTestAddr("deadline-lag-framed")
}

func (l *deadlineLagRuntimeFramedListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	<-ctx.Done()
	time.Sleep(l.returnDelay)
	return nil, ctx.Err()
}

func (*deadlineLagRuntimeFramedListener) Close() error { return nil }

type deadlineBoundaryRuntimeFramedListener struct {
	deadlineObserved chan struct{}
	closeCalled      chan struct{}
	returnRelease    chan struct{}
	returned         chan struct{}
	deadlineOnce     sync.Once
	closeOnce        sync.Once
	returnOnce       sync.Once
}

func newDeadlineBoundaryRuntimeFramedListener() *deadlineBoundaryRuntimeFramedListener {
	return &deadlineBoundaryRuntimeFramedListener{
		deadlineObserved: make(chan struct{}),
		closeCalled:      make(chan struct{}),
		returnRelease:    make(chan struct{}),
		returned:         make(chan struct{}),
	}
}

func (*deadlineBoundaryRuntimeFramedListener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionStream
}

func (*deadlineBoundaryRuntimeFramedListener) Addr() net.Addr {
	return runtimeListenerTestAddr("deadline-boundary-framed")
}

func (l *deadlineBoundaryRuntimeFramedListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	<-ctx.Done()
	l.deadlineOnce.Do(func() { close(l.deadlineObserved) })
	<-l.returnRelease
	l.returnOnce.Do(func() { close(l.returned) })
	return nil, ctx.Err()
}

func (l *deadlineBoundaryRuntimeFramedListener) Close() error {
	l.closeOnce.Do(func() { close(l.closeCalled) })
	return nil
}

type deadlineErrorRuntimeFramedListener struct {
	err     func(error) error
	invoked atomic.Bool
}

func (*deadlineErrorRuntimeFramedListener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionStream
}

func (*deadlineErrorRuntimeFramedListener) Addr() net.Addr {
	return runtimeListenerTestAddr("deadline-error-framed")
}

func (l *deadlineErrorRuntimeFramedListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	l.invoked.Store(true)
	<-ctx.Done()
	return nil, l.err(ctx.Err())
}

func (*deadlineErrorRuntimeFramedListener) Close() error { return nil }

type runtimeListenerCloseSignalConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *runtimeListenerCloseSignalConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func newAbnormalNetListener() *abnormalNetListener {
	return &abnormalNetListener{
		acceptRelease: make(chan struct{}),
		closeRelease:  make(chan struct{}),
		closed:        make(chan struct{}),
		connections:   make(chan net.Conn, 1),
	}
}

func (l *abnormalNetListener) Accept() (net.Conn, error) {
	l.record(&l.acceptCalls)
	runRuntimeListenerCallbackAction(l.acceptAction, l.acceptRelease)
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.acceptRelease:
		return nil, net.ErrClosed
	}
}

func (l *abnormalNetListener) Close() error {
	l.record(&l.closeCalls)
	runRuntimeListenerCallbackAction(l.closeAction, l.closeRelease)
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *abnormalNetListener) Addr() net.Addr {
	l.record(&l.addrCalls)
	runRuntimeListenerCallbackAction(l.addrAction, l.closeRelease)
	return runtimeListenerTestAddr("stream")
}

func (l *abnormalNetListener) record(counter *int) {
	l.mu.Lock()
	*counter++
	l.mu.Unlock()
}

func (l *abnormalNetListener) counts() (addr, accept, close int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.addrCalls, l.acceptCalls, l.closeCalls
}

func runRuntimeListenerCallbackAction(action runtimeListenerCallbackAction, block <-chan struct{}) {
	switch action {
	case runtimeListenerCallbackPanic:
		panic(runtimeListenerCallbackPanicValue{})
	case runtimeListenerCallbackGoexit:
		runtime.Goexit()
	case runtimeListenerCallbackBlock:
		<-block
	}
}

func TestRuntimeListenerMetadataAbnormalExitRollsBackClaim(t *testing.T) {
	tests := []struct {
		name      string
		operation ListenerCallbackOperation
		reason    ListenerCallbackFailure
		listen    func(*Runtime) (*SessionListener, error)
	}{
		{
			name: "framed SessionKind panic", operation: ListenerCallbackSessionKind, reason: ListenerCallbackPanic,
			listen: func(rt *Runtime) (*SessionListener, error) {
				source := newAbnormalFramedListener()
				source.sessionKindAction = runtimeListenerCallbackPanic
				return rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
			},
		},
		{
			name: "framed SessionKind Goexit", operation: ListenerCallbackSessionKind, reason: ListenerCallbackAbnormalExit,
			listen: func(rt *Runtime) (*SessionListener, error) {
				source := newAbnormalFramedListener()
				source.sessionKindAction = runtimeListenerCallbackGoexit
				return rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
			},
		},
		{
			name: "framed Addr panic", operation: ListenerCallbackAddr, reason: ListenerCallbackPanic,
			listen: func(rt *Runtime) (*SessionListener, error) {
				source := newAbnormalFramedListener()
				source.addrAction = runtimeListenerCallbackPanic
				return rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
			},
		},
		{
			name: "framed Addr Goexit", operation: ListenerCallbackAddr, reason: ListenerCallbackAbnormalExit,
			listen: func(rt *Runtime) (*SessionListener, error) {
				source := newAbnormalFramedListener()
				source.addrAction = runtimeListenerCallbackGoexit
				return rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
			},
		},
		{
			name: "stream Addr panic", operation: ListenerCallbackAddr, reason: ListenerCallbackPanic,
			listen: func(rt *Runtime) (*SessionListener, error) {
				source := newAbnormalNetListener()
				source.addrAction = runtimeListenerCallbackPanic
				return rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "stream", Listener: source}}})
			},
		},
		{
			name: "stream Addr Goexit", operation: ListenerCallbackAddr, reason: ListenerCallbackAbnormalExit,
			listen: func(rt *Runtime) (*SessionListener, error) {
				source := newAbnormalNetListener()
				source.addrAction = runtimeListenerCallbackGoexit
				return rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "stream", Listener: source}}})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			listener, err := test.listen(rt)
			if listener != nil {
				t.Fatal("Listen returned a listener after abnormal metadata callback")
			}
			assertRuntimeListenerCallbackError(t, err, test.operation, test.reason)
			assertRuntimeListenerClaimReleased(t, rt)
			assertRuntimeListenerCanBeReused(t, rt)
		})
	}
}

func TestRuntimeListenerAcceptAbnormalExitTerminatesSource(t *testing.T) {
	tests := []struct {
		name      string
		operation ListenerCallbackOperation
		reason    ListenerCallbackFailure
		start     func(*testing.T, *Runtime) (*SessionListener, func(), int)
	}{
		{
			name: "framed panic", operation: ListenerCallbackAcceptPath, reason: ListenerCallbackPanic,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), int) {
				source := newAbnormalFramedListener()
				source.acceptAction = runtimeListenerCallbackPanic
				listener, err := rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() {}, 1
			},
		},
		{
			name: "framed Goexit", operation: ListenerCallbackAcceptPath, reason: ListenerCallbackAbnormalExit,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), int) {
				source := newAbnormalFramedListener()
				source.acceptAction = runtimeListenerCallbackGoexit
				listener, err := rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() {}, 1
			},
		},
		{
			name: "net.Listener panic", operation: ListenerCallbackAccept, reason: ListenerCallbackPanic,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), int) {
				source := newAbnormalNetListener()
				source.acceptAction = runtimeListenerCallbackPanic
				listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "stream", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() {}, 1
			},
		},
		{
			name: "net.Listener Goexit", operation: ListenerCallbackAccept, reason: ListenerCallbackAbnormalExit,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), int) {
				source := newAbnormalNetListener()
				source.acceptAction = runtimeListenerCallbackGoexit
				listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "stream", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() {}, 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			listener, cleanup, wantSources := test.start(t, rt)
			defer cleanup()
			awaitRuntimeListenerClosed(t, listener)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := listener.AcceptStream(ctx)
			assertRuntimeListenerCallbackError(t, err, test.operation, test.reason)
			if err := listener.Close(); err != nil {
				t.Fatalf("Close after source termination: %v", err)
			}
			assertRuntimeListenerSourceCount(t, listener, 0, wantSources)
			assertRuntimeListenerClaimReleased(t, rt)
		})
	}
}

func TestSessionListenerCloseAbnormalSourceStillReleasesRuntime(t *testing.T) {
	tests := []struct {
		name   string
		reason ListenerCallbackFailure
		start  func(*testing.T, *Runtime) (*SessionListener, func(), func() int)
	}{
		{
			name: "framed panic", reason: ListenerCallbackPanic,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), func() int) {
				source := newAbnormalFramedListener()
				source.closeAction = runtimeListenerCallbackPanic
				listener, err := rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() { close(source.acceptRelease) }, func() int { _, _, _, calls := source.counts(); return calls }
			},
		},
		{
			name: "framed Goexit", reason: ListenerCallbackAbnormalExit,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), func() int) {
				source := newAbnormalFramedListener()
				source.closeAction = runtimeListenerCallbackGoexit
				listener, err := rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "framed", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() { close(source.acceptRelease) }, func() int { _, _, _, calls := source.counts(); return calls }
			},
		},
		{
			name: "net.Listener panic", reason: ListenerCallbackPanic,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), func() int) {
				source := newAbnormalNetListener()
				source.closeAction = runtimeListenerCallbackPanic
				listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "stream", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() { close(source.acceptRelease) }, func() int { _, _, calls := source.counts(); return calls }
			},
		},
		{
			name: "net.Listener Goexit", reason: ListenerCallbackAbnormalExit,
			start: func(t *testing.T, rt *Runtime) (*SessionListener, func(), func() int) {
				source := newAbnormalNetListener()
				source.closeAction = runtimeListenerCallbackGoexit
				listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "stream", Listener: source}}})
				if err != nil {
					t.Fatal(err)
				}
				return listener, func() { close(source.acceptRelease) }, func() int { _, _, calls := source.counts(); return calls }
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			listener, releaseAccept, closeCalls := test.start(t, rt)
			const callers = 8
			results := make(chan error, callers)
			for range callers {
				go func() { results <- listener.Close() }()
			}
			for range callers {
				assertRuntimeListenerCallbackError(t, <-results, ListenerCallbackClose, test.reason)
			}
			if got := closeCalls(); got != 1 {
				t.Fatalf("underlying Close calls=%d want 1", got)
			}
			releaseAccept()
			assertRuntimeListenerSourceCount(t, listener, 0, 1)
			assertRuntimeListenerClaimReleased(t, rt)
			assertRuntimeListenerCanBeReused(t, rt)
		})
	}
}

func TestSessionListenerCloseBlockedCallbackIsBoundedAndNotSuccessful(t *testing.T) {
	rt := newRuntimeListenerCallbackRuntime(t)
	source := newAbnormalNetListener()
	source.closeAction = runtimeListenerCallbackBlock
	listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "blocked", Listener: source}}})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	source.connections <- server
	deadline := time.Now().Add(time.Second)
	for runtimeListenerInflight(listener) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := runtimeListenerInflight(listener); got != 1 {
		t.Fatalf("inflight paths=%d want 1", got)
	}
	started := time.Now()
	err = listener.Close()
	if elapsed := time.Since(started); elapsed > 2*runtimeListenerCallTimeout {
		t.Fatalf("Close elapsed %s, want <= %s", elapsed, 2*runtimeListenerCallTimeout)
	}
	assertRuntimeListenerCallbackError(t, err, ListenerCallbackClose, ListenerCallbackTimeout)
	_, _, closeCalls := source.counts()
	if closeCalls != 1 {
		t.Fatalf("underlying Close calls=%d want 1", closeCalls)
	}
	if got := runtimeListenerInflight(listener); got != 0 {
		t.Fatalf("inflight paths after blocked source Close=%d want 0", got)
	}
	if got := len(listener.handshakes); got != 0 {
		t.Fatalf("handshake slots after blocked source Close=%d want 0", got)
	}
	assertRuntimeListenerSourceCount(t, listener, 0, 1)
	assertRuntimeListenerClaimReleased(t, rt)
	close(source.closeRelease)
	close(source.acceptRelease)
	t.Run("late Accept results are closed", testRuntimeListenerLateAcceptCleanup)
	t.Run("callback permits are isolated across runtimes", testRuntimeListenerCallbackPermitIsolation)
	t.Run("global callback limit preserves cleanup capacity", testRuntimeListenerGlobalCallbackLimit)
}

func testRuntimeListenerCallbackPermitIsolation(t *testing.T) {
	blockedSources := make([]StreamSource, 0, runtimeListenerCallLimit)
	blockedListeners := make([]*blockedRuntimeAcceptListener, 0, runtimeListenerCallLimit)
	for index := range runtimeListenerCallLimit {
		source := newBlockedRuntimeAcceptListener()
		blockedListeners = append(blockedListeners, source)
		blockedSources = append(blockedSources, StreamSource{
			Name:     fmt.Sprintf("blocked-%d", index),
			Listener: source,
		})
	}

	blockedRuntime := newRuntimeListenerCallbackRuntime(t)
	blocked, err := blockedRuntime.Listen(ListenConfig{Streams: blockedSources})
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	for index, source := range blockedListeners {
		awaitRuntimeListenerCallbackSignal(t, source.entered, fmt.Sprintf("blocked Accept %d", index))
	}

	independentRuntime := newRuntimeListenerCallbackRuntime(t)
	independentSource := newAbnormalNetListener()
	independent, err := independentRuntime.Listen(ListenConfig{
		Streams: []StreamSource{{Name: "independent", Listener: independentSource}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	independentSource.connections <- server

	deadline := time.Now().Add(500 * time.Millisecond)
	for runtimeListenerInflight(independent) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := runtimeListenerInflight(independent); got != 1 {
		t.Fatalf("independent listener inflight paths=%d want 1 while another runtime is saturated", got)
	}
	started := time.Now()
	if err := independent.Close(); err != nil {
		t.Fatalf("independent listener Close: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= runtimeListenerCallTimeout {
		t.Fatalf("independent listener Close waited for another runtime's callbacks: %s", elapsed)
	}
	assertRuntimeListenerClaimReleased(t, independentRuntime)

	started = time.Now()
	if err := blocked.Close(); err != nil {
		t.Fatalf("saturated listener Close: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= runtimeListenerCallTimeout {
		t.Fatalf("saturated listener cleanup shared its blocked Accept capacity: %s", elapsed)
	}
	assertRuntimeListenerClaimReleased(t, blockedRuntime)
}

func testRuntimeListenerGlobalCallbackLimit(t *testing.T) {
	runtimes := []*Runtime{
		newRuntimeListenerCallbackRuntime(t),
		newRuntimeListenerCallbackRuntime(t),
	}
	sources := make([]*blockedRuntimeMetadataListener, 0, runtimeListenerProcessLimit)
	results := make(chan error, runtimeListenerProcessLimit)
	for _, rt := range runtimes {
		for index := range runtimeListenerCallLimit {
			source := newBlockedRuntimeMetadataListener()
			sources = append(sources, source)
			go func() {
				_, err := rt.Listen(ListenConfig{Streams: []StreamSource{{
					Name:     fmt.Sprintf("blocked-metadata-%d", index),
					Listener: source,
				}}})
				results <- err
			}()
		}
	}
	for index, source := range sources {
		awaitRuntimeListenerCallbackSignal(t, source.entered, fmt.Sprintf("blocked metadata %d", index))
	}

	extraRuntime := newRuntimeListenerCallbackRuntime(t)
	extraSource := newBlockedRuntimeMetadataListener()
	started := time.Now()
	listener, err := extraRuntime.Listen(ListenConfig{Streams: []StreamSource{{
		Name:     "globally-limited",
		Listener: extraSource,
	}}})
	if listener != nil {
		t.Fatal("globally limited Listen returned a listener")
	}
	assertRuntimeListenerCallbackError(t, err, ListenerCallbackAddr, ListenerCallbackResourceLimited)
	if elapsed := time.Since(started); elapsed > 2*runtimeListenerCallTimeout {
		t.Fatalf("global callback limit took %s, want <= %s", elapsed, 2*runtimeListenerCallTimeout)
	}
	select {
	case <-extraSource.entered:
		t.Fatal("resource-limited callback was invoked")
	default:
	}

	cleanupOwner := newRuntimeListenerCallbackOwnerForRuntime(extraRuntime)
	defer cleanupOwner.release()
	sourceClosed := make(chan struct{}, 1)
	if err := closeRuntimeListenerCallbacks([]runtimeListenerCloser{{
		source: "cleanup-source",
		close: func() error {
			sourceClosed <- struct{}{}
			return nil
		},
	}}, cleanupOwner); err != nil {
		t.Fatalf("source cleanup under metadata saturation: %v", err)
	}
	select {
	case <-sourceClosed:
	default:
		t.Fatal("source cleanup callback was not invoked")
	}

	path := newAbnormalRuntimePathConn()
	if err := closeRuntimeListenerPath("cleanup-path", path, cleanupOwner); err != nil {
		t.Fatalf("path cleanup under metadata saturation: %v", err)
	}
	select {
	case <-path.closeReturned:
	default:
		t.Fatal("path cleanup callback was not invoked")
	}
	cleanupOwner.release()

	for range sources {
		assertRuntimeListenerCallbackError(t, <-results, ListenerCallbackAddr, ListenerCallbackTimeout)
	}
	for _, source := range sources {
		close(source.release)
	}
	deadline := time.Now().Add(time.Second)
	for len(runtimeListenerProcessCallbackPermits.metadataCalls) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(runtimeListenerProcessCallbackPermits.metadataCalls); got != 0 {
		t.Fatalf("global metadata permits after callback release=%d want 0", got)
	}
	for _, rt := range append(runtimes, extraRuntime) {
		deadline = time.Now().Add(time.Second)
		for runtimeListenerCallbackScopePresent(rt) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if runtimeListenerCallbackScopePresent(rt) {
			t.Fatal("callback scope remained after all owners and callbacks were released")
		}
	}
}

func runtimeListenerCallbackScopePresent(rt *Runtime) bool {
	runtimeListenerCallbackScopes.Lock()
	defer runtimeListenerCallbackScopes.Unlock()
	return runtimeListenerCallbackScopes.byRuntime[rt] != nil
}

func testRuntimeListenerLateAcceptCleanup(t *testing.T) {
	t.Run("net.Listener", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		tracked := &runtimeListenerCloseSignalConn{
			Conn: server, closed: make(chan struct{}),
		}
		source := &lateRuntimeNetListener{
			conn: tracked, entered: make(chan struct{}), release: make(chan struct{}),
		}
		rt := newRuntimeListenerCallbackRuntime(t)
		listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "late", Listener: source}}})
		if err != nil {
			t.Fatal(err)
		}
		awaitRuntimeListenerCallbackSignal(t, source.entered, "late net.Listener Accept")
		if err := listener.Close(); err != nil {
			t.Fatalf("Close before late Accept result: %v", err)
		}
		close(source.release)
		awaitRuntimeListenerCallbackSignal(t, tracked.closed, "late net.Conn cleanup")
		if len(listener.streamAccept) != 0 || len(listener.FlowIDs()) != 0 {
			t.Fatalf("late net.Conn was published: queued=%d flows=%d", len(listener.streamAccept), len(listener.FlowIDs()))
		}
	})

	t.Run("PathListener", func(t *testing.T) {
		path := newAbnormalRuntimePathConn()
		source := &lateRuntimeFramedListener{
			path: path, entered: make(chan struct{}), release: make(chan struct{}),
		}
		rt := newRuntimeListenerCallbackRuntime(t)
		listener, err := rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "late", Listener: source}}})
		if err != nil {
			t.Fatal(err)
		}
		awaitRuntimeListenerCallbackSignal(t, source.entered, "late PathListener AcceptPath")
		closeErr := listener.Close()
		assertRuntimeListenerCallbackInJoin(
			t, closeErr, ListenerCallbackAcceptPath, ListenerCallbackTimeout,
		)
		close(source.release)
		awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "late PathConn cleanup")
		if len(listener.streamAccept) != 0 || len(listener.FlowIDs()) != 0 {
			t.Fatalf("late PathConn was published: queued=%d flows=%d", len(listener.streamAccept), len(listener.FlowIDs()))
		}
	})
}

func TestRuntimeListenerLateAcceptCleanupUsesReservedCapacityAcrossScopes(t *testing.T) {
	runtimeA := newRuntimeListenerCallbackRuntime(t)
	runtimeB := newRuntimeListenerCallbackRuntime(t)
	ownerA := newRuntimeListenerCallbackOwnerForRuntime(runtimeA)
	ownerB := newRuntimeListenerCallbackOwnerForRuntime(runtimeB)
	defer ownerA.release()
	defer ownerB.release()

	latePath := newAbnormalRuntimePathConn()
	latePath.closeAction = runtimeListenerCallbackBlock
	acceptEntered := make(chan struct{})
	acceptRelease := make(chan struct{})
	acceptResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, _, err := invokeRuntimeListenerAcceptedPath(
			ctx,
			ownerA,
			"reserved-late",
			ListenerCallbackAcceptPath,
			func() (transport.PathConn, error) {
				close(acceptEntered)
				<-acceptRelease
				return latePath, nil
			},
			func(path transport.PathConn) transport.PathConn { return path },
		)
		acceptResult <- err
	}()
	awaitRuntimeListenerCallbackSignal(t, acceptEntered, "reserved late AcceptPath")

	type blockedCleanup struct {
		path *abnormalRuntimePathConn
		call *runtimeListenerPathClose
	}
	blocked := make([]blockedCleanup, 0, runtimeListenerProcessLimit-1)
	reserveBlocked := func(owner *runtimeListenerCallbackOwner, source string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		lease, err := reserveRuntimeListenerPathClose(ctx, source, owner)
		cancel()
		if err != nil {
			t.Fatalf("reserve %s cleanup: %v", source, err)
		}
		path := newAbnormalRuntimePathConn()
		path.closeAction = runtimeListenerCallbackBlock
		call := newRuntimeListenerPathClose(source, path, lease, nil)
		call.start()
		awaitRuntimeListenerCallbackSignal(t, path.closeEntered, source+" close")
		blocked = append(blocked, blockedCleanup{path: path, call: call})
	}
	for index := 1; index < runtimeListenerCallLimit; index++ {
		reserveBlocked(ownerA, fmt.Sprintf("runtime-a-%d", index))
	}
	for index := 0; index < runtimeListenerCallLimit; index++ {
		reserveBlocked(ownerB, fmt.Sprintf("runtime-b-%d", index))
	}

	if err := <-acceptResult; err == nil {
		t.Fatal("late AcceptPath did not time out")
	} else {
		assertRuntimeListenerCallbackError(t, err, ListenerCallbackAcceptPath, ListenerCallbackTimeout)
	}
	extraInvoked := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, _, err := invokeRuntimeListenerAcceptedPath(
		ctx,
		ownerA,
		"hard-limit",
		ListenerCallbackAcceptPath,
		func() (transport.PathConn, error) {
			extraInvoked <- struct{}{}
			return newAbnormalRuntimePathConn(), nil
		},
		func(path transport.PathConn) transport.PathConn { return path },
	)
	cancel()
	assertRuntimeListenerCallbackError(t, err, ListenerCallbackAcceptPath, ListenerCallbackResourceLimited)
	select {
	case <-extraInvoked:
		t.Fatal("AcceptPath ran without reserved cleanup capacity")
	default:
	}

	close(acceptRelease)
	awaitRuntimeListenerCallbackSignal(t, latePath.closeEntered, "late reserved PathConn.Close")
	close(latePath.closeRelease)
	for _, cleanup := range blocked {
		close(cleanup.path.closeRelease)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(runtimeListenerProcessCallbackPermits.pathCloseCalls) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(runtimeListenerProcessCallbackPermits.pathCloseCalls); got != 0 {
		t.Fatalf("process path-close reservations after release=%d want 0", got)
	}
}

func TestRuntimeListenerFramedAcceptAllowsBoundedDeadlineReturn(t *testing.T) {
	owner := newRuntimeListenerCallbackOwner()
	source := FramedSource{
		Name: "deadline-lag",
		Listener: &deadlineLagRuntimeFramedListener{
			returnDelay: 20 * time.Millisecond,
		},
	}

	started := time.Now()
	path, closeCall, acceptTimedOut, err := invokeRuntimeListenerFramedAccept(
		context.Background(), owner, source, 10*time.Millisecond,
	)
	if path != nil || closeCall != nil {
		t.Fatalf("deadline accept returned path=%T closeCall=%v", path, closeCall)
	}
	if !acceptTimedOut || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acceptTimedOut=%t err=%v, want normal context deadline", acceptTimedOut, err)
	}
	var callbackErr *ListenerCallbackError
	if errors.As(err, &callbackErr) {
		t.Fatalf("compliant deadline return was misclassified as callback failure: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond || elapsed >= runtimeListenerCallTimeout {
		t.Fatalf("bounded hand-back elapsed=%s, want callback delay below %s", elapsed, runtimeListenerCallTimeout)
	}
	if terminal := owner.terminalDiagnostics(); terminal != nil {
		t.Fatalf("compliant deadline return left terminal diagnostics: %v", terminal)
	}
	deadline := time.Now().Add(time.Second)
	for (len(owner.permits.acceptCalls) != 0 || len(owner.permits.pathCloseCalls) != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(owner.permits.acceptCalls); got != 0 {
		t.Fatalf("accept permits after callback return=%d want 0", got)
	}
	if got := len(owner.permits.pathCloseCalls); got != 0 {
		t.Fatalf("path-close permits after nil callback result=%d want 0", got)
	}
}

func TestSessionListenerCloseWaitsForDeadlineBoundaryAcceptCleanup(t *testing.T) {
	rt := newRuntimeListenerCallbackRuntime(t)
	source := newDeadlineBoundaryRuntimeFramedListener()
	listener, err := rt.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "deadline-boundary", Carrier: CarrierUDP, Listener: source,
	}}})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-source.deadlineObserved:
	case <-time.After(runtimeHandshakeTimeout + 2*time.Second):
		t.Fatal("AcceptPath deadline did not occur")
	}
	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	awaitRuntimeListenerCallbackSignal(t, source.closeCalled, "FramedSource.Close")
	select {
	case err := <-closed:
		t.Fatalf("SessionListener.Close returned before AcceptPath cleanup: %v", err)
	default:
	}

	close(source.returnRelease)
	awaitRuntimeListenerCallbackSignal(t, source.returned, "AcceptPath return")
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("SessionListener.Close: %v", err)
		}
	case <-time.After(2 * runtimeListenerCallTimeout):
		t.Fatal("SessionListener.Close did not join compliant AcceptPath hand-back")
	}
	if diagnostic := listener.callbackOwner().terminalDiagnostics(); diagnostic != nil {
		t.Fatalf("deadline/shutdown boundary left terminal diagnostics: %v", diagnostic)
	}
	if got := len(listener.callbackOwner().permits.acceptCalls); got != 0 {
		t.Fatalf("accept permits when Close returned=%d want 0", got)
	}
	if got := len(listener.callbackOwner().permits.pathCloseCalls); got != 0 {
		t.Fatalf("path-close permits when Close returned=%d want 0", got)
	}
	assertRuntimeListenerClaimReleased(t, rt)
}

func TestRuntimeListenerFramedAcceptPreservesDeadlineAdjacentErrors(t *testing.T) {
	want := errors.New("accept sentinel")
	tests := []struct {
		name string
		err  func(error) error
	}{
		{name: "sentinel", err: func(error) error { return want }},
		{name: "joined", err: func(deadline error) error { return errors.Join(deadline, want) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner := newRuntimeListenerCallbackOwner()
			listener := &deadlineErrorRuntimeFramedListener{err: test.err}
			path, closeCall, acceptTimedOut, err := invokeRuntimeListenerFramedAccept(
				context.Background(), owner, FramedSource{Name: test.name, Listener: listener}, 5*time.Millisecond,
			)
			if path != nil || closeCall != nil {
				t.Fatalf("AcceptPath returned path=%T closeCall=%v", path, closeCall)
			}
			if acceptTimedOut {
				t.Fatalf("acceptTimedOut=true for terminal error %v", err)
			}
			if !errors.Is(err, want) {
				t.Fatalf("error=%v, want preserved sentinel", err)
			}
			if got := len(owner.permits.acceptCalls); got != 0 {
				t.Fatalf("accept permits after terminal result=%d want 0", got)
			}
		})
	}
}

func TestRuntimeListenerFramedAcceptRejectsInvalidTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Nanosecond} {
		listener := &deadlineErrorRuntimeFramedListener{err: func(err error) error { return err }}
		path, closeCall, acceptTimedOut, err := invokeRuntimeListenerFramedAccept(
			context.Background(), newRuntimeListenerCallbackOwner(),
			FramedSource{Name: "invalid-timeout", Listener: listener}, timeout,
		)
		if path != nil || closeCall != nil || acceptTimedOut {
			t.Fatalf("timeout=%s returned path=%T closeCall=%v acceptTimedOut=%t", timeout, path, closeCall, acceptTimedOut)
		}
		assertRuntimeListenerCallbackError(t, err, ListenerCallbackAcceptPath, ListenerCallbackInvalidResult)
		if listener.invoked.Load() {
			t.Fatalf("timeout=%s invoked AcceptPath", timeout)
		}
	}
}

func TestRuntimeListenerReservationsDoNotCapActiveSessionsAt64(t *testing.T) {
	type endpoint struct {
		runtime  *Runtime
		listener *SessionListener
		raw      net.Listener
		name     string
	}
	clientRuntime := newRuntimeListenerCallbackRuntime(t)
	endpoints := make([]endpoint, 0, 2)
	for index := range 2 {
		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serverRuntime := newRuntimeListenerCallbackRuntime(t)
		name := fmt.Sprintf("capacity-%d", index)
		listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
			Name: name, Carrier: CarrierTCP, Listener: raw,
		}}})
		if err != nil {
			_ = raw.Close()
			t.Fatal(err)
		}
		if err := clientRuntime.RegisterStreamFactory(name, StreamFactory{
			Carrier: CarrierTCP,
			Dial: func(ctx context.Context, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			},
		}); err != nil {
			t.Fatal(err)
		}
		endpoints = append(endpoints, endpoint{runtime: serverRuntime, listener: listener, raw: raw, name: name})
	}
	defer func() {
		for _, endpoint := range endpoints {
			_ = endpoint.listener.Close()
		}
	}()

	const sessionsPerRuntime = 33
	clients := make([]Conn, 0, 2*sessionsPerRuntime)
	servers := make([]Conn, 0, 2*sessionsPerRuntime)
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
		for _, conn := range servers {
			_ = conn.Close()
		}
	}()
	for _, endpoint := range endpoints {
		for range sessionsPerRuntime {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Path(endpoint.name, PathSpec{
				Transport: endpoint.name,
				Address:   endpoint.raw.Addr().String(),
			})})
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			server, err := endpoint.listener.AcceptStream(ctx)
			cancel()
			if err != nil {
				_ = client.Close()
				t.Fatal(err)
			}
			clients = append(clients, client)
			servers = append(servers, server)
		}
	}
	if got := len(clients); got != 66 {
		t.Fatalf("active sessions=%d want 66", got)
	}
	if got := len(runtimeListenerProcessCallbackPermits.pathCloseCalls); got > len(endpoints) {
		t.Fatalf("active sessions retained listener cleanup reservations=%d want <=%d standing accepts", got, len(endpoints))
	}
}

type abnormalRuntimeDeadlineConn struct {
	net.Conn
	action    runtimeListenerCallbackAction
	entered   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func newAbnormalRuntimeDeadlineConn(conn net.Conn, action runtimeListenerCallbackAction) *abnormalRuntimeDeadlineConn {
	return &abnormalRuntimeDeadlineConn{
		Conn:    conn,
		action:  action,
		entered: make(chan struct{}),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (conn *abnormalRuntimeDeadlineConn) SetDeadline(time.Time) error {
	conn.enterOnce.Do(func() { close(conn.entered) })
	runRuntimeListenerCallbackAction(conn.action, conn.release)
	return nil
}

func (conn *abnormalRuntimeDeadlineConn) Close() error {
	conn.closeOnce.Do(func() { close(conn.closed) })
	return conn.Conn.Close()
}

func TestRuntimeListenerStreamDeadlineCallbacksAreClaimedAndContained(t *testing.T) {
	for _, test := range []struct {
		name   string
		action runtimeListenerCallbackAction
		reason ListenerCallbackFailure
	}{
		{name: "panic", action: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", action: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
		{name: "block", action: runtimeListenerCallbackBlock, reason: ListenerCallbackTimeout},
	} {
		for _, operation := range []ListenerCallbackOperation{ListenerCallbackSetDeadline, ListenerCallbackClearDeadline} {
			t.Run(test.name+"/"+string(operation), func(t *testing.T) {
				listener := newBareRuntimePathListener(nil)
				local, peer := net.Pipe()
				defer peer.Close()
				raw := newAbnormalRuntimeDeadlineConn(local, test.action)
				path := tcp.Wrap(raw)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				lease, err := reserveRuntimeListenerPathClose(ctx, "deadline", listener.callbackOwner())
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				listener.handshakes <- struct{}{}
				claim, ok := listener.trackInflight("deadline", path, newRuntimeListenerPathClose(
					"deadline", &runtimeListenerNetConnCleanup{conn: raw}, lease, nil,
				))
				if !ok {
					lease.release()
					t.Fatal("could not track deadline connection")
				}
				result := make(chan error, 1)
				go func() {
					result <- listener.setClaimedStreamDeadline(claim, raw, time.Now(), operation)
				}()
				awaitRuntimeListenerCallbackSignal(t, raw.entered, string(operation))
				if got := runtimeListenerInflight(listener); got != 1 {
					t.Fatalf("inflight during %s=%d want 1", operation, got)
				}
				if test.action == runtimeListenerCallbackBlock {
					callErr := <-result
					assertRuntimeListenerCallbackError(t, callErr, operation, test.reason)
					claim.finish(false)
					if err := claim.close.wait(); err != nil {
						t.Fatalf("claimed connection cleanup: %v", err)
					}
					awaitRuntimeListenerCallbackSignal(t, raw.closed, "claimed connection cleanup")
					close(raw.release)
					return
				}
				callErr := <-result
				assertRuntimeListenerCallbackError(t, callErr, operation, test.reason)
				claim.finish(false)
				if err := claim.close.wait(); err != nil {
					t.Fatalf("claimed connection cleanup: %v", err)
				}
				awaitRuntimeListenerCallbackSignal(t, raw.closed, "claimed connection cleanup")
			})
		}
	}
}

type abnormalRuntimePacketConn struct {
	localAction runtimeListenerCallbackAction
	readAction  runtimeListenerCallbackAction
	closeAction runtimeListenerCallbackAction
	readResultN *int

	localEntered chan struct{}
	readEntered  chan struct{}
	closeEntered chan struct{}
	localRelease chan struct{}
	readRelease  chan struct{}
	closeRelease chan struct{}
	closed       chan struct{}

	localOnce  sync.Once
	readOnce   sync.Once
	closeOnce  sync.Once
	closedOnce sync.Once
}

type abnormalRuntimePacketWriteConn struct {
	*abnormalRuntimePacketConn
	action  runtimeListenerCallbackAction
	entered chan struct{}
	once    sync.Once
}

func (conn *abnormalRuntimePacketWriteConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	conn.once.Do(func() { close(conn.entered) })
	runRuntimeListenerCallbackAction(conn.action, conn.closeRelease)
	return len(payload), nil
}

func newAbnormalRuntimePacketConn() *abnormalRuntimePacketConn {
	return &abnormalRuntimePacketConn{
		localEntered: make(chan struct{}),
		readEntered:  make(chan struct{}),
		closeEntered: make(chan struct{}),
		localRelease: make(chan struct{}),
		readRelease:  make(chan struct{}),
		closeRelease: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (conn *abnormalRuntimePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	conn.readOnce.Do(func() { close(conn.readEntered) })
	if conn.readResultN != nil {
		return *conn.readResultN, runtimeListenerTestAddr("peer"), nil
	}
	if conn.readAction == runtimeListenerCallbackReturn {
		select {
		case <-conn.closed:
			return 0, nil, net.ErrClosed
		case <-conn.readRelease:
			return 0, nil, net.ErrClosed
		}
	}
	runRuntimeListenerCallbackAction(conn.readAction, conn.readRelease)
	return 0, nil, net.ErrClosed
}

func (*abnormalRuntimePacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (conn *abnormalRuntimePacketConn) Close() error {
	conn.closeOnce.Do(func() { close(conn.closeEntered) })
	runRuntimeListenerCallbackAction(conn.closeAction, conn.closeRelease)
	conn.closedOnce.Do(func() { close(conn.closed) })
	return nil
}

func (conn *abnormalRuntimePacketConn) LocalAddr() net.Addr {
	conn.localOnce.Do(func() { close(conn.localEntered) })
	if conn.localAction == runtimeListenerCallbackBlock {
		select {
		case <-conn.localRelease:
		case <-conn.closed:
		}
		return runtimeListenerTestAddr("packet")
	}
	runRuntimeListenerCallbackAction(conn.localAction, conn.localRelease)
	return runtimeListenerTestAddr("packet")
}

func (*abnormalRuntimePacketConn) SetDeadline(time.Time) error      { return nil }
func (*abnormalRuntimePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*abnormalRuntimePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestRuntimeListenerPacketLocalAddrFailureReleasesRuntimeClaim(t *testing.T) {
	for _, test := range []struct {
		name   string
		action runtimeListenerCallbackAction
		reason ListenerCallbackFailure
	}{
		{name: "panic", action: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", action: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
		{name: "block", action: runtimeListenerCallbackBlock, reason: ListenerCallbackTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			raw := newAbnormalRuntimePacketConn()
			raw.localAction = test.action
			listener, err := rt.Listen(ListenConfig{Packets: []PacketSource{{Name: "packet", Carrier: CarrierUDP, Conn: raw, MaxDatagramSize: 1400}}})
			if listener != nil {
				t.Fatal("Listen returned a listener after PacketConn.LocalAddr failure")
			}
			assertRuntimeListenerCallbackError(t, err, ListenerCallbackPacketLocalAddr, test.reason)
			awaitRuntimeListenerCallbackSignal(t, raw.closeEntered, "failed packet source cleanup")
			assertRuntimeListenerClaimReleased(t, rt)
			assertRuntimeListenerCanBeReused(t, rt)
		})
	}
}

func TestRuntimeListenerPacketReadAbnormalExitIsContained(t *testing.T) {
	for _, test := range []struct {
		name   string
		action runtimeListenerCallbackAction
		reason ListenerCallbackFailure
	}{
		{name: "panic", action: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", action: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			raw := newAbnormalRuntimePacketConn()
			raw.readAction = test.action
			listener, err := rt.Listen(ListenConfig{Packets: []PacketSource{{Name: "packet", Carrier: CarrierUDP, Conn: raw, MaxDatagramSize: 1400}}})
			if err != nil {
				t.Fatal(err)
			}
			awaitRuntimeListenerClosed(t, listener)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = listener.AcceptPacket(ctx)
			assertRuntimeListenerCallbackError(t, err, ListenerCallbackPacketRead, test.reason)
			_ = listener.Close()
			assertRuntimeListenerClaimReleased(t, rt)
		})
	}
}

func TestRuntimeListenerPacketWorkersCloseAfterAbnormalExit(t *testing.T) {
	for _, test := range []struct {
		name   string
		action runtimeListenerCallbackAction
		reason ListenerCallbackFailure
	}{
		{name: "panic", action: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", action: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
	} {
		t.Run("read/"+test.name, func(t *testing.T) {
			raw := newAbnormalRuntimePacketConn()
			raw.readAction = test.action
			conn := newRuntimeListenerPacketConn("packet-read", raw, newRuntimeListenerCallbackOwner())
			_, _, err := conn.ReadFrom(make([]byte, 64))
			assertRuntimeListenerCallbackError(t, err, ListenerCallbackPacketRead, test.reason)
			select {
			case <-conn.closed:
			case <-time.After(time.Second):
				t.Fatal("abnormal read worker did not close its wrapper")
			}
			if _, _, err := conn.ReadFrom(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("second ReadFrom error=%v want net.ErrClosed", err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		})

		t.Run("write/"+test.name, func(t *testing.T) {
			raw := &abnormalRuntimePacketWriteConn{
				abnormalRuntimePacketConn: newAbnormalRuntimePacketConn(),
				action:                    test.action,
				entered:                   make(chan struct{}),
			}
			conn := newRuntimeListenerPacketConn("packet-write", raw, newRuntimeListenerCallbackOwner())
			_, err := conn.WriteTo([]byte("payload"), runtimeListenerTestAddr("peer"))
			assertRuntimeListenerCallbackError(t, err, ListenerCallbackPacketWrite, test.reason)
			select {
			case <-conn.closed:
			case <-time.After(time.Second):
				t.Fatal("abnormal write worker did not close its wrapper")
			}
			if _, err := conn.WriteTo([]byte("payload"), runtimeListenerTestAddr("peer")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("second WriteTo error=%v want net.ErrClosed", err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeListenerPacketCloseHasIndependentCleanupCapacity(t *testing.T) {
	owner := newRuntimeListenerCallbackOwner()
	leases := make([]*runtimeListenerCallbackLease, 0, runtimeListenerCallLimit)
	defer func() {
		for _, lease := range leases {
			lease.release()
		}
	}()
	for index := 0; index < runtimeListenerCallLimit; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		lease, err := acquireRuntimeListenerCallbackLease(
			ctx, owner, fmt.Sprintf("packet-control-%d", index), ListenerCallbackPacketControl,
		)
		cancel()
		if err != nil {
			t.Fatalf("reserve packet control %d: %v", index, err)
		}
		leases = append(leases, lease)
	}

	raw := newAbnormalRuntimePacketConn()
	conn := newRuntimeListenerPacketConn("packet-close", raw, owner)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close under packet-control saturation: %v", err)
	}
	select {
	case <-raw.closeEntered:
	default:
		t.Fatal("raw PacketConn.Close did not run through the cleanup class")
	}
}

func TestRuntimeListenerPacketReadThatIgnoresCloseCannotRetainRuntimeClaim(t *testing.T) {
	rt := newRuntimeListenerCallbackRuntime(t)
	raw := newAbnormalRuntimePacketConn()
	raw.readAction = runtimeListenerCallbackBlock
	listener, err := rt.Listen(ListenConfig{Packets: []PacketSource{{Name: "packet", Carrier: CarrierUDP, Conn: raw, MaxDatagramSize: 1400}}})
	if err != nil {
		t.Fatal(err)
	}
	awaitRuntimeListenerCallbackSignal(t, raw.readEntered, "PacketConn.ReadFrom")
	started := time.Now()
	err = listener.Close()
	assertRuntimeListenerCallbackError(t, err, ListenerCallbackPacketRead, ListenerCallbackTimeout)
	if elapsed := time.Since(started); elapsed > 2*runtimeListenerCallTimeout {
		t.Fatalf("Close waited %s for hostile PacketConn.ReadFrom", elapsed)
	}
	assertRuntimeListenerClaimReleased(t, rt)
	assertRuntimeListenerCanBeReused(t, rt)
	close(raw.readRelease)
}

func TestRuntimeListenerPacketCloseTimeoutNamesCallerClose(t *testing.T) {
	rt := newRuntimeListenerCallbackRuntime(t)
	raw := newAbnormalRuntimePacketConn()
	raw.closeAction = runtimeListenerCallbackBlock
	defer func() {
		if !runtimeListenerChannelClosed(raw.closeRelease) {
			close(raw.closeRelease)
		}
	}()
	listener, err := rt.Listen(ListenConfig{Packets: []PacketSource{{Name: "packet", Carrier: CarrierUDP, Conn: raw, MaxDatagramSize: 1400}}})
	if err != nil {
		t.Fatal(err)
	}
	awaitRuntimeListenerCallbackSignal(t, raw.readEntered, "PacketConn.ReadFrom")
	err = listener.Close()
	assertRuntimeListenerCallbackError(t, err, ListenerCallbackPacketClose, ListenerCallbackTimeout)
	assertRuntimeListenerClaimReleased(t, rt)
	close(raw.closeRelease)
}

func TestRuntimeListenerPacketCallbacksReportNonCleanTeardown(t *testing.T) {
	t.Run("blocked write", func(t *testing.T) {
		raw := &abnormalRuntimePacketWriteConn{
			abnormalRuntimePacketConn: newAbnormalRuntimePacketConn(),
			action:                    runtimeListenerCallbackBlock,
			entered:                   make(chan struct{}),
		}
		conn := newRuntimeListenerPacketConn("blocked-write", raw, newRuntimeListenerCallbackOwner())
		writeDone := make(chan error, 1)
		go func() {
			_, err := conn.WriteTo([]byte("payload"), runtimeListenerTestAddr("peer"))
			writeDone <- err
		}()
		awaitRuntimeListenerCallbackSignal(t, raw.entered, "PacketConn.WriteTo")
		assertRuntimeListenerCallbackError(t, conn.Close(), ListenerCallbackPacketWrite, ListenerCallbackTimeout)
		close(raw.closeRelease)
		select {
		case <-writeDone:
		case <-time.After(time.Second):
			t.Fatal("blocked PacketConn.WriteTo did not exit after release")
		}
	})

	for _, malformed := range []int{-1, 65} {
		t.Run(fmt.Sprintf("malformed read n=%d", malformed), func(t *testing.T) {
			raw := newAbnormalRuntimePacketConn()
			raw.readResultN = &malformed
			conn := newRuntimeListenerPacketConn("malformed-read", raw, newRuntimeListenerCallbackOwner())
			_, _, err := conn.ReadFrom(make([]byte, 64))
			assertRuntimeListenerCallbackError(t, err, ListenerCallbackPacketRead, ListenerCallbackInvalidResult)
			if err := conn.Close(); err != nil {
				t.Fatalf("Close after malformed ReadFrom: %v", err)
			}
		})
	}
}

func TestRuntimeListenerSourceCleanupIsReservedBeforeOwnership(t *testing.T) {
	rt := newRuntimeListenerCallbackRuntime(t)
	sources := make([]StreamSource, 0, runtimeListenerCallLimit)
	blocked := make([]*abnormalNetListener, 0, runtimeListenerCallLimit)
	for index := range runtimeListenerCallLimit {
		source := newAbnormalNetListener()
		source.closeAction = runtimeListenerCallbackBlock
		blocked = append(blocked, source)
		sources = append(sources, StreamSource{Name: fmt.Sprintf("reserved-%d", index), Listener: source})
	}
	listener, err := rt.Listen(ListenConfig{Streams: sources})
	if err != nil {
		t.Fatal(err)
	}
	closeErr := listener.Close()
	assertRuntimeListenerCallbackError(t, closeErr, ListenerCallbackClose, ListenerCallbackTimeout)
	for _, source := range blocked {
		deadline := time.Now().Add(time.Second)
		for {
			_, _, closeCalls := source.counts()
			if closeCalls == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("pre-reserved source Close callback did not start")
			}
			time.Sleep(time.Millisecond)
		}
	}

	replacementSource := newAbnormalNetListener()
	replacement, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "replacement", Listener: replacementSource}}})
	if replacement != nil {
		t.Fatal("replacement acquired source ownership without cleanup capacity")
	}
	assertRuntimeListenerCallbackError(t, err, ListenerCallbackClose, ListenerCallbackResourceLimited)
	_, acceptCalls, closeCalls := replacementSource.counts()
	if acceptCalls != 0 || closeCalls != 0 {
		t.Fatalf("resource-limited replacement callbacks accept/close=%d/%d want 0/0", acceptCalls, closeCalls)
	}

	for _, source := range blocked {
		close(source.closeRelease)
		close(source.acceptRelease)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(runtimeListenerProcessCallbackPermits.sourceCloseCalls) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(runtimeListenerProcessCallbackPermits.sourceCloseCalls); got != 0 {
		t.Fatalf("source cleanup reservations after release=%d want 0", got)
	}
}

func TestRuntimeListenerReplacementFencesOldBridgeAndEnginePublication(t *testing.T) {
	rt := newRuntimeListenerCallbackRuntime(t)
	old := newBareRuntimePathListener(rt)
	old.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
	if err := rt.claimListener(old); err != nil {
		t.Fatal(err)
	}
	old.generation = old.callbacks.activateGeneration()

	path := newAbnormalRuntimePathConn()
	path.closeAction = runtimeListenerCallbackBlock
	claim := claimRuntimeListenerPath(t, old, "old", path)
	flowID := engine.NewClientFlowID()
	reservation, err := old.reserveBridge(claim, flowID)
	if err != nil {
		t.Fatal(err)
	}
	closeErr := old.Close()
	assertRuntimeListenerCallbackError(t, closeErr, ListenerCallbackPathClose, ListenerCallbackTimeout)
	if got := rt.bridges.Len(); got != 0 {
		t.Fatalf("old listener retained %d bridge reservations after Close", got)
	}
	assertRuntimeListenerClaimReleased(t, rt)

	replacementSource := newAbnormalNetListener()
	replacement, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "replacement", Listener: replacementSource}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = replacement.Close()
		close(path.closeRelease)
		awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "old path cleanup exit")
	}()
	if old.generationActive() {
		t.Fatal("replacement listener did not revoke old listener generation")
	}
	if _, err := old.reserveBridge(claim, engine.NewClientFlowID()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old listener reserve after replacement=%v want net.ErrClosed", err)
	}
	staleEngine := engine.New(engine.SideServer, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer staleEngine.Close()
	if err := old.activateBridge(claim, reservation, engine.NewClientFlowID(), staleEngine); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old listener activation after replacement=%v want net.ErrClosed", err)
	}
	if got := rt.bridges.Len(); got != 0 {
		t.Fatalf("old listener mutated replacement bridge namespace: len=%d", got)
	}
}

type runtimeListenerFrameLimitPath struct {
	*abnormalRuntimePathConn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (path *runtimeListenerFrameLimitPath) MaxFrameSize() int {
	path.once.Do(func() { close(path.entered) })
	<-path.release
	return 0
}

func TestRuntimeListenerEngineAttachOwnsExactlyOneCleanup(t *testing.T) {
	t.Run("adopted admission", func(t *testing.T) {
		rt := newRuntimeListenerCallbackRuntime(t)
		listener := newBareRuntimePathListener(rt)
		listener.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
		if err := rt.claimListener(listener); err != nil {
			t.Fatal(err)
		}
		listener.generation = listener.callbacks.activateGeneration()

		e, targetID := newRuntimeListenerAdmissionEngine(t, true)
		defer e.Close()
		base := newAbnormalRuntimePathConn()
		path := &runtimeListenerFrameLimitPath{
			abnormalRuntimePathConn: base,
			entered:                 make(chan struct{}),
			release:                 make(chan struct{}),
		}
		claim := claimRuntimeListenerPath(t, listener, "attach-race", path)
		result := make(chan error, 1)
		go func() {
			_, _, err := attachClaimedServerPath(
				claim, e, path, PathSpec{Transport: "attach-race"}, targetID, 1<<16-1,
			)
			claim.finish(false)
			result <- err
		}()
		awaitRuntimeListenerCallbackSignal(t, path.entered, "engine MaxFrameSize admission")
		if err := listener.Close(); err != nil {
			t.Fatalf("listener Close during engine admission: %v", err)
		}
		if err := <-result; err == nil {
			t.Fatal("blocked MaxFrameSize admission unexpectedly succeeded")
		}
		close(path.release)
		awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "engine-owned admission cleanup")
		time.Sleep(10 * time.Millisecond)
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("PathConn.Close calls=%d want exactly 1", got)
		}
	})

	t.Run("pre-adoption rejection retains listener cleanup", func(t *testing.T) {
		rt := newRuntimeListenerCallbackRuntime(t)
		listener := newBareRuntimePathListener(rt)
		listener.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
		if err := rt.claimListener(listener); err != nil {
			t.Fatal(err)
		}
		listener.generation = listener.callbacks.activateGeneration()

		e, _ := newRuntimeListenerAdmissionEngine(t, true)
		defer e.Close()
		path := newAbnormalRuntimePathConn()
		claim := claimRuntimeListenerPath(t, listener, "pre-adoption-rejection", path)
		if !claim.beginEngineAttach(e) {
			t.Fatal("listener claim did not enter engine attach")
		}
		if !claim.resolveEngineAttach(e, 0, false) {
			t.Fatal("live listener claim became inactive while restoring ownership")
		}
		claim.finish(false)
		awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "listener-owned rejected admission cleanup")
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("PathConn.Close calls=%d want exactly 1", got)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("canceled pre-adoption rejection restores listener cleanup", func(t *testing.T) {
		rt := newRuntimeListenerCallbackRuntime(t)
		listener := newBareRuntimePathListener(rt)
		listener.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
		if err := rt.claimListener(listener); err != nil {
			t.Fatal(err)
		}
		listener.generation = listener.callbacks.activateGeneration()

		e, _ := newRuntimeListenerAdmissionEngine(t, true)
		defer e.Close()
		path := newAbnormalRuntimePathConn()
		claim := claimRuntimeListenerPath(t, listener, "canceled-pre-adoption-rejection", path)
		if !claim.beginEngineAttach(e) {
			t.Fatal("listener claim did not enter engine attach")
		}
		if !claim.cancel() {
			t.Fatal("listener claim was not canceled")
		}
		if claim.resolveEngineAttach(e, 0, false) {
			t.Fatal("canceled listener claim became active after ownership rejection")
		}
		awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "canceled listener-owned rejected admission cleanup")
		claim.finish(false)
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("PathConn.Close calls=%d want exactly 1", got)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cancel before adopted result transfers cleanup once", func(t *testing.T) {
		rt := newRuntimeListenerCallbackRuntime(t)
		listener := newBareRuntimePathListener(rt)
		listener.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
		if err := rt.claimListener(listener); err != nil {
			t.Fatal(err)
		}
		listener.generation = listener.callbacks.activateGeneration()
		e, targetID := newRuntimeListenerAdmissionEngine(t, true)
		defer e.Close()
		path := newAbnormalRuntimePathConn()
		claim := claimRuntimeListenerPath(t, listener, "cancel-before-adopted-result", path)
		if !claim.beginEngineAttach(e) {
			t.Fatal("listener claim did not enter engine attach")
		}
		pathID, adopted, err := e.PreparePathBoundWithOwnership(path, PathSpec{Transport: "memory"}, engine.PathBinding{
			LocalTXTargetID:           targetID,
			PeerTXTargetID:            targetID,
			LocalReceiveFrameCapacity: 1<<16 - 1,
			PeerReceiveFrameCapacity:  1<<16 - 1,
		})
		if err != nil || !adopted {
			t.Fatalf("engine preparation id/adopted/error=%d/%t/%v", pathID, adopted, err)
		}
		if got := path.maxFrameCalls.Load(); got != 1 {
			t.Fatalf("MaxFrameSize stimulus calls=%d want 1", got)
		}
		if !claim.cancel() {
			t.Fatal("listener claim was not canceled before result handoff")
		}
		if claim.resolveEngineAttach(e, pathID, adopted) {
			t.Fatal("canceled listener claim accepted adopted result")
		}
		claim.finish(false)
		awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "engine cleanup after canceled adopted result")
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("PathConn.Close calls=%d want exactly 1", got)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cancel after adopted result aborts before commit", func(t *testing.T) {
		rt := newRuntimeListenerCallbackRuntime(t)
		listener := newBareRuntimePathListener(rt)
		listener.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
		if err := rt.claimListener(listener); err != nil {
			t.Fatal(err)
		}
		listener.generation = listener.callbacks.activateGeneration()
		e, targetID := newRuntimeListenerAdmissionEngine(t, true)
		defer e.Close()
		path := newAbnormalRuntimePathConn()
		claim := claimRuntimeListenerPath(t, listener, "cancel-after-adopted-result", path)
		pathID, _, err := attachClaimedServerPath(claim, e, path, PathSpec{Transport: "memory"}, targetID, 1<<16-1)
		if err != nil || pathID == 0 {
			t.Fatalf("claimed preparation id/error=%d/%v", pathID, err)
		}
		if !claim.cancel() {
			t.Fatal("listener claim was not canceled before admission commit")
		}
		claim.finish(false)
		awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "engine cleanup after pre-commit cancellation")
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("PathConn.Close calls=%d want exactly 1", got)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

type queuedRuntimeCloseErrorPath struct {
	closed    chan struct{}
	closeOnce sync.Once
	err       error
}

func (path *queuedRuntimeCloseErrorPath) Read([]byte) (int, error) {
	<-path.closed
	return 0, io.EOF
}

func (path *queuedRuntimeCloseErrorPath) Write(payload []byte) (int, error) {
	return len(payload), nil
}

func (path *queuedRuntimeCloseErrorPath) Close() error {
	path.closeOnce.Do(func() { close(path.closed) })
	return path.err
}

func (*queuedRuntimeCloseErrorPath) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (*queuedRuntimeCloseErrorPath) OnDeath(func(transport.DeathCause, error)) {}
func (*queuedRuntimeCloseErrorPath) LocalAddr() string                         { return "queued-local" }
func (*queuedRuntimeCloseErrorPath) RemoteAddr() string                        { return "queued-remote" }

func TestRuntimeListenerAggregatesQueuedSessionCloseErrors(t *testing.T) {
	wantErr := errors.New("queued engine cleanup failed")
	e, targetID := newRuntimeListenerAdmissionEngine(t, false)
	path := &queuedRuntimeCloseErrorPath{closed: make(chan struct{}), err: wantErr}
	if _, err := e.AttachPathBound(path, transport.PathSpec{Transport: "queued"}, engine.PathBinding{
		LocalTXTargetID: targetID,
		PeerTXTargetID:  targetID,
	}); err != nil {
		t.Fatal(err)
	}

	rt := newRuntimeListenerCallbackRuntime(t)
	listener := newBareRuntimePathListener(rt)
	listener.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
	if err := rt.claimListener(listener); err != nil {
		t.Fatal(err)
	}
	listener.generation = listener.callbacks.activateGeneration()
	listener.streamSlots <- struct{}{}
	listener.streamAccept <- &acceptedStreamConn{engine: e}
	if err := listener.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("listener Close error=%v want queued engine error", err)
	}
}

func newRuntimeListenerAdmissionEngine(t *testing.T, packet bool) (*engine.Engine, proto.TargetID) {
	t.Helper()
	graph, err := compileTargetGraph(Path("path", PathSpec{Transport: "memory", Address: "peer"}))
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.SideServer, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	if err := e.ConfigureLocalGraph(1, graph.manifest); err != nil {
		_ = e.Close()
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, graph.manifest); err != nil {
		_ = e.Close()
		t.Fatal(err)
	}
	if packet {
		e.SetPacketMode()
	}
	targetID, err := e.LocalPathTargetID("path")
	if err != nil {
		_ = e.Close()
		t.Fatal(err)
	}
	return e, targetID
}

func TestSessionListenerCloseAbnormalSourceCleansInflightHandshake(t *testing.T) {
	for _, test := range []struct {
		name   string
		action runtimeListenerCallbackAction
		reason ListenerCallbackFailure
	}{
		{name: "panic", action: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", action: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			source := newAbnormalNetListener()
			source.closeAction = test.action
			listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "stream", Listener: source}}})
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			defer client.Close()
			source.connections <- server
			deadline := time.Now().Add(time.Second)
			for runtimeListenerInflight(listener) != 1 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := runtimeListenerInflight(listener); got != 1 {
				t.Fatalf("inflight paths=%d want 1", got)
			}

			err = listener.Close()
			assertRuntimeListenerCallbackError(t, err, ListenerCallbackClose, test.reason)
			close(source.acceptRelease)
			if got := runtimeListenerInflight(listener); got != 0 {
				t.Fatalf("inflight paths after Close=%d want 0", got)
			}
			if got := len(listener.handshakes); got != 0 {
				t.Fatalf("handshake slots after Close=%d want 0", got)
			}
			assertRuntimeListenerSourceCount(t, listener, 0, 1)
			assertRuntimeListenerClaimReleased(t, rt)
		})
	}
}

func newRuntimeListenerCallbackRuntime(t *testing.T) *Runtime {
	t.Helper()
	rt, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func assertRuntimeListenerCallbackError(t *testing.T, err error, operation ListenerCallbackOperation, reason ListenerCallbackFailure) {
	t.Helper()
	var callbackErr *ListenerCallbackError
	if !errors.As(err, &callbackErr) {
		t.Fatalf("error=%v, want ListenerCallbackError", err)
	}
	if callbackErr.Operation != operation || callbackErr.Reason != reason {
		t.Fatalf("callback error=%+v, want operation=%s reason=%s", callbackErr, operation, reason)
	}
}

func assertRuntimeListenerClaimReleased(t *testing.T, rt *Runtime) {
	t.Helper()
	rt.listenMu.Lock()
	defer rt.listenMu.Unlock()
	if rt.listener != nil {
		t.Fatal("Runtime retained SessionListener claim")
	}
}

func assertRuntimeListenerCanBeReused(t *testing.T, rt *Runtime) {
	t.Helper()
	source := newAbnormalNetListener()
	listener, err := rt.Listen(ListenConfig{Streams: []StreamSource{{Name: "replacement", Listener: source}}})
	if err != nil {
		t.Fatalf("Runtime could not create replacement listener: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("replacement Close: %v", err)
	}
}

func awaitRuntimeListenerClosed(t *testing.T, listener *SessionListener) {
	t.Helper()
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("SessionListener did not close after terminal source failure")
	}
}

func assertRuntimeListenerSourceCount(t *testing.T, listener *SessionListener, wantActive, total int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		listener.sourceMu.Lock()
		active := listener.activeSource
		listener.sourceMu.Unlock()
		if active == wantActive {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active sources=%d want %d (configured=%d)", active, wantActive, total)
		}
		time.Sleep(time.Millisecond)
	}
}

type abnormalRuntimePathConn struct {
	localAction      runtimeListenerCallbackAction
	remoteAction     runtimeListenerCallbackAction
	closeAction      runtimeListenerCallbackAction
	closeAfterAction runtimeListenerCallbackAction
	closeErr         error

	localEntered   chan struct{}
	localReturned  chan struct{}
	remoteEntered  chan struct{}
	remoteReturned chan struct{}
	closeEntered   chan struct{}
	closeReturned  chan struct{}
	addressRelease chan struct{}
	closeRelease   chan struct{}

	localEnterOnce   sync.Once
	localReturnOnce  sync.Once
	remoteEnterOnce  sync.Once
	remoteReturnOnce sync.Once
	closeEnterOnce   sync.Once
	closeReturnOnce  sync.Once
	closeCalls       atomic.Int32
	maxFrameCalls    atomic.Int32
}

func newAbnormalRuntimePathConn() *abnormalRuntimePathConn {
	return &abnormalRuntimePathConn{
		localEntered:   make(chan struct{}),
		localReturned:  make(chan struct{}),
		remoteEntered:  make(chan struct{}),
		remoteReturned: make(chan struct{}),
		closeEntered:   make(chan struct{}),
		closeReturned:  make(chan struct{}),
		addressRelease: make(chan struct{}),
		closeRelease:   make(chan struct{}),
	}
}

func (*abnormalRuntimePathConn) Read([]byte) (int, error) { return 0, io.EOF }
func (*abnormalRuntimePathConn) Write(frame []byte) (int, error) {
	return len(frame), nil
}
func (path *abnormalRuntimePathConn) Close() error {
	path.closeCalls.Add(1)
	path.closeEnterOnce.Do(func() { close(path.closeEntered) })
	defer path.closeReturnOnce.Do(func() { close(path.closeReturned) })
	runRuntimeListenerCallbackAction(path.closeAction, path.closeRelease)
	runRuntimeListenerCallbackAction(path.closeAfterAction, path.closeRelease)
	return path.closeErr
}
func (*abnormalRuntimePathConn) Quality() transport.PathQuality { return transport.PathQuality{} }
func (path *abnormalRuntimePathConn) MaxFrameSize() int {
	path.maxFrameCalls.Add(1)
	return 1<<16 - 1
}
func (*abnormalRuntimePathConn) OnDeath(func(transport.DeathCause, error)) {
}
func (path *abnormalRuntimePathConn) LocalAddr() string {
	path.localEnterOnce.Do(func() { close(path.localEntered) })
	defer path.localReturnOnce.Do(func() { close(path.localReturned) })
	runRuntimeListenerCallbackAction(path.localAction, path.addressRelease)
	return "path-local"
}
func (path *abnormalRuntimePathConn) RemoteAddr() string {
	path.remoteEnterOnce.Do(func() { close(path.remoteEntered) })
	defer path.remoteReturnOnce.Do(func() { close(path.remoteReturned) })
	runRuntimeListenerCallbackAction(path.remoteAction, path.addressRelease)
	return "path-remote"
}

func TestRuntimeListenerPathAddressAbnormalExitIsOptionalAndContained(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation ListenerCallbackOperation
		action    runtimeListenerCallbackAction
	}{
		{name: "LocalAddr panic", operation: ListenerCallbackLocalAddr, action: runtimeListenerCallbackPanic},
		{name: "LocalAddr Goexit", operation: ListenerCallbackLocalAddr, action: runtimeListenerCallbackGoexit},
		{name: "RemoteAddr panic", operation: ListenerCallbackRemoteAddr, action: runtimeListenerCallbackPanic},
		{name: "RemoteAddr Goexit", operation: ListenerCallbackRemoteAddr, action: runtimeListenerCallbackGoexit},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener := newBareRuntimePathListener(nil)
			path := newAbnormalRuntimePathConn()
			if test.operation == ListenerCallbackLocalAddr {
				path.localAction = test.action
			} else {
				path.remoteAction = test.action
			}
			claim := claimRuntimeListenerPath(t, listener, "abnormal-address", path)

			address, active := listener.pathAddress(claim, test.operation)
			if !active {
				t.Fatal("abnormal diagnostic callback revoked a live admission claim")
			}
			if address != "" {
				t.Fatalf("abnormal diagnostic address=%q want empty fallback", address)
			}
			if !claim.active() {
				t.Fatal("live claim disappeared after optional diagnostic failure")
			}
			claim.finish(false)
			if err := claim.close.wait(); err != nil {
				t.Fatalf("path cleanup: %v", err)
			}
		})
	}
}

func TestRuntimeListenerCloseCancelsBlockedPathAddressWithoutLateAdmission(t *testing.T) {
	for _, operation := range []ListenerCallbackOperation{ListenerCallbackRemoteAddr, ListenerCallbackLocalAddr} {
		t.Run(string(operation), func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			listener := newBareRuntimePathListener(rt)
			if err := rt.claimListener(listener); err != nil {
				t.Fatal(err)
			}
			path := newAbnormalRuntimePathConn()
			var entered, returned <-chan struct{}
			if operation == ListenerCallbackRemoteAddr {
				path.remoteAction = runtimeListenerCallbackBlock
				entered, returned = path.remoteEntered, path.remoteReturned
			} else {
				path.localAction = runtimeListenerCallbackBlock
				entered, returned = path.localEntered, path.localReturned
			}
			claim := claimRuntimeListenerPath(t, listener, "blocked-address", path)
			payload := runtimeListenerCallbackHelloPayload(t, "blocked-address")

			owned := make(chan bool, 1)
			listener.workers.Add(1)
			go func() {
				defer listener.workers.Done()
				accepted := listener.handleRuntimeHello(claim, payload, func() error { return nil })
				claim.finish(accepted)
				owned <- accepted
			}()
			awaitRuntimeListenerCallbackSignal(t, entered, string(operation)+" callback")

			started := time.Now()
			if err := listener.Close(); err != nil {
				t.Fatalf("Close during blocked %s: %v", operation, err)
			}
			if elapsed := time.Since(started); elapsed >= runtimeListenerCallTimeout {
				t.Fatalf("Close waited for blocked %s callback: %s", operation, elapsed)
			}
			if accepted := <-owned; accepted {
				t.Fatal("closed listener admitted a session after its address claim was revoked")
			}
			if runtimeListenerInflight(listener) != 0 || len(listener.handshakes) != 0 {
				t.Fatalf("closed listener retained claim state: inflight=%d handshakes=%d", runtimeListenerInflight(listener), len(listener.handshakes))
			}
			if len(listener.streamAccept) != 0 || len(listener.FlowIDs()) != 0 {
				t.Fatalf("closed listener published late admission: queued=%d flows=%d", len(listener.streamAccept), len(listener.FlowIDs()))
			}
			assertRuntimeListenerClaimReleased(t, rt)

			close(path.addressRelease)
			awaitRuntimeListenerCallbackSignal(t, returned, "late "+string(operation)+" return")
			time.Sleep(10 * time.Millisecond)
			if len(listener.streamAccept) != 0 || len(listener.FlowIDs()) != 0 {
				t.Fatalf("late %s result resurrected admission: queued=%d flows=%d", operation, len(listener.streamAccept), len(listener.FlowIDs()))
			}
		})
	}
}

func TestPathHandshakeDeadlineContainsAbnormalCloseAndRevokesClaim(t *testing.T) {
	for _, test := range []struct {
		name   string
		action runtimeListenerCallbackAction
		reason ListenerCallbackFailure
	}{
		{name: "panic", action: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", action: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
		{name: "block", action: runtimeListenerCallbackBlock, reason: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			listener := newBareRuntimePathListener(rt)
			if err := rt.claimListener(listener); err != nil {
				t.Fatal(err)
			}
			path := newAbnormalRuntimePathConn()
			path.closeAction = test.action
			claim := claimRuntimeListenerPath(t, listener, "deadline-close", path)
			clear := armClaimedPathHandshakeDeadline(claim, 10*time.Millisecond)
			defer clear()
			awaitRuntimeListenerCallbackSignal(t, path.closeEntered, "deadline PathConn.Close")

			deadline := time.Now().Add(250 * time.Millisecond)
			for (runtimeListenerInflight(listener) != 0 || len(listener.handshakes) != 0) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if runtimeListenerInflight(listener) != 0 || len(listener.handshakes) != 0 {
				t.Fatalf("deadline retained claim state: inflight=%d handshakes=%d", runtimeListenerInflight(listener), len(listener.handshakes))
			}
			if listener.publishStream(claim, &acceptedStreamConn{}) {
				t.Fatal("revoked deadline claim was published")
			}

			started := time.Now()
			if err := listener.Close(); err != nil {
				t.Fatalf("listener Close after deadline revocation: %v", err)
			}
			if elapsed := time.Since(started); elapsed >= runtimeListenerCallTimeout {
				t.Fatalf("listener Close waited for malformed timer-side Close: %s", elapsed)
			}
			assertRuntimeListenerClaimReleased(t, rt)

			if test.action == runtimeListenerCallbackBlock {
				close(path.closeRelease)
				if err := claim.close.wait(); err != nil {
					t.Fatalf("released PathConn.Close: %v", err)
				}
				return
			}
			assertRuntimeListenerCallbackError(t, claim.close.wait(), ListenerCallbackPathClose, test.reason)
		})
	}
}

func TestRuntimeListenerLatePathCloseTerminalDiagnostics(t *testing.T) {
	wantLate := errors.New("late PathConn.Close failure")
	tests := []struct {
		name        string
		afterAction runtimeListenerCallbackAction
		closeErr    error
		reason      ListenerCallbackFailure
	}{
		{name: "error", closeErr: wantLate},
		{name: "panic", afterAction: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", afterAction: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			listener := newBareRuntimePathListener(rt)
			listener.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
			if err := rt.claimListener(listener); err != nil {
				t.Fatal(err)
			}
			listener.generation = listener.callbackOwner().activateGeneration()

			path := newAbnormalRuntimePathConn()
			path.closeAction = runtimeListenerCallbackBlock
			path.closeAfterAction = test.afterAction
			path.closeErr = test.closeErr
			claim := claimRuntimeListenerPath(t, listener, "late-terminal", path)
			claim.close.timeout = 10 * time.Millisecond

			const closeCallers = 8
			initial := make(chan error, closeCallers)
			for range closeCallers {
				go func() { initial <- listener.Close() }()
			}
			awaitRuntimeListenerCallbackSignal(t, path.closeEntered, "blocked PathConn.Close")
			for range closeCallers {
				assertRuntimeListenerCallbackError(t, <-initial, ListenerCallbackPathClose, ListenerCallbackTimeout)
			}
			if got := path.closeCalls.Load(); got != 1 {
				t.Fatalf("PathConn.Close calls=%d want 1", got)
			}
			if got := len(listener.callbackOwner().permits.pathCloseCalls); got != 1 {
				t.Fatalf("path-close permits after timeout=%d want 1", got)
			}

			// A replacement generation must not inherit an old listener's late
			// diagnostics even while the old callback still owns its permit.
			replacement := newBareRuntimePathListener(rt)
			replacement.callbacks = newRuntimeListenerCallbackOwnerForRuntime(rt)
			if err := rt.claimListener(replacement); err != nil {
				t.Fatal(err)
			}
			replacement.generation = replacement.callbackOwner().activateGeneration()

			close(path.closeRelease)
			awaitRuntimeListenerCallbackSignal(t, path.closeReturned, "late PathConn.Close return")
			deadline := time.Now().Add(time.Second)
			for len(listener.callbackOwner().permits.pathCloseCalls) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := len(listener.callbackOwner().permits.pathCloseCalls); got != 0 {
				t.Fatalf("path-close permits after terminal completion=%d want 0", got)
			}

			terminal := make(chan error, closeCallers)
			for range closeCallers {
				go func() { terminal <- listener.Close() }()
			}
			for range closeCallers {
				err := <-terminal
				assertRuntimeListenerCallbackInJoin(t, err, ListenerCallbackPathClose, ListenerCallbackTimeout)
				if test.closeErr != nil {
					if !errors.Is(err, test.closeErr) {
						t.Fatalf("terminal Close error=%v want late error %v", err, test.closeErr)
					}
				} else {
					assertRuntimeListenerCallbackInJoin(t, err, ListenerCallbackPathClose, test.reason)
				}
			}
			if err := replacement.Close(); err != nil {
				t.Fatalf("replacement generation inherited old diagnostics: %v", err)
			}
			if got := path.closeCalls.Load(); got != 1 {
				t.Fatalf("PathConn.Close calls after repeated listener Close=%d want 1", got)
			}
		})
	}
}

func TestSessionListenerLateSourceCloseTerminalDiagnostics(t *testing.T) {
	wantLate := errors.New("late FramedSource.Close failure")
	tests := []struct {
		name        string
		afterAction runtimeListenerCallbackAction
		closeErr    error
		reason      ListenerCallbackFailure
	}{
		{name: "error", closeErr: wantLate},
		{name: "panic", afterAction: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", afterAction: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := newRuntimeListenerCallbackRuntime(t)
			source := newAbnormalFramedListener()
			source.closeAction = runtimeListenerCallbackBlock
			source.closeAfterAction = test.afterAction
			source.closeErr = test.closeErr
			listener, err := rt.Listen(ListenConfig{Framed: []FramedSource{{Name: "late-source", Listener: source}}})
			if err != nil {
				t.Fatal(err)
			}
			listener.closers[0].timeout = 10 * time.Millisecond

			const closeCallers = 8
			initial := make(chan error, closeCallers)
			for range closeCallers {
				go func() { initial <- listener.Close() }()
			}
			for range closeCallers {
				assertRuntimeListenerCallbackError(t, <-initial, ListenerCallbackClose, ListenerCallbackTimeout)
			}
			if _, _, _, got := source.counts(); got != 1 {
				t.Fatalf("FramedSource.Close calls=%d want 1", got)
			}
			if got := len(listener.callbackOwner().permits.sourceCloseCalls); got != 1 {
				t.Fatalf("source-close permits after timeout=%d want 1", got)
			}

			close(source.closeRelease)
			awaitRuntimeListenerCallbackSignal(t, source.closeReturned, "late FramedSource.Close return")
			deadline := time.Now().Add(time.Second)
			for len(listener.callbackOwner().permits.sourceCloseCalls) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := len(listener.callbackOwner().permits.sourceCloseCalls); got != 0 {
				t.Fatalf("source-close permits after terminal completion=%d want 0", got)
			}

			terminal := listener.Close()
			assertRuntimeListenerCallbackInJoin(t, terminal, ListenerCallbackClose, ListenerCallbackTimeout)
			if test.closeErr != nil {
				if !errors.Is(terminal, test.closeErr) {
					t.Fatalf("terminal Close error=%v want late error %v", terminal, test.closeErr)
				}
			} else {
				assertRuntimeListenerCallbackInJoin(t, terminal, ListenerCallbackClose, test.reason)
			}
			if _, _, _, got := source.counts(); got != 1 {
				t.Fatalf("FramedSource.Close calls after repeated Close=%d want 1", got)
			}
		})
	}
}

func TestRuntimeListenerAbandonedCallbackRecordsTerminalAndCleansExactlyOnce(t *testing.T) {
	wantLate := errors.New("late AcceptPath failure")
	tests := []struct {
		name   string
		action runtimeListenerCallbackAction
		err    error
		reason ListenerCallbackFailure
	}{
		{name: "error", err: wantLate},
		{name: "panic", action: runtimeListenerCallbackPanic, reason: ListenerCallbackPanic},
		{name: "Goexit", action: runtimeListenerCallbackGoexit, reason: ListenerCallbackAbnormalExit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner := newRuntimeListenerCallbackOwner()
			entered := make(chan struct{})
			release := make(chan struct{})
			cleaned := make(chan struct{})
			var cleanupCalls atomic.Int32
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			_, err, abandoned := invokeRuntimeListenerCallbackWithCleanup(
				ctx,
				owner,
				"late-accept",
				ListenerCallbackAcceptPath,
				func() (int, error) {
					close(entered)
					<-release
					runRuntimeListenerCallbackAction(test.action, release)
					return 42, test.err
				},
				func(int) {
					if cleanupCalls.Add(1) == 1 {
						close(cleaned)
					}
				},
			)
			awaitRuntimeListenerCallbackSignal(t, entered, "abandoned callback entry")
			if !abandoned {
				t.Fatal("timed-out callback was not marked abandoned")
			}
			assertRuntimeListenerCallbackError(t, err, ListenerCallbackAcceptPath, ListenerCallbackTimeout)
			if got := len(owner.permits.acceptCalls); got != 1 {
				t.Fatalf("accept permits after timeout=%d want 1", got)
			}

			stopReaders := make(chan struct{})
			var readers sync.WaitGroup
			for range 8 {
				readers.Add(1)
				go func() {
					defer readers.Done()
					for {
						select {
						case <-stopReaders:
							return
						default:
							_ = owner.terminalDiagnostics()
						}
					}
				}()
			}
			close(release)
			awaitRuntimeListenerCallbackSignal(t, cleaned, "late callback cleanup")
			close(stopReaders)
			readers.Wait()
			if got := cleanupCalls.Load(); got != 1 {
				t.Fatalf("late cleanup calls=%d want 1", got)
			}
			deadline := time.Now().Add(time.Second)
			for len(owner.permits.acceptCalls) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := len(owner.permits.acceptCalls); got != 0 {
				t.Fatalf("accept permits after callback completion=%d want 0", got)
			}

			diagnostic := owner.terminalDiagnostics()
			if test.err != nil {
				if !errors.Is(diagnostic, test.err) {
					t.Fatalf("terminal diagnostics=%v want %v", diagnostic, test.err)
				}
			} else {
				assertRuntimeListenerCallbackInJoin(t, diagnostic, ListenerCallbackAcceptPath, test.reason)
			}
		})
	}
}

func TestRuntimeListenerTerminalDiagnosticsPruneExpectedCloseOnly(t *testing.T) {
	for _, test := range []struct {
		name     string
		expected error
	}{
		{name: "net.ErrClosed", expected: net.ErrClosed},
		{name: "context.Canceled", expected: context.Canceled},
	} {
		t.Run(test.name+" expected-only wrapper", func(t *testing.T) {
			owner := newRuntimeListenerCallbackOwner()
			owner.recordTerminalDiagnostic(fmt.Errorf(
				"outer: %w", fmt.Errorf("inner: %w", test.expected),
			))
			if err := owner.terminalDiagnostics(); err != nil {
				t.Fatalf("expected-only diagnostic=%v want nil", err)
			}
		})

		t.Run(test.name+" nested joined failure", func(t *testing.T) {
			owner := newRuntimeListenerCallbackOwner()
			want := errors.New("independent late failure")
			owner.recordTerminalDiagnostic(fmt.Errorf(
				"outer: %w",
				errors.Join(fmt.Errorf("expected: %w", test.expected), want),
			))
			diagnostic := owner.terminalDiagnostics()
			if !errors.Is(diagnostic, want) {
				t.Fatalf("terminal diagnostic=%v want %v", diagnostic, want)
			}
			if errors.Is(diagnostic, test.expected) {
				t.Fatalf("terminal diagnostic retained expected branch: %v", diagnostic)
			}
		})
	}

	t.Run("non-expected typed wrapper retains identity", func(t *testing.T) {
		want := &runtimeListenerTypedDiagnosticError{cause: errors.New("connection reset")}
		if diagnostic := runtimeListenerTerminalDiagnostic(want); diagnostic != want {
			t.Fatalf("direct diagnostic=%T %v want original pointer %p", diagnostic, diagnostic, want)
		}
		owner := newRuntimeListenerCallbackOwner()
		owner.recordTerminalDiagnostic(want)
		diagnostic := owner.terminalDiagnostics()
		var typed *runtimeListenerTypedDiagnosticError
		if !errors.As(diagnostic, &typed) {
			t.Fatalf("terminal diagnostic=%v lost typed wrapper", diagnostic)
		}
		if typed != want {
			t.Fatalf("terminal diagnostic wrapper=%p want original pointer %p", typed, want)
		}
	})

	assertInvalid := func(t *testing.T, err error) {
		t.Helper()
		diagnostic := runtimeListenerTerminalDiagnostic(err)
		var callbackErr *ListenerCallbackError
		if !errors.As(diagnostic, &callbackErr) {
			t.Fatalf("diagnostic=%v want ListenerCallbackError", diagnostic)
		}
		if callbackErr.Source != "session-listener-diagnostics" ||
			callbackErr.Operation != ListenerCallbackClose ||
			callbackErr.Reason != ListenerCallbackInvalidResult {
			t.Fatalf("diagnostic=%+v want sanitized InvalidResult", callbackErr)
		}
	}

	t.Run("self-cycle", func(t *testing.T) {
		assertInvalid(t, &runtimeListenerSelfCycleError{})
	})
	t.Run("multi-cycle", func(t *testing.T) {
		first := &runtimeListenerMultiCycleError{}
		second := &runtimeListenerMultiCycleError{}
		first.children = []error{second}
		second.children = []error{first}
		assertInvalid(t, first)
	})
	t.Run("panicking single unwrap", func(t *testing.T) {
		assertInvalid(t, &runtimeListenerPanicUnwrapOneError{})
	})
	t.Run("panicking multi unwrap", func(t *testing.T) {
		assertInvalid(t, &runtimeListenerPanicUnwrapManyError{})
	})
	t.Run("panicking Is", func(t *testing.T) {
		assertInvalid(t, &runtimeListenerPanicIsError{})
	})
	t.Run("depth budget", func(t *testing.T) {
		var err error = errors.New("deep leaf")
		for range runtimeListenerErrorDepthLimit + 1 {
			err = &runtimeListenerTypedDiagnosticError{cause: err}
		}
		assertInvalid(t, err)
	})
	t.Run("node budget fanout", func(t *testing.T) {
		children := make([]error, runtimeListenerErrorNodeLimit)
		for index := range children {
			children[index] = errors.New("fanout leaf")
		}
		assertInvalid(t, &runtimeListenerMultiCycleError{children: children})
	})
}

func assertRuntimeListenerCallbackInJoin(t *testing.T, err error, operation ListenerCallbackOperation, reason ListenerCallbackFailure) {
	t.Helper()
	var visit func(error) bool
	visit = func(candidate error) bool {
		if candidate == nil {
			return false
		}
		if callbackErr, ok := candidate.(*ListenerCallbackError); ok && callbackErr.Operation == operation && callbackErr.Reason == reason {
			return true
		}
		switch joined := candidate.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range joined.Unwrap() {
				if visit(child) {
					return true
				}
			}
		case interface{ Unwrap() error }:
			return visit(joined.Unwrap())
		}
		return false
	}
	if !visit(err) {
		t.Fatalf("error=%v, want ListenerCallbackError operation=%s reason=%s", err, operation, reason)
	}
}

func newBareRuntimePathListener(rt *Runtime) *SessionListener {
	return &SessionListener{
		runtime:      rt,
		streamAccept: make(chan *acceptedStreamConn, 1),
		packetAccept: make(chan *acceptedPacketConn, 1),
		streamSlots:  make(chan struct{}, 1),
		packetSlots:  make(chan struct{}, 1),
		handshakes:   make(chan struct{}, 1),
		kinds:        map[string]transport.PathSessionKind{"blocked-address": transport.PathSessionStream},
		carriers:     make(map[string]CarrierFamily),
		inflight:     make(map[uint64]*runtimeListenerInflightClaim),
		closed:       make(chan struct{}),
		closeDone:    make(chan struct{}),
	}
}

func claimRuntimeListenerPath(t *testing.T, listener *SessionListener, source string, path transport.PathConn) *runtimeListenerInflightClaim {
	t.Helper()
	listener.handshakes <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := reserveRuntimeListenerPathClose(ctx, source, listener.callbackOwner())
	if err != nil {
		t.Fatalf("reserve path cleanup: %v", err)
	}
	claim, ok := listener.trackInflight(source, path, newRuntimeListenerPathClose(source, path, lease, nil))
	if !ok {
		lease.release()
		t.Fatal("could not acquire runtime listener path claim")
	}
	return claim
}

func runtimeListenerCallbackHelloPayload(t *testing.T, source string) []byte {
	t.Helper()
	client := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer client.Close()
	graph, err := compileTargetGraph(Path("path", PathSpec{Transport: source, Address: "peer"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigureLocalGraph(1, graph.manifest); err != nil {
		t.Fatal(err)
	}
	instanceID := engine.NewInstanceID()
	client.SetLocalInstanceID(instanceID)
	targetID, err := client.LocalPathTargetID("path")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := (proto.HelloPayload{
		Negotiation:     client.LocalNegotiation(),
		FlowID:          client.FlowID(),
		InstanceID:      instanceID,
		InitialTargetID: targetID,
		LocalTXManifest: client.LocalGraphManifest(),
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func awaitRuntimeListenerCallbackSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("%s did not occur", name)
	}
}
