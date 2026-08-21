package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type configDispatchTracer struct {
	mu          sync.Mutex
	authorized  []transport.FrameDispatchAuthorization
	completions []transport.FrameDispatchCompletion
}

type configDispatchSpan struct {
	tracer *configDispatchTracer
}

func (tracer *configDispatchTracer) BeginFrameDispatch(
	authorization transport.FrameDispatchAuthorization,
) transport.FrameDispatchSpan {
	tracer.mu.Lock()
	tracer.authorized = append(tracer.authorized, authorization)
	tracer.mu.Unlock()
	return &configDispatchSpan{tracer: tracer}
}

func (span *configDispatchSpan) FinishFrameDispatch(completion transport.FrameDispatchCompletion) {
	span.tracer.mu.Lock()
	span.tracer.completions = append(span.tracer.completions, completion)
	span.tracer.mu.Unlock()
}

func TestNewWithConfigRejectsInvalidValues(t *testing.T) {
	if _, err := NewWithConfig(Config{WriteBufferBytes: -1}); err == nil {
		t.Fatal("negative WriteBufferBytes was accepted")
	}
}

func TestConfiguredTransportRejectsTracerFactoryFailureAndTypedNil(t *testing.T) {
	factoryFailure := errors.New("tracer factory failed")
	var typedNil *configDispatchTracer
	for _, test := range []struct {
		name string
		new  DispatchTracerFactory
		want error
	}{
		{
			name: "factory error",
			new: func(DispatchTracePath) (transport.FrameDispatchTracer, error) {
				return nil, factoryFailure
			},
			want: factoryFailure,
		},
		{
			name: "typed nil",
			new: func(DispatchTracePath) (transport.FrameDispatchTracer, error) {
				return typedNil, nil
			},
		},
		{
			name: "factory panic",
			new: func(DispatchTracePath) (transport.FrameDispatchTracer, error) {
				panic(factoryFailure)
			},
			want: factoryFailure,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, _ := listener.Accept()
				accepted <- conn
			}()
			factory, err := NewWithConfig(Config{NewDispatchTracer: test.new})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := factory.DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()}); err == nil ||
				(test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("DialPath error=%v want=%v", err, test.want)
			}
			if peer := <-accepted; peer != nil {
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 1)
				if n, readErr := peer.Read(buffer); readErr == nil || n != 0 {
					t.Fatalf("rejected path remained open: read=(%d,%v)", n, readErr)
				}
				_ = peer.Close()
			}
		})
	}
}

func TestConfiguredTransportProbeDoesNotCreateDispatchTracer(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = conn.Close()
		}
		accepted <- err
	}()
	var calls atomic.Int32
	factory, err := NewWithConfig(Config{
		NewDispatchTracer: func(DispatchTracePath) (transport.FrameDispatchTracer, error) {
			calls.Add(1)
			return nil, errors.New("probe invoked dispatch tracer factory")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	quality, err := factory.Probe(ctx, transport.PathSpec{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if quality.RTT <= 0 || calls.Load() != 0 {
		t.Fatalf("probe RTT/tracer calls=%s/%d, want positive/0", quality.RTT, calls.Load())
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredTransportRejectsCancellationDuringTracerFactory(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerReady := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		peerReady <- conn
	}()
	entered := make(chan struct{})
	release := make(chan struct{})
	factory, err := NewWithConfig(Config{
		NewDispatchTracer: func(DispatchTracePath) (transport.FrameDispatchTracer, error) {
			close(entered)
			<-release
			return &configDispatchTracer{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		path, dialErr := factory.DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()})
		if path != nil {
			_ = path.Close()
		}
		result <- dialErr
	}()
	<-entered
	cancel()
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("DialPath error=%v, want context.Canceled", err)
	}
	peer := <-peerReady
	if peer == nil {
		t.Fatal("server did not accept canceled configured path")
	}
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if n, err := peer.Read(buffer); err == nil || n != 0 {
		t.Fatalf("canceled configured path remained open: read=(%d,%v)", n, err)
	}
}

func TestConfiguredListenerRejectsPathWhenClosedDuringTracerFactory(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	listener, err := ListenWithConfig("tcp4", "127.0.0.1:0", Config{
		NewDispatchTracer: func(DispatchTracePath) (transport.FrameDispatchTracer, error) {
			close(entered)
			<-release
			return &configDispatchTracer{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		path, acceptErr := listener.AcceptPath(ctx)
		if path != nil {
			_ = path.Close()
		}
		result <- acceptErr
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	<-entered
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcceptPath error=%v, want net.ErrClosed", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if n, err := client.Read(buffer); err == nil || n != 0 {
		t.Fatalf("listener-published path survived Close: read=(%d,%v)", n, err)
	}
}

func TestConfiguredTransportTracesOwnedRawTCPWithoutWrappingSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	tracer := &configDispatchTracer{}
	var tracedPath DispatchTracePath
	factory, err := NewWithConfig(Config{
		WriteBufferBytes: 4096,
		NewDispatchTracer: func(path DispatchTracePath) (transport.FrameDispatchTracer, error) {
			tracedPath = path
			return tracer, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pathValue, err := factory.DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	path, ok := pathValue.(*PathConn)
	if !ok {
		t.Fatalf("configured path type=%T, want *tcp.PathConn", pathValue)
	}
	t.Cleanup(func() { _ = path.Close() })
	if path.claim == nil {
		t.Fatal("configured path lost its owned mobility claim")
	}
	if tracedPath.Role != PathRoleDialer || tracedPath.LocalAddr != path.LocalAddr() ||
		tracedPath.RemoteAddr != path.RemoteAddr() {
		t.Fatalf("configured trace path=%+v path=%s->%s", tracedPath, path.LocalAddr(), path.RemoteAddr())
	}
	endpoint, generation, current := path.endpoint.current()
	if !current || generation != 1 {
		t.Fatalf("configured endpoint current=%t generation=%d", current, generation)
	}
	if _, raw := endpoint.(*net.TCPConn); !raw {
		t.Fatalf("configured endpoint type=%T, want raw *net.TCPConn", endpoint)
	}

	var peer net.Conn
	select {
	case peer = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = peer.Close() })

	frame := dispatchTestFrame(t, 41, []byte("configured-owned-tcp"))
	received := make(chan error, 1)
	go func() {
		wire := make([]byte, LengthPrefixSize+len(frame))
		_, readErr := io.ReadFull(peer, wire)
		received <- readErr
	}()
	if n, err := path.WriteFrameDispatch(frame, dispatchTestAuthorization(frame, 41)); err != nil || n != len(frame) {
		t.Fatalf("configured dispatch=(%d,%v), want (%d,nil)", n, err, len(frame))
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}

	tracer.mu.Lock()
	defer tracer.mu.Unlock()
	if len(tracer.authorized) != 1 || len(tracer.completions) != 1 {
		t.Fatalf("trace authorization/completion=%d/%d", len(tracer.authorized), len(tracer.completions))
	}
	if tracer.authorized[0].Sequence != 41 || tracer.authorized[0].PhysicalOccurrence != 1 ||
		tracer.authorized[0].EndpointGeneration != 1 || tracer.authorized[0].FrameDigest != proto.DigestFrame(frame) {
		t.Fatalf("configured authorization=%+v", tracer.authorized[0])
	}
	if !tracer.completions[0].WholeFrameAccepted || tracer.completions[0].BytesWritten != len(frame) ||
		tracer.completions[0].Err != nil {
		t.Fatalf("configured completion=%+v", tracer.completions[0])
	}
}

func TestConfiguredListenerCreatesPathLocalTracerBeforeAcceptReturns(t *testing.T) {
	tracer := &configDispatchTracer{}
	var tracedPath DispatchTracePath
	listener, err := ListenWithConfig("tcp4", "127.0.0.1:0", Config{
		NewDispatchTracer: func(path DispatchTracePath) (transport.FrameDispatchTracer, error) {
			tracedPath = path
			return tracer, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan transport.PathConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		path, err := listener.AcceptPath(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- path
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var pathValue transport.PathConn
	select {
	case pathValue = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	path, ok := pathValue.(*PathConn)
	if !ok {
		t.Fatalf("configured accepted path type=%T, want *tcp.PathConn", pathValue)
	}
	defer path.Close()
	if tracedPath.Role != PathRoleAcceptor || tracedPath.LocalAddr != path.LocalAddr() ||
		tracedPath.RemoteAddr != path.RemoteAddr() {
		t.Fatalf("accept trace path=%+v path=%s->%s", tracedPath, path.LocalAddr(), path.RemoteAddr())
	}
	frame := dispatchTestFrame(t, 42, []byte("configured-acceptor"))
	received := make(chan error, 1)
	go func() {
		wire := make([]byte, LengthPrefixSize+len(frame))
		_, err := io.ReadFull(client, wire)
		received <- err
	}()
	if n, err := path.WriteFrameDispatch(frame, dispatchTestAuthorization(frame, 42)); err != nil || n != len(frame) {
		t.Fatalf("acceptor dispatch=(%d,%v), want (%d,nil)", n, err, len(frame))
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	tracer.mu.Lock()
	defer tracer.mu.Unlock()
	if len(tracer.authorized) != 1 || len(tracer.completions) != 1 {
		t.Fatalf("acceptor trace authorization/completion=%d/%d", len(tracer.authorized), len(tracer.completions))
	}
}
