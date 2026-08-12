package quic

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	qg "github.com/FrankoonG/quic-go"
	"github.com/FrankoonG/quic-go/qlog"
	"github.com/FrankoonG/quic-go/qlogwriter"

	"github.com/FrankoonG/rendr/transport"
)

type tracingInvocation struct {
	isClient bool
	connID   qg.ConnectionID
	trace    *recordingTrace
}

type tracingFactory struct {
	mu          sync.Mutex
	invocations []*tracingInvocation
}

func (f *tracingFactory) tracer(
	_ context.Context,
	isClient bool,
	connID qg.ConnectionID,
) qlogwriter.Trace {
	invocation := &tracingInvocation{
		isClient: isClient,
		connID:   connID,
		trace:    &recordingTrace{recorder: &eventRecorder{}},
	}
	f.mu.Lock()
	f.invocations = append(f.invocations, invocation)
	f.mu.Unlock()
	return invocation.trace
}

func (f *tracingFactory) snapshot() []*tracingInvocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*tracingInvocation(nil), f.invocations...)
}

type recordingTrace struct {
	recorder *eventRecorder
}

var _ qlogwriter.Trace = (*recordingTrace)(nil)

func (t *recordingTrace) AddProducer() qlogwriter.Recorder {
	return t.recorder
}

func (*recordingTrace) SupportsSchemas(string) bool { return true }

type eventRecorder struct {
	mu     sync.Mutex
	events []qlogwriter.Event
}

var _ qlogwriter.Recorder = (*eventRecorder)(nil)

func (r *eventRecorder) RecordEvent(event qlogwriter.Event) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (*eventRecorder) Close() error { return nil }

func (r *eventRecorder) snapshot() []qlogwriter.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]qlogwriter.Event(nil), r.events...)
}

type tracingAcceptResult struct {
	path *PathConn
	err  error
}

func TestDialAndListenerTracerInvokedOncePerConnection(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	clientTraces := &tracingFactory{}
	serverTraces := &tracingFactory{}
	listener, err := ListenWithTracer("127.0.0.1:0", serverTLS, serverTraces.tracer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	dialer := &Transport{ClientTLS: clientTLS, Tracer: clientTraces.tracer}

	const connectionCount = 2
	for index := 0; index < connectionCount; index++ {
		accepted := make(chan tracingAcceptResult, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path, acceptErr := listener.Accept(ctx)
			accepted <- tracingAcceptResult{path: path, err: acceptErr}
		}()

		path, dialErr := dialer.DialPath(
			context.Background(),
			transport.PathSpec{Address: listener.Addr().String()},
		)
		if dialErr != nil {
			t.Fatalf("dial connection %d: %v", index, dialErr)
		}
		client := path.(*PathConn)
		payload := []byte(fmt.Sprintf("trace connection %d", index))
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write connection %d: %v", index, err)
		}
		result := <-accepted
		if result.err != nil {
			t.Fatalf("accept connection %d: %v", index, result.err)
		}
		assertPathRead(t, result.path, payload)
		if err := client.Close(); err != nil {
			t.Fatalf("close client connection %d: %v", index, err)
		}
		if err := result.path.Close(); err != nil {
			t.Fatalf("close server connection %d: %v", index, err)
		}
		assertOneTraceInvocationPerConnection(t, clientTraces, index+1, true)
		assertOneTraceInvocationPerConnection(t, serverTraces, index+1, false)
		clientInvocation := clientTraces.snapshot()[index]
		serverInvocation := serverTraces.snapshot()[index]
		if clientInvocation.connID.String() != serverInvocation.connID.String() {
			t.Fatalf(
				"connection %d trace IDs differ: client=%s listener=%s",
				index, clientInvocation.connID, serverInvocation.connID,
			)
		}
	}
}

func TestCIDRebindPathValidationStaysInConnectionTrace(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	clientTraces := &tracingFactory{}
	serverTraces := &tracingFactory{}
	listener, err := ListenWithTracer("127.0.0.1:0", serverTLS, serverTraces.tracer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var (
		client             *PathConn
		server             *PathConn
		candidateTransport *qg.Transport
		candidateSocket    interface{ Close() error }
	)
	t.Cleanup(func() {
		if client != nil {
			_ = client.Close()
		}
		if server != nil {
			_ = server.Close()
		}
		if candidateTransport != nil {
			_ = candidateTransport.Close()
		}
		if candidateSocket != nil {
			_ = candidateSocket.Close()
		}
	})

	accepted := make(chan tracingAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		path, acceptErr := listener.Accept(ctx)
		accepted <- tracingAcceptResult{path: path, err: acceptErr}
	}()
	path, err := (&Transport{
		ClientTLS: clientTLS,
		Tracer:    clientTraces.tracer,
	}).DialPath(context.Background(), transport.PathSpec{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	client = path.(*PathConn)
	if _, err := client.Write([]byte("before traced migration")); err != nil {
		t.Fatal(err)
	}
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	server = result.path
	assertPathRead(t, server, []byte("before traced migration"))

	clientBefore := requireSingleTraceInvocation(t, clientTraces, true)
	serverBefore := requireSingleTraceInvocation(t, serverTraces, false)
	beforeStreamCIDs := streamPacketConnectionIDs(clientBefore.trace.recorder.snapshot())
	if len(beforeStreamCIDs) == 0 {
		t.Fatal("client trace lacks pre-migration STREAM packet CID")
	}
	preMigrationCID := beforeStreamCIDs[len(beforeStreamCIDs)-1]
	preMigrationEventCount := len(clientBefore.trace.recorder.snapshot())
	connectionBefore := client.conn
	localBefore := client.LocalAddr()
	socket, err := udpSocketWithBuffers(context.Background(), &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	candidateSocket = socket
	candidateTransport = &qg.Transport{Conn: socket.PacketConn()}
	if localCandidate := candidateTransport.Conn.LocalAddr().String(); localCandidate == localBefore {
		t.Fatalf("candidate path reused active UDP tuple %s", localCandidate)
	}
	candidate, err := connectionBefore.AddPath(candidateTransport)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 5*time.Second)
	err = candidate.Probe(probeCtx)
	cancelProbe()
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if err := candidate.Switch(); err != nil {
		t.Fatalf("Switch: %v", err)
	}
	if client.conn != connectionBefore {
		t.Fatal("CID rebind replaced the traced quic-go connection")
	}
	assertPathTransfer(t, client, server, []byte("after traced migration"))

	clientAfter := requireSingleTraceInvocation(t, clientTraces, true)
	serverAfter := requireSingleTraceInvocation(t, serverTraces, false)
	if clientAfter != clientBefore || serverAfter != serverBefore {
		t.Fatal("CID rebind replaced a connection trace")
	}
	clientEvents := clientBefore.trace.recorder.snapshot()
	if preMigrationEventCount > len(clientEvents) {
		t.Fatal("client trace shrank during CID migration")
	}
	afterStreamCIDs := streamPacketConnectionIDs(clientEvents[preMigrationEventCount:])
	if len(afterStreamCIDs) == 0 {
		t.Fatal("client trace lacks post-migration STREAM packet CID")
	}
	for _, cid := range afterStreamCIDs {
		if cid == preMigrationCID {
			t.Fatalf("post-migration STREAM reused pre-migration destination CID %s", cid)
		}
	}
	assertPathValidationFrames(t, clientBefore.trace.recorder.snapshot(), true)
	assertPathValidationFrames(t, serverBefore.trace.recorder.snapshot(), false)
}

func streamPacketConnectionIDs(events []qlogwriter.Event) []string {
	var ids []string
	for _, event := range events {
		var packet *qlog.PacketSent
		switch value := event.(type) {
		case qlog.PacketSent:
			packet = &value
		case *qlog.PacketSent:
			packet = value
		default:
			continue
		}
		for _, frame := range packet.Frames {
			if _, ok := frame.Frame.(*qlog.StreamFrame); ok {
				ids = append(ids, packet.Header.DestConnectionID.String())
				break
			}
		}
	}
	return ids
}

func assertOneTraceInvocationPerConnection(
	t *testing.T,
	factory *tracingFactory,
	want int,
	wantClient bool,
) {
	t.Helper()
	invocations := factory.snapshot()
	if len(invocations) != want {
		t.Fatalf("tracer invocations=%d want=%d", len(invocations), want)
	}
	for _, invocation := range invocations {
		if invocation.isClient != wantClient {
			t.Fatalf("tracer isClient=%v want=%v", invocation.isClient, wantClient)
		}
		if invocation.connID.Len() == 0 {
			t.Fatal("tracer received an empty original destination connection ID")
		}
	}
}

func requireSingleTraceInvocation(
	t *testing.T,
	factory *tracingFactory,
	wantClient bool,
) *tracingInvocation {
	t.Helper()
	assertOneTraceInvocationPerConnection(t, factory, 1, wantClient)
	return factory.snapshot()[0]
}

type pathValidationFrames struct {
	sentChallenges     map[[8]byte]struct{}
	receivedChallenges map[[8]byte]struct{}
	sentResponses      map[[8]byte]struct{}
	receivedResponses  map[[8]byte]struct{}
}

func assertPathValidationFrames(t *testing.T, events []qlogwriter.Event, client bool) {
	t.Helper()
	frames := pathValidationFrames{
		sentChallenges:     make(map[[8]byte]struct{}),
		receivedChallenges: make(map[[8]byte]struct{}),
		sentResponses:      make(map[[8]byte]struct{}),
		receivedResponses:  make(map[[8]byte]struct{}),
	}
	for _, event := range events {
		switch event := event.(type) {
		case qlog.PacketSent:
			frames.add(event.Frames, true)
		case qlog.PacketReceived:
			frames.add(event.Frames, false)
		case *qlog.PacketSent:
			frames.add(event.Frames, true)
		case *qlog.PacketReceived:
			frames.add(event.Frames, false)
		}
	}
	if client {
		if !matchingPathValidationToken(frames.sentChallenges, frames.receivedResponses) {
			t.Fatalf("client trace lacks a matching sent PATH_CHALLENGE and received PATH_RESPONSE: %+v", frames)
		}
		return
	}
	if !matchingPathValidationToken(frames.receivedChallenges, frames.sentResponses) {
		t.Fatalf("listener trace lacks a matching received PATH_CHALLENGE and sent PATH_RESPONSE: %+v", frames)
	}
}

func (f *pathValidationFrames) add(frames []qlog.Frame, sent bool) {
	for _, frame := range frames {
		switch frame := frame.Frame.(type) {
		case *qlog.PathChallengeFrame:
			if sent {
				f.sentChallenges[frame.Data] = struct{}{}
			} else {
				f.receivedChallenges[frame.Data] = struct{}{}
			}
		case *qlog.PathResponseFrame:
			if sent {
				f.sentResponses[frame.Data] = struct{}{}
			} else {
				f.receivedResponses[frame.Data] = struct{}{}
			}
		}
	}
}

func matchingPathValidationToken(first, second map[[8]byte]struct{}) bool {
	for token := range first {
		if _, ok := second[token]; ok {
			return true
		}
	}
	return false
}
