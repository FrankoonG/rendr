package rendr

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
	transporttcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeFramedSourceAcceptsStreamAndPacketSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "framed-pipe", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterStreamFactory("framed-pipe", StreamFactory{
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
	root := Path("framed", PathSpec{Transport: "framed-pipe", Address: "peer"})

	streamClient, err := clientRuntime.Dial(ctx, SessionConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer streamClient.Close()
	streamServer, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer streamServer.Close()
	assertFramedStreamRoundTrip(t, streamClient, streamServer, []byte("framed-stream"))

	packetClient, err := clientRuntime.DialPacket(ctx, SessionConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer packetClient.Close()
	packetServer, err := listener.AcceptPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packetServer.Close()
	assertFramedPacketRoundTrip(t, packetClient, packetServer, []byte("framed-packet"))
}

func TestRuntimeListenerValidatesFramedSources(t *testing.T) {
	var typedNil *framedPipeListener
	shared := newFramedPipeListener()
	tests := []struct {
		name    string
		sources []FramedSource
		want    string
	}{
		{name: "empty name", sources: []FramedSource{{Listener: newFramedPipeListener()}}, want: "empty name"},
		{name: "invalid carrier", sources: []FramedSource{{Name: "bad", Carrier: CarrierFamily(255), Listener: newFramedPipeListener()}}, want: "invalid carrier"},
		{name: "invalid session kind", sources: []FramedSource{{Name: "bad-kind", Listener: &framedPipeListener{
			paths: make(chan transport.PathConn), closed: make(chan struct{}), kind: transport.PathSessionKind(255),
		}}}, want: "invalid session kind"},
		{name: "typed nil", sources: []FramedSource{{Name: "nil", Listener: typedNil}}, want: "nil Listener"},
		{name: "duplicate name", sources: []FramedSource{
			{Name: "same", Listener: newFramedPipeListener()},
			{Name: "same", Listener: newFramedPipeListener()},
		}, want: "duplicate inbound source"},
		{name: "shared listener", sources: []FramedSource{
			{Name: "first", Listener: shared},
			{Name: "second", Listener: shared},
		}, want: "share one network object"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, err := NewRuntime(RuntimeConfig{})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := runtime.Listen(ListenConfig{Framed: test.sources})
			if listener != nil {
				_ = listener.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Listen error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestRuntimeFramedSourceRejectsIncompatibleSessionKind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	paths.kind = transport.PathSessionPacket
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "packet-only", Carrier: CarrierUDP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterStreamFactory("packet-only", StreamFactory{
		Carrier: CarrierUDP,
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
	root := Path("packet-only", PathSpec{Transport: "packet-only", Address: "peer"})
	if conn, err := clientRuntime.Dial(ctx, SessionConfig{Root: root}); err == nil {
		_ = conn.Close()
		t.Fatal("stream session unexpectedly used packet-only FramedSource")
	}

	packetClient, err := clientRuntime.DialPacket(ctx, SessionConfig{Root: root})
	if err != nil {
		t.Fatalf("packet session after rejected stream: %v", err)
	}
	defer packetClient.Close()
	packetServer, err := listener.AcceptPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packetServer.Close()
	assertFramedPacketRoundTrip(t, packetClient, packetServer, []byte("packet-only"))
}

func TestRuntimeFramedSourceRejectsIncompatibleBridge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	initial := newFramedPipeListener()
	packetOnly := newFramedPipeListener()
	packetOnly.kind = transport.PathSessionPacket
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{
		{Name: "initial", Carrier: CarrierTCP, Listener: initial},
		{Name: "packet-only", Carrier: CarrierUDP, Listener: packetOnly},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	registerFramedPipeFactory(t, clientRuntime, "initial", CarrierTCP, initial)
	registerFramedPipeFactory(t, clientRuntime, "packet-only", CarrierUDP, packetOnly)
	client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Selector("root", []Target{
		Path("initial", PathSpec{Transport: "initial", Address: "peer"}),
		Path("packet-only", PathSpec{Transport: "packet-only", Address: "peer"}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if got := len(client.Paths()); got != 1 {
		t.Fatalf("client attached paths = %d, want 1", got)
	}
	if got := len(server.Paths()); got != 1 {
		t.Fatalf("server attached paths = %d, want 1", got)
	}
	assertFramedStreamRoundTrip(t, client, server, []byte("bridge-rejected"))
}

func registerFramedPipeFactory(t *testing.T, runtime *Runtime, name string, carrier CarrierFamily, paths *framedPipeListener) {
	t.Helper()
	if err := runtime.RegisterStreamFactory(name, StreamFactory{
		Carrier: carrier,
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
}

func TestPathHandshakeDeadlineClosesOrCancels(t *testing.T) {
	t.Run("timeout closes path", func(t *testing.T) {
		pathConn, peer := net.Pipe()
		defer peer.Close()
		path := transporttcp.Wrap(pathConn)
		clear := armPathHandshakeDeadlineAfter(path, 10*time.Millisecond)
		defer clear()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("peer read succeeded after handshake deadline")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("handshake deadline did not close path")
		}
	})

	t.Run("clear cancels timeout", func(t *testing.T) {
		pathConn, peer := net.Pipe()
		defer peer.Close()
		path := transporttcp.Wrap(pathConn)
		clear := armPathHandshakeDeadlineAfter(path, 10*time.Millisecond)
		clear()
		clear()
		if err := peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("peer read unexpectedly succeeded")
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("cleared deadline closed path: %v", err)
		}
		_ = path.Close()
	})
}

func assertFramedStreamRoundTrip(t *testing.T, client, server Conn, payload []byte) {
	t.Helper()
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeErr <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("server payload = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := server.Write(payload)
		writeErr <- err
	}()
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("client payload = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func assertFramedPacketRoundTrip(t *testing.T, client, server PacketConn, payload []byte) {
	t.Helper()
	if _, err := client.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload)+16)
	n, _, err := server.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("server packet = %q, want %q", got[:n], payload)
	}
	if _, err := server.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("client packet = %q, want %q", got[:n], payload)
	}
}

type framedPipeListener struct {
	paths  chan transport.PathConn
	closed chan struct{}
	kind   transport.PathSessionKind
	once   sync.Once
}

func newFramedPipeListener() *framedPipeListener {
	return &framedPipeListener{
		paths:  make(chan transport.PathConn),
		closed: make(chan struct{}),
		kind:   transport.PathSessionAny,
	}
}

func (l *framedPipeListener) SessionKind() transport.PathSessionKind { return l.kind }

func (l *framedPipeListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	select {
	case path := <-l.paths:
		return path, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *framedPipeListener) Publish(ctx context.Context, path transport.PathConn) error {
	select {
	case l.paths <- path:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-l.closed:
		return net.ErrClosed
	}
}

func (l *framedPipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *framedPipeListener) Addr() net.Addr { return addrFromString("framed-pipe") }

var _ transport.PathListener = (*framedPipeListener)(nil)
