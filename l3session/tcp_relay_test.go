package l3session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestTCPRelayBridgesEndpointThroughRendrStreamSession(t *testing.T) {
	ln := newTestStreamSessionListener(t, "tcp")
	defer ln.Close()

	accepted := acceptStream(t, ln)
	id := tcpRelayIdentity()
	ev := tcpRelayEvent(id, rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}))
	app, endpoint := newTCPRelayConnPair(t)
	defer app.Close()

	relay := &TCPRelay{}
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(context.Background(), ev, endpoint) }()

	server := <-accepted
	registry, egressApp, egress := startTestTCPPeerRelay(t, server)
	_ = registry
	defer egressApp.Close()
	defer server.Close()
	go func() {
		buf, err := io.ReadAll(egressApp)
		if err != nil {
			t.Errorf("egress read: %v", err)
			return
		}
		if string(buf) != "hello" {
			t.Errorf("server read %q want hello", buf)
			return
		}
		if _, err := egressApp.Write([]byte("world")); err != nil {
			t.Errorf("egress write: %v", err)
			return
		}
		if err := egressApp.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Errorf("egress CloseWrite: %v", err)
		}
	}()

	if _, err := app.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := app.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(app, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("app read %q want world", got)
	}
	if _, err := app.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("app read after response = %v, want EOF", err)
	}
	if got := egress.identity(); got != id {
		t.Fatalf("peer egress identity = %s, want %s", got, id)
	}
	_ = app.Close()
	_ = egressApp.Close()
	waitTestTCPPeerRelay(t, egress.peerDone)
	if _, ok := server.(rendr.StreamHalfCloser); !ok {
		t.Fatal("accepted rendr Conn does not implement StreamHalfCloser")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for relay shutdown")
	}
}

func TestRelayTCPRejectsUnsupportedHalfClose(t *testing.T) {
	leftApp, leftRelay := net.Pipe()
	rightRelay, rightApp := net.Pipe()
	defer leftApp.Close()
	defer rightApp.Close()
	done := make(chan error, 1)
	go func() { done <- relayTCP(context.Background(), leftRelay, rightRelay, 0) }()
	received := make(chan error, 1)
	go func() {
		buf := make([]byte, len("request"))
		_, err := io.ReadFull(rightApp, buf)
		received <- err
	}()
	if _, err := leftApp.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	_ = leftApp.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTCPHalfCloseUnsupported) {
			t.Fatalf("relay error = %v, want ErrTCPHalfCloseUnsupported", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not reject endpoint without CloseWrite")
	}
}

func TestRelayTCPDestinationWriteFailureIsNotCleanEOF(t *testing.T) {
	writeErr := net.ErrClosed
	left := newScriptedRelayConn()
	left.readPayload = []byte("must-not-truncate")
	right := newScriptedRelayConn()
	right.blockRead = true
	right.writeErr = writeErr

	err := relayTCP(context.Background(), left, right, 0)
	if !errors.Is(err, ErrTCPDestinationWriteFailed) || !errors.Is(err, writeErr) {
		t.Fatalf("relay error=%v, want destination write classification wrapping %v", err, writeErr)
	}
	if right.writes != 1 {
		t.Fatalf("destination writes=%d want 1", right.writes)
	}
}

func TestRelayTCPSourceReadFailureIsClassified(t *testing.T) {
	readErr := errors.New("injected source reset")
	left := newScriptedRelayConn()
	left.readErr = readErr
	right := newScriptedRelayConn()
	right.blockRead = true

	err := relayTCP(context.Background(), left, right, 0)
	if !errors.Is(err, ErrTCPSourceReadFailed) || !errors.Is(err, readErr) {
		t.Fatalf("relay error=%v, want source read classification wrapping %v", err, readErr)
	}
}

func TestRelayTCPCloseWriteFailureIsClassified(t *testing.T) {
	closeWriteErr := errors.New("injected FIN propagation failure")
	left := newScriptedRelayConn()
	left.readErr = io.EOF
	right := newScriptedRelayConn()
	right.blockRead = true
	right.closeWriteErr = closeWriteErr

	err := relayTCP(context.Background(), left, right, 0)
	if !errors.Is(err, ErrTCPDestinationCloseWriteFailed) || !errors.Is(err, closeWriteErr) {
		t.Fatalf("relay error=%v, want CloseWrite classification wrapping %v", err, closeWriteErr)
	}
	if right.closeWrites != 1 || right.writes != 0 {
		t.Fatalf("CloseWrite/writes=%d/%d want 1/0", right.closeWrites, right.writes)
	}
}

type scriptedRelayConn struct {
	mu            sync.Mutex
	closed        chan struct{}
	closeOnce     sync.Once
	readPayload   []byte
	readErr       error
	readDone      bool
	blockRead     bool
	writeErr      error
	closeWriteErr error
	writes        int
	closeWrites   int
}

func newScriptedRelayConn() *scriptedRelayConn {
	return &scriptedRelayConn{closed: make(chan struct{})}
}

func (c *scriptedRelayConn) Read(dst []byte) (int, error) {
	c.mu.Lock()
	if c.blockRead {
		closed := c.closed
		c.mu.Unlock()
		<-closed
		return 0, net.ErrClosed
	}
	if !c.readDone {
		c.readDone = true
		n := copy(dst, c.readPayload)
		err := c.readErr
		c.mu.Unlock()
		return n, err
	}
	closed := c.closed
	c.mu.Unlock()
	<-closed
	return 0, net.ErrClosed
}

func (c *scriptedRelayConn) Write(src []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(src), nil
}

func (c *scriptedRelayConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeWrites++
	return c.closeWriteErr
}

func (c *scriptedRelayConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*scriptedRelayConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (*scriptedRelayConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (*scriptedRelayConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedRelayConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedRelayConn) SetWriteDeadline(time.Time) error { return nil }

func TestWriteAllContextCancelsBlockedWrite(t *testing.T) {
	conn := newBlockingRelayConn()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- writeAllContext(ctx, conn, []byte("blocked")) }()
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("write did not block")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("writeAllContext error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt blocked write")
	}
}

type blockingRelayConn struct {
	closed       chan struct{}
	writeStarted chan struct{}
	closeOnce    sync.Once
	writeOnce    sync.Once
}

func newBlockingRelayConn() *blockingRelayConn {
	return &blockingRelayConn{closed: make(chan struct{}), writeStarted: make(chan struct{})}
}

func (c *blockingRelayConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingRelayConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingRelayConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*blockingRelayConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (*blockingRelayConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (*blockingRelayConn) SetDeadline(time.Time) error      { return nil }
func (*blockingRelayConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingRelayConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPRelayPreservesFlowAcrossStreamMigration(t *testing.T) {
	ln := newTestStreamSessionListener(t, "tcp")
	defer ln.Close()

	accepted := acceptStream(t, ln)
	id := tcpRelayIdentity()
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		rendr.Path("tcp-b", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
	})
	app, endpoint := newTCPRelayConnPair(t)
	defer app.Close()

	relay := &TCPRelay{}
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(context.Background(), tcpRelayEvent(id, root), endpoint) }()

	server := <-accepted
	_, egressApp, egress := startTestTCPPeerRelay(t, server)
	defer egressApp.Close()
	defer server.Close()
	oneDone := startEchoStream(t, egressApp, "one", "ack-one")
	writeAndReadStream(t, app, "one", "ack-one")
	waitEcho(t, oneDone, "one")

	sess, ok := relay.manager().Session(id)
	if !ok || sess.Conn == nil {
		t.Fatalf("missing stream session: ok=%v sess=%+v", ok, sess)
	}
	admin := sess.Conn.(streamControl)
	_ = waitForSessionPathAttached(t, admin, "tcp-b", 3*time.Second)
	if err := admin.SelectTarget("root", "tcp-b"); err != nil {
		t.Fatal(err)
	}
	twoDone := startEchoStream(t, egressApp, "two", "ack-two")
	writeAndReadStream(t, app, "two", "ack-two")
	waitEcho(t, twoDone, "two")
	if admin.FlowID() != server.FlowID() {
		t.Fatalf("flow id changed across migration: client=%x server=%x", admin.FlowID(), server.FlowID())
	}

	if got := egress.identity(); got != id {
		t.Fatalf("peer egress identity = %s, want %s", got, id)
	}
	_ = app.Close()
	_ = egressApp.Close()
	waitTestTCPPeerRelay(t, egress.peerDone)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for relay shutdown")
	}
}

func acceptStream(t *testing.T, ln *rendr.SessionListener) <-chan rendr.Conn {
	t.Helper()
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
	return accepted
}

func tcpRelayIdentity() l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func tcpRelayEvent(id l3ingress.L3Identity, root rendr.Target) l3ingress.PacketEvent {
	return l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id},
		Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
		},
		Decided: true,
	}
}

func startEchoStream(t *testing.T, c net.Conn, want, reply string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(c, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != want {
			done <- fmt.Errorf("server read %q want %q", buf, want)
			return
		}
		_, err := c.Write([]byte(reply))
		done <- err
	}()
	return done
}

type testTCPEgress struct {
	mu       sync.Mutex
	conn     l3ingress.TCPConn
	got      l3ingress.L3Identity
	peerDone <-chan error
}

func (e *testTCPEgress) DialTCP(_ context.Context, id l3ingress.L3Identity) (l3ingress.TCPConn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return nil, errors.New("test TCP egress already consumed")
	}
	e.got = id
	conn := e.conn
	e.conn = nil
	return conn, nil
}

func (*testTCPEgress) DialUDP(context.Context, l3ingress.L3Identity) (net.PacketConn, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("unexpected UDP dial")
}

func (e *testTCPEgress) identity() l3ingress.L3Identity {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.got
}

func startTestTCPPeerRelay(t *testing.T, server rendr.Conn) (*l3ingress.EgressRegistry, net.Conn, *testTCPEgress) {
	t.Helper()
	egressApp, egressConn := newTCPRelayConnPair(t)
	registry := l3ingress.NewEgressRegistry()
	egress := &testTCPEgress{conn: egressConn}
	if err := registry.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	egress.peerDone = done
	go func() { done <- (&TCPPeerRelay{Conn: server, Egresses: registry}).Run(context.Background()) }()
	return registry, egressApp, egress
}

func newTCPRelayConnPair(t *testing.T) (l3ingress.TCPConn, l3ingress.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = client.Close()
		_ = listener.Close()
		t.Fatal("timed out accepting TCP test pair")
	}
	_ = listener.Close()
	clientTCP, clientOK := client.(l3ingress.TCPConn)
	serverTCP, serverOK := server.(l3ingress.TCPConn)
	if !clientOK || !serverOK {
		_ = client.Close()
		_ = server.Close()
		t.Fatalf("loopback TCP pair lacks CloseWrite: %T/%T", client, server)
	}
	return clientTCP, serverTCP
}

func waitTestTCPPeerRelay(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for TCP peer relay shutdown")
	}
}

func waitEcho(t *testing.T, done <-chan error, label string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for server echo %q", label)
	}
}

func writeAndReadStream(t *testing.T, c net.Conn, send, want string) {
	t.Helper()
	if _, err := c.Write([]byte(send)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("app read %q want %q", got, want)
	}
}
