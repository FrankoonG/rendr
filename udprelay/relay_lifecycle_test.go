package udprelay

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

func TestRelayReadFailuresTerminateBothDirections(t *testing.T) {
	tests := []struct {
		name      string
		direction string
		trigger   func(*lifecyclePacketConn, *lifecyclePacketConn, error)
	}{
		{
			name:      "UDP socket",
			direction: "UDP to rendr read UDP",
			trigger: func(udp, _ *lifecyclePacketConn, failure error) {
				udp.reads <- lifecycleRead{err: failure}
			},
		},
		{
			name:      "carrier",
			direction: "rendr to UDP read carrier",
			trigger: func(_, carrier *lifecyclePacketConn, failure error) {
				carrier.reads <- lifecycleRead{err: failure}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			udp := newLifecyclePacketConn()
			carrier := newLifecyclePacketConn()
			failure := errors.New("injected " + tt.name + " read failure")
			tt.trigger(udp, carrier, failure)

			r := startRelay(context.Background(), asRendrPacketConn(carrier), udp, lifecycleAddr("target"), 64)
			waitRelayDone(t, r)
			assertRelayFailure(t, r, failure, tt.direction)
			assertClosedOnce(t, udp, carrier)
		})
	}
}

func TestRelayWriteFailuresTerminateBothDirections(t *testing.T) {
	tests := []struct {
		name      string
		direction string
		want      error
		configure func(*lifecyclePacketConn, *lifecyclePacketConn, error)
	}{
		{
			name:      "carrier error",
			direction: "UDP to rendr write carrier",
			configure: func(udp, carrier *lifecyclePacketConn, failure error) {
				udp.reads <- lifecycleRead{payload: []byte("request"), addr: lifecycleAddr("peer")}
				carrier.writeFn = func([]byte, net.Addr) (int, error) { return 0, failure }
			},
		},
		{
			name:      "UDP error",
			direction: "rendr to UDP write UDP",
			configure: func(udp, carrier *lifecyclePacketConn, failure error) {
				carrier.reads <- lifecycleRead{payload: []byte("reply")}
				udp.writeFn = func([]byte, net.Addr) (int, error) { return 0, failure }
			},
		},
		{
			name:      "short carrier write",
			direction: "UDP to rendr write carrier",
			want:      io.ErrShortWrite,
			configure: func(udp, carrier *lifecyclePacketConn, _ error) {
				udp.reads <- lifecycleRead{payload: []byte("request"), addr: lifecycleAddr("peer")}
				carrier.writeFn = func(p []byte, _ net.Addr) (int, error) { return len(p) - 1, nil }
			},
		},
		{
			name:      "short UDP write",
			direction: "rendr to UDP write UDP",
			want:      io.ErrShortWrite,
			configure: func(udp, carrier *lifecyclePacketConn, _ error) {
				carrier.reads <- lifecycleRead{payload: []byte("reply")}
				udp.writeFn = func(p []byte, _ net.Addr) (int, error) { return len(p) - 1, nil }
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			udp := newLifecyclePacketConn()
			carrier := newLifecyclePacketConn()
			failure := errors.New("injected " + tt.name)
			tt.configure(udp, carrier, failure)

			r := startRelay(context.Background(), asRendrPacketConn(carrier), udp, lifecycleAddr("target"), 64)
			waitRelayDone(t, r)
			want := tt.want
			if want == nil {
				want = failure
			}
			assertRelayFailure(t, r, want, tt.direction)
			assertClosedOnce(t, udp, carrier)
		})
	}
}

func TestRelayRejectsTruncatedDatagramsWithoutForwarding(t *testing.T) {
	t.Run("loopback UDP to rendr", func(t *testing.T) {
		carrier := newLifecyclePacketConn()
		r, err := Start(context.Background(), Config{
			PacketConn: asRendrPacketConn(carrier),
			LocalAddr:  "127.0.0.1:0",
			BufferSize: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		app, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close()
		if _, err := app.WriteTo([]byte("123456"), r.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		waitRelayDone(t, r)
		assertRelayFailure(t, r, io.ErrShortBuffer, "UDP to rendr read UDP")
		if got := carrier.writeCalls.Load(); got != 0 {
			t.Fatalf("carrier writes = %d, want 0 for truncated payload", got)
		}
	})

	t.Run("rendr to UDP", func(t *testing.T) {
		udp := newLifecyclePacketConn()
		carrier := newLifecyclePacketConn()
		carrier.reads <- lifecycleRead{payload: []byte("123456")}

		r := startRelay(context.Background(), asRendrPacketConn(carrier), udp, lifecycleAddr("target"), 4)
		waitRelayDone(t, r)
		assertRelayFailure(t, r, io.ErrShortBuffer, "rendr to UDP read carrier")
		if got := udp.writeCalls.Load(); got != 0 {
			t.Fatalf("UDP writes = %d, want 0 for truncated payload", got)
		}
	})
}

func TestRelayOversizedRendrPacketTerminates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln := newPacketSessionListener(t, "udpflow")
	defer ln.Close()
	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		pc, err := ln.AcceptPacket(ctx)
		if err == nil {
			accepted <- pc
		}
	}()

	client, err := newRuntime(t).DialPacket(ctx, rendr.SessionConfig{Root: packetSelector(ln.Addr().String())})
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()

	r, err := Start(ctx, Config{PacketConn: client})
	if err != nil {
		t.Fatal(err)
	}
	app, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	payload := make([]byte, 33<<10)
	if n, err := app.WriteTo(payload, r.LocalAddr()); err != nil || n != len(payload) {
		t.Fatalf("write oversized datagram = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	waitRelayDone(t, r)
	assertRelayFailure(t, r, rendr.ErrPacketTooLarge, "UDP to rendr write carrier")
}

func TestRelayCleanCloseHasNoTerminalCause(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		udp := newLifecyclePacketConn()
		carrier := newLifecyclePacketConn()
		r := startRelay(context.Background(), asRendrPacketConn(carrier), udp, nil, 64)

		if err := r.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		waitRelayDone(t, r)
		if err := r.Err(); err != nil {
			t.Fatalf("Err after explicit Close = %v, want nil", err)
		}
		assertClosedOnce(t, udp, carrier)
	})

	t.Run("context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		udp := newLifecyclePacketConn()
		carrier := newLifecyclePacketConn()
		r := startRelay(ctx, asRendrPacketConn(carrier), udp, nil, 64)

		cancel()
		waitRelayDone(t, r)
		if err := r.Err(); err != nil {
			t.Fatalf("Err after context cancellation = %v, want nil", err)
		}
		assertClosedOnce(t, udp, carrier)
	})
}

func TestRelayFirstTerminalCauseIsStableDuringConcurrentFailures(t *testing.T) {
	udp := newLifecyclePacketConn()
	carrier := newLifecyclePacketConn()
	firstFailure := errors.New("first carrier read failure")
	secondFailure := errors.New("second carrier write failure")
	allowFirst := make(chan struct{})
	allowSecond := make(chan struct{})
	writeEntered := make(chan struct{})
	closeEntered := make(chan struct{})
	allowClose := make(chan struct{})
	carrier.readFn = func([]byte) (int, net.Addr, error) {
		<-allowFirst
		return 0, nil, firstFailure
	}
	carrier.writeFn = func([]byte, net.Addr) (int, error) {
		close(writeEntered)
		<-allowSecond
		return 0, secondFailure
	}
	carrier.closeFn = func() error {
		close(closeEntered)
		<-allowClose
		return nil
	}
	udp.reads <- lifecycleRead{payload: []byte("race"), addr: lifecycleAddr("peer")}

	r := startRelay(context.Background(), asRendrPacketConn(carrier), udp, nil, 64)
	waitSignal(t, writeEntered, "carrier write entry")
	close(allowFirst)
	waitSignal(t, closeEntered, "carrier close entry")
	close(allowSecond)
	close(allowClose)
	waitRelayDone(t, r)

	first := r.Err()
	if !errors.Is(first, firstFailure) {
		t.Fatalf("Err = %v, want first failure %v", first, firstFailure)
	}
	if errors.Is(first, secondFailure) {
		t.Fatalf("Err = %v, unexpectedly includes losing failure %v", first, secondFailure)
	}
	for i := 0; i < 100; i++ {
		if got := r.Err(); got != first {
			t.Fatalf("Err call %d returned unstable cause %v; first was %v", i, got, first)
		}
		_ = r.Close()
	}
	assertClosedOnce(t, udp, carrier)
}

func TestRelayConcurrentCloseWaitsForShutdownCompletion(t *testing.T) {
	udp := newLifecyclePacketConn()
	carrier := newLifecyclePacketConn()
	failure := errors.New("carrier read failed")
	closeEntered := make(chan struct{})
	allowClose := make(chan struct{})
	carrier.closeFn = func() error {
		close(closeEntered)
		<-allowClose
		return nil
	}
	carrier.reads <- lifecycleRead{err: failure}
	r := startRelay(context.Background(), asRendrPacketConn(carrier), udp, lifecycleAddr("target"), 64)
	waitSignal(t, closeEntered, "carrier close entry")

	closeDone := make(chan error, 1)
	go func() { closeDone <- r.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("concurrent Close returned before shutdown completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowClose)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("concurrent Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Close did not return after shutdown completed")
	}
	waitRelayDone(t, r)
	assertRelayFailure(t, r, failure, "rendr to UDP read carrier")
	assertClosedOnce(t, udp, carrier)
}

func TestServerRemovesFailedRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	acceptor := newLifecycleAcceptor()
	carrier := newLifecyclePacketConn()
	failRead := make(chan struct{})
	carrier.readFn = func([]byte) (int, net.Addr, error) {
		<-failRead
		return 0, nil, errors.New("carrier died")
	}
	acceptor.accepts <- asRendrPacketConn(carrier)

	server, err := Listen(ctx, ServeConfig{
		Listener:   acceptor,
		LocalAddr:  "127.0.0.1:0",
		TargetAddr: "127.0.0.1:9",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	waitServerRelayCount(t, server, 1)

	close(failRead)
	waitServerRelayCount(t, server, 0)
	if got := carrier.closeCalls.Load(); got != 1 {
		t.Fatalf("carrier closes = %d, want 1", got)
	}
	select {
	case <-server.done:
		t.Fatal("one relay failure stopped the accepting server")
	default:
	}
}

func TestRelayRepeatedFailureAndCloseRemainBounded(t *testing.T) {
	before := runtime.NumGoroutine()
	const iterations = 128
	for i := 0; i < iterations; i++ {
		udp := newLifecyclePacketConn()
		carrier := newLifecyclePacketConn()
		carrier.reads <- lifecycleRead{err: errors.New("carrier failure")}
		r := startRelay(context.Background(), asRendrPacketConn(carrier), udp, lifecycleAddr("target"), 64)
		waitRelayDone(t, r)
		for closeCall := 0; closeCall < 8; closeCall++ {
			_ = r.Close()
		}
		assertClosedOnce(t, udp, carrier)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if got := runtime.NumGoroutine(); got <= before+4 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("goroutines after repeated failure = %d, baseline = %d", runtime.NumGoroutine(), before)
}

type lifecycleAddr string

func (a lifecycleAddr) Network() string { return "udp" }
func (a lifecycleAddr) String() string  { return string(a) }

type lifecycleRead struct {
	payload []byte
	addr    net.Addr
	err     error
}

type lifecyclePacketConn struct {
	reads chan lifecycleRead

	readFn  func([]byte) (int, net.Addr, error)
	writeFn func([]byte, net.Addr) (int, error)
	closeFn func() error

	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls atomic.Int32
	writeCalls atomic.Int32
}

func newLifecyclePacketConn() *lifecyclePacketConn {
	return &lifecyclePacketConn{
		reads:  make(chan lifecycleRead, 1),
		closed: make(chan struct{}),
	}
}

func (c *lifecyclePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readFn != nil {
		return c.readFn(p)
	}
	select {
	case read := <-c.reads:
		n := copy(p, read.payload)
		if n != len(read.payload) && read.err == nil {
			return n, read.addr, io.ErrShortBuffer
		}
		return n, read.addr, read.err
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *lifecyclePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeCalls.Add(1)
	if c.writeFn != nil {
		return c.writeFn(p, addr)
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *lifecyclePacketConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	if c.closeFn != nil {
		return c.closeFn()
	}
	return nil
}

func (c *lifecyclePacketConn) LocalAddr() net.Addr              { return lifecycleAddr("local") }
func (c *lifecyclePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *lifecyclePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *lifecyclePacketConn) SetWriteDeadline(time.Time) error { return nil }

type lifecycleRendrPacketConn struct {
	*lifecyclePacketConn
}

func asRendrPacketConn(pc *lifecyclePacketConn) rendr.PacketConn {
	return &lifecycleRendrPacketConn{lifecyclePacketConn: pc}
}

func (*lifecycleRendrPacketConn) Paths() []rendr.PathInfo { return nil }
func (*lifecycleRendrPacketConn) FlowID() [16]byte        { return [16]byte{} }
func (*lifecycleRendrPacketConn) Status() rendr.Status    { return rendr.Status{} }

type lifecycleAcceptor struct {
	accepts   chan rendr.PacketConn
	closed    chan struct{}
	closeOnce sync.Once
}

func newLifecycleAcceptor() *lifecycleAcceptor {
	return &lifecycleAcceptor{
		accepts: make(chan rendr.PacketConn, 1),
		closed:  make(chan struct{}),
	}
}

func (a *lifecycleAcceptor) AcceptPacket(ctx context.Context) (rendr.PacketConn, error) {
	select {
	case pc := <-a.accepts:
		return pc, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.closed:
		return nil, net.ErrClosed
	}
}

func (a *lifecycleAcceptor) Close() error {
	a.closeOnce.Do(func() { close(a.closed) })
	return nil
}

func waitRelayDone(t *testing.T, r *Relay) {
	t.Helper()
	select {
	case <-r.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not stop")
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func assertRelayFailure(t *testing.T, r *Relay, want error, operation string) {
	t.Helper()
	got := r.Err()
	if !errors.Is(got, want) {
		t.Fatalf("Err = %v, want cause %v", got, want)
	}
	if !strings.Contains(got.Error(), operation) {
		t.Fatalf("Err = %q, want operation %q", got, operation)
	}
}

func assertClosedOnce(t *testing.T, conns ...*lifecyclePacketConn) {
	t.Helper()
	for i, conn := range conns {
		if got := conn.closeCalls.Load(); got != 1 {
			t.Fatalf("connection %d close calls = %d, want 1", i, got)
		}
		select {
		case <-conn.closed:
		default:
			t.Fatalf("connection %d was not closed", i)
		}
	}
}

func waitServerRelayCount(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := server.Relays(); got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("server relays = %d, want %d", server.Relays(), want)
}
