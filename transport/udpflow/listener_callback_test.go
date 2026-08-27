package udpflow

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type listenerAbnormalAction uint8

const (
	listenerActionBlock listenerAbnormalAction = iota
	listenerActionPanic
	listenerActionGoexit
	listenerActionReturn
)

type listenerAbnormalPacketConn struct {
	readAction  listenerAbnormalAction
	closeAction listenerAbnormalAction

	readStarted  chan struct{}
	closeStarted chan struct{}
	readRelease  chan struct{}
	closeRelease chan struct{}
	readOnce     sync.Once
	closeOnce    sync.Once
	closeCalls   atomic.Int32
}

func newListenerAbnormalPacketConn() *listenerAbnormalPacketConn {
	return &listenerAbnormalPacketConn{
		readAction:   listenerActionBlock,
		closeAction:  listenerActionReturn,
		readStarted:  make(chan struct{}),
		closeStarted: make(chan struct{}),
		readRelease:  make(chan struct{}),
		closeRelease: make(chan struct{}),
	}
}

func runListenerAbnormalAction(action listenerAbnormalAction, release <-chan struct{}) {
	switch action {
	case listenerActionPanic:
		panic("listener callback panic")
	case listenerActionGoexit:
		runtime.Goexit()
	case listenerActionBlock:
		<-release
	}
}

func (c *listenerAbnormalPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	runListenerAbnormalAction(c.readAction, c.readRelease)
	return 0, nil, net.ErrClosed
}

func (c *listenerAbnormalPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (c *listenerAbnormalPacketConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closeStarted) })
	runListenerAbnormalAction(c.closeAction, c.closeRelease)
	return nil
}

func (c *listenerAbnormalPacketConn) LocalAddr() net.Addr              { return listenerTestAddr("abnormal") }
func (c *listenerAbnormalPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *listenerAbnormalPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *listenerAbnormalPacketConn) SetWriteDeadline(time.Time) error { return nil }

type listenerAbnormalMessageConn struct {
	*listenerAbnormalPacketConn
}

func (c *listenerAbnormalMessageConn) ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	runListenerAbnormalAction(c.readAction, c.readRelease)
	return 0, 0, 0, nil, net.ErrClosed
}

func listenerCallbackError(t *testing.T, err error, callback string, reason ListenerCallbackFailureReason) *ListenerCallbackError {
	t.Helper()
	var callbackErr *ListenerCallbackError
	if !errors.As(err, &callbackErr) || callbackErr.Callback != callback || callbackErr.Reason != reason {
		t.Fatalf("error=%v callback=%+v want %s/%s", err, callbackErr, callback, reason)
	}
	return callbackErr
}

func waitListenerSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestListenerPacketConnPanicSubprocess(t *testing.T) {
	if operation := os.Getenv("RENDR_UDPFLOW_LISTENER_PANIC"); operation != "" {
		conn := newListenerAbnormalPacketConn()
		var packetConn net.PacketConn = conn
		switch operation {
		case "ReadFrom":
			conn.readAction = listenerActionPanic
		case "ReadMsgUDP":
			conn.readAction = listenerActionPanic
			packetConn = &listenerAbnormalMessageConn{listenerAbnormalPacketConn: conn}
		case "Close":
			conn.closeAction = listenerActionPanic
		default:
			t.Fatalf("unknown helper operation %q", operation)
		}
		listener, err := NewListenerFromPacketConn(packetConn, MaxDatagram)
		if err != nil {
			t.Fatal(err)
		}
		if operation == "Close" {
			waitListenerSignal(t, conn.readStarted, "ReadFrom entry")
			err = listener.Close()
			listenerCallbackError(t, err, "PacketConn.Close", ListenerCallbackFailurePanic)
			close(conn.readRelease)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err = listener.Accept(ctx)
		if !errors.Is(err, ErrListenerRead) {
			t.Fatalf("Accept error=%v does not contain ErrListenerRead", err)
		}
		listenerCallbackError(t, err, "PacketConn."+operation, ListenerCallbackFailurePanic)
		return
	}

	for _, operation := range []string{"ReadFrom", "ReadMsgUDP", "Close"} {
		t.Run(operation, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestListenerPacketConnPanicSubprocess$")
			command.Env = append(os.Environ(), "RENDR_UDPFLOW_LISTENER_PANIC="+operation)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("panic helper crashed for %s: %v\n%s", operation, err, output)
			}
		})
	}
}

func TestListenerPacketConnGoexitPublishesStableErrors(t *testing.T) {
	for _, operation := range []string{"ReadFrom", "ReadMsgUDP", "Close"} {
		t.Run(operation, func(t *testing.T) {
			conn := newListenerAbnormalPacketConn()
			var packetConn net.PacketConn = conn
			if operation == "Close" {
				conn.closeAction = listenerActionGoexit
			} else {
				conn.readAction = listenerActionGoexit
				if operation == "ReadMsgUDP" {
					packetConn = &listenerAbnormalMessageConn{listenerAbnormalPacketConn: conn}
				}
			}
			listener, err := NewListenerFromPacketConn(packetConn, MaxDatagram)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "Close" {
				waitListenerSignal(t, conn.readStarted, "ReadFrom entry")
				first := listener.Close()
				listenerCallbackError(t, first, "PacketConn.Close", ListenerCallbackFailureGoexit)
				second := listener.Close()
				if first != second {
					t.Fatalf("Close error identity changed: first=%p second=%p", first, second)
				}
				_, acceptErr := listener.Accept(context.Background())
				if !errors.Is(acceptErr, net.ErrClosed) {
					t.Fatalf("Accept error=%v want stable net.ErrClosed", acceptErr)
				}
				close(conn.readRelease)
				return
			}
			_, first := listener.Accept(context.Background())
			if !errors.Is(first, ErrListenerRead) {
				t.Fatalf("Accept error=%v does not contain ErrListenerRead", first)
			}
			listenerCallbackError(t, first, "PacketConn."+operation, ListenerCallbackFailureGoexit)
			_, second := listener.Accept(context.Background())
			if first != second {
				t.Fatalf("Accept error identity changed: first=%p second=%p", first, second)
			}
		})
	}
}

func TestListenerBlockedReadCallbacksAreProcessBoundedAndRecover(t *testing.T) {
	const limit = 4
	executor := newListenerCallbackExecutor(limit)
	listeners := make([]*Listener, 0, limit)
	connections := make([]*listenerAbnormalPacketConn, 0, limit)
	for index := 0; index < limit; index++ {
		conn := newListenerAbnormalPacketConn()
		listener, err := newListenerFromPacketConnWithExecutor(conn, MaxDatagram, executor)
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		connections = append(connections, conn)
		waitListenerSignal(t, conn.readStarted, "blocked ReadFrom entry")
	}

	for index := 0; index < 16; index++ {
		conn := newListenerAbnormalPacketConn()
		listener, err := newListenerFromPacketConnWithExecutor(conn, MaxDatagram, executor)
		if err != nil {
			t.Fatal(err)
		}
		_, acceptErr := listener.Accept(context.Background())
		if !errors.Is(acceptErr, ErrListenerRead) {
			t.Fatalf("overflow Accept %d error=%v", index, acceptErr)
		}
		listenerCallbackError(t, acceptErr, "PacketConn.ReadFrom", ListenerCallbackFailureSaturated)
		select {
		case <-conn.readStarted:
			t.Fatalf("overflow ReadFrom %d was invoked", index)
		default:
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("overflow Close %d: %v", index, err)
		}
	}
	if got := len(executor.slots[listenerCallbackRead]); got != limit {
		t.Fatalf("retained read callbacks=%d want %d", got, limit)
	}

	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(executor.slots[listenerCallbackRead]); got != limit {
		t.Fatalf("Close pretended blocked reads returned: retained=%d want %d", got, limit)
	}
	for _, conn := range connections {
		close(conn.readRelease)
	}
	listenerEventually(t, func() bool {
		return len(executor.slots[listenerCallbackRead]) == 0
	}, "read callback permits did not recover")

	conn := newListenerMemoryPacketConn()
	listener, err := newListenerFromPacketConnWithExecutor(conn, MaxDatagram, executor)
	if err != nil {
		t.Fatal(err)
	}
	flowID := listenerFlowID(8801)
	if err := conn.inject(listenerDatagram(t, flowID, []byte("recovered")), listenerTestAddr("peer")); err != nil {
		t.Fatal(err)
	}
	path := listenerAccept(t, listener)
	if got := string(listenerRead(t, path)); got != "recovered" {
		t.Fatalf("recovered payload=%q", got)
	}
	_ = listener.Close()
	_ = path.Close()
}

func TestListenerBlockedCloseCallbacksAreProcessBoundedAndStable(t *testing.T) {
	const limit = 3
	executor := newListenerCallbackExecutor(limit)
	connections := make([]*listenerAbnormalPacketConn, 0, limit+1)
	results := make(chan error, limit)
	for index := 0; index < limit; index++ {
		conn := newListenerAbnormalPacketConn()
		conn.closeAction = listenerActionBlock
		listener, err := newListenerFromPacketConnWithExecutor(conn, MaxDatagram, executor)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		waitListenerSignal(t, conn.readStarted, "blocked ReadFrom entry")
		go func() { results <- listener.Close() }()
		waitListenerSignal(t, conn.closeStarted, "blocked Close entry")
	}
	for index := 0; index < limit; index++ {
		listenerCallbackError(t, <-results, "PacketConn.Close", ListenerCallbackFailureTimeout)
	}
	if got := len(executor.slots[listenerCallbackClose]); got != limit {
		t.Fatalf("retained close callbacks=%d want %d", got, limit)
	}

	overflow := newListenerAbnormalPacketConn()
	overflow.closeAction = listenerActionReturn
	overflowListener, err := newListenerFromPacketConnWithExecutor(overflow, MaxDatagram, executor)
	if err != nil {
		t.Fatal(err)
	}
	_, readCapacityErr := overflowListener.Accept(context.Background())
	if !errors.Is(readCapacityErr, ErrListenerRead) {
		t.Fatalf("overflow Accept error=%v", readCapacityErr)
	}
	listenerCallbackError(t, readCapacityErr, "PacketConn.ReadFrom", ListenerCallbackFailureSaturated)
	first := overflowListener.Close()
	listenerCallbackError(t, first, "PacketConn.Close", ListenerCallbackFailureSaturated)
	select {
	case <-overflow.closeStarted:
		t.Fatal("saturated PacketConn.Close was invoked")
	default:
	}

	for _, conn := range connections {
		close(conn.closeRelease)
		close(conn.readRelease)
	}
	listenerEventually(t, func() bool {
		return len(executor.slots[listenerCallbackClose]) == 0 &&
			len(executor.slots[listenerCallbackRead]) == 0
	}, "listener callback permits did not recover")
	if err := overflowListener.Close(); err != nil {
		t.Fatalf("retry Close after executor recovery: %v", err)
	}
	waitListenerSignal(t, overflow.closeStarted, "retried PacketConn.Close entry")
	if calls := overflow.closeCalls.Load(); calls != 1 {
		t.Fatalf("retried PacketConn.Close calls=%d want 1", calls)
	}
	if err := overflowListener.Close(); err != nil {
		t.Fatalf("completed Close: %v", err)
	}
	if calls := overflow.closeCalls.Load(); calls != 1 {
		t.Fatalf("completed PacketConn.Close calls=%d want 1", calls)
	}

	recovered := newListenerAbnormalPacketConn()
	recovered.readAction = listenerActionReturn
	recoveredListener, err := newListenerFromPacketConnWithExecutor(recovered, MaxDatagram, executor)
	if err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool {
		_, err := recoveredListener.Accept(context.Background())
		return errors.Is(err, ErrListenerRead)
	}, "recovered listener read did not terminate")
	if err := recoveredListener.Close(); err != nil {
		t.Fatalf("recovered Close: %v", err)
	}
}

type listenerAcceptedCloseConn struct {
	*listenerMemoryPacketConn
	action  listenerAbnormalAction
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (conn *listenerAcceptedCloseConn) Close() error {
	conn.once.Do(func() { close(conn.started) })
	runListenerAbnormalAction(conn.action, conn.release)
	return nil
}

func TestListenerAcceptedPathPublishesStableFinalCloseFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		action listenerAbnormalAction
		reason ListenerCallbackFailureReason
	}{
		{name: "goexit", action: listenerActionGoexit, reason: ListenerCallbackFailureGoexit},
		{name: "timeout", action: listenerActionBlock, reason: ListenerCallbackFailureTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := newListenerMemoryPacketConn()
			conn := &listenerAcceptedCloseConn{
				listenerMemoryPacketConn: base,
				action:                   test.action,
				started:                  make(chan struct{}),
				release:                  make(chan struct{}),
			}
			listener, err := NewListenerFromPacketConn(conn, MaxDatagram)
			if err != nil {
				t.Fatal(err)
			}
			flowID := listenerFlowID(8750)
			if err := conn.inject(listenerDatagram(t, flowID, []byte("accepted")), listenerTestAddr("peer")); err != nil {
				t.Fatal(err)
			}
			path := listenerAccept(t, listener)
			if got := string(listenerRead(t, path)); got != "accepted" {
				t.Fatalf("payload=%q", got)
			}
			if err := listener.Close(); err != nil {
				t.Fatalf("admission Close=%v", err)
			}
			if _, err := listener.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept before physical close=%v", err)
			}
			first := path.Close()
			listenerCallbackError(t, first, "PacketConn.Close", test.reason)
			waitListenerSignal(t, conn.started, "accepted PacketConn.Close entry")
			if test.action == listenerActionBlock {
				close(conn.release)
			}
			// The abnormal wrapper intentionally does not close the embedded
			// socket. Release its read callback explicitly so this test does not
			// retain global callback capacity after verifying Close containment.
			if err := base.Close(); err != nil {
				t.Fatalf("base Close: %v", err)
			}
			if second := path.Close(); first != second {
				t.Fatalf("path Close error identity changed: first=%p second=%p", first, second)
			}
			second := listener.Close()
			if test.action == listenerActionBlock {
				if second != nil {
					t.Fatalf("listener retained transient timeout after close completed: %v", second)
				}
			} else if first != second {
				t.Fatalf("listener Close error identity changed: first=%p second=%p", first, second)
			}
			if _, err := listener.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept after physical close=%v", err)
			}
		})
	}
}

func TestListenerTerminalDeathWaitsForPayloadConsumption(t *testing.T) {
	conn := newListenerScriptPacketConn()
	flowID := listenerFlowID(8802)
	terminalErr := errors.New("paused-reader terminal failure")
	conn.results <- listenerReadResult{
		packet: listenerTestPacket{
			data: listenerDatagram(t, flowID, []byte("terminal-payload")),
			addr: listenerTestAddr("terminal-peer"),
		},
		err: terminalErr,
	}
	listener, err := NewListenerFromPacketConn(conn, MaxDatagram)
	if err != nil {
		t.Fatal(err)
	}
	path := listenerAccept(t, listener)
	type deathResult struct {
		cause transport.DeathCause
		err   error
	}
	death := make(chan deathResult, 1)
	path.OnDeath(func(cause transport.DeathCause, err error) {
		death <- deathResult{cause: cause, err: err}
	})
	select {
	case got := <-death:
		t.Fatalf("death published before paused reader consumed payload: %+v", got)
	case <-time.After(30 * time.Millisecond):
	}
	if got := string(listenerRead(t, path)); got != "terminal-payload" {
		t.Fatalf("terminal payload=%q", got)
	}
	select {
	case got := <-death:
		t.Fatalf("death published synchronously with terminal payload: %+v", got)
	default:
	}
	if n, err := path.Read(make([]byte, MaxDatagram)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("terminal replay Read=%d, %v want 0, net.ErrClosed", n, err)
	}
	select {
	case got := <-death:
		if got.cause != transport.CauseTransportError || !errors.Is(got.err, terminalErr) {
			t.Fatalf("death=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal death was not published after payload consumption")
	}
}

type listenerEmbeddedUDPReadFromWrapper struct {
	*net.UDPConn
}

// Shadow the embedded method so this wrapper intentionally exposes only the
// portable PacketConn receive contract to Listener.
func (*listenerEmbeddedUDPReadFromWrapper) ReadMsgUDP() {}

func (c *listenerEmbeddedUDPReadFromWrapper) ReadFrom(payload []byte) (int, net.Addr, error) {
	return c.UDPConn.ReadFrom(payload)
}

func TestListenerEmbeddedUDPConnWrapperRejectsSilentOversizePrefix(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &listenerEmbeddedUDPReadFromWrapper{UDPConn: receiver}
	listener, err := NewListenerFromPacketConn(wrapper, MaxDatagram)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	datagram := listenerDatagram(
		t,
		listenerFlowID(8803),
		bytes.Repeat([]byte{0x5c}, MaxDatagram+128),
	)
	if written, err := sender.Write(datagram); err != nil || written != len(datagram) {
		t.Fatalf("Write=%d, %v want %d, nil", written, err, len(datagram))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = listener.Accept(ctx)
	if !errors.Is(err, ErrListenerRead) || !errors.Is(err, ErrTruncatedPacket) {
		t.Fatalf("Accept error=%v want listener/truncated error", err)
	}
	if got := listenerFlowCount(listener); got != 0 {
		t.Fatalf("oversize wrapper prefix created %d flows", got)
	}
}
