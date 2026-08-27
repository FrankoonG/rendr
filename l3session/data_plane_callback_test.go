package l3session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

type hostileDataPlaneAction uint8

const (
	hostileReturn hostileDataPlaneAction = iota
	hostilePanic
	hostileGoexit
	hostileBlock
)

type hostileDataPlaneConn struct {
	operation  string
	action     hostileDataPlaneAction
	entered    chan struct{}
	release    <-chan struct{}
	observed   chan<- byte
	closeCalls atomic.Int32
	once       sync.Once
}

func (conn *hostileDataPlaneConn) invoke(operation string) {
	if conn.operation != operation {
		return
	}
	conn.once.Do(func() {
		if conn.entered != nil {
			close(conn.entered)
		}
	})
	switch conn.action {
	case hostilePanic:
		panic(hostileDataPlanePanic{})
	case hostileGoexit:
		runtime.Goexit()
	case hostileBlock:
		<-conn.release
	}
}

type hostileDataPlanePanic struct{}

func (conn *hostileDataPlaneConn) Read(p []byte) (int, error) {
	conn.invoke("Read")
	if len(p) != 0 {
		p[0] = 0x5a
		return 1, nil
	}
	return 0, nil
}
func (conn *hostileDataPlaneConn) Write(p []byte) (int, error) {
	conn.invoke("Write")
	if conn.observed != nil && len(p) != 0 {
		conn.observed <- p[0]
	}
	return len(p), nil
}
func (conn *hostileDataPlaneConn) ReadFrom(p []byte) (int, net.Addr, error) {
	conn.invoke("ReadFrom")
	if len(p) != 0 {
		p[0] = 0x6b
		return 1, packetAddr("hostile-peer"), nil
	}
	return 0, packetAddr("hostile-peer"), nil
}
func (conn *hostileDataPlaneConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	conn.invoke("WriteTo")
	return len(p), nil
}
func (conn *hostileDataPlaneConn) Close() error {
	conn.closeCalls.Add(1)
	conn.invoke("Close")
	return nil
}
func (conn *hostileDataPlaneConn) CloseRead() error {
	conn.invoke("CloseRead")
	return nil
}
func (conn *hostileDataPlaneConn) CloseWrite() error {
	conn.invoke("CloseWrite")
	return nil
}
func (*hostileDataPlaneConn) LocalAddr() net.Addr  { return packetAddr("hostile-local") }
func (*hostileDataPlaneConn) RemoteAddr() net.Addr { return packetAddr("hostile-remote") }
func (conn *hostileDataPlaneConn) SetDeadline(time.Time) error {
	conn.invoke("SetDeadline")
	return nil
}
func (conn *hostileDataPlaneConn) SetReadDeadline(time.Time) error {
	conn.invoke("SetReadDeadline")
	return nil
}
func (conn *hostileDataPlaneConn) SetWriteDeadline(time.Time) error {
	conn.invoke("SetWriteDeadline")
	return nil
}

func invokeHostileDataPlaneOperation(operation string, action hostileDataPlaneAction) error {
	conn := &hostileDataPlaneConn{operation: operation, action: action}
	stream := newDataPlaneStream(conn, "test stream", conn.Close)
	packet := newDataPlanePacket(conn, "test packet", conn.Close)
	switch operation {
	case "Read":
		_, err := stream.read(context.Background(), make([]byte, 1))
		return err
	case "Write":
		_, err := stream.write(context.Background(), []byte{1})
		return err
	case "ReadFrom":
		_, _, err := packet.readFrom(context.Background(), make([]byte, 1))
		return err
	case "WriteTo":
		_, err := packet.writeTo(context.Background(), []byte{1}, packetAddr("peer"))
		return err
	case "CloseRead":
		return stream.closeRead()
	case "CloseWrite":
		return stream.closeWrite()
	case "SetDeadline":
		return stream.setDeadline(time.Now())
	case "SetReadDeadline":
		return packet.setReadDeadline(time.Now())
	case "SetWriteDeadline":
		return packet.setWriteDeadline(time.Now())
	case "StreamClose":
		conn.operation = "Close"
		return stream.close()
	case "PacketClose":
		conn.operation = "Close"
		return packet.close()
	default:
		return errors.New("unknown hostile operation")
	}
}

func TestDataPlanePanicsAreContainedInSubprocess(t *testing.T) {
	if operation := os.Getenv("RENDR_L3SESSION_PANIC_OPERATION"); operation != "" {
		err := invokeHostileDataPlaneOperation(operation, hostilePanic)
		assertSessionCallbackReason(t, err, CallbackFailurePanic)
		var callbackErr *CallbackError
		if !errors.As(err, &callbackErr) {
			t.Fatalf("panic error=%v want CallbackError", err)
		}
		if callbackErr.PanicType != "l3session.hostileDataPlanePanic" {
			t.Fatalf("panic type=%q", callbackErr.PanicType)
		}
		return
	}
	operations := []string{
		"Read", "Write", "ReadFrom", "WriteTo", "CloseRead", "CloseWrite",
		"SetDeadline", "SetReadDeadline", "SetWriteDeadline", "StreamClose", "PacketClose",
	}
	for _, operation := range operations {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestDataPlanePanicsAreContainedInSubprocess$")
			command.Env = append(os.Environ(), "RENDR_L3SESSION_PANIC_OPERATION="+operation)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("panic subprocess failed: %v\n%s", err, output)
			}
		})
	}
}

func TestDataPlaneGoexitAlwaysPublishesTerminalResult(t *testing.T) {
	operations := []string{
		"Read", "Write", "ReadFrom", "WriteTo", "CloseRead", "CloseWrite",
		"SetDeadline", "SetReadDeadline", "SetWriteDeadline", "StreamClose", "PacketClose",
	}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			result := make(chan error, 1)
			go func() { result <- invokeHostileDataPlaneOperation(operation, hostileGoexit) }()
			select {
			case err := <-result:
				assertSessionCallbackReason(t, err, CallbackFailureGoexit)
			case <-time.After(time.Second):
				t.Fatal("Goexit callback stranded its terminal result")
			}
		})
	}
}

func TestDataPlaneBlockedCallbacksHaveProcessBoundAndRecover(t *testing.T) {
	const testLimit = 8
	executor := newDataPlaneCallbackExecutor(testLimit)
	release := make(chan struct{})
	results := make(chan error, testLimit)
	entered := make([]<-chan struct{}, 0, testLimit)
	for index := 0; index < testLimit; index++ {
		started := make(chan struct{})
		entered = append(entered, started)
		conn := &hostileDataPlaneConn{
			operation: "Read", action: hostileBlock, entered: started, release: release,
		}
		stream := newDataPlaneStreamWithExecutor(executor, conn, "blocked stream", conn.Close)
		go func() {
			_, err := stream.read(context.Background(), make([]byte, 1))
			results <- err
		}()
	}
	for index, started := range entered {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("blocked callback %d did not start", index)
		}
	}

	healthy := &hostileDataPlaneConn{}
	stream := newDataPlaneStreamWithExecutor(executor, healthy, "overflow stream", healthy.Close)
	started := time.Now()
	_, err := stream.read(context.Background(), make([]byte, 1))
	assertSessionCallbackReason(t, err, CallbackFailureSaturated)
	if elapsed := time.Since(started); elapsed > dataPlaneControlTimeout {
		t.Fatalf("capacity rejection took %s", elapsed)
	}

	close(release)
	for index := 0; index < testLimit; index++ {
		if err := <-results; err != nil {
			t.Fatalf("released callback %d error=%v", index, err)
		}
	}
	if n, err := stream.read(context.Background(), make([]byte, 1)); err != nil || n != 1 {
		t.Fatalf("callback capacity did not recover: n=%d err=%v", n, err)
	}
}

type observedPipeConn struct {
	net.Conn
	readEntered  chan struct{}
	writeEntered chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
}

func (conn *observedPipeConn) Read(payload []byte) (int, error) {
	conn.readOnce.Do(func() { close(conn.readEntered) })
	return conn.Conn.Read(payload)
}

func (conn *observedPipeConn) Write(payload []byte) (int, error) {
	conn.writeOnce.Do(func() { close(conn.writeEntered) })
	return conn.Conn.Write(payload)
}

func TestDataPlaneMoreThan64IdleNetPipeOperationsResume(t *testing.T) {
	const sessions = 96
	t.Run("reads", func(t *testing.T) {
		type fixture struct {
			peer    net.Conn
			entered <-chan struct{}
			result  <-chan error
		}
		fixtures := make([]fixture, 0, sessions)
		for index := 0; index < sessions; index++ {
			local, peer := net.Pipe()
			observed := &observedPipeConn{
				Conn: local, readEntered: make(chan struct{}), writeEntered: make(chan struct{}),
			}
			stream := newDataPlaneStream(observed, "idle net.Pipe read", observed.Close)
			result := make(chan error, 1)
			go func() {
				buffer := make([]byte, 1)
				n, err := stream.read(context.Background(), buffer)
				if err == nil && (n != 1 || buffer[0] != 0x5a) {
					err = errors.New("unexpected net.Pipe read payload")
				}
				result <- err
			}()
			fixtures = append(fixtures, fixture{peer: peer, entered: observed.readEntered, result: result})
		}
		for index, fixture := range fixtures {
			select {
			case <-fixture.entered:
			case <-time.After(time.Second):
				t.Fatalf("idle read %d did not enter", index)
			}
		}
		for _, fixture := range fixtures {
			fixture := fixture
			go func() { _, _ = fixture.peer.Write([]byte{0x5a}) }()
		}
		for index, fixture := range fixtures {
			if err := <-fixture.result; err != nil {
				t.Fatalf("idle read %d failed: %v", index, err)
			}
			_ = fixture.peer.Close()
		}
	})

	t.Run("writes", func(t *testing.T) {
		type fixture struct {
			peer    net.Conn
			entered <-chan struct{}
			result  <-chan error
		}
		fixtures := make([]fixture, 0, sessions)
		for index := 0; index < sessions; index++ {
			local, peer := net.Pipe()
			observed := &observedPipeConn{
				Conn: local, readEntered: make(chan struct{}), writeEntered: make(chan struct{}),
			}
			stream := newDataPlaneStream(observed, "idle net.Pipe write", observed.Close)
			result := make(chan error, 1)
			go func() {
				n, err := stream.write(context.Background(), []byte{0x6b})
				if err == nil && n != 1 {
					err = errors.New("unexpected net.Pipe write count")
				}
				result <- err
			}()
			fixtures = append(fixtures, fixture{peer: peer, entered: observed.writeEntered, result: result})
		}
		for index, fixture := range fixtures {
			select {
			case <-fixture.entered:
			case <-time.After(time.Second):
				t.Fatalf("idle write %d did not enter", index)
			}
		}
		for _, fixture := range fixtures {
			fixture := fixture
			go func() {
				buffer := make([]byte, 1)
				_, _ = fixture.peer.Read(buffer)
			}()
		}
		for index, fixture := range fixtures {
			if err := <-fixture.result; err != nil {
				t.Fatalf("idle write %d failed: %v", index, err)
			}
			_ = fixture.peer.Close()
		}
	})
}

func TestCanceledReadCannotMutateCallerBufferAfterReturn(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	conn := &hostileDataPlaneConn{
		operation: "Read", action: hostileBlock, entered: started, release: release,
	}
	stream := newDataPlaneStream(conn, "retained-buffer stream", conn.Close)
	ctx, cancel := context.WithCancel(context.Background())
	buffer := []byte{0x11}
	result := make(chan error, 1)
	go func() {
		_, err := stream.read(ctx, buffer)
		result <- err
	}()
	<-started
	cancel()
	err := <-result
	assertSessionCallbackReason(t, err, CallbackFailureTimeout)
	buffer[0] = 0x33
	close(release)
	time.Sleep(2 * time.Millisecond)
	if buffer[0] != 0x33 {
		t.Fatalf("late Read callback mutated caller buffer: %#x", buffer[0])
	}
}

func TestCanceledWriteRetainsPrivatePayloadSnapshot(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	observed := make(chan byte, 1)
	conn := &hostileDataPlaneConn{
		operation: "Write", action: hostileBlock, entered: started, release: release, observed: observed,
	}
	stream := newDataPlaneStream(conn, "retained-payload stream", conn.Close)
	ctx, cancel := context.WithCancel(context.Background())
	payload := []byte{0x11}
	result := make(chan error, 1)
	go func() {
		_, err := stream.write(ctx, payload)
		result <- err
	}()
	<-started
	cancel()
	err := <-result
	assertSessionCallbackReason(t, err, CallbackFailureTimeout)
	payload[0] = 0x33
	close(release)
	select {
	case got := <-observed:
		if got != 0x11 {
			t.Fatalf("late Write observed caller mutation: %#x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("late Write did not finish")
	}
}

func TestTCPHandshakeCallbacksPublishAbnormalExit(t *testing.T) {
	tests := []struct {
		name   string
		action hostileDataPlaneAction
		want   CallbackFailureReason
	}{
		{name: "panic", action: hostilePanic, want: CallbackFailurePanic},
		{name: "goexit", action: hostileGoexit, want: CallbackFailureGoexit},
	}
	operations := []struct {
		name      string
		operation string
		invoke    func(context.Context, net.Conn) error
	}{
		{
			name: "write envelope", operation: "Write",
			invoke: func(ctx context.Context, conn net.Conn) error {
				return writeAllContext(ctx, conn, []byte{1})
			},
		},
		{
			name: "read ready", operation: "Read",
			invoke: func(ctx context.Context, conn net.Conn) error {
				_, err := readTCPReadyContext(ctx, conn)
				return err
			},
		},
		{
			name: "read peer envelope", operation: "Read",
			invoke: func(ctx context.Context, conn net.Conn) error {
				_, err := readTCPEnvelopeContext(ctx, conn)
				return err
			},
		},
	}
	for _, test := range tests {
		for _, operation := range operations {
			t.Run(test.name+"/"+operation.name, func(t *testing.T) {
				conn := &hostileDataPlaneConn{operation: operation.operation, action: test.action}
				assertSessionCallbackReason(t, operation.invoke(context.Background(), conn), test.want)
			})
		}
	}
}

func TestBlockedCloseRetainsSingleAuthorityUntilActualReturn(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	conn := &hostileDataPlaneConn{
		operation: "Close", action: hostileBlock, entered: started, release: release,
	}
	stream := newDataPlaneStream(conn, "blocked-close stream", conn.Close)
	result := make(chan error, 1)
	go func() { result <- stream.close() }()
	<-started
	select {
	case err := <-result:
		assertSessionCallbackReason(t, err, CallbackFailureTimeout)
	case <-time.After(2 * dataPlaneCloseTimeout):
		t.Fatal("blocked Close exceeded its bounded wait")
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("Close calls before release=%d want 1", got)
	}
	close(release)
	if err := stream.close(); err != nil {
		t.Fatalf("Close after actual return=%v", err)
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("Close calls after retry=%d want 1", got)
	}
}

type dataPlaneAdoptionEgress struct {
	tcp       l3ingress.TCPConn
	udp       net.PacketConn
	udpRemote netip.AddrPort
	tcpCalls  atomic.Int32
	udpCalls  atomic.Int32
}

func (egress *dataPlaneAdoptionEgress) DialTCP(
	context.Context,
	l3ingress.L3Identity,
) (l3ingress.TCPConn, error) {
	egress.tcpCalls.Add(1)
	return egress.tcp, nil
}

func (egress *dataPlaneAdoptionEgress) DialUDP(
	context.Context,
	l3ingress.L3Identity,
) (net.PacketConn, netip.AddrPort, error) {
	egress.udpCalls.Add(1)
	return egress.udp, egress.udpRemote, nil
}

type dataPlanePeerRendrConn struct {
	reader     *bytes.Reader
	writeErr   error
	closeCalls atomic.Int32
}

func newDataPlanePeerRendrConn(payload []byte, writeErr error) *dataPlanePeerRendrConn {
	return &dataPlanePeerRendrConn{reader: bytes.NewReader(payload), writeErr: writeErr}
}

func (conn *dataPlanePeerRendrConn) Read(payload []byte) (int, error) {
	return conn.reader.Read(payload)
}

func (conn *dataPlanePeerRendrConn) Write(payload []byte) (int, error) {
	if conn.writeErr != nil {
		return 0, conn.writeErr
	}
	return len(payload), nil
}

func (conn *dataPlanePeerRendrConn) Close() error {
	conn.closeCalls.Add(1)
	return nil
}

func (*dataPlanePeerRendrConn) CloseWrite() error                { return nil }
func (*dataPlanePeerRendrConn) LocalAddr() net.Addr              { return packetAddr("peer-local") }
func (*dataPlanePeerRendrConn) RemoteAddr() net.Addr             { return packetAddr("peer-remote") }
func (*dataPlanePeerRendrConn) SetDeadline(time.Time) error      { return nil }
func (*dataPlanePeerRendrConn) SetReadDeadline(time.Time) error  { return nil }
func (*dataPlanePeerRendrConn) SetWriteDeadline(time.Time) error { return nil }
func (*dataPlanePeerRendrConn) Paths() []rendr.PathInfo          { return nil }
func (*dataPlanePeerRendrConn) FlowID() [16]byte                 { return [16]byte{1} }
func (*dataPlanePeerRendrConn) Status() rendr.Status             { return rendr.Status{} }

func dataPlaneCleanupTestIdentity(protocol l3ingress.Protocol) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   protocol,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 42000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func registerDataPlaneAdoptionEgress(t *testing.T, egress l3ingress.Egress) *l3ingress.EgressRegistry {
	t.Helper()
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("vpn", egress); err != nil {
		t.Fatal(err)
	}
	return registry
}

func blockDataPlaneCloseExecution(
	t *testing.T,
	executor *dataPlaneCallbackExecutor,
) func() {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	task, err := startDataPlaneCallback(
		executor,
		"injected blocked Close",
		dataPlaneCloseCallback,
		func() (struct{}, error) {
			close(entered)
			<-release
			return struct{}{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("injected Close did not occupy executor capacity")
	}
	var once sync.Once
	unblock := func() {
		once.Do(func() {
			close(release)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := task.wait(ctx); err != nil {
				t.Errorf("injected Close release: %v", err)
			}
		})
	}
	t.Cleanup(unblock)
	return unblock
}

func requireDataPlaneCleanupCapacityRecovered(
	t *testing.T,
	executor *dataPlaneCallbackExecutor,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		reservation, err := reserveDataPlaneCleanupWithExecutor(executor, "capacity recovery")
		if err == nil {
			reservation.Release()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("data-plane cleanup authority capacity did not recover")
}

func TestPeerRelaysReserveCleanupBeforeAdoptingEgress(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		executor := newDataPlaneCallbackExecutor(1)
		held, err := reserveDataPlaneCleanupWithExecutor(executor, "held TCP cleanup")
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()

		identity := dataPlaneCleanupTestIdentity(l3ingress.ProtocolTCP)
		envelope, err := encodeTCPEnvelope(identity, "vpn")
		if err != nil {
			t.Fatal(err)
		}
		peer := newDataPlanePeerRendrConn(envelope, nil)
		egress := &dataPlaneAdoptionEgress{}
		err = (&TCPPeerRelay{
			Conn: peer, Egresses: registerDataPlaneAdoptionEgress(t, egress),
			dataPlaneExecutor: executor,
		}).Run(context.Background())
		assertSessionCallbackReason(t, err, CallbackFailureSaturated)
		if calls := egress.tcpCalls.Load(); calls != 0 {
			t.Fatalf("TCP egress Dial calls=%d want 0", calls)
		}
		if calls := peer.closeCalls.Load(); calls != 0 {
			t.Fatalf("caller-owned peer Close calls=%d want 0", calls)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		executor := newDataPlaneCallbackExecutor(1)
		held, err := reserveDataPlaneCleanupWithExecutor(executor, "held UDP cleanup")
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()

		identity := dataPlaneCleanupTestIdentity(l3ingress.ProtocolUDP)
		envelope, err := appendUDPEnvelope(nil, identity, "vpn", []byte("query"))
		if err != nil {
			t.Fatal(err)
		}
		peer := newScriptedRendrPacketConn(envelope)
		defer peer.Close()
		egress := &dataPlaneAdoptionEgress{}
		err = (&UDPPeerRelay{
			PacketConn: peer, Egresses: registerDataPlaneAdoptionEgress(t, egress),
			dataPlaneExecutor: executor,
		}).Run(context.Background())
		assertSessionCallbackReason(t, err, CallbackFailureSaturated)
		if calls := egress.udpCalls.Load(); calls != 0 {
			t.Fatalf("UDP egress Dial calls=%d want 0", calls)
		}
	})
}

func TestRejectedPeerEgressCleanupSurvivesSaturatedExecutor(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		executor := newDataPlaneCallbackExecutor(1)
		unblock := blockDataPlaneCloseExecution(t, executor)

		identity := dataPlaneCleanupTestIdentity(l3ingress.ProtocolTCP)
		envelope, err := encodeTCPEnvelope(identity, "vpn")
		if err != nil {
			t.Fatal(err)
		}
		readyErr := errors.New("injected peer ready write failure")
		peer := newDataPlanePeerRendrConn(envelope, readyErr)
		closeEntered := make(chan struct{})
		egressConn := &hostileDataPlaneConn{operation: "Close", entered: closeEntered}
		egress := &dataPlaneAdoptionEgress{tcp: egressConn}

		err = (&TCPPeerRelay{
			Conn: peer, Egresses: registerDataPlaneAdoptionEgress(t, egress),
			dataPlaneExecutor: executor,
		}).Run(context.Background())
		if !errors.Is(err, readyErr) {
			t.Fatalf("TCP relay error=%v want %v", err, readyErr)
		}
		assertSessionCallbackReason(t, err, CallbackFailureTimeout)
		if calls := egressConn.closeCalls.Load(); calls != 0 {
			t.Fatalf("TCP egress Close calls before capacity release=%d want 0", calls)
		}

		unblock()
		select {
		case <-closeEntered:
		case <-time.After(time.Second):
			t.Fatal("discarded TCP cleanup authority did not close adopted egress")
		}
		if calls := egressConn.closeCalls.Load(); calls != 1 {
			t.Fatalf("TCP egress Close calls=%d want 1", calls)
		}
		requireDataPlaneCleanupCapacityRecovered(t, executor)
	})

	t.Run("UDP", func(t *testing.T) {
		executor := newDataPlaneCallbackExecutor(1)
		unblock := blockDataPlaneCloseExecution(t, executor)

		identity := dataPlaneCleanupTestIdentity(l3ingress.ProtocolUDP)
		envelope, err := appendUDPEnvelope(nil, identity, "vpn", []byte("query"))
		if err != nil {
			t.Fatal(err)
		}
		peer := newScriptedRendrPacketConn(envelope)
		defer peer.Close()
		egressConn := newPeerTestPacketConn()
		egress := &dataPlaneAdoptionEgress{udp: egressConn}

		err = (&UDPPeerRelay{
			PacketConn: peer, Egresses: registerDataPlaneAdoptionEgress(t, egress),
			dataPlaneExecutor: executor,
		}).Run(context.Background())
		if err == nil {
			t.Fatalf("UDP relay error=%v want cleanup timeout", err)
		}
		assertSessionCallbackReason(t, err, CallbackFailureTimeout)
		if calls := egressConn.closeCalls.Load(); calls != 0 {
			t.Fatalf("UDP egress Close calls before capacity release=%d want 0", calls)
		}

		unblock()
		select {
		case <-egressConn.done:
		case <-time.After(time.Second):
			t.Fatal("discarded UDP cleanup authority did not close adopted egress")
		}
		if calls := egressConn.closeCalls.Load(); calls != 1 {
			t.Fatalf("UDP egress Close calls=%d want 1", calls)
		}
		requireDataPlaneCleanupCapacityRecovered(t, executor)
	})
}
