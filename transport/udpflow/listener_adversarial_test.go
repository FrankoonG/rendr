package udpflow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type listenerTestAddr string

func (a listenerTestAddr) Network() string { return "listener-test" }
func (a listenerTestAddr) String() string  { return string(a) }

type listenerTestPacket struct {
	data []byte
	addr net.Addr
}

type listenerReadResult struct {
	packet listenerTestPacket
	err    error
}

type listenerScriptPacketConn struct {
	results   chan listenerReadResult
	readCalls chan time.Time
	closed    chan struct{}

	closeOnce  sync.Once
	closeCount atomic.Int32
	readCount  atomic.Int32
}

func newListenerScriptPacketConn() *listenerScriptPacketConn {
	return &listenerScriptPacketConn{
		results:   make(chan listenerReadResult, 32),
		readCalls: make(chan time.Time, 32),
		closed:    make(chan struct{}),
	}
}

func (c *listenerScriptPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	c.readCount.Add(1)
	c.readCalls <- time.Now()
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case result := <-c.results:
		if result.err != nil {
			return 0, nil, result.err
		}
		n := copy(buf, result.packet.data)
		return n, result.packet.addr, nil
	}
}

func (c *listenerScriptPacketConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(buf), nil
	}
}

func (c *listenerScriptPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeCount.Add(1)
		close(c.closed)
	})
	return nil
}

func (c *listenerScriptPacketConn) LocalAddr() net.Addr              { return listenerTestAddr("script-listener") }
func (c *listenerScriptPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *listenerScriptPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *listenerScriptPacketConn) SetWriteDeadline(time.Time) error { return nil }

type listenerTemporaryReadError struct{}

func (listenerTemporaryReadError) Error() string   { return "temporary packet read failure" }
func (listenerTemporaryReadError) Timeout() bool   { return false }
func (listenerTemporaryReadError) Temporary() bool { return true }

type listenerMemoryPacketConn struct {
	reads  chan listenerTestPacket
	writes chan listenerTestPacket
	closed chan struct{}

	closeOnce  sync.Once
	closeCount atomic.Int32
	readCount  atomic.Int32
}

func newListenerMemoryPacketConn() *listenerMemoryPacketConn {
	capacity := maxListenerFlows + acceptQueueSize + 256
	return &listenerMemoryPacketConn{
		reads:  make(chan listenerTestPacket, capacity),
		writes: make(chan listenerTestPacket, capacity),
		closed: make(chan struct{}),
	}
}

func (c *listenerMemoryPacketConn) inject(data []byte, addr net.Addr) error {
	pkt := listenerTestPacket{data: bytes.Clone(data), addr: addr}
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	select {
	case <-c.closed:
		return net.ErrClosed
	case c.reads <- pkt:
		return nil
	}
}

func (c *listenerMemoryPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case pkt := <-c.reads:
		c.readCount.Add(1)
		n := copy(buf, pkt.data)
		return n, pkt.addr, nil
	}
}

func (c *listenerMemoryPacketConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	pkt := listenerTestPacket{data: bytes.Clone(buf), addr: addr}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.writes <- pkt:
		return len(buf), nil
	}
}

func (c *listenerMemoryPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeCount.Add(1)
		close(c.closed)
	})
	return nil
}

func (c *listenerMemoryPacketConn) LocalAddr() net.Addr { return listenerTestAddr("listener") }
func (c *listenerMemoryPacketConn) SetDeadline(time.Time) error {
	return nil
}
func (c *listenerMemoryPacketConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *listenerMemoryPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func listenerFlowID(n uint64) [proto.UDPFlowIDSize]byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], n)
	var flowID [proto.UDPFlowIDSize]byte
	copy(flowID[:], raw[1:])
	return flowID
}

func listenerDatagram(t *testing.T, flowID [proto.UDPFlowIDSize]byte, payload []byte) []byte {
	t.Helper()
	datagram := make([]byte, proto.UDPFlowHeaderSize+len(payload))
	hdr := proto.UDPFlowHeader{Version: proto.UDPFlowVersion, FlowID: flowID}
	if err := hdr.Encode(datagram[:proto.UDPFlowHeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(datagram[proto.UDPFlowHeaderSize:], payload)
	return datagram
}

func listenerAccept(t *testing.T, l *Listener) *ServerPathConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pc, err := l.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	return pc
}

func listenerRead(t *testing.T, pc *ServerPathConn) []byte {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		buf := make([]byte, MaxDatagram)
		n, err := pc.Read(buf)
		resultCh <- result{data: bytes.Clone(buf[:n]), err: err}
	}()
	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatalf("Read: %v", got.err)
		}
		return got.data
	case <-time.After(2 * time.Second):
		t.Fatal("Read timed out")
		return nil
	}
}

func listenerFlowCount(l *Listener) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.flows)
}

func listenerHasFlow(l *Listener, flowID [proto.UDPFlowIDSize]byte, pc *ServerPathConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	got, ok := l.flows[flowID]
	return ok && (pc == nil || got == pc)
}

func listenerEventually(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}

func TestNewListenerFromPacketConnUsesGenericAddresses(t *testing.T) {
	if _, err := NewListenerFromPacketConn(nil); err == nil {
		t.Fatal("NewListenerFromPacketConn(nil) succeeded")
	}

	conn := newListenerMemoryPacketConn()
	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	flowID := listenerFlowID(1)
	peer := listenerTestAddr("peer-a")
	request := []byte("request")
	if err := conn.inject(listenerDatagram(t, flowID, request), peer); err != nil {
		t.Fatal(err)
	}

	server := listenerAccept(t, l)
	if got := listenerRead(t, server); !bytes.Equal(got, request) {
		t.Fatalf("Read = %q, want %q", got, request)
	}

	reply := []byte("reply")
	if _, err := server.Write(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-conn.writes:
		if packet.addr != peer {
			t.Fatalf("WriteTo addr = %v, want %v", packet.addr, peer)
		}
		hdr, err := proto.DecodeUDPFlow(packet.data[:proto.UDPFlowHeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		if hdr.FlowID != flowID {
			t.Fatalf("WriteTo flow ID = %x, want %x", hdr.FlowID, flowID)
		}
		if got := packet.data[proto.UDPFlowHeaderSize:]; !bytes.Equal(got, reply) {
			t.Fatalf("WriteTo payload = %q, want %q", got, reply)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTo timed out")
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := conn.closeCount.Load(); got != 0 {
		t.Fatalf("PacketConn closed with accepted flow: count=%d", got)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "PacketConn was not closed")
}

func TestListenerFlowChurnDoesNotLeakEntries(t *testing.T) {
	conn := newListenerMemoryPacketConn()
	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	peer := listenerTestAddr("churn-peer")

	for i := uint64(1); i <= 256; i++ {
		flowID := listenerFlowID(i)
		payload := []byte(fmt.Sprintf("flow-%d", i))
		if err := conn.inject(listenerDatagram(t, flowID, payload), peer); err != nil {
			t.Fatal(err)
		}
		server := listenerAccept(t, l)
		if got := listenerRead(t, server); !bytes.Equal(got, payload) {
			t.Fatalf("flow %d payload = %q, want %q", i, got, payload)
		}
		if i%2 == 0 {
			server.declareDeath(errors.New("injected transport death"))
		} else if err := server.Close(); err != nil {
			t.Fatal(err)
		}
		if got := listenerFlowCount(l); got != 0 {
			t.Fatalf("flow table length after churn %d = %d, want 0", i, got)
		}
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "PacketConn leaked after churn")
}

func TestListenerAcceptQueueSaturationDoesNotBlockExistingFlow(t *testing.T) {
	conn := newListenerMemoryPacketConn()
	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	peer := listenerTestAddr("saturation-peer")

	for i := 0; i < acceptQueueSize; i++ {
		flowID := listenerFlowID(uint64(i + 1))
		if err := conn.inject(listenerDatagram(t, flowID, []byte("first")), peer); err != nil {
			t.Fatal(err)
		}
	}
	listenerEventually(t, func() bool {
		return conn.readCount.Load() == acceptQueueSize && listenerFlowCount(l) == acceptQueueSize
	}, "accept queue did not fill")

	rejectedID := listenerFlowID(10_000)
	if err := conn.inject(listenerDatagram(t, rejectedID, []byte("reject")), peer); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.readCount.Load() == acceptQueueSize+1 }, "rejected flow was not read")
	if listenerHasFlow(l, rejectedID, nil) {
		t.Fatal("rejected flow remained in the flow table")
	}
	if got := listenerFlowCount(l); got != acceptQueueSize {
		t.Fatalf("flow table length = %d, want %d", got, acceptQueueSize)
	}

	existingID := listenerFlowID(1)
	if err := conn.inject(listenerDatagram(t, existingID, []byte("second")), peer); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.readCount.Load() == acceptQueueSize+2 }, "existing flow delivery blocked")

	server := listenerAccept(t, l)
	if got := server.FlowID(); got != existingID {
		t.Fatalf("first accepted flow = %x, want %x", got, existingID)
	}
	if got := listenerRead(t, server); !bytes.Equal(got, []byte("first")) {
		t.Fatalf("first payload = %q", got)
	}
	if got := listenerRead(t, server); !bytes.Equal(got, []byte("second")) {
		t.Fatalf("second payload = %q", got)
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := conn.closeCount.Load(); got != 0 {
		t.Fatalf("PacketConn closed while accepted flow remained: count=%d", got)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "PacketConn was not closed after saturation test")
}

func TestListenerFlowTableIsBounded(t *testing.T) {
	conn := newListenerMemoryPacketConn()
	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	peer := listenerTestAddr("bound-peer")

	l.mu.Lock()
	for i := 0; i < maxListenerFlows; i++ {
		flowID := listenerFlowID(uint64(i + 1))
		l.flows[flowID] = newServerPathConn(l, flowID, peer)
	}
	l.mu.Unlock()

	overflowID := listenerFlowID(maxListenerFlows + 1)
	if err := conn.inject(listenerDatagram(t, overflowID, []byte("overflow")), peer); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.readCount.Load() == 1 }, "overflow packet was not processed")
	if got := listenerFlowCount(l); got != maxListenerFlows {
		t.Fatalf("flow table length = %d, want %d", got, maxListenerFlows)
	}
	if listenerHasFlow(l, overflowID, nil) {
		t.Fatal("overflow flow entered the table")
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "PacketConn was not closed after bounded-table test")
}

func TestListenerStaleCloseDoesNotDeleteReplacementFlow(t *testing.T) {
	conn := newListenerMemoryPacketConn()
	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	flowID := listenerFlowID(77)
	oldPeer := listenerTestAddr("old-peer")
	if err := conn.inject(listenerDatagram(t, flowID, []byte("old")), oldPeer); err != nil {
		t.Fatal(err)
	}
	old := listenerAccept(t, l)
	if got := listenerRead(t, old); !bytes.Equal(got, []byte("old")) {
		t.Fatalf("old payload = %q", got)
	}

	newPeer := listenerTestAddr("new-peer")
	replacement := newServerPathConn(l, flowID, newPeer)
	l.mu.Lock()
	replacement.accepted = true
	l.flows[flowID] = replacement
	l.mu.Unlock()

	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if !listenerHasFlow(l, flowID, replacement) {
		t.Fatal("stale close deleted the replacement flow")
	}

	if err := conn.inject(listenerDatagram(t, flowID, []byte("new")), newPeer); err != nil {
		t.Fatal(err)
	}
	if got := listenerRead(t, replacement); !bytes.Equal(got, []byte("new")) {
		t.Fatalf("replacement payload = %q", got)
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "replacement did not release PacketConn")
}

func TestListenerCloseDrainsAcceptedFlow(t *testing.T) {
	conn := newListenerMemoryPacketConn()
	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	flowID := listenerFlowID(91)
	peer := listenerTestAddr("draining-peer")
	if err := conn.inject(listenerDatagram(t, flowID, []byte("before-close")), peer); err != nil {
		t.Fatal(err)
	}
	server := listenerAccept(t, l)
	if got := listenerRead(t, server); !bytes.Equal(got, []byte("before-close")) {
		t.Fatalf("initial payload = %q", got)
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := conn.closeCount.Load(); got != 0 {
		t.Fatalf("PacketConn closed before accepted flow: count=%d", got)
	}
	if _, err := l.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}

	newFlowID := listenerFlowID(92)
	if err := conn.inject(listenerDatagram(t, newFlowID, []byte("drop")), peer); err != nil {
		t.Fatal(err)
	}
	if err := conn.inject(listenerDatagram(t, flowID, []byte("during-drain")), peer); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.readCount.Load() == 3 }, "draining packets were not processed")
	if listenerHasFlow(l, newFlowID, nil) {
		t.Fatal("new flow was admitted while draining")
	}
	if got := listenerRead(t, server); !bytes.Equal(got, []byte("during-drain")) {
		t.Fatalf("draining payload = %q", got)
	}

	if _, err := server.Write([]byte("draining-reply")); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-conn.writes:
		if packet.addr != peer {
			t.Fatalf("draining reply addr = %v, want %v", packet.addr, peer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("draining reply timed out")
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "PacketConn remained open after draining")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := conn.closeCount.Load(); got != 1 {
		t.Fatalf("PacketConn close count = %d, want 1", got)
	}
}

func TestListenerConcurrentCloseAndDeath(t *testing.T) {
	for iteration := 0; iteration < 32; iteration++ {
		conn := newListenerMemoryPacketConn()
		l, err := NewListenerFromPacketConn(conn)
		if err != nil {
			t.Fatal(err)
		}
		flowID := listenerFlowID(uint64(iteration + 1))
		peer := listenerTestAddr("race-peer")
		if err := conn.inject(listenerDatagram(t, flowID, []byte("initial")), peer); err != nil {
			t.Fatal(err)
		}
		server := listenerAccept(t, l)
		_ = listenerRead(t, server)
		concurrentDatagram := listenerDatagram(t, flowID, []byte("concurrent read"))

		start := make(chan struct{})
		var wg sync.WaitGroup
		for worker := 0; worker < 64; worker++ {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				<-start
				switch worker % 6 {
				case 0:
					_ = l.Close()
				case 1:
					_ = server.Close()
				case 2:
					server.declareDeath(errors.New("concurrent death"))
				case 3:
					server.OnDeath(func(transport.DeathCause, error) {})
				case 4:
					_, _ = server.Write([]byte("concurrent write"))
				case 5:
					_ = conn.inject(concurrentDatagram, peer)
				}
			}(worker)
		}
		close(start)
		wg.Wait()

		_ = l.Close()
		_ = server.Close()
		server.declareDeath(errors.New("final death"))
		listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "concurrent close did not close PacketConn")
		if got := listenerFlowCount(l); got != 0 {
			t.Fatalf("iteration %d flow table length = %d, want 0", iteration, got)
		}
		if got := conn.closeCount.Load(); got != 1 {
			t.Fatalf("iteration %d PacketConn close count = %d, want 1", iteration, got)
		}
	}
}

func TestListenerPermanentReadFailureIsTerminal(t *testing.T) {
	permanentErr := errors.New("permanent read sentinel")
	conn := newListenerScriptPacketConn()
	flowID := listenerFlowID(501)
	peer := listenerTestAddr("permanent-peer")
	conn.results <- listenerReadResult{packet: listenerTestPacket{
		data: listenerDatagram(t, flowID, []byte("initial")),
		addr: peer,
	}}

	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	server := listenerAccept(t, l)
	if got := listenerRead(t, server); !bytes.Equal(got, []byte("initial")) {
		t.Fatalf("initial payload = %q", got)
	}

	type deathResult struct {
		cause transport.DeathCause
		err   error
	}
	deathCh := make(chan deathResult, 1)
	server.OnDeath(func(cause transport.DeathCause, err error) {
		deathCh <- deathResult{cause: cause, err: err}
	})
	conn.results <- listenerReadResult{err: permanentErr}

	select {
	case death := <-deathCh:
		if death.cause != transport.CauseTransportError {
			t.Fatalf("death cause = %v, want transport error", death.cause)
		}
		if !errors.Is(death.err, ErrListenerRead) || !errors.Is(death.err, permanentErr) {
			t.Fatalf("death error = %v, want listener and permanent sentinels", death.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("path death notification timed out")
	}

	if _, err := server.Read(make([]byte, MaxDatagram)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("path Read after listener failure = %v, want net.ErrClosed", err)
	}

	_, firstAcceptErr := l.Accept(context.Background())
	if !errors.Is(firstAcceptErr, ErrListenerRead) || !errors.Is(firstAcceptErr, permanentErr) {
		t.Fatalf("Accept error = %v, want listener and permanent sentinels", firstAcceptErr)
	}
	_, secondAcceptErr := l.Accept(context.Background())
	if firstAcceptErr != secondAcceptErr {
		t.Fatalf("Accept error identity changed: first=%p second=%p", firstAcceptErr, secondAcceptErr)
	}

	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "terminal read did not close PacketConn")
	readsAfterFailure := conn.readCount.Load()
	time.Sleep(4 * readRetryInitialBackoff)
	if got := conn.readCount.Load(); got != readsAfterFailure {
		t.Fatalf("ReadFrom continued after permanent failure: before=%d after=%d", readsAfterFailure, got)
	}
	if got := listenerFlowCount(l); got != 0 {
		t.Fatalf("flow table length = %d, want 0", got)
	}

	_ = l.Close()
	_ = server.Close()
	if got := conn.closeCount.Load(); got != 1 {
		t.Fatalf("PacketConn close count = %d, want 1", got)
	}
}

func TestListenerTemporaryReadBurstBacksOffAndRecovers(t *testing.T) {
	conn := newListenerScriptPacketConn()
	temporaryErr := listenerTemporaryReadError{}
	for i := 0; i < 3; i++ {
		conn.results <- listenerReadResult{err: fmt.Errorf("temporary read %d: %w", i, temporaryErr)}
	}
	flowID := listenerFlowID(502)
	conn.results <- listenerReadResult{packet: listenerTestPacket{
		data: listenerDatagram(t, flowID, []byte("recovered")),
		addr: listenerTestAddr("temporary-peer"),
	}}

	l, err := NewListenerFromPacketConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	server := listenerAccept(t, l)
	if got := listenerRead(t, server); !bytes.Equal(got, []byte("recovered")) {
		t.Fatalf("recovered payload = %q", got)
	}

	if got := conn.readCount.Load(); got != 5 {
		// The fifth call is blocked waiting for the next packet after recovery.
		t.Fatalf("ReadFrom call count = %d, want 5", got)
	}
	callTimes := make([]time.Time, 0, 5)
	for len(callTimes) < 5 {
		select {
		case callTime := <-conn.readCalls:
			callTimes = append(callTimes, callTime)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out collecting ReadFrom call times")
		}
	}
	for i, want := range []time.Duration{
		readRetryInitialBackoff,
		2 * readRetryInitialBackoff,
		4 * readRetryInitialBackoff,
	} {
		if gap := callTimes[i+1].Sub(callTimes[i]); gap < want {
			t.Fatalf("retry %d gap = %v, want at least %v", i+1, gap, want)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	listenerEventually(t, func() bool { return conn.closeCount.Load() == 1 }, "recovered listener did not close PacketConn")
}
