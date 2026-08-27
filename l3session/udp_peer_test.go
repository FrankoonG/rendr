package l3session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestUDPPeerRelayDispatchesIdentityAndBridgesReplies(t *testing.T) {
	ln := newTestPacketSessionListener(t, "udpflow")
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan rendr.PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		pc, err := ln.AcceptPacket(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- pc
	}()
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	client, err := runtime.DialPacket(ctx, rendr.SessionConfig{
		Root:               rendr.Path("udp", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		PreserveL3Identity: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server rendr.PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	egressConn := newPeerTestPacketConn()
	egress := &peerTestEgress{conn: egressConn}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("vpn", egress); err != nil {
		t.Fatal(err)
	}
	peerErr := make(chan error, 1)
	go func() {
		peerErr <- (&UDPPeerRelay{PacketConn: server, Egresses: registry}).Run(ctx)
	}()

	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 42000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 53,
	}
	request, err := appendUDPEnvelope(nil, id, "vpn", []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo(request, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-egressConn.writes:
		if string(got) != "query" {
			t.Fatalf("egress payload=%q want query", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := egress.identity(); got != id {
		t.Fatalf("egress identity=%s want %s", got, id)
	}

	egressConn.reads <- peerTestPacket{
		payload: []byte("forged"),
		addr:    net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.99:53")),
	}
	egressConn.reads <- peerTestPacket{
		payload: []byte("answer"),
		addr:    net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.20:53")),
	}
	buf := make([]byte, 32)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "answer" {
		t.Fatalf("reply=%q want answer", buf[:n])
	}
	_ = egressConn.Close()
	select {
	case err := <-peerErr:
		if err != nil {
			t.Fatalf("peer relay: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestPacketSourceMatchesIPv4AndIPv6(t *testing.T) {
	for _, tt := range []struct {
		name     string
		expected string
		actual   string
		match    bool
	}{
		{name: "ipv4", expected: "198.51.100.20:53", actual: "198.51.100.20:53", match: true},
		{name: "ipv4-wrong-port", expected: "198.51.100.20:53", actual: "198.51.100.20:54"},
		{name: "ipv6", expected: "[2001:db8::20]:53", actual: "[2001:db8::20]:53", match: true},
		{name: "ipv6-wrong-address", expected: "[2001:db8::20]:53", actual: "[2001:db8::21]:53"},
		{name: "mapped-ipv4", expected: "198.51.100.20:53", actual: "[::ffff:198.51.100.20]:53", match: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			expected := netip.MustParseAddrPort(tt.expected)
			actual := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(tt.actual))
			if got := packetSourceMatches(actual, expected); got != tt.match {
				t.Fatalf("packetSourceMatches(%s, %s)=%v want %v", actual, expected, got, tt.match)
			}
		})
	}
}

func TestUDPPeerRelayRejectsMetadataChange(t *testing.T) {
	firstID := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("198.51.100.1"),
		SrcPort: 1000, DstPort: 2000,
	}
	secondID := firstID
	secondID.SrcPort++
	first, _ := appendUDPEnvelope(nil, firstID, "vpn", []byte("one"))
	second, _ := appendUDPEnvelope(nil, secondID, "vpn", []byte("two"))
	packetConn := newScriptedRendrPacketConn(first, second)
	egressConn := newPeerTestPacketConn()
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("vpn", &peerTestEgress{conn: egressConn}); err != nil {
		t.Fatal(err)
	}
	err := (&UDPPeerRelay{PacketConn: packetConn, Egresses: registry}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "identity or egress changed") {
		t.Fatalf("err=%v want metadata-change rejection", err)
	}
}

func TestUDPPeerRelayCancellationClosesEgressBeforeJoiningWorkers(t *testing.T) {
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.10"), DstIP: netip.MustParseAddr("198.51.100.20"),
		SrcPort: 42000, DstPort: 53,
	}
	first, err := appendUDPEnvelope(nil, id, "vpn", []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	packetConn := newBlockingRendrPacketConn(first)
	defer packetConn.Close()
	egressConn := newPeerTestPacketConn()
	egressConn.ignoreReadDeadlines = true
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("vpn", &peerTestEgress{conn: egressConn}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&UDPPeerRelay{PacketConn: packetConn, Egresses: registry}).Run(ctx)
	}()
	select {
	case <-egressConn.writes:
	case <-time.After(time.Second):
		t.Fatal("UDP peer relay did not start egress forwarding")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not terminate after cancellation")
	}
	if got := egressConn.closeCalls.Load(); got != 1 {
		t.Fatalf("egress Close calls=%d want 1", got)
	}
	if got := packetConn.closeCalls.Load(); got != 0 {
		t.Fatalf("caller-owned rendr PacketConn Close calls=%d want 0", got)
	}
}

func TestUDPPeerRelayCancellationBoundsUncooperativeRendrWorker(t *testing.T) {
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.10"), DstIP: netip.MustParseAddr("198.51.100.20"),
		SrcPort: 42000, DstPort: 53,
	}
	first, err := appendUDPEnvelope(nil, id, "vpn", []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	packetConn := newBlockingRendrPacketConn(first)
	packetConn.ignoreReadDeadlines = true
	egressConn := newPeerTestPacketConn()
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("vpn", &peerTestEgress{conn: egressConn}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&UDPPeerRelay{PacketConn: packetConn, Egresses: registry}).Run(ctx)
	}()
	select {
	case <-egressConn.writes:
	case <-time.After(time.Second):
		t.Fatal("UDP peer relay did not start egress forwarding")
	}
	select {
	case <-packetConn.readStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP peer relay did not enter the uncooperative ReadFrom")
	}
	started := time.Now()
	cancel()
	select {
	case err := <-done:
		assertSessionCallbackReason(t, err, CallbackFailureTimeout)
		if elapsed := time.Since(started); elapsed > 3*udpPeerWorkerShutdownTimeout {
			t.Fatalf("Run shutdown elapsed=%s want <=%s", elapsed, 3*udpPeerWorkerShutdownTimeout)
		}
	case <-time.After(3 * udpPeerWorkerShutdownTimeout):
		t.Fatal("Run remained blocked behind uncooperative caller-owned PacketConn")
	}
	if got := packetConn.closeCalls.Load(); got != 0 {
		t.Fatalf("caller-owned rendr PacketConn Close calls=%d want 0", got)
	}
	if got := egressConn.closeCalls.Load(); got != 1 {
		t.Fatalf("egress Close calls=%d want 1", got)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUDPPeerRelaySmallBufferDoesNotTruncateDatagrams(t *testing.T) {
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.10"), DstIP: netip.MustParseAddr("198.51.100.20"),
		SrcPort: 42000, DstPort: 53,
	}
	requestPayload := bytes.Repeat([]byte{0xa5}, maxUDPPeerPayloadSize)
	egressName := strings.Repeat("e", udpEnvelopeMaxEgressName)
	first, err := appendUDPEnvelope(nil, id, egressName, requestPayload)
	if err != nil {
		t.Fatal(err)
	}
	packetConn := newBlockingRendrPacketConn(first)
	defer packetConn.Close()
	egressConn := newPeerTestPacketConn()
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register(egressName, &peerTestEgress{conn: egressConn}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&UDPPeerRelay{
			PacketConn: packetConn,
			Egresses:   registry,
			BufferSize: 128,
		}).Run(ctx)
	}()
	select {
	case got := <-egressConn.writes:
		if !bytes.Equal(got, requestPayload) {
			t.Errorf("request payload length=%d want %d", len(got), len(requestPayload))
		}
	case <-time.After(time.Second):
		t.Fatal("UDP peer relay did not forward request")
	}

	replyPayload := bytes.Repeat([]byte{0x5a}, maxUDPPeerPayloadSize)
	egressConn.reads <- peerTestPacket{
		payload: replyPayload,
		addr:    net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.20:53")),
	}
	select {
	case got := <-packetConn.writes:
		if !bytes.Equal(got, replyPayload) {
			t.Errorf("reply payload length=%d want %d", len(got), len(replyPayload))
		}
	case <-time.After(time.Second):
		t.Fatal("UDP peer relay did not forward reply")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not terminate after cancellation")
	}
}

type peerTestEgress struct {
	mu   sync.Mutex
	id   l3ingress.L3Identity
	conn *peerTestPacketConn
}

func (e *peerTestEgress) DialTCP(context.Context, l3ingress.L3Identity) (l3ingress.TCPConn, error) {
	return nil, errors.New("UDP test egress")
}

func (e *peerTestEgress) DialUDP(_ context.Context, id l3ingress.L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.mu.Lock()
	e.id = id
	e.mu.Unlock()
	return e.conn, netip.MustParseAddrPort("198.51.100.20:53"), nil
}

func (e *peerTestEgress) identity() l3ingress.L3Identity {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.id
}

type peerTestPacketConn struct {
	reads               chan peerTestPacket
	writes              chan []byte
	done                chan struct{}
	deadline            chan struct{}
	closeOnce           sync.Once
	deadOnce            sync.Once
	closeCalls          atomic.Int32
	ignoreReadDeadlines bool
}

type peerTestPacket struct {
	payload []byte
	addr    net.Addr
}

func newPeerTestPacketConn() *peerTestPacketConn {
	return &peerTestPacketConn{
		reads:    make(chan peerTestPacket, 4),
		writes:   make(chan []byte, 4),
		done:     make(chan struct{}),
		deadline: make(chan struct{}),
	}
}

func (c *peerTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.reads:
		return copy(p, packet.payload), packet.addr, nil
	case <-c.done:
		return 0, nil, io.EOF
	case <-c.deadline:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *peerTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case c.writes <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *peerTestPacketConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}
func (c *peerTestPacketConn) LocalAddr() net.Addr { return rendrPeerAddr }
func (c *peerTestPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *peerTestPacketConn) SetReadDeadline(t time.Time) error {
	if c.ignoreReadDeadlines {
		return nil
	}
	if !t.IsZero() && !t.After(time.Now()) {
		c.deadOnce.Do(func() { close(c.deadline) })
	}
	return nil
}
func (c *peerTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedRendrPacketConn struct {
	*peerTestPacketConn
	packets chan []byte
}

func newScriptedRendrPacketConn(packets ...[]byte) *scriptedRendrPacketConn {
	c := &scriptedRendrPacketConn{
		peerTestPacketConn: newPeerTestPacketConn(),
		packets:            make(chan []byte, len(packets)),
	}
	for _, packet := range packets {
		c.packets <- packet
	}
	return c
}

func (c *scriptedRendrPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.packets:
		return copy(p, packet), rendrPeerAddr, nil
	default:
		return 0, nil, io.EOF
	}
}
func (c *scriptedRendrPacketConn) Paths() []rendr.PathInfo { return nil }
func (c *scriptedRendrPacketConn) FlowID() [16]byte        { return [16]byte{1} }
func (c *scriptedRendrPacketConn) Status() rendr.Status    { return rendr.Status{} }

type blockingRendrPacketConn struct {
	*peerTestPacketConn
	packets     chan []byte
	readStarted chan struct{}
	readOnce    sync.Once
}

func newBlockingRendrPacketConn(packets ...[]byte) *blockingRendrPacketConn {
	c := &blockingRendrPacketConn{
		peerTestPacketConn: newPeerTestPacketConn(),
		packets:            make(chan []byte, len(packets)),
		readStarted:        make(chan struct{}),
	}
	for _, packet := range packets {
		c.packets <- packet
	}
	return c
}

func (c *blockingRendrPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.packets:
		return copy(p, packet), rendrPeerAddr, nil
	default:
		c.readOnce.Do(func() { close(c.readStarted) })
		return c.peerTestPacketConn.ReadFrom(p)
	}
}
func (c *blockingRendrPacketConn) Paths() []rendr.PathInfo { return nil }
func (c *blockingRendrPacketConn) FlowID() [16]byte        { return [16]byte{1} }
func (c *blockingRendrPacketConn) Status() rendr.Status    { return rendr.Status{} }
