package l3session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

type terminalPacketRead struct {
	payload []byte
	addr    net.Addr
	err     error
}

type terminalRendrPacketConn struct {
	mu        sync.Mutex
	reads     []terminalPacketRead
	writes    [][]byte
	readCalls atomic.Int32
	closed    atomic.Bool
}

func (conn *terminalRendrPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	conn.readCalls.Add(1)
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.reads) == 0 {
		return 0, nil, io.EOF
	}
	read := conn.reads[0]
	conn.reads = conn.reads[1:]
	return copy(payload, read.payload), read.addr, read.err
}
func (conn *terminalRendrPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	conn.mu.Lock()
	conn.writes = append(conn.writes, bytes.Clone(payload))
	conn.mu.Unlock()
	return len(payload), nil
}
func (conn *terminalRendrPacketConn) Close() error {
	conn.closed.Store(true)
	return nil
}
func (*terminalRendrPacketConn) LocalAddr() net.Addr              { return packetAddr("terminal-local") }
func (*terminalRendrPacketConn) SetDeadline(time.Time) error      { return nil }
func (*terminalRendrPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*terminalRendrPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (*terminalRendrPacketConn) Paths() []rendr.PathInfo          { return nil }
func (*terminalRendrPacketConn) FlowID() [16]byte                 { return [16]byte{1} }
func (*terminalRendrPacketConn) Status() rendr.Status             { return rendr.Status{} }

func (conn *terminalRendrPacketConn) writeSnapshot() [][]byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	result := make([][]byte, len(conn.writes))
	for index := range conn.writes {
		result[index] = bytes.Clone(conn.writes[index])
	}
	return result
}

type terminalPacketEgress struct {
	conn   net.PacketConn
	remote netip.AddrPort
}

func (*terminalPacketEgress) DialTCP(context.Context, l3ingress.L3Identity) (l3ingress.TCPConn, error) {
	return nil, errors.New("UDP-only terminal test egress")
}
func (egress *terminalPacketEgress) DialUDP(
	context.Context,
	l3ingress.L3Identity,
) (net.PacketConn, netip.AddrPort, error) {
	return egress.conn, egress.remote, nil
}

func terminalUDPIdentity() l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.70"), SrcPort: 47000,
		DstIP: netip.MustParseAddr("198.51.100.70"), DstPort: 53,
	}
}

func TestUDPPeerRelayInitialReadDeliversNBeforeTerminalError(t *testing.T) {
	id := terminalUDPIdentity()
	envelope, err := appendUDPEnvelope(nil, id, "terminal", []byte("initial-final"))
	if err != nil {
		t.Fatal(err)
	}
	terminalErr := errors.New("initial read terminal")
	rendrConn := &terminalRendrPacketConn{reads: []terminalPacketRead{{
		payload: envelope, addr: rendrPeerAddr, err: terminalErr,
	}}}
	egressConn := &terminalRendrPacketConn{}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("terminal", &terminalPacketEgress{
		conn: egressConn, remote: netip.MustParseAddrPort("198.51.100.70:53"),
	}); err != nil {
		t.Fatal(err)
	}
	err = (&UDPPeerRelay{PacketConn: rendrConn, Egresses: registry}).Run(context.Background())
	if !errors.Is(err, terminalErr) {
		t.Fatalf("Run error=%v want terminal error", err)
	}
	writes := egressConn.writeSnapshot()
	if len(writes) != 1 || string(writes[0]) != "initial-final" {
		t.Fatalf("egress writes=%q want one final payload", writes)
	}
	if got := rendrConn.readCalls.Load(); got != 1 {
		t.Fatalf("initial ReadFrom calls=%d want 1", got)
	}
}

func TestUDPPeerRelayRequestReadDeliversNBeforeTerminalError(t *testing.T) {
	id := terminalUDPIdentity()
	first := udpEnvelope{Identity: id, Egress: "terminal", Payload: []byte("first")}
	wire, err := appendUDPEnvelope(nil, id, "terminal", []byte("request-final"))
	if err != nil {
		t.Fatal(err)
	}
	terminalErr := errors.New("request read terminal")
	rendrConn := &terminalRendrPacketConn{reads: []terminalPacketRead{{
		payload: wire, addr: rendrPeerAddr, err: terminalErr,
	}}}
	egressConn := &terminalRendrPacketConn{}
	relay := &UDPPeerRelay{}
	err = relay.forwardUDPRequests(
		context.Background(),
		first,
		newDataPlanePacket(rendrConn, "request source", nil),
		newDataPlanePacket(egressConn, "request destination", egressConn.Close),
		netip.MustParseAddrPort("198.51.100.70:53"),
		defaultUDPPeerBufferSize,
	)
	if !errors.Is(err, terminalErr) {
		t.Fatalf("forward error=%v want terminal error", err)
	}
	writes := egressConn.writeSnapshot()
	if len(writes) != 1 || string(writes[0]) != "request-final" {
		t.Fatalf("egress writes=%q want one final payload", writes)
	}
	if got := rendrConn.readCalls.Load(); got != 1 {
		t.Fatalf("request ReadFrom calls=%d want 1", got)
	}
}

func TestUDPPeerRelayReplyReadDeliversNBeforeTerminalError(t *testing.T) {
	remote := netip.MustParseAddrPort("198.51.100.70:53")
	terminalErr := errors.New("reply read terminal")
	egressConn := &terminalRendrPacketConn{reads: []terminalPacketRead{{
		payload: []byte("reply-final"), addr: net.UDPAddrFromAddrPort(remote), err: terminalErr,
	}}}
	rendrConn := &terminalRendrPacketConn{}
	relay := &UDPPeerRelay{}
	err := relay.forwardUDPReplies(
		context.Background(),
		newDataPlanePacket(rendrConn, "reply destination", nil),
		newDataPlanePacket(egressConn, "reply source", egressConn.Close),
		remote,
		defaultUDPPeerBufferSize,
	)
	if !errors.Is(err, terminalErr) {
		t.Fatalf("forward error=%v want terminal error", err)
	}
	writes := rendrConn.writeSnapshot()
	if len(writes) != 1 || string(writes[0]) != "reply-final" {
		t.Fatalf("rendr writes=%q want one final payload", writes)
	}
	if got := egressConn.readCalls.Load(); got != 1 {
		t.Fatalf("reply ReadFrom calls=%d want 1", got)
	}
}

func TestUDPRelayReplyReadDeliversNBeforeTerminalError(t *testing.T) {
	id := terminalUDPIdentity()
	terminalErr := errors.New("local reply terminal")
	packetConn := &terminalRendrPacketConn{reads: []terminalPacketRead{{
		payload: []byte("local-final"), addr: rendrPeerAddr, err: terminalErr,
	}}}
	sess := &Session{
		request: l3ingress.SessionRequest{
			Identity: id,
			Ref:      l3ingress.FlowRef{Identity: id, Generation: 1},
		},
		packetConn: packetConn,
	}
	manager := &Manager{sessions: map[l3ingress.L3Identity]*Session{id: sess}}
	device := &packetCaptureDevice{writes: make(chan []byte, 1)}
	relay := &UDPRelay{
		Device: device, Manager: manager,
		packets: map[l3ingress.L3Identity]*Session{id: sess},
	}
	relay.readReplies(context.Background(), id, sess)
	select {
	case packet := <-device.writes:
		meta, err := l3ingress.ParsePacket(packet)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := l3ingress.UDPPayload(packet, meta)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != "local-final" {
			t.Fatalf("payload=%q", payload)
		}
	default:
		t.Fatal("final local reply was not delivered")
	}
	if got := packetConn.readCalls.Load(); got != 1 {
		t.Fatalf("local ReadFrom calls=%d want 1", got)
	}
}
