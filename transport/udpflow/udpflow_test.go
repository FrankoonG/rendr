package udpflow

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// TestUDPFlowDialAndWrite: a manual UDP "peer" sets up at 127.0.0.1
// then DialPath produces a PathConn aimed at it. The first Write
// must arrive as a single datagram beginning with the UDP-flow
// header followed by the rendr frame bytes verbatim.
func TestUDPFlowDialAndWrite(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	tp := New()
	pcRaw, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: peer.LocalAddr().String(),
		Opts:    map[string]string{"flow_id_hex": "00112233445566"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := pcRaw.(*PathConn)
	defer pc.Close()
	claim := pc.LeafMobilityClaim()
	if claim == nil {
		t.Fatal("adapter-dialed UDP flow has no sealed ownership claim")
	}
	facts := claim.Snapshot()
	if facts.Kind != leafmobility.KindUDPFlow || facts.Role != leafmobility.RoleDialer ||
		facts.Scope != leafmobility.ScopeEndpoint || facts.Generation == 0 {
		t.Fatalf("adapter-dialed UDP flow facts=%+v", facts)
	}

	frame := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02}
	n, err := pc.Write(frame)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(frame) {
		t.Errorf("Write returned %d, want %d", n, len(frame))
	}

	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	got, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{
		proto.UDPFlowVersion,                     // VER
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // FLOW_ID
		0x00, 0x00, 0x00, 0x0A, // PAYLOAD_LEN
	}, frame...) //nolint:gocritic // intentional concat
	if !bytes.Equal(buf[:got], want) {
		t.Fatalf("on-wire datagram mismatch:\n got=%x\nwant=%x", buf[:got], want)
	}

	if got, want := pc.Writes(), uint64(1); got != want {
		t.Errorf("Writes() = %d, want %d", got, want)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if !claim.Retired() {
		t.Fatal("direct close did not retire unbound UDP-flow claim")
	}
}

// TestUDPFlowDialReadRoundTrip: the peer echoes back the same
// datagram; DialPath's PathConn.Read should strip the UDP-flow
// header and return the rendr frame bytes.
func TestUDPFlowDialReadRoundTrip(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	tp := New()
	pcRaw, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: peer.LocalAddr().String(),
		Opts:    map[string]string{"flow_id_hex": "aabbccddeeff00"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc := pcRaw.(*PathConn)
	defer pc.Close()

	frame := []byte("opaque-payload")
	if _, err := pc.Write(frame); err != nil {
		t.Fatal(err)
	}

	// Peer reads the datagram. An old-epoch copy must be ignored before the
	// valid echo is accepted on the same flow id.
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, src, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch := append([]byte(nil), buf[:n]...)
	oldEpoch[0] = 0
	if _, err := peer.WriteToUDP(oldEpoch, src); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(buf[:n], src); err != nil {
		t.Fatal(err)
	}

	// Client reads the echo and should observe only the rendr frame.
	if err := pc.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2048)
	rn, err := pc.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:rn], frame) {
		t.Fatalf("Read returned %x; want %x", got[:rn], frame)
	}
}

func TestUDPFlowOversizeRejected(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	tp := New()
	pc, err := tp.DialPath(context.Background(), transport.PathSpec{Address: peer.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.Write(make([]byte, MaxDatagram)); err == nil {
		t.Fatal("expected error for oversize frame")
	}
}

// TestUDPFlowListenerRoundTrip: Listen + Dial via the udpflow
// adapter exchange a single rendr frame each direction. Confirms
// the listener demux from a shared UDP socket and the server-side
// ServerPathConn.Write back-channel.
func TestUDPFlowListenerRoundTrip(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tp := New()
	cliRaw, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: ln.Addr().String(),
		Opts:    map[string]string{"flow_id_hex": "01020304050607"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cli := cliRaw.(*PathConn)
	defer cli.Close()

	frame := []byte("client->server")
	if _, err := cli.Write(frame); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	got := make([]byte, 1024)
	n, err := srv.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], frame) {
		t.Fatalf("server got %x want %x", got[:n], frame)
	}

	reply := []byte("server->client")
	if _, err := srv.Write(reply); err != nil {
		t.Fatal(err)
	}

	if err := cli.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got2 := make([]byte, 1024)
	rn, err := cli.Read(got2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2[:rn], reply) {
		t.Fatalf("client got %x want %x", got2[:rn], reply)
	}
}

// TestUDPFlowMigrationSameFlowFromNewTuple: send a datagram with
// the established flow_id from a fresh UDP socket. The listener
// should re-route to the existing ServerPathConn and update its
// RemoteAddr - the engine / application sees no event.
func TestUDPFlowMigrationSameFlowFromNewTuple(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tp := New()
	cli, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: ln.Addr().String(),
		Opts:    map[string]string{"flow_id_hex": "deadbeefcafe00"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := srv.RemoteAddr()
	buf := make([]byte, 64)
	if _, err := srv.Read(buf); err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()

	// New 4-tuple: hand-construct a UDP datagram with same flow_id.
	cli2, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: ln.Addr().String(),
		Opts:    map[string]string{"flow_id_hex": "deadbeefcafe00"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli2.Close()
	if _, err := cli2.Write([]byte("migrated")); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Read(buf); err != nil {
		t.Fatal(err)
	}
	second := srv.RemoteAddr()
	if first == second {
		t.Fatalf("expected migrated remote addr; both are %s", first)
	}
}

func TestUDPFlowRandomFlowID(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	tp := New()
	pcRaw, err := tp.DialPath(context.Background(), transport.PathSpec{Address: peer.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	pc := pcRaw.(*PathConn)
	defer pc.Close()
	var zero [proto.UDPFlowIDSize]byte
	if pc.FlowID() == zero {
		t.Fatal("random flow id came out all-zero")
	}

	t.Run("wrap error retains caller ownership", func(t *testing.T) {
		raw := &wrapOwnershipPacketConn{}
		wrapped, err := WrapFromSpec(raw, transport.PathSpec{Address: "not-a-host-port"}, MaxDatagram)
		if err == nil || wrapped != nil {
			t.Fatalf("WrapFromSpec result/error=%v/%v want nil/non-nil", wrapped, err)
		}
		if closes := raw.closes.Load(); closes != 0 {
			t.Fatalf("WrapFromSpec error closed caller PacketConn %d times", closes)
		}
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}
		if closes := raw.closes.Load(); closes != 1 {
			t.Fatalf("caller cleanup count=%d want=1", closes)
		}
	})
}

func TestPacketAsConnDropsWrongAndHostileSourcesWithMatchingFlowID(t *testing.T) {
	flowID := [proto.UDPFlowIDSize]byte{1, 2, 3, 4, 5, 6, 7}
	peer := udpflowTestAddr("peer")
	snapshot, err := SnapshotPeer(peer)
	if err != nil {
		t.Fatal(err)
	}
	raw := &sourceFilteringPacketConn{reads: make(chan sourceFilteringRead, 3)}
	path, err := Wrap(raw, snapshot, flowID, MaxDatagram)
	if err != nil {
		t.Fatal(err)
	}
	defer path.Close()
	if claim := path.LeafMobilityClaim(); claim != nil {
		t.Fatalf("external PacketConn wrapper fabricated ownership claim: %+v", claim.Snapshot())
	}

	var hostileCalls atomic.Int32
	raw.reads <- sourceFilteringRead{packet: udpflowTestPacket(t, flowID, []byte("wrong-source")), source: udpflowTestAddr("attacker")}
	raw.reads <- sourceFilteringRead{packet: udpflowTestPacket(t, flowID, []byte("panic-source")), source: hostileUDPFlowAddr{calls: &hostileCalls}}
	raw.reads <- sourceFilteringRead{packet: udpflowTestPacket(t, flowID, []byte("accepted")), source: snapshot.Identity()}

	buffer := make([]byte, 64)
	n, err := path.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "accepted" {
		t.Fatalf("accepted payload=%q want accepted", got)
	}
	if got := raw.readCalls.Load(); got != 3 {
		t.Fatalf("ReadFrom calls=%d want 3", got)
	}
	if got := hostileCalls.Load(); got != 0 {
		t.Fatalf("runtime matching invoked hostile source address methods %d times", got)
	}
}

func TestPacketAsConnStandardPeerRejectsCustomStringSpoofWithoutCallbacks(t *testing.T) {
	flowID := [proto.UDPFlowIDSize]byte{7, 6, 5, 4, 3, 2, 1}
	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4242, Zone: "zone"}
	snapshot, err := SnapshotPeer(peer)
	if err != nil {
		t.Fatal(err)
	}
	raw := &sourceFilteringPacketConn{reads: make(chan sourceFilteringRead, 2)}
	path, err := Wrap(raw, snapshot, flowID, MaxDatagram)
	if err != nil {
		t.Fatal(err)
	}
	defer path.Close()
	var hostileCalls atomic.Int32
	raw.reads <- sourceFilteringRead{
		packet: udpflowTestPacket(t, flowID, []byte("spoof")),
		source: hostileUDPFlowAddr{calls: &hostileCalls},
	}
	raw.reads <- sourceFilteringRead{
		packet: udpflowTestPacket(t, flowID, []byte("accepted")),
		source: &net.UDPAddr{IP: net.ParseIP("192.0.2.10").To4(), Port: 4242, Zone: "zone"},
	}
	buffer := make([]byte, 64)
	n, err := path.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "accepted" {
		t.Fatalf("accepted payload=%q want accepted", got)
	}
	if got := hostileCalls.Load(); got != 0 {
		t.Fatalf("runtime matching invoked custom string spoof methods %d times", got)
	}
}

func udpflowTestPacket(t *testing.T, flowID [proto.UDPFlowIDSize]byte, payload []byte) []byte {
	t.Helper()
	packet := make([]byte, proto.UDPFlowHeaderSize+len(payload))
	header := proto.UDPFlowHeader{Version: proto.UDPFlowVersion, FlowID: flowID, PayloadSize: uint32(len(payload))}
	if err := header.Encode(packet[:proto.UDPFlowHeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(packet[proto.UDPFlowHeaderSize:], payload)
	return packet
}

type udpflowTestAddr string

func (udpflowTestAddr) Network() string     { return "udpflow-test" }
func (addr udpflowTestAddr) String() string { return string(addr) }

type hostileUDPFlowAddr struct{ calls *atomic.Int32 }

func (addr hostileUDPFlowAddr) Network() string {
	addr.calls.Add(1)
	panic("hostile Network")
}
func (addr hostileUDPFlowAddr) String() string {
	addr.calls.Add(1)
	panic("hostile String")
}

type sourceFilteringRead struct {
	packet []byte
	source net.Addr
	err    error
}

type sourceFilteringPacketConn struct {
	reads     chan sourceFilteringRead
	readCalls atomic.Int32
	closed    atomic.Bool
}

func (conn *sourceFilteringPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	conn.readCalls.Add(1)
	result := <-conn.reads
	return copy(buffer, result.packet), result.source, result.err
}
func (*sourceFilteringPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}
func (conn *sourceFilteringPacketConn) Close() error {
	conn.closed.Store(true)
	return nil
}
func (*sourceFilteringPacketConn) LocalAddr() net.Addr              { return udpflowTestAddr("local") }
func (*sourceFilteringPacketConn) SetDeadline(time.Time) error      { return nil }
func (*sourceFilteringPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*sourceFilteringPacketConn) SetWriteDeadline(time.Time) error { return nil }

type wrapOwnershipPacketConn struct{ closes atomic.Int32 }

func (*wrapOwnershipPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*wrapOwnershipPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (pc *wrapOwnershipPacketConn) Close() error {
	pc.closes.Add(1)
	return nil
}
func (*wrapOwnershipPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*wrapOwnershipPacketConn) SetDeadline(time.Time) error      { return nil }
func (*wrapOwnershipPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*wrapOwnershipPacketConn) SetWriteDeadline(time.Time) error { return nil }
