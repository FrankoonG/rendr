package udpflow

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// TestUDPFlowDialAndWrite: a manual UDP "peer" sets up at 127.0.0.1
// then DialPath produces a PathConn aimed at it. The first Write
// must arrive as a single datagram beginning with the 8-byte flow
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
// datagram; DialPath's PathConn.Read should strip the 8-byte
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
}
