package udpflow

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

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
		0x00,                                     // VER
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // FLOW_ID
	}, frame...) //nolint:gocritic // intentional concat
	if !bytes.Equal(buf[:got], want) {
		t.Fatalf("on-wire datagram mismatch:\n got=%x\nwant=%x", buf[:got], want)
	}

	if got, want := pc.Writes(), uint64(1); got != want {
		t.Errorf("Writes() = %d, want %d", got, want)
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

	// Peer reads the datagram and echoes it back verbatim.
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, src, err := peer.ReadFromUDP(buf)
	if err != nil {
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
