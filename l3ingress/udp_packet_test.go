package l3ingress

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestUDPPayloadExtractsData(t *testing.T) {
	packet := mustBuildUDPPacket(t, L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 10001,
		DstIP:   netip.MustParseAddr("198.51.100.1"),
		DstPort: 53,
	}, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := UDPPayload(packet, meta)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "query" {
		t.Fatalf("payload=%q", payload)
	}
}

func TestBuildUDPPacketRoundTripIPv4(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("192.0.2.20"),
		DstPort: 53000,
	}
	packet := mustBuildUDPPacket(t, id, []byte("answer"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Identity != id {
		t.Fatalf("identity=%+v want %+v", meta.Identity, id)
	}
	payload, err := UDPPayload(packet, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("answer")) {
		t.Fatalf("payload=%q", payload)
	}
}

func TestAppendUDPPacketReusesBuffer(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("192.0.2.20"),
		DstPort: 53000,
	}
	buf := make([]byte, 0, 1500)
	first, err := AppendUDPPacket(buf, id, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	firstCap := cap(first)
	second, err := AppendUDPPacket(first[:0], id, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if cap(second) != firstCap {
		t.Fatalf("cap changed from %d to %d", firstCap, cap(second))
	}
	meta, err := ParsePacket(second)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := UDPPayload(second, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("two")) {
		t.Fatalf("payload=%q", payload)
	}
}

func TestBuildUDPPacketRoundTripIPv6(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("2001:db8::10"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("2001:db8::20"),
		DstPort: 53000,
	}
	packet := mustBuildUDPPacket(t, id, []byte("answer6"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Identity != id {
		t.Fatalf("identity=%+v want %+v", meta.Identity, id)
	}
	payload, err := UDPPayload(packet, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("answer6")) {
		t.Fatalf("payload=%q", payload)
	}
}

func TestBuildUDPPacketIPv4PayloadBoundary(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("192.0.2.20"),
		DstPort: 53000,
	}
	const maxPayload = 0xffff - 20 - 8
	payload := bytes.Repeat([]byte{0xa5}, maxPayload)
	packet := mustBuildUDPPacket(t, id, payload)
	if got, want := len(packet), 0xffff; got != want {
		t.Fatalf("packet length=%d want %d", got, want)
	}
	if got, want := int(binary.BigEndian.Uint16(packet[2:4])), len(packet); got != want {
		t.Fatalf("ipv4 total length=%d want %d", got, want)
	}
	if got, want := int(binary.BigEndian.Uint16(packet[24:26])), 8+maxPayload; got != want {
		t.Fatalf("udp length=%d want %d", got, want)
	}
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, err := UDPPayload(packet, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatal("maximum IPv4 UDP payload did not round trip")
	}

	_, err = BuildUDPPacket(id, make([]byte, maxPayload+1))
	assertReason(t, err, ReasonInvalidHeader)
}

func TestBuildUDPPacketIPv6PayloadBoundary(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("2001:db8::10"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("2001:db8::20"),
		DstPort: 53000,
	}
	const maxPayload = 0xffff - 8
	payload := bytes.Repeat([]byte{0x5a}, maxPayload)
	packet := mustBuildUDPPacket(t, id, payload)
	if got, want := len(packet), 40+0xffff; got != want {
		t.Fatalf("packet length=%d want %d", got, want)
	}
	if got, want := int(binary.BigEndian.Uint16(packet[4:6])), 0xffff; got != want {
		t.Fatalf("ipv6 payload length=%d want %d", got, want)
	}
	if got, want := int(binary.BigEndian.Uint16(packet[44:46])), 0xffff; got != want {
		t.Fatalf("udp length=%d want %d", got, want)
	}
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, err := UDPPayload(packet, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatal("maximum IPv6 UDP payload did not round trip")
	}

	_, err = BuildUDPPacket(id, make([]byte, maxPayload+1))
	assertReason(t, err, ReasonInvalidHeader)
}

func mustBuildUDPPacket(t *testing.T, id L3Identity, payload []byte) []byte {
	t.Helper()
	packet, err := BuildUDPPacket(id, payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
