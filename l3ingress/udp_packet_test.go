package l3ingress

import (
	"bytes"
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

func mustBuildUDPPacket(t *testing.T, id L3Identity, payload []byte) []byte {
	t.Helper()
	packet, err := BuildUDPPacket(id, payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
