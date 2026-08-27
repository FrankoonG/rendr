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

func TestBuildUDPPacketIPv6EncodesComputedZeroChecksumAsFFFF(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP,
		SrcIP: netip.MustParseAddr("2001:db8:1::10"), SrcPort: 31000,
		DstIP: netip.MustParseAddr("2001:db8:2::20"), DstPort: 32000,
	}
	var packet []byte
	for candidate := 0; candidate <= 0xffff; candidate++ {
		payload := []byte{byte(candidate >> 8), byte(candidate)}
		got := mustBuildUDPPacket(t, id, payload)
		probe := append([]byte(nil), got...)
		probe[46], probe[47] = 0, 0
		if independentUDPv6Checksum(probe) == 0 {
			packet = got
			break
		}
	}
	if packet == nil {
		t.Fatal("failed to brute-force an IPv6 UDP checksum-zero payload")
	}
	if got := binary.BigEndian.Uint16(packet[46:48]); got != 0xffff {
		t.Fatalf("wire checksum=%#04x want 0xffff", got)
	}
	if got := independentUDPv6Checksum(packet); got != 0 {
		t.Fatalf("independent checksum verification=%#04x want 0", got)
	}
}

func independentUDPv6Checksum(packet []byte) uint16 {
	udpLen := int(binary.BigEndian.Uint16(packet[44:46]))
	words := make([]byte, 40+udpLen)
	copy(words[0:16], packet[8:24])
	copy(words[16:32], packet[24:40])
	binary.BigEndian.PutUint32(words[32:36], uint32(udpLen))
	words[39] = 17
	copy(words[40:], packet[40:40+udpLen])
	var sum uint64
	for index := 0; index+1 < len(words); index += 2 {
		sum += uint64(words[index])<<8 | uint64(words[index+1])
	}
	if len(words)%2 != 0 {
		sum += uint64(words[len(words)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
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
