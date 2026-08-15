package l3ingress

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestParseIPv4TCPIdentity(t *testing.T) {
	pkt := ipv4Packet(6, [4]byte{10, 0, 0, 1}, [4]byte{203, 0, 113, 9}, 12345, 443)
	pkt[33] = TCPFlagSYN | TCPFlagACK
	meta, err := ParsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	want := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("203.0.113.9"),
		DstPort: 443,
	}
	if meta.Identity != want {
		t.Fatalf("identity: got %+v want %+v", meta.Identity, want)
	}
	if meta.IPVersion != 4 || meta.PayloadOffset != 20 || meta.PayloadLen != 20 {
		t.Fatalf("bad meta: %+v", meta)
	}
	if got := want.Reverse(); got.SrcPort != 443 || got.DstPort != 12345 {
		t.Fatalf("reverse ports: %+v", got)
	}
	if meta.TCPFlags != TCPFlagSYN|TCPFlagACK {
		t.Fatalf("tcp flags=%02x", meta.TCPFlags)
	}
	if reason, ok := TCPFlowCloseReason(meta); ok || reason != "" {
		t.Fatalf("unexpected close reason=%q ok=%v", reason, ok)
	}
}

func TestParseTCPCloseFlags(t *testing.T) {
	pkt := ipv4Packet(6, [4]byte{10, 0, 0, 1}, [4]byte{203, 0, 113, 9}, 12345, 443)
	pkt[33] = TCPFlagFIN
	meta, err := ParsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if reason, ok := TCPFlowCloseReason(meta); !ok || reason != FlowCloseTCPFIN {
		t.Fatalf("fin reason=%q ok=%v", reason, ok)
	}
	pkt[33] = TCPFlagRST
	meta, err = ParsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if reason, ok := TCPFlowCloseReason(meta); !ok || reason != FlowCloseTCPRST {
		t.Fatalf("rst reason=%q ok=%v", reason, ok)
	}
}

func TestParseIPv6UDPIdentity(t *testing.T) {
	pkt := ipv6Packet(17, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 4444, 5555)
	meta, err := ParsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if meta.IPVersion != 6 || meta.PayloadOffset != 40 || meta.PayloadLen != 8 {
		t.Fatalf("bad ipv6 meta: %+v", meta)
	}
	if meta.Identity.Proto != ProtocolUDP || meta.Identity.SrcPort != 4444 || meta.Identity.DstPort != 5555 {
		t.Fatalf("bad ipv6 identity: %+v", meta.Identity)
	}
}

func TestParseIPv6RejectsSecurityHeadersBeforePayloadClassification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		protocol   byte
		forgedNext byte
	}{
		{name: "esp-forged-tcp", protocol: 50, forgedNext: byte(ProtocolTCP)},
		{name: "ah-forged-udp", protocol: 51, forgedNext: byte(ProtocolUDP)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := ipv6Packet(tc.protocol, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1234, 443)
			pkt[40] = tc.forgedNext
			pkt[41] = 0

			_, err := ParsePacket(pkt)
			assertReason(t, err, ReasonUnsupportedProtocol)
		})
	}
}

func TestParseIPv6RejectsSecurityHeadersAfterExtension(t *testing.T) {
	for _, protocol := range []byte{50, 51} {
		pkt := make([]byte, 56)
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], 16)
		pkt[6] = 60
		pkt[40] = protocol
		pkt[41] = 0
		pkt[48] = byte(ProtocolUDP)
		binary.BigEndian.PutUint16(pkt[49:51], 0x1122)
		binary.BigEndian.PutUint16(pkt[51:53], 0x3344)

		_, err := ParsePacket(pkt)
		assertReason(t, err, ReasonUnsupportedProtocol)
	}
}

func TestParseIPv6SecurityHeaderTruncationIsBounded(t *testing.T) {
	for _, protocol := range []byte{50, 51} {
		t.Run(Protocol(protocol).String(), func(t *testing.T) {
			withoutPayload := make([]byte, 40)
			withoutPayload[0] = 0x60
			withoutPayload[6] = protocol
			_, err := ParsePacket(withoutPayload)
			assertReason(t, err, ReasonUnsupportedProtocol)

			truncated := append([]byte(nil), withoutPayload...)
			binary.BigEndian.PutUint16(truncated[4:6], 8)
			_, err = ParsePacket(truncated)
			assertReason(t, err, ReasonShortPacket)
		})
	}
}

func TestParseIPv6ExtensionCannotConsumeBytesBeyondDeclaredPayload(t *testing.T) {
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[6] = 60 // destination options, but declared payload length is zero
	packet[40] = byte(ProtocolUDP)
	packet[41] = 0

	_, err := ParsePacket(packet)
	assertReason(t, err, ReasonShortPacket)
}

func TestParseRejectsUnsupportedProtocol(t *testing.T) {
	pkt := ipv4Packet(47, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 0, 0)
	_, err := ParsePacket(pkt)
	assertReason(t, err, ReasonUnsupportedProtocol)
}

func TestParseRejectsShortPacket(t *testing.T) {
	_, err := ParsePacket([]byte{0x45, 0, 0})
	assertReason(t, err, ReasonShortPacket)
}

func assertReason(t *testing.T, err error, reason ParseReason) {
	t.Helper()
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("got %T %v, want ParseError", err, err)
	}
	if pe.Reason != reason {
		t.Fatalf("reason=%s want %s (%v)", pe.Reason, reason, err)
	}
}

func ipv4Packet(proto byte, src, dst [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

func ipv6Packet(proto byte, src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 8)
	pkt[6] = proto
	src16 := src.As16()
	dst16 := dst.As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	return pkt
}
