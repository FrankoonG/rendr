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

func TestParseIPv4UDPMoreFragmentFirstFragment(t *testing.T) {
	pkt := ipv4Packet(17, [4]byte{192, 0, 2, 10}, [4]byte{198, 51, 100, 20}, 5353, 53000)
	flagsFrag := uint16(0x2000)
	binary.BigEndian.PutUint16(pkt[6:8], flagsFrag)
	meta, err := ParsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.Fragmented || !meta.MoreFragments || meta.FragmentOffset != 0 {
		t.Fatalf("fragment flags not preserved: %+v", meta)
	}
	if meta.Identity.Proto != ProtocolUDP || meta.Identity.SrcPort != 5353 || meta.Identity.DstPort != 53000 {
		t.Fatalf("udp identity: %+v", meta.Identity)
	}
}

func TestParseRejectsIPv4NonInitialFragment(t *testing.T) {
	pkt := ipv4Packet(17, [4]byte{192, 0, 2, 10}, [4]byte{198, 51, 100, 20}, 1, 2)
	binary.BigEndian.PutUint16(pkt[6:8], 1)
	_, err := ParsePacket(pkt)
	assertReason(t, err, ReasonNonInitialFragment)
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
