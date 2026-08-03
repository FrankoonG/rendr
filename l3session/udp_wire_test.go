package l3session

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/l3ingress"
)

func TestUDPEnvelopeRoundTrip(t *testing.T) {
	identities := []l3ingress.L3Identity{
		{
			Proto:   l3ingress.ProtocolUDP,
			SrcIP:   netip.MustParseAddr("192.0.2.10"),
			SrcPort: 42000,
			DstIP:   netip.MustParseAddr("198.51.100.20"),
			DstPort: 53,
		},
		{
			Proto:   l3ingress.ProtocolUDP,
			SrcIP:   netip.MustParseAddr("2001:db8::10"),
			SrcPort: 42000,
			DstIP:   netip.MustParseAddr("2001:db8::20"),
			DstPort: 53,
		},
	}
	for _, id := range identities {
		packet, err := appendUDPEnvelope([]byte("prefix"), id, "vpn-egress", []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		if string(packet[:6]) != "prefix" {
			t.Fatalf("prefix changed: %q", packet[:6])
		}
		decoded, err := decodeUDPEnvelope(packet[6:])
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Identity != id || decoded.Egress != "vpn-egress" || !bytes.Equal(decoded.Payload, []byte("payload")) {
			t.Fatalf("decoded=%+v", decoded)
		}
	}
}

func TestUDPEnvelopeRejectsMalformedAndChangingMetadata(t *testing.T) {
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("198.51.100.1"),
		SrcPort: 1, DstPort: 2,
	}
	valid, err := appendUDPEnvelope(nil, id, "direct", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		packet func() []byte
		want   string
	}{
		{name: "short", packet: func() []byte { return valid[:4] }, want: "too short"},
		{name: "magic", packet: func() []byte { p := append([]byte(nil), valid...); p[0] ^= 1; return p }, want: "magic"},
		{name: "version", packet: func() []byte { p := append([]byte(nil), valid...); p[4]++; return p }, want: "version"},
		{name: "flags", packet: func() []byte { p := append([]byte(nil), valid...); p[5] = 1; return p }, want: "flags"},
		{name: "egress overrun", packet: func() []byte { p := append([]byte(nil), valid...); p[6], p[7] = 0x04, 0x00; return p }, want: "overruns"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeUDPEnvelope(tt.packet())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
	if _, err := appendUDPEnvelope(nil, id, "", nil); err == nil {
		t.Fatal("empty egress accepted")
	}
	tcpID := id
	tcpID.Proto = l3ingress.ProtocolTCP
	if _, err := appendUDPEnvelope(nil, tcpID, "direct", nil); err == nil {
		t.Fatal("TCP identity accepted in UDP envelope")
	}
}
