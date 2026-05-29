package l3ingress

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/virtualif"
)

func TestIdentityWireRoundTripIPv4(t *testing.T) {
	want := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.1.2.3"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("198.51.100.9"),
		DstPort: 443,
	}
	enc, err := want.EncodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != IdentityWireSize {
		t.Fatalf("wire size=%d want %d", len(enc), IdentityWireSize)
	}
	got, err := DecodeIdentity(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("identity: got %+v want %+v", got, want)
	}
}

func TestIdentityWireRoundTripIPv6(t *testing.T) {
	want := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("2001:db8::1"),
		SrcPort: 4444,
		DstIP:   netip.MustParseAddr("2001:db8::2"),
		DstPort: 5555,
	}
	enc, err := want.EncodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeIdentity(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("identity: got %+v want %+v", got, want)
	}
}

func TestIdentityWireRejectsMixedFamilies(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolTCP,
		SrcIP: netip.MustParseAddr("10.0.0.1"),
		DstIP: netip.MustParseAddr("2001:db8::1"),
	}
	if _, err := id.EncodeBinary(); err == nil {
		t.Fatal("mixed address families accepted")
	}
}

func TestRequirePeerL3Identity(t *testing.T) {
	if err := RequirePeerL3Identity(proto.CapsL3Identity); err != nil {
		t.Fatal(err)
	}
	err := RequirePeerL3Identity(0)
	var ve *virtualif.Error
	if !errors.As(err, &ve) {
		t.Fatalf("got %T %v, want virtualif.Error", err, err)
	}
	if ve.Reason != virtualif.ReasonPeerL3IdentityUnsupported {
		t.Fatalf("reason=%s want %s", ve.Reason, virtualif.ReasonPeerL3IdentityUnsupported)
	}
}

func TestRequirePeerEgress(t *testing.T) {
	if err := RequirePeerEgress(true); err != nil {
		t.Fatal(err)
	}
	err := RequirePeerEgress(false)
	var ve *virtualif.Error
	if !errors.As(err, &ve) {
		t.Fatalf("got %T %v, want virtualif.Error", err, err)
	}
	if ve.Reason != virtualif.ReasonPeerEgressUnsupported {
		t.Fatalf("reason=%s want %s", ve.Reason, virtualif.ReasonPeerEgressUnsupported)
	}
}
