package l3ingress

import (
	"bytes"
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

func TestIdentityWireRejectsAddressAliasesAndZones(t *testing.T) {
	for _, id := range []L3Identity{
		{
			Proto: ProtocolTCP, SrcIP: netip.MustParseAddr("::ffff:192.0.2.1"),
			DstIP: netip.MustParseAddr("::ffff:198.51.100.1"),
		},
		{
			Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("fe80::1%ingress0"),
			DstIP: netip.MustParseAddr("fe80::2%egress0"),
		},
	} {
		if _, err := id.EncodeBinary(); !errors.Is(err, ErrNonCanonicalIdentity) {
			t.Fatalf("EncodeBinary(%+v) error=%v, want ErrNonCanonicalIdentity", id, err)
		}
	}
}

func TestIdentityWireRejectsNonCanonicalRecords(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 1234,
		DstIP: netip.MustParseAddr("198.51.100.1"), DstPort: 4321,
	}
	valid, err := id.EncodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	mapped := id
	mapped.SrcIP = netip.MustParseAddr("::ffff:192.0.2.1")
	mapped.DstIP = netip.MustParseAddr("::ffff:198.51.100.1")
	mappedRecord := append([]byte(nil), valid...)
	mappedRecord[2] = addrFamily6
	copy(mappedRecord[8:24], mapped.SrcIP.AsSlice())
	copy(mappedRecord[24:40], mapped.DstIP.AsSlice())

	tests := map[string][]byte{
		"trailing data":       append(append([]byte(nil), valid...), 0),
		"reserved byte":       mutateIdentityRecord(valid, 3),
		"IPv4 source padding": mutateIdentityRecord(valid, 12),
		"IPv4 target padding": mutateIdentityRecord(valid, 28),
		"IPv4 mapped alias":   mappedRecord,
	}
	for name, record := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeIdentity(record); err == nil {
				t.Fatal("accepted a non-canonical identity record")
			}
		})
	}
	if got, err := DecodeIdentity(valid); err != nil || got != id {
		t.Fatalf("canonical record decoded as %+v, %v", got, err)
	}
}

func mutateIdentityRecord(record []byte, offset int) []byte {
	mutated := bytes.Clone(record)
	mutated[offset] = 1
	return mutated
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
