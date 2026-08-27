package l3ingress

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/virtualif"
)

// ErrNonCanonicalIdentity means an identity has more than one routing or wire
// representation. The codec rejects aliases instead of silently normalizing
// session keys.
var ErrNonCanonicalIdentity = errors.New("l3ingress: non-canonical identity")

const (
	identityWireVersion = 1
	addrFamily4         = 4
	addrFamily6         = 6

	// IdentityWireSize is the stable binary size of one L3Identity
	// metadata record.
	IdentityWireSize = 40
)

// EncodeBinary encodes id into a fixed-size wire metadata record.
func (id L3Identity) EncodeBinary() ([]byte, error) {
	b, err := id.AppendBinary(nil)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// AppendBinary appends id's wire metadata record to dst.
func (id L3Identity) AppendBinary(dst []byte) ([]byte, error) {
	family, src, dstIP, err := identityAddrBytes(id)
	if err != nil {
		return dst, err
	}
	record := make([]byte, IdentityWireSize)
	record[0] = identityWireVersion
	record[1] = byte(id.Proto)
	record[2] = family
	binary.BigEndian.PutUint16(record[4:6], id.SrcPort)
	binary.BigEndian.PutUint16(record[6:8], id.DstPort)
	copy(record[8:24], src[:])
	copy(record[24:40], dstIP[:])
	return append(dst, record...), nil
}

// DecodeIdentity decodes one fixed-size L3Identity metadata record.
func DecodeIdentity(b []byte) (L3Identity, error) {
	if len(b) != IdentityWireSize {
		return L3Identity{}, fmt.Errorf("l3ingress: identity metadata size %d, want %d", len(b), IdentityWireSize)
	}
	if b[0] != identityWireVersion {
		return L3Identity{}, fmt.Errorf("l3ingress: unsupported identity metadata version %d", b[0])
	}
	family := b[2]
	id := L3Identity{
		Proto:   Protocol(b[1]),
		SrcPort: binary.BigEndian.Uint16(b[4:6]),
		DstPort: binary.BigEndian.Uint16(b[6:8]),
	}
	switch family {
	case addrFamily4:
		var src4 [4]byte
		var dst4 [4]byte
		copy(src4[:], b[8:12])
		copy(dst4[:], b[24:28])
		id.SrcIP = netip.AddrFrom4(src4)
		id.DstIP = netip.AddrFrom4(dst4)
	case addrFamily6:
		var src16 [16]byte
		var dst16 [16]byte
		copy(src16[:], b[8:24])
		copy(dst16[:], b[24:40])
		id.SrcIP = netip.AddrFrom16(src16)
		id.DstIP = netip.AddrFrom16(dst16)
	default:
		return L3Identity{}, fmt.Errorf("l3ingress: unsupported address family %d", family)
	}
	canonical, err := id.EncodeBinary()
	if err != nil {
		return L3Identity{}, err
	}
	if !bytes.Equal(canonical, b) {
		return L3Identity{}, fmt.Errorf("%w: reserved or padding bytes are non-zero", ErrNonCanonicalIdentity)
	}
	return id, nil
}

// RequirePeerL3Identity validates that a peer advertised L3 identity
// metadata support before a PreserveL3Identity flow is accepted.
func RequirePeerL3Identity(peerCaps uint32) error {
	if peerCaps&proto.CapsL3Identity != 0 {
		return nil
	}
	return &virtualif.Error{
		Op:     "l3 identity capability",
		Reason: virtualif.ReasonPeerL3IdentityUnsupported,
	}
}

// RequirePeerEgress validates that an embedding peer supplied an egress
// hook compatible with L3 identity metadata.
func RequirePeerEgress(ok bool) error {
	if ok {
		return nil
	}
	return &virtualif.Error{
		Op:     "l3 identity egress",
		Reason: virtualif.ReasonPeerEgressUnsupported,
	}
}

func identityAddrBytes(id L3Identity) (byte, [16]byte, [16]byte, error) {
	var src [16]byte
	var dst [16]byte
	if err := requireCanonicalWireAddr("source", id.SrcIP); err != nil {
		return 0, src, dst, err
	}
	if err := requireCanonicalWireAddr("destination", id.DstIP); err != nil {
		return 0, src, dst, err
	}
	if id.SrcIP.Is4() && id.DstIP.Is4() {
		src4 := id.SrcIP.As4()
		dst4 := id.DstIP.As4()
		copy(src[:4], src4[:])
		copy(dst[:4], dst4[:])
		return addrFamily4, src, dst, nil
	}
	if id.SrcIP.Is6() && id.DstIP.Is6() {
		src = id.SrcIP.As16()
		dst = id.DstIP.As16()
		return addrFamily6, src, dst, nil
	}
	return 0, src, dst, fmt.Errorf("l3ingress: mixed or invalid address families: %s -> %s", id.SrcIP, id.DstIP)
}

func requireCanonicalWireAddr(endpoint string, addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid %s address", ErrNonCanonicalIdentity, endpoint)
	}
	if addr.Zone() != "" {
		return fmt.Errorf("%w: %s address zone is not representable", ErrNonCanonicalIdentity, endpoint)
	}
	if addr.Is4In6() || addr.Unmap() != addr {
		return fmt.Errorf("%w: %s address is an IPv4 alias", ErrNonCanonicalIdentity, endpoint)
	}
	return nil
}
