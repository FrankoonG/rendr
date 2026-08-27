package l3session

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/FrankoonG/rendr/l3ingress"
)

// ErrNonCanonicalL3Identity means an L3 tuple has more than one possible
// routing or wire representation. Such tuples are rejected before they can
// become session keys.
var ErrNonCanonicalL3Identity = errors.New("l3session: non-canonical L3 identity")

func requireCanonicalIdentity(id l3ingress.L3Identity, want l3ingress.Protocol) error {
	if id.Proto != want {
		return fmt.Errorf("%w: protocol=%s want=%s", ErrNonCanonicalL3Identity, id.Proto, want)
	}
	if err := requireCanonicalIdentityAddr("source", id.SrcIP); err != nil {
		return err
	}
	if err := requireCanonicalIdentityAddr("destination", id.DstIP); err != nil {
		return err
	}
	if id.SrcIP.Is4() != id.DstIP.Is4() {
		return fmt.Errorf("%w: mixed address families", ErrNonCanonicalL3Identity)
	}
	return nil
}

func requireCanonicalIdentityAddr(endpoint string, addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid %s address", ErrNonCanonicalL3Identity, endpoint)
	}
	if addr.Zone() != "" {
		return fmt.Errorf("%w: %s address has an unrepresentable zone", ErrNonCanonicalL3Identity, endpoint)
	}
	if addr.Is4In6() || addr.Unmap() != addr {
		return fmt.Errorf("%w: %s address is an IPv4 alias", ErrNonCanonicalL3Identity, endpoint)
	}
	return nil
}

func requireCanonicalSessionRequest(req l3ingress.SessionRequest) error {
	var want l3ingress.Protocol
	switch req.Kind {
	case l3ingress.SessionKindStream:
		want = l3ingress.ProtocolTCP
	case l3ingress.SessionKindPacket:
		want = l3ingress.ProtocolUDP
	default:
		return nil
	}
	if err := requireCanonicalIdentity(req.Identity, want); err != nil {
		return err
	}
	if req.Ref != (l3ingress.FlowRef{}) {
		if req.Ref.Generation == 0 || req.Ref.Identity != req.Identity {
			return fmt.Errorf("%w: flow reference does not name the canonical identity", ErrNonCanonicalL3Identity)
		}
	}
	return nil
}

func appendCanonicalIdentity(dst []byte, id l3ingress.L3Identity, want l3ingress.Protocol) ([]byte, error) {
	if err := requireCanonicalIdentity(id, want); err != nil {
		return dst, err
	}
	return id.AppendBinary(dst)
}

func decodeCanonicalIdentity(record []byte, want l3ingress.Protocol) (l3ingress.L3Identity, error) {
	if len(record) != l3ingress.IdentityWireSize {
		return l3ingress.L3Identity{}, fmt.Errorf(
			"%w: wire size=%d want=%d",
			ErrNonCanonicalL3Identity,
			len(record),
			l3ingress.IdentityWireSize,
		)
	}
	id, err := l3ingress.DecodeIdentity(record)
	if err != nil {
		return l3ingress.L3Identity{}, err
	}
	if err := requireCanonicalIdentity(id, want); err != nil {
		return l3ingress.L3Identity{}, err
	}
	canonical, err := id.EncodeBinary()
	if err != nil {
		return l3ingress.L3Identity{}, err
	}
	if !bytes.Equal(canonical, record) {
		return l3ingress.L3Identity{}, fmt.Errorf("%w: wire record has reserved or padding data", ErrNonCanonicalL3Identity)
	}
	return id, nil
}

func canonicalAddrPort(value netip.AddrPort) (netip.AddrPort, bool) {
	if !value.IsValid() {
		return netip.AddrPort{}, false
	}
	addr := value.Addr()
	if addr.Is4In6() {
		if addr.Zone() != "" {
			return netip.AddrPort{}, false
		}
		addr = addr.Unmap()
	}
	if addr.Is4() && addr.Zone() != "" {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, value.Port()), true
}

func canonicalUDPAddr(addr net.Addr) (netip.AddrPort, bool) {
	value, ok := addr.(*net.UDPAddr)
	if !ok || value == nil || value.Port < 0 || value.Port > 1<<16-1 {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(value.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	if value.Zone != "" {
		if !ip.Is6() || ip.Is4In6() {
			return netip.AddrPort{}, false
		}
		ip = ip.WithZone(value.Zone)
	}
	return canonicalAddrPort(netip.AddrPortFrom(ip, uint16(value.Port)))
}
