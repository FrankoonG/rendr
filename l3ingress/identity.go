// Package l3ingress contains the L3/L4 classification layer shared by
// TUN today and a possible TAP frontend later.
package l3ingress

import (
	"fmt"
	"net/netip"
)

// Protocol is the IP protocol number carried by an L3Identity.
type Protocol uint8

const (
	ProtocolICMP   Protocol = 1
	ProtocolTCP    Protocol = 6
	ProtocolUDP    Protocol = 17
	ProtocolICMPv6 Protocol = 58
)

// L3Identity is the logical source/destination tuple captured at TUN
// ingress and carried through rendr to peer-side egress hooks.
type L3Identity struct {
	Proto   Protocol
	SrcIP   netip.Addr
	SrcPort uint16
	DstIP   netip.Addr
	DstPort uint16
}

// Reverse returns the tuple as seen by reply traffic.
func (id L3Identity) Reverse() L3Identity {
	return L3Identity{
		Proto:   id.Proto,
		SrcIP:   id.DstIP,
		SrcPort: id.DstPort,
		DstIP:   id.SrcIP,
		DstPort: id.SrcPort,
	}
}

// HasPorts reports whether both endpoint ports are meaningful.
func (id L3Identity) HasPorts() bool {
	return id.Proto == ProtocolTCP || id.Proto == ProtocolUDP
}

func (id L3Identity) String() string {
	if id.HasPorts() {
		return fmt.Sprintf("%s %s:%d -> %s:%d", id.Proto, id.SrcIP, id.SrcPort, id.DstIP, id.DstPort)
	}
	return fmt.Sprintf("%s %s -> %s", id.Proto, id.SrcIP, id.DstIP)
}

func (p Protocol) String() string {
	switch p {
	case ProtocolICMP:
		return "icmp"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolICMPv6:
		return "icmpv6"
	default:
		return fmt.Sprintf("proto(%d)", uint8(p))
	}
}
