package l3ingress

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// ParseReason is a machine-readable packet classification failure.
type ParseReason string

const (
	ReasonShortPacket          ParseReason = "short_packet"
	ReasonUnsupportedIPVersion ParseReason = "unsupported_ip_version"
	ReasonInvalidHeader        ParseReason = "invalid_header"
	ReasonUnsupportedProtocol  ParseReason = "unsupported_protocol"
	ReasonNonInitialFragment   ParseReason = "non_initial_fragment"
	ReasonIPv6ExtensionLoop    ParseReason = "ipv6_extension_loop"
)

// ParseError keeps TUN/l3ingress failures inspectable without forcing
// callers to scrape error strings.
type ParseError struct {
	Reason ParseReason
	Detail string
}

func (e *ParseError) Error() string {
	if e.Detail == "" {
		return "l3ingress: " + string(e.Reason)
	}
	return "l3ingress: " + string(e.Reason) + ": " + e.Detail
}

// PacketMeta is the parsed L3/L4 identity plus offsets into the
// original packet. Packet is never retained by ParsePacket.
type PacketMeta struct {
	Identity       L3Identity
	IPVersion      int
	HeaderLen      int
	PayloadOffset  int
	PayloadLen     int
	Fragmented     bool
	MoreFragments  bool
	FragmentOffset int
}

// ParsePacket classifies one raw IP packet as read from a TUN device.
// It currently extracts TCP/UDP ports and ICMP identities for IPv4 and
// IPv6. Non-initial fragments are rejected because they do not carry
// enough L4 header bytes to create a stable flow identity.
func ParsePacket(packet []byte) (PacketMeta, error) {
	if len(packet) < 1 {
		return PacketMeta{}, parseErr(ReasonShortPacket, "missing IP version")
	}
	switch packet[0] >> 4 {
	case 4:
		return parseIPv4(packet)
	case 6:
		return parseIPv6(packet)
	default:
		return PacketMeta{}, parseErr(ReasonUnsupportedIPVersion, fmt.Sprintf("version=%d", packet[0]>>4))
	}
}

func parseIPv4(packet []byte) (PacketMeta, error) {
	if len(packet) < 20 {
		return PacketMeta{}, parseErr(ReasonShortPacket, fmt.Sprintf("ipv4 header len=%d", len(packet)))
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 {
		return PacketMeta{}, parseErr(ReasonInvalidHeader, fmt.Sprintf("ipv4 ihl=%d", ihl))
	}
	if len(packet) < ihl {
		return PacketMeta{}, parseErr(ReasonShortPacket, fmt.Sprintf("ipv4 options need=%d have=%d", ihl, len(packet)))
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl {
		return PacketMeta{}, parseErr(ReasonInvalidHeader, fmt.Sprintf("ipv4 total=%d ihl=%d", totalLen, ihl))
	}
	if len(packet) < totalLen {
		return PacketMeta{}, parseErr(ReasonShortPacket, fmt.Sprintf("ipv4 total=%d have=%d", totalLen, len(packet)))
	}
	frag := binary.BigEndian.Uint16(packet[6:8])
	more := frag&0x2000 != 0
	offset := int(frag&0x1fff) * 8
	if offset != 0 {
		return PacketMeta{}, parseErr(ReasonNonInitialFragment, fmt.Sprintf("ipv4 offset=%d", offset))
	}
	var src4 [4]byte
	var dst4 [4]byte
	copy(src4[:], packet[12:16])
	copy(dst4[:], packet[16:20])
	src := netip.AddrFrom4(src4)
	dst := netip.AddrFrom4(dst4)
	proto := Protocol(packet[9])
	meta := PacketMeta{
		Identity: L3Identity{
			Proto: proto,
			SrcIP: src,
			DstIP: dst,
		},
		IPVersion:      4,
		HeaderLen:      ihl,
		PayloadOffset:  ihl,
		PayloadLen:     totalLen - ihl,
		Fragmented:     more,
		MoreFragments:  more,
		FragmentOffset: offset,
	}
	if err := fillPorts(packet[:totalLen], &meta, ihl); err != nil {
		return PacketMeta{}, err
	}
	return meta, nil
}

func parseIPv6(packet []byte) (PacketMeta, error) {
	if len(packet) < 40 {
		return PacketMeta{}, parseErr(ReasonShortPacket, fmt.Sprintf("ipv6 header len=%d", len(packet)))
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	totalLen := 40 + payloadLen
	if len(packet) < totalLen {
		return PacketMeta{}, parseErr(ReasonShortPacket, fmt.Sprintf("ipv6 total=%d have=%d", totalLen, len(packet)))
	}
	var srcBytes [16]byte
	var dstBytes [16]byte
	copy(srcBytes[:], packet[8:24])
	copy(dstBytes[:], packet[24:40])
	next := packet[6]
	off := 40
	fragmented := false
	more := false
	fragOffset := 0
	for hops := 0; isIPv6Extension(next); hops++ {
		if hops > 8 {
			return PacketMeta{}, parseErr(ReasonIPv6ExtensionLoop, "too many IPv6 extension headers")
		}
		if next == 44 {
			if len(packet) < off+8 {
				return PacketMeta{}, parseErr(ReasonShortPacket, "ipv6 fragment header")
			}
			frag := binary.BigEndian.Uint16(packet[off+2 : off+4])
			fragOffset = int((frag>>3)&0x1fff) * 8
			more = frag&0x1 != 0
			fragmented = true
			next = packet[off]
			off += 8
			if fragOffset != 0 {
				return PacketMeta{}, parseErr(ReasonNonInitialFragment, fmt.Sprintf("ipv6 offset=%d", fragOffset))
			}
			continue
		}
		if len(packet) < off+2 {
			return PacketMeta{}, parseErr(ReasonShortPacket, "ipv6 extension header")
		}
		hdrLen := (int(packet[off+1]) + 1) * 8
		if len(packet) < off+hdrLen {
			return PacketMeta{}, parseErr(ReasonShortPacket, fmt.Sprintf("ipv6 extension need=%d have=%d", off+hdrLen, len(packet)))
		}
		next = packet[off]
		off += hdrLen
	}
	meta := PacketMeta{
		Identity: L3Identity{
			Proto: Protocol(next),
			SrcIP: netip.AddrFrom16(srcBytes),
			DstIP: netip.AddrFrom16(dstBytes),
		},
		IPVersion:      6,
		HeaderLen:      off,
		PayloadOffset:  off,
		PayloadLen:     totalLen - off,
		Fragmented:     fragmented,
		MoreFragments:  more,
		FragmentOffset: fragOffset,
	}
	if err := fillPorts(packet[:totalLen], &meta, off); err != nil {
		return PacketMeta{}, err
	}
	return meta, nil
}

func fillPorts(packet []byte, meta *PacketMeta, off int) error {
	switch meta.Identity.Proto {
	case ProtocolTCP, ProtocolUDP:
		if len(packet) < off+4 {
			return parseErr(ReasonShortPacket, fmt.Sprintf("%s header ports", meta.Identity.Proto))
		}
		meta.Identity.SrcPort = binary.BigEndian.Uint16(packet[off : off+2])
		meta.Identity.DstPort = binary.BigEndian.Uint16(packet[off+2 : off+4])
		return nil
	case ProtocolICMP, ProtocolICMPv6:
		return nil
	default:
		return parseErr(ReasonUnsupportedProtocol, meta.Identity.Proto.String())
	}
}

func isIPv6Extension(next byte) bool {
	switch next {
	case 0, 43, 44, 50, 51, 60:
		return true
	default:
		return false
	}
}

func parseErr(reason ParseReason, detail string) error {
	return &ParseError{Reason: reason, Detail: detail}
}
