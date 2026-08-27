package l3ingress

import (
	"encoding/binary"
	"fmt"
)

// UDPPayload returns the UDP payload slice from a parsed raw IP packet.
func UDPPayload(packet []byte, meta PacketMeta) ([]byte, error) {
	if meta.Identity.Proto != ProtocolUDP {
		return nil, fmt.Errorf("l3ingress: %s is not udp", meta.Identity.Proto)
	}
	off := meta.PayloadOffset
	if off < 0 || len(packet) < off+8 {
		return nil, parseErr(ReasonShortPacket, "udp header")
	}
	udpLen := int(binary.BigEndian.Uint16(packet[off+4 : off+6]))
	if udpLen < 8 {
		return nil, parseErr(ReasonInvalidHeader, fmt.Sprintf("udp length=%d", udpLen))
	}
	if len(packet) < off+udpLen {
		return nil, parseErr(ReasonShortPacket, fmt.Sprintf("udp length=%d have=%d", udpLen, len(packet)-off))
	}
	return packet[off+8 : off+udpLen], nil
}

// BuildUDPPacket builds a raw IP packet carrying one UDP datagram.
func BuildUDPPacket(id L3Identity, payload []byte) ([]byte, error) {
	return AppendUDPPacket(nil, id, payload)
}

// AppendUDPPacket appends a raw IP packet carrying one UDP datagram to dst.
// The returned packet does not retain payload, so callers may reuse payload
// after the call returns.
func AppendUDPPacket(out []byte, id L3Identity, payload []byte) ([]byte, error) {
	if id.Proto != ProtocolUDP {
		return nil, fmt.Errorf("l3ingress: %s is not udp", id.Proto)
	}
	if !id.SrcIP.IsValid() || !id.DstIP.IsValid() {
		return nil, parseErr(ReasonInvalidHeader, "invalid udp endpoint address")
	}
	if id.SrcIP.Is4() && id.DstIP.Is4() {
		if len(payload) > 0xffff-20-8 {
			return nil, parseErr(ReasonInvalidHeader, fmt.Sprintf("ipv4 udp payload too large: %d", len(payload)))
		}
		return appendIPv4UDPPacket(out, id, payload), nil
	}
	if id.SrcIP.Is6() && id.DstIP.Is6() {
		if len(payload) > 0xffff-8 {
			return nil, parseErr(ReasonInvalidHeader, fmt.Sprintf("ipv6 udp payload too large: %d", len(payload)))
		}
		return appendIPv6UDPPacket(out, id, payload), nil
	}
	return nil, parseErr(ReasonInvalidHeader, "mixed udp address families")
}

func appendIPv4UDPPacket(dst []byte, id L3Identity, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	oldLen := len(dst)
	dst = appendZeroed(dst, totalLen)
	pkt := dst[oldLen:]
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = byte(ProtocolUDP)
	src := id.SrcIP.As4()
	dstIP := id.DstIP.As4()
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[20:22], id.SrcPort)
	binary.BigEndian.PutUint16(pkt[22:24], id.DstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	return dst
}

func appendIPv6UDPPacket(dst []byte, id L3Identity, payload []byte) []byte {
	payloadLen := 8 + len(payload)
	oldLen := len(dst)
	dst = appendZeroed(dst, 40+payloadLen)
	pkt := dst[oldLen:]
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = byte(ProtocolUDP)
	pkt[7] = 64
	src := id.SrcIP.As16()
	dstIP := id.DstIP.As16()
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dstIP[:])
	binary.BigEndian.PutUint16(pkt[40:42], id.SrcPort)
	binary.BigEndian.PutUint16(pkt[42:44], id.DstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(payloadLen))
	copy(pkt[48:], payload)
	udpChecksum := udpIPv6Checksum(pkt, payloadLen)
	if udpChecksum == 0 {
		// RFC 8200 requires a non-zero UDP checksum for IPv6. In one's
		// complement arithmetic, an all-zero result is transmitted as 0xffff.
		udpChecksum = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[46:48], udpChecksum)
	return dst
}

func appendZeroed(dst []byte, n int) []byte {
	oldLen := len(dst)
	need := oldLen + n
	if cap(dst) < need {
		nextCap := need
		if doubled := cap(dst) * 2; doubled > nextCap {
			nextCap = doubled
		}
		buf := make([]byte, oldLen, nextCap)
		copy(buf, dst)
		dst = buf
	}
	dst = dst[:need]
	clear(dst[oldLen:need])
	return dst
}

func udpIPv6Checksum(pkt []byte, udpLen int) uint16 {
	pseudo := make([]byte, 40+udpLen)
	copy(pseudo[0:16], pkt[8:24])
	copy(pseudo[16:32], pkt[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpLen))
	pseudo[39] = byte(ProtocolUDP)
	copy(pseudo[40:], pkt[40:40+udpLen])
	return checksum(pseudo)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
