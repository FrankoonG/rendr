package l3session

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf8"

	"github.com/FrankoonG/rendr/l3ingress"
)

const (
	udpEnvelopeVersion       = 1
	udpEnvelopeHeaderSize    = 8
	udpEnvelopeMaxEgressName = 1024
)

var udpEnvelopeMagic = [4]byte{'R', '3', 'U', 'P'}

type udpEnvelope struct {
	Identity l3ingress.L3Identity
	Egress   string
	Payload  []byte
}

func appendUDPEnvelope(dst []byte, id l3ingress.L3Identity, egress string, payload []byte) ([]byte, error) {
	if id.Proto != l3ingress.ProtocolUDP {
		return dst, fmt.Errorf("l3session: UDP envelope cannot carry %s identity", id.Proto)
	}
	if egress == "" || len(egress) > udpEnvelopeMaxEgressName || !utf8.ValidString(egress) {
		return dst, fmt.Errorf("l3session: invalid UDP envelope egress name length=%d", len(egress))
	}
	start := len(dst)
	dst = append(dst, make([]byte, udpEnvelopeHeaderSize)...)
	copy(dst[start:start+4], udpEnvelopeMagic[:])
	dst[start+4] = udpEnvelopeVersion
	// Byte 5 is reserved flags and must remain zero in version 1.
	binary.BigEndian.PutUint16(dst[start+6:start+8], uint16(len(egress)))
	var err error
	dst, err = appendCanonicalIdentity(dst, id, l3ingress.ProtocolUDP)
	if err != nil {
		return dst[:start], err
	}
	dst = append(dst, egress...)
	dst = append(dst, payload...)
	return dst, nil
}

func decodeUDPEnvelope(packet []byte) (udpEnvelope, error) {
	minimum := udpEnvelopeHeaderSize + l3ingress.IdentityWireSize + 1
	if len(packet) < minimum {
		return udpEnvelope{}, fmt.Errorf("l3session: UDP envelope too short: %d < %d", len(packet), minimum)
	}
	if !bytes.Equal(packet[:4], udpEnvelopeMagic[:]) {
		return udpEnvelope{}, fmt.Errorf("l3session: UDP envelope magic mismatch")
	}
	if packet[4] != udpEnvelopeVersion {
		return udpEnvelope{}, fmt.Errorf("l3session: unsupported UDP envelope version %d", packet[4])
	}
	if packet[5] != 0 {
		return udpEnvelope{}, fmt.Errorf("l3session: unsupported UDP envelope flags 0x%02x", packet[5])
	}
	egressLen := int(binary.BigEndian.Uint16(packet[6:8]))
	if egressLen < 1 || egressLen > udpEnvelopeMaxEgressName {
		return udpEnvelope{}, fmt.Errorf("l3session: invalid UDP envelope egress length %d", egressLen)
	}
	identityStart := udpEnvelopeHeaderSize
	egressStart := identityStart + l3ingress.IdentityWireSize
	payloadStart := egressStart + egressLen
	if payloadStart > len(packet) {
		return udpEnvelope{}, fmt.Errorf("l3session: UDP envelope egress overruns packet: need %d have %d", payloadStart, len(packet))
	}
	id, err := decodeCanonicalIdentity(packet[identityStart:egressStart], l3ingress.ProtocolUDP)
	if err != nil {
		return udpEnvelope{}, err
	}
	if id.Proto != l3ingress.ProtocolUDP {
		return udpEnvelope{}, fmt.Errorf("l3session: UDP envelope contains %s identity", id.Proto)
	}
	egressBytes := packet[egressStart:payloadStart]
	if !utf8.Valid(egressBytes) {
		return udpEnvelope{}, fmt.Errorf("l3session: UDP envelope egress is not UTF-8")
	}
	return udpEnvelope{
		Identity: id,
		Egress:   string(egressBytes),
		Payload:  packet[payloadStart:],
	}, nil
}
