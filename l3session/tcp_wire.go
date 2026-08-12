package l3session

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/FrankoonG/rendr/l3ingress"
)

const (
	tcpEnvelopeVersion       = 2
	tcpEnvelopeHeaderSize    = 8
	tcpEnvelopeMaxEgressName = 1024
	tcpReadySize             = 8
)

var tcpEnvelopeMagic = [4]byte{'R', '3', 'T', 'P'}
var tcpReadyMagic = [4]byte{'R', '3', 'T', 'A'}

type tcpReadyStatus uint8

const (
	tcpReadyInvalid tcpReadyStatus = iota
	tcpReadyOK
	tcpReadyEgressUnavailable
	tcpReadyEgressDialFailed
	tcpReadyHalfCloseUnsupported
	tcpReadyInternalFailure
)

type tcpEnvelope struct {
	Identity l3ingress.L3Identity
	Egress   string
}

func encodeTCPEnvelope(id l3ingress.L3Identity, egress string) ([]byte, error) {
	if id.Proto != l3ingress.ProtocolTCP {
		return nil, fmt.Errorf("l3session: TCP envelope cannot carry %s identity", id.Proto)
	}
	if egress == "" || len(egress) > tcpEnvelopeMaxEgressName || !utf8.ValidString(egress) {
		return nil, fmt.Errorf("l3session: invalid TCP envelope egress name length=%d", len(egress))
	}
	wire := make([]byte, tcpEnvelopeHeaderSize)
	copy(wire[:4], tcpEnvelopeMagic[:])
	wire[4] = tcpEnvelopeVersion
	// Byte 5 is reserved flags and must remain zero in version 2.
	binary.BigEndian.PutUint16(wire[6:8], uint16(len(egress)))
	var err error
	wire, err = id.AppendBinary(wire)
	if err != nil {
		return nil, err
	}
	wire = append(wire, egress...)
	return wire, nil
}

func readTCPEnvelope(r io.Reader) (tcpEnvelope, error) {
	fixed := make([]byte, tcpEnvelopeHeaderSize+l3ingress.IdentityWireSize)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return tcpEnvelope{}, fmt.Errorf("l3session: read TCP envelope prefix: %w", err)
	}
	if !bytes.Equal(fixed[:4], tcpEnvelopeMagic[:]) {
		return tcpEnvelope{}, fmt.Errorf("l3session: TCP envelope magic mismatch")
	}
	if fixed[4] != tcpEnvelopeVersion {
		return tcpEnvelope{}, fmt.Errorf("l3session: unsupported TCP envelope version %d", fixed[4])
	}
	if fixed[5] != 0 {
		return tcpEnvelope{}, fmt.Errorf("l3session: unsupported TCP envelope flags 0x%02x", fixed[5])
	}
	egressLen := int(binary.BigEndian.Uint16(fixed[6:8]))
	if egressLen < 1 || egressLen > tcpEnvelopeMaxEgressName {
		return tcpEnvelope{}, fmt.Errorf("l3session: invalid TCP envelope egress length %d", egressLen)
	}
	id, err := l3ingress.DecodeIdentity(fixed[tcpEnvelopeHeaderSize:])
	if err != nil {
		return tcpEnvelope{}, err
	}
	if id.Proto != l3ingress.ProtocolTCP {
		return tcpEnvelope{}, fmt.Errorf("l3session: TCP envelope contains %s identity", id.Proto)
	}
	egress := make([]byte, egressLen)
	if _, err := io.ReadFull(r, egress); err != nil {
		return tcpEnvelope{}, fmt.Errorf("l3session: read TCP envelope egress: %w", err)
	}
	if !utf8.Valid(egress) {
		return tcpEnvelope{}, fmt.Errorf("l3session: TCP envelope egress is not UTF-8")
	}
	return tcpEnvelope{Identity: id, Egress: string(egress)}, nil
}

func encodeTCPReady(status tcpReadyStatus) ([]byte, error) {
	if !validTCPReadyStatus(status) {
		return nil, fmt.Errorf("l3session: invalid TCP readiness status %d", status)
	}
	wire := make([]byte, tcpReadySize)
	copy(wire[:4], tcpReadyMagic[:])
	wire[4] = tcpEnvelopeVersion
	wire[5] = byte(status)
	// Bytes 6-7 are reserved for version 2 and must remain zero.
	return wire, nil
}

func readTCPReady(r io.Reader) (tcpReadyStatus, error) {
	wire := make([]byte, tcpReadySize)
	if _, err := io.ReadFull(r, wire); err != nil {
		return tcpReadyInvalid, fmt.Errorf("l3session: read TCP readiness: %w", err)
	}
	if !bytes.Equal(wire[:4], tcpReadyMagic[:]) {
		return tcpReadyInvalid, fmt.Errorf("l3session: TCP readiness magic mismatch")
	}
	if wire[4] != tcpEnvelopeVersion {
		return tcpReadyInvalid, fmt.Errorf("l3session: unsupported TCP readiness version %d", wire[4])
	}
	if wire[6] != 0 || wire[7] != 0 {
		return tcpReadyInvalid, fmt.Errorf("l3session: unsupported TCP readiness flags 0x%02x%02x", wire[6], wire[7])
	}
	status := tcpReadyStatus(wire[5])
	if !validTCPReadyStatus(status) {
		return tcpReadyInvalid, fmt.Errorf("l3session: invalid TCP readiness status %d", status)
	}
	return status, nil
}

func validTCPReadyStatus(status tcpReadyStatus) bool {
	return status >= tcpReadyOK && status <= tcpReadyInternalFailure
}
