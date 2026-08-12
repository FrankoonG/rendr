package proto

import (
	"encoding/binary"
	"fmt"
)

const (
	PathRetirementWireVersion uint8 = 1
	PathRetirementPayloadSize       = 144
)

var pathRetirementMagic = [4]byte{'R', 'P', 'R', 'T'}

type PathRetirementReason uint8

const (
	PathRetirementReasonInvalid        PathRetirementReason = 0
	PathRetirementReasonTransport      PathRetirementReason = 1
	PathRetirementReasonAdministrative PathRetirementReason = 2
)

func (r PathRetirementReason) Valid() bool {
	return r == PathRetirementReasonTransport || r == PathRetirementReasonAdministrative
}

// PathRetirementPayload identifies one shared logical leaf generation. Path
// IDs and local owners are deliberately absent because they differ by peer.
type PathRetirementPayload struct {
	SessionEpoch          SessionEpoch
	Direction             SenderDirection
	Reason                PathRetirementReason
	SenderGraphRevision   uint64
	SenderGraphDigest     GraphDigest
	SenderTargetID        TargetID
	ReceiverGraphRevision uint64
	ReceiverGraphDigest   GraphDigest
	ReceiverTargetID      TargetID
	RouteGeneration       uint64
}

func (p PathRetirementPayload) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	wire := make([]byte, PathRetirementPayloadSize)
	copy(wire[0:4], pathRetirementMagic[:])
	wire[4] = PathRetirementWireVersion
	wire[5] = byte(p.Direction)
	wire[6] = byte(p.Reason)
	copy(wire[8:24], p.SessionEpoch[:])
	binary.BigEndian.PutUint64(wire[24:32], p.SenderGraphRevision)
	copy(wire[32:64], p.SenderGraphDigest[:])
	copy(wire[64:80], p.SenderTargetID[:])
	binary.BigEndian.PutUint64(wire[80:88], p.ReceiverGraphRevision)
	copy(wire[88:120], p.ReceiverGraphDigest[:])
	copy(wire[120:136], p.ReceiverTargetID[:])
	binary.BigEndian.PutUint64(wire[136:144], p.RouteGeneration)
	return wire, nil
}

func DecodePathRetirement(wire []byte) (PathRetirementPayload, error) {
	var p PathRetirementPayload
	if len(wire) != PathRetirementPayloadSize {
		return p, fmt.Errorf("proto: path retirement payload size: %d != %d", len(wire), PathRetirementPayloadSize)
	}
	if string(wire[0:4]) != string(pathRetirementMagic[:]) || wire[4] != PathRetirementWireVersion {
		return p, fmt.Errorf("proto: invalid path retirement envelope")
	}
	if wire[7] != 0 {
		return p, fmt.Errorf("proto: path retirement reserved byte must be zero")
	}
	p.Direction = SenderDirection(wire[5])
	p.Reason = PathRetirementReason(wire[6])
	copy(p.SessionEpoch[:], wire[8:24])
	p.SenderGraphRevision = binary.BigEndian.Uint64(wire[24:32])
	copy(p.SenderGraphDigest[:], wire[32:64])
	copy(p.SenderTargetID[:], wire[64:80])
	p.ReceiverGraphRevision = binary.BigEndian.Uint64(wire[80:88])
	copy(p.ReceiverGraphDigest[:], wire[88:120])
	copy(p.ReceiverTargetID[:], wire[120:136])
	p.RouteGeneration = binary.BigEndian.Uint64(wire[136:144])
	if err := p.Validate(); err != nil {
		return PathRetirementPayload{}, err
	}
	return p, nil
}

func (p PathRetirementPayload) Validate() error {
	if p.SessionEpoch == (SessionEpoch{}) {
		return fmt.Errorf("proto: path retirement has zero session epoch")
	}
	if !p.Direction.Valid() {
		return fmt.Errorf("proto: path retirement has invalid direction %d", p.Direction)
	}
	if !p.Reason.Valid() {
		return fmt.Errorf("proto: path retirement has invalid reason %d", p.Reason)
	}
	if p.SenderGraphRevision == 0 || p.SenderGraphDigest == (GraphDigest{}) || p.SenderTargetID == (TargetID{}) {
		return fmt.Errorf("proto: path retirement has incomplete sender binding")
	}
	if p.ReceiverGraphRevision == 0 || p.ReceiverGraphDigest == (GraphDigest{}) || p.ReceiverTargetID == (TargetID{}) {
		return fmt.Errorf("proto: path retirement has incomplete receiver binding")
	}
	if p.RouteGeneration == 0 {
		return fmt.Errorf("proto: path retirement has zero route generation")
	}
	return nil
}
