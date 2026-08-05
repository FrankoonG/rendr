package proto

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	PathAdmissionWireVersion    uint8 = 1
	PathAdmissionMaxReasonBytes       = 512

	// PathAdmissionBindingSize is the canonical transaction envelope and
	// immutable admission identity. Commit ends at this boundary.
	PathAdmissionBindingSize   = 192
	PathAdmissionCommitSize    = PathAdmissionBindingSize
	PathAdmissionAckHeaderSize = 200
	PathAdmissionAckMaxSize    = PathAdmissionAckHeaderSize + PathAdmissionMaxReasonBytes
	PathAdmissionConfirmSize   = 200
)

var pathAdmissionMagic = [4]byte{'R', 'P', 'A', 'X'}

type pathAdmissionMessage uint8

const (
	pathAdmissionMessageCommit  pathAdmissionMessage = 1
	pathAdmissionMessageAck     pathAdmissionMessage = 2
	pathAdmissionMessageConfirm pathAdmissionMessage = 3
)

// PathAdmissionKind identifies the handshake that prepared an admission.
type PathAdmissionKind uint8

const (
	PathAdmissionKindInvalid PathAdmissionKind = 0
	PathAdmissionKindHello   PathAdmissionKind = 1
	PathAdmissionKindBridge  PathAdmissionKind = 2
)

func (k PathAdmissionKind) Valid() bool {
	return k == PathAdmissionKindHello || k == PathAdmissionKindBridge
}

// PathAdmissionPhase identifies a durable transition in the admission
// transaction. HELLO_ACK or BRIDGE_ACK supplies the preceding PREPARED state.
type PathAdmissionPhase uint8

const (
	PathAdmissionPhaseInvalid   PathAdmissionPhase = 0
	PathAdmissionPhasePrepared  PathAdmissionPhase = 1
	PathAdmissionPhaseCommit    PathAdmissionPhase = 2
	PathAdmissionPhaseCommitted PathAdmissionPhase = 3
	PathAdmissionPhaseConfirm   PathAdmissionPhase = 4
	PathAdmissionPhaseFinal     PathAdmissionPhase = 5
	PathAdmissionPhaseActivated PathAdmissionPhase = 6
)

type PathAdmissionID [16]byte
type PathAdmissionProposalDigest [32]byte
type PathAdmissionPlanDigest [32]byte

// PathAdmissionBinding is echoed byte-for-byte by every phase. It binds a
// path admission to one session, graph leaf, predecessor generation, proposal,
// and responder plan, so a delayed phase cannot commit a different path.
type PathAdmissionBinding struct {
	Kind                   PathAdmissionKind
	Direction              SenderDirection
	SessionEpoch           SessionEpoch
	AdmissionID            PathAdmissionID
	InitiatorGraphRevision uint64
	InitiatorGraphDigest   GraphDigest
	InitiatorTargetID      TargetID
	ResponderTargetID      TargetID
	BaseLeafGeneration     uint64
	ProposalDigest         PathAdmissionProposalDigest
	ResponderPlanDigest    PathAdmissionPlanDigest
}

func (b PathAdmissionBinding) Validate() error {
	if !b.Kind.Valid() {
		return fmt.Errorf("proto: path admission has invalid kind %d", b.Kind)
	}
	if !b.Direction.Valid() {
		return fmt.Errorf("proto: path admission has invalid sender direction %d", b.Direction)
	}
	if b.SessionEpoch == (SessionEpoch{}) {
		return fmt.Errorf("proto: path admission has zero session epoch")
	}
	if b.AdmissionID == (PathAdmissionID{}) {
		return fmt.Errorf("proto: path admission has zero admission id")
	}
	if b.InitiatorGraphRevision == 0 {
		return fmt.Errorf("proto: path admission has zero initiator graph revision")
	}
	if b.InitiatorGraphDigest == (GraphDigest{}) {
		return fmt.Errorf("proto: path admission has zero initiator graph digest")
	}
	if b.InitiatorTargetID == (TargetID{}) {
		return fmt.Errorf("proto: path admission has zero initiator target id")
	}
	if b.ResponderTargetID == (TargetID{}) {
		return fmt.Errorf("proto: path admission has zero responder target id")
	}
	if b.BaseLeafGeneration == ^uint64(0) {
		return fmt.Errorf("proto: path admission base leaf generation cannot advance")
	}
	if b.ProposalDigest == (PathAdmissionProposalDigest{}) {
		return fmt.Errorf("proto: path admission has zero proposal digest")
	}
	if b.ResponderPlanDigest == (PathAdmissionPlanDigest{}) {
		return fmt.Errorf("proto: path admission has zero responder plan digest")
	}
	return nil
}

// CommittedGeneration returns the sole generation this binding can publish.
func (b PathAdmissionBinding) CommittedGeneration() (uint64, error) {
	if err := b.Validate(); err != nil {
		return 0, err
	}
	return b.BaseLeafGeneration + 1, nil
}

// PathAdmissionCommit asks the responder to commit the prepared admission in
// an RX-visible, TX-fenced state. Its wire representation is fixed-size.
type PathAdmissionCommit struct {
	PathAdmissionBinding
	Phase PathAdmissionPhase
}

func (p PathAdmissionCommit) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return encodePathAdmissionBinding(p.PathAdmissionBinding, pathAdmissionMessageCommit, p.Phase, AckOK)
}

func DecodePathAdmissionCommit(wire []byte) (PathAdmissionCommit, error) {
	if len(wire) != PathAdmissionCommitSize {
		return PathAdmissionCommit{}, fmt.Errorf("proto: path admission commit payload size: %d != %d", len(wire), PathAdmissionCommitSize)
	}
	binding, phase, code, err := decodePathAdmissionBinding(wire, pathAdmissionMessageCommit)
	if err != nil {
		return PathAdmissionCommit{}, err
	}
	p := PathAdmissionCommit{PathAdmissionBinding: binding, Phase: phase}
	if code != AckOK {
		return PathAdmissionCommit{}, fmt.Errorf("proto: path admission commit has invalid phase or reserved code")
	}
	if err := p.validate(); err != nil {
		return PathAdmissionCommit{}, err
	}
	return p, nil
}

func (p PathAdmissionCommit) validate() error {
	if err := p.PathAdmissionBinding.Validate(); err != nil {
		return err
	}
	if p.Phase != PathAdmissionPhaseCommit {
		return fmt.Errorf("proto: path admission commit has invalid phase %d", p.Phase)
	}
	return nil
}

// PathAdmissionAck acknowledges either the fenced commit or final publication.
// Reason is optional for every code but is always bounded and valid UTF-8.
type PathAdmissionAck struct {
	PathAdmissionBinding
	Phase  PathAdmissionPhase
	Code   AckCode
	Reason string
}

func (p PathAdmissionAck) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	b, err := encodePathAdmissionBinding(p.PathAdmissionBinding, pathAdmissionMessageAck, p.Phase, p.Code)
	if err != nil {
		return nil, err
	}
	b = append(b, make([]byte, PathAdmissionAckHeaderSize-PathAdmissionBindingSize+len(p.Reason))...)
	binary.BigEndian.PutUint16(b[192:194], uint16(len(p.Reason)))
	copy(b[PathAdmissionAckHeaderSize:], p.Reason)
	return b, nil
}

func DecodePathAdmissionAck(wire []byte) (PathAdmissionAck, error) {
	if len(wire) < PathAdmissionAckHeaderSize {
		return PathAdmissionAck{}, fmt.Errorf("proto: path admission ack payload too short: %d < %d", len(wire), PathAdmissionAckHeaderSize)
	}
	if len(wire) > PathAdmissionAckMaxSize {
		return PathAdmissionAck{}, fmt.Errorf("proto: path admission ack payload too large: %d > %d", len(wire), PathAdmissionAckMaxSize)
	}
	reasonLen := int(binary.BigEndian.Uint16(wire[192:194]))
	if reasonLen > PathAdmissionMaxReasonBytes || len(wire)-PathAdmissionAckHeaderSize != reasonLen {
		return PathAdmissionAck{}, fmt.Errorf("proto: path admission ack reason length %d does not match payload", reasonLen)
	}
	if binary.BigEndian.Uint16(wire[194:196]) != 0 || binary.BigEndian.Uint32(wire[196:200]) != 0 {
		return PathAdmissionAck{}, fmt.Errorf("proto: path admission ack reserved bytes must be zero")
	}
	binding, phase, code, err := decodePathAdmissionBinding(wire[:PathAdmissionBindingSize], pathAdmissionMessageAck)
	if err != nil {
		return PathAdmissionAck{}, err
	}
	p := PathAdmissionAck{
		PathAdmissionBinding: binding,
		Phase:                phase,
		Code:                 code,
		Reason:               string(wire[PathAdmissionAckHeaderSize:]),
	}
	if err := p.validate(); err != nil {
		return PathAdmissionAck{}, err
	}
	return p, nil
}

func (p PathAdmissionAck) validate() error {
	if err := p.PathAdmissionBinding.Validate(); err != nil {
		return err
	}
	if p.Phase != PathAdmissionPhasePrepared && p.Phase != PathAdmissionPhaseCommitted &&
		p.Phase != PathAdmissionPhaseFinal && p.Phase != PathAdmissionPhaseActivated {
		return fmt.Errorf("proto: path admission ack has invalid phase %d", p.Phase)
	}
	if p.Code > AckRejectProtoState {
		return fmt.Errorf("proto: path admission ack has invalid code %d", p.Code)
	}
	if len(p.Reason) > PathAdmissionMaxReasonBytes || !utf8.ValidString(p.Reason) {
		return fmt.Errorf("proto: path admission ack reason is invalid or exceeds %d bytes", PathAdmissionMaxReasonBytes)
	}
	return nil
}

// ValidateForCommit rejects delayed or mutated ACKs before engine state is
// changed. Phase and AckCode remain message-specific decisions for the caller.
func (p PathAdmissionAck) ValidateForCommit(commit PathAdmissionCommit) error {
	if err := commit.validate(); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	if p.PathAdmissionBinding != commit.PathAdmissionBinding {
		return fmt.Errorf("proto: path admission ack identity does not match commit")
	}
	return nil
}

// PathAdmissionConfirm authorizes publication of the committed generation.
type PathAdmissionConfirm struct {
	PathAdmissionBinding
	CommittedGeneration uint64
}

func (p PathAdmissionConfirm) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	b, err := encodePathAdmissionBinding(p.PathAdmissionBinding, pathAdmissionMessageConfirm, PathAdmissionPhaseConfirm, AckOK)
	if err != nil {
		return nil, err
	}
	b = append(b, make([]byte, PathAdmissionConfirmSize-PathAdmissionBindingSize)...)
	binary.BigEndian.PutUint64(b[192:200], p.CommittedGeneration)
	return b, nil
}

func DecodePathAdmissionConfirm(wire []byte) (PathAdmissionConfirm, error) {
	if len(wire) != PathAdmissionConfirmSize {
		return PathAdmissionConfirm{}, fmt.Errorf("proto: path admission confirm payload size: %d != %d", len(wire), PathAdmissionConfirmSize)
	}
	binding, phase, code, err := decodePathAdmissionBinding(wire[:PathAdmissionBindingSize], pathAdmissionMessageConfirm)
	if err != nil {
		return PathAdmissionConfirm{}, err
	}
	if phase != PathAdmissionPhaseConfirm || code != AckOK {
		return PathAdmissionConfirm{}, fmt.Errorf("proto: path admission confirm has invalid phase or reserved code")
	}
	p := PathAdmissionConfirm{
		PathAdmissionBinding: binding,
		CommittedGeneration:  binary.BigEndian.Uint64(wire[192:200]),
	}
	if err := p.validate(); err != nil {
		return PathAdmissionConfirm{}, err
	}
	return p, nil
}

func (p PathAdmissionConfirm) validate() error {
	want, err := p.PathAdmissionBinding.CommittedGeneration()
	if err != nil {
		return err
	}
	if p.CommittedGeneration == 0 || p.CommittedGeneration != want {
		return fmt.Errorf("proto: path admission confirm generation %d, want %d", p.CommittedGeneration, want)
	}
	return nil
}

// ValidateForCommit rejects a confirmation replayed against another admission.
func (p PathAdmissionConfirm) ValidateForCommit(commit PathAdmissionCommit) error {
	if err := commit.validate(); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	if p.PathAdmissionBinding != commit.PathAdmissionBinding {
		return fmt.Errorf("proto: path admission confirm identity does not match commit")
	}
	return nil
}

func encodePathAdmissionBinding(b PathAdmissionBinding, message pathAdmissionMessage, phase PathAdmissionPhase, code AckCode) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	wire := make([]byte, PathAdmissionBindingSize)
	copy(wire[0:4], pathAdmissionMagic[:])
	wire[4], wire[5], wire[6], wire[7] = PathAdmissionWireVersion, byte(message), byte(b.Kind), byte(b.Direction)
	wire[8], wire[9] = byte(phase), byte(code)
	copy(wire[16:32], b.SessionEpoch[:])
	copy(wire[32:48], b.AdmissionID[:])
	binary.BigEndian.PutUint64(wire[48:56], b.InitiatorGraphRevision)
	copy(wire[56:88], b.InitiatorGraphDigest[:])
	copy(wire[88:104], b.InitiatorTargetID[:])
	copy(wire[104:120], b.ResponderTargetID[:])
	binary.BigEndian.PutUint64(wire[120:128], b.BaseLeafGeneration)
	copy(wire[128:160], b.ProposalDigest[:])
	copy(wire[160:192], b.ResponderPlanDigest[:])
	return wire, nil
}

func decodePathAdmissionBinding(wire []byte, want pathAdmissionMessage) (PathAdmissionBinding, PathAdmissionPhase, AckCode, error) {
	if len(wire) != PathAdmissionBindingSize {
		return PathAdmissionBinding{}, PathAdmissionPhaseInvalid, AckRejectUnknown, fmt.Errorf("proto: path admission binding size: %d != %d", len(wire), PathAdmissionBindingSize)
	}
	if string(wire[0:4]) != string(pathAdmissionMagic[:]) || wire[4] != PathAdmissionWireVersion || pathAdmissionMessage(wire[5]) != want {
		return PathAdmissionBinding{}, PathAdmissionPhaseInvalid, AckRejectUnknown, fmt.Errorf("proto: invalid path admission envelope")
	}
	if binary.BigEndian.Uint16(wire[10:12]) != 0 || binary.BigEndian.Uint32(wire[12:16]) != 0 {
		return PathAdmissionBinding{}, PathAdmissionPhaseInvalid, AckRejectUnknown, fmt.Errorf("proto: path admission reserved bytes must be zero")
	}
	b := PathAdmissionBinding{
		Kind:                   PathAdmissionKind(wire[6]),
		Direction:              SenderDirection(wire[7]),
		InitiatorGraphRevision: binary.BigEndian.Uint64(wire[48:56]),
		BaseLeafGeneration:     binary.BigEndian.Uint64(wire[120:128]),
	}
	copy(b.SessionEpoch[:], wire[16:32])
	copy(b.AdmissionID[:], wire[32:48])
	copy(b.InitiatorGraphDigest[:], wire[56:88])
	copy(b.InitiatorTargetID[:], wire[88:104])
	copy(b.ResponderTargetID[:], wire[104:120])
	copy(b.ProposalDigest[:], wire[128:160])
	copy(b.ResponderPlanDigest[:], wire[160:192])
	if err := b.Validate(); err != nil {
		return PathAdmissionBinding{}, PathAdmissionPhaseInvalid, AckRejectUnknown, err
	}
	return b, PathAdmissionPhase(wire[8]), AckCode(wire[9]), nil
}
