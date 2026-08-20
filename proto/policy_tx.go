package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	PolicyTransactionWireVersion uint8 = 4
	PolicyMaxCauseBytes                = 256
	PolicyMaxReasonBytes               = 512

	PolicyTransactionBindingSize = 80
	PolicyPrepareHeaderSize      = 136
	PolicyAckHeaderSize          = 232
	PolicyCommitSize             = 168
)

var policyTransactionMagic = [4]byte{'R', 'P', 'T', 'X'}

type policyTransactionMessage uint8

const (
	policyTransactionPrepare policyTransactionMessage = 1
	policyTransactionAck     policyTransactionMessage = 2
	policyTransactionCommit  policyTransactionMessage = 3
)

// PolicyTransactionBinding identifies one transaction, session, sender
// direction, and immutable graph. Generation is deliberately not part of the
// binding: only the sender owner assigns the next generation after PREPARE.
type PolicyTransactionBinding struct {
	SessionEpoch  SessionEpoch
	Direction     SenderDirection
	GraphBinding  GraphBinding
	TransactionID [16]byte
}

func (b PolicyTransactionBinding) Validate() error {
	if b.SessionEpoch == (SessionEpoch{}) {
		return fmt.Errorf("proto: policy transaction has zero session epoch")
	}
	if !b.Direction.Valid() {
		return fmt.Errorf("proto: policy transaction has invalid sender direction %d", b.Direction)
	}
	if b.GraphBinding.Revision == 0 {
		return fmt.Errorf("proto: policy transaction has zero graph revision")
	}
	if b.GraphBinding.Digest == (GraphDigest{}) {
		return fmt.Errorf("proto: policy transaction has zero graph digest")
	}
	if b.TransactionID == ([16]byte{}) {
		return fmt.Errorf("proto: policy transaction has zero transaction id")
	}
	return nil
}

type PolicyAction uint8

const (
	PolicyActionInvalid          PolicyAction = 0
	PolicyActionSelectChild      PolicyAction = 1
	PolicyActionSelectBestNormal PolicyAction = 2
	PolicyActionSelectBestPeak   PolicyAction = 3
)

type PolicyProposalDigest [32]byte
type PolicyReservationID [16]byte
type PolicyCommitChallenge [32]byte

// PolicyPrepare asks the sender owner to reserve generation base+1 for one
// selector immediate-child change. It does not alter dispatch by itself.
type PolicyPrepare struct {
	PolicyTransactionBinding
	BaseGeneration uint64
	Action         PolicyAction
	SelectorID     TargetID
	TargetID       TargetID
	Cause          string
}

func (p PolicyPrepare) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	b, err := encodePolicyTransactionBinding(p.PolicyTransactionBinding, policyTransactionPrepare)
	if err != nil {
		return nil, err
	}
	b = append(b, make([]byte, PolicyPrepareHeaderSize-PolicyTransactionBindingSize+len(p.Cause))...)
	binary.BigEndian.PutUint64(b[80:88], p.BaseGeneration)
	b[88] = byte(p.Action)
	copy(b[96:112], p.SelectorID[:])
	copy(b[112:128], p.TargetID[:])
	binary.BigEndian.PutUint16(b[128:130], uint16(len(p.Cause)))
	copy(b[PolicyPrepareHeaderSize:], p.Cause)
	return b, nil
}

func DecodePolicyPrepare(wire []byte) (PolicyPrepare, error) {
	if len(wire) < PolicyPrepareHeaderSize {
		return PolicyPrepare{}, fmt.Errorf("proto: policy prepare payload too short: %d < %d", len(wire), PolicyPrepareHeaderSize)
	}
	binding, err := decodePolicyTransactionBinding(wire[:PolicyTransactionBindingSize], policyTransactionPrepare)
	if err != nil {
		return PolicyPrepare{}, err
	}
	if binary.BigEndian.Uint64(wire[88:96])&0x00ffffffffffffff != 0 || binary.BigEndian.Uint16(wire[130:132]) != 0 || binary.BigEndian.Uint32(wire[132:136]) != 0 {
		return PolicyPrepare{}, fmt.Errorf("proto: policy prepare reserved bytes must be zero")
	}
	causeLen := int(binary.BigEndian.Uint16(wire[128:130]))
	if causeLen > PolicyMaxCauseBytes || len(wire)-PolicyPrepareHeaderSize != causeLen {
		return PolicyPrepare{}, fmt.Errorf("proto: policy prepare cause length %d does not match payload", causeLen)
	}
	p := PolicyPrepare{
		PolicyTransactionBinding: binding,
		BaseGeneration:           binary.BigEndian.Uint64(wire[80:88]),
		Action:                   PolicyAction(wire[88]),
		Cause:                    string(wire[PolicyPrepareHeaderSize:]),
	}
	copy(p.SelectorID[:], wire[96:112])
	copy(p.TargetID[:], wire[112:128])
	if err := p.validate(); err != nil {
		return PolicyPrepare{}, err
	}
	return p, nil
}

func (p PolicyPrepare) validate() error {
	if err := p.PolicyTransactionBinding.Validate(); err != nil {
		return err
	}
	if p.SelectorID == (TargetID{}) {
		return fmt.Errorf("proto: policy prepare has zero selector id")
	}
	switch p.Action {
	case PolicyActionSelectChild:
		if p.TargetID == (TargetID{}) {
			return fmt.Errorf("proto: select-child policy prepare has zero target id")
		}
	case PolicyActionSelectBestNormal, PolicyActionSelectBestPeak:
		if p.TargetID != (TargetID{}) {
			return fmt.Errorf("proto: selector-class policy prepare must not carry a target id")
		}
	default:
		return fmt.Errorf("proto: policy prepare has invalid action %d", p.Action)
	}
	if len(p.Cause) > PolicyMaxCauseBytes || !utf8.ValidString(p.Cause) {
		return fmt.Errorf("proto: policy prepare cause is invalid or exceeds %d bytes", PolicyMaxCauseBytes)
	}
	return nil
}

// ProposalDigest binds every semantic PREPARE field, including the immutable
// session/graph binding and transaction ID. ACK and COMMIT echo it so a delayed
// phase can never be applied to a different proposal after TxID reuse.
func (p PolicyPrepare) ProposalDigest() (PolicyProposalDigest, error) {
	wire, err := p.Encode()
	if err != nil {
		return PolicyProposalDigest{}, err
	}
	h := sha256.New()
	h.Write([]byte("rendr-policy-proposal-v4\x00"))
	h.Write(wire)
	var digest PolicyProposalDigest
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

type PolicyAckPhase uint8

const (
	PolicyAckPhaseInvalid PolicyAckPhase = 0
	PolicyAckPhasePrepare PolicyAckPhase = 1
	PolicyAckPhaseFinal   PolicyAckPhase = 2
)

type PolicyAckCode uint8

const (
	PolicyAckCodeInvalid    PolicyAckCode = 0
	PolicyAckCodeAccept     PolicyAckCode = 1
	PolicyAckCodeReject     PolicyAckCode = 2
	PolicyAckCodeBusy       PolicyAckCode = 3
	PolicyAckCodeStale      PolicyAckCode = 4
	PolicyAckCodeSuperseded PolicyAckCode = 5
)

// PolicyAck v4 uses a 232-byte fixed header followed by Reason:
//
//	0:80    transaction binding
//	80:82   phase and code
//	82:88   reserved
//	88:112  policy, current-policy, and selector generations
//	112:144 current and resolved target IDs
//	144:176 proposal digest
//	176:192 reservation ID
//	192:224 commit challenge
//	224:226 reason length
//	226:232 reserved
type PolicyAck struct {
	PolicyTransactionBinding
	Phase              PolicyAckPhase
	Code               PolicyAckCode
	Generation         uint64
	CurrentGeneration  uint64
	SelectorGeneration uint64
	CurrentTargetID    TargetID
	ResolvedTargetID   TargetID
	ProposalDigest     PolicyProposalDigest
	ReservationID      PolicyReservationID
	CommitChallenge    PolicyCommitChallenge
	Reason             string
}

func (p PolicyAck) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	b, err := encodePolicyTransactionBinding(p.PolicyTransactionBinding, policyTransactionAck)
	if err != nil {
		return nil, err
	}
	b = append(b, make([]byte, PolicyAckHeaderSize-PolicyTransactionBindingSize+len(p.Reason))...)
	b[80], b[81] = byte(p.Phase), byte(p.Code)
	binary.BigEndian.PutUint64(b[88:96], p.Generation)
	binary.BigEndian.PutUint64(b[96:104], p.CurrentGeneration)
	binary.BigEndian.PutUint64(b[104:112], p.SelectorGeneration)
	copy(b[112:128], p.CurrentTargetID[:])
	copy(b[128:144], p.ResolvedTargetID[:])
	copy(b[144:176], p.ProposalDigest[:])
	copy(b[176:192], p.ReservationID[:])
	copy(b[192:224], p.CommitChallenge[:])
	binary.BigEndian.PutUint16(b[224:226], uint16(len(p.Reason)))
	copy(b[PolicyAckHeaderSize:], p.Reason)
	return b, nil
}

func DecodePolicyAck(wire []byte) (PolicyAck, error) {
	if len(wire) < PolicyAckHeaderSize {
		return PolicyAck{}, fmt.Errorf("proto: policy ack payload too short: %d < %d", len(wire), PolicyAckHeaderSize)
	}
	binding, err := decodePolicyTransactionBinding(wire[:PolicyTransactionBindingSize], policyTransactionAck)
	if err != nil {
		return PolicyAck{}, err
	}
	if binary.BigEndian.Uint16(wire[82:84]) != 0 || binary.BigEndian.Uint32(wire[84:88]) != 0 || binary.BigEndian.Uint16(wire[226:228]) != 0 || binary.BigEndian.Uint32(wire[228:232]) != 0 {
		return PolicyAck{}, fmt.Errorf("proto: policy ack reserved bytes must be zero")
	}
	reasonLen := int(binary.BigEndian.Uint16(wire[224:226]))
	if reasonLen > PolicyMaxReasonBytes || len(wire)-PolicyAckHeaderSize != reasonLen {
		return PolicyAck{}, fmt.Errorf("proto: policy ack reason length %d does not match payload", reasonLen)
	}
	p := PolicyAck{
		PolicyTransactionBinding: binding,
		Phase:                    PolicyAckPhase(wire[80]),
		Code:                     PolicyAckCode(wire[81]),
		Generation:               binary.BigEndian.Uint64(wire[88:96]),
		CurrentGeneration:        binary.BigEndian.Uint64(wire[96:104]),
		SelectorGeneration:       binary.BigEndian.Uint64(wire[104:112]),
		Reason:                   string(wire[PolicyAckHeaderSize:]),
	}
	copy(p.CurrentTargetID[:], wire[112:128])
	copy(p.ResolvedTargetID[:], wire[128:144])
	copy(p.ProposalDigest[:], wire[144:176])
	copy(p.ReservationID[:], wire[176:192])
	copy(p.CommitChallenge[:], wire[192:224])
	if err := p.validate(); err != nil {
		return PolicyAck{}, err
	}
	return p, nil
}

func (p PolicyAck) validate() error {
	if err := p.PolicyTransactionBinding.Validate(); err != nil {
		return err
	}
	if p.Phase != PolicyAckPhasePrepare && p.Phase != PolicyAckPhaseFinal {
		return fmt.Errorf("proto: policy ack has invalid phase %d", p.Phase)
	}
	if p.Code < PolicyAckCodeAccept || p.Code > PolicyAckCodeSuperseded {
		return fmt.Errorf("proto: policy ack has invalid code %d", p.Code)
	}
	if p.Code == PolicyAckCodeAccept && p.Generation == 0 {
		return fmt.Errorf("proto: accepted policy ack has zero generation")
	}
	if p.Code == PolicyAckCodeAccept && p.SelectorGeneration == 0 {
		return fmt.Errorf("proto: accepted policy ack has zero selector generation")
	}
	if p.Code == PolicyAckCodeAccept && p.CurrentTargetID == (TargetID{}) {
		return fmt.Errorf("proto: accepted policy ack has zero current target id")
	}
	if p.Code == PolicyAckCodeAccept && p.ResolvedTargetID == (TargetID{}) {
		return fmt.Errorf("proto: accepted policy ack has zero resolved target id")
	}
	if p.Code != PolicyAckCodeAccept && p.ResolvedTargetID != (TargetID{}) {
		return fmt.Errorf("proto: rejected policy ack must not carry a resolved target id")
	}
	if p.ProposalDigest == (PolicyProposalDigest{}) {
		return fmt.Errorf("proto: policy ack has zero proposal digest")
	}
	if p.Code == PolicyAckCodeAccept && p.ReservationID == (PolicyReservationID{}) {
		return fmt.Errorf("proto: accepted policy ack has zero reservation id")
	}
	if p.Phase == PolicyAckPhasePrepare && p.CommitChallenge != (PolicyCommitChallenge{}) {
		return fmt.Errorf("proto: prepare policy ack carries a commit challenge")
	}
	if p.Phase == PolicyAckPhaseFinal && p.CommitChallenge == (PolicyCommitChallenge{}) {
		return fmt.Errorf("proto: final policy ack has zero commit challenge")
	}
	if len(p.Reason) > PolicyMaxReasonBytes || !utf8.ValidString(p.Reason) {
		return fmt.Errorf("proto: policy ack reason is invalid or exceeds %d bytes", PolicyMaxReasonBytes)
	}
	if p.Code == PolicyAckCodeAccept && p.Reason != "" {
		return fmt.Errorf("proto: accepted policy ack must not carry a reason")
	}
	if p.Code != PolicyAckCodeAccept && p.Reason == "" {
		return fmt.Errorf("proto: rejected policy ack must carry a reason")
	}
	return nil
}

type PolicyCommit struct {
	PolicyTransactionBinding
	Generation      uint64
	ProposalDigest  PolicyProposalDigest
	ReservationID   PolicyReservationID
	CommitChallenge PolicyCommitChallenge
}

func (p PolicyCommit) Encode() ([]byte, error) {
	if p.Generation == 0 {
		return nil, fmt.Errorf("proto: policy commit has zero generation")
	}
	if p.ProposalDigest == (PolicyProposalDigest{}) {
		return nil, fmt.Errorf("proto: policy commit has zero proposal digest")
	}
	if p.ReservationID == (PolicyReservationID{}) {
		return nil, fmt.Errorf("proto: policy commit has zero reservation id")
	}
	if p.CommitChallenge == (PolicyCommitChallenge{}) {
		return nil, fmt.Errorf("proto: policy commit has zero challenge")
	}
	b, err := encodePolicyTransactionBinding(p.PolicyTransactionBinding, policyTransactionCommit)
	if err != nil {
		return nil, err
	}
	b = append(b, make([]byte, 8)...)
	b = append(b, make([]byte, 32)...)
	b = append(b, make([]byte, 16)...)
	b = append(b, make([]byte, 32)...)
	binary.BigEndian.PutUint64(b[80:88], p.Generation)
	copy(b[88:120], p.ProposalDigest[:])
	copy(b[120:136], p.ReservationID[:])
	copy(b[136:168], p.CommitChallenge[:])
	return b, nil
}

func DecodePolicyCommit(wire []byte) (PolicyCommit, error) {
	if len(wire) != PolicyCommitSize {
		return PolicyCommit{}, fmt.Errorf("proto: policy commit payload size: %d != %d", len(wire), PolicyCommitSize)
	}
	binding, err := decodePolicyTransactionBinding(wire[:PolicyTransactionBindingSize], policyTransactionCommit)
	if err != nil {
		return PolicyCommit{}, err
	}
	p := PolicyCommit{PolicyTransactionBinding: binding, Generation: binary.BigEndian.Uint64(wire[80:88])}
	copy(p.ProposalDigest[:], wire[88:120])
	copy(p.ReservationID[:], wire[120:136])
	copy(p.CommitChallenge[:], wire[136:168])
	if p.Generation == 0 {
		return PolicyCommit{}, fmt.Errorf("proto: policy commit has zero generation")
	}
	if p.ProposalDigest == (PolicyProposalDigest{}) {
		return PolicyCommit{}, fmt.Errorf("proto: policy commit has zero proposal digest")
	}
	if p.ReservationID == (PolicyReservationID{}) {
		return PolicyCommit{}, fmt.Errorf("proto: policy commit has zero reservation id")
	}
	if p.CommitChallenge == (PolicyCommitChallenge{}) {
		return PolicyCommit{}, fmt.Errorf("proto: policy commit has zero challenge")
	}
	return p, nil
}

func encodePolicyTransactionBinding(b PolicyTransactionBinding, message policyTransactionMessage) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	wire := make([]byte, PolicyTransactionBindingSize)
	copy(wire[0:4], policyTransactionMagic[:])
	wire[4], wire[5], wire[6] = PolicyTransactionWireVersion, byte(message), byte(b.Direction)
	copy(wire[8:24], b.SessionEpoch[:])
	binary.BigEndian.PutUint64(wire[24:32], b.GraphBinding.Revision)
	copy(wire[32:64], b.GraphBinding.Digest[:])
	copy(wire[64:80], b.TransactionID[:])
	return wire, nil
}

func decodePolicyTransactionBinding(wire []byte, want policyTransactionMessage) (PolicyTransactionBinding, error) {
	if len(wire) != PolicyTransactionBindingSize {
		return PolicyTransactionBinding{}, fmt.Errorf("proto: policy transaction binding size: %d != %d", len(wire), PolicyTransactionBindingSize)
	}
	if string(wire[0:4]) != string(policyTransactionMagic[:]) || wire[4] != PolicyTransactionWireVersion || policyTransactionMessage(wire[5]) != want {
		return PolicyTransactionBinding{}, fmt.Errorf("proto: invalid policy transaction envelope")
	}
	if wire[7] != 0 {
		return PolicyTransactionBinding{}, fmt.Errorf("proto: policy transaction reserved byte must be zero")
	}
	b := PolicyTransactionBinding{
		Direction:    SenderDirection(wire[6]),
		GraphBinding: GraphBinding{Revision: binary.BigEndian.Uint64(wire[24:32])},
	}
	copy(b.SessionEpoch[:], wire[8:24])
	copy(b.GraphBinding.Digest[:], wire[32:64])
	copy(b.TransactionID[:], wire[64:80])
	if err := b.Validate(); err != nil {
		return PolicyTransactionBinding{}, err
	}
	return b, nil
}
