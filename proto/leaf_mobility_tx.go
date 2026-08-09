package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	LeafMobilityPeerPlanWireVersion    uint8 = 3
	LeafMobilityPeerPlanMaxReasonBytes       = 512
	LeafMobilityPeerPlanMaxLeaseMillis       = 90_000

	LeafMobilityPeerPlanBindingSize   = 200
	LeafMobilityPeerPlanPrepareSize   = 240
	LeafMobilityPeerPlanAckHeaderSize = 392
	LeafMobilityPeerPlanAckMaxSize    = LeafMobilityPeerPlanAckHeaderSize + LeafMobilityPeerPlanMaxReasonBytes
	LeafMobilityPeerPlanCommitSize    = 376
)

var leafMobilityPeerPlanMagic = [4]byte{'R', 'L', 'T', 'X'}

// ValidateLeafMobilityCtrlFlags rejects reserved FLAGS bits and control codes
// outside the leaf-mobility transaction. The current wire version defines no
// per-code FLAGS extensions for PREPARE, ACK, or COMMIT.
func ValidateLeafMobilityCtrlFlags(flags uint16) error {
	code := CtrlCodeFromFlags(flags)
	switch code {
	case CtrlLeafMobilityPrepare, CtrlLeafMobilityAck, CtrlLeafMobilityCommit:
	default:
		return fmt.Errorf("proto: control %s is not a leaf mobility transaction control", code)
	}
	if flags != FlagsForCtrl(code) {
		return fmt.Errorf("proto: leaf mobility control %s has non-zero reserved flags 0x%03x", code, flags&^FlagsForCtrl(code))
	}
	return nil
}

type leafMobilityPeerPlanMessage uint8

const (
	leafMobilityPeerPlanMessagePrepare leafMobilityPeerPlanMessage = 1
	leafMobilityPeerPlanMessageAck     leafMobilityPeerPlanMessage = 2
	leafMobilityPeerPlanMessageCommit  leafMobilityPeerPlanMessage = 3
)

// LeafMobilityActorSide identifies the endpoint owner that may eventually
// mutate one leaf. The coordinator and actor are separate wire facts.
type LeafMobilityActorSide uint8

const (
	LeafMobilityActorInvalid LeafMobilityActorSide = 0
	LeafMobilityActorClient  LeafMobilityActorSide = 1
	LeafMobilityActorServer  LeafMobilityActorSide = 2
)

func (s LeafMobilityActorSide) Valid() bool {
	return s == LeafMobilityActorClient || s == LeafMobilityActorServer
}

type LeafMobilitySessionKind uint8

const (
	LeafMobilitySessionInvalid LeafMobilitySessionKind = 0
	LeafMobilitySessionStream  LeafMobilitySessionKind = 1
	LeafMobilitySessionPacket  LeafMobilitySessionKind = 2
)

func (k LeafMobilitySessionKind) Valid() bool {
	return k == LeafMobilitySessionStream || k == LeafMobilitySessionPacket
}

// LeafMobilityOperation is a stable wire enum, not a capability bitset.
type LeafMobilityOperation uint8

const (
	LeafMobilityOperationInvalid          LeafMobilityOperation = 0
	LeafMobilityOperationTCPRepair        LeafMobilityOperation = 1
	LeafMobilityOperationQUICCIDRebind    LeafMobilityOperation = 2
	LeafMobilityOperationUDPFlowRebind    LeafMobilityOperation = 3
	LeafMobilityOperationGVisorLinkRebind LeafMobilityOperation = 4
)

func (o LeafMobilityOperation) Valid() bool {
	return o >= LeafMobilityOperationTCPRepair && o <= LeafMobilityOperationGVisorLinkRebind
}

type LeafMobilityFallback uint8

const (
	LeafMobilityFallbackInvalid      LeafMobilityFallback = 0
	LeafMobilityFallbackRedialAttach LeafMobilityFallback = 1
)

type LeafMobilityResourceScope uint8

const (
	LeafMobilityResourceInvalid      LeafMobilityResourceScope = 0
	LeafMobilityResourceEndpoint     LeafMobilityResourceScope = 1
	LeafMobilityResourceSharedLink   LeafMobilityResourceScope = 2
	LeafMobilityResourceProcessLocal LeafMobilityResourceScope = 3
)

func (s LeafMobilityResourceScope) Valid() bool {
	return s >= LeafMobilityResourceEndpoint && s <= LeafMobilityResourceProcessLocal
}

type LeafMobilityResourceID [16]byte

type LeafMobilityPlanDigest [32]byte
type LeafMobilityProposalDigest [32]byte
type LeafMobilityPeerDigest [32]byte
type LeafMobilityAgreementDigest [32]byte
type LeafMobilityPublicationDigest [32]byte
type LeafMobilityReservationID [16]byte

// LeafMobilityPeerPlanBinding is canonical from the client/server viewpoint.
// Local/peer ordering must never enter the wire digest because it reverses at
// the opposite endpoint.
type LeafMobilityPeerPlanBinding struct {
	CoordinatorSide LeafMobilityActorSide
	ActorSide       LeafMobilityActorSide
	Direction       SenderDirection
	SessionKind     LeafMobilitySessionKind
	Operation       LeafMobilityOperation
	Fallback        LeafMobilityFallback
	LeaseMillis     uint32
	SessionEpoch    SessionEpoch
	TransactionID   [16]byte
	ClientGraph     GraphBinding
	ServerGraph     GraphBinding
	// Subject fields identify the leaf being migrated. They never describe the
	// OOB control route, which may replay this transaction on any session path.
	SubjectClientTargetID  TargetID
	SubjectServerTargetID  TargetID
	BaseGeneration         uint64
	ResourceScope          LeafMobilityResourceScope
	ResourceID             LeafMobilityResourceID
	SubjectRouteGeneration uint64
}

func (b LeafMobilityPeerPlanBinding) Validate() error {
	if !b.CoordinatorSide.Valid() {
		return fmt.Errorf("proto: leaf mobility peer plan has invalid coordinator side %d", b.CoordinatorSide)
	}
	if !b.ActorSide.Valid() {
		return fmt.Errorf("proto: leaf mobility peer plan has invalid actor side %d", b.ActorSide)
	}
	if b.CoordinatorSide != LeafMobilityActorClient {
		return fmt.Errorf("proto: v1 leaf mobility coordinator must be the client")
	}
	if !b.Direction.Valid() {
		return fmt.Errorf("proto: leaf mobility peer plan has invalid direction %d", b.Direction)
	}
	if !b.SessionKind.Valid() {
		return fmt.Errorf("proto: leaf mobility peer plan has invalid session kind %d", b.SessionKind)
	}
	if !b.Operation.Valid() {
		return fmt.Errorf("proto: leaf mobility peer plan has invalid operation %d", b.Operation)
	}
	switch b.Operation {
	case LeafMobilityOperationTCPRepair, LeafMobilityOperationGVisorLinkRebind:
		if b.SessionKind != LeafMobilitySessionStream {
			return fmt.Errorf("proto: leaf mobility operation %d requires a stream session", b.Operation)
		}
	case LeafMobilityOperationUDPFlowRebind:
		if b.SessionKind != LeafMobilitySessionPacket {
			return fmt.Errorf("proto: UDP flow rebind requires a packet session")
		}
	case LeafMobilityOperationQUICCIDRebind:
		// QUIC stream and DATAGRAM sessions both share connection migration.
	}
	if b.Fallback != LeafMobilityFallbackRedialAttach {
		return fmt.Errorf("proto: leaf mobility peer plan has invalid fallback %d", b.Fallback)
	}
	if b.LeaseMillis == 0 || b.LeaseMillis > LeafMobilityPeerPlanMaxLeaseMillis {
		return fmt.Errorf("proto: leaf mobility peer plan lease %dms is outside [1,%d]", b.LeaseMillis, LeafMobilityPeerPlanMaxLeaseMillis)
	}
	if b.SessionEpoch == (SessionEpoch{}) {
		return fmt.Errorf("proto: leaf mobility peer plan has zero session epoch")
	}
	if b.TransactionID == ([16]byte{}) {
		return fmt.Errorf("proto: leaf mobility peer plan has zero transaction id")
	}
	for name, graph := range map[string]GraphBinding{"client": b.ClientGraph, "server": b.ServerGraph} {
		if graph.Revision == 0 || graph.Digest == (GraphDigest{}) {
			return fmt.Errorf("proto: leaf mobility peer plan has invalid %s graph binding", name)
		}
	}
	if b.SubjectClientTargetID == (TargetID{}) || b.SubjectServerTargetID == (TargetID{}) {
		return fmt.Errorf("proto: leaf mobility peer plan has zero subject client or server target id")
	}
	if b.BaseGeneration == ^uint64(0) {
		return fmt.Errorf("proto: leaf mobility peer plan generation cannot advance")
	}
	if !b.ResourceScope.Valid() || b.ResourceID == (LeafMobilityResourceID{}) {
		return fmt.Errorf("proto: leaf mobility peer plan has invalid resource identity")
	}
	if b.SubjectRouteGeneration == 0 {
		return fmt.Errorf("proto: leaf mobility peer plan has zero subject route generation")
	}
	return nil
}

// LeafMobilityPeerPlanView converts one endpoint's local/peer observations to
// client/server canonical wire order. LeaseMillis creates a local deadline
// only on the first observation of LeaseKey; replay must never refresh it.
type LeafMobilityPeerPlanView struct {
	LocalSide              LeafMobilityActorSide
	CoordinatorSide        LeafMobilityActorSide
	ActorSide              LeafMobilityActorSide
	Direction              SenderDirection
	SessionKind            LeafMobilitySessionKind
	Operation              LeafMobilityOperation
	Fallback               LeafMobilityFallback
	LeaseMillis            uint32
	SessionEpoch           SessionEpoch
	TransactionID          [16]byte
	LocalGraph             GraphBinding
	PeerGraph              GraphBinding
	LocalTargetID          TargetID
	PeerTargetID           TargetID
	BaseGeneration         uint64
	ResourceScope          LeafMobilityResourceScope
	ResourceID             LeafMobilityResourceID
	SubjectRouteGeneration uint64
}

func (v LeafMobilityPeerPlanView) CanonicalBinding() (LeafMobilityPeerPlanBinding, error) {
	binding := LeafMobilityPeerPlanBinding{
		CoordinatorSide:        v.CoordinatorSide,
		ActorSide:              v.ActorSide,
		Direction:              v.Direction,
		SessionKind:            v.SessionKind,
		Operation:              v.Operation,
		Fallback:               v.Fallback,
		LeaseMillis:            v.LeaseMillis,
		SessionEpoch:           v.SessionEpoch,
		TransactionID:          v.TransactionID,
		BaseGeneration:         v.BaseGeneration,
		ResourceScope:          v.ResourceScope,
		ResourceID:             v.ResourceID,
		SubjectRouteGeneration: v.SubjectRouteGeneration,
	}
	switch v.LocalSide {
	case LeafMobilityActorClient:
		binding.ClientGraph, binding.ServerGraph = v.LocalGraph, v.PeerGraph
		binding.SubjectClientTargetID, binding.SubjectServerTargetID = v.LocalTargetID, v.PeerTargetID
	case LeafMobilityActorServer:
		binding.ClientGraph, binding.ServerGraph = v.PeerGraph, v.LocalGraph
		binding.SubjectClientTargetID, binding.SubjectServerTargetID = v.PeerTargetID, v.LocalTargetID
	default:
		return LeafMobilityPeerPlanBinding{}, fmt.Errorf("proto: leaf mobility peer-plan view has invalid local side %d", v.LocalSide)
	}
	if err := binding.Validate(); err != nil {
		return LeafMobilityPeerPlanBinding{}, err
	}
	return binding, nil
}

type LeafMobilityLeaseKey struct {
	SessionEpoch   SessionEpoch
	TransactionID  [16]byte
	BaseGeneration uint64
}

func (b LeafMobilityPeerPlanBinding) LeaseKey() LeafMobilityLeaseKey {
	return LeafMobilityLeaseKey{SessionEpoch: b.SessionEpoch, TransactionID: b.TransactionID, BaseGeneration: b.BaseGeneration}
}

func (b LeafMobilityPeerPlanBinding) ReservedGeneration() (uint64, error) {
	if err := b.Validate(); err != nil {
		return 0, err
	}
	return b.BaseGeneration + 1, nil
}

type LeafMobilityPeerPlanPrepare struct {
	LeafMobilityPeerPlanBinding
	ActorEndpointGeneration uint64
	ActorPlanDigest         LeafMobilityPlanDigest
}

func (p LeafMobilityPeerPlanPrepare) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	wire, err := encodeLeafMobilityPeerPlanBinding(p.LeafMobilityPeerPlanBinding, leafMobilityPeerPlanMessagePrepare)
	if err != nil {
		return nil, err
	}
	wire = append(wire, make([]byte, LeafMobilityPeerPlanPrepareSize-LeafMobilityPeerPlanBindingSize)...)
	offset := LeafMobilityPeerPlanBindingSize
	binary.BigEndian.PutUint64(wire[offset:offset+8], p.ActorEndpointGeneration)
	copy(wire[offset+8:offset+40], p.ActorPlanDigest[:])
	return wire, nil
}

func DecodeLeafMobilityPeerPlanPrepare(wire []byte) (LeafMobilityPeerPlanPrepare, error) {
	if len(wire) != LeafMobilityPeerPlanPrepareSize {
		return LeafMobilityPeerPlanPrepare{}, fmt.Errorf("proto: leaf mobility prepare payload size: %d != %d", len(wire), LeafMobilityPeerPlanPrepareSize)
	}
	binding, err := decodeLeafMobilityPeerPlanBinding(wire[:LeafMobilityPeerPlanBindingSize], leafMobilityPeerPlanMessagePrepare)
	if err != nil {
		return LeafMobilityPeerPlanPrepare{}, err
	}
	offset := LeafMobilityPeerPlanBindingSize
	p := LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     binary.BigEndian.Uint64(wire[offset : offset+8]),
	}
	copy(p.ActorPlanDigest[:], wire[offset+8:offset+40])
	if err := p.validate(); err != nil {
		return LeafMobilityPeerPlanPrepare{}, err
	}
	return p, nil
}

func (p LeafMobilityPeerPlanPrepare) validate() error {
	if err := p.LeafMobilityPeerPlanBinding.Validate(); err != nil {
		return err
	}
	if p.ActorEndpointGeneration == 0 {
		return fmt.Errorf("proto: leaf mobility prepare has zero actor endpoint generation")
	}
	if p.ActorPlanDigest == (LeafMobilityPlanDigest{}) {
		return fmt.Errorf("proto: leaf mobility prepare has zero actor plan digest")
	}
	return nil
}

func (p LeafMobilityPeerPlanPrepare) ProposalDigest() (LeafMobilityProposalDigest, error) {
	wire, err := p.Encode()
	if err != nil {
		return LeafMobilityProposalDigest{}, err
	}
	h := sha256.New()
	h.Write([]byte("rendr-leaf-mobility-proposal-v3\x00"))
	h.Write(wire)
	var digest LeafMobilityProposalDigest
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

type LeafMobilityPeerPlanAckPhase uint8

const (
	LeafMobilityPeerPlanAckPhaseInvalid  LeafMobilityPeerPlanAckPhase = 0
	LeafMobilityPeerPlanAckPhasePrepared LeafMobilityPeerPlanAckPhase = 1
	LeafMobilityPeerPlanAckPhaseFinal    LeafMobilityPeerPlanAckPhase = 2
	LeafMobilityPeerPlanAckPhaseReleased LeafMobilityPeerPlanAckPhase = 3
)

// LeafMobilityPeerPlanCommitStage separates publication of the execution
// decision from the terminal proof that both resource guards can be released.
// Abort is the pre-COMMIT terminal stage. PREPARE publication still consumes
// a resource generation so delayed attempts cannot reuse an old base.
type LeafMobilityPeerPlanCommitStage uint8

const (
	LeafMobilityPeerPlanCommitStageInvalid    LeafMobilityPeerPlanCommitStage = 0
	LeafMobilityPeerPlanCommitStageCommit     LeafMobilityPeerPlanCommitStage = 1
	LeafMobilityPeerPlanCommitStageComplete   LeafMobilityPeerPlanCommitStage = 2
	LeafMobilityPeerPlanCommitStageRolledBack LeafMobilityPeerPlanCommitStage = 3
	LeafMobilityPeerPlanCommitStageAbort      LeafMobilityPeerPlanCommitStage = 4
)

func (s LeafMobilityPeerPlanCommitStage) valid() bool {
	return s >= LeafMobilityPeerPlanCommitStageCommit && s <= LeafMobilityPeerPlanCommitStageAbort
}

func (s LeafMobilityPeerPlanCommitStage) consumesGeneration() bool {
	return s.valid()
}

type LeafMobilityPeerPlanAckCode uint8

const (
	LeafMobilityPeerPlanAckCodeInvalid    LeafMobilityPeerPlanAckCode = 0
	LeafMobilityPeerPlanAckCodeAccept     LeafMobilityPeerPlanAckCode = 1
	LeafMobilityPeerPlanAckCodeReject     LeafMobilityPeerPlanAckCode = 2
	LeafMobilityPeerPlanAckCodeBusy       LeafMobilityPeerPlanAckCode = 3
	LeafMobilityPeerPlanAckCodeStale      LeafMobilityPeerPlanAckCode = 4
	LeafMobilityPeerPlanAckCodeSuperseded LeafMobilityPeerPlanAckCode = 5
)

type LeafMobilityPeerPlanAck struct {
	LeafMobilityPeerPlanBinding
	Phase LeafMobilityPeerPlanAckPhase
	Code  LeafMobilityPeerPlanAckCode
	Stage LeafMobilityPeerPlanCommitStage
	// CurrentGeneration is BaseGeneration in the prepared phase and the
	// reserved Generation in the final phase. A final rejection still closes
	// the committed reservation; a later generation belongs to another
	// transaction and must not be reported through this ACK.
	CurrentGeneration       uint64
	Generation              uint64
	ActorEndpointGeneration uint64
	PeerEndpointGeneration  uint64
	ProposalDigest          LeafMobilityProposalDigest
	PeerPlanDigest          LeafMobilityPeerDigest
	AgreementDigest         LeafMobilityAgreementDigest
	ReservationID           LeafMobilityReservationID
	PublicationDigest       LeafMobilityPublicationDigest
	Reason                  string
}

func (p LeafMobilityPeerPlanAck) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	wire, err := encodeLeafMobilityPeerPlanBinding(p.LeafMobilityPeerPlanBinding, leafMobilityPeerPlanMessageAck)
	if err != nil {
		return nil, err
	}
	wire = append(wire, make([]byte, LeafMobilityPeerPlanAckHeaderSize-LeafMobilityPeerPlanBindingSize+len(p.Reason))...)
	offset := LeafMobilityPeerPlanBindingSize
	wire[offset], wire[offset+1], wire[offset+2] = byte(p.Phase), byte(p.Code), byte(p.Stage)
	binary.BigEndian.PutUint64(wire[offset+8:offset+16], p.CurrentGeneration)
	binary.BigEndian.PutUint64(wire[offset+16:offset+24], p.Generation)
	binary.BigEndian.PutUint64(wire[offset+24:offset+32], p.ActorEndpointGeneration)
	binary.BigEndian.PutUint64(wire[offset+32:offset+40], p.PeerEndpointGeneration)
	copy(wire[offset+40:offset+72], p.ProposalDigest[:])
	copy(wire[offset+72:offset+104], p.PeerPlanDigest[:])
	copy(wire[offset+104:offset+136], p.AgreementDigest[:])
	copy(wire[offset+136:offset+152], p.ReservationID[:])
	binary.BigEndian.PutUint16(wire[offset+152:offset+154], uint16(len(p.Reason)))
	copy(wire[offset+160:offset+192], p.PublicationDigest[:])
	copy(wire[LeafMobilityPeerPlanAckHeaderSize:], p.Reason)
	return wire, nil
}

func DecodeLeafMobilityPeerPlanAck(wire []byte) (LeafMobilityPeerPlanAck, error) {
	if len(wire) < LeafMobilityPeerPlanAckHeaderSize || len(wire) > LeafMobilityPeerPlanAckMaxSize {
		return LeafMobilityPeerPlanAck{}, fmt.Errorf("proto: leaf mobility ACK payload size %d is outside [%d,%d]", len(wire), LeafMobilityPeerPlanAckHeaderSize, LeafMobilityPeerPlanAckMaxSize)
	}
	offset := LeafMobilityPeerPlanBindingSize
	if wire[offset+3] != 0 || binary.BigEndian.Uint32(wire[offset+4:offset+8]) != 0 ||
		binary.BigEndian.Uint16(wire[offset+154:offset+156]) != 0 || binary.BigEndian.Uint32(wire[offset+156:offset+160]) != 0 {
		return LeafMobilityPeerPlanAck{}, fmt.Errorf("proto: leaf mobility ACK reserved bytes must be zero")
	}
	reasonLen := int(binary.BigEndian.Uint16(wire[offset+152 : offset+154]))
	if reasonLen > LeafMobilityPeerPlanMaxReasonBytes || len(wire)-LeafMobilityPeerPlanAckHeaderSize != reasonLen {
		return LeafMobilityPeerPlanAck{}, fmt.Errorf("proto: leaf mobility ACK reason length %d does not match payload", reasonLen)
	}
	binding, err := decodeLeafMobilityPeerPlanBinding(wire[:LeafMobilityPeerPlanBindingSize], leafMobilityPeerPlanMessageAck)
	if err != nil {
		return LeafMobilityPeerPlanAck{}, err
	}
	p := LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: binding,
		Phase:                       LeafMobilityPeerPlanAckPhase(wire[offset]),
		Code:                        LeafMobilityPeerPlanAckCode(wire[offset+1]),
		Stage:                       LeafMobilityPeerPlanCommitStage(wire[offset+2]),
		CurrentGeneration:           binary.BigEndian.Uint64(wire[offset+8 : offset+16]),
		Generation:                  binary.BigEndian.Uint64(wire[offset+16 : offset+24]),
		ActorEndpointGeneration:     binary.BigEndian.Uint64(wire[offset+24 : offset+32]),
		PeerEndpointGeneration:      binary.BigEndian.Uint64(wire[offset+32 : offset+40]),
		Reason:                      string(wire[LeafMobilityPeerPlanAckHeaderSize:]),
	}
	copy(p.ProposalDigest[:], wire[offset+40:offset+72])
	copy(p.PeerPlanDigest[:], wire[offset+72:offset+104])
	copy(p.AgreementDigest[:], wire[offset+104:offset+136])
	copy(p.ReservationID[:], wire[offset+136:offset+152])
	copy(p.PublicationDigest[:], wire[offset+160:offset+192])
	if err := p.validate(); err != nil {
		return LeafMobilityPeerPlanAck{}, err
	}
	return p, nil
}

func (p LeafMobilityPeerPlanAck) validate() error {
	if err := p.LeafMobilityPeerPlanBinding.Validate(); err != nil {
		return err
	}
	if p.Phase != LeafMobilityPeerPlanAckPhasePrepared && p.Phase != LeafMobilityPeerPlanAckPhaseFinal &&
		p.Phase != LeafMobilityPeerPlanAckPhaseReleased {
		return fmt.Errorf("proto: leaf mobility ACK has invalid phase %d", p.Phase)
	}
	switch p.Phase {
	case LeafMobilityPeerPlanAckPhasePrepared:
		if p.Stage != LeafMobilityPeerPlanCommitStageInvalid {
			return fmt.Errorf("proto: prepared leaf mobility ACK cannot name a commit stage")
		}
		if p.PublicationDigest != (LeafMobilityPublicationDigest{}) {
			return fmt.Errorf("proto: prepared leaf mobility ACK has a publication digest")
		}
	case LeafMobilityPeerPlanAckPhaseFinal:
		if p.Stage != LeafMobilityPeerPlanCommitStageCommit {
			return fmt.Errorf("proto: final leaf mobility ACK must acknowledge COMMIT")
		}
		if p.PublicationDigest == (LeafMobilityPublicationDigest{}) {
			return fmt.Errorf("proto: final leaf mobility ACK has zero publication digest")
		}
	case LeafMobilityPeerPlanAckPhaseReleased:
		if p.Stage != LeafMobilityPeerPlanCommitStageComplete &&
			p.Stage != LeafMobilityPeerPlanCommitStageRolledBack &&
			p.Stage != LeafMobilityPeerPlanCommitStageAbort {
			return fmt.Errorf("proto: released leaf mobility ACK has invalid resolution stage %d", p.Stage)
		}
		if err := validateLeafMobilityPublicationDigest(p.Stage, p.PublicationDigest); err != nil {
			return fmt.Errorf("proto: released leaf mobility ACK: %w", err)
		}
	}
	if p.Code < LeafMobilityPeerPlanAckCodeAccept || p.Code > LeafMobilityPeerPlanAckCodeSuperseded {
		return fmt.Errorf("proto: leaf mobility ACK has invalid code %d", p.Code)
	}
	if p.ActorEndpointGeneration == 0 || p.ProposalDigest == (LeafMobilityProposalDigest{}) {
		return fmt.Errorf("proto: leaf mobility ACK lacks actor generation or proposal digest")
	}
	if len(p.Reason) > LeafMobilityPeerPlanMaxReasonBytes || !utf8.ValidString(p.Reason) {
		return fmt.Errorf("proto: leaf mobility ACK reason is invalid or exceeds %d bytes", LeafMobilityPeerPlanMaxReasonBytes)
	}
	wantGeneration, err := p.ReservedGeneration()
	if err != nil {
		return err
	}
	wantCurrent := p.BaseGeneration
	if p.Phase == LeafMobilityPeerPlanAckPhaseFinal ||
		(p.Phase == LeafMobilityPeerPlanAckPhaseReleased && p.Stage.consumesGeneration()) {
		wantCurrent = wantGeneration
	}
	if p.CurrentGeneration != wantCurrent {
		return fmt.Errorf("proto: leaf mobility ACK has invalid current generation")
	}
	hasAgreement := p.Code == LeafMobilityPeerPlanAckCodeAccept ||
		p.Phase == LeafMobilityPeerPlanAckPhaseFinal || p.Phase == LeafMobilityPeerPlanAckPhaseReleased
	if hasAgreement {
		if p.Generation != wantGeneration || p.PeerEndpointGeneration == 0 ||
			p.PeerPlanDigest == (LeafMobilityPeerDigest{}) || p.AgreementDigest == (LeafMobilityAgreementDigest{}) ||
			p.ReservationID == (LeafMobilityReservationID{}) {
			return fmt.Errorf("proto: leaf mobility ACK lacks canonical agreement evidence")
		}
		if p.Code == LeafMobilityPeerPlanAckCodeAccept && p.Reason != "" {
			return fmt.Errorf("proto: accepted leaf mobility ACK has a rejection reason")
		}
		if p.Code != LeafMobilityPeerPlanAckCodeAccept && p.Reason == "" {
			return fmt.Errorf("proto: rejected final leaf mobility ACK lacks a reason")
		}
		want, err := ComputeLeafMobilityAgreementDigest(
			p.LeafMobilityPeerPlanBinding, p.Generation, p.ActorEndpointGeneration,
			p.PeerEndpointGeneration, p.ProposalDigest, p.PeerPlanDigest, p.ReservationID,
		)
		if err != nil || want != p.AgreementDigest {
			return fmt.Errorf("proto: leaf mobility ACK has invalid agreement digest")
		}
		return nil
	}
	if p.Generation != 0 || p.PeerEndpointGeneration != 0 || p.PeerPlanDigest != (LeafMobilityPeerDigest{}) ||
		p.AgreementDigest != (LeafMobilityAgreementDigest{}) || p.ReservationID != (LeafMobilityReservationID{}) || p.Reason == "" {
		return fmt.Errorf("proto: rejected leaf mobility ACK has invalid agreement evidence")
	}
	return nil
}

func (p LeafMobilityPeerPlanAck) ValidateForPrepare(prepare LeafMobilityPeerPlanPrepare) error {
	if err := prepare.validate(); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	if p.Phase != LeafMobilityPeerPlanAckPhasePrepared {
		return fmt.Errorf("proto: leaf mobility prepare requires a prepared ACK")
	}
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		return err
	}
	if p.LeafMobilityPeerPlanBinding != prepare.LeafMobilityPeerPlanBinding ||
		p.ActorEndpointGeneration != prepare.ActorEndpointGeneration || p.ProposalDigest != proposal {
		return fmt.Errorf("proto: leaf mobility ACK does not match prepare")
	}
	return nil
}

type LeafMobilityPeerPlanCommit struct {
	LeafMobilityPeerPlanBinding
	Stage                   LeafMobilityPeerPlanCommitStage
	Generation              uint64
	ActorEndpointGeneration uint64
	PeerEndpointGeneration  uint64
	ProposalDigest          LeafMobilityProposalDigest
	PeerPlanDigest          LeafMobilityPeerDigest
	AgreementDigest         LeafMobilityAgreementDigest
	ReservationID           LeafMobilityReservationID
	PublicationDigest       LeafMobilityPublicationDigest
}

func (p LeafMobilityPeerPlanCommit) Encode() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	wire, err := encodeLeafMobilityPeerPlanBinding(p.LeafMobilityPeerPlanBinding, leafMobilityPeerPlanMessageCommit)
	if err != nil {
		return nil, err
	}
	wire = append(wire, make([]byte, LeafMobilityPeerPlanCommitSize-LeafMobilityPeerPlanBindingSize)...)
	offset := LeafMobilityPeerPlanBindingSize
	binary.BigEndian.PutUint64(wire[offset:offset+8], p.Generation)
	binary.BigEndian.PutUint64(wire[offset+8:offset+16], p.ActorEndpointGeneration)
	binary.BigEndian.PutUint64(wire[offset+16:offset+24], p.PeerEndpointGeneration)
	copy(wire[offset+24:offset+56], p.ProposalDigest[:])
	copy(wire[offset+56:offset+88], p.PeerPlanDigest[:])
	copy(wire[offset+88:offset+120], p.AgreementDigest[:])
	copy(wire[offset+120:offset+136], p.ReservationID[:])
	wire[offset+136] = byte(p.Stage)
	copy(wire[offset+144:offset+176], p.PublicationDigest[:])
	return wire, nil
}

func DecodeLeafMobilityPeerPlanCommit(wire []byte) (LeafMobilityPeerPlanCommit, error) {
	if len(wire) != LeafMobilityPeerPlanCommitSize {
		return LeafMobilityPeerPlanCommit{}, fmt.Errorf("proto: leaf mobility commit payload size: %d != %d", len(wire), LeafMobilityPeerPlanCommitSize)
	}
	binding, err := decodeLeafMobilityPeerPlanBinding(wire[:LeafMobilityPeerPlanBindingSize], leafMobilityPeerPlanMessageCommit)
	if err != nil {
		return LeafMobilityPeerPlanCommit{}, err
	}
	offset := LeafMobilityPeerPlanBindingSize
	p := LeafMobilityPeerPlanCommit{
		LeafMobilityPeerPlanBinding: binding,
		Stage:                       LeafMobilityPeerPlanCommitStage(wire[offset+136]),
		Generation:                  binary.BigEndian.Uint64(wire[offset : offset+8]),
		ActorEndpointGeneration:     binary.BigEndian.Uint64(wire[offset+8 : offset+16]),
		PeerEndpointGeneration:      binary.BigEndian.Uint64(wire[offset+16 : offset+24]),
	}
	copy(p.ProposalDigest[:], wire[offset+24:offset+56])
	copy(p.PeerPlanDigest[:], wire[offset+56:offset+88])
	copy(p.AgreementDigest[:], wire[offset+88:offset+120])
	copy(p.ReservationID[:], wire[offset+120:offset+136])
	copy(p.PublicationDigest[:], wire[offset+144:offset+176])
	if binary.BigEndian.Uint32(wire[offset+137:offset+141]) != 0 ||
		wire[offset+141] != 0 || binary.BigEndian.Uint16(wire[offset+142:offset+144]) != 0 {
		return LeafMobilityPeerPlanCommit{}, fmt.Errorf("proto: leaf mobility commit reserved bytes must be zero")
	}
	if err := p.validate(); err != nil {
		return LeafMobilityPeerPlanCommit{}, err
	}
	return p, nil
}

func (p LeafMobilityPeerPlanCommit) validate() error {
	if err := p.LeafMobilityPeerPlanBinding.Validate(); err != nil {
		return err
	}
	if !p.Stage.valid() {
		return fmt.Errorf("proto: leaf mobility commit has invalid stage %d", p.Stage)
	}
	if err := validateLeafMobilityPublicationDigest(p.Stage, p.PublicationDigest); err != nil {
		return err
	}
	wantGeneration, err := p.ReservedGeneration()
	if err != nil {
		return err
	}
	if p.Generation != wantGeneration || p.ActorEndpointGeneration == 0 || p.PeerEndpointGeneration == 0 ||
		p.ProposalDigest == (LeafMobilityProposalDigest{}) || p.PeerPlanDigest == (LeafMobilityPeerDigest{}) ||
		p.AgreementDigest == (LeafMobilityAgreementDigest{}) || p.ReservationID == (LeafMobilityReservationID{}) {
		return fmt.Errorf("proto: leaf mobility commit lacks canonical agreement evidence")
	}
	want, err := ComputeLeafMobilityAgreementDigest(
		p.LeafMobilityPeerPlanBinding, p.Generation, p.ActorEndpointGeneration,
		p.PeerEndpointGeneration, p.ProposalDigest, p.PeerPlanDigest, p.ReservationID,
	)
	if err != nil || want != p.AgreementDigest {
		return fmt.Errorf("proto: leaf mobility commit has invalid agreement digest")
	}
	return nil
}

func (p LeafMobilityPeerPlanCommit) ValidateForPrepared(prepare LeafMobilityPeerPlanPrepare, ack LeafMobilityPeerPlanAck) error {
	if err := ack.ValidateForPrepare(prepare); err != nil {
		return err
	}
	if ack.Phase != LeafMobilityPeerPlanAckPhasePrepared || ack.Code != LeafMobilityPeerPlanAckCodeAccept {
		return fmt.Errorf("proto: leaf mobility commit requires an accepted prepared ACK")
	}
	if err := p.validate(); err != nil {
		return err
	}
	if p.LeafMobilityPeerPlanBinding != ack.LeafMobilityPeerPlanBinding ||
		p.Generation != ack.Generation || p.ActorEndpointGeneration != ack.ActorEndpointGeneration ||
		p.PeerEndpointGeneration != ack.PeerEndpointGeneration || p.ProposalDigest != ack.ProposalDigest ||
		p.PeerPlanDigest != ack.PeerPlanDigest || p.AgreementDigest != ack.AgreementDigest ||
		p.ReservationID != ack.ReservationID {
		return fmt.Errorf("proto: leaf mobility commit does not match prepared ACK")
	}
	return nil
}

// ValidateForCommit correlates a post-COMMIT terminal resolution with the
// exact staged publication. Pre-COMMIT ROLLED_BACK and ABORT instead correlate
// through ValidateForPrepared and carry a zero publication digest.
func (p LeafMobilityPeerPlanCommit) ValidateForCommit(commit LeafMobilityPeerPlanCommit) error {
	if err := commit.validate(); err != nil {
		return err
	}
	if commit.Stage != LeafMobilityPeerPlanCommitStageCommit {
		return fmt.Errorf("proto: leaf mobility terminal resolution requires COMMIT")
	}
	if err := p.validate(); err != nil {
		return err
	}
	if p.Stage != LeafMobilityPeerPlanCommitStageComplete && p.Stage != LeafMobilityPeerPlanCommitStageRolledBack {
		return fmt.Errorf("proto: leaf mobility COMMIT has invalid terminal resolution stage %d", p.Stage)
	}
	correlated := p
	correlated.Stage = LeafMobilityPeerPlanCommitStageCommit
	if correlated != commit {
		return fmt.Errorf("proto: leaf mobility terminal resolution does not match COMMIT")
	}
	return nil
}

func (p LeafMobilityPeerPlanAck) ValidateForCommit(commit LeafMobilityPeerPlanCommit) error {
	if err := commit.validate(); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	wantPhase := LeafMobilityPeerPlanAckPhaseReleased
	if commit.Stage == LeafMobilityPeerPlanCommitStageCommit {
		wantPhase = LeafMobilityPeerPlanAckPhaseFinal
	}
	if p.Phase != wantPhase || p.Stage != commit.Stage {
		return fmt.Errorf("proto: leaf mobility commit stage %d requires ACK phase %d", commit.Stage, wantPhase)
	}
	if p.LeafMobilityPeerPlanBinding != commit.LeafMobilityPeerPlanBinding ||
		p.Generation != commit.Generation || p.ActorEndpointGeneration != commit.ActorEndpointGeneration ||
		p.PeerEndpointGeneration != commit.PeerEndpointGeneration || p.ProposalDigest != commit.ProposalDigest ||
		p.PeerPlanDigest != commit.PeerPlanDigest || p.AgreementDigest != commit.AgreementDigest ||
		p.ReservationID != commit.ReservationID || p.PublicationDigest != commit.PublicationDigest {
		return fmt.Errorf("proto: leaf mobility final ACK does not match commit")
	}
	return nil
}

func validateLeafMobilityPublicationDigest(stage LeafMobilityPeerPlanCommitStage, digest LeafMobilityPublicationDigest) error {
	switch stage {
	case LeafMobilityPeerPlanCommitStageCommit, LeafMobilityPeerPlanCommitStageComplete:
		if digest == (LeafMobilityPublicationDigest{}) {
			return fmt.Errorf("proto: leaf mobility stage %d has zero publication digest", stage)
		}
	case LeafMobilityPeerPlanCommitStageAbort:
		if digest != (LeafMobilityPublicationDigest{}) {
			return fmt.Errorf("proto: leaf mobility ABORT has a publication digest")
		}
	case LeafMobilityPeerPlanCommitStageRolledBack:
		// A rollback before COMMIT has no publication digest. After COMMIT it
		// echoes the already-bound digest; correlation validates exact equality.
	}
	return nil
}

func ComputeLeafMobilityAgreementDigest(
	binding LeafMobilityPeerPlanBinding,
	generation uint64,
	actorEndpointGeneration uint64,
	peerEndpointGeneration uint64,
	proposalDigest LeafMobilityProposalDigest,
	peerPlanDigest LeafMobilityPeerDigest,
	reservationID LeafMobilityReservationID,
) (LeafMobilityAgreementDigest, error) {
	if err := binding.Validate(); err != nil {
		return LeafMobilityAgreementDigest{}, err
	}
	wantGeneration, err := binding.ReservedGeneration()
	if err != nil {
		return LeafMobilityAgreementDigest{}, err
	}
	if generation != wantGeneration || actorEndpointGeneration == 0 || peerEndpointGeneration == 0 ||
		proposalDigest == (LeafMobilityProposalDigest{}) || peerPlanDigest == (LeafMobilityPeerDigest{}) ||
		reservationID == (LeafMobilityReservationID{}) {
		return LeafMobilityAgreementDigest{}, fmt.Errorf("proto: invalid leaf mobility agreement evidence")
	}
	canonical, err := encodeLeafMobilityPeerPlanBinding(binding, leafMobilityPeerPlanMessagePrepare)
	if err != nil {
		return LeafMobilityAgreementDigest{}, err
	}
	canonical[5] = 0
	h := sha256.New()
	h.Write([]byte("rendr-leaf-mobility-agreement-v3\x00"))
	h.Write(canonical)
	var scalar [24]byte
	binary.BigEndian.PutUint64(scalar[0:8], generation)
	binary.BigEndian.PutUint64(scalar[8:16], actorEndpointGeneration)
	binary.BigEndian.PutUint64(scalar[16:24], peerEndpointGeneration)
	h.Write(scalar[:])
	h.Write(proposalDigest[:])
	h.Write(peerPlanDigest[:])
	h.Write(reservationID[:])
	var digest LeafMobilityAgreementDigest
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func encodeLeafMobilityPeerPlanBinding(binding LeafMobilityPeerPlanBinding, message leafMobilityPeerPlanMessage) ([]byte, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	wire := make([]byte, LeafMobilityPeerPlanBindingSize)
	copy(wire[0:4], leafMobilityPeerPlanMagic[:])
	wire[4], wire[5] = LeafMobilityPeerPlanWireVersion, byte(message)
	wire[6], wire[7] = byte(binding.CoordinatorSide), byte(binding.ActorSide)
	wire[8], wire[9] = byte(binding.Direction), byte(binding.SessionKind)
	wire[10], wire[11] = byte(binding.Operation), byte(binding.Fallback)
	binary.BigEndian.PutUint32(wire[12:16], binding.LeaseMillis)
	copy(wire[16:32], binding.SessionEpoch[:])
	copy(wire[32:48], binding.TransactionID[:])
	binary.BigEndian.PutUint64(wire[48:56], binding.ClientGraph.Revision)
	copy(wire[56:88], binding.ClientGraph.Digest[:])
	binary.BigEndian.PutUint64(wire[88:96], binding.ServerGraph.Revision)
	copy(wire[96:128], binding.ServerGraph.Digest[:])
	copy(wire[128:144], binding.SubjectClientTargetID[:])
	copy(wire[144:160], binding.SubjectServerTargetID[:])
	binary.BigEndian.PutUint64(wire[160:168], binding.BaseGeneration)
	wire[168] = byte(binding.ResourceScope)
	copy(wire[176:192], binding.ResourceID[:])
	binary.BigEndian.PutUint64(wire[192:200], binding.SubjectRouteGeneration)
	return wire, nil
}

func decodeLeafMobilityPeerPlanBinding(wire []byte, want leafMobilityPeerPlanMessage) (LeafMobilityPeerPlanBinding, error) {
	if len(wire) != LeafMobilityPeerPlanBindingSize {
		return LeafMobilityPeerPlanBinding{}, fmt.Errorf("proto: leaf mobility binding size: %d != %d", len(wire), LeafMobilityPeerPlanBindingSize)
	}
	if string(wire[0:4]) != string(leafMobilityPeerPlanMagic[:]) || wire[4] != LeafMobilityPeerPlanWireVersion || leafMobilityPeerPlanMessage(wire[5]) != want {
		return LeafMobilityPeerPlanBinding{}, fmt.Errorf("proto: invalid leaf mobility peer plan envelope")
	}
	if wire[169] != 0 || binary.BigEndian.Uint16(wire[170:172]) != 0 || binary.BigEndian.Uint32(wire[172:176]) != 0 {
		return LeafMobilityPeerPlanBinding{}, fmt.Errorf("proto: leaf mobility peer plan reserved bytes must be zero")
	}
	binding := LeafMobilityPeerPlanBinding{
		CoordinatorSide:        LeafMobilityActorSide(wire[6]),
		ActorSide:              LeafMobilityActorSide(wire[7]),
		Direction:              SenderDirection(wire[8]),
		SessionKind:            LeafMobilitySessionKind(wire[9]),
		Operation:              LeafMobilityOperation(wire[10]),
		Fallback:               LeafMobilityFallback(wire[11]),
		LeaseMillis:            binary.BigEndian.Uint32(wire[12:16]),
		ClientGraph:            GraphBinding{Revision: binary.BigEndian.Uint64(wire[48:56])},
		ServerGraph:            GraphBinding{Revision: binary.BigEndian.Uint64(wire[88:96])},
		BaseGeneration:         binary.BigEndian.Uint64(wire[160:168]),
		ResourceScope:          LeafMobilityResourceScope(wire[168]),
		SubjectRouteGeneration: binary.BigEndian.Uint64(wire[192:200]),
	}
	copy(binding.SessionEpoch[:], wire[16:32])
	copy(binding.TransactionID[:], wire[32:48])
	copy(binding.ClientGraph.Digest[:], wire[56:88])
	copy(binding.ServerGraph.Digest[:], wire[96:128])
	copy(binding.SubjectClientTargetID[:], wire[128:144])
	copy(binding.SubjectServerTargetID[:], wire[144:160])
	copy(binding.ResourceID[:], wire[176:192])
	if err := binding.Validate(); err != nil {
		return LeafMobilityPeerPlanBinding{}, err
	}
	return binding, nil
}
