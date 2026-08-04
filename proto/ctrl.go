package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// CtrlCode identifies a control-frame subtype. It occupies the low 8
// bits of the FLAGS field when Header.Type == FrameCtrl.
type CtrlCode uint8

const (
	CtrlHello          CtrlCode = 0x01
	CtrlMigrateNotify  CtrlCode = 0x02
	CtrlPathQuality    CtrlCode = 0x03
	CtrlHeartbeat      CtrlCode = 0x04
	CtrlBye            CtrlCode = 0x05
	CtrlPathProbe      CtrlCode = 0x06
	CtrlPathProbeReply CtrlCode = 0x07
	CtrlPolicyRequest  CtrlCode = 0x08
	CtrlHelloAck       CtrlCode = 0x09
	CtrlBridgeTag      CtrlCode = 0x10
	CtrlBridgeAck      CtrlCode = 0x11
)

type InstanceID [16]byte

const (
	ProtocolMajor uint16 = 1
	ProtocolMinor uint16 = 0
)

type FeatureSet uint64

const (
	FeatureReplayLedger   FeatureSet = 1 << 0
	FeatureDirectionalACK FeatureSet = 1 << 1
	FeatureStrictDecode   FeatureSet = 1 << 2

	SupportedFeatures FeatureSet = FeatureReplayLedger | FeatureDirectionalACK | FeatureStrictDecode
	RequiredFeatures  FeatureSet = SupportedFeatures
)

type GraphDigest [32]byte
type TargetID [16]byte

type GraphBinding struct {
	Revision uint64
	Digest   GraphDigest
}

// Negotiation is carried by both HELLO and HELLO_ACK before any bridge state
// is allocated. Minor versions remain feature-negotiated within protocol 1.
type Negotiation struct {
	ProtocolMajor uint16
	ProtocolMinor uint16
	Supported     FeatureSet
	Required      FeatureSet
	SessionEpoch  SessionEpoch
	GraphRevision uint64
	GraphDigest   GraphDigest
}

const NegotiationSize = 80

func NewNegotiation(epoch SessionEpoch) Negotiation {
	return Negotiation{
		ProtocolMajor: ProtocolMajor,
		ProtocolMinor: ProtocolMinor,
		Supported:     SupportedFeatures,
		Required:      RequiredFeatures,
		SessionEpoch:  epoch,
		GraphRevision: 1,
	}
}

func (n Negotiation) GraphBinding() GraphBinding {
	return GraphBinding{Revision: n.GraphRevision, Digest: n.GraphDigest}
}

func (n Negotiation) encodeTo(b []byte) {
	binary.BigEndian.PutUint16(b[0:2], n.ProtocolMajor)
	binary.BigEndian.PutUint16(b[2:4], n.ProtocolMinor)
	binary.BigEndian.PutUint64(b[8:16], uint64(n.Supported))
	binary.BigEndian.PutUint64(b[16:24], uint64(n.Required))
	copy(b[24:40], n.SessionEpoch[:])
	binary.BigEndian.PutUint64(b[40:48], n.GraphRevision)
	copy(b[48:80], n.GraphDigest[:])
}

func decodeNegotiation(b []byte) (Negotiation, error) {
	if len(b) < NegotiationSize {
		return Negotiation{}, fmt.Errorf("proto: negotiation too short: %d < %d", len(b), NegotiationSize)
	}
	if binary.BigEndian.Uint32(b[4:8]) != 0 {
		return Negotiation{}, fmt.Errorf("proto: negotiation reserved bytes must be zero")
	}
	n := Negotiation{
		ProtocolMajor: binary.BigEndian.Uint16(b[0:2]),
		ProtocolMinor: binary.BigEndian.Uint16(b[2:4]),
		Supported:     FeatureSet(binary.BigEndian.Uint64(b[8:16])),
		Required:      FeatureSet(binary.BigEndian.Uint64(b[16:24])),
		GraphRevision: binary.BigEndian.Uint64(b[40:48]),
	}
	copy(n.SessionEpoch[:], b[24:40])
	copy(n.GraphDigest[:], b[48:80])
	if n.ProtocolMajor != ProtocolMajor {
		return Negotiation{}, fmt.Errorf("proto: unsupported protocol major %d", n.ProtocolMajor)
	}
	if n.Required&^SupportedFeatures != 0 {
		return Negotiation{}, fmt.Errorf("proto: unknown required features 0x%x", uint64(n.Required&^SupportedFeatures))
	}
	if n.Required&^n.Supported != 0 {
		return Negotiation{}, fmt.Errorf("proto: required features not advertised as supported")
	}
	if n.GraphRevision == 0 {
		return Negotiation{}, fmt.Errorf("proto: zero graph revision")
	}
	return n, nil
}

// ProbePayload carries timestamps for per-path RTT measurement.
// Probe frames are intentionally out-of-band of the SEQ reorder
// buffer: the engine handles them directly in the per-path reader
// and never delivers them to the application stream.
type ProbePayload struct {
	TS uint64 // sender's monotonic ns at issue time
	ID uint64 // random probe id so the reply can be matched
}

const ProbePayloadSize = 16
const ackProbeReplyMagic uint64 = 0x52454e44525f4143 // "RENDR_AC" prefix
const ackPayloadVersion uint8 = 1

func (p ProbePayload) Encode() []byte {
	b := make([]byte, ProbePayloadSize)
	binary.BigEndian.PutUint64(b[0:8], p.TS)
	binary.BigEndian.PutUint64(b[8:16], p.ID)
	return b
}

func DecodeProbe(b []byte) (ProbePayload, error) {
	var p ProbePayload
	if err := requireExactPayloadSize("probe", len(b), ProbePayloadSize); err != nil {
		return p, err
	}
	p.TS = binary.BigEndian.Uint64(b[0:8])
	p.ID = binary.BigEndian.Uint64(b[8:16])
	return p, nil
}

// SenderDirection identifies the sequenced sender an ACK applies to.
type SenderDirection uint8

const (
	SenderDirectionInvalid        SenderDirection = 0
	SenderDirectionClientToServer SenderDirection = 1
	SenderDirectionServerToClient SenderDirection = 2
)

func (d SenderDirection) Valid() bool {
	return d == SenderDirectionClientToServer || d == SenderDirectionServerToClient
}

// SessionEpoch binds control-plane evidence to one logical connection.
type SessionEpoch [16]byte
type FrameDigest [32]byte
type AckProof [16]byte

func DigestFrame(frame []byte) FrameDigest {
	return sha256.Sum256(frame)
}

func InitialAckProof(epoch SessionEpoch, direction SenderDirection, graphRevision uint64, graphDigest GraphDigest) AckProof {
	h := sha256.New()
	h.Write([]byte("rendr-ack-proof-v1\x00"))
	h.Write(epoch[:])
	h.Write([]byte{byte(direction)})
	var revision [8]byte
	binary.BigEndian.PutUint64(revision[:], graphRevision)
	h.Write(revision[:])
	h.Write(graphDigest[:])
	var proof AckProof
	copy(proof[:], h.Sum(nil))
	return proof
}

func AdvanceAckProof(previous AckProof, frame FrameDigest) AckProof {
	h := sha256.New()
	h.Write([]byte("rendr-ack-chain-v1\x00"))
	h.Write(previous[:])
	h.Write(frame[:])
	var proof AckProof
	copy(proof[:], h.Sum(nil))
	return proof
}

// AckPayload carries the receiver's cumulative SEQ floor. NextSeq is the
// first frame not yet contiguously received. Gap asks the sender to replay
// from NextSeq; repeated gap ACKs make a lost first request recoverable.
type AckPayload struct {
	SessionEpoch  SessionEpoch
	Direction     SenderDirection
	GraphRevision uint64
	GraphDigest   GraphDigest
	NextSeq       uint64
	Gap           bool
	Proof         AckProof
}

const AckPayloadSize = 96

func (p AckPayload) Encode() []byte {
	b := make([]byte, AckPayloadSize)
	binary.BigEndian.PutUint64(b[0:8], ackProbeReplyMagic)
	b[8] = ackPayloadVersion
	b[9] = byte(p.Direction)
	if p.Gap {
		b[10] = 1
	}
	copy(b[16:32], p.SessionEpoch[:])
	binary.BigEndian.PutUint64(b[32:40], p.GraphRevision)
	copy(b[40:72], p.GraphDigest[:])
	binary.BigEndian.PutUint64(b[72:80], p.NextSeq)
	copy(b[80:96], p.Proof[:])
	return b
}

func DecodeAck(b []byte) (AckPayload, bool) {
	if len(b) != AckPayloadSize {
		return AckPayload{}, false
	}
	if binary.BigEndian.Uint64(b[0:8]) != ackProbeReplyMagic {
		return AckPayload{}, false
	}
	if b[8] != ackPayloadVersion || !SenderDirection(b[9]).Valid() {
		return AckPayload{}, false
	}
	if b[10]&^byte(1) != 0 || b[11] != 0 || binary.BigEndian.Uint32(b[12:16]) != 0 {
		return AckPayload{}, false
	}
	var p AckPayload
	p.Direction = SenderDirection(b[9])
	p.Gap = b[10]&1 != 0
	copy(p.SessionEpoch[:], b[16:32])
	p.GraphRevision = binary.BigEndian.Uint64(b[32:40])
	copy(p.GraphDigest[:], b[40:72])
	p.NextSeq = binary.BigEndian.Uint64(b[72:80])
	copy(p.Proof[:], b[80:96])
	return p, true
}

func (c CtrlCode) String() string {
	switch c {
	case CtrlHello:
		return "HELLO"
	case CtrlMigrateNotify:
		return "MIGRATE_NOTIFY"
	case CtrlPathQuality:
		return "PATH_QUALITY"
	case CtrlHeartbeat:
		return "HEARTBEAT"
	case CtrlBye:
		return "BYE"
	case CtrlPathProbe:
		return "PATH_PROBE"
	case CtrlPathProbeReply:
		return "PATH_PROBE_REPLY"
	case CtrlPolicyRequest:
		return "POLICY_REQUEST"
	case CtrlHelloAck:
		return "HELLO_ACK"
	case CtrlBridgeTag:
		return "BRIDGE_TAG"
	case CtrlBridgeAck:
		return "BRIDGE_ACK"
	default:
		return fmt.Sprintf("ctrl(0x%02x)", uint8(c))
	}
}

// CtrlCodeFromFlags extracts the control-code from a FLAGS value.
// Only meaningful when the frame's Type is FrameCtrl.
func CtrlCodeFromFlags(flags uint16) CtrlCode {
	return CtrlCode(flags & 0xFF)
}

// FlagsForCtrl builds a FLAGS value from a control code. The upper 4
// FLAGS bits (out of 12) are reserved for per-code use and default to 0.
func FlagsForCtrl(c CtrlCode) uint16 {
	return uint16(c) & 0xFF
}

// Caps bits negotiated in the HELLO payload. The set is forward-
// extensible: a peer that does not understand a bit must ignore it.
const (
	// CapsPacketMode: client requests packet-boundary semantics
	// (one frame -> one packet). The server's engine switches its
	// receive drainer to deliver per-frame packets rather than
	// concatenated byte stream. Stream-mode peers ignore this bit.
	CapsPacketMode uint32 = 1 << 0

	// CapsL3Identity: peer can carry original L3/L4 identity metadata
	// for TUN/l3ingress flows and expose it to peer-side egress hooks.
	CapsL3Identity uint32 = 1 << 1
)

// HelloPayload declares the initiator's TX graph and the path leaf carrying
// this initial handshake. Dial-specific addresses and options never enter the
// manifest.
type HelloPayload struct {
	Negotiation
	FlowID          [16]byte
	InstanceID      InstanceID
	Caps            uint32
	InitialTargetID TargetID
	LocalTXManifest GraphManifest
}

const HelloPayloadSize = NegotiationSize + 56

func (p HelloPayload) Encode() ([]byte, error) {
	manifest, err := p.LocalTXManifest.Encode()
	if err != nil {
		return nil, fmt.Errorf("proto: encode hello graph: %w", err)
	}
	if err := validateGraphNegotiation(p.Negotiation, p.LocalTXManifest); err != nil {
		return nil, err
	}
	node, ok := p.LocalTXManifest.Node(p.InitialTargetID)
	if !ok || node.Kind != GraphNodeKindPath {
		return nil, fmt.Errorf("proto: hello initial target is not a path in the graph")
	}
	b := make([]byte, HelloPayloadSize)
	p.Negotiation.encodeTo(b[:NegotiationSize])
	copy(b[80:96], p.FlowID[:])
	copy(b[96:112], p.InstanceID[:])
	binary.BigEndian.PutUint32(b[112:116], p.Caps)
	copy(b[116:132], p.InitialTargetID[:])
	binary.BigEndian.PutUint32(b[132:136], uint32(len(manifest)))
	b = append(b, manifest...)
	return b, nil
}

func DecodeHello(b []byte) (HelloPayload, error) {
	var p HelloPayload
	if len(b) < HelloPayloadSize {
		return p, fmt.Errorf("proto: hello payload too short: %d < %d", len(b), HelloPayloadSize)
	}
	var err error
	p.Negotiation, err = decodeNegotiation(b[:NegotiationSize])
	if err != nil {
		return HelloPayload{}, err
	}
	copy(p.FlowID[:], b[80:96])
	copy(p.InstanceID[:], b[96:112])
	p.Caps = binary.BigEndian.Uint32(b[112:116])
	copy(p.InitialTargetID[:], b[116:132])
	if p.SessionEpoch != SessionEpoch(p.FlowID) {
		return HelloPayload{}, fmt.Errorf("proto: hello session epoch does not match flow id")
	}
	manifestLen := int(binary.BigEndian.Uint32(b[132:136]))
	if manifestLen != len(b)-HelloPayloadSize || manifestLen > GraphManifestMaxWireBytes {
		return HelloPayload{}, fmt.Errorf("proto: hello graph length %d does not match remaining payload %d", manifestLen, len(b)-HelloPayloadSize)
	}
	p.LocalTXManifest, err = DecodeGraphManifest(b[HelloPayloadSize:])
	if err != nil {
		return HelloPayload{}, fmt.Errorf("proto: decode hello graph: %w", err)
	}
	if err := validateGraphNegotiation(p.Negotiation, p.LocalTXManifest); err != nil {
		return HelloPayload{}, err
	}
	node, ok := p.LocalTXManifest.Node(p.InitialTargetID)
	if !ok || node.Kind != GraphNodeKindPath {
		return HelloPayload{}, fmt.Errorf("proto: hello initial target is not a path in the graph")
	}
	return p, nil
}

type HelloAckPayload struct {
	Negotiation
	FlowID              [16]byte
	InstanceID          InstanceID
	Caps                uint32
	InitialTargetID     TargetID
	AcceptedPeerBinding GraphBinding
	LocalTXManifest     GraphManifest
}

const HelloAckPayloadSize = NegotiationSize + 96

func (p HelloAckPayload) Encode() ([]byte, error) {
	manifest, err := p.LocalTXManifest.Encode()
	if err != nil {
		return nil, fmt.Errorf("proto: encode hello_ack graph: %w", err)
	}
	if err := validateGraphNegotiation(p.Negotiation, p.LocalTXManifest); err != nil {
		return nil, err
	}
	if p.AcceptedPeerBinding.Revision == 0 {
		return nil, fmt.Errorf("proto: hello_ack has zero accepted peer graph revision")
	}
	node, ok := p.LocalTXManifest.Node(p.InitialTargetID)
	if !ok || node.Kind != GraphNodeKindPath {
		return nil, fmt.Errorf("proto: hello_ack initial target is not a path in the graph")
	}
	b := make([]byte, HelloAckPayloadSize)
	p.Negotiation.encodeTo(b[:NegotiationSize])
	copy(b[80:96], p.FlowID[:])
	copy(b[96:112], p.InstanceID[:])
	binary.BigEndian.PutUint32(b[112:116], p.Caps)
	copy(b[116:132], p.InitialTargetID[:])
	binary.BigEndian.PutUint64(b[132:140], p.AcceptedPeerBinding.Revision)
	copy(b[140:172], p.AcceptedPeerBinding.Digest[:])
	binary.BigEndian.PutUint32(b[172:176], uint32(len(manifest)))
	b = append(b, manifest...)
	return b, nil
}

func DecodeHelloAck(b []byte) (HelloAckPayload, error) {
	var p HelloAckPayload
	if len(b) < HelloAckPayloadSize {
		return p, fmt.Errorf("proto: hello_ack payload too short: %d < %d", len(b), HelloAckPayloadSize)
	}
	var err error
	p.Negotiation, err = decodeNegotiation(b[:NegotiationSize])
	if err != nil {
		return HelloAckPayload{}, err
	}
	copy(p.FlowID[:], b[80:96])
	copy(p.InstanceID[:], b[96:112])
	p.Caps = binary.BigEndian.Uint32(b[112:116])
	copy(p.InitialTargetID[:], b[116:132])
	p.AcceptedPeerBinding.Revision = binary.BigEndian.Uint64(b[132:140])
	copy(p.AcceptedPeerBinding.Digest[:], b[140:172])
	if p.SessionEpoch != SessionEpoch(p.FlowID) {
		return HelloAckPayload{}, fmt.Errorf("proto: hello_ack session epoch does not match flow id")
	}
	if p.AcceptedPeerBinding.Revision == 0 {
		return HelloAckPayload{}, fmt.Errorf("proto: hello_ack has zero accepted peer graph revision")
	}
	manifestLen := int(binary.BigEndian.Uint32(b[172:176]))
	if manifestLen != len(b)-HelloAckPayloadSize || manifestLen > GraphManifestMaxWireBytes {
		return HelloAckPayload{}, fmt.Errorf("proto: hello_ack graph length %d does not match remaining payload %d", manifestLen, len(b)-HelloAckPayloadSize)
	}
	p.LocalTXManifest, err = DecodeGraphManifest(b[HelloAckPayloadSize:])
	if err != nil {
		return HelloAckPayload{}, fmt.Errorf("proto: decode hello_ack graph: %w", err)
	}
	if err := validateGraphNegotiation(p.Negotiation, p.LocalTXManifest); err != nil {
		return HelloAckPayload{}, err
	}
	node, ok := p.LocalTXManifest.Node(p.InitialTargetID)
	if !ok || node.Kind != GraphNodeKindPath {
		return HelloAckPayload{}, fmt.Errorf("proto: hello_ack initial target is not a path in the graph")
	}
	return p, nil
}

func validateGraphNegotiation(negotiation Negotiation, manifest GraphManifest) error {
	digest, err := manifest.Digest()
	if err != nil {
		return fmt.Errorf("proto: invalid negotiated graph: %w", err)
	}
	if digest != negotiation.GraphDigest {
		return fmt.Errorf("proto: negotiated graph digest mismatch")
	}
	return nil
}

// MigrateNotifyPayload: new_path_id (4B).
type MigrateNotifyPayload struct {
	NewPathID uint32
}

const MigrateNotifyPayloadSize = 4

func (p MigrateNotifyPayload) Encode() []byte {
	b := make([]byte, MigrateNotifyPayloadSize)
	binary.BigEndian.PutUint32(b, p.NewPathID)
	return b
}

func DecodeMigrateNotify(b []byte) (MigrateNotifyPayload, error) {
	if err := requireExactPayloadSize("migrate_notify", len(b), MigrateNotifyPayloadSize); err != nil {
		return MigrateNotifyPayload{}, err
	}
	return MigrateNotifyPayload{NewPathID: binary.BigEndian.Uint32(b[0:4])}, nil
}

// PathQualityPayload: rtt_us (4B) + jitter_us (4B) + loss_pp (2B).
//
// The microsecond resolution gives ~71 minutes max RTT before overflow;
// loss_pp is parts-per-thousand so 0-1000 covers full range with
// 0.1% resolution. The Go API (rendr.PathQuality) uses time.Duration
// and converts on encode.
type PathQualityPayload struct {
	RTTus    uint32
	JitterUs uint32
	LossPP   uint16
}

const PathQualityPayloadSize = 10

func (p PathQualityPayload) Encode() []byte {
	b := make([]byte, PathQualityPayloadSize)
	binary.BigEndian.PutUint32(b[0:4], p.RTTus)
	binary.BigEndian.PutUint32(b[4:8], p.JitterUs)
	binary.BigEndian.PutUint16(b[8:10], p.LossPP)
	return b
}

func DecodePathQuality(b []byte) (PathQualityPayload, error) {
	if err := requireExactPayloadSize("path_quality", len(b), PathQualityPayloadSize); err != nil {
		return PathQualityPayload{}, err
	}
	return PathQualityPayload{
		RTTus:    binary.BigEndian.Uint32(b[0:4]),
		JitterUs: binary.BigEndian.Uint32(b[4:8]),
		LossPP:   binary.BigEndian.Uint16(b[8:10]),
	}, nil
}

// HeartbeatPayload: timestamp (8B, monotonic-ish nanos from sender).
type HeartbeatPayload struct {
	Timestamp uint64
}

const HeartbeatPayloadSize = 8

func (p HeartbeatPayload) Encode() []byte {
	b := make([]byte, HeartbeatPayloadSize)
	binary.BigEndian.PutUint64(b, p.Timestamp)
	return b
}

func DecodeHeartbeat(b []byte) (HeartbeatPayload, error) {
	if err := requireExactPayloadSize("heartbeat", len(b), HeartbeatPayloadSize); err != nil {
		return HeartbeatPayload{}, err
	}
	return HeartbeatPayload{Timestamp: binary.BigEndian.Uint64(b[0:8])}, nil
}

// ByeReason categorises a BYE.
type ByeReason uint8

const (
	ByeNormal     ByeReason = 0x00
	ByeMigBudget  ByeReason = 0x01 // migration budget exhausted
	ByeZombie     ByeReason = 0x02 // zombie protection tripped
	ByeProtoVer   ByeReason = 0x03
	ByeAppRequest ByeReason = 0x04
)

// ByePayload: reason (1B).
type ByePayload struct {
	Reason ByeReason
}

const ByePayloadSize = 1

func (p ByePayload) Encode() []byte {
	return []byte{byte(p.Reason)}
}

func DecodeBye(b []byte) (ByePayload, error) {
	if err := requireExactPayloadSize("bye", len(b), ByePayloadSize); err != nil {
		return ByePayload{}, err
	}
	return ByePayload{Reason: ByeReason(b[0])}, nil
}

// BridgeTagPayload is sent only on path bring-up so the server-side
// bridge table can attach the new PathConn to the correct Conn.
type BridgeTagPayload struct {
	BridgeID               [16]byte
	AttachID               [16]byte
	InstanceID             InstanceID
	ExpectedPeerInstanceID InstanceID
	SessionEpoch           SessionEpoch
	Direction              SenderDirection
	GraphRevision          uint64
	GraphDigest            GraphDigest
	TargetID               TargetID
}

const BridgeTagPayloadSize = 144

func (p BridgeTagPayload) Encode() []byte {
	b := make([]byte, BridgeTagPayloadSize)
	copy(b[0:16], p.BridgeID[:])
	copy(b[16:32], p.AttachID[:])
	copy(b[32:48], p.InstanceID[:])
	copy(b[48:64], p.ExpectedPeerInstanceID[:])
	copy(b[64:80], p.SessionEpoch[:])
	b[80] = byte(p.Direction)
	binary.BigEndian.PutUint64(b[88:96], p.GraphRevision)
	copy(b[96:128], p.GraphDigest[:])
	copy(b[128:144], p.TargetID[:])
	return b
}

func DecodeBridgeTag(b []byte) (BridgeTagPayload, error) {
	if err := requireExactPayloadSize("bridge_tag", len(b), BridgeTagPayloadSize); err != nil {
		return BridgeTagPayload{}, err
	}
	var p BridgeTagPayload
	copy(p.BridgeID[:], b[0:16])
	copy(p.AttachID[:], b[16:32])
	copy(p.InstanceID[:], b[32:48])
	copy(p.ExpectedPeerInstanceID[:], b[48:64])
	copy(p.SessionEpoch[:], b[64:80])
	p.Direction = SenderDirection(b[80])
	if !p.Direction.Valid() || binary.BigEndian.Uint64(b[80:88])&0x00ffffffffffffff != 0 {
		return BridgeTagPayload{}, fmt.Errorf("proto: bridge_tag invalid direction or reserved bytes")
	}
	p.GraphRevision = binary.BigEndian.Uint64(b[88:96])
	copy(p.GraphDigest[:], b[96:128])
	copy(p.TargetID[:], b[128:144])
	if p.SessionEpoch != SessionEpoch(p.BridgeID) {
		return BridgeTagPayload{}, fmt.Errorf("proto: bridge_tag session epoch does not match bridge id")
	}
	if p.GraphRevision == 0 {
		return BridgeTagPayload{}, fmt.Errorf("proto: bridge_tag zero graph revision")
	}
	if p.AttachID == ([16]byte{}) {
		return BridgeTagPayload{}, fmt.Errorf("proto: bridge_tag zero attach id")
	}
	return p, nil
}

type AckCode uint8

const (
	AckOK               AckCode = 0x00
	AckRejectUnknown    AckCode = 0x01
	AckRejectInstance   AckCode = 0x02
	AckRejectAttach     AckCode = 0x03
	AckRejectMalformed  AckCode = 0x04
	AckRejectDuplicate  AckCode = 0x05
	AckRejectProtoState AckCode = 0x06
)

func (c AckCode) OK() bool { return c == AckOK }

func (c AckCode) String() string {
	switch c {
	case AckOK:
		return "ok"
	case AckRejectUnknown:
		return "unknown_flow"
	case AckRejectInstance:
		return "instance_mismatch"
	case AckRejectAttach:
		return "attach_failed"
	case AckRejectMalformed:
		return "malformed"
	case AckRejectDuplicate:
		return "duplicate"
	case AckRejectProtoState:
		return "proto_state"
	default:
		return fmt.Sprintf("ack(0x%02x)", uint8(c))
	}
}

type BridgeAckPayload struct {
	BridgeID          [16]byte
	AttachID          [16]byte
	InstanceID        InstanceID
	SessionEpoch      SessionEpoch
	Direction         SenderDirection
	GraphRevision     uint64
	GraphDigest       GraphDigest
	TargetID          TargetID
	ResponderTargetID TargetID
	Code              AckCode
	Reason            string
}

const BridgeAckPayloadSize = 145

func (p BridgeAckPayload) Encode() []byte {
	b := make([]byte, BridgeAckPayloadSize)
	copy(b[0:16], p.BridgeID[:])
	copy(b[16:32], p.AttachID[:])
	copy(b[32:48], p.InstanceID[:])
	copy(b[48:64], p.SessionEpoch[:])
	b[64] = byte(p.Direction)
	binary.BigEndian.PutUint64(b[72:80], p.GraphRevision)
	copy(b[80:112], p.GraphDigest[:])
	copy(b[112:128], p.TargetID[:])
	copy(b[128:144], p.ResponderTargetID[:])
	b[144] = byte(p.Code)
	if p.Reason != "" {
		b = appendString8(b, p.Reason)
	}
	return b
}

func DecodeBridgeAck(b []byte) (BridgeAckPayload, error) {
	var p BridgeAckPayload
	if len(b) < BridgeAckPayloadSize {
		return p, fmt.Errorf("proto: bridge_ack payload too short: %d < %d", len(b), BridgeAckPayloadSize)
	}
	copy(p.BridgeID[:], b[0:16])
	copy(p.AttachID[:], b[16:32])
	copy(p.InstanceID[:], b[32:48])
	copy(p.SessionEpoch[:], b[48:64])
	p.Direction = SenderDirection(b[64])
	if !p.Direction.Valid() || binary.BigEndian.Uint64(b[64:72])&0x00ffffffffffffff != 0 {
		return BridgeAckPayload{}, fmt.Errorf("proto: bridge_ack invalid direction or reserved bytes")
	}
	p.GraphRevision = binary.BigEndian.Uint64(b[72:80])
	copy(p.GraphDigest[:], b[80:112])
	copy(p.TargetID[:], b[112:128])
	copy(p.ResponderTargetID[:], b[128:144])
	p.Code = AckCode(b[144])
	if p.SessionEpoch != SessionEpoch(p.BridgeID) {
		return BridgeAckPayload{}, fmt.Errorf("proto: bridge_ack session epoch does not match bridge id")
	}
	if p.GraphRevision == 0 {
		return BridgeAckPayload{}, fmt.Errorf("proto: bridge_ack zero graph revision")
	}
	if p.AttachID == ([16]byte{}) {
		return BridgeAckPayload{}, fmt.Errorf("proto: bridge_ack zero attach id")
	}
	if p.ResponderTargetID == (TargetID{}) {
		return BridgeAckPayload{}, fmt.Errorf("proto: bridge_ack zero responder target id")
	}
	var err error
	p.Reason, err = decodeOptionalString8("bridge_ack reason", b[BridgeAckPayloadSize:])
	if err != nil {
		return BridgeAckPayload{}, err
	}
	return p, nil
}

// ExecutionKind is the wire-level group executor selected by a policy
// request. It is intentionally independent from any public or engine enum.
type ExecutionKind uint8

const (
	ExecutionKindInvalid  ExecutionKind = 0
	ExecutionKindSelector ExecutionKind = 1
	ExecutionKindBond     ExecutionKind = 2
	ExecutionKindRace     ExecutionKind = 3
)

// Valid reports whether k identifies a wire executor.
func (k ExecutionKind) Valid() bool {
	return k == ExecutionKindSelector || k == ExecutionKindBond || k == ExecutionKindRace
}

// PolicyRequestPayload asks the peer to update its local sender policy for
// this flow. It is used by receive-side selector decisions: the receiver can
// observe RX saturation, but the peer owns the corresponding TX dispatch.
type PolicyRequestPayload struct {
	Kind       ExecutionKind
	ActiveName string
	ScopeNames []string
	Cause      string
}

func (p PolicyRequestPayload) Encode() []byte {
	b := []byte{byte(p.Kind), 0, 0, 0}
	b[1] = byte(len(p.ScopeNames))
	b = appendString8(b, p.ActiveName)
	for _, name := range p.ScopeNames {
		b = appendString8(b, name)
	}
	b = appendString8(b, p.Cause)
	return b
}

func DecodePolicyRequest(b []byte) (PolicyRequestPayload, error) {
	if len(b) < 4 {
		return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request payload too short: %d < 4", len(b))
	}
	p := PolicyRequestPayload{Kind: ExecutionKind(b[0])}
	if !p.Kind.Valid() {
		return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request invalid execution kind: %d", b[0])
	}
	if b[2] != 0 || b[3] != 0 {
		return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request reserved bytes must be zero")
	}
	count := int(b[1])
	rest := b[4:]
	var ok bool
	p.ActiveName, rest, ok = readString8(rest)
	if !ok {
		return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request missing active name")
	}
	p.ScopeNames = make([]string, 0, count)
	for i := 0; i < count; i++ {
		var name string
		name, rest, ok = readString8(rest)
		if !ok {
			return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request missing scope name %d", i)
		}
		p.ScopeNames = append(p.ScopeNames, name)
	}
	p.Cause, rest, ok = readString8(rest)
	if !ok {
		return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request missing cause")
	}
	if len(rest) != 0 {
		return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request trailing bytes: %d", len(rest))
	}
	return p, nil
}

func appendPathName(b []byte, name string) []byte {
	return appendString8(b, name)
}

func decodeOptionalString8(field string, b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	value, rest, ok := readString8(b)
	if !ok {
		return "", fmt.Errorf("proto: malformed %s", field)
	}
	if value == "" {
		return "", fmt.Errorf("proto: empty %s", field)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("proto: %s trailing bytes: %d", field, len(rest))
	}
	return value, nil
}

func appendString8(b []byte, s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	b = append(b, byte(len(s)))
	return append(b, s...)
}

func readString8(b []byte) (string, []byte, bool) {
	if len(b) < 1 {
		return "", b, false
	}
	n := int(b[0])
	if len(b) < 1+n {
		return "", b, false
	}
	return string(b[1 : 1+n]), b[1+n:], true
}

func requireExactPayloadSize(name string, got, want int) error {
	if got != want {
		return fmt.Errorf("proto: %s payload size: %d != %d", name, got, want)
	}
	return nil
}
