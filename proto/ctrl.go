package proto

import (
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

func (p ProbePayload) Encode() []byte {
	b := make([]byte, ProbePayloadSize)
	binary.BigEndian.PutUint64(b[0:8], p.TS)
	binary.BigEndian.PutUint64(b[8:16], p.ID)
	return b
}

func DecodeProbe(b []byte) (ProbePayload, error) {
	var p ProbePayload
	if len(b) < ProbePayloadSize {
		return p, fmt.Errorf("proto: probe payload too short: %d < %d", len(b), ProbePayloadSize)
	}
	p.TS = binary.BigEndian.Uint64(b[0:8])
	p.ID = binary.BigEndian.Uint64(b[8:16])
	return p, nil
}

// AckPayload carries the receiver's cumulative SEQ floor. NextSeq is
// the first frame SEQ not yet contiguously received, so all frames
// with SEQ < NextSeq are safe to trim from resend windows.
//
// ACKs are encoded as a PATH_PROBE_REPLY extension rather than as a
// new control code. Older peers decode the first 16 bytes as an
// unmatched probe reply with ID=0 and ignore it; newer peers recognize
// the magic and consume it out of band.
type AckPayload struct {
	NextSeq uint64
}

const AckPayloadSize = ProbePayloadSize + 8

func (p AckPayload) Encode() []byte {
	b := make([]byte, AckPayloadSize)
	binary.BigEndian.PutUint64(b[0:8], ackProbeReplyMagic)
	binary.BigEndian.PutUint64(b[8:16], 0)
	binary.BigEndian.PutUint64(b[16:24], p.NextSeq)
	return b
}

func DecodeAck(b []byte) (AckPayload, bool) {
	if len(b) < AckPayloadSize {
		return AckPayload{}, false
	}
	if binary.BigEndian.Uint64(b[0:8]) != ackProbeReplyMagic {
		return AckPayload{}, false
	}
	if binary.BigEndian.Uint64(b[8:16]) != 0 {
		return AckPayload{}, false
	}
	return AckPayload{NextSeq: binary.BigEndian.Uint64(b[16:24])}, true
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

// HelloPayload: flow_id (16B) + instance_id (16B) + caps (4B).
type HelloPayload struct {
	FlowID     [16]byte
	InstanceID InstanceID
	Caps       uint32
	PathName   string
}

const (
	HelloPayloadLegacySize = 20
	HelloPayloadSize       = 36
)

func (p HelloPayload) Encode() []byte {
	b := make([]byte, HelloPayloadSize)
	copy(b[0:16], p.FlowID[:])
	copy(b[16:32], p.InstanceID[:])
	binary.BigEndian.PutUint32(b[32:36], p.Caps)
	if p.PathName != "" {
		b = appendPathName(b, p.PathName)
	}
	return b
}

func DecodeHello(b []byte) (HelloPayload, error) {
	var p HelloPayload
	if len(b) < HelloPayloadLegacySize {
		return p, fmt.Errorf("proto: hello payload too short: %d < %d", len(b), HelloPayloadLegacySize)
	}
	copy(p.FlowID[:], b[0:16])
	if len(b) >= HelloPayloadSize {
		copy(p.InstanceID[:], b[16:32])
		p.Caps = binary.BigEndian.Uint32(b[32:36])
		p.PathName, _ = decodePathName(b[HelloPayloadSize:])
		return p, nil
	}
	p.Caps = binary.BigEndian.Uint32(b[16:20])
	p.PathName, _ = decodePathName(b[HelloPayloadLegacySize:])
	return p, nil
}

func (p HelloPayload) EncodeWithPathName(name string) []byte {
	p.PathName = name
	return p.Encode()
}

type HelloAckPayload struct {
	FlowID     [16]byte
	InstanceID InstanceID
	Caps       uint32
}

const HelloAckPayloadSize = 36

func (p HelloAckPayload) Encode() []byte {
	b := make([]byte, HelloAckPayloadSize)
	copy(b[0:16], p.FlowID[:])
	copy(b[16:32], p.InstanceID[:])
	binary.BigEndian.PutUint32(b[32:36], p.Caps)
	return b
}

func DecodeHelloAck(b []byte) (HelloAckPayload, error) {
	var p HelloAckPayload
	if len(b) < HelloAckPayloadSize {
		return p, fmt.Errorf("proto: hello_ack payload too short: %d < %d", len(b), HelloAckPayloadSize)
	}
	copy(p.FlowID[:], b[0:16])
	copy(p.InstanceID[:], b[16:32])
	p.Caps = binary.BigEndian.Uint32(b[32:36])
	return p, nil
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
	if len(b) < MigrateNotifyPayloadSize {
		return MigrateNotifyPayload{}, fmt.Errorf("proto: migrate_notify payload too short: %d < %d", len(b), MigrateNotifyPayloadSize)
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
	if len(b) < PathQualityPayloadSize {
		return PathQualityPayload{}, fmt.Errorf("proto: path_quality payload too short: %d < %d", len(b), PathQualityPayloadSize)
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
	if len(b) < HeartbeatPayloadSize {
		return HeartbeatPayload{}, fmt.Errorf("proto: heartbeat payload too short: %d < %d", len(b), HeartbeatPayloadSize)
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
	if len(b) < ByePayloadSize {
		return ByePayload{}, fmt.Errorf("proto: bye payload too short: %d < %d", len(b), ByePayloadSize)
	}
	return ByePayload{Reason: ByeReason(b[0])}, nil
}

// BridgeTagPayload is sent only on path bring-up so the server-side
// bridge table can attach the new PathConn to the correct Conn.
type BridgeTagPayload struct {
	BridgeID               [16]byte
	InstanceID             InstanceID
	ExpectedPeerInstanceID InstanceID
	PathName               string
}

const (
	BridgeTagPayloadLegacySize = 16
	BridgeTagPayloadSize       = 48
)

func (p BridgeTagPayload) Encode() []byte {
	b := make([]byte, BridgeTagPayloadSize)
	copy(b[0:16], p.BridgeID[:])
	copy(b[16:32], p.InstanceID[:])
	copy(b[32:48], p.ExpectedPeerInstanceID[:])
	if p.PathName != "" {
		b = appendPathName(b, p.PathName)
	}
	return b
}

func DecodeBridgeTag(b []byte) (BridgeTagPayload, error) {
	if len(b) < BridgeTagPayloadLegacySize {
		return BridgeTagPayload{}, fmt.Errorf("proto: bridge_tag payload too short: %d < %d", len(b), BridgeTagPayloadLegacySize)
	}
	var p BridgeTagPayload
	copy(p.BridgeID[:], b[0:16])
	if len(b) >= BridgeTagPayloadSize {
		copy(p.InstanceID[:], b[16:32])
		copy(p.ExpectedPeerInstanceID[:], b[32:48])
		p.PathName, _ = decodePathName(b[BridgeTagPayloadSize:])
		return p, nil
	}
	p.PathName, _ = decodePathName(b[BridgeTagPayloadLegacySize:])
	return p, nil
}

func (p BridgeTagPayload) EncodeWithPathName(name string) []byte {
	p.PathName = name
	return p.Encode()
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
	BridgeID   [16]byte
	InstanceID InstanceID
	Code       AckCode
	Reason     string
}

const BridgeAckPayloadSize = 33

func (p BridgeAckPayload) Encode() []byte {
	b := make([]byte, BridgeAckPayloadSize)
	copy(b[0:16], p.BridgeID[:])
	copy(b[16:32], p.InstanceID[:])
	b[32] = byte(p.Code)
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
	copy(p.InstanceID[:], b[16:32])
	p.Code = AckCode(b[32])
	p.Reason, _ = decodePathName(b[BridgeAckPayloadSize:])
	return p, nil
}

// PolicyRequestPayload asks the peer to update its local sender policy for
// this flow. It is used by receive-side selector decisions: the receiver can
// observe RX saturation, but the peer owns the corresponding TX dispatch.
type PolicyRequestPayload struct {
	Mode       uint8
	ActiveName string
	ScopeNames []string
	Cause      string
}

func (p PolicyRequestPayload) Encode() []byte {
	b := []byte{p.Mode, 0, 0, 0}
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
	p := PolicyRequestPayload{Mode: b[0]}
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
	p.Cause, _, ok = readString8(rest)
	if !ok {
		return PolicyRequestPayload{}, fmt.Errorf("proto: policy_request missing cause")
	}
	return p, nil
}

func appendPathName(b []byte, name string) []byte {
	return appendString8(b, name)
}

func decodePathName(b []byte) (string, bool) {
	name, _, ok := readString8(b)
	return name, ok
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
