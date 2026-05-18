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
	CtrlBridgeTag      CtrlCode = 0x10
)

// ProbePayload carries timestamps for per-path RTT measurement.
// Probe frames are intentionally out-of-band of the SEQ reorder
// buffer: the engine handles them directly in the per-path reader
// and never delivers them to the application stream.
type ProbePayload struct {
	TS uint64 // sender's monotonic ns at issue time
	ID uint64 // random probe id so the reply can be matched
}

const ProbePayloadSize = 16

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
	case CtrlBridgeTag:
		return "BRIDGE_TAG"
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
)

// HelloPayload: flow_id (16B) + caps (4B). 20 bytes on the wire.
type HelloPayload struct {
	FlowID [16]byte
	Caps   uint32
}

const HelloPayloadSize = 20

func (p HelloPayload) Encode() []byte {
	b := make([]byte, HelloPayloadSize)
	copy(b[0:16], p.FlowID[:])
	binary.BigEndian.PutUint32(b[16:20], p.Caps)
	return b
}

func DecodeHello(b []byte) (HelloPayload, error) {
	var p HelloPayload
	if len(b) < HelloPayloadSize {
		return p, fmt.Errorf("proto: hello payload too short: %d < %d", len(b), HelloPayloadSize)
	}
	copy(p.FlowID[:], b[0:16])
	p.Caps = binary.BigEndian.Uint32(b[16:20])
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

// BridgeTagPayload: bridge_id (16B). Sent only on path bring-up so
// the server-side bridge table can attach the new PathConn to the
// correct Conn.
type BridgeTagPayload struct {
	BridgeID [16]byte
}

const BridgeTagPayloadSize = 16

func (p BridgeTagPayload) Encode() []byte {
	b := make([]byte, BridgeTagPayloadSize)
	copy(b, p.BridgeID[:])
	return b
}

func DecodeBridgeTag(b []byte) (BridgeTagPayload, error) {
	if len(b) < BridgeTagPayloadSize {
		return BridgeTagPayload{}, fmt.Errorf("proto: bridge_tag payload too short: %d < %d", len(b), BridgeTagPayloadSize)
	}
	var p BridgeTagPayload
	copy(p.BridgeID[:], b[0:16])
	return p, nil
}
