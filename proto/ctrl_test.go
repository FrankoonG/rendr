package proto

import (
	"bytes"
	"testing"
)

func TestCtrlCodeFromFlags(t *testing.T) {
	if got := CtrlCodeFromFlags(FlagsForCtrl(CtrlHello)); got != CtrlHello {
		t.Fatalf("hello round-trip: got %v want %v", got, CtrlHello)
	}
	if got := CtrlCodeFromFlags(FlagsForCtrl(CtrlBridgeTag)); got != CtrlBridgeTag {
		t.Fatalf("bridge_tag round-trip: got %v want %v", got, CtrlBridgeTag)
	}
	if got := CtrlCodeFromFlags(FlagsForCtrl(CtrlBridgeAck)); got != CtrlBridgeAck {
		t.Fatalf("bridge_ack round-trip: got %v want %v", got, CtrlBridgeAck)
	}
}

func TestHelloRoundTrip(t *testing.T) {
	want := HelloPayload{FlowID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, Caps: 0xAABB_CCDD}
	got, err := DecodeHello(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("hello: got %+v want %+v", got, want)
	}
}

func TestMigrateNotifyRoundTrip(t *testing.T) {
	want := MigrateNotifyPayload{NewPathID: 0xDEADBEEF}
	got, err := DecodeMigrateNotify(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migrate_notify: got %+v want %+v", got, want)
	}
}

func TestPathQualityRoundTrip(t *testing.T) {
	want := PathQualityPayload{RTTus: 12345, JitterUs: 678, LossPP: 7}
	got, err := DecodePathQuality(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("path_quality: got %+v want %+v", got, want)
	}
}

func TestHeartbeatRoundTrip(t *testing.T) {
	want := HeartbeatPayload{Timestamp: 1_700_000_000_000_000_000}
	got, err := DecodeHeartbeat(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("heartbeat: got %+v want %+v", got, want)
	}
}

func TestByeRoundTrip(t *testing.T) {
	want := ByePayload{Reason: ByeMigBudget}
	got, err := DecodeBye(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bye: got %+v want %+v", got, want)
	}
}

func TestBridgeTagRoundTrip(t *testing.T) {
	want := BridgeTagPayload{BridgeID: [16]byte{0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8}}
	got, err := DecodeBridgeTag(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bridge_tag: got %+v want %+v", got, want)
	}
}

func TestHelloAckRoundTrip(t *testing.T) {
	want := HelloAckPayload{
		FlowID:     [16]byte{1, 2, 3, 4},
		InstanceID: InstanceID{5, 6, 7, 8},
		Caps:       0xAABB_CCDD,
	}
	got, err := DecodeHelloAck(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("hello_ack: got %+v want %+v", got, want)
	}
}

func TestBridgeAckRoundTrip(t *testing.T) {
	want := BridgeAckPayload{
		BridgeID:   [16]byte{0xFE, 0xED},
		InstanceID: InstanceID{1, 2, 3, 4},
		Code:       AckRejectInstance,
		Reason:     "instance mismatch",
	}
	got, err := DecodeBridgeAck(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bridge_ack: got %+v want %+v", got, want)
	}
}

func TestHelloPathNameRoundTrip(t *testing.T) {
	want := HelloPayload{FlowID: [16]byte{1, 2, 3, 4}, Caps: CapsPacketMode, PathName: "A"}
	got, err := DecodeHello(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("hello path name: got %+v want %+v", got, want)
	}
}

func TestBridgeTagPathNameRoundTrip(t *testing.T) {
	want := BridgeTagPayload{BridgeID: [16]byte{0xFE, 0xED}, PathName: "B"}
	got, err := DecodeBridgeTag(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bridge tag path name: got %+v want %+v", got, want)
	}
}

func TestPolicyRequestRoundTrip(t *testing.T) {
	want := PolicyRequestPayload{
		Mode:       2,
		ActiveName: "B",
		ScopeNames: []string{"B", "C"},
		Cause:      "peak-transfer-rx",
	}
	got, err := DecodePolicyRequest(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != want.Mode || got.ActiveName != want.ActiveName || got.Cause != want.Cause {
		t.Fatalf("policy request: got %+v want %+v", got, want)
	}
	if len(got.ScopeNames) != 2 || got.ScopeNames[0] != "B" || got.ScopeNames[1] != "C" {
		t.Fatalf("policy request scope names=%v", got.ScopeNames)
	}
}

func TestRejectShortPayloads(t *testing.T) {
	short := []byte{0}
	if _, err := DecodeHello(short); err == nil {
		t.Error("hello accepted short input")
	}
	if _, err := DecodeMigrateNotify(short); err == nil {
		t.Error("migrate_notify accepted short input")
	}
	if _, err := DecodePathQuality(short); err == nil {
		t.Error("path_quality accepted short input")
	}
	if _, err := DecodeHeartbeat(short); err == nil {
		t.Error("heartbeat accepted short input")
	}
	if _, err := DecodeBridgeTag(short); err == nil {
		t.Error("bridge_tag accepted short input")
	}
	if _, err := DecodeHelloAck(short); err == nil {
		t.Error("hello_ack accepted short input")
	}
	if _, err := DecodeBridgeAck(short); err == nil {
		t.Error("bridge_ack accepted short input")
	}
	if _, err := DecodePolicyRequest(short); err == nil {
		t.Error("policy_request accepted short input")
	}
	if _, err := DecodeBye(nil); err == nil {
		t.Error("bye accepted nil input")
	}
}

func TestCtrlCodeStability(t *testing.T) {
	cases := []struct {
		code CtrlCode
		want byte
	}{
		{CtrlHello, 0x01},
		{CtrlMigrateNotify, 0x02},
		{CtrlPathQuality, 0x03},
		{CtrlHeartbeat, 0x04},
		{CtrlBye, 0x05},
		{CtrlPathProbe, 0x06},
		{CtrlPathProbeReply, 0x07},
		{CtrlPolicyRequest, 0x08},
		{CtrlHelloAck, 0x09},
		{CtrlBridgeTag, 0x10},
		{CtrlBridgeAck, 0x11},
	}
	for _, c := range cases {
		if byte(c.code) != c.want {
			t.Errorf("%s drifted: got 0x%02x want 0x%02x (bump proto.Version if intentional)", c.code, byte(c.code), c.want)
		}
	}
}

func TestCapsBitStability(t *testing.T) {
	if CapsPacketMode != 0x00000001 {
		t.Errorf("CapsPacketMode drifted: got 0x%08x want 0x00000001 (bump proto.Version if intentional)",
			CapsPacketMode)
	}
	if CapsL3Identity != 0x00000002 {
		t.Errorf("CapsL3Identity drifted: got 0x%08x want 0x00000002 (bump proto.Version if intentional)",
			CapsL3Identity)
	}
}

func TestProbeWireStability(t *testing.T) {
	p := ProbePayload{TS: 0x1122334455667788, ID: 0x99AABBCCDDEEFF00}
	want := []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("probe wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestAckPayloadRoundTrip(t *testing.T) {
	want := AckPayload{NextSeq: 0x0102030405060708}
	got, ok := DecodeAck(want.Encode())
	if !ok {
		t.Fatal("DecodeAck rejected encoded ack")
	}
	if got != want {
		t.Fatalf("ack: got %+v want %+v", got, want)
	}
	if _, ok := DecodeAck(ProbePayload{TS: 1, ID: 2}.Encode()); ok {
		t.Fatal("DecodeAck accepted ordinary probe payload")
	}
}

func TestAckPayloadWireStability(t *testing.T) {
	p := AckPayload{NextSeq: 0x0102030405060708}
	want := []byte{
		0x52, 0x45, 0x4e, 0x44, 0x52, 0x5f, 0x41, 0x43,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("ack wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestBridgeTagWireStability(t *testing.T) {
	p := BridgeTagPayload{
		BridgeID: [16]byte{
			0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
		InstanceID:             InstanceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
		ExpectedPeerInstanceID: InstanceID{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
	}
	want := []byte{
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("bridge_tag wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestMigrateNotifyWireStability(t *testing.T) {
	p := MigrateNotifyPayload{NewPathID: 0xDEADBEEF}
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("migrate_notify wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestPathQualityWireStability(t *testing.T) {
	p := PathQualityPayload{RTTus: 0x11223344, JitterUs: 0x55667788, LossPP: 0x99AA}
	want := []byte{
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("path_quality wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestHeartbeatWireStability(t *testing.T) {
	p := HeartbeatPayload{Timestamp: 0x0102030405060708}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("heartbeat wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestByeWireStability(t *testing.T) {
	cases := []struct {
		reason ByeReason
		want   byte
	}{
		{ByeNormal, 0x00},
		{ByeMigBudget, 0x01},
		{ByeProtoVer, 0x03},
	}
	for _, c := range cases {
		p := ByePayload{Reason: c.reason}
		enc := p.Encode()
		if len(enc) != 1 || enc[0] != c.want {
			t.Errorf("bye(%v) wire drift: got %x want %02x", c.reason, enc, c.want)
		}
	}
}

func TestHelloWireStability(t *testing.T) {
	p := HelloPayload{
		FlowID:     [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		InstanceID: InstanceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
		Caps:       0x01020304,
	}
	want := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x01, 0x02, 0x03, 0x04,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("hello wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}
