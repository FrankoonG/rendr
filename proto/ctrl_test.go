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
		{CtrlBridgeTag, 0x10},
	}
	for _, c := range cases {
		if byte(c.code) != c.want {
			t.Errorf("%s drifted: got 0x%02x want 0x%02x (bump proto.Version if intentional)", c.code, byte(c.code), c.want)
		}
	}
}

func TestHelloWireStability(t *testing.T) {
	p := HelloPayload{
		FlowID: [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		Caps:   0x01020304,
	}
	want := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x01, 0x02, 0x03, 0x04,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("hello wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}
