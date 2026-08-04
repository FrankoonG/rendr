package proto

import (
	"bytes"
	"testing"
)

func TestUDPFlowHeaderRoundTrip(t *testing.T) {
	cases := []UDPFlowHeader{
		{Version: 0, FlowID: [UDPFlowIDSize]byte{}},
		{Version: 0, FlowID: [UDPFlowIDSize]byte{1, 2, 3, 4, 5, 6, 7}},
		{Version: 0xFF, FlowID: [UDPFlowIDSize]byte{0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE}},
	}
	for _, want := range cases {
		var buf [UDPFlowHeaderSize]byte
		if err := want.Encode(buf[:]); err != nil {
			t.Fatalf("encode %+v: %v", want, err)
		}
		got, err := DecodeUDPFlow(buf[:])
		if err != nil {
			t.Fatalf("decode %x: %v", buf, err)
		}
		if got != want {
			t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
		}
	}
}

func TestUDPFlowHeaderRejectsShort(t *testing.T) {
	if _, err := DecodeUDPFlow([]byte{0, 1, 2}); err == nil {
		t.Fatal("expected error for short input")
	}
	if err := (UDPFlowHeader{}).Encode([]byte{0, 1, 2}); err == nil {
		t.Fatal("expected error for short encode buf")
	}
}

// TestUDPFlowFrameRoundTrip exercises Encode -> DecodeUDPFlowFrame
// end-to-end including the payload slice contract.
func TestUDPFlowFrameRoundTrip(t *testing.T) {
	want := UDPFlowFrame{
		Header:  UDPFlowHeader{Version: UDPFlowVersion, FlowID: [UDPFlowIDSize]byte{9, 8, 7, 6, 5, 4, 3}},
		Payload: []byte("opaque udp body"),
	}
	wire, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeUDPFlowFrame(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != want.Header {
		t.Errorf("header mismatch: %+v vs %+v", got.Header, want.Header)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("payload mismatch: %q vs %q", got.Payload, want.Payload)
	}
}

// TestUDPFlowWireStability pins the byte layout. Any change here
// without bumping UDPFlowVersion violates CLAUDE.md hard rule #7.
func TestUDPFlowWireStability(t *testing.T) {
	h := UDPFlowHeader{
		Version: UDPFlowVersion,
		FlowID:  [UDPFlowIDSize]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
	}
	var buf [UDPFlowHeaderSize]byte
	if err := h.Encode(buf[:]); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	if !bytes.Equal(buf[:], want) {
		t.Fatalf("wire drift:\n got=%x\nwant=%x\n(bumping UDPFlowVersion is required if intentional)", buf, want)
	}
}
