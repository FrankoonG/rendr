package proto

import (
	"bytes"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	cases := []Header{
		{Version: 0, Type: FrameData, Last: false, Flags: 0, Seq: 0},
		{Version: 0, Type: FrameCtrl, Last: true, Flags: 0x05, Seq: 1},
		{Version: 0, Type: FrameData, Last: true, Flags: 0xFFF, Seq: MaxSeq},
		{Version: 0, Type: FrameCtrl, Last: false, Flags: 0x010, Seq: 1<<24 + 7},
	}
	for _, want := range cases {
		var buf [HeaderSize]byte
		if err := want.Encode(buf[:]); err != nil {
			t.Fatalf("encode %+v: %v", want, err)
		}
		got, err := DecodeHeader(buf[:])
		if err != nil {
			t.Fatalf("decode %x: %v", buf, err)
		}
		if got != want {
			t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v\n  bytes=%x", got, want, buf)
		}
	}
}

func TestHeaderRejectsBadVersion(t *testing.T) {
	h := Header{Version: 4} // 4 > 2-bit max of 3
	if err := h.Encode(make([]byte, HeaderSize)); err == nil {
		t.Fatal("expected error for version > 3")
	}
}

func TestHeaderRejectsBadFlags(t *testing.T) {
	h := Header{Flags: 0x1000}
	if err := h.Encode(make([]byte, HeaderSize)); err == nil {
		t.Fatal("expected error for flags > 12 bits")
	}
}

func TestHeaderRejectsOversizedSeq(t *testing.T) {
	h := Header{Seq: MaxSeq + 1}
	if err := h.Encode(make([]byte, HeaderSize)); err == nil {
		t.Fatal("expected error for seq > 48 bits")
	}
}

func TestHeaderRejectsShortBuf(t *testing.T) {
	if _, err := DecodeHeader([]byte{0, 0, 0}); err == nil {
		t.Fatal("expected error for short input")
	}
	if err := (Header{}).Encode([]byte{0, 0, 0}); err == nil {
		t.Fatal("expected error for short encode buf")
	}
}

// TestVersionConstants pins the wire-protocol version constants. A
// drift here without an accompanying review of every byte-stability
// test in this package would violate hard rule #7 (versioned wire
// format). Either bump these intentionally (and update the byte
// tests in lockstep) or do not change them.
func TestVersionConstants(t *testing.T) {
	if Version != 3 {
		t.Errorf("proto.Version drifted: got %d want 3", Version)
	}
	if UDPFlowVersion != 2 {
		t.Errorf("proto.UDPFlowVersion drifted: got %d want 2", UDPFlowVersion)
	}
}

// TestHeaderWireStability pins the byte layout. If this test fails
// without an accompanying Version bump, the change violates CLAUDE.md
// hard rule #7.
func TestHeaderWireStability(t *testing.T) {
	h := Header{
		Version: 0,
		Type:    FrameCtrl,
		Last:    true,
		Flags:   0x123,
		Seq:     0x0000_0001_2345_6789,
	}
	var buf [HeaderSize]byte
	if err := h.Encode(buf[:]); err != nil {
		t.Fatal(err)
	}
	// VER=0(00), T=1, F=1, FLAGS=0x123(0001 0010 0011), SEQ_LOW16=0x6789
	//  word0 = 00 1 1 000100100011 0110011110001001
	//        = 0011_0001_0010_0011_0110_0111_1000_1001
	//        = 0x31236789
	//  word1 = upper 32 bits of 0x0000000123456789 right-shifted by 16
	//        = 0x00012345
	want := []byte{0x31, 0x23, 0x67, 0x89, 0x00, 0x01, 0x23, 0x45}
	if !bytes.Equal(buf[:], want) {
		t.Fatalf("wire layout drift:\n got=%x\nwant=%x\n(any change here requires bumping proto.Version)", buf[:], want)
	}
}
