package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// M3 wire tests (M3 design §A3, §A11.1 WP1): the golden vectors M3 adds,
// the optional PREFACE bit OptMux, mode 3, the session handle rule and
// REL{DETACH}. The DETACH codec and FuzzDetach_L44 are in detach_test.go.

// headerRejectVec is a whole frame (valid CRC) whose header DecodeFrame
// rejects with err: the frame decoder fails before any payload parser runs.
func headerRejectVec(name string, h Header, payload []byte, err error) vector {
	return vector{name: name, b: AppendFrame(nil, h, payload), kind: "reject", as: "header", err: err}
}

// goldenVectorsM3 builds the vectors M3 adds (M3 design §A3.7), after
// every M1 and M2 vector, which stays byte-identical: OptMux in both
// prefaces, mode 3 in OPEN and JOIN, session frames with handles other than
// 1, DETACH bare and REL-wrapped, the raw-UDP H1 of a mux-eligible
// datagram carrier, and the rejections.
func goldenVectorsM3() []vector {
	var vs []vector
	add := func(v vector) { vs = append(vs, v) }

	add(prefaceVec("preface_optmux", Preface{Kind: KindStream, Opt: OptMux, Instance: gDialer, CarrierID: gCarrier}))
	add(prefaceAckVec("preface_ack_optmux", PrefaceAck{Status: PrefaceOK, Opt: OptMux, Instance: gPassive, CarrierID: gCarrier}))
	add(frameVec("open_mode_race", TypeOpen, 0, FirstFseq, SessionHandle, Open{SID: gSID, Kind: KindStream, Mode: ModeRace, RetainMs: 34000, Window: 8 << 20}))
	add(frameVec("join_mode_race", TypeJoin, 0, FirstFseq, SessionHandle, Join{SID: gSID, Mode: ModeRace, RxNext: 1 << 20}))

	// Session frames on later handles of a MUX trunk (M3-D4): the codec
	// accepts any non-zero handle.
	add(frameVec("data_handle_2", TypeData, 0, 2, 2, dataVal{Off: 0, Body: []byte{0x5a}}))
	add(frameVec("data_handle_max", TypeData, 0, 2, 0xffffffff, dataVal{Off: 1 << 20, Body: pattern(100, 0x10)}))
	add(frameVec("ack_handle_7", TypeAck, FlagAckDone, 3, 7, Ack{Delivered: 1 << 20, Window: 8 << 20, EpochEcho: 3}))
	add(frameVec("dgram_handle_3", TypeDgram, 0, 12, 3, dgramVal{Seq: 9, Body: pattern(64, 0x20)}))

	// DETACH (§A3.4): bare on a stream trunk, REL-wrapped on a datagram
	// trunk.
	add(frameVec("detach_ended", TypeDetach, 0, 18, 0, Detach{Handle: 2, Reason: DetachEnded}))
	add(frameVec("detach_retired", TypeDetach, 0, 18, 0, Detach{Handle: 0xffffffff, Reason: DetachRetired}))
	add(relVec("rel_detach", 16, RelHead{Cseq: 7, Type: TypeDetach}, Detach{Handle: 3, Reason: DetachEnded}))

	// The raw-UDP H1 of a mux-eligible datagram carrier: flow header ‖
	// PREFACE(OptMux) ‖ REL{OPEN} (the bit rides the verbatim H1, §A3.1).
	pre := prefaceVec("", Preface{Kind: KindDatagram, Opt: OptMux, Instance: gDialer, CarrierID: gCarrier})
	open := relVec("", PrefaceFseq(pre.b), RelHead{Cseq: FirstCseq, Type: TypeOpen, Handle: SessionHandle}, gPacketOpen())
	add(udpVec("udp_h1_open_optmux", gFlow, datagramVec("", pre, open)))

	// Rejections: the DETACH payload rules, its length (a header rule:
	// PayloadBounds), mode 4, and handle 0 on a session frame.
	add(rejectFrameVec("detach_handle_0", TypeDetach, 18, 0, Detach{Handle: 0, Reason: DetachEnded}, ErrValue))
	add(rejectFrameVec("detach_reason_0", TypeDetach, 18, 0, Detach{Handle: 2, Reason: 0}, ErrValue))
	add(rejectFrameVec("detach_reason_3", TypeDetach, 18, 0, Detach{Handle: 2, Reason: 3}, ErrValue))
	add(headerRejectVec("detach_trailing", Header{Type: TypeDetach, Fseq: 18}, []byte{0, 0, 0, 2, 1, 0}, ErrLength))
	add(headerRejectVec("detach_short", Header{Type: TypeDetach, Fseq: 18}, []byte{0, 0, 0, 2}, ErrLength))
	add(rejectFrameVec("open_mode_4", TypeOpen, FirstFseq, SessionHandle, Open{SID: gSID, Kind: KindStream, Mode: MaxMode + 1, RetainMs: 34000, Window: 8 << 20}, ErrValue))
	add(headerRejectVec("data_handle_0", Header{Type: TypeData, Fseq: 2}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0x5a}, ErrHandle))
	return vs
}

// TestPrefaceOptMux_L44: OptMux is optional PREFACE bit 0 (M3-D3): a
// PREFACE and a PREFACE_ACK carry it in opt and decode it; the passive
// echoes it iff the PREFACE carried it and echoes no bit it does not know;
// the carrier is a MUX trunk iff both carry it; a PREFACE_ACK with OptMux
// for a PREFACE without it is a carrier error (ErrMalformed, not a
// version answer); unknown optional bits are still ignored and OptMux as a
// required bit is still an unknown required feature (M3 design §A3.1).
func TestPrefaceOptMux_L44(t *testing.T) {
	if OptMux != 1 || KnownOptional != OptMux || KnownRequired != 0 {
		t.Fatalf("OptMux %#x, KnownOptional %#x, KnownRequired %#x", OptMux, KnownOptional, KnownRequired)
	}
	// Set and decoded, on both carrier kinds, with and without unknown
	// optional bits (byte 15 holds bit 0 of opt).
	b := make([]byte, PrefaceLen)
	for _, kind := range []CarrierKind{KindStream, KindDatagram} {
		for _, opt := range []uint32{OptMux, OptMux | 0x80000000, 0xffffffff, 0x80000000, 0} {
			p := Preface{Kind: kind, Opt: opt, Instance: gDialer, CarrierID: gCarrier}
			PutPreface(b, &p)
			if binary.BigEndian.Uint32(b[12:16]) != opt || (b[15]&1 == 1) != (opt&OptMux != 0) {
				t.Errorf("PREFACE opt %#x encoded as % x", opt, b[12:16])
			}
			if got, err := ParsePreface(b); err != nil || got != p {
				t.Errorf("PREFACE kind %d opt %#x: %+v, %v", kind, opt, got, err)
			}
			a := PrefaceAck{Status: PrefaceOK, Opt: EchoOpt(opt), Instance: gPassive, CarrierID: gCarrier}
			PutPrefaceAck(b, &a)
			if got, err := ParsePrefaceAck(b); err != nil || got != a {
				t.Errorf("PREFACE_ACK opt %#x: %+v, %v", a.Opt, got, err)
			}
			// The echo: OptMux iff offered, never an unknown bit.
			if want := opt & OptMux; a.Opt != want {
				t.Errorf("EchoOpt(%#x) = %#x, want %#x", opt, a.Opt, want)
			}
			// The dialer's view of its own offer and that echo.
			mux, err := MuxNegotiated(opt, a.Opt)
			if err != nil || mux != (opt&OptMux != 0) {
				t.Errorf("MuxNegotiated(%#x, %#x) = %v, %v", opt, a.Opt, mux, err)
			}
		}
	}
	// OptMux required is still an unknown required feature (FEATURE).
	req := Preface{Kind: KindStream, Req: OptMux, Instance: gDialer, CarrierID: gCarrier}
	PutPreface(b, &req)
	if _, err := ParsePreface(b); !errors.Is(err, ErrFeature) {
		t.Errorf("OptMux as a required bit: %v, want ErrFeature", err)
	}
	// Negotiation table: one side only gives a dedicated carrier; an
	// unsolicited OptMux in the answer is a carrier error; other optional
	// bits never matter.
	for _, c := range []struct {
		sent, answered uint32
		mux            bool
		err            error
	}{
		{0, 0, false, nil},
		{OptMux, 0, false, nil},
		{OptMux, OptMux, true, nil},
		{OptMux | 0x40, OptMux, true, nil},
		{OptMux, OptMux | 0x80000000, true, nil},
		{0, 0x80000000, false, nil},
		{0x80000000, 0x80000000, false, nil},
		{0xfffffffe, 0xfffffffe, false, nil},
		{0, OptMux, false, ErrMalformed},
		{0xfffffffe, OptMux, false, ErrMalformed},
		{0x80000000, 0xffffffff, false, ErrMalformed},
	} {
		mux, err := MuxNegotiated(c.sent, c.answered)
		if mux != c.mux || !sameErr(err, c.err) {
			t.Errorf("MuxNegotiated(%#x, %#x) = %v, %v; want %v, %v", c.sent, c.answered, mux, err, c.mux, c.err)
		}
	}
	for _, c := range []struct{ in, out uint32 }{{0, 0}, {OptMux, OptMux}, {0xfffffffe, 0}, {0xffffffff, OptMux}, {0x80000001, OptMux}} {
		if got := EchoOpt(c.in); got != c.out {
			t.Errorf("EchoOpt(%#x) = %#x, want %#x", c.in, got, c.out)
		}
	}
	// The golden prefaces carry exactly bit 0 and differ from M1's only in
	// opt and the CRC.
	for _, pair := range [][2]string{{"preface", "preface_optmux"}, {"preface_ack_ok", "preface_ack_optmux"}} {
		plain, mux := goldenByName(t, pair[0]).b, goldenByName(t, pair[1]).b
		if !bytes.Equal(plain[:12], mux[:12]) || !bytes.Equal(plain[16:36], mux[16:36]) || binary.BigEndian.Uint32(mux[12:16]) != OptMux {
			t.Errorf("%s vs %s: % x / % x", pair[0], pair[1], plain, mux)
		}
	}
}

// TestModeRaceParse_L44: OPEN.mode and JOIN.mode accept 1 … MaxMode = 3
// (ModeRace, M3-D28) on both session kinds; 0 and 4 … 255 are ErrValue,
// which the passive answers BAD_REQUEST CodeBadMode (§A3.5).
func TestModeRaceParse_L44(t *testing.T) {
	if ModeRace != 3 || MaxMode != ModeRace || CodeBadMode != 1 {
		t.Fatalf("ModeRace %d, MaxMode %d, CodeBadMode %d", ModeRace, MaxMode, CodeBadMode)
	}
	buf := make([]byte, OpenFixedLen)
	var jb [JoinLen]byte
	accepted := 0
	for m := range 256 {
		mode := uint8(m)
		want := error(nil)
		if mode < 1 || mode > 3 {
			want = ErrValue
		}
		for _, o := range []Open{
			{SID: gSID, Kind: KindStream, Mode: mode, RetainMs: 1, Window: 1 << 20},
			{SID: gSID, Kind: KindDatagram, Mode: mode, Window: gBudget, PMTU: gMaxPayload},
		} {
			n := PutOpen(buf, &o)
			got, err := ParseOpen(buf[:n], 0)
			if !sameErr(err, want) || (err == nil && got.Mode != mode) || (err != nil && got.SID != ([16]byte{})) {
				t.Errorf("OPEN kind %d mode %d: %+v, %v, want %v", o.Kind, mode, got.Mode, err, want)
			}
			if err == nil {
				accepted++
			}
		}
		j := Join{SID: gSID, Mode: mode, RxNext: 5}
		PutJoin(jb[:], &j)
		got, err := ParseJoin(jb[:])
		if !sameErr(err, want) || (err == nil && got != j) {
			t.Errorf("JOIN mode %d: %+v, %v, want %v", mode, got, err, want)
		}
		if err == nil {
			accepted++
		}
	}
	if accepted != 3*3 {
		t.Fatalf("%d mode encodings accepted, want 9 (modes 1–3 in two OPENs and a JOIN)", accepted)
	}
	// The golden race OPEN and JOIN carry 3 in byte 17 and 16 of their
	// payloads; the mode-4 OPEN is a payload rejection.
	if p := goldenByName(t, "open_mode_race").b[HeaderLen:]; p[17] != 3 {
		t.Errorf("open_mode_race mode byte %d", p[17])
	}
	if p := goldenByName(t, "join_mode_race").b[HeaderLen:]; p[16] != 3 {
		t.Errorf("join_mode_race mode byte %d", p[16])
	}
	if v := goldenByName(t, "open_mode_4"); v.kind != "reject" || v.b[HeaderLen+17] != 4 || !errors.Is(v.err, ErrValue) {
		t.Errorf("open_mode_4: %s % x %v", v.kind, v.b[HeaderLen+16:HeaderLen+18], v.err)
	}
}

// TestSessionHandleRule_L14: a session frame carries any handle but 0 —
// 0 is ErrHandle, every other value up to 2^32−1 parses (L14: no wrap or
// sign trouble at the top of the space) — for every session type, bare and
// REL-wrapped; carrier-level frames (DETACH included) keep handle 0, bare
// and REL-wrapped (M3 design §A3.2, M3-D4). SessionHandle stays 1, the
// first handle of every carrier.
func TestSessionHandleRule_L14(t *testing.T) {
	if SessionHandle != 1 {
		t.Fatalf("SessionHandle %d", SessionHandle)
	}
	handles := []uint32{0, 1, 2, 3, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff}
	session, carrier := 0, 0
	for i := range 0x80 {
		ty := Type(i)
		if !ty.Known() {
			continue
		}
		lo, _, _ := PayloadBounds(ty)
		if ty.CarrierLevel() {
			carrier++
		} else {
			session++
		}
		for _, h := range handles {
			want := error(nil)
			if ty.CarrierLevel() != (h == 0) {
				want = ErrHandle
			}
			got, err := ParseHeader(hdrBytes(byte(ty), 0, uint32(lo), 9, h))
			if !sameErr(err, want) || (err == nil && got.Handle != h) {
				t.Errorf("%v handle %#x: %+v, %v, want %v", ty, h, got, err, want)
			}
			// A whole frame decodes with its handle as given.
			if err == nil {
				if f, _, ferr := DecodeFrame(AppendFrame(nil, Header{Type: ty, Fseq: 9, Handle: h}, make([]byte, lo))); ferr != nil || f.Handle != h {
					t.Errorf("%v frame handle %#x: %+v, %v", ty, h, f.Header, ferr)
				}
			}
			if !Wrappable(ty) {
				continue
			}
			rh, inner, err := ParseRel(relPayload(RelHead{Cseq: 1, Type: ty, Handle: h}, validInner(ty)))
			if !sameErr(err, want) || (err == nil && (rh.Handle != h || !bytes.Equal(inner, validInner(ty)))) {
				t.Errorf("REL{%v} handle %#x: %+v, %v, want %v", ty, h, rh, err, want)
			}
		}
	}
	if session != 11 || carrier != 7 {
		t.Fatalf("%d session and %d carrier-level core types, want 11 and 7", session, carrier)
	}
	// The golden vectors with handles 2, 7, 3 and 2^32−1 decode with them;
	// handle 0 on DATA is a header rejection.
	for name, h := range map[string]uint32{"data_handle_2": 2, "data_handle_max": 0xffffffff, "ack_handle_7": 7, "dgram_handle_3": 3} {
		if f, _, err := DecodeFrame(goldenByName(t, name).b); err != nil || f.Handle != h {
			t.Errorf("%s: handle %d, %v", name, f.Handle, err)
		}
	}
	if _, _, err := DecodeFrame(goldenByName(t, "data_handle_0").b); !errors.Is(err, ErrHandle) {
		t.Errorf("data_handle_0: %v, want ErrHandle", err)
	}
	// The M1 and M2 vectors keep handle 1 on every session frame (a
	// dedicated carrier carries handle 1 only; the carrier enforces it).
	for _, v := range goldenVectors() {
		if v.kind == "frame" && !v.hdr.Type.Extension() && !v.hdr.Type.CarrierLevel() &&
			v.hdr.Handle != SessionHandle && !bytes.Contains([]byte(v.name), []byte("handle")) {
			t.Errorf("%s: session handle %d", v.name, v.hdr.Handle)
		}
	}
}

// TestWrappableDetach: DETACH is REL-wrapped on datagram trunks (M3-D6):
// Wrappable, its inner handle 0 (any other is ErrHandle), its inner payload
// exactly 5 bytes (ErrLength otherwise), no inner flag (ErrFlags); the
// REL{DETACH} frame is 32 bytes and fits ControlFloor; RelMaxPayload is
// unchanged (§A3.6).
func TestWrappableDetach(t *testing.T) {
	if !Wrappable(TypeDetach) {
		t.Fatal("DETACH is not wrappable")
	}
	inner := []byte{0, 0, 0, 3, 1}
	rh, in, err := ParseRel(relPayload(RelHead{Cseq: 0xffffffff, Type: TypeDetach}, inner))
	if err != nil || rh != (RelHead{Cseq: 0xffffffff, Type: TypeDetach}) || !bytes.Equal(in, inner) {
		t.Fatalf("REL{DETACH}: %+v % x %v", rh, in, err)
	}
	if d, err := ParseDetach(in); err != nil || d != (Detach{Handle: 3, Reason: DetachEnded}) {
		t.Errorf("REL{DETACH} inner: %+v, %v", d, err)
	}
	for _, c := range []struct {
		name  string
		h     RelHead
		inner []byte
		err   error
	}{
		{"inner handle 1", RelHead{Cseq: 1, Type: TypeDetach, Handle: 1}, inner, ErrHandle},
		{"inner handle 3", RelHead{Cseq: 1, Type: TypeDetach, Handle: 3}, inner, ErrHandle},
		{"inner flag", RelHead{Cseq: 1, Type: TypeDetach, Flags: 1}, inner, ErrFlags},
		{"inner 4 bytes", RelHead{Cseq: 1, Type: TypeDetach}, inner[:4], ErrLength},
		{"inner 6 bytes", RelHead{Cseq: 1, Type: TypeDetach}, append(bytes.Clone(inner), 0), ErrLength},
		{"inner empty", RelHead{Cseq: 1, Type: TypeDetach}, nil, ErrLength},
	} {
		rh, in, err := ParseRel(relPayload(c.h, c.inner))
		if !errors.Is(err, c.err) || rh != (RelHead{}) || in != nil {
			t.Errorf("REL{DETACH} %s: %+v, %v, want %v", c.name, rh, err, c.err)
		}
	}
	// The payload rules apply after unwrapping (the carrier parses the
	// inner payload at dispatch).
	if _, in, err := ParseRel(relPayload(RelHead{Cseq: 1, Type: TypeDetach}, []byte{0, 0, 0, 0, 2})); err != nil {
		t.Fatal(err)
	} else if _, err := ParseDetach(in); !errors.Is(err, ErrValue) {
		t.Errorf("REL{DETACH handle 0}: %v, want ErrValue", err)
	}
	v := goldenByName(t, "rel_detach")
	if len(v.b) != 32 || FrameOverhead+RelHeadLen+DetachLen != 32 || 32 > ControlFloor || RelMaxPayload != 275 {
		t.Errorf("REL{DETACH} %d bytes, RelMaxPayload %d", len(v.b), RelMaxPayload)
	}
	if r, ok := v.val.(relVal); !ok || r.Head.Type != TypeDetach || r.Head.Handle != 0 {
		t.Errorf("rel_detach decodes as %+v", v.val)
	}
}
