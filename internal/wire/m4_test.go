package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// M4 wire tests (M4 design §A3.1, §A3.3, §A3.5, §A12.1 WP7): OPEN flag bit
// 0 (EARLY) becomes legal on stream OPENs; every other bit stays reserved,
// and EARLY on a packet OPEN is ErrReserved. Every M1–M3 golden vector
// stays byte-identical (they all carry flags 0). The size rows of the
// first flight are in TestControlFrameSizes_L37.

// goldenVectorsM4 builds the vectors M4 adds (M4 design §A3.5), after every
// M1–M3 vector: the M1 OPEN vector (open_mlen0) with EARLY set, EARLY on a
// packet OPEN, and flag bit 1 (still reserved); then (WP13 B-1) a PREFACE
// and a PREFACE_ACK with OptEndCode and the JOIN_ACK(UNKNOWN_SESSION) on
// handle 1 that carries an end code under it (the code-free form is
// join_ack_unknown_session).
func goldenVectorsM4() []vector {
	var vs []vector
	add := func(v vector) { vs = append(vs, v) }

	add(frameVec("open_early", TypeOpen, 0, FirstFseq, SessionHandle, gEarlyOpen()))
	packet := gPacketOpen()
	packet.Flags = OpenFlagEarly
	add(rejectFrameVec("open_early_packet", TypeOpen, FirstFseq, SessionHandle, packet, ErrReserved))
	bit1 := gEarlyOpen()
	bit1.Flags = 1 << 1
	add(rejectFrameVec("open_flags_2", TypeOpen, FirstFseq, SessionHandle, bit1, ErrReserved))
	add(prefaceVec("preface_optendcode", Preface{Kind: KindStream, Opt: OptEndCode, Instance: gDialer, CarrierID: gCarrier}))
	add(prefaceAckVec("preface_ack_optendcode", PrefaceAck{Status: PrefaceOK, Opt: OptEndCode, Instance: gPassive, CarrierID: gCarrier}))
	add(frameVec("join_ack_unknown_session_endcode", TypeJoinAck, 0, FirstFseq, SessionHandle, joinAckMuxVal{A: JoinAck{Status: StatusUnknownSession}, Code: gEndCode}))
	return vs
}

// gEndCode is the end code of the golden JOIN_ACK(UNKNOWN_SESSION) under
// OptEndCode: an application abort code (0x5000).
const gEndCode uint32 = 0x5000

// gEarlyOpen is the M1 OPEN vector open_mlen0 with OpenFlagEarly.
func gEarlyOpen() Open {
	return Open{SID: gSID, Kind: KindStream, Mode: 1, Flags: OpenFlagEarly, RetainMs: 34000, Window: 8 << 20}
}

// TestOpenEarlyRules_L44: of the 2^16 flag values, a stream OPEN accepts
// exactly 0 and OpenFlagEarly (and decodes the flag back), a packet OPEN
// exactly 0; every other value is ErrReserved. EARLY changes no other
// check: the earlier checks (length, SID, kind, mode) keep their errors
// and order, and the flag check runs before the PMTU checks. An accepted
// EARLY OPEN re-encodes to the same bytes, its metadata (an l4 address,
// say) aliasing the input. The golden open_early is open_mlen0 with only
// the flags field changed (M4 design §A3.1, §A3.5, M4-D3).
func TestOpenEarlyRules_L44(t *testing.T) {
	enc := func(o Open) []byte {
		b := make([]byte, OpenFixedLen+len(o.Metadata))
		PutOpen(b, &o)
		return b
	}
	stream := Open{SID: gSID, Kind: KindStream, Mode: 1, RetainMs: 34000, Window: 8 << 20}
	packet := gPacketOpen()
	accepted := map[CarrierKind][]uint16{}
	for _, base := range []Open{stream, packet} {
		for fl := range 1 << 16 {
			o := base
			o.Flags = uint16(fl)
			got, err := ParseOpen(enc(o), 0)
			want := error(ErrReserved)
			if fl == 0 || (uint16(fl) == OpenFlagEarly && base.Kind == KindStream) {
				want = nil
			}
			if !sameErr(err, want) {
				t.Fatalf("kind %d flags %#04x: %v, want %v", base.Kind, fl, err, want)
			}
			if err != nil {
				if got.SID != ([16]byte{}) || got.Flags != 0 {
					t.Fatalf("kind %d flags %#04x: error %v with a non-zero result %+v", base.Kind, fl, err, got)
				}
				continue
			}
			if got.Flags != uint16(fl) {
				t.Fatalf("kind %d flags %#04x decoded as %#04x", base.Kind, fl, got.Flags)
			}
			accepted[base.Kind] = append(accepted[base.Kind], uint16(fl))
		}
	}
	if s, p := accepted[KindStream], accepted[KindDatagram]; len(s) != 2 || s[1] != OpenFlagEarly || len(p) != 1 || p[0] != 0 {
		t.Fatalf("accepted flags: stream %v, packet %v; want [0 1] and [0]", s, p)
	}
	if OpenFlagEarly != 1 || EarlyWindow != 65536 {
		t.Fatalf("OpenFlagEarly %#x, EarlyWindow %d", OpenFlagEarly, EarlyWindow)
	}

	// The checks before the flags keep their errors, also when EARLY sits
	// on a packet OPEN or bit 1 is set; the flag check comes before the
	// PMTU checks (a packet EARLY OPEN with a bad PMTU is
	// ErrReserved, a stream EARLY OPEN with a PMTU too).
	early := stream
	early.Flags = OpenFlagEarly
	zeroSID, kind3, mode4, streamPMTU, packetBadPMTU, packetBadWindow := early, early, early, early, packet, packet
	zeroSID.SID = [16]byte{}
	kind3.Kind = 3
	mode4.Mode = MaxMode + 1
	// The packet-EARLY and the other-flag checks come after the kind and
	// mode checks: a bad mode stays ErrValue (root answers CodeBadMode,
	// not CodeBadValue) whatever the flags say.
	mode0 := early
	mode0.Mode = 0
	packetMode0, packetMode4 := packet, packet
	packetMode0.Flags, packetMode0.Mode = OpenFlagEarly, 0
	packetMode4.Flags, packetMode4.Mode = OpenFlagEarly, MaxMode+1
	bit1Kind3, bit1Mode0, bit1Mode4 := kind3, mode0, mode4
	bit1Kind3.Flags, bit1Mode0.Flags, bit1Mode4.Flags = 1<<1, 1<<1, 1<<1
	streamPMTU.PMTU = MinPacketPayload
	packetBadPMTU.Flags, packetBadPMTU.PMTU = OpenFlagEarly, 0
	packetBadWindow.Flags, packetBadWindow.Window = OpenFlagEarly, 1
	for _, c := range []struct {
		name string
		b    []byte
		max  int
		err  error
	}{
		{"short", enc(early)[:OpenFixedLen-1], 0, ErrShort},
		{"mlen beyond maxMeta", enc(Open{SID: gSID, Kind: KindStream, Mode: 1, Flags: OpenFlagEarly, Metadata: make([]byte, 11)}), 10, ErrLength},
		{"metadata trailing", append(enc(early), 0), 0, ErrTrailing},
		{"zero SID", enc(zeroSID), 0, ErrReserved},
		{"kind 3", enc(kind3), 0, ErrValue},
		{"mode 4", enc(mode4), 0, ErrValue},
		{"mode 0", enc(mode0), 0, ErrValue},
		{"packet, mode 0", enc(packetMode0), 0, ErrValue},
		{"packet, mode 4", enc(packetMode4), 0, ErrValue},
		{"bit 1, kind 3", enc(bit1Kind3), 0, ErrValue},
		{"bit 1, mode 0", enc(bit1Mode0), 0, ErrValue},
		{"bit 1, mode 4", enc(bit1Mode4), 0, ErrValue},
		{"stream with a PMTU", enc(streamPMTU), 0, ErrReserved},
		{"packet, PMTU 0", enc(packetBadPMTU), 0, ErrReserved},
		{"packet, window 1", enc(packetBadWindow), 0, ErrReserved},
	} {
		if _, err := ParseOpen(c.b, c.max); !sameErr(err, c.err) {
			t.Errorf("EARLY OPEN, %s: %v, want %v", c.name, err, c.err)
		}
	}

	// An EARLY OPEN with metadata (the IPv4 l4 address of §A3.3) re-encodes
	// to the same bytes, and its metadata aliases the input.
	withMeta := early
	withMeta.Metadata = l4MetaIPv4()
	b := enc(withMeta)
	o, err := ParseOpen(b, 4096)
	if err != nil || o.Flags != OpenFlagEarly || !bytes.Equal(o.Metadata, withMeta.Metadata) || &o.Metadata[0] != &b[OpenFixedLen] || !bytes.Equal(enc(o), b) {
		t.Fatalf("EARLY OPEN with metadata: %+v, %v", o, err)
	}
	if a := testing.AllocsPerRun(100, func() { sinkOpen, sinkErr = ParseOpen(b, 4096) }); a != 0 {
		t.Errorf("ParseOpen of an EARLY OPEN: %v allocs", a)
	}

	// The golden vectors: open_early is open_mlen0 with only the flags
	// field (payload bytes 18–19) set to 0x0001; the two rejections carry
	// EARLY on a packet OPEN and bit 1.
	m1, e := goldenByName(t, "open_mlen0"), goldenByName(t, "open_early")
	p1, pe := m1.b[HeaderLen:len(m1.b)-TrailerLen], e.b[HeaderLen:len(e.b)-TrailerLen]
	if len(p1) != len(pe) || !bytes.Equal(p1[:18], pe[:18]) || !bytes.Equal(p1[20:], pe[20:]) || binary.BigEndian.Uint16(p1[18:20]) != 0 || binary.BigEndian.Uint16(pe[18:20]) != OpenFlagEarly {
		t.Errorf("open_early is not open_mlen0 with flags 0x0001:\n% x\n% x", p1, pe)
	}
	if v := goldenByName(t, "open_early_packet"); v.kind != "reject" || !errors.Is(v.err, ErrReserved) || v.b[HeaderLen+16] != byte(KindDatagram) || binary.BigEndian.Uint16(v.b[HeaderLen+18:]) != OpenFlagEarly {
		t.Errorf("open_early_packet: %s % x %v", v.kind, v.b[HeaderLen+16:HeaderLen+20], v.err)
	}
	if v := goldenByName(t, "open_flags_2"); v.kind != "reject" || !errors.Is(v.err, ErrReserved) || binary.BigEndian.Uint16(v.b[HeaderLen+18:]) != 2 {
		t.Errorf("open_flags_2: %s % x %v", v.kind, v.b[HeaderLen+16:HeaderLen+20], v.err)
	}
}

// TestEarlyFirstFlightDecodes_L43: the largest first flight of M4 design
// §A3.2/§A3.3 — PREFACE ‖ OPEN(EARLY, 4 KiB of metadata) ‖ DATA(handle 1,
// offset 0, EarlyWindow bytes) — is one byte string the M1 decoder takes
// apart frame by frame: the OPEN at the PREFACE's first fseq f, the DATA at
// f+1 with the early bytes intact; it fits the 256 KiB write batch and one
// frame payload. A smaller flight ("hello") decodes the same way.
func TestEarlyFirstFlightDecodes_L43(t *testing.T) {
	for _, c := range []struct {
		name string
		meta []byte
		body []byte
		size int
	}{
		{"largest", l4MetaMax(), pattern(EarlyWindow, 7), 69746},
		{"hello", l4MetaIPv4(), []byte("hello"), PrefaceLen + 60 + 13 + 8 + 5 + 4},
	} {
		pre := make([]byte, PrefaceLen)
		PutPreface(pre, &Preface{Kind: KindStream, Instance: gDialer, CarrierID: gCarrier})
		f := PrefaceFseq(pre)
		o := gEarlyOpen()
		o.Metadata = c.meta
		flight := append(bytes.Clone(pre), AppendFrame(nil, Header{Type: TypeOpen, Fseq: f, Handle: SessionHandle}, encodeTyped(TypeOpen, o))...)
		flight = AppendFrame(flight, Header{Type: TypeData, Fseq: f + 1, Handle: SessionHandle}, encodeTyped(TypeData, dataVal{Off: 0, Body: c.body}))
		if len(flight) != c.size || len(flight) > 256<<10 {
			t.Errorf("%s: first flight %d bytes, want %d (≤ the 256 KiB batch)", c.name, len(flight), c.size)
		}
		if _, err := ParsePreface(flight[:PrefaceLen]); err != nil {
			t.Fatalf("%s: PREFACE: %v", c.name, err)
		}
		rest := flight[PrefaceLen:]
		fr, n, err := DecodeFrame(rest)
		if err != nil || fr.Type != TypeOpen || fr.Fseq != f || fr.Handle != SessionHandle {
			t.Fatalf("%s: first frame %+v, %v", c.name, fr.Header, err)
		}
		got, err := ParseOpen(fr.Payload, MaxMetadata)
		if err != nil || got.Flags != OpenFlagEarly || !bytes.Equal(got.Metadata, c.meta) {
			t.Fatalf("%s: OPEN %+v, %v", c.name, got, err)
		}
		rest = rest[n:]
		fr, n, err = DecodeFrame(rest)
		if err != nil || fr.Type != TypeData || fr.Fseq != f+1 || fr.Handle != SessionHandle || n != len(rest) || int(fr.Len) > MaxFramePayload {
			t.Fatalf("%s: second frame %+v, n %d of %d, %v", c.name, fr.Header, n, len(rest), err)
		}
		off, err := ParseDataOffset(fr.Payload)
		body := fr.Payload[DataPrefixLen:]
		if err != nil || off != 0 || !bytes.Equal(body, c.body) || off+uint64(len(body)) > EarlyWindow {
			t.Fatalf("%s: DATA offset %d, %d bytes, %v", c.name, off, len(body), err)
		}
	}
}

// l4MetaIPv4 is the l4 metadata of the IPv4 loopback, port 443, without an
// application part, as a hand-built byte layout (M4 design §A3.4; package
// wire cannot import l4, R1-28): magic "L4", version 1, CONNECT, atyp 1,
// four address bytes, port.
func l4MetaIPv4() []byte {
	return []byte{0x4c, 0x34, 0x01, 0x01, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x01, 0xbb}
}

// l4MetaLongestDomain is the l4 metadata of the longest domain (253 bytes
// of labels and a trailing dot, n = 254), port 443, without an application
// part: an 8 + 254 = 262-byte header, hand-built.
func l4MetaLongestDomain() []byte {
	name := bytes.Repeat([]byte("a"), 63)
	name = append(name, '.')
	name = append(name, bytes.Repeat([]byte("b"), 63)...)
	name = append(name, '.')
	name = append(name, bytes.Repeat([]byte("c"), 63)...)
	name = append(name, '.')
	name = append(name, bytes.Repeat([]byte("d"), 61)...) // 253 bytes
	name = append(name, '.')                              // the trailing dot
	b := []byte{0x4c, 0x34, 0x01, 0x01, 0x03, byte(len(name))}
	b = append(b, name...)
	return append(b, 0x01, 0xbb)
}

// l4MetaMax is MaxMetadata's default (4 KiB) of l4 metadata: the IPv4
// header and 4,085 application bytes.
func l4MetaMax() []byte {
	b := l4MetaIPv4()
	return append(b, pattern(4096-len(b), 0x4c)...)
}

// refOpenErr is an independent statement of ParseOpen's check order (M1
// design §5.3, M2 design §A3.5, M3 mode 3, M4 design §A3.1).
func refOpenErr(p []byte, maxMeta int) error {
	if len(p) < 32 {
		return ErrShort
	}
	maxMeta = max(0, min(maxMeta, 65535))
	mlen := int(p[30])<<8 | int(p[31])
	switch {
	case mlen > maxMeta:
		return ErrLength
	case len(p)-32 < mlen:
		return ErrShort
	case len(p)-32 > mlen:
		return ErrTrailing
	case bytes.Equal(p[:16], make([]byte, 16)):
		return ErrReserved
	}
	kind, mode := p[16], p[17]
	flags := uint16(p[18])<<8 | uint16(p[19])
	window := uint32(p[24])<<24 | uint32(p[25])<<16 | uint32(p[26])<<8 | uint32(p[27])
	pmtu := int(p[28])<<8 | int(p[29])
	if kind != 1 && kind != 2 || mode < 1 || mode > 3 {
		return ErrValue
	}
	for bit := 1; bit < 16; bit++ {
		if flags&(1<<bit) != 0 {
			return ErrReserved
		}
	}
	if kind == 1 {
		if pmtu != 0 {
			return ErrReserved
		}
		return nil
	}
	switch {
	case flags&1 != 0:
		return ErrReserved
	case pmtu < 512 || pmtu > 65507:
		return ErrValue
	case window != 0 && (window < 537 || window > 65507):
		return ErrValue
	}
	return nil
}

// FuzzOpen_L44: ParseOpen on any payload and two metadata limits: no
// panic, the input unchanged, the error the reference check order gives,
// an accepted payload re-encodes to itself with its metadata aliasing the
// input, an error returns the zero Open, and no allocation. Seeds: the
// payload of every OPEN golden vector (the M4 EARLY ones included), each
// truncated by one byte and extended by one, and EARLY seeds of §A3.5
// (an l4 address, the longest domain, 4 KiB, packet EARLY, EARLY with
// every other bit).
func FuzzOpen_L44(f *testing.F) {
	var seeds [][]byte
	for _, v := range goldenVectors() {
		frame := v.kind == "frame" || v.kind == "reject" && v.as == "frame"
		if frame && Type(v.b[0]) == TypeOpen {
			seeds = append(seeds, v.b[HeaderLen:len(v.b)-TrailerLen])
		}
	}
	for _, m := range [][]byte{l4MetaIPv4(), l4MetaLongestDomain(), l4MetaMax()} {
		o := gEarlyOpen()
		o.Metadata = m
		seeds = append(seeds, encodeTyped(TypeOpen, o))
	}
	for _, fl := range []uint16{OpenFlagEarly | 1<<1, OpenFlagEarly | 1<<15, 0xffff} {
		o := gEarlyOpen()
		o.Flags = fl
		seeds = append(seeds, encodeTyped(TypeOpen, o))
	}
	packet := gPacketOpen()
	packet.Flags = OpenFlagEarly
	seeds = append(seeds, encodeTyped(TypeOpen, packet))
	// Check order against the kind and mode checks: a bad mode or kind
	// with EARLY on a packet OPEN, or with bit 1, is still ErrValue.
	for _, fl := range []uint16{OpenFlagEarly, 1 << 1} {
		for _, km := range [][2]byte{{byte(KindDatagram), 0}, {byte(KindDatagram), MaxMode + 1}, {byte(KindStream), 0}, {3, 1}} {
			o := gPacketOpen()
			o.Flags, o.Kind, o.Mode = fl, CarrierKind(km[0]), km[1]
			seeds = append(seeds, encodeTyped(TypeOpen, o))
		}
	}
	if len(seeds) < 20 {
		f.Fatalf("only %d OPEN seeds", len(seeds))
	}
	for _, s := range seeds {
		f.Add(s)
		f.Add(s[:len(s)-1])
		f.Add(append(bytes.Clone(s), 0))
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		orig := bytes.Clone(p)
		for _, maxMeta := range []int{MaxMetadata, 4096} {
			o, err := ParseOpen(p, maxMeta)
			if want := refOpenErr(p, maxMeta); !sameErr(err, want) {
				t.Fatalf("maxMeta %d: %v, the reference says %v (% x)", maxMeta, err, want, p[:min(len(p), OpenFixedLen)])
			}
			if err != nil {
				if o.SID != ([16]byte{}) || o.Metadata != nil || o.Flags != 0 {
					t.Fatalf("error %v with a non-zero result %+v", err, o)
				}
			} else {
				out := make([]byte, OpenFixedLen+len(o.Metadata))
				if PutOpen(out, &o); !bytes.Equal(out, p) {
					t.Fatalf("accepted OPEN re-encodes differently:\n in % x\nout % x", p, out)
				}
				if len(o.Metadata) > 0 && &o.Metadata[0] != &p[OpenFixedLen] {
					t.Fatal("metadata does not alias the input")
				}
			}
			checkAllocs(t, "ParseOpen", func() { sinkOpen, sinkErr = ParseOpen(p, maxMeta) })
		}
		if !bytes.Equal(p, orig) {
			t.Fatal("ParseOpen modified its input")
		}
	})
}
