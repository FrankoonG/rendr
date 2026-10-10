package wire

import "encoding/binary"

// Preface is a dialer PREFACE (40 bytes, not a frame):
//
//	"RND2" | major u8 | minor u8 | kind u8 | role u8 (=1) | req u32 | opt u32 |
//	instance [16] | carrierID u32 | crc32c u32 (over bytes 0..35)
type Preface struct {
	Minor     uint8
	Kind      CarrierKind
	Req, Opt  uint32   // required feature bits (none known: KnownRequired) / optional ones (OptMux, M3-D3)
	Instance  [16]byte // the dialer Runtime's InstanceID; all-zero is invalid
	CarrierID uint32   // assigned by the dialer, unique while in use in its Runtime; 0 is invalid
}

// PrefaceAck is the passive's PREFACE_ACK (40 bytes, not a frame):
//
//	"RND2" | major u8 | minor u8 | status u8 | role u8 (=2) | req u32 | opt u32 |
//	instance [16] | carrierID u32 (echo) | crc32c u32
type PrefaceAck struct {
	Minor     uint8
	Status    PrefaceStatus
	Req, Opt  uint32   // Opt of an OK answer: EchoOpt of the PREFACE's (MuxNegotiated checks it)
	Instance  [16]byte // the passive Runtime's InstanceID; all-zero is invalid
	CarrierID uint32   // echo of the PREFACE carrierID
}

// PutPreface writes exactly PrefaceLen bytes of p (major Major, role dialer,
// CRC) into b[:PrefaceLen]. It panics if len(b) < PrefaceLen (programming
// error).
func PutPreface(b []byte, p *Preface) {
	putPreface(b, p.Minor, uint8(p.Kind), RoleDialer, p.Req, p.Opt, &p.Instance, p.CarrierID)
}

// PutPrefaceAck writes exactly PrefaceLen bytes of a (major Major, role
// passive, CRC) into b[:PrefaceLen]. It panics if len(b) < PrefaceLen.
func PutPrefaceAck(b []byte, a *PrefaceAck) {
	putPreface(b, a.Minor, uint8(a.Status), RolePassive, a.Req, a.Opt, &a.Instance, a.CarrierID)
}

// PrefaceFseq returns the fseq of the first frame in the carrier direction
// that b — the PrefaceLen bytes of a PREFACE or a PREFACE_ACK — opens: its
// CRC32C field (bytes 36–39). The dialer's direction starts at its
// PREFACE's, the passive's at its PREFACE_ACK's, and both differ between
// carriers (instance, carrier ID), so a frame spliced in from another
// carrier at the same frame index fails the fseq check like any other
// (design §0.13 A6; L43). It panics if len(b) < PrefaceLen.
func PrefaceFseq(b []byte) uint32 {
	return binary.BigEndian.Uint32(b[36:PrefaceLen])
}

// putPreface writes the 40-byte layout shared by PREFACE and PREFACE_ACK;
// byte 6 is the kind (PREFACE) or the status (PREFACE_ACK).
func putPreface(b []byte, minor, b6 uint8, role Role, req, opt uint32, inst *[16]byte, id uint32) {
	_ = b[PrefaceLen-1]
	copy(b[0:4], Magic[:])
	b[4] = Major
	b[5] = minor
	b[6] = b6
	b[7] = uint8(role)
	binary.BigEndian.PutUint32(b[8:12], req)
	binary.BigEndian.PutUint32(b[12:16], opt)
	copy(b[16:32], inst[:])
	binary.BigEndian.PutUint32(b[32:36], id)
	binary.BigEndian.PutUint32(b[36:40], CRC(b[:36]))
}

// ParsePreface decodes a PREFACE. len(b) must be exactly PrefaceLen. Checks,
// in this canonical order (design §5.1; the passive's answer is derived from
// the error alone): length (ErrShort/ErrTrailing), magic (ErrMagic), CRC
// (ErrCRC), major (ErrMajor), role (ErrMalformed), kind (ErrMalformed for
// anything but stream or datagram), zero instance or zero carrier ID
// (ErrMalformed), required bits outside KnownRequired (ErrFeature). Unknown
// optional bits are ignored.
//
// Every major keeps the 40-byte length, the magic, the major in byte 4 and
// the CRC32C of bytes 0–35 in bytes 36–39; only the other fields may change
// meaning. The major is therefore checked before any of them, so a PREFACE
// of another major is answered PREFACE_ACK(VERSION), never closed silently.
//
// Only ErrFeature comes with the decoded value (every other field is valid,
// so the FEATURE answer can echo the carrier ID); every other error returns
// the zero Preface.
func ParsePreface(b []byte) (Preface, error) {
	if err := checkPreface(b, RoleDialer); err != nil {
		return Preface{}, err
	}
	p := Preface{
		Minor:     b[5],
		Kind:      CarrierKind(b[6]),
		Req:       binary.BigEndian.Uint32(b[8:12]),
		Opt:       binary.BigEndian.Uint32(b[12:16]),
		CarrierID: binary.BigEndian.Uint32(b[32:36]),
	}
	copy(p.Instance[:], b[16:32])
	if p.Kind != KindStream && p.Kind != KindDatagram {
		return Preface{}, ErrMalformed
	}
	if p.Instance == ([16]byte{}) || p.CarrierID == 0 {
		return Preface{}, ErrMalformed
	}
	if p.Req&^KnownRequired != 0 {
		return p, ErrFeature
	}
	return p, nil
}

// ParsePrefaceAck decodes a PREFACE_ACK in the same canonical order for the
// passive role (byte 6 is the status, which must be a defined PrefaceStatus:
// ErrMalformed otherwise). A well-formed VERSION or FEATURE answer is
// returned with a nil error. ErrMajor (valid magic and CRC, another major)
// and ErrFeature (unknown required bits) are deterministic capability gaps
// as well: the dialer maps all four to ErrVersion (design §5.1). Every other
// error is a carrier error. As for ParsePreface, only ErrFeature comes with
// the decoded value.
func ParsePrefaceAck(b []byte) (PrefaceAck, error) {
	if err := checkPreface(b, RolePassive); err != nil {
		return PrefaceAck{}, err
	}
	a := PrefaceAck{
		Minor:     b[5],
		Status:    PrefaceStatus(b[6]),
		Req:       binary.BigEndian.Uint32(b[8:12]),
		Opt:       binary.BigEndian.Uint32(b[12:16]),
		CarrierID: binary.BigEndian.Uint32(b[32:36]),
	}
	copy(a.Instance[:], b[16:32])
	if a.Status > PrefaceCapacity {
		return PrefaceAck{}, ErrMalformed
	}
	if a.Instance == ([16]byte{}) || a.CarrierID == 0 {
		return PrefaceAck{}, ErrMalformed
	}
	if a.Req&^KnownRequired != 0 {
		return a, ErrFeature
	}
	return a, nil
}

// checkPreface runs the steps of the canonical order (design §5.1) that do
// not depend on the direction's byte 6: length, magic, CRC, major and role.
func checkPreface(b []byte, role Role) error {
	switch {
	case len(b) < PrefaceLen:
		return ErrShort
	case len(b) > PrefaceLen:
		return ErrTrailing
	}
	if b[0] != Magic[0] || b[1] != Magic[1] || b[2] != Magic[2] || b[3] != Magic[3] {
		return ErrMagic
	}
	if CRC(b[:36]) != binary.BigEndian.Uint32(b[36:40]) {
		return ErrCRC
	}
	if b[4] != Major {
		return ErrMajor
	}
	if Role(b[7]) != role {
		return ErrMalformed
	}
	return nil
}

// EchoOpt returns the opt field of the PREFACE_ACK(OK) that answers a
// PREFACE whose opt field is offered: the optional bits this build
// implements that the PREFACE announced (KnownOptional). A passive that
// implements mux therefore echoes OptMux iff the PREFACE carried it
// (M3-D3) and never echoes a bit it does not know. A passive that does not
// want a feature on a carrier clears its bit from the result.
func EchoOpt(offered uint32) uint32 { return offered & KnownOptional }

// MuxNegotiated reports whether a carrier is a MUX trunk from the opt field
// the dialer sent in its PREFACE and the opt field of the PREFACE_ACK(OK)
// it received: true iff both carry OptMux (M3-D3). A PREFACE_ACK carrying
// OptMux for a PREFACE without it is ErrMalformed — a carrier error of the
// attempt, never ErrVersion (M3 design §A3.1). Every other optional bit is
// ignored in both fields.
func MuxNegotiated(sent, answered uint32) (bool, error) {
	if answered&OptMux != 0 && sent&OptMux == 0 {
		return false, ErrMalformed
	}
	return sent&answered&OptMux != 0, nil
}
