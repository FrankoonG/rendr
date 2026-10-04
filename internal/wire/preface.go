package wire

// Preface is a dialer PREFACE (40 bytes, not a frame):
//
//	"RND2" | major u8 | minor u8 | kind u8 | role u8 (=1) | req u32 | opt u32 |
//	instance [16] | carrierID u32 | crc32c u32 (over bytes 0..35)
type Preface struct {
	Minor     uint8
	Kind      CarrierKind
	Req, Opt  uint32   // required / optional feature bits; M1 sends 0/0
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
	Req, Opt  uint32
	Instance  [16]byte // the passive Runtime's InstanceID; all-zero is invalid
	CarrierID uint32   // echo of the PREFACE carrierID
}

// PutPreface writes exactly PrefaceLen bytes of p (major Major, role dialer,
// CRC) into b[:PrefaceLen]. It panics if len(b) < PrefaceLen (programming
// error).
func PutPreface(b []byte, p *Preface) {
	panic("unimplemented: M1b")
}

// PutPrefaceAck writes exactly PrefaceLen bytes of a (major Major, role
// passive, CRC) into b[:PrefaceLen]. It panics if len(b) < PrefaceLen.
func PutPrefaceAck(b []byte, a *PrefaceAck) {
	panic("unimplemented: M1b")
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
func ParsePreface(b []byte) (Preface, error) {
	panic("unimplemented: M1b")
}

// ParsePrefaceAck decodes a PREFACE_ACK in the same canonical order for the
// passive role (byte 6 is the status, which must be a defined PrefaceStatus:
// ErrMalformed otherwise). A well-formed VERSION or FEATURE answer is
// returned with a nil error. ErrMajor (valid magic and CRC, another major)
// and ErrFeature (unknown required bits) are deterministic capability gaps
// as well: the dialer maps all four to ErrVersion (design §5.1). Every other
// error is a carrier error.
func ParsePrefaceAck(b []byte) (PrefaceAck, error) {
	panic("unimplemented: M1b")
}
