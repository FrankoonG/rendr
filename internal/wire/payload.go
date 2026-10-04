package wire

import (
	"encoding/binary"
	"math"
)

// Open is the OPEN payload:
//
//	sid[16] | kind u8 | mode u8 | flags u16 | retain_ms u32 | window u32 | pmtu u16 | mlen u16 | metadata
type Open struct {
	SID      [16]byte    // chosen by the dialer from crypto/rand; all-zero is invalid (ErrReserved)
	Kind     CarrierKind // session kind: 1 stream (M1)
	Mode     uint8       // 1 selector, 2 bond (3 race decodes; answered BAD_REQUEST until M3)
	Flags    uint16      // OpenFlagEarly reserved until M4: all bits must be 0
	RetainMs uint32      // the dialer's PassiveRetain in milliseconds
	Window   uint32      // the dialer's initial receive window (0 is legal: memory pressure)
	PMTU     uint16      // 0 for stream sessions (M2)
	Metadata []byte      // mlen u16 + bytes; aliases the input when decoded
}

// PutOpen writes o into dst and returns OpenFixedLen + len(o.Metadata). It
// panics if dst is too small or len(o.Metadata) > MaxMetadata.
func PutOpen(dst []byte, o *Open) int {
	if len(o.Metadata) > MaxMetadata {
		panic("rendr/wire: PutOpen: metadata beyond MaxMetadata")
	}
	n := OpenFixedLen + len(o.Metadata)
	_ = dst[n-1]
	copy(dst[0:16], o.SID[:])
	dst[16] = uint8(o.Kind)
	dst[17] = o.Mode
	binary.BigEndian.PutUint16(dst[18:20], o.Flags)
	binary.BigEndian.PutUint32(dst[20:24], o.RetainMs)
	binary.BigEndian.PutUint32(dst[24:28], o.Window)
	binary.BigEndian.PutUint16(dst[28:30], o.PMTU)
	binary.BigEndian.PutUint16(dst[30:32], uint16(len(o.Metadata)))
	copy(dst[OpenFixedLen:n], o.Metadata)
	return n
}

// ParseOpen decodes an OPEN payload. The explicit mlen must equal the
// remaining bytes exactly; mlen > maxMeta returns ErrLength before the
// metadata is touched. Kind must be 1 or 2, mode 1..3 (ErrValue); flags and
// PMTU on a stream session must be 0 (ErrReserved). Semantic acceptance
// (kind stream, mode not race, window) is the admission's job.
//
// Check order: fixed part present (ErrShort), mlen > maxMeta (ErrLength),
// mlen against the remaining bytes (ErrShort/ErrTrailing), zero SID
// (ErrReserved), kind and mode (ErrValue), flags and PMTU (ErrReserved).
// maxMeta is clamped to [0, MaxMetadata]. An empty metadata decodes as nil.
func ParseOpen(p []byte, maxMeta int) (Open, error) {
	if len(p) < OpenFixedLen {
		return Open{}, ErrShort
	}
	maxMeta = min(max(maxMeta, 0), MaxMetadata)
	mlen := int(binary.BigEndian.Uint16(p[30:32]))
	if mlen > maxMeta {
		return Open{}, ErrLength
	}
	if err := exactTail(len(p)-OpenFixedLen, mlen); err != nil {
		return Open{}, err
	}
	o := Open{
		Kind:     CarrierKind(p[16]),
		Mode:     p[17],
		Flags:    binary.BigEndian.Uint16(p[18:20]),
		RetainMs: binary.BigEndian.Uint32(p[20:24]),
		Window:   binary.BigEndian.Uint32(p[24:28]),
		PMTU:     binary.BigEndian.Uint16(p[28:30]),
	}
	copy(o.SID[:], p[0:16])
	switch {
	case o.SID == ([16]byte{}):
		return Open{}, ErrReserved
	case o.Kind != KindStream && o.Kind != KindDatagram:
		return Open{}, ErrValue
	case o.Mode < 1 || o.Mode > 3:
		return Open{}, ErrValue
	case o.Flags != 0:
		return Open{}, ErrReserved
	case o.Kind == KindStream && o.PMTU != 0:
		return Open{}, ErrReserved
	}
	if mlen > 0 {
		o.Metadata = p[OpenFixedLen:len(p):len(p)]
	}
	return o, nil
}

// OpenAck is the OPEN_ACK payload: status u8 | window u32 | code u32 | mlen u8 | msg.
// Canonical form (design §5.3): Status OK carries Code 0 and no Msg; every
// other status carries Window 0.
type OpenAck struct {
	Status AckStatus
	Window uint32 // passive's initial receive window (may be 0 under memory pressure); 0 unless Status is OK
	Code   uint32 // REJECTED: application code; other non-OK statuses: Code* reason; 0 for OK
	Msg    []byte // ≤ MaxMsg bytes; empty for OK
}

// PutOpenAck writes a into dst and returns OpenAckFixedLen + len(a.Msg)
// (OpenAckFixedLen for OK). It writes the canonical zero fields itself
// whatever a holds (Window 0 unless OK; Code 0 and no Msg for OK), so a
// refusal path cannot emit an answer the peer rejects. It panics if dst is
// too small or len(a.Msg) > MaxMsg.
func PutOpenAck(dst []byte, a *OpenAck) int {
	if len(a.Msg) > MaxMsg {
		panic("rendr/wire: PutOpenAck: message beyond MaxMsg")
	}
	window, code, msg := uint32(0), a.Code, a.Msg
	if a.Status == StatusOK {
		window, code, msg = a.Window, 0, nil
	}
	n := OpenAckFixedLen + len(msg)
	_ = dst[n-1]
	dst[0] = uint8(a.Status)
	binary.BigEndian.PutUint32(dst[1:5], window)
	binary.BigEndian.PutUint32(dst[5:9], code)
	dst[9] = uint8(len(msg))
	copy(dst[OpenAckFixedLen:n], msg)
	return n
}

// ParseOpenAck decodes an OPEN_ACK payload: exact length, known status, and
// the canonical zero fields (ErrReserved otherwise). Check order: fixed part
// (ErrShort), mlen against the remaining bytes (ErrShort/ErrTrailing),
// status (ErrValue), canonical zero fields (ErrReserved). An empty message
// decodes as nil.
func ParseOpenAck(p []byte) (OpenAck, error) {
	if len(p) < OpenAckFixedLen {
		return OpenAck{}, ErrShort
	}
	mlen := int(p[9])
	if err := exactTail(len(p)-OpenAckFixedLen, mlen); err != nil {
		return OpenAck{}, err
	}
	a := OpenAck{
		Status: AckStatus(p[0]),
		Window: binary.BigEndian.Uint32(p[1:5]),
		Code:   binary.BigEndian.Uint32(p[5:9]),
	}
	if a.Status > StatusGoingAway {
		return OpenAck{}, ErrValue
	}
	if a.Status == StatusOK {
		if a.Code != 0 || mlen != 0 {
			return OpenAck{}, ErrReserved
		}
	} else if a.Window != 0 {
		return OpenAck{}, ErrReserved
	}
	if mlen > 0 {
		a.Msg = p[OpenAckFixedLen:len(p):len(p)]
	}
	return a, nil
}

// Join is the JOIN payload: sid[16] | mode u8 | rxNext u64.
type Join struct {
	SID    [16]byte
	Mode   uint8
	RxNext uint64 // the dialer's delivered offset: trims the passive's retransmissions (never a window)
}

// PutJoin writes j into dst and returns JoinLen.
func PutJoin(dst []byte, j *Join) int {
	_ = dst[JoinLen-1]
	copy(dst[0:16], j.SID[:])
	dst[16] = j.Mode
	binary.BigEndian.PutUint64(dst[17:25], j.RxNext)
	return JoinLen
}

// ParseJoin decodes a JOIN payload (exactly JoinLen bytes, non-zero SID,
// mode 1..3). Errors: ErrShort/ErrTrailing, ErrReserved (zero SID), ErrValue
// (mode).
func ParseJoin(p []byte) (Join, error) {
	if err := exactTail(len(p), JoinLen); err != nil {
		return Join{}, err
	}
	j := Join{Mode: p[16], RxNext: binary.BigEndian.Uint64(p[17:25])}
	copy(j.SID[:], p[0:16])
	switch {
	case j.SID == ([16]byte{}):
		return Join{}, ErrReserved
	case j.Mode < 1 || j.Mode > 3:
		return Join{}, ErrValue
	}
	return j, nil
}

// JoinAck is the JOIN_ACK payload: status u8 | rxNext u64.
type JoinAck struct {
	Status AckStatus
	RxNext uint64 // the passive's delivered offset (0 unless Status is OK)
}

// PutJoinAck writes a into dst and returns JoinAckLen. It writes RxNext 0
// itself for every status other than OK.
func PutJoinAck(dst []byte, a *JoinAck) int {
	_ = dst[JoinAckLen-1]
	rx := a.RxNext
	if a.Status != StatusOK {
		rx = 0
	}
	dst[0] = uint8(a.Status)
	binary.BigEndian.PutUint64(dst[1:9], rx)
	return JoinAckLen
}

// ParseJoinAck decodes a JOIN_ACK payload (exactly JoinAckLen bytes, known
// status, RxNext 0 unless OK: ErrReserved otherwise).
func ParseJoinAck(p []byte) (JoinAck, error) {
	if err := exactTail(len(p), JoinAckLen); err != nil {
		return JoinAck{}, err
	}
	a := JoinAck{Status: AckStatus(p[0]), RxNext: binary.BigEndian.Uint64(p[1:9])}
	switch {
	case a.Status > StatusGoingAway:
		return JoinAck{}, ErrValue
	case a.Status != StatusOK && a.RxNext != 0:
		return JoinAck{}, ErrReserved
	}
	return a, nil
}

// PutDataOffset writes the DATA prefix (stream offset) into dst[:DataPrefixLen].
func PutDataOffset(dst []byte, off uint64) {
	_ = dst[7]
	dst[0], dst[1], dst[2], dst[3] = byte(off>>56), byte(off>>48), byte(off>>40), byte(off>>32)
	dst[4], dst[5], dst[6], dst[7] = byte(off>>24), byte(off>>16), byte(off>>8), byte(off)
}

// ParseDataOffset returns the offset of a DATA payload p. p must hold at
// least DataPrefixLen+1 bytes (empty DATA is malformed: ErrLength) and
// offset+len(data) must not overflow uint64 (ErrValue). A reader that does
// not hold the payload contiguously (a big DATA payload read into its own
// buffer) applies the same end rule to the offset and the payload length
// from the header: off ≤ 2^64 − 1 − n for n = Len − DataPrefixLen bytes.
func ParseDataOffset(p []byte) (uint64, error) {
	if len(p) <= DataPrefixLen {
		return 0, ErrLength
	}
	off := binary.BigEndian.Uint64(p[0:8])
	if off > math.MaxUint64-uint64(len(p)-DataPrefixLen) {
		return 0, ErrValue
	}
	return off, nil
}

// Ack is the ACK payload: delivered u64 | window u32 | epochEcho u32.
// FIN_DELIVERED and DONE travel as header flags.
type Ack struct {
	Delivered uint64 // bytes delivered to the ACK sender's application (rRead)
	Window    uint32 // right edge − Delivered; the right edge never retracts
	EpochEcho uint32 // passive: last applied SCHED epoch; dialer: 0
}

// PutAck writes a into dst and returns AckLen.
func PutAck(dst []byte, a *Ack) int {
	_ = dst[AckLen-1]
	binary.BigEndian.PutUint64(dst[0:8], a.Delivered)
	binary.BigEndian.PutUint32(dst[8:12], a.Window)
	binary.BigEndian.PutUint32(dst[12:16], a.EpochEcho)
	return AckLen
}

// ParseAck decodes an ACK payload (exactly AckLen bytes).
func ParseAck(p []byte) (Ack, error) {
	if err := exactTail(len(p), AckLen); err != nil {
		return Ack{}, err
	}
	return Ack{
		Delivered: binary.BigEndian.Uint64(p[0:8]),
		Window:    binary.BigEndian.Uint32(p[8:12]),
		EpochEcho: binary.BigEndian.Uint32(p[12:16]),
	}, nil
}

// PutFin writes the FIN payload (final stream offset) and returns FinLen.
func PutFin(dst []byte, off uint64) int {
	_ = dst[FinLen-1]
	binary.BigEndian.PutUint64(dst[0:8], off)
	return FinLen
}

// ParseFin decodes a FIN payload (exactly FinLen bytes).
func ParseFin(p []byte) (uint64, error) {
	if err := exactTail(len(p), FinLen); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(p[0:8]), nil
}

// Rst is the RST payload: code u32 | mlen u8 | msg.
type Rst struct {
	Code uint32 // AbortCode
	Msg  []byte // ≤ MaxMsg bytes
}

// PutRst writes r into dst and returns RstFixedLen + len(r.Msg). It panics
// if dst is too small or len(r.Msg) > MaxMsg.
func PutRst(dst []byte, r *Rst) int {
	if len(r.Msg) > MaxMsg {
		panic("rendr/wire: PutRst: message beyond MaxMsg")
	}
	n := RstFixedLen + len(r.Msg)
	_ = dst[n-1]
	binary.BigEndian.PutUint32(dst[0:4], r.Code)
	dst[4] = uint8(len(r.Msg))
	copy(dst[RstFixedLen:n], r.Msg)
	return n
}

// ParseRst decodes an RST payload (exact length). Every code is accepted:
// codes below 256 belong to rendr, and an unknown one from a later minor
// must still end the session. An empty message decodes as nil.
func ParseRst(p []byte) (Rst, error) {
	if len(p) < RstFixedLen {
		return Rst{}, ErrShort
	}
	mlen := int(p[4])
	if err := exactTail(len(p)-RstFixedLen, mlen); err != nil {
		return Rst{}, err
	}
	r := Rst{Code: binary.BigEndian.Uint32(p[0:4])}
	if mlen > 0 {
		r.Msg = p[RstFixedLen:len(p):len(p)]
	}
	return r, nil
}

// Sched is the SCHED payload: epoch u32 | n u8 | carrierID[n] u32. The
// SchedCause travels in the header flags.
type Sched struct {
	Epoch uint32
	N     int                 // 1..MaxSchedIDs
	IDs   [MaxSchedIDs]uint32 // IDs[:N] non-zero and distinct
}

// PutSched writes s into dst and returns SchedFixedLen + 4·s.N. It panics if
// s.N is outside 1..MaxSchedIDs or dst is too small; the IDs are written as
// given (the dialer publishes only live, distinct carrier IDs).
func PutSched(dst []byte, s *Sched) int {
	if s.N < 1 || s.N > MaxSchedIDs {
		panic("rendr/wire: PutSched: carrier count outside 1..MaxSchedIDs")
	}
	n := SchedFixedLen + 4*s.N
	_ = dst[n-1]
	binary.BigEndian.PutUint32(dst[0:4], s.Epoch)
	dst[4] = uint8(s.N)
	for i, id := range s.IDs[:s.N] {
		binary.BigEndian.PutUint32(dst[SchedFixedLen+4*i:], id)
	}
	return n
}

// ParseSched decodes a SCHED payload: exact length 5 + 4n, 1 ≤ n ≤
// MaxSchedIDs, IDs non-zero and distinct (ErrValue). Check order: fixed part
// (ErrShort), n (ErrValue), exact length (ErrShort/ErrTrailing), IDs
// (ErrValue). IDs beyond N are zero.
func ParseSched(p []byte) (Sched, error) {
	if len(p) < SchedFixedLen {
		return Sched{}, ErrShort
	}
	n := int(p[4])
	if n < 1 || n > MaxSchedIDs {
		return Sched{}, ErrValue
	}
	if err := exactTail(len(p)-SchedFixedLen, 4*n); err != nil {
		return Sched{}, err
	}
	s := Sched{Epoch: binary.BigEndian.Uint32(p[0:4]), N: n}
	for i := range n {
		id := binary.BigEndian.Uint32(p[SchedFixedLen+4*i:])
		if id == 0 {
			return Sched{}, ErrValue
		}
		for _, prev := range s.IDs[:i] {
			if prev == id {
				return Sched{}, ErrValue
			}
		}
		s.IDs[i] = id
	}
	return s, nil
}

// Ping is the PING and PONG payload: id u32 | ts u64 | nonce u64 | pad. A
// PONG echoes the PING payload field for field with the same pad length.
type Ping struct {
	ID    uint32 // per carrier, serial arithmetic
	TS    uint64 // sender's monotonic nanoseconds at encode; diagnostic only
	Nonce uint64 // per-carrier random salt XOR ID: binds a PONG to the incarnation (L23)
	Pad   int    // number of zero pad bytes, 0..MaxPingPad (M1 senders send 0)
}

// PutPing writes p (and p.Pad zero bytes) into dst and returns
// PingFixedLen + p.Pad. It panics if p.Pad is outside 0..MaxPingPad or dst
// is too small.
func PutPing(dst []byte, p *Ping) int {
	if p.Pad < 0 || p.Pad > MaxPingPad {
		panic("rendr/wire: PutPing: pad outside 0..MaxPingPad")
	}
	n := PingFixedLen + p.Pad
	_ = dst[n-1]
	binary.BigEndian.PutUint32(dst[0:4], p.ID)
	binary.BigEndian.PutUint64(dst[4:12], p.TS)
	binary.BigEndian.PutUint64(dst[12:20], p.Nonce)
	clear(dst[PingFixedLen:n])
	return n
}

// ParsePing decodes a PING or PONG payload: ≥ PingFixedLen bytes, pad ≤
// MaxPingPad (ErrLength), every pad byte zero (ErrReserved). A reader that
// streams a pad larger than its buffer applies the same zero rule to every
// chunk of it; the pad length comes from the header (Len − PingFixedLen).
func ParsePing(p []byte) (Ping, error) {
	if len(p) < PingFixedLen {
		return Ping{}, ErrShort
	}
	pad := len(p) - PingFixedLen
	if pad > MaxPingPad {
		return Ping{}, ErrLength
	}
	if !allZero(p[PingFixedLen:]) {
		return Ping{}, ErrReserved
	}
	return Ping{
		ID:    binary.BigEndian.Uint32(p[0:4]),
		TS:    binary.BigEndian.Uint64(p[4:12]),
		Nonce: binary.BigEndian.Uint64(p[12:20]),
		Pad:   pad,
	}, nil
}

// PutReason writes a one-byte CLOSE or GOAWAY reason and returns ReasonLen.
func PutReason(dst []byte, r uint8) int {
	dst[0] = r
	return ReasonLen
}

// ParseClose decodes a CLOSE payload (exactly 1 byte, a known CloseReason).
func ParseClose(p []byte) (CloseReason, error) {
	if err := exactTail(len(p), ReasonLen); err != nil {
		return 0, err
	}
	switch r := CloseReason(p[0]); r {
	case CloseRetire, CloseCapacity:
		return r, nil
	}
	return 0, ErrValue
}

// ParseGoAway decodes a GOAWAY payload (exactly 1 byte, a known GoAwayReason).
func ParseGoAway(p []byte) (GoAwayReason, error) {
	if err := exactTail(len(p), ReasonLen); err != nil {
		return 0, err
	}
	if r := GoAwayReason(p[0]); r == GoAwayShutdown {
		return r, nil
	}
	return 0, ErrValue
}

// exactTail compares the bytes present with the bytes a length field or a
// fixed size requires: fewer is ErrShort, more is ErrTrailing.
func exactTail(have, want int) error {
	switch {
	case have < want:
		return ErrShort
	case have > want:
		return ErrTrailing
	}
	return nil
}

// allZero reports whether every byte of b is zero (PING pad).
func allZero(b []byte) bool {
	for len(b) >= 8 {
		if binary.LittleEndian.Uint64(b) != 0 {
			return false
		}
		b = b[8:]
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
