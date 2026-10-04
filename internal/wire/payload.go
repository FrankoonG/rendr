package wire

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
	panic("unimplemented: M1b")
}

// ParseOpen decodes an OPEN payload. The explicit mlen must equal the
// remaining bytes exactly; mlen > maxMeta returns ErrLength before the
// metadata is touched. Kind must be 1 or 2, mode 1..3 (ErrValue); flags and
// PMTU on a stream session must be 0 (ErrReserved). Semantic acceptance
// (kind stream, mode not race, window) is the admission's job.
func ParseOpen(p []byte, maxMeta int) (Open, error) {
	panic("unimplemented: M1b")
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
	panic("unimplemented: M1b")
}

// ParseOpenAck decodes an OPEN_ACK payload: exact length, known status, and
// the canonical zero fields (ErrReserved otherwise).
func ParseOpenAck(p []byte) (OpenAck, error) {
	panic("unimplemented: M1b")
}

// Join is the JOIN payload: sid[16] | mode u8 | rxNext u64.
type Join struct {
	SID    [16]byte
	Mode   uint8
	RxNext uint64 // the dialer's delivered offset: trims the passive's retransmissions (never a window)
}

// PutJoin writes j into dst and returns JoinLen.
func PutJoin(dst []byte, j *Join) int {
	panic("unimplemented: M1b")
}

// ParseJoin decodes a JOIN payload (exactly JoinLen bytes, non-zero SID,
// mode 1..3).
func ParseJoin(p []byte) (Join, error) {
	panic("unimplemented: M1b")
}

// JoinAck is the JOIN_ACK payload: status u8 | rxNext u64.
type JoinAck struct {
	Status AckStatus
	RxNext uint64 // the passive's delivered offset (0 unless Status is OK)
}

// PutJoinAck writes a into dst and returns JoinAckLen. It writes RxNext 0
// itself for every status other than OK.
func PutJoinAck(dst []byte, a *JoinAck) int {
	panic("unimplemented: M1b")
}

// ParseJoinAck decodes a JOIN_ACK payload (exactly JoinAckLen bytes, known
// status, RxNext 0 unless OK: ErrReserved otherwise).
func ParseJoinAck(p []byte) (JoinAck, error) {
	panic("unimplemented: M1b")
}

// PutDataOffset writes the DATA prefix (stream offset) into dst[:DataPrefixLen].
func PutDataOffset(dst []byte, off uint64) {
	_ = dst[7]
	dst[0], dst[1], dst[2], dst[3] = byte(off>>56), byte(off>>48), byte(off>>40), byte(off>>32)
	dst[4], dst[5], dst[6], dst[7] = byte(off>>24), byte(off>>16), byte(off>>8), byte(off)
}

// ParseDataOffset returns the offset of a DATA payload p. p must hold at
// least DataPrefixLen+1 bytes (empty DATA is malformed: ErrLength) and
// offset+len(data) must not overflow uint64 (ErrValue).
func ParseDataOffset(p []byte) (uint64, error) {
	panic("unimplemented: M1b")
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
	panic("unimplemented: M1b")
}

// ParseAck decodes an ACK payload (exactly AckLen bytes).
func ParseAck(p []byte) (Ack, error) {
	panic("unimplemented: M1b")
}

// PutFin writes the FIN payload (final stream offset) and returns FinLen.
func PutFin(dst []byte, off uint64) int {
	panic("unimplemented: M1b")
}

// ParseFin decodes a FIN payload (exactly FinLen bytes).
func ParseFin(p []byte) (uint64, error) {
	panic("unimplemented: M1b")
}

// Rst is the RST payload: code u32 | mlen u8 | msg.
type Rst struct {
	Code uint32 // AbortCode
	Msg  []byte // ≤ MaxMsg bytes
}

// PutRst writes r into dst and returns RstFixedLen + len(r.Msg).
func PutRst(dst []byte, r *Rst) int {
	panic("unimplemented: M1b")
}

// ParseRst decodes an RST payload (exact length).
func ParseRst(p []byte) (Rst, error) {
	panic("unimplemented: M1b")
}

// Sched is the SCHED payload: epoch u32 | n u8 | carrierID[n] u32. The
// SchedCause travels in the header flags.
type Sched struct {
	Epoch uint32
	N     int                 // 1..MaxSchedIDs
	IDs   [MaxSchedIDs]uint32 // IDs[:N] non-zero and distinct
}

// PutSched writes s into dst and returns SchedFixedLen + 4·s.N.
func PutSched(dst []byte, s *Sched) int {
	panic("unimplemented: M1b")
}

// ParseSched decodes a SCHED payload: exact length 5 + 4n, 1 ≤ n ≤
// MaxSchedIDs, IDs non-zero and distinct (ErrValue).
func ParseSched(p []byte) (Sched, error) {
	panic("unimplemented: M1b")
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
// PingFixedLen + p.Pad.
func PutPing(dst []byte, p *Ping) int {
	panic("unimplemented: M1b")
}

// ParsePing decodes a PING or PONG payload: ≥ PingFixedLen bytes, pad ≤
// MaxPingPad, every pad byte zero (ErrReserved).
func ParsePing(p []byte) (Ping, error) {
	panic("unimplemented: M1b")
}

// PutReason writes a one-byte CLOSE or GOAWAY reason and returns ReasonLen.
func PutReason(dst []byte, r uint8) int {
	dst[0] = r
	return ReasonLen
}

// ParseClose decodes a CLOSE payload (exactly 1 byte, a known CloseReason).
func ParseClose(p []byte) (CloseReason, error) {
	panic("unimplemented: M1b")
}

// ParseGoAway decodes a GOAWAY payload (exactly 1 byte, a known GoAwayReason).
func ParseGoAway(p []byte) (GoAwayReason, error) {
	panic("unimplemented: M1b")
}
