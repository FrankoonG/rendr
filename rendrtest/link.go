package rendrtest

import (
	"context"
	"net"
	"time"
)

// Dir is a link direction.
type Dir uint8

// Directions.
const (
	Up   Dir = 1 // dialer → passive
	Down Dir = 2 // passive → dialer
)

// FrameType names a rendr frame type for frame-targeted controls.
type FrameType uint8

// Frame types (values equal the wire format's type bytes).
const (
	FrameOpen    FrameType = 0x01
	FrameOpenAck FrameType = 0x02
	FrameJoin    FrameType = 0x03
	FrameJoinAck FrameType = 0x04
	FrameData    FrameType = 0x10
	FrameAck     FrameType = 0x11
	FrameFin     FrameType = 0x12
	FrameRst     FrameType = 0x13
	FrameSched   FrameType = 0x14
	FramePing    FrameType = 0x30
	FramePong    FrameType = 0x31
	FrameClose   FrameType = 0x32
	FrameGoAway  FrameType = 0x33
)

// CorruptMode selects how CorruptNextFrame damages a frame.
type CorruptMode uint8

// Corruption modes.
const (
	CorruptHeader  CorruptMode = 1 // flip a bit of the header's fseq: the receiver sees an fseq violation
	CorruptPayload CorruptMode = 2 // flip a payload bit: the receiver sees a CRC violation
	CorruptTrailer CorruptMode = 3 // flip a CRC bit
	// ForgeAckBeyondSent rewrites an ACK's delivered offset far beyond
	// anything sent, keeping fseq and recomputing the CRC: the receiver must
	// kill exactly this carrier for "ACK beyond sent" (L13).
	ForgeAckBeyondSent CorruptMode = 4
)

// DialBehavior makes the link's factory misbehave (L51).
type DialBehavior uint8

// Dial behaviours.
const (
	DialNormal      DialBehavior = 0
	DialError       DialBehavior = 1 // return an error at once
	DialHang        DialBehavior = 2 // block until ctx ends
	DialHangForever DialBehavior = 3 // ignore ctx; return an error only after Release or Close
	DialNilNil      DialBehavior = 4 // return (nil, nil)
	DialPanic       DialBehavior = 5 // panic
	DialGoexit      DialBehavior = 6 // runtime.Goexit
	DialLateSuccess DialBehavior = 7 // ignore ctx; succeed after Release (the late conn must be closed once)
)

// BlockMode controls writes on one side of a link's carriers.
type BlockMode uint8

// Block modes.
const (
	BlockOff  BlockMode = 0 // writes proceed
	BlockSoft BlockMode = 1 // writes block but honour deadlines and Close
	BlockHard BlockMode = 2 // writes block and ignore deadlines and Close until Release (an abandoned call)
)

// WriteResult scripts the result of one conn Write (L42).
type WriteResult struct {
	N         int   // bytes reported written (relative to len(p) when Relative)
	Relative  bool  // N is added to len(p) (e.g. −3 for "len−3", +1 for "len+1")
	Err       error // error returned with N
	Transmit  bool  // the reported bytes are actually forwarded (otherwise nothing is)
	ZeroWrite bool  // report (0, nil) regardless of N
}

// LinkConfig configures a Link.
type LinkConfig struct {
	// Name is the link's name (the factory name in the fixture).
	Name string
	// Accept receives the passive end of every new carrier, typically
	// (*rendr.Listener).Handle.
	Accept func(net.Conn) error
	// Buffer is how many bytes per direction a Write may hand to the link
	// before it blocks (default 2 MiB). Bytes accepted but not yet delivered
	// are lost when the carrier is killed: the buffer-loss model of L10/L61.
	Buffer int
}

// Link is an in-memory path: every Dial creates one carrier whose two
// directions pass through pumps that apply delay/jitter (order preserving),
// a token-bucket rate, blackhole, stall, frame-aware corruption, drops and
// injection. Controls apply to current and future carriers.
type Link struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewLink returns a link; nothing runs until the first Dial.
func NewLink(cfg LinkConfig) *Link {
	panic("unimplemented: M1b")
}

// Name returns the link name.
func (l *Link) Name() string {
	panic("unimplemented: M1b")
}

// Dial is a rendr StreamCarrier.Dial: it creates one carrier through the
// link (honouring SetRefuse, SetBlackhole and SetDial) and passes the far
// end to Accept on a link-owned goroutine.
func (l *Link) Dial(ctx context.Context) (net.Conn, error) {
	panic("unimplemented: M1b")
}

// DialEarly is a rendr StreamCarrier.DialEarly: first travels ahead of the
// stream (the far end reads it first) and is classified like any first bytes.
func (l *Link) DialEarly(ctx context.Context, first []byte) (net.Conn, error) {
	panic("unimplemented: M1b")
}

// SetDelay sets the one-way delay and uniform jitter of both directions.
func (l *Link) SetDelay(oneWay, jitter time.Duration) {
	panic("unimplemented: M1b")
}

// SetRate caps each direction at bytesPerSec (0 = unlimited).
func (l *Link) SetRate(bytesPerSec float64) {
	panic("unimplemented: M1b")
}

// SetBlackhole makes bytes vanish without closing anything; new dials
// "open" but never answer (counted as Dropped).
func (l *Link) SetBlackhole(on bool) {
	panic("unimplemented: M1b")
}

// SetStall holds bytes (not lost) until un-stalled (counted as Held).
func (l *Link) SetStall(on bool) {
	panic("unimplemented: M1b")
}

// SetRefuse makes new dials fail.
func (l *Link) SetRefuse(on bool) {
	panic("unimplemented: M1b")
}

// SetDial sets the factory behaviour for new dials.
func (l *Link) SetDial(b DialBehavior) {
	panic("unimplemented: M1b")
}

// Kill closes both ends of every current carrier and returns how many it
// killed (counted as Killed). Bytes buffered in the link are lost.
func (l *Link) Kill() int {
	panic("unimplemented: M1b")
}

// CorruptNext flips one byte in the next chunk forwarded in direction d of
// every current carrier (M1a behaviour).
func (l *Link) CorruptNext(d Dir) {
	panic("unimplemented: M1b")
}

// CorruptNextFrame damages the next frame of type t forwarded in direction
// d on every current carrier (frame-wide CRC and ACK-beyond-sent tests).
func (l *Link) CorruptNextFrame(d Dir, t FrameType, m CorruptMode) {
	panic("unimplemented: M1b")
}

// DropNextFrame removes the next frame of type t in direction d on every
// current carrier: the receiver sees an fseq gap (L43).
func (l *Link) DropNextFrame(d Dir, t FrameType) {
	panic("unimplemented: M1b")
}

// InjectAfterNextFrame inserts one frame of type t with the given flags,
// handle and payload after the next frame of type after in direction d, with
// the correct fseq and CRC; later frames of that direction are re-stamped so
// that only the injected frame's semantics can trigger a reaction (stale
// PONG, conflicting FIN, ACK beyond sent, ...).
func (l *Link) InjectAfterNextFrame(d Dir, after, t FrameType, flags uint8, handle uint32, payload []byte) {
	panic("unimplemented: M1b")
}

// CaptureNextFrame copies the raw bytes (header through trailer) of the next
// frame of type t forwarded in direction d on any current carrier into the
// returned channel (buffered, one frame) and forwards the frame unchanged.
// Tests use it to learn values they cannot compute, such as an old
// incarnation's PING nonce for a stale-PONG injection (L21), or to obtain
// another session's frame for a splice (L43).
func (l *Link) CaptureNextFrame(d Dir, t FrameType) <-chan []byte {
	panic("unimplemented: M1b")
}

// InjectRaw inserts raw at the next frame boundary in direction d on every
// current carrier, byte for byte: neither fseq nor CRC is re-stamped, so
// spliced bytes of another carrier or session hit the receiver's fseq and
// CRC checks exactly as a misbehaving relay's would (L43). Counted as
// FramesInjected.
func (l *Link) InjectRaw(d Dir, raw []byte) {
	panic("unimplemented: M1b")
}

// ScriptWrites makes the next Writes of side d's conn (Up: the dialer's
// conn, Down: the passive's) return the scripted results (L42).
func (l *Link) ScriptWrites(d Dir, r ...WriteResult) {
	panic("unimplemented: M1b")
}

// BlockWrites blocks Writes of side d's conns per m.
func (l *Link) BlockWrites(d Dir, m BlockMode) {
	panic("unimplemented: M1b")
}

// PanicWrites makes the next Write of side d's conns panic (L51).
func (l *Link) PanicWrites(d Dir) {
	panic("unimplemented: M1b")
}

// OverRead makes the next Read of side d's conns report len(p)+1 (L42).
func (l *Link) OverRead(d Dir) {
	panic("unimplemented: M1b")
}

// Release unblocks every Hard-blocked write and hanging dial, so that a
// synctest bubble can end without leaked goroutines.
func (l *Link) Release() {
	panic("unimplemented: M1b")
}

// Stats returns the link counters.
func (l *Link) Stats() Stats {
	panic("unimplemented: M1b")
}

// Carriers lists every carrier the link created, in creation order.
func (l *Link) Carriers() []CarrierInfo {
	panic("unimplemented: M1b")
}

// NextSeq is the Seq the next carrier of the link will get.
func (l *Link) NextSeq() int {
	panic("unimplemented: M1b")
}

// Close refuses new carriers, closes every current one and joins every
// goroutine the link started. Idempotent.
func (l *Link) Close() {
	panic("unimplemented: M1b")
}

// Counts are fault and traffic counters of a set of carriers.
type Counts struct {
	Killed          int64         // carriers closed by Kill
	Bytes           int64         // bytes forwarded (both directions)
	Dropped         int64         // bytes discarded by the blackhole
	Held            int64         // chunks held back by a stall
	Corrupted       int64         // chunks corrupted by CorruptNext
	FramesCorrupted int64         // frames damaged by CorruptNextFrame
	FramesDropped   int64         // frames removed by DropNextFrame
	FramesInjected  int64         // frames inserted by InjectAfterNextFrame or InjectRaw
	BufferLost      int64         // bytes accepted by a Write and lost when the carrier was killed
	MaxDelay        time.Duration // largest delay applied
}

// Stats are a link's counters: over all carriers, session carriers only,
// and probe carriers only.
type Stats struct {
	All, Session, Probe Counts
	Throttled           int64 // bytes that passed the rate limiter
	Dials               int64 // factory calls
	DialFailures        int64 // factory calls that failed (refused, scripted, ...)
}

// CarrierInfo is a snapshot of one carrier for per-carrier assertions.
type CarrierInfo struct {
	Seq      int       // creation order on its link
	First    FrameType // first frame type after the PREFACE (0 until it crossed)
	Session  bool      // First is OPEN or JOIN
	Up, Down int64     // bytes delivered in each direction
	Held     int64     // chunks held by a stall
	Closed   bool
}
