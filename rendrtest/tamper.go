package rendrtest

import "net"

// FrameDetach is the M3 carrier-level frame that ends one handle of a
// shared (mux) carrier.
const FrameDetach FrameType = 0x36

// Tamper is a frame-aware man-in-the-middle between a client-side and a
// server-side net.Conn (the integrity backstop's adversary, M3 design
// §A9.2). Two pumps forward the bytes in both directions, parsing the
// PREFACE and then every frame header as they go, byte-identically unless
// an operation is armed. Each operation acts once, at a frame index of one
// direction (0 is the first frame after the PREFACE) or at a byte offset,
// and has its own counter (Stats), the proof that the stimulus fired.
// Log is the per-direction frame tap.
//
// It works over a Link inside a synctest bubble and over real sockets.
// Close joins its goroutines and closes both conns.
type Tamper struct {
	client, server net.Conn
}

// FrameRec is one forwarded frame as the frame tap saw it.
type FrameRec struct {
	Type   FrameType
	Handle uint32
	Flags  uint8
	Len    int // payload length
}

// TamperStats counts the operations that fired, one counter per operation.
type TamperStats struct {
	Flipped, Dropped, Duplicated, Replayed int
	Spliced, Switched, Rewritten           int
	Held                                   int // Hold calls that stopped a direction
}

// NewTamper starts forwarding between client (the dialer's side: Up is
// what it writes) and server (the passive's side: Down is what it writes).
func NewTamper(client, server net.Conn) *Tamper {
	panic("unimplemented: M3")
}

// FlipBit flips bit bit (0 = the first bit of the frame's header) of frame
// frameN of direction d.
func (t *Tamper) FlipBit(d Dir, frameN, bit int) { panic("unimplemented: M3") }

// DropFrame forwards every frame of direction d except frame frameN.
func (t *Tamper) DropFrame(d Dir, frameN int) { panic("unimplemented: M3") }

// DuplicateFrame forwards frame frameN of direction d twice in a row.
func (t *Tamper) DuplicateFrame(d Dir, frameN int) { panic("unimplemented: M3") }

// ReplayFrame forwards frame frameN of direction d again after the frame
// at index after (an old frame re-sent later).
func (t *Tamper) ReplayFrame(d Dir, frameN, after int) { panic("unimplemented: M3") }

// Splice makes direction d forward, from byte at of its stream on (counted
// from the PREFACE's first byte; a frame boundary or mid-frame), the bytes
// of the same direction of from instead of its own: the bytes of two
// carriers spliced.
func (t *Tamper) Splice(d Dir, from *Tamper, at int64) { panic("unimplemented: M3") }

// SwitchUpstream makes the tamper act as a relay that reconnects its
// upstream mid-stream: it dials a fresh server-side conn and forwards the
// client's remaining bytes into it.
func (t *Tamper) SwitchUpstream(dial func() (net.Conn, error)) { panic("unimplemented: M3") }

// RewriteHandle rewrites the handle of frame frameN of direction d to h,
// recomputing the frame's CRC when recrc is true (a broken peer) and
// leaving it stale otherwise (a damaged path).
func (t *Tamper) RewriteHandle(d Dir, frameN int, h uint32, recrc bool) {
	panic("unimplemented: M3")
}

// Hold stops forwarding direction d at the next frame boundary; Release
// resumes it.
func (t *Tamper) Hold(d Dir) { panic("unimplemented: M3") }

// Release resumes a direction stopped by Hold.
func (t *Tamper) Release(d Dir) { panic("unimplemented: M3") }

// Log returns a copy of the frames forwarded in direction d so far, in
// order (the frame tap).
func (t *Tamper) Log(d Dir) []FrameRec { panic("unimplemented: M3") }

// Stats returns the operation counters.
func (t *Tamper) Stats() TamperStats { panic("unimplemented: M3") }

// Close stops both pumps, closes both conns and joins the goroutines.
func (t *Tamper) Close() error { panic("unimplemented: M3") }
