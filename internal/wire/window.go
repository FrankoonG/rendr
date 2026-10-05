package wire

// The two receive windows of M2 (M2-D13, M2-D36). Both are circular bitmaps
// with O(1) amortized updates: advancing clears only the bits it passes, a
// jump of at least the width clears the whole map, nothing shifts, and a
// permanently missing number pins nothing (the window follows the newest
// number, L39). Neither allocates after initialization.

// WindowVerdict classifies one number offered to a window.
type WindowVerdict uint8

// Window verdicts.
const (
	// WindowNew: the number was not seen and is inside the window (or newer
	// than everything seen); it is now marked.
	WindowNew WindowVerdict = iota
	// WindowDuplicate: the number was already marked.
	WindowDuplicate
	// WindowLate: the number is older than the window can tell (at least
	// the width behind the newest).
	WindowLate
)

// FseqWindow is the anti-replay window of one datagram-carrier direction
// (plan:333): FseqWindowBits frames in u32 serial arithmetic (L14).
// Duplicates and late frames are dropped and counted by the caller, never
// violations; there is no forward-jump bound (a sender jumps by every frame
// lost in an outage).
type FseqWindow struct {
	top  uint32                      // the newest fseq accepted
	bits [FseqWindowBits / 64]uint64 // bit (f mod FseqWindowBits) marks fseq f within the window
}

// Init starts the window at first, the fseq of the direction's first frame:
// everything before it counts as seen.
func (w *FseqWindow) Init(first uint32) {
	panic("unimplemented: M2")
}

// Accept marks f and returns WindowNew, or reports it as a duplicate or as
// late. The caller applies it only after the frame's CRC verified.
func (w *FseqWindow) Accept(f uint32) WindowVerdict {
	panic("unimplemented: M2")
}

// SeqWindow is a packet session's receive dedup window over u64 seqs (L39):
// len(storage)·64 bits, a power of two ≥ 1024 (DefaultSeqWindowBits by
// default). The caller provides the storage once, so Accept never
// allocates.
type SeqWindow struct {
	top     uint64   // the newest seq accepted (valid when started)
	started bool     // a seq was accepted
	bits    []uint64 // storage provided by Init
}

// Init sets the storage (cleared); its length must be a power of two ≥ 16.
func (w *SeqWindow) Init(storage []uint64) {
	panic("unimplemented: M2")
}

// Accept marks seq and returns WindowNew, or reports a duplicate, or a seq
// older than the window (WindowLate: counted as DropLate).
func (w *SeqWindow) Accept(seq uint64) WindowVerdict {
	panic("unimplemented: M2")
}
