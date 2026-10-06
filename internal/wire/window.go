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
// lost in an outage). A frame reordered inside the window is accepted once
// (the window is not strict +1, M2-D13).
type FseqWindow struct {
	top  uint32                      // the newest fseq accepted
	bits [FseqWindowBits / 64]uint64 // bit (f mod FseqWindowBits) marks fseq f within the window
}

// Init starts the window at first, the fseq of the direction's first frame:
// everything before it counts as seen — the FseqWindowBits fseqs up to
// first − 1 are duplicates, older ones late — so nothing from before the
// direction's start is accepted.
func (w *FseqWindow) Init(first uint32) {
	w.top = first - 1
	for i := range w.bits {
		w.bits[i] = ^uint64(0)
	}
}

// Accept marks f and returns WindowNew, or reports it as a duplicate or as
// late. The caller applies it only after the frame's CRC verified. An f
// newer than the newest accepted (f − newest in 1 … 2^31 − 1, serial
// arithmetic) moves the window forward — clearing the bits it passes, all
// of them after a jump of FseqWindowBits or more — and is new; any other f
// is late when it is FseqWindowBits or more behind the newest, a duplicate
// when marked, else new (a reordered frame inside the window).
func (w *FseqWindow) Accept(f uint32) WindowVerdict {
	d := f - w.top
	if int32(d) > 0 {
		if d >= FseqWindowBits {
			w.bits = [FseqWindowBits / 64]uint64{}
		} else {
			clearRing(w.bits[:], uint64(w.top)+1, uint64(d))
		}
		w.top = f
		setRing(w.bits[:], uint64(f))
		return WindowNew
	}
	if w.top-f >= FseqWindowBits {
		return WindowLate
	}
	return markRing(w.bits[:], uint64(f))
}

// minSeqWindowWords is the smallest SeqWindow storage: 1024 bits.
const minSeqWindowWords = 16

// SeqWindow is a packet session's receive dedup window over u64 seqs (L39):
// len(storage)·64 bits, a power of two ≥ 1024 (DefaultSeqWindowBits by
// default). The caller provides the storage once, so Accept never
// allocates.
type SeqWindow struct {
	top     uint64   // the newest seq accepted (valid when started)
	started bool     // a seq was accepted
	bits    []uint64 // storage provided by Init
}

// Init sets the storage (cleared); its length must be a power of two ≥ 16
// (it panics otherwise: a programming error).
func (w *SeqWindow) Init(storage []uint64) {
	if n := len(storage); n < minSeqWindowWords || n&(n-1) != 0 {
		panic("rendr/wire: SeqWindow.Init: storage length is not a power of two ≥ 16")
	}
	clear(storage)
	*w = SeqWindow{bits: storage}
}

// Accept marks seq and returns WindowNew, or reports a duplicate, or a seq
// older than the window (WindowLate: counted as DropLate). The first
// accepted seq sets the newest; a seq after the newest moves the window
// forward as FseqWindow's does (seqs do not wrap: the session ends before
// 2^62, L14); a seq at least the width behind the newest is late, a marked
// one a duplicate, any other new — also one older than the first accepted,
// so a reordered start loses nothing.
func (w *SeqWindow) Accept(seq uint64) WindowVerdict {
	width := uint64(len(w.bits)) * 64
	switch {
	case !w.started:
		w.started = true
	case seq > w.top:
		if d := seq - w.top; d >= width {
			clear(w.bits)
		} else {
			clearRing(w.bits, w.top+1, d)
		}
	case w.top-seq >= width:
		return WindowLate
	default:
		return markRing(w.bits, seq)
	}
	w.top = seq
	setRing(w.bits, seq)
	return WindowNew
}

// clearRing clears n consecutive bits of the circular bitmap bits (len(bits)
// a power of two) from bit index from on, wrapping at len(bits)·64; 0 < n <
// len(bits)·64. It touches at most n/64 + 2 words.
func clearRing(bits []uint64, from, n uint64) {
	mask := uint64(len(bits) - 1)
	for n > 0 {
		off := from % 64
		k := min(64-off, n)
		bits[(from/64)&mask] &^= (^uint64(0) >> (64 - k)) << off
		from += k
		n -= k
	}
}

// setRing sets bit i (mod len(bits)·64) of the circular bitmap bits.
func setRing(bits []uint64, i uint64) {
	bits[(i/64)&uint64(len(bits)-1)] |= 1 << (i % 64)
}

// markRing sets bit i (mod len(bits)·64) and reports WindowNew, or
// WindowDuplicate if it was already set.
func markRing(bits []uint64, i uint64) WindowVerdict {
	word := &bits[(i/64)&uint64(len(bits)-1)]
	m := uint64(1) << (i % 64)
	if *word&m != 0 {
		return WindowDuplicate
	}
	*word |= m
	return WindowNew
}
