package rendrtest

import (
	"encoding/binary"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// FrameDetach is the M3 carrier-level frame that ends one handle of a
// shared (mux) carrier.
const FrameDetach FrameType = 0x36

const (
	tamperLogMax  = 1 << 20  // frames each direction's Log keeps
	tamperReadBuf = 64 << 10 // largest chunk a pump reads at once
)

// tamperTeeMax is the bytes a splice may hold queued before it drops (and
// counts) frames; a variable so that its test needs no 16 MiB stream.
var tamperTeeMax = 16 << 20

// Tamper is a frame-aware man-in-the-middle between a client-side and a
// server-side net.Conn (the integrity backstop's adversary, M3 design
// §A9.2). Two pumps forward the bytes in both directions, parsing the
// PREFACE and then every frame header as they go, byte-identically unless
// an operation is armed. Each operation acts once, at a frame index of one
// direction (0 is the first frame after the PREFACE) or at a byte offset,
// and has its own counter (Stats), the proof that the stimulus fired.
// Log is the per-direction frame tap.
//
// Frame indices count the frames the direction's sender wrote, whatever
// the tamper did to earlier ones (a dropped frame keeps its index, a
// duplicate or a replay repeats it). An operation armed for a frame that
// already passed never fires; NextOfType selects the next frame of a type
// instead of a fixed index. A frame is forwarded once it arrived whole;
// a frame header whose length exceeds wire.MaxFramePayload loses the frame
// sync, and the rest of the direction passes through untouched and
// unlogged. A stream that ends inside a frame is forwarded as it was
// written.
//
// The tamper ends as a relay with half-close semantics. A direction whose
// source ends (EOF or a read error) forwards everything it read, then
// half-closes its destination (CloseWrite where the conn has it, else
// Close); a direction whose destination write fails stops alone, so the
// other direction still delivers its tail. Once both directions are done,
// at Close, or when a SwitchUpstream dial fails, the tamper ends and
// closes both conns. A direction with an active Splice is done only when
// its splice writer stops too. It works over a Link inside a synctest
// bubble and over real sockets. Close joins its goroutines.
type Tamper struct {
	mu     sync.Mutex
	cond   sync.Cond // Hold waits; broadcast by Release and at the end
	client net.Conn
	server net.Conn // the current upstream (SwitchUpstream replaces it)
	gen    uint64   // upstream generation
	closed bool
	done   chan struct{} // closed at the end
	dirs   [2]tdir       // [Up.index()] client → server, [Down.index()] server → client
	stats  TamperStats
	wg     sync.WaitGroup
}

// tdir is the armed state and the frame tap of one direction (t.mu).
type tdir struct {
	ops     []tamperOp
	replays []tamperReplay
	hold    bool
	stopped bool  // the direction waits in a Hold
	writing bool  // its pump is inside a conn Write
	off     int64 // bytes forwarded
	log     []FrameRec
	splice  *tsplice // armed or active Splice of this direction
	own     *tsink   // the active Splice's queue
	sinks   []*tsink // other tampers' splices fed by this direction's frames
	live    int      // the pump and an active splice writer, while they serve the direction
	eof     bool     // the pump's source ended and all it read went out
	ended   bool     // live reached 0
}

type opKind uint8

const (
	opFlip opKind = iota + 1
	opDrop
	opDup
	opReplay
	opRewrite
)

// tamperOp is one armed frame operation.
type tamperOp struct {
	kind  opKind
	frame int       // the frame index, unless typed
	typ   FrameType // typed: the next frame of this type
	typed bool
	bit   int    // opFlip
	after int    // opReplay: the frame index (typed: the count of frames) after which the copy is re-sent
	h     uint32 // opRewrite
	recrc bool   // opRewrite
}

// tamperReplay is a frame copy waiting for its re-send.
type tamperReplay struct {
	after int // re-sent after the frame with this index
	b     []byte
	rec   FrameRec
}

// tsplice is a Splice of one direction.
type tsplice struct {
	from   *Tamper
	at     int64
	active bool
}

// tsink queues the frames another tamper tees into an active splice.
type tsink struct {
	mu      sync.Mutex
	q       []tsinkItem
	bytes   int
	closed  bool
	wake    chan struct{} // cap 1
	dropped atomic.Int64  // frames dropped beyond tamperTeeMax
}

type tsinkItem struct {
	b   []byte
	rec FrameRec
}

// tparse is a pump's framing state.
type tparse struct {
	pre    int // PREFACE bytes passed
	idx    int // index of the next frame
	opaque bool
	acc    []byte
}

// FrameRec is one forwarded frame as the frame tap saw it: its header
// fields as forwarded (after the tamper's own changes), its index in the
// sender's stream, and the offset of its first byte in the forwarded
// stream. A frame cut by a Splice is logged although only its first bytes
// were forwarded; a frame of another tamper forwarded by a Splice is
// logged with Spliced set and that tamper's index.
type FrameRec struct {
	Len     int // payload length
	Index   int
	Off     int64
	Handle  uint32
	Fseq    uint32
	Type    FrameType
	Flags   uint8
	Spliced bool
}

// TamperStats counts the operations that fired, one counter per operation.
type TamperStats struct {
	Flipped, Dropped, Duplicated, Replayed int
	Spliced, Switched, Rewritten           int
	Held                                   int   // Hold calls that stopped a direction
	SplicedBytes                           int64 // bytes forwarded from another tamper by Splice
	// FlipMissed counts FlipBit operations whose bit lay outside their
	// frame: nothing was flipped and Flipped did not count them.
	FlipMissed int
	// SpliceDropped counts the frames an active Splice dropped because more
	// than 16 MiB of them waited for a stopped (held or blocked) direction.
	SpliceDropped int64
}

// NextOfType returns a frame index for the operations that selects the
// next frame of type typ that the direction's sender writes after the
// operation was armed, instead of a fixed frame (a negative value). For
// ReplayFrame with such a selector, after counts the frames that follow
// the selected one (at least 1) instead of naming an index.
func NextOfType(typ FrameType) int { return -1 - int(typ) }

// NewTamper starts forwarding between client (the dialer's side: Up is
// what it writes) and server (the passive's side: Down is what it writes).
func NewTamper(client, server net.Conn) *Tamper {
	t := &Tamper{client: client, server: server, done: make(chan struct{})}
	t.cond.L = &t.mu
	t.dirs[0].live, t.dirs[1].live = 1, 1
	t.wg.Add(2)
	go t.pump(Up)
	go t.pump(Down)
	return t
}

// FlipBit flips bit bit of frame frameN of direction d: bit 0 is the most
// significant bit of the frame's first header byte, bits count on in
// network order through payload and CRC trailer, and a negative bit counts
// from the end (−1 is the CRC's last bit). A bit outside the frame flips
// nothing and counts as FlipMissed instead of Flipped.
func (t *Tamper) FlipBit(d Dir, frameN, bit int) {
	t.arm(d, tamperOp{kind: opFlip, bit: bit}, frameN)
}

// DropFrame forwards every frame of direction d except frame frameN.
func (t *Tamper) DropFrame(d Dir, frameN int) { t.arm(d, tamperOp{kind: opDrop}, frameN) }

// DuplicateFrame forwards frame frameN of direction d twice in a row.
func (t *Tamper) DuplicateFrame(d Dir, frameN int) { t.arm(d, tamperOp{kind: opDup}, frameN) }

// ReplayFrame forwards frame frameN of direction d again after the frame
// at index after (an old frame re-sent later, byte-identical to the
// original). It panics unless after > frameN (for a NextOfType selector:
// after ≥ 1).
func (t *Tamper) ReplayFrame(d Dir, frameN, after int) {
	if frameN >= 0 && after <= frameN || frameN < 0 && after < 1 {
		panic("rendrtest: ReplayFrame: the replay must follow the frame")
	}
	t.arm(d, tamperOp{kind: opReplay, after: after}, frameN)
}

// Splice makes direction d forward, from byte at of its stream on (counted
// from the PREFACE's first byte as forwarded; a frame boundary or
// mid-frame), the frames that direction d of from forwards from then on
// instead of its own: the bytes of two carriers spliced. The tamper's own
// later bytes of d are discarded; from forwards its frames unchanged, and
// the copies start at from's next frame boundary. At or below the bytes
// already forwarded the splice starts at once. A direction splices once:
// later calls are ignored. It panics when from is t.
func (t *Tamper) Splice(d Dir, from *Tamper, at int64) {
	if from == t || from == nil {
		panic("rendrtest: Splice: needs another tamper")
	}
	i := d.index()
	t.mu.Lock()
	dd := &t.dirs[i]
	if t.closed || dd.splice != nil {
		t.mu.Unlock()
		return
	}
	dd.splice = &tsplice{from: from, at: at}
	var s *tsink
	if !dd.writing && at <= dd.off {
		s = t.activateLocked(i)
	}
	t.mu.Unlock()
	t.startSplice(d, from, s)
}

// SwitchUpstream makes the tamper act as a relay that reconnects its
// upstream mid-stream: it dials a fresh server-side conn, closes the old
// one and forwards the client's remaining bytes into the new one (a write
// cut by the switch continues there), while Down forwards what the new
// upstream sends, parsed from a fresh PREFACE on (bytes of a frame the old
// upstream had not finished are dropped; frame indices count on). A failed
// dial ends the tamper like a lost upstream. When Up already ended with
// the dialer's EOF, the new upstream is half-closed at once; a Down that
// already ended stays ended.
func (t *Tamper) SwitchUpstream(dial func() (net.Conn, error)) {
	c, err := dial()
	t.mu.Lock()
	if t.closed || err != nil || c == nil {
		t.mu.Unlock()
		if c != nil {
			c.Close()
		}
		t.shutdown()
		return
	}
	old := t.server
	t.server = c
	t.gen++
	t.stats.Switched++
	up := &t.dirs[Up.index()]
	upEOF := up.ended && up.eof
	t.mu.Unlock()
	old.Close()
	if upEOF {
		halfClose(c)
	}
}

// RewriteHandle rewrites the handle of frame frameN of direction d to h,
// recomputing the frame's CRC when recrc is true (a broken peer) and
// leaving it stale otherwise (a damaged path).
func (t *Tamper) RewriteHandle(d Dir, frameN int, h uint32, recrc bool) {
	t.arm(d, tamperOp{kind: opRewrite, h: h, recrc: recrc}, frameN)
}

// Hold stops forwarding direction d at the next frame boundary; Release
// resumes it.
func (t *Tamper) Hold(d Dir) {
	t.mu.Lock()
	t.dirs[d.index()].hold = true
	t.mu.Unlock()
}

// Release resumes a direction stopped by Hold.
func (t *Tamper) Release(d Dir) {
	t.mu.Lock()
	t.dirs[d.index()].hold = false
	t.cond.Broadcast()
	t.mu.Unlock()
}

// Log returns a copy of the frames forwarded in direction d so far, in
// order (the frame tap). It keeps the first 2^20 frames of a direction
// (40 bytes each: at most 40 MiB) and copies them on every call, so read
// it once after the stimulus rather than polling it.
func (t *Tamper) Log(d Dir) []FrameRec {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.dirs[d.index()].log)
}

// Stats returns the operation counters.
func (t *Tamper) Stats() TamperStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.stats
	for _, dd := range t.dirs {
		if dd.own != nil {
			st.SpliceDropped += dd.own.dropped.Load()
		}
	}
	return st
}

// Close stops both pumps, closes both conns and joins the goroutines.
// Idempotent.
func (t *Tamper) Close() error {
	t.shutdown()
	t.wg.Wait()
	return nil
}

// arm queues op for frame frameN (or a NextOfType selector) of d.
func (t *Tamper) arm(d Dir, op tamperOp, frameN int) {
	if frameN < 0 {
		k := -1 - frameN
		if k > 0xff {
			panic("rendrtest: Tamper: bad frame selector")
		}
		op.typed, op.typ = true, FrameType(k)
	} else {
		op.frame = frameN
	}
	t.mu.Lock()
	dd := &t.dirs[d.index()]
	dd.ops = append(dd.ops, op)
	t.mu.Unlock()
}

// leave records that one server of direction d (its pump, or the writer
// of its active splice) stopped; eof: the pump's source ended and all it
// read went out. When the last one leaves, a source end half-closes d's
// destination; when both directions are done the tamper ends.
func (t *Tamper) leave(d Dir, eof bool) {
	t.mu.Lock()
	dd := &t.dirs[d.index()]
	dd.live--
	dd.eof = dd.eof || eof
	var dst net.Conn
	end := false
	if dd.live == 0 && !t.closed {
		dd.ended = true
		if dd.eof {
			dst = t.client
			if d == Up {
				dst = t.server
			}
		}
		end = t.dirs[0].ended && t.dirs[1].ended
	}
	t.mu.Unlock()
	if dst != nil {
		halfClose(dst)
	}
	if end {
		t.shutdown()
	}
}

// halfClose half-closes c where it has CloseWrite, else closes it (net.Pipe
// and Link conns have no half-close).
func halfClose(c net.Conn) {
	if closeWrite(c) != nil {
		c.Close()
	}
}

// shutdown ends the tamper: both pumps stop at their next step, every
// waiter wakes and both conns are closed. Idempotent.
func (t *Tamper) shutdown() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	close(t.done)
	t.cond.Broadcast()
	c, s := t.client, t.server
	t.mu.Unlock()
	c.Close()
	s.Close()
}

// source returns the conn a direction's pump reads and its generation.
func (t *Tamper) source(d Dir) (net.Conn, uint64) {
	if d == Up {
		return t.client, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.server, t.gen
}

// pump forwards one direction until its source ends, its destination
// fails or the tamper ends.
func (t *Tamper) pump(d Dir) {
	defer t.wg.Done()
	src, gen := t.source(d)
	var p tparse
	buf := make([]byte, tamperReadBuf)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			p.acc = append(p.acc, buf[:n]...)
			if !t.forward(d, &p) {
				t.leave(d, false)
				return
			}
		}
		if err == nil {
			continue
		}
		if d == Down {
			t.mu.Lock()
			moved := !t.closed && t.gen != gen
			if moved {
				src, gen = t.server, t.gen
			}
			t.mu.Unlock()
			if moved { // the old upstream's leftovers are gone with it
				p.pre, p.opaque, p.acc = 0, false, p.acc[:0]
				continue
			}
		}
		t.leave(d, len(p.acc) == 0 || t.emit(d, p.acc, nil, false))
		return
	}
}

// forward forwards every complete unit of p.acc (PREFACE bytes, whole
// frames, opaque bytes) and keeps the rest; false when the tamper ended.
func (t *Tamper) forward(d Dir, p *tparse) bool {
	b := p.acc
	for len(b) > 0 {
		switch {
		case p.opaque:
			if !t.emit(d, b, nil, false) {
				return false
			}
			b = nil
		case p.pre < wire.PrefaceLen:
			k := min(wire.PrefaceLen-p.pre, len(b))
			if !t.emit(d, b[:k], nil, false) {
				return false
			}
			p.pre += k
			b = b[k:]
		default:
			end, frames := frameRun(b)
			if frames == 0 {
				if len(b) >= wire.HeaderLen && frameLen(b) > wire.MaxFramePayload {
					p.opaque = true
					continue
				}
				p.acc = append(p.acc[:0], b...)
				return true
			}
			if !t.frames(d, p, b[:end], frames) {
				return false
			}
			b = b[end:]
		}
	}
	p.acc = p.acc[:0]
	return true
}

// frameLen is the payload length in the header at the front of b.
func frameLen(b []byte) int { return int(b[2])<<16 | int(b[3])<<8 | int(b[4]) }

// frameRun returns the length of the run of complete, in-sync frames at
// the front of b and their number.
func frameRun(b []byte) (end, frames int) {
	for len(b)-end >= wire.HeaderLen {
		n := frameLen(b[end:])
		if n > wire.MaxFramePayload || len(b)-end < wire.FrameOverhead+n {
			break
		}
		end += wire.FrameOverhead + n
		frames++
	}
	return end, frames
}

// recOf is the frame tap's record of frame fb.
func recOf(fb []byte, idx int, off int64) FrameRec {
	return FrameRec{Type: FrameType(fb[0]), Flags: fb[1], Len: frameLen(fb),
		Fseq: binary.BigEndian.Uint32(fb[5:9]), Handle: binary.BigEndian.Uint32(fb[9:13]),
		Index: idx, Off: off}
}

// frames forwards a run of whole frames: in one write when nothing is
// armed for the direction, else frame by frame through the operations.
func (t *Tamper) frames(d Dir, p *tparse, run []byte, n int) bool {
	i := d.index()
	t.mu.Lock()
	dd := &t.dirs[i]
	plain := len(dd.ops) == 0 && len(dd.replays) == 0 && !dd.hold && dd.splice == nil && len(dd.sinks) == 0
	t.mu.Unlock()
	if plain {
		recs := make([]FrameRec, 0, n)
		for off := 0; off < len(run); {
			recs = append(recs, recOf(run[off:], p.idx, int64(off)))
			p.idx++
			off += wire.FrameOverhead + frameLen(run[off:])
		}
		return t.emit(d, run, recs, false)
	}
	for len(run) > 0 {
		size := wire.FrameOverhead + frameLen(run)
		if !t.frame(d, p.idx, run[:size]) {
			return false
		}
		p.idx++
		run = run[size:]
	}
	return true
}

// frame applies the operations armed for frame idx (fb, borrowed) and
// forwards the result, its tee copies and the replays due after it.
func (t *Tamper) frame(d Dir, idx int, fb []byte) bool {
	i := d.index()
	typ := FrameType(fb[0])
	t.mu.Lock()
	dd := &t.dirs[i]
	var ops []tamperOp
	dd.ops = slices.DeleteFunc(dd.ops, func(op tamperOp) bool {
		if op.typed && op.typ == typ || !op.typed && op.frame == idx {
			ops = append(ops, op)
			return true
		}
		return false
	})
	out, copies := fb, 1
	for _, op := range ops {
		switch op.kind {
		case opDrop:
			copies = 0
			t.stats.Dropped++
		case opDup:
			t.stats.Duplicated++
			copies++
		case opReplay:
			after := op.after
			if op.typed {
				after += idx
			}
			dd.replays = append(dd.replays, tamperReplay{after: after, b: slices.Clone(fb), rec: recOf(fb, idx, 0)})
		}
	}
	if copies > 0 {
		for _, op := range ops {
			switch op.kind {
			case opRewrite:
				if &out[0] == &fb[0] {
					out = slices.Clone(fb)
				}
				binary.BigEndian.PutUint32(out[9:13], op.h)
				if op.recrc {
					end := len(out) - wire.TrailerLen
					wire.PutTrailer(out[end:], wire.CRC(out[:end]))
				}
				t.stats.Rewritten++
			case opFlip:
				if &out[0] == &fb[0] {
					out = slices.Clone(fb)
				}
				bits, b := 8*len(out), op.bit
				if b < 0 {
					b += bits
				}
				if b < 0 || b >= bits {
					t.stats.FlipMissed++
					continue
				}
				out[b/8] ^= 0x80 >> (b % 8)
				t.stats.Flipped++
			}
		}
	}
	var due []tamperReplay
	dd.replays = slices.DeleteFunc(dd.replays, func(r tamperReplay) bool {
		if r.after == idx {
			due = append(due, r)
			return true
		}
		return false
	})
	var sinks []*tsink
	dd.sinks = slices.DeleteFunc(dd.sinks, func(s *tsink) bool {
		if s.isClosed() {
			return true
		}
		sinks = append(sinks, s)
		return false
	})
	t.mu.Unlock()
	rec := recOf(out, idx, 0)
	for range copies {
		for _, s := range sinks {
			s.push(out, rec)
		}
		if !t.emit(d, out, []FrameRec{rec}, false) {
			return false
		}
	}
	for _, r := range due {
		for _, s := range sinks {
			s.push(r.b, r.rec)
		}
		if !t.emit(d, r.b, []FrameRec{r.rec}, false) {
			return false
		}
		t.mu.Lock()
		t.stats.Replayed++
		t.mu.Unlock()
	}
	return true
}

// emit forwards b in direction d after any Hold, logging recs (their Off
// relative to b) for the frames whose first byte went out. Own bytes stop
// at an armed Splice's offset and are discarded once it is active;
// spliced bytes are another tamper's frames. False when the tamper ended
// or the write failed.
func (t *Tamper) emit(d Dir, b []byte, recs []FrameRec, spliced bool) bool {
	i := d.index()
	t.mu.Lock()
	dd := &t.dirs[i]
	for dd.hold && !t.closed {
		if !dd.stopped {
			dd.stopped = true
			t.stats.Held++
		}
		t.cond.Wait()
	}
	dd.stopped = false
	if t.closed {
		t.mu.Unlock()
		return false
	}
	part := b
	if sp := dd.splice; !spliced && sp != nil {
		if sp.active {
			t.mu.Unlock()
			return true
		}
		if lim := sp.at - dd.off; lim < int64(len(b)) {
			part = b[:max(lim, 0)]
		}
	}
	dst, gen := t.client, t.gen
	if d == Up {
		dst = t.server
	}
	dd.writing = !spliced
	base := dd.off
	t.mu.Unlock()

	w := 0
	var err error
	for w < len(part) {
		var n int
		n, err = dst.Write(part[w:])
		w += max(n, 0)
		if err == nil {
			continue
		}
		if d == Up {
			t.mu.Lock()
			moved := !t.closed && t.gen != gen
			if moved {
				dst, gen, err = t.server, t.gen, nil
			}
			t.mu.Unlock()
			if moved {
				continue
			}
		}
		break
	}

	t.mu.Lock()
	dd.off += int64(w)
	if !spliced {
		dd.writing = false
	} else {
		t.stats.SplicedBytes += int64(w)
	}
	for _, r := range recs {
		if r.Off < int64(w) && len(dd.log) < tamperLogMax {
			r.Off += base
			r.Spliced = spliced
			dd.log = append(dd.log, r)
		}
	}
	var s *tsink
	var from *Tamper
	if sp := dd.splice; err == nil && !spliced && sp != nil && !sp.active && sp.at <= dd.off {
		from = sp.from
		s = t.activateLocked(i)
	}
	t.mu.Unlock()
	t.startSplice(d, from, s)
	return err == nil
}

// activateLocked starts the armed splice of direction i: its sink and the
// writer goroutine's place in the wait group. t.mu held, t not closed.
func (t *Tamper) activateLocked(i int) *tsink {
	dd := &t.dirs[i]
	dd.splice.active = true
	dd.own = &tsink{wake: make(chan struct{}, 1)}
	dd.live++
	t.stats.Spliced++
	t.wg.Add(1)
	return dd.own
}

// startSplice registers sink s with from and starts its writer (s nil:
// nothing was activated).
func (t *Tamper) startSplice(d Dir, from *Tamper, s *tsink) {
	if s == nil {
		return
	}
	from.mu.Lock()
	fd := &from.dirs[d.index()]
	fd.sinks = append(fd.sinks, s)
	from.mu.Unlock()
	go t.spliceWriter(d, s)
}

// spliceWriter forwards the frames teed into s until a write fails or the
// tamper ends.
func (t *Tamper) spliceWriter(d Dir, s *tsink) {
	defer t.wg.Done()
	defer t.leave(d, false)
	defer s.close()
	for {
		select {
		case <-s.wake:
		case <-t.done:
			return
		}
		for _, it := range s.take() {
			if !t.emit(d, it.b, []FrameRec{it.rec}, true) {
				return
			}
		}
	}
}

// push queues a copy of frame b (dropped and counted beyond the bound;
// ignored once closed).
func (s *tsink) push(b []byte, rec FrameRec) {
	s.mu.Lock()
	switch {
	case s.closed:
	case s.bytes+len(b) > tamperTeeMax:
		s.dropped.Add(1)
	default:
		s.q = append(s.q, tsinkItem{b: slices.Clone(b), rec: rec})
		s.bytes += len(b)
		signal(s.wake)
	}
	s.mu.Unlock()
}

// take removes and returns the queued frames.
func (s *tsink) take() []tsinkItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.q
	s.q, s.bytes = nil, 0
	return q
}

func (s *tsink) close() {
	s.mu.Lock()
	s.closed, s.q = true, nil
	s.mu.Unlock()
}

func (s *tsink) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
