package rendrtest

import (
	"encoding/binary"
	"slices"
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// tracker follows the framing of one direction of a carrier: the 40-byte
// PREFACE (or PREFACE_ACK), then frames of HeaderLen + len + TrailerLen
// bytes. Bytes stream through as they arrive; while an operation is armed
// (or an earlier injection requires every later fseq to be re-stamped) a
// header is assembled before it is forwarded, and a frame an operation
// targets is held whole. A length beyond MaxFramePayload loses frame sync:
// the rest of the stream passes through untouched (the receiver kills the
// carrier anyway). The tracker only parses; it never validates.
type tracker struct {
	pre    int                  // PREFACE bytes passed
	hdr    [wire.HeaderLen]byte // header being assembled
	hn     int
	sent   bool // the header's bytes are forwarded as they come (nothing armed)
	in     bool // inside a frame whose header was seen
	rest   int  // bytes of the current frame still to come (payload + trailer)
	hold   bool // the current frame is collected in fb
	fb     []byte
	op     frameOp
	opaque bool
	kind   int32     // class of the first frame (kindUnknown until seen)
	first  FrameType // type of the first frame
	shift  uint32    // fseq added to every frame after injections
	out    []byte

	corrupts []corruptOp
	drops    []FrameType
	injects  []*injection
	captures []*capture
	raws     [][]byte
}

type corruptOp struct {
	t FrameType
	m CorruptMode
}

type injection struct {
	after, t FrameType
	flags    uint8
	handle   uint32
	payload  []byte
}

// capture is shared by the carriers it was armed on; the first match wins.
type capture struct {
	t     FrameType
	ch    chan []byte
	fired atomic.Bool
}

// frameOp is what happens to the current frame.
type frameOp struct {
	drop    bool
	corrupt CorruptMode
	capture *capture
	inject  *injection
}

// events counts what one feed did to frames.
type events struct {
	corrupted, dropped, injected, captured int64
}

// classify maps the first frame of a carrier to its class.
func classify(t FrameType) int32 {
	switch t {
	case FrameOpen, FrameJoin:
		return kindSession
	case FramePing:
		return kindProbe
	}
	return kindOther
}

// idle reports whether no frame can need holding: nothing is armed and no
// injection shifted the fseq.
func (t *tracker) idle() bool {
	return t.shift == 0 && len(t.corrupts) == 0 && len(t.drops) == 0 && len(t.injects) == 0 && len(t.captures) == 0
}

// held is how many accepted bytes the tracker holds back.
func (t *tracker) held() int {
	if t.sent {
		return len(t.fb)
	}
	return t.hn + len(t.fb)
}

// atBoundary reports whether bytes inserted now would sit between two
// frames: after the PREFACE and not inside a frame (a partly assembled
// header that was held back follows the insertion).
func (t *tracker) atBoundary() bool {
	return t.pre == wire.PrefaceLen && !t.in && !t.opaque && (t.hn == 0 || !t.sent)
}

// flush returns the bytes held back when the writer's side ended: a stream
// that ends inside a frame is delivered as it was written.
func (t *tracker) flush() []byte {
	var out []byte
	if t.hn > 0 && !t.sent {
		out = append(out, t.hdr[:t.hn]...)
	}
	out = append(out, t.fb...)
	t.hn, t.fb, t.in, t.hold = 0, t.fb[:0], false, false
	return out
}

// feed processes p (borrowed) and returns the bytes to forward (owned; nil
// when nothing is due).
func (t *tracker) feed(p []byte, ev *events) []byte {
	t.out = make([]byte, 0, len(p)+64)
	for len(p) > 0 {
		switch {
		case t.opaque:
			t.out = append(t.out, p...)
			p = nil
		case t.pre < wire.PrefaceLen:
			k := min(wire.PrefaceLen-t.pre, len(p))
			t.out = append(t.out, p[:k]...)
			t.pre += k
			p = p[k:]
			if t.pre == wire.PrefaceLen {
				t.boundary(ev)
			}
		case !t.in:
			if t.hn == 0 {
				t.sent = t.idle()
			}
			k := copy(t.hdr[t.hn:], p)
			if t.sent {
				t.out = append(t.out, p[:k]...)
			}
			t.hn += k
			p = p[k:]
			if t.hn == wire.HeaderLen {
				t.startFrame()
			}
		default:
			k := min(t.rest, len(p))
			if t.hold {
				t.fb = append(t.fb, p[:k]...)
			} else {
				t.out = append(t.out, p[:k]...)
			}
			t.rest -= k
			p = p[k:]
			if t.rest == 0 {
				t.in = false
				if t.hold {
					t.hold = false
					t.process(ev)
					t.fb = t.fb[:0]
				}
				t.boundary(ev)
			}
		}
	}
	out := t.out
	t.out = nil
	if len(out) == 0 {
		return nil
	}
	return out
}

// startFrame decides the fate of the frame whose header is complete.
func (t *tracker) startFrame() {
	t.hn = 0
	typ := FrameType(t.hdr[0])
	n := int(t.hdr[2])<<16 | int(t.hdr[3])<<8 | int(t.hdr[4])
	if n > wire.MaxFramePayload {
		t.opaque = true
		if !t.sent {
			t.out = append(t.out, t.hdr[:]...)
		}
		return
	}
	if t.kind == kindUnknown {
		t.kind, t.first = classify(typ), typ
	}
	t.in, t.rest = true, n+wire.TrailerLen
	if t.sent { // already forwarded: operations armed meanwhile wait for the next frame
		t.op, t.hold = frameOp{}, false
		return
	}
	t.op = t.match(typ)
	t.hold = t.op != (frameOp{}) || t.shift != 0
	if t.hold {
		t.fb = append(t.fb[:0], t.hdr[:]...)
	} else {
		t.out = append(t.out, t.hdr[:]...)
	}
}

// match takes the armed operations that apply to the next frame of type
// typ. A dropped frame gets nothing else.
func (t *tracker) match(typ FrameType) (op frameOp) {
	if i := slices.Index(t.drops, typ); i >= 0 {
		t.drops = slices.Delete(t.drops, i, i+1)
		op.drop = true
		return op
	}
	if i := slices.IndexFunc(t.corrupts, func(c corruptOp) bool { return c.t == typ }); i >= 0 {
		op.corrupt = t.corrupts[i].m
		t.corrupts = slices.Delete(t.corrupts, i, i+1)
	}
	t.captures = slices.DeleteFunc(t.captures, func(c *capture) bool {
		if c.fired.Load() {
			return true
		}
		if c.t != typ || op.capture != nil {
			return false
		}
		op.capture = c
		return true
	})
	if i := slices.IndexFunc(t.injects, func(in *injection) bool { return in.after == typ }); i >= 0 {
		op.inject = t.injects[i]
		t.injects = slices.Delete(t.injects, i, i+1)
	}
	return op
}

// process applies the frame's operations to the whole frame in fb and
// forwards the result: re-stamp (fseq + shift, CRC recomputed), ACK forgery
// (CRC recomputed, fseq kept), then damage (CRC kept), capture, and an
// injected frame after it.
func (t *tracker) process(ev *events) {
	fb, op := t.fb, t.op
	if op.drop {
		ev.dropped++
		return
	}
	end := len(fb) - wire.TrailerLen
	seq := binary.BigEndian.Uint32(fb[5:9]) + t.shift
	binary.BigEndian.PutUint32(fb[5:9], seq)
	restamp := t.shift != 0
	if op.corrupt == ForgeAckBeyondSent && FrameType(fb[0]) == FrameAck && end-wire.HeaderLen >= 8 {
		p := fb[wire.HeaderLen:]
		binary.BigEndian.PutUint64(p, binary.BigEndian.Uint64(p)+forgeBeyond)
		restamp = true
	}
	if restamp {
		wire.PutTrailer(fb[end:], wire.CRC(fb[:end]))
	}
	switch op.corrupt {
	case CorruptHeader:
		fb[8] ^= 0x01 // the low bit of the fseq
	case CorruptPayload:
		if end > wire.HeaderLen {
			fb[wire.HeaderLen+(end-wire.HeaderLen)/2] ^= 0x01
		} else {
			fb[end] ^= 0x01 // no payload: damage the CRC instead
		}
	case CorruptTrailer:
		fb[end] ^= 0x01
	}
	if op.corrupt != 0 {
		ev.corrupted++
	}
	t.out = append(t.out, fb...)
	if c := op.capture; c != nil && c.fired.CompareAndSwap(false, true) {
		c.ch <- slices.Clone(fb)
		ev.captured++
	}
	if in := op.inject; in != nil {
		h := wire.Header{Type: wire.Type(in.t), Flags: in.flags, Fseq: seq + 1, Handle: in.handle}
		t.out = wire.AppendFrame(t.out, h, in.payload)
		t.shift++
		ev.injected++
	}
}

// boundary emits the raw injections armed for the next frame boundary.
func (t *tracker) boundary(ev *events) {
	for _, r := range t.raws {
		t.out = append(t.out, r...)
		ev.injected++
	}
	t.raws = nil
}
