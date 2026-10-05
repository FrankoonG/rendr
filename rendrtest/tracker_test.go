package rendrtest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// feedChunked runs stream through tr in random pieces of 1..maxPiece bytes
// and returns the concatenated output.
func feedChunked(tr *tracker, stream []byte, seed uint64, maxPiece int, ev *events) []byte {
	r := rand.New(rand.NewPCG(seed, ^seed))
	var out []byte
	for len(stream) > 0 {
		n := min(len(stream), 1+r.IntN(maxPiece))
		out = append(out, tr.feed(stream[:n], ev)...)
		stream = stream[n:]
	}
	return out
}

var pieceSizes = []int{1, 5, 13, 17, 97, 4096, 1 << 20}

// TestTrackerChunkingInvariant: with nothing armed — and with an armed
// operation that matches no frame, which makes every header and frame pass
// the holding path — the golden stream comes out byte for byte in every
// chunking, classified by its first frame.
func TestTrackerChunkingInvariant(t *testing.T) {
	stream := prefaceBytes(1)
	for _, f := range goldenFrames(t, 1) {
		stream = append(stream, f...)
	}
	for _, armed := range []bool{false, true} {
		for i, max := range pieceSizes {
			var tr tracker
			if armed {
				tr.corrupts = []corruptOp{{FrameType(0x7e), CorruptPayload}}
			}
			var ev events
			out := feedChunked(&tr, stream, uint64(i), max, &ev)
			if !bytes.Equal(out, stream) || ev != (events{}) {
				t.Fatalf("armed %v, pieces ≤ %d: %d of %d bytes or different bytes, events %+v", armed, max, len(out), len(stream), ev)
			}
			if tr.kind != kindSession || tr.first != FrameOpen || tr.held() != 0 || !tr.atBoundary() {
				t.Fatalf("armed %v: kind %d first %#x held %d boundary %v", armed, tr.kind, tr.first, tr.held(), tr.atBoundary())
			}
		}
	}
}

// opsStream is a small session stream: OPEN, DATA, ACK, PING, DATA, ACK,
// PONG, FIN with fseq 1..8.
func opsStream() (preface []byte, frames [][]byte) {
	payloads := []struct {
		t FrameType
		p []byte
	}{
		{FrameOpen, openPayload()},
		{FrameData, dataPayload(0, []byte("first data"))},
		{FrameAck, ackPayload(100)},
		{FramePing, pingPayload(4)},
		{FrameData, dataPayload(10, []byte("second data"))},
		{FrameAck, ackPayload(200)},
		{FramePong, pingPayload(7)},
		{FrameFin, binary.BigEndian.AppendUint64(nil, 21)},
	}
	for i, p := range payloads {
		frames = append(frames, frameBytes(p.t, uint32(1+i), p.p))
	}
	return prefaceBytes(2), frames
}

// TestTrackerFrameOps: each frame operation does exactly what it promises
// to exactly one frame, in every chunking (L13, L21, L43).
func TestTrackerFrameOps(t *testing.T) {
	pre, frames := opsStream()
	stream := append([]byte(nil), pre...)
	for _, f := range frames {
		stream = append(stream, f...)
	}
	// diffs returns the offsets where out differs from in (same length).
	diffs := func(t *testing.T, out []byte) []int {
		if len(out) != len(stream) {
			t.Fatalf("output %d bytes, want %d", len(out), len(stream))
		}
		var d []int
		for i := range out {
			if out[i] != stream[i] {
				d = append(d, i)
			}
		}
		return d
	}
	ackAt := len(pre) + len(frames[0]) + len(frames[1]) // the first ACK
	injected := pingPayload(99)
	cases := []struct {
		name  string
		arm   func(tr *tracker) *capture
		want  events
		check func(t *testing.T, out []byte, cp *capture)
	}{
		{"drop", func(tr *tracker) *capture { tr.drops = []FrameType{FrameData}; return nil },
			events{dropped: 1}, func(t *testing.T, out []byte, _ *capture) {
				want := append(append([]byte(nil), pre...), frames[0]...)
				for _, f := range frames[2:] {
					want = append(want, f...)
				}
				if !bytes.Equal(out, want) {
					t.Fatal("output is not the stream minus the first DATA frame")
				}
			}},
		{"corrupt-header", func(tr *tracker) *capture {
			tr.corrupts = []corruptOp{{FrameAck, CorruptHeader}}
			return nil
		}, events{corrupted: 1}, func(t *testing.T, out []byte, _ *capture) {
			if d := diffs(t, out); len(d) != 1 || d[0] != ackAt+8 || fseqOf(out[ackAt:]) != 2 {
				t.Fatalf("damaged offsets %v, want only the fseq low bit of the ACK", d)
			}
			if _, _, err := wire.DecodeFrame(out[ackAt:]); !errors.Is(err, wire.ErrCRC) {
				t.Fatalf("damaged ACK decodes with %v, want ErrCRC (CRC kept)", err)
			}
		}},
		{"corrupt-payload", func(tr *tracker) *capture {
			tr.corrupts = []corruptOp{{FrameAck, CorruptPayload}}
			return nil
		}, events{corrupted: 1}, func(t *testing.T, out []byte, _ *capture) {
			d := diffs(t, out)
			if len(d) != 1 || d[0] < ackAt+wire.HeaderLen || d[0] >= ackAt+wire.HeaderLen+wire.AckLen {
				t.Fatalf("damaged offsets %v, want one ACK payload byte", d)
			}
			if _, _, err := wire.DecodeFrame(out[ackAt:]); !errors.Is(err, wire.ErrCRC) {
				t.Fatalf("damaged ACK decodes with %v, want ErrCRC", err)
			}
		}},
		{"corrupt-trailer", func(tr *tracker) *capture {
			tr.corrupts = []corruptOp{{FrameAck, CorruptTrailer}}
			return nil
		}, events{corrupted: 1}, func(t *testing.T, out []byte, _ *capture) {
			trailer := ackAt + wire.HeaderLen + wire.AckLen
			if d := diffs(t, out); len(d) != 1 || d[0] != trailer {
				t.Fatalf("damaged offsets %v, want the ACK's first CRC byte", d)
			}
		}},
		{"forge-ack", func(tr *tracker) *capture {
			tr.corrupts = []corruptOp{{FrameAck, ForgeAckBeyondSent}}
			return nil
		}, events{corrupted: 1}, func(t *testing.T, out []byte, _ *capture) {
			f, _, err := wire.DecodeFrame(out[ackAt:])
			if err != nil {
				t.Fatalf("forged ACK does not decode: %v", err)
			}
			a, err := wire.ParseAck(f.Payload)
			if err != nil || a.Delivered != 100+forgeBeyond || f.Fseq != 3 || f.Flags != 0 {
				t.Fatalf("forged ACK %+v fseq %d (%v), want delivered 100+2^40, fseq 3", a, f.Fseq, err)
			}
			if fs := decodeAll(t, out[len(pre):]); len(fs) != len(frames) {
				t.Fatalf("%d frames, want %d", len(fs), len(frames))
			}
		}},
		{"inject-twice", func(tr *tracker) *capture {
			tr.injects = []*injection{
				{after: FrameData, t: FramePong, payload: injected},
				{after: FrameData, t: FrameClose, payload: []byte{1}},
			}
			return nil
		}, events{injected: 2}, func(t *testing.T, out []byte, _ *capture) {
			fs := decodeAll(t, out[len(pre):])
			if len(fs) != len(frames)+2 {
				t.Fatalf("%d frames, want %d", len(fs), len(frames)+2)
			}
			for i, f := range fs {
				if f.Fseq != uint32(1+i) {
					t.Fatalf("frame %d has fseq %d: not re-stamped", i, f.Fseq)
				}
			}
			if fs[2].Type != wire.TypePong || !bytes.Equal(fs[2].Payload, injected) || fs[6].Type != wire.TypeClose || fs[6].Handle != 0 {
				t.Fatalf("injected frames %v / %v not after the DATA frames", fs[2].Header, fs[6].Header)
			}
			if fs[3].Type != wire.TypeAck || fs[9].Type != wire.TypeFin {
				t.Fatal("original frames out of order after the injection")
			}
		}},
		{"capture", func(tr *tracker) *capture {
			cp := &capture{t: FramePong, ch: make(chan []byte, 1)}
			tr.captures = []*capture{cp}
			return cp
		}, events{captured: 1}, func(t *testing.T, out []byte, cp *capture) {
			if d := diffs(t, out); len(d) != 0 {
				t.Fatal("a capture changed the stream")
			}
			if got := <-cp.ch; !bytes.Equal(got, frames[6]) {
				t.Fatalf("captured %x, want the PONG %x", got, frames[6])
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i, max := range pieceSizes {
				var tr tracker
				cp := c.arm(&tr)
				var ev events
				out := feedChunked(&tr, stream, uint64(100+i), max, &ev)
				if ev != c.want {
					t.Fatalf("pieces ≤ %d: events %+v, want %+v", max, ev, c.want)
				}
				c.check(t, out, cp)
			}
		})
	}
}

// TestTrackerRawAtNextBoundary: raw bytes armed in the middle of a frame
// are emitted right after it, never inside it; a lost frame sync passes the
// rest through untouched and nothing armed fires.
func TestTrackerRawAtNextBoundary(t *testing.T) {
	pre, frames := opsStream()
	var tr tracker
	var ev events
	out := tr.feed(append(append([]byte(nil), pre...), frames[0][:7]...), &ev)
	if tr.atBoundary() {
		t.Fatal("inside a frame's header counts as a boundary")
	}
	tr.raws = append(tr.raws, []byte("SPLICE"))
	out = append(out, tr.feed(frames[0][7:], &ev)...)
	want := append(append(append([]byte(nil), pre...), frames[0]...), "SPLICE"...)
	if !bytes.Equal(out, want) || ev.injected != 1 || !tr.atBoundary() {
		t.Fatalf("raw bytes not emitted at the frame boundary (injected %d)", ev.injected)
	}

	bad := frameBytes(FrameData, 2, dataPayload(0, []byte("x")))
	bad[2] = 0xff // length beyond MaxFramePayload
	rest := append(bad, frames[2]...)
	tr.drops = []FrameType{FrameAck}
	if got := tr.feed(rest, &ev); !bytes.Equal(got, rest) || ev.dropped != 0 || !tr.opaque {
		t.Fatal("after a lost frame sync the stream was modified")
	}
}

// TestLinkFrameControlsEndToEnd: the frame controls on a live carrier, as
// the receiving rendr end would see them, counted for the session class.
func TestLinkFrameControlsEndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "frames"})
		defer h.l.Close()
		cli, srv := h.session()

		// DropNextFrame: an fseq gap at the receiver.
		h.l.DropNextFrame(Up, FrameData)
		write(t, cli, append(frameBytes(FrameData, 2, dataPayload(0, []byte("lost"))), frameBytes(FramePing, 3, pingPayload(3))...))
		if f := readFrame(t, srv); FrameType(f[0]) != FramePing || fseqOf(f) != 3 {
			t.Fatalf("after a dropped DATA the receiver got %#x fseq %d, want PING fseq 3", f[0], fseqOf(f))
		}

		// ForgeAckBeyondSent: a valid frame with an impossible offset.
		h.l.CorruptNextFrame(Down, FrameAck, ForgeAckBeyondSent)
		write(t, srv, frameBytes(FrameAck, 2, ackPayload(4)))
		fr, _, err := wire.DecodeFrame(readFrame(t, cli))
		if err != nil || fr.Fseq != 2 {
			t.Fatalf("forged ACK: %v fseq %d", err, fr.Fseq)
		}
		if a, _ := wire.ParseAck(fr.Payload); a.Delivered != 4+forgeBeyond {
			t.Fatalf("forged delivered %d", a.Delivered)
		}

		// CaptureNextFrame + InjectRaw: a captured frame spliced back in
		// arrives at once and byte for byte (no re-stamp).
		ch := h.l.CaptureNextFrame(Up, FramePing)
		ping := frameBytes(FramePing, 4, pingPayload(4))
		write(t, cli, ping)
		readFrame(t, srv)
		captured := <-ch
		if !bytes.Equal(captured, ping) {
			t.Fatal("captured bytes differ from the PING")
		}
		h.l.InjectRaw(Up, captured)
		if got := readFrame(t, srv); !bytes.Equal(got, ping) {
			t.Fatal("InjectRaw re-stamped or changed the spliced frame")
		}

		// InjectAfterNextFrame: a stale PONG after the next PONG; later
		// frames re-stamped so only the injected frame is foreign.
		stale := pingPayload(1)
		h.l.InjectAfterNextFrame(Down, FramePong, FramePong, 0, 0, stale)
		write(t, srv, append(frameBytes(FramePong, 3, pingPayload(4)), frameBytes(FrameAck, 4, ackPayload(9))...))
		var got []byte
		for range 3 {
			got = append(got, readFrame(t, cli)...)
		}
		fs := decodeAll(t, got)
		if fs[0].Fseq != 3 || fs[1].Fseq != 4 || !bytes.Equal(fs[1].Payload, stale) || fs[2].Type != wire.TypeAck || fs[2].Fseq != 5 {
			t.Fatalf("frames after injection: %v %v %v", fs[0].Header, fs[1].Header, fs[2].Header)
		}

		st := h.l.Stats()
		if st.Session.FramesDropped != 1 || st.Session.FramesCorrupted != 1 || st.Session.FramesInjected != 2 || st.Probe != (Counts{}) {
			t.Fatalf("session frame counters %+v, probe %+v", st.Session, st.Probe)
		}
	})
}
