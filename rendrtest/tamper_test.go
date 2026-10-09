package rendrtest

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// tamperRig is a Tamper between two net.Pipe pairs: the test writes Up on
// dialer and Down on passive; up and down collect what crossed.
type tamperRig struct {
	dialer, passive net.Conn
	tm              *Tamper
	up, down        *readAsync
}

func newTamperRig() *tamperRig {
	d, c := net.Pipe()
	s, p := net.Pipe()
	r := &tamperRig{dialer: d, passive: p, tm: NewTamper(c, s)}
	r.up, r.down = readBackground(p), readBackground(d)
	return r
}

// close ends the tamper and both test conns and waits for the readers.
func (r *tamperRig) close() {
	r.tm.Close()
	r.dialer.Close()
	r.passive.Close()
	r.up.result()
	r.down.result()
}

// dataFrames returns n DATA frames with fseq first, first+1, … whose
// payloads carry tag and the frame number (sizes differ per frame).
func dataFrames(first uint32, n int, tag byte) [][]byte {
	fs := make([][]byte, n)
	for i := range fs {
		body := bytes.Repeat([]byte{tag, byte(i)}, 5+i)
		fs[i] = frameBytes(FrameData, first+uint32(i), dataPayload(uint64(i)*100, body))
	}
	return fs
}

func cat(parts ...[]byte) []byte { return slices.Concat(parts...) }

// frameOffsets returns the offset of every frame of fs in a stream that
// starts with a PREFACE.
func frameOffsets(fs [][]byte) []int64 {
	off, out := int64(wire.PrefaceLen), make([]int64, len(fs))
	for i, f := range fs {
		out[i] = off
		off += int64(len(f))
	}
	return out
}

// checkLog compares a direction's frame tap with the frames fs forwarded
// at their offsets, indices idx.
func checkLog(t *testing.T, got []FrameRec, fs [][]byte, idx []int) {
	t.Helper()
	if len(got) != len(fs) {
		t.Fatalf("Log has %d frames, want %d: %+v", len(got), len(fs), got)
	}
	off := int64(wire.PrefaceLen)
	for i, f := range fs {
		want := FrameRec{Type: FrameType(f[0]), Flags: f[1], Len: len(f) - wire.FrameOverhead,
			Fseq: binary.BigEndian.Uint32(f[5:9]), Handle: binary.BigEndian.Uint32(f[9:13]), Index: idx[i], Off: off}
		if got[i] != want {
			t.Fatalf("Log[%d] = %+v, want %+v", i, got[i], want)
		}
		off += int64(len(f))
	}
}

func seq(n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}

// TestTamperTransparent: with nothing armed, both directions arrive
// byte-identically — every frame type and size of the wire format's golden
// vectors (DETACH included), written in random pieces, and a frame of the
// largest payload — and the frame tap logs every frame with its header
// fields, index and offset. Over net.Pipe, over a Link in a bubble, and a
// header beyond MaxFramePayload passes the rest through untouched.
func TestTamperTransparent(t *testing.T) {
	big := frameBytes(FrameData, 0, dataPayload(0, bytes.Repeat([]byte{0xa5}, wire.MaxFramePayload-wire.DataPrefixLen)))
	streams := func(t *testing.T, first uint32) [][]byte {
		fs := goldenFrames(t, first)
		bf := slices.Clone(big)
		binary.BigEndian.PutUint32(bf[5:9], first+uint32(len(fs)))
		end := len(bf) - wire.TrailerLen
		wire.PutTrailer(bf[end:], wire.CRC(bf[:end]))
		hasDetach := false
		for _, f := range fs {
			hasDetach = hasDetach || FrameType(f[0]) == FrameDetach
		}
		if !hasDetach {
			t.Fatal("the golden vectors carry no DETACH frame")
		}
		return append(fs, bf)
	}
	run := func(t *testing.T, r *tamperRig) {
		defer r.close()
		upF, downF := streams(t, 1), streams(t, 1000)
		upB, downB := cat(prefaceBytes(7), slices.Concat(upF...)), cat(prefaceAckBytes(7), slices.Concat(downF...))
		done := make(chan struct{})
		go func() {
			defer close(done)
			chunked(t, r.passive, downB, 2, 3000)
		}()
		chunked(t, r.dialer, upB, 1, 3000)
		<-done
		synctest.Wait()
		if got := r.up.bytes(); !bytes.Equal(got, upB) {
			t.Fatalf("Up: %d bytes arrived, want the %d written identically", len(got), len(upB))
		}
		if got := r.down.bytes(); !bytes.Equal(got, downB) {
			t.Fatalf("Down: %d bytes arrived, want the %d written identically", len(got), len(downB))
		}
		checkLog(t, r.tm.Log(Up), upF, seq(len(upF)))
		checkLog(t, r.tm.Log(Down), downF, seq(len(downF)))
		if s := r.tm.Stats(); s != (TamperStats{}) {
			t.Fatalf("Stats = %+v with nothing armed", s)
		}
	}
	t.Run("pipe", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { run(t, newTamperRig()) })
	})
	t.Run("link", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newHarness(t, LinkConfig{Name: "tamper"})
			defer h.l.Close()
			cli, srv := h.dial()
			s, p := net.Pipe()
			r := &tamperRig{dialer: cli, passive: p, tm: NewTamper(srv, s)}
			r.up, r.down = readBackground(p), readBackground(cli)
			run(t, r)
		})
	})
	t.Run("opaque", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newTamperRig()
			defer r.close()
			fs := dataFrames(1, 2, 'a')
			bad := slices.Clone(fs[1])
			bad[2] = 0xff // a length beyond MaxFramePayload: frame sync lost
			tail := bytes.Repeat([]byte{7}, 5000)
			r.tm.DropFrame(Up, 2) // armed for a frame the tamper can no longer see
			in := cat(prefaceBytes(7), fs[0], bad, tail)
			write(t, r.dialer, in)
			synctest.Wait()
			if got := r.up.bytes(); !bytes.Equal(got, in) {
				t.Fatalf("Up: %d bytes arrived, want the %d written identically", len(got), len(in))
			}
			checkLog(t, r.tm.Log(Up), fs[:1], []int{0})
			if s := r.tm.Stats(); s.Dropped != 0 {
				t.Fatalf("Stats = %+v: an operation fired after the frame sync was lost", s)
			}
		})
	})
	t.Run("partial-at-end", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newTamperRig()
			defer r.close()
			fs := dataFrames(1, 2, 'a')
			in := cat(prefaceBytes(7), fs[0], fs[1][:9])
			write(t, r.dialer, in)
			r.dialer.Close()
			got, _ := r.up.result()
			if !bytes.Equal(got, in) {
				t.Fatalf("a stream that ends inside a frame: %d bytes arrived, want the %d written", len(got), len(in))
			}
		})
	})
}

// upRun writes PREFACE ‖ fs on the dialer and returns what arrived Up.
func upRun(t *testing.T, r *tamperRig, fs [][]byte) []byte {
	t.Helper()
	write(t, r.dialer, cat(prefaceBytes(7), slices.Concat(fs...)))
	synctest.Wait()
	return r.up.bytes()
}

// TestTamperFlipBit: FlipBit flips exactly the addressed bit of the
// addressed frame — bit 40 is the fseq's first bit, −1 the CRC's last bit,
// a NextOfType selector the next frame of that type — in the given
// direction only; the receiver sees an fseq or CRC violation; one count
// per flip.
func TestTamperFlipBit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTamperRig()
		defer r.close()
		fs := dataFrames(1, 8, 'u')
		fs[6] = frameBytes(FrameAck, 7, ackPayload(9))
		r.tm.FlipBit(Up, 3, 40)
		r.tm.FlipBit(Up, 5, -1)
		r.tm.FlipBit(Up, NextOfType(FrameAck), 8)
		r.tm.FlipBit(Down, 3, 40) // the other direction stays untouched
		want := slices.Clone(fs)
		want[3] = slices.Clone(fs[3])
		want[3][5] ^= 0x80
		want[5] = slices.Clone(fs[5])
		want[5][len(fs[5])-1] ^= 0x01
		want[6] = slices.Clone(fs[6])
		want[6][1] ^= 0x80
		if got := upRun(t, r, fs); !bytes.Equal(got, cat(prefaceBytes(7), slices.Concat(want...))) {
			t.Fatalf("Up after the flips differs from the expected bytes")
		}
		if _, _, err := wire.DecodeFrame(want[5]); !errors.Is(err, wire.ErrCRC) {
			t.Fatalf("the CRC flip decodes with %v, want ErrCRC", err)
		}
		if f, _, err := wire.DecodeFrame(want[3]); err == nil && f.Fseq == 4 {
			t.Fatal("the fseq flip left the fseq intact")
		}
		if s := r.tm.Stats(); s.Flipped != 3 {
			t.Fatalf("Flipped = %d, want 3", s.Flipped)
		}
		checkLog(t, r.tm.Log(Up), want, seq(8))
	})
}

// TestTamperDropFrame: DropFrame forwards every frame but the addressed
// one (the receiver sees an fseq gap); the tap and the counter show it.
func TestTamperDropFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTamperRig()
		defer r.close()
		fs := dataFrames(1, 6, 'd')
		r.tm.DropFrame(Up, 2)
		r.tm.DropFrame(Up, NextOfType(FrameAck)) // no ACK comes: never fires
		want := slices.Concat(fs[:2], fs[3:])
		if got := upRun(t, r, fs); !bytes.Equal(got, cat(prefaceBytes(7), slices.Concat(want...))) {
			t.Fatal("Up after DropFrame differs from the frames without frame 2")
		}
		if s := r.tm.Stats(); s.Dropped != 1 {
			t.Fatalf("Dropped = %d, want 1", s.Dropped)
		}
		checkLog(t, r.tm.Log(Up), want, []int{0, 1, 3, 4, 5})
	})
}

// TestTamperDuplicateFrame: DuplicateFrame forwards the addressed frame
// twice in a row, byte-identically.
func TestTamperDuplicateFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTamperRig()
		defer r.close()
		fs := dataFrames(1, 6, 'D')
		r.tm.DuplicateFrame(Up, 4)
		want := slices.Concat(fs[:5], fs[4:])
		if got := upRun(t, r, fs); !bytes.Equal(got, cat(prefaceBytes(7), slices.Concat(want...))) {
			t.Fatal("Up after DuplicateFrame differs from the frames with frame 4 twice")
		}
		if s := r.tm.Stats(); s.Duplicated != 1 {
			t.Fatalf("Duplicated = %d, want 1", s.Duplicated)
		}
		checkLog(t, r.tm.Log(Up), want, []int{0, 1, 2, 3, 4, 4, 5})
	})
}

// TestTamperReplayFrame: ReplayFrame re-sends the addressed frame, byte
// for byte, after a later frame (absolute index, or a count after a
// NextOfType selector); a replay must follow its frame.
func TestTamperReplayFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTamperRig()
		defer r.close()
		fs := dataFrames(1, 9, 'r')
		fs[2] = frameBytes(FrameAck, 3, ackPayload(5))
		r.tm.ReplayFrame(Up, 1, 4)
		r.tm.ReplayFrame(Up, NextOfType(FrameAck), 5) // frame 2, after frame 7
		want := slices.Concat(fs[:5], [][]byte{fs[1]}, fs[5:8], [][]byte{fs[2]}, fs[8:])
		if got := upRun(t, r, fs); !bytes.Equal(got, cat(prefaceBytes(7), slices.Concat(want...))) {
			t.Fatal("Up after ReplayFrame differs from the expected order")
		}
		if s := r.tm.Stats(); s.Replayed != 2 {
			t.Fatalf("Replayed = %d, want 2", s.Replayed)
		}
		checkLog(t, r.tm.Log(Up), want, []int{0, 1, 2, 3, 4, 1, 5, 6, 7, 2, 8})
		for _, bad := range [][2]int{{3, 3}, {3, 1}, {NextOfType(FrameData), 0}} {
			func() {
				defer func() {
					if recover() == nil {
						t.Errorf("ReplayFrame(%d, %d) did not panic", bad[0], bad[1])
					}
				}()
				r.tm.ReplayFrame(Up, bad[0], bad[1])
			}()
		}
	})
}

// TestTamperRewriteHandle: RewriteHandle puts another handle into the
// addressed frame, with a valid CRC when asked (a broken peer: the frame
// decodes with the new handle) or the stale one (a damaged path: ErrCRC).
func TestTamperRewriteHandle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTamperRig()
		defer r.close()
		fs := dataFrames(1, 5, 'h')
		r.tm.RewriteHandle(Up, 1, 7, true)
		r.tm.RewriteHandle(Up, 3, 9, false)
		got := upRun(t, r, fs)
		frames := got[wire.PrefaceLen:]
		var dec []wire.Frame
		var errs []error
		for len(frames) > 0 {
			n := wire.FrameOverhead + frameLen(frames)
			f, _, err := wire.DecodeFrame(frames[:n])
			dec, errs = append(dec, f), append(errs, err)
			frames = frames[n:]
		}
		if len(dec) != 5 || errs[1] != nil || dec[1].Handle != 7 || !errors.Is(errs[3], wire.ErrCRC) {
			t.Fatalf("frames %d, frame 1: handle %d err %v; frame 3: err %v; want handle 7 nil and ErrCRC",
				len(dec), dec[1].Handle, errs[1], errs[3])
		}
		for _, i := range []int{0, 2, 4} {
			if errs[i] != nil || dec[i].Handle != wire.SessionHandle {
				t.Fatalf("frame %d changed: handle %d err %v", i, dec[i].Handle, errs[i])
			}
		}
		if h := binary.BigEndian.Uint32(got[wire.PrefaceLen+len(fs[0])+len(fs[1])+len(fs[2])+9:]); h != 9 {
			t.Fatalf("frame 3 carries handle %d, want 9", h)
		}
		if s := r.tm.Stats(); s.Rewritten != 2 {
			t.Fatalf("Rewritten = %d, want 2", s.Rewritten)
		}
		if lg := r.tm.Log(Up); lg[1].Handle != 7 || lg[3].Handle != 9 {
			t.Fatalf("Log handles %d and %d, want 7 and 9", lg[1].Handle, lg[3].Handle)
		}
	})
}

// TestTamperHold: Hold stops a direction at the next frame boundary —
// nothing more arrives, the other direction keeps flowing — and Release
// resumes it with every byte; one count per stop.
func TestTamperHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTamperRig()
		defer r.close()
		fs := dataFrames(1, 6, 'H')
		head := cat(prefaceBytes(7), fs[0], fs[1])
		write(t, r.dialer, head)
		synctest.Wait()
		r.tm.Hold(Up)
		r.tm.Hold(Up) // a second Hold of a held direction: one stop
		wrote := make(chan struct{})
		go func() {
			defer close(wrote)
			write(t, r.dialer, slices.Concat(fs[2:]...))
		}()
		down := cat(prefaceAckBytes(7), slices.Concat(dataFrames(50, 3, 'v')...))
		write(t, r.passive, down)
		synctest.Wait()
		if got := r.up.bytes(); !bytes.Equal(got, head) {
			t.Fatalf("Up moved while held: %d bytes, want %d", len(got), len(head))
		}
		if got := r.down.bytes(); !bytes.Equal(got, down) {
			t.Fatal("Down stopped while only Up was held")
		}
		if s := r.tm.Stats(); s.Held != 1 || len(r.tm.Log(Up)) != 2 {
			t.Fatalf("Held = %d, Log(Up) = %d frames; want 1 and 2", s.Held, len(r.tm.Log(Up)))
		}
		r.tm.Release(Up)
		<-wrote
		synctest.Wait()
		if got := r.up.bytes(); !bytes.Equal(got, cat(prefaceBytes(7), slices.Concat(fs...))) {
			t.Fatal("Up after Release lacks bytes")
		}
	})
}

// TestTamperSplice: from the given offset on, a direction forwards the
// frames another tamper forwards instead of its own — at a frame boundary
// and mid-frame — while the other tamper's own stream stays intact; the
// spliced frames are logged as such and counted.
func TestTamperSplice(t *testing.T) {
	for _, mid := range []int64{0, 7} {
		t.Run(map[int64]string{0: "boundary", 7: "mid-frame"}[mid], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				x, y := newTamperRig(), newTamperRig()
				defer x.close()
				defer y.close()
				yf, xf := dataFrames(1, 6, 'y'), dataFrames(1, 4, 'x')
				at := frameOffsets(yf)[3] + mid
				y.tm.Splice(Up, x.tm, at)
				write(t, y.dialer, cat(prefaceBytes(7), slices.Concat(yf...)))
				synctest.Wait()
				if s := y.tm.Stats(); s.Spliced != 1 {
					t.Fatalf("Spliced = %d after the offset passed, want 1", s.Spliced)
				}
				xin := cat(prefaceBytes(8), slices.Concat(xf...))
				write(t, x.dialer, xin)
				synctest.Wait()
				if got := x.up.bytes(); !bytes.Equal(got, xin) {
					t.Fatal("the splice source's own stream changed")
				}
				ownCut := cat(prefaceBytes(7), slices.Concat(yf[:3]...), yf[3][:mid])
				want := cat(ownCut, slices.Concat(xf...))
				if got := y.up.bytes(); !bytes.Equal(got, want) {
					t.Fatalf("mid %d: %d bytes arrived, want %d: own bytes up to the offset, then the other's frames", mid, len(got), len(want))
				}
				s := y.tm.Stats()
				if s.SplicedBytes != int64(len(slices.Concat(xf...))) {
					t.Fatalf("SplicedBytes = %d, want %d", s.SplicedBytes, len(slices.Concat(xf...)))
				}
				lg := y.tm.Log(Up)
				own := 3
				if mid > 0 {
					own = 4 // the cut frame is logged
				}
				if len(lg) != own+4 {
					t.Fatalf("Log has %d frames, want %d", len(lg), own+4)
				}
				for i, rec := range lg {
					if rec.Spliced != (i >= own) {
						t.Fatalf("Log[%d].Spliced = %v", i, rec.Spliced)
					}
				}
				if last := lg[len(lg)-1]; last.Index != 3 || last.Off != int64(len(want)-len(xf[3])) {
					t.Fatalf("the last spliced frame logged as %+v", last)
				}
			})
		})
	}
	t.Run("self", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newTamperRig()
			defer r.close()
			defer func() {
				if recover() == nil {
					t.Error("Splice from itself did not panic")
				}
			}()
			r.tm.Splice(Up, r.tm, 0)
		})
	})
}

// TestTamperSwitchUpstream: the relay reconnects its upstream mid-stream:
// the old upstream is closed, the dialer's remaining bytes go into the
// fresh conn (no PREFACE of their own), and Down forwards what the new
// upstream sends.
func TestTamperSwitchUpstream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTamperRig()
		defer r.close()
		fs := dataFrames(1, 5, 's')
		write(t, r.dialer, cat(prefaceBytes(7), fs[0], fs[1]))
		synctest.Wait()
		s2, p2 := net.Pipe()
		up2 := readBackground(p2)
		defer up2.result()
		defer p2.Close()
		defer r.tm.Close()
		r.tm.SwitchUpstream(func() (net.Conn, error) { return s2, nil })
		if _, err := r.up.result(); err == nil {
			t.Fatal("the old upstream was not closed")
		}
		write(t, r.dialer, slices.Concat(fs[2:]...))
		synctest.Wait()
		if got := up2.bytes(); !bytes.Equal(got, slices.Concat(fs[2:]...)) {
			t.Fatalf("the new upstream got %d bytes, want the dialer's remaining %d", len(got), len(slices.Concat(fs[2:]...)))
		}
		down := cat(prefaceAckBytes(9), slices.Concat(dataFrames(1, 2, 'n')...))
		write(t, p2, down)
		synctest.Wait()
		if got := r.down.bytes(); !bytes.Equal(got, down) {
			t.Fatal("Down did not forward the new upstream's bytes")
		}
		if s := r.tm.Stats(); s.Switched != 1 || len(r.tm.Log(Up)) != 5 || len(r.tm.Log(Down)) != 2 {
			t.Fatalf("Switched = %d, Log(Up) %d, Log(Down) %d; want 1, 5, 2", s.Switched, len(r.tm.Log(Up)), len(r.tm.Log(Down)))
		}
	})
	t.Run("dial-fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newTamperRig()
			defer r.close()
			r.tm.SwitchUpstream(func() (net.Conn, error) { return nil, errors.New("no route") })
			if _, err := r.down.result(); err == nil {
				t.Fatal("a failed upstream dial left the dialer's conn open")
			}
			if s := r.tm.Stats(); s.Switched != 0 {
				t.Fatalf("Switched = %d after a failed dial", s.Switched)
			}
		})
	})
}

// TestTamperCloseJoins: Close ends a tamper whose pumps are blocked — one
// in a Hold, one writing to a conn nobody reads — closes both conns and
// joins every goroutine (the bubble fails on a leftover); a conn failure
// ends the tamper by itself.
func TestTamperCloseJoins(t *testing.T) {
	t.Run("blocked", func(t *testing.T) { synctest.Test(t, tamperCloseBlocked) })
	t.Run("conn-fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newTamperRig()
			defer r.close()
			r.passive.Close() // the passive side fails: the tamper ends and closes the dialer's side
			if _, err := r.down.result(); err == nil {
				t.Fatal("the dialer's conn stayed open after the passive side failed")
			}
		})
	})
}

func tamperCloseBlocked(t *testing.T) {
	{
		d, c := net.Pipe()
		s, p := net.Pipe()
		tm := NewTamper(c, s)
		defer p.Close()
		defer d.Close()
		defer tm.Close()
		tm.Hold(Up)
		go d.Write(cat(prefaceBytes(7), dataFrames(1, 1, 'c')[0]))
		go p.Write(prefaceAckBytes(7)) // nobody reads d: the Down pump blocks writing
		synctest.Wait()
		tm.Close()
		tm.Close()
		if _, err := d.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("the dialer's conn after Close: %v", err)
		}
		d.Close()
		p.Close()
	}
}

// TestTamperRealSockets: the same tamper between real loopback TCP
// sockets, outside any bubble: byte-identical by default, one flip
// fires, and nothing leaks.
func TestTamperRealSockets(t *testing.T) {
	check := AssertNoLeak(t)
	defer check()
	listen := func() net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	front, back := listen(), listen()
	defer front.Close()
	defer back.Close()
	accepted := func(ln net.Listener) chan net.Conn {
		ch := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				c = nil
			}
			ch <- c
		}()
		return ch
	}
	fa, ba := accepted(front), accepted(back)
	var dl net.Dialer
	dialer, err := dl.DialContext(context.Background(), "tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := <-fa
	server, err := dl.DialContext(context.Background(), "tcp", back.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	passive := <-ba
	if client == nil || passive == nil {
		t.Fatal("accept failed")
	}
	tm := NewTamper(client, server)
	defer passive.Close()
	defer dialer.Close()
	defer tm.Close()
	fs := dataFrames(1, 40, 'R')
	tm.FlipBit(Up, 20, -1)
	in := cat(prefaceBytes(7), slices.Concat(fs...))
	go dialer.Write(in)
	got := make([]byte, len(in))
	if _, err := io.ReadFull(passive, got); err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(in)
	want[frameOffsets(fs)[20]+int64(len(fs[20]))-1] ^= 0x01
	if !bytes.Equal(got, want) {
		t.Fatal("real sockets: the bytes differ from the input with one flipped CRC bit")
	}
	dialer.Close() // the tamper ends with its dialer side; Close joins it, so its log is complete
	if _, err := passive.Read(make([]byte, 1)); err == nil {
		t.Fatal("the passive side stayed open after the dialer closed")
	}
	tm.Close()
	if s := tm.Stats(); s.Flipped != 1 || len(tm.Log(Up)) != 40 {
		t.Fatalf("Flipped = %d, Log %d frames; want 1 and 40", s.Flipped, len(tm.Log(Up)))
	}
}
