package carrier

import (
	"errors"
	"math"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// hCheckReceived verifies that an endpoint received DATA covering [0, n)
// in order with the hPattern bytes (keepData endpoints only).
func hCheckReceived(t *testing.T, ep *hEP, n uint64) {
	t.Helper()
	var next uint64
	for _, d := range ep.received() {
		if d.off != next || len(d.b) != d.n {
			t.Fatalf("DATA at %d (%d bytes), want %d", d.off, d.n, next)
		}
		for i, b := range d.b {
			if b != hPattern(d.off+uint64(i)) {
				t.Fatalf("DATA byte at %d differs", d.off+uint64(i))
			}
		}
		next += uint64(d.n)
	}
	if next != n {
		t.Fatalf("received [0, %d), want [0, %d)", next, n)
	}
}

// TestInvalidReadCounts_L42: a Read count outside [0, len] or (0, nil)
// kills the carrier with transport_error before anything is sized by it;
// bytes returned together with an error are processed first, then the
// carrier dies (L01).
func TestInvalidReadCounts_L42(t *testing.T) {
	errBoom := errors.New("boom")
	cases := []struct {
		name      string
		read      func(nc net.Conn, p []byte) (int, error)
		delivered int
		detail    string
	}{
		{"negative", func(nc net.Conn, p []byte) (int, error) { return -1, nil }, 0, "invalid count -1"},
		{"beyond", func(nc net.Conn, p []byte) (int, error) { return len(p) + 1, nil }, 0, "invalid count"},
		{"zero-nil", func(nc net.Conn, p []byte) (int, error) { return 0, nil }, 0, "(0, nil)"},
		{"bytes-then-error", func(nc net.Conn, p []byte) (int, error) { n, _ := nc.Read(p); return n, errBoom }, 100, "boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				var calls atomic.Int32
				c, p := hPair(t, env, func(nc net.Conn) net.Conn {
					return &hookConn{Conn: nc, onRead: func(nc net.Conn, b []byte) (int, error) {
						if calls.Add(1) == 1 {
							return tc.read(nc, b)
						}
						return nc.Read(b)
					}}
				})
				ep := &hEP{keepData: true}
				c.Start(ep, &hBell{}, StartOptions{})
				go p.sendFrames(hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(0, 100)})
				hWait(t, c)
				dead, cause, detail, _ := c.Death()
				if !dead || cause != CauseTransportError || !strings.Contains(detail, tc.detail) {
					t.Fatalf("death %v %v %q, want transport_error containing %q", dead, cause, detail, tc.detail)
				}
				hCheckReceived(t, ep, uint64(tc.delivered))
				p.close()
				if env.Budget.Used() != 0 {
					t.Fatalf("budget %d", env.Budget.Used())
				}
			})
		})
	}
}

// TestOversizeLengthNoAlloc_L42: a header claiming MaxFramePayload + 1
// bytes kills the carrier with protocol_violation without anything being
// allocated or read according to that length (heap growth well below the
// claimed size).
func TestOversizeLengthNoAlloc_L42(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		var hdr [wire.HeaderLen]byte
		h := wire.Header{Type: wire.TypeData, Fseq: env.Presets.firstFseq(), Handle: wire.SessionHandle}
		wire.PutHeader(hdr[:], &h)
		hdr[2], hdr[3], hdr[4] = 0x10, 0x00, 0x01 // Len = 1 MiB + 1 (PutHeader refuses it)
		synctest.Wait()                           // the peer's reader allocated its own buffers
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		c.Start(&hEP{}, &hBell{}, StartOptions{})
		go p.sendRaw(hdr[:])
		hWait(t, c)
		runtime.ReadMemStats(&after)
		dead, cause, detail, _ := c.Death()
		if !dead || cause != CauseProtocolViolation || !strings.Contains(detail, "header") {
			t.Fatalf("death %v %v %q", dead, cause, detail)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew >= 1<<20 {
			t.Fatalf("heap grew by %d bytes for a rejected 1 MiB + 1 header", grew)
		}
		p.close()
	})
}

// TestBigDataClassBoundary_L42 (C15): the real reader receives every
// payload n = 2^k + 30 … 2^k + 64 for k = 14, 15, 16 (around each class top:
// Get(n + LookAhead) and the read bound n + LookAhead), plus the BigData
// edges and the largest DATA a frame can carry, as one contiguous stream,
// so each Read of a big payload also takes the next frame's head along
// (look-ahead carried over). Every payload arrives intact, big ones by
// reference, and every buffer returns.
func TestBigDataClassBoundary_L42(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		ep := &hEP{keepData: true}
		c.Start(ep, &hBell{}, StartOptions{})
		var sizes []int
		for k := 14; k <= 16; k++ {
			for d := 30; d <= 64; d++ {
				sizes = append(sizes, 1<<k+d)
			}
		}
		sizes = append(sizes, BigData-1, BigData, BigData+39, BigData+40, BigData-1, 1, BigData,
			wire.MaxFramePayload-wire.DataPrefixLen, 1<<19+40, 1) // the largest DATA, a 512 KiB class edge
		var frames []hFrame
		var off uint64
		for _, n := range sizes {
			frames = append(frames, hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(off, n)})
			off += uint64(n)
		}
		if err := p.sendFrames(frames...); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if dead, cause, detail, _ := c.Death(); dead {
			t.Fatalf("died: %v %s", cause, detail)
		}
		hCheckReceived(t, ep, off)
		for i, d := range ep.received() {
			if want := sizes[i] >= BigData; d.byRef != want {
				t.Fatalf("payload %d (%d bytes): by reference %v, want %v", i, d.n, d.byRef, want)
			}
		}
		if got := c.Stats().RxBytes; got != off {
			t.Fatalf("RxBytes %d, want %d", got, off)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		if env.Budget.Used() != 0 {
			t.Fatalf("budget %d after every buffer was released", env.Budget.Used())
		}
	})
}

// TestFseqWrap_L14: with fseq preset to 2^32 − 3 in both directions, two
// carriers exchange well over 10 frames each way through the wrap (0
// included) without a violation, and the stream stays intact.
func TestFseqWrap_L14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Presets.FirstFseq = math.MaxUint32 - 2
		a, b := net.Pipe()
		ca, cb := hConn(env, a), hConn(env, b)
		src := newSource(env, 4<<10, false)
		src.offer(20 * 4 << 10)
		sink := &hEP{keepData: true}
		ca.Start(src, &hBell{}, StartOptions{})
		cb.Start(sink, &hBell{}, StartOptions{})
		// One batch carries 20 DATA frames; then DATA, PINGs and PONGs keep
		// both directions going until each side wrote ≥ 10 frames.
		for ca.Stats().Frames < 30 || cb.Stats().Frames < 10 {
			time.Sleep(60 * time.Millisecond)
			synctest.Wait()
			src.offer(4 << 10)
			ca.Wake()
		}
		synctest.Wait()
		for name, c := range map[string]*Conn{"A": ca, "B": cb} {
			if dead, cause, detail, _ := c.Death(); dead {
				t.Fatalf("%s died at the wrap: %v %s", name, cause, detail)
			}
		}
		ca.Kill(CauseLocalClose, "test end")
		hWait(t, ca)
		hWait(t, cb)
		if ca.wr.fseq > 100 || cb.rd.fseq > 100 || cb.wr.fseq > 100 || ca.rd.fseq > 100 {
			t.Fatalf("fseq did not wrap: A tx %d rx %d, B tx %d rx %d", ca.wr.fseq, ca.rd.fseq, cb.wr.fseq, cb.rd.fseq)
		}
		hCheckReceived(t, sink, src.next)
		src.chunk.Release()
	})
}

// TestStreamedFrames: frames larger than the 16 KiB stage that are not big
// DATA are streamed through it: a PING with a 40,000-byte zero pad is
// answered by a PONG echoing the pad length; extensions of 100 KiB and of
// 100 bytes with arbitrary flags and handles are CRC-checked and skipped;
// the stream continues. A non-zero byte deep in a streamed pad is a
// violation.
func TestStreamedFrames(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		ep := &hEP{keepData: true}
		c.Start(ep, &hBell{}, StartOptions{})
		synctest.Wait()
		big := make([]byte, 100<<10)
		for i := range big {
			big[i] = byte(i)
		}
		err := p.sendFrames(
			hFrame{t: wire.TypePing, payload: pingPayload(wire.Ping{ID: 9, Nonce: 99, Pad: 40000})},
			hFrame{t: 0x80, flags: 0xff, handle: 0, payload: big},
			hFrame{t: 0xfe, flags: 0x01, handle: 77, payload: big[:100]},
			hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(0, 300)},
		)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if dead, cause, detail, _ := c.Death(); dead {
			t.Fatalf("died: %v %s", cause, detail)
		}
		hCheckReceived(t, ep, 300)
		var pong *wire.Ping
		for _, f := range p.received() {
			if f.Type == wire.TypePong {
				pg, err := wire.ParsePing(f.Payload)
				if err != nil {
					t.Fatal(err)
				}
				pong = &pg
			}
		}
		if pong == nil || pong.ID != 9 || pong.Nonce != 99 || pong.Pad != 40000 {
			t.Fatalf("PONG %+v", pong)
		}
		// A streamed pad with a non-zero byte.
		bad := pingPayload(wire.Ping{ID: 10, Pad: 40000})
		bad[len(bad)-7] = 1
		go p.sendFrames(hFrame{t: wire.TypePing, payload: bad})
		hWait(t, c)
		if dead, cause, detail, _ := c.Death(); !dead || cause != CauseProtocolViolation || !strings.Contains(detail, "pad") {
			t.Fatalf("death %v %v %q", dead, cause, detail)
		}
		p.close()
	})
}

// TestReaderViolations_L43: each kind of broken input kills only the
// carrier with protocol_violation (invariant 6): an fseq gap, a CRC
// mismatch, a session frame on a carrier without a session, a handshake
// frame after establishment, a frame after the peer's CLOSE, a malformed
// CLOSE, DATA whose end overflows, and an endpoint that refuses a frame.
func TestReaderViolations_L43(t *testing.T) {
	data := dataPayload(0, 10)
	type step struct {
		frames []hFrame
		raw    []byte
	}
	crcBroken := func(fseq uint32) []byte {
		b := wire.AppendFrame(nil, wire.Header{Type: wire.TypeData, Fseq: fseq, Handle: wire.SessionHandle}, data)
		b[len(b)-1] ^= 1
		return b
	}
	overflow := make([]byte, wire.DataPrefixLen+2)
	wire.PutDataOffset(overflow, math.MaxUint64-1)
	cases := []struct {
		name        string
		sessionless bool
		epErr       bool
		steps       func(first uint32) []step
		detail      string
	}{
		{"fseq gap", false, false, func(f uint32) []step {
			return []step{{raw: wire.AppendFrame(nil, wire.Header{Type: wire.TypeData, Fseq: f + 1, Handle: wire.SessionHandle}, data)}}
		}, "fseq"},
		{"crc", false, false, func(f uint32) []step { return []step{{raw: crcBroken(f)}} }, "crc"},
		{"session frame without a session", true, false, func(uint32) []step {
			return []step{{frames: []hFrame{{t: wire.TypeData, handle: wire.SessionHandle, payload: data}}}}
		}, "without a session"},
		{"handshake frame after establishment", false, false, func(uint32) []step {
			return []step{{frames: []hFrame{{t: wire.TypeJoinAck, handle: wire.SessionHandle, payload: make([]byte, wire.JoinAckLen)}}}}
		}, "after establishment"},
		{"frame after CLOSE", false, false, func(uint32) []step {
			return []step{{frames: []hFrame{{t: wire.TypeClose, payload: []byte{1}}, {t: wire.TypePing, payload: pingPayload(wire.Ping{ID: 1})}}}}
		}, "after the peer's CLOSE"},
		{"bad CLOSE", false, false, func(uint32) []step {
			return []step{{frames: []hFrame{{t: wire.TypeClose, payload: []byte{9}}}}}
		}, "CLOSE"},
		{"DATA end overflow", false, false, func(uint32) []step {
			return []step{{frames: []hFrame{{t: wire.TypeData, handle: wire.SessionHandle, payload: overflow}}}}
		}, "DATA"},
		{"endpoint refuses", false, true, func(uint32) []step {
			return []step{{frames: []hFrame{{t: wire.TypeAck, handle: wire.SessionHandle, payload: make([]byte, wire.AckLen)}}}}
		}, "refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				c, p := hPair(t, env, nil)
				var ep Endpoint
				if !tc.sessionless {
					e := &hEP{}
					if tc.epErr {
						e.ctrlErr = errors.New("refused")
					}
					ep = e
				}
				c.Start(ep, &hBell{}, StartOptions{Sessionless: tc.sessionless})
				for _, s := range tc.steps(env.Presets.firstFseq()) {
					if s.raw != nil {
						go p.sendRaw(s.raw)
					} else {
						go p.sendFrames(s.frames...)
					}
				}
				hWait(t, c)
				dead, cause, detail, _ := c.Death()
				if !dead || cause != CauseProtocolViolation || !strings.Contains(detail, tc.detail) {
					t.Fatalf("death %v %v %q, want protocol_violation containing %q", dead, cause, detail, tc.detail)
				}
				p.close()
				if env.Budget.Used() != 0 {
					t.Fatalf("budget %d", env.Budget.Used())
				}
			})
		})
	}
}
