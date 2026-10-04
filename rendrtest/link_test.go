package rendrtest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestLinkRawBytesBothWays: arbitrary bytes (no rendr framing) cross both
// directions intact in any chunking; the per-carrier and link byte counters
// match exactly; an unframed carrier is neither session nor probe.
func TestLinkRawBytesBothWays(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "raw"})
		defer h.l.Close()
		cli, srv := h.dial()
		up := make([]byte, 300<<10)
		down := make([]byte, 200<<10)
		PRNG(1).Read(up)
		PRNG(2).Read(down)
		ru, rd := readBackground(srv), readBackground(cli)
		chunked(t, cli, up, 1, 9000)
		chunked(t, srv, down, 2, 7000)
		synctest.Wait()
		if !bytes.Equal(ru.bytes(), up) || !bytes.Equal(rd.bytes(), down) {
			t.Fatalf("received %d/%d bytes up, %d/%d down, or different bytes", len(ru.bytes()), len(up), len(rd.bytes()), len(down))
		}
		ci := h.l.Carriers()
		if len(ci) != 1 || ci[0].Up != int64(len(up)) || ci[0].Down != int64(len(down)) || ci[0].Session || ci[0].Closed {
			t.Fatalf("carrier info %+v", ci)
		}
		st := h.l.Stats()
		if st.All.Bytes != int64(len(up)+len(down)) || st.Session.Bytes != 0 || st.Probe.Bytes != 0 {
			t.Fatalf("byte counters %+v", st)
		}
		cli.Close()
		if got, err := ru.result(); err != io.EOF || len(got) != len(up) {
			t.Fatalf("passive end after the dialer's close: %d bytes, %v; want %d, EOF", len(got), err, len(up))
		}
		if !h.l.Carriers()[0].Closed {
			t.Fatal("carrier not closed after its dialer end closed")
		}
	})
}

// TestLinkGoldenFrameStream: the PREFACE and every golden frame of
// internal/wire, written in pieces of 1..97 bytes (headers split anywhere),
// arrive byte for byte; the carrier is classified by its first frame.
func TestLinkGoldenFrameStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "golden"})
		defer h.l.Close()
		frames := goldenFrames(t, 1)
		if FrameType(frames[0][0]) != FrameOpen {
			t.Fatalf("golden stream starts with %#x, want OPEN", frames[0][0])
		}
		stream := prefaceBytes(1)
		for _, f := range frames {
			stream = append(stream, f...)
		}
		cli, srv := h.dial()
		ra := readBackground(srv)
		chunked(t, cli, stream, 3, 97)
		cli.Close()
		got, err := ra.result()
		if err != io.EOF || !bytes.Equal(got, stream) {
			t.Fatalf("got %d of %d bytes (%v) or different bytes", len(got), len(stream), err)
		}
		fs := decodeAll(t, got[wire.PrefaceLen:])
		for i, f := range fs {
			if f.Fseq != uint32(1+i) {
				t.Fatalf("frame %d has fseq %d", i, f.Fseq)
			}
		}
		if ci := h.l.Carriers()[0]; ci.First != FrameOpen || !ci.Session {
			t.Fatalf("classification %+v, want First OPEN, Session", ci)
		}
		if st := h.l.Stats(); st.Session.Bytes != int64(len(stream)) || st.Probe.Bytes != 0 {
			t.Fatalf("session bytes %d, probe bytes %d; want %d, 0", st.Session.Bytes, st.Probe.Bytes, len(stream))
		}
	})
}

// TestLinkDelayJitterKeepsOrder: a fixed delay is exact; with jitter every
// byte arrives within delay ± jitter of its write and the stream order is
// kept.
func TestLinkDelayJitterKeepsOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "delay"})
		defer h.l.Close()
		h.l.SetDelay(100*time.Millisecond, 0)
		cli, srv := h.dial()
		start := time.Now()
		write(t, cli, []byte{0xAA})
		readN(t, srv, 1)
		if d := time.Since(start); d != 100*time.Millisecond {
			t.Fatalf("one-way delay %v, want 100ms", d)
		}
		h.l.SetDelay(100*time.Millisecond, 50*time.Millisecond)
		ra := readBackground(srv)
		sent := make([]time.Time, 200)
		for i := range sent {
			sent[i] = time.Now()
			write(t, cli, []byte{byte(i)})
			time.Sleep(time.Millisecond)
		}
		time.Sleep(time.Second)
		got, at := ra.bytes(), ra.times()
		if len(got) != len(sent) {
			t.Fatalf("received %d of %d bytes", len(got), len(sent))
		}
		var jittered bool
		for i, b := range got {
			if b != byte(i) {
				t.Fatalf("byte %d is %d: the stream was reordered", i, b)
			}
			d := at[i].Sub(sent[i])
			if d < 50*time.Millisecond || d > 150*time.Millisecond {
				t.Fatalf("byte %d took %v, outside 100ms ± 50ms", i, d)
			}
			jittered = jittered || d != 100*time.Millisecond
		}
		if !jittered {
			t.Fatal("no jitter was applied")
		}
		if md := h.l.Stats().All.MaxDelay; md <= 100*time.Millisecond || md > 150*time.Millisecond {
			t.Fatalf("MaxDelay %v, want in (100ms, 150ms]", md)
		}
		// A writer that closes while its bytes are still delayed in the link
		// gets them delivered first, then EOF (graceful close).
		h.l.SetDelay(100*time.Millisecond, 0)
		write(t, cli, []byte("last"))
		closedAt := time.Now()
		cli.Close()
		got, err := ra.result()
		if err != io.EOF || string(got[len(got)-4:]) != "last" || time.Since(closedAt) != 100*time.Millisecond {
			t.Fatalf("after a close with bytes in flight: %q, %v after %v", got[len(got)-4:], err, time.Since(closedAt))
		}
	})
}

// TestLinkRateSharedBottleneck: the rate limiter is one FIFO per direction
// shared by the link's carriers: a probe PING written after a session's
// 512 KiB burst waits behind the whole burst (the queueing the self-load
// guard tests rely on), and every limited byte is counted as Throttled.
func TestLinkRateSharedBottleneck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "rate"})
		defer h.l.Close()
		sCli, sSrv := h.session()
		pCli, pSrv := h.probe()
		const rate = 1 << 20
		h.l.SetRate(rate)
		var bulk []byte
		for i := range 8 {
			bulk = append(bulk, frameBytes(FrameData, uint32(2+i), dataPayload(uint64(i)<<16, make([]byte, 64<<10)))...)
		}
		ping := frameBytes(FramePing, 2, pingPayload(2))
		start := time.Now()
		rs := readBackground(sSrv)
		write(t, sCli, bulk)
		write(t, pCli, ping)
		readFrame(t, pSrv)
		pingAt := time.Since(start)
		want := time.Duration(float64(len(bulk)+len(ping)) / rate * float64(time.Second))
		if pingAt < want-time.Millisecond || pingAt > want+time.Millisecond {
			t.Fatalf("PING behind a %d-byte burst arrived after %v, want ≈ %v (one shared bottleneck)", len(bulk), pingAt, want)
		}
		time.Sleep(time.Second)
		if got := rs.bytes(); !bytes.Equal(got, bulk) {
			t.Fatalf("burst: %d of %d bytes or different bytes", len(got), len(bulk))
		}
		if th := h.l.Stats().Throttled; th != int64(len(bulk)+len(ping)) {
			t.Fatalf("Throttled %d, want %d", th, len(bulk)+len(ping))
		}
	})
}

// TestLinkKillLosesBufferedBytes: a Write returns once the link holds its
// bytes (bounded by Buffer); Kill loses exactly the bytes the far end had
// not read (BufferLost), and both conns then fail as a dead carrier does.
func TestLinkKillLosesBufferedBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const buffer = 64 << 10
		h := newHarness(t, LinkConfig{Name: "kill", Buffer: buffer})
		defer h.l.Close()
		cli, srv := h.dial()
		type res struct {
			n   int
			err error
		}
		done := make(chan res, 1)
		go func() {
			n, err := cli.Write(make([]byte, 100<<10))
			done <- res{n, err}
		}()
		synctest.Wait()
		select {
		case r := <-done:
			t.Fatalf("Write returned %v before the link buffer drained", r)
		default:
		}
		if n := h.l.Kill(); n != 1 {
			t.Fatalf("Kill = %d, want 1", n)
		}
		r := <-done
		if r.n != buffer || !errors.Is(r.err, io.ErrClosedPipe) {
			t.Fatalf("blocked Write = (%d, %v), want (%d, io.ErrClosedPipe)", r.n, r.err, buffer)
		}
		st := h.l.Stats()
		if st.All.Killed != 1 || st.All.BufferLost != buffer || st.All.Bytes != 0 {
			t.Fatalf("Killed %d, BufferLost %d, Bytes %d; want 1, %d, 0", st.All.Killed, st.All.BufferLost, st.All.Bytes, buffer)
		}
		if _, err := srv.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("passive Read after Kill: %v, want EOF", err)
		}
		if _, err := cli.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("dialer Read after Kill: %v, want EOF", err)
		}
		if h.l.Kill() != 0 || !h.l.Carriers()[0].Closed {
			t.Fatal("a killed carrier is still current")
		}
	})
}

// TestLinkStallHoldsBytes: a stall holds bytes without losing them.
func TestLinkStallHoldsBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "stall"})
		defer h.l.Close()
		cli, srv := h.dial()
		ra := readBackground(srv)
		h.l.SetStall(true)
		data := make([]byte, 10<<10)
		PRNG(4).Read(data)
		write(t, cli, data)
		time.Sleep(5 * time.Second)
		if n := len(ra.bytes()); n != 0 {
			t.Fatalf("%d bytes crossed a stalled link", n)
		}
		if st := h.l.Stats(); st.All.Held != 1 || h.l.Carriers()[0].Held != 1 {
			t.Fatalf("Held %d / carrier %d, want 1", st.All.Held, h.l.Carriers()[0].Held)
		}
		h.l.SetStall(false)
		synctest.Wait()
		if !bytes.Equal(ra.bytes(), data) {
			t.Fatal("stalled bytes were not delivered intact after the stall")
		}
	})
}

// TestLinkBlackholeDropsAndDeadDials: blackholed bytes vanish (counted, by
// class); a dial while blackholed "opens" but never reaches Accept and is
// not a carrier; lifting the blackhole delivers new bytes only.
func TestLinkBlackholeDropsAndDeadDials(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "bh"})
		defer h.l.Close()
		cli, srv := h.session()
		ra := readBackground(srv)
		h.l.SetBlackhole(true)
		lost := frameBytes(FrameData, 2, dataPayload(0, make([]byte, 1000)))
		write(t, cli, lost)
		hello := append(prefaceBytes(9), frameBytes(FrameOpen, 1, openPayload())...)
		dead, err := h.l.Dial(context.Background())
		if err != nil {
			t.Fatalf("dial while blackholed: %v", err)
		}
		write(t, dead, hello)
		synctest.Wait()
		if n := len(ra.bytes()); n != 0 {
			t.Fatalf("%d bytes crossed a blackhole", n)
		}
		select {
		case <-h.acc:
			t.Fatal("a blackholed dial reached Accept")
		default:
		}
		st := h.l.Stats()
		want := int64(len(lost) + len(hello))
		if st.All.Dropped != want || st.Session.Dropped != want || h.l.NextSeq() != 1 {
			t.Fatalf("Dropped all %d session %d, NextSeq %d; want %d, %d, 1", st.All.Dropped, st.Session.Dropped, h.l.NextSeq(), want, want)
		}
		h.l.SetBlackhole(false)
		after := frameBytes(FramePing, 3, pingPayload(3))
		write(t, cli, after)
		synctest.Wait()
		if got := ra.bytes(); !bytes.Equal(got, after) {
			t.Fatalf("after the blackhole: %x, want %x", got, after)
		}
		h.l.Kill()
		if _, err := dead.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("dead dial after Kill: %v, want EOF", err)
		}
	})
}

// TestLinkCorruptNextFlipsOneChunk: CorruptNext damages exactly one byte of
// the next chunk in its direction (M1a behaviour).
func TestLinkCorruptNextFlipsOneChunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "corrupt"})
		defer h.l.Close()
		cli, srv := h.dial()
		h.l.CorruptNext(Up)
		data := make([]byte, 1000)
		PRNG(5).Read(data)
		write(t, cli, data)
		got := readN(t, srv, len(data))
		var diff []int
		for i := range got {
			if got[i] != data[i] {
				diff = append(diff, i)
			}
		}
		if len(diff) != 1 || got[diff[0]] != data[diff[0]]^0xFF {
			t.Fatalf("corrupted positions %v, want exactly one flipped byte", diff)
		}
		write(t, cli, data)
		if !bytes.Equal(readN(t, srv, len(data)), data) {
			t.Fatal("the chunk after the corrupted one was damaged too")
		}
		if c := h.l.Stats().All.Corrupted; c != 1 {
			t.Fatalf("Corrupted %d, want 1", c)
		}
	})
}

// TestLinkDialEarlyGoesFirst: DialEarly's first bytes precede everything the
// dialer writes, and they classify the carrier before anything crossed.
func TestLinkDialEarlyGoesFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "early"})
		defer h.l.Close()
		first := append(prefaceBytes(3), frameBytes(FrameJoin, 1, make([]byte, wire.JoinLen))...)
		cli, err := h.l.DialEarly(context.Background(), first)
		if err != nil {
			t.Fatalf("DialEarly: %v", err)
		}
		if ci := h.l.Carriers()[0]; ci.First != FrameJoin || !ci.Session {
			t.Fatalf("classification %+v, want JOIN session", ci)
		}
		srv := <-h.acc
		next := frameBytes(FramePing, 2, pingPayload(5))
		write(t, cli, next)
		if got := readN(t, srv, len(first)+len(next)); !bytes.Equal(got, append(first, next...)) {
			t.Fatal("the early bytes did not precede the stream")
		}
	})
}

// TestLinkDialBehaviours: every factory misbehaviour of L51, counted.
func TestLinkDialBehaviours(t *testing.T) {
	type tc struct {
		name string
		run  func(t *testing.T, h *harness) (failed bool)
	}
	cases := []tc{
		{"normal", func(t *testing.T, h *harness) bool {
			c, err := h.l.Dial(context.Background())
			if err != nil || c == nil {
				t.Fatalf("Dial = (%v, %v)", c, err)
			}
			<-h.acc
			return false
		}},
		{"refuse", func(t *testing.T, h *harness) bool {
			h.l.SetRefuse(true)
			if c, err := h.l.Dial(context.Background()); c != nil || !errors.Is(err, errRefused) {
				t.Fatalf("refused Dial = (%v, %v)", c, err)
			}
			return true
		}},
		{"error", func(t *testing.T, h *harness) bool {
			h.l.SetDial(DialError)
			if c, err := h.l.Dial(context.Background()); c != nil || !errors.Is(err, errScripted) {
				t.Fatalf("Dial = (%v, %v)", c, err)
			}
			return true
		}},
		{"hang", func(t *testing.T, h *harness) bool {
			h.l.SetDial(DialHang)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			if c, err := h.l.Dial(ctx); c != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != time.Second {
				t.Fatalf("Dial = (%v, %v) after %v, want ctx error after 1s", c, err, time.Since(start))
			}
			return true
		}},
		{"hang-forever", func(t *testing.T, h *harness) bool {
			h.l.SetDial(DialHangForever)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan error, 1)
			go func() {
				_, err := h.l.Dial(ctx)
				done <- err
			}()
			time.Sleep(time.Hour)
			select {
			case err := <-done:
				t.Fatalf("hanging dial returned %v before Release", err)
			default:
			}
			h.l.Release()
			if err := <-done; !errors.Is(err, errReleased) {
				t.Fatalf("released dial: %v", err)
			}
			return true
		}},
		{"nil-nil", func(t *testing.T, h *harness) bool {
			h.l.SetDial(DialNilNil)
			if c, err := h.l.Dial(context.Background()); c != nil || err != nil {
				t.Fatalf("Dial = (%v, %v), want (nil, nil)", c, err)
			}
			return true
		}},
		{"panic", func(t *testing.T, h *harness) (failed bool) {
			h.l.SetDial(DialPanic)
			defer func() {
				if recover() == nil {
					t.Fatal("DialPanic did not panic")
				}
				failed = true
			}()
			h.l.Dial(context.Background())
			return false
		}},
		{"goexit", func(t *testing.T, h *harness) bool {
			h.l.SetDial(DialGoexit)
			returned, exited := false, make(chan struct{})
			go func() {
				defer close(exited)
				h.l.Dial(context.Background())
				returned = true
			}()
			<-exited
			if returned {
				t.Fatal("DialGoexit returned")
			}
			return true
		}},
		{"late-success", func(t *testing.T, h *harness) bool {
			h.l.SetDial(DialLateSuccess)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan net.Conn, 1)
			go func() {
				c, _ := h.l.Dial(ctx)
				done <- c
			}()
			time.Sleep(time.Hour)
			if h.l.NextSeq() != 0 {
				t.Fatal("late dial created a carrier before Release")
			}
			h.l.Release()
			c := <-done
			if c == nil {
				t.Fatal("late dial failed after Release")
			}
			<-h.acc
			c.Close()
			return false
		}},
		{"closed", func(t *testing.T, h *harness) bool {
			h.l.Close()
			if c, err := h.l.Dial(context.Background()); c != nil || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Dial after Close = (%v, %v)", c, err)
			}
			return true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, LinkConfig{Name: c.name})
				defer h.l.Close()
				failed := c.run(t, h)
				st := h.l.Stats()
				want := int64(0)
				if failed {
					want = 1
				}
				if st.Dials != 1 || st.DialFailures != want {
					t.Fatalf("Dials %d, DialFailures %d; want 1, %d", st.Dials, st.DialFailures, want)
				}
			})
		})
	}
}

// TestLinkCloseReleasesAndJoins: Close returns with blocked writes, hanging
// dials and in-flight bytes pending; the blocked calls return, later dials
// fail, and the bubble ends with no goroutine left.
func TestLinkCloseReleasesAndJoins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "close"})
		h.l.SetDelay(time.Hour, 0)
		cli, _ := h.dial()
		write(t, cli, []byte("in flight"))
		h.l.BlockWrites(Up, BlockHard)
		blocked := make(chan error, 1)
		go func() {
			_, err := cli.Write([]byte("blocked"))
			blocked <- err
		}()
		h.l.SetDial(DialHangForever)
		hung := make(chan error, 1)
		go func() {
			_, err := h.l.Dial(context.Background())
			hung <- err
		}()
		synctest.Wait()
		h.l.Close()
		if err := <-blocked; err == nil {
			t.Fatal("a Hard-blocked write on a closed link succeeded")
		}
		if err := <-hung; err == nil {
			t.Fatal("a hanging dial succeeded after Close")
		}
		h.l.Close() // idempotent
		if !h.l.Carriers()[0].Closed {
			t.Fatal("carrier still open after Close")
		}
	})
}

// TestLinkConnMisbehaviours: scripted write results, Soft and Hard write
// blocks, write panics and over-reads (L42, L51).
func TestLinkConnMisbehaviours(t *testing.T) {
	errX := errors.New("scripted")
	t.Run("script", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newHarness(t, LinkConfig{Name: "script"})
			defer h.l.Close()
			cli, srv := h.dial()
			ra := readBackground(srv)
			h.l.ScriptWrites(Up,
				WriteResult{N: -3, Relative: true, Transmit: true},
				WriteResult{ZeroWrite: true, N: 5, Err: errX},
				WriteResult{N: -1},
				WriteResult{N: 1, Relative: true},
				WriteResult{N: -1, Relative: true, Err: errX, Transmit: true})
			p := []byte("0123456789")
			want := []struct {
				n   int
				err error
			}{{7, nil}, {0, nil}, {-1, nil}, {11, nil}, {9, errX}, {10, nil}}
			for i, w := range want {
				if n, err := cli.Write(p); n != w.n || err != w.err {
					t.Fatalf("write %d = (%d, %v), want (%d, %v)", i, n, err, w.n, w.err)
				}
			}
			synctest.Wait()
			if got := string(ra.bytes()); got != "0123456"+"012345678"+"0123456789" {
				t.Fatalf("forwarded %q", got)
			}
		})
	})
	t.Run("block-soft", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newHarness(t, LinkConfig{Name: "soft"})
			defer h.l.Close()
			cli, _ := h.dial()
			h.l.BlockWrites(Up, BlockSoft)
			cli.SetWriteDeadline(time.Now().Add(time.Second))
			start := time.Now()
			_, err := cli.Write([]byte("x"))
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) != time.Second {
				t.Fatalf("Soft-blocked Write with a 1s deadline: %v after %v", err, time.Since(start))
			}
			cli.SetWriteDeadline(time.Time{})
			done := make(chan error, 1)
			go func() {
				_, err := cli.Write([]byte("y"))
				done <- err
			}()
			synctest.Wait()
			cli.Close()
			if err := <-done; !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("Soft-blocked Write after Close: %v", err)
			}
		})
	})
	t.Run("block-hard", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newHarness(t, LinkConfig{Name: "hard"})
			defer h.l.Close()
			cli, srv := h.dial()
			ra := readBackground(cli)
			h.l.BlockWrites(Down, BlockHard)
			done := make(chan error, 1)
			go func() {
				_, err := srv.Write([]byte("late"))
				done <- err
			}()
			synctest.Wait()
			srv.SetWriteDeadline(time.Now().Add(time.Second))
			time.Sleep(time.Hour)
			select {
			case err := <-done:
				t.Fatalf("Hard-blocked Write returned %v without Release", err)
			default:
			}
			srv.SetWriteDeadline(time.Time{})
			h.l.Release()
			if err := <-done; err != nil {
				t.Fatalf("released Write: %v", err)
			}
			synctest.Wait()
			if got := string(ra.bytes()); got != "late" {
				t.Fatalf("released Write delivered %q", got)
			}
		})
	})
	t.Run("panic-and-over-read", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newHarness(t, LinkConfig{Name: "panic"})
			defer h.l.Close()
			cli, srv := h.dial()
			h.l.PanicWrites(Up)
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("PanicWrites: the Write did not panic")
					}
				}()
				cli.Write([]byte("boom"))
			}()
			h.l.OverRead(Down)
			write(t, cli, []byte("0123456789"))
			if n, err := srv.Read(make([]byte, 4)); n != 5 || err != nil {
				t.Fatalf("over-read = (%d, %v), want (5, nil)", n, err)
			}
			if n, err := srv.Read(make([]byte, 16)); n != 6 || err != nil {
				t.Fatalf("next Read = (%d, %v), want (6, nil)", n, err)
			}
		})
	})
}

// TestLinkConcurrentControls: every control called concurrently with
// traffic on four carriers (writers, readers, a Kill at the end) neither
// races (-race) nor deadlocks (the bubble ends), and Kill ends every
// carrier.
func TestLinkConcurrentControls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, LinkConfig{Name: "concurrent", Buffer: 32 << 10})
		defer h.l.Close()
		var wg sync.WaitGroup
		for range 4 {
			cli, srv := h.session()
			wg.Go(func() {
				for j := range 300 {
					if _, err := cli.Write(frameBytes(FrameData, uint32(2+j), dataPayload(uint64(j), make([]byte, 1+j*37)))); err != nil {
						return
					}
				}
			})
			wg.Go(func() { io.Copy(io.Discard, srv) })
			wg.Go(func() { io.Copy(io.Discard, cli) })
		}
		wg.Go(func() {
			for i := range 60 {
				h.l.CorruptNextFrame(Up, FrameData, CorruptMode(1+i%3))
				h.l.DropNextFrame(Up, FrameData)
				h.l.InjectAfterNextFrame(Up, FrameData, FramePing, 0, 0, pingPayload(uint32(i)))
				h.l.InjectRaw(Down, []byte{byte(i)})
				h.l.CaptureNextFrame(Up, FrameData)
				h.l.CorruptNext(Down)
				h.l.SetDelay(time.Duration(i%5)*time.Millisecond, time.Millisecond)
				h.l.SetRate(float64(1+i%3) * (1 << 20))
				h.l.SetStall(i%2 == 0)
				h.l.BlockWrites(Up, BlockMode(i%2))
				h.l.Stats()
				h.l.Carriers()
				time.Sleep(time.Millisecond)
			}
			h.l.SetStall(false)
			h.l.BlockWrites(Up, BlockOff)
		})
		time.Sleep(time.Second)
		h.l.Kill()
		wg.Wait()
		for _, ci := range h.l.Carriers() {
			if !ci.Closed {
				t.Fatalf("carrier %d still open after Kill", ci.Seq)
			}
		}
	})
}
