package rendrtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Every test here but the allocation gate (testing.AllocsPerRun) and the
// real loopback dial runs inside a synctest bubble: a goroutine left
// blocked in a TargetConn or a behaviour when the bubble ends fails the
// test (synctest reports the deadlock), so each row also proves that
// nothing leaks.

// isReset reports whether err is ErrReset as callers see it: errors.Is
// with syscall.ECONNRESET (errConnReset is that errno on every OS but
// plan9).
func isReset(err error) bool { return errors.Is(err, ErrReset) && errors.Is(err, errConnReset) }

// writeAsync writes b and closes the returned channel with the result.
type writeResult struct {
	n   int
	err error
}

func writeAsync(c net.Conn, b []byte, closeWrite bool) <-chan writeResult {
	ch := make(chan writeResult, 1)
	go func() {
		n, err := c.Write(b)
		if closeWrite && err == nil {
			err = c.(*TargetConn).CloseWrite()
		}
		ch <- writeResult{n, err}
	}()
	return ch
}

// pending reports whether ch has not delivered yet (after the bubble
// settled).
func pending[T any](ch <-chan T) bool {
	synctest.Wait()
	select {
	case v := <-ch:
		_ = v
		return false
	default:
		return true
	}
}

// TestTargetPipeHalfClose: CloseWrite delivers the buffered bytes, then
// io.EOF, and leaves the other direction open; a Close after both FINs is
// silent on both ends.
func TestTargetPipeHalfClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s := TargetPipe(1024)
		data, reply := prngBytes(1, 10_000), prngBytes(2, 7_000)
		w := writeAsync(c, data, true)
		got, err := io.ReadAll(s)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("server read %d bytes, %v; want %d bytes then EOF", len(got), err, len(data))
		}
		if r := <-w; r.n != len(data) || r.err != nil {
			t.Fatalf("client write: %d, %v", r.n, r.err)
		}
		if n, err := s.Read(make([]byte, 8)); n != 0 || err != io.EOF {
			t.Fatalf("server read after EOF: %d, %v; want 0, EOF", n, err)
		}
		if n, err := c.Write([]byte{1}); n != 0 || err == nil || isReset(err) {
			t.Fatalf("client write after its CloseWrite: %d, %v; want a write-shut error", n, err)
		}
		// The other direction still flows.
		w = writeAsync(s, reply, true)
		got, err = io.ReadAll(c)
		if err != nil || !bytes.Equal(got, reply) {
			t.Fatalf("client read %d bytes, %v; want %d bytes then EOF", len(got), err, len(reply))
		}
		if r := <-w; r.err != nil {
			t.Fatalf("server write: %v", r.err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("client Close: %v", err)
		}
		if n, err := s.Read(make([]byte, 8)); n != 0 || err != io.EOF {
			t.Fatalf("server read after the client's silent Close: %d, %v; want EOF", n, err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("server Close: %v", err)
		}
		if err := c.Close(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second Close: %v; want net.ErrClosed", err)
		}
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after Close: %v; want net.ErrClosed", err)
		}
		if err := c.CloseWrite(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("CloseWrite after Close: %v; want net.ErrClosed", err)
		}
	})
}

// TestTargetPipeReset: SetLinger(0) then Close, a Close with unread bytes,
// and a write to a closed peer reset the other end: its Read and Write
// return ErrReset (ECONNRESET), blocked calls wake, the bytes in flight
// are gone.
func TestTargetPipeReset(t *testing.T) {
	t.Run("linger0", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			c.Write(prngBytes(1, 100))
			s.Write(prngBytes(2, 100))
			if err := c.SetLinger(0); err != nil {
				t.Fatal(err)
			}
			c.Close()
			if n, err := s.Read(make([]byte, 200)); n != 0 || !isReset(err) {
				t.Fatalf("server Read: %d, %v; want 0, ECONNRESET (the buffered bytes are gone)", n, err)
			}
			if n, err := s.Write([]byte{1}); n != 0 || !isReset(err) {
				t.Fatalf("server Write: %d, %v; want 0, ECONNRESET", n, err)
			}
			if err := s.CloseWrite(); !isReset(err) {
				t.Fatalf("server CloseWrite: %v; want ECONNRESET", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("server Close: %v", err)
			}
		})
	})
	t.Run("linger restored", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			c.SetLinger(0)
			if err := c.SetLinger(5); err != nil {
				t.Fatal(err)
			}
			c.Close() // a graceful Close again: a FIN
			if n, err := s.Read(make([]byte, 8)); n != 0 || err != io.EOF {
				t.Fatalf("server Read: %d, %v; want EOF, not a reset", n, err)
			}
			s.Close()
		})
	})
	t.Run("wakes a blocked Read", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			done := make(chan error, 1)
			go func() {
				_, err := s.Read(make([]byte, 10))
				done <- err
			}()
			if !pending(done) {
				t.Fatal("Read returned without data")
			}
			c.SetLinger(0)
			c.Close()
			if err := <-done; !isReset(err) {
				t.Fatalf("blocked Read: %v; want ECONNRESET", err)
			}
			s.Close()
		})
	})
	t.Run("wakes a blocked Write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(1024)
			w := writeAsync(s, prngBytes(3, 10_000), false)
			if !pending(w) {
				t.Fatal("Write beyond the buffer returned while nobody reads")
			}
			c.SetLinger(0)
			c.Close()
			if r := <-w; r.n != 1024 || !isReset(r.err) {
				t.Fatalf("blocked Write: %d, %v; want 1024, ECONNRESET", r.n, r.err)
			}
			s.Close()
		})
	})
	t.Run("unread bytes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			c.Write([]byte("hello"))
			s.Close() // "hello" unread: a reset
			if _, err := c.Read(make([]byte, 8)); !isReset(err) {
				t.Fatalf("client Read: %v; want ECONNRESET", err)
			}
			if _, err := c.Write([]byte{1}); !isReset(err) {
				t.Fatalf("client Write: %v; want ECONNRESET", err)
			}
			c.Close()
		})
	})
	t.Run("write after the peer closed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			c.Close() // nothing unread: a FIN
			if _, err := s.Read(make([]byte, 8)); err != io.EOF {
				t.Fatalf("server Read: %v; want EOF", err)
			}
			if n, err := s.Write([]byte("late")); n != 4 || err != nil {
				t.Fatalf("first Write to a closed peer: %d, %v; want 4, nil (as TCP)", n, err)
			}
			if _, err := s.Write([]byte{1}); !isReset(err) {
				t.Fatalf("second Write: %v; want ECONNRESET (the peer's answer)", err)
			}
			if _, err := s.Read(make([]byte, 8)); !isReset(err) {
				t.Fatalf("Read after the reset: %v; want ECONNRESET", err)
			}
			s.Close()
		})
	})
}

// TestTargetPipeCloseAfterCloseWriteSilent (R1-3): a Close after CloseWrite
// with nothing unread is invisible to the other end (its buffered bytes
// still arrive, then EOF, and no reset ever follows); with unread bytes it
// is a reset.
func TestTargetPipeCloseAfterCloseWriteSilent(t *testing.T) {
	t.Run("silent", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(64 << 10)
			data := prngBytes(4, 20_000)
			c.Write(data)
			c.CloseWrite()
			if err := c.Close(); err != nil { // the 20,000 bytes are still in flight
				t.Fatal(err)
			}
			got, err := io.ReadAll(s)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("server read %d bytes, %v; want %d then EOF", len(got), err, len(data))
			}
			time.Sleep(time.Hour)
			if _, err := s.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("server Read an hour later: %v; want EOF, never a reset", err)
			}
			if err := s.CloseWrite(); err != nil {
				t.Fatalf("server CloseWrite: %v; the server end must not be reset", err)
			}
			s.Close()
		})
	})
	t.Run("silent to a stalled target", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetStall(), 0)
			c, _ := tg.Dial(t.Context(), "stall:1")
			c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			c.(*TargetConn).CloseWrite()
			c.Close()
			time.Sleep(time.Hour)
			synctest.Wait()
			k := tg.Counts()
			if k.Open != 1 || k.RSTIn != 0 || k.FINIn != 1 {
				t.Fatalf("counts after the client's Close: %+v; want the target still open, FIN in, no reset", k)
			}
			tg.Close()
			k = tg.Counts()
			// The target's reset still leaves, although the client is gone.
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "stall:1", BytesIn: 18, FINIn: true, RSTOut: true})
		})
	})
	t.Run("unread bytes reset", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(64 << 10)
			s.Write([]byte("answer")) // the client never reads it
			c.CloseWrite()
			if _, err := s.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("server Read: %v; want EOF", err)
			}
			c.Close()
			if _, err := s.Read(make([]byte, 1)); !isReset(err) {
				t.Fatalf("server Read after the Close with unread bytes: %v; want ECONNRESET", err)
			}
			s.Close()
		})
	})
}

// TestTargetPipeBackpressure: each direction holds exactly buf bytes, a
// writer blocks until the reader takes them, and the deadlines cut a
// blocked call at their instant (virtual time).
func TestTargetPipeBackpressure(t *testing.T) {
	t.Run("bounded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			data := prngBytes(5, 10_240)
			w := writeAsync(c, data, false)
			var got []byte
			buf := make([]byte, 64<<10)
			for i, want := range []int{4096, 4096, 2048} {
				if i < 2 && !pending(w) {
					t.Fatalf("Write returned with %d of %d bytes read", len(got), len(data))
				}
				n, err := s.Read(buf)
				if n != want || err != nil {
					t.Fatalf("Read: %d, %v; want %d (the buffer's bound)", n, err, want)
				}
				got = append(got, buf[:n]...)
			}
			if r := <-w; r.n != len(data) || r.err != nil {
				t.Fatalf("Write: %d, %v", r.n, r.err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("bytes differ")
			}
			c.Close()
			s.Close()
		})
	})
	t.Run("write deadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			start := time.Now()
			c.SetWriteDeadline(start.Add(50 * time.Millisecond))
			n, err := c.Write(make([]byte, 10_240))
			var ne net.Error
			if n != 4096 || !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("Write: %d, %v; want 4096, a timeout", n, err)
			}
			if d := time.Since(start); d != 50*time.Millisecond {
				t.Fatalf("Write returned after %v; want 50ms", d)
			}
			c.SetWriteDeadline(time.Time{})
			if n, err := s.Read(make([]byte, 8192)); n != 4096 || err != nil {
				t.Fatalf("Read: %d, %v", n, err)
			}
			if n, err := c.Write(make([]byte, 100)); n != 100 || err != nil {
				t.Fatalf("Write after clearing the deadline: %d, %v", n, err)
			}
			c.Close()
			s.Close()
		})
	})
	t.Run("past deadline wakes blocked calls", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			rd := make(chan error, 1)
			go func() {
				_, err := s.Read(make([]byte, 8))
				rd <- err
			}()
			w := writeAsync(s, make([]byte, 10_240), false) // c never reads
			time.Sleep(time.Second)
			synctest.Wait()
			if len(rd) != 0 || len(w) != 0 {
				t.Fatal("a Read without data or a Write beyond the buffer returned")
			}
			at := time.Now() // no timer fires from here on: virtual time stays
			s.SetReadDeadline(at)
			s.SetWriteDeadline(at)
			synctest.Wait()
			select {
			case err := <-rd:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("blocked Read: %v; want a timeout", err)
				}
			default:
				t.Fatal("a deadline in the past did not wake the blocked Read")
			}
			select {
			case r := <-w:
				if r.n != 4096 || !errors.Is(r.err, os.ErrDeadlineExceeded) {
					t.Fatalf("blocked Write: %d, %v; want 4096, a timeout", r.n, r.err)
				}
			default:
				t.Fatal("a deadline in the past did not wake the blocked Write")
			}
			if !time.Now().Equal(at) {
				t.Fatalf("woken %v after the deadline; want at once", time.Since(at))
			}
			c.Close()
			s.Close()
		})
	})
	t.Run("read deadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			start := time.Now()
			s.SetReadDeadline(start.Add(50 * time.Millisecond))
			go func() {
				time.Sleep(20 * time.Millisecond)
				s.SetReadDeadline(start.Add(100 * time.Millisecond)) // extended while blocked
			}()
			if _, err := s.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read: %v; want a timeout", err)
			}
			if d := time.Since(start); d != 100*time.Millisecond {
				t.Fatalf("Read returned after %v; want 100ms (the extended deadline)", d)
			}
			c.Write([]byte("x"))
			if _, err := s.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read with data past the deadline: %v; want a timeout", err)
			}
			s.SetDeadline(time.Time{})
			if n, err := s.Read(make([]byte, 8)); n != 1 || err != nil {
				t.Fatalf("Read after clearing: %d, %v", n, err)
			}
			c.Close()
			s.Close()
		})
	})
}

// dialTarget dials tg inside a test.
func dialTarget(t *testing.T, tg *Target, addr string) *TargetConn {
	t.Helper()
	c, err := tg.Dial(t.Context(), addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return c.(*TargetConn)
}

// settledCounts waits for the bubble to settle and returns the counts.
func settledCounts(tg *Target) TargetCounts {
	synctest.Wait()
	return tg.Counts()
}

// checkConn compares one connection's record with the expected one (SHA
// fields only when the expected value is non-zero).
func checkConn(t *testing.T, got, want TargetConnCounts) {
	t.Helper()
	if want.SHAIn == ([32]byte{}) {
		want.SHAIn = got.SHAIn
	}
	if want.SHAOut == ([32]byte{}) {
		want.SHAOut = got.SHAOut
	}
	if got != want {
		t.Fatalf("connection counts:\n got %+v\nwant %+v", got, want)
	}
}

func prngDigest(t *testing.T, seed uint64, n int64) [32]byte {
	t.Helper()
	d, err := Digest(PRNG(seed), n)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestTargetBehaviours: each behaviour does what its doc says, and the
// counters (bytes, SHA-256 per direction, FIN and RST each way, Open)
// record it exactly.
func TestTargetBehaviours(t *testing.T) {
	empty := sha256.Sum256(nil)
	t.Run("echo", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetEcho(), 4096)
			c := dialTarget(t, tg, "echo:7")
			data := prngBytes(6, 300<<10)
			w := writeAsync(c, data, true)
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("echo: %d bytes, %v", len(got), err)
			}
			<-w
			c.Close()
			k := settledCounts(tg)
			sum := sha256.Sum256(data)
			if k.Accepted != 1 || k.Open != 0 || k.FINIn != 1 || k.FINOut != 1 || k.RSTIn != 0 || k.RSTOut != 0 {
				t.Fatalf("totals: %+v", k)
			}
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "echo:7", BytesIn: int64(len(data)), BytesOut: int64(len(data)),
				SHAIn: sum, SHAOut: sum, FINIn: true, FINOut: true})
		})
	})
	t.Run("gen", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const n = 1 << 20
			tg := NewTarget(TargetGen(n, 7), 0)
			c := dialTarget(t, tg, "gen")
			if err := NewVerifier(7, n).ReadAll(c); err != nil {
				t.Fatalf("gen stream: %v", err)
			}
			if k := settledCounts(tg); k.Open != 1 {
				t.Fatalf("Gen closed before the client's FIN: %+v", k)
			}
			c.Write([]byte("ignored"))
			c.CloseWrite()
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "gen", BytesIn: 7, BytesOut: n,
				SHAOut: prngDigest(t, 7, n), FINIn: true, FINOut: true})
			c.Close()
		})
	})
	t.Run("sink", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetSink(), 4096)
			c := dialTarget(t, tg, "sink")
			data := prngBytes(8, 100<<10)
			w := writeAsync(c, data, true)
			if got, err := io.ReadAll(c); len(got) != 0 || err != nil {
				t.Fatalf("sink answered %d bytes, %v; want only a FIN", len(got), err)
			}
			<-w
			c.Close()
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "sink", BytesIn: int64(len(data)),
				SHAIn: sha256.Sum256(data), SHAOut: empty, FINIn: true, FINOut: true})
		})
	})
	t.Run("stall", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetStall(), 0)
			c := dialTarget(t, tg, "stall")
			c.Write(make([]byte, 10_000))
			c.CloseWrite()
			time.Sleep(time.Hour)
			if k := settledCounts(tg); k.Open != 1 || k.BytesIn != 10_000 || k.FINOut != 0 {
				t.Fatalf("stall: %+v; want held open after reading 10,000 bytes", k)
			}
			c.SetLinger(0)
			c.Close()
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "stall", BytesIn: 10_000, FINIn: true, RSTIn: true})
		})
	})
	t.Run("noread", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetNoRead(), 4096)
			c := dialTarget(t, tg, "noread")
			w := writeAsync(c, make([]byte, 10_000), false)
			time.Sleep(time.Hour)
			if !pending(w) {
				t.Fatal("a Write beyond the buffer completed: the target read")
			}
			if k := tg.Counts(); k.Open != 1 || k.BytesIn != 0 {
				t.Fatalf("noread: %+v", k)
			}
			c.SetLinger(0)
			c.Close()
			if r := <-w; r.n != 4096 || !errors.Is(r.err, net.ErrClosed) {
				t.Fatalf("client Write: %d, %v; want 4096, net.ErrClosed", r.n, r.err)
			}
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "noread", RSTIn: true})
		})
	})
	t.Run("rstafter", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const n = 100 << 10
			tg := NewTarget(TargetRSTAfter(n), 4096)
			c := dialTarget(t, tg, "rst")
			c.Write([]byte("request"))
			// A slow reader: the target finishes each write while the
			// client sleeps, so a reset before the client read the last
			// bytes would cut them.
			var got []byte
			buf := make([]byte, 1000)
			var err error
			for err == nil {
				var k int
				k, err = c.Read(buf)
				got = append(got, buf[:k]...)
				time.Sleep(time.Millisecond)
			}
			if int64(len(got)) != n || !isReset(err) {
				t.Fatalf("client read %d bytes, %v; want %d bytes then ECONNRESET, never EOF", len(got), err, n)
			}
			if sha256.Sum256(got) != prngDigest(t, 0, n) {
				t.Fatal("rstafter stream differs from PRNG(0)")
			}
			c.Close()
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "rst", BytesIn: 7, BytesOut: n,
				SHAIn: sha256.Sum256([]byte("request")), RSTOut: true})
		})
	})
	t.Run("half", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const n = 70 << 10
			tg := NewTarget(TargetHalf(n), 4096)
			c := dialTarget(t, tg, "half")
			data := prngBytes(9, 50<<10)
			w := writeAsync(c, data, true)
			<-w
			got, err := io.ReadAll(c)
			if int64(len(got)) != n || err != nil {
				t.Fatalf("half answered %d bytes, %v", len(got), err)
			}
			c.Close()
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "half", BytesIn: int64(len(data)), BytesOut: n,
				SHAIn: sha256.Sum256(data), SHAOut: prngDigest(t, 0, n), FINIn: true, FINOut: true})
		})
	})
	t.Run("reqresp", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetReqResp(1000, 5000), 4096)
			c := dialTarget(t, tg, "rr")
			c.Write(make([]byte, 1000))
			got := make([]byte, 6000)
			n, err := io.ReadFull(c, got)
			if n != 5000 || err != io.ErrUnexpectedEOF {
				t.Fatalf("answer: %d bytes, %v; want 5000 bytes then EOF", n, err)
			}
			if k := settledCounts(tg); k.Open != 1 {
				t.Fatal("ReqResp closed before the client's FIN")
			}
			c.CloseWrite()
			c.Close()
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "rr", BytesIn: 1000, BytesOut: 5000,
				SHAOut: prngDigest(t, 0, 5000), FINIn: true, FINOut: true})
			// A FIN before the request is complete: a FIN alone.
			c = dialTarget(t, tg, "rr2")
			c.Write(make([]byte, 10))
			c.CloseWrite()
			if got, err := io.ReadAll(c); len(got) != 0 || err != nil {
				t.Fatalf("short request answered %d bytes, %v", len(got), err)
			}
			c.Close()
			k = settledCounts(tg)
			checkConn(t, k.Conns[1], TargetConnCounts{Addr: "rr2", BytesIn: 10, SHAOut: empty, FINIn: true, FINOut: true})
		})
	})
	t.Run("ignorefin", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetIgnoreFIN(), 0)
			c := dialTarget(t, tg, "ignorefin")
			c.CloseWrite()
			start := time.Now()
			buf := make([]byte, 4096)
			for i := range 5 {
				n, err := c.Read(buf)
				if n != ignoreFINChunk || err != nil {
					t.Fatalf("chunk %d: %d, %v", i, n, err)
				}
				if d := time.Since(start); d != time.Duration(i)*100*time.Millisecond {
					t.Fatalf("chunk %d at %v; want %v", i, d, time.Duration(i)*100*time.Millisecond)
				}
			}
			c.Close() // nothing unread: a FIN; the next chunk is answered with a reset
			time.Sleep(100 * time.Millisecond)
			k := settledCounts(tg)
			checkConn(t, k.Conns[0], TargetConnCounts{Addr: "ignorefin", BytesOut: 6 * ignoreFINChunk,
				SHAIn: empty, FINIn: true, RSTIn: true})
		})
	})
	t.Run("dial", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetEcho(), 0)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if c, err := tg.Dial(ctx, "a"); c != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("Dial with a done ctx: %v, %v", c, err)
			}
			c := dialTarget(t, tg, "b")
			tg.Close() // resets the held connection
			if _, err := c.Read(make([]byte, 1)); !isReset(err) {
				t.Fatalf("Read after Target.Close: %v; want ECONNRESET", err)
			}
			c.Close()
			if _, err := tg.Dial(t.Context(), "c"); !errors.Is(err, errConnRefused) {
				t.Fatalf("Dial after Close: %v; want refused", err)
			}
			if k := tg.Counts(); k.Accepted != 1 || k.Open != 0 || k.RSTOut != 1 {
				t.Fatalf("counts: %+v", k)
			}
		})
	})
}

// TestScriptedDial: each outcome fails, hangs, panics or connects as its
// doc says; the script advances per call and repeats its last outcome;
// the counters see every call and every returned conn until its Close.
func TestScriptedDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tg := NewTarget(TargetEcho(), 0)
		dial, counts := ScriptedDial(
			OutcomeRefuse(), OutcomeNetUnreachable(), OutcomeHostUnreachable(),
			OutcomeHang(), OutcomeIgnoreCtx(2*time.Second), OutcomeLate(2*time.Second),
			OutcomeDNSNotFound(), OutcomeDNSFailure(), OutcomePanic(), OutcomeGoexit(),
			OutcomeNilNil(), OutcomeOK(tg),
		)
		call := func(timeout time.Duration) (c net.Conn, err error, took time.Duration, panicked any, returned bool) {
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			start := time.Now()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { panicked = recover() }()
				c, err = dial(ctx, "target.test:80")
				returned = true
			}()
			<-done
			return c, err, time.Since(start), panicked, returned
		}
		for _, want := range []error{errConnRefused, errNetUnreach, errHostUnreach} {
			c, err, _, _, _ := call(time.Second)
			var oe *net.OpError
			if c != nil || !errors.Is(err, want) || !errors.As(err, &oe) || oe.Op != "dial" {
				t.Fatalf("errno outcome: %v, %v; want a dial *net.OpError with %v", c, err, want)
			}
		}
		if errConnRefused == errNetUnreach || errNetUnreach == errHostUnreach {
			t.Fatal("the errno outcomes are not distinct")
		}
		if c, err, took, _, _ := call(time.Second); c != nil || !errors.Is(err, context.DeadlineExceeded) || took != time.Second {
			t.Fatalf("Hang: %v, %v after %v; want ctx's error at 1s", c, err, took)
		}
		if c, err, took, _, _ := call(time.Second); c != nil || err == nil || took != 2*time.Second {
			t.Fatalf("IgnoreCtx: %v, %v after %v; want a failure at 2s", c, err, took)
		}
		c, err, took, _, _ := call(time.Second)
		if c == nil || err != nil || took != 2*time.Second || counts.Unclosed() != 1 {
			t.Fatalf("Late: %v, %v after %v, unclosed %d; want a conn at 2s", c, err, took, counts.Unclosed())
		}
		c.Close()
		if counts.Unclosed() != 0 {
			t.Fatalf("unclosed after Close: %d", counts.Unclosed())
		}
		var de *net.DNSError
		if _, err, _, _, _ := call(time.Second); !errors.As(err, &de) || !de.IsNotFound || de.Name != "target.test" {
			t.Fatalf("DNSNotFound: %v", err)
		}
		if _, err, _, _, _ := call(time.Second); !errors.As(err, &de) || de.IsNotFound || !de.IsTemporary {
			t.Fatalf("DNSFailure: %v", err)
		}
		if _, _, _, p, _ := call(time.Second); p == nil {
			t.Fatal("Panic did not panic")
		}
		if _, _, _, p, returned := call(time.Second); p != nil || returned {
			t.Fatalf("Goexit: panicked %v, returned %v; want neither", p, returned)
		}
		if c, err, _, _, returned := call(time.Second); c != nil || err != nil || !returned {
			t.Fatalf("NilNil: %v, %v", c, err)
		}
		for i := range 2 { // OK, then OK again: the last outcome repeats
			c, err, _, _, _ := call(time.Second)
			if err != nil || c == nil {
				t.Fatalf("OK %d: %v", i, err)
			}
			c.Write([]byte("ping"))
			c.(*TargetConn).CloseWrite()
			if got, _ := io.ReadAll(c); string(got) != "ping" {
				t.Fatalf("OK %d echoed %q", i, got)
			}
		}
		if counts.Unclosed() != 2 {
			t.Fatalf("unclosed: %d; want the two OK conns", counts.Unclosed())
		}
		if k := settledCounts(tg); k.Accepted != 2 || k.Conns[1].Addr != "target.test:80" {
			t.Fatalf("target counts: %+v", k)
		}
		if counts.Calls() != 13 {
			t.Fatalf("calls: %d; want 13", counts.Calls())
		}
		tg.Close()
		if counts.Unclosed() != 2 {
			t.Fatal("Target.Close closed the client ends")
		}

		none, nc := ScriptedDial()
		var calls atomic.Int64
		for range 2 {
			if c, err := none(t.Context(), "x"); c != nil || err == nil {
				t.Fatalf("empty script: %v, %v", c, err)
			}
			calls.Add(1)
		}
		if nc.Calls() != calls.Load() {
			t.Fatalf("empty script calls: %d", nc.Calls())
		}
	})
}

// TestTargetPipeSteadyStateAllocs: once a pipe's buffers exist, Writes and
// the Reads that take them allocate nothing (l4's zero-allocation gate
// runs Forward over TargetPipes).
func TestTargetPipeSteadyStateAllocs(t *testing.T) {
	c, s := TargetPipe(4096)
	b, r := make([]byte, 1024), make([]byte, 1024)
	c.Write(b)
	s.Read(r)
	s.Write(b)
	c.Read(r)
	if n := testing.AllocsPerRun(1000, func() {
		c.Write(b)
		s.Read(r)
		s.Write(b)
		c.Read(r)
	}); n != 0 {
		t.Fatalf("%.1f allocations per round trip; want 0", n)
	}
	c.Close()
	s.Close()
}

// pipeStats gives the server end of a plain TargetPipe a Target's counters.
func pipeStats(s *TargetConn) *connStats {
	st := &connStats{mu: new(sync.Mutex), srv: s, hin: sha256.New(), hout: sha256.New(), open: true}
	s.p.mu.Lock()
	s.p.st[s.side] = st
	s.p.mu.Unlock()
	return st
}

// snapshot copies st's flags and byte counts under its lock.
func (s *connStats) snapshot() TargetConnCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return TargetConnCounts{BytesIn: s.bytesIn, BytesOut: s.bytesOut, FINIn: s.finIn, FINOut: s.finOut,
		RSTIn: s.rstIn, RSTOut: s.rstOut, Open: s.open}
}

// TestTargetPipeCloseAfterPeerClosedCounts: a Close after the peer's Close
// records what TCP would send (FIN, or RST with SetLinger(0) or unread
// bytes), although the peer no longer observes it.
func TestTargetPipeCloseAfterPeerClosedCounts(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(c, s *TargetConn)
		want TargetConnCounts
	}{
		{"fin", func(c, s *TargetConn) {
			c.Close()
			s.Read(make([]byte, 1))
			s.Close()
		}, TargetConnCounts{FINIn: true, FINOut: true}},
		{"linger0", func(c, s *TargetConn) {
			c.Close()
			s.SetLinger(0)
			s.Close()
		}, TargetConnCounts{FINIn: true, RSTOut: true}},
		{"unread bytes", func(c, s *TargetConn) {
			c.Write([]byte("hello"))
			c.CloseWrite()
			c.Close() // silent: "hello" is still in flight
			s.Close() // unread: an RST
		}, TargetConnCounts{FINIn: true, RSTOut: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, s := TargetPipe(4096)
				st := pipeStats(s)
				tc.run(c, s)
				if got := st.snapshot(); got != tc.want {
					t.Fatalf("counts:\n got %+v\nwant %+v", got, tc.want)
				}
			})
		})
	}
}

// TestTargetRSTAfterCountsBufferedInput: TargetRSTAfter's reset reads what
// the client's Writes accepted before it, so BytesIn does not depend on
// when the discarding goroutine ran.
func TestTargetRSTAfterCountsBufferedInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s := TargetPipe(4096)
		st := pipeStats(s)
		if n, err := c.Write([]byte("late")); n != 4 || err != nil { // nobody has read it
			t.Fatalf("Write: %d, %v", n, err)
		}
		s.resetTakingInput()
		if got := st.snapshot(); got != (TargetConnCounts{BytesIn: 4, RSTOut: true}) {
			t.Fatalf("counts: %+v; want the 4 accepted bytes read, then RST out", got)
		}
		if _, err := c.Read(make([]byte, 8)); !isReset(err) {
			t.Fatalf("client Read: %v; want ECONNRESET", err)
		}
		c.Close()
	})
}

// released reports whether both of c's pipe buffers are gone.
func released(c *TargetConn) bool {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	return c.p.dir[0].buf == nil && c.p.dir[1].buf == nil
}

// TestTargetPipeReleasesBuffers: a pipe keeps its buffers while an open
// end may still read them, and drops them once both ends are closed; a
// Target's record of a finished connection does not keep the pipe.
func TestTargetPipeReleasesBuffers(t *testing.T) {
	t.Run("graceful", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			data := prngBytes(10, 1000)
			c.Write(data)
			c.CloseWrite()
			c.Close() // silent; the 1,000 bytes stay readable
			if released(s) {
				t.Fatal("buffers released while the server end can still read them")
			}
			if got, err := io.ReadAll(s); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("server read %d bytes, %v", len(got), err)
			}
			s.Close()
			if !released(s) {
				t.Fatal("buffers kept after both ends closed")
			}
		})
	})
	t.Run("reset", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, s := TargetPipe(4096)
			c.Write([]byte("hello"))
			s.Write([]byte("world"))
			s.Close() // unread "hello": a reset
			c.Close()
			if !released(c) {
				t.Fatal("buffers kept after a reset and both Closes")
			}
		})
	})
	t.Run("target", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tg := NewTarget(TargetEcho(), 0)
			var conns []*TargetConn
			for range 3 {
				c := dialTarget(t, tg, "echo")
				w := writeAsync(c, prngBytes(11, 16<<10), true)
				io.ReadAll(c)
				<-w
				c.Close()
				conns = append(conns, c)
			}
			synctest.Wait()
			tg.mu.Lock()
			for k, s := range tg.conns {
				if s.srv != nil {
					t.Errorf("connection %d: the record still holds its closed server end", k)
				}
			}
			tg.mu.Unlock()
			for k, c := range conns {
				if !released(c) {
					t.Errorf("connection %d: buffers kept after both ends closed", k)
				}
			}
			if k := tg.Counts(); k.Accepted != 3 || k.Open != 0 || k.BytesIn != 3*16<<10 {
				t.Fatalf("counts: %+v", k)
			}
			tg.Close()
		})
	})
}
