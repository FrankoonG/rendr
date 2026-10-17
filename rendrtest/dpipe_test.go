package rendrtest

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The contract of DatagramPipe and its DatagramConn ends (M6 design
// §A2.3, §A16.1 row WP3): boundaries kept; zero-length datagrams;
// injection once and persistent; both truncation modes; the queue bound,
// seeded loss and duplication, delay; deadlines as net.Conn; counters;
// Close joins; durable blocking inside a synctest bubble; no allocation in
// steady state.

// dpData returns size deterministic bytes for datagram k of tag; from 3
// bytes on they name both (dpKey), so datagrams of one test never collide.
func dpData(tag byte, k, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(int(tag)*31 + k*17 + i*7 + i>>8)
	}
	if size >= 3 {
		b[0], b[1], b[2] = tag, byte(k>>8), byte(k)
	}
	return b
}

// dpKey returns the tag and index dpData wrote into b (len(b) >= 3).
func dpKey(b []byte) (tag byte, k int) { return b[0], int(b[1])<<8 | int(b[2]) }

// dpRecv reads one datagram from c (into a 64-KiB buffer).
func dpRecv(t *testing.T, c net.Conn) []byte {
	t.Helper()
	buf := make([]byte, 64<<10)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return buf[:n]
}

// dpQuiet asserts that nothing is readable at c within d.
func dpQuiet(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64<<10)
	if n, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %d, %v; want a timeout (nothing readable)", n, err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
}

func dpWrite(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if n, err := c.Write(b); n != len(b) || err != nil {
		t.Fatalf("Write(%d bytes) = %d, %v", len(b), n, err)
	}
}

// dpReadAsync reads once from c in a goroutine and reports the outcome.
type dpResult struct {
	b   []byte
	err error
	at  time.Time
}

func dpReadAsync(c net.Conn) <-chan dpResult {
	ch := make(chan dpResult, 1)
	go func() {
		buf := make([]byte, 64<<10)
		n, err := c.Read(buf)
		ch <- dpResult{buf[:n], err, time.Now()}
	}()
	return ch
}

// dpBlocked asserts that the read behind ch has not returned: with every
// goroutine of the bubble durably blocked, it would have.
func dpBlocked(t *testing.T, ch <-chan dpResult) {
	t.Helper()
	synctest.Wait()
	select {
	case r := <-ch:
		t.Fatalf("Read returned %d bytes, %v; want it blocked", len(r.b), r.err)
	default:
	}
}

// dpMonotonic reports whether t carries a monotonic clock reading (Round(0)
// strips it and so changes the value).
func dpMonotonic(t time.Time) bool { return t != t.Round(0) }

func dpCounts(t *testing.T, c *DatagramConn, want DatagramConnCounts) {
	t.Helper()
	if got := c.Counts(); got != want {
		t.Fatalf("Counts = %+v; want %+v", got, want)
	}
}

func TestDatagramPipeContract(t *testing.T) {
	// Each Write is one datagram, delivered whole and alone, in order, both
	// ways; the caller's buffer is copied (overwriting it later changes
	// nothing).
	t.Run("boundaries", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sizes := []int{0, 1, 5, 11, 257, 1400, 9000, 65507}
			a, b := NewDatagramPipe(DatagramPipeConfig{})
			for dir, ends := range [2][2]*DatagramConn{{a, b}, {b, a}} {
				w, r := ends[0], ends[1]
				scratch := make([]byte, 64<<10)
				for k, n := range sizes {
					dpWrite(t, w, append(scratch[:0], dpData(byte(dir), k, n)...))
				}
				clear(scratch)
				for k, n := range sizes {
					if got := dpRecv(t, r); !bytes.Equal(got, dpData(byte(dir), k, n)) {
						t.Fatalf("dir %d datagram %d: got %d bytes, want %d intact", dir, k, len(got), n)
					}
				}
				dpQuiet(t, r, time.Millisecond)
			}
			k := uint64(len(sizes))
			dpCounts(t, a, DatagramConnCounts{In: k, Out: k})
			dpCounts(t, b, DatagramConnCounts{In: k, Out: k})
		})
	})

	// A zero-length datagram is a datagram; a Read into an empty buffer
	// returns (0, nil) at once and consumes nothing (the net package's
	// rule).
	t.Run("zero-length", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := NewDatagramPipe(DatagramPipeConfig{})
			dpWrite(t, a, nil)
			dpWrite(t, a, []byte{})
			dpWrite(t, a, []byte("abc"))
			buf := make([]byte, 16)
			for i := range 2 {
				if n, err := b.Read(buf); n != 0 || err != nil {
					t.Fatalf("Read %d of a zero-length datagram = %d, %v; want 0, nil", i, n, err)
				}
			}
			if n, err := b.Read(nil); n != 0 || err != nil {
				t.Fatalf("Read(nil) = %d, %v; want 0, nil", n, err)
			}
			if got := dpRecv(t, b); string(got) != "abc" {
				t.Fatalf("after Read(nil): %q; want the queued datagram", got)
			}
			dpCounts(t, b, DatagramConnCounts{In: 3})
			dpCounts(t, a, DatagramConnCounts{Out: 3})
		})
	})

	// A datagram longer than the Read's buffer: n = len(b), the rest
	// discarded; TruncWindows also returns ErrMsgSize. A datagram of
	// exactly len(b) is not truncated.
	t.Run("truncation", func(t *testing.T) {
		for _, mode := range []TruncMode{TruncLinux, TruncWindows} {
			t.Run([]string{"linux", "windows"}[mode], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					a, b := NewDatagramPipe(DatagramPipeConfig{Trunc: mode})
					long, next, exact := dpData(1, 0, 100), dpData(1, 1, 20), dpData(1, 2, 10)
					dpWrite(t, a, long)
					dpWrite(t, a, next)
					dpWrite(t, a, exact)
					buf := make([]byte, 10)
					n, err := b.Read(buf)
					if n != len(buf) || !bytes.Equal(buf, long[:10]) {
						t.Fatalf("mode %d: truncated Read = %d, %x; want 10 bytes, the datagram's head", mode, n, buf)
					}
					var oe *net.OpError
					switch {
					case mode == TruncLinux && err != nil:
						t.Fatalf("TruncLinux: err = %v; want nil", err)
					case mode == TruncWindows && (!errors.Is(err, ErrMsgSize) || !errors.As(err, &oe) || oe.Op != "read"):
						t.Fatalf("TruncWindows: err = %v; want a read *net.OpError matching ErrMsgSize", err)
					}
					if got := dpRecv(t, b); !bytes.Equal(got, next) {
						t.Fatalf("mode %d: after the truncated read got %d bytes; want the next datagram (the rest discarded)", mode, len(got))
					}
					if n, err := b.Read(buf); n != 10 || err != nil || !bytes.Equal(buf, exact) {
						t.Fatalf("mode %d: exact-size Read = %d, %v; want 10, nil", mode, n, err)
					}
					dpCounts(t, b, DatagramConnCounts{In: 3, Truncated: 1})
				})
			})
		}
	})

	// Inject: the next Read returns the error as given, consuming nothing;
	// persistent: every Read until cleared; it wakes a waiting Read. A
	// passed read deadline comes first, as on a real socket.
	t.Run("read-injection", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := NewDatagramPipe(DatagramPipeConfig{})
			once, always, late := errors.New("once"), errors.New("persistent"), errors.New("late")
			d := dpData(2, 0, 64)
			dpWrite(t, a, d)
			b.Inject(once, false)
			buf := make([]byte, 128)
			if n, err := b.Read(buf); n != 0 || err != once {
				t.Fatalf("injected Read = %d, %v; want 0, %v", n, err, once)
			}
			if got := dpRecv(t, b); !bytes.Equal(got, d) {
				t.Fatal("the injected Read consumed the queued datagram")
			}
			dpWrite(t, a, d)
			b.Inject(always, true)
			for i := range 5 {
				if n, err := b.Read(buf); n != 0 || err != always {
					t.Fatalf("persistent Read %d = %d, %v; want 0, %v", i, n, err, always)
				}
			}
			if err := b.SetReadDeadline(time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read past the deadline with an injection = %v; want the timeout first", err)
			}
			b.SetReadDeadline(time.Time{})
			b.Inject(nil, false)
			if got := dpRecv(t, b); !bytes.Equal(got, d) {
				t.Fatal("after clearing the injection: not the queued datagram")
			}
			ch := dpReadAsync(b)
			dpBlocked(t, ch)
			b.Inject(late, false)
			if r := <-ch; r.err != late {
				t.Fatalf("a waiting Read woken by Inject returned %v; want %v", r.err, late)
			}
			dpCounts(t, b, DatagramConnCounts{In: 2, Injected: 7})
		})
	})

	// InjectWrite: the next n Writes return the error and send nothing.
	t.Run("write-injection", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := NewDatagramPipe(DatagramPipeConfig{})
			e := errors.New("enobufs")
			a.InjectWrite(e, 2)
			for i := range 2 {
				if n, err := a.Write(dpData(3, i, 50)); n != 0 || err != e {
					t.Fatalf("injected Write %d = %d, %v; want 0, %v", i, n, err, e)
				}
			}
			d := dpData(3, 2, 50)
			dpWrite(t, a, d)
			if got := dpRecv(t, b); !bytes.Equal(got, d) {
				t.Fatal("the first datagram read is not the first Write that succeeded")
			}
			dpQuiet(t, b, time.Millisecond)
			a.InjectWrite(e, 5)
			a.InjectWrite(nil, 5)
			dpWrite(t, a, d)
			dpRecv(t, b)
			dpCounts(t, a, DatagramConnCounts{Out: 2, Injected: 2})
			dpCounts(t, b, DatagramConnCounts{In: 2})
		})
	})

	// Queue bounds each direction: beyond it a datagram is dropped and
	// counted at the receiving end, as a socket buffer drops; reading
	// frees room.
	t.Run("queue-bound", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := NewDatagramPipe(DatagramPipeConfig{Queue: 4})
			for k := range 10 {
				dpWrite(t, a, dpData(4, k, 30))
			}
			dpCounts(t, b, DatagramConnCounts{Dropped: 6})
			for k := range 4 {
				if got := dpRecv(t, b); !bytes.Equal(got, dpData(4, k, 30)) {
					t.Fatalf("datagram %d is not the %dth written (tail drop keeps the first ones)", k, k)
				}
			}
			dpQuiet(t, b, time.Millisecond)
			dpWrite(t, a, dpData(4, 10, 30))
			if got := dpRecv(t, b); !bytes.Equal(got, dpData(4, 10, 30)) {
				t.Fatal("after draining, a new datagram is not delivered")
			}
			dpCounts(t, a, DatagramConnCounts{Out: 11})
			dpCounts(t, b, DatagramConnCounts{In: 5, Dropped: 6})

			c, d := NewDatagramPipe(DatagramPipeConfig{}) // the default bound: 256
			for k := range 300 {
				dpWrite(t, c, dpData(4, k, 8))
			}
			dpCounts(t, d, DatagramConnCounts{Dropped: 300 - 256})

			// With Delay the bound counts the datagrams in flight too, as
			// netem's limit does: a waiting reader makes no room before they
			// arrive, so 6 written at once into a bound of 4 lose 2 at once.
			const delay = 10 * time.Millisecond
			e, f := NewDatagramPipe(DatagramPipeConfig{Queue: 4, Delay: delay})
			rf := dpReadAsync(f)
			dpBlocked(t, rf)
			t0 := time.Now()
			for k := range 6 {
				dpWrite(t, e, dpData(4, 20+k, 30))
			}
			dpCounts(t, f, DatagramConnCounts{Dropped: 2})
			if r := <-rf; r.err != nil || !bytes.Equal(r.b, dpData(4, 20, 30)) || r.at.Sub(t0) != delay {
				t.Fatalf("the waiting Read got %d bytes, %v at +%v; want the first datagram at +%v", len(r.b), r.err, r.at.Sub(t0), delay)
			}
			for k := 1; k < 4; k++ {
				if got := dpRecv(t, f); !bytes.Equal(got, dpData(4, 20+k, 30)) {
					t.Fatalf("delayed datagram %d is not the %dth written", k, k)
				}
			}
			dpQuiet(t, f, time.Millisecond)
			dpCounts(t, f, DatagramConnCounts{In: 4, Dropped: 2})
		})
	})

	// Loss and duplication per datagram and direction from Seed: equal
	// configurations give equal fates; every datagram is delivered, dropped
	// or still queued; a duplicate arrives right behind its original.
	t.Run("loss-duplication", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const total = 2000
			run := func(cfg DatagramPipeConfig) (fwd, back []int) {
				a, b := NewDatagramPipe(cfg)
				for k := range total {
					dpWrite(t, a, dpData(5, k, 12))
					dpWrite(t, b, dpData(6, k, 12))
				}
				collect := func(c *DatagramConn, tag byte) []int {
					var got []int
					buf := make([]byte, 64)
					c.SetReadDeadline(time.Now().Add(time.Millisecond))
					for {
						n, err := c.Read(buf)
						if errors.Is(err, os.ErrDeadlineExceeded) {
							return got
						}
						tg, k := dpKey(buf[:n])
						if err != nil || tg != tag || !bytes.Equal(buf[:n], dpData(tag, k, 12)) {
							t.Fatalf("Read = %x, %v; want an intact datagram of tag %d", buf[:n], err, tag)
						}
						got = append(got, k)
					}
				}
				fwd, back = collect(b, 5), collect(a, 6)
				for _, c := range []*DatagramConn{a, b} {
					got := c.Counts()
					if cfg.Dup == 0 && got.In+got.Dropped != total {
						t.Fatalf("In %d + Dropped %d != %d written", got.In, got.Dropped, total)
					}
				}
				return fwd, back
			}
			lossy := DatagramPipeConfig{Queue: 3 * total, Loss: 0.3, Seed: 7}
			f1, b1 := run(lossy)
			f2, b2 := run(lossy)
			if !slices.Equal(f1, f2) || !slices.Equal(b1, b2) {
				t.Fatal("equal configurations gave different loss patterns")
			}
			if lost := total - len(f1); lost < total/5 || lost > total*2/5 {
				t.Fatalf("Loss 0.3 dropped %d of %d", lost, total)
			}
			if slices.Equal(f1, b1) {
				t.Fatal("both directions drew the same loss pattern")
			}
			if !slices.IsSorted(f1) {
				t.Fatal("lossy delivery reordered datagrams")
			}
			f3, _ := run(DatagramPipeConfig{Queue: 3 * total, Loss: 0.3, Seed: 8})
			if slices.Equal(f1, f3) {
				t.Fatal("another Seed gave the same loss pattern")
			}

			fd, _ := run(DatagramPipeConfig{Queue: 3 * total, Dup: 0.5, Seed: 7})
			dups := len(fd) - total
			if dups < total/3 || dups > total*2/3 {
				t.Fatalf("Dup 0.5 duplicated %d of %d", dups, total)
			}
			for i, seen := 0, 0; i < len(fd); i++ {
				switch {
				case fd[i] == seen:
					seen++
				case seen > 0 && fd[i] == seen-1 && fd[i-1] == seen-1:
				default:
					t.Fatalf("delivery %d is datagram %d; want each once, in order, a duplicate right behind its original", i, fd[i])
				}
			}

			// A duplicate that does not fit is never made: neither
			// delivered nor counted Dropped (its original was delivered).
			g, h := NewDatagramPipe(DatagramPipeConfig{Queue: 1, Dup: 1})
			dpWrite(t, g, []byte("once"))
			dpCounts(t, h, DatagramConnCounts{})
			if got := dpRecv(t, h); string(got) != "once" {
				t.Fatalf("got %q; want the original", got)
			}
			dpQuiet(t, h, time.Millisecond)
			dpCounts(t, h, DatagramConnCounts{In: 1})
		})
	})

	// Delay: one-way, both directions, order kept; a read deadline before
	// the arrival times out and the datagram still arrives on time.
	t.Run("delay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const delay = 30 * time.Millisecond
			a, b := NewDatagramPipe(DatagramPipeConfig{Delay: delay})
			for _, ends := range [2][2]*DatagramConn{{a, b}, {b, a}} {
				w, r := ends[0], ends[1]
				t0 := time.Now()
				for k := range 3 {
					dpWrite(t, w, dpData(7, k, 40))
					time.Sleep(10 * time.Millisecond)
				}
				r.SetReadDeadline(t0.Add(20 * time.Millisecond))
				if _, err := r.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(t0) != 30*time.Millisecond {
					// The writes took 30 ms; the deadline at 20 ms has passed.
					t.Fatalf("Read past the deadline = %v at %v", err, time.Since(t0))
				}
				r.SetReadDeadline(time.Time{})
				for k := range 3 {
					got := dpRecv(t, r)
					if want := delay + time.Duration(k)*10*time.Millisecond; !bytes.Equal(got, dpData(7, k, 40)) || time.Since(t0) != want {
						t.Fatalf("datagram %d at %v; want it intact at %v", k, time.Since(t0), want)
					}
				}
			}
			t0 := time.Now()
			dpWrite(t, a, []byte("x"))
			b.SetReadDeadline(t0.Add(10 * time.Millisecond))
			if _, err := b.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(t0) != 10*time.Millisecond {
				t.Fatalf("deadline before the arrival: %v at %v; want a timeout at 10ms", err, time.Since(t0))
			}
			b.SetReadDeadline(time.Time{})
			if got := dpRecv(t, b); string(got) != "x" || time.Since(t0) != delay {
				t.Fatalf("got %q at %v; want x at %v", got, time.Since(t0), delay)
			}
		})
	})

	// Deadlines as net.Conn: a timeout error at the deadline instant; a
	// changed deadline wakes a waiting Read; a passed deadline fails a
	// Read even with a datagram queued; a passed write deadline fails a
	// Write, which then sends nothing.
	t.Run("deadlines", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := NewDatagramPipe(DatagramPipeConfig{})
			t0 := time.Now()
			b.SetReadDeadline(t0.Add(50 * time.Millisecond))
			_, err := b.Read(make([]byte, 8))
			var ne net.Error
			if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() || time.Since(t0) != 50*time.Millisecond {
				t.Fatalf("Read = %v at %v; want a timeout at 50ms", err, time.Since(t0))
			}
			b.SetReadDeadline(time.Time{})
			ch := dpReadAsync(b)
			time.Sleep(20 * time.Millisecond)
			dpBlocked(t, ch)
			b.SetReadDeadline(time.Now())
			if r := <-ch; !errors.Is(r.err, os.ErrDeadlineExceeded) || r.at.Sub(t0) != 70*time.Millisecond {
				t.Fatalf("waiting Read after SetReadDeadline(now) = %v at %v; want a timeout at once", r.err, r.at.Sub(t0))
			}
			dpWrite(t, a, []byte("queued"))
			if _, err := b.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read past the deadline with a datagram queued = %v; want a timeout", err)
			}
			b.SetDeadline(time.Time{})
			if got := dpRecv(t, b); string(got) != "queued" {
				t.Fatalf("after clearing the deadline: %q", got)
			}
			a.SetWriteDeadline(time.Now())
			if n, err := a.Write([]byte("late")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Write past the deadline = %d, %v; want 0 and a timeout", n, err)
			}
			a.SetDeadline(time.Time{})
			dpQuiet(t, b, time.Millisecond)
			dpWrite(t, a, []byte("ok"))
			if got := dpRecv(t, b); string(got) != "ok" {
				t.Fatalf("after clearing the write deadline: %q", got)
			}
			dpCounts(t, a, DatagramConnCounts{Out: 2})
		})
	})

	// On the real clock a deadline is fixed against the runtime clock when
	// it is set, as net.Conn's is: a wall-only time (Round(0), UTC,
	// time.Unix) is held as the same instant with a monotonic reading, so a
	// wall-clock step cannot move the timer or the expiry check. A step
	// cannot be made in a test, so the held value is checked (inside a
	// bubble the clock has no monotonic reading and no steps).
	t.Run("deadline-fixed-at-set", func(t *testing.T) {
		a, b := NewDatagramPipe(DatagramPipeConfig{})
		defer a.Close()
		wall := time.Now().Add(time.Hour).Round(0)
		b.SetReadDeadline(wall)
		a.SetWriteDeadline(wall.UTC())
		for name, dl := range map[string]time.Time{"read": b.rx.rdl, "write": a.wdl} {
			if !dl.Equal(wall) || !dpMonotonic(dl) {
				t.Fatalf("%s deadline held as %v; want %v with a monotonic reading", name, dl, wall)
			}
		}
		b.SetReadDeadline(time.Now().Add(5 * time.Millisecond).Round(0))
		if _, err := b.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read with a wall-only deadline = %v; want a timeout", err)
		}
		b.SetDeadline(time.Time{})
		a.SetDeadline(time.Time{})
		if !b.rx.rdl.IsZero() || !a.wdl.IsZero() {
			t.Fatal("a cleared deadline is not zero")
		}
	})

	// Close: every later call of both ends returns net.ErrClosed; waiting
	// Reads return at once (also one waiting for a delayed datagram); the
	// datagrams still queued are counted Dropped; a second Close of an end
	// fails, the other end's first Close succeeds. The pipe starts no
	// goroutine: the bubble ends with the readers.
	t.Run("close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := NewDatagramPipe(DatagramPipeConfig{Delay: time.Hour})
			for k := range 3 {
				dpWrite(t, b, dpData(8, k, 10))
			}
			dpWrite(t, a, dpData(8, 9, 10))
			dpWrite(t, a, dpData(8, 10, 10))
			ra, rb := dpReadAsync(a), dpReadAsync(b)
			time.Sleep(time.Minute)
			dpBlocked(t, ra)
			dpBlocked(t, rb)
			t0 := time.Now()
			if err := a.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			for _, ch := range []<-chan dpResult{ra, rb} {
				if r := <-ch; !errors.Is(r.err, net.ErrClosed) || r.at != t0 {
					t.Fatalf("waiting Read after Close = %v at +%v; want net.ErrClosed at once", r.err, r.at.Sub(t0))
				}
			}
			for _, c := range []*DatagramConn{a, b} {
				if _, err := c.Read(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Read after Close = %v", err)
				}
				if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Write after Close = %v", err)
				}
				if err := c.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("SetReadDeadline after Close = %v", err)
				}
			}
			if err := a.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("second Close = %v; want net.ErrClosed", err)
			}
			if err := b.Close(); err != nil {
				t.Fatalf("the other end's first Close = %v; want nil", err)
			}
			dpCounts(t, a, DatagramConnCounts{Out: 2, Dropped: 3})
			dpCounts(t, b, DatagramConnCounts{Out: 3, Dropped: 2})
		})
	})

	// Addresses: documentation *net.UDPAddr values by default (Network
	// "udp", so a datagram-conn check accepts the ends), each end's
	// RemoteAddr the other's LocalAddr; configured ones as given.
	t.Run("addresses", func(t *testing.T) {
		a, b := NewDatagramPipe(DatagramPipeConfig{})
		doc := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24")}
		for i, c := range []*DatagramConn{a, b} {
			u, ok := c.LocalAddr().(*net.UDPAddr)
			if !ok || u.Network() != "udp" || !doc[i].Contains(u.AddrPort().Addr()) || u.Port == 0 {
				t.Fatalf("end %d LocalAddr = %#v; want a *net.UDPAddr in %v", i, c.LocalAddr(), doc[i])
			}
		}
		if a.RemoteAddr() != b.LocalAddr() || b.RemoteAddr() != a.LocalAddr() || a.LocalAddr().String() == b.LocalAddr().String() {
			t.Fatalf("addresses a %v→%v, b %v→%v", a.LocalAddr(), a.RemoteAddr(), b.LocalAddr(), b.RemoteAddr())
		}
		x, y := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 7}, &net.UnixAddr{Name: "y", Net: "unixgram"}
		c, d := NewDatagramPipe(DatagramPipeConfig{AddrA: x, AddrB: y})
		if c.LocalAddr() != x || c.RemoteAddr() != y || d.LocalAddr() != y || d.RemoteAddr() != x {
			t.Fatal("configured addresses not reported as given")
		}
		a.Close()
		c.Close()
	})

	// Outside any bubble, on the real clock: a delayed datagram arrives;
	// concurrent writers and a reader keep every datagram whole, once, and
	// in each writer's order (the race detector's row).
	t.Run("real-clock-concurrent", func(t *testing.T) {
		a, b := NewDatagramPipe(DatagramPipeConfig{Delay: time.Millisecond, Queue: 4096})
		t0 := time.Now()
		dpWrite(t, a, []byte("late"))
		if got := dpRecv(t, b); string(got) != "late" || time.Since(t0) < time.Millisecond {
			t.Fatalf("delayed datagram %q after %v", got, time.Since(t0))
		}
		const writers, per = 4, 500
		var wg sync.WaitGroup
		for w := range writers {
			wg.Go(func() {
				for k := range per {
					if _, err := a.Write(dpData(byte(w), k, 100+k%7)); err != nil {
						t.Errorf("Write: %v", err)
						return
					}
				}
			})
		}
		b.SetReadDeadline(time.Now().Add(10 * time.Second)) // a lost datagram fails here, not at the test timeout
		next := make([]int, writers)
		for range writers * per {
			got := dpRecv(t, b)
			w, k := dpKey(got)
			if int(w) >= writers || k != next[w] || !bytes.Equal(got, dpData(w, k, 100+k%7)) {
				t.Fatalf("datagram (%d, %d) of %d bytes; want writer %d's next one intact", w, k, len(got), w)
			}
			next[w]++
		}
		wg.Wait()
		dpCounts(t, b, DatagramConnCounts{In: writers*per + 1})
		a.Close()
	})

	// Steady state allocates nothing: the copies reuse freed buffers of
	// their size class (l4's allocation gates run on pipes), at every class
	// up to the largest datagram, also after a burst of small datagrams
	// filled the smallest class's free list, whose length stays bounded.
	t.Run("steady-state-allocs", func(t *testing.T) {
		a, b := NewDatagramPipe(DatagramPipeConfig{Queue: 1024})
		r := make([]byte, 64<<10)
		a.SetReadDeadline(time.Now().Add(10 * time.Second))
		b.SetReadDeadline(time.Now().Add(10 * time.Second))
		small := dpData(9, 1, 100)
		for range 300 {
			dpWrite(t, a, small)
		}
		for i := range 300 {
			if n, err := b.Read(r); n != len(small) || err != nil {
				t.Fatalf("burst read %d = %d, %v", i, n, err)
			}
		}
		if got := len(a.n.free[0]); got != dpRecycleMax {
			t.Fatalf("after 300 freed small buffers the free list holds %d; want the bound %d", got, dpRecycleMax)
		}
		for _, size := range []int{1400, 9000, 65507} {
			w := dpData(9, 0, size)
			bad := 0 // rounds that did not deliver w both ways (no allocation to count them)
			round := func() {
				a.Write(w)
				n1, err1 := b.Read(r)
				b.Write(w)
				n2, err2 := a.Read(r)
				if err1 != nil || err2 != nil || n1 != len(w) || n2 != len(w) || r[size-1] != w[size-1] {
					bad++
				}
			}
			round()
			if n := testing.AllocsPerRun(1000, round); n != 0 || bad != 0 {
				t.Fatalf("%d-byte datagrams after a burst of 100-byte ones: %.1f allocations per round trip, %d rounds not delivered; want 0 and 0", size, n, bad)
			}
		}
		a.Close()
	})
}

// TestDatagramPipeAccountingIdentity: through loss, the queue bound,
// truncation, injections and a Close, every datagram written is read or
// counted Dropped at the receiving end.
func TestDatagramPipeAccountingIdentity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := NewDatagramPipe(DatagramPipeConfig{Queue: 16, Loss: 0.1, Seed: 3, Trunc: TruncWindows})
		buf := make([]byte, 64)
		for k := range 500 {
			if k%50 == 0 {
				a.InjectWrite(errors.New("w"), 2)
				b.Inject(errors.New("r"), false)
			}
			a.Write(dpData(10, k, 32+k%64))
			if k%3 == 0 {
				b.SetReadDeadline(time.Now().Add(time.Millisecond))
				b.Read(buf)
			}
		}
		b.SetReadDeadline(time.Now().Add(time.Millisecond))
		for i := 0; ; i++ {
			_, err := b.Read(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil && !errors.Is(err, ErrMsgSize) || i > 16 {
				t.Fatalf("drain read %d = %v; want the queued datagrams (≤ 16), then a timeout", i, err)
			}
		}
		if got := b.Counts().Injected; got != 10 {
			t.Fatalf("b Injected = %d; want 10 (each injected once, consumed by one Read)", got)
		}
		for k := range 5 {
			a.Write(dpData(10, k, 8)) // still queued at the Close
		}
		b.Close()
		sa, sb := a.Counts(), b.Counts()
		if sa.Out != sb.In+sb.Dropped || sa.Out != 485 || sa.Injected != 20 || sb.Truncated == 0 || sb.Dropped <= 5 {
			t.Fatalf("a %+v, b %+v: want Out = In + Dropped, 485 sent, 20 refused", sa, sb)
		}
	})
}
