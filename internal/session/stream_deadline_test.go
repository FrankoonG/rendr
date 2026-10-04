package session

import (
	"bytes"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// isTimeout: the deadline error of net.Conn (os.ErrDeadlineExceeded, a
// net.Error with Timeout() true).
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
}

// TestDeadlineSemantics_L06: net.Conn deadline semantics per direction —
// a 200 ms deadline fires at 200 ms; a deadline shortened while a call is
// blocked takes effect at once; an extended deadline's old firing does
// nothing; a past deadline wakes every blocked reader; a Write that times
// out with the peer's window at 0 returns (k, timeout) and exactly those k
// bytes are delivered once the window opens; DATA, replay and ACKs go on
// after the deadline; the session stays usable in both directions.
func TestDeadlineSemantics_L06(t *testing.T) {
	t.Run("fires", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := newTestSession(sopt{role: RolePassive})
			start := time.Now()
			if err := s.SetReadDeadline(start.Add(200 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			n, err := s.Read(make([]byte, 10))
			if d := time.Since(start); n != 0 || !isTimeout(err) || d < 150*time.Millisecond || d > 500*time.Millisecond {
				t.Fatalf("Read = (%d, %v) after %v, want a timeout at 200 ms", n, err, d)
			}
			// The session is unaffected: clear the deadline and read data.
			l, _ := addLane(s, 1, false)
			if err := s.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if err := l.Data(nil, 0, []byte("after"), nil); err != nil {
				t.Fatal(err)
			}
			if got := readN(t, s, 5); string(got) != "after" {
				t.Fatalf("Read after the timeout = %q", got)
			}
		})
	})

	t.Run("shortened while blocked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := newTestSession(sopt{role: RolePassive})
			start := time.Now()
			_ = s.SetReadDeadline(start.Add(5 * time.Second))
			done := make(chan ioResult, 1)
			go func() {
				n, err := s.Read(make([]byte, 10))
				done <- ioResult{n, err}
			}()
			synctest.Wait()
			if len(done) != 0 {
				t.Fatal("Read returned before any deadline")
			}
			_ = s.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			r := <-done
			if d := time.Since(start); !isTimeout(r.err) || d > 300*time.Millisecond {
				t.Fatalf("Read = (%d, %v) after %v, want a timeout ≤ 300 ms after shortening", r.n, r.err, d)
			}
		})
	})

	t.Run("extended deadline's old firing does nothing", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := newTestSession(sopt{role: RolePassive})
			start := time.Now()
			_ = s.SetReadDeadline(start.Add(100 * time.Millisecond))
			done := make(chan ioResult, 1)
			go func() {
				n, err := s.Read(make([]byte, 10))
				done <- ioResult{n, err}
			}()
			synctest.Wait()
			_ = s.SetReadDeadline(start.Add(300 * time.Millisecond))
			time.Sleep(150 * time.Millisecond) // virtual: past the old deadline
			synctest.Wait()
			if len(done) != 0 {
				t.Fatal("the extended deadline's old firing failed the Read")
			}
			r := <-done
			if d := time.Since(start); !isTimeout(r.err) || d != 300*time.Millisecond {
				t.Fatalf("Read = (%d, %v) at %v, want a timeout at the extended 300 ms", r.n, r.err, d)
			}
		})
	})

	t.Run("past deadline wakes five readers", func(t *testing.T) {
		// Real time: Reads serialize on rmu, and goroutines queued on a
		// mutex are not durably blocked, so a bubble could never settle.
		s := newTestSession(sopt{role: RolePassive})
		done := make(chan ioResult, 5)
		for range 5 {
			go func() {
				n, err := s.Read(make([]byte, 10))
				done <- ioResult{n, err}
			}()
		}
		// Gate: one reader waits inside Read; the others queue behind it.
		for !locked(s, func(st *stream) bool { return st.rwaiting }) {
			runtime.Gosched()
		}
		if len(done) != 0 {
			t.Fatal("a reader returned without data or deadline")
		}
		_ = s.SetReadDeadline(time.Now().Add(-time.Second))
		bound := time.NewTimer(10 * time.Second)
		defer bound.Stop()
		for i := range 5 {
			select {
			case r := <-done:
				if !isTimeout(r.err) || r.n != 0 {
					t.Fatalf("reader %d = (%d, %v), want (0, timeout)", i, r.n, r.err)
				}
			case <-bound.C:
				t.Fatalf("only %d of 5 blocked readers woke after a past deadline", i)
			}
		}
	})

	t.Run("window-0 write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const w = 256 << 10
			p := newPair(sopt{window: w}, sopt{}, 2)
			// The peer's window is 0 (OPEN_ACK window 0): nothing may be sent.
			p.a.mu.Lock()
			p.a.st.peerLimit = p.a.st.sBase
			p.a.mu.Unlock()

			// A deadline already passed: nothing is accepted, no offset is used.
			_ = p.a.SetWriteDeadline(time.Now().Add(-time.Millisecond))
			if n, err := p.a.Write([]byte("x")); n != 0 || !isTimeout(err) {
				t.Fatalf("Write with a past deadline = (%d, %v), want (0, timeout)", n, err)
			}
			if r := locked(p.a, func(st *stream) uint64 { return st.resEnd }); r != 0 {
				t.Fatalf("a timed-out Write reserved %d bytes", r)
			}

			start := time.Now()
			_ = p.a.SetWriteDeadline(start.Add(50 * time.Millisecond))
			msg := pattern(0, 1<<20)
			n, err := p.a.Write(msg)
			if !isTimeout(err) || n != w || time.Since(start) != 50*time.Millisecond {
				t.Fatalf("Write of 1 MiB at window 0 = (%d, %v) after %v, want (%d, timeout) at 50 ms", n, err, time.Since(start), w)
			}
			// Control and DATA go on after the expiry: the window opens (the
			// peer's ACK), the k accepted bytes leave and arrive — exactly k.
			p.pump(true)
			if got := readN(t, p.b, n); !bytes.Equal(got, msg[:n]) {
				t.Fatal("the k accepted bytes arrived corrupted")
			}
			p.pump(true)
			if extra := locked(p.b, func(st *stream) uint64 { return st.rTail - st.rRead }); extra != 0 {
				t.Fatalf("%d bytes beyond the k accepted ones arrived", extra)
			}
			if c := count(p.traceAB, wire.TypeData); c == 0 {
				t.Fatal("no DATA after the deadline: the stimulus did not happen")
			}

			// Replay goes on after the deadline: more bytes in flight on link
			// 1, its carrier dies, link 2 replays them.
			_ = p.a.SetWriteDeadline(time.Time{})
			more := pattern(uint64(n), 64<<10)
			if k, err := p.a.Write(more); k != len(more) || err != nil {
				t.Fatalf("Write after clearing the deadline = (%d, %v)", k, err)
			}
			_ = p.a.SetWriteDeadline(time.Now().Add(-time.Second)) // expired again
			fs, b := fill(p.al[0], time.Now())                     // sent, then lost with the carrier
			b.ReleaseRefs()
			if len(fs) == 0 {
				t.Fatal("no DATA in flight before the kill")
			}
			killLane(p.a, p.al[0])
			killLane(p.b, p.bl[0])
			p.cut[0] = true
			route(p.a, p.al[1], true)
			route(p.b, p.bl[1], true)
			p.pump(true)
			if got := readN(t, p.b, len(more)); !bytes.Equal(got, more) {
				t.Fatal("replayed bytes corrupted")
			}
			// Usable both ways.
			_ = p.a.SetWriteDeadline(time.Time{})
			if k, err := p.b.Write([]byte("reply")); k != 5 || err != nil {
				t.Fatalf("peer Write = (%d, %v)", k, err)
			}
			p.pump(true)
			if got := readN(t, p.a, 5); string(got) != "reply" {
				t.Fatalf("reverse Read = %q", got)
			}
			if len(p.errs) != 0 {
				t.Fatalf("violations: %v", p.errs)
			}
			p.close(t)
		})
	})

	t.Run("end error wins over the deadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := newTestSession(sopt{role: RolePassive})
			_ = s.SetReadDeadline(time.Now().Add(-time.Second))
			_ = s.SetWriteDeadline(time.Now().Add(-time.Second))
			endSession(s, ErrNoPath)
			if _, err := s.Read(make([]byte, 1)); !errors.Is(err, ErrNoPath) {
				t.Fatalf("Read = %v, want ErrNoPath over the deadline", err)
			}
			if _, err := s.Write([]byte{1}); !errors.Is(err, ErrNoPath) {
				t.Fatalf("Write = %v, want ErrNoPath over the deadline", err)
			}
		})
	})
}
