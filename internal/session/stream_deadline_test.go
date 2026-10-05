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

// stIsTimeout: the deadline error of net.Conn (os.ErrDeadlineExceeded, a
// net.Error with Timeout() true).
func stIsTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
}

// TestDeadlineSemantics_L06: net.Conn deadline semantics per direction —
// a 200 ms deadline fires at 200 ms, also when given as a wall-clock time
// without a monotonic reading; a deadline shortened while a call is
// blocked takes effect at once; an extended deadline's old firing does
// nothing; a past deadline wakes every blocked reader and fails a Read
// even while bytes are buffered (they stay readable once the deadline is
// cleared); a Write that times out with the peer's window at 0 returns
// (k, timeout) and exactly those k bytes are delivered once the window
// opens; DATA, replay and ACKs go on after the deadline; the session stays
// usable in both directions.
func TestDeadlineSemantics_L06(t *testing.T) {
	t.Run("fires", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive})
			start := time.Now()
			// Round(0): a wall-clock time, as from time.Unix.
			if err := s.SetReadDeadline(start.Add(200 * time.Millisecond).Round(0)); err != nil {
				t.Fatal(err)
			}
			n, err := s.Read(make([]byte, 10))
			if d := time.Since(start); n != 0 || !stIsTimeout(err) || d < 150*time.Millisecond || d > 500*time.Millisecond {
				t.Fatalf("Read = (%d, %v) after %v, want a timeout at 200 ms", n, err, d)
			}
			// The session is unaffected: clear the deadline and read data.
			l, _ := stAddLane(s, 1, false)
			if err := s.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if err := l.Data(nil, 0, []byte("after"), nil); err != nil {
				t.Fatal(err)
			}
			if got := stReadN(t, s, 5); string(got) != "after" {
				t.Fatalf("Read after the timeout = %q", got)
			}
		})
	})

	t.Run("shortened while blocked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive})
			start := time.Now()
			_ = s.SetReadDeadline(start.Add(5 * time.Second))
			done := make(chan stIO, 1)
			go func() {
				n, err := s.Read(make([]byte, 10))
				done <- stIO{n, err}
			}()
			synctest.Wait()
			if len(done) != 0 {
				t.Fatal("Read returned before any deadline")
			}
			_ = s.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			r := <-done
			if d := time.Since(start); !stIsTimeout(r.err) || d > 300*time.Millisecond {
				t.Fatalf("Read = (%d, %v) after %v, want a timeout ≤ 300 ms after shortening", r.n, r.err, d)
			}
		})
	})

	t.Run("extended deadline's old firing does nothing", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive})
			start := time.Now()
			_ = s.SetReadDeadline(start.Add(100 * time.Millisecond))
			done := make(chan stIO, 1)
			go func() {
				n, err := s.Read(make([]byte, 10))
				done <- stIO{n, err}
			}()
			synctest.Wait()
			_ = s.SetReadDeadline(start.Add(300 * time.Millisecond))
			time.Sleep(150 * time.Millisecond) // virtual: past the old deadline
			synctest.Wait()
			if len(done) != 0 {
				t.Fatal("the extended deadline's old firing failed the Read")
			}
			r := <-done
			if d := time.Since(start); !stIsTimeout(r.err) || d != 300*time.Millisecond {
				t.Fatalf("Read = (%d, %v) at %v, want a timeout at the extended 300 ms", r.n, r.err, d)
			}
		})
	})

	t.Run("wall-clock deadline becomes monotonic", func(t *testing.T) {
		// Real time (a bubble's clock has no monotonic reading); nothing
		// waits. Like net.Conn, Set turns the deadline into a duration once,
		// so a later wall-clock step can neither strand nor advance it.
		s := stSession(stOpt{role: RolePassive})
		_ = s.SetWriteDeadline(time.Now().Add(time.Hour).Round(0))
		if dl := stLocked(s, func(st *stream) time.Time { return st.wdl.t }); dl == dl.Round(0) || time.Until(dl) > time.Hour {
			t.Fatalf("stored write deadline %v: want a monotonic reading at most an hour ahead", dl)
		}
		stEnd(s, errClosed)
	})

	t.Run("past deadline before buffered bytes", func(t *testing.T) {
		s := stSession(stOpt{role: RolePassive})
		l, _ := stAddLane(s, 1, false)
		if err := l.Data(nil, 0, []byte("held"), nil); err != nil {
			t.Fatal(err)
		}
		_ = s.SetReadDeadline(time.Now().Add(-time.Second))
		for range 2 {
			if n, err := s.Read(make([]byte, 10)); n != 0 || !stIsTimeout(err) {
				t.Fatalf("Read with 4 bytes buffered after the deadline = (%d, %v), want (0, timeout) as net.Conn", n, err)
			}
		}
		_ = s.SetReadDeadline(time.Time{})
		if got := stReadN(t, s, 4); string(got) != "held" {
			t.Fatalf("buffered bytes after clearing the deadline = %q", got)
		}
		stEnd(s, errClosed)
	})

	t.Run("past deadline wakes five readers", func(t *testing.T) {
		// Real time. Since §0.14 B12 Reads serialize on the rsem channel
		// semaphore, so queued Reads block durably and a bubble would work
		// as well; TestQueuedCallsDeadline_L06/reads covers this case in
		// one.
		s := stSession(stOpt{role: RolePassive})
		done := make(chan stIO, 5)
		for range 5 {
			go func() {
				n, err := s.Read(make([]byte, 10))
				done <- stIO{n, err}
			}()
		}
		// Gate: one reader waits inside Read; the others queue behind it.
		for !stLocked(s, func(st *stream) bool { return st.rwaiting }) {
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
				if !stIsTimeout(r.err) || r.n != 0 {
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
			p := stNewPair(stOpt{window: w}, stOpt{}, 2)
			// The peer's window is 0 (OPEN_ACK window 0): nothing may be sent.
			p.a.mu.Lock()
			p.a.st.peerLimit = p.a.st.sBase
			p.a.mu.Unlock()

			// A deadline already passed: nothing is accepted, no offset is used.
			_ = p.a.SetWriteDeadline(time.Now().Add(-time.Millisecond))
			if n, err := p.a.Write([]byte("x")); n != 0 || !stIsTimeout(err) {
				t.Fatalf("Write with a past deadline = (%d, %v), want (0, timeout)", n, err)
			}
			if r := stLocked(p.a, func(st *stream) uint64 { return st.resEnd }); r != 0 {
				t.Fatalf("a timed-out Write reserved %d bytes", r)
			}

			start := time.Now()
			_ = p.a.SetWriteDeadline(start.Add(50 * time.Millisecond))
			msg := stPattern(0, 1<<20)
			n, err := p.a.Write(msg)
			if !stIsTimeout(err) || n != w || time.Since(start) != 50*time.Millisecond {
				t.Fatalf("Write of 1 MiB at window 0 = (%d, %v) after %v, want (%d, timeout) at 50 ms", n, err, time.Since(start), w)
			}
			// Control and DATA go on after the expiry: the window opens (the
			// peer's ACK), the k accepted bytes leave and arrive — exactly k.
			p.pump(true)
			if got := stReadN(t, p.b, n); !bytes.Equal(got, msg[:n]) {
				t.Fatal("the k accepted bytes arrived corrupted")
			}
			p.pump(true)
			if extra := stLocked(p.b, func(st *stream) uint64 { return st.rTail - st.rRead }); extra != 0 {
				t.Fatalf("%d bytes beyond the k accepted ones arrived", extra)
			}
			if c := stCount(p.traceAB, wire.TypeData); c == 0 {
				t.Fatal("no DATA after the deadline: the stimulus did not happen")
			}

			// Replay goes on after the deadline: more bytes in flight on link
			// 1, its carrier dies, link 2 replays them.
			_ = p.a.SetWriteDeadline(time.Time{})
			more := stPattern(uint64(n), 64<<10)
			if k, err := p.a.Write(more); k != len(more) || err != nil {
				t.Fatalf("Write after clearing the deadline = (%d, %v)", k, err)
			}
			_ = p.a.SetWriteDeadline(time.Now().Add(-time.Second)) // expired again
			fs, b := stFill(p.al[0], time.Now())                   // sent, then lost with the carrier
			b.ReleaseRefs()
			if len(fs) == 0 {
				t.Fatal("no DATA in flight before the kill")
			}
			stKillLane(p.a, p.al[0])
			stKillLane(p.b, p.bl[0])
			p.cut[0] = true
			stRoute(p.a, p.al[1], true)
			stRoute(p.b, p.bl[1], true)
			p.pump(true)
			if got := stReadN(t, p.b, len(more)); !bytes.Equal(got, more) {
				t.Fatal("replayed bytes corrupted")
			}
			// Usable both ways.
			_ = p.a.SetWriteDeadline(time.Time{})
			if k, err := p.b.Write([]byte("reply")); k != 5 || err != nil {
				t.Fatalf("peer Write = (%d, %v)", k, err)
			}
			p.pump(true)
			if got := stReadN(t, p.a, 5); string(got) != "reply" {
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
			s := stSession(stOpt{role: RolePassive})
			_ = s.SetReadDeadline(time.Now().Add(-time.Second))
			_ = s.SetWriteDeadline(time.Now().Add(-time.Second))
			stEnd(s, ErrNoPath)
			if _, err := s.Read(make([]byte, 1)); !errors.Is(err, ErrNoPath) {
				t.Fatalf("Read = %v, want ErrNoPath over the deadline", err)
			}
			if _, err := s.Write([]byte{1}); !errors.Is(err, ErrNoPath) {
				t.Fatalf("Write = %v, want ErrNoPath over the deadline", err)
			}
		})
	})
}
