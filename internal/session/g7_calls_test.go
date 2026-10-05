package session

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// Application calls queued behind another call of the same direction
// (design §0.14 B12): Reads and Writes are serialized by 1-slot channel
// semaphores, so a queued call blocks durably inside a synctest bubble —
// with sync.Mutex it waited in Mutex.Lock, which a bubble does not count
// as durably blocked, so synctest.Wait and every virtual-time wait hung —
// and it keeps net.Conn semantics: a deadline, Close, CloseWrite (Writes)
// or the session's end fails the call that holds the semaphore and every
// queued one at the same instant; Close also reaches a queued call while
// the holder cannot return yet. Every test here hangs on the mutex version
// (bound such a run with -timeout).

// g7Call is the outcome of one asynchronous Read or Write and its time.
type g7Call struct {
	n   int
	err error
	at  time.Time
}

// g7Go runs f on a new goroutine of the caller's bubble.
func g7Go(f func() (int, error)) <-chan g7Call {
	ch := make(chan g7Call, 1)
	go func() {
		n, err := f()
		ch <- g7Call{n, err, time.Now()}
	}()
	return ch
}

// g7Settled waits until the bubble settled and returns the calls that have
// not returned yet (by index).
func g7Settled(calls []<-chan g7Call) (running []int) {
	synctest.Wait()
	for i, c := range calls {
		if len(c) == 0 {
			running = append(running, i)
		}
	}
	return running
}

// g7Reads starts n Reads of 10 bytes on s.
func g7Reads(s *Session, n int) []<-chan g7Call {
	calls := make([]<-chan g7Call, n)
	for i := range calls {
		calls[i] = g7Go(func() (int, error) { return s.Read(make([]byte, 10)) })
	}
	return calls
}

// g7Writes starts n Writes of size bytes each on s.
func g7Writes(s *Session, n, size int) []<-chan g7Call {
	calls := make([]<-chan g7Call, n)
	for i := range calls {
		calls[i] = g7Go(func() (int, error) { return s.Write(stPattern(uint64(i)<<32, size)) })
	}
	return calls
}

// g7All collects every call's result after the bubble settled; a call that
// has not returned fails t.
func g7All(t *testing.T, what string, calls []<-chan g7Call) []g7Call {
	t.Helper()
	if r := g7Settled(calls); len(r) != 0 {
		t.Fatalf("%s: calls %v still blocked", what, r)
	}
	out := make([]g7Call, len(calls))
	for i, c := range calls {
		out[i] = <-c
	}
	return out
}

// g7Ended makes the test's cleanup end s (idempotent), so that a failing
// test still releases every blocked call before its bubble exits.
func g7Ended(t *testing.T, s *Session) *Session {
	t.Cleanup(func() { stEnd(s, errClosed) })
	return s
}

// g7Hold returns a hook that holds the first call reaching it until free
// runs (at the latest in the test's cleanup), and a channel closed once
// that call is held.
func g7Hold(t *testing.T) (hook func(), held <-chan struct{}, free func()) {
	var first atomic.Bool
	var once sync.Once
	entered, release := make(chan struct{}), make(chan struct{})
	hook = func() {
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
	}
	free = func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	return hook, entered, free
}

// TestQueuedCallsDeadline_L06 (L06: five blocked readers all wake when the
// deadline passes; deadlines apply to pending calls): inside a bubble, five
// Reads block on a session with nothing to read — one waits for data, four
// queue for the read semaphore — and five Writes of 1 MiB block on a full
// 256 KiB send window — one waits for room, four queue. A read deadline
// 200 ms ahead fails all five Reads with (0, timeout) at 200 ms, and a write
// deadline already passed fails all five Writes at once: the holder with
// the 256 KiB it accepted, every queued one with (0, timeout) and nothing
// reserved (no side effect before acceptance).
func TestQueuedCallsDeadline_L06(t *testing.T) {
	t.Run("reads", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := g7Ended(t, stSession(stOpt{role: RolePassive}))
			calls := g7Reads(s, 5)
			if r := g7Settled(calls); len(r) != 5 || !stLocked(s, func(st *stream) bool { return st.rwaiting }) {
				t.Fatalf("calls %v blocked, want all five with one waiting for data", r)
			}
			start := time.Now()
			if err := s.SetReadDeadline(start.Add(200 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second)
			for i, r := range g7All(t, "Reads after their deadline", calls) {
				if r.n != 0 || !stIsTimeout(r.err) || r.at.Sub(start) != 200*time.Millisecond {
					t.Fatalf("Read %d = (%d, %v) at %v, want (0, timeout) at 200 ms", i, r.n, r.err, r.at.Sub(start))
				}
			}
			stEnd(s, errClosed)
		})
	})
	t.Run("writes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const w = 256 << 10
			s := g7Ended(t, stSession(stOpt{window: w})) // no lane: nothing is sent or acknowledged
			calls := g7Writes(s, 5, 1<<20)
			if r := g7Settled(calls); len(r) != 5 || !stLocked(s, func(st *stream) bool { return st.wwaiting && st.end == w }) {
				t.Fatalf("calls %v blocked, want all five with one holding the full window", r)
			}
			start := time.Now()
			if err := s.SetWriteDeadline(start.Add(-time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			holders := 0
			for i, r := range g7All(t, "Writes after a past deadline", calls) {
				if !stIsTimeout(r.err) || !r.at.Equal(start) || (r.n != 0 && r.n != w) {
					t.Fatalf("Write %d = (%d, %v) at %v, want (0 or %d, timeout) at once", i, r.n, r.err, r.at.Sub(start), w)
				}
				if r.n == w {
					holders++
				}
			}
			if holders != 1 {
				t.Fatalf("%d Writes accepted the window, want exactly the holder", holders)
			}
			if r := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.end, st.resEnd} }); r != [2]uint64{w, w} {
				t.Fatalf("committed/reserved end %v after the deadline, want both %d: a queued Write took an offset", r, w)
			}
			stEnd(s, errClosed)
		})
	})
}

// g7Batch checks the results of reads Reads followed by Writes that all
// failed with want at the same instant: every Read returned 0 bytes, and
// exactly one Write — the holder — returned the window w it had accepted.
func g7Batch(t *testing.T, rs []g7Call, reads int, want error, w int, at time.Time) {
	t.Helper()
	holders := 0
	for i, r := range rs {
		if !errors.Is(r.err, want) || !r.at.Equal(at) || (r.n != 0 && (i < reads || r.n != w)) {
			t.Fatalf("call %d = (%d, %v) at %+v, want (0 or the window, %v) at once", i, r.n, r.err, r.at.Sub(at), want)
		}
		if r.n == w {
			holders++
		}
	}
	if holders != 1 {
		t.Fatalf("%d Writes returned the accepted window, want exactly the holder", holders)
	}
}

// TestQueuedCallsEnd_L03_L04_L07 (L03: Close wakes every blocked call with
// net.ErrClosed; L04: Writes after CloseWrite return net.ErrClosed; L07:
// one outcome for a Read racing Close). A call queued for a semaphore
// returns as soon as the call ahead of it can no longer complete:
//
// close, closewrite, end: three Reads (one waiting for data, two queued)
// and three Writes (one waiting for window room, two queued) on a session
// whose 256 KiB send window is full. Close fails all six with
// net.ErrClosed at that instant; CloseWrite fails the three Writes with
// net.ErrClosed and leaves the Reads blocked (the FIN sits at the window's
// end); the session's end fails all six with its error. The Write holder
// returns the window it accepted, every other call 0 bytes.
//
// read-holder-held, write-holder-held: Close reaches a queued call
// directly, while the holder cannot return yet — a Read held between its
// copy and its commit (Hooks.ReadDequeued), a Write held in its copy (the
// copy hook): the queued call, and a call made after Close, return (0,
// net.ErrClosed) at Close, before the holder; the holder then completes as
// before (the Read: Close won, (0, net.ErrClosed); the Write: its
// reservation commits below the FIN).
func TestQueuedCallsEnd_L03_L04_L07(t *testing.T) {
	const w = 256 << 10
	for _, tc := range []struct {
		name string
		stop func(s *Session)
		want error
	}{
		{"close", func(s *Session) { _ = s.Close() }, net.ErrClosed},
		{"closewrite", func(s *Session) { _ = s.CloseWrite() }, net.ErrClosed},
		{"end", func(s *Session) { stEnd(s, ErrNoPath) }, ErrNoPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := g7Ended(t, stSession(stOpt{window: w}))
				reads, writes := g7Reads(s, 3), g7Writes(s, 3, 1<<20)
				calls := append(append([]<-chan g7Call(nil), reads...), writes...)
				if r := g7Settled(calls); len(r) != 6 || !stLocked(s, func(st *stream) bool { return st.rwaiting && st.wwaiting }) {
					t.Fatalf("calls %v blocked, want all six with a Read and a Write waiting inside", r)
				}
				at := time.Now()
				tc.stop(s)
				if tc.name == "closewrite" {
					if r := g7Settled(reads); len(r) != 3 {
						t.Fatalf("CloseWrite: Reads %v still blocked, want all three", r)
					}
					g7Batch(t, g7All(t, "Writes after CloseWrite", writes), 0, tc.want, w, at)
					if fin := stLocked(s, func(st *stream) uint64 { return st.fin.off }); fin != w {
						t.Fatalf("FIN at %d, want the end of the accepted window %d", fin, w)
					}
					stEnd(s, errClosed)
					return
				}
				g7Batch(t, g7All(t, tc.name, calls), 3, tc.want, w, at)
				stEnd(s, errClosed)
			})
		})
	}
	for _, tc := range []struct {
		name string
		// open builds the session with hook installed at the holder's
		// waiting point and returns the call the test makes three times.
		open func(t *testing.T, hook func()) (*Session, func() (int, error))
		// held checks the holder's result once it was released.
		held func(t *testing.T, s *Session, r g7Call)
	}{
		{"read-holder-held", func(t *testing.T, hook func()) (*Session, func() (int, error)) {
			s, _, data := stBufferedReceiver(t, stOpt{hooks: &testhooks.Hooks{ReadDequeued: hook}})
			return s, func() (int, error) { return s.Read(make([]byte, len(data))) }
		}, func(t *testing.T, s *Session, r g7Call) {
			if r.n != 0 || !errors.Is(r.err, net.ErrClosed) {
				t.Fatalf("holder Read = (%d, %v), want (0, net.ErrClosed): Close won", r.n, r.err)
			}
			stEnd(s, errClosed)
			if u := s.env.Carrier.Budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d after the end", u)
			}
		}},
		{"write-holder-held", func(t *testing.T, hook func()) (*Session, func() (int, error)) {
			s := stSession(stOpt{window: 1 << 20})
			stSetCopyHook(t, s, hook)
			return s, func() (int, error) { return s.Write(stPattern(0, 64<<10)) }
		}, func(t *testing.T, s *Session, r g7Call) {
			if r.n != 64<<10 || r.err != nil {
				t.Fatalf("holder Write = (%d, %v), want (65536, nil): its reservation commits below the FIN", r.n, r.err)
			}
			if fin := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.fin.off, st.end} }); fin != [2]uint64{64 << 10, 64 << 10} {
				t.Fatalf("FIN offset and committed end %v, want both 65536", fin)
			}
			stEnd(s, errClosed)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				hook, entered, free := g7Hold(t)
				s, call := tc.open(t, hook)
				g7Ended(t, s)
				holder := g7Go(call)
				<-entered // the holder is between its reservation (or copy) and its commit
				queued := g7Go(call)
				if r := g7Settled([]<-chan g7Call{holder, queued}); len(r) != 2 {
					t.Fatalf("calls %v blocked, want the holder and the queued call", r)
				}
				at := time.Now()
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				late := g7Go(call) // made after Close, while the holder still holds the semaphore
				calls := []<-chan g7Call{holder, queued, late}
				if r := g7Settled(calls); len(r) != 1 || r[0] != 0 {
					t.Fatalf("after Close calls %v still blocked, want only the held holder", r)
				}
				for i, c := range calls[1:] {
					if r := <-c; r.n != 0 || !errors.Is(r.err, net.ErrClosed) || !r.at.Equal(at) {
						t.Fatalf("%s call = (%d, %v) at %v, want (0, net.ErrClosed) at Close", [2]string{"queued", "late"}[i], r.n, r.err, r.at.Sub(at))
					}
				}
				free()
				tc.held(t, s, g7All(t, "the released holder", calls[:1])[0])
			})
		})
	}
}
