package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestEarlyCloseDuringFirstWriteDelivers_L03 (M4-D12, L03; WP13-A-2): a
// Close that runs while the first Write of a deferred EarlyReturn session
// copies its round keeps Close's meaning. The round was reserved before the
// Close, so the FIN offset includes it ("a Write that already holds a
// reservation completes below it"), and a Write that reports n > 0 bytes
// must see exactly those n bytes delivered: the opening starts, the passive
// reads them and then io.EOF within Linger. A Write that returns
// (0, net.ErrClosed) is acceptable too, except in close-settled. Never
// (n > 0) with no factory call.
//
// Rows:
//   - close: the hook only closes; the Write commits right after it;
//   - close-settled: the hook waits for the actor's step before the copy,
//     so the opening starts while the round is still uncommitted (the early
//     span excludes it; it is sent after the verdict, below the FIN). The
//     actor decided before the commit, so the outcome is fixed (F20): the
//     Write returns (len, nil), the factory is called and the passive reads
//     every byte, then io.EOF;
//   - close-cap: a Write larger than EarlyDataMax; the Close lands in its
//     first (capped) round, the next round returns net.ErrClosed;
//   - max0: EarlyDataMax 0, the first Write waits for the verdict, so the
//     Close lands in a round reserved after it (an ordinary session);
//   - abort: Abort in the hook discards unsent data: the session ends
//     locally, no factory is called, whatever n the Write returns;
//   - empty: Close before any Write reserved anything is still a local end
//     with no factory call (M4-D12 unchanged).
func TestEarlyCloseDuringFirstWriteDelivers_L03(t *testing.T) {
	const linger = 5 * time.Second
	for _, tc := range []struct {
		name   string
		max    int  // EarlyDataMax
		size   int  // the Write's length
		abort  bool // Abort instead of Close in the hook
		settle bool // the hook waits for the actor's step before the copy
		empty  bool // no hook: Close first, then the Write
	}{
		{name: "close", max: 64 << 10, size: 5},
		{name: "close-settled", max: 64 << 10, size: 5, settle: true},
		{name: "close-cap", max: 16 << 10, size: 40 << 10},
		{name: "max0", max: 0, size: 5},
		{name: "abort", max: 64 << 10, size: 5, abort: true},
		{name: "empty", max: 64 << 10, size: 5, empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := eaNewWorld(t, nil)
				defer w.teardown()
				l := w.eaLink("a")
				spec := w.eaSpec(ModeSelector, tc.max, l)
				spec.Params.Linger = linger
				s := w.eaDial(spec)
				msg := stPattern(0, tc.size)

				var closedAt time.Time
				var once sync.Once
				if tc.empty {
					closedAt = time.Now()
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					stSetCopyHook(t, s, func() {
						once.Do(func() {
							closedAt = time.Now()
							if tc.abort {
								if err := s.Abort(0x1000, "bye"); err != nil {
									t.Error(err)
								}
							} else if err := s.Close(); err != nil {
								t.Error(err)
							}
							if tc.settle {
								synctest.Wait() // the actor handles the Close before the copy
							}
						})
					})
				}

				var p *Session
				var r eaResult
				if tc.max == 0 && !tc.empty {
					// The Write waits for the verdict: confirm the opening
					// its cap triggered.
					wr := eaAsync(func() (int, error) { return s.Write(msg) })
					p = w.eaPending()
					if err := p.Confirm(); err != nil {
						t.Fatal(err)
					}
					r = <-wr
				} else {
					r.n, r.err = s.Write(msg)
				}
				if r.err != nil && !errors.Is(r.err, net.ErrClosed) {
					t.Fatalf("Write = (%d, %v), want nil or net.ErrClosed", r.n, r.err)
				}
				if tc.settle && (r.n != len(msg) || r.err != nil) {
					// The opening started before the copy (the hook waited for
					// the actor's step): the round is committed below the FIN
					// and delivered after the verdict (F20).
					t.Fatalf("Write = (%d, %v), want (%d, nil): the round reserved before the Close is delivered after the verdict", r.n, r.err, len(msg))
				}

				if tc.abort || tc.empty {
					if tc.empty && (r.n != 0 || r.err == nil) {
						t.Fatalf("Write after Close = (%d, %v), want (0, net.ErrClosed)", r.n, r.err)
					}
					acDone(t, s, time.Second)
					time.Sleep(60 * time.Second) // anything an opening started would have run
					synctest.Wait()
					if d := l.Stats().Dials; d != 0 {
						t.Fatalf("%d factory calls, want 0 (a local end)", d)
					}
					select {
					case p := <-w.b.pending:
						w.sess = append(w.sess, p)
						t.Fatal("the passive admitted a session")
					default:
					}
					if err := s.Status().Err; !errors.Is(err, net.ErrClosed) {
						t.Fatalf("dialer end %v, want net.ErrClosed", err)
					}
					return
				}

				if r.n == 0 {
					// Close came first for every byte: the session may end
					// locally (nothing was accepted).
					if r.err == nil {
						t.Fatalf("Write = (0, nil) for %d bytes", len(msg))
					}
					acDone(t, s, 2*linger)
					return
				}
				if p == nil {
					time.Sleep(100 * time.Millisecond)
					synctest.Wait()
					if d := l.Stats().Dials; d == 0 {
						t.Fatalf("Write = (%d, %v), but no factory was called: the accepted bytes were dropped (state %v, end %v)",
							r.n, r.err, s.State(), s.Status().Err)
					}
					p = w.eaPending()
					if err := p.Confirm(); err != nil {
						t.Fatal(err)
					}
				}
				got := eaReadAll(t, p) // io.EOF: the dialer's FIN follows the bytes
				if !bytes.Equal(got, msg[:r.n]) {
					t.Fatalf("the passive read %d bytes, want exactly the %d the Write accepted", len(got), r.n)
				}
				if d := time.Since(closedAt); d >= linger {
					t.Fatalf("the passive reached EOF %v after the Close, want within Linger (%v)", d, linger)
				}
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
				acDone(t, s, 5*time.Second)
				if err := s.Status().Err; err != io.EOF {
					t.Fatalf("dialer end %v, want a clean end", err)
				}
				eaNoViolation(t, "passive", p)
			})
		})
	}
}
