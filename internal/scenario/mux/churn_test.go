package mux

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// goroutines counts the goroutines rendr started — those created by a
// function of package rendr or of its internal packages (scenario
// packages excluded), wherever they are blocked now — and returns them by
// creator.
func goroutines() (ours int, byTop map[string]int) {
	buf := make([]byte, 64<<20)
	buf = buf[:runtime.Stack(buf, true)]
	byTop = map[string]int{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		by := ""
		if i := strings.LastIndex(g, "\ncreated by "); i >= 0 {
			by = g[i+len("\ncreated by "):]
			if j := strings.IndexAny(by, " \n"); j >= 0 {
				by = by[:j]
			}
		}
		if !strings.HasPrefix(by, "github.com/FrankoonG/rendr/v2.") && !strings.HasPrefix(by, "github.com/FrankoonG/rendr/v2/internal/") ||
			strings.HasPrefix(by, "github.com/FrankoonG/rendr/v2/internal/scenario/") {
			continue
		}
		ours++
		byTop[strings.TrimPrefix(by, "github.com/FrankoonG/rendr/v2")]++
	}
	return ours, byTop
}

// histogram formats byTop, largest first.
func histogram(byTop map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range byTop {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v > s[j].v || (s[i].v == s[j].v && s[i].k < s[j].k) })
	var b strings.Builder
	for _, e := range s {
		fmt.Fprintf(&b, "\n\t%6d %s", e.v, e.k)
	}
	return b.String()
}

// TestMuxChurn_L52 (M3 design §A11.2; L52, M3-D20, plan:649): 1,000
// selector sessions (250 under -race, R1-11) of a one-factory Peer over a
// Link of 20 ms RTT open, echo and close through mux: one session starts
// every 10 ms, opens, moves 4 KiB each way (verified, the passive's
// direction first), closes both ends and waits for both ends' clean end
// (io.EOF); about ten are open at any time, so new sessions join a live
// shared carrier. After every 100 sessions the churn pauses until they
// ended: the shared carrier must close at its last view (the Link's
// session carriers all closed, Status.Mux counting no carrier on either
// Runtime, within 5 s), and the next burst dials a new one.
//
// PASS: every exchange verified and every session ended with io.EOF on
// both ends; the sessions went through mux — at least 90 % of them opened
// their view on a live carrier (FastPaths) and the factory was called for
// at most 10 % of them (one carrier per burst); every carrier closed at
// its last view, also after the last burst: every session carrier the
// Link ever carried is closed, one per factory call, before Peer and
// Runtime.Close; the rendr goroutines are back at the baseline taken
// after the Runtimes, the Listener and the Peer were built (L52: every
// goroutine of a session, a view and a carrier joined); both Runtimes'
// BufferedBytes are back at 0 and the session registry at its baseline;
// then Runtime.Close leaves nothing.
func TestMuxChurn_L52(t *testing.T) {
	n := 1000
	if raceEnabled {
		n = 250 // R1-11
	}
	synctest.Test(t, func(t *testing.T) {
		const gap, burst = 10 * time.Millisecond, 100
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond})
		peer := w.peer("a")
		synctest.Wait()
		base, _ := goroutines()
		var done atomic.Int64
		var wg sync.WaitGroup
		errs := make(chan error, n)
		start := time.Now()
		next := start
		for i := range n {
			if i > 0 && i%burst == 0 {
				// A pause: the burst's sessions end, the shared carrier
				// closes at its last view, and the next burst dials anew.
				wg.Wait()
				waitFor(t, 5*time.Second, fmt.Sprintf("the shared carrier closed after burst %d", i/burst), func() bool {
					_, open := sessionCarriers(w.link("a"))
					return open == 0 && w.d.Status().Mux.Carriers == 0 && w.p.Status().Mux.Carriers == 0
				})
				next = time.Now()
			}
			sleepUntil(next)
			next = next.Add(gap)
			wg.Go(func() {
				s, err := w.tryOpen(peer, fmt.Sprintf("C%d", i), rendr.ModeSelector)
				if err == nil {
					err = echo(s, 4<<10, uint64(10+2*i))
				}
				if err == nil {
					s.d.Close()
					s.p.Close()
					for _, c := range []*rendr.Conn{s.d, s.p} {
						select {
						case <-c.Done():
						case <-time.After(30 * time.Second):
							err = fmt.Errorf("session %s not done 30 s after Close", s.key)
						}
						if st := c.Status(); err == nil && st.Err != io.EOF {
							err = fmt.Errorf("session %s: the %v ended with %v, want io.EOF", s.key, st.Role, st.Err)
						}
					}
				}
				if err != nil {
					errs <- err
					return
				}
				done.Add(1)
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if t.Failed() {
			t.FailNow()
		}
		took := time.Since(start)
		m := w.d.Status().Mux
		calls := w.dials("a")
		if done.Load() != int64(n) || m.FastPaths*10 < uint64(9*n) || calls*10 > n {
			t.Fatalf("%d of %d sessions done; FastPaths %d, factory calls %d: want all done, FastPaths ≥ 90 %% and calls ≤ 10 %%", done.Load(), n, m.FastPaths, calls)
		}
		w.muxIdle(10 * time.Second)
		all, open := sessionCarriers(w.link("a"))
		if open != 0 || all != calls {
			t.Fatalf("the Link carried %d session carriers (%d open) for %d factory calls, want every one closed", all, open, calls)
		}
		var ours int
		var byTop map[string]int
		waitFor(t, 10*time.Second, "the rendr goroutines back at the baseline", func() bool {
			synctest.Wait()
			ours, byTop = goroutines()
			return ours <= base
		})
		for i, rt := range []*rendr.Runtime{w.d, w.p} {
			if b := rt.Status().BufferedBytes; b != 0 {
				t.Fatalf("%s BufferedBytes %d after the churn, want 0", side(i), b)
			}
		}
		if l, p := testhooks.LiveSessions.Load()-w.live0, testhooks.ParkedSessions.Load()-w.parked0; l != 0 || p != 0 {
			t.Fatalf("session registry after the churn: %+d live, %+d parked", l, p)
		}
		t.Logf("%d sessions in %v: %d factory calls, Mux %+v; rendr goroutines %d (baseline %d):%s", n, took, calls, m, ours, base, histogram(byTop))
		w.noViolation()
		w.close()
	})
}
