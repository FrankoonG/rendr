package mux

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// shareBytes is what each session of the sharing scenarios moves each way.
const shareBytes = 256 << 10

// exchangeAll runs echo on every session concurrently (seed by index) and
// fails the test on the first error.
func exchangeAll(t testing.TB, ps []pair, n int64, seed uint64) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, len(ps))
	for i, s := range ps {
		wg.Go(func() { errs <- echo(s, n, seed+uint64(2*i)) })
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatalf("the exchanges did not finish within a minute")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}

// requireShared requires that every session (both ends) holds exactly one
// live carrier, the same one for all, reporting Shared == len(ps), and
// returns it.
func requireShared(t testing.TB, ps []pair) rendr.CarrierID {
	t.Helper()
	var id rendr.CarrierID
	for _, s := range ps {
		for i, c := range []*rendr.Conn{s.d, s.p} {
			live := liveOf(c.Status())
			if len(live) != 1 {
				t.Fatalf("session %s (%s): %d live carriers %+v, want 1", s.key, side(i), len(live), live)
			}
			if id == 0 {
				id = live[0].ID
			}
			if live[0].ID != id || live[0].Shared != len(ps) {
				t.Fatalf("session %s (%s): live carrier %d with Shared %d, want carrier %d with Shared %d", s.key, side(i), live[0].ID, live[0].Shared, id, len(ps))
			}
		}
	}
	return id
}

// TestMuxSharesOneCarrier (M3 design §A11.2; M3-D1, M3-D8, M3-D16): a
// one-factory Peer (default Props: shared carriers) opens 8 selector
// sessions concurrently over one Link of 20 ms RTT.
//
// Stimulus: the 8 concurrent Dials. Proof that they shared: the factory
// was called once for a session carrier and the Listener accepted one
// carrier; every session lists that one carrier on both ends with
// Shared = 8; Status.Mux counts 1 carrier and 8 views on both Runtimes,
// the dialer's FastPaths count the 7 sessions that placed their OPEN on
// the live carrier instead of dialling (those that waited for the first
// dial are also counted in Coalesced, at most 7). Load and integrity: every session moves 256 KiB each way, the
// passive's direction first (a passive-first exchange on a view opened on
// a started carrier needs the dialer's go frame, M3-D8), verified byte for
// byte; each session's row of the shared carrier attributes at least its
// own payload to it in both directions (per-view counters, M3-D49). Then
// every session closes cleanly, the carrier closes at its last view
// (M3-D20) and Runtime.Close leaves nothing.
func TestMuxSharesOneCarrier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond})
		peer := w.peer("a")
		ps := w.openMany(peer, "S", 8, func(int) rendr.Mode { return rendr.ModeSelector })

		if got, acc := w.dials("a"), w.accepted("a"); got != 1 || acc != 1 {
			t.Fatalf("8 sessions made %d factory calls and the Listener accepted %d carriers, want 1 each", got, acc)
		}
		id := requireShared(t, ps)
		w.identities("after the opens", ps)
		if m := w.d.Status().Mux; m.Carriers != 1 || m.Views != 8 || m.FastPaths != 7 || m.Coalesced > 7 {
			t.Fatalf("dialer Status.Mux %+v, want 1 carrier, 8 views, FastPaths 7 and Coalesced ≤ 7", m)
		}
		if m := w.p.Status().Mux; m.Carriers != 1 || m.Views != 8 {
			t.Fatalf("passive Status.Mux %+v, want 1 carrier and 8 views", m)
		}

		exchangeAll(t, ps, shareBytes, 1)
		for _, s := range ps {
			for i, c := range []*rendr.Conn{s.d, s.p} {
				cs, _ := carrierOf(c.Status(), id)
				if cs.TxBytes < shareBytes || cs.RxBytes < shareBytes {
					t.Fatalf("session %s (%s): its row of carrier %d counts TxBytes %d and RxBytes %d, want ≥ %d each", s.key, side(i), id, cs.TxBytes, cs.RxBytes, shareBytes)
				}
			}
		}
		if got, acc := w.dials("a"), w.accepted("a"); got != 1 || acc != 1 {
			t.Fatalf("after the exchanges: %d factory calls, %d accepted carriers, want 1 each", got, acc)
		}
		t.Logf("8 sessions on carrier %d; dialer Mux %+v", id, w.d.Status().Mux)

		closeAll(t, ps)
		w.muxIdle(10 * time.Second)
		w.noViolation()
		w.close()
	})
}

// TestMuxCheapSubflowDialsPerSession (M3 design §A11.2; M3-D2, plan §3.2):
// the same 8 concurrent selector sessions over a factory with
// Props.CheapSubflow: every session dials its own carrier — 8 factory
// calls, 8 carriers accepted, 8 distinct carriers each reporting Shared 1
// and Handle 1 — and nothing is shared (Status.Mux counts no carrier, no
// fast path and no coalesced attempt). Every session moves 256 KiB each
// way, verified, closes cleanly, and Runtime.Close leaves nothing.
func TestMuxCheapSubflowDialsPerSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, props: rendr.Props{CheapSubflow: true}})
		peer := w.peer("a")
		ps := w.openMany(peer, "S", 8, func(int) rendr.Mode { return rendr.ModeSelector })

		if got, acc := w.dials("a"), w.accepted("a"); got != 8 || acc != 8 {
			t.Fatalf("8 sessions made %d factory calls and the Listener accepted %d carriers, want 8 each", got, acc)
		}
		seen := map[rendr.CarrierID]bool{}
		for _, s := range ps {
			for i, c := range []*rendr.Conn{s.d, s.p} {
				live := liveOf(c.Status())
				if len(live) != 1 || live[0].Shared != 1 || live[0].Handle != 1 {
					t.Fatalf("session %s (%s): live carriers %+v, want one with Shared 1 and Handle 1", s.key, side(i), live)
				}
				if i == 0 {
					if seen[live[0].ID] {
						t.Fatalf("session %s shares carrier %d", s.key, live[0].ID)
					}
					seen[live[0].ID] = true
				}
			}
		}
		for i, rt := range []*rendr.Runtime{w.d, w.p} {
			if m := rt.Status().Mux; m != (rendr.MuxStatus{}) {
				t.Fatalf("%s Status.Mux %+v, want zero (no shared carrier)", side(i), m)
			}
		}
		exchangeAll(t, ps, shareBytes, 1)
		closeAll(t, ps)
		w.noViolation()
		w.close()
	})
}

// TestMuxLastSessionClosesCarrier (M3 design §A5.9, §A11.2; M3-D6, M3-D20,
// PA-39): three selector sessions share the one carrier of a one-factory
// Peer (20 ms RTT) and are closed one after the other.
//
// Stimulus: each session's clean close (both ends, io.EOF). While a session
// is left the carrier lives: a closing session retires only its own view
// (DETACH, not CLOSE), so after each close and RetireGrace + 1 s the
// remaining sessions still list the same live carrier, neither Runtime
// published an EventCarrierDown of it, the Link still has exactly one open
// session carrier, Status.Mux counts the remaining views on both ends, and
// the remaining sessions still exchange 64 KiB each way (verified). After
// the last session ended, the carrier closes at its last view: within
// RetireGrace the passive's Status.Mux counts no carrier and the Link's
// carrier is closed. A following session dials a new carrier (one more
// factory call and accept, a new CarrierID), works, and closes; Runtime.Close
// then leaves nothing.
func TestMuxLastSessionClosesCarrier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const retireGrace = 2 * time.Second // the default
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond})
		peer := w.peer("a")
		var ps []pair
		for _, k := range []string{"S0", "S1", "S2"} {
			ps = append(ps, w.open(peer, k, rendr.ModeSelector))
		}
		id := requireShared(t, ps)
		exchangeAll(t, ps, 64<<10, 1)
		l := w.link("a")

		for i := range ps {
			s := ps[i]
			closeBoth(t, s)
			rest := ps[i+1:]
			if len(rest) == 0 {
				break
			}
			time.Sleep(retireGrace + time.Second)
			for _, r := range rest {
				for j, c := range []*rendr.Conn{r.d, r.p} {
					if live := liveOf(c.Status()); len(live) != 1 || live[0].ID != id {
						t.Fatalf("after %s closed: session %s (%s) lists live carriers %+v, want carrier %d", s.key, r.key, side(j), live, id)
					}
				}
			}
			for j, log := range []*eventLog{w.dev, w.pev} {
				for _, r := range rest {
					if ev, ok := log.sessionDown(r.d.ID(), id); ok {
						t.Fatalf("after %s closed: the %s published %+v for session %s", s.key, side(j), ev, r.key)
					}
				}
			}
			if _, open := sessionCarriers(l); open != 1 {
				t.Fatalf("after %s closed: %d open session carriers on the Link, want the shared one", s.key, open)
			}
			for j, rt := range []*rendr.Runtime{w.d, w.p} {
				if m := rt.Status().Mux; m.Carriers != 1 || m.Views != len(rest) {
					t.Fatalf("after %s closed: %s Status.Mux %+v, want 1 carrier with %d views", s.key, side(j), m, len(rest))
				}
			}
			exchangeAll(t, rest, 64<<10, uint64(10*(i+1)))
		}

		last := time.Now()
		waitFor(t, retireGrace, "the shared carrier to close at its last view", func() bool {
			_, open := sessionCarriers(l)
			return open == 0 && w.p.Status().Mux.Carriers == 0 && w.d.Status().Mux.Carriers == 0
		})
		t.Logf("the carrier closed %v after the last session ended", time.Since(last))
		if got, acc := w.dials("a"), w.accepted("a"); got != 1 || acc != 1 {
			t.Fatalf("three sessions made %d factory calls and %d accepted carriers, want 1 each", got, acc)
		}

		next := w.open(peer, "S3", rendr.ModeSelector)
		if got, acc := w.dials("a"), w.accepted("a"); got != 2 || acc != 2 {
			t.Fatalf("the following session made the factory calls %d and accepted carriers %d, want 2 each (a new carrier)", got, acc)
		}
		if nid := requireShared(t, []pair{next}); nid == id {
			t.Fatalf("the following session uses the closed carrier %d", id)
		}
		exchangeAll(t, []pair{next}, 64<<10, 100)
		closeBoth(t, next)
		w.muxIdle(retireGrace)
		w.noViolation()
		w.close()
	})
}

// TestMuxNeverAcrossPeers (M3 design §A5.8 scope, §A11.2): two Peers with
// identical factories (the same Link and factory name) to one Listener
// open 4 selector sessions each, concurrently and interleaved. The pool is
// per Peer: two factory calls and two accepted carriers, the sessions of
// each Peer on one carrier (Shared 4 on both ends), the two carriers
// distinct; the dialer's Status.Mux counts 2 carriers and 8 views. Every
// session moves 256 KiB each way, verified. Then the first Peer's sessions
// close: its carrier closes at its last view while the second Peer's
// carrier lives on untouched (same ID, no EventCarrierDown, still
// exchanging), and a new session of the first Peer dials its own carrier
// (a third factory call) instead of joining the second Peer's.
func TestMuxNeverAcrossPeers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond})
		peers := []*rendr.Peer{w.peer("a"), w.peer("a")}
		var groups [2][]pair
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Go(func() {
				s, err := w.tryOpen(peers[i%2], "P"+string(rune('0'+i%2))+"S"+string(rune('0'+i)), rendr.ModeSelector)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				groups[i%2] = append(groups[i%2], s)
				mu.Unlock()
			})
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
		if got, acc := w.dials("a"), w.accepted("a"); got != 2 || acc != 2 {
			t.Fatalf("two Peers made %d factory calls and the Listener accepted %d carriers, want 2 each", got, acc)
		}
		ids := [2]rendr.CarrierID{requireShared(t, groups[0]), requireShared(t, groups[1])}
		if ids[0] == ids[1] {
			t.Fatalf("both Peers' sessions are on carrier %d", ids[0])
		}
		w.identities("after the opens", append(append([]pair{}, groups[0]...), groups[1]...))
		if m := w.d.Status().Mux; m.Carriers != 2 || m.Views != 8 {
			t.Fatalf("dialer Status.Mux %+v, want 2 carriers and 8 views", m)
		}
		exchangeAll(t, append(append([]pair{}, groups[0]...), groups[1]...), shareBytes, 1)

		closeAll(t, groups[0])
		waitFor(t, 2*time.Second, "the first Peer's carrier to close at its last view", func() bool {
			return w.d.Status().Mux.Carriers == 1 && w.p.Status().Mux.Carriers == 1
		})
		if id := requireShared(t, groups[1]); id != ids[1] {
			t.Fatalf("the second Peer's sessions moved from carrier %d to %d", ids[1], id)
		}
		for j, log := range []*eventLog{w.dev, w.pev} {
			if evs := log.downOf(ids[1]); len(evs) != 0 {
				t.Fatalf("the %s published %+v for the second Peer's carrier", side(j), evs)
			}
		}
		exchangeAll(t, groups[1], 64<<10, 100)

		s := w.open(peers[0], "P0S8", rendr.ModeSelector)
		if got := w.dials("a"); got != 3 {
			t.Fatalf("the first Peer's new session made the factory calls %d in all, want 3 (its own carrier)", got)
		}
		if live := liveOf(s.d.Status()); len(live) != 1 || live[0].ID == ids[1] || live[0].Shared != 1 {
			t.Fatalf("the first Peer's new session lists %+v, want its own carrier (not %d) with Shared 1", live, ids[1])
		}
		exchangeAll(t, []pair{s}, 64<<10, 200)
		closeBoth(t, s)
		closeAll(t, groups[1])
		w.muxIdle(2 * time.Second)
		w.noViolation()
		w.close()
	})
}
