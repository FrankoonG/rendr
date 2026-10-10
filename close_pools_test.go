package rendr

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRuntimeCloseJoinsPoolBackAfterSnapshot (KL-25; L52, WP16 API-1): a
// closed Peer's pool that registers with its Runtime again after
// Runtime.Close took its first snapshot of the pools is joined by Close's
// second check before Close returns.
//
// A session survives Peer.Close on its shared trunk over link a; the trunk
// is killed while the link holds the session's redial (DialLateSuccess),
// and another Peer's NewPeer prunes the closed pool, which no longer
// tracks a trunk, from the Runtime (premise). Runtime.Close begins; right
// after its snapshot (Hooks.ClosePools) the held dial is released, its
// trunk is published, and the pool registers again through
// carrier.Env.PoolLive (premise: the Runtime tracks a pool its snapshot
// did not hold). Each one-way trip of the link takes 50 ms, so the trunk's
// end after its session (the session's view ends, then the trunk's CLOSE
// exchange) outlasts the session's own end by at least a round trip.
//
// PASS: when Runtime.Close returns, the pool that registered after the
// snapshot is joined (Pool.Wait with a done context returns nil: closed,
// no live trunk, no watcher), and both Runtimes end with nothing left.
// Without the second check Close returns before that trunk ends.
func TestRuntimeCloseJoinsPoolBackAfterSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var armed atomic.Bool
		var e *e2ePair
		var back *carrier.Pool // the pool that registered after the snapshot
		hooks := &testhooks.Hooks{ClosePools: func() {
			if !armed.CompareAndSwap(true, false) {
				return
			}
			before := mxPools(e.d)
			e.links[0].SetDial(rendrtest.DialNormal)
			e.links[0].Release()
			for deadline := time.Now().Add(5 * time.Second); back == nil && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				for p := range mxPools(e.d) {
					if _, ok := before[p]; !ok {
						back = p
					}
				}
			}
		}}
		e = e2eNew(t, Config{}, Config{}, &testhooks.Overrides{Hooks: hooks}, ListenConfig{}, "a", "b")
		e.links[0].SetDelay(50*time.Millisecond, 0)
		p := e.mxPeer(e2eCarrier(e.links[0]))
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		e2eExchange(t, dc, pc, 32<<10, 1)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		e.links[0].SetDial(rendrtest.DialLateSuccess) // the redial waits for Release
		e.links[0].Kill()
		mxWait(t, 30*time.Second, "the held redial", func() bool { return e.links[0].Stats().Dials >= 2 })
		synctest.Wait()
		other := e.mxPeer(e2eCarrier(e.links[1])) // its pool's addPool prunes the closed pool
		if n := len(mxPools(e.d)); n != 1 {
			t.Fatalf("premise: the Runtime tracks %d pools after the prune, want 1 (the other Peer's)", n)
		}

		armed.Store(true)
		if err := e.d.Close(); err != nil {
			t.Fatal(err)
		}
		if back == nil {
			t.Fatal("premise: no pool registered with the Runtime after Close's snapshot (the released redial did not publish a trunk)")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := back.Wait(ctx); err != nil {
			t.Fatalf("Runtime.Close returned before the pool that registered after its snapshot was joined (%v)", err)
		}
		_ = other
		e.close()
	})
}

// mxPools returns the pools rt tracks.
func mxPools(rt *Runtime) map[*carrier.Pool]struct{} {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make(map[*carrier.Pool]struct{}, len(rt.pools))
	for p := range rt.pools {
		out[p] = struct{}{}
	}
	return out
}
