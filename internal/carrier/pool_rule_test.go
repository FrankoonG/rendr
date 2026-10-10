package carrier

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPoolNotMuxedReleasesWaiters (E16): the claimant's passive does not
// echo OptMux (an M2 passive): its carrier is dedicated and never
// published, and its waiters retry at once — each dials a dedicated
// carrier of its own in turn; nobody fails.
func TestPoolNotMuxedReleasesWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		clearOpt := func(b []byte) { b[12], b[13], b[14], b[15] = 0, 0, 0, 0 }
		pt.srv.wrap = func(_ int, nc net.Conn) net.Conn { return phRewrite(nc, clearOpt) }
		gate := make(chan struct{})
		pt.srv.setGate(gate)
		ch := make(chan poolRes, 3)
		for i := 1; i <= 3; i++ {
			pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
		}
		synctest.Wait()
		start := time.Now()
		close(gate)
		for _, r := range collect(t, ch, 3) {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || r.est.Conn.Mux() {
				t.Fatalf("attempt %d: %v (fresh %v)", r.sid, r.err, r.est != nil && r.est.Fresh)
			}
			if r.at != start {
				t.Fatalf("attempt %d returned %v after the gate opened, want at once", r.sid, r.at.Sub(start))
			}
			pt.attach(r.est)
		}
		synctest.Wait()
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 3 || st.Carriers != 0 || st.FastPaths != 0 {
			t.Fatalf("%d factory calls, stats %+v; want 3 dedicated carriers and nothing published", d, st)
		}
	})
}

// TestPoolUsableRule (M3-D17, M3-D27, R1-6, R1-10): each clause of the
// usable rule alone excludes a trunk — no OptMux, not started, dying,
// retiring, the peer's CLOSE, the peer's GOAWAY, our CLOSE, write-blocked,
// sealed, at its view cap, marked full by CodeMuxFull, a stream session on
// a datagram trunk, a JOIN for another instance, a view of the session
// that is not yet reaped; CodeListenerClosed excludes OPENs only. Among
// usable trunks the one with the most views wins, then the oldest.
func TestPoolUsableRule(t *testing.T) {
	var zero [16]byte
	pick := func(p *Pool, dk wire.Type, inst [16]byte, sess uintptr) *Conn {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.pickLocked(0, dk, inst, sess, nil)
	}
	pool := func(env *Env, cs ...*Conn) *Pool {
		p := NewPool(env, []Factory{{Name: "f0", Mux: true}})
		p.trunks[0] = cs
		return p
	}
	type clause struct {
		name string
		mod  func(env *Env)
		set  func(t *testing.T, d *muxSide) // makes the trunk unusable for an OPEN of a stream session
	}
	clauses := []clause{
		{name: "dying", set: func(t *testing.T, d *muxSide) { d.c.KillTrunk(CauseLocalClose, "test") }},
		{name: "retiring", set: func(t *testing.T, d *muxSide) { d.c.retireTrunk(wire.CloseRetire) }},
		{name: "peer CLOSE", set: func(t *testing.T, d *muxSide) { d.c.peerClosed.Store(true) }},
		{name: "peer GOAWAY", set: func(t *testing.T, d *muxSide) { d.c.peerGoAway.Store(true) }},
		{name: "our CLOSE", set: func(t *testing.T, d *muxSide) { d.c.closeSent.Store(true) }},
		{name: "write-blocked", set: func(t *testing.T, d *muxSide) { d.c.wstate.Store(d.c.wstate.Load() | 1) }},
		{name: "sealed", set: func(t *testing.T, d *muxSide) { d.c.seal() }},
		{name: "full", set: func(t *testing.T, d *muxSide) {
			d.c.mx.Lock()
			d.c.ms.full = true
			d.c.mx.Unlock()
		}},
		{name: "view cap", mod: func(env *Env) { env.Timing.MuxMaxViews = 2 }, set: func(t *testing.T, d *muxSide) {
			d.open(t, wire.TypeOpen, 9)
		}},
		{name: "own view", set: func(t *testing.T, d *muxSide) { d.c.bindSession(5) }},
	}
	for _, cl := range clauses {
		t.Run(cl.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d, _ := muxPair(t, cl.mod)
				synctest.Wait()
				p := pool(d.env, d.c)
				if got := pick(p, wire.TypeData, zero, 5); got != d.c {
					t.Fatal("the trunk is not usable before the clause")
				}
				cl.set(t, d)
				if got := pick(p, wire.TypeData, zero, 5); got != nil {
					t.Fatalf("clause %q: the trunk is still usable", cl.name)
				}
			})
		})
	}
	t.Run("no OptMux", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := dgEnv()
			a, b := net.Pipe()
			c := newConn(env, a, 7, mPassiveInst, 0, "f0", true)
			hCleanup(t, c, startPeer(b, env.Presets.firstFseq()))
			c.Start(&dEP{}, &hBell{}, StartOptions{})
			if got := pick(pool(env, c), wire.TypeData, zero, 5); got != nil {
				t.Fatal("a dedicated trunk is usable")
			}
		})
	})
	t.Run("not started", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := dgEnv()
			a, b := net.Pipe()
			c := newConn(env, a, 7, mPassiveInst, 0, "f0", true)
			c.mux = true
			hCleanup(t, c, startPeer(b, env.Presets.firstFseq()))
			if got := pick(pool(env, c), wire.TypeData, zero, 5); got != nil {
				t.Fatal("an unstarted trunk is usable")
			}
		})
	})
	t.Run("kind", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, _, _, _ := dgMuxPair(t, 1200, nil)
			synctest.Wait()
			p := pool(d.env, d.c)
			if got := pick(p, wire.TypeData, zero, 5); got != nil {
				t.Fatal("a datagram trunk is usable for a stream session")
			}
			if got := pick(p, wire.TypeDgram, zero, 5); got != d.c {
				t.Fatal("a datagram trunk is not usable for a packet session")
			}
		})
	})
	t.Run("instance", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, _ := muxPair(t, nil)
			synctest.Wait()
			p := pool(d.env, d.c)
			if got := pick(p, wire.TypeData, mPassiveInst, 5); got != d.c {
				t.Fatal("a JOIN for the trunk's instance cannot use it")
			}
			if got := pick(p, wire.TypeData, hPeerInst, 5); got != nil {
				t.Fatal("a JOIN for another instance can use the trunk")
			}
		})
	})
	t.Run("listener closed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, _ := muxPair(t, nil)
			synctest.Wait()
			d.c.mx.Lock()
			d.c.openFull = true
			d.c.mx.Unlock()
			p := pool(d.env, d.c)
			if got := pick(p, wire.TypeData, zero, 5); got != nil {
				t.Fatal("an OPEN can use a trunk whose Listener closed")
			}
			if got := pick(p, wire.TypeData, mPassiveInst, 5); got != d.c {
				t.Fatal("a JOIN cannot use a trunk whose Listener closed")
			}
		})
	})
	t.Run("own view reaped", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, _ := muxPair(t, nil)
			synctest.Wait()
			mv, _ := d.open(t, wire.TypeOpen, 7) // session 7's view
			synctest.Wait()
			p := pool(d.env, d.c)
			if got := pick(p, wire.TypeData, zero, 7); got != nil {
				t.Fatal("session 7 can open a second view on the trunk")
			}
			if got := pick(p, wire.TypeData, zero, 8); got != d.c {
				t.Fatal("session 8 cannot use the trunk")
			}
			mv.c.Kill(CauseLocalClose, "ended")
			waitDone(t, mv.c.Done(), "view 2")
			if got := pick(p, wire.TypeData, zero, 7); got != d.c {
				t.Fatal("session 7 cannot return after its view ended")
			}
		})
	})
	t.Run("factory", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil) // factories p0 and p1 to one passive
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, zero)
			if err != nil || !est1.Fresh {
				t.Fatalf("p0: %v", err)
			}
			pt.attach(est1)
			est2, err := pt.attempt(context.Background(), 1, wire.TypeOpen, 2, zero)
			if err != nil || !est2.Fresh || est2.Conn.trunk == est1.Conn.trunk {
				t.Fatalf("p1 with a live p0 trunk: %v (fresh %v)", err, est2 != nil && est2.Fresh)
			}
			pt.attach(est2)
			est3, err := pt.attempt(context.Background(), 1, wire.TypeOpen, 3, zero)
			if err != nil || est3.Fresh || est3.Conn.trunk != est2.Conn.trunk {
				t.Fatalf("p1's next attempt did not take p1's trunk: %v", err)
			}
			pt.attach(est3)
			if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.FastPaths != 1 || st.Carriers != 2 {
				t.Fatalf("%d factory calls, stats %+v; want one trunk per factory", d, st)
			}
		})
	})
	t.Run("choice", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, _ := muxPair(t, nil)
			b, _ := muxPair(t, nil)
			c, _ := muxPair(t, nil)
			synctest.Wait()
			b.open(t, wire.TypeOpen, 2)
			if got := pick(pool(a.env, a.c, b.c, c.c), wire.TypeData, zero, 5); got != b.c {
				t.Fatal("the trunk with the most views was not chosen")
			}
			if got := pick(pool(a.env, a.c, c.c), wire.TypeData, zero, 5); got != a.c {
				t.Fatal("of two trunks with as many views the oldest was not chosen")
			}
		})
	})
}

// TestPoolBlockedNotUsable_L08 (E11; L08): a trunk whose batch write is
// blocked (WriteBlocked) takes no new view: the next attempt dials,
// although the blocked trunk is the fullest.
func TestPoolBlockedNotUsable_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		var tap *frameTap
		pt.srv.wrap = func(n int, nc net.Conn) net.Conn {
			if n != 1 {
				return nc
			}
			tap = newFrameTap(nc)
			return tap
		}
		est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		if err != nil {
			t.Fatal(err)
		}
		defer tap.release()
		pt.attach(est1)
		est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
		if err != nil || est2.Fresh {
			t.Fatalf("fast path: %v", err)
		}
		pt.attach(est2)
		synctest.Wait()
		tap.hold()
		est1.Conn.RequestPing() // a write that blocks
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if !est1.Conn.WriteBlocked() {
			t.Fatal("the held write did not mark the trunk write-blocked")
		}
		start := time.Now()
		est3, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 3, [16]byte{})
		if err != nil || !est3.Fresh || est3.Conn.trunk == est1.Conn.trunk {
			t.Fatalf("attempt on a write-blocked trunk: %v (fresh %v)", err, est3 != nil && est3.Fresh)
		}
		pt.attach(est3)
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.FastPaths != 1 || time.Since(start) != 0 {
			t.Fatalf("%d factory calls, stats %+v, %v: want a dial at once and no view on the blocked trunk", d, st, time.Since(start))
		}
		tap.release()
	})
}

// TestPoolPickThenDeath (E3): a listed trunk that died is skipped; a trunk
// that dies between the pick and openView (openView fails ErrDead), or
// after its view's handle was allocated but before the view's first frame
// was placed — whether the view's own end or the trunk's Done comes
// first — makes the attempt continue with a dial of its own, no failure.
func TestPoolPickThenDeath(t *testing.T) {
	t.Run("dead between the pick and openView", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil {
				t.Fatal(err)
			}
			pt.attach(est1)
			killed := false
			pt.p.afterPick = func(c *Conn) {
				if c.trunk == est1.Conn.trunk {
					killed = c.KillTrunk(CauseTransportError, "killed after the pick")
				}
			}
			est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
			if !killed {
				t.Fatal("the attempt did not pick the live trunk")
			}
			if err != nil || !est2.Fresh || !isOK(est2) || est2.Conn.trunk == est1.Conn.trunk {
				t.Fatalf("attempt whose trunk died before openView: %v", err)
			}
			pt.attach(est2)
			if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.FastPaths != 0 {
				t.Fatalf("%d factory calls, stats %+v; want no fast path and a dial", d, st)
			}
		})
	})
	t.Run("trunk done before the first frame", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil {
				t.Fatal(err)
			}
			pt.attach(est1)
			pt.env.Hooks = &testhooks.Hooks{BeforeOpenView: func(carrier, handle uint32) {
				if carrier == est1.Conn.ID() {
					est1.Conn.KillTrunk(CauseTransportError, "killed after the pick")
					synctest.Wait() // the trunk's Done (finishAll: opening → dead) before the attempt looks
					select {
					case <-est1.Conn.trunk.tdone:
					default:
						t.Error("the killed trunk is not done before the attempt goes on")
					}
				}
			}}
			est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
			if err != nil || !est2.Fresh || !isOK(est2) || est2.Conn.trunk == est1.Conn.trunk {
				t.Fatalf("attempt whose trunk finished before its first frame: %v", err)
			}
			pt.attach(est2)
			if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.FastPaths != 1 {
				t.Fatalf("%d factory calls, stats %+v; want the fast path then a dial", d, st)
			}
		})
	})
	t.Run("dead before the pick", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil {
				t.Fatal(err)
			}
			pt.attach(est1)
			synctest.Wait()
			est1.Conn.KillTrunk(CauseTransportError, "test kill")
			est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
			if err != nil || !est2.Fresh || !isOK(est2) {
				t.Fatalf("attempt after the death: %v", err)
			}
			pt.attach(est2)
			if d := pt.srv.dials.Load(); d != 2 {
				t.Fatalf("%d factory calls, want 2", d)
			}
		})
	})
	t.Run("dead before the first frame", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			closeGate := make(chan struct{})
			pt := newPoolT(t, nil, nil)
			pt.srv.wrap = func(n int, nc net.Conn) net.Conn {
				if n != 1 {
					return nc
				}
				// The dead trunk's Done waits: its views end by the attempt's
				// own Kill, never by the trunk's Done (a deterministic order).
				return &hookConn{Conn: nc, onClose: func(nc net.Conn) error { <-closeGate; return nc.Close() }}
			}
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil {
				t.Fatal(err)
			}
			defer close(closeGate)
			pt.attach(est1)
			synctest.Wait()
			pt.env.Hooks = &testhooks.Hooks{BeforeOpenView: func(carrier, handle uint32) {
				if carrier == est1.Conn.ID() {
					est1.Conn.KillTrunk(CauseTransportError, "killed after the pick")
				}
			}}
			est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
			if err != nil || !est2.Fresh || !isOK(est2) || est2.Conn.trunk == est1.Conn.trunk {
				t.Fatalf("attempt whose trunk died before its first frame: %v", err)
			}
			pt.attach(est2)
			if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.FastPaths != 1 {
				t.Fatalf("%d factory calls, stats %+v; want the fast path then a dial", d, st)
			}
		})
	})
}

// TestPoolSealAtZero (M3-D20, §A5.9, E2): a published trunk leaves the pool
// at its last view — sealed, retired with CLOSE (both ends close) — and
// the next attempt dials; while a view remains it stays. An openView that
// counted before the close check keeps the trunk open.
func TestPoolSealAtZero(t *testing.T) {
	t.Run("last view", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			pt.attach(est1)
			est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
			if err != nil || est2.Fresh {
				t.Fatalf("fast path: %v", err)
			}
			pt.attach(est2)
			synctest.Wait()
			tr := est1.Conn.trunk
			est2.Conn.Kill(CauseLocalClose, "session 2 ended")
			waitDone(t, est2.Conn.Done(), "view 2")
			synctest.Wait()
			if len(pt.p.listed(0)) != 1 || tr.sealed || tr.closeSent.Load() {
				t.Fatal("the trunk left the pool with a view remaining")
			}
			est1.Conn.Kill(CauseLocalClose, "session 1 ended")
			waitDone(t, est1.Conn.Done(), "view 1")
			synctest.Wait()
			if len(pt.p.listed(0)) != 0 || !tr.sealed {
				t.Fatal("the trunk stayed in the pool at zero views")
			}
			waitDone(t, tr.tdone, "the dialer trunk")
			if !tr.closeSent.Load() {
				t.Fatal("the trunk closed without its CLOSE")
			}
			waitDone(t, pt.srv.accepted()[0].trunk.tdone, "the passive trunk")
			if st := pt.p.Stats(); st.Carriers != 0 || st.Views != 0 {
				t.Fatalf("stats %+v after the close", st)
			}
			est3, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 3, [16]byte{})
			if err != nil || !est3.Fresh {
				t.Fatalf("attempt after the close: %v", err)
			}
			pt.attach(est3)
			if d := pt.srv.dials.Load(); d != 2 {
				t.Fatalf("%d factory calls, want 2", d)
			}
		})
	})
	t.Run("views ended before the publication", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil || !est1.Fresh {
				t.Fatalf("claimant: %v", err)
			}
			ch := make(chan poolRes, 1)
			pt.goAttempt(context.Background(), wire.TypeOpen, 2, ch) // waits for the fresh trunk
			synctest.Wait()
			tr := est1.Conn.trunk
			// Start publishes on a goroutine of its own (poolStarted), which
			// takes Pool.mu: holding it until view 1's Done closed makes the
			// publication find no view. Without the hold the publication
			// could run first, the waiter's retry then opened view 2 on the
			// published trunk, and the trunk rightly stayed (a premise race,
			// about 1 in 1200 host -race runs under load).
			pt.p.mu.Lock()
			est1.Conn.Start(&dEP{}, &hBell{}, StartOptions{})
			est1.Conn.Kill(CauseLocalClose, "session 1 ended") // its only view ends before the publication
			waitDone(t, est1.Conn.Done(), "view 1")
			pt.p.mu.Unlock()
			synctest.Wait()
			est1.Conn.poolStarted()
			synctest.Wait()
			if len(pt.p.listed(0)) != 0 || !tr.sealed {
				t.Fatal("a trunk without views was published")
			}
			waitDone(t, tr.tdone, "the trunk without views")
			if !tr.closeSent.Load() {
				t.Fatal("the trunk without views closed without its CLOSE")
			}
			r := collect(t, ch, 1)[0]
			if r.err != nil || !r.est.Fresh || r.est.Conn.trunk == tr {
				t.Fatalf("the waiter: %v (fresh %v)", r.err, r.est != nil && r.est.Fresh)
			}
			pt.attach(r.est)
			if d := pt.srv.dials.Load(); d != 2 {
				t.Fatalf("%d factory calls, want 2", d)
			}
		})
	})
	t.Run("open races the close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			pt.attach(est1)
			synctest.Wait()
			tr := est1.Conn.trunk
			// The last view ends while an attempt holds Pool.mu: the view
			// count reaches 0 and the pool's hook waits for the lock; the
			// attempt's openView counts first (as Attempt does under the
			// lock), so the hook finds a view and nothing closes.
			pt.p.mu.Lock()
			est1.Conn.Kill(CauseLocalClose, "session 1 ended")
			c := pt.p.pickLocked(0, wire.TypeData, [16]byte{}, 9, nil)
			if c == nil {
				pt.p.mu.Unlock()
				t.Fatal("the trunk is not usable at zero views before the close")
			}
			v, err := c.openView(wire.TypeOpen, poolPayload(wire.TypeOpen, 9), 9)
			pt.p.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if len(pt.p.listed(0)) != 1 || tr.sealed {
				t.Fatal("the trunk closed although a view was opened before the close check")
			}
			est, err := v.awaitResponse(context.Background(), nil)
			if err != nil || !isOK(est) {
				t.Fatalf("the racing view: %v", err)
			}
			pt.ests = append(pt.ests, est)
			pt.attach(est)
			synctest.Wait()
			est.Conn.Kill(CauseLocalClose, "session 9 ended")
			waitDone(t, tr.tdone, "the trunk at its last view")
		})
	})
}

// TestPoolNeverAcrossPeers (M3-D16): two Peers' pools with the same
// factories to one Listener never share a trunk.
func TestPoolNeverAcrossPeers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		pb := NewPool(pt.env, []Factory{pt.srv.factory("p0", 0)})
		a1, err := pt.attemptOn(context.Background(), pt.p, 0, wire.TypeOpen, 1, [16]byte{})
		if err != nil || !a1.Fresh {
			t.Fatal(err)
		}
		pt.attach(a1)
		synctest.Wait()
		b1, err := pt.attemptOn(context.Background(), pb, 0, wire.TypeOpen, 2, [16]byte{})
		if err != nil || !b1.Fresh || b1.Conn.trunk == a1.Conn.trunk {
			t.Fatalf("Peer B's first attempt: %v (fresh %v)", err, b1 != nil && b1.Fresh)
		}
		pt.attach(b1)
		a2, _ := pt.attemptOn(context.Background(), pt.p, 0, wire.TypeOpen, 3, [16]byte{})
		b2, _ := pt.attemptOn(context.Background(), pb, 0, wire.TypeOpen, 4, [16]byte{})
		if a2 == nil || b2 == nil || a2.Conn.trunk != a1.Conn.trunk || b2.Conn.trunk != b1.Conn.trunk {
			t.Fatal("a fast path crossed Peers")
		}
		pt.attach(a2)
		pt.attach(b2)
		if d := pt.srv.dials.Load(); d != 2 || len(pt.srv.accepted()) != 2 {
			t.Fatalf("%d factory calls, want one per Peer", d)
		}
	})
}

// TestPoolMuxFull (M3-D12, M3-D17): a trunk at the view cap takes no new
// view (the attempt dials without placing an OPEN on it); a passive with a
// smaller cap answers CAPACITY CodeMuxFull, which counts in MuxFull, marks
// the trunk full until a view leaves and makes the attempt dial — without
// returning the refusal.
func TestPoolMuxFull(t *testing.T) {
	cap2 := func(env *Env) { env.Timing.MuxMaxViews = 2 }
	t.Run("dialer cap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, cap2, cap2)
			est1, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			pt.attach(est1)
			est2, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
			pt.attach(est2)
			est3, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 3, [16]byte{})
			if err != nil || !est3.Fresh || !isOK(est3) {
				t.Fatalf("attempt at the cap: %v", err)
			}
			pt.attach(est3)
			synctest.Wait()
			if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.MuxFull != 0 || st.FastPaths != 1 || len(pt.srv.admitted()) != 1 {
				t.Fatalf("%d factory calls, stats %+v, %d admitted; want no OPEN on the full trunk", d, st, len(pt.srv.admitted()))
			}
		})
	})
	t.Run("passive cap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, cap2)
			est1, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			pt.attach(est1)
			est2, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
			pt.attach(est2)
			est3, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 3, [16]byte{})
			if err != nil || !est3.Fresh || !isOK(est3) {
				t.Fatalf("attempt refused CodeMuxFull: %v (fresh %v)", err, est3 != nil && est3.Fresh)
			}
			pt.attach(est3)
			synctest.Wait()
			if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.MuxFull != 1 {
				t.Fatalf("%d factory calls, stats %+v; want one CodeMuxFull and a dial", d, st)
			}
			t1 := est1.Conn
			if pt.p.usable(t1, 9) {
				t.Fatal("the full trunk is usable")
			}
			est4, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 4, [16]byte{})
			if est4 == nil || est4.Conn.trunk != est3.Conn.trunk || pt.p.Stats().MuxFull != 1 {
				t.Fatalf("the next attempt did not take the other trunk at once (MuxFull %d)", pt.p.Stats().MuxFull)
			}
			pt.attach(est4)
			est2.Conn.Kill(CauseLocalClose, "session 2 ended")
			waitDone(t, est2.Conn.Done(), "view 2")
			synctest.Wait()
			if !pt.p.usable(t1, 9) {
				t.Fatal("the trunk stayed full after a view left")
			}
		})
	})
}

// TestMuxHandleExhaustion_L14 (M3-D4, E9; L14): with the first handle
// preset to 2^32−2 the trunk allocates 2^32−2 and 2^32−1, then seals: the
// next attempt dials a new trunk (whose handles start over), no handle is
// reused, and the sealed trunk closes at its last view.
func TestMuxHandleExhaustion_L14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, func(env *Env) { env.Presets.FirstHandle = 0xFFFFFFFE }, nil)
		var a []*Established
		for i := byte(1); i <= 3; i++ {
			est, err := pt.attempt(context.Background(), 0, wire.TypeOpen, i, [16]byte{})
			if err != nil || !isOK(est) {
				t.Fatalf("attempt %d: %v", i, err)
			}
			pt.attach(est)
			a = append(a, est)
		}
		for i, want := range []uint32{1, 0xFFFFFFFE, 0xFFFFFFFF} {
			if a[i].Conn.Handle() != want || a[i].Conn.trunk != a[0].Conn.trunk {
				t.Fatalf("view %d: handle %#x, want %#x on the first trunk", i, a[i].Conn.Handle(), want)
			}
		}
		t1 := a[0].Conn.trunk
		if !t1.sealed {
			t.Fatal("the trunk is not sealed at the end of its handle space")
		}
		b1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 4, [16]byte{})
		if err != nil || !b1.Fresh || b1.Conn.trunk == t1 || b1.Conn.Handle() != 1 {
			t.Fatalf("attempt after the seal: %v", err)
		}
		pt.attach(b1)
		b2, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 5, [16]byte{})
		if b2 == nil || b2.Conn.trunk != b1.Conn.trunk || b2.Conn.Handle() != 0xFFFFFFFE {
			t.Fatal("the new trunk's handles do not start over")
		}
		pt.attach(b2)
		synctest.Wait()
		if d := pt.srv.dials.Load(); d != 2 {
			t.Fatalf("%d factory calls, want 2", d)
		}
		for _, e := range a {
			e.Conn.Kill(CauseLocalClose, "session ended")
		}
		waitDone(t, t1.tdone, "the sealed trunk at its last view")
		if !t1.closeSent.Load() {
			t.Fatal("the sealed trunk closed without its CLOSE")
		}
		var hs []uint32
		for _, mv := range pt.srv.admitted() {
			if mv.c.trunk == pt.srv.accepted()[0].trunk {
				hs = append(hs, mv.c.Handle())
			}
		}
		if len(hs) != 2 || hs[0] != 0xFFFFFFFE || hs[1] != 0xFFFFFFFF {
			t.Fatalf("the passive admitted handles %#x on the first trunk", hs)
		}
	})
}

// TestPoolClose (§A2.3, §A4.5, L52; not a design row: the Close and Wait
// behaviour of this pool): Close is idempotent and leaves the attempts of
// the sessions that survive Peer.Close their fast paths; Wait returns only
// once Close ran and every trunk the pool dialled is done — it blocks
// while a trunk runs (and before Close on an empty pool) and returns nil
// after the last view closed the trunk.
func TestPoolClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		short := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			return pt.p.Wait(ctx)
		}
		if err := short(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Wait before Close: %v, want it blocked", err)
		}
		est1, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		pt.attach(est1)
		pt.p.Close()
		pt.p.Close()
		est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
		if err != nil || est2.Fresh || est2.Conn.trunk != est1.Conn.trunk {
			t.Fatalf("attempt after Close: %v (fresh %v), want a fast path", err, est2 != nil && est2.Fresh)
		}
		pt.attach(est2)
		est1.Conn.poolStarted() // a second publication is a no-op
		synctest.Wait()
		if len(pt.p.listed(0)) != 1 {
			t.Fatal("the published trunk was listed twice")
		}
		if err := short(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Wait with a running trunk: %v, want it blocked", err)
		}
		done := make(chan error, 1)
		go func() { done <- pt.p.Wait(context.Background()) }()
		tr := est1.Conn.trunk
		est1.Conn.Kill(CauseLocalClose, "session 1 ended")
		est2.Conn.Kill(CauseLocalClose, "session 2 ended")
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Wait: %v", err)
			}
		case <-time.After(time.Minute):
			t.Fatal("Wait did not return after the last view closed the trunk")
		}
		select {
		case <-tr.tdone:
		default:
			t.Fatal("Wait returned before the trunk was done")
		}
		if !tr.closeSent.Load() {
			t.Fatal("the trunk closed without its CLOSE")
		}
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 1 || st.FastPaths != 1 {
			t.Fatalf("%d factory calls, stats %+v", d, st)
		}
	})
}

// TestPoolPublishOutsideLocks (§A4.2): Conn.Start may run under the
// session's lock, which Pool.mu is never taken under, so poolStarted does
// not take Pool.mu on its caller's goroutine: it returns while Pool.mu is
// held, and the publication follows.
func TestPoolPublishOutsideLocks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		if err != nil || !est1.Fresh {
			t.Fatalf("claimant: %v", err)
		}
		est1.Conn.Start(&dEP{}, &hBell{}, StartOptions{})
		pt.p.mu.Lock()
		returned := make(chan struct{})
		go func() {
			est1.Conn.poolStarted()
			close(returned)
		}()
		// A goroutine blocked on a mutex is not durably blocked for the
		// bubble, so the bound is a count of yields, not virtual time.
		ok := false
		for i := 0; i < 100000 && !ok; i++ {
			select {
			case <-returned:
				ok = true
			default:
				runtime.Gosched()
			}
		}
		pt.p.mu.Unlock()
		if !ok {
			<-returned
			t.Fatal("poolStarted took Pool.mu on its caller's goroutine")
		}
		synctest.Wait()
		if len(pt.p.listed(0)) != 1 || pt.p.inFlight(0) {
			t.Fatal("the trunk was not published")
		}
	})
}
