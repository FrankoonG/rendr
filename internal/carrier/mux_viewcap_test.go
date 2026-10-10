package carrier

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestMuxKillThenOpenAtCap (§A5.6, §A5.8, R1-4 rule 3, M3-D12; WP16
// MUX-1): a dialer view counts against MuxMaxViews until it leaves the
// view table — not until its Done closes — because the passive counts its
// own view until it placed its DETACH. With both caps at 3, views 1, 2 and 3
// live and the passive's DETACH(2) held back (its view 2 inside a Fill), a
// Kill of view 2 frees no place yet: a compliant dialer opens view 4 (an
// OPEN or a JOIN) only once the trunk takes it, and the passive answers OK,
// never CAPACITY. Ten seconds later both sides hold three views, the trunk
// is not marked full, and once another view leaves it takes a new one. On
// a datagram trunk the dialer's view leaves at the passive's DETACH once
// our REL{DETACH} was acknowledged.
func TestMuxKillThenOpenAtCap(t *testing.T) {
	for _, row := range []struct {
		kind wire.Type
		dg   bool
	}{{wire.TypeOpen, false}, {wire.TypeJoin, false}, {wire.TypeOpen, true}, {wire.TypeJoin, true}} {
		kind := row.kind
		name := kind.String()
		if row.dg {
			name += "/datagram"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cap3 := func(env *Env) { env.Timing.MuxMaxViews, env.Timing.MuxMaxViewsDatagram = 3, 3 }
				var d, p *muxSide
				if row.dg {
					d, p, _, _ = dgMuxPair(t, 1200, cap3)
				} else {
					d, p = muxPair(t, cap3)
				}
				d.open(t, wire.TypeOpen, 2)
				d.open(t, wire.TypeOpen, 3)
				synctest.Wait()
				// The passive's view 2 sits inside a Fill until released: its
				// DETACH(2), the answer to ours, waits behind it.
				pv := p.view(2)
				gate := make(chan struct{})
				var entered atomic.Bool
				pv.src.mu.Lock()
				pv.src.hook = func(c *Conn, b *Batch) {
					if entered.CompareAndSwap(false, true) {
						<-gate
					}
				}
				pv.src.mu.Unlock()
				pv.c.Wake()
				synctest.Wait()
				if !entered.Load() {
					t.Fatal("the passive view's Fill was not called")
				}
				released := false
				release := func() {
					if !released {
						released = true
						close(gate)
					}
				}
				defer release()
				d.view(2).c.Kill(CauseLocalClose, "session 2 ended")
				synctest.Wait()
				payload := mOpenPayload(4, row.dg)
				if kind == wire.TypeJoin {
					payload = mJoinPayload(4)
				}
				// A compliant dialer: a new view only when the trunk takes it.
				v, err := d.c.openView(kind, payload, 4)
				if err != nil {
					if err != ErrDead {
						t.Fatalf("openView: %v", err)
					}
					release() // the passive's DETACH(2) completes the exchange
					synctest.Wait()
					if v, err = d.c.openView(kind, payload, 4); err != nil {
						t.Fatalf("openView after the DETACH exchange: %v (dialer views %d)", err, d.c.Views())
					}
				}
				type res struct {
					est *Established
					err error
				}
				ch := make(chan res, 1)
				go func() {
					est, err := v.awaitResponse(context.Background(), nil)
					ch <- res{est, err}
				}()
				synctest.Wait()
				release()
				r := <-ch
				if r.err != nil {
					t.Fatalf("view 4: %v", r.err)
				}
				if st, code, _ := responseStatus(r.est.Resp, r.est.Payload); st != wire.StatusOK {
					t.Fatalf("view 4 refused: status %v code %d (code %d on the view); the dialer exceeded the passive's cap", st, code, v.respCode())
				}
				d.attach(v)
				time.Sleep(10 * time.Second)
				synctest.Wait()
				if dv, pvs := d.c.Views(), p.c.Views(); dv != 3 || pvs != 3 {
					t.Fatalf("10 s later: dialer views %d, passive views %d; want 3 and 3", dv, pvs)
				}
				d.c.mx.Lock()
				full := d.c.ms.full
				d.c.mx.Unlock()
				if full {
					t.Fatal("the trunk is marked full")
				}
				if d.c.usableForMux(wire.TypeDgram, [16]byte{}, 0) {
					t.Fatal("the trunk at its cap takes a new view")
				}
				d.view(3).c.Kill(CauseLocalClose, "session 3 ended")
				synctest.Wait()
				time.Sleep(time.Second)
				synctest.Wait()
				if !d.c.usableForMux(wire.TypeDgram, [16]byte{}, 0) {
					t.Fatalf("a view left (dialer views %d, passive views %d) and the trunk takes no new view", d.c.Views(), p.c.Views())
				}
				if dead, cause, detail, _ := d.c.KillTrunkDeath(); dead {
					t.Fatalf("the trunk died: %v %s", cause, detail)
				}
			})
		})
	}
}

// TestMuxFullClearsWhenRetiringViewLeaves (§A5.8, M3-D12; WP16 MUX-1): a
// trunk's CodeMuxFull mark lasts until a view leaves, and a retiring dialer
// view leaves when it leaves the view table — when the peer's DETACH
// completes the exchange — not at its Done. Against a scripted passive: view
// 2 is killed (our DETACH(2) placed, its Done closed, the peer's DETACH(2)
// outstanding), view 3 is answered CAPACITY CodeMuxFull — the trunk is full
// for the trunk's usable rule and for a pool that marked it — and the
// peer's DETACH(2) then makes the trunk take new views again.
func TestMuxFullClearsWhenRetiringViewLeaves(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		v2, res2 := s.openRaw(t, wire.TypeOpen, 2)
		synctest.Wait()
		_ = p.send(wire.TypeOpenAck, 0, v2.Handle(), okAck(wire.TypeOpenAck))
		if est, err := res2(); err != nil || !isOK(est) {
			t.Fatalf("view 2: %v", err)
		}
		s.attach(v2)
		synctest.Wait()
		v2.Kill(CauseLocalClose, "session 2 ended")
		waitDone(t, v2.Done(), "view 2")
		v3, res3 := s.openRaw(t, wire.TypeOpen, 3)
		synctest.Wait()
		full := make([]byte, wire.OpenAckFixedLen)
		n := wire.PutOpenAck(full, &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeMuxFull})
		_ = p.send(wire.TypeOpenAck, 0, v3.Handle(), full[:n])
		if est, err := res3(); err != nil || isOK(est) {
			t.Fatalf("view 3: %v, want the CodeMuxFull refusal", err)
		}
		synctest.Wait()
		pool := NewPool(s.env, []Factory{{Name: "f0", Mux: true}})
		pool.full = map[*trunk]bool{s.c.trunk: true} // as fastPathRetry marks it
		if s.c.usableForMux(wire.TypeData, [16]byte{}, 0) || pool.usable(s.c, 9) {
			t.Fatal("the full trunk is usable")
		}
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(v2.Handle(), wire.DetachEnded))
		synctest.Wait()
		if !s.c.usableForMux(wire.TypeData, [16]byte{}, 0) {
			t.Fatalf("view 2 left the table (views %d) and the trunk stays full", s.c.Views())
		}
		if !pool.usable(s.c, 9) {
			t.Fatal("the trunk's mark cleared and the pool's stays")
		}
		if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
			t.Fatalf("the trunk died: %v %s", cause, detail)
		}
	})
}
