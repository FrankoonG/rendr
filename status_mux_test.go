package rendr

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestStatusMuxFullBothRoles (§A2.1, M3-D12; WP16 API-2): Status.Mux.MuxFull
// counts CAPACITY CodeMuxFull answers in both roles: on the passive every
// such answer its trunks placed, on the dialer every such answer its pools
// received. The view-cap setup of TestPassiveAdmitOnTrunk_L48: the passive
// holds at most four views per trunk, and 1 + 6 sessions are dialled on one
// Peer; every refusal the passive answered reached the dialer's pool, so the
// two counts are equal and at least 1.
func TestStatusMuxFullBothRoles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, nil), p: wpTestRuntime(t, Config{}, &testhooks.Overrides{MuxMaxViews: 4})}
		e.ln = wpListen(t, e.p, ListenConfig{AcceptBacklog: 64})
		var taps mxTaps
		defer taps.close()
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
		t.Cleanup(l.Close)
		e.links = []*rendrtest.Link{l}
		p := e.mxPeer(mxTapCarrier(l, &taps))
		s1, q1 := e2eOpen(t, p, e.ln, DialOptions{})
		acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
		var rs []<-chan dialResult
		for range 6 {
			rs = append(rs, e2eDialAsync(context.Background(), p, DialOptions{}))
		}
		var cs []*Conn
		for _, r := range rs {
			x := <-r
			if x.err != nil {
				t.Fatal(x.err)
			}
			cs = append(cs, x.c)
		}
		acc.stop()
		synctest.Wait()
		dialer := p.pool.Stats().MuxFull
		pm, dm := e.p.Status().Mux, e.d.Status().Mux
		if dialer == 0 || taps.dials.Load() < 2 {
			t.Fatalf("pool MuxFull %d, %d factory calls; want CodeMuxFull answers and a second carrier", dialer, taps.dials.Load())
		}
		if pm.MuxFull != dialer {
			t.Fatalf("passive Status.Mux.MuxFull %d, but it answered %d CodeMuxFull refusals (the dialer's count)", pm.MuxFull, dialer)
		}
		if dm.MuxFull != dialer {
			t.Fatalf("dialer Status.Mux.MuxFull %d, pool %d", dm.MuxFull, dialer)
		}
		for _, c := range append(cs, s1, q1) {
			c.Close()
		}
		for _, c := range acc.conns {
			c.Close()
		}
		e.close()
	})
}

// TestStatusMuxSurvivesPeerClose (M3-D49, §A2.3; WP16 API-1): a closed
// Peer's pool keeps serving its surviving sessions, and the trunks it dials
// for them are in the dialer's Status.Mux like any other (the identity of
// TestStatusMuxIdentities: Carriers and Views match the passive's), until
// both Runtimes closed (Mux zero).
//
//   - failover: a Peer with [CheapSubflow c, default a] carries a selector
//     session on c; Peer.Close; c refuses dials and its carrier is killed;
//     the session fails over onto a, whose trunk the closed Peer's pool
//     dials after Peer.Close's prune.
//   - redial gap: the session is on a when the Peer closes; a's trunk is
//     killed while dials are held; another Peer is created during the gap
//     (NewPeer prunes the pools); the held dial is released.
func TestStatusMuxSurvivesPeerClose(t *testing.T) {
	check := func(t *testing.T, e *e2ePair, what string) {
		t.Helper()
		synctest.Wait()
		dm, pm := e.d.Status().Mux, e.p.Status().Mux
		if dm.Carriers != 1 || dm.Views != 1 || pm.Carriers != 1 || pm.Views != 1 {
			t.Fatalf("%s: dialer Mux %+v, passive Mux %+v; want 1 trunk with 1 view on both", what, dm, pm)
		}
	}
	onA := func(c *Conn) bool {
		for _, cs := range c.Status().Carriers {
			if cs.State != CarrierDead && cs.Name == "a" {
				return true
			}
		}
		return false
	}
	t.Run("failover", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "c", "a")
			p := e.mxPeer(dedicated(e2eCarrier(e.links[0])), e2eCarrier(e.links[1]))
			e.links[1].SetRefuse(true) // the session opens on c
			dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
			if cs := mxCarrier(t, dc, "c"); cs.ID == 0 {
				t.Fatal("the session is not on c")
			}
			e.links[1].SetRefuse(false)
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			e.links[0].SetRefuse(true)
			e.links[0].Kill()
			mxWait(t, 30*time.Second, "the failover onto a", func() bool { return onA(dc) })
			e2eExchange(t, dc, pc, 32<<10, 1)
			check(t, e, "after the failover")
			e2eFinish(t, dc, pc)
			e.close()
			for _, rt := range []*Runtime{e.d, e.p} {
				if m := rt.Status().Mux; m.Carriers != 0 || m.Views != 0 {
					t.Fatalf("Runtime %v after Close: Mux %+v", rt.InstanceID(), m)
				}
			}
		})
	})
	t.Run("redial gap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
			p := e.mxPeer(e2eCarrier(e.links[0]))
			dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
			check(t, e, "before Peer.Close")
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			e.links[0].SetDial(rendrtest.DialLateSuccess) // the redial waits for Release
			e.links[0].Kill()
			mxWait(t, 30*time.Second, "the held redial", func() bool { return e.links[0].Stats().Dials >= 2 })
			synctest.Wait()
			other := e.mxPeer(e2eCarrier(e.links[1])) // its pool's addPool prunes the pools
			e.links[0].SetDial(rendrtest.DialNormal)
			e.links[0].Release()
			mxWait(t, 30*time.Second, "the session back on a", func() bool { return onA(dc) })
			e2eExchange(t, dc, pc, 32<<10, 2)
			check(t, e, "after the redial")
			other.Close()
			e2eFinish(t, dc, pc)
			e.close()
			for _, rt := range []*Runtime{e.d, e.p} {
				if m := rt.Status().Mux; m.Carriers != 0 || m.Views != 0 {
					t.Fatalf("Runtime %v after Close: Mux %+v", rt.InstanceID(), m)
				}
			}
		})
	})
}
