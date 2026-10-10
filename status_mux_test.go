package rendr

import (
	"context"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestStatusMuxFullBothRoles (§A2.1, M3-D12; WP16 API-2): Status.Mux.MuxFull
// counts CAPACITY CodeMuxFull answers in both roles: on the passive every
// such answer its trunks placed, on the dialer every such answer its pools
// received. The passive's count equals the CodeMuxFull OPEN_ACKs and
// JOIN_ACKs on the wire towards the dialer, and no other CAPACITY answer
// counts.
//
//   - view cap: the setup of TestPassiveAdmitOnTrunk_L48 — the passive holds
//     at most four views per trunk, and 1 + 6 sessions are dialled on one
//     Peer — makes at least one CodeMuxFull answer, every one of which
//     reached the dialer's pool; the dialer's counters stay when its closed
//     Peer's pool is pruned (they are cumulative);
//   - backlog: an AcceptBacklog of 1 and a stalled Accept make a CAPACITY
//     CodeBacklog answer on a live trunk and no CodeMuxFull: the passive
//     counts nothing.
func TestStatusMuxFullBothRoles(t *testing.T) {
	t.Run("view cap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, nil), p: wpTestRuntime(t, Config{}, &testhooks.Overrides{MuxMaxViews: 4})}
			e.ln = wpListen(t, e.p, ListenConfig{AcceptBacklog: 64})
			var taps mxTaps
			defer taps.close()
			var ans ansCount
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
			t.Cleanup(l.Close)
			e.links = []*rendrtest.Link{l}
			p := e.mxPeer(ans.carrier(mxTapCarrier(l, &taps)))
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
			full, other := ans.counts()
			if dialer == 0 || full == 0 || taps.dials.Load() < 2 {
				t.Fatalf("pool MuxFull %d, %d CodeMuxFull answers on the wire, %d factory calls; want CodeMuxFull answers and a second carrier", dialer, full, taps.dials.Load())
			}
			if pm.MuxFull != uint64(full) {
				t.Fatalf("passive Status.Mux.MuxFull %d, but it answered %d CodeMuxFull refusals (and %d other CAPACITY answers)", pm.MuxFull, full, other)
			}
			if dm.MuxFull != dialer || dialer != uint64(full) {
				t.Fatalf("dialer Status.Mux.MuxFull %d, pool %d, %d CodeMuxFull answers received", dm.MuxFull, dialer, full)
			}
			for _, c := range append(cs, s1, q1) {
				c.Close()
			}
			for _, c := range acc.conns {
				c.Close()
			}
			// The counters are cumulative: the closed Peer's pool, pruned
			// once its trunks are done, keeps its counts in Status.Mux.
			before := e.d.Status().Mux
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := p.pool.Wait(ctx); err != nil {
				t.Fatalf("the closed Peer's pool: %v", err)
			}
			p2 := e.mxPeer(mxTapCarrier(l, &taps)) // NewPeer prunes the pools
			e.d.mu.Lock()
			_, kept := e.d.pools[p.pool]
			e.d.mu.Unlock()
			if kept {
				t.Fatal("the closed Peer's drained pool was not pruned")
			}
			if after := e.d.Status().Mux; after.FastPaths != before.FastPaths || after.Coalesced != before.Coalesced || after.MuxFull != before.MuxFull {
				t.Fatalf("dialer Status.Mux %+v after the prune, %+v before: the counters went back", after, before)
			}
			p2.Close()
			e.close()
		})
	})
	t.Run("backlog", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, nil), p: wpTestRuntime(t, Config{}, nil)}
			e.ln = wpListen(t, e.p, ListenConfig{AcceptBacklog: 1})
			var taps mxTaps
			defer taps.close()
			var ans ansCount
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
			t.Cleanup(l.Close)
			e.links = []*rendrtest.Link{l}
			p := e.mxPeer(ans.carrier(mxTapCarrier(l, &taps)))
			s1, q1 := e2eOpen(t, p, e.ln, DialOptions{})
			// Accept stalls: the first Dial fills the backlog, the second
			// gets CAPACITY CodeBacklog as an answer on the live trunk.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r1 := e2eDialAsync(ctx, p, DialOptions{})
			mxWait(t, 10*time.Second, "the first Dial pending", func() bool { return e.p.Status().Sessions.Pending == 1 })
			r2 := e2eDialAsync(ctx, p, DialOptions{})
			mxWait(t, 10*time.Second, "a CodeBacklog answer", func() bool { _, other := ans.counts(); return other > 0 })
			synctest.Wait()
			full, other := ans.counts()
			if full != 0 || taps.dials.Load() != 1 {
				t.Fatalf("%d CodeMuxFull answers, %d factory calls; want none and one trunk", full, taps.dials.Load())
			}
			if pm := e.p.Status().Mux; pm.MuxFull != 0 {
				t.Fatalf("passive Status.Mux.MuxFull %d after %d CAPACITY answers that were not CodeMuxFull", pm.MuxFull, other)
			}
			cancel()
			for _, r := range []<-chan dialResult{r1, r2} {
				if x := <-r; x.err == nil {
					x.c.Close()
				}
			}
			s1.Close()
			q1.Close()
			e.close()
		})
	})
}

// ansCount counts the CAPACITY answers (OPEN_ACK, and JOIN_ACK in its MUX
// encoding) a dialer's carriers read: CodeMuxFull and any other code.
type ansCount struct {
	mu          sync.Mutex
	full, other int
}

func (a *ansCount) counts() (full, other int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.full, a.other
}

// carrier wraps sc: every carrier's inbound frames are parsed and counted.
func (a *ansCount) carrier(sc StreamCarrier) StreamCarrier {
	dial := sc.Dial
	sc.Dial = func(ctx context.Context) (net.Conn, error) {
		c, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return &ansConn{Conn: c, a: a, skip: wire.PrefaceLen}, nil // the PREFACE_ACK, then frames
	}
	return sc
}

// ansConn parses what is read through it: the PREFACE_ACK, then frames
// (header, then the payload of an OPEN_ACK or JOIN_ACK, skipping every
// other payload and the trailers).
type ansConn struct {
	net.Conn
	a          *ansCount
	hdr, body  []byte
	want, skip int
	typ        wire.Type
}

func (x *ansConn) Read(b []byte) (int, error) {
	n, err := x.Conn.Read(b)
	x.feed(b[:n])
	return n, err
}

func (x *ansConn) feed(p []byte) {
	for len(p) > 0 {
		switch {
		case x.skip > 0:
			k := min(x.skip, len(p))
			x.skip -= k
			p = p[k:]
		case x.want > 0:
			k := min(x.want, len(p))
			x.body = append(x.body, p[:k]...)
			x.want -= k
			p = p[k:]
			if x.want == 0 {
				x.answer()
				x.body = x.body[:0]
				x.skip = wire.TrailerLen
			}
		default:
			k := min(wire.HeaderLen-len(x.hdr), len(p))
			x.hdr = append(x.hdr, p[:k]...)
			p = p[k:]
			if len(x.hdr) < wire.HeaderLen {
				continue
			}
			typ, n := wire.Type(x.hdr[0]), int(x.hdr[2])<<16|int(x.hdr[3])<<8|int(x.hdr[4])
			x.hdr = x.hdr[:0]
			if (typ == wire.TypeOpenAck || typ == wire.TypeJoinAck) && n > 0 {
				x.typ, x.want = typ, n
			} else {
				x.skip = n + wire.TrailerLen
			}
		}
	}
}

func (x *ansConn) answer() {
	var st wire.AckStatus
	var code uint32
	switch x.typ {
	case wire.TypeOpenAck:
		a, err := wire.ParseOpenAck(x.body)
		if err != nil {
			return
		}
		st, code = a.Status, a.Code
	default:
		a, c, err := wire.ParseJoinAckMux(x.body)
		if err != nil {
			return
		}
		st, code = a.Status, c
	}
	if st != wire.StatusCapacity {
		return
	}
	x.a.mu.Lock()
	if code == wire.CodeMuxFull {
		x.a.full++
	} else {
		x.a.other++
	}
	x.a.mu.Unlock()
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
