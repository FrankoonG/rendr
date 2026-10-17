package rendr

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRuntimeCloseJoinsTrunks_L52 (M3-D25, M3-D26, §A4.6; L52): shared
// trunks belong to their owners — the Peer's pool on the dialer (also after
// Peer.Close: its sessions survive it), the Runtime's trunk set on the
// passive — and Runtime.Close joins them: after both Runtimes closed with
// sessions still open on shared trunks of two factories, Status.Mux is
// zero on both, no actor runs, nothing was abandoned, and no rendr
// goroutine is left.
func TestRuntimeCloseJoinsTrunks_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		p := e.peer()
		var conns []*Conn
		for i := range 4 {
			mode := ModeSelector
			if i%2 == 1 {
				mode = ModeBond
			}
			dc, pc := e2eOpen(t, p, e.ln, DialOptions{Mode: mode})
			conns = append(conns, dc, pc)
		}
		mxWait(t, 2*time.Second, "both trunks", func() bool { return e.d.Status().Mux.Carriers == 2 })
		if m := e.p.Status().Mux; m.Carriers != 2 || m.Views < 4 {
			t.Fatalf("passive Mux %+v, want 2 shared trunks", m)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		e2eExchange(t, conns[0], conns[1], 64<<10, 1) // the sessions survive Peer.Close
		if e.d.Status().Mux.Carriers != 2 {
			t.Fatal("Peer.Close closed its sessions' trunks")
		}
		start := time.Now()
		e.d.Close()
		e.p.Close()
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("the Runtimes closed in %v", el)
		}
		for _, rt := range []*Runtime{e.d, e.p} {
			st := rt.Status()
			if st.Mux.Carriers != 0 || st.Mux.Views != 0 || st.Actors != 0 || st.Abandoned != 0 || len(mxTrunkSet(rt)) != 0 {
				t.Fatalf("Runtime %v after Close: %+v", rt.InstanceID(), st)
			}
		}
		for _, l := range e.links {
			l.Close()
		}
		synctest.Wait()
		if n, by := rendrGoroutines(); n != 0 {
			t.Fatalf("%d rendr goroutines after both Runtimes closed: %v", n, by)
		}
	})
}

// TestMuxRuntimeClose_L50_L52 (E15, M3-D26; A11.3's "no GOAWAY" mutant):
// the passive's Runtime.Close while the dialer opens views on a shared
// trunk: the trunk carries one GOAWAY, the sessions pending on it are
// answered GOING_AWAY (their Dials fail with ErrCapacity), the open session
// on it ends with AbortGoingAway, no view is admitted after the GOAWAY, and
// both Runtimes end with nothing left.
func TestMuxRuntimeClose_L50_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		s, _ := e2eOpen(t, p, e.ln, DialOptions{})
		var rs []<-chan dialResult
		for range 5 {
			rs = append(rs, e2eDialAsync(context.Background(), p, DialOptions{}))
		}
		synctest.Wait() // five OPENs pending on the trunk (Accept never called)
		if ps := e.p.Status(); ps.Sessions.Pending != 5 {
			t.Fatalf("passive %+v, want 5 pending", ps.Sessions)
		}
		e.p.Close()
		for i, r := range rs {
			if x := <-r; x.c != nil || !errors.Is(x.err, ErrCapacity) {
				t.Fatalf("Dial %d pending at Runtime.Close: %v, %v; want ErrCapacity", i, x.c, x.err)
			}
		}
		e2eDone(t, s, 5*time.Second)
		var ae *AbortError
		if _, err := s.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortGoingAway {
			t.Fatalf("the open session after the passive's Runtime.Close: %v", err)
		}
		tp := taps.tap(t, 0)
		if n := len(mxFrames(tp, rendrtest.Down, rendrtest.FrameGoAway, 0)); n != 1 {
			t.Fatalf("%d GOAWAYs on the trunk, want 1", n)
		}
		// No view after the GOAWAY: every response the trunk carried after
		// it answered one of the five pending OPENs (GOING_AWAY).
		after, seen := 0, false
		for _, r := range tp.Log(rendrtest.Down) {
			if r.Type == rendrtest.FrameGoAway {
				seen = true
			} else if seen && (r.Type == rendrtest.FrameOpenAck || r.Type == rendrtest.FrameJoinAck) {
				after++
			}
		}
		if after > 5 {
			t.Fatalf("%d responses after the GOAWAY, want at most the 5 pending sessions' refusals", after)
		}
		if !p.goneAway(e.p.InstanceID()) {
			t.Fatal("the dialer's Peer did not record the instance that went away")
		}
		e.d.Close()
		for _, l := range e.links {
			l.Close()
		}
		wpNoState(t, e.d)
		wpNoState(t, e.p)
	})
}

// TestStatusMuxIdentities (M3-D49, §A10.2): Status.Mux.Carriers counts the
// live MUX trunks of each Runtime and Status.Mux.Views their views (Σ over
// those trunks); a CheapSubflow factory's dedicated carriers count in
// neither; every live view reports Shared ≥ 1 (the views on its trunk); a
// selector session on loss-free links reports no duplicate and no race
// copy; after both Runtimes closed Carriers, Views and Actors are 0.
func TestStatusMuxIdentities(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b", "c")
		p := e.peer(e.links[0], e.links[1])
		pc := e.dedicatedPeer(e.links[2])
		var conns []*Conn
		for range 3 {
			dc, sc := e2eOpen(t, p, e.ln, DialOptions{})
			conns = append(conns, dc, sc)
		}
		bd, bp := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		conns = append(conns, bd, bp)
		mxWait(t, 2*time.Second, "the bond's members", func() bool { return mxMembers(bd) == 2 })
		cd, cq := e2eOpen(t, pc, e.ln, DialOptions{})
		conns = append(conns, cd, cq)
		for i := 0; i < len(conns); i += 2 {
			e2eExchange(t, conns[i], conns[i+1], 32<<10, uint64(i))
		}
		synctest.Wait()
		for _, rt := range []*Runtime{e.d, e.p} {
			if m := rt.Status().Mux; m.Carriers != 2 || m.Views != 5 {
				t.Fatalf("Runtime %v: Mux %+v, want 2 trunks with 5 views (3 + bond on a, bond on b)", rt.InstanceID(), m)
			}
		}
		views := map[uint32]int{}
		for i := 0; i < len(conns); i += 2 {
			for _, cs := range mxSessionCarriers(conns[i]) {
				if cs.State != 0 && cs.Stats.Shared < 1 {
					t.Fatalf("a live carrier with Shared %d: %+v", cs.Stats.Shared, cs)
				}
				views[cs.ID] = max(views[cs.ID], cs.Stats.Shared)
			}
		}
		sum := 0
		for id, n := range views {
			if id != uint32(mxCarrier(t, cd, "c").ID) {
				sum += n
			}
		}
		if sum != 5 {
			t.Fatalf("Σ Shared over the MUX trunks %d (%v), want Status.Mux.Views 5", sum, views)
		}
		if st := conns[0].Status(); st.DupBytes != 0 || st.Race != (RaceCounters{}) {
			t.Fatalf("selector session %+v", st)
		}
		for i := 0; i < len(conns); i += 2 {
			e2eFinish(t, conns[i], conns[i+1])
		}
		e.close()
		for _, rt := range []*Runtime{e.d, e.p} {
			if st := rt.Status(); st.Mux.Carriers != 0 || st.Mux.Views != 0 || st.Actors != 0 {
				t.Fatalf("Runtime %v after Close: %+v", rt.InstanceID(), st)
			}
		}
	})
}

// TestPassiveTrunkZeroViewsBounded (M3-D22, PA-39; A11.3's "never close"
// mutant): a passive MUX trunk left without views by a dialer that never
// closes it is bounded: after RetireGrace at zero views it counts against
// the Sessionless limits — beyond Sessionless.PerInstance it gets
// CLOSE(capacity) at once — and after Sessionless.Idle at zero views the
// counted ones are closed as well. Six raw MUX trunks from one instance,
// PerInstance 2.
func TestPassiveTrunkZeroViewsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const trunks, per = 6, 2
		idle := 30 * time.Second // ≥ 3×max(PingIdle, Probe.Interval)
		cfg := Config{RetireGrace: time.Second, Sessionless: SessionlessLimits{PerInstance: per, Idle: idle}}
		ov := &testhooks.Overrides{DeadMin: 10 * time.Minute, DeadMax: 10 * time.Minute, WriteStall: 10 * time.Minute}
		rt := wpTestRuntime(t, cfg, ov)
		ln := wpListen(t, rt, ListenConfig{})
		acc := newAcceptLog(ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
		inst := wpInst(9)
		type rawTrunk struct {
			d      *wpDialer
			mu     sync.Mutex
			closes []wire.CloseReason
			eof    bool
		}
		var rs []*rawTrunk
		var wg sync.WaitGroup
		for i := range trunks {
			r := &rawTrunk{d: wpConnect(t, ln, inst, uint32(100+i))}
			pre := make([]byte, wire.PrefaceLen)
			wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: inst, CarrierID: uint32(100 + i), Opt: wire.OptMux})
			ack, ok, _ := r.d.sendPreface(pre)
			if !ok || ack.Status != wire.PrefaceOK || ack.Opt&wire.OptMux == 0 {
				t.Fatalf("PREFACE_ACK %+v (%v), want OK with OptMux", ack, ok)
			}
			r.d.send(wire.TypeOpen, 0, wpOpen(wpSID(500+i), wire.KindStream, 1, nil))
			r.d.expectOpenAck(wire.StatusOK, 0)
			r.d.send(wire.TypeRst, 0, wpRst(wire.RstClosed, "gone"))
			wg.Go(func() { // the raw dialer reads everything, answers nothing
				for {
					f, err := r.d.recv()
					if err != nil {
						r.mu.Lock()
						r.eof = true
						r.mu.Unlock()
						return
					}
					if f.Type == wire.TypeClose {
						reason, _ := wire.ParseClose(f.Payload)
						r.mu.Lock()
						r.closes = append(r.closes, reason)
						r.mu.Unlock()
					}
				}
			})
			rs = append(rs, r)
		}
		closesOf := func(want wire.CloseReason) int {
			n := 0
			for _, r := range rs {
				r.mu.Lock()
				for _, c := range r.closes {
					if c == want {
						n++
					}
				}
				r.mu.Unlock()
			}
			return n
		}
		mxWait(t, 5*time.Second, "the bound at RetireGrace", func() bool { return closesOf(wire.CloseCapacity) == trunks-per })
		mxWait(t, 2*time.Second, "the refused trunks drain", func() bool { return rt.Status().Mux.Carriers == per })
		if st := rt.Status(); st.Sessionless != per || st.Mux.Carriers != per || st.Mux.Views != 0 {
			t.Fatalf("after RetireGrace at zero views: %+v; want %d counted Sessionless", st, per)
		}
		if n := closesOf(wire.CloseRetire); n != 0 {
			t.Fatalf("%d trunks closed before Sessionless.Idle", n)
		}
		mxWait(t, idle+time.Second, "the bound at Sessionless.Idle", func() bool { return closesOf(wire.CloseRetire) == per })
		for _, r := range rs {
			r.d.close()
		}
		wg.Wait()
		acc.stop()
		for _, c := range acc.conns {
			c.Close()
		}
		mxWait(t, 5*time.Second, "the trunk set empties", func() bool { return len(mxTrunkSet(rt)) == 0 })
		if st := rt.Status(); st.Sessionless != 0 || st.Mux.Carriers != 0 {
			t.Fatalf("after the closes: %+v", st)
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestPassiveTrunkZeroViewsTotal (M3-D22, the per-Runtime half and the
// return of a view; TestPassiveTrunkZeroViewsBounded is the per-instance
// half): six raw MUX trunks of two dialer instances, three each, are left
// without views; with Sessionless.Total 3 (PerInstance 16, never binding)
// after RetireGrace three of them hold a Sessionless place and the other
// three get CLOSE(capacity) at once. Then an OPEN for a new handle arrives
// on one of the counted trunks: its view's admission gives the place back
// (Status.Sessionless drops to 2) and the trunk lives on — at
// Sessionless.Idle only the two still counted trunks are retired.
func TestPassiveTrunkZeroViewsTotal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const trunks, total = 6, 3
		idle := 30 * time.Second
		cfg := Config{RetireGrace: time.Second, Sessionless: SessionlessLimits{PerInstance: 16, Total: total, Idle: idle}}
		ov := &testhooks.Overrides{DeadMin: 10 * time.Minute, DeadMax: 10 * time.Minute, WriteStall: 10 * time.Minute}
		rt := wpTestRuntime(t, cfg, ov)
		ln := wpListen(t, rt, ListenConfig{})
		acc := newAcceptLog(ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
		type rawTrunk struct {
			d      *wpDialer
			mu     sync.Mutex
			closes []wire.CloseReason
			acks   []wire.OpenAck // OPEN_ACKs for handle 2
		}
		var rs []*rawTrunk
		var wg sync.WaitGroup
		for i := range trunks {
			inst := wpInst(byte(9 + i%2))
			id := uint32(100 + i)
			r := &rawTrunk{d: wpConnect(t, ln, inst, id)}
			pre := make([]byte, wire.PrefaceLen)
			wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: inst, CarrierID: id, Opt: wire.OptMux})
			ack, ok, _ := r.d.sendPreface(pre)
			if !ok || ack.Status != wire.PrefaceOK || ack.Opt&wire.OptMux == 0 {
				t.Fatalf("PREFACE_ACK %+v (%v), want OK with OptMux", ack, ok)
			}
			r.d.send(wire.TypeOpen, 0, wpOpen(wpSID(600+i), wire.KindStream, 1, nil))
			r.d.expectOpenAck(wire.StatusOK, 0)
			r.d.send(wire.TypeRst, 0, wpRst(wire.RstClosed, "gone"))
			wg.Go(func() { // the raw dialer reads everything, answers nothing
				for {
					f, err := r.d.recv()
					if err != nil {
						return
					}
					r.mu.Lock()
					switch {
					case f.Type == wire.TypeClose:
						reason, _ := wire.ParseClose(f.Payload)
						r.closes = append(r.closes, reason)
					case f.Type == wire.TypeOpenAck && f.Handle == 2:
						oa, _ := wire.ParseOpenAck(f.Payload)
						r.acks = append(r.acks, oa)
					}
					r.mu.Unlock()
				}
			})
			rs = append(rs, r)
		}
		closes := func(r *rawTrunk, want wire.CloseReason) int {
			r.mu.Lock()
			defer r.mu.Unlock()
			n := 0
			for _, c := range r.closes {
				if c == want {
					n++
				}
			}
			return n
		}
		closesOf := func(want wire.CloseReason) int {
			n := 0
			for _, r := range rs {
				n += closes(r, want)
			}
			return n
		}
		mxWait(t, 5*time.Second, "the Total bound at RetireGrace", func() bool { return closesOf(wire.CloseCapacity) == trunks-total })
		mxWait(t, 2*time.Second, "the refused trunks drain", func() bool { return rt.Status().Mux.Carriers == total })
		if st := rt.Status(); st.Sessionless != total || st.Mux.Views != 0 {
			t.Fatalf("after RetireGrace at zero views: %+v; want %d counted Sessionless", st, total)
		}
		var back *rawTrunk
		for _, r := range rs {
			if closes(r, wire.CloseCapacity) == 0 {
				back = r
				break
			}
		}
		// A new view on the counted trunk: OPEN for handle 2.
		f := wire.AppendFrame(nil, wire.Header{Type: wire.TypeOpen, Fseq: back.d.txFseq, Handle: 2}, wpOpen(wpSID(700), wire.KindStream, 1, nil))
		back.d.txFseq++
		if _, err := back.d.nc.Write(f); err != nil {
			t.Fatal(err)
		}
		mxWait(t, 2*time.Second, "the new view's OPEN_ACK(OK)", func() bool {
			back.mu.Lock()
			defer back.mu.Unlock()
			return len(back.acks) == 1 && back.acks[0].Status == wire.StatusOK
		})
		if st := rt.Status(); st.Sessionless != total-1 || st.Mux.Carriers != total || st.Mux.Views != 1 {
			t.Fatalf("after a view returned to a counted trunk: %+v; want %d counted Sessionless", st, total-1)
		}
		mxWait(t, idle+time.Second, "the bound at Sessionless.Idle", func() bool { return closesOf(wire.CloseRetire) == total-1 })
		if n := closes(back, wire.CloseRetire) + closes(back, wire.CloseCapacity); n != 0 {
			t.Fatalf("the trunk with a view again got %d CLOSEs", n)
		}
		for _, r := range rs {
			r.d.close()
		}
		wg.Wait()
		acc.stop()
		for _, c := range acc.conns {
			c.Close()
		}
		mxWait(t, 5*time.Second, "the trunk set empties", func() bool { return len(mxTrunkSet(rt)) == 0 })
		if st := rt.Status(); st.Sessionless != 0 || st.Mux.Carriers != 0 {
			t.Fatalf("after the closes: %+v", st)
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

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

// TestPassiveTrunkGoroutines (F44's two goroutines per carrier; L52; the
// passive twin of carrier TestPoolTrunkGoroutines): a passive MUX trunk
// costs its reader and writer only — the trunk set's bookkeeping runs at
// the trunk's Done (carrier OnTrunkDone), not on a goroutine that waits
// for it. Two Peers with one Link each put each session on its own trunk:
// once the actors are parked, the second trunk adds exactly four rendr
// goroutines (a reader and a writer on each end) and none of package rendr
// itself. Its end still runs the bookkeeping: the passive set drops the
// trunk after its last view retired it, and after Runtime.Close no rendr
// goroutine is left. Observed before the change: five goroutines per
// trunk, the fifth the passive Runtime's watchTrunk.
func TestPassiveTrunkGoroutines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		parked := func() bool { return e.d.Status().Actors == 0 && e.p.Status().Actors == 0 }
		root := func(by map[string]int) int {
			n := 0
			for fn, k := range by {
				if strings.HasPrefix(fn, "github.com/FrankoonG/rendr/v2.") {
					n += k
				}
			}
			return n
		}

		da, qa := e2eOpen(t, e.peer(e.links[0]), e.ln, DialOptions{})
		mxWait(t, 30*time.Second, "one passive trunk, actors parked", func() bool {
			return len(mxTrunkSet(e.p)) == 1 && e.d.Status().Mux.Carriers == 1 && parked()
		})
		synctest.Wait()
		n1, by1 := rendrGoroutines()

		db, qb := e2eOpen(t, e.peer(e.links[1]), e.ln, DialOptions{})
		mxWait(t, 30*time.Second, "two passive trunks, actors parked", func() bool {
			return len(mxTrunkSet(e.p)) == 2 && e.d.Status().Mux.Carriers == 2 && parked()
		})
		synctest.Wait()
		n2, by2 := rendrGoroutines()
		if n2-n1 != 4 || root(by2) != root(by1) {
			t.Fatalf("a second trunk added %d rendr goroutines (%d of package rendr), want 4 (reader and writer per end) and none of package rendr:\nbefore %v\nafter  %v",
				n2-n1, root(by2)-root(by1), by1, by2)
		}

		// The bookkeeping at the trunk's Done: the session on link b ends,
		// the dialer retires the trunk at its last view, and the passive
		// set drops it.
		db.Close()
		qb.Close()
		mxWait(t, 30*time.Second, "the passive set dropped the retired trunk", func() bool {
			return len(mxTrunkSet(e.p)) == 1 && e.p.Status().Mux.Carriers == 1
		})
		e2eExchange(t, da, qa, 64<<10, 1) // the other trunk carries on
		da.Close()
		qa.Close()
		e.close()
		synctest.Wait()
		if n, by := rendrGoroutines(); n != 0 {
			t.Fatalf("%d rendr goroutines after both Runtimes closed: %v", n, by)
		}
	})
}
