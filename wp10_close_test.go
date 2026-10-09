package rendr

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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

// TestMuxDatagramOpenBudget_L37 (M3-D24, §A3.3; L37): a packet session that
// opens on a live datagram trunk offers the trunk's current budget in its
// OPEN (a REL{OPEN} with the next cseq, no new handshake): the passive
// accepts it, the session's MaxPayload fits the trunk's frame budget, and a
// datagram of that size crosses the shared trunk both ways.
func TestMuxDatagramOpenBudget_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		p := h.peer(h.carrier("h1", 1, nil))
		d1, p1 := peOpen(t, p, h.ln, DialOptions{})
		d2, p2 := peOpen(t, p, h.ln, DialOptions{})
		if m := h.d.Status().Mux; m.Carriers != 1 || m.Views != 2 || m.FastPaths != 1 {
			t.Fatalf("dialer Mux %+v, want the second session on the live datagram trunk", m)
		}
		budget := d1.Status().Carriers[0].MTU
		if budget == 0 || d2.Status().Carriers[0].MTU != budget {
			t.Fatalf("budgets %d and %d", budget, d2.Status().Carriers[0].MTU)
		}
		mp := d2.Status().MaxPayload
		if mp <= 0 || mp > budget-wire.DgramOverhead || mp != p2.Status().MaxPayload {
			t.Fatalf("MaxPayload %d / %d on a trunk of budget %d", mp, p2.Status().MaxPayload, budget)
		}
		big := make([]byte, mp)
		for i := range big {
			big[i] = byte(i)
		}
		buf := make([]byte, 65536)
		for _, c := range [][2]*PacketConn{{d2, p2}, {p2, d2}} {
			if _, err := c[0].WriteTo(big, nil); err != nil {
				t.Fatal(err)
			}
			c[1].SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := c[1].ReadFrom(buf)
			if err != nil || n != mp || string(buf[:n]) != string(big) {
				t.Fatalf("a %d-byte datagram: %d bytes, %v", mp, n, err)
			}
		}
		for _, c := range []*PacketConn{d1, p1, d2, p2} {
			c.Close()
		}
		h.close()
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
