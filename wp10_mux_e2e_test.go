package rendr

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestLaneHandleFromViewE2E (M3-D4, M3-D16; WP10): three sessions of one
// Peer share the one carrier of its single factory — one factory call,
// handles 1, 2 and 3 allocated in order, the OPENs of handles 2 and 3
// placed on the live trunk —, every frame of each session carries its
// view's handle in both directions (DATA of handles 1, 2 and 3 only), every
// byte arrives intact, and both Runtimes count one MUX trunk with three
// views.
func TestLaneHandleFromViewE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		var dcs, pcs [3]*Conn
		for i := range 3 {
			dcs[i], pcs[i] = e2eOpen(t, p, e.ln, DialOptions{})
		}
		if n := taps.dials.Load(); n != 1 {
			t.Fatalf("%d factory calls for three sessions, want 1 (one shared carrier)", n)
		}
		for i := range 3 {
			if dh, ph := mxHandleOf(t, dcs[i], "a"), mxHandleOf(t, pcs[i], ""); dh != uint32(i+1) || ph != dh {
				t.Fatalf("session %d: handle %d on the dialer, %d on the passive; want %d on both", i, dh, ph, i+1)
			}
		}
		for i := range 3 {
			e2eExchange(t, dcs[i], pcs[i], 256<<10+int64(i), uint64(10+i))
		}
		tp := taps.tap(t, 0)
		for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
			hs := mxHandles(tp, d, rendrtest.FrameData)
			if len(hs) != 3 || hs[1] == 0 || hs[2] == 0 || hs[3] == 0 {
				t.Fatalf("direction %v: DATA by handle %v, want handles 1, 2 and 3 only", d, hs)
			}
		}
		var opens []uint32
		for _, r := range mxFrames(tp, rendrtest.Up, rendrtest.FrameOpen, 0) {
			opens = append(opens, r.Handle)
		}
		if len(opens) != 3 || opens[0] != 1 || opens[1] != 2 || opens[2] != 3 {
			t.Fatalf("OPENs on the trunk by handle %v, want [1 2 3] in allocation order", opens)
		}
		for _, rt := range []*Runtime{e.d, e.p} {
			if m := rt.Status().Mux; m.Carriers != 1 || m.Views != 3 {
				t.Fatalf("Runtime %v: Mux %+v, want 1 carrier with 3 views", rt.InstanceID(), m)
			}
		}
		if m := e.d.Status().Mux; m.FastPaths != 2 {
			t.Fatalf("dialer Mux %+v, want 2 fast paths", m)
		}
		for i := range 3 {
			e2eFinish(t, dcs[i], pcs[i])
		}
		e.close()
	})
}

// TestHeldAfterResponseFill (M3-D8, PA-27; WP10): a session opened on a
// started trunk is held on the passive after its OPEN_ACK(OK) until the
// dialer's first frame for it: its application's first bytes, written
// right after Confirm, are not placed while the dialer's direction is held
// (the passive placed the OPEN_ACK and nothing else for the handle), and
// they follow once the dialer's go frame — an ACK, the view's first frame
// after its OPEN — arrives. Handle 1 of the trunk was not held.
func TestHeldAfterResponseFill(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		d1, p1 := e2eOpen(t, p, e.ln, DialOptions{})
		tp := taps.tap(t, 0)

		res := e2eDialAsync(context.Background(), p, DialOptions{})
		pend, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // the OPEN of handle 2 was read by the passive
		tp.Hold(rendrtest.Up)
		sc, err := pend.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		banner := []byte("server speaks first")
		if n, err := sc.Write(banner); n != len(banner) || err != nil {
			t.Fatalf("passive Write: %d, %v", n, err)
		}
		r := <-res
		if r.err != nil {
			t.Fatal(r.err)
		}
		dc := r.c
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		var down2 []rendrtest.FrameType
		for _, rec := range tp.Log(rendrtest.Down) {
			if rec.Handle == 2 {
				down2 = append(down2, rec.Type)
			}
		}
		if len(down2) != 1 || down2[0] != rendrtest.FrameOpenAck {
			t.Fatalf("passive frames for handle 2 before the go frame: %v, want the OPEN_ACK only", down2)
		}
		if st := sc.Status(); st.TxBytes != uint64(len(banner)) || mxCarrier(t, sc, "").TxBytes != 0 {
			t.Fatalf("held: passive committed %d bytes, its carrier sent %d; want %d and 0", st.TxBytes, mxCarrier(t, sc, "").TxBytes, len(banner))
		}
		tp.Release(rendrtest.Up)
		got := make([]byte, len(banner))
		if err := dc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(dc, got); err != nil || string(got) != string(banner) {
			t.Fatalf("dialer read %q, %v; want the banner", got, err)
		}
		dc.SetReadDeadline(time.Time{})
		synctest.Wait() // the tamper logged what it forwarded
		var up2 []rendrtest.FrameType
		for _, rec := range tp.Log(rendrtest.Up) {
			if rec.Handle == 2 {
				up2 = append(up2, rec.Type)
			}
		}
		if len(up2) < 2 || up2[0] != rendrtest.FrameOpen || up2[1] != rendrtest.FrameAck {
			t.Fatalf("dialer frames for handle 2: %v, want OPEN then the go frame (ACK)", up2)
		}
		e2eExchange(t, d1, p1, 64<<10, 3)
		e2eExchange(t, dc, sc, 64<<10, 5)
		e2eFinish(t, d1, p1)
		e2eFinish(t, dc, sc)
		e.close()
	})
}

// TestLaneGoFrameE2E (M3-D8, R1-12; WP10): the go frame on the wire — the
// first frame of a stream session's view opened on a started trunk is an
// ACK, a packet session's on a stream trunk a plain PACK — and
// passive-first data of a view on a started datagram trunk (whose go frame
// is REL{PACK}) reaches the dialer.
func TestLaneGoFrameE2E(t *testing.T) {
	t.Run("packet on a stream trunk", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			var taps mxTaps
			defer taps.close()
			p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
			d1, p1 := e2eOpen(t, p, e.ln, DialOptions{})
			res := make(chan *PacketConn, 1)
			go func() {
				c, err := p.DialPacket(context.Background(), DialOptions{})
				if err != nil {
					t.Error(err)
				}
				res <- c
			}()
			pend, err := e.ln.AcceptPacket(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			sc, err := pend.Confirm()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sc.WriteTo([]byte("first"), nil); err != nil {
				t.Fatal(err)
			}
			dc := <-res
			if dc == nil {
				t.FailNow()
			}
			buf := make([]byte, 64)
			dc.SetReadDeadline(time.Now().Add(time.Second))
			if n, _, err := dc.ReadFrom(buf); err != nil || string(buf[:n]) != "first" {
				t.Fatalf("dialer ReadFrom: %q, %v", buf[:n], err)
			}
			var up2 []rendrtest.FrameType
			for _, rec := range taps.tap(t, 0).Log(rendrtest.Up) {
				if rec.Handle == 2 {
					up2 = append(up2, rec.Type)
				}
			}
			if len(up2) < 2 || up2[0] != rendrtest.FrameOpen || up2[1] != rendrtest.FramePack {
				t.Fatalf("dialer frames for handle 2: %v, want OPEN then the go frame (a plain PACK)", up2)
			}
			dc.Close()
			sc.Close()
			e2eFinish(t, d1, p1)
			e.close()
		})
	})
	t.Run("packet on a datagram trunk", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := peNewHub(t, Config{}, ListenConfig{}, nil)
			p := h.peer(h.carrier("h1", 1, nil))
			d1, p1 := peOpen(t, p, h.ln, DialOptions{})
			res := make(chan *PacketConn, 1)
			go func() {
				c, err := p.DialPacket(context.Background(), DialOptions{})
				if err != nil {
					t.Error(err)
				}
				res <- c
			}()
			pend, err := h.ln.AcceptPacket(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			sc, err := pend.Confirm()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sc.WriteTo([]byte("first"), nil); err != nil {
				t.Fatal(err)
			}
			dc := <-res
			if dc == nil {
				t.FailNow()
			}
			if m := h.d.Status().Mux; m.Carriers != 1 || m.Views != 2 || m.FastPaths != 1 {
				t.Fatalf("dialer Mux %+v, want one datagram trunk with two views (a fast path)", m)
			}
			buf := make([]byte, 64)
			dc.SetReadDeadline(time.Now().Add(time.Second))
			if n, _, err := dc.ReadFrom(buf); err != nil || string(buf[:n]) != "first" {
				t.Fatalf("dialer ReadFrom: %q, %v (the passive's hold never ended: no go frame)", buf[:n], err)
			}
			dc.Close()
			sc.Close()
			d1.Close()
			p1.Close()
			h.close()
		})
	})
}

// TestAttemptThroughPool (M3-D16, M3-D2; WP10): a session's attempts go
// through its Peer's pool — the second session of a Peer opens a view on
// the live trunk with no factory call (FastPaths), four sessions dialled at
// once on a fresh Peer make one factory call (three coalesced waiters,
// served by fast paths at the publication) — while a CheapSubflow factory
// keeps M2's path: one factory call and one dedicated carrier per session,
// no MUX trunk counted.
func TestAttemptThroughPool(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		var mux, cheap, burst mxTaps
		defer mux.close()
		defer cheap.close()
		defer burst.close()
		pm := e.mxPeer(mxTapCarrier(e.links[0], &mux))
		a1, b1 := mxOpenWithin(t, pm, e.ln, DialOptions{}, 10*time.Second)
		a2, b2 := mxOpenWithin(t, pm, e.ln, DialOptions{}, 10*time.Second)
		if n, m := mux.dials.Load(), e.d.Status().Mux; n != 1 || m.FastPaths != 1 || m.Carriers != 1 || m.Views != 2 {
			t.Fatalf("mux Peer: %d factory calls, Mux %+v; want 1 call, 1 fast path, 1 carrier with 2 views", n, m)
		}
		cc := dedicated(mxTapCarrier(e.links[0], &cheap))
		pc := e.mxPeer(cc)
		if pc.pool != nil {
			t.Fatal("a Peer of CheapSubflow factories only has a pool")
		}
		c1, d1 := e2eOpen(t, pc, e.ln, DialOptions{})
		c2, d2 := e2eOpen(t, pc, e.ln, DialOptions{})
		if n, m := cheap.dials.Load(), e.d.Status().Mux; n != 2 || m.Carriers != 1 || m.Views != 2 {
			t.Fatalf("CheapSubflow Peer: %d factory calls, Mux %+v; want 2 calls and no MUX trunk of its own", n, m)
		}

		pb := e.mxPeer(mxTapCarrier(e.links[0], &burst))
		acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
		var rs []<-chan dialResult
		for range 4 {
			rs = append(rs, e2eDialAsync(context.Background(), pb, DialOptions{}))
		}
		var ds []*Conn
		for i, r := range rs {
			var x dialResult
			select {
			case x = <-r:
			case <-time.After(10 * time.Second):
				t.Fatalf("concurrent Dial %d did not return within 10 s: its coalesced wait was never served", i)
			}
			if x.err != nil {
				t.Fatal(x.err)
			}
			ds = append(ds, x.c)
		}
		acc.stop()
		ps := pb.pool.Stats()
		if n := burst.dials.Load(); n != 1 || ps.Coalesced != 3 || ps.FastPaths != 3 || ps.Carriers != 1 || ps.Views != 4 {
			t.Fatalf("four concurrent Dials: %d factory calls, pool %+v; want 1 call, 3 coalesced, 3 fast paths, 1 carrier with 4 views", n, ps)
		}
		for _, d := range ds {
			d.Close()
		}
		for _, c := range []*Conn{a1, b1, a2, b2, c1, d1, c2, d2} {
			c.Close()
		}
		e.close()
	})
}

// TestViewGoneJoin_L52 (M3-D25, M3-D43; L52): Session.Done covers the
// session's views and never a shared trunk. Two sessions share a trunk;
// one ends while the passive's DETACH for its view is kept from being
// written (a hook on the passive's writer): its Done stays open until its
// view retired — at the DETACH bound, the trunk untouched — and then
// closes while the trunk still carries the other session, which keeps
// delivering intact; the trunk closes at its last view afterwards.
func TestViewGoneJoin_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var held, placed chan struct{}
		held, placed = make(chan struct{}, 1), make(chan struct{}, 1)
		var holdH uint32
		phooks := &testhooks.Hooks{AfterDetach: func(c, h uint32, sent bool) {
			if sent && h == holdH {
				select {
				case held <- struct{}{}:
					<-release // the passive's writer holds its batch with the DETACH
				default:
				}
			}
		}}
		dhooks := &testhooks.Hooks{AfterDetach: func(c, h uint32, sent bool) {
			if sent && h == holdH {
				select {
				case placed <- struct{}{}:
				default:
				}
			}
		}}
		e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, &testhooks.Overrides{Hooks: dhooks}), p: wpTestRuntime(t, Config{}, &testhooks.Overrides{Hooks: phooks})}
		e.ln = wpListen(t, e.p, ListenConfig{})
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
		t.Cleanup(l.Close)
		e.links = []*rendrtest.Link{l}
		p := e.peer()
		d1, p1 := e2eOpen(t, p, e.ln, DialOptions{})
		d2, p2 := e2eOpen(t, p, e.ln, DialOptions{})
		holdH = mxHandleOf(t, d2, "a")
		trunk := mxCarrier(t, d1, "a").ID

		// The DONE exchange of d2 completes; both ends retire their views.
		go func() {
			p2.CloseWrite()
			io.Copy(io.Discard, p2)
			p2.Close()
		}()
		d2.CloseWrite()
		io.Copy(io.Discard, d2)
		d2.Close()
		<-held // the passive placed its DETACH: its writer holds it
		select {
		case <-placed:
		case <-time.After(time.Second):
			t.Fatal("the dialer's DETACH was never placed")
		}
		start := time.Now()
		select {
		case <-d2.s.Done():
			t.Fatal("Session.Done closed with its view's DETACH exchange open")
		case <-time.After(50 * time.Millisecond):
		}
		select {
		case <-d2.s.Done():
		case <-time.After(1100 * time.Millisecond):
			t.Fatal("Session.Done not closed after its view's DETACH bound")
		}
		if el := time.Since(start); el > 1100*time.Millisecond {
			t.Fatalf("Done after %v", el)
		}
		var row *CarrierStatus
		st := d2.Status()
		for i := range st.Carriers {
			if st.Carriers[i].ID == trunk {
				row = &st.Carriers[i]
			}
		}
		if row == nil || row.DeathCause != CauseRetired {
			t.Fatalf("the ended session's view: %+v, want retired", st.Carriers)
		}
		if c := mxCarrier(t, d1, "a"); c.ID != trunk || c.State == CarrierDead {
			t.Fatalf("the other session's carrier %+v, want the shared trunk %d alive", c, trunk)
		}
		if m := e.d.Status().Mux; m.Carriers != 1 || m.Views != 1 {
			t.Fatalf("dialer Mux %+v after the view's end, want the trunk with one view", m)
		}
		close(release)
		e2eExchange(t, d1, p1, 256<<10, 7)
		if st := d1.Status(); st.Migrations != (MigrationCounts{}) {
			t.Fatalf("the other session migrated: %+v", st.Migrations)
		}
		e2eFinish(t, d1, p1)
		mxWait(t, 3*time.Second, "the trunk closes at its last view", func() bool { return e.d.Status().Mux.Carriers == 0 })
		e.close()
	})
}

// TestOpeningRaceLoserKeepsSharedTrunk (R1-2, R1-5, M3-D61): the losing
// attempt of a session's opening race is a fast-path view on a trunk that
// carries two other sessions. The session's Dial is withdrawn while its
// OPEN waits for its verdict — once before the passive's Confirm, once
// with the OPEN_ACK(OK) already on its way (held in the tamper) —: the
// view is abandoned with RST(AbortWithdrawn), then DETACH, on the trunk
// (one RST of its handle, one more DETACH); the passive's session ends
// within 1 s; the trunk and both neighbours' lanes live (no death, no
// failover, no failed mark), and their data stays intact.
func TestOpeningRaceLoserKeepsSharedTrunk(t *testing.T) {
	for _, okSent := range []bool{false, true} {
		name := "before the verdict"
		if okSent {
			name = "OPEN_ACK(OK) crossing"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
				e.links[0].SetDelay(time.Millisecond, 0) // a ranks first
				e.links[1].SetDelay(5*time.Millisecond, 0)
				var ta, tb mxTaps
				defer ta.close()
				defer tb.close()
				p := e.mxPeer(mxTapCarrier(e.links[0], &ta), mxTapCarrier(e.links[1], &tb))
				n1, m1 := e2eOpen(t, p, e.ln, DialOptions{})
				n2, m2 := e2eOpen(t, p, e.ln, DialOptions{})
				if n1.Status().Carriers[0].Name != "a" || n2.Status().Carriers[0].Name != "a" {
					t.Fatalf("neighbours on %+v and %+v, want both on a", n1.Status().Carriers, n2.Status().Carriers)
				}
				var tp *rendrtest.Tamper
				for i := range ta.count() {
					if len(mxFrames(ta.tap(t, i), rendrtest.Up, rendrtest.FrameOpen, 0)) > 0 {
						tp = ta.tap(t, i) // the session trunk (not a probe carrier)
					}
				}
				dialsA := ta.dials.Load()
				detBefore := len(mxFrames(tp, rendrtest.Up, rendrtest.FrameDetach, 0))

				ctx, cancel := context.WithCancel(context.Background())
				res := e2eDialAsync(ctx, p, DialOptions{})
				pend, err := e.ln.Accept(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				var x *Conn
				if okSent {
					tp.Hold(rendrtest.Down)
					if x, err = pend.Confirm(); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
				}
				withdrawn := time.Now()
				cancel()
				if r := <-res; r.err == nil || !errors.Is(r.err, context.Canceled) {
					t.Fatalf("withdrawn Dial: %v, %v", r.c, r.err)
				}
				if okSent {
					tp.Release(rendrtest.Down)
					e2eDone(t, x, time.Second)
				} else {
					mxWait(t, time.Second, "the passive's pending session ends", func() bool {
						_, err := pend.Confirm()
						return err != nil
					})
				}
				if el := time.Since(withdrawn); el > time.Second {
					t.Fatalf("the passive session ended %v after the withdrawal", el)
				}
				synctest.Wait()
				if got := len(mxFrames(tp, rendrtest.Up, rendrtest.FrameRst, 3)); got != 1 {
					t.Fatalf("%d RSTs for handle 3 on the trunk, want 1 (AbortWithdrawn)", got)
				}
				if got := len(mxFrames(tp, rendrtest.Up, rendrtest.FrameDetach, 0)) - detBefore; got != 1 {
					t.Fatalf("%d more DETACHes from the dialer, want 1", got)
				}
				if n := ta.dials.Load(); n != dialsA {
					t.Fatalf("%d factory calls of a during the withdrawal, want none", n-dialsA)
				}
				for _, c := range []*Conn{n1, n2} {
					if st := c.Status(); st.Migrations != (MigrationCounts{}) || st.NoPathEpisodes != 0 || mxCarrier(t, c, "a").State == CarrierDead {
						t.Fatalf("neighbour %+v", st)
					}
				}
				if fs := p.Status().Factories[0]; fs.Failed {
					t.Fatalf("factory a marked failed (%s)", fs.FailReason)
				}
				e2eExchange(t, n1, m1, 128<<10, 1)
				e2eExchange(t, n2, m2, 128<<10, 2)
				e2eFinish(t, n1, m1)
				e2eFinish(t, n2, m2)
				e.close()
			})
		})
	}
}

// TestSessionEndBoundSparesNeighbours (R1-2, M3-D61, C24): a session whose
// view's last frames and DETACH cannot be placed by its close bound (the
// trunk's writes are held) is ended by Kill on its view at that bound: only
// that view ends (local_close), the trunk lives, and three neighbours on
// it keep delivering intact once the writes resume, with no death, no
// migration and no new carrier.
func TestSessionEndBoundSparesNeighbours(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := &testhooks.Overrides{Linger: 100 * time.Millisecond}
		e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		var ds, ps [4]*Conn
		for i := range 4 {
			ds[i], ps[i] = e2eOpen(t, p, e.ln, DialOptions{})
		}
		tp := taps.tap(t, 0)
		trunk := mxCarrier(t, ds[0], "a").ID
		tp.Hold(rendrtest.Up)
		// The trunk's writer blocks in its Write first (a neighbour's data),
		// so the ending session's last frames cannot be placed.
		if _, err := ds[1].Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		closedAt := time.Now()
		ds[0].Close() // its FIN cannot leave: Linger, then RST, then the close bound
		select {
		case <-ds[0].s.Done():
		case <-time.After(1300 * time.Millisecond):
			t.Fatal("the ended session's Done not closed after its close bound")
		}
		if el := time.Since(closedAt); el < time.Second {
			t.Fatalf("Done %v after Close, before Linger + the close bound", el)
		}
		var row *CarrierStatus
		st := ds[0].Status()
		for i := range st.Carriers {
			if st.Carriers[i].ID == trunk {
				row = &st.Carriers[i]
			}
		}
		if row == nil || row.DeathCause != CauseLocalClose {
			t.Fatalf("the ended session's view %+v, want local_close at the close bound", st.Carriers)
		}
		tp.Release(rendrtest.Up)
		if _, err := io.ReadFull(ps[1], make([]byte, 1000)); err != nil { // the neighbour's bytes that blocked the writer
			t.Fatal(err)
		}
		for i := 1; i < 4; i++ {
			e2eExchange(t, ds[i], ps[i], 128<<10, uint64(i))
			st := ds[i].Status()
			if c := mxCarrier(t, ds[i], "a"); c.ID != trunk || st.Migrations != (MigrationCounts{}) || st.NoPathEpisodes != 0 {
				t.Fatalf("neighbour %d: carrier %+v, %+v", i, c, st)
			}
		}
		if n := taps.dials.Load(); n != 1 {
			t.Fatalf("%d factory calls, want the one trunk", n)
		}
		for i := 1; i < 4; i++ {
			e2eFinish(t, ds[i], ps[i])
		}
		ps[0].Close()
		e.close()
	})
}
