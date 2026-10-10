package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
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
// is REL{PACK}) reaches the dialer. A stream trunk carries sessions of one
// kind (KINDSPLIT): the packet session's view opens on the started stream
// trunk of an earlier packet session, beside the stream session's own
// trunk.
func TestLaneGoFrameE2E(t *testing.T) {
	t.Run("packet on a stream trunk", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			var taps mxTaps
			defer taps.close()
			p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
			d1, p1 := e2eOpen(t, p, e.ln, DialOptions{})
			openPkt := func() (dc, sc *PacketConn) {
				t.Helper()
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
				sc, err = pend.Confirm()
				if err != nil {
					t.Fatal(err)
				}
				return <-res, sc
			}
			dc0, sc0 := openPkt() // view 1 of the packet sessions' stream trunk
			if dc0 == nil {
				t.FailNow()
			}
			if n, m := taps.count(), e.d.Status().Mux; n != 2 || m.Carriers != 2 || m.Views != 2 {
				t.Fatalf("%d trunks dialled, dialer Mux %+v; want a stream trunk per session kind", n, m)
			}
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
			if n, m := taps.count(), e.d.Status().Mux; n != 2 || m.Carriers != 2 || m.Views != 3 || m.FastPaths != 1 {
				t.Fatalf("%d trunks dialled, dialer Mux %+v; want the second packet session as a fast path on the packet sessions' trunk", n, m)
			}
			var up2 []rendrtest.FrameType
			for _, rec := range taps.tap(t, 1).Log(rendrtest.Up) {
				if rec.Handle == 2 {
					up2 = append(up2, rec.Type)
				}
			}
			if len(up2) < 2 || up2[0] != rendrtest.FrameOpen || up2[1] != rendrtest.FramePack {
				t.Fatalf("dialer frames for handle 2: %v, want OPEN then the go frame (a plain PACK)", up2)
			}
			dc.Close()
			sc.Close()
			dc0.Close()
			sc0.Close()
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

		// The burst's factory call waits on a gate until all four Dials are
		// in the pool: the first in that call, the other three coalesced on
		// it. Without the gate the premise was a scheduling accident — a
		// Dial whose goroutine ran after the call returned found the trunk
		// live and took the fast path uncoalesced (Coalesced 2, the race
		// lane's flake).
		bc := mxTapCarrier(e.links[0], &burst)
		gate := make(chan struct{})
		var gateOnce sync.Once
		open := func() { gateOnce.Do(func() { close(gate) }) }
		defer open() // a failure must not leave the factory call blocked
		var gated atomic.Int32
		dial := bc.Dial
		bc.Dial = func(ctx context.Context) (net.Conn, error) {
			gated.Add(1)
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return dial(ctx)
		}
		pb := e.mxPeer(bc)
		acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
		var rs []<-chan dialResult
		for range 4 {
			rs = append(rs, e2eDialAsync(context.Background(), pb, DialOptions{}))
		}
		synctest.Wait()
		if n, ps := gated.Load(), pb.pool.Stats(); n != 1 || ps.Coalesced != 3 {
			t.Fatalf("premise: %d factory calls in flight, pool %+v; want 1 call with 3 coalesced waiters", n, ps)
		}
		open()
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
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(release) }) // a failure must not leave the passive's writer held
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
		// The passive's direction ends first (its FIN delivered and
		// confirmed), then the dialer's: the passive's DONE needs nothing
		// more than the dialer's FIN and goes out first, so the dialer ends —
		// its DONE and DETACH placed together — when that DONE arrives, and
		// the passive's DETACH, which follows the dialer's DONE, is alone in
		// the batch the hook holds. (Without this order the held batch could
		// carry the passive's DONE beside its DETACH: the dialer then waited
		// for that DONE and never placed its DETACH — a premise flake of the
		// race lane.)
		p2.CloseWrite()
		io.Copy(io.Discard, d2)            // the dialer delivered the passive's FIN
		time.Sleep(200 * time.Millisecond) // and confirmed it to the passive
		d2.CloseWrite()
		go func() {
			io.Copy(io.Discard, p2)
			p2.Close()
		}()
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
		releaseOnce.Do(func() { close(release) })
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

// The datagram go frame under loss (M3-D8 as amended by m3 DGMUX; L40).
// On a started datagram trunk a dialer view owes its go frame — a REL{PACK}
// — at attach. The REL window is the trunk's (wire.RelWindow frames per
// direction, shared by every view's OPENs, go frames, FINs and DETACHes),
// and a lost REL holds it at its cseq until REL retransmits it (RelRTOMin
// 200 ms at least), longer than Packet.MaxAge (100 ms). A lane whose Fill
// placed nothing while its go frame found no REL room lost every datagram
// the application wrote right after DialPacket (DropAge = writes, the
// passive's Received 0: the pool's lesson/pkt-openclose case at 1 % loss).

// mxDgTap wraps the conns of a datagram factory (the dialer's side of a
// peHub): it logs the dialer's outgoing session frames (DGRAMs, plain
// frames of a handle, REL inner frames) with handle, cseq and time, and,
// once armed, removes the first copy of the
// drop-th distinct REL{OPEN} frame from its datagram — the datagram's
// other frames leave as written, so the frame looks lost and its cseq
// stays unacknowledged until REL retransmits it.
type mxDgTap struct {
	mu             sync.Mutex
	drop           int             // the REL{OPEN} (1-based, distinct cseqs after arming) whose first copy is removed; 0: none
	opens          map[uint32]bool // REL{OPEN} cseqs seen after arming
	dropCs         uint32
	dropped        int
	dropAt, retxAt time.Time
	log            []mxDgRec
}

// mxDgRec is one logged outgoing frame of the dialer.
type mxDgRec struct {
	at     time.Time
	typ    wire.Type // the frame's type, or the REL inner type
	rel    bool      // a REL inner frame
	handle uint32
	cseq   uint32 // REL frames only
}

// arm makes the tap remove the first copy of the n-th REL{OPEN} from now.
func (m *mxDgTap) arm(n int) {
	m.mu.Lock()
	m.drop, m.opens = n, map[uint32]bool{}
	m.mu.Unlock()
}

// wrap returns dial with every conn passing through the tap.
func (m *mxDgTap) wrap(dial func(context.Context) (net.PacketConn, net.Addr, error)) func(context.Context) (net.PacketConn, net.Addr, error) {
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		return &mxDgConn{PacketConn: pc, m: m}, a, nil
	}
}

// mxDgConn is a dialer conn of an mxDgTap.
type mxDgConn struct {
	net.PacketConn
	m *mxDgTap
}

func (c *mxDgConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	out := c.m.filter(b, time.Now())
	if len(out) == len(b) {
		return c.PacketConn.WriteTo(b, addr)
	}
	if len(out) > 0 {
		if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
			return 0, err
		}
	}
	return len(b), nil // the removed frame is lost on the way
}

// filter logs the frames of datagram b sent at now and returns b, or a
// copy without the removed REL{OPEN} frame.
func (m *mxDgTap) filter(b []byte, now time.Time) []byte {
	if wire.IsPreface(b) {
		return b // a handshake datagram (the trunk's H1)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []byte
	cut := false
	for rest := b; len(rest) > 0; {
		f, n, err := wire.DecodeFrame(rest)
		if err != nil {
			out = append(out, rest...)
			break
		}
		raw := rest[:n]
		rest = rest[n:]
		switch f.Type {
		case wire.TypeDgram:
			m.log = append(m.log, mxDgRec{at: now, typ: f.Type, handle: f.Handle})
		case wire.TypeRel:
			rh, _, err := wire.ParseRel(f.Payload)
			if err != nil {
				break
			}
			m.log = append(m.log, mxDgRec{at: now, typ: rh.Type, rel: true, handle: rh.Handle, cseq: rh.Cseq})
			if rh.Type != wire.TypeOpen || m.drop == 0 {
				break
			}
			if m.opens[rh.Cseq] {
				if m.dropped > 0 && rh.Cseq == m.dropCs && m.retxAt.IsZero() {
					m.retxAt = now // REL's retransmission of the removed copy
				}
				break
			}
			m.opens[rh.Cseq] = true
			if len(m.opens) == m.drop {
				m.dropCs, m.dropAt = rh.Cseq, now
				m.dropped++
				cut = true
				continue // not copied: lost
			}
		default:
			if f.Handle != 0 {
				m.log = append(m.log, mxDgRec{at: now, typ: f.Type, handle: f.Handle})
			}
		}
		out = append(out, raw...)
	}
	if !cut {
		return b
	}
	return out
}

// mxDgCycle is one DialPacket cycle of mxDgRun: the dialer's session, when
// DialPacket returned, and the session's handle on the trunk.
type mxDgCycle struct {
	dc       *PacketConn
	returned time.Time
	handle   uint32
}

// mxDgRun dials n packet sessions on p at once. The writing side — each
// dialer right after its DialPacket returned, as the field case does, or
// with passiveWrites each passive session right after its Confirm while
// its dialer stays silent — writes writes datagrams (mxDgWrite); the other
// side reads each session's datagrams (verified) until writes arrived or
// within passed without one. within must cover the longest DialPacket
// under the test's loss (an OPEN_ACK retransmitted by REL), as a passive
// session is accepted before its dialer's DialPacket returns. It returns
// the cycles, the passive sessions (in accept order, not the cycles'
// order) and the readers' verifiers: the passive sessions' (accept order),
// with passiveWrites the dialers' (cycle order).
func mxDgRun(t *testing.T, p *Peer, ln *Listener, n, writes int, within time.Duration, passiveWrites bool) ([]mxDgCycle, []*PacketConn, []*rendrtest.PacketVerifier) {
	t.Helper()
	cycles := make([]mxDgCycle, n)
	vs := make([]*rendrtest.PacketVerifier, n)
	errs := make(chan error, 2*n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.DialPacket(context.Background(), DialOptions{})
			if err != nil {
				errs <- err
				return
			}
			cycles[i] = mxDgCycle{dc: c, returned: time.Now()}
			if passiveWrites {
				vs[i] = mxDgRead(c, writes, within)
				return
			}
			if err := mxDgWrite(c, writes); err != nil {
				errs <- err
			}
		}()
	}
	pcs := make([]*PacketConn, n)
	for i := range n {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pp, err := ln.AcceptPacket(ctx)
		cancel()
		if err != nil {
			t.Fatalf("AcceptPacket %d: %v", i, err)
		}
		if pcs[i], err = pp.Confirm(); err != nil {
			t.Fatalf("Confirm %d: %v", i, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !passiveWrites {
				vs[i] = mxDgRead(pcs[i], writes, within)
				return
			}
			if err := mxDgWrite(pcs[i], writes); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("writer: %v", err)
	}
	for i := range cycles {
		for _, cs := range cycles[i].dc.Status().Carriers {
			if cs.State != CarrierDead {
				cycles[i].handle = cs.Handle
			}
		}
	}
	return cycles, pcs, vs
}

// mxDgWrite writes writes datagrams on c (seed 40, seqs from 0, 64 bytes)
// at once and waits (at most 2 s) until its counters account for every
// write: each is either sent or dropped within MaxAge of its write (the
// writer and the age step run after WriteTo returns).
func mxDgWrite(c *PacketConn, writes int) error {
	buf := make([]byte, 64)
	for k := range writes {
		if _, err := c.WriteTo(rendrtest.PacketPayload(buf, 40, uint64(k), len(buf), time.Now()), nil); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		pk := c.Status().Packet
		if pk.Sent+pk.DropQueue+pk.DropAge+pk.DropTooLarge+pk.DropNoPath >= uint64(writes) {
			return nil
		}
		if time.Now().After(deadline) {
			return nil // the caller's assertion reports the counters
		}
		time.Sleep(time.Millisecond)
	}
}

// mxDgRead reads c until n datagrams arrived or within passed without one,
// verifying each against seed 40 (peRecv without a testing.TB: it runs on
// its own goroutine; a corrupt datagram shows in the verifier's Result).
func mxDgRead(c *PacketConn, n int, within time.Duration) *rendrtest.PacketVerifier {
	v := rendrtest.NewPacketVerifier(40)
	buf := make([]byte, wire.MaxDatagram)
	for range n {
		c.SetReadDeadline(time.Now().Add(within))
		k, _, err := c.ReadFrom(buf)
		if err != nil {
			break
		}
		_ = v.Add(buf[:k], time.Now())
	}
	c.SetReadDeadline(time.Time{})
	return v
}

// mxDgEnd closes the sessions and waits for each Done (bounded).
func mxDgEnd(t *testing.T, cs ...*PacketConn) {
	t.Helper()
	for _, c := range cs {
		c.Close()
	}
	for _, c := range cs {
		select {
		case <-c.Done():
		case <-time.After(time.Minute):
			t.Fatal("a session did not end within a minute of its Close")
		}
	}
}

// mxDgDialers returns the dialer sessions of cycles.
func mxDgDialers(cycles []mxDgCycle) []*PacketConn {
	out := make([]*PacketConn, 0, len(cycles))
	for _, c := range cycles {
		out = append(out, c.dc)
	}
	return out
}

// TestMuxDatagramGoFrameUnderLoss_L40 (M3-D8 as amended by m3 DGMUX; L40,
// the RI finding of lesson/pkt-openclose): 16 packet sessions dialled at
// once on a started datagram trunk, each writing 10 datagrams right after
// DialPacket returned. Stimulus (mxDgHeldWindow): the first copy of the
// fourth REL{OPEN} is lost (removed by the tap), so the trunk's REL window
// stays full at its cseq until REL retransmits it — longer than MaxAge —
// while the views whose OPENs went before it attach and owe their go
// frames (at least two attach, at least one go frame finds no REL room).
// Every session's datagrams leave at once (Sent 10, DropAge 0; the first
// DGRAM of its handle on the wire within one REL RTO of DialPacket's
// return) and arrive intact (the passive's verifier: 10 unique, nothing
// corrupt): no session ends with DropAge = writes and the passive's
// Received 0; every view's go frame (REL{PACK}) is still placed once REL
// room frees. The "passive writes first" row has the dialers silent and
// each passive write 10 datagrams right after Confirm: a dialer frame
// other than a DGRAM (an unreliable PACK) ends each passive's hold within
// one REL RTO of DialPacket's return, so the passive sends all 10 (DropAge
// 0) and its dialer receives them intact. The "1 % loss" row runs 100
// rounds of 16 concurrent cycles over a hub with 10 ms and 1 % loss each
// way: every cycle's datagrams leave (Sent 10, DropAge 0) and at least
// 95 % of all arrive intact.
func TestMuxDatagramGoFrameUnderLoss_L40(t *testing.T) {
	const writes = 10
	for _, passiveWrites := range []bool{false, true} {
		name := "window held by a lost OPEN"
		if passiveWrites {
			name = "window held by a lost OPEN, passive writes first"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { mxDgHeldWindow(t, writes, passiveWrites) })
		})
	}
	t.Run("1 % loss", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := peNewHub(t, Config{}, ListenConfig{}, nil)
			p := h.peer(h.carrier("h1", 1, nil))
			d1, p1 := peOpen(t, p, h.ln, DialOptions{})
			for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
				h.hub.SetDelay(d, 10*time.Millisecond, 0)
				h.hub.SetLoss(d, 0.01)
			}
			sent, got := 0, uint64(0)
			for round := range 100 {
				cycles, pcs, vs := mxDgRun(t, p, h.ln, 16, writes, 3*time.Second, false)
				for i, c := range cycles {
					pk := c.dc.Status().Packet
					if pk.Sent != writes || pk.DropAge != 0 {
						t.Fatalf("round %d session %d (handle %d): %+v, want its %d datagrams sent at once (the go frame held them)", round, i, c.handle, *pk, writes)
					}
					r := vs[i].Result()
					if r.Corrupt != 0 || r.Duplicates != 0 || r.BadSize != 0 {
						t.Fatalf("round %d passive %d: %+v", round, i, r)
					}
					sent += writes
					got += r.Unique
				}
				mxDgEnd(t, append(mxDgDialers(cycles), pcs...)...)
			}
			if float64(got) < 0.95*float64(sent) {
				t.Fatalf("%d of %d datagrams arrived at 1 %% loss", got, sent)
			}
			t.Logf("%d of %d datagrams arrived", got, sent)
			mxDgEnd(t, d1, p1)
			h.close()
		})
	})
}

// mxDgHeldWindow is the "window held by a lost OPEN" row of
// TestMuxDatagramGoFrameUnderLoss_L40: 16 packet sessions dialled at once
// on a started datagram trunk while the first copy of the drop-th
// REL{OPEN} is lost, so that the trunk's REL window stays full at its
// cseq until REL retransmits it (longer than MaxAge) while the views whose
// OPENs went before it attach and owe their go frames. The writing side
// (mxDgRun) writes writes datagrams per session; with passiveWrites the
// dialers stay silent, so only a dialer frame that is not a DGRAM can end
// each passive's hold (M3-D8).
func mxDgHeldWindow(t *testing.T, writes int, passiveWrites bool) {
	const drop = 4 // three views attach before the lost OPEN
	h := peNewHub(t, Config{}, ListenConfig{}, nil)
	tap := &mxDgTap{}
	fc := h.carrier("h1", 1, nil)
	fc.Dial = tap.wrap(fc.Dial)
	p := h.peer(fc)
	d1, p1 := peOpen(t, p, h.ln, DialOptions{}) // the started trunk (view 1)
	synctest.Wait()
	tap.arm(drop)
	cycles, pcs, vs := mxDgRun(t, p, h.ln, 16, writes, 2*time.Second, passiveWrites)

	// Stimulus: one REL{OPEN} copy lost; the window full at its cseq for
	// longer than MaxAge; views attached meanwhile.
	tap.mu.Lock()
	dropped, dropCs, dropAt, retxAt := tap.dropped, tap.dropCs, tap.dropAt, tap.retxAt
	maxCs := dropCs
	for _, r := range tap.log {
		if r.cseq != 0 && r.at.Before(retxAt) && wire.SeqLess(maxCs, r.cseq) {
			maxCs = r.cseq
		}
	}
	log := append([]mxDgRec(nil), tap.log...)
	tap.mu.Unlock()
	const maxAge = 100 * time.Millisecond // Packet.MaxAge's default
	if dropped != 1 || retxAt.IsZero() || retxAt.Sub(dropAt) <= maxAge {
		t.Fatalf("stimulus: %d REL{OPEN} copies removed, retransmitted %v after the loss; want 1, later than MaxAge", dropped, retxAt.Sub(dropAt))
	}
	if maxCs-dropCs < wire.RelWindow-1 {
		t.Fatalf("stimulus: REL cseqs %d…%d placed before the retransmission, want a full window (%d)", dropCs, maxCs, wire.RelWindow)
	}
	attached, refused := 0, 0
	for _, c := range cycles {
		if c.returned.Before(dropAt) || !c.returned.Before(retxAt) {
			continue
		}
		attached++
		// Its go frame found the window full: no REL{PACK} of its handle
		// before the retransmission.
		early := false
		for _, r := range log {
			if r.handle == c.handle && r.typ == wire.TypePack && r.rel && r.at.Before(retxAt) {
				early = true
				break
			}
		}
		if !early {
			refused++
		}
	}
	if attached < 2 || refused < 1 {
		t.Fatalf("stimulus: %d DialPackets returned while the REL window was held, %d of their go frames refused; want at least 2 and 1", attached, refused)
	}

	// Load and integrity: every session's datagrams left at once and
	// arrived intact.
	if passiveWrites {
		mxDgCheckPassive(t, cycles, pcs, vs, writes, log)
	} else {
		mxDgCheck(t, cycles, vs, writes, log)
	}
	// The go frame keeps its purpose: every view's REL{PACK} is placed
	// once REL room frees, so the passive's hold ends although every other
	// dialer frame might have been lost.
	peWait(t, 2*time.Second, "every view's go frame", func() bool {
		tap.mu.Lock()
		defer tap.mu.Unlock()
		gone := map[uint32]bool{}
		for _, r := range tap.log {
			if r.typ == wire.TypePack && r.rel {
				gone[r.handle] = true
			}
		}
		for _, c := range cycles {
			if !gone[c.handle] {
				return false
			}
		}
		return true
	})
	t.Logf("REL window held %v (cseq %d…%d); %d views attached meanwhile, %d go frames refused", retxAt.Sub(dropAt), dropCs, maxCs, attached, refused)
	mxDgEnd(t, append(mxDgDialers(cycles), pcs...)...)
	mxDgEnd(t, d1, p1)
	h.close()
}

// mxDgCheckPassive is mxDgCheck for passive writers: every passive
// session sent its writes and dropped none by age, every dialer received
// them intact, and each dialer's first frame of its handle after its OPEN
// (the frame that ends the passive's hold) went on the wire within one REL
// RTO (RelRTOMin, 200 ms) of DialPacket's return.
func mxDgCheckPassive(t *testing.T, cycles []mxDgCycle, pcs []*PacketConn, vs []*rendrtest.PacketVerifier, writes int, log []mxDgRec) {
	t.Helper()
	first := map[uint32]mxDgRec{}
	for _, r := range log {
		if r.handle != 0 && r.typ != wire.TypeOpen {
			if _, ok := first[r.handle]; !ok {
				first[r.handle] = r
			}
		}
	}
	for i, c := range cycles {
		r, ok := first[c.handle]
		if !ok || r.at.Sub(c.returned) > 200*time.Millisecond {
			t.Errorf("session %d (handle %d): first dialer frame %v (rel %v) on the wire %v after DialPacket returned (any: %v), want within one REL RTO", i, c.handle, r.typ, r.rel, r.at.Sub(c.returned), ok)
		}
		if r := vs[i].Result(); r.Unique != uint64(writes) || r.Corrupt != 0 || r.Duplicates != 0 || r.BadSize != 0 {
			t.Errorf("dialer session %d (handle %d): %+v, want %d intact datagrams", i, c.handle, r, writes)
		}
	}
	for i, c := range pcs {
		if pk := c.Status().Packet; pk.Sent != uint64(writes) || pk.DropAge != 0 {
			t.Errorf("passive session %d: %+v, want its %d datagrams sent (the response hold kept them)", i, *pk, writes)
		}
	}
}

// mxDgCheck asserts every cycle's counters and the passive's verdicts:
// all writes sent, none dropped by age, the first DGRAM of each handle on
// the wire within one REL RTO (RelRTOMin, 200 ms) of DialPacket's return,
// and writes unique intact datagrams at the passive.
func mxDgCheck(t *testing.T, cycles []mxDgCycle, vs []*rendrtest.PacketVerifier, writes int, log []mxDgRec) {
	t.Helper()
	first := map[uint32]time.Time{}
	for _, r := range log {
		if r.typ == wire.TypeDgram {
			if _, ok := first[r.handle]; !ok {
				first[r.handle] = r.at
			}
		}
	}
	for i, c := range cycles {
		pk := c.dc.Status().Packet
		if pk.Sent != uint64(writes) || pk.DropAge != 0 {
			t.Errorf("session %d (handle %d): %+v, want its %d datagrams sent (the go frame held them)", i, c.handle, *pk, writes)
		}
		at, ok := first[c.handle]
		if !ok || at.Sub(c.returned) > 200*time.Millisecond {
			t.Errorf("session %d (handle %d): first DGRAM on the wire %v after DialPacket returned (any: %v), want within one REL RTO", i, c.handle, at.Sub(c.returned), ok)
		}
	}
	for i, v := range vs {
		if r := v.Result(); r.Unique != uint64(writes) || r.Corrupt != 0 || r.Duplicates != 0 || r.BadSize != 0 {
			t.Errorf("passive session %d: %+v, want %d intact datagrams", i, r, writes)
		}
	}
}
