package rendr

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// mxSessionTap returns the newest tamper of taps that carries a session
// frame (OPEN or JOIN) of the dialer.
func mxSessionTap(t testing.TB, taps *mxTaps) *rendrtest.Tamper {
	t.Helper()
	ts := mxSessionTaps(t, taps)
	if len(ts) == 0 {
		t.Fatal("no session trunk among the taps")
	}
	return ts[len(ts)-1]
}

// mxDetachLog records the AfterDetach hook calls per (carrier, handle) in
// order: sent is a DETACH placed, !sent one dispatched (both Runtimes of
// a test share the hook and the CarrierIDs).
type mxDetachLog struct {
	mu  sync.Mutex
	evs map[[2]uint32][]bool
}

func (m *mxDetachLog) add(c, h uint32, sent bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.evs == nil {
		m.evs = map[[2]uint32][]bool{}
	}
	m.evs[[2]uint32{c, h}] = append(m.evs[[2]uint32{c, h}], sent)
}

func (m *mxDetachLog) of(c, h uint32) []bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]bool(nil), m.evs[[2]uint32{c, h}]...)
}

// mxPendingRig is the world of the attached-pending × peer DETACH rows: a
// dialer whose DialResult hook can hold attempt results (armed) until
// unblock and whose BeforeWrite hook can hold one trunk's writer
// (writeOn) until unblockWrite, a passive whose sessions idle out after
// 1 s (the dialer's never do), and the AfterDetach log of both.
type mxPendingRig struct {
	e       *e2ePair
	dl      mxDetachLog
	armed   atomic.Bool
	gated   chan struct{}
	release chan struct{}
	once    sync.Once

	writeOn  atomic.Uint32 // CarrierID whose writer BeforeWrite holds; 0: none
	wheld    chan struct{}
	wrelease chan struct{}
	wonce    sync.Once
}

func (g *mxPendingRig) unblock()      { g.once.Do(func() { close(g.release) }) }
func (g *mxPendingRig) unblockWrite() { g.wonce.Do(func() { close(g.wrelease) }) }

func newMxPendingRig(t *testing.T) *mxPendingRig {
	g := &mxPendingRig{gated: make(chan struct{}, 1), release: make(chan struct{}), wheld: make(chan struct{}, 1), wrelease: make(chan struct{})}
	t.Cleanup(g.unblock)
	t.Cleanup(g.unblockWrite)
	hk := &testhooks.Hooks{
		AfterDetach: g.dl.add,
		DialResult: func(uint32) {
			if !g.armed.Load() {
				return
			}
			select {
			case g.gated <- struct{}{}:
			default:
			}
			<-g.release
		},
		BeforeWrite: func(c uint32, _, _ int) {
			if id := g.writeOn.Load(); id == 0 || c != id {
				return
			}
			select {
			case g.wheld <- struct{}{}:
			default:
			}
			<-g.wrelease
		},
	}
	base := testhooks.Overrides{DeadMin: time.Minute, DeadMax: time.Minute, WriteStall: time.Minute, Hooks: hk}
	pov := base
	pov.Hooks = &testhooks.Hooks{AfterDetach: g.dl.add} // the dialer's hooks hold the dialer only
	pov.IdleTimeout = time.Second
	e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, &base), p: wpTestRuntime(t, Config{}, &pov)}
	e.ln = wpListen(t, e.p, ListenConfig{})
	for _, n := range []string{"a", "b"} {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: n, Accept: e.ln.Handle})
		e.links = append(e.links, l)
		t.Cleanup(l.Close)
	}
	e.links[0].SetDelay(time.Millisecond, 0) // a ranks first
	e.links[1].SetDelay(5*time.Millisecond, 0)
	g.e = e
	return g
}

// confirmOne accepts and confirms the next session on the rig's Listener
// within 5 s.
func (g *mxPendingRig) confirmOne(t *testing.T) *Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pend, err := g.e.ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := pend.Confirm()
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// mxNewHandle returns the handle above 1 of the newest dialer frame of
// type typ on tp, waiting up to 2 s.
func mxNewHandle(t *testing.T, tp *rendrtest.Tamper, typ rendrtest.FrameType) uint32 {
	t.Helper()
	var h uint32
	mxWait(t, 2*time.Second, "a new view's first frame", func() bool {
		for _, rec := range mxFrames(tp, rendrtest.Up, typ, 0) {
			if rec.Handle > 1 {
				h = rec.Handle
			}
		}
		return h != 0
	})
	return h
}

// detachAfterResponse runs the rows' core on trunk tp (CarrierID id) for
// the view h whose OK response tp holds back: the passive session sc idles
// out (DETACH(ended) only: its view is held); the dialer's writer of the
// trunk is held in its next write (a PING at the latest), so that the
// DETACH it owes cannot be placed — placing it would complete the
// exchange and end the view, which the attach would then see as dead
// rather than detached; the held direction is released while the hook
// holds attempt results until the dialer dispatched the passive's DETACH;
// then the result goes to the actor (the window of the row: the view is
// detached, not ended); then the writer goes on and the dialer's own
// DETACH(h) answer follows.
func (g *mxPendingRig) detachAfterResponse(t *testing.T, tp *rendrtest.Tamper, id, h uint32, sc *Conn) {
	t.Helper()
	synctest.Wait()
	g.armed.Store(true)
	e2eDone(t, sc, 3*time.Second) // IdleTimeout: the held view gets DETACH(ended) only
	synctest.Wait()
	if ev := g.dl.of(id, h); len(ev) != 1 || !ev[0] {
		t.Fatalf("DETACH events of (%d, %d) before the release: %v, want the passive's placement only", id, h, ev)
	}
	g.writeOn.Store(id)
	select {
	case <-g.wheld:
	case <-time.After(time.Minute):
		t.Fatal("the dialer's writer of the trunk wrote nothing within a minute")
	}
	tp.Release(rendrtest.Down)
	select {
	case <-g.gated:
	case <-time.After(2 * time.Second):
		t.Fatal("no dial result reached the hook (stimulus)")
	}
	mxWait(t, 2*time.Second, "the dialer dispatched the peer's DETACH", func() bool {
		ev := g.dl.of(id, h)
		return len(ev) >= 2 && !ev[1]
	})
	synctest.Wait()
	if ev := g.dl.of(id, h); len(ev) != 2 {
		t.Fatalf("DETACH events of (%d, %d) at the attach: %v, want ours not yet placed (the window)", id, h, ev)
	}
	g.armed.Store(false)
	g.unblock()
	synctest.Wait()
	g.writeOn.Store(0)
	g.unblockWrite()
	mxWait(t, 2*time.Second, "our DETACH(h) answer", func() bool {
		ev := g.dl.of(id, h)
		return len(ev) >= 3 && ev[2]
	})
}

// TestAttachedPendingPeerDetach (R1-9, the dialer's attached-pending ×
// the peer's DETACH row; the session half of TestHandleStateMachine): a
// view on a live trunk is answered OK, and the passive detaches it before
// the dialer's actor attaches it — the passive session reached
// IdleTimeout while its view was held, and the trunk's frames to the
// dialer were held back until then (Tamper.Hold), so the dialer reads the
// OK response followed by DETACH(h); a DialResult hook keeps the attempt's
// result from the actor until the dialer's trunk dispatched that DETACH
// (stimulus). The attach then finds the view detached, and the dialer
// answered with its own DETACH(h) after it dispatched the peer's.
//
//   - JOIN: a bond's member JOIN on trunk B: no lane for h (no live or
//     dead row), the attempt counts as a carrier refusal (no factory
//     carries a failure mark), and the session (its passive's RST held on
//     trunk A) stays open.
//   - OPEN: a selector Dial of a one-factory Peer whose OPEN rides the live
//     trunk: the session never binds to that answer, and its Dial fails
//     (the passive session is gone: a later OPEN meets its tombstone)
//     instead of returning a session whose only carrier was detached.
func TestAttachedPendingPeerDetach(t *testing.T) {
	t.Run("JOIN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newMxPendingRig(t)
			e := g.e
			var ta, tb mxTaps
			defer ta.close()
			defer tb.close()
			p := e.mxPeer(mxTapCarrier(e.links[0], &ta), mxTapCarrier(e.links[1], &tb))
			k, kq := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond}) // trunks A and B
			mxWait(t, time.Second, "the first bond's members", func() bool { return mxMembers(k) == 2 })
			trunkA, trunkB := mxSessionTap(t, &ta), mxSessionTap(t, &tb)
			idB := uint32(mxCarrier(t, k, "b").ID)
			trunkB.Hold(rendrtest.Down) // the next view's JOIN_ACK stays on the passive's side
			res := e2eDialAsync(context.Background(), p, DialOptions{Mode: ModeBond})
			sc := g.confirmOne(t)
			var r dialResult
			select {
			case r = <-res:
			case <-time.After(5 * time.Second):
				t.Fatal("the second bond's Dial did not return")
			}
			if r.err != nil {
				t.Fatal(r.err)
			}
			h := mxNewHandle(t, trunkB, rendrtest.FrameJoin)
			trunkA.Hold(rendrtest.Down) // the passive's end of the session (its RST) stays on A
			g.detachAfterResponse(t, trunkB, idB, h, sc)
			for _, row := range mxSessionCarriers(r.c) {
				if uint32(row.ID) == idB && row.Stats.Handle == h {
					t.Fatalf("the detached view %d got a lane: %+v", h, row)
				}
			}
			if st := r.c.Status(); st.State != StateOpen {
				t.Fatalf("the dialer's session (its passive's RST still held) is %v: %v", st.State, st.Err)
			}
			for _, f := range p.Status().Factories {
				if f.Failed {
					t.Fatalf("factory %s carries a failure mark (%s): the refusal counted as a failure", f.Name, f.FailReason)
				}
			}
			trunkA.Release(rendrtest.Down)
			r.c.Close()
			k.Close()
			kq.Close()
			e.close()
		})
	})
	t.Run("OPEN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newMxPendingRig(t)
			e := g.e
			var ta mxTaps
			defer ta.close()
			p := e.mxPeer(mxTapCarrier(e.links[0], &ta))
			k, kq := e2eOpen(t, p, e.ln, DialOptions{}) // trunk A
			trunkA := mxSessionTap(t, &ta)
			idA := uint32(mxCarrier(t, k, "a").ID)
			trunkA.Hold(rendrtest.Down) // the next view's OPEN_ACK stays on the passive's side
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res := e2eDialAsync(ctx, p, DialOptions{})
			sc := g.confirmOne(t)
			h := mxNewHandle(t, trunkA, rendrtest.FrameOpen)
			g.detachAfterResponse(t, trunkA, idA, h, sc)
			var r dialResult
			select {
			case r = <-res:
			case <-time.After(30 * time.Second):
				t.Fatal("the Dial did not return")
			}
			if r.err == nil {
				t.Fatalf("Dial returned a session on an answer its passive detached: %+v", r.c.Status())
			}
			t.Logf("Dial: %v", r.err)
			k.Close()
			kq.Close()
			e.close()
		})
	})
}

// mxFlipReason arms tp so that the next DETACH of direction d arrives with
// reason ended instead of retired and a valid CRC: two bits of the reason
// byte and the CRC32C trailer bits they change (CRC32C is affine, so the
// trailer's change depends only on the flipped bits, not on the frame).
func mxFlipReason(tp *rendrtest.Tamper, d rendrtest.Dir) {
	const reasonAt = wire.HeaderLen + 4 // DETACH payload: handle u32 · reason u8
	n := wire.HeaderLen + wire.DetachLen
	diff := make([]byte, n)
	diff[reasonAt] = byte(wire.DetachRetired ^ wire.DetachEnded)
	var tr [wire.TrailerLen]byte
	wire.PutTrailer(tr[:], wire.CRC(diff)^wire.CRC(make([]byte, n)))
	at := rendrtest.NextOfType(rendrtest.FrameDetach)
	for i, b := range append([]byte{diff[reasonAt]}, tr[:]...) {
		off := reasonAt
		if i > 0 {
			off = n + i - 1
		}
		for j := range 8 {
			if b&(0x80>>j) != 0 {
				tp.FlipBit(d, at, off*8+j)
			}
		}
	}
}

// TestDetachEndedOnLiveView (R1-5 rule 3, R1-9's last row; the
// DETACH(ended) half of TestDetachReasonInformational): a live view of a
// live selector session receives DETACH(ended). The dialer's planned
// switch away from trunk A places DETACH(retired) for its view; the tamper
// turns its reason into ended on the way, re-checksummed, so the frame is
// valid (stimulus: Stats.Flipped). The passive reads the reason as
// informational only: its lane leaves as for a retirement (row retired),
// the session keeps delivering — 8 MiB each way across the switch and
// 64 KiB after it, intact —, no RST is placed on the trunk, there is no
// EOF and no death migration, and the trunk with its neighbour bond lives
// on.
func TestDetachEndedOnLiveView(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, mxSwitchOverrides(time.Hour), ListenConfig{}, "a", "b")
		la, lb := e.links[0], e.links[1]
		la.SetDelay(time.Millisecond, 0)
		lb.SetDelay(5*time.Millisecond, 0)
		var ta, tb mxTaps
		defer ta.close()
		defer tb.close()
		p := e.mxPeer(mxTapCarrier(la, &ta), mxTapCarrier(lb, &tb))
		k, kq := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 2*time.Second, "the keeper's members", func() bool { return mxMembers(k) == 2 })
		s, sq := e2eOpen(t, p, e.ln, DialOptions{})
		old := mxCarrier(t, sq, "")
		tpA := mxSessionTaps(t, &ta)[0]
		upDet := len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameDetach, 0))
		mxFlipReason(tpA, rendrtest.Up)
		done := make(chan error, 1)
		go func() { done <- e2eExchangeErr(s, sq, 8<<20, 51) }()
		la.SetDelay(20*time.Millisecond, 0)
		mxWait(t, 30*time.Second, "both old lanes leave", func() bool {
			rows, drows := mxCarrierRows(sq, old.ID), mxCarrierRows(s, old.ID)
			return len(rows) == 1 && rows[0].State == session.LaneDead && len(drows) == 1 && drows[0].State == session.LaneDead
		})
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if st := tpA.Stats(); st.Flipped == 0 || st.FlipMissed != 0 {
			t.Fatalf("tamper %+v: the DETACH's reason was not rewritten (stimulus)", st)
		}
		if n := len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameDetach, 0)) - upDet; n != 1 {
			t.Fatalf("%d DETACHes from the dialer on trunk A, want the one rewritten", n)
		}
		if row := mxCarrierRows(sq, old.ID)[0]; row.DeathCause.String() != CauseRetired.String() {
			t.Fatalf("the passive's detached lane: %v %s, want retired (the reason is informational)", row.DeathCause, row.DeathDetail)
		}
		if n := len(mxFrames(tpA, rendrtest.Down, rendrtest.FrameRst, 0)) + len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameRst, 0)); n != 0 {
			t.Fatalf("%d RSTs on the trunk", n)
		}
		for _, c := range []*Conn{s, sq, k, kq} {
			if st := c.Status(); st.State != StateOpen || st.Err != nil || st.Migrations.Death != 0 {
				t.Fatalf("%v after the DETACH(ended): %+v", st.Role, st)
			}
		}
		if n := mxMembers(k); n != 2 {
			t.Fatalf("the neighbour bond has %d members, want both (trunk A lives)", n)
		}
		e2eExchange(t, s, sq, 64<<10, 53)
		e2eExchange(t, k, kq, 64<<10, 55)
		e2eFinish(t, s, sq)
		e2eFinish(t, k, kq)
		e.close()
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

// TestOpeningRaceLoserDetachOnly (R1-5 rule 2, R1-2): a real opening race
// on two live trunks. The keeper bond holds views on trunks A and B; a
// selector session's OPEN rides A (it ranks first), whose answers are held
// in the tamper, so after JoinStagger its race opens a second OPEN on B —
// two fast paths, no factory call. The passive holds the second OPEN as a
// duplicate of its pending session; the application confirms it and both
// carriers are answered OK. B's answer opens the session; A's late
// OPEN_ACK(OK) arrives after the session opened: the losing view is
// retired with DETACH only — no RST for its handle, since the session did
// open —, the session delivers on B, both trunks and the keeper's lanes
// live, no factory is marked failed and nobody counts a death.
func TestOpeningRaceLoserDetachOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		e.links[0].SetDelay(time.Millisecond, 0) // a ranks first
		e.links[1].SetDelay(5*time.Millisecond, 0)
		var ta, tb mxTaps
		defer ta.close()
		defer tb.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &ta), mxTapCarrier(e.links[1], &tb))
		k, kq := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		mxWait(t, time.Second, "the keeper's members", func() bool { return mxMembers(k) == 2 })
		trunkA, trunkB := mxSessionTap(t, &ta), mxSessionTap(t, &tb)
		dials := ta.dials.Load() + tb.dials.Load()
		detA := len(mxFrames(trunkA, rendrtest.Up, rendrtest.FrameDetach, 0))
		trunkA.Hold(rendrtest.Down) // the answers on A wait
		res := e2eDialAsync(context.Background(), p, DialOptions{})
		hA := mxNewHandle(t, trunkA, rendrtest.FrameOpen)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pend, err := e.ln.Accept(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		hB := mxNewHandle(t, trunkB, rendrtest.FrameOpen) // the race's second OPEN, after JoinStagger
		synctest.Wait()
		sc, err := pend.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		var r dialResult
		select {
		case r = <-res:
		case <-time.After(5 * time.Second):
			t.Fatal("the Dial did not return on B's answer")
		}
		if r.err != nil {
			t.Fatal(r.err)
		}
		trunkA.Release(rendrtest.Down)
		mxWait(t, 5*time.Second, "the loser's DETACH on A", func() bool {
			return len(mxFrames(trunkA, rendrtest.Up, rendrtest.FrameDetach, 0))-detA == 1
		})
		synctest.Wait()
		if n := len(mxFrames(trunkA, rendrtest.Down, rendrtest.FrameOpenAck, hA)); n != 1 {
			t.Fatalf("%d OPEN_ACKs for handle %d on A, want the passive's answer (stimulus: the late OK)", n, hA)
		}
		if n := len(mxFrames(trunkA, rendrtest.Up, rendrtest.FrameRst, hA)); n != 0 {
			t.Fatalf("%d RSTs for the losing handle %d: the session opened, so DETACH only", n, hA)
		}
		if a, ok := activeName(r.c); !ok || a != "b" {
			t.Fatalf("the session's active carrier %q, want b (handle %d)", a, hB)
		}
		if n := ta.dials.Load() + tb.dials.Load(); n != dials {
			t.Fatalf("%d factory calls during the race, want none (two fast paths)", n-dials)
		}
		for _, c := range []*Conn{r.c, sc, k, kq} {
			if st := c.Status(); st.State != StateOpen || st.Migrations.Death != 0 || st.NoPathEpisodes != 0 {
				t.Fatalf("%v: %+v", st.Role, st)
			}
		}
		if n := mxMembers(k); n != 2 {
			t.Fatalf("the keeper has %d members, want both", n)
		}
		for _, f := range p.Status().Factories {
			if f.Failed {
				t.Fatalf("factory %s marked failed (%s)", f.Name, f.FailReason)
			}
		}
		e2eExchange(t, r.c, sc, 256<<10, 61)
		e2eExchange(t, k, kq, 256<<10, 63)
		e2eFinish(t, r.c, sc)
		e2eFinish(t, k, kq)
		e.close()
	})
}

// activeName returns the factory name of c's active carrier.
func activeName(c *Conn) (string, bool) {
	for _, cs := range c.Status().Carriers {
		if cs.State == CarrierActive {
			return cs.Name, true
		}
	}
	return "", false
}
