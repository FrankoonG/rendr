package rendr

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Passive admission on live trunks (M3-D21 … M3-D23, R1-4, R1-6, R1-10).
// A test drives a Peer's pool directly where it needs a dialer that breaks
// its own rules — a second view of one session on a trunk, a JOIN that the
// usable rule would not place, more OPENs at once than any session would
// make (mxInject: a fresh session key per call, no check).

// mxSessKey is a session key no session has (the pool's one-view rule).
var mxSessKey atomic.Uintptr

func init() { mxSessKey.Store(1 << 40) }

// mxInject places one OPEN or JOIN with payload on a live trunk of factory
// f of p (the pool's fast path, or a dial when none is usable) and returns
// the response's status and code once it arrived.
func mxInject(ctx context.Context, p *Peer, f int, kind wire.Type, payload []byte) (*carrier.Established, wire.AckStatus, uint32, error) {
	return mxInjectTo(ctx, p, f, kind, payload, [16]byte{})
}

// mxInjectTo is mxInject with the bound instance inst of a JOIN (the pool
// places it only on a trunk of that instance; zero: any trunk that takes an
// OPEN).
func mxInjectTo(ctx context.Context, p *Peer, f int, kind wire.Type, payload []byte, inst [16]byte) (*carrier.Established, wire.AckStatus, uint32, error) {
	dk := wire.TypeData // a JOIN: of a stream session (every JOIN these tests inject)
	if o, err := wire.ParseOpen(payload, len(payload)); kind == wire.TypeOpen && err == nil && o.Kind == wire.KindDatagram {
		dk = wire.TypeDgram
	}
	est, err := p.pool.Attempt(ctx, f, p.rt.cenv.IDs.Next(), kind, payload, nil, inst, mxSessKey.Add(1), dk)
	if err != nil {
		return nil, 0, 0, err
	}
	switch est.Resp.Type {
	case wire.TypeOpenAck:
		a, err := wire.ParseOpenAck(est.Payload)
		return est, a.Status, a.Code, err
	case wire.TypeJoinAck:
		a, err := wire.ParseJoinAck(est.Payload)
		return est, a.Status, 0, err
	}
	return est, 0, 0, errors.New("not a response")
}

// mxDrop ends an injected view that was answered OK (its DETACH).
func mxDrop(est *carrier.Established) {
	if est != nil {
		est.Conn.Kill(carrier.CauseLocalClose, "test: injected view done")
	}
}

// TestPassiveAdmitOnTrunk_L48 (M3-D21, M3-D12, R1-4; L48): admission of
// new handles runs on the trunk's reader and never waits for the
// application. With Accept stalled and AcceptBacklog 2, six OPENs on a live
// trunk leave two sessions pending and get four CAPACITY CodeBacklog
// answers, while a JOIN of another session that arrives right behind them
// is admitted at once (JOINs never wait behind OPENs). On a trunk whose
// passive holds at most four views, OPENs beyond the cap get CAPACITY
// CodeMuxFull: the dialer's pool marks the trunk full and the attempts
// continue on a new carrier of the factory.
func TestPassiveAdmitOnTrunk_L48(t *testing.T) {
	t.Run("backlog bound, JOIN admitted", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{AcceptBacklog: 2}, "a", "b")
			p := e.peer(e.links[0])
			pb := e.peer(e.links[1])
			s1, q1 := e2eOpen(t, p, e.ln, DialOptions{})
			s2, q2 := e2eOpen(t, pb, e.ln, DialOptions{}) // another session, on another Peer's carrier
			var wg sync.WaitGroup
			type res struct {
				st   wire.AckStatus
				code uint32
				err  error
			}
			out := make(chan res, 6)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for i := range 6 {
				wg.Go(func() {
					est, st, code, err := mxInject(ctx, p, 0, wire.TypeOpen, wpOpen(wpSID(100+i), wire.KindStream, 1, nil))
					if st == wire.StatusOK {
						mxDrop(est)
					}
					out <- res{st, code, err}
				})
			}
			synctest.Wait()
			est, st, _, err := mxInject(context.Background(), p, 0, wire.TypeJoin, wpJoin(s2.ID(), 1, 0))
			if err != nil || st != wire.StatusOK {
				t.Fatalf("JOIN behind the OPEN flood: %v, %v; want OK", st, err)
			}
			if CarrierID(est.Conn.ID()) != mxCarrier(t, s1, "a").ID {
				t.Fatalf("the JOIN went to carrier %d, want the live trunk %d", est.Conn.ID(), mxCarrier(t, s1, "a").ID)
			}
			mxDrop(est)
			refused := 0
			for range 4 {
				r := <-out
				if r.err != nil || r.st != wire.StatusCapacity || r.code != wire.CodeBacklog {
					t.Fatalf("an OPEN beyond the backlog: %v code %d, %v; want CAPACITY CodeBacklog", r.st, r.code, r.err)
				}
				refused++
			}
			if ps := e.p.Status(); ps.AcceptBacklog[0] != 2 || ps.Sessions.Pending != 2 {
				t.Fatalf("passive %+v, want 2 pending sessions holding the backlog", ps)
			}
			if c := mxCarrier(t, s1, "a"); c.State == CarrierDead {
				t.Fatal("the trunk died")
			}
			e2eExchange(t, s1, q1, 64<<10, 1)
			cancel()
			wg.Wait()
			for _, c := range []*Conn{s1, q1, s2, q2} {
				c.Close()
			}
			e.close()
		})
	})
	t.Run("view cap", func(t *testing.T) {
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
			if st := p.pool.Stats(); st.MuxFull == 0 || taps.dials.Load() < 2 {
				t.Fatalf("pool %+v, %d factory calls; want CodeMuxFull answers and a second carrier", st, taps.dials.Load())
			}
			for _, tr := range mxTrunkSet(e.p) {
				if n := tr.Views(); n > 4 {
					t.Fatalf("a passive trunk holds %d views, above its cap 4", n)
				}
			}
			for _, c := range append(cs, s1, q1) {
				c.Close()
			}
			for _, c := range acc.conns {
				c.Close()
			}
			e.close()
		})
	})
}

// TestMuxCompliantOpenBurst_L48 (R1-4): a compliant burst — 254 OPENs of
// new sessions and a JOIN of another session placed at once on a live
// trunk, its views then at the dialer's cap of 256 — with Accept stalled
// and AcceptBacklog 128: the trunk lives (the refusal ring holds every
// answer a compliant dialer can have outstanding), 128 sessions are
// pending, 126 OPENs are answered CAPACITY CodeBacklog, and the JOIN is
// admitted.
func TestMuxCompliantOpenBurst_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const opens, backlog = 254, 128
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{AcceptBacklog: backlog}, "a", "b")
		p := e.peer(e.links[0])
		pb := e.peer(e.links[1])
		s1, q1 := e2eOpen(t, p, e.ln, DialOptions{})
		s2, q2 := e2eOpen(t, pb, e.ln, DialOptions{})
		trunk := mxCarrier(t, s1, "a").ID
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var wg sync.WaitGroup
		var backlogged, other atomic.Int32
		for i := range opens {
			wg.Go(func() {
				est, st, code, err := mxInject(ctx, p, 0, wire.TypeOpen, wpOpen(wpSID(1000+i), wire.KindStream, 1, nil))
				switch {
				case err == nil && st == wire.StatusCapacity && code == wire.CodeBacklog:
					backlogged.Add(1)
				case err == nil && st == wire.StatusOK:
					mxDrop(est)
				case ctx.Err() == nil:
					other.Add(1)
				}
			})
		}
		var jst wire.AckStatus
		var jerr error
		wg.Go(func() {
			var est *carrier.Established
			est, jst, _, jerr = mxInject(ctx, p, 0, wire.TypeJoin, wpJoin(s2.ID(), 1, 0))
			if jst == wire.StatusOK {
				mxDrop(est)
			}
		})
		mxWait(t, 5*time.Second, "every refusal answered", func() bool { return backlogged.Load() == opens-backlog })
		synctest.Wait()
		if jerr != nil || jst != wire.StatusOK {
			t.Fatalf("the JOIN in the burst: %v, %v; want OK", jst, jerr)
		}
		if n := other.Load(); n != 0 {
			t.Fatalf("%d OPENs got another answer or an error", n)
		}
		if ps := e.p.Status(); ps.Sessions.Pending != backlog || ps.AcceptBacklog[0] != backlog {
			t.Fatalf("passive %+v, want %d pending", ps, backlog)
		}
		if c := mxCarrier(t, s1, "a"); c.ID != trunk || c.State == CarrierDead {
			t.Fatalf("the trunk %d: %+v", trunk, c)
		}
		e2eExchange(t, s1, q1, 64<<10, 3)
		cancel()
		wg.Wait()
		for _, c := range []*Conn{s1, q1, s2, q2} {
			c.Close()
		}
		e.close()
	})
}

// TestMuxOpenAfterListenerClose_L50 (M3-D63, R1-10; L50): an OPEN on a
// live trunk whose Listener closed is answered CAPACITY CodeListenerClosed,
// a carrier refusal: the dialer's next Dial makes a factory call (its new
// carrier reaches the Runtime's other Listener) and its Peer's gone-away set
// is unchanged; a JOIN on the same trunk is still admitted.
func TestMuxOpenAfterListenerClose_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, pr := wpTestRuntime(t, Config{}, nil), wpTestRuntime(t, Config{}, nil)
		ln1, ln2 := wpListen(t, pr, ListenConfig{}), wpListen(t, pr, ListenConfig{})
		var route atomic.Pointer[Listener]
		route.Store(ln1)
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(c net.Conn) error { return route.Load().Handle(c) }})
		t.Cleanup(l.Close)
		var taps mxTaps
		defer taps.close()
		e := &e2ePair{t: t, d: d, p: pr, ln: ln1, links: []*rendrtest.Link{l}}
		p := e.mxPeer(mxTapCarrier(l, &taps))
		s1, q1 := e2eOpen(t, p, ln1, DialOptions{})
		trunk := mxCarrier(t, s1, "a").ID
		route.Store(ln2)
		if err := ln1.Close(); err != nil {
			t.Fatal(err)
		}
		before := taps.dials.Load()
		res := e2eDialAsync(context.Background(), p, DialOptions{})
		actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
		pend, err := ln2.Accept(actx)
		acancel()
		if err != nil {
			r := <-res
			t.Fatalf("no session reached the other Listener (%v); the Dial: %v", err, r.err)
		}
		q3, err := pend.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-res
		if r.err != nil {
			t.Fatal(r.err)
		}
		s3 := r.c
		if n := taps.dials.Load() - before; n != 1 {
			t.Fatalf("%d factory calls for the Dial after Listener.Close, want 1", n)
		}
		if c := mxCarrier(t, s3, "a"); c.ID == trunk {
			t.Fatal("the new session opened on the closed Listener's trunk")
		}
		if p.goneAway(pr.InstanceID()) {
			t.Fatal("Listener.Close put the running instance in the Peer's gone-away set")
		}
		var lc int
		for _, r := range mxFrames(taps.tap(t, 0), rendrtest.Down, rendrtest.FrameOpenAck, 2) {
			_ = r
			lc++
		}
		if lc != 1 {
			t.Fatalf("%d OPEN_ACKs for handle 2 on the closed Listener's trunk, want the one refusal", lc)
		}
		est, st, _, err := mxInjectTo(context.Background(), p, 0, wire.TypeJoin, wpJoin(s3.ID(), 1, 0), pr.InstanceID())
		if err != nil || st != wire.StatusOK || CarrierID(est.Conn.ID()) != trunk {
			t.Fatalf("a JOIN on the closed Listener's trunk: %v, %v on carrier %v; want OK on %d", st, err, est, trunk)
		}
		mxDrop(est)
		e2eExchange(t, s1, q1, 64<<10, 1)
		e2eExchange(t, s3, q3, 64<<10, 2)
		e2eFinish(t, s1, q1)
		e2eFinish(t, s3, q3)
		e.close()
	})
}

// TestMuxOneViewPerSession (E5, M3-D23, R1-6): a second view of one session
// on one trunk (injected: the pool would not place it) is refused —
// JOIN_ACK BAD_REQUEST, a duplicate OPEN OPEN_ACK BAD_REQUEST
// CodeDuplicateView — and the session's first view stays live and
// delivers.
func TestMuxOneViewPerSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		p := e.peer()
		s, q := e2eOpen(t, p, e.ln, DialOptions{})
		_, st, _, err := mxInject(context.Background(), p, 0, wire.TypeJoin, wpJoin(s.ID(), 1, 0))
		if err != nil || st != wire.StatusBadRequest {
			t.Fatalf("a second view by JOIN: %v, %v; want BAD_REQUEST", st, err)
		}
		_, st, code, err := mxInject(context.Background(), p, 0, wire.TypeOpen, wpOpen(s.ID(), wire.KindStream, 1, nil))
		if err != nil || st != wire.StatusBadRequest || code != wire.CodeDuplicateView {
			t.Fatalf("a second view by OPEN: %v code %d, %v; want BAD_REQUEST CodeDuplicateView", st, code, err)
		}
		if c := mxCarrier(t, s, "a"); c.State == CarrierDead {
			t.Fatal("the first view died")
		}
		// The pool's own rule (M3-D17, R1-6): an attempt of the session
		// itself never goes to a trunk on which it holds a view — it dials
		// a carrier of its own instead, where its JOIN is admitted.
		trunk := mxCarrier(t, s, "a").ID
		est, err := p.pool.Attempt(context.Background(), 0, p.rt.cenv.IDs.Next(), wire.TypeJoin, wpJoin(s.ID(), 1, 0), nil,
			e.p.InstanceID(), uintptr(unsafe.Pointer(s.s)), wire.TypeData)
		if err != nil {
			t.Fatal(err)
		}
		if ja, _ := wire.ParseJoinAck(est.Payload); CarrierID(est.Conn.ID()) == trunk || ja.Status != wire.StatusOK {
			t.Fatalf("the session's own JOIN went to carrier %d (its view's trunk %d), answered %d", est.Conn.ID(), trunk, ja.Status)
		}
		mxDrop(est)
		e2eExchange(t, s, q, 128<<10, 4)
		if st := s.Status(); st.Migrations != (MigrationCounts{}) {
			t.Fatalf("migrations %+v", st.Migrations)
		}
		e2eFinish(t, s, q)
		e.close()
	})
}

// TestMuxJoinInstanceMismatch (E8): a JOIN on a trunk of an instance that
// does not know its session (injected: the pool places a JOIN only on a
// trunk of the session's bound instance) is answered UNKNOWN_SESSION on its
// handle, and the trunk lives.
func TestMuxJoinInstanceMismatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		p := e.peer()
		s, q := e2eOpen(t, p, e.ln, DialOptions{})
		p2 := wpTestRuntime(t, Config{}, nil)
		ln2 := wpListen(t, p2, ListenConfig{})
		l2 := rendrtest.NewLink(rendrtest.LinkConfig{Name: "b", Accept: ln2.Handle})
		t.Cleanup(l2.Close)
		x, y := e2eOpen(t, e.mxPeer(e2eCarrier(l2)), ln2, DialOptions{}) // bound to another instance
		_, st, _, err := mxInject(context.Background(), p, 0, wire.TypeJoin, wpJoin(x.ID(), 1, 0))
		if err != nil || st != wire.StatusUnknownSession {
			t.Fatalf("a JOIN of another instance's session: %v, %v; want UNKNOWN_SESSION", st, err)
		}
		if c := mxCarrier(t, s, "a"); c.State == CarrierDead {
			t.Fatal("the trunk died")
		}
		e2eExchange(t, s, q, 64<<10, 1)
		e2eFinish(t, s, q)
		e2eFinish(t, x, y)
		p2.Close()
		e.close()
		wpNoState(t, p2)
	})
}

// TestMuxCancelCrossesConfirm_L49 (E6, R1-5; L49): a Dial withdrawn while
// its OPEN view waits on a live trunk — before the passive's Confirm, and
// with the passive's OPEN_ACK(OK) crossing the withdrawal — ends the
// passive's session within 1 s of the withdrawal (the view's
// RST(AbortWithdrawn) precedes its DETACH; with DETACH alone the session
// would stay pending until AcceptTimeout), and Confirm afterwards reports
// the session lost.
func TestMuxCancelCrossesConfirm_L49(t *testing.T) {
	for _, confirmFirst := range []bool{false, true} {
		name := "withdraw, then Confirm"
		if confirmFirst {
			name = "Confirm, then withdraw"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
				var taps mxTaps
				defer taps.close()
				p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
				s, q := e2eOpen(t, p, e.ln, DialOptions{})
				ctx, cancel := context.WithCancel(context.Background())
				res := e2eDialAsync(ctx, p, DialOptions{})
				pend, err := e.ln.Accept(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				var sc *Conn
				if confirmFirst {
					taps.tap(t, 0).Hold(rendrtest.Down) // the OPEN_ACK(OK) crosses the withdrawal
					if sc, err = pend.Confirm(); err != nil {
						t.Fatal(err)
					}
				}
				withdrawn := time.Now()
				cancel()
				if r := <-res; !errors.Is(r.err, context.Canceled) {
					t.Fatalf("withdrawn Dial: %v", r.err)
				}
				if confirmFirst {
					taps.tap(t, 0).Release(rendrtest.Down)
					e2eDone(t, sc, time.Second)
				} else {
					time.Sleep(10 * time.Millisecond)
					if c, err := pend.Confirm(); c != nil || !errors.Is(err, ErrSessionLost) {
						t.Fatalf("Confirm after the withdrawal: %v, %v; want ErrSessionLost", c, err)
					}
				}
				if el := time.Since(withdrawn); el > time.Second {
					t.Fatalf("the passive session ended %v after the withdrawal", el)
				}
				e2eExchange(t, s, q, 64<<10, 9)
				e2eFinish(t, s, q)
				e.close()
			})
		})
	}
}

// TestMuxOpenLostWithTrunk_L47 (E4; L47): the trunk dies after a session's
// OPEN was placed on it and before its verdict: that attempt fails as in M1,
// the session's retried OPEN on the other factory takes the passive's
// duplicate-OPEN path, and exactly one session exists, opens and delivers.
func TestMuxOpenLostWithTrunk_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		e.links[0].SetDelay(time.Millisecond, 0) // a ranks first
		e.links[1].SetDelay(5*time.Millisecond, 0)
		p := e.peer()
		n, m := e2eOpen(t, p, e.ln, DialOptions{}) // the neighbour keeps trunk a
		if mxCarrier(t, n, "").Name != "a" {
			t.Fatalf("the neighbour opened on %+v, want a", n.Status().Carriers)
		}
		res := e2eDialAsync(context.Background(), p, DialOptions{})
		pend, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		e.links[0].Kill() // the trunk with the pending OPEN dies
		time.Sleep(2 * time.Second)
		x, err := pend.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-res
		if r.err != nil {
			t.Fatal(r.err)
		}
		if ps := e.p.Status(); ps.Sessions.Open != 2 {
			t.Fatalf("passive %+v, want the neighbour and one new session", ps.Sessions)
		}
		e2eExchange(t, r.c, x, 128<<10, 5)
		e2eExchange(t, n, m, 64<<10, 6)
		e2eFinish(t, r.c, x)
		e2eFinish(t, n, m)
		e.close()
	})
}

// TestHeldViewSessionEnd (R1-9): a view JOINed on a started trunk is still
// held — its JOIN_ACK(OK) placed, the dialer's go frame not arrived —
// when its passive session reaches IdleTimeout: the passive places nothing
// for that handle but its DETACH(ended): the frame tap shows the JOIN_ACK
// and no other frame of the handle (no RST), and one more DETACH.
func TestHeldViewSessionEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := &testhooks.Overrides{IdleTimeout: time.Second, DeadMin: time.Minute, DeadMax: time.Minute, WriteStall: time.Minute}
		e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a", "b")
		e.links[0].SetDelay(time.Millisecond, 0) // a ranks first: the bonds OPEN on a, JOIN on b
		e.links[1].SetDelay(5*time.Millisecond, 0)
		var ta, tb mxTaps
		defer ta.close()
		defer tb.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &ta), mxTapCarrier(e.links[1], &tb))
		k, kq := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond}) // trunks A and B
		mxWait(t, time.Second, "the first bond's members", func() bool { return mxMembers(k) == 2 })
		var trunkB *rendrtest.Tamper
		for i := range tb.count() {
			if len(mxFrames(tb.tap(t, i), rendrtest.Up, rendrtest.FrameJoin, 0))+len(mxFrames(tb.tap(t, i), rendrtest.Up, rendrtest.FrameOpen, 0)) > 0 {
				trunkB = tb.tap(t, i)
			}
		}
		trunkB.Hold(rendrtest.Down) // the JOIN_ACK of the next view on B does not reach the dialer
		detBefore := 0
		res := e2eDialAsync(context.Background(), p, DialOptions{Mode: ModeBond})
		pend, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		sc, err := pend.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-res
		if r.err != nil {
			t.Fatal(r.err)
		}
		var h uint32
		mxWait(t, 2*time.Second, "the second bond's JOIN on trunk B", func() bool {
			for _, rec := range mxFrames(trunkB, rendrtest.Up, rendrtest.FrameJoin, 0) {
				if rec.Handle > 1 {
					h = rec.Handle
				}
			}
			return h != 0
		})
		synctest.Wait()
		_ = detBefore
		e2eDone(t, sc, 3*time.Second) // IdleTimeout
		synctest.Wait()
		trunkB.Release(rendrtest.Down)
		synctest.Wait()
		var types []rendrtest.FrameType
		for _, rec := range trunkB.Log(rendrtest.Down) {
			if rec.Handle == h {
				types = append(types, rec.Type)
			}
		}
		if len(types) != 1 || types[0] != rendrtest.FrameJoinAck {
			t.Fatalf("passive frames for the held handle %d: %v, want the JOIN_ACK only", h, types)
		}
		if n := len(mxFrames(trunkB, rendrtest.Down, rendrtest.FrameDetach, 0)) - detBefore; n < 1 {
			t.Fatal("no DETACH from the passive for the held view")
		}
		r.c.Close()
		k.Close()
		kq.Close()
		e.close()
	})
}

// TestAdmitWhileWaking (R1-17): JOINs of a session admitted on a trunk —
// Env.Admit reaches Session.Join (Session.mu) on the trunk's reader —
// while that session's producers wake its views (Session.mu → trunk.mx)
// in both directions: 1000 JOINs (refused: the session already holds a
// view there) with no deadlock, every JOIN answered, and every byte of the
// streams placed and delivered intact.
func TestAdmitWhileWaking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		p := e.peer()
		s, q := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		mxWait(t, time.Second, "both members", func() bool { return mxMembers(s) == 2 })
		done := make(chan error, 1)
		go func() { done <- e2eExchangeErr(s, q, 8<<20, 21) }()
		for i := range 1000 {
			_, st, _, err := mxInject(context.Background(), p, i%2, wire.TypeJoin, wpJoin(s.ID(), 2, 0))
			if err != nil || st != wire.StatusBadRequest {
				t.Fatalf("JOIN %d: %v, %v; want BAD_REQUEST (a second view)", i, st, err)
			}
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		e2eFinish(t, s, q)
		e.close()
	})
}

// mxMembers counts c's live bond members.
func mxMembers(c *Conn) int {
	n := 0
	for _, cs := range c.Status().Carriers {
		if cs.State == CarrierMember {
			n++
		}
	}
	return n
}
