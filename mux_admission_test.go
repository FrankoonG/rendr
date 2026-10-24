package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Passive admission on live trunks (M3-D21 … M3-D23, R1-4, R1-6, R1-10).
// A test drives a Peer's pool directly where it needs a dialer that breaks
// its own rules — a second view of one session on a trunk, a JOIN that the
// usable rule would not place, more OPENs at once than any session would
// make (mxInject: a fresh session key per call, no check).

// mxSessKey is a session key no session has (the pool's one-view rule): a
// session's key is its address (a Go heap object), and the keys handed
// out count up from 1 MiB below the top of the address space: above any Go
// heap address on the supported targets, and within a 32-bit uintptr. The
// row only needs a key no live session has.
var mxSessKey atomic.Uintptr

func init() { mxSessKey.Store(^uintptr(0) - 1<<20) }

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

// TestMuxJoinAtPassiveViewCap_L48 (M3-D12, §A5.8, R1-4; WP16 W3): a JOIN
// that reaches a trunk at the passive's view cap is answered JOIN_ACK
// CAPACITY CodeMuxFull — the code rides the MUX JOIN_ACK — so the dialer's
// pool takes it like an OPEN's: the trunk is marked full and the attempt
// continues on a new carrier of the factory without a penalty. The passive
// holds at most four views per trunk, the dialer its default.
//
//   - injected JOIN: a trunk filled to four views gets a JOIN of a live
//     session; the attempt is answered OK on a second carrier within one
//     DialTimeout.
//   - bond: the trunks of both factories are filled to four views; a bond
//     session opens (its OPEN is refused CodeMuxFull on one full trunk) and
//     needs its second member through a JOIN on the other full trunk; both
//     members attach within one DialTimeout of the Dial.
func TestMuxJoinAtPassiveViewCap_L48(t *testing.T) {
	const dialTimeout = 10 * time.Second // Config.DialTimeout's default
	pair := func(t *testing.T, names ...string) (*e2ePair, []*mxTaps) {
		e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, nil), p: wpTestRuntime(t, Config{}, &testhooks.Overrides{MuxMaxViews: 4})}
		e.ln = wpListen(t, e.p, ListenConfig{AcceptBacklog: 64})
		var taps []*mxTaps
		for _, n := range names {
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: n, Accept: e.ln.Handle})
			t.Cleanup(l.Close)
			e.links = append(e.links, l)
			tp := &mxTaps{}
			t.Cleanup(tp.close)
			taps = append(taps, tp)
		}
		return e, taps
	}
	t.Run("injected JOIN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e, taps := pair(t, "a", "b")
			p := e.mxPeer(mxTapCarrier(e.links[0], taps[0]))
			pb := e.mxPeer(e2eCarrier(e.links[1]))
			s1, q1 := e2eOpen(t, p, e.ln, DialOptions{})
			s2, q2 := e2eOpen(t, pb, e.ln, DialOptions{}) // the session that JOINs, on another Peer's carrier
			acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
			for i := range 3 { // views 2, 3 and 4 of the trunk: the passive's cap
				_, st, code, err := mxInject(context.Background(), p, 0, wire.TypeOpen, wpOpen(wpSID(300+i), wire.KindStream, 1, nil))
				if err != nil || st != wire.StatusOK {
					t.Fatalf("filling OPEN %d: %v code %d, %v", i, st, code, err)
				}
			}
			if d := taps[0].dials.Load(); d != 1 {
				t.Fatalf("%d factory calls while filling, want the one trunk", d)
			}
			start := time.Now()
			est, st, _, err := mxInject(context.Background(), p, 0, wire.TypeJoin, wpJoin(s2.ID(), 1, 0))
			if err != nil || st != wire.StatusOK {
				t.Fatalf("JOIN at the passive's view cap: %v, %v; want OK on another carrier", st, err)
			}
			if el := time.Since(start); el > dialTimeout {
				t.Fatalf("the JOIN took %v, more than one DialTimeout", el)
			}
			if d, ms := taps[0].dials.Load(), p.pool.Stats().MuxFull; d != 2 || ms != 1 {
				t.Fatalf("%d factory calls, pool MuxFull %d; want the full trunk marked and one new carrier", d, ms)
			}
			if pm := e.p.Status().Mux.MuxFull; pm != 1 {
				t.Fatalf("passive MuxFull %d, want 1", pm)
			}
			mxDrop(est)
			acc.stop()
			for _, c := range append(acc.conns, s1, q1, s2, q2) {
				c.Close()
			}
			e.close()
		})
	})
	t.Run("bond", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e, taps := pair(t, "a", "b")
			p := e.mxPeer(mxTapCarrier(e.links[0], taps[0]), mxTapCarrier(e.links[1], taps[1]))
			s0, q0 := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
			mxWait(t, dialTimeout, "the first bond's members", func() bool { return mxMembers(s0) == 2 })
			acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
			for f := range 2 {
				for i := range 3 {
					_, st, code, err := mxInject(context.Background(), p, f, wire.TypeOpen, wpOpen(wpSID(400+10*f+i), wire.KindStream, 1, nil))
					if err != nil || st != wire.StatusOK {
						t.Fatalf("filling OPEN %d on factory %d: %v code %d, %v", i, f, st, code, err)
					}
				}
			}
			for _, tr := range mxTrunkSet(e.p) {
				if n := tr.Views(); n != 4 {
					t.Fatalf("a passive trunk holds %d views, want its cap 4", n)
				}
			}
			start := time.Now()
			ch := e2eDialAsync(context.Background(), p, DialOptions{Mode: ModeBond})
			r := <-ch
			if r.err != nil {
				t.Fatalf("Dial: %v", r.err)
			}
			s := r.c
			mxWait(t, dialTimeout, "the second member through a JOIN", func() bool { return mxMembers(s) == 2 })
			if el := time.Since(start); el > dialTimeout {
				t.Fatalf("the members attached after %v, more than one DialTimeout", el)
			}
			if ms := p.pool.Stats().MuxFull; ms < 2 {
				t.Fatalf("pool MuxFull %d, want the OPEN's and the JOIN's", ms)
			}
			acc.stop()
			for _, c := range append(acc.conns, s, s0, q0) {
				c.Close()
			}
			e.close()
		})
	})
}

// TestMuxCloseLeavesNoPoolTrunk_L52 (L52, C24, invariant 4; M3 design
// §A4.6: MUX trunks close after their last view or at the M1 close bound;
// m6 rc6): Runtime.Close leaves no dialer MUX trunk behind. Close posts
// nothing to a pool trunk itself: the trunk drains as its views end —
// through their sessions' Shutdown (RST, GOAWAY, DETACH), the passive's
// DETACH or the trunk's death — and the pool closes it at its last view.
// So a pool trunk whose CLOSE is still unwritten at the close bound,
// min(1 s, DeadMax) — its views held by no session of the closing Runtime,
// or its writer stuck in the embedder's Write — is killed then, as the
// passive's trunks are, and joined. On 33de081 Close's pool join gave up at
// its bound and Close returned with the trunk running (race-unit gate run
// 1, TestMuxJoinAtPassiveViewCap_L48/bond: its two sessions had finished
// before Close's Shutdown reached them, so no GOAWAY crossed, and the views
// the row injected kept both full trunks).
//
// The bond scenario at the passive's view cap of
// TestMuxJoinAtPassiveViewCap_L48: two factories, the passive holds four
// views per trunk; a bond session opens trunks A and B; three injected
// OPENs per trunk fill them (mxInject: views no session holds, which the
// passive confirms); the session finishes cleanly and a fourth injected
// OPEN per trunk refills each to the cap. A bond Dial then has its OPEN
// refused CodeMuxFull on one full trunk and its JOIN on the other, each
// followed by a dial of a new trunk, and the dialer's Runtime closes at
// each phase:
//
//   - OPEN refusal in flight: queued at the passive, held in the tampers;
//   - OPEN redial: the factory call after the OPEN's refusal, held until
//     its context ends;
//   - JOIN refusal in flight: queued at the passive, held in the tampers;
//   - JOIN redial: the factory call after the JOIN's refusal, held;
//   - members attached: both members on their new trunks;
//   - sessions ended: the bond session finished cleanly before Close (the
//     gate's interleaving).
//
// Rows "stuck writer", without injected views: a selector session's trunk
// whose writer is stuck in the embedder's Write (its tamper stopped
// reading; WriteStall and both ends' death deadline beyond Close's bound),
// with the session open at Close, and with the session ended before Close
// (Linger 1 s): the pool retired the trunk at its last view, and its CLOSE
// is stuck behind that Write.
//
// After Close returns, within its bound: the dialer's Status.Mux.Carriers
// and Views are 0, BufferedBytes 0, Abandoned 0, no session or
// reservation, and its pool is joined; once the passive and the links
// closed, no rendr goroutine is left and rendr closed every dialer conn
// exactly once.
func TestMuxCloseLeavesNoPoolTrunk_L52(t *testing.T) {
	const dialTimeout = 10 * time.Second
	type phase int
	const (
		openInFlight phase = iota
		openRedial
		joinInFlight
		joinRedial
		attached
		ended
	)
	for _, ph := range []struct {
		name string
		at   phase
	}{
		{"OPEN refusal in flight", openInFlight},
		{"OPEN redial", openRedial},
		{"JOIN refusal in flight", joinInFlight},
		{"JOIN redial", joinRedial},
		{"members attached", attached},
		{"sessions ended", ended},
	} {
		t.Run(ph.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				k := newPCKit(t, testhooks.Overrides{}, testhooks.Overrides{}, "a", "b")
				pool := k.peer.pool
				s0, q0 := e2eOpen(t, k.peer, k.ln, DialOptions{Mode: ModeBond})
				mxWait(t, dialTimeout, "the first bond's members", func() bool { return mxMembers(s0) == 2 })
				acc := newAcceptLog(k.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
				sid := 600
				inject := func(f int) {
					t.Helper()
					_, st, code, err := mxInject(context.Background(), k.peer, f, wire.TypeOpen, wpOpen(wpSID(sid), wire.KindStream, 1, nil))
					sid++
					if err != nil || st != wire.StatusOK {
						t.Fatalf("injected OPEN on factory %d: %v code %d, %v", f, st, code, err)
					}
				}
				for f := range 2 {
					for range 3 {
						inject(f)
					}
				}
				e2eFinish(t, s0, q0) // its views leave A and B
				for f := range 2 {
					inject(f)
				}
				for _, tr := range mxTrunkSet(k.p) {
					if n := tr.Views(); n != 4 {
						t.Fatalf("a passive trunk holds %d views, want its cap 4", n)
					}
				}
				if st := k.d.Status().Mux; st.Carriers != 2 || st.Views != 8 {
					t.Fatalf("premise: dialer MUX %+v, want trunks A and B with four injected views each", st)
				}

				var once atomic.Bool
				switch ph.at {
				case openInFlight: // the bond's OPEN on a full trunk: its answer stays in the tampers
					k.onView(func() {
						if once.CompareAndSwap(false, true) {
							k.holdDown()
						}
					})
				case joinInFlight: // the OPEN, then the JOIN on the other full trunk
					var views atomic.Int32
					k.onView(func() {
						if views.Add(1) == 2 {
							k.holdDown()
						}
					})
				case openRedial, joinRedial:
					mf := uint64(1)
					if ph.at == joinRedial {
						mf = 2
					}
					k.holdDial(func(int) bool { return pool.Stats().MuxFull == mf && once.CompareAndSwap(false, true) })
				}
				ch := e2eDialAsync(context.Background(), k.peer, DialOptions{Mode: ModeBond})
				var s *Conn
				switch ph.at {
				case openInFlight, joinInFlight:
					want := uint64(1)
					if ph.at == joinInFlight {
						want = 2
					}
					mxWait(t, dialTimeout, "the refusal queued at the passive", func() bool { return k.p.Status().Mux.MuxFull == want })
					if n := pool.Stats().MuxFull; n != want-1 {
						t.Fatalf("premise: the dialer's pool got %d CodeMuxFull answers, want %d (the last one held)", n, want-1)
					}
				case openRedial, joinRedial:
					select {
					case <-k.held:
					case <-time.After(dialTimeout):
						t.Fatalf("no factory call after the refusal within %v", dialTimeout)
					}
				default:
					r := <-ch
					if r.err != nil {
						t.Fatalf("Dial: %v", r.err)
					}
					s = r.c
					mxWait(t, dialTimeout, "the second member through a JOIN", func() bool { return mxMembers(s) == 2 })
					if ms := pool.Stats().MuxFull; ms < 2 {
						t.Fatalf("pool MuxFull %d, want the OPEN's and the JOIN's", ms)
					}
					if ph.at == ended {
						var q *Conn
						mxWait(t, dialTimeout, "the bond's passive end", func() bool {
							acc.mu.Lock()
							defer acc.mu.Unlock()
							for _, c := range acc.conns {
								if c.ID() == s.ID() {
									q = c
								}
							}
							return q != nil
						})
						e2eFinish(t, s, q)
					}
				}
				k.closeDialer(t)
				if s == nil {
					s = (<-ch).c // the JOIN rows: the Dial returned with its first member
				}
				if s != nil {
					s.Close()
				}
				k.finish(t, acc)
			})
		})
	}
	for _, ended := range []bool{false, true} {
		name := "stuck writer"
		if ended {
			name = "stuck writer, session ended"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// The write stall bound (WriteStall, up to 30 s) and both
				// ends' death deadline beyond Close's bound: neither the
				// trunk's watchdog nor a death ends it during Close.
				slow := testhooks.Overrides{WriteStall: 10 * time.Second, DeadMin: 10 * time.Second, DeadMax: 10 * time.Second}
				dov := slow
				dov.Linger = time.Second
				k := newPCKit(t, dov, slow, "a")
				dc, pc := e2eOpen(t, k.peer, k.ln, DialOptions{})
				e2eExchange(t, dc, pc, 64<<10, 1)
				tp := k.taps[0].tap(t, 0)
				tp.Hold(rendrtest.Up) // the tamper stops reading the dialer's conn: the next Write blocks
				if _, err := dc.Write(make([]byte, 256<<10)); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if n := tp.Stats().Held; n == 0 {
					t.Fatal("stimulus: the tamper held no write of the dialer")
				}
				if ended {
					// Its FIN unplaced, the session ends at Linger and kills
					// its view at its close bound; the pool then retires the
					// trunk, whose CLOSE waits behind the stuck Write.
					dc.Close()
					e2eDone(t, dc, 5*time.Second)
					synctest.Wait() // the pool's view hook ran
					if st := k.d.Status().Mux; st.Carriers != 0 || st.Views != 0 {
						t.Fatalf("premise: dialer MUX %+v, want the trunk retired at its last view", st)
					}
					if st := k.d.Status(); st.BufferedBytes == 0 {
						t.Fatal("premise: nothing charged, want the retired trunk's reader stage")
					}
				}
				k.closeDialer(t)
				pc.Close()
				k.finish(t, nil)
			})
		})
	}
}

// pcKit is the scenario kit of TestMuxCloseLeavesNoPoolTrunk_L52: the e2e
// pair (the passive holds four views per trunk), one dialer Peer over a
// tapped factory per name whose conns are counted (pcConn), a held factory
// call and a hook at every view a dial attempt opens on a live trunk.
type pcKit struct {
	*e2ePair
	taps []*mxTaps
	peer *Peer
	view atomic.Pointer[func()]         // Hooks.BeforeOpenView
	hold atomic.Pointer[func(int) bool] // whether a factory call (of factory f) is held until its context ends
	held chan int                       // the factory of the held call

	mu    sync.Mutex
	conns []*pcConn
}

// pcConn counts the Close calls of a dialer conn.
type pcConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *pcConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// newPCKit builds the kit with the dialer's overrides dov and the
// passive's pov (each with its own hooks; the passive holds four views per
// trunk).
func newPCKit(t *testing.T, dov, pov testhooks.Overrides, names ...string) *pcKit {
	t.Helper()
	k := &pcKit{held: make(chan int, 1)}
	dov.Hooks = &testhooks.Hooks{BeforeOpenView: func(uint32, uint32) {
		if f := k.view.Load(); f != nil {
			(*f)()
		}
	}}
	pov.MuxMaxViews = 4
	k.e2ePair = &e2ePair{t: t, d: wpTestRuntime(t, Config{}, &dov), p: wpTestRuntime(t, Config{}, &pov)}
	k.ln = wpListen(t, k.p, ListenConfig{AcceptBacklog: 64})
	cs := make([]Carrier, len(names))
	for i, n := range names {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: n, Accept: k.ln.Handle})
		t.Cleanup(l.Close)
		k.links = append(k.links, l)
		tp := &mxTaps{}
		t.Cleanup(tp.close)
		k.taps = append(k.taps, tp)
		cs[i] = k.factory(i, l, tp)
	}
	k.peer = k.mxPeer(cs...)
	return k
}

// factory is mxTapCarrier's factory over l with each conn counted and a
// call that hold selects held until its context ends.
func (k *pcKit) factory(f int, l *rendrtest.Link, taps *mxTaps) StreamCarrier {
	sc := mxTapCarrier(l, taps)
	dial := sc.Dial
	sc.Dial = func(ctx context.Context) (net.Conn, error) {
		if h := k.hold.Load(); h != nil && (*h)(f) {
			k.held <- f
			<-ctx.Done()
			return nil, context.Cause(ctx)
		}
		c, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		pc := &pcConn{Conn: c}
		k.mu.Lock()
		k.conns = append(k.conns, pc)
		k.mu.Unlock()
		return pc, nil
	}
	return sc
}

func (k *pcKit) onView(f func())           { k.view.Store(&f) }
func (k *pcKit) holdDial(f func(int) bool) { k.hold.Store(&f) }

// holdDown stops every tamper so far in the passive-to-dialer direction.
func (k *pcKit) holdDown() {
	for _, m := range k.taps {
		m.mu.Lock()
		for _, tp := range m.tps {
			tp.Hold(rendrtest.Down)
		}
		m.mu.Unlock()
	}
}

// closeDialer closes the dialer's Runtime and requires that it left
// nothing: Close within its bound, no MUX trunk or view, no byte charged,
// nothing abandoned, no session or reservation, and its pool joined.
func (k *pcKit) closeDialer(t *testing.T) {
	t.Helper()
	eff := k.d.eff
	bound := max(min(time.Second, eff.cfg.DeadMax)+eff.timing.AbandonWait, 2*eff.timing.AbandonWait) + closeSlack
	start := time.Now()
	k.d.Close()
	if el := time.Since(start); el > bound {
		t.Errorf("Runtime.Close took %v, bound %v", el, bound)
	}
	if st := k.d.Status(); st.Mux.Carriers != 0 || st.Mux.Views != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 {
		t.Fatalf("after Runtime.Close the dialer still has %d MUX carriers with %d views, %d bytes charged, %d abandoned",
			st.Mux.Carriers, st.Mux.Views, st.BufferedBytes, st.Abandoned)
	}
	wpNoState(t, k.d)
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if err := k.peer.pool.Wait(done); err != nil {
		t.Fatalf("the pool still counts a trunk after Runtime.Close: %v", err)
	}
}

// finish ends the passive side and requires no rendr goroutine left and
// every dialer conn closed exactly once.
func (k *pcKit) finish(t *testing.T, acc *acceptLog) {
	t.Helper()
	for _, m := range k.taps {
		m.mu.Lock()
		for _, tp := range m.tps {
			tp.Release(rendrtest.Up)
			tp.Release(rendrtest.Down)
		}
		m.mu.Unlock()
	}
	if acc != nil {
		acc.stop()
		for _, c := range acc.conns {
			c.Close()
		}
	}
	k.p.Close()
	for _, l := range k.links {
		l.Close()
	}
	for _, m := range k.taps {
		m.close()
	}
	wpNoState(t, k.p)
	if n := k.p.Status().Abandoned; n != 0 {
		t.Fatalf("the passive abandoned %d goroutines", n)
	}
	synctest.Wait()
	if n, left := rendrGoroutines(); n != 0 {
		t.Fatalf("rendr goroutines after both Close calls: %v", left)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, c := range k.conns {
		if n := c.closes.Load(); n != 1 {
			t.Fatalf("dialer conn %d (of %d) closed %d times", i, len(k.conns), n)
		}
	}
}

// TestMuxWithdrawAtAsyncAttach_R1_5 (R1-5, §A3.3; WP16 W1): a Dial whose
// opening race placed its second OPEN as a view on another live trunk —
// which the passive admits through AttachOpen, attached only when the
// session's actor adopts it — is cancelled while that actor is held before
// the adopt. The dialer withdraws both OPENs (RST(AbortWithdrawn), then
// DETACH): no shared trunk dies (no protocol_violation), the bond session
// that shares them keeps its members and moves data, and the withdrawn
// session leaves no pending session once its actor runs.
//
// Row "only lane": the first OPEN's carrier dies (refused for good) before
// the cancel, so the second OPEN's view is the pending session's only lane
// and the RST recorded before the attach is the only withdrawal it can
// get: it must reach the session at its adopt, which then ends within 1 s
// (L49's server-side bound) — not at AcceptTimeout (R1-5 rule 3).
func TestMuxWithdrawAtAsyncAttach_R1_5(t *testing.T) {
	for _, onlyLane := range []bool{false, true} {
		name := "first lane alive"
		if onlyLane {
			name = "only lane"
		}
		t.Run(name, func(t *testing.T) { testMuxWithdrawAtAsyncAttach(t, onlyLane) })
	}
}

func testMuxWithdrawAtAsyncAttach(t *testing.T, onlyLane bool) {
	synctest.Test(t, func(t *testing.T) {
		var (
			mu    sync.Mutex
			known = map[SessionID]bool{}
			hold  = make(chan struct{})
			held  bool
			// blocked closes when the dialled session's actor is held: its
			// linger (1 s) ran out and it tried to park; the second OPEN
			// comes at JoinStagger (3 s).
			blocked = make(chan struct{})
			once    sync.Once
			relOnce sync.Once
		)
		release := func() {
			mu.Lock()
			held = false
			mu.Unlock()
			relOnce.Do(func() { close(hold) })
		}
		defer release() // a failed assertion leaves no actor held
		hk := &testhooks.Hooks{AtPark: func(sid [16]byte) {
			mu.Lock()
			block := !known[SessionID(sid)] && held
			mu.Unlock()
			if block {
				once.Do(func() { close(blocked) })
				<-hold // the withdrawn session's actor: the adopt waits
			}
		}}
		e := &e2ePair{t: t, d: wpTestRuntime(t, Config{JoinStagger: 3 * time.Second}, nil), p: wpTestRuntime(t, Config{}, &testhooks.Overrides{Hooks: hk})}
		e.ln = wpListen(t, e.p, ListenConfig{})
		var taps [2]mxTaps
		for i, n := range []string{"a", "b"} {
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: n, Accept: e.ln.Handle})
			t.Cleanup(l.Close)
			e.links = append(e.links, l)
			t.Cleanup(taps[i].close)
		}
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps[0]), mxTapCarrier(e.links[1], &taps[1]))
		// A bond session puts a live trunk on each factory.
		s0, q0 := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 10*time.Second, "the bond's members", func() bool { return mxMembers(s0) == 2 })
		trunks := mxTrunkSet(e.p)
		if len(trunks) != 2 {
			t.Fatalf("%d passive trunks, want 2", len(trunks))
		}
		mu.Lock()
		known[s0.ID()] = true
		held = true
		mu.Unlock()
		// The OPENs for handle 2 a factory's carriers placed (probe carriers
		// place none).
		opens := func(i int) int {
			n := 0
			for k := range taps[i].count() {
				n += len(mxFrames(taps[i].tap(t, k), rendrtest.Up, rendrtest.FrameOpen, 2))
			}
			return n
		}
		ctx, cancel := context.WithCancel(context.Background())
		ch := e2eDialAsync(ctx, p, DialOptions{}) // Accept stalled: no answer
		mxWait(t, 10*time.Second, "the second OPEN on the other trunk", func() bool { return opens(0) == 1 && opens(1) == 1 })
		synctest.Wait() // admitted: the adopt is posted to the held actor
		select {
		case <-blocked:
		default:
			t.Fatal("the dialled session's actor was not held when its second OPEN came")
		}
		if ps := e.p.Status(); ps.Sessions.Pending != 1 {
			t.Fatalf("passive %+v, want the dialled session pending", ps.Sessions)
		}
		want := 2 // the passive trunks that must live
		if onlyLane {
			// The first OPEN's carrier (and the bond's member on it) dies
			// and stays down: the second OPEN's view is the pending
			// session's only lane.
			e.links[0].SetRefuse(true)
			e.links[0].Kill()
			mxWait(t, 10*time.Second, "trunk a gone", func() bool { return len(mxTrunkSet(e.p)) == 1 })
			trunks = mxTrunkSet(e.p)
			want = 1
			synctest.Wait()
			if ps := e.p.Status(); ps.Sessions.Pending != 1 {
				t.Fatalf("passive %+v, want the dialled session pending (it survives its lanes)", ps.Sessions)
			}
		}
		cancel()
		if r := <-ch; r.err == nil {
			t.Fatal("the cancelled Dial returned a session")
		}
		time.Sleep(time.Second) // the withdrawal's RSTs and DETACHes cross
		synctest.Wait()
		alive := func(what string) {
			t.Helper()
			for _, tr := range trunks {
				if dead, cause, detail, _ := tr.Death(); dead || tr.TrunkDying() {
					t.Fatalf("%s: a shared trunk died: %v %s", what, cause, detail)
				}
			}
			if n := len(mxTrunkSet(e.p)); n != want {
				t.Fatalf("%s: %d passive trunks, want %d", what, n, want)
			}
		}
		alive("after the withdrawal")
		release()
		synctest.Wait()
		mxWait(t, time.Second, "the withdrawn session gone", func() bool { return e.p.Status().Sessions.Pending == 0 })
		alive("after the adopt")
		if n := mxMembers(s0); n != want {
			t.Fatalf("the bond holds %d members, want %d", n, want)
		}
		e2eExchange(t, s0, q0, 64<<10, 5)
		e2eFinish(t, s0, q0)
		e.close()
	})
}

// TestMuxViewDeadBeforeStartReachesSession_R2_12 (M3 design R2-12,
// §A5.7 item 6, §A10.3; DGDOWN): a MUX trunk's death that catches a
// session's view attached-pending — the OPEN answered OK, the attach
// checked the view alive, the session has not started it — reaches that
// session when it starts the view after the death. Every Start of a
// carrier runs inside an actor step (attachLocked under handleLocked), and
// the reapDead of that same step reads the view's Death, which reports the
// trunk's death record whether or not the view is attached yet; the death
// step records the carrier's end like any other (one EventCarrierDown with
// the trunk's ID and cause, its row dead in Status), and the session
// recovers on a new trunk. The late Start's doorbell ring
// (Conn.startView) is defensive at this level: without it the same step
// still reaps the view (mutant r12b passes here), and
// TestDgTrunkDeathReachesEveryViewState pins the ring at carrier level.
//
// Session A is open on the stream trunk of link a. Session B's Dial takes
// the live trunk (a new view, its OPEN answered OK); in B's attach, right
// before the view's Start (Hooks.BeforeAttachStart), the link is killed
// and the hook returns only once A recorded the trunk's death (premise: the
// trunk's death record is set before B's Start). PASS: B's Dial succeeds;
// B emits EventCarrierUp and then exactly one EventCarrierDown for the
// trunk, with transport_error, dated at or after A's; B's Status lists the
// trunk dead with transport_error; A records its own CarrierDown; both
// sessions recover on another carrier within 10 s and exchange 32 KiB
// each way, verified; a clean end. Observed with a view's Death that does
// not report its trunk's death before the view is attached: B keeps the
// dead view as its live carrier.
func TestMuxViewDeadBeforeStartReachesSession_R2_12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var (
			armed  atomic.Bool
			caught atomic.Uint32 // the carrier B's attach was about to start
			a      *Conn         // session A's dialer end
			e      *e2ePair
			mu     sync.Mutex
			evs    []Event
		)
		hooks := &testhooks.Hooks{BeforeAttachStart: func(_ [16]byte, cid uint32) {
			if !armed.CompareAndSwap(true, false) {
				return
			}
			caught.Store(cid)
			e.links[0].Kill()
			for deadline := time.Now().Add(5 * time.Second); !mxDeadRow(a, CarrierID(cid)); time.Sleep(time.Millisecond) {
				if !time.Now().Before(deadline) {
					t.Errorf("premise: session A did not record the death of trunk %d within 5 s of the kill", cid)
					return
				}
			}
		}}
		dcfg := Config{OnEvent: func(ev Event) {
			mu.Lock()
			evs = append(evs, ev)
			mu.Unlock()
		}}
		e = e2eNew(t, dcfg, Config{}, &testhooks.Overrides{Hooks: hooks}, ListenConfig{}, "a")
		p := e.mxPeer(e2eCarrier(e.links[0]))
		var ap *Conn
		a, ap = e2eOpen(t, p, e.ln, DialOptions{})
		e2eExchange(t, a, ap, 32<<10, 1)
		trunk := mxCarrier(t, a, "a").ID

		armed.Store(true)
		b, bp := e2eOpen(t, p, e.ln, DialOptions{})
		if armed.Load() || CarrierID(caught.Load()) != trunk {
			t.Fatalf("stimulus: B's attach started carrier %d, want a view of A's trunk %d caught before its Start", caught.Load(), trunk)
		}
		onOther := func(c *Conn) bool {
			live := liveCarriers(c.Status())
			return len(live) == 1 && live[0].ID != trunk
		}
		for deadline := time.Now().Add(10 * time.Second); !onOther(a) || !onOther(b); time.Sleep(time.Millisecond) {
			if !time.Now().Before(deadline) {
				t.Fatalf("10 s after the kill: A lists %+v, B lists %+v; want both on one live carrier other than trunk %d (B's view, started after the trunk's death, did not reach B)",
					liveCarriers(a.Status()), liveCarriers(b.Status()), trunk)
			}
		}
		e2eExchange(t, a, ap, 32<<10, 2)
		e2eExchange(t, b, bp, 32<<10, 3)
		synctest.Wait()

		mu.Lock()
		var aDown, bUp, bDown []Event
		for _, ev := range evs {
			if ev.Carrier != trunk {
				continue
			}
			switch {
			case ev.Session == a.ID() && ev.Kind == EventCarrierDown:
				aDown = append(aDown, ev)
			case ev.Session == b.ID() && ev.Kind == EventCarrierUp:
				bUp = append(bUp, ev)
			case ev.Session == b.ID() && ev.Kind == EventCarrierDown:
				bDown = append(bDown, ev)
			}
		}
		mu.Unlock()
		if len(aDown) != 1 {
			t.Fatalf("session A: %d EventCarrierDown for trunk %d, want 1", len(aDown), trunk)
		}
		if len(bUp) != 1 || len(bDown) != 1 {
			t.Fatalf("session B: %d EventCarrierUp and %d EventCarrierDown for trunk %d, want 1 each: the view started after the trunk's death did not reach its session", len(bUp), len(bDown), trunk)
		}
		if d := bDown[0]; d.Cause != CauseTransportError || d.Seq < bUp[0].Seq || d.Time.Before(aDown[0].Time) {
			t.Fatalf("session B's EventCarrierDown %+v (up %+v, A's down %+v), want transport_error after its EventCarrierUp, dated at or after A's", d, bUp[0], aDown[0])
		}
		var row *CarrierStatus
		for _, cs := range b.Status().Carriers {
			if cs.ID == trunk {
				row = &cs
			}
		}
		if row == nil || row.State != CarrierDead || row.DeathCause != CauseTransportError {
			t.Fatalf("session B's Status row of trunk %d: %+v, want dead with transport_error", trunk, row)
		}
		e2eFinish(t, a, ap)
		e2eFinish(t, b, bp)
		e.close()
	})
}

// mxDeadRow reports whether c lists carrier id dead.
func mxDeadRow(c *Conn, id CarrierID) bool {
	for _, cs := range c.Status().Carriers {
		if cs.ID == id && cs.State == CarrierDead {
			return true
		}
	}
	return false
}

// pkMembers returns the frame budgets of c's live member carriers.
func pkMembers(c *PacketConn) []int {
	var mtus []int
	for _, cs := range c.Status().Carriers {
		if cs.DeathCause == CauseNone && cs.State == CarrierMember {
			mtus = append(mtus, cs.MTU)
		}
	}
	return mtus
}

// pkExchange writes n datagrams of exactly MaxPayload bytes, each with its
// own pattern, from a to b and requires each to arrive intact, then a's
// counters to show n sent and none refused as too large.
func pkExchange(t *testing.T, side string, a, b *PacketConn, n int) {
	t.Helper()
	size := a.MaxPayload()
	msg := make([]byte, size)
	buf := make([]byte, size+1)
	for i := range n {
		for j := range msg {
			msg[j] = byte(i*31 + j)
		}
		if w, err := a.WriteTo(msg, nil); err != nil || w != size {
			t.Fatalf("%s: WriteTo(%d bytes) #%d: %d, %v", side, size, i, w, err)
		}
		b.SetReadDeadline(time.Now().Add(time.Second))
		r, _, err := b.ReadFrom(buf)
		if err != nil || r != size || string(buf[:r]) != string(msg) {
			t.Fatalf("%s: datagram #%d of %d bytes: %d bytes, %v", side, i, size, r, err)
		}
	}
	if c := *a.Status().Packet; c.Sent != uint64(n) || c.DropTooLarge != 0 {
		t.Fatalf("%s: sender counters %+v, want %d sent and no DropTooLarge", side, c, n)
	}
}

// TestMuxDatagramJoinBudget_L37 (M3-D24, §A3.3; L37): a packet JOIN placed
// on a live datagram trunk offers the trunk's current budget in
// JOIN.rxNext (patchViewOffer), and neither end calls SetBudget on that
// view (the trunk's budget is fixed once it started). Two bond packet
// sessions on one Peer of two datagram factories: the second session's
// OPEN and JOIN both ride the first session's trunks (two fast paths, no
// factory call: stimulus). Both of its members run at the trunks' budget
// on both ends, and datagrams of its MaxPayload cross both ways intact.
func TestMuxDatagramJoinBudget_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		p := h.peer(h.carrier("h1", 1, nil), h.carrier("h2", 2, nil))
		d1, p1 := peOpen(t, p, h.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 5*time.Second, "session 1's two members", func() bool { return len(pkMembers(d1)) == 2 && len(pkMembers(p1)) == 2 })
		d2, p2 := peOpen(t, p, h.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 5*time.Second, "session 2's two members", func() bool { return len(pkMembers(d2)) == 2 && len(pkMembers(p2)) == 2 })
		if m := h.d.Status().Mux; m.Carriers != 2 || m.Views != 4 || m.FastPaths != 2 {
			t.Fatalf("dialer Mux %+v, want session 2's OPEN and JOIN on session 1's two trunks", m)
		}
		budget := pkMembers(d1)[0]
		for _, s := range []struct {
			side string
			c    *PacketConn
		}{{"dialer 1", d1}, {"passive 1", p1}, {"dialer 2", d2}, {"passive 2", p2}} {
			for _, mtu := range pkMembers(s.c) {
				if mtu != budget {
					t.Fatalf("%s: member budgets %v, want %d (the trunks')", s.side, pkMembers(s.c), budget)
				}
			}
		}
		if mp := d2.MaxPayload(); mp <= 0 || mp > budget-25 || mp != p2.MaxPayload() || mp != d1.MaxPayload() {
			t.Fatalf("MaxPayload %d/%d (session 1 %d) on trunks of budget %d", mp, p2.MaxPayload(), d1.MaxPayload(), budget)
		}
		pkExchange(t, "dialer 2 → passive 2", d2, p2, 16)
		pkExchange(t, "passive 2 → dialer 2", p2, d2, 16)
		for _, c := range []*PacketConn{d1, p1, d2, p2} {
			c.Close()
		}
		h.close()
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
		d1, p1 := mxPeOpen(t, p, h.ln, DialOptions{}, 10*time.Second)
		d2, p2 := mxPeOpen(t, p, h.ln, DialOptions{}, 10*time.Second)
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

// CAPACITY CodeBacklog means one thing (wire.CodeBacklog, plan §4): the
// Listener's AcceptBacklog of the OPEN's session kind is full. A dialer
// takes it for a terminal answer, so a session that is pending — admitted,
// its backlog slot held, the application about to decide — must never be
// answered with it: the application's verdict reaches the dialer, or, when
// the view that carried the OPEN ends first, the dialer retries on another
// carrier and the verdict reaches it there (m3 BACKLOG, FINDING C of the
// G6 mixed-NAT case: rejected sessions on live MUX trunks were answered
// CAPACITY code 2 while the passive's backlog held 13 to 28 of 128).
// The session never answers CodeBacklog in place of a verdict, and neither
// does the carrier: its fallback refusal of a view killed with its verdict
// still unplaced (abandonLocked at the close bound) carries CodeCarriers,
// which the dialer retries (TestPendingVerdictUnplacedAtCloseBy_L48).
// Helpers of these tests start with "bk".

// bkGate holds the passive's MUX writer in its AfterViewFill hook at the
// first DRR Fill of a view above handle 1 once armed: the call has
// returned (the pending session placed nothing, it has no verdict yet) and
// the writer has not yet decided what that empty call means.
type bkGate struct {
	armed   atomic.Bool
	once    sync.Once
	fired   chan uint32   // the held handle
	release chan struct{} // closed by the test
}

func newBKGate() *bkGate {
	return &bkGate{fired: make(chan uint32, 1), release: make(chan struct{})}
}

func (g *bkGate) hook(_, h uint32) {
	if h <= wire.SessionHandle || !g.armed.Load() {
		return
	}
	held := false
	g.once.Do(func() { held = true })
	if !held {
		return
	}
	g.fired <- h
	<-g.release
}

// bkOverrides returns the dialer's and the passive's overrides: identical
// presets (L14), the gate on the passive only.
func bkOverrides(g *bkGate) (d, p *testhooks.Overrides) {
	return &testhooks.Overrides{}, &testhooks.Overrides{Hooks: &testhooks.Hooks{AfterViewFill: g.hook}}
}

// bkWantReject requires err to be the application's rejection with code.
func bkWantReject(t testing.TB, err error, code uint32) {
	t.Helper()
	var re *RejectError
	if !errors.As(err, &re) || re.Code != code {
		t.Fatalf("Dial: %v; want *RejectError{Code: %d} (CodeBacklog is %d)", err, code, wire.CodeBacklog)
	}
}

// TestPassiveBacklogCodeOnlyWhenFull_L48 (m3 BACKLOG; L48, R1-9): the
// application rejects a session pending on a view of a live MUX trunk
// while the trunk's writer is between that view's DRR Fill — which placed
// nothing, the session had no verdict yet — and the writer's decision on
// the empty call. The stimulus is the AfterViewFill hook holding the
// writer exactly there while Accept and Reject complete. The dialer must
// get the application's RejectError; before the fix the writer read the
// retirement that Reject had queued meanwhile as "the session set no
// verdict", abandoned the view and answered CAPACITY CodeBacklog with a
// backlog of one pending session out of 128. The same rows on a datagram
// trunk (packet sessions), and the one legitimate CodeBacklog: a full
// backlog.
func TestPassiveBacklogCodeOnlyWhenFull_L48(t *testing.T) {
	t.Run("stream trunk", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newBKGate()
			ovD, ovP := bkOverrides(g)
			e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, ovD), p: wpTestRuntime(t, Config{}, ovP)}
			e.ln = wpListen(t, e.p, ListenConfig{})
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
			t.Cleanup(l.Close)
			p := e.mxPeer(e2eCarrier(l))
			dc, pc := e2eOpen(t, p, e.ln, DialOptions{}) // the trunk, its view 1 live

			g.armed.Store(true)
			res := e2eDialAsync(context.Background(), p, DialOptions{})
			var h uint32
			select {
			case h = <-g.fired:
			case <-time.After(5 * time.Second):
				t.Fatal("the passive writer never called the pending view's Fill")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pend, err := e.ln.Accept(ctx)
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if err := pend.Reject(4242, "rejected while the writer was in the view's Fill"); err != nil {
				t.Fatalf("Reject: %v", err)
			}
			close(g.release)
			var r dialResult
			select {
			case r = <-res:
			case <-time.After(10 * time.Second):
				t.Fatal("Dial did not return")
			}
			if r.err == nil {
				r.c.Close()
			}
			bkWantReject(t, r.err, 4242)
			if h <= wire.SessionHandle {
				t.Fatalf("held handle %d: not a view of the live trunk", h)
			}
			// Integrity: the first session never noticed (one trunk, both
			// ends exchange in full).
			e2eExchange(t, dc, pc, 64<<10, 7)
			dc.Close()
			pc.Close()
		})
	})
	t.Run("datagram trunk", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			g := newBKGate()
			ovD, ovP := bkOverrides(g)
			e := &pePair{t: t, d: wpTestRuntime(t, Config{}, ovD), p: wpTestRuntime(t, Config{}, ovP)}
			e.ln = wpListen(t, e.p, ListenConfig{})
			l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "u", Queue: 8192, Accept: e.accept(0)})
			e.links = append(e.links, l)
			t.Cleanup(func() { l.Close() })
			p := e.peer(peDatagramCarrier(l, 1400))
			dc, pc := peOpen(t, p, e.ln, DialOptions{}) // the trunk, its view 1 live

			g.armed.Store(true)
			ch := peDial(p, DialOptions{})
			select {
			case <-g.fired:
			case <-time.After(5 * time.Second):
				t.Fatal("the passive writer never called the pending view's Fill")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pend, err := e.ln.AcceptPacket(ctx)
			if err != nil {
				t.Fatalf("AcceptPacket: %v", err)
			}
			if err := pend.Reject(4243, "rejected while the writer was in the view's Fill"); err != nil {
				t.Fatalf("Reject: %v", err)
			}
			close(g.release)
			var r peDialed
			select {
			case r = <-ch:
			case <-time.After(10 * time.Second):
				t.Fatal("DialPacket did not return")
			}
			if r.err == nil {
				r.c.Close()
			}
			bkWantReject(t, r.err, 4243)
			peSend(t, dc, 11, 0, 8, 200)
			peRecv(t, pc, 11, 8, 5*time.Second)
			dc.Close()
			pc.Close()
		})
	})
	t.Run("rejects under a bulk transfer", func(t *testing.T) {
		// The G6 load shape without a gate: a session on the same trunk
		// moves 16 MiB each way at 16 MiB/s while 24 sessions are dialed
		// and rejected one after another on that trunk. Every Dial gets the
		// application's RejectError, and the bulk arrives intact. (A guard
		// of the load shape: it fails when the pending view is not woken
		// for its verdict; the narrow writer races of the gated rows above
		// it does not reach reliably.)
		synctest.Test(t, func(t *testing.T) {
			e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, nil), p: wpTestRuntime(t, Config{}, nil)}
			e.ln = wpListen(t, e.p, ListenConfig{})
			// A short link queue: the control frames wait behind at most
			// 64 KiB of bulk, so the rejects keep pace with the transfer.
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle, Buffer: 64 << 10})
			t.Cleanup(l.Close)
			p := e.mxPeer(e2eCarrier(l))
			dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
			l.SetDelay(2*time.Millisecond, 0)
			l.SetRate(16 << 20)
			bulk := make(chan error, 1)
			go func() { bulk <- e2eExchangeErr(dc, pc, 16<<20, 13) }()
			for i := range 24 {
				res := e2eDialAsync(context.Background(), p, DialOptions{})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				pend, err := e.ln.Accept(ctx)
				cancel()
				if err != nil {
					t.Fatalf("Accept %d: %v", i, err)
				}
				if err := pend.Reject(4242, "rejected under load"); err != nil {
					t.Fatalf("Reject %d: %v", i, err)
				}
				r := <-res
				if r.err == nil {
					r.c.Close()
				}
				var re *RejectError
				if !errors.As(r.err, &re) || re.Code != 4242 {
					t.Fatalf("Dial %d: %v; want *RejectError{Code: 4242} (CodeBacklog is %d)", i, r.err, wire.CodeBacklog)
				}
			}
			select {
			case err := <-bulk:
				t.Fatalf("the bulk exchange ended (%v) before the last reject: no load", err)
			default:
			}
			if err := <-bulk; err != nil {
				t.Fatalf("bulk exchange: %v", err)
			}
			dc.Close()
			pc.Close()
		})
	})
	t.Run("confirmed, then Runtime.Close", func(t *testing.T) {
		// The application confirms while the writer is held after the
		// view's empty Fill, and the passive Runtime closes before the OK
		// is placed. The OK must still be the view's first frame — never
		// CAPACITY CodeBacklog in its place —, and the view must not wait
		// for the close bound's kill: the dialer, which saw the trunk's
		// GOAWAY, drops the OK with its DETACH, which ends the held view
		// (R1-9), so Runtime.Close returns well within closeBound.
		synctest.Test(t, func(t *testing.T) {
			g := newBKGate()
			ovD, ovP := bkOverrides(g)
			e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, ovD), p: wpTestRuntime(t, Config{}, ovP)}
			e.ln = wpListen(t, e.p, ListenConfig{})
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
			t.Cleanup(l.Close)
			p := e.mxPeer(e2eCarrier(l))
			e2eOpen(t, p, e.ln, DialOptions{}) // the trunk, its view 1 live
			g.armed.Store(true)
			res := e2eDialAsync(context.Background(), p, DialOptions{})
			select {
			case <-g.fired:
			case <-time.After(5 * time.Second):
				t.Fatal("the passive writer never called the pending view's Fill")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pend, err := e.ln.Accept(ctx)
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if _, err := pend.Confirm(); err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			start := time.Now()
			closed := make(chan struct{})
			go func() {
				e.p.Close()
				close(closed)
			}()
			mxWait(t, 100*time.Millisecond, "the confirmed session shut down", func() bool {
				return pend.s.State() == session.StateEnded
			})
			close(g.release)
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Runtime.Close did not return")
			}
			if d := time.Since(start); d >= 500*time.Millisecond {
				t.Fatalf("Runtime.Close took %v: the confirmed view waited for the close bound's kill", d)
			}
			// The dialer may take the OK (a Conn) or, having seen the
			// trunk's GOAWAY first, drop it and fail elsewhere; never the
			// backlog answer.
			r := <-res
			if r.err == nil {
				r.c.Close()
			} else if strings.Contains(r.err.Error(), fmt.Sprintf("CAPACITY (code %d)", wire.CodeBacklog)) {
				t.Fatalf("Dial: %v; the confirmed session's view was answered CodeBacklog", r.err)
			}
		})
	})
	t.Run("withdrawn: its other view", func(t *testing.T) {
		// A pending session holds two views, one per trunk (the OPEN and
		// its duplicate). The dialer withdraws the duplicate's attempt
		// (RST(AbortWithdrawn), R1-5 rule 1): the session ends withdrawn
		// and the first view, whose OPEN still awaits a response (R1-9),
		// is answered with the tombstone's verdict, UNKNOWN_SESSION —
		// before the fix the carrier answered CAPACITY CodeBacklog.
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
			p, pb := e.peer(e.links[0]), e.peer(e.links[1])
			s1, q1 := e2eOpen(t, p, e.ln, DialOptions{})  // trunk a, view 1 live
			s2, q2 := e2eOpen(t, pb, e.ln, DialOptions{}) // trunk b, view 1 live
			open := wpOpen(wpSID(4100), wire.KindStream, 1, nil)
			type res struct {
				st   wire.AckStatus
				code uint32
				err  error
			}
			x := make(chan res, 1)
			go func() {
				est, st, code, err := mxInject(context.Background(), p, 0, wire.TypeOpen, open)
				if err == nil && st == wire.StatusOK {
					mxDrop(est)
				}
				x <- res{st, code, err}
			}()
			synctest.Wait() // pending on trunk a's view (Accept is never called)
			ctx, cancel := context.WithCancelCause(context.Background())
			y := make(chan error, 1)
			go func() {
				est, st, _, err := mxInject(ctx, pb, 0, wire.TypeOpen, open)
				if err == nil && st == wire.StatusOK {
					mxDrop(est)
				}
				y <- err
			}()
			synctest.Wait() // the duplicate parked on trunk b's view
			if st := e.p.Status(); st.Sessions.Pending != 1 {
				t.Fatalf("pending sessions %d, want 1", st.Sessions.Pending)
			}
			cancel(carrier.ErrWithdrawn)
			if err := <-y; err == nil {
				t.Fatal("the withdrawn attempt returned a response")
			}
			var r res
			select {
			case r = <-x:
			case <-time.After(5 * time.Second):
				t.Fatal("the first view got no response")
			}
			if r.err != nil || r.st != wire.StatusUnknownSession {
				t.Fatalf("first view of a withdrawn session: %v code %d, %v; want UNKNOWN_SESSION (CodeBacklog is %d)", r.st, r.code, r.err, wire.CodeBacklog)
			}
			// The trunks and their sessions live on.
			e2eExchange(t, s1, q1, 32<<10, 3)
			e2eExchange(t, s2, q2, 32<<10, 5)
			for _, c := range []*Conn{s1, q1, s2, q2} {
				c.Close()
			}
		})
	})
	t.Run("withdrawn: dedicated carriers retire unanswered", func(t *testing.T) {
		// The same withdrawal on two dedicated carriers (no MUX): the
		// carrier whose OPEN still awaits a response retires without one
		// (§6.2) — its CLOSE is its only frame. Only a MUX view is owed the
		// tombstone's UNKNOWN_SESSION; a dedicated carrier ends with its
		// CLOSE, which already tells the dialer the attempt is over.
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			inst := wpInst(0xb7)
			open := wpOpen(wpSID(4101), wire.KindStream, 1, nil)
			first := wpConnect(t, ln, inst, 1)
			first.hello(rt)
			first.send(wire.TypeOpen, 0, open)
			synctest.Wait() // pending (Accept is never called)
			dup := wpConnect(t, ln, inst, 2)
			dup.hello(rt)
			dup.send(wire.TypeOpen, 0, open)
			synctest.Wait() // the duplicate parked on the pending session
			if st := rt.Status(); st.Sessions.Pending != 1 {
				t.Fatalf("pending sessions %d, want 1", st.Sessions.Pending)
			}
			dup.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), ""))
			var wg sync.WaitGroup
			wg.Go(func() { dup.drain() })
			seen := first.drain()
			wg.Wait()
			if len(seen) != 1 || seen[0] != wire.TypeClose {
				t.Fatalf("the first carrier of a withdrawn session placed %v; want its CLOSE only (§6.2)", seen)
			}
			synctest.Wait()
			if st := rt.Status(); st.Sessions != (SessionCounts{Tombstones: 1}) || st.AcceptBacklog[0] != 0 {
				t.Fatalf("after the withdrawal: %+v", st)
			}
		})
	})
	t.Run("full backlog", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{AcceptBacklog: 1}, "a")
			p := e.peer()
			first := e2eDialAsync(context.Background(), p, DialOptions{})
			synctest.Wait() // pending, its slot held: Accept is not called yet
			r := <-e2eDialAsync(context.Background(), p, DialOptions{})
			if !errors.Is(r.err, ErrCapacity) {
				t.Fatalf("second Dial: %v; want ErrCapacity (backlog full)", r.err)
			}
			pend, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if err := pend.Reject(4242, "x"); err != nil {
				t.Fatalf("Reject: %v", err)
			}
			bkWantReject(t, (<-first).err, 4242)
		})
	})
}

// TestPendingSurvivesTrunkDeath_L48 (m3 BACKLOG; design §6.2: a pending
// session survives the death of its carriers): the only trunk that
// carried a session's OPEN dies before the application decides. The
// dialer's attempt ends with the carrier, the Dial goes on (a new trunk,
// the OPEN again), and the application's verdict — given before or after
// the new OPEN arrived — reaches the dialer as its RejectError, never a
// CAPACITY answer.
func TestPendingSurvivesTrunkDeath_L48(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rejectFirst bool // Reject before the dialer's new OPEN can arrive
	}{
		{"verdict after the new OPEN", false},
		{"verdict before the new OPEN", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
				l := e.links[0]
				p := e.peer()
				dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
				res := e2eDialAsync(context.Background(), p, DialOptions{})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				pend, err := e.ln.Accept(ctx)
				if err != nil {
					t.Fatalf("Accept: %v", err)
				}
				if tc.rejectFirst {
					l.SetRefuse(true) // the new trunk cannot come up yet
				}
				if n := l.Kill(); n == 0 {
					t.Fatal("no carrier to kill")
				}
				synctest.Wait()
				if pend.s.State() != session.StatePending {
					t.Fatalf("pending session after its trunk died: state %v", pend.s.State())
				}
				if tc.rejectFirst {
					if err := pend.Reject(4242, "after the trunk died"); err != nil {
						t.Fatalf("Reject: %v", err)
					}
					l.SetRefuse(false)
				} else {
					mxWait(t, 30*time.Second, "the new OPEN parked on the pending session", func() bool {
						return len(pend.s.Status().Carriers) >= 2
					})
					if err := pend.Reject(4242, "after the trunk died"); err != nil {
						t.Fatalf("Reject: %v", err)
					}
				}
				var r dialResult
				select {
				case r = <-res:
				case <-time.After(60 * time.Second):
					t.Fatal("Dial did not return")
				}
				if r.err == nil {
					r.c.Close()
				}
				bkWantReject(t, r.err, 4242)
				// The open session migrated to the new trunk intact.
				e2eExchange(t, dc, pc, 64<<10, 9)
				dc.Close()
				pc.Close()
			})
		})
	}
}

// TestPendingVerdictUnplacedAtCloseBy_L48 (m3 BACKLOG follow-up, fixed at
// I3 in carrier abandonLocked): the application rejects a session pending
// on a view of a live MUX trunk while the trunk's writer is held (the
// AfterViewFill gate) past the session's close bound, so the session's
// end procedure Kills the view with its REJECTED unplaced. The carrier's
// fallback refusal (abandonLocked) must be a code the dialer retries —
// never CAPACITY CodeBacklog, which says the backlog is full and is
// terminal — so the Dial retries and gets the verdict from the tombstone.
func TestPendingVerdictUnplacedAtCloseBy_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newBKGate()
		ovD, ovP := bkOverrides(g)
		e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, ovD), p: wpTestRuntime(t, Config{}, ovP)}
		e.ln = wpListen(t, e.p, ListenConfig{})
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
		t.Cleanup(l.Close)
		p := e.mxPeer(e2eCarrier(l))
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		g.armed.Store(true)
		res := e2eDialAsync(context.Background(), p, DialOptions{})
		select {
		case <-g.fired:
		case <-time.After(5 * time.Second):
			t.Fatal("the passive writer never called the pending view's Fill")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pend, err := e.ln.Accept(ctx)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if err := pend.Reject(4242, "rejected; the writer is held past closeBy"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		time.Sleep(1500 * time.Millisecond) // past closeBy = min(1 s, DeadMax): the view is killed
		close(g.release)
		var r dialResult
		select {
		case r = <-res:
		case <-time.After(30 * time.Second):
			t.Fatal("Dial did not return")
		}
		if r.err == nil {
			r.c.Close()
		}
		bkWantReject(t, r.err, 4242)
		dc.Close()
		pc.Close()
	})
}
