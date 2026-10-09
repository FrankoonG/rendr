package rendr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// CAPACITY CodeBacklog means one thing (wire.CodeBacklog, plan §4): the
// Listener's AcceptBacklog of the OPEN's session kind is full. A dialer
// takes it for a terminal answer, so a session that is pending — admitted,
// its backlog slot held, the application about to decide — must never be
// answered with it: the application's verdict reaches the dialer, or, when
// the view that carried the OPEN ends first, the dialer retries on another
// carrier and the verdict reaches it there (m3 BACKLOG, FINDING C of the
// G6 mixed-NAT case: rejected sessions on live MUX trunks were answered
// CAPACITY code 2 while the passive's backlog held 13 to 28 of 128).
// The session never answers CodeBacklog in place of a verdict; the one
// remaining exception is the carrier's fallback refusal of a view killed
// with its verdict still unplaced (abandonLocked at the close bound), an
// open item of the carrier's view-end code.
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
