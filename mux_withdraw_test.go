package rendr

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestMuxWithdrawAtAsyncAttach_R1_5 (R1-5, §A3.3; WP16 W1): a Dial whose
// opening race placed its second OPEN as a view on another live trunk —
// which the passive admits through AttachOpen, attached only when the
// session's actor adopts it — is cancelled while that actor is held before
// the adopt. The dialer withdraws both OPENs (RST(AbortWithdrawn), then
// DETACH): neither shared trunk dies (no protocol_violation), the bond
// session that shares them keeps both members and moves data, and the
// withdrawn session leaves no pending session once its actor runs.
func TestMuxWithdrawAtAsyncAttach_R1_5(t *testing.T) {
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
			if n := len(mxTrunkSet(e.p)); n != 2 {
				t.Fatalf("%s: %d passive trunks, want 2", what, n)
			}
		}
		alive("after the withdrawal")
		release()
		synctest.Wait()
		mxWait(t, 10*time.Second, "the withdrawn session gone", func() bool { return e.p.Status().Sessions.Pending == 0 })
		alive("after the adopt")
		if n := mxMembers(s0); n != 2 {
			t.Fatalf("the bond holds %d members, want 2", n)
		}
		e2eExchange(t, s0, q0, 64<<10, 5)
		e2eFinish(t, s0, q0)
		e.close()
	})
}
