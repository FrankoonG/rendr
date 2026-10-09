package rendr

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestPoolVerdictGrace (WP10 amendment to M3-D18): a coalesced waiter
// waits for the claimant's dial, not for the passive application's verdict
// on the claimant's session. While the first session of a Peer waits for
// its Accept and Confirm on a fresh carrier whose handshake completed, a
// second Dial of the Peer waits at most the verdict grace and then dials a
// carrier of its own — no failure counted, its session opens at once — and
// once the first session is confirmed both carriers are the Peer's: a third
// Dial is served on a live one without a factory call.
func TestPoolVerdictGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		r1 := e2eDialAsync(context.Background(), p, DialOptions{})
		pend1, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // the first session waits for its verdict
		start := time.Now()
		r2 := e2eDialAsync(context.Background(), p, DialOptions{})
		pend2, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		q2, err := pend2.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		var d2 *Conn
		select {
		case r := <-r2:
			if r.err != nil {
				t.Fatal(r.err)
			}
			d2 = r.c
		case <-time.After(time.Second):
			t.Fatal("the second Dial waited for the first session's verdict")
		}
		if el := time.Since(start); el > 500*time.Millisecond {
			t.Fatalf("the second Dial took %v", el)
		}
		if n := taps.dials.Load(); n != 2 {
			t.Fatalf("%d factory calls, want 2 (the waiter dialled its own after the grace)", n)
		}
		if st := p.pool.Stats(); st.Coalesced != 1 {
			t.Fatalf("pool %+v, want the second Dial counted as coalesced", st)
		}
		q1, err := pend1.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-r1
		if r.err != nil {
			t.Fatal(r.err)
		}
		d1 := r.c
		d3, q3 := e2eOpen(t, p, e.ln, DialOptions{})
		if n := taps.dials.Load(); n != 2 {
			t.Fatalf("%d factory calls after the third Dial, want no new one", n)
		}
		if m := e.d.Status().Mux; m.Carriers != 2 || m.Views != 3 {
			t.Fatalf("dialer Mux %+v, want both carriers published with three views", m)
		}
		for i, pr := range [][2]*Conn{{d1, q1}, {d2, q2}, {d3, q3}} {
			e2eExchange(t, pr[0], pr[1], 64<<10, uint64(i))
			e2eFinish(t, pr[0], pr[1])
		}
		e.close()
	})
}

// TestFirstHandlePreset_L14 (L14, M3-D4, PA-37): the FirstHandle counter
// preset (testhooks, equal in both Runtimes) reaches the dialer's trunks: a
// Peer's second and third sessions get handles 0xFFFFFFFE and 0xFFFFFFFF
// on its trunk, which then seals at the end of the handle space; the
// fourth session dials a new trunk (handle 1 there), and every session
// delivers intact.
func TestFirstHandlePreset_L14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := &testhooks.Overrides{FirstHandle: 0xFFFFFFFE}
		e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		var ds, ps [4]*Conn
		want := []uint32{1, 0xFFFFFFFE, 0xFFFFFFFF, 1}
		for i := range 4 {
			ds[i], ps[i] = e2eOpen(t, p, e.ln, DialOptions{})
			if h := mxHandleOf(t, ds[i], "a"); h != want[i] {
				t.Fatalf("session %d: handle %#x, want %#x", i, h, want[i])
			}
		}
		if n := taps.dials.Load(); n != 2 {
			t.Fatalf("%d factory calls, want 2 (the sealed trunk takes no fourth view)", n)
		}
		for i := range 4 {
			e2eExchange(t, ds[i], ps[i], 64<<10, uint64(i))
			e2eFinish(t, ds[i], ps[i])
		}
		e.close()
	})
}
