package rendr

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

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
