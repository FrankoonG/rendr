package carrier

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The KINDSPLIT rows (M3 amendment to §A5.8, M3-D17 and M3-D24): a stream
// MUX trunk carries sessions of one kind. The pool keys its trunks and its
// dials in flight by (factory, session kind).

// goAttemptKind runs an attempt of a session of kind dk on its own
// goroutine; its result goes to ch.
func (pt *poolT) goAttemptKind(ctx context.Context, kind wire.Type, sid byte, dk wire.Type, ch chan<- poolRes) {
	go func() {
		est, err := pt.attemptKind(ctx, pt.p, 0, kind, sid, [16]byte{}, nil, dk)
		ch <- poolRes{sid: sid, est: est, err: err}
	}()
}

// TestPoolKindSplit: on one stream factory a stream session and a packet
// session each dial a trunk of their own (two factory calls; the packet
// OPEN is no fast path on the stream trunk); later OPENs and JOINs of
// either kind are fast paths on the trunk of their kind only; Stats counts
// both trunks and every view. The trunks record their kind.
func TestPoolKindSplit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		ctx := context.Background()
		open := func(sid byte, dk wire.Type) *Established {
			t.Helper()
			est, err := pt.attemptKind(ctx, pt.p, 0, wire.TypeOpen, sid, [16]byte{}, nil, dk)
			if err != nil || !isOK(est) {
				t.Fatalf("OPEN %d: %v", sid, err)
			}
			pt.attach(est)
			return est
		}
		sA := open(1, wire.TypeData)
		pB := open(2, wire.TypeDgram)
		if !sA.Fresh || !pB.Fresh || sA.Conn.trunk == pB.Conn.trunk {
			t.Fatalf("fresh %v and %v, one trunk %v: want a trunk per session kind", sA.Fresh, pB.Fresh, sA.Conn.trunk == pB.Conn.trunk)
		}
		if a, b := sA.Conn.kinds, pB.Conn.kinds; a != wire.TypeData || b != wire.TypeDgram {
			t.Fatalf("trunk kinds %v and %v, want DATA and DGRAM", a, b)
		}
		synctest.Wait()
		inst := sA.Conn.PeerInstance()
		join := func(sid byte, dk wire.Type) *Established {
			t.Helper()
			est, err := pt.attemptKind(ctx, pt.p, 0, wire.TypeJoin, sid, inst, nil, dk)
			if err != nil || !isOK(est) {
				t.Fatalf("JOIN %d: %v", sid, err)
			}
			pt.attach(est)
			return est
		}
		for _, c := range []struct {
			est  *Established
			want *trunk
		}{
			{open(3, wire.TypeData), sA.Conn.trunk},
			{open(4, wire.TypeDgram), pB.Conn.trunk},
			{join(5, wire.TypeData), sA.Conn.trunk},
			{join(6, wire.TypeDgram), pB.Conn.trunk},
		} {
			if c.est.Fresh || c.est.Conn.trunk != c.want {
				t.Fatalf("view %d: fresh %v, on its kind's trunk %v", c.est.Conn.Handle(), c.est.Fresh, c.est.Conn.trunk == c.want)
			}
		}
		synctest.Wait()
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.Carriers != 2 || st.Views != 6 || st.FastPaths != 4 || st.Coalesced != 0 {
			t.Fatalf("%d factory calls, stats %+v; want 2 calls, 2 carriers with 6 views, 4 fast paths", d, st)
		}
		if a, b := sA.Conn.Shared(), pB.Conn.Shared(); a != 3 || b != 3 {
			t.Fatalf("Shared %d and %d, want 3 each", a, b)
		}
	})
}

// TestPoolKindSplitCoalescing: concurrent attempts of both kinds on a
// factory without a trunk make one factory call per kind; each kind's
// waiters wait for the dial of their own kind only and land on its trunk
// once the claimant's session started it, while the other kind's trunk
// is still unpublished.
func TestPoolKindSplitCoalescing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 3
		pt := newPoolT(t, nil, nil)
		gate := make(chan struct{})
		pt.srv.setGate(gate)
		chs := map[wire.Type]chan poolRes{wire.TypeData: make(chan poolRes, n), wire.TypeDgram: make(chan poolRes, n)}
		for i := range n {
			pt.goAttemptKind(context.Background(), wire.TypeOpen, byte(1+i), wire.TypeData, chs[wire.TypeData])
			pt.goAttemptKind(context.Background(), wire.TypeOpen, byte(11+i), wire.TypeDgram, chs[wire.TypeDgram])
		}
		synctest.Wait()
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.Coalesced != 2*(n-1) {
			t.Fatalf("%d factory calls, Coalesced %d; want 2 (one per kind) and %d", d, st.Coalesced, 2*(n-1))
		}
		close(gate)
		synctest.Wait()
		claims := map[wire.Type]poolRes{}
		for dk, ch := range chs {
			if got := pendingResults(ch); got != 1 {
				t.Fatalf("kind %v: %d results before the claimant's session started its trunk, want the claimant's only", dk, got)
			}
			c := collect(t, ch, 1)[0]
			if c.err != nil || !c.est.Fresh || !isOK(c.est) {
				t.Fatalf("kind %v claimant: %v", dk, c.err)
			}
			claims[dk] = c
		}
		// Only the stream claimant's session starts its trunk: the stream
		// waiters land on it, the packet waiters keep waiting for theirs.
		pt.attach(claims[wire.TypeData].est)
		for _, r := range collect(t, chs[wire.TypeData], n-1) {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || r.est.Conn.trunk != claims[wire.TypeData].est.Conn.trunk {
				t.Fatalf("stream waiter %d: %v (fresh %v)", r.sid, r.err, r.est != nil && r.est.Fresh)
			}
			pt.attach(r.est)
		}
		synctest.Wait()
		if got := pendingResults(chs[wire.TypeDgram]); got != 0 {
			t.Fatalf("%d packet waiters returned before their own trunk was published", got)
		}
		pt.attach(claims[wire.TypeDgram].est)
		for _, r := range collect(t, chs[wire.TypeDgram], n-1) {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || r.est.Conn.trunk != claims[wire.TypeDgram].est.Conn.trunk {
				t.Fatalf("packet waiter %d: %v (fresh %v)", r.sid, r.err, r.est != nil && r.est.Fresh)
			}
			pt.attach(r.est)
		}
		synctest.Wait()
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.Carriers != 2 || st.Views != 2*n || st.FastPaths != 2*(n-1) {
			t.Fatalf("%d factory calls, stats %+v; want 2 carriers with %d views", d, st, 2*n)
		}
	})
}
