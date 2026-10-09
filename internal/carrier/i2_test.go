package carrier

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestTrunkMuxFullMark (M3-D12, M3-D17; I2): a CAPACITY CodeMuxFull answer
// to an OPEN marks the dialer's trunk full in the trunk's own usable rule
// (usableForMux), not only in the pool's mark, until a view other than the
// refused one leaves. The refused view's own Done must not clear the mark:
// that Done closes right after the refusal, so clearing on it left the
// trunk's clause without effect (WP9's finding against viewDoneClosed).
func TestTrunkMuxFullMark(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, func(env *Env) { env.Timing.MuxMaxViews = 2 })
		est1, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		pt.attach(est1)
		est2, _ := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
		pt.attach(est2)
		tr := est1.Conn
		if !tr.usableFor(wire.TypeData, [16]byte{}, 9) {
			t.Fatal("the trunk is not usable before the refusal")
		}
		est3, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 3, [16]byte{})
		if err != nil || !est3.Fresh || !isOK(est3) {
			t.Fatalf("attempt after the CodeMuxFull refusal: %v", err)
		}
		pt.attach(est3)
		synctest.Wait()
		if st := pt.p.Stats(); st.MuxFull != 1 {
			t.Fatalf("stats %+v, want one CodeMuxFull answer", st)
		}
		if tr.usableFor(wire.TypeData, [16]byte{}, 9) {
			t.Fatal("the trunk that answered CodeMuxFull is usable by its own rule (the refused view's Done cleared the mark)")
		}
		est2.Conn.Kill(CauseLocalClose, "session 2 ended")
		waitDone(t, est2.Conn.Done(), "view 2")
		synctest.Wait()
		if !tr.usableFor(wire.TypeData, [16]byte{}, 9) {
			t.Fatal("the trunk stayed full after another view left")
		}
	})
}

// TestPoolStatsCountStartedFreshTrunk (M3-D49; I2): a fresh trunk whose
// session started view 1 counts in the pool's Stats (Status.Mux) at once,
// not only after its asynchronous publication: a session that just opened
// on a shared carrier is never missing from Status.Mux (the race lane saw
// Mux.Carriers 0 right after a Dial on a mux trunk returned).
func TestPoolStatsCountStartedFreshTrunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		est, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		if err != nil || !est.Fresh || !isOK(est) {
			t.Fatalf("attempt: %v", err)
		}
		if st := pt.p.Stats(); st.Carriers != 0 || st.Views != 0 {
			t.Fatalf("stats %+v before the session started view 1, want nothing counted", st)
		}
		mv := &mView{c: est.Conn, ep: &dEP{}, src: newVSource(pt.env), bell: &hBell{}, done: &hBell{}}
		mv.ep.fill = mv.src.fill
		// Start without letting the publication goroutine run first.
		pt.p.mu.Lock()
		est.Conn.Start(mv.ep, mv.bell, StartOptions{})
		pt.p.mu.Unlock()
		if st := pt.p.Stats(); st.Carriers != 1 || st.Views != 1 {
			t.Fatalf("stats %+v right after Start, want the started trunk with its view", st)
		}
		synctest.Wait()
		if st := pt.p.Stats(); st.Carriers != 1 || st.Views != 1 {
			t.Fatalf("stats %+v after the publication, want it counted once", st)
		}
	})
}
