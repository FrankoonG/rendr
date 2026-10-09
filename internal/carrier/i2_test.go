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
