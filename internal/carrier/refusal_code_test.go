package carrier

import (
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestOnlyCapacityListenerClosedBlocksOpens_R1_10 (R1-10, M3-D63): a
// dialer MUX trunk stops taking OPENs only when the passive answered an
// OPEN with CAPACITY CodeListenerClosed. The code field of any other
// refusal is not a carrier code: REJECTED carries the application's own
// code (wire, D10), so an application that rejects with code 7 — the
// value of CodeListenerClosed — must not close the shared trunk to every
// later OPEN. Before the fix it did (admit.go checked the code, not the
// status): the pool then dialed a new trunk for each OPEN, and in the
// detach churn (TestMuxDetachAfterLocalViewEnd_R1_9, which rejects with
// code 7) an accept-timeout session whose every new trunk's claimant
// timed out ended with ErrNoPath after NoPathGrace instead of
// ErrCapacity (sweep run 20261011-142409-5ae4). Each row refuses one
// OPEN view on the passive with the row's status and code 7, then asks
// the pool's usable rule for an OPEN and a JOIN of another session.
func TestOnlyCapacityListenerClosedBlocksOpens_R1_10(t *testing.T) {
	var zero [16]byte
	for _, tc := range []struct {
		name   string
		st     wire.AckStatus
		openOK bool // the trunk still takes OPENs after the refusal
	}{
		{"rejected with application code 7", wire.StatusRejected, true},
		{"capacity CodeListenerClosed", wire.StatusCapacity, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d, p := muxPair(t, nil)
				p.admit = func(s *muxSide, v *Conn, h wire.Header, _ []byte) {
					v.Refuse(v.Handle(), Answer{Type: wire.TypeOpenAck, Status: tc.st, Code: wire.CodeListenerClosed})
				}
				synctest.Wait()
				_, wait := d.openRaw(t, wire.TypeOpen, 9)
				est, err := wait()
				if err != nil {
					t.Fatalf("the refused view: %v, want its response", err)
				}
				if a, perr := wire.ParseOpenAck(est.Payload); perr != nil || a.Status != tc.st || a.Code != wire.CodeListenerClosed {
					t.Fatalf("stimulus: response %+v (%v), want status %v code %d", a, perr, tc.st, wire.CodeListenerClosed)
				}
				synctest.Wait()
				pl := NewPool(d.env, []Factory{{Name: "f0", Mux: true}})
				pl.trunks[0] = []*Conn{d.c}
				pl.mu.Lock()
				open := pl.pickLocked(0, wire.TypeData, zero, 5, nil)
				join := pl.pickLocked(0, wire.TypeData, mPassiveInst, 5, nil)
				pl.mu.Unlock()
				if (open == d.c) != tc.openOK {
					t.Fatalf("an OPEN after the refusal can use the trunk: %v, want %v", open == d.c, tc.openOK)
				}
				if join != d.c {
					t.Fatal("a JOIN cannot use the trunk after the refusal")
				}
			})
		})
	}
}
