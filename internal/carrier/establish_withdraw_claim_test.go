package carrier

import (
	"context"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestWithdrawalClaimsCloseBeforeHandshakeLeaves_L49 (R1-4, L49; WP13
// review): a withdrawal decided while the handshake is still inside a conn
// call sends RST(withdrawn) after the complete first flight even when the
// handshake leaves the conn — finish, its own close, join — between the
// withdrawal's decision and the start of its close: an OPEN_ACK that a
// racing Confirm sent ends the response read on its own, so the handshake
// does not need the withdrawal's close to leave. The withdrawal claims the
// close in the same critical section in which it decides (abortDecide),
// so the handshake's code-free close loses to it. The rows: the first
// flight written by the hello writer, and by a DialEarly factory (no
// writer). The test drives the interleaving through the two steps of abort
// (the decision, then the close it decided) and the handshake's real exit
// (leave), so it is deterministic. Before the fix the decision released
// the lock unclaimed, the handshake's close won, and the conn closed with
// no RST: the passive kept the Confirmed, withdrawn session until
// PassiveRetain (the pool's TestDialCancelAfterAccept_L49/racing_Confirm
// failure, run 20261011-051624-343d).
func TestWithdrawalClaimsCloseBeforeHandshakeLeaves_L49(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dialEarly bool
	}{
		{"hello writer", false},
		{"DialEarly", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env, _ := phEnvs()
				a, b := net.Pipe()
				t.Cleanup(func() { b.Close() })
				go io.Copy(io.Discard, b) // the passive reads everything and never answers
				rec := &efRec{Conn: a}
				first := env.Presets.firstFseq()
				pre := make([]byte, wire.PrefaceLen)
				wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: env.Local, CarrierID: 1})
				hello := wire.AppendFrame(pre, wire.Header{Type: wire.TypeOpen, Fseq: first, Handle: wire.SessionHandle}, openPayload(0))
				ctx, cancel := context.WithCancelCause(context.Background())
				cancel(ErrWithdrawn)
				g := newHsGuard(ctx, env, rec, tc.dialEarly)
				g.rstOpen, g.first = true, first
				if tc.dialEarly {
					if _, err := rec.Write(hello); err != nil { // the factory's PREFACE ‖ OPEN
						t.Fatalf("first flight: %v", err)
					}
				} else {
					g.startHello(hello, false)
					<-g.wdone // the hello Write returned: the first flight is complete
				}

				closeConn := g.abortDecide() // the withdrawal is decided ...
				start := time.Now()
				if !g.leave(false) { // ... and the handshake leaves before its close begins
					t.Fatal("leave: the handshake did not see the abort")
				}
				if d := time.Since(start); d != 0 {
					t.Fatalf("the handshake left %v after the withdrawal, want at once", d)
				}
				closeConn()
				time.Sleep(env.Timing.withDefaults().AbandonWait + 3*drainMax) // past every bound the close armed
				synctest.Wait()

				fs, rest := efFrames(t, rec.bytes()[wire.PrefaceLen:])
				if rest != 0 || len(fs) != 2 || fs[0].Type != wire.TypeOpen || fs[0].Fseq != first || fs[1].Type != wire.TypeRst || fs[1].Fseq != first+1 {
					t.Fatalf("after the PREFACE: %d frames (+%d bytes) %+v, want OPEN at %d and RST(withdrawn) at %d", len(fs), rest, fs, first, first+1)
				}
				if r, err := wire.ParseRst(fs[1].Payload); err != nil || r.Code != wire.RstWithdrawn {
					t.Fatalf("RST %+v %v, want code withdrawn", r, err)
				}
				if _, err := a.Write([]byte{0}); err == nil {
					t.Fatal("the conn is still open")
				}
				if env.Abandon.Len() != 0 {
					t.Fatalf("abandoned %d", env.Abandon.Len())
				}
			})
		})
	}
}
