package carrier

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// lateHelloConn delivers its first Write at once and returns it late: the
// hello writer is preempted after the passive read the whole first flight
// (or, with DialEarly, the DATA frame) and before it records that. The
// withdrawal's SetDeadline(now) does not shorten the delay (a Write that
// ignores its deadline after the bytes left).
type lateHelloConn struct {
	net.Conn
	late      time.Duration
	delivered func() // runs once, between the delivery and the late return
	first     atomic.Bool
}

func (c *lateHelloConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.first.CompareAndSwap(false, true) {
		c.delivered()
		time.Sleep(c.late)
	}
	return n, err
}

// TestEstablishWithdrawAfterCompleteHelloReturnLate_L49 (R1-4, L49; WP13
// A-1): a withdrawal that arrives after the passive read the whole first
// flight but before the hello writer's Write returned still sends
// RST(withdrawn) right after that flight — at fseq first + 1, or first + 2
// after an early DATA frame, with or without DialEarly — because the
// withdrawal's goroutine waits (bounded by drainMax) for the hello writer
// before it decides. Establish still returns at the withdrawal: the
// withdrawal's goroutine, not the handshake, joins that writer. The
// passive carrier reads the RST and survives; nothing is abandoned.
// Before the fix the decision read the writer's flags before its Write
// returned and closed the conn without an RST: the passive kept the
// withdrawn session until PassiveRetain.
func TestEstablishWithdrawAfterCompleteHelloReturnLate_L49(t *testing.T) {
	for _, tc := range []struct {
		name      string
		early     int
		dialEarly bool
	}{
		{"no early data", 0, false},
		{"early data, Dial", 2048, false},
		{"early data, DialEarly", 2048, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const late = 5 * time.Millisecond
				envD, envP := phEnvs()
				a, b := net.Pipe()
				t.Cleanup(func() { b.Close() }) // a failed test still ends its bubble
				ep := &phFirst{}                // never answers: the OPEN stays pending
				var early []byte
				if tc.early > 0 {
					early = efEarly(tc.early)
				}
				pass := phPassive(envP, b, nil, func(h *Hello) {
					h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true, Early: len(early) > 0})
				})
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				var withdrawnAt time.Time
				rec := &efRec{Conn: a}
				wrap := func(nc net.Conn) net.Conn {
					return &lateHelloConn{Conn: nc, late: late, delivered: func() {
						withdrawnAt = time.Now()
						cancel(ErrWithdrawn)
					}}
				}
				f := Factory{Name: "late", Dial: func(context.Context) (net.Conn, error) { return wrap(rec), nil }}
				if tc.dialEarly {
					f.DialEarly = func(_ context.Context, first []byte) (net.Conn, error) {
						return wrap(newEfOrdered(rec, first)), nil // the hello writer's DATA Write returns late
					}
				}
				_, err := EstablishEarly(ctx, envD, f, envD.IDs.Next(), wire.TypeOpen, openPayload(0), early, nil)
				returned := time.Now()
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != CauseLocalClose || !errors.Is(err, ErrWithdrawn) {
					t.Fatalf("Establish: %v, want the withdrawal", err)
				}
				ph := <-pass
				if ph.err != nil {
					t.Fatalf("ReadHello: %v", ph.err)
				}
				time.Sleep(late) // the hello Write returns; the withdrawal's goroutine decides then
				synctest.Wait()
				first := envD.Presets.firstFseq()
				if len(early) > 0 {
					efCheckFlight(t, rec.bytes(), first, early, wire.TypeRst)
				} else {
					fs, rest := efFrames(t, rec.bytes()[wire.PrefaceLen:])
					if rest != 0 || len(fs) != 2 || fs[0].Type != wire.TypeOpen || fs[0].Fseq != first || fs[1].Type != wire.TypeRst || fs[1].Fseq != first+1 {
						t.Fatalf("after the PREFACE: %d frames (+%d bytes) %+v, want OPEN at %d and RST at %d", len(fs), rest, fs, first, first+1)
					}
				}
				if codes := ep.rstCodes(); len(codes) != 1 || codes[0] != wire.RstWithdrawn {
					t.Fatalf("the passive carrier read RST codes %v, want one RST(withdrawn) after the first flight", codes)
				}
				if withdrawnAt.IsZero() || returned.Sub(withdrawnAt) != 0 {
					t.Fatalf("Establish returned %v after the withdrawal, want at once", returned.Sub(withdrawnAt))
				}
				if dead, cause, detail, _ := ph.h.Conn.Death(); dead {
					t.Fatalf("the passive carrier died: %v %s", cause, detail)
				}
				ph.h.Conn.Kill(CauseLocalClose, "test end")
				hWait(t, ph.h.Conn)
				time.Sleep(envD.Timing.withDefaults().AbandonWait + 3*drainMax) // past every bound the withdrawal armed
				synctest.Wait()
				if envD.IDs.inUse() != 0 || envD.Abandon.Len() != 0 {
					t.Fatalf("IDs in use %d, abandoned %d", envD.IDs.inUse(), envD.Abandon.Len())
				}
			})
		})
	}
}
