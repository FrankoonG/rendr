package carrier

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPoolFastPathErrorIsAView_L27 (m6 item rc5; L27): every error of a
// fast-path view (a view of an already started trunk) is marked
// EstablishError.View, with PrefaceOK as before (the session's cadence
// counts it as a refusal): the PREFACE exchange was the trunk's, at the
// trunk's dial, so it proves nothing about the path now and the session
// keeps the factory's failed mark. A claimant's own Establish error after
// its PREFACE exchange is no view's. Before rc5 the view errors were
// unmarked, and the fast-path OPENs of a dead path's trunks (race losers)
// cleared the factory's mark one by one as their trunks died, while the
// death steps set it again (TestMuxDgramMassRejoinAfterBlackhole_L27_L72's
// (d): 10–20 ringing snapshots against at most 6).
func TestPoolFastPathErrorIsAView_L27(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause Cause
		end   func(pt *poolT, trunk *Conn, cancel context.CancelCauseFunc)
	}{
		{"trunk died", CauseTransportError, func(_ *poolT, trunk *Conn, _ context.CancelCauseFunc) {
			trunk.KillTrunk(CauseTransportError, "test: the path died")
		}},
		{"withdrawn", CauseLocalClose, func(_ *poolT, _ *Conn, cancel context.CancelCauseFunc) { cancel(ErrWithdrawn) }},
		{"DialTimeout", CauseTransportError, func(pt *poolT, _ *Conn, _ context.CancelCauseFunc) {
			time.Sleep(pt.env.Timing.withDefaults().DialTimeout)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pt := newPoolT(t, nil, nil)
				est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
				if err != nil || !est1.Fresh {
					t.Fatalf("first attempt: %v", err)
				}
				pt.attach(est1)
				pt.srv.mu.Lock()
				pt.srv.holdViews = true // the passive admits the view and never answers it
				pt.srv.mu.Unlock()
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				ch := make(chan poolRes, 1)
				pt.goAttempt(ctx, wire.TypeOpen, 2, ch)
				synctest.Wait()
				if n := len(pt.srv.admitted()); n != 1 {
					t.Fatalf("premise: %d views admitted, want the fast path's", n)
				}
				tc.end(pt, est1.Conn, cancel)
				r := collect(t, ch, 1)[0]
				var ee *EstablishError
				if !errors.As(r.err, &ee) || ee.Stage != "response" || ee.Cause != tc.cause || !ee.PrefaceOK || !ee.View {
					t.Fatalf("fast path: %v (%+v), want a response-stage %v error with PrefaceOK and View", r.err, ee, tc.cause)
				}
				if st := pt.p.Stats(); st.FastPaths != 1 || pt.srv.dials.Load() != 1 {
					t.Fatalf("stats %+v, %d factory calls: want the one fast path", st, pt.srv.dials.Load())
				}
			})
		})
	}
	t.Run("check refused", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil || !est1.Fresh {
				t.Fatalf("first attempt: %v", err)
			}
			pt.attach(est1)
			synctest.Wait()
			errCheck := errors.New("test: the session's check refused the instance")
			_, err = pt.attemptCheck(context.Background(), pt.p, 0, wire.TypeOpen, 2, [16]byte{}, func(*wire.PrefaceAck) error { return errCheck })
			var ee *EstablishError
			if !errors.As(err, &ee) || !errors.Is(err, errCheck) || ee.Cause != CauseInstanceMismatch || !ee.PrefaceOK || !ee.View {
				t.Fatalf("fast path: %v (%+v), want the check's instance mismatch with PrefaceOK and View", err, ee)
			}
			if st := pt.p.Stats(); st.FastPaths != 1 || pt.srv.dials.Load() != 1 {
				t.Fatalf("stats %+v, %d factory calls: want the one fast path", st, pt.srv.dials.Load())
			}
		})
	})
	t.Run("a claimant's own error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			errCheck := errors.New("test: the session's check refused the instance")
			_, err := pt.attemptCheck(context.Background(), pt.p, 0, wire.TypeOpen, 1, [16]byte{}, func(*wire.PrefaceAck) error { return errCheck })
			var ee *EstablishError
			if !errors.As(err, &ee) || !errors.Is(err, errCheck) || !ee.PrefaceOK || ee.View {
				t.Fatalf("claimant: %v (%+v), want its own error after the PREFACE exchange, not a view's", err, ee)
			}
			synctest.Wait() // the passive ends the withdrawn carrier before the bubble does
		})
	})
}
