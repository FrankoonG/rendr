package carrier

import (
	"context"
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPoolWaiterOlderDialFailure (M3-D18 amended by WP13, L22 and L20 at
// unit level): a claimant's failure counts for a coalesced waiter unless
// the claimant's dial timed out and began before the waiter's attempt; then
// the waiter goes round again at once and dials itself. The claimant's
// and the waiter's starts are separated in (virtual) time, which the
// scenario rows cannot control, so both conditions of the rule have a row
// that fails without them:
//   - "older timeout": the claimant's dial began 10 ms before the waiter's
//     attempt and timed out: the waiter dials itself and succeeds (the
//     rule; without it the waiter returns the older dial's timeout);
//   - "older refusal": the claimant's dial began 10 ms before the waiter's
//     attempt and failed without a timeout: the waiter returns that failure
//     with no dial of its own (mutant: an older dial's every failure sends
//     the waiter round);
//   - "same-time timeout": the claimant's dial began with the waiter's
//     attempt and timed out: the waiter returns that timeout with no dial
//     of its own (mutant: every timeout sends the waiter round).
func TestPoolWaiterOlderDialFailure(t *testing.T) {
	type row struct {
		name     string
		lag      time.Duration // the waiter's attempt starts this long after the claimant's dial
		dialErr  error         // every gated factory call's error (nil: honorHang until DialTimeout)
		dials    int32         // factory calls in all
		waiterOK bool          // the waiter's attempt succeeds (else it returns the claimant's error)
	}
	timeoutErr := os.ErrDeadlineExceeded // a timeout (Timeout() true) that is no context error
	for _, r := range []row{
		{name: "older timeout", lag: 10 * time.Millisecond, dials: 2, waiterOK: true},
		{name: "older refusal", lag: 10 * time.Millisecond, dialErr: errors.New("connection refused"), dials: 1},
		{name: "same-time timeout", dialErr: timeoutErr, dials: 1},
	} {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pt := newPoolT(t, nil, nil)
				gate := make(chan struct{})
				if r.dialErr != nil {
					pt.srv.setGate(gate)
					pt.srv.dialErr = r.dialErr
				} else {
					close(gate)
					pt.srv.honorHang = true // the first call waits for its DialTimeout
				}
				claimant := make(chan poolRes, 1)
				pt.goAttempt(context.Background(), wire.TypeOpen, 1, claimant)
				synctest.Wait()
				if pt.srv.dials.Load() != 1 || !pt.p.inFlight(0) {
					t.Fatal("the claimant's dial is not in flight (stimulus)")
				}
				if r.lag > 0 {
					time.Sleep(r.lag)
				}
				waiter := make(chan poolRes, 1)
				pt.goAttempt(context.Background(), wire.TypeOpen, 2, waiter)
				synctest.Wait()
				if st := pt.p.Stats(); st.Coalesced != 1 || pt.srv.dials.Load() != 1 {
					t.Fatalf("the second attempt did not wait for the claimant's dial: %+v, %d factory calls (stimulus)", st, pt.srv.dials.Load())
				}
				if r.dialErr != nil {
					close(gate) // the claimant's dial fails now
				}
				c := collect(t, claimant, 1)[0]
				if c.err == nil {
					t.Fatal("the claimant's dial succeeded (stimulus)")
				}
				if got := timedOut(c.err); got != (r.dialErr == nil || r.dialErr == timeoutErr) {
					t.Fatalf("the claimant failed with %v (timeout %v) (stimulus)", c.err, got)
				}
				w := collect(t, waiter, 1)[0]
				synctest.Wait()
				if r.waiterOK {
					if w.err != nil || !isOK(w.est) {
						t.Fatalf("the waiter: %v; want its own dial's carrier after the older dial's timeout", w.err)
					}
					pt.attach(w.est)
				} else if w.err == nil || w.err != c.err {
					t.Fatalf("the waiter: %v; want the claimant's failure %v", w.err, c.err)
				}
				if d := pt.srv.dials.Load(); d != r.dials {
					t.Fatalf("%d factory calls, want %d", d, r.dials)
				}
			})
		})
	}
}
