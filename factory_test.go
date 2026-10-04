package rendr

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestFactoryMisbehaviour_L51: an embedder factory is untrusted (L51). A
// factory that returns (nil, nil), panics or calls runtime.Goexit cannot
// crash the process: every attempt fails, and Dial ends with ErrNoPath at
// NoPathGrace wrapping ErrNilConn or ErrFactoryPanic. A factory that ignores
// its context, and one that succeeds only after Runtime.Close, cannot hold
// Runtime.Close: it returns within 200 ms, the in-flight Dial returns
// net.ErrClosed, the stuck factory calls are counted in Status.Abandoned
// until they return, and a conn returned late is closed exactly once.
func TestFactoryMisbehaviour_L51(t *testing.T) {
	cases := []struct {
		name string
		beh  rendrtest.DialBehavior
		want error // nil: the factory blocks; the Dial is still in flight at Close
	}{
		{"nil conn and nil error", rendrtest.DialNilNil, carrier.ErrNilConn},
		{"panic", rendrtest.DialPanic, carrier.ErrFactoryPanic},
		{"Goexit", rendrtest.DialGoexit, carrier.ErrFactoryPanic},
		{"ignores ctx", rendrtest.DialHangForever, nil},
		{"succeeds after Close", rendrtest.DialLateSuccess, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				grace := time.Second // the failing factories: ErrNoPath at the grace
				if tc.want == nil {
					grace = 5 * time.Second // the blocking ones: the Dial is still in flight at Close
				}
				ov := &testhooks.Overrides{NoPathGrace: grace, DialTimeout: 300 * time.Millisecond}
				e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
				link := e.links[0]
				link.SetDial(tc.beh)
				tc2 := newTrackedConns(false)
				p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{tc2.wrap("a", link.Dial)}})
				if err != nil {
					t.Fatal(err)
				}
				res := e2eDialAsync(context.Background(), p, DialOptions{})
				if tc.want != nil {
					r := <-res
					if r.c != nil || !errors.Is(r.err, ErrNoPath) || !errors.Is(r.err, tc.want) || r.at < time.Second {
						t.Fatalf("Dial = %v, %v after %v; want ErrNoPath wrapping %v at the grace", r.c, r.err, r.at, tc.want)
					}
					if n := link.Stats().Dials; n < 2 {
						t.Fatalf("%d factory calls: the slot did not retry", n)
					}
				} else {
					time.Sleep(time.Second) // several attempts time out on the hanging factory
				}
				start := time.Now()
				e.d.Close()
				if el := time.Since(start); el > 200*time.Millisecond {
					t.Fatalf("Runtime.Close took %v with a misbehaving factory", el)
				}
				if tc.want != nil {
					synctest.Wait()
					if st := e.d.Status(); st.Abandoned != 0 {
						t.Fatalf("abandoned %d", st.Abandoned)
					}
					e.close()
					return
				}
				if r := <-res; r.c != nil || !errors.Is(r.err, net.ErrClosed) {
					t.Fatalf("in-flight Dial at Close: %v, %v", r.c, r.err)
				}
				calls := link.Stats().Dials
				time.Sleep(2 * e.d.eff.timing.AbandonWait) // past every stuck call's abandonment bound
				synctest.Wait()
				if n := e.d.Status().Abandoned; n != int(calls) || calls < 2 {
					t.Fatalf("abandoned %d, want every one of the %d factory calls stuck in the embedder", n, calls)
				}
				link.Release() // the calls return: an error, or a conn after the caller gave up
				synctest.Wait()
				time.Sleep(time.Second) // a late conn's close drains at most 1 s
				synctest.Wait()
				if n := e.d.Status().Abandoned; n != 0 {
					t.Fatalf("abandoned %d after the factory calls returned", n)
				}
				if tc.beh == rendrtest.DialLateSuccess {
					if cs := tc2.closes(); len(cs) != int(calls) {
						t.Fatalf("%d late conns for %d calls", len(cs), calls)
					}
					tc2.requireClosedOnce(t)
				}
				e.close()
			})
		})
	}
}
