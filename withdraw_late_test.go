package rendr

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// gatedHelloConn delivers its first Write (the hello: PREFACE ‖ OPEN) at
// once but returns it only when gate is closed, ignoring every deadline:
// the hello writer preempted after the passive read the OPEN.
type gatedHelloConn struct {
	net.Conn
	gate  <-chan struct{}
	first atomic.Bool
}

func (c *gatedHelloConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.first.CompareAndSwap(false, true) {
		<-c.gate
	}
	return n, err
}

// TestDialCancelAfterHelloReturnLate_L49 (L49, R1-4; WP13 A-1, the I3
// racing-Confirm failure): a Dial cancelled after the passive admitted its
// OPEN — and, in one row, Confirmed it — while the dialer's hello Write
// has delivered its bytes but returns only 5 ms after the cancellation.
// The Dial returns the context error within 200 ms, and the passive learns
// the withdrawal within 1 s: the Confirmed Conn's Read returns
// *AbortError{AbortWithdrawn}; an unconfirmed session ends and its Confirm
// returns ErrSessionLost. Before the fix no RST followed the OPEN and the
// passive kept the session until PassiveRetain (ErrNoPath after 34 s).
func TestDialCancelAfterHelloReturnLate_L49(t *testing.T) {
	for _, confirm := range []bool{true, false} {
		name := "pending"
		if confirm {
			name = "confirmed"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
				gate := make(chan struct{})
				var gateOnce sync.Once
				release := func() { gateOnce.Do(func() { close(gate) }) }
				t.Cleanup(release) // a failed test still ends its bubble
				l := e.links[0]
				p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: l.Name(), Dial: func(ctx context.Context) (net.Conn, error) {
					c, err := l.Dial(ctx)
					if c == nil {
						return nil, err
					}
					return &gatedHelloConn{Conn: c, gate: gate}, err
				}}}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				res := e2eDialAsync(ctx, p, DialOptions{})
				pc, err := e.ln.Accept(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				confirmed := make(chan *Conn, 1)
				if confirm {
					go func() {
						c, _ := pc.Confirm()
						confirmed <- c
					}()
				}
				synctest.Wait() // the passive admitted (and confirmed) the OPEN; the hello Write has not returned
				cancel()
				time.AfterFunc(5*time.Millisecond, release)
				t0 := time.Now()
				if r := <-res; r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
					t.Fatalf("Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
				}
				if confirm {
					sc := <-confirmed
					if sc == nil {
						t.Fatal("stimulus: Confirm failed before the cancellation")
					}
					var ae *AbortError
					if _, err := sc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortWithdrawn || !ae.Remote || time.Since(t0) > time.Second {
						t.Fatalf("the Confirmed passive end of a withdrawn session: %v after %v", err, time.Since(t0))
					}
				} else {
					select {
					case <-pc.s.Done():
					case <-time.After(time.Second):
						t.Fatal("the passive did not learn the withdrawal within 1 s")
					}
					if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) {
						t.Fatalf("Confirm after the withdrawal: %v", err)
					}
				}
				synctest.Wait()
				e.close()
			})
		})
	}
}
