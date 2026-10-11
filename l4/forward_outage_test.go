package l4

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestForwardTargetResetDuringOutage_L47 (L47, A8.3, plan §5; WP13 B-1):
// the passive's end decision while the session has no carrier — the case
// rendr exists for — reaches the dialer with its code. The only link is
// killed and refuses new carriers; on the passive then either the egress
// Forward's target resets (AbortReset) or the application aborts with an
// application code. The RST has no lane to take, the session ends and its
// tombstone keeps the code; once the link accepts again, the dialer's
// rejoin is answered JOIN_ACK(UNKNOWN_SESSION) with that code (OptEndCode),
// so the dialer ends with *AbortError{code, Remote} — the ingress Forward
// resets its client — instead of ErrSessionLost. Before the fix it ended
// with "session lost: JOIN_ACK UNKNOWN_SESSION" on every run.
func TestForwardTargetResetDuringOutage_L47(t *testing.T) {
	for _, tc := range []struct {
		name string
		want rendr.AbortCode
	}{
		{"target reset through Forward", AbortReset},
		{"application abort", testAbort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newWorld(t, worldOpts{})
				d, p := w.open(rendr.DialOptions{})
				cli, srv := rendrtest.TargetPipe(0)
				in := forwardAsync(context.Background(), d, srv)
				l := w.links[0]
				l.SetRefuse(true)
				if n := l.Kill(); n == 0 {
					t.Fatal("stimulus: no carrier killed")
				}
				time.Sleep(50 * time.Millisecond) // both ends lost the carrier: a no-path episode
				var tg *rendrtest.Target
				if tc.want == AbortReset {
					tg = rendrtest.NewTarget(rendrtest.TargetRSTAfter(1<<10), 0)
					tconn, err := tg.Dial(context.Background(), kitTarget)
					if err != nil {
						t.Fatal(err)
					}
					out := <-forwardAsync(context.Background(), p, tconn)
					if !isReset(out.LocalErr) || out.Clean {
						t.Fatalf("stimulus: egress Forward %+v, want the target's reset", out)
					}
				} else {
					p.Abort(testAbort, "outage")
				}
				waitDone(t, p, time.Second) // ended without a lane for its RST
				if st := w.p.Status(); st.Sessions.Tombstones != 1 {
					t.Fatalf("stimulus: passive %+v, want the ended session's tombstone", st.Sessions)
				}
				l.SetRefuse(false)
				var r ForwardResult
				select {
				case r = <-in:
				case <-time.After(time.Minute):
					t.Fatalf("the ingress Forward did not end: %+v", d.Status())
				}
				if code, remote, ok := abortCode(r.SessionErr); !ok || code != tc.want || !remote || r.Clean {
					t.Fatalf("ingress Forward %+v, want *AbortError{%d, Remote}", r, tc.want)
				}
				if _, _, err := readAll(cli); !isReset(err) {
					t.Fatalf("client end %v, want a reset (never io.EOF)", err)
				}
				waitDone(t, d, time.Minute)
				if tg != nil {
					tg.Close()
				}
				w.shutdown()
			})
		})
	}
}
