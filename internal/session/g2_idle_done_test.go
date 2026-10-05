package session

import (
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"
)

// TestIdleAfterDoneIsClean_L05 (design §0.14 B4, extended at the close-b
// integration): IdleTimeout is shorter than both the grace and the Linger,
// counted from the last application commit. The peer ended cleanly, its
// DONE was lost with the dying carrier and every redial is refused. Once
// our DONE was sent the idle rule no longer applies (Linger bounds the wait
// for the peer's DONE): the session ends with io.EOF at the episode expiry,
// not with ErrIdleTimeout and RST(Idle). Control (before-done): a session
// whose DONE was not sent still ends with ErrIdleTimeout.
func TestIdleAfterDoneIsClean_L05(t *testing.T) {
	const grace, linger, idle = 15 * time.Second, 30 * time.Second, 10 * time.Second
	t.Run("done", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			w.a.p.Grace, w.a.p.Linger, w.a.p.IdleTimeout = grace, linger, idle
			l1 := w.link("p1")
			a, b := w.open(ModeSelector, nil, l1)
			l1.SetRefuse(true)
			g2DialerWaits(t, l1, a, b, 31)
			start := g2EpisodeStart(t, a)
			acDone(t, a, 40*time.Second)
			g2CheckExpiry(t, w.a, a, start, grace, linger, io.EOF)
		})
	})
	t.Run("before-done", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			w.a.p.Grace, w.a.p.Linger, w.a.p.IdleTimeout = grace, linger, idle
			l1 := w.link("p1")
			a, b := w.open(ModeSelector, nil, l1)
			acHalfCloseSettled(t, a, b, g2N, 51)
			l1.SetRefuse(true)
			if l1.Kill() != 1 {
				t.Fatal("no carrier killed (stimulus)")
			}
			acDone(t, a, 40*time.Second)
			if st := a.Status(); !errors.Is(st.Err, ErrIdleTimeout) {
				t.Fatalf("end %v, want ErrIdleTimeout: our DONE was not sent", st.Err)
			}
			if sent, _ := g2Done(a); sent {
				t.Fatal("our DONE was sent in the before-done control")
			}
		})
	})
}
