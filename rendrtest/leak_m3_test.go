package rendrtest

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestAssertNoLeakSeesParkedSession (M3 design Revision 1, R1-24): a
// session that never ends while parked holds no goroutine, no carrier and
// no timer, so only the session registry shows it. The leak check fails on
// a live session (reporting the parked ones) with no goroutine in sight,
// passes once a live session ends within its settle bound, and passes
// with none. The gauges are bumped as the session actor does at Start and
// at park; the end-to-end row with a real parked session follows WP5.
func TestAssertNoLeakSeesParkedSession(t *testing.T) {
	lc := leakCheck{wait: 2 * time.Second}
	t.Run("parked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &fakeTB{TB: t}
			check := lc.assert(f)
			testhooks.LiveSessions.Add(1)
			testhooks.ParkedSessions.Add(1)
			defer testhooks.LiveSessions.Add(-1)
			defer testhooks.ParkedSessions.Add(-1)
			check()
			msg := f.failures()
			m := leakReport.FindStringSubmatch(msg)
			if m == nil || m[2] != "0" || !strings.Contains(msg, "1 live session(s) (1 parked)") {
				t.Fatalf("the check passed or misreported a parked session: %q", msg)
			}
		})
	})
	t.Run("ends-within-bound", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &fakeTB{TB: t}
			check := lc.assert(f)
			testhooks.LiveSessions.Add(1)
			go func() {
				time.Sleep(500 * time.Millisecond)
				testhooks.LiveSessions.Add(-1)
			}()
			check()
			if msg := f.failures(); msg != "" {
				t.Fatalf("failed although the session ended within the bound: %q", msg)
			}
		})
	})
	t.Run("none", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &fakeTB{TB: t}
			lc.assert(f)()
			if msg := f.failures(); msg != "" {
				t.Fatalf("failed without a session: %q", msg)
			}
		})
	})
}
