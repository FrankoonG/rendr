package lessons2

import (
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestControlCreditWhenWindowFull_L16 (L16: control frames keep their own
// credit). The passive application never reads, so the dialer's window
// fills to 100% — every byte it may send is unacknowledged — and the
// application's Write blocks. With that Write still blocked:
//
//   - a forced switch (the active carrier is killed) completes at once: the
//     new carrier JOINs, the whole window is replayed on it without any new
//     credit, and the death migration is counted on both ends;
//   - the switch's SCHED is written and echoed (SchedEchoed == SchedEpoch on
//     the dialer, the same epoch applied on the passive);
//   - CloseWrite, respectively Close, returns at once, the blocked Write
//     returns (window, net.ErrClosed), and exactly one FIN — at the end of
//     the window — ever crosses the wire.
//
// The passive then reads the window intact followed by io.EOF, and the
// session ends cleanly on both sides.
func TestControlCreditWhenWindowFull_L16(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(*rendr.Conn) error
	}{
		{"CloseWrite", (*rendr.Conn).CloseWrite},
		{"Close", (*rendr.Conn).Close},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const win = 256 << 10
				cfg := rendr.Config{Window: win}
				e := newEnv(t, cfg, cfg, nil)
				a := e.path("a", time.Millisecond)
				b := e.path("b", time.Millisecond)
				dc, pc := e.open(e.peer(a, b), rendr.DialOptions{})
				act, ok := activeOf(dc.Status())
				if !ok {
					t.Fatalf("no active carrier after Dial: %+v", dc.Status())
				}
				from, to := a, b
				if act.Name == "b" {
					from, to = b, a
				}

				// Load: the window fills to 100% and the Write blocks.
				const seed = 16
				payload := prngBytes(seed, win+64<<10)
				wres := goOp(func() (int, error) { return dc.Write(payload) })
				waitFor(t, 5*time.Second, time.Millisecond, "window full", func() bool {
					return dc.Status().TxBytes == win && pc.Status().RxBytes == win
				})
				if st, ps := dc.Status(), pc.Status(); st.AckedBytes != 0 || ps.DeliveredBytes != 0 || !running(wres) {
					t.Fatalf("window not held full: dialer %+v, passive delivered %d, Write returned %v", st, ps.DeliveredBytes, !running(wres))
				}
				sched0 := len(a.sent(wire.TypeSched)) + len(b.sent(wire.TypeSched))
				epoch0 := dc.Status().SchedEpoch

				// The forced switch: the active carrier dies.
				if n := from.link.Kill(); n < 1 {
					t.Fatalf("Kill on %s killed %d carriers", from.name, n)
				}
				took := waitFor(t, time.Second, time.Millisecond, "forced switch", func() bool {
					st := dc.Status()
					c, ok := activeOf(st)
					return ok && c.Name == to.name && st.SchedEpoch > epoch0 && st.SchedEchoed == st.SchedEpoch &&
						pc.Status().SchedEpoch == st.SchedEpoch
				})
				t.Logf("switch %s → %s completed in %v with the window full", from.name, to.name, took)
				waitFor(t, 5*time.Second, time.Millisecond, "window replayed", func() bool {
					return dc.Status().RetransmittedBytes == win
				})
				if !running(wres) {
					t.Fatal("the application Write returned during the switch")
				}
				st, ps := dc.Status(), pc.Status()
				if st.AckedBytes != 0 || ps.DeliveredBytes != 0 || ps.RxBytes != win || st.Migrations.Death != 1 || ps.Migrations.Death != 1 {
					t.Fatalf("after the switch: dialer %+v, passive %+v", st, ps)
				}
				if n := len(a.sent(wire.TypeSched)) + len(b.sent(wire.TypeSched)); n <= sched0 {
					t.Fatalf("no SCHED written with the window full (%d before, %d after)", sched0, n)
				}
				death := false
				for _, f := range to.sent(wire.TypeSched) {
					death = death || wire.SchedCause(f.flags&wire.SchedCauseMask) == wire.SchedDeath
				}
				if !death {
					t.Fatalf("no SCHED(death) written on the new carrier: %+v", to.sent(wire.TypeSched))
				}
				if got := from.link.Stats().Session.Killed; got < 1 {
					t.Fatalf("stimulus: %d session carriers killed on %s", got, from.name)
				}

				// CloseWrite / Close returns at once; the blocked Write returns.
				start := time.Now()
				if err := tc.close(dc); err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if el := time.Since(start); el != 0 {
					t.Fatalf("%s took %v with the window full", tc.name, el)
				}
				w := await(t, wres, 10*time.Millisecond, "blocked Write after "+tc.name)
				if w.n != win || !errors.Is(w.err, net.ErrClosed) {
					t.Fatalf("blocked Write = (%d, %v), want (%d, net.ErrClosed)", w.n, w.err, win)
				}
				waitFor(t, time.Second, time.Millisecond, "FIN on the wire", func() bool {
					return len(a.sent(wire.TypeFin))+len(b.sent(wire.TypeFin)) > 0
				})

				// The passive reads the window intact, then io.EOF.
				pc.SetReadDeadline(time.Now().Add(10 * time.Second))
				if err := rendrtest.NewVerifier(seed, win).ReadAll(pc); err != nil {
					t.Fatalf("passive stream: %v", err)
				}
				switch tc.name {
				case "CloseWrite":
					endClean(t, dc, pc)
				default:
					if err := pc.Close(); err != nil {
						t.Fatal(err)
					}
					for _, c := range []*rendr.Conn{dc, pc} {
						waitEnded(t, c, 30*time.Second)
						if st := c.Status(); st.Err != io.EOF {
							t.Fatalf("%v ended with %v, want a clean end", st.Role, st.Err)
						}
					}
				}
				fins := append(a.sent(wire.TypeFin), b.sent(wire.TypeFin)...)
				if len(fins) != 1 || fins[0].off != win {
					t.Fatalf("FINs on the wire: %+v, want exactly one at offset %d", fins, win)
				}
				e.close()
			})
		})
	}
}
