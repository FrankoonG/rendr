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
//   - a switch completes without waiting for credit: forced (the active
//     carrier is killed: the new carrier JOINs, a death migration) or
//     planned (the active path's RTT rises 50-fold: a quality switch after
//     the selector's dwell); either way the whole window is replayed on the
//     new carrier without any new credit, and the migration is counted on
//     both ends; a planned switch's predecessor, whose spans are never
//     acknowledged, sends CLOSE exactly RetireGrace after the switch and
//     ends as retired, not as a death;
//   - the switch's SCHED is written and echoed (SchedEchoed == SchedEpoch on
//     the dialer, the same epoch applied on the passive);
//   - CloseWrite, respectively Close, returns at once, the blocked Write
//     returns (window, net.ErrClosed), and exactly one FIN — at the end of
//     the window — ever crosses the wire.
//
// The passive then reads the window intact followed by io.EOF, and the
// session ends cleanly on both sides.
func TestControlCreditWhenWindowFull_L16(t *testing.T) {
	for _, sw := range []struct {
		name    string
		planned bool
	}{
		{"forced switch", false},
		{"planned switch", true},
	} {
		for _, tc := range []struct {
			name  string
			close func(*rendr.Conn) error
		}{
			{"CloseWrite", (*rendr.Conn).CloseWrite},
			{"Close", (*rendr.Conn).Close},
		} {
			t.Run(sw.name+", "+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					windowFullSwitch(t, sw.planned, tc.name, tc.close)
				})
			})
		}
	}
}

// windowFullSwitch is one run of TestControlCreditWhenWindowFull_L16.
func windowFullSwitch(t *testing.T, planned bool, closeName string, closeFn func(*rendr.Conn) error) {
	const (
		win         = 256 << 10
		oneWay      = time.Millisecond
		slowOneWay  = 50 * oneWay     // the planned switch: the active path's new delay
		retireGrace = 2 * time.Second // RetireGrace (the default, set explicitly)
	)
	cfg := rendr.Config{Window: win, RetireGrace: retireGrace}
	e := newEnv(t, cfg, cfg, nil)
	a := e.path("a", oneWay)
	b := e.path("b", oneWay)
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

	// The switch: the active carrier dies, or its path slows down.
	cause, want := wire.SchedDeath, rendr.MigrationCounts{Death: 1}
	within := time.Second
	if planned {
		cause, want = wire.SchedQuality, rendr.MigrationCounts{Quality: 1}
		within = 30 * time.Second // probe samples, then the selector's dwell
		from.link.SetDelay(slowOneWay, 0)
	} else if n := from.link.Kill(); n < 1 {
		t.Fatalf("Kill on %s killed %d carriers", from.name, n)
	}
	took := waitFor(t, within, time.Millisecond, "switch", func() bool {
		st := dc.Status()
		c, ok := activeOf(st)
		return ok && c.Name == to.name && st.SchedEpoch > epoch0 && st.SchedEchoed == st.SchedEpoch &&
			pc.Status().SchedEpoch == st.SchedEpoch
	})
	t.Logf("switch %s → %s completed %v after the stimulus with the window full", from.name, to.name, took)
	waitFor(t, 5*time.Second, time.Millisecond, "window replayed", func() bool {
		return dc.Status().RetransmittedBytes == win
	})
	if !running(wres) {
		t.Fatal("the application Write returned during the switch")
	}
	st, ps := dc.Status(), pc.Status()
	if st.AckedBytes != 0 || ps.DeliveredBytes != 0 || ps.RxBytes != win || st.Migrations != want || ps.Migrations != want {
		t.Fatalf("after the switch: dialer %+v, passive %+v; want migrations %+v on both ends", st, ps, want)
	}
	if n := len(a.sent(wire.TypeSched)) + len(b.sent(wire.TypeSched)); n <= sched0 {
		t.Fatalf("no SCHED written with the window full (%d before, %d after)", sched0, n)
	}
	sent := false
	for _, f := range to.sent(wire.TypeSched) {
		sent = sent || wire.SchedCause(f.flags&wire.SchedCauseMask) == cause
	}
	if !sent {
		t.Fatalf("no SCHED with cause %d written on the new carrier: %+v", cause, to.sent(wire.TypeSched))
	}
	if planned {
		// The selector's evidence, the probes of the old path, saw the delay.
		if d := from.link.Stats().Probe.MaxDelay; d < slowOneWay {
			t.Fatalf("stimulus: probe carriers of %s delayed by at most %v", from.name, d)
		}
		// The predecessor's spans are never acknowledged: it retires with
		// CLOSE exactly RetireGrace after the switch, and nobody died.
		migs := e.dev.of(rendr.EventMigration)
		if len(migs) != 1 || migs[0].Cause != rendr.CauseQuality {
			t.Fatalf("migration events: %+v", migs)
		}
		retireAt := migs[0].Time.Add(retireGrace)
		waitFor(t, 2*retireGrace, time.Millisecond, "predecessor's CLOSE", func() bool { return len(from.sent(wire.TypeClose)) > 0 })
		if cl := from.sent(wire.TypeClose); len(cl) != 1 || !cl[0].at.Equal(retireAt) {
			t.Fatalf("predecessor's CLOSE frames %+v, want one at the switch + RetireGrace (%v)", cl, retireAt)
		}
		waitFor(t, time.Second, time.Millisecond, "predecessor ended", func() bool { return len(deadOf(dc.Status(), from.name)) == 1 })
		if st := dc.Status(); deadOf(st, from.name)[0].DeathCause != rendr.CauseRetired || st.Migrations != want || pc.Status().Migrations != want {
			t.Fatalf("after the predecessor retired: dialer %+v, passive migrations %+v", st, pc.Status().Migrations)
		}
		if !running(wres) {
			t.Fatal("the application Write returned when the predecessor retired")
		}
	} else if got := from.link.Stats().Session.Killed; got < 1 {
		t.Fatalf("stimulus: %d session carriers killed on %s", got, from.name)
	}

	// CloseWrite / Close returns at once; the blocked Write returns.
	start := time.Now()
	if err := closeFn(dc); err != nil {
		t.Fatalf("%s: %v", closeName, err)
	}
	if el := time.Since(start); el != 0 {
		t.Fatalf("%s took %v with the window full", closeName, el)
	}
	w := await(t, wres, 10*time.Millisecond, "blocked Write after "+closeName)
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
	switch closeName {
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
}
