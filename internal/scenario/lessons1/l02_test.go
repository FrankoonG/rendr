package lessons1

import (
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestFinViaSecondCarrier_L02: carrier 1 silently drops the FIN (the Link
// removes the frame; the carrier itself stays up until the passive sees
// the fseq gap at the next frame and kills it). The passive's Read must not
// return io.EOF on carrier 1's death; the FIN is re-sent at the same
// offset on carrier 2 and only its arrival there yields io.EOF after
// exactly the bytes written.
func TestFinViaSecondCarrier_L02(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 1 << 20
		f := newFixture(t, opts{}, "a")
		l := f.link("a")
		l.SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})

		type result struct {
			err error
			at  time.Time
		}
		read := make(chan result, 1)
		go func() {
			err := readStream(pc, n, 1, nil)
			read <- result{err, time.Now()}
		}()
		runWithin(t, time.Minute, "writes", func() error { _, err := writeStream(dc, n, 1, 64<<10); return err })
		eventually(t, 10*time.Second, "everything acknowledged", func() bool { return dc.Status().AckedBytes == n })
		l.DropNextFrame(rendrtest.Up, rendrtest.FrameFin)
		if err := dc.CloseWrite(); err != nil {
			t.Fatal(err)
		}

		// Carrier 1 dies on the passive's fseq check; its death is no EOF.
		eventually(t, 30*time.Second, "carrier 1 dead on the passive", func() bool { return len(deadCarriers(pc.Status())) == 1 })
		select {
		case r := <-read:
			t.Fatalf("passive Read returned %v when carrier 1 died, before any FIN arrived", r.err)
		default:
		}
		r := recv(t, read, time.Minute, "the passive stream")
		if r.err != nil {
			t.Fatalf("passive stream: %v", r.err)
		}
		synctest.Wait() // the passive actor applies the SCHED carried with the FIN

		// Stimulus: one FIN frame dropped on a session carrier; the dialer
		// wrote the FIN twice at offset n, once per carrier.
		if got := l.Stats().Session.FramesDropped; got != 1 {
			t.Fatalf("FIN frames dropped: %d, want 1", got)
		}
		dt := f.wire.sessionTaps(dialerSide, "a")
		pt := f.wire.sessionTaps(passiveSide, "a")
		if len(dt) != 2 || len(pt) != 2 {
			t.Fatalf("session carriers: %d dialer taps, %d passive taps, want 2 and 2", len(dt), len(pt))
		}
		for i, tp := range dt {
			fins := tp.sent(wire.TypeFin)
			if len(fins) != 1 || fins[0].off != n {
				t.Fatalf("carrier %d carried FINs %+v, want one at %d", i+1, fins, n)
			}
		}
		// The passive read exactly one FIN, on carrier 2, and returned io.EOF
		// only after it.
		if fins := pt[0].recv(wire.TypeFin); len(fins) != 0 {
			t.Fatalf("the passive read a FIN on carrier 1: %+v", fins)
		}
		fins := pt[1].recv(wire.TypeFin)
		if len(fins) != 1 || fins[0].off != n {
			t.Fatalf("FINs read on carrier 2: %+v, want one at %d", fins, n)
		}
		if r.at.Before(fins[0].at) {
			t.Fatalf("io.EOF at %v, before the FIN arrived on carrier 2 at %v", r.at, fins[0].at)
		}
		if d := deadCarriers(pc.Status()); len(d) != 1 || d[0].DeathCause != rendr.CauseProtocolViolation || uint32(d[0].ID) != pt[0].cid.Load() {
			t.Fatalf("passive's dead carriers %+v, want carrier 1 killed for the fseq gap", d)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := c.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) || st.DeliveredBytes+st.TxBytes != n {
				t.Fatalf("%v: %+v", st.Role, st)
			}
		}
		if err := pc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readEOF(t, dc, "dialer")
		finish(t, dc, pc)
		f.close()
	})
}

// TestKillWithoutFinBlocksRead_L02: the only carrier is killed with no FIN
// and the factory refuses every redial. Both ends' Reads stay blocked for
// the whole no-path grace (no io.EOF, no error); then each fails with
// ErrNoPath — the dialer at NoPathGrace after the death, the passive at
// its PassiveRetain — which is neither io.EOF nor a timeout.
func TestKillWithoutFinBlocksRead_L02(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			n      = 256 << 10
			grace  = 2 * time.Second
			idle   = 2 * time.Second
			dead   = 4 * time.Second // DeadMax default
			slack  = time.Second
			retain = grace + idle + dead + slack // PassiveRetain (plan §3.6)
		)
		ov := testhooks.Overrides{NoPathGrace: grace, PingIdle: idle, RetainSlack: slack}
		f := newFixture(t, opts{ov: ov}, "a")
		l := f.link("a")
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		runWithin(t, time.Minute, "data", func() error {
			if _, err := writeStream(dc, n, 1, 32<<10); err != nil {
				return err
			}
			_, err := io.CopyN(rendrtest.NewVerifier(1, n), pc, n)
			return err
		})

		type result struct {
			n   int
			err error
			at  time.Time
		}
		blocked := func(c *rendr.Conn) <-chan result {
			ch := make(chan result, 1)
			go func() {
				k, err := c.Read(make([]byte, 1))
				ch <- result{k, err, time.Now()}
			}()
			return ch
		}
		dr, pr := blocked(dc), blocked(pc)
		synctest.Wait()
		l.SetRefuse(true)
		killedAt := time.Now()
		if k := l.Kill(); k != 1 {
			t.Fatalf("Kill hit %d carriers, want the session's", k)
		}

		// Both Reads stay blocked inside the grace; both ends are in a
		// no-path episode and the dialer keeps redialling.
		time.Sleep(grace - time.Millisecond)
		for _, x := range []struct {
			c  *rendr.Conn
			ch <-chan result
		}{{dc, dr}, {pc, pr}} {
			select {
			case r := <-x.ch:
				t.Fatalf("%v Read returned (%d, %v) inside the grace", x.c.Status().Role, r.n, r.err)
			default:
			}
			if st := x.c.Status(); !st.InNoPath || st.NoPathEpisodes != 1 || st.State != rendr.StateOpen {
				t.Fatalf("%v inside the grace: %+v", st.Role, st)
			}
		}
		if s := l.Stats(); s.Session.Killed != 1 || s.DialFailures == 0 {
			t.Fatalf("link stats %+v: want one killed session carrier and refused redials", s)
		}

		// ErrNoPath, not EOF, not a timeout: the dialer at grace, the passive
		// at its retention.
		check := func(r result, role string, at time.Duration) {
			var ne net.Error
			if r.n != 0 || !errors.Is(r.err, rendr.ErrNoPath) || r.err == io.EOF || !errors.As(r.err, &ne) || ne.Timeout() {
				t.Fatalf("%s Read: (%d, %v), want ErrNoPath", role, r.n, r.err)
			}
			if got := r.at.Sub(killedAt); got < at || got > at+100*time.Millisecond {
				t.Fatalf("%s Read failed %v after the kill, want %v", role, got, at)
			}
		}
		check(recv(t, dr, retain, "the dialer's blocked Read"), "dialer", grace)
		check(recv(t, pr, retain, "the passive's blocked Read"), "passive", retain)
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := c.Status(); st.State != rendr.StateEnded || !errors.Is(st.Err, rendr.ErrNoPath) || st.DeliveredBytes+st.TxBytes != n {
				t.Fatalf("%v after the grace: %+v", st.Role, st)
			}
		}
		f.close()
	})
}
