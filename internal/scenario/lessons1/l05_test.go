package lessons1

import (
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestTerminalAckLossRecoveredOnNewCarrier_L05: the client's Close returns
// nil at once; the passive's terminal ACK (FIN_DELIVERED for the client's
// FIN) is lost and the carrier that carried it dies (the passive's own FIN
// right behind it shows the fseq gap). The session is not stuck: the
// client redials, and the terminal ACK, the passive's FIN and both DONEs
// cross the carrier that attached after the FIN; both ends finish cleanly
// (io.EOF) within a few round trips.
func TestTerminalAckLossRecoveredOnNewCarrier_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 256 << 10
		f := newFixture(t, opts{}, "a")
		l := f.link("a")
		l.SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		runWithin(t, time.Minute, "data", func() error {
			if _, err := writeStream(dc, n, 1, 32<<10); err != nil {
				return err
			}
			_, err := io.CopyN(rendrtest.NewVerifier(1, n), pc, n)
			return err
		})
		eventually(t, 10*time.Second, "data acknowledged", func() bool { return dc.Status().AckedBytes == n })
		synctest.Wait()

		// The next ACK the passive writes — FIN_DELIVERED for the client's
		// FIN — never arrives.
		l.DropNextFrame(rendrtest.Down, rendrtest.FrameAck)
		passive := make(chan error, 1)
		go func() {
			if k, err := pc.Read(make([]byte, 1)); k != 0 || err != io.EOF {
				passive <- fmt.Errorf("Read: (%d, %v)", k, err)
				return
			}
			passive <- pc.Close()
		}()
		closedAt := time.Now()
		if err := dc.Close(); err != nil || time.Since(closedAt) != 0 {
			t.Fatalf("client Close: %v after %v, want nil at once", err, time.Since(closedAt))
		}
		if err := recv(t, passive, 30*time.Second, "the passive's EOF and Close"); err != nil {
			t.Fatalf("passive: EOF then Close: %v", err)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := waitEnded(t, c, 5*time.Second); st.Err != io.EOF {
				t.Fatalf("%v ended with %v, want io.EOF", st.Role, st.Err)
			}
		}
		synctest.Wait()

		// Stimulus: the terminal ACK was dropped on carrier 1, which died.
		if got := l.Stats().Session.FramesDropped; got != 1 {
			t.Fatalf("frames dropped: %d, want the terminal ACK", got)
		}
		dt, pt := f.wire.sessionTaps(dialerSide, "a"), f.wire.sessionTaps(passiveSide, "a")
		if len(dt) != 2 || len(pt) != 2 {
			t.Fatalf("session carriers: %d / %d taps, want 2 and 2", len(dt), len(pt))
		}
		lost := 0
		for _, fr := range pt[0].sent(wire.TypeAck) {
			if fr.finDelivered() {
				lost++
			}
		}
		for _, fr := range dt[0].recv(wire.TypeAck) {
			if fr.finDelivered() {
				t.Fatalf("the client read a terminal ACK on carrier 1: %+v", fr)
			}
		}
		if lost != 1 {
			t.Fatalf("terminal ACKs written on carrier 1: %d, want the lost one", lost)
		}
		if d := deadCarriers(dc.Status()); len(d) < 1 || uint32(d[0].ID) != dt[0].cid.Load() || d[0].DeathCause != rendr.CauseProtocolViolation {
			t.Fatalf("client's dead carriers %+v, want carrier 1 killed for the fseq gap", d)
		}
		// Completion on carrier 2, which attached after the FIN.
		fin := dt[0].sent(wire.TypeFin)
		join := dt[1].sent(wire.TypeJoin)
		if len(fin) != 1 || len(join) != 1 || !join[0].at.After(fin[0].at) {
			t.Fatalf("FIN %+v on carrier 1, JOIN %+v on carrier 2: carrier 2 must attach after the FIN", fin, join)
		}
		var ackOn2, doneIn, doneOut bool
		for _, fr := range dt[1].recv(wire.TypeAck) {
			ackOn2 = ackOn2 || fr.finDelivered()
			doneIn = doneIn || fr.done()
		}
		for _, fr := range dt[1].sent(wire.TypeAck) {
			doneOut = doneOut || fr.done()
		}
		if !ackOn2 || !doneIn || !doneOut {
			t.Fatalf("on carrier 2: terminal ACK %v, passive DONE %v, client DONE %v; want all", ackOn2, doneIn, doneOut)
		}
		if el := endedAt(t, f.dev, dc).Sub(closedAt); el > 100*time.Millisecond {
			t.Fatalf("the client's linger took %v (RTT 2 ms)", el)
		}
		if st := dc.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) || st.AckedBytes != n {
			t.Fatalf("client: %+v", st)
		}
		f.close()
	})
}

// TestNoFailoverAfterDone_L05: a bond session with two carriers finishes
// both ways (FINs delivered, DONE exchanged) and both of its carriers are
// killed once the second DONE crossed. Neither end fails over: no
// migration, rejoin, no-path episode or new session carrier, and both end
// with io.EOF (design X3: a cleanly finished session never starts a
// no-path episode, no dialer race). Two strike points:
//
//   - after-done: the kill follows the arrival of both DONEs, while the
//     carriers drain their retirement;
//   - in-final-done-read: the client's application reads its last byte
//     last, so the passive's DONE is the final one and reaches the client;
//     both links are killed inside the client's carrier Read that delivered
//     it, and that Read returns its bytes 1 ms later — the client's other
//     carrier, and the writer of this one, see the kill before its reader
//     dispatches the DONE that already crossed.
func TestNoFailoverAfterDone_L05(t *testing.T) {
	iters := 8
	if lessonsRace {
		iters = 3
	}
	for _, at := range []string{"after-done", "in-final-done-read"} {
		t.Run(at, func(t *testing.T) {
			for i := range iters {
				synctest.Test(t, func(t *testing.T) { noFailoverAfterDone(t, at, i) })
			}
		})
	}
}

func noFailoverAfterDone(t *testing.T, at string, i int) {
	f := newFixture(t, opts{}, "a", "b")
	la, lb := f.link("a"), f.link("b")
	delay := time.Duration(1+i) * 500 * time.Microsecond
	la.SetDelay(delay, 0)
	lb.SetDelay(delay+time.Duration(i%3)*300*time.Microsecond, 0)
	dc, pc := f.open(f.peer("a", "b"), rendr.DialOptions{Mode: rendr.ModeBond})
	eventually(t, 10*time.Second, "two bond members", func() bool {
		return len(dc.Status().Carriers) == 2 && len(f.wire.sessionTaps(dialerSide, "")) == 2
	})
	const sessionDials = 2
	n := int64(4 << 20)
	if lessonsRace {
		n = 1 << 20
	}
	var killedIn atomic.Bool
	switch at {
	case "after-done":
		runWithin(t, time.Minute, "exchange", func() error { return exchange(dc, pc, n, uint64(i), 64<<10) })
	case "in-final-done-read":
		// Both directions stream and half-close; the passive reads to EOF,
		// the client every byte but the last. A side sends FIN_DELIVERED
		// once its application read up to the peer's FIN, and DONE once its
		// own FIN was acknowledged that way too: holding the client's last
		// byte until the passive's FIN_DELIVERED was applied makes the
		// client's DONE leave first and the passive's DONE — sent when the
		// client's FIN_DELIVERED arrives — the final one, towards the client.
		v := rendrtest.NewVerifier(uint64(i)+1, n)
		errs := make(chan error, 4)
		go func() { errs <- sendAndClose(dc, n, uint64(i)) }()
		go func() { errs <- sendAndClose(pc, n, uint64(i)+1) }()
		go func() { errs <- readStream(pc, n, uint64(i), nil) }()
		go func() { _, err := io.CopyN(v, dc, n-1); errs <- err }()
		for range 4 {
			if err := recv(t, errs, time.Minute, "both streams"); err != nil {
				t.Fatalf("iteration %d: streams: %v", i, err)
			}
		}
		if _, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
			return fr.finDelivered() && !fr.out && fr.tap.side == dialerSide
		}); !ok {
			t.Fatalf("iteration %d: the client never read the passive's FIN_DELIVERED", i)
		}
		synctest.Wait() // the client applied it
		if dones := f.wire.count(func(fr frame) bool { return fr.done() }); dones != 0 {
			t.Fatalf("iteration %d: %d DONE frames before the client read its last byte", i, dones)
		}
		f.wire.setHook(func(fr frame) {
			if fr.done() && !fr.out && fr.tap.side == dialerSide && killedIn.CompareAndSwap(false, true) {
				la.Kill()
				lb.Kill()
				time.Sleep(time.Millisecond) // the Read delivering the DONE returns late
			}
		})
		runWithin(t, 30*time.Second, "the client's last byte and EOF", func() error {
			if _, err := io.CopyN(v, dc, 1); err != nil {
				return err
			}
			if k, err := dc.Read(make([]byte, 1)); k != 0 || err != io.EOF {
				return fmt.Errorf("Read after the passive's FIN: (%d, %v)", k, err)
			}
			return v.Done(io.EOF)
		})
	}
	synctest.Wait()

	// Both close; for after-done, kill both carriers once both DONEs crossed.
	for _, c := range []*rendr.Conn{dc, pc} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []side{passiveSide, dialerSide} {
		if _, ok := f.wire.wait(10*time.Second, func(fr frame) bool { return fr.done() && !fr.out && fr.tap.side == s }); !ok {
			t.Fatalf("iteration %d: no DONE reached the %v", i, s)
		}
	}
	if at == "after-done" {
		la.Kill()
		lb.Kill()
	}
	for _, x := range []struct {
		c   *rendr.Conn
		log *evLog
	}{{dc, f.dev}, {pc, f.pev}} {
		st := waitEnded(t, x.c, 10*time.Second)
		if st.Err != io.EOF || st.Migrations != noMigrations || st.Rejoins != 0 || st.NoPathEpisodes != 0 {
			t.Fatalf("iteration %d: %v after the DONE: %+v", i, st.Role, st)
		}
		if evs := len(x.log.of(x.c.ID(), rendr.EventMigration)) + len(x.log.of(x.c.ID(), rendr.EventNoPathStart)); evs != 0 {
			t.Fatalf("iteration %d: %v emitted %d migration/no-path events", i, st.Role, evs)
		}
	}
	synctest.Wait()
	if got := len(f.wire.sessionTaps(dialerSide, "")); got != sessionDials {
		t.Fatalf("iteration %d: %d session carriers dialled after the members attached", i, got-sessionDials)
	}
	// Stimulus: the kills hit live session carriers — draining their
	// retirement, or still members holding the final DONE in a Read.
	if k := la.Stats().Session.Killed + lb.Stats().Session.Killed; k == 0 {
		t.Fatalf("iteration %d: the kills hit no session carrier", i)
	}
	if at == "in-final-done-read" && !killedIn.Load() {
		t.Fatalf("iteration %d: the client read no DONE", i)
	}
	f.close()
}
