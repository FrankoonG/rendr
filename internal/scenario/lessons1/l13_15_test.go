package lessons1

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestAckBeyondSentKillsCarrier_L13: an ACK claiming delivery far beyond
// anything sent (ForgeAckBeyondSent: fseq and CRC intact) is a protocol
// violation of the carrier that delivered it: carrier A is killed, the
// forged value never counts as acknowledgement, and the selector session
// continues on B with its stream intact. Run with the forgery reaching the
// dialer (the passive's ACK) and reaching the passive (the dialer's ACK).
func TestAckBeyondSentKillsCarrier_L13(t *testing.T) {
	for _, dir := range []rendrtest.Dir{rendrtest.Down, rendrtest.Up} {
		name := "forged-to-dialer"
		if dir == rendrtest.Up {
			name = "forged-to-passive"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { ackBeyondSent(t, dir) })
		})
	}
}

func ackBeyondSent(t *testing.T, dir rendrtest.Dir) {
	n := int64(4 << 20)
	if lessonsRace {
		n = 1 << 20
	}
	f := newFixture(t, opts{}, "a", "b")
	la, lb := f.link("a"), f.link("b")
	la.SetDelay(time.Millisecond, 0)
	lb.SetDelay(2*time.Millisecond, 0)
	la.SetRate(32 << 20) // the stream spans virtual time: the forgery lands mid-stream
	lb.SetRate(32 << 20)
	dc, pc := f.open(f.peer("a", "b"), rendr.DialOptions{})
	if c, ok := carrierIn(dc.Status(), rendr.CarrierActive); !ok || c.Name != "a" {
		t.Fatalf("active carrier %+v, want one on a", c)
	}
	// The receiver of the forged ACK is the sender of the stream.
	snd, rcv := dc, pc
	if dir == rendrtest.Up {
		snd, rcv = pc, dc
	}
	var g gauge
	errs := make(chan error, 2)
	go func() { errs <- sendAndClose(snd, n, 1) }()
	go func() { errs <- readStream(rcv, n, 1, &g) }()
	reached(t, &g, n/3, time.Minute)
	la.CorruptNextFrame(dir, rendrtest.FrameAck, rendrtest.ForgeAckBeyondSent)
	for range 2 {
		if err := recv(t, errs, time.Minute, "the stream"); err != nil {
			t.Fatalf("stream: %v", err)
		}
	}
	synctest.Wait()

	// Stimulus: one ACK forged on A's session carrier; the side that read
	// it killed A for "ack beyond sent".
	if got := la.Stats().Session.FramesCorrupted; got != 1 {
		t.Fatalf("ACKs forged: %d, want 1", got)
	}
	d := deadCarriers(snd.Status())
	if len(d) != 1 || d[0].DeathCause != rendr.CauseProtocolViolation || !strings.Contains(d[0].DeathDetail, "beyond") {
		t.Fatalf("%v's dead carriers %+v, want A killed for an ACK beyond sent", snd.Status().Role, d)
	}
	// The session continued on B; the forged ACK acknowledged nothing.
	if c, ok := carrierIn(dc.Status(), rendr.CarrierActive); !ok || c.Name != "b" {
		t.Fatalf("active carrier after the forgery %+v, want one on b", c)
	}
	eventually(t, time.Second, "stream acknowledged", func() bool { return snd.Status().AckedBytes == uint64(n) })
	if st := snd.Status(); st.AckedBytes != uint64(n) || st.RetransmittedBytes == 0 {
		t.Fatalf("sender: acked %d of %d, retransmitted %d", st.AckedBytes, n, st.RetransmittedBytes)
	}
	for _, c := range []*rendr.Conn{dc, pc} {
		if st := c.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) {
			t.Fatalf("%v migrations %+v, want 1 death", st.Role, st.Migrations)
		}
	}
	if err := closeWrite(rcv); err != nil {
		t.Fatal(err)
	}
	readEOF(t, snd, "sender")
	finish(t, dc, pc)
	f.close()
}

// readEOF requires that c's next Read returns (0, io.EOF) within 30 s.
func readEOF(t testing.TB, c *rendr.Conn, who string) {
	t.Helper()
	runWithin(t, 30*time.Second, who+" Read at the peer's FIN", func() error {
		if k, err := c.Read(make([]byte, 1)); k != 0 || err != io.EOF {
			return fmt.Errorf("(%d, %v), want (0, io.EOF)", k, err)
		}
		return nil
	})
}

// TestOffsetExhaustion_L14: with both Runtimes' stream offsets preset to
// 1 MiB below the offset limit (2^62), bytes below the limit are delivered
// normally; the Write that would cross it fails with
// AbortError(AbortExhausted), the session ends with exactly one
// RST(Exhausted) on the wire, and the peer ends with the same code as a
// remote abort.
func TestOffsetExhaustion_L14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			limit = uint64(1) << 62
			room  = 1 << 20
			n     = room - 100
		)
		ov := testhooks.Overrides{FirstOffset: limit - room}
		f := newFixture(t, opts{ov: ov}, "a")
		f.link("a").SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		runWithin(t, time.Minute, "the stream below the limit", func() error {
			if _, err := writeStream(dc, n, 1, 64<<10); err != nil {
				return fmt.Errorf("writes: %w", err)
			}
			_, err := io.CopyN(rendrtest.NewVerifier(1, n), pc, n)
			return err
		})
		eventually(t, time.Second, "acknowledged", func() bool { return dc.Status().AckedBytes == n })
		synctest.Wait()

		k, err := dc.Write(make([]byte, 200))
		var ae *rendr.AbortError
		if k != 0 || !errors.As(err, &ae) || ae.Code != rendr.AbortExhausted || ae.Remote || !errors.Is(err, rendr.ErrAborted) {
			t.Fatalf("Write across the limit: (%d, %v), want (0, local AbortExhausted)", k, err)
		}
		dst := waitEnded(t, dc, time.Second)
		if !errors.As(dst.Err, &ae) || ae.Code != rendr.AbortExhausted || ae.Remote {
			t.Fatalf("dialer ended with %v", dst.Err)
		}
		pst := waitEnded(t, pc, time.Second)
		if !errors.As(pst.Err, &ae) || ae.Code != rendr.AbortExhausted || !ae.Remote {
			t.Fatalf("passive ended with %v, want a remote AbortExhausted", pst.Err)
		}
		if k, err := pc.Read(make([]byte, 1)); k != 0 || !errors.Is(err, rendr.ErrAborted) {
			t.Fatalf("passive Read after the reset: (%d, %v)", k, err)
		}
		synctest.Wait()
		rsts := f.wire.pick(func(fr frame) bool { return fr.typ == wire.TypeRst && fr.out && fr.fate == fateWritten })
		if len(rsts) != 1 || rsts[0].tap.side != dialerSide || rsts[0].rst != wire.RstExhausted {
			t.Fatalf("RSTs on the wire %+v, want exactly one RST(Exhausted) from the dialer", rsts)
		}
		// Every DATA frame stayed below the limit.
		for _, fr := range f.wire.pick(func(fr frame) bool { return fr.typ == wire.TypeData && fr.out }) {
			if fr.dataEnd() > limit || fr.off < limit-room {
				t.Fatalf("DATA [%d, %d) outside [limit − 1 MiB, limit)", fr.off, fr.dataEnd())
			}
		}
		if dst.TxBytes != n || pst.DeliveredBytes != n {
			t.Fatalf("tx %d, delivered %d, want %d", dst.TxBytes, pst.DeliveredBytes, n)
		}
		f.close()
	})
}

// TestReplayAfterBlackholeWithinWindow_L15: a selector session on carrier A
// with a 400 ms RTT runs window-limited; A is then blackholed, so the
// sender fills the peer's whole advertised window into the void, and A is
// killed. The entire window is replayed on B (5 ms) at once, without a
// single byte beyond the receiver's advertised right edge (no window
// violation, no carrier killed for one), and the stream arrives intact.
// The sender's own window (send buffer) is twice the receiver's, as after
// the lesson's "enlarged window": only the receiver's advertised edge may
// bound what is in flight, so a sender that overruns it is caught.
func TestReplayAfterBlackholeWithinWindow_L15(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			window = 1 << 20 // the receiver's (passive's) window
			n      = 8 << 20
		)
		ov := testhooks.Overrides{SelectorDwell: time.Hour, SelectorCooldown: time.Hour}
		o := opts{ov: ov, dcfg: rendr.Config{Window: 2 * window}, pcfg: rendr.Config{Window: window}}
		f := newFixture(t, o, "a", "b")
		la, lb := f.link("a"), f.link("b")
		la.SetDelay(200*time.Millisecond, 0)
		lb.SetDelay(5*time.Millisecond, 0)
		lb.SetRefuse(true) // the session opens on A
		peer := f.peer("a", "b")
		dc, pc := f.open(peer, rendr.DialOptions{})
		lb.SetRefuse(false)
		if c, ok := carrierIn(dc.Status(), rendr.CarrierActive); !ok || c.Name != "a" {
			t.Fatalf("active carrier %+v, want one on a", c)
		}
		if w := pc.Status().Window; w != window {
			t.Fatalf("the passive advertises %d, want its Config.Window %d", w, window)
		}
		var g gauge
		errs := make(chan error, 2)
		go func() { errs <- sendAndClose(dc, n, 1) }()
		go func() { errs <- readStream(pc, n, 1, &g) }()
		reached(t, &g, 3<<20, 2*time.Minute)
		eventually(t, 30*time.Second, "b's probe evidence", func() bool {
			return peer.Status().Factories[1].Evidence == rendr.EvidenceFresh
		})

		// A runs window-limited: every ACK train lets the sender emit a burst
		// up to the right edge just advertised. A is blackholed the moment a
		// burst reaches that edge: the whole window is outstanding, the
		// burst vanishes in flight, and so does every later ACK and PONG.
		a := f.wire.sessionTaps(dialerSide, "a")[0]
		var edgeA atomic.Uint64
		var armed, holed atomic.Bool
		holedCh := make(chan time.Time, 1)
		f.wire.setHook(func(fr frame) {
			if fr.tap != a {
				return
			}
			switch {
			case !fr.out && fr.typ == wire.TypeAck:
				for e := fr.ack.Delivered + uint64(fr.ack.Window); ; {
					old := edgeA.Load()
					if e <= old || edgeA.CompareAndSwap(old, e) {
						break
					}
				}
			case fr.out && fr.typ == wire.TypeData && fr.fate == fateWritten && armed.Load() && fr.dataEnd() >= edgeA.Load():
				if holed.CompareAndSwap(false, true) {
					la.SetBlackhole(true)
					holedCh <- time.Now()
				}
			}
		})
		armed.Store(true)
		var holedAt time.Time
		select {
		case holedAt = <-holedCh:
		case <-time.After(5 * time.Second):
			sent, edge := windowState(f, a)
			c, _ := carrierIn(dc.Status(), rendr.CarrierActive)
			if c.ID != rendr.CarrierID(a.cid.Load()) {
				t.Fatalf("A ended before a burst filled the window: dialer's dead carriers %+v, passive's %+v",
					deadCarriers(dc.Status()), deadCarriers(pc.Status()))
			}
			t.Fatalf("no burst reached the right edge on the 400 ms carrier within 5 s: %d of %d bytes sent, "+
				"%d of the %d-byte window outstanding; carrier %q cap %d, rate %.0f B/s, srtt %v: "+
				"the carrier's in-flight cap, not the window, limits the flow",
				sent, edge, int64(sent)-int64(dc.Status().AckedBytes), window, c.Name, c.Cap, c.Rate, c.SRTT)
		}
		time.Sleep(450 * time.Millisecond) // more than one RTT: everything in flight vanished
		sent, _ := windowState(f, a)
		acked := dc.Status().AckedBytes
		if gap := int64(sent) - int64(acked); gap != window {
			t.Fatalf("sent %d, acknowledged %d: %d unacknowledged, want the receiver's whole window %d", sent, acked, gap, window)
		}
		if late := f.wire.count(func(fr frame) bool { return fr.tap == a && !fr.out && fr.at.After(holedAt) }); late != 0 {
			t.Fatalf("the dialer read %d frames on A through the blackhole", late)
		}
		killedAt := time.Now()
		if k := la.Kill(); k < 1 {
			t.Fatal("killing A hit no carrier")
		}
		for range 2 {
			if err := recv(t, errs, 2*time.Minute, "the stream"); err != nil {
				t.Fatalf("stream: %v", err)
			}
		}
		synctest.Wait()

		// Stimulus: the blackhole swallowed A's traffic (the ACKs that would
		// have acknowledged the window among it).
		if dr := la.Stats().Session.Dropped; dr == 0 {
			t.Fatal("nothing vanished in A's blackhole")
		}
		// The whole outstanding window [acked, sent) was recovered on B: the
		// JOIN_ACK proved [acked, rx) delivered (the passive's ACKs for it
		// were lost), and B replayed everything above, [rx, sent), in order
		// and promptly — the bytes the blackhole swallowed.
		bt := f.wire.sessionTaps(dialerSide, "b")
		if len(bt) != 1 {
			t.Fatalf("%d session carriers on b", len(bt))
		}
		ja := bt[0].recv(wire.TypeJoinAck)
		if len(ja) != 1 {
			t.Fatalf("JOIN_ACKs on b: %+v", ja)
		}
		rx := ja[0].rx
		if rx < acked || rx >= sent {
			t.Fatalf("the passive had delivered up to %d at the JOIN; want within [%d, %d) (data lost in the blackhole)", rx, acked, sent)
		}
		covered := rx
		var firstAt time.Time
		for _, d := range bt[0].sent(wire.TypeData) {
			if d.off != covered {
				break
			}
			if firstAt.IsZero() {
				firstAt = d.at
			}
			covered = d.dataEnd()
			if covered >= sent {
				break
			}
		}
		if covered < sent {
			t.Fatalf("B replayed [%d, %d) in order, want [%d, %d)", rx, covered, rx, sent)
		}
		if el := firstAt.Sub(killedAt); el > 500*time.Millisecond {
			t.Fatalf("the replay started %v after A's death", el)
		}
		// No byte beyond the receiver's advertised right edge, no violation.
		checkRightEdge(t, f, window)
		for _, c := range []*rendr.Conn{dc, pc} {
			for _, d := range deadCarriers(c.Status()) {
				if d.DeathCause == rendr.CauseProtocolViolation {
					t.Fatalf("%v: a carrier was killed for a protocol violation: %+v", c.Status().Role, d)
				}
			}
		}
		if st := dc.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) || st.RetransmittedBytes < sent-rx {
			t.Fatalf("dialer: %+v", st)
		}
		if err := pc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readEOF(t, dc, "dialer")
		finish(t, dc, pc)
		f.close()
	})
}

// windowState returns the end of the DATA the dialer wrote on tap a (the
// stream bytes sent) and the right edge the dialer received there (max of
// delivered + window over the ACKs it read on a).
func windowState(f *fixture, a *tap) (sent, edge uint64) {
	for _, d := range a.sent(wire.TypeData) {
		sent = max(sent, d.dataEnd())
	}
	for _, fr := range f.wire.pick(func(fr frame) bool { return fr.tap == a && !fr.out && fr.typ == wire.TypeAck }) {
		edge = max(edge, fr.ack.Delivered+uint64(fr.ack.Window))
	}
	return sent, edge
}

// checkRightEdge requires that every DATA frame the passive read ended at
// or below the largest right edge it had advertised before (the OPEN_ACK
// window, then delivered + window of every ACK it wrote).
func checkRightEdge(t *testing.T, f *fixture, window uint64) {
	t.Helper()
	edge := window
	frames := f.wire.pick(func(fr frame) bool {
		return fr.tap.side == passiveSide && ((fr.out && fr.typ == wire.TypeAck && fr.fate == fateWritten) || (!fr.out && fr.typ == wire.TypeData))
	})
	for _, fr := range frames {
		if fr.out {
			edge = max(edge, fr.ack.Delivered+uint64(fr.ack.Window))
			continue
		}
		if fr.dataEnd() > edge {
			t.Fatalf("the passive read DATA [%d, %d) beyond its advertised right edge %d", fr.off, fr.dataEnd(), edge)
		}
	}
}
