package lessons1

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRetransmitWithoutAppTraffic_L11: the application writes once and
// then stays silent. The first transmission of offset 0 vanishes (its Write
// reports success; the passive kills that carrier at the fseq gap), and the
// replay — the second write of offset 0, on the next carrier — fails. With
// no further application traffic, the session still delivers the bytes
// exactly once on the third carrier, within a second.
func TestRetransmitWithoutAppTraffic_L11(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 64 << 10
		f := newFixture(t, opts{}, "a")
		f.link("a").SetDelay(time.Millisecond, 0)
		var mu sync.Mutex
		var attempts []fate // every Write that carried DATA at offset 0
		f.wire.setOnNew(func(tp *tap) {
			if tp.side != dialerSide {
				return
			}
			seq := tp.seq
			tp.setPlan(func(_ *tap, fs []frame) planVerdict {
				for _, fr := range fs {
					if fr.typ != wire.TypeData || fr.off != 0 {
						continue
					}
					mu.Lock()
					defer mu.Unlock()
					switch seq {
					case 1:
						attempts = append(attempts, fateSwallowed)
						return planVerdict{swallow: true} // reported written, never sent
					case 2:
						attempts = append(attempts, fateFailed)
						return planVerdict{fail: errInjected} // the replay fails
					}
					attempts = append(attempts, fateWritten)
					return planVerdict{}
				}
				return planVerdict{}
			})
		})
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		got := make(chan time.Time, 1)
		go func() {
			v := rendrtest.NewVerifier(1, n)
			if _, err := io.CopyN(v, pc, n); err != nil {
				t.Errorf("passive read: %v", err)
			}
			got <- time.Now()
		}()
		src := make([]byte, n)
		rendrtest.PRNG(1).Read(src)
		wrote := time.Now()
		runWithin(t, time.Second, "the only Write", func() error {
			if k, err := dc.Write(src); k != n || err != nil {
				return fmt.Errorf("(%d, %v), want (%d, nil)", k, err, n)
			}
			return nil
		})
		// No application traffic from here until the bytes arrived.
		at := recv(t, got, time.Minute, "the passive's bytes")
		if el := at.Sub(wrote); el > time.Second {
			t.Fatalf("delivered %v after the only Write, want ≤ 1 s", el)
		}
		eventually(t, time.Second, "acknowledged", func() bool { return dc.Status().AckedBytes == n })
		synctest.Wait()

		mu.Lock()
		got3 := append([]fate(nil), attempts...)
		mu.Unlock()
		if len(got3) != 3 || got3[0] != fateSwallowed || got3[1] != fateFailed || got3[2] != fateWritten {
			t.Fatalf("writes of offset 0: %v, want swallowed, failed, written", got3)
		}
		dt := f.wire.sessionTaps(dialerSide, "a")
		if len(dt) != 3 || dt[0].faults.Load() != 1 || dt[1].faults.Load() != 1 {
			t.Fatalf("%d carriers; faults %v", len(dt), []int64{dt[0].faults.Load(), dt[1].faults.Load()})
		}
		st := dc.Status()
		if st.Migrations != (rendr.MigrationCounts{Death: 2}) || st.RetransmittedBytes < n || st.TxBytes != n {
			t.Fatalf("dialer: %+v", st)
		}
		if pst := pc.Status(); pst.RxBytes != n || pst.DeliveredBytes != n {
			t.Fatalf("passive received %d / delivered %d, want exactly %d", pst.RxBytes, pst.DeliveredBytes, n)
		}
		endBoth(t, dc, pc)
		f.close()
	})
}

// TestSoleCarrierTailRecovered_L11: the session's only carrier silently
// drops the last DATA frame, a 24-byte tail, and nothing else is written.
// The carrier's next PING shows the passive the fseq gap; the carrier is
// replaced and the tail arrives on its successor within a second, with
// exactly one (death) migration on each end.
func TestSoleCarrierTailRecovered_L11(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			head = 64 << 10
			tail = 24
		)
		f := newFixture(t, opts{}, "a")
		l := f.link("a")
		l.SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		v := rendrtest.NewVerifier(1, head+tail)
		buf := make([]byte, head+tail)
		rendrtest.PRNG(1).Read(buf)
		runWithin(t, time.Minute, "the head", func() error {
			if _, err := dc.Write(buf[:head]); err != nil {
				return err
			}
			_, err := io.CopyN(v, pc, head)
			return err
		})
		eventually(t, time.Second, "head acknowledged", func() bool { return dc.Status().AckedBytes == head })
		synctest.Wait()

		l.DropNextFrame(rendrtest.Up, rendrtest.FrameData)
		got := make(chan time.Time, 1)
		go func() {
			if _, err := io.CopyN(v, pc, tail); err != nil {
				t.Errorf("tail: %v", err)
			}
			got <- time.Now()
		}()
		wrote := time.Now()
		runWithin(t, time.Second, "the tail's Write", func() error { _, err := dc.Write(buf[head:]); return err })
		at := recv(t, got, time.Minute, "the tail")
		if el := at.Sub(wrote); el > time.Second {
			t.Fatalf("tail delivered %v after its Write, want ≤ 1 s", el)
		}
		synctest.Wait()

		// Stimulus: the 24-byte tail frame was dropped on carrier 1; the
		// next frame there — the PING (or a PONG it rode behind) of the busy
		// PING cadence — showed the passive the fseq gap and killed the
		// carrier.
		if got := l.Stats().Session.FramesDropped; got != 1 {
			t.Fatalf("frames dropped: %d", got)
		}
		dt := f.wire.sessionTaps(dialerSide, "a")
		if len(dt) != 2 {
			t.Fatalf("%d session carriers, want the original and its replacement", len(dt))
		}
		out := f.wire.pick(func(fr frame) bool { return fr.tap == dt[0] && fr.out && fr.fate == fateWritten && fr.typ.Known() })
		i := len(out) - 1
		for i >= 0 && !(out[i].typ == wire.TypeData && out[i].off == head) {
			i--
		}
		if i < 0 || out[i].n != wire.DataPrefixLen+tail || i+1 >= len(out) ||
			(out[i+1].typ != wire.TypePing && out[i+1].typ != wire.TypePong) || out[i+1].at.Sub(out[i].at) > 2*50*time.Millisecond {
			t.Fatalf("carrier 1 wrote %+v: want the %d-byte tail DATA at %d followed within two PingBusy by a PING or PONG", out, tail, head)
		}
		pt := f.wire.sessionTaps(passiveSide, "a")
		for _, fr := range pt[0].recv(wire.TypeData) {
			if fr.off == head {
				t.Fatal("the passive read the dropped tail on carrier 1")
			}
		}
		var onB bool
		for _, fr := range pt[1].recv(wire.TypeData) {
			onB = onB || (fr.off == head && fr.dataEnd() == head+tail)
		}
		if !onB {
			t.Fatal("the tail did not arrive on carrier 2")
		}
		if d := deadCarriers(pc.Status()); len(d) != 1 || d[0].DeathCause != rendr.CauseProtocolViolation || !strings.Contains(d[0].DeathDetail, "fseq") {
			t.Fatalf("passive's dead carriers %+v, want carrier 1 killed for the fseq gap", d)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := c.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) {
				t.Fatalf("%v migrations %+v, want exactly 1 death", st.Role, st.Migrations)
			}
		}
		endBoth(t, dc, pc)
		f.close()
	})
}

// TestAckLossRecovers_L11: a writer blocked on a small window while the
// reverse path loses everything for a while — every ACK (and PONG) the
// passive writes vanishes, so its send buffer stays full. Once the reverse
// path works again, its first frame (at the latest the PONG to the
// dialer's next busy PING, sent every PingBusy while bytes are unproven,
// P12) shows the dialer the fseq gap, the carrier is replaced, and the
// passive's acknowledgement on the new carrier (the JOIN_ACK's rxNext, and
// the ACK the new duty lane places at once, design §4.6) unblocks the
// writer. Bounds: within two ACK intervals (2·AckDelay) of the
// replacement's JOIN, and within PingBusy + 2·AckDelay of the moment the
// reverse path recovered, whatever the phase of the PING cadence — the
// loss durations span one PingBusy period. The stream arrives intact.
func TestAckLossRecovers_L11(t *testing.T) {
	for _, loss := range []time.Duration{100, 115, 130, 145} {
		t.Run(fmt.Sprintf("loss-%dms", loss), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { ackLossRecovers(t, loss*time.Millisecond) })
		})
	}
}

func ackLossRecovers(t *testing.T, loss time.Duration) {
	const (
		window   = 256 << 10
		n        = 4 << 20
		ackDelay = 20 * time.Millisecond // AckDelay (plan §4: ACK every 64 KiB or 20 ms)
		pingBusy = 50 * time.Millisecond // PingBusy (default)
	)
	f := newFixture(t, opts{ov: testhooks.Overrides{Window: window}}, "a")
	f.link("a").SetDelay(time.Millisecond, 0)
	dc, pc := f.open(f.peer("a"), rendr.DialOptions{})

	// The writer records when each Write returned.
	var mu sync.Mutex
	var writes []time.Time
	werr := make(chan error, 1)
	go func() {
		src := rendrtest.PRNG(1)
		buf := make([]byte, 16<<10)
		for done := 0; done < n; done += len(buf) {
			src.Read(buf)
			if _, err := dc.Write(buf); err != nil {
				werr <- err
				return
			}
			mu.Lock()
			writes = append(writes, time.Now())
			mu.Unlock()
		}
		werr <- dc.CloseWrite()
	}()
	var g gauge
	rerr := make(chan error, 1)
	go func() { rerr <- readStream(pc, n, 1, &g) }()

	reached(t, &g, n/4, time.Minute)
	// Every write of the passive on carrier 1 vanishes for loss.
	p1 := f.wire.sessionTaps(passiveSide, "a")[0]
	lossFrom := time.Now()
	lossTo := lossFrom.Add(loss)
	var swallowed atomic.Int64
	p1.setPlan(func(_ *tap, fs []frame) planVerdict {
		if time.Now().Before(lossTo) {
			swallowed.Add(1)
			return planVerdict{swallow: true}
		}
		return planVerdict{}
	})
	if err := recv(t, werr, time.Minute, "the writer"); err != nil {
		t.Fatalf("writer: %v", err)
	}
	if err := recv(t, rerr, time.Minute, "the passive stream"); err != nil {
		t.Fatalf("passive stream: %v", err)
	}
	synctest.Wait()

	// Stimulus: ACKs were lost, the dialer killed carrier 1 at the gap.
	if swallowed.Load() == 0 {
		t.Fatal("no passive write was lost")
	}
	dt := f.wire.sessionTaps(dialerSide, "a")
	if len(dt) != 2 {
		t.Fatalf("%d session carriers, want the original and its replacement", len(dt))
	}
	if d := deadCarriers(dc.Status()); len(d) != 1 || d[0].DeathCause != rendr.CauseProtocolViolation {
		t.Fatalf("dialer's dead carriers %+v, want carrier 1 killed for the fseq gap", d)
	}
	joins, acks := dt[1].sent(wire.TypeJoin), dt[1].recv(wire.TypeAck)
	if len(joins) != 1 || len(acks) == 0 {
		t.Fatalf("carrier 2: JOINs %+v, %d ACKs read", joins, len(acks))
	}
	mu.Lock()
	ws := append([]time.Time(nil), writes...)
	mu.Unlock()
	var stalled, resumed time.Time // the last Write that returned before lossTo, the first one at or after it
	for _, w := range ws {
		if w.Before(lossTo) {
			stalled = w
		} else if resumed.IsZero() {
			resumed = w
		}
	}
	// The writer stalled during the loss (its buffer filled) ...
	if stalled.After(lossFrom.Add(loss / 2)) {
		t.Fatalf("the writer kept writing during the loss (last write before its end at %v, loss %v..%v)", stalled, lossFrom, lossTo)
	}
	// ... and resumed promptly once the reverse path worked again.
	if resumed.IsZero() {
		t.Fatal("the writer never resumed")
	}
	timeline := fmt.Sprintf("after the recovery: JOIN +%v, first ACK on carrier 2 +%v, writer resumed +%v",
		joins[0].at.Sub(lossTo), acks[0].at.Sub(lossTo), resumed.Sub(lossTo))
	if el := resumed.Sub(lossTo); el > pingBusy+2*ackDelay {
		t.Fatalf("the writer resumed %v after the reverse path recovered, want ≤ PingBusy + 2·AckDelay = %v (%s)", el, pingBusy+2*ackDelay, timeline)
	}
	if el := resumed.Sub(joins[0].at); el > 2*ackDelay {
		t.Fatalf("the writer resumed %v after the replacement's JOIN, want ≤ 2·AckDelay = %v (%s)", el, 2*ackDelay, timeline)
	}
	if el := resumed.Sub(acks[0].at); el > 2*ackDelay {
		t.Fatalf("the writer resumed %v after the first ACK on carrier 2, want ≤ %v (%s)", el, 2*ackDelay, timeline)
	}
	if st := dc.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) || st.TxBytes != n {
		t.Fatalf("dialer: %+v", st)
	}
	if err := pc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readEOF(t, dc, "dialer")
	finish(t, dc, pc)
	f.close()
}
