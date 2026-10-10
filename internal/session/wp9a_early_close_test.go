package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// EarlyReturn (WP9a), part 2: Close and Abort before the verdict, carrier
// deaths and duplicate OPENs around the first flight. Helpers in
// wp9a_early_dial_test.go.

// eaNoViolation fails when any carrier of s died as a protocol violation.
func eaNoViolation(t testing.TB, who string, s *Session) {
	t.Helper()
	for _, c := range s.Status().Carriers {
		if c.DeathCause == carrier.CauseProtocolViolation {
			t.Fatalf("%s: carrier %d died as a protocol violation: %s", who, c.ID, c.DeathDetail)
		}
	}
}

// eaLive counts the live carriers of s.
func eaLive(s *Session) int {
	n := 0
	for _, c := range s.Status().Carriers {
		if c.State != LaneDead {
			n++
		}
	}
	return n
}

// TestEarlyCloseWhileOpeningDelivers_L03 (M4-D12): Write then Close before
// the verdict keeps Close's meaning: the opening continues; after the
// Confirm the bytes are delivered and the FIN follows; a refusal ends the
// session with the refusal; Linger expiring first withdraws (the passive's
// pending session ends, the dialer's Status().Err is net.ErrClosed).
func TestEarlyCloseWhileOpeningDelivers_L03(t *testing.T) {
	for _, tc := range []string{"delivers", "refused", "linger"} {
		t.Run(tc, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := eaNewWorld(t, nil)
				defer w.teardown()
				l := w.eaLink("a")
				spec := w.eaSpec(ModeSelector, 64<<10, l)
				spec.Params.Linger = time.Second
				s := w.eaDial(spec)
				msg := stPattern(0, 2000)
				if _, err := s.Write(msg); err != nil {
					t.Fatal(err)
				}
				closed := time.Now()
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Read after Close: %v, want net.ErrClosed", err)
				}
				p := w.eaPending()
				switch tc {
				case "delivers":
					if err := p.Confirm(); err != nil {
						t.Fatal(err)
					}
					// A4.1: a Close before the verdict makes the opened
					// session closing at its first OPEN_ACK(OK).
					acWaitFor(t, time.Second, "the dialer's verdict", func() bool { return s.State() != StatePending })
					if st := s.State(); st != StateClosing {
						t.Fatalf("state %v after the verdict of a closed session, want closing", st)
					}
					if got := eaReadAll(t, p); !bytes.Equal(got, msg) {
						t.Fatalf("the passive read %d bytes, want the %d written before Close", len(got), len(msg))
					}
					if err := p.Close(); err != nil {
						t.Fatal(err)
					}
					acDone(t, s, 5*time.Second)
					if err := s.Status().Err; err != io.EOF {
						t.Fatalf("dialer end %v, want a clean end", err)
					}
				case "refused":
					if err := p.Reject(0x4C340003, "no"); err != nil {
						t.Fatal(err)
					}
					acDone(t, s, 5*time.Second)
					var re *RejectError
					if err := s.Status().Err; !errors.As(err, &re) || re.Code != 0x4C340003 {
						t.Fatalf("dialer end %v, want the *RejectError", err)
					}
				case "linger":
					acDone(t, s, 5*time.Second)
					if err := s.Status().Err; !errors.Is(err, net.ErrClosed) {
						t.Fatalf("dialer end %v, want net.ErrClosed", err)
					}
					if ev := w.a.ev.of(s.ID(), EventSessionEnd); len(ev) != 1 || ev[0].Time.Sub(closed) != time.Second {
						t.Fatalf("SessionEnd %+v, want one at Close + Linger (1 s)", ev)
					}
					acDone(t, p, time.Second) // withdrawn, long before its AcceptTimeout
					if v, ok := w.b.reg.endedVerdict(p); !ok || v.Opened {
						t.Fatalf("passive verdict %+v (%v), want a withdrawn pending session", v, ok)
					}
					eaNoViolation(t, "passive", p)
				}
			})
		})
	}
}

// TestEarlyAbortWithdraws_L49 (M4-D20, R1-4): Abort while the EARLY
// attempt's Establish awaits the response withdraws the opening: the
// passive processes RST(AbortWithdrawn) — written after the whole first
// flight, at fseq first + 2 — and its pending session ends at once (not at
// its AcceptTimeout), no carrier dies as a protocol violation, and the
// dialer ends with net.ErrClosed. With a DialEarly factory too.
func TestEarlyAbortWithdraws_L49(t *testing.T) {
	for _, dialEarly := range []bool{false, true} {
		name := "dial"
		if dialEarly {
			name = "dialearly"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := eaNewWorld(t, nil)
				defer w.teardown()
				l := w.eaLink("a")
				spec := w.eaSpec(ModeSelector, 64<<10, l)
				if dialEarly {
					spec.Factories[0].DialEarly = l.DialEarly
				}
				s := w.eaDial(spec)
				if _, err := s.Write(stPattern(0, 3000)); err != nil {
					t.Fatal(err)
				}
				p := w.eaPending()
				eaWaitEarly(t, p, 3000)
				if err := s.Abort(0x1000, "changed my mind"); err != nil {
					t.Fatal(err)
				}
				acWaitFor(t, 20*time.Millisecond, "the passive's end at the withdrawal", func() bool {
					_, ok := w.b.reg.endedVerdict(p)
					return ok
				})
				acDone(t, p, time.Second)
				eaNoViolation(t, "passive", p)
				if v, ok := w.b.reg.endedVerdict(p); !ok || v.Opened || v.Status == wire.StatusCapacity {
					t.Fatalf("passive verdict %+v (%v), want withdrawn", v, ok)
				}
				if err := p.Confirm(); err == nil {
					t.Fatal("Confirm of a withdrawn session succeeded")
				}
				acDone(t, s, 5*time.Second)
				if err := s.Status().Err; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("dialer end %v, want net.ErrClosed", err)
				}
			})
		})
	}
}

// TestEarlyDataSurvivesCarrierDeath_L10 (M4-D7, L10): after the verdict
// the early span [0, kw) is in flight on the winner's lane. Two rows:
//   - "held": the passive holds the span when the winner dies (no ACK yet,
//     its application has not read): nothing was sent twice while the
//     lane lived (no retransmission, no duplicate at the passive); the
//     JOIN_ACK's rxNext trims the requeued span, so the row asserts the
//     failover and that every byte is delivered once, in order;
//   - "unarrived": the winner (a slow DialEarly link) dies while its early
//     DATA frame is still on the wire: the passive holds nothing at the
//     kill, so the span is requeued from the lane's in-flight entry and
//     resent on the next lane (RetransmittedBytes ≥ the span), and every
//     byte is delivered once, in order.
func TestEarlyDataSurvivesCarrierDeath_L10(t *testing.T) {
	t.Run("held", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := eaNewWorld(t, nil)
			defer w.teardown()
			l1, l2 := w.eaLink("a"), w.eaLink("b")
			s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l1, l2))
			msg := stPattern(0, 4000)
			if _, err := s.Write(msg); err != nil {
				t.Fatal(err)
			}
			p := w.eaPending()
			eaWaitEarly(t, p, uint64(len(msg)))
			if err := p.Confirm(); err != nil {
				t.Fatal(err)
			}
			acWaitFor(t, time.Second, "the dialer opened", func() bool { return s.State() == StateOpen })
			time.Sleep(100 * time.Millisecond)
			synctest.Wait()
			if r, d := s.Status().RetransmittedBytes, p.Status().DupBytes; r != 0 || d != 0 {
				t.Fatalf("retransmitted %d, passive duplicates %d while the winner lives: want 0 and 0", r, d)
			}
			if l2.Stats().Dials != 0 {
				t.Fatal("the second factory was dialled before the first answered")
			}
			l1.Kill() // the winner dies before the passive application read (no ACK)
			more := stPattern(uint64(len(msg)), 50<<10)
			if _, err := s.Write(more); err != nil {
				t.Fatal(err)
			}
			if err := s.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if got := eaReadAll(t, p); !bytes.Equal(got, append(slices.Clone(msg), more...)) {
				t.Fatalf("the passive read %d bytes, want %d once and in order", len(got), len(msg)+len(more))
			}
			// Stimulus: the winner's carrier died and another one carried
			// the rest.
			st := s.Status()
			if st.MigDeath+st.Rejoins == 0 || l1.Stats().Session.Killed == 0 {
				t.Fatalf("no failover after the kill: %+v", st)
			}
		})
	})
	t.Run("unarrived", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := eaNewWorld(t, nil)
			defer w.teardown()
			l1, l2 := w.eaLink("a"), w.eaLink("b")
			l1.SetRate(16 << 10) // the 60 KiB early DATA frame needs about 4 s
			spec := w.eaSpec(ModeSelector, 64<<10, l1, l2)
			spec.Factories[0].DialEarly = l1.DialEarly
			s := w.eaDial(spec)
			msg := stPattern(0, 60<<10)
			if _, err := s.Write(msg); err != nil {
				t.Fatal(err)
			}
			p := w.eaPending()
			if err := p.Confirm(); err != nil {
				t.Fatal(err)
			}
			acWaitFor(t, time.Second, "the dialer opened", func() bool { return s.State() == StateOpen })
			if e := s.Status().EarlyBytes; e != uint64(len(msg)) {
				t.Fatalf("dialer EarlyBytes %d, want %d (the winner carried the span)", e, len(msg))
			}
			p.mu.Lock()
			held := p.st.rTail - p.p.FirstOffset
			p.mu.Unlock()
			if held >= uint64(len(msg)) {
				t.Fatalf("the passive holds %d bytes before the kill: the row needs the DATA frame still on the wire", held)
			}
			l1.Kill() // the winner dies with its early DATA frame on the wire
			if err := s.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if got := eaReadAll(t, p); !bytes.Equal(got, msg) {
				t.Fatalf("the passive read %d bytes, want %d once and in order", len(got), len(msg))
			}
			st := s.Status()
			if st.RetransmittedBytes < uint64(len(msg))-held {
				t.Fatalf("retransmitted %d, want ≥ %d (the span the passive did not hold at the kill)", st.RetransmittedBytes, uint64(len(msg))-held)
			}
			if st.MigDeath+st.Rejoins == 0 || l1.Stats().Session.Killed == 0 || l2.Stats().Dials == 0 {
				t.Fatalf("no failover after the kill: %+v", st)
			}
			eaNoViolation(t, "passive", p)
		})
	})
}

// TestEarlyRedialBeforeOpenAck_L10 (R1-2, L10): the carrier dies after its
// first flight, before the OPEN_ACK; the redial carries the same span from
// 0 again; the passive keeps the first copy (the duplicate is dropped by
// offset) and every byte is delivered once.
func TestEarlyRedialBeforeOpenAck_L10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		msg := stPattern(0, 3000)
		if _, err := s.Write(msg); err != nil {
			t.Fatal(err)
		}
		p := w.eaPending()
		eaWaitEarly(t, p, uint64(len(msg)))
		l.Kill()
		acWaitFor(t, 5*time.Second, "the redial's first flight", func() bool { return len(fl.get()) == 2 })
		acWaitFor(t, 5*time.Second, "the passive adopted the redial", func() bool { return eaLive(p) == 1 })
		if ks := fl.get(); !slices.Equal(ks, []int{len(msg), len(msg)}) {
			t.Fatalf("early first flights %v, want the same span twice", ks)
		}
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if err := s.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if got := eaReadAll(t, p); !bytes.Equal(got, msg) {
			t.Fatalf("the passive read %d bytes, want %d once", len(got), len(msg))
		}
		if st := p.Status(); st.EarlyBytes != uint64(len(msg)) {
			t.Fatalf("passive EarlyBytes %d, want %d", st.EarlyBytes, len(msg))
		}
		if st := s.Status(); st.EarlyBytes != uint64(len(msg)) {
			t.Fatalf("dialer EarlyBytes %d, want %d", st.EarlyBytes, len(msg))
		}
	})
}

// TestEarlyDuplicateOpenDedup_L47 (L47): both factories of an opening race
// carry the early span; the passive adopts both OPENs into one pending
// session (one Accept), holds the bytes once, and delivers them once.
func TestEarlyDuplicateOpenDedup_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l1, l2 := w.eaLink("a"), w.eaLink("b")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l1, l2))
		msg := stPattern(0, 3000)
		if _, err := s.Write(msg); err != nil {
			t.Fatal(err)
		}
		p := w.eaPending()
		acWaitFor(t, 5*time.Second, "both OPENs adopted", func() bool { return eaLive(p) == 2 })
		if ks := fl.get(); !slices.Equal(ks, []int{len(msg), len(msg)}) {
			t.Fatalf("early first flights %v, want the span twice", ks)
		}
		if e, _ := eaEarly(p); e != uint64(len(msg)) {
			t.Fatalf("passive early %d, want %d (held once)", e, len(msg))
		}
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if err := s.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if got := eaReadAll(t, p); !bytes.Equal(got, msg) {
			t.Fatalf("the passive read %d bytes, want %d once", len(got), len(msg))
		}
		if n := len(w.b.pending); n != 0 {
			t.Fatalf("%d more sessions admitted, want one Accept", n)
		}
		eaNoViolation(t, "dialer", s)
		eaNoViolation(t, "passive", p)
	})
}

// TestEarlyOpenAckLostRetry_L47 (L47): the first OPEN_ACK is dropped; the
// attempt fails and the redial's duplicate OPEN (with the same span) is
// answered OK by the open session: one Accept, every byte once.
func TestEarlyOpenAckLostRetry_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		msg := stPattern(0, 2000)
		if _, err := s.Write(msg); err != nil {
			t.Fatal(err)
		}
		p := w.eaPending()
		eaWaitEarly(t, p, uint64(len(msg)))
		l.DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck)
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		acWaitFor(t, 10*time.Second, "the dialer opened on the retry", func() bool { return s.State() == StateOpen })
		if n := l.Stats().Session.FramesDropped; n != 1 {
			t.Fatalf("%d frames dropped, want the one OPEN_ACK", n)
		}
		if d := l.Stats().Dials; d < 2 {
			t.Fatalf("%d dials, want a retry", d)
		}
		if err := s.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if got := eaReadAll(t, p); !bytes.Equal(got, msg) {
			t.Fatalf("the passive read %d bytes, want %d once", len(got), len(msg))
		}
		if n := len(w.b.pending); n != 0 {
			t.Fatalf("%d more sessions admitted, want one Accept", n)
		}
	})
}
