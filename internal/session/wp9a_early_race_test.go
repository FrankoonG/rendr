package session

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// EarlyReturn (WP9a), part 3: the one early span across opening attempts
// and modes (R1-2, AM-2), the fast path (M4-D17), the winner's span
// (M4-D7, M4-D18), fseq continuity and the allocation gate. Helpers in
// wp9a_early_dial_test.go and wp9a_early_close_test.go.

// eaPool makes a carrier.Pool over spec's factories, factory i
// mux-eligible where mux[i], and sets it as spec's pool. The caller closes
// it before the world's teardown.
func eaPool(w *acWorld, spec *DialSpec, mux ...bool) *carrier.Pool {
	for i := range spec.Factories {
		spec.Factories[i].Mux = mux[i]
	}
	p := carrier.NewPool(w.a.cenv, spec.Factories)
	spec.Pool = p
	return p
}

// eaOpenClassic dials spec without EarlyReturn and confirms the next
// admitted session.
func eaOpenClassic(w *acWorld, spec DialSpec) (dialer, passive *Session) {
	w.t.Helper()
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := w.dial(context.Background(), spec, nil)
		ch <- res{s, err}
	}()
	passive = w.eaPending()
	if err := passive.Confirm(); err != nil {
		w.t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.s, passive
}

// eaModeName names a mode for subtests.
func eaModeName(m Mode) string {
	switch m {
	case ModeSelector:
		return "selector"
	case ModeBond:
		return "bond"
	case ModeRace:
		return "race"
	}
	return "mode"
}

// eaFinish half-closes s and checks that p reads want once, in order.
func eaFinish(t testing.TB, s, p *Session, want []byte) {
	t.Helper()
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := eaReadAll(t, p); !bytes.Equal(got, want) {
		t.Fatalf("the passive read %d bytes, want %d once and in order", len(got), len(want))
	}
}

// TestEarlyRaceAttemptsShareSpan (R1-2, AM-2): the early span is fixed
// once per session. Two factories; a second Write lands before the second
// attempt starts; both OPENs still carry exactly the first span, the first
// attempt wins, no ACK goes beyond what was sent (no carrier dies as a
// protocol violation) and every byte is delivered once — in selector,
// bond and race. The "waiter" row: a coalesced waiter of the pool that
// dials beside an unanswered claimant (its verdict grace ran out) carries
// the session's span on its own fresh carrier and can win with it.
func TestEarlyRaceAttemptsShareSpan(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeBond, ModeRace} {
		t.Run(eaModeName(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var fl eaFlights
				w := eaNewWorld(t, fl.hooks())
				defer w.teardown()
				l1, l2 := w.eaLink("a"), w.eaLink("b")
				l2.SetDelay(20*time.Millisecond, 0) // the second OPEN_ACK arrives last
				s := w.eaDial(w.eaSpec(mode, 64<<10, l1, l2))
				first, second := stPattern(0, 1000), stPattern(1000, 2000)
				if _, err := s.Write(first); err != nil {
					t.Fatal(err)
				}
				synctest.Wait() // the first attempt started: the span is fixed
				if _, err := s.Write(second); err != nil {
					t.Fatal(err)
				}
				p := w.eaPending()
				acWaitFor(t, 5*time.Second, "both OPENs adopted", func() bool { return eaLive(p) == 2 })
				if ks := fl.get(); !slices.Equal(ks, []int{len(first), len(first)}) {
					t.Fatalf("early first flights %v, want the first span twice", ks)
				}
				if err := p.Confirm(); err != nil {
					t.Fatal(err)
				}
				eaFinish(t, s, p, append(slices.Clone(first), second...))
				eaNoViolation(t, "dialer", s)
				eaNoViolation(t, "passive", p)
				if e := s.Status().EarlyBytes; e != uint64(len(first)) {
					t.Fatalf("dialer EarlyBytes %d, want %d", e, len(first))
				}
			})
		})
	}
	t.Run("waiter", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var fl eaFlights
			w := eaNewWorld(t, fl.hooks())
			defer w.teardown()
			l := w.eaLink("a")
			specA := w.spec(ModeSelector, l)
			pool := eaPool(w, &specA, true)
			defer pool.Close()
			// Session A claims the factory's dial; its passive stays
			// unanswered, so the dial stays in flight.
			type res struct {
				s   *Session
				err error
			}
			ach := make(chan res, 1)
			go func() {
				a, err := dial(context.Background(), w.a.env, specA, nil)
				ach <- res{a, err}
			}()
			pa := w.eaPending()
			specB := w.eaSpec(ModeSelector, 64<<10, l)
			specB.Factories, specB.Pool = specA.Factories, pool
			b := w.eaDial(specB)
			msg := stPattern(0, 2500)
			if _, err := b.Write(msg); err != nil {
				t.Fatal(err)
			}
			pb := w.eaPending() // B dialled beside A once A's verdict grace ran out
			eaWaitEarly(t, pb, uint64(len(msg)))
			if ks := fl.get(); !slices.Equal(ks, []int{len(msg)}) {
				t.Fatalf("early first flights %v, want B's span once", ks)
			}
			if err := pb.Confirm(); err != nil {
				t.Fatal(err)
			}
			eaFinish(t, b, pb, msg)
			if e := b.Status().EarlyBytes; e != uint64(len(msg)) {
				t.Fatalf("B's EarlyBytes %d, want %d (a fresh EARLY carrier won)", e, len(msg))
			}
			if err := pa.Confirm(); err != nil {
				t.Fatal(err)
			}
			r := <-ach
			if r.err != nil {
				t.Fatalf("A's Dial: %v", r.err)
			}
			w.sess = append(w.sess, r.s)
		})
	})
}

// TestEarlyFastPathNoEarly (M4-D17, M4-D3): on a live MUX trunk the
// session's OPEN takes the fast path: no EARLY, no first-flight DATA, the
// bytes follow the attach; no second carrier is dialled; EarlyBytes 0.
func TestEarlyFastPathNoEarly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l := w.eaLink("a")
		specA := w.spec(ModeSelector, l)
		pool := eaPool(w, &specA, true)
		defer pool.Close()
		eaOpenClassic(w, specA) // the live trunk
		specB := w.eaSpec(ModeSelector, 64<<10, l)
		specB.Factories, specB.Pool = specA.Factories, pool
		b := w.eaDial(specB)
		msg := []byte("abc")
		if _, err := b.Write(msg); err != nil {
			t.Fatal(err)
		}
		pb := w.eaPending()
		if e, eo := eaEarly(pb); e != 0 || eo {
			t.Fatalf("passive early %d, EARLY OPEN %v on the fast path: want neither", e, eo)
		}
		if ks := fl.get(); len(ks) != 0 {
			t.Fatalf("early first flights %v, want none", ks)
		}
		if d := l.Stats().Dials; d != 1 {
			t.Fatalf("%d dials, want the one trunk", d)
		}
		if err := pb.Confirm(); err != nil {
			t.Fatal(err)
		}
		eaFinish(t, b, pb, msg)
		if st := b.Status(); st.EarlyBytes != 0 {
			t.Fatalf("dialer EarlyBytes %d on the fast path, want 0", st.EarlyBytes)
		}
	})
}

// eaFastPathWinner runs R1-2's fast-path case: factory 0 has a live MUX
// trunk (the fast path, no EARLY), factory 1 dials a fresh dedicated
// carrier that carries the span with EARLY; the passive adopts both; the
// fast-path view's OPEN_ACK arrives first and wins. It returns both
// sessions after the passive read every byte.
func eaFastPathWinner(t *testing.T) (s, p *Session, msg []byte) {
	var fl eaFlights
	w := eaNewWorld(t, fl.hooks())
	t.Cleanup(w.teardown)
	l1, l2 := w.eaLink("trunk"), w.eaLink("fresh")
	l2.SetDelay(20*time.Millisecond, 0)
	specA := w.spec(ModeSelector, l1, l2)
	pool := eaPool(w, &specA, true, false)
	t.Cleanup(pool.Close)
	eaOpenClassic(w, specA)
	specB := w.eaSpec(ModeSelector, 64<<10, l1, l2)
	specB.Factories, specB.Pool = specA.Factories, pool
	s = w.eaDial(specB)
	msg = stPattern(0, 3000)
	if _, err := s.Write(msg); err != nil {
		t.Fatal(err)
	}
	p = w.eaPending()
	acWaitFor(t, 5*time.Second, "the fresh EARLY carrier adopted", func() bool {
		e, _ := eaEarly(p)
		return e == uint64(len(msg)) && eaLive(p) == 2
	})
	if ks := fl.get(); !slices.Equal(ks, []int{len(msg)}) {
		t.Fatalf("early first flights %v, want the fresh carrier's only", ks)
	}
	if err := p.Confirm(); err != nil {
		t.Fatal(err)
	}
	acWaitFor(t, time.Second, "the dialer opened", func() bool { return s.State() == StateOpen })
	eaFinish(t, s, p, msg)
	eaNoViolation(t, "dialer", s)
	eaNoViolation(t, "passive", p)
	return s, p, msg
}

// TestEarlyFastPathWinnerLoserEarly (R1-2 rule 3): a fast-path winner with
// a fresh-carrier loser that carried EARLY: sNext moves to k0, so the
// passive's ACKs of the loser's copy are legal (no violation), [0, k0) is
// resent once from retx on the winner (the passive drops it as
// duplicates) and every byte is delivered once.
func TestEarlyFastPathWinnerLoserEarly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, msg := eaFastPathWinner(t)
		if r := s.Status().RetransmittedBytes; r != uint64(len(msg)) {
			t.Fatalf("retransmitted %d, want the span once (%d) from retx", r, len(msg))
		}
		if d := p.Status().DupBytes; d != uint64(len(msg)) {
			t.Fatalf("passive duplicates %d, want %d (the resent span)", d, len(msg))
		}
	})
}

// TestEarlyBytesWinnerOnly (M4-D18, R1-23): the dialer's EarlyBytes is the
// winner's span — 0 for a fast-path winner, although a losing attempt
// carried EARLY; the passive's is the bytes it took before the verdict.
func TestEarlyBytesWinnerOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, msg := eaFastPathWinner(t)
		if e := s.Status().EarlyBytes; e != 0 {
			t.Fatalf("dialer EarlyBytes %d, want 0 (a fast-path view won)", e)
		}
		if e := p.Status().EarlyBytes; e != uint64(len(msg)) {
			t.Fatalf("passive EarlyBytes %d, want %d", e, len(msg))
		}
	})
}

// TestEarlyBondAndRace (M4-D7, M3-D30): bond — the early span is in flight
// on the winner (not resent while it lives, no duplicate at the passive)
// when the second member joins; race — the second member sends its own
// copies of the span from its cursor (counted as race copies). Every byte
// is delivered once.
func TestEarlyBondAndRace(t *testing.T) {
	for _, mode := range []Mode{ModeBond, ModeRace} {
		t.Run(eaModeName(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := eaNewWorld(t, nil)
				defer w.teardown()
				l1, l2 := w.eaLink("a"), w.eaLink("b")
				s := w.eaDial(w.eaSpec(mode, 64<<10, l1, l2))
				msg := stPattern(0, 5000)
				if _, err := s.Write(msg); err != nil {
					t.Fatal(err)
				}
				p := w.eaPending()
				eaWaitEarly(t, p, uint64(len(msg)))
				if err := p.Confirm(); err != nil {
					t.Fatal(err)
				}
				acWaitFor(t, 5*time.Second, "two members", func() bool { return eaLive(s) == 2 })
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				st, pt := s.Status(), p.Status()
				if st.EarlyBytes != uint64(len(msg)) || st.RetransmittedBytes != 0 {
					t.Fatalf("EarlyBytes %d retransmitted %d, want %d and 0", st.EarlyBytes, st.RetransmittedBytes, len(msg))
				}
				switch mode {
				case ModeBond:
					if pt.DupBytes != 0 {
						t.Fatalf("passive duplicates %d in bond, want 0 (the span is in flight on the winner)", pt.DupBytes)
					}
				case ModeRace:
					if st.Race.CopyBytes < uint64(len(msg)) {
						t.Fatalf("race copies %d, want ≥ %d (the second member's own copy)", st.Race.CopyBytes, len(msg))
					}
				}
				eaFinish(t, s, p, msg)
				eaNoViolation(t, "dialer", s)
				eaNoViolation(t, "passive", p)
			})
		})
	}
}

// TestEarlyFseqContinuity_L14 (L14, M4-D4): after the first flight
// (PREFACE ‖ OPEN(EARLY) ‖ DATA at fseq f, f+1) the winner's lane
// continues at f+2: a 1 MiB transfer each way runs on that one carrier
// without an fseq violation, a carrier death or a rejoin.
func TestEarlyFseqContinuity_L14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		msg := stPattern(0, 1000)
		if _, err := s.Write(msg); err != nil {
			t.Fatal(err)
		}
		p := w.eaPending()
		eaWaitEarly(t, p, uint64(len(msg)))
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other early bytes")
		}
		if wErr, rErr := acTransfer(s, p, 1<<20, 7, false); wErr != nil || rErr != nil {
			t.Fatalf("dialer → passive: %v, %v", wErr, rErr)
		}
		if wErr, rErr := acTransfer(p, s, 1<<20, 8, false); wErr != nil || rErr != nil {
			t.Fatalf("passive → dialer: %v, %v", wErr, rErr)
		}
		for _, x := range []*Session{s, p} {
			st := x.Status()
			if len(st.Carriers) != 1 || st.Carriers[0].State == LaneDead || st.Rejoins != 0 {
				t.Fatalf("%v carriers %+v rejoins %d, want the one first carrier alive", x.Role(), st.Carriers, st.Rejoins)
			}
		}
		if n := l.Stats().Dials; n != 1 {
			t.Fatalf("%d dials, want 1", n)
		}
	})
}

// TestEarlySnapshotAllocs (R1-2, §A12.6): fixing the early span and its
// copy cost one allocation per session; a Write admitted before the
// verdict allocates nothing.
func TestEarlySnapshotAllocs(t *testing.T) {
	s := stSession(stOpt{})
	s.p.EarlyDataMax = 64 << 10
	a := newActor(s)
	a.d = &dialer{spec: DialSpec{EarlyReturn: true}, started: true}
	s.mu.Lock()
	s.ctl.state = StatePending
	s.mu.Unlock()
	msg := stPattern(0, 1000)
	if _, err := s.Write(msg); err != nil {
		t.Fatal(err)
	}
	if !streamRaceEnabled {
		if n := testing.AllocsPerRun(100, func() {
			if _, err := s.Write(msg[:10]); err != nil {
				t.Fatal(err)
			}
		}); n != 0 {
			t.Fatalf("%v allocations per pre-verdict Write, want 0", n)
		}
	}
	span := func() []byte {
		a.d.early = earlySpan{}
		s.mu.Lock()
		e := a.earlySpanLocked()
		s.mu.Unlock()
		return e.bytes()
	}
	extra := int(s.Status().TxBytes-uint64(len(msg))) / 10 // the measured Writes (none under -race)
	if got, want := span(), append(slices.Clone(msg), bytes.Repeat(msg[:10], extra)...); !bytes.Equal(got, want) {
		t.Fatalf("span of %d bytes, want the %d committed ones", len(got), len(want))
	}
	if !streamRaceEnabled {
		if n := testing.AllocsPerRun(100, func() { span() }); n != 1 {
			t.Fatalf("%v allocations per span, want 1", n)
		}
	}
}
