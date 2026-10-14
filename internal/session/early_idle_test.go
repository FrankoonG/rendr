package session

import (
	"bytes"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// EarlyReturn and IdleTimeout before the trigger (K21; plan:277, plan:385):
// a session the application holds but never used ends with ErrIdleTimeout
// at its IdleTimeout from Dial and sends nothing (earlyIdleLocked); a Write
// counts as use, also one still copying at the deadline. Helpers start
// with "ei".

// eiIdle is the IdleTimeout of these rows (Params: no clamp).
const eiIdle = 10 * time.Second

// eiSpec is an EarlyReturn DialSpec over l with IdleTimeout eiIdle.
func (w *acWorld) eiSpec(l ...*rendrtest.Link) DialSpec {
	spec := w.eaSpec(ModeSelector, 64<<10, l...)
	spec.Params.IdleTimeout = eiIdle
	return spec
}

// TestEarlyIdleUnusedEndsLocally (K21): a deferred session ends with
// ErrIdleTimeout at Dial + IdleTimeout and not earlier, without a factory
// call or an admitted session; Registry.Ended runs once (the root releases
// the MaxSessions unit there) with no opened verdict, and one
// EventSessionEnd carries the error.
func TestEarlyIdleUnusedEndsLocally(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eiSpec(l))
		dialed := time.Now()
		time.Sleep(eiIdle - time.Millisecond)
		synctest.Wait()
		if st := s.State(); st != StatePending {
			t.Fatalf("1 ms before the idle limit: state %v, want pending", st)
		}
		acDone(t, s, time.Second)
		if el := time.Since(dialed); el < eiIdle || el > eiIdle+time.Millisecond {
			t.Fatalf("ended %v after Dial, want IdleTimeout %v", el, eiIdle)
		}
		if err := s.Status().Err; !errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("end %v, want ErrIdleTimeout", err)
		}
		if v, ok := w.a.reg.endedVerdict(s); !ok || v.Opened {
			t.Fatalf("Registry.Ended: %v %+v, want called with no opened verdict", ok, v)
		}
		if ev := w.a.ev.of(s.ID(), EventSessionEnd); len(ev) != 1 || !errors.Is(ev[0].Err, ErrIdleTimeout) {
			t.Fatalf("SessionEnd events %+v, want one with ErrIdleTimeout", ev)
		}
		time.Sleep(time.Minute) // anything an opening started would have run
		synctest.Wait()
		if d := l.Stats().Dials; d != 0 {
			t.Fatalf("%d factory calls, want 0 (nothing is sent)", d)
		}
		select {
		case p := <-w.b.pending:
			w.sess = append(w.sess, p)
			t.Fatal("the passive admitted a session")
		default:
		}
	})
}

// TestEarlyIdleWriteCopyingAtDeadline (K21): a Write that holds its
// reservation when the idle deadline passes (its copy is held from 1 s
// before the deadline to 1 s after) is activity: it returns (n, nil), its
// commit opens the session and the passive reads its bytes.
func TestEarlyIdleWriteCopyingAtDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eiSpec(l))
		dialed := time.Now()
		var copiedAt time.Time
		stSetCopyHook(t, s, func() {
			if copiedAt.IsZero() {
				time.Sleep(time.Until(dialed.Add(eiIdle)) + time.Second)
				copiedAt = time.Now()
			}
		})
		time.Sleep(eiIdle - time.Second)
		msg := stPattern(0, 1000)
		if n, err := s.Write(msg); n != len(msg) || err != nil {
			t.Fatalf("Write copying across the idle deadline = (%d, %v), want (%d, nil)", n, err, len(msg))
		}
		if !copiedAt.After(dialed.Add(eiIdle)) {
			t.Fatalf("premise: the copy ended %v after Dial, want past the idle limit", copiedAt.Sub(dialed))
		}
		p := w.eaPending()
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
		if d := l.Stats().Dials; d != 1 {
			t.Fatalf("%d factory calls, want 1", d)
		}
	})
}

// TestEarlyIdleTriggerRacesDeadline (K21): a Read at the very instant of
// the idle deadline races the expiry; each run ends in exactly one of the
// two outcomes — the Read's trigger claimed the session first (it opens and
// the Read returns the passive's bytes) or the expiry did (the Read returns
// ErrIdleTimeout and nothing was dialled) — never a session left pending.
func TestEarlyIdleTriggerRacesDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		var opened, expired int
		for range 20 {
			dials := l.Stats().Dials
			s := w.eaDial(w.eiSpec(l))
			time.Sleep(eiIdle)
			rd := eaAsync(func() (int, error) { return s.Read(make([]byte, 4)) })
			synctest.Wait()
			if l.Stats().Dials == dials {
				r := <-rd
				if r.n != 0 || !errors.Is(r.err, ErrIdleTimeout) {
					t.Fatalf("nothing dialled, but the Read returned (%d, %v), want ErrIdleTimeout", r.n, r.err)
				}
				acDone(t, s, time.Second)
				expired++
				continue
			}
			p := w.eaPending()
			if err := p.Confirm(); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Write([]byte("pong")); err != nil {
				t.Fatal(err)
			}
			if r := <-rd; r.n != 4 || r.err != nil {
				t.Fatalf("the trigger won, but the Read returned (%d, %v)", r.n, r.err)
			}
			if st := s.State(); st != StateOpen {
				t.Fatalf("the trigger won, but the dialer is %v", st)
			}
			s.Abort(0x1000, "done")
			acDone(t, s, 5*time.Second)
			acDone(t, p, 5*time.Second)
			opened++
		}
		t.Logf("outcomes: %d opened by the Read, %d expired", opened, expired)
	})
}
