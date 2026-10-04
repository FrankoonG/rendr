package session

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Pending-session lifecycle (design §6.2; D8, D28): Confirm, Reject,
// AcceptTimeout → CAPACITY, withdrawal by the dialer, and the verdicts the
// tombstone repeats.

// TestActorPendingReject: Reject reaches the dialer as *RejectError; the
// tombstone repeats REJECTED to a retried OPEN of the same session ID; a
// later Confirm returns an error.
func TestActorPendingReject(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1 := w.link("p1")
		spec := w.spec(ModeSelector, l1)
		errc := make(chan error, 1)
		go func() {
			_, err := w.dial(context.Background(), spec, nil)
			errc <- err
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		if b.State() != StatePending {
			t.Fatalf("admitted session state %v, want pending", b.State())
		}
		if err := b.Reject(42, "not today"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		err := <-errc
		var re *RejectError
		if !errors.As(err, &re) || re.Code != 42 || re.Msg != "not today" || !errors.Is(err, ErrRejected) {
			t.Fatalf("Dial: %v, want *RejectError{42, not today}", err)
		}
		<-b.Done()
		v, ok := w.b.reg.endedVerdict(b)
		if !ok || v.Opened || v.Status != wire.StatusRejected || v.Code != 42 || v.Msg != "not today" {
			t.Fatalf("passive verdict %+v (ended %v), want REJECTED(42)", v, ok)
		}
		if err := b.Confirm(); err == nil {
			t.Fatal("Confirm after Reject succeeded")
		}
		// A retried OPEN of the same session gets the same answer.
		spec.SID = b.ID()
		if _, err := w.dial(context.Background(), spec, nil); !errors.As(err, &re) || re.Code != 42 {
			t.Fatalf("retried Dial: %v, want the tombstone's REJECTED(42)", err)
		}
		if len(w.b.reg.opened) != 0 {
			t.Fatal("a rejected session reported Opened")
		}
	})
}

// TestActorAcceptTimeoutIsCapacity: without Confirm the pending session
// answers CAPACITY(CodeAcceptTimeout) after AcceptTimeout; Dial returns
// ErrCapacity and a late Confirm returns ErrCapacity too.
func TestActorAcceptTimeoutIsCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.b.p.AcceptTimeout = time.Second
		spec := w.spec(ModeSelector, w.link("p1"))
		start := time.Now()
		errc := make(chan error, 1)
		go func() {
			_, err := w.dial(context.Background(), spec, nil)
			errc <- err
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		err := <-errc
		if !errors.Is(err, ErrCapacity) {
			t.Fatalf("Dial: %v, want ErrCapacity", err)
		}
		if d := time.Since(start); d < time.Second || d > 1500*time.Millisecond {
			t.Fatalf("Dial failed after %v, want the 1 s AcceptTimeout", d)
		}
		if err := b.Confirm(); !errors.Is(err, ErrCapacity) {
			t.Fatalf("late Confirm: %v, want ErrCapacity", err)
		}
		<-b.Done()
		if v, _ := w.b.reg.endedVerdict(b); v.Status != wire.StatusCapacity || v.Code != wire.CodeAcceptTimeout {
			t.Fatalf("verdict %+v, want CAPACITY(CodeAcceptTimeout)", v)
		}
	})
}

// TestActorPendingWithdrawn: Dial's ctx ends while the OPEN is parked on a
// pending session; Dial returns the ctx error within 100 ms, the dialer
// withdraws with RST(AbortWithdrawn) and the passive ends: Confirm returns
// ErrSessionLost and the tombstone answers UNKNOWN_SESSION.
func TestActorPendingWithdrawn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		spec := w.spec(ModeSelector, w.link("p1"))
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() {
			_, err := w.dial(ctx, spec, nil)
			errc <- err
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		synctest.Wait() // the OPEN is parked: the dialer waits for OPEN_ACK
		cancel()
		start := time.Now()
		err := <-errc
		if !errors.Is(err, context.Canceled) || time.Since(start) > 100*time.Millisecond {
			t.Fatalf("Dial: %v after %v, want context.Canceled at once", err, time.Since(start))
		}
		<-b.Done()
		if err := b.Confirm(); !errors.Is(err, ErrSessionLost) {
			t.Fatalf("Confirm after withdrawal: %v, want ErrSessionLost", err)
		}
		if v, _ := w.b.reg.endedVerdict(b); v.Status != wire.StatusUnknownSession || v.Opened {
			t.Fatalf("verdict %+v, want UNKNOWN_SESSION", v)
		}
	})
}

// TestActorPendingRefuseGoingAway: RefusePending(GOING_AWAY) (a Listener
// closing while its Runtime closes) answers the pending session's OPEN
// with GOING_AWAY (the dialer: ErrCapacity, and its Peer notes the
// instance); Confirm then returns net.ErrClosed and a second RefusePending
// false.
func TestActorPendingRefuseGoingAway(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		noted := make(chan [16]byte, 1)
		spec := w.spec(ModeSelector, w.link("p1"))
		spec.NoteGoAway = func(inst [16]byte) { noted <- inst }
		errc := make(chan error, 1)
		go func() {
			_, err := w.dial(context.Background(), spec, nil)
			errc <- err
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		if !b.RefusePending(wire.StatusGoingAway, 0) {
			t.Fatal("RefusePending on a pending session returned false")
		}
		if err := <-errc; !errors.Is(err, ErrCapacity) {
			t.Fatalf("Dial: %v, want ErrCapacity (GOING_AWAY)", err)
		}
		if inst := <-noted; inst != w.b.cenv.Local {
			t.Fatalf("NoteGoAway(%x), want the passive instance", inst)
		}
		if err := b.Confirm(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Confirm after GOING_AWAY: %v, want net.ErrClosed", err)
		}
		if b.RefusePending(wire.StatusGoingAway, 0) {
			t.Fatal("RefusePending on an ended session returned true")
		}
	})
}

// TestActorDialNoPathAtGrace: every attempt fails; Dial returns ErrNoPath
// wrapping the last carrier error once NoPathGrace passed since the call,
// after at least two attempts (stimulus), and no Registry.Opened.
func TestActorDialNoPathAtGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.Grace = 3 * time.Second
		l1 := w.link("p1")
		l1.SetDial(rendrtest.DialError)
		start := time.Now()
		_, err := w.dial(context.Background(), w.spec(ModeSelector, l1), nil)
		if !errors.Is(err, ErrNoPath) || !strings.Contains(err.Error(), "last carrier error") {
			t.Fatalf("Dial: %v, want ErrNoPath wrapping the last carrier error", err)
		}
		if d := time.Since(start); d < 3*time.Second || d > 3100*time.Millisecond {
			t.Fatalf("Dial failed after %v, want the 3 s grace", d)
		}
		if n := l1.Stats().Dials; n < 2 {
			t.Fatalf("%d factory calls, want the cadence's retries", n)
		}
	})
}

// TestActorPendingShutdown: Shutdown (Runtime.Close) of a pending session
// answers its OPEN with GOING_AWAY ahead of the carrier's GOAWAY and CLOSE:
// Dial fails with ErrCapacity and notes the instance as gone away; the
// tombstone repeats GOING_AWAY and a later Confirm returns net.ErrClosed.
func TestActorPendingShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		noted := make(chan [16]byte, 1)
		spec := w.spec(ModeSelector, w.link("p1"))
		spec.NoteGoAway = func(inst [16]byte) { noted <- inst }
		errc := make(chan error, 1)
		go func() {
			_, err := w.dial(context.Background(), spec, nil)
			errc <- err
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		b.Shutdown()
		if err := <-errc; !errors.Is(err, ErrCapacity) {
			t.Fatalf("Dial: %v, want ErrCapacity (GOING_AWAY)", err)
		}
		if inst := <-noted; inst != w.b.cenv.Local {
			t.Fatalf("NoteGoAway(%x), want the passive instance", inst)
		}
		<-b.Done()
		if v, _ := w.b.reg.endedVerdict(b); v.Opened || v.Status != wire.StatusGoingAway {
			t.Fatalf("verdict %+v, want GOING_AWAY", v)
		}
		if err := b.Confirm(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Confirm after Shutdown: %v, want net.ErrClosed", err)
		}
		if st := b.Status(); st.State != StateEnded || !errors.Is(st.Err, net.ErrClosed) {
			t.Fatalf("passive %v %v, want ended with net.ErrClosed", st.State, st.Err)
		}
	})
}

// TestActorConfirmAfterWithdrawal: the dialer's RST(AbortWithdrawn) is
// already stored when the passive's actor drains a Confirm in the same step
// (the actor was held in its event sink meanwhile): Confirm must answer
// ErrSessionLost — never open a withdrawn session and report it Opened
// (§6.2) — and the tombstone answers UNKNOWN_SESSION.
func TestActorConfirmAfterWithdrawal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.JoinStagger = 10 * time.Millisecond
		l1, l2 := w.link("p1"), w.link("p2")
		spec := w.spec(ModeSelector, l1, l2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errc := make(chan error, 1)
		go func() {
			_, err := w.dial(ctx, spec, nil)
			errc <- err
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		acWaitFor(t, time.Second, "both OPENs parked", func() bool {
			b.mu.Lock()
			defer b.mu.Unlock()
			return len(b.lanes) == 2
		})
		// Hold the passive's actor in its event sink on the CarrierDown of
		// the parked OPEN killed below.
		held, release := make(chan struct{}, 1), make(chan struct{})
		hold := func(ev Event) {
			if ev.Kind == EventCarrierDown && ev.Session == b.ID() {
				select {
				case held <- struct{}{}:
					<-release
				default:
				}
			}
		}
		w.b.ev.hold.Store(&hold)
		defer w.b.ev.hold.Store(nil)
		l1.Kill()
		<-held
		cancel() // Dial returns; the dialer withdraws its OPEN still parked on p2
		if err := <-errc; !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial: %v, want context.Canceled", err)
		}
		acWaitFor(t, time.Second, "the withdrawal RST stored", func() bool {
			b.mu.Lock()
			defer b.mu.Unlock()
			return b.st.rstIn != nil
		})
		confirmed := make(chan error, 1)
		go func() { confirmed <- b.Confirm() }()
		acWaitFor(t, time.Second, "the Confirm queued", func() bool {
			b.mb.mu.Lock()
			defer b.mb.mu.Unlock()
			return len(b.mb.cmds) > 0
		})
		close(release)
		if err := <-confirmed; !errors.Is(err, ErrSessionLost) {
			t.Fatalf("Confirm after the withdrawal RST: %v, want ErrSessionLost", err)
		}
		<-b.Done()
		if v, _ := w.b.reg.endedVerdict(b); v.Opened || v.Status != wire.StatusUnknownSession {
			t.Fatalf("verdict %+v, want withdrawn (UNKNOWN_SESSION)", v)
		}
		w.b.reg.mu.Lock()
		opened := len(w.b.reg.opened)
		w.b.reg.mu.Unlock()
		if opened != 0 {
			t.Fatal("a withdrawn session reported Opened")
		}
	})
}

// TestActorVerdictRepliesBeforeEnded: Reject and RefusePending get their
// answer before the actor reports the verdict to Registry.Ended, as
// Confirm does before Opened. A Registry.Ended that waits for something
// the caller does only after its Reject or RefusePending returned (for
// example a lock the caller still holds) would otherwise never complete.
func TestActorVerdictRepliesBeforeEnded(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		name := "reject"
		if refuse {
			name = "refuse"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				gate := make(chan struct{})
				var closeOnce sync.Once
				defer closeOnce.Do(func() { close(gate) }) // before the teardown, also when the test fails
				prev := w.b.reg.onEnded
				w.b.reg.onEnded = func(s *Session, v Verdict) {
					<-gate
					prev(s, v)
				}
				spec := w.spec(ModeSelector, w.link("p1"))
				errc := make(chan error, 1)
				go func() {
					_, err := w.dial(context.Background(), spec, nil)
					errc <- err
				}()
				b := <-w.b.pending
				w.sess = append(w.sess, b)
				replied := make(chan error, 1)
				go func() {
					if refuse {
						if !b.RefusePending(wire.StatusGoingAway, 0) {
							replied <- errors.New("RefusePending returned false on a pending session")
							return
						}
						replied <- nil
						return
					}
					replied <- b.Reject(9, "no")
				}()
				select {
				case err := <-replied:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("the verdict's reply waited for Registry.Ended")
				}
				closeOnce.Do(func() { close(gate) })
				err := <-errc
				var re *RejectError
				switch {
				case refuse && !errors.Is(err, ErrCapacity):
					t.Fatalf("Dial: %v, want ErrCapacity (GOING_AWAY)", err)
				case !refuse && (!errors.As(err, &re) || re.Code != 9):
					t.Fatalf("Dial: %v, want *RejectError{9}", err)
				}
				<-b.Done()
				if _, ok := w.b.reg.endedVerdict(b); !ok {
					t.Fatal("Registry.Ended was never called")
				}
			})
		})
	}
}
