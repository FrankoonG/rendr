package session

import (
	"context"
	"errors"
	"net"
	"strings"
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

// TestActorPendingShutdown: Shutdown of a pending session answers
// GOING_AWAY (the dialer: ErrCapacity); Confirm returns net.ErrClosed.
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
