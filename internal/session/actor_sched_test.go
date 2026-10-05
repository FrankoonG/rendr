package session

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// SCHED application on the passive (design §7.5, §7.6; L45, C26).

// acSched delivers SCHED{epoch, ids} with cause c on the passive lane l as
// its reader would (Control after CRC verification).
func acSched(t testing.TB, l *lane, c wire.SchedCause, epoch uint32, ids ...uint32) {
	t.Helper()
	sc := wire.Sched{Epoch: epoch, N: len(ids)}
	copy(sc.IDs[:], ids)
	var p [wire.SchedFixedLen + 4*wire.MaxSchedIDs]byte
	n := wire.PutSched(p[:], &sc)
	h := wire.Header{Type: wire.TypeSched, Flags: uint8(c), Len: uint32(n), Handle: wire.SessionHandle}
	if err := l.Control(l.c, h, p[:n]); err != nil {
		t.Fatalf("SCHED %d: %v", epoch, err)
	}
}

// TestEpochOrdering_L45: SCHEDs arriving with epochs 3, 1, 2 leave the
// passive at epoch 3 — an older epoch is never applied, also not after a
// newer one was stored — and the applied epoch is echoed.
func TestEpochOrdering_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		a, b := w.open(ModeSelector, nil, w.link("p1"))
		acWaitFor(t, time.Second, "the first SCHED applied", func() bool { return b.Status().SchedEpoch == 1 })
		b.mu.Lock()
		pl := b.lanes[0]
		b.mu.Unlock()
		for _, e := range []uint32{3, 1, 2} {
			acSched(t, pl, wire.SchedInitial, e, pl.id)
			synctest.Wait() // the passive's actor ran
			if got := b.Status().SchedEpoch; got != 3 {
				t.Fatalf("after SCHED %d: applied epoch %d, want 3", e, got)
			}
		}
		// The echo of epoch 3 reached the dialer, which ignores an echo of
		// an epoch it never published: its echoed epoch stays 1.
		b.mu.Lock()
		echo := b.ctl.epoch
		b.mu.Unlock()
		if echo != 3 {
			t.Fatalf("passive echoes %d, want 3", echo)
		}
		if st := a.Status(); st.SchedEpoch != 1 || st.SchedEchoed != 1 {
			t.Fatalf("dialer epoch %d echoed %d, want 1 and 1", st.SchedEpoch, st.SchedEchoed)
		}
		if st := b.Status(); st.MigDeath+st.MigQuality+st.MigExplicit != 0 {
			t.Fatalf("initial-cause SCHEDs counted migrations: %+v", st)
		}
		if we, re := acTransfer(b, a, 256<<10, 4, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// TestInitialSchedNeverCounts_L45: two OPENs of the opening race park on
// the pending passive session; its epoch-0 sender is the oldest one (p1),
// while the dialer's first OPEN_ACK(OK) arrives over p2 (p1 is slow), so
// the dialer's initial SCHED moves the passive's sending lane. Neither end
// counts a migration (C26); routing converges on the dialer's carrier.
func TestInitialSchedNeverCounts_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p2")
		l1.SetDelay(50*time.Millisecond, 0)
		l2.SetDelay(time.Millisecond, 0)
		spec := w.spec(ModeSelector, l1, l2)
		type res struct {
			s   *Session
			err error
		}
		ch := make(chan res, 1)
		go func() {
			s, err := w.dial(context.Background(), spec, nil)
			ch <- res{s, err}
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		acWaitFor(t, 2*time.Second, "both OPENs parked", func() bool {
			b.mu.Lock()
			defer b.mu.Unlock()
			return len(b.lanes) == 2
		})
		b.mu.Lock()
		oldest := b.lanes[0].id
		b.mu.Unlock()
		if err := b.Confirm(); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		r := <-ch
		if r.err != nil {
			t.Fatalf("Dial: %v", r.err)
		}
		a := r.s
		active := acActive(a)
		if active == oldest || a.Status().Carriers[0].Name != "p2" {
			t.Fatalf("dialer active %d (%+v); the passive's epoch-0 sender %d must differ", active, a.Status().Carriers, oldest)
		}
		acWaitFor(t, 2*time.Second, "routing converged", func() bool {
			_, routed, _ := acRouted(b)
			return routed == active && a.Status().SchedEchoed == 1
		})
		if we, re := acTransfer(b, a, 1<<20, 13, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
		for _, s := range []*Session{a, b} {
			if st := s.Status(); st.MigDeath+st.MigQuality+st.MigExplicit != 0 {
				t.Fatalf("%v counted migrations: %d/%d/%d", s.Role(), st.MigDeath, st.MigQuality, st.MigExplicit)
			}
		}
	})
}
