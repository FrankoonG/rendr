package session

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"
)

// F-8: an EarlyReturn dialer is the application's before its open binds the
// peer instance (M4-D12, M4-D15): the actor writes Session.peer in
// openOKLocked after Dial returned, while the application may call
// PeerInstance and Status at any time. Readers other than the actor see the
// peer only once it is published: PeerInstance through bound (an atomic
// stored right after the write), Status through the control snapshot that
// the same critical section publishes — never the bare field. Before the
// fix Status read the field unsynchronised (race-unit pass 3 at the M5
// pin: Session.status against openOKLocked).

// TestPeerInstanceUnpublishedUntilBound (F-8; white-box, deterministic):
// the state inside openOKLocked's critical section — the peer written,
// bound not yet stored, the snapshot not yet republished — is set by hand
// on a deferred EarlyReturn session, under s.mu as the actor writes it.
// PeerInstance reports the unbound zero until bound is stored; Status
// reports the snapshot's peer, zero while its State is Pending, whatever
// the field holds. The real open then publishes the passive's instance on
// both, with StateOpen.
func TestPeerInstanceUnpublishedUntilBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		want := w.b.cenv.Local
		var zero [16]byte
		check := func(when string, bound bool, inst, status [16]byte) {
			t.Helper()
			st := s.Status()
			if s.PeerBound() != bound || s.PeerInstance() != inst || st.PeerInstance != status {
				t.Fatalf("%s: PeerBound %v PeerInstance %x Status().PeerInstance %x (state %v), want %v %x %x",
					when, s.PeerBound(), s.PeerInstance(), st.PeerInstance, st.State, bound, inst, status)
			}
		}
		check("after Dial", false, zero, zero)

		// The actor's write, before its store of bound: unpublished.
		forged := [16]byte{0xF8, 0x8F}
		s.mu.Lock()
		s.peer = forged
		s.mu.Unlock()
		check("peer written, bound not stored", false, zero, zero)

		// bound stored: PeerInstance publishes the peer; Status keeps the
		// snapshot's, which still says Pending.
		s.bound.Store(true)
		if st := s.Status(); st.State != StatePending {
			t.Fatalf("state %v without a republished snapshot, want pending", st.State)
		}
		check("bound stored, snapshot not republished", true, forged, zero)

		// Back to the unbound state; the real open binds the passive.
		s.mu.Lock()
		s.bound.Store(false)
		s.peer = zero
		s.mu.Unlock()
		check("restored", false, zero, zero)
		msg := stPattern(0, 1000)
		if _, err := s.Write(msg); err != nil {
			t.Fatalf("Write: %v", err)
		}
		p := w.eaPending()
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
		acWaitFor(t, 5*time.Second, "the dialer opened", func() bool { return s.State() == StateOpen })
		if st := s.Status(); st.State != StateOpen || st.PeerInstance != want {
			t.Fatalf("open: Status state %v PeerInstance %x, want open and %x", st.State, st.PeerInstance, want)
		}
		check("open", true, want, want)
		if st := p.Status(); st.PeerInstance != w.a.cenv.Local || p.PeerInstance() != w.a.cenv.Local {
			t.Fatalf("passive: Status().PeerInstance %x PeerInstance %x, want the dialer's %x", st.PeerInstance, p.PeerInstance(), w.a.cenv.Local)
		}
	})
}

// TestPeerInstanceAfterBoundIsThePeer (F-8; the order openOKLocked keeps,
// a -race row): PeerInstance's gate is sound only because the actor
// writes s.peer before it stores bound, so that a reader that saw bound
// set also sees the write (the atomic store releases it). The reader here
// synchronises with the open only through PeerBound — it polls it, in the
// bubble's virtual time, from before the trigger until it reports the
// binding — and then reads PeerInstance once: it must be the passive's
// instance. With the store moved above the write the reader's load of
// bound no longer orders the write before its read, and the race detector
// reports the pair on the first run whichever happened first in real time
// (deterministic in the happens-before sense, as
// TestEarlyReturnPeerInstanceDuringOpen); without -race the row checks
// the value.
func TestPeerInstanceAfterBoundIsThePeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		want := w.b.cenv.Local
		got := make(chan [16]byte, 1)
		go func() {
			for !s.PeerBound() {
				time.Sleep(10 * time.Microsecond)
			}
			got <- s.PeerInstance()
		}()
		msg := stPattern(0, 1000)
		if _, err := s.Write(msg); err != nil {
			t.Fatalf("Write: %v", err)
		}
		p := w.eaPending()
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		var inst [16]byte
		select {
		case inst = <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("the reader never saw the dialer bound")
		}
		if inst != want {
			t.Fatalf("PeerInstance once PeerBound reported the binding: %x, want the passive's %x", inst, want)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
	})
}

// TestStatusSnapshotCarriesPeer (F-8; white-box unit row): Status takes
// the peer instance from the published snapshot. A passive session's first
// snapshot (initialSnapLocked, NewPending) carries the dialer's instance,
// so its Status reports it before its actor ever ran; a dialer's first
// snapshot carries none, and the snapshot the actor publishes after the
// binding (publishLocked, the same critical section as StateOpen) carries
// the bound instance with that state.
func TestStatusSnapshotCarriesPeer(t *testing.T) {
	inst := [16]byte{0xF8, 0x01}
	ps := &Session{p: Params{Role: RolePassive}, peer: inst}
	ps.mu.Lock()
	ps.ctl.state = StatePending
	ps.initialSnapLocked()
	ps.mu.Unlock()
	if st := ps.Status(); st.PeerInstance != inst || ps.PeerInstance() != inst {
		t.Fatalf("passive before its actor ran: Status().PeerInstance %x PeerInstance %x, want %x", st.PeerInstance, ps.PeerInstance(), inst)
	}

	ds := &Session{p: Params{Role: RoleDialer}}
	ds.mu.Lock()
	ds.ctl.state = StatePending
	ds.initialSnapLocked()
	ds.mu.Unlock()
	if st := ds.Status(); st.PeerInstance != ([16]byte{}) || st.State != StatePending {
		t.Fatalf("dialer before the binding: Status state %v PeerInstance %x, want pending and zero", st.State, st.PeerInstance)
	}
	a := newActor(ds)
	ds.mu.Lock()
	ds.peer = inst // openOKLocked's binding, then its publication
	ds.bound.Store(true)
	ds.ctl.state = StateOpen
	a.publishLocked(time.Now())
	ds.mu.Unlock()
	if st := ds.Status(); st.PeerInstance != inst || st.State != StateOpen || ds.PeerInstance() != inst {
		t.Fatalf("dialer after the binding: Status state %v PeerInstance %x, PeerInstance %x; want open and %x", st.State, st.PeerInstance, ds.PeerInstance(), inst)
	}
}

// TestEarlyReturnPeerInstanceDuringOpen (F-8; a -race row, deterministic
// in the happens-before sense): a reader goroutine started before the
// trigger reads PeerInstance and then synchronises with nothing the open
// does (no synctest.Wait runs before the passive confirmed, so not even
// the bubble's park edges order it). Under -race the bare field read
// races with openOKLocked's write whichever comes first in real time, so
// the row FAILS without the publication rule; with it the read loads bound
// first. Without -race it checks the values: zero or the passive's
// instance during the open, the passive's once it is observed open.
func TestEarlyReturnPeerInstanceDuringOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := eaNewWorld(t, nil)
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		want := w.b.cenv.Local
		release := make(chan struct{})
		got := make(chan [2][16]byte, 1)
		go func() {
			during := s.PeerInstance()
			<-release
			got <- [2][16]byte{during, s.PeerInstance()}
		}()
		msg := stPattern(0, 1000)
		if _, err := s.Write(msg); err != nil {
			t.Fatalf("Write: %v", err)
		}
		p := w.eaPending()
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		acWaitFor(t, 5*time.Second, "the dialer opened", func() bool { return s.State() == StateOpen })
		close(release)
		r := <-got
		if r[0] != ([16]byte{}) && r[0] != want {
			t.Fatalf("PeerInstance during the open: %x, want zero or %x", r[0], want)
		}
		if r[1] != want {
			t.Fatalf("PeerInstance once open: %x, want %x", r[1], want)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
	})
}
