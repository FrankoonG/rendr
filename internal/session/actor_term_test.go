package session

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Termination component tests (design §4.7; D4): a clean end by DONE both
// ways, the linger expiry RST and the peer's RST.

// TestActorDoneBothWays: both directions half-close after their data; the
// DONE exchange ends both sessions cleanly (io.EOF), the passive's verdict
// is Opened, and every byte arrived intact.
func TestActorDoneBothWays(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeBond} {
		t.Run(acModeName(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				l1, l2 := w.link("p1"), w.link("p2")
				a, b := w.open(mode, nil, l1, l2)

				const ab, ba = 3 << 20, 1 << 20
				errs := make(chan error, 4)
				go func() {
					we, re := acTransfer(a, b, ab, 11, true)
					errs <- we
					errs <- re
				}()
				go func() {
					we, re := acTransfer(b, a, ba, 12, true)
					errs <- we
					errs <- re
				}()
				for range 4 {
					if err := <-errs; err != nil {
						t.Fatalf("transfer: %v", err)
					}
				}
				finished := time.Now()
				for _, s := range []*Session{a, b} {
					// DONE ends both at once, long before the Linger fallback.
					select {
					case <-s.Done():
					case <-time.After(10 * time.Second):
						t.Fatalf("%v session did not end after DONE both ways", s.Role())
					}
					if d := time.Since(finished); d > 200*time.Millisecond {
						t.Fatalf("%v session ended %v after both FINs were delivered, want the DONE exchange", s.Role(), d)
					}
					st := s.Status()
					if st.State != StateEnded || !errors.Is(st.Err, io.EOF) {
						t.Fatalf("%v: state %v err %v, want ended with io.EOF", s.Role(), st.State, st.Err)
					}
					if st.TxBytes == 0 || st.DeliveredBytes == 0 {
						t.Fatalf("%v: no load: %+v", s.Role(), st)
					}
				}
				if v, ok := w.b.reg.endedVerdict(b); !ok || !v.Opened {
					t.Fatalf("passive verdict %+v (ended %v), want Opened", v, ok)
				}
				if _, ok := w.a.reg.endedVerdict(a); !ok {
					t.Fatal("dialer session did not report Registry.Ended")
				}
				if n := len(w.a.ev.of(a.ID(), EventSessionEnd)); n != 1 {
					t.Fatalf("dialer SessionEnd events: %d, want 1", n)
				}
				// Reads keep returning io.EOF, Writes net.ErrClosed.
				if _, err := a.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("Read after the clean end: %v, want io.EOF", err)
				}
				if _, err := a.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Write after the clean end: %v, want net.ErrClosed", err)
				}
			})
		})
	}
}

// TestActorLingerExpiryResets: the passive application never reads, so the
// dialer's FIN is never delivered; the dialer's Close lingers for Linger,
// then sends RST(AbortLinger) and ends with net.ErrClosed; the passive ends
// with *AbortError{AbortLinger, Remote: true} and its next Read returns it.
func TestActorLingerExpiryResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		a, b := w.open(ModeSelector, nil, w.link("p1"))
		if err := acWritePRNG(a, 256<<10, 3); err != nil {
			t.Fatalf("Write: %v", err)
		}
		closedAt := time.Now()
		if err := a.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		<-a.Done()
		elapsed := time.Since(closedAt)
		if linger := a.p.Linger; elapsed < linger || elapsed > linger+time.Second {
			t.Fatalf("dialer ended %v after Close, want Linger %v (+1 s)", elapsed, linger)
		}
		if st := a.Status(); !errors.Is(st.Err, net.ErrClosed) {
			t.Fatalf("dialer end error %v, want net.ErrClosed", st.Err)
		}
		<-b.Done()
		var ae *AbortError
		if st := b.Status(); !errors.As(st.Err, &ae) || ae.Code != AbortLinger || !ae.Remote {
			t.Fatalf("passive end error %v, want *AbortError{AbortLinger, Remote}", st.Err)
		}
		if _, err := b.Read(make([]byte, 16)); !errors.As(err, &ae) || ae.Code != AbortLinger {
			t.Fatalf("passive Read after the RST: %v, want the AbortError", err)
		}
		if v, _ := w.a.reg.endedVerdict(a); !v.Opened {
			t.Fatalf("dialer verdict %+v", v)
		}
		w.a.reg.mu.Lock()
		on := w.a.reg.lingering[a]
		w.a.reg.mu.Unlock()
		if on {
			t.Fatal("dialer still reported as lingering after its end")
		}
	})
}

// TestActorPeerRstEndsSession: the passive's IdleTimeout expires (the
// session stays silent), so it sends RST(AbortIdle) and ends with
// ErrIdleTimeout; the dialer ends at once with *AbortError{AbortIdle,
// Remote: true} and sends no RST back.
func TestActorPeerRstEndsSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.b.p.IdleTimeout = 3 * time.Second
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		start := time.Now()
		<-b.Done()
		if idle := time.Since(start); idle < 2*time.Second || idle > 4*time.Second {
			t.Fatalf("passive ended %v after the open, want its 3 s IdleTimeout", idle)
		}
		<-a.Done()
		var ae *AbortError
		if st := a.Status(); !errors.As(st.Err, &ae) || ae.Code != AbortIdle || !ae.Remote {
			t.Fatalf("dialer end error %v, want *AbortError{AbortIdle, Remote}", st.Err)
		}
		if _, err := a.Read(make([]byte, 1)); !errors.As(err, &ae) {
			t.Fatalf("dialer Read after the RST: %v, want the AbortError", err)
		}
		if st := b.Status(); !errors.Is(st.Err, ErrIdleTimeout) {
			t.Fatalf("passive end error %v, want ErrIdleTimeout", st.Err)
		}
		a.mu.Lock()
		rst := a.ctl.rst
		a.mu.Unlock()
		if rst != nil {
			t.Fatalf("the dialer answered the RST with RST %+v", rst)
		}
		if got := l1.Stats().Session.Bytes; got == 0 {
			t.Fatal("no bytes crossed the link")
		}
	})
}

// acModeName names a mode for subtest names.
func acModeName(m Mode) string {
	if m == ModeBond {
		return "bond"
	}
	return "selector"
}

// TestActorOffsetExhaustion: a Write that would pass the offset limit
// returns *AbortError{AbortExhausted}; the session ends with exactly one
// RST(Exhausted), which the peer receives as *AbortError{AbortExhausted,
// Remote: true} (L14).
func TestActorOffsetExhaustion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.FirstOffset = 1<<62 - 1<<20
		w.b.p.FirstOffset = w.a.p.FirstOffset
		a, b := w.open(ModeSelector, nil, w.link("p1"))
		read := make(chan error, 1)
		go func() { // the peer reads, so the window keeps opening
			buf := make([]byte, 64<<10)
			for {
				if _, err := b.Read(buf); err != nil {
					read <- err
					return
				}
			}
		}()
		err := acWritePRNG(a, 2<<20, 3)
		var ae *AbortError
		if !errors.As(err, &ae) || ae.Code != AbortExhausted || ae.Remote {
			t.Fatalf("Write past the limit: %v, want *AbortError{AbortExhausted}", err)
		}
		acDone(t, a, 5*time.Second)
		acDone(t, b, 5*time.Second)
		if err := <-read; !errors.As(err, &ae) || ae.Code != AbortExhausted {
			t.Fatalf("peer Read: %v, want the AbortError", err)
		}
		if st := b.Status(); !errors.As(st.Err, &ae) || ae.Code != AbortExhausted || !ae.Remote {
			t.Fatalf("peer end error %v, want *AbortError{AbortExhausted, Remote}", st.Err)
		}
		if st := a.Status(); !errors.As(st.Err, &ae) || ae.Code != AbortExhausted || ae.Remote {
			t.Fatalf("local end error %v", st.Err)
		}
	})
}

// TestActorShutdownGoesAway: Runtime.Close on the passive (Shutdown) sends
// GOAWAY and RST(AbortGoingAway) and ends it with net.ErrClosed; the dialer
// ends with *AbortError{AbortGoingAway, Remote: true} and its Peer notes
// the instance as gone away (D21).
func TestActorShutdownGoesAway(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		noted := make(chan [16]byte, 4)
		l1 := w.link("p1")
		spec := w.spec(ModeSelector, l1)
		spec.NoteGoAway = func(inst [16]byte) { noted <- inst }
		ch := make(chan *Session, 1)
		go func() {
			s, err := w.dial(context.Background(), spec, nil)
			if err != nil {
				t.Errorf("Dial: %v", err)
			}
			ch <- s
		}()
		b := w.confirmNext()
		a := <-ch
		b.Shutdown()
		acDone(t, b, 5*time.Second)
		acDone(t, a, 5*time.Second)
		if st := b.Status(); !errors.Is(st.Err, net.ErrClosed) {
			t.Fatalf("passive end error %v, want net.ErrClosed", st.Err)
		}
		var ae *AbortError
		if st := a.Status(); !errors.As(st.Err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
			t.Fatalf("dialer end error %v, want *AbortError{AbortGoingAway, Remote}", st.Err)
		}
		select {
		case inst := <-noted:
			if inst != w.b.cenv.Local {
				t.Fatalf("NoteGoAway(%x), want the passive instance", inst)
			}
		default:
			// The RST may win the race against the GOAWAY: then no note.
		}
	})
}

// TestActorUnknownSessionIsSessionLost: the passive's retention (1 s) runs
// out during an outage that the dialer's grace (10 s) survives; the
// dialer's JOIN then gets UNKNOWN_SESSION from the bound instance and the
// session ends at once with ErrSessionLost (L19).
func TestActorUnknownSessionIsSessionLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.Grace, w.a.p.Retain = 10*time.Second, time.Second
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		l1.SetRefuse(true)
		l1.Kill()
		acDone(t, b, 10*time.Second)
		if st := b.Status(); !errors.Is(st.Err, ErrNoPath) {
			t.Fatalf("passive end %v, want ErrNoPath after its retention", st.Err)
		}
		l1.SetRefuse(false)
		start := time.Now()
		select {
		case <-a.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("the dialer did not end after UNKNOWN_SESSION")
		}
		if st := a.Status(); !errors.Is(st.Err, ErrSessionLost) {
			t.Fatalf("dialer end %v, want ErrSessionLost", st.Err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("ErrSessionLost %v after the path returned", d)
		}
		if joins, _ := w.b.counts(); joins[wire.StatusUnknownSession] == 0 {
			t.Fatal("no JOIN was answered UNKNOWN_SESSION (stimulus)")
		}
	})
}

// TestActorPeerRestartFastFail: the session has no live carrier and its
// redial reaches another instance of the peer (a restart): the session
// ends with ErrSessionLost without waiting for the grace (plan §3.4).
func TestActorPeerRestartFastFail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		p2 := acNewPassive(t, 3, nil) // the restarted peer
		defer p2.wg.Wait()
		l1 := w.link("p1")
		l2 := rendrtest.NewLink(rendrtest.LinkConfig{Name: "p2", Accept: p2.accept})
		w.links = append(w.links, l2)
		w.a.p.Grace = 30 * time.Second
		a, _ := w.open(ModeSelector, nil, l1, l2)
		l1.SetRefuse(true)
		start := time.Now()
		l1.Kill()
		acDone(t, a, 10*time.Second)
		if st := a.Status(); !errors.Is(st.Err, ErrSessionLost) {
			t.Fatalf("end %v, want ErrSessionLost", st.Err)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("ErrSessionLost after %v, want the fast fail", d)
		}
		if l2.Stats().Dials == 0 {
			t.Fatal("the restarted instance was never dialled (stimulus)")
		}
	})
}
