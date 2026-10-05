package session

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// End rules of an open session (design §4.7; D4, D18, W6) beyond the
// basic ones of actor_term_test.go: the DONE exchange's fallbacks, the
// AbortClosed reset, the IdleTimeout clock and window re-advertisement.

// acHalfCloseSettled runs both directions to the point where only the
// dialer's reading of the passive's data and FIN is missing for the DONE
// exchange: the dialer sent n bytes and its FIN, the passive read them to
// their end, sent n bytes of PRNG(seed+1) and half-closed; the dialer has
// its FIN acknowledged and the passive's data and FIN stored, unread (so
// the passive's FIN is not delivered: the dialer's application must read
// first); every delayed ACK has left. The caller then reads the dialer's
// side with acReadToEOF.
func acHalfCloseSettled(t testing.TB, a, b *Session, n int64, seed uint64) {
	t.Helper()
	if err := acWritePRNG(a, n, seed); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := rendrtest.NewVerifier(seed, n).ReadAll(b); err != nil {
		t.Fatalf("passive read: %v", err)
	}
	if err := acWritePRNG(b, n, seed+1); err != nil {
		t.Fatalf("passive Write: %v", err)
	}
	if err := b.CloseWrite(); err != nil {
		t.Fatalf("passive CloseWrite: %v", err)
	}
	acWaitFor(t, time.Second, "the FINs exchanged", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.st.fin.acked && a.st.peerFinSet && !a.st.peerFinDelivered
	})
	time.Sleep(100 * time.Millisecond) // delayed ACKs (20 ms) have left
	synctest.Wait()
}

// acReadToEOF reads the passive's n bytes of PRNG(seed+1) and its FIN on
// the dialer (acHalfCloseSettled).
func acReadToEOF(t testing.TB, a *Session, n int64, seed uint64) {
	t.Helper()
	if err := rendrtest.NewVerifier(seed+1, n).ReadAll(a); err != nil {
		t.Fatalf("dialer read: %v", err)
	}
}

// TestActorUnknownSessionAfterDoneIsClean (D4): the passive's DONE is lost
// (the frame is dropped, so the dialer kills that carrier at the next
// frame's fseq gap). The passive got the dialer's DONE and ended cleanly;
// the dialer, which sent its DONE, redials, and the bound instance answers
// its JOIN UNKNOWN_SESSION: that is a clean end (io.EOF), not
// ErrSessionLost, since everything of ours was confirmed.
func TestActorUnknownSessionAfterDoneIsClean(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		acHalfCloseSettled(t, a, b, 256<<10, 93)
		l1.DropNextFrame(rendrtest.Down, rendrtest.FrameAck) // the passive's next ACK is its DONE
		acReadToEOF(t, a, 256<<10, 93)
		acDone(t, b, 5*time.Second)
		if st := b.Status(); !errors.Is(st.Err, io.EOF) {
			t.Fatalf("passive end %v, want io.EOF (DONE both ways)", st.Err)
		}
		acDone(t, a, 5*time.Second)
		if st := a.Status(); !errors.Is(st.Err, io.EOF) {
			t.Fatalf("dialer end %v, want io.EOF after UNKNOWN_SESSION following our DONE", st.Err)
		}
		if l1.Stats().Session.FramesDropped != 1 {
			t.Fatal("the passive's DONE was not dropped (stimulus)")
		}
		if joins, _ := w.b.counts(); joins[wire.StatusUnknownSession] != 1 {
			t.Fatalf("JOIN answers %v, want one UNKNOWN_SESSION", joins)
		}
	})
}

// TestActorDoneLingerEndsClean (D4): as above, but the path refuses every
// redial: the dialer, which sent its DONE and never received the peer's,
// ends cleanly (io.EOF) once Linger passed since its DONE — not with
// ErrNoPath at the grace — because everything of ours was confirmed.
func TestActorDoneLingerEndsClean(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.Grace = 10 * time.Second // longer than Linger: the DONE rule decides
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		acHalfCloseSettled(t, a, b, 256<<10, 94)
		l1.DropNextFrame(rendrtest.Down, rendrtest.FrameAck)
		l1.SetRefuse(true)
		acReadToEOF(t, a, 256<<10, 94)
		acWaitFor(t, time.Second, "the dialer placed its DONE", func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.st.doneSent
		})
		a.mu.Lock()
		doneAt := a.st.doneSentAt
		a.mu.Unlock()
		acDone(t, a, 5*time.Second)
		if st := a.Status(); !errors.Is(st.Err, io.EOF) {
			t.Fatalf("dialer end %v, want io.EOF after Linger since its DONE", st.Err)
		}
		if d := time.Since(doneAt); d < a.p.Linger || d > a.p.Linger+100*time.Millisecond {
			t.Fatalf("ended %v after its DONE, want Linger %v", d, a.p.Linger)
		}
		if l1.Stats().Session.FramesDropped != 1 || l1.Stats().DialFailures == 0 {
			t.Fatal("no DONE dropped or no redial refused (stimulus)")
		}
		acDone(t, b, 5*time.Second)
	})
}

// TestActorCloseDiscardResets (§4.7 reset rules, R17): the dialer's
// application closes while the passive keeps sending; once our FIN was
// delivered and data had to be discarded after Close (no FIN from the
// peer), the dialer sends RST(AbortClosed) and ends with net.ErrClosed
// (TCP close semantics); the passive's blocked Write returns
// *AbortError{AbortClosed, Remote: true}.
func TestActorCloseDiscardResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		a, b := w.open(ModeSelector, nil, w.link("p1"))
		werr := make(chan error, 1)
		go func() { // the passive keeps sending
			buf := make([]byte, 16<<10)
			for {
				if _, err := b.Write(buf); err != nil {
					werr <- err
					return
				}
			}
		}()
		rerr := make(chan error, 1)
		go func() { // ... and reads the dialer's data and FIN
			_, err := io.Copy(io.Discard, b)
			rerr <- err
		}()
		if err := acWritePRNG(a, 64<<10, 95); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		acDone(t, a, 5*time.Second)
		if st := a.Status(); !errors.Is(st.Err, net.ErrClosed) {
			t.Fatalf("dialer end %v, want net.ErrClosed", st.Err)
		}
		a.mu.Lock()
		rst, discarded := a.ctl.rst, a.st.discardedAfterClose
		a.mu.Unlock()
		if rst == nil || rst.Code != wire.RstClosed || !discarded {
			t.Fatalf("dialer RST %+v, discarded after Close %v; want RST(AbortClosed) after discarding", rst, discarded)
		}
		var ae *AbortError
		if err := <-werr; !errors.As(err, &ae) || ae.Code != AbortClosed || !ae.Remote {
			t.Fatalf("passive Write: %v, want *AbortError{AbortClosed, Remote}", err)
		}
		if err := <-rerr; err != nil && !errors.As(err, &ae) {
			t.Fatalf("passive Read: %v", err)
		}
		acDone(t, b, 5*time.Second)
	})
}

// TestActorIdleTimeoutCountsFromOpen: the IdleTimeout clock starts no
// earlier than the open. A passive session confirmed 12 s after admission
// and a dialer whose opening took 11 s, both with IdleTimeout 10 s, stay
// open after the open and end by IdleTimeout 10 s after it (§4.7), not at
// once.
func TestActorIdleTimeoutCountsFromOpen(t *testing.T) {
	for _, dialerSide := range []bool{false, true} {
		name := "passive-pending"
		if dialerSide {
			name = "dialer-opening"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				const idle = 10 * time.Second
				w.a.p.Grace, w.a.p.Retain = 30*time.Second, 40*time.Second
				w.b.p.AcceptTimeout = 30 * time.Second
				l1 := w.link("p1")
				spec := w.spec(ModeSelector, l1)
				if dialerSide {
					spec.Params.IdleTimeout = idle
					l1.SetRefuse(true)
				} else {
					w.b.p.IdleTimeout = idle
				}
				type res struct {
					s   *Session
					err error
				}
				ch := make(chan res, 1)
				go func() {
					s, err := w.dial(context.Background(), spec, nil)
					ch <- res{s, err}
				}()
				var s *Session // the side under test
				if dialerSide {
					time.Sleep(11 * time.Second) // the opening phase outlasts IdleTimeout
					l1.SetRefuse(false)
					w.confirmNext()
					r := <-ch
					if r.err != nil {
						t.Fatalf("Dial: %v", r.err)
					}
					s = r.s
				} else {
					b := <-w.b.pending
					w.sess = append(w.sess, b)
					time.Sleep(12 * time.Second) // pending longer than IdleTimeout
					if err := b.Confirm(); err != nil {
						t.Fatalf("Confirm: %v", err)
					}
					if r := <-ch; r.err != nil {
						t.Fatalf("Dial: %v", r.err)
					}
					s = b
				}
				opened := time.Now()
				time.Sleep(time.Second)
				if st := s.Status(); st.State != StateOpen {
					t.Fatalf("1 s after the open: %v %v, want open (idle counts from the open)", st.State, st.Err)
				}
				acDone(t, s, 2*idle)
				if st := s.Status(); !errors.Is(st.Err, ErrIdleTimeout) {
					t.Fatalf("end %v, want ErrIdleTimeout", st.Err)
				}
				// The open is up to one handshake round trip (the
				// passive's OPEN_ACK) away from the instant measured here.
				if d := time.Since(opened); d < idle-10*time.Millisecond || d > idle+100*time.Millisecond {
					t.Fatalf("ended %v after the open, want IdleTimeout %v", d, idle)
				}
			})
		})
	}
}

// TestActorWindowReadvertised (D18, W6): session S2's receive window is
// shut (advertised below 64 KiB) by Budget pressure from another session's
// unread data, while S2's application has read everything — so nothing on
// S2 would ever place another ACK. When the other application drains, only
// S2's re-advertisement deadline (every WindowReadvertise while the last
// advertised window is below 64 KiB) can reopen the window; S2's transfer
// then completes intact.
func TestActorWindowReadvertised(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.b.cenv.Budget = carrier.NewBudget(1 << 20)
		l1, l2 := w.link("p1"), w.link("p2")
		a1, b1 := w.open(ModeSelector, nil, l1)
		a2, b2 := w.open(ModeSelector, nil, l2)
		const held = 1 << 20
		if err := acWritePRNG(a1, held, 96); err != nil {
			t.Fatalf("S1 Write: %v", err)
		}
		acWaitFor(t, 2*time.Second, "S1's unread data buffered", func() bool { return b1.Status().RxBytes == held })
		const n = 2 << 20
		done := make(chan [2]error, 1)
		go func() {
			we, re := acTransfer(a2, b2, n, 97, false)
			done <- [2]error{we, re}
		}()
		acWaitFor(t, 5*time.Second, "S2's window shut", func() bool { return b2.Status().Window < 64<<10 })
		d0 := b2.Status().DeliveredBytes
		time.Sleep(time.Second)
		if d1 := b2.Status().DeliveredBytes; d1 != d0 || d1 >= n {
			t.Fatalf("S2 delivered %d → %d of %d while the Budget was full: not stalled (stimulus)", d0, d1, n)
		}
		acReadVerify(t, b1, held, 96) // the pressure goes; S2 sees no event
		select {
		case r := <-done:
			if r[0] != nil || r[1] != nil {
				t.Fatalf("S2 transfer: %v %v", r[0], r[1])
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("S2 still stalled at %d of %d bytes after the Budget freed", b2.Status().DeliveredBytes, n)
		}
		if b2.Status().Window < 64<<10 {
			t.Fatalf("S2 window %d after the transfer, want reopened", b2.Status().Window)
		}
	})
}
