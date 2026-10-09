package session

import (
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The actor side of a packet session's end and of its no-path episodes (M2
// design §A5.1, §A5.2, §A5.6; M2-D35, M2-D40): Close and the end through
// the actor, the EOF straggler deadline and the no-path ageing step.

// TestPacketCloseEndsClean (M2-D40): Close on one end of a packet session
// returns at once; the datagrams it queued still leave, then its FIN; the
// peer reads every one of them and then io.EOF, and the DONE exchange ends
// both sessions cleanly (io.EOF, every carrier and buffer released). Later
// calls on the closed end return net.ErrClosed, never io.EOF (L07).
func TestPacketCloseEndsClean(t *testing.T) {
	for _, closer := range []string{"dialer", "passive"} {
		t.Run(closer, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := wpNewWorld(t, nil)
				defer w.teardown()
				l := wpLink(w, "p1", 1400)
				a, b := wpOpen(w, wpSpec(w, ModeSelector, 1400, l), nil)
				from, to := a, b
				if closer == "passive" {
					from, to = b, a
				}
				const n = 10
				for i := range uint64(n) {
					dpWrite(t, from, i, 700)
				}
				start := time.Now()
				if err := from.Close(); err != nil || time.Since(start) != 0 {
					t.Fatalf("Close = %v after %v, want nil at once", err, time.Since(start))
				}
				if _, err := from.WriteTo([]byte{1}); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("WriteTo after Close = %v, want net.ErrClosed", err)
				}
				if _, err := from.ReadFrom(make([]byte, 10)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ReadFrom after Close = %v, want net.ErrClosed", err)
				}
				buf := make([]byte, 2000)
				for i := range uint64(n) {
					k, err := to.ReadFrom(buf)
					if err != nil || k != 700 || dpID(buf) != i {
						t.Fatalf("datagram %d: %d bytes (id %d), %v", i, k, dpID(buf), err)
					}
				}
				if k, err := to.ReadFrom(buf); k != 0 || err != io.EOF {
					t.Fatalf("after the closer's datagrams: %d, %v; want io.EOF", k, err)
				}
				acDone(t, from, 5*time.Second)
				acDone(t, to, 5*time.Second)
				for _, s := range []*Session{from, to} {
					if st := s.Status(); st.State != StateEnded || st.Err != io.EOF {
						t.Fatalf("%v ended %v with %v, want io.EOF", s.Role(), st.State, st.Err)
					}
				}
				if _, err := to.WriteTo([]byte{1}); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
					t.Fatalf("the peer's WriteTo after the end = %v", err)
				}
			})
		})
	}
}

// TestPacketActorFinWait_L40 (M2-D40): when the peer's FIN arrives with a
// seq below it never received, the actor's straggler deadline (finWaitAt)
// delivers the FIN once the receive queue is empty: ReadFrom returns every
// queued datagram, waits until finWaitAt, and then io.EOF — never earlier
// (a straggler may still come) and never forever (L40).
func TestPacketActorFinWait_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := dpNewPair(dpOpt{}, dpOpt{}, true)
		for i := range uint64(3) {
			dpWrite(t, p.a.s, i, 100)
		}
		dpClose(p.a.s)
		lost := uint64(1) // seq 1 never arrives
		dpSettle(t, p, func(_ int, f carrier.BatchFrame) bool { return f.Header.Type == wire.TypeDgram && f.Seq == lost })
		b := p.b.s
		a := &actor{s: b}
		got, err := dpReadAll(t, b)
		if len(got) != 2 || err != nil {
			t.Fatalf("before finWait: %d datagrams, %v; want 2 and a wait", len(got), err)
		}
		at := wpLocked(b, func() time.Time { return b.pk.finWaitAt })
		if at.IsZero() || wpLocked(b, func() bool { return b.st.peerFinDelivered }) {
			t.Fatal("stimulus: the peer's FIN did not arm finWaitAt, or was delivered with a seq missing")
		}
		b.mu.Lock()
		a.packetLocked(time.Now())
		want := a.wakeAt
		b.mu.Unlock()
		if !want.Equal(at) {
			t.Fatalf("the actor armed %v, want finWaitAt %v", want, at)
		}
		time.Sleep(time.Until(at))
		b.mu.Lock()
		a.wakeAt = time.Time{}
		a.packetLocked(time.Now())
		b.mu.Unlock()
		if _, err := b.ReadFrom(make([]byte, 200)); err != io.EOF {
			t.Fatalf("after finWaitAt: %v, want io.EOF", err)
		}
	})
}

// TestPacketActorNoPathAgeing (M2-D35): while no data lane exists the
// actor's ageing step drops the datagrams older than MaxAge (DropNoPath)
// and arms itself at the next expiry; episodeEndLocked records the end of
// the no-path episode, so a datagram queued during it that ages out later
// still counts DropNoPath, and one queued after it DropAge.
func TestPacketActorNoPathAgeing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{maxAge: 100 * time.Millisecond})
		a := &actor{s: s}
		dpWrite(t, s, 1, 100)
		t0 := time.Now()
		s.mu.Lock()
		a.packetLocked(t0)
		s.mu.Unlock()
		if want := t0.Add(100*time.Millisecond + 1); !a.wakeAt.Equal(want) {
			t.Fatalf("ageing armed at %v, want %v", a.wakeAt.Sub(t0), want.Sub(t0))
		}
		time.Sleep(101 * time.Millisecond)
		s.mu.Lock()
		a.wakeAt = time.Time{}
		a.packetLocked(time.Now())
		s.mu.Unlock()
		if c := dpCtr(s); c.DropNoPath != 1 || c.DropAge != 0 || !a.wakeAt.IsZero() {
			t.Fatalf("after MaxAge without a data lane: %+v, armed %v; want DropNoPath 1, nothing armed", c, a.wakeAt)
		}

		// A datagram queued during the episode, then the episode ends.
		dpWrite(t, s, 2, 100)
		time.Sleep(10 * time.Millisecond)
		s.mu.Lock()
		s.ctl.inNoPath = true
		a.episodeEndLocked(time.Now())
		s.mu.Unlock()
		l, _ := dpAddLane(s, 1, true, true)
		time.Sleep(10 * time.Millisecond)
		dpWrite(t, s, 3, 100) // queued after the episode
		time.Sleep(150 * time.Millisecond)
		b := dpFill(l, time.Now())
		b.ReleaseRefs()
		if c := dpCtr(s); c.DropNoPath != 2 || c.DropAge != 1 || c.Sent != 0 {
			t.Fatalf("counters %+v: want the episode's datagram DropNoPath and the later one DropAge", c)
		}
	})
}
