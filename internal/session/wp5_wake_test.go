package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The wakeups of a parked actor (M3 §A8.2; R1-7, R1-14): every doorbell
// ring kicks it, and the joins the running loop selects on ring it through
// Conn.OnDone.

// wp5Linger is the actor linger of the wakeup tests: short, so that the
// actors park between the stimuli.
const wp5Linger = 20 * time.Millisecond

// wp5OpenParked opens a selector session over one link and waits until
// both actors parked.
func wp5OpenParked(t *testing.T, w *wp5World) (a, b *Session, l *rendrtest.Link) {
	t.Helper()
	l = w.link("p1")
	a, b = w.open(ModeSelector, nil, l)
	wp5WaitParked(t, a, time.Second)
	wp5WaitParked(t, b, time.Second)
	if w.ga.Load()+w.gb.Load() != 0 {
		t.Fatalf("stimulus: %d running actors, want both parked", w.ga.Load()+w.gb.Load())
	}
	return a, b, l
}

// wp5DeadIn reports whether s's Status lists carrier id as dead.
func wp5DeadIn(s *Session, id uint32) bool {
	for _, c := range s.Status().Carriers {
		if c.ID == id && c.State == LaneDead {
			return true
		}
	}
	return false
}

// TestParkedActorWakesOnDeath (R1-7): the only lane of a parked dialer
// session dies (a carrier Kill rings the Start doorbell, never a post): the
// death step runs at that virtual instant — the carrier is reported dead
// and the redial restores the session.
func TestParkedActorWakesOnDeath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wp5NewWorld(t, nil, wp5Linger)
		defer w.teardown()
		a, b, _ := wp5OpenParked(t, w)
		l := wp5Lane(a, 0)
		if !l.c.Kill(carrier.CauseLocalClose, "wp5 test") {
			t.Fatal("stimulus: the lane's carrier was already dead")
		}
		synctest.Wait() // no virtual time passes
		if !wp5DeadIn(a, l.id) {
			t.Fatalf("the death of carrier %d was not handled at once: %+v", l.id, a.Status().Carriers)
		}
		if we, re := acTransfer(a, b, 64<<10, 31, false); we != nil || re != nil {
			t.Fatalf("transfer after the death: %v %v", we, re)
		}
		if st := a.Status(); st.MigDeath+st.Rejoins == 0 {
			t.Fatalf("no death migration or rejoin counted: %+v", st)
		}
	})
}

// TestParkedActorWakesOnAppClose (R1-7): Close on a parked session rings
// the actor through ringActor (no post): at that virtual instant it is
// Closing and reported to the Registry as lingering; the FIN reaches the
// peer and both ends finish cleanly.
func TestParkedActorWakesOnAppClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wp5NewWorld(t, nil, wp5Linger)
		defer w.teardown()
		a, b, _ := wp5OpenParked(t, w)
		if err := a.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		synctest.Wait() // no virtual time passes
		w.a.reg.mu.Lock()
		on := w.a.reg.lingering[a]
		w.a.reg.mu.Unlock()
		if a.State() != StateClosing || !on {
			t.Fatalf("at the Close instant: state %v, lingering %v; want Closing and true", a.State(), on)
		}
		if _, err := b.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("peer Read after the Close: %v, want io.EOF", err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("peer Close: %v", err)
		}
		acDone(t, a, 5*time.Second)
		acDone(t, b, 5*time.Second)
		if st := a.Status(); st.Err != io.EOF {
			t.Fatalf("end error %v, want io.EOF", st.Err)
		}
	})
}

// TestParkedActorWakesOnPeerRst (R1-7): the peer's Runtime.Close sends RST
// to a parked session (the stream records factRst and rings, no post): the
// session ends with the remote abort one link delay after the peer's
// Shutdown, not later.
func TestParkedActorWakesOnPeerRst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wp5NewWorld(t, nil, wp5Linger)
		defer w.teardown()
		a, b, _ := wp5OpenParked(t, w)
		b.Shutdown()
		time.Sleep(acLinkDelay)
		synctest.Wait()
		if a.State() != StateEnded {
			t.Fatalf("state %v one link delay after the peer's RST was sent, want ended", a.State())
		}
		var ae *AbortError
		if st := a.Status(); !errors.As(st.Err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
			t.Fatalf("end error %v, want the peer's *AbortError{AbortGoingAway, Remote}", st.Err)
		}
		acDone(t, a, 5*time.Second)
	})
}

// TestParkedEndPhaseJoinsUnstartedConn (R1-7 rule 3, M3-D43): in the end
// phase the only carrier left to join is one the session dropped unstarted
// (as a refused or late answer would be); the actor parks waiting for it
// and exits at the virtual instant its Done closes: the join rings through
// Conn.OnDone.
func TestParkedEndPhaseJoinsUnstartedConn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wp5NewWorld(t, nil, wp5Linger)
		defer w.teardown()
		a, _, _ := wp5OpenParked(t, w)

		// An unstarted carrier: a passive end that read its hello.
		got := make(chan *carrier.Conn, 1)
		var hs sync.WaitGroup
		defer hs.Wait()
		lx := rendrtest.NewLink(rendrtest.LinkConfig{Name: "x", Accept: func(nc net.Conn) error {
			hs.Go(func() {
				h, err := carrier.ReadHello(w.b.cenv, nc, time.Now().Add(2*time.Second), 4096, nil)
				if err != nil {
					t.Errorf("ReadHello: %v", err)
					got <- nil
					return
				}
				got <- h.Conn
			})
			return nil
		}})
		w.links = append(w.links, lx)
		o := wire.Open{SID: [16]byte{0xEE, 5}, Kind: wire.KindStream, Mode: uint8(ModeSelector), RetainMs: 5000, Window: 1 << 20}
		op := make([]byte, wire.OpenFixedLen)
		op = op[:wire.PutOpen(op, &o)]
		ctx, cancel := context.WithCancel(context.Background())
		hs.Go(func() {
			if est, err := carrier.Establish(ctx, w.a.cenv, carrier.Factory{Name: "x", Dial: lx.Dial}, w.a.cenv.IDs.Next(), wire.TypeOpen, op, nil); err == nil {
				est.Conn.Kill(carrier.CauseLocalClose, "unexpected answer")
			}
		})
		x := <-got
		cancel()
		if x == nil {
			t.Fatal("no unstarted carrier")
		}

		// Hand x to a's exit join from its end phase (on the actor goroutine).
		var injected atomic.Bool
		act := a.mb.actor.Load()
		hook := func(s *Session) {
			if s == a && act.ending && injected.CompareAndSwap(false, true) {
				act.dropConn(x)
			}
		}
		afterUnlockHook.Store(&hook)
		defer afterUnlockHook.CompareAndSwap(&hook, nil)
		a.Shutdown()
		acWaitFor(t, 5*time.Second, "the end phase waits for x alone, parked", func() bool {
			if !injected.Load() || wp5State(a) != actorParked {
				return false
			}
			return len(act.gone) == 1 && act.gone[0] == x && len(a.lanes) == 0 // parked: nothing runs the actor
		})
		select {
		case <-a.Done():
			t.Fatal("the session is done before x was joined")
		default:
		}
		x.Kill(carrier.CauseLocalClose, "wp5 test")
		select {
		case <-x.Done():
		case <-time.After(time.Second):
			t.Fatal("stimulus: x is not done after its Kill")
		}
		joined := time.Now()
		select {
		case <-a.Done():
		case <-time.After(time.Millisecond):
			t.Fatal("the parked end-phase actor did not exit when x's Done closed")
		}
		if d := time.Since(joined); d != 0 {
			t.Fatalf("Done %v after x's join, want at once", d)
		}
	})
}

// wp5Gate holds a carrier's reader inside a Read once armed: the first
// Read that returns after arming blocks, discards what it read, and
// returns net.ErrClosed when released.
type wp5Gate struct {
	armed   atomic.Bool
	held    chan struct{} // closed when a Read is held
	release chan struct{}
	once    sync.Once
}

func newWP5Gate() *wp5Gate {
	return &wp5Gate{held: make(chan struct{}), release: make(chan struct{})}
}

type wp5GateConn struct {
	net.Conn
	g *wp5Gate
}

func (c *wp5GateConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.g.armed.Load() {
		c.g.once.Do(func() { close(c.g.held) })
		<-c.g.release
		return 0, net.ErrClosed
	}
	return n, err
}

// TestActorAwaitReaderRings (R1-14, M3-D43): our DONE was sent and the
// peer's is outstanding when the dialer's carrier dies while its reader is
// held inside a Read call: the death step waits for that reader
// (readerWait). Parked and running, the reader's exit closes the carrier's
// Done, which wakes the actor at that virtual instant: the lane is reaped.
func TestActorAwaitReaderRings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		linger time.Duration
		state  uint32
	}{
		{"parked", wp5Linger, actorParked},
		{"running", time.Hour, actorRunning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := wp5NewWorld(t, nil, tc.linger)
				defer w.teardown()
				w.a.p.Linger = time.Minute // the DONE wait outlasts the test
				l := w.link("p1")
				g := newWP5Gate()
				spec := w.spec(ModeSelector, l)
				spec.Factories[0].Dial = func(ctx context.Context) (net.Conn, error) {
					c, err := l.Dial(ctx)
					if err != nil {
						return nil, err
					}
					return &wp5GateConn{Conn: c, g: g}, nil
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
				b := w.confirmNext()
				r := <-ch
				if r.err != nil {
					t.Fatalf("Dial: %v", r.err)
				}
				a := r.s
				acHalfCloseSettled(t, a, b, 64<<10, 41)
				g.armed.Store(true)
				acReadToEOF(t, a, 64<<10, 41)
				select {
				case <-g.held:
				case <-time.After(5 * time.Second):
					t.Fatal("stimulus: the reader was never held")
				}
				acWaitFor(t, time.Second, "our DONE sent", func() bool { sent, _ := g2Done(a); return sent })
				lane := wp5Lane(a, 0)
				lane.c.Kill(carrier.CauseLocalClose, "wp5 test")
				time.Sleep(10 * wp5Linger)
				synctest.Wait()
				if st := wp5State(a); st != tc.state && !(tc.state == actorRunning && st == actorAgain) {
					t.Fatalf("stimulus: actor state %d while the reader is held, want %d", st, tc.state)
				}
				if sent, peer := g2Done(a); !sent || peer {
					t.Fatalf("stimulus: DONE sent %v, peer's %v; want true, false", sent, peer)
				}
				if wp5Lane(a, 0) != lane || wp5DeadIn(a, lane.id) {
					t.Fatal("stimulus: the lane was reaped while its reader is held")
				}
				g.armed.Store(false) // the redial's carriers read freely
				close(g.release)
				select {
				case <-lane.c.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("stimulus: the carrier is not done after its reader exited")
				}
				joined := time.Now()
				synctest.Wait()
				if time.Since(joined) != 0 || !wp5DeadIn(a, lane.id) {
					t.Fatalf("the lane was not reaped at the instant its reader exited: %+v", a.Status().Carriers)
				}
			})
		})
	}
}

// TestParkedActorDeadlines (M3 §A8.3): the deadlines of a parked actor fire
// on its reusable timer at their exact virtual times: IdleTimeout,
// NoPathGrace, AcceptTimeout, Linger and the SCHED resend.
func TestParkedActorDeadlines(t *testing.T) {
	t.Run("IdleTimeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wp5NewWorld(t, nil, wp5Linger)
			defer w.teardown()
			w.a.p.IdleTimeout = 3 * time.Second
			a, _, _ := wp5OpenParked(t, w)
			a.mu.Lock()
			base := a.st.lastData
			a.mu.Unlock()
			if at := a.mb.actor.Load().openedAt; at.After(base) {
				base = at
			}
			due := base.Add(w.a.p.IdleTimeout)
			time.Sleep(time.Until(due) - time.Millisecond)
			synctest.Wait()
			if wp5State(a) != actorParked || a.State() != StateOpen {
				t.Fatalf("1 ms before IdleTimeout: actor state %d, session %v; want parked and open", wp5State(a), a.State())
			}
			acDone(t, a, 5*time.Second)
			at, err := g2EndAt(t, w.a, a)
			if !errors.Is(err, ErrIdleTimeout) || !at.Equal(due) {
				t.Fatalf("ended at %v with %v, want at %v with ErrIdleTimeout", at.Sub(base), err, w.a.p.IdleTimeout)
			}
		})
	})
	t.Run("NoPathGrace", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wp5NewWorld(t, nil, wp5Linger)
			defer w.teardown()
			a, _, l := wp5OpenParked(t, w)
			l.SetRefuse(true)
			l.Kill()
			start := g2EpisodeStart(t, a)
			due := start.Add(w.a.p.Grace)
			time.Sleep(time.Until(due) - time.Millisecond)
			synctest.Wait()
			if wp5State(a) != actorParked {
				t.Fatalf("1 ms before the episode expiry: actor state %d, want parked", wp5State(a))
			}
			acDone(t, a, 5*time.Second)
			at, err := g2EndAt(t, w.a, a)
			if !errors.Is(err, ErrNoPath) || !at.Equal(due) {
				t.Fatalf("ended %v after the episode began with %v, want at the grace %v with ErrNoPath", at.Sub(start), err, w.a.p.Grace)
			}
		})
	})
	t.Run("AcceptTimeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wp5NewWorld(t, nil, wp5Linger)
			defer w.teardown()
			w.a.p.Grace = 30 * time.Second
			w.b.p.AcceptTimeout = time.Second
			var endedAt atomic.Pointer[time.Time]
			tomb := w.b.reg.onEnded
			w.b.reg.onEnded = func(s *Session, v Verdict) {
				now := time.Now()
				endedAt.Store(&now)
				tomb(s, v)
			}
			l := w.link("p1")
			spec := w.spec(ModeSelector, l)
			dialed := make(chan error, 1)
			go func() {
				_, err := w.dial(context.Background(), spec, nil)
				dialed <- err
			}()
			b := <-w.b.pending
			w.sess = append(w.sess, b)
			b.mu.Lock()
			due := b.lanes[0].since.Add(w.b.p.AcceptTimeout)
			b.mu.Unlock()
			time.Sleep(time.Until(due) - time.Millisecond)
			synctest.Wait()
			if wp5State(b) != actorParked || b.State() != StatePending {
				t.Fatalf("1 ms before AcceptTimeout: actor state %d, session %v; want parked and pending", wp5State(b), b.State())
			}
			acDone(t, b, 5*time.Second)
			if at := endedAt.Load(); at == nil || !at.Equal(due) {
				t.Fatalf("the pending session ended at %v, want at AcceptTimeout %v", at, due)
			}
			if err := <-dialed; !errors.Is(err, ErrCapacity) {
				t.Fatalf("Dial: %v, want ErrCapacity", err)
			}
		})
	})
	t.Run("Linger", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wp5NewWorld(t, nil, wp5Linger)
			defer w.teardown()
			a, _, _ := wp5OpenParked(t, w)
			if err := acWritePRNG(a, 256<<10, 51); err != nil { // the peer never reads
				t.Fatalf("Write: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			a.mu.Lock()
			due := a.st.closedAt.Add(w.a.p.Linger)
			a.mu.Unlock()
			time.Sleep(time.Until(due) - time.Millisecond)
			synctest.Wait()
			if wp5State(a) != actorParked {
				t.Fatalf("1 ms before the Linger expiry: actor state %d, want parked", wp5State(a))
			}
			acDone(t, a, 5*time.Second)
			at, err := g2EndAt(t, w.a, a)
			if !errors.Is(err, net.ErrClosed) || !at.Equal(due) {
				t.Fatalf("ended at %v with %v, want at %v with net.ErrClosed", at, err, due)
			}
		})
	})
	t.Run("SchedResend", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wp5NewWorld(t, nil, wp5Linger)
			defer w.teardown()
			l1, l2 := w.link("p1"), w.link("p2")
			a, b := w.open(ModeBond, nil, l1, l2)
			acWaitFor(t, 2*time.Second, "two members, SCHED echoed", func() bool {
				_, _, data := acRouted(a)
				st := a.Status()
				return data == 2 && st.SchedEchoed == st.SchedEpoch
			})
			release := wpsessHold(t, b) // the passive applies and echoes nothing
			defer release()
			wp5WaitParked(t, a, time.Second)
			l2.SetRefuse(true)
			first := l1.CaptureNextFrame(rendrtest.Up, rendrtest.FrameSched)
			wp5Lane(a, 1).c.Kill(carrier.CauseLocalClose, "wp5 test") // a member death publishes a SCHED
			var sent time.Time
			select {
			case <-first:
				sent = time.Now()
			case <-time.After(time.Second):
				t.Fatal("stimulus: no SCHED after the member's death")
			}
			resend := l1.CaptureNextFrame(rendrtest.Up, rendrtest.FrameSched)
			synctest.Wait()
			every := a.mb.actor.Load().resendEvery() // the lanes only change on the actor
			time.Sleep(every - time.Millisecond)
			synctest.Wait()
			if wp5State(a) != actorParked {
				t.Fatalf("1 ms before the SCHED resend: actor state %d, want parked", wp5State(a))
			}
			select {
			case <-resend:
			case <-time.After(time.Second):
				t.Fatal("the unechoed SCHED was never resent")
			}
			if d := time.Since(sent); d != every {
				t.Fatalf("SCHED resent %v after it was sent, want the resend interval %v", d, every)
			}
		})
	})
}
