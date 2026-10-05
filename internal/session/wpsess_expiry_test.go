package session

import (
	"context"
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

// An attach queued in the step whose no-path expiry is due wins (design
// §7.7, L18; §0.13 A7 (d)): the actor handles the step's commands first
// and decides the expiry afterwards, only while no carrier is alive and
// the episode is unchanged. The tests hold an actor across the instant its
// episode expires while an attach is queued — a JOIN adopted on the
// passive, a dial result on the dialer — so that the actor finds both in
// one step. An actor that checked the expiry first would end the session
// with ErrNoPath and refuse the carrier that had already come back.
// Package-level helpers of this file start with "wpsess".

// wpsessGate holds a factory's dials, honouring their ctx, while it is
// closed.
type wpsessGate struct {
	ch      atomic.Pointer[chan struct{}]
	waiting atomic.Int32 // dials held now
}

// shut makes later dials wait; open lets every held and later dial pass.
func (g *wpsessGate) shut() {
	ch := make(chan struct{})
	g.ch.Store(&ch)
}

func (g *wpsessGate) open() {
	if p := g.ch.Swap(nil); p != nil {
		close(*p)
	}
}

// factory is factory l through the gate.
func (g *wpsessGate) factory(l *rendrtest.Link) carrier.Factory {
	return carrier.Factory{Name: l.Name(), Dial: func(ctx context.Context) (net.Conn, error) {
		if p := g.ch.Load(); p != nil {
			g.waiting.Add(1)
			select {
			case <-*p:
				g.waiting.Add(-1)
			case <-ctx.Done():
				g.waiting.Add(-1)
				return nil, ctx.Err()
			}
		}
		return l.Dial(ctx)
	}}
}

// wpsessHold holds s's actor right before its next wait: a ring makes it
// run one step, after which it stays held until the returned release (the
// caller defers it, so that a failing test never leaves it held).
func wpsessHold(t *testing.T, s *Session) (release func()) {
	t.Helper()
	var armed, held atomic.Bool
	ch := make(chan struct{})
	hook := func(x *Session) {
		if x == s && armed.CompareAndSwap(true, false) {
			held.Store(true)
			<-ch
		}
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			close(ch)
			beforeWaitHook.CompareAndSwap(&hook, nil)
		})
	}
	beforeWaitHook.Store(&hook)
	armed.Store(true)
	s.ringActor()
	synctest.Wait()
	if !held.Load() {
		release()
		t.Fatalf("%s actor not held (stimulus)", wpsessRole(s))
	}
	return release
}

// wpsessRole names s's role in failure messages.
func wpsessRole(s *Session) string {
	if s.Role() == RoleDialer {
		return "dialer"
	}
	return "passive"
}

// wpsessQueued counts the commands of type T waiting in s's mailbox.
func wpsessQueued[T command](s *Session) int {
	s.mb.mu.Lock()
	defer s.mb.mu.Unlock()
	n := 0
	for _, c := range s.mb.cmds {
		if _, ok := c.(T); ok {
			n++
		}
	}
	return n
}

// wpsessEpisodeBy waits until s is in a no-path episode and returns when its
// grace expires: the episode's start (the death of its last carrier) plus
// grace.
func wpsessEpisodeBy(t *testing.T, s *Session, grace time.Duration) time.Time {
	t.Helper()
	var start time.Time
	acWaitFor(t, 5*time.Second, "a no-path episode", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		start = s.ctl.episodeStart
		return s.ctl.inNoPath
	})
	return start.Add(grace)
}

// wpsessCheckRecovered checks that s survived its due expiry: open, out of
// its single episode, which ended (NoPathEnd) in a step at or after the
// expiry; side records s's events.
func wpsessCheckRecovered(t *testing.T, side *acSide, s *Session, by time.Time) {
	t.Helper()
	st := s.Status()
	if st.State != StateOpen || st.Err != nil || st.InNoPath || st.NoPathEpisodes != 1 {
		t.Fatalf("%s: state %v err %v, in no-path %v, %d episodes; want open after one episode", wpsessRole(s), st.State, st.Err, st.InNoPath, st.NoPathEpisodes)
	}
	ends := side.ev.of(s.ID(), EventNoPathEnd)
	if len(ends) != 1 {
		t.Fatalf("%s: %d NoPathEnd events, want 1", wpsessRole(s), len(ends))
	}
	if ends[0].Time.Before(by) {
		t.Fatalf("%s: the attach was handled %v before the expiry: not the step under test (stimulus)", wpsessRole(s), by.Sub(ends[0].Time))
	}
}

// TestWpsessQueuedAttachBeatsExpiry_L18: a selector session loses its only
// carrier; the redial is held at the factory until just before the grace of
// the side under test expires. That side's actor is then held, the redial
// proceeds and its attach is queued there — the JOIN's adopt on the
// passive, the JOIN_ACK(OK) result on the dialer — and virtual time passes
// the expiry before the actor runs again. Its next step finds the attach and
// the due expiry together: the attach must win (the episode ends, the
// session stays open and carries data both ways intact); deciding the
// expiry first ends it with ErrNoPath.
func TestWpsessQueuedAttachBeatsExpiry_L18(t *testing.T) {
	const grace = 3 * time.Second
	for _, side := range []string{"passive", "dialer"} {
		t.Run(side, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				if side == "passive" {
					w.a.p.Grace, w.a.p.Retain = 30*time.Second, grace // the passive's grace is the Retain of the OPEN
				} else {
					w.a.p.Grace, w.a.p.Retain = grace, 30*time.Second
				}
				w.a.cenv.Timing.DialTimeout = 30 * time.Second // the held redial is not cut
				l := w.link("p1")
				var g wpsessGate
				spec := w.spec(ModeSelector, l)
				spec.Factories = []carrier.Factory{g.factory(l)}
				a, b := w.openSpec(spec, nil)

				g.shut()
				if l.Kill() != 1 {
					t.Fatal("no carrier killed (stimulus)")
				}
				s, sd := b, w.b.acSide
				if side == "dialer" {
					s, sd = a, w.a
				}
				by := wpsessEpisodeBy(t, s, grace)
				acWaitFor(t, time.Second, "the redial held at the factory", func() bool { return g.waiting.Load() == 1 })
				time.Sleep(time.Until(by) - 100*time.Millisecond)

				release := wpsessHold(t, s)
				defer release()
				g.open()
				queued := func() int {
					if side == "dialer" {
						return wpsessQueued[*dialResult](s)
					}
					return wpsessQueued[*adopt](s)
				}
				acWaitFor(t, time.Second, "the attach queued at the held actor", func() bool { return queued() == 1 })
				time.Sleep(time.Until(by) + 100*time.Millisecond)
				synctest.Wait()
				if queued() != 1 || !time.Now().After(by) || s.Status().State != StateOpen {
					t.Fatalf("before the held step: %d attaches queued, expiry passed %v, state %v (stimulus)", queued(), time.Now().After(by), s.Status().State)
				}

				release()
				acWaitFor(t, time.Second, "both ends attached", func() bool {
					return acActive(a) != 0 && acActive(b) != 0 || a.Status().State == StateEnded || b.Status().State == StateEnded
				})
				wpsessCheckRecovered(t, sd, s, by)
				if joins, _ := w.b.counts(); joins[wire.StatusOK] != 1 {
					t.Fatalf("JOIN answers %v, want one OK", joins)
				}
				if we, re := acTransfer(a, b, 256<<10, 131, false); we != nil || re != nil {
					t.Fatalf("dialer → passive after the recovery: %v %v", we, re)
				}
				if we, re := acTransfer(b, a, 256<<10, 132, false); we != nil || re != nil {
					t.Fatalf("passive → dialer after the recovery: %v %v", we, re)
				}
			})
		})
	}
}
