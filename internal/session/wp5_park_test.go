package session

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// WP5 (M3 design §A8; M3-D42 … M3-D44, R1-7, R1-14, R1-22): the parked
// actor. An idle session's actor parks after its linger and holds no
// goroutine; every doorbell ring, its timer and the joins it waits for
// restart it, one step at a time. Package-level helpers of these files
// start with "wp5".

// wp5World is an actor-test world whose two "Runtimes" count their running
// actors (Params.Actors) and use linger as Params.ActorLinger (0: the
// default, 1 s).
type wp5World struct {
	*acWorld
	ga, gb atomic.Int64 // running actors: dialer side, passive side
}

func wp5NewWorld(t testing.TB, hooks *testhooks.Hooks, linger time.Duration) *wp5World {
	w := &wp5World{acWorld: acNewWorld(t, hooks)}
	w.a.p.ActorLinger, w.b.p.ActorLinger = linger, linger
	w.a.p.Actors, w.b.p.Actors = &w.ga, &w.gb
	return w
}

// wp5State returns the state word of s's actor (parked before Start).
func wp5State(s *Session) uint32 {
	if a := s.mb.actor.Load(); a != nil {
		return a.state.Load()
	}
	return actorParked
}

// wp5WaitParked waits (in virtual time) until s's actor is parked. Once
// it returns after a synctest.Wait with no time advanced, nothing runs the
// actor, so the test may read its fields.
func wp5WaitParked(t testing.TB, s *Session, within time.Duration) {
	t.Helper()
	acWaitFor(t, within, wpsessRole(s)+" actor parked", func() bool { return wp5State(s) == actorParked })
}

// wp5Lane returns s's lane of factory i (dialer) or its first lane (i < 0).
func wp5Lane(s *Session, i int) *lane {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lanes {
		if i < 0 || l.factory == i {
			return l
		}
	}
	return nil
}

// TestActorParksWhenIdle (M3-D42, M3-D44): both actors of an idle session
// run right after the open and park once the default linger (1 s) passed
// since their last step that did work — the dialer's exactly then: the
// running-actor gauge (Status.Actors) drops to 0 and the parked gauge
// counts both. Traffic restarts them and they park again; the session
// stays open and intact.
func TestActorParksWhenIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var target atomic.Pointer[Session]
		var parkAt atomic.Pointer[time.Time]
		hooks := &testhooks.Hooks{AtPark: func(id [16]byte) {
			if s := target.Load(); s != nil && s.id == id && parkAt.Load() == nil {
				now := time.Now()
				parkAt.Store(&now)
			}
		}}
		w := wp5NewWorld(t, hooks, 0)
		defer w.teardown()
		a, b := w.open(ModeSelector, nil, w.link("p1"))
		target.Store(a)
		synctest.Wait()
		if ga, gb := w.ga.Load(), w.gb.Load(); ga != 1 || gb != 1 {
			t.Fatalf("stimulus: %d and %d running actors right after the open, want 1 and 1", ga, gb)
		}
		parked0 := testhooks.ParkedSessions.Load()
		start := time.Now()
		for w.ga.Load()+w.gb.Load() != 0 {
			if time.Since(start) > 2*defActorLinger {
				t.Fatalf("actors still running %v after the open: %d and %d", time.Since(start), w.ga.Load(), w.gb.Load())
			}
			time.Sleep(time.Millisecond)
			synctest.Wait()
		}
		if took := time.Since(start); took > defActorLinger+50*time.Millisecond || took < defActorLinger-100*time.Millisecond {
			t.Fatalf("the actors parked %v after the open, want after the linger %v", took, defActorLinger)
		}
		if at, last := parkAt.Load(), a.mb.actor.Load().lastWork; at == nil || at.Sub(last) != defActorLinger {
			t.Fatalf("the dialer parked at %v, %v after its last step that did work, want exactly the linger %v", at, at.Sub(last), defActorLinger)
		}
		if wp5State(a) != actorParked || wp5State(b) != actorParked {
			t.Fatalf("states %d and %d with no running actor, want parked", wp5State(a), wp5State(b))
		}
		if d := testhooks.ParkedSessions.Load() - parked0; d != 2 {
			t.Fatalf("ParkedSessions grew by %d, want 2", d)
		}
		if we, re := acTransfer(a, b, 256<<10, 21, false); we != nil || re != nil {
			t.Fatalf("transfer after parking: %v %v", we, re)
		}
		if a.State() != StateOpen || b.State() != StateOpen {
			t.Fatalf("states %v and %v after parking, want open", a.State(), b.State())
		}
		time.Sleep(2 * defActorLinger)
		synctest.Wait()
		if ga, gb := w.ga.Load(), w.gb.Load(); ga != 0 || gb != 0 {
			t.Fatalf("%d and %d actors running two lingers after the transfer, want 0", ga, gb)
		}
	})
}

// TestActorParkPostRace_L09 (M3-D42, L09): a hook posts a command exactly at
// the instant the actor tries to park — inline on the parking goroutine
// (the CAS then finds again) or from a goroutine of its own (the post meets
// a parked or still running actor) — 10,000 times. No wakeup is lost: each
// command is handled within one virtual millisecond of its post.
func TestActorParkPostRace_L09(t *testing.T) {
	const n = 10000
	synctest.Test(t, func(t *testing.T) {
		type posted struct {
			at    time.Time
			reply chan bool
		}
		var target atomic.Pointer[Session]
		var count, attempts atomic.Int64
		posts := make(chan posted, n)
		hooks := &testhooks.Hooks{AtPark: func(id [16]byte) {
			s := target.Load()
			if s == nil || id != s.id {
				return
			}
			attempts.Add(1)
			i := count.Load()
			if i >= n {
				return
			}
			count.Add(1)
			p := posted{at: time.Now(), reply: make(chan bool, 1)}
			posts <- p
			c := &refuse{reply: p.reply} // an open session answers false
			if i%2 == 0 {
				s.mb.post(c)
			} else {
				go s.mb.post(c)
			}
		}}
		w := wp5NewWorld(t, hooks, time.Millisecond)
		defer w.teardown()
		a, _ := w.open(ModeSelector, nil, w.link("p1"))
		target.Store(a)
		for i := range n {
			var p posted
			select {
			case p = <-posts:
			case <-time.After(time.Second):
				t.Fatalf("post %d: the actor never tried to park again", i)
			}
			select {
			case ok := <-p.reply:
				if ok {
					t.Fatalf("post %d: an open session answered a refusal as pending", i)
				}
			case <-time.After(time.Millisecond):
				t.Fatalf("post %d (inline %v): not handled within 1 ms: lost wakeup", i, i%2 == 0)
			}
			if d := time.Since(p.at); d > time.Millisecond {
				t.Fatalf("post %d handled %v after it was posted", i, d)
			}
		}
		if c, at := count.Load(), attempts.Load(); c != n || at < n {
			t.Fatalf("stimulus: %d posts at %d park attempts, want %d", c, at, n)
		}
	})
}

// TestActorNeverConcurrent_L09 (M3-D42, L09): 1000 kicks and rings from 8
// goroutines, in rounds that start together on a parked actor, while every
// critical section of a step yields: at most one goroutine is ever inside
// a step of the session, the running-actor gauge never exceeds 1 (no kick
// starts a second goroutine), and the kicks restarted the parked actor in
// every round.
func TestActorNeverConcurrent_L09(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var parks atomic.Int64
		var target atomic.Pointer[Session]
		hooks := &testhooks.Hooks{AtPark: func(id [16]byte) {
			if s := target.Load(); s != nil && s.id == id {
				parks.Add(1)
			}
		}}
		w := wp5NewWorld(t, hooks, time.Nanosecond) // park after every step without work
		defer w.teardown()
		a, b := w.open(ModeSelector, nil, w.link("p1"))
		time.Sleep(10 * time.Millisecond)
		wp5WaitParked(t, a, time.Second)
		target.Store(a)
		var in, maxIn, maxRun, steps atomic.Int64
		raise := func(v *atomic.Int64, k int64) {
			for {
				m := v.Load()
				if k <= m || v.CompareAndSwap(m, k) {
					return
				}
			}
		}
		hook := func(s *Session) {
			if s != a {
				return
			}
			steps.Add(1)
			raise(&maxIn, in.Add(1))
			raise(&maxRun, w.ga.Load())
			runtime.Gosched()
			in.Add(-1)
		}
		afterUnlockHook.Store(&hook)
		defer afterUnlockHook.CompareAndSwap(&hook, nil)
		act := a.mb.actor.Load()
		for round := range 125 {
			go1 := make(chan struct{})
			var wg sync.WaitGroup
			for g := range 8 {
				wg.Go(func() {
					<-go1 // the 8 kicks of a round start together on the parked actor
					if (g+round)%2 == 0 {
						act.kick()
					} else {
						a.ringActor()
					}
				})
			}
			runtime.Gosched()
			close(go1)
			wg.Wait()
			time.Sleep(time.Millisecond) // the actor parks
			synctest.Wait()
		}
		synctest.Wait()
		if m, r := maxIn.Load(), maxRun.Load(); m != 1 || r != 1 {
			t.Fatalf("%d goroutines inside steps of one session at once and %d running actors, want 1 and 1", m, r)
		}
		if p, s := parks.Load(), steps.Load(); p < 125 || s < 2*p {
			t.Fatalf("stimulus: %d park attempts and %d critical sections for 1000 kicks", p, s)
		}
		if st := wp5State(a); st != actorParked {
			t.Fatalf("state %d after the kicks, want parked", st)
		}
		if we, re := acTransfer(a, b, 64<<10, 22, false); we != nil || re != nil {
			t.Fatalf("transfer after the kicks: %v %v", we, re)
		}
	})
}

// TestActorParkZeroAllocs (M3 §A11.4, R1-26): a ring of a parked actor
// with an armed deadline (IdleTimeout) restarts it; the step finds no work
// and parks again at once, re-arming the reusable timer: at most one
// allocation per park (the goroutine). The race lane runs it without the
// assertion.
func TestActorParkZeroAllocs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var parks atomic.Int64
		var target atomic.Pointer[Session]
		hooks := &testhooks.Hooks{AtPark: func(id [16]byte) {
			if s := target.Load(); s != nil && s.id == id {
				parks.Add(1)
			}
		}}
		w := wp5NewWorld(t, hooks, 20*time.Millisecond)
		defer w.teardown()
		w.a.p.IdleTimeout = time.Hour
		a, _ := w.open(ModeSelector, nil, w.link("p1"))
		wp5WaitParked(t, a, time.Second)
		if act := a.mb.actor.Load(); act.wakeAt.IsZero() {
			t.Fatal("stimulus: the parked actor has no deadline armed")
		}
		target.Store(a)
		const runs = 200
		allocs := testing.AllocsPerRun(runs, func() {
			a.ringActor()
			synctest.Wait()
		})
		if p := parks.Load(); p != runs+1 {
			t.Fatalf("stimulus: %d parks for %d rings (+1 warm-up)", p, runs)
		}
		if wp5State(a) != actorParked {
			t.Fatal("the actor is not parked after the rings")
		}
		t.Logf("%.2f allocations per kick and park", allocs)
		if !streamRaceEnabled && allocs > 1 {
			t.Fatalf("%.2f allocations per kick and park, want ≤ 1", allocs)
		}
	})
}

// TestKickBeforeStart (R1-7 rule 2): commands posted to a pending passive
// session before Start wait in the mailbox; their rings and kicks start
// nothing (no actor is published yet); Start then runs them in the order
// posted: the Confirm first (the session opens), then a refusal (no longer
// pending), then a Reject (too late).
func TestKickBeforeStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wp5NewWorld(t, nil, 0)
		defer w.teardown()
		pend := make(chan *Session, 1)
		var hs sync.WaitGroup
		defer hs.Wait()
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "p1", Accept: func(nc net.Conn) error {
			hs.Go(func() {
				h, err := carrier.ReadHello(w.b.cenv, nc, time.Now().Add(2*time.Second), 4096, nil)
				if err != nil {
					t.Errorf("ReadHello: %v", err)
					return
				}
				o, err := wire.ParseOpen(h.Payload, 4096)
				if err != nil {
					t.Errorf("ParseOpen: %v", err)
					return
				}
				pp := w.b.p
				pp.Role, pp.Mode = RolePassive, Mode(o.Mode)
				pp.Grace = min(max(time.Duration(o.RetainMs)*time.Millisecond, time.Second), 400*time.Second)
				pend <- NewPending(w.b.env, PassiveSpec{SID: o.SID, Params: pp, DialerInstance: h.Preface.Instance, PeerWindow: o.Window, Metadata: o.Metadata}, h.Conn)
			})
			return nil
		}})
		l.SetDelay(acLinkDelay, 0)
		w.links = append(w.links, l)
		spec := w.spec(ModeSelector, l)
		type res struct {
			s   *Session
			err error
		}
		dialed := make(chan res, 1)
		go func() {
			s, err := w.dial(context.Background(), spec, nil)
			dialed <- res{s, err}
		}()
		b := <-pend
		w.sess = append(w.sess, b)
		conf := make(chan error, 1)
		ref := make(chan bool, 1)
		rej := make(chan error, 1)
		if !b.mb.post(&confirm{reply: conf}) || !b.mb.post(&refuse{status: wire.StatusCapacity, reply: ref}) ||
			!b.mb.post(&reject{code: 1, msg: "late", reply: rej}) {
			t.Fatal("a post before Start was refused")
		}
		b.ringActor()
		b.mb.Ring()
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		if b.mb.actor.Load() != nil || w.gb.Load() != 0 {
			t.Fatalf("kicks before Start started an actor (published %v, %d running)", b.mb.actor.Load() != nil, w.gb.Load())
		}
		if len(conf)+len(ref)+len(rej) != 0 {
			t.Fatal("a command posted before Start was handled before Start")
		}
		b.Start()
		synctest.Wait()
		if err := <-conf; err != nil {
			t.Fatalf("Confirm posted first: %v, want nil (handled first)", err)
		}
		if <-ref {
			t.Fatal("the refusal posted second found the session pending: handled before the Confirm")
		}
		if err := <-rej; err == nil {
			t.Fatal("the Reject posted last succeeded: handled before the Confirm")
		}
		r := <-dialed
		if r.err != nil {
			t.Fatalf("Dial: %v", r.err)
		}
		if we, re := acTransfer(r.s, b, 64<<10, 23, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}
