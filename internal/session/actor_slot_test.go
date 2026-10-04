package session

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Redial slots (design §7.1, §7.7; plan §3.6): one attempt at a time per
// factory slot, the first attempt after a death immediate, then
// max(lastStart + backoff, end of the failed attempt).

// acDialScript makes the n-th factory call of a test (0: the opening)
// behave as script[n] on link; later calls behave normally. It records
// every call's start time.
type acDialScript struct {
	mu     sync.Mutex
	link   *rendrtest.Link
	script []rendrtest.DialBehavior
	starts []time.Time
}

func (d *acDialScript) hook(int) {
	d.mu.Lock()
	n := len(d.starts)
	d.starts = append(d.starts, time.Now())
	b := rendrtest.DialNormal
	if n < len(d.script) {
		b = d.script[n]
	}
	d.mu.Unlock()
	d.link.SetDial(b)
}

func (d *acDialScript) calls() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.starts...)
}

// TestSlotCadenceHungAttempts_L20: after the death of the only carrier the
// slot redials at once; attempts that hang until DialTimeout are followed
// by the next one right when they end (no backoff on top of a hung
// attempt); fast failures then back off from the previous start
// (0.5 s·2ⁿ capped at BackoffMax, jitter fixed at ×1.0); the sixth attempt
// attaches.
func TestSlotCadenceHungAttempts_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ds := &acDialScript{script: []rendrtest.DialBehavior{
			rendrtest.DialNormal, // the opening
			rendrtest.DialHang, rendrtest.DialHang, rendrtest.DialHang,
			rendrtest.DialError, rendrtest.DialError,
			rendrtest.DialNormal,
		}}
		w := acNewWorld(t, &testhooks.Hooks{DialStart: ds.hook})
		defer w.teardown()
		w.a.p.Grace, w.a.p.Retain, w.a.p.BackoffMax = 30*time.Second, 40*time.Second, 4*time.Second
		ds.link = w.link("p1")
		a, b := w.open(ModeSelector, nil, ds.link)
		synctest.Wait()
		t0 := time.Now()
		ds.link.Kill()
		acWaitFor(t, 20*time.Second, "the sixth attempt attached", func() bool {
			return len(ds.calls()) == 7 && acActive(a) != 0
		})
		want := []time.Duration{0, 2 * time.Second, 4 * time.Second, 6 * time.Second, 10 * time.Second, 14 * time.Second}
		got := ds.calls()[1:]
		for i, d := range want {
			if at := got[i].Sub(t0); at != d {
				t.Fatalf("attempt %d started at t0+%v, want t0+%v (all: %v)", i+1, at, d, acRel(got, t0))
			}
		}
		if st := a.Status(); st.MigDeath != 1 || st.Rejoins != 1 {
			t.Fatalf("after the redial: death migrations %d rejoins %d, want 1 and 1", st.MigDeath, st.Rejoins)
		}
		if we, re := acTransfer(a, b, 1<<20, 5, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

func acRel(ts []time.Time, t0 time.Time) []time.Duration {
	out := make([]time.Duration, len(ts))
	for i, x := range ts {
		out[i] = x.Sub(t0)
	}
	return out
}

// TestSlotCoalescesRedials_L51: while the slot's redial hangs, 128 doorbell
// rings and 128 health publications run the actor again and again: the
// factory is still called exactly once (one attempt per slot, no permit
// pool); when the hung attempt ends, exactly one more starts and attaches.
func TestSlotCoalescesRedials_L51(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ds := &acDialScript{script: []rendrtest.DialBehavior{rendrtest.DialNormal, rendrtest.DialHang}}
		w := acNewWorld(t, &testhooks.Hooks{DialStart: ds.hook})
		defer w.teardown()
		h := acNewHealth(1, w.a.p.Selector.Fresh)
		h.set(10 * time.Millisecond)
		ds.link = w.link("p1")
		a, _ := w.open(ModeSelector, h, ds.link)
		synctest.Wait()
		ds.link.Kill()
		synctest.Wait()
		if n := len(ds.calls()); n != 2 {
			t.Fatalf("%d factory calls after the death, want the opening and one redial", n)
		}
		for range 128 {
			a.mb.ring()
			h.bump()
			synctest.Wait() // the actor ran a step for them
		}
		time.Sleep(time.Second) // still inside the hung attempt (DialTimeout 2 s)
		if n := len(ds.calls()); n != 2 {
			t.Fatalf("%d factory calls while the redial hung, want 2", n)
		}
		acWaitFor(t, 5*time.Second, "the next attempt attached", func() bool { return acActive(a) != 0 })
		if n := len(ds.calls()); n != 3 {
			t.Fatalf("%d factory calls in all, want 3", n)
		}
	})
}

// TestCloseCancelsBlockedRedial_L21: the session ends while its redial is
// blocked in the factory: the attempt's ctx is cancelled at once, Done
// closes without waiting for the factory, a result that arrives late is
// closed exactly once, and the slot never attaches again.
func TestCloseCancelsBlockedRedial_L21(t *testing.T) {
	cases := []struct {
		name  string
		beh   rendrtest.DialBehavior
		close bool // the application's Close (linger expiry) instead of Shutdown
	}{
		{"shutdown/hang", rendrtest.DialHang, false},
		{"linger/late-success", rendrtest.DialLateSuccess, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ds := &acDialScript{script: []rendrtest.DialBehavior{rendrtest.DialNormal, tc.beh}}
				w := acNewWorld(t, &testhooks.Hooks{DialStart: ds.hook})
				defer w.teardown()
				w.a.p.Linger = time.Second
				ds.link = w.link("p1")
				a, _ := w.open(ModeSelector, nil, ds.link)
				synctest.Wait()
				ds.link.Kill()
				synctest.Wait()
				if n := len(ds.calls()); n != 2 {
					t.Fatalf("%d factory calls, want the opening and the blocked redial", n)
				}
				var endAt time.Time
				if tc.close {
					a.Close()
					endAt = time.Now().Add(a.p.Linger)
				} else {
					a.Shutdown()
					endAt = time.Now()
				}
				<-a.Done()
				if d := time.Since(endAt); d > 100*time.Millisecond {
					t.Fatalf("Done %v after the end, want the blocked redial cancelled at once", d)
				}
				if tc.beh == rendrtest.DialLateSuccess {
					ds.link.Release() // the factory finally returns a conn
				}
				time.Sleep(3 * time.Second)
				synctest.Wait()
				info := ds.link.Carriers()
				if len(info) != 1+(map[bool]int{true: 1}[tc.beh == rendrtest.DialLateSuccess]) {
					t.Fatalf("carriers on the link: %+v", info)
				}
				for _, c := range info {
					if !c.Closed {
						t.Fatalf("carrier %d not closed: %+v", c.Seq, c)
					}
				}
				if len(info) == 2 && info[1].Session {
					t.Fatal("the late conn became a session carrier")
				}
				if n := len(ds.calls()); n != 2 {
					t.Fatalf("%d factory calls, want no redial after the end", n)
				}
				for _, c := range a.Status().Carriers {
					if c.State != LaneDead {
						t.Fatalf("a carrier attached after the end: %+v", c)
					}
				}
			})
		})
	}
}
