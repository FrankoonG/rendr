package timers

import (
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestIdleSessionsRealDeadlines (M3 design §A11.2, M3-D42; plan:649): 100
// selector sessions, each on its own carrier, with Config.IdleTimeout =
// 10 s on the passive Runtime (the dialer's is off, so that only the
// passives' deadlines fire): the dialer writes one byte and the passive
// reads it, session i 37·i ms after the first (500 ms after every session
// opened), so the 100 deadlines are distinct instants; then every session
// stays idle and its actors park (after the linger every actor is parked:
// Status.Actors 0 on both Runtimes, 200 parked sessions in the registry).
// Each deadline must fire on the parked actor at its virtual time: the
// passive's clock last moved at its Read of the byte (t_p; it has no data
// of its own to be acknowledged), so its session ends with ErrIdleTimeout
// at t_p + IdleTimeout (virtual time, ≤ 1 ms of tolerance), and the
// dialer's with the passive's AbortIdle reset one one-way delay later.
// Both times are read from the EventSessionEnd of each end (Done closes
// only after the carrier's retirement, one RTT later). Nothing is left
// after Runtime.Close.
func TestIdleSessionsRealDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			n       = 100
			idle    = 10 * time.Second
			stagger = 37 * time.Millisecond
		)
		w := newWorld(t, worldOpts{n: n, pcfg: rendr.Config{IdleTimeout: idle}},
			linkSpec{name: "a", oneWay: oneWay, props: rendr.Props{CheapSubflow: true}})
		ps := w.openMany(n, func(int) rendr.Mode { return rendr.ModeSelector })
		start := time.Now().Add(500 * time.Millisecond) // after every session opened on both ends
		last := make([]time.Time, n)                    // t_p: the passive's Read of the byte
		done := make(chan int, n)
		for i, s := range ps {
			go func() {
				defer func() { done <- i }()
				sleepUntil(start.Add(time.Duration(i) * stagger))
				if _, err := s.d.Write([]byte{byte(i)}); err != nil {
					t.Errorf("session %d: Write: %v", i, err)
					return
				}
				var b [1]byte
				if _, err := io.ReadFull(s.p, b[:]); err != nil || b[0] != byte(i) {
					t.Errorf("session %d: the passive read %d, %v", i, b[0], err)
					return
				}
				last[i] = time.Now()
			}()
		}
		for range n {
			<-done
		}
		if t.Failed() {
			t.FailNow()
		}

		// Every actor parks after the linger, long before the first deadline.
		sleepUntil(last[n-1].Add(2 * linger))
		synctest.Wait()
		if a, b := w.actors(); a != 0 || b != 0 {
			t.Fatalf("premise: Status.Actors %d and %d after the linger, want every actor parked", a, b)
		}
		if l, p := w.registry(); l != 2*n || p != 2*n {
			t.Fatalf("premise: %d live and %d parked sessions, want %d each", l, p, 2*n)
		}

		// The deadlines: each session's end is published (EventSessionEnd)
		// when its actor ends it; Done follows once its carrier retired.
		for i, s := range ps {
			for j, c := range []*rendr.Conn{s.d, s.p} {
				select {
				case <-c.Done():
				case <-time.After(time.Minute):
					t.Fatalf("session %d: the %s's end did not come within a minute: %+v", i, [2]string{"dialer", "passive"}[j], c.Status())
				}
			}
		}
		var worst time.Duration
		for i, s := range ps {
			var evs [2]rendr.Event
			for j, c := range []*rendr.Conn{s.d, s.p} {
				ev, ok := w.ends[j].of(c.ID())
				if !ok {
					t.Fatalf("session %d: no EventSessionEnd on the %s", i, [2]string{"dialer", "passive"}[j])
				}
				evs[j] = ev
			}
			due := last[i].Add(idle)
			if d := evs[1].Time.Sub(due); d < 0 || d > time.Millisecond {
				t.Fatalf("session %d: the passive's IdleTimeout fired at %+v of its due time (t_p + %v), want within [0, 1 ms]", i, d, idle)
			} else {
				worst = max(worst, d)
			}
			if !errors.Is(evs[1].Err, rendr.ErrIdleTimeout) || !errors.Is(s.p.Status().Err, rendr.ErrIdleTimeout) {
				t.Fatalf("session %d: the passive ended with %v (status %v), want ErrIdleTimeout", i, evs[1].Err, s.p.Status().Err)
			}
			if d := evs[0].Time.Sub(evs[1].Time); d != oneWay {
				t.Fatalf("session %d: the dialer ended %v after the passive, want the reset's one-way delay %v", i, d, oneWay)
			}
			var ae *rendr.AbortError
			if err := s.d.Status().Err; !errors.As(err, &ae) || ae.Code != rendr.AbortIdle || !ae.Remote {
				t.Fatalf("session %d: the dialer ended with %v, want the peer's AbortIdle", i, err)
			}
		}
		t.Logf("%d deadlines fired on parked actors, at most %v after t_p + %v", n, worst, idle)
		w.close()
	})
}

// sleepUntil sleeps until at (no-op when it passed).
func sleepUntil(at time.Time) {
	if d := time.Until(at); d > 0 {
		time.Sleep(d)
	}
}
