package carrier

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// phStarts records probe attempt start times per factory through
// Hooks.DialStart (Establish runs it right before the factory call).
type phStarts struct {
	mu   sync.Mutex
	base time.Time
	at   map[int][]time.Duration
}

func newPhStarts(env *Env) *phStarts {
	s := &phStarts{base: time.Now(), at: make(map[int][]time.Duration)}
	env.Hooks = &testhooks.Hooks{DialStart: func(i int) {
		s.mu.Lock()
		s.at[i] = append(s.at[i], time.Since(s.base))
		s.mu.Unlock()
	}}
	return s
}

func (s *phStarts) of(i int) []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.at[i])
}

// phCadence lists the start times plan §3.6 prescribes for a slot whose
// attempts all fail at once: 0, then previous start + Backoff(n) with the
// cap max and jitter u, up to (excluding) cut.
func phCadence(max time.Duration, u float64, cut time.Duration) []time.Duration {
	out := []time.Duration{0}
	for n := 0; ; n++ {
		next := out[len(out)-1] + sched.Backoff(n, max, u)
		if next >= cut {
			return out
		}
		out = append(out, next)
	}
}

// TestProbeCadenceAfterFailures_L20 (plan §3.6, design §7.7): a probe slot
// whose path keeps failing starts its attempts at previous start +
// min(0.5 s·2ⁿ, Probe.BackoffMax) × U[0.8, 1.2) — checked at the jitter
// extremes and the middle; an attempt hung until DialTimeout is followed
// at once by the next (the next start is never before the failed attempt
// ended); the path's recovery attaches a probe carrier on the next attempt,
// whose success clears the failed mark set by the failures.
func TestProbeCadenceAfterFailures_L20(t *testing.T) {
	for _, u := range []float64{0, 0.5, 1 - 1e-9} {
		t.Run(fmt.Sprintf("Jitter%.2f", u), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var starts *phStarts
				r := newPhRig(t, 2, func(env *Env, p *HealthParams) {
					starts = newPhStarts(env)
					p.Rand = func() float64 { return u }
				})
				r.links[0].SetRefuse(true)
				r.links[1].SetRefuse(true)
				r.h.Use()
				const cut = 14 * time.Second
				r.until(cut - time.Millisecond)
				want := phCadence(4*time.Second, u, cut)
				for i := range 2 {
					if got := starts.of(i); !slices.Equal(got, want) {
						t.Fatalf("factory %d starts %v, want %v", i, got, want)
					}
				}
				s := r.h.Snapshot()
				for i := range 2 {
					if !s.Failed[i] || s.Info[i].FailReason != "transport_error" || s.Info[i].Attempts != uint64(len(want)) || s.Info[i].ProbeCarrier != 0 {
						t.Fatalf("factory %d: failed %v, info %+v", i, s.Failed[i], s.Info[i])
					}
				}
				if st := r.links[1].Stats(); st.DialFailures != int64(len(want)) {
					t.Fatalf("stimulus: %d refused dials, want %d", st.DialFailures, len(want))
				}
			})
		})
	}
	t.Run("HungThenRecovered", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var starts *phStarts
			r := newPhRig(t, 2, func(env *Env, p *HealthParams) {
				starts = newPhStarts(env)
				env.Timing.DialTimeout = 6 * time.Second
			})
			r.links[1].SetRefuse(true)
			r.h.Use()
			r.until(12 * time.Second) // failures at 0, 0.5, 1.5, 3.5, 7.5, 11.5 s
			r.links[1].SetRefuse(false)
			r.links[1].SetDial(rendrtest.DialHang) // the 15.5 s attempt hangs until DialTimeout
			r.until(21 * time.Second)
			r.links[1].SetDial(rendrtest.DialNormal)
			r.until(21600 * time.Millisecond)
			ms := time.Millisecond
			want := []time.Duration{0, 500 * ms, 1500 * ms, 3500 * ms, 7500 * ms, 11500 * ms, 15500 * ms, 21500 * ms}
			if got := starts.of(1); !slices.Equal(got, want) {
				t.Fatalf("starts %v, want %v (the attempt after the hung one starts when it ends at 21.5 s)", got, want)
			}
			s := r.h.Snapshot()
			if s.Failed[1] || s.Info[1].ProbeCarrier == 0 || s.Info[1].Attempts != 8 || s.Sum[1].N != 1 {
				t.Fatalf("after the recovery: failed %v, info %+v, summary %+v", s.Failed[1], s.Info[1], s.Sum[1])
			}
			if got := starts.of(0); len(got) != 1 || s.Info[0].Attempts != 1 {
				t.Fatalf("the healthy factory redialled: %v", got)
			}
		})
	})
}

// TestProbeCapacityRefusalBacksOff_L20 (plan §3.5): a passive whose
// sessionless pool is full answers each probe with CLOSE(capacity); the
// factory is marked failed with reason "capacity" and the slot backs off
// like after any probe failure (0, 0.5, 1.5, 3.5 s …) instead of
// reconnecting in a loop; once the pool has room, the next attempt
// attaches and clears the mark.
func TestProbeCapacityRefusalBacksOff_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var starts *phStarts
		r := newPhRig(t, 2, func(env *Env, p *HealthParams) { starts = newPhStarts(env) })
		r.pas.setCapacity(true)
		r.h.Use()
		r.until(4 * time.Second)
		want := phCadence(4*time.Second, 0.5, 4*time.Second)
		s := r.h.Snapshot()
		for i := range 2 {
			if got := starts.of(i); !slices.Equal(got, want) {
				t.Fatalf("factory %d starts %v, want %v", i, got, want)
			}
			if !s.Failed[i] || s.Info[i].FailReason != "capacity" || s.Info[i].ProbeCarrier != 0 {
				t.Fatalf("factory %d: failed %v, info %+v", i, s.Failed[i], s.Info[i])
			}
			// Stimulus: the passive answered every one of them with CLOSE.
			pas := r.pas.on(i)
			if len(pas) != len(want) {
				t.Fatalf("passive saw %d probe carriers on path %d, want %d", len(pas), i, len(want))
			}
			for _, c := range pas {
				if hCause(c) != CauseLocalClose {
					t.Fatalf("passive carrier ended %v, want local_close (WriteAndClose)", hCause(c))
				}
			}
		}
		r.pas.setCapacity(false)
		r.until(7600 * time.Millisecond) // the next attempts start at 7.5 s
		s = r.h.Snapshot()
		for i := range 2 {
			if s.Failed[i] || s.Info[i].ProbeCarrier == 0 || s.Sum[i].N != 1 || s.Info[i].Attempts != uint64(len(want)+1) {
				t.Fatalf("factory %d after the pool had room: failed %v, info %+v, summary %+v", i, s.Failed[i], s.Info[i], s.Sum[i])
			}
		}
	})
}

// TestProbeEarlyEndRedialSpacing_L20 (design §7.8): a probe carrier that
// dies right after its establishment is replaced no earlier than one
// backoff step after the start of the attempt that established it, so a
// path that accepts and then drops every probe carrier cannot make the
// slot redial in a loop; one that lived longer is replaced at once. Each
// death marks the factory failed with its cause; the replacement clears it.
func TestProbeEarlyEndRedialSpacing_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var starts *phStarts
		r := newPhRig(t, 2, func(env *Env, p *HealthParams) { starts = newPhStarts(env) })
		r.h.Use()
		r.until(30 * time.Millisecond) // established at 20 ms
		if n := r.links[0].Kill(); n != 1 {
			t.Fatalf("killed %d", n)
		}
		r.until(40 * time.Millisecond)
		if s := r.h.Snapshot(); !s.Failed[0] || s.Info[0].FailReason != "transport_error" {
			t.Fatalf("after the early death: failed %v, info %+v", s.Failed[0], s.Info[0])
		}
		r.until(5 * time.Second)
		ms := time.Millisecond
		if got := starts.of(0); !slices.Equal(got, []time.Duration{0, 500 * ms}) {
			t.Fatalf("starts %v, want [0 500ms]", got)
		}
		if s := r.h.Snapshot(); s.Failed[0] || s.Info[0].ProbeCarrier == 0 {
			t.Fatalf("not replaced at 0.5 s: failed %v, info %+v", s.Failed[0], s.Info[0])
		}
		r.links[0].Kill() // lived 4.5 s: replaced at once
		r.until(5030 * time.Millisecond)
		r.links[0].Kill() // the replacement dies 30 ms after its attempt began
		r.until(6 * time.Second)
		want := []time.Duration{0, 500 * ms, 5000 * ms, 5500 * ms}
		if got := starts.of(0); !slices.Equal(got, want) {
			t.Fatalf("starts %v, want %v", got, want)
		}
		if s := r.h.Snapshot(); s.Failed[0] || s.Info[0].ProbeCarrier == 0 || s.Info[0].Attempts != 4 {
			t.Fatalf("final: failed %v, info %+v", s.Failed[0], s.Info[0])
		}
	})
}

// TestHealthFailedMarkNeedsLaterSuccess_L27 (plan §3.9, design §7.3): a
// death's mark keeps the factory ranked last — repeated deaths do not flap
// — until a success that happened after it: a probe dial that started
// before the mark establishes without clearing it; the PONG of the first
// PING committed after the mark clears it; Succeeded (a session carrier's
// PREFACE exchange) clears it at once.
func TestHealthFailedMarkNeedsLaterSuccess_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPhRig(t, 2, nil)
		r.links[1].SetDelay(200*time.Millisecond, 0) // establishment 400 ms, PING RTT 400 ms
		bell := &hBell{}
		defer r.h.Subscribe(bell)()
		r.h.Use()
		r.until(100 * time.Millisecond)
		r.h.MarkFailed(1, "ping_timeout") // while the attempt that started at 0 runs
		r.until(450 * time.Millisecond)
		s := r.h.Snapshot()
		if s.Info[1].ProbeCarrier == 0 || !s.Failed[1] {
			t.Fatalf("established at 400 ms: info %+v, failed %v (a dial that began before the mark must not clear it)", s.Info[1], s.Failed[1])
		}
		r.until(800 * time.Millisecond) // the PONG of the PING committed at 400 ms
		s = r.h.Snapshot()
		if s.Failed[1] || s.Sum[1].N != 1 || s.Sum[1].Mean != 400*time.Millisecond {
			t.Fatalf("PONG after the mark: failed %v, summary %+v", s.Failed[1], s.Sum[1])
		}
		r.until(time.Second)
		v, rings := r.h.Snapshot().Version, bell.n.Load()
		r.h.MarkFailed(1, "write_stall")
		if s = r.h.Snapshot(); !s.Failed[1] || s.Info[1].FailReason != "write_stall" {
			t.Fatalf("MarkFailed: %+v", s.Info[1])
		}
		r.h.Succeeded(1)
		if s = r.h.Snapshot(); s.Failed[1] || s.Info[1].FailReason != "" || s.Version != v+2 || bell.n.Load() != rings+2 {
			t.Fatalf("Succeeded: failed %v, info %+v, version %d→%d, rings %d→%d", s.Failed[1], s.Info[1], v, s.Version, rings, bell.n.Load())
		}
	})
}
