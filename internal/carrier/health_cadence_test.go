package carrier

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// prStarts records probe attempt start times per factory through
// Hooks.DialStart (Establish runs it right before the factory call).
type prStarts struct {
	mu   sync.Mutex
	base time.Time
	at   map[int][]time.Duration
}

func newPrStarts(env *Env) *prStarts {
	s := &prStarts{base: time.Now(), at: make(map[int][]time.Duration)}
	env.Hooks = &testhooks.Hooks{DialStart: func(i int) {
		s.mu.Lock()
		s.at[i] = append(s.at[i], time.Since(s.base))
		s.mu.Unlock()
	}}
	return s
}

func (s *prStarts) of(i int) []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.at[i])
}

// prCadence lists the start times plan §3.6 prescribes for a slot whose
// attempts all fail at once: 0, then previous start + Backoff(n) with the
// cap max and jitter u, up to (excluding) cut.
func prCadence(max time.Duration, u float64, cut time.Duration) []time.Duration {
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
				var starts *prStarts
				r := newPrRig(t, 2, func(env *Env, p *HealthParams) {
					starts = newPrStarts(env)
					p.Rand = func() float64 { return u }
				})
				r.links[0].SetRefuse(true)
				r.links[1].SetRefuse(true)
				r.h.Use()
				const cut = 14 * time.Second
				r.until(cut - time.Millisecond)
				want := prCadence(4*time.Second, u, cut)
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
			var starts *prStarts
			r := newPrRig(t, 2, func(env *Env, p *HealthParams) {
				starts = newPrStarts(env)
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
// reconnecting in a loop. Every refused carrier is discarded at once — its
// conn closed, its CarrierID released — not kept until probing stops. Once
// the pool has room, the next attempt attaches and clears the mark.
func TestProbeCapacityRefusalBacksOff_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var starts *prStarts
		r := newPrRig(t, 2, func(env *Env, p *HealthParams) { starts = newPrStarts(env) })
		r.pas.setCapacity(true)
		r.h.Use()
		want := prCadence(4*time.Second, 0.5, 4*time.Second)
		for _, at := range want {
			r.until(at + 30*time.Millisecond) // the refusal arrived at at + 20 ms
			if n := r.env.IDs.inUse(); n != 0 {
				t.Fatalf("at %v: %d CarrierIDs in use without a probe carrier (a refused carrier was kept)", at+30*time.Millisecond, n)
			}
		}
		r.until(4 * time.Second)
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
		if n := r.env.IDs.inUse(); n != 2 {
			t.Fatalf("%d CarrierIDs in use with two probe carriers", n)
		}
	})
}

// TestProbeAcceptThenDropBacksOff_L20 (plan §3.6 applied to probe slots,
// design §7.7, §7.8): a path that accepts every probe carrier and drops it
// right after the establishment — killed (a death: the factory is marked
// failed with its cause until the next establishment) or retired with
// CLOSE (a planned end: no mark) — is redialled like a path that refuses
// (0, 0.5, 1.5, 3.5, 7.5, 11.5 s: the spacing grows to Probe.BackoffMax),
// never at dial speed, although every attempt completes the PREFACE
// exchange. A probe carrier that held the path for at least BackoffMax is
// replaced at once when it dies, and the failure count restarts: a
// replacement that dies 30 ms after its attempt began is redialled one
// Backoff(0) step after that start. Through all the reconnects the run
// keeps its carrier and attempt lists bounded.
func TestProbeAcceptThenDropBacksOff_L20(t *testing.T) {
	for _, tc := range []struct {
		name   string
		retire bool
	}{{"Killed", false}, {"Retired", true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var starts *prStarts
				r := newPrRig(t, 2, func(env *Env, p *HealthParams) { starts = newPrStarts(env) })
				// Each probe carrier of path 0 is established at its attempt's
				// start + 20 ms and ended by the passive at + 25 ms, before the
				// PONG of its first PING (+ 40 ms).
				r.pas.setDrop(0, prDrop{after: 15 * time.Millisecond, retire: tc.retire})
				r.h.Use()
				r.until(12 * time.Second)
				want := prCadence(4*time.Second, 0.5, 12*time.Second)
				if got := starts.of(0); !slices.Equal(got, want) {
					t.Fatalf("starts %v, want the refusal cadence %v", got, want)
				}
				// Stimulus: every attempt established a carrier that the passive
				// then ended, and none produced a sample.
				s := r.h.Snapshot()
				pas := r.pas.on(0)
				wantCause, wantReason := CauseLocalClose, "transport_error"
				if tc.retire {
					wantCause, wantReason = CauseRetired, ""
				}
				if len(pas) != len(want) || s.Info[0].Samples != 0 || s.Info[0].ProbeCarrier != 0 || s.Info[0].Attempts != uint64(len(want)) {
					t.Fatalf("passive carriers %d (want %d), info %+v", len(pas), len(want), s.Info[0])
				}
				for k, c := range pas {
					if hCause(c) != wantCause {
						t.Fatalf("passive carrier %d ended %v, want %v", k, hCause(c), wantCause)
					}
				}
				if s.Failed[0] != !tc.retire || s.Info[0].FailReason != wantReason {
					t.Fatalf("after the last drop: failed %v, info %+v", s.Failed[0], s.Info[0])
				}
				// Bounded (invariant 4): six incarnations of path 0, yet the run
				// holds at most one not yet pruned dead carrier per slot.
				r.h.mu.Lock()
				live, atts := len(r.h.run.live), len(r.h.run.atts)
				r.h.mu.Unlock()
				if live > 2*len(r.links) || atts > len(r.links) {
					t.Fatalf("the run's lists grew: %d carriers, %d attempts", live, atts)
				}

				// The path keeps its carriers again: the 15.5 s attempt attaches
				// and samples; nearly 10 s later its death is replaced at once.
				r.pas.setDrop(0, prDrop{})
				r.until(25 * time.Second)
				if s = r.h.Snapshot(); s.Info[0].ProbeCarrier == 0 || s.Info[0].Samples < 5 || s.Failed[0] {
					t.Fatalf("the healthy path did not attach: failed %v, info %+v", s.Failed[0], s.Info[0])
				}
				if n := r.links[0].Kill(); n != 1 {
					t.Fatalf("killed %d carriers on path 0, want the probe", n)
				}
				r.until(25030 * time.Millisecond) // re-established at 25.02 s
				if n := r.links[0].Kill(); n != 1 {
					t.Fatalf("killed %d carriers on path 0, want the new probe", n)
				}
				r.until(26 * time.Second)
				ms := time.Millisecond
				want = append(want, 15500*ms, 25000*ms, 25500*ms)
				if got := starts.of(0); !slices.Equal(got, want) {
					t.Fatalf("starts %v, want %v", got, want)
				}
				if s = r.h.Snapshot(); s.Failed[0] || s.Info[0].ProbeCarrier == 0 || s.Info[0].Attempts != uint64(len(want)) {
					t.Fatalf("final: failed %v, info %+v", s.Failed[0], s.Info[0])
				}
				if got := starts.of(1); len(got) != 1 {
					t.Fatalf("the healthy factory redialled: %v", got)
				}
			})
		})
	}
}

// TestProbeFailureReasons_L20 (design §7.8; FactoryStatus.FailReason): a
// probe the passive refuses marks its factory failed with a reason that
// names the answer — a non-OK PREFACE_ACK by its status, an established
// probe answered by CLOSE or GOAWAY instead of its PONG by that answer —
// discards the refused carrier at once and backs off like any probe
// failure, while the other factory keeps its probe.
func TestProbeFailureReasons_L20(t *testing.T) {
	cases := []struct {
		name   string
		refuse prRefuse
		reason string
	}{
		{"PrefaceCapacity", prRefuse{status: wire.PrefaceCapacity}, "capacity"},
		{"PrefaceGoingAway", prRefuse{status: wire.PrefaceGoingAway}, "going_away"},
		{"PrefaceVersion", prRefuse{status: wire.PrefaceVersion}, "version"},
		{"PrefaceFeature", prRefuse{status: wire.PrefaceFeature}, "feature"},
		{"CloseCapacity", prRefuse{answer: wire.TypeClose, reason: uint8(wire.CloseCapacity)}, "capacity"},
		{"CloseRetire", prRefuse{answer: wire.TypeClose, reason: uint8(wire.CloseRetire)}, "closed"},
		{"GoAway", prRefuse{answer: wire.TypeGoAway, reason: uint8(wire.GoAwayShutdown)}, "going_away"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var starts *prStarts
				r := newPrRig(t, 2, func(env *Env, p *HealthParams) { starts = newPrStarts(env) })
				r.pas.setRefuse(1, tc.refuse)
				r.h.Use()
				r.until(time.Second) // refused at 20 ms and 520 ms
				s := r.h.Snapshot()
				if !s.Failed[1] || s.Info[1].FailReason != tc.reason || s.Info[1].ProbeCarrier != 0 || s.Info[1].Attempts != 2 {
					t.Fatalf("refused factory: failed %v, info %+v, want reason %q", s.Failed[1], s.Info[1], tc.reason)
				}
				if got, want := starts.of(1), []time.Duration{0, 500 * time.Millisecond}; !slices.Equal(got, want) {
					t.Fatalf("starts %v, want %v", got, want)
				}
				if n := r.pas.refusals(1); n != 2 {
					t.Fatalf("stimulus: the passive refused %d carriers, want 2", n)
				}
				if n := r.env.IDs.inUse(); n != 1 || s.Failed[0] || s.Info[0].ProbeCarrier == 0 {
					t.Fatalf("%d CarrierIDs in use (want factory 0's probe only), factory 0: failed %v, info %+v", n, s.Failed[0], s.Info[0])
				}
			})
		})
	}
}

// TestProbeAttemptGoexit_L51: an embedder conn call that runs
// runtime.Goexit on a probe attempt's goroutine — here the Read of the
// PREFACE_ACK inside Establish — ends that attempt as a failure (failed
// mark, backoff) without leaking its CarrierID or a goroutine; the next
// attempt attaches and clears the mark.
func TestProbeAttemptGoexit_L51(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var starts *prStarts
		var goexits atomic.Int32
		r := newPrRigDial(t, 2, func(env *Env, p *HealthParams) { starts = newPrStarts(env) },
			func(i int, l *rendrtest.Link) func(context.Context) (net.Conn, error) {
				if i != 1 {
					return l.Dial
				}
				return func(ctx context.Context) (net.Conn, error) {
					nc, err := l.Dial(ctx)
					if err != nil {
						return nil, err
					}
					return prGoexitConn{Conn: nc, n: &goexits}, nil
				}
			})
		r.h.Use()
		r.until(100 * time.Millisecond)
		s := r.h.Snapshot()
		if goexits.Load() != 1 || !s.Failed[1] || s.Info[1].FailReason != "transport_error" || s.Info[1].ProbeCarrier != 0 {
			t.Fatalf("after the Goexit: goexits %d, failed %v, info %+v", goexits.Load(), s.Failed[1], s.Info[1])
		}
		if n, ab := r.env.IDs.inUse(), r.env.Abandon.Len(); n != 1 || ab != 0 {
			t.Fatalf("after the Goexit: %d CarrierIDs in use (want factory 0's probe), %d abandoned", n, ab)
		}
		r.until(time.Second)
		s = r.h.Snapshot()
		if got, want := starts.of(1), []time.Duration{0, 500 * time.Millisecond}; !slices.Equal(got, want) {
			t.Fatalf("starts %v, want %v", got, want)
		}
		if s.Failed[1] || s.Info[1].ProbeCarrier == 0 || s.Sum[1].N != 1 {
			t.Fatalf("the next attempt did not attach: failed %v, info %+v, summary %+v", s.Failed[1], s.Info[1], s.Sum[1])
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
		r := newPrRig(t, 2, nil)
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
