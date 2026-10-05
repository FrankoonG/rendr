package rendr

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"runtime/metrics"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Idle cost per session (design §0.14 B18, R16): goroutines, actor and
// writer wakeups per idle minute, the two memory accounts, heap and stack
// of idle sessions between two Runtimes. TestG5IdleSessionCost_L52 asserts
// the recorded bounds inside a synctest bubble (one virtual idle minute);
// BenchmarkIdleSessions reports the same figures in real time.
//
// Two carrier kinds serve different figures. net.Pipe carriers add no
// buffer or goroutine of a test carrier, so goroutines, heap and stack are
// rendr's own. But a synchronous pipe often hands a probe PONG back before
// its PING's Write returned; such a PONG gives no RTT sample (L23), and
// PONGs that arrive at the same instant coalesce into one wakeup, so over
// net.Pipe a multi-factory Peer's probe samples, and the actor wakeups they
// cause, depend on scheduling (none at GOMAXPROCS=1 without -race). The
// "-paths" cases run every factory over an asynchronous rendrtest Link with
// its own one-way delay (5, 20, 50 ms), where every probe PING gives a
// sample at a distinct instant: they bound the wakeups against the probe
// samples counted in the same minute, and their stimulus is that count. The
// Links' buffers would distort the heap figures there, so those are bounded
// over net.Pipe only.

// g5IdleCase is one measured session shape with its recorded bounds per
// session pair (both ends). Measured on the Windows host (Go 1.26; this
// test at GOMAXPROCS 1, 2, 4 and 64, with and without -race, and
// BenchmarkIdleSessions in real time):
//   - selector, one factory (no probing): 6 goroutines, no actor wakeup
//     and 17–23 writer wakeups per idle minute, heap 85–96 KiB, stack in
//     use 5.2 KiB (7.1 KiB under -race);
//   - bond3 over net.Pipe: 14 goroutines, 53–69 writer wakeups per idle
//     minute, heap 235–252 KiB, stack in use 13.2 KiB (18.2 KiB under
//     -race); its actor wakeups follow the probe samples the pipes happen
//     to give, 0–80 per idle minute (0 at GOMAXPROCS=1 without -race; 18
//     in real time), never more than the samples;
//   - selector3-paths and bond3-paths: exactly one actor wakeup per probe
//     sample of the Peer, 90 per idle minute (3 factories × 60 s / the
//     default 2 s Probe.Interval; also in real time), because every health
//     publication rings every dialer session of the Peer, whatever its
//     mode; 24–27 and 70–80 writer wakeups per idle minute.
type g5IdleCase struct {
	name      string
	mode      Mode
	factories int             // factories of the Peer
	n         int             // idle sessions measured by the test (the benchmark opens g5BenchSessions)
	delays    []time.Duration // one-way delay of each factory's rendrtest Link; nil: net.Pipe carriers

	goroutines    float64 // structural: actor + reader + writer per carrier, on each side
	writerWakeups float64 // bound per idle minute
	heap, stack   float64 // bounds in bytes (stack: in use, as scanned by the GC); 0: not bounded (Links)
}

// carriers returns the carriers of one session of c: one for a selector,
// one per factory for a bond.
func (c g5IdleCase) carriers() int {
	if c.mode == ModeBond {
		return c.factories
	}
	return 1
}

// g5PathDelays are the one-way delays of the "-paths" cases' three Links.
var g5PathDelays = []time.Duration{5 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond}

var g5IdleCases = []g5IdleCase{
	{name: "selector", mode: ModeSelector, factories: 1, n: 16,
		goroutines: 6, writerWakeups: 36, heap: 128 << 10, stack: 10 << 10},
	{name: "bond3", mode: ModeBond, factories: 3, n: 8,
		goroutines: 14, writerWakeups: 100, heap: 320 << 10, stack: 24 << 10},
	{name: "selector3-paths", mode: ModeSelector, factories: 3, n: 8, delays: g5PathDelays,
		goroutines: 6, writerWakeups: 36},
	{name: "bond3-paths", mode: ModeBond, factories: 3, n: 8, delays: g5PathDelays,
		goroutines: 14, writerWakeups: 100},
}

// g5WakeSlack is the bound's allowance per session pair and idle minute
// above one actor wakeup per probe sample of the Peer.
const g5WakeSlack = 1

// g5Cost is the measured idle cost of one session pair (both ends).
type g5Cost struct {
	goroutines    float64 // rendr goroutines per pair
	actorWakeups  float64 // session actor resumptions per pair per idle minute
	writerWakeups float64 // carrier writer resumptions per pair per idle minute
	samples       float64 // probe samples of the Peer (every factory, loaded included) per idle minute
	opening       float64 // actor resumptions per pair while the sessions opened (proves the counter works)
	data, stages  float64 // bytes per side: the MaxBufferedBytes account, the reader stages
	heap          float64 // live heap after GC, bytes per pair
	stackUsed     float64 // stack in use (scanned by the GC), bytes per pair
	stackSpans    float64 // growth of the stack spans (runtime.MemStats.StackInuse), bytes per pair
}

// Entry functions (innermost frame outside package runtime) of the waits
// whose resumptions g5Wakeups counts.
const (
	g5ActorWait  = "github.com/FrankoonG/rendr/v2/internal/session.(*actor).run"
	g5WriterWait = "github.com/FrankoonG/rendr/v2/internal/carrier.(*Conn).sleep"
)

// g5Wakeups returns how often goroutines resumed from a blocking wait whose
// innermost non-runtime frame is fn, as recorded by the block profile
// (cumulative). A wait is recorded only if it began while the block profile
// rate was positive: the callers enable it (rate 1, every event) before the
// goroutines they measure exist.
func g5Wakeups(fn string) int64 {
	var recs []runtime.BlockProfileRecord
	for {
		n, _ := runtime.BlockProfile(nil)
		recs = make([]runtime.BlockProfileRecord, n+64)
		if n, ok := runtime.BlockProfile(recs); ok {
			recs = recs[:n]
			break
		}
	}
	var total int64
	for _, r := range recs {
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			if !strings.HasPrefix(f.Function, "runtime.") {
				if f.Function == fn {
					total += r.Count
				}
				break
			}
			if !more {
				break
			}
		}
	}
	return total
}

// g5Snap is one sample of the process, of both Runtimes and of the Peer.
type g5Snap struct {
	goroutines            int
	actor, writer         int64
	data, buffered        [2]int64 // dialer, passive
	carriers              [2]int64 // live session carriers: dialer, passive
	probes, sessionless   int      // the Peer's probe carriers; the passive's sessionless carriers (their far ends)
	samples               uint64   // the Peer's probe samples so far (every factory, loaded included)
	heap, spans, stackUse uint64
}

// g5Sample collects garbage (repeatedly, so that idle stacks shrink) and
// samples e, the Peer and the sessions: dialed are the dialer ends, acc
// holds the passive ends.
func g5Sample(e *e2ePair, peer *Peer, dialed []*Conn, acc *acceptLog) g5Snap {
	for range 4 {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	scan := []metrics.Sample{{Name: "/gc/scan/stack:bytes"}}
	metrics.Read(scan)
	g, _ := rendrGoroutines()
	s := g5Snap{goroutines: g, actor: g5Wakeups(g5ActorWait), writer: g5Wakeups(g5WriterWait),
		heap: m.HeapAlloc, spans: m.StackInuse, stackUse: scan[0].Value.Uint64()}
	for i, rt := range []*Runtime{e.d, e.p} {
		s.data[i] = rt.budget.Used()
		s.buffered[i] = rt.Status().BufferedBytes
	}
	acc.mu.Lock()
	passive := slices.Clone(acc.conns)
	acc.mu.Unlock()
	for i, ends := range [][]*Conn{dialed, passive} {
		for _, c := range ends {
			s.carriers[i] += int64(len(liveCarriers(c.Status())))
		}
	}
	for _, f := range peer.Status().Factories {
		s.samples += f.Samples
		if f.ProbeCarrier != 0 {
			s.probes++
		}
	}
	s.sessionless = e.p.Status().Sessionless
	return s
}

// g5PipeCarrier is a factory whose carriers are net.Pipe pairs, the
// passive end handed to ln.Handle.
func g5PipeCarrier(name string, ln *Listener) StreamCarrier {
	return StreamCarrier{Name: name, Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		if err := ln.Handle(a); err != nil {
			a.Close()
			b.Close()
			return nil, err
		}
		return b, nil
	}}
}

// g5NewPair builds the two Runtimes of case c (default Config): for a
// "-paths" case with one rendrtest Link per factory, each with its one-way
// delay (create it inside the bubble that uses it).
func g5NewPair(tb testing.TB, c g5IdleCase) *e2ePair {
	tb.Helper()
	var names []string
	for i := range c.delays {
		names = append(names, string(rune('a'+i)))
	}
	e := e2eNew(tb, Config{}, Config{}, nil, ListenConfig{}, names...)
	for i, l := range e.links {
		l.SetDelay(c.delays[i], 0)
	}
	return e
}

// g5MeasureIdle opens c's warm-up session (a multi-factory Peer's probe
// carriers run from then on) and then n idle sessions of c's shape between
// e's Runtimes, measures what the n sessions added, and ends every session.
// settle waits until nothing moves after the sleeps of settleFor; check,
// if set, gets every sample (taken after settle). Wakeups and probe samples
// are counted during an idle period (idle, scaled to one minute) with all
// n+1 sessions; writer wakeups also with the warm-up session alone, and
// the difference excludes the writers of the Peer's probe carriers and of
// their sessionless far ends. The block profile must be enabled already
// (g5Wakeups).
func g5MeasureIdle(t testing.TB, e *e2ePair, c g5IdleCase, n int, settleFor, idle time.Duration, settle func(), check func(when string, s g5Snap)) g5Cost {
	t.Helper()
	acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
	defer acc.stop()
	cs := make([]Carrier, c.factories)
	for i := range cs {
		if i < len(e.links) {
			cs[i] = e2eCarrier(e.links[i])
		} else {
			cs[i] = g5PipeCarrier(string(rune('a'+i)), e.ln)
		}
	}
	peer, err := e.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	var dialed []*Conn
	dial := func() {
		dc, err := peer.Dial(context.Background(), DialOptions{Mode: c.mode})
		if err != nil {
			t.Fatalf("Dial %d: %v", len(dialed), err)
		}
		dialed = append(dialed, dc)
	}
	sample := func(when string) g5Snap {
		settle()
		s := g5Sample(e, peer, dialed, acc)
		if check != nil {
			check(when, s)
		}
		return s
	}
	dial()
	time.Sleep(settleFor)
	warm := sample("with the warm-up session")
	time.Sleep(idle)
	base := sample("after the warm-up session's idle period")
	for range n {
		dial()
	}
	time.Sleep(settleFor)
	open := sample(fmt.Sprintf("with %d more sessions", n))
	time.Sleep(idle)
	end := sample("after their idle period")

	per := func(a, b int64) float64 { return float64(b-a) / float64(n) }
	cost := g5Cost{
		goroutines:    per(int64(base.goroutines), int64(open.goroutines)),
		actorWakeups:  float64(end.actor-open.actor) / (float64(n+1) * idle.Minutes()),
		writerWakeups: float64((end.writer-open.writer)-(base.writer-warm.writer)) / (float64(n) * idle.Minutes()),
		samples:       float64(end.samples-open.samples) / idle.Minutes(),
		opening:       per(base.actor, open.actor),
		heap:          per(int64(base.heap), int64(open.heap)),
		stackUsed:     per(int64(base.stackUse), int64(open.stackUse)),
		stackSpans:    per(int64(base.spans), int64(open.spans)),
	}
	for i := range 2 {
		cost.data += per(base.data[i], open.data[i]) / 2
		cost.stages += per(base.buffered[i]-base.data[i], open.buffered[i]-open.data[i]) / 2
	}
	if live := len(liveCarriers(dialed[len(dialed)-1].Status())); live != c.carriers() {
		t.Errorf("%s: the last session has %d live carriers, want %d", c.name, live, c.carriers())
	}

	acc.mu.Lock()
	all := append(dialed, acc.conns...)
	acc.mu.Unlock()
	if len(all) != 2*(n+1) {
		t.Errorf("%s: %d session ends, want %d", c.name, len(all), 2*(n+1))
	}
	for _, sc := range all {
		sc.Close()
	}
	for _, sc := range all {
		select {
		case <-sc.s.Done():
		case <-time.After(time.Minute):
			t.Fatalf("session %v not done a minute after Close: %+v", sc.ID(), sc.Status())
		}
	}
	return cost
}

// g5EnableBlockProfile records every blocking event until the test or
// benchmark ends (the profile itself is cumulative; g5Wakeups takes
// differences).
func g5EnableBlockProfile(tb testing.TB) {
	runtime.SetBlockProfileRate(1)
	tb.Cleanup(func() { runtime.SetBlockProfileRate(0) })
}

// g5CheckAccounts requires the account split of B2 in a quiescent sample of
// case c: every session is idle, so neither Runtime's MaxBufferedBytes
// account holds a byte, and BufferedBytes minus it is one reader stage per
// started carrier: the session carriers, plus the Peer's probe carriers on
// the dialer and their sessionless far ends on the passive (stimulus: a
// multi-factory Peer runs one probe carrier per factory).
func g5CheckAccounts(t testing.TB, c g5IdleCase, when string, s g5Snap) {
	t.Helper()
	if want := c.factories; want > 1 && (s.probes != want || s.sessionless != want) {
		t.Errorf("%s: %d probe carriers on the dialer and %d sessionless carriers on the passive, want %d each",
			when, s.probes, s.sessionless, want)
	}
	others := [2]int64{int64(s.probes), int64(s.sessionless)}
	for i, side := range [2][2]string{{"dialer", "probe"}, {"passive", "sessionless"}} {
		want := (s.carriers[i] + others[i]) * g5StageBytes
		if got := s.buffered[i] - s.data[i]; s.data[i] != 0 || got != want {
			t.Errorf("%s, %s: %d bytes in the MaxBufferedBytes account and %d in the stage account, want 0 and %d (one reader stage for each of %d session and %d %s carriers)",
				when, side[0], s.data[i], got, want, s.carriers[i], others[i], side[1])
		}
	}
}

// TestG5IdleSessionCost_L52 (design §0.14 B18, R16; L52): idle sessions cost
// what was recorded, with headroom, per session pair (both ends) in a
// virtual idle minute: a selector pair runs 6 goroutines and a 3-member
// bond pair 14 (an actor, and a reader and a writer per carrier, on each
// side). An actor wakes at most once per probe sample of its Peer
// (g5WakeSlack aside): a single-factory Peer has none, so its sessions
// sleep; a multi-factory Peer publishes its health at every sample and
// rings each of its dialer sessions, selector or bond. Writers wake for the
// PINGs of PingIdle (10 s) and their PONGs. The MaxBufferedBytes account
// holds nothing, and the stage account exactly one 16 KiB stage per started
// carrier, probe and sessionless carriers included (B2); heap and stack in
// use stay within the recorded bounds (net.Pipe cases). Stimulus and load:
// over the delayed paths the Peer took exactly one probe sample per factory
// and Probe.Interval during the idle minute; a multi-factory Peer's probe
// carriers and their sessionless far ends were up at every sample; the
// counted actors woke while the sessions opened, and idle writers woke at
// least once per carrier end.
func TestG5IdleSessionCost_L52(t *testing.T) {
	for _, c := range g5IdleCases {
		t.Run(c.name, func(t *testing.T) {
			g5EnableBlockProfile(t)
			synctest.Test(t, func(t *testing.T) {
				e := g5NewPair(t, c)
				check := func(when string, s g5Snap) { g5CheckAccounts(t, c, when, s) }
				cost := g5MeasureIdle(t, e, c, c.n, 30*time.Second, time.Minute, synctest.Wait, check)
				t.Logf("%s, %d sessions: %.2f goroutines, %.2f actor wakeups (%.2f probe samples) and %.2f writer wakeups per idle minute, data %.0f B and stages %.0f B per side, heap %.1f KiB, stack in use %.1f KiB (spans %+.1f KiB) per pair",
					c.name, c.n, cost.goroutines, cost.actorWakeups, cost.samples, cost.writerWakeups, cost.data, cost.stages,
					cost.heap/1024, cost.stackUsed/1024, cost.stackSpans/1024)
				if cost.opening < 1 || cost.writerWakeups < float64(2*c.carriers()) {
					t.Errorf("load: %.2f actor resumptions per pair while opening, %.2f writer wakeups per pair per idle minute: the wakeup counter sees nothing",
						cost.opening, cost.writerWakeups)
				}
				if c.delays != nil {
					if want := float64(c.factories) * float64(time.Minute/e.d.eff.health.Interval); cost.samples != want {
						t.Errorf("stimulus: %.2f probe samples in the idle minute, want %.0f (one per factory and Probe.Interval %v)",
							cost.samples, want, e.d.eff.health.Interval)
					}
				}
				if cost.goroutines != c.goroutines {
					t.Errorf("%.2f goroutines per pair, want %v", cost.goroutines, c.goroutines)
				}
				if cost.actorWakeups > cost.samples+g5WakeSlack || cost.writerWakeups > c.writerWakeups {
					t.Errorf("%.2f actor and %.2f writer wakeups per pair per idle minute, want at most %.2f (one per probe sample, %.2f, + %d) and %v",
						cost.actorWakeups, cost.writerWakeups, cost.samples+g5WakeSlack, cost.samples, g5WakeSlack, c.writerWakeups)
				}
				if want := float64(c.carriers() * g5StageBytes); cost.data != 0 || cost.stages != want {
					t.Errorf("per side and session: %.0f bytes in the MaxBufferedBytes account and %.0f in the stage account, want 0 and %.0f",
						cost.data, cost.stages, want)
				}
				if c.heap > 0 && (cost.heap > c.heap || cost.stackUsed > c.stack) {
					t.Errorf("heap %.1f KiB and stack in use %.1f KiB per pair, want at most %.0f and %.0f KiB",
						cost.heap/1024, cost.stackUsed/1024, c.heap/1024, c.stack/1024)
				}
				e.close()
			})
		})
	}
}

// Real-time parameters of BenchmarkIdleSessions.
const (
	g5BenchSessions = 128              // idle sessions per case
	g5BenchSettle   = time.Second      // after the warm-up session and after the dials
	g5BenchIdle     = 10 * time.Second // one PingIdle period, scaled to a minute
)

// BenchmarkIdleSessions (perf lane, design §12.4, R16) reports the idle
// cost of every g5IdleCases shape, per session pair (both ends) unless the
// unit says per side: goroutines, session actor and carrier writer wakeups
// per idle minute next to the Peer's probe samples per minute (one actor
// wakeup per sample at most; over net.Pipe the samples depend on
// scheduling), the MaxBufferedBytes and reader stage accounts and, over
// net.Pipe only, live heap, stack in use and the growth of the stack spans
// (allocation granularity: platform dependent and noisy). Counts are taken
// over one real PingIdle period (no synctest bubble in benchmarks): about
// 22 s per case.
func BenchmarkIdleSessions(b *testing.B) {
	for _, c := range g5IdleCases {
		b.Run(c.name, func(b *testing.B) {
			g5EnableBlockProfile(b)
			var cost g5Cost
			for b.Loop() {
				e := g5NewPair(b, c)
				cost = g5MeasureIdle(b, e, c, g5BenchSessions, g5BenchSettle, g5BenchIdle, func() {}, nil)
				e.close()
			}
			b.ReportMetric(0, "ns/op")
			b.ReportMetric(cost.goroutines, "goroutines/pair")
			b.ReportMetric(cost.actorWakeups, "actor-wakeups/pair-min")
			b.ReportMetric(cost.samples, "probe-samples/min")
			b.ReportMetric(cost.writerWakeups, "writer-wakeups/pair-min")
			b.ReportMetric(cost.data, "data-B/side")
			b.ReportMetric(cost.stages, "stage-B/side")
			if c.heap > 0 {
				b.ReportMetric(cost.heap, "heap-B/pair")
				b.ReportMetric(cost.stackUsed, "stack-used-B/pair")
				b.ReportMetric(cost.stackSpans, "stack-spans-B/pair")
			}
		})
	}
}
