package rendr

import (
	"context"
	"net"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Idle cost per session (design §0.14 B18, R16): goroutines, actor and
// writer wakeups per idle minute, the two memory accounts, heap and stack
// of idle sessions between two Runtimes over net.Pipe carriers (no buffer
// or goroutine of a test carrier is counted). TestG5IdleSessionCost_L52
// asserts the recorded bounds inside a synctest bubble (one virtual idle
// minute); BenchmarkIdleSessions reports the same figures in real time.

// g5IdleCase is one measured session shape with its recorded bounds per
// session pair (both ends). Measured on the Windows host (Go 1.26; this
// test, several runs with and without -race, and BenchmarkIdleSessions):
// selector 6 goroutines, 0 actor and 21–23 writer wakeups per idle minute,
// heap 87–96 KiB, stack in use 5.2 KiB (7.1 KiB under -race); 3-member
// bond 14 goroutines, 35–85 actor wakeups (every health publication of the
// Peer rings each of its dialer sessions: at most one per probe sample,
// 3 factories × 30 per minute at the default 2 s Probe.Interval) and 55–69
// writer wakeups per idle minute, heap 243–253 KiB, stack in use 13.2 KiB
// (18.2 KiB under -race).
type g5IdleCase struct {
	name      string
	mode      Mode
	factories int // net.Pipe factories of the Peer
	n         int // idle sessions measured by the test (the benchmark opens g5BenchSessions)

	goroutines    float64 // structural: actor + reader + writer per carrier, on each side
	actorWakeups  float64 // bound per idle minute
	writerWakeups float64 // bound per idle minute
	heap, stack   float64 // bounds in bytes (stack: in use, as scanned by the GC)
}

var g5IdleCases = []g5IdleCase{
	{name: "selector", mode: ModeSelector, factories: 1, n: 16,
		goroutines: 6, actorWakeups: 1, writerWakeups: 36, heap: 128 << 10, stack: 10 << 10},
	{name: "bond3", mode: ModeBond, factories: 3, n: 8,
		goroutines: 14, actorWakeups: 120, writerWakeups: 100, heap: 320 << 10, stack: 24 << 10},
}

// g5Cost is the measured idle cost of one session pair (both ends).
type g5Cost struct {
	goroutines    float64 // rendr goroutines per pair
	actorWakeups  float64 // session actor resumptions per pair per idle minute
	writerWakeups float64 // carrier writer resumptions per pair per idle minute
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

// g5Snap is one sample of the process and of both Runtimes.
type g5Snap struct {
	goroutines            int
	actor, writer         int64
	data, buffered        [2]int64 // dialer, passive
	heap, spans, stackUse uint64
}

// g5Sample collects garbage (repeatedly, so that idle stacks shrink) and
// samples e.
func g5Sample(e *e2ePair) g5Snap {
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

// g5MeasureIdle opens c's warm-up session (a multi-factory Peer's probe
// carriers run from then on) and then n idle sessions of c's shape between
// e's Runtimes, measures what the n sessions added, and ends every session.
// settle waits until nothing moves after the sleeps of settleFor. Wakeups
// are counted during an idle period (idle, scaled to one minute) with all
// n+1 sessions; writer wakeups also with the warm-up session alone, and
// the difference excludes the writers of the Peer's probe carriers. The
// block profile must be enabled already (g5Wakeups).
func g5MeasureIdle(t testing.TB, e *e2ePair, c g5IdleCase, n int, settleFor, idle time.Duration, settle func()) g5Cost {
	t.Helper()
	acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) { return pc.Confirm() })
	defer acc.stop()
	cs := make([]Carrier, c.factories)
	for i := range cs {
		cs[i] = g5PipeCarrier(string(rune('a'+i)), e.ln)
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
	dial()
	time.Sleep(settleFor)
	settle()
	warm := g5Sample(e)
	time.Sleep(idle)
	settle()
	base := g5Sample(e)
	for range n {
		dial()
	}
	time.Sleep(settleFor)
	settle()
	open := g5Sample(e)
	time.Sleep(idle)
	settle()
	end := g5Sample(e)

	per := func(a, b int64) float64 { return float64(b-a) / float64(n) }
	cost := g5Cost{
		goroutines:    per(int64(base.goroutines), int64(open.goroutines)),
		actorWakeups:  float64(end.actor-open.actor) / (float64(n+1) * idle.Minutes()),
		writerWakeups: float64((end.writer-open.writer)-(base.writer-warm.writer)) / (float64(n) * idle.Minutes()),
		opening:       per(base.actor, open.actor),
		heap:          per(int64(base.heap), int64(open.heap)),
		stackUsed:     per(int64(base.stackUse), int64(open.stackUse)),
		stackSpans:    per(int64(base.spans), int64(open.spans)),
	}
	for i := range 2 {
		cost.data += per(base.data[i], open.data[i]) / 2
		cost.stages += per(base.buffered[i]-base.data[i], open.buffered[i]-open.data[i]) / 2
	}
	if live := len(liveCarriers(dialed[len(dialed)-1].Status())); live != c.factories {
		t.Errorf("%s: the last session has %d live carriers, want %d", c.name, live, c.factories)
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

// TestG5IdleSessionCost_L52 (design §0.14 B18, R16; L52): idle sessions cost
// what was recorded, with headroom, per session pair (both ends) in a
// virtual idle minute: a single-carrier selector pair runs 6 goroutines and
// a 3-member bond pair 14 (an actor, and a reader and a writer per carrier,
// on each side); no selector actor wakes while idle, a bond's dialer actor
// at most once per health publication of its Peer; writers wake for the
// PINGs of PingIdle (10 s) and their PONGs. The MaxBufferedBytes account
// holds nothing, the stage account exactly one 16 KiB stage per carrier
// (B2), and heap and stack in use stay within the recorded bounds. Load
// proof: the counted actors woke while the sessions opened, and idle
// writers woke at least once per carrier end.
func TestG5IdleSessionCost_L52(t *testing.T) {
	for _, c := range g5IdleCases {
		t.Run(c.name, func(t *testing.T) {
			g5EnableBlockProfile(t)
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{})
				cost := g5MeasureIdle(t, e, c, c.n, 30*time.Second, time.Minute, synctest.Wait)
				t.Logf("%s, %d sessions: %.2f goroutines, %.2f actor and %.2f writer wakeups per idle minute, data %.0f B and stages %.0f B per side, heap %.1f KiB, stack in use %.1f KiB (spans %+.1f KiB) per pair",
					c.name, c.n, cost.goroutines, cost.actorWakeups, cost.writerWakeups, cost.data, cost.stages,
					cost.heap/1024, cost.stackUsed/1024, cost.stackSpans/1024)
				if cost.opening < 1 || cost.writerWakeups < float64(2*c.factories) {
					t.Errorf("load: %.2f actor resumptions per pair while opening, %.2f writer wakeups per pair per idle minute: the wakeup counter sees nothing",
						cost.opening, cost.writerWakeups)
				}
				if cost.goroutines != c.goroutines {
					t.Errorf("%.2f goroutines per pair, want %v", cost.goroutines, c.goroutines)
				}
				if cost.actorWakeups > c.actorWakeups || cost.writerWakeups > c.writerWakeups {
					t.Errorf("%.2f actor and %.2f writer wakeups per pair per idle minute, want at most %v and %v",
						cost.actorWakeups, cost.writerWakeups, c.actorWakeups, c.writerWakeups)
				}
				if want := float64(c.factories * g5StageBytes); cost.data != 0 || cost.stages != want {
					t.Errorf("per side: %.0f bytes in the MaxBufferedBytes account and %.0f in the stage account, want 0 and %.0f",
						cost.data, cost.stages, want)
				}
				if cost.heap > c.heap || cost.stackUsed > c.stack {
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
// cost of a single-carrier selector session and of a 3-member bond
// session, per session pair (both ends) unless the unit says per side:
// goroutines, session actor and carrier writer wakeups per idle minute
// (counted over one real PingIdle period), the MaxBufferedBytes and reader
// stage accounts, live heap, stack in use and the growth of the stack
// spans (allocation granularity: platform dependent and noisy). It runs in
// real time (no synctest bubble in benchmarks): about 22 s per case.
func BenchmarkIdleSessions(b *testing.B) {
	for _, c := range g5IdleCases {
		b.Run(c.name, func(b *testing.B) {
			g5EnableBlockProfile(b)
			var cost g5Cost
			for b.Loop() {
				e := e2eNew(b, Config{}, Config{}, nil, ListenConfig{})
				cost = g5MeasureIdle(b, e, c, g5BenchSessions, g5BenchSettle, g5BenchIdle, func() {})
				e.close()
			}
			b.ReportMetric(0, "ns/op")
			b.ReportMetric(cost.goroutines, "goroutines/pair")
			b.ReportMetric(cost.actorWakeups, "actor-wakeups/pair-min")
			b.ReportMetric(cost.writerWakeups, "writer-wakeups/pair-min")
			b.ReportMetric(cost.data, "data-B/side")
			b.ReportMetric(cost.stages, "stage-B/side")
			b.ReportMetric(cost.heap, "heap-B/pair")
			b.ReportMetric(cost.stackUsed, "stack-used-B/pair")
			b.ReportMetric(cost.stackSpans, "stack-spans-B/pair")
		})
	}
}
