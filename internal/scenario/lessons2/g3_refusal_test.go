package lessons2

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPersistentRefusalBacksOff_L20 (L20; design §0.14 B6): a bond Peer with
// two factories dials a passive whose MaxCarriersPerSession is 1. The
// session opens on a, and the member slot of b is refused with JOIN_ACK
// CAPACITY for as long as a lives. b never dialled before the bond kicked
// its slot when the session opened, so that kick opens no recovery window
// (sched.Cadence). Its JOIN dials must follow the redial cadence of plan
// §3.6 as amended — the first refusal resets n, every later one counts as a
// failure — so the k-th interval (k from 0) lies within
// [min(0.5 s·2ᵏ, cap) × 0.8, min(0.5 s·2ᵏ, cap) × 1.2] and the count in 60
// virtual seconds stays within what those bounds allow (with the cap of 4 s:
// 15 to 21; the old cadence redialled every ≈ 0.5 s, about 120 times). In
// the second case every other JOIN dial of b fails in the factory, so
// refusals and failures alternate; the cadence must grow just the same (a
// cadence that resets n at every refusal that follows a failure redials
// about 85 times). Meanwhile the session keeps delivering on a: one
// integrity-checked exchange in both directions every 5 s, all DATA on a,
// none on b, no death, no rejoin, no no-path episode.
func TestPersistentRefusalBacksOff_L20(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failEven bool // every second JOIN dial of b fails in its factory
	}{
		{"every JOIN refused with CAPACITY", false},
		{"refusals between failed dials", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { g3PersistentRefusal(t, tc.failEven) })
		})
	}
}

// g3Starts counts the attempt starts within window of the first one when
// the k-th interval (k from 0) is gap(k).
func g3Starts(window time.Duration, gap func(k int) time.Duration) int {
	n, at := 1, time.Duration(0)
	for k := 0; ; k++ {
		at += gap(k)
		if at > window {
			return n
		}
		n++
	}
}

func g3PersistentRefusal(t *testing.T, failEven bool) {
	const (
		window     = time.Minute      // observed from b's first JOIN dial
		grace      = 15 * time.Second // NoPathGrace (the default, set explicitly)
		backoffMax = 4 * time.Second  // RejoinBackoffMax (the default, set explicitly)
		// timerSlack: the session actor arms no timer shorter than 1 ms, so
		// an attempt may start up to 1 ms after its cadence allows it.
		timerSlack = time.Millisecond
		round      = 5 * time.Second // one exchange per round
		chunk      = 64 << 10        // bytes per direction and round
	)
	// A session slot's cap: min(RejoinBackoffMax, NoPathGrace/2) (plan §3.6).
	cap := min(backoffMax, grace/2)
	// The dialer runs with the default configuration and the real jitter
	// source: the bounds below hold for every draw.
	e := newEnv(t, rendr.Config{NoPathGrace: grace, RejoinBackoffMax: backoffMax},
		rendr.Config{MaxCarriersPerSession: 1}, nil)
	for _, rt := range []*rendr.Runtime{e.d, e.p} {
		if adj := rt.Status().ConfigAdjustments; len(adj) != 0 {
			t.Fatalf("configuration adjusted: %v", adj)
		}
	}
	a := e.path("a", 5*time.Millisecond) // the faster path: ranked first, the session opens on it
	b := e.path("b", 10*time.Millisecond)
	b.early = true // its factory sees the first frame: JOIN dials are told apart from probe dials
	var joins atomic.Int64
	if failEven {
		b.gate = func(_ context.Context, _ int64, first []byte) error {
			if len(first) > wire.PrefaceLen && wire.Type(first[wire.PrefaceLen]) == wire.TypeJoin && joins.Add(1)%2 == 0 {
				return errRefused
			}
			return nil
		}
	}
	start := time.Now()
	dc, pc := e.open(e.peer(a, b), rendr.DialOptions{Mode: rendr.ModeBond})
	waitFor(t, 5*time.Second, time.Millisecond, "b's first JOIN dial", func() bool {
		return len(b.callsSince(start, wire.TypeJoin)) > 0
	})
	if opens := b.callsSince(start, wire.TypeOpen); len(opens) != 0 {
		t.Fatalf("stimulus: the session did not open on a alone (OPEN dials of b: %+v)", opens)
	}
	t0 := b.callsSince(start, wire.TypeJoin)[0].at
	end := t0.Add(window)

	// The session keeps delivering on a while b is refused.
	rounds := 0
	for time.Now().Before(end) {
		exchange(t, dc, pc, chunk, uint64(600+2*rounds))
		rounds++
		time.Sleep(min(round, time.Until(end)))
	}
	synctest.Wait() // a JOIN dial due at the end of the window has been made
	var calls []dialCall
	for _, c := range b.callsSince(t0, wire.TypeJoin) {
		if !c.at.After(end) {
			calls = append(calls, c)
		}
	}

	// The cadence: every interval within its jitter bounds, so the count
	// within the window is bounded as well.
	gaps := make([]time.Duration, 0, len(calls))
	for k := 1; k < len(calls); k++ {
		gaps = append(gaps, calls[k].at.Sub(calls[k-1].at))
	}
	maxN := g3Starts(window, func(k int) time.Duration { return sched.Backoff(k, cap, 0) })
	minN := g3Starts(window, func(k int) time.Duration { return sched.Backoff(k, cap, 1) + timerSlack })
	t.Logf("%d JOIN dials of b in %v (bounds %d–%d), intervals %v", len(calls), window, minN, maxN, gaps)
	for k, gap := range gaps {
		if lo, hi := sched.Backoff(k, cap, 0), sched.Backoff(k, cap, 1)+timerSlack; gap < lo || gap > hi {
			t.Fatalf("JOIN dial %d of b started %v after the previous one, want within [%v, %v] (failure number %d, cap %v)",
				k+2, gap, lo, hi, k, cap)
		}
	}
	if len(calls) > maxN || len(calls) < minN {
		t.Fatalf("%d JOIN dials of b in %v, want %d–%d", len(calls), window, minN, maxN)
	}

	// Stimulus: every JOIN of the window that reached the passive was
	// refused with JOIN_ACK CAPACITY (the others failed in the factory).
	reached := len(calls)
	if failEven {
		reached = (len(calls) + 1) / 2 // dials 1, 3, 5, …
	}
	time.Sleep(3 * 20 * time.Millisecond) // three round trips of b: the last JOIN of the window was answered
	sc := b.sessionConns(true)
	if len(sc) < reached {
		t.Fatalf("stimulus: %d JOIN carriers of b, want at least the %d dials of the window that reached the passive", len(sc), reached)
	}
	for i, c := range sc[:reached] {
		if f, ok := c.in.first(); !ok || f.typ != wire.TypeJoinAck || wire.AckStatus(f.b0) != wire.StatusCapacity {
			t.Fatalf("stimulus: JOIN carrier %d of b got %+v (ok %v), want JOIN_ACK CAPACITY", i+1, f, ok)
		}
	}

	// Load and integrity: every exchange arrived intact, all of it on a.
	ds, ps := dc.Status(), pc.Status()
	want := uint64(rounds * chunk)
	if rounds < int(window/round) || ds.DeliveredBytes != want || ps.DeliveredBytes != want || ds.TxBytes != want || ps.TxBytes != want {
		t.Fatalf("load: %d rounds; dialer delivered %d sent %d, passive delivered %d sent %d; want %d each",
			rounds, ds.DeliveredBytes, ds.TxBytes, ps.DeliveredBytes, ps.TxBytes, want)
	}
	if n := len(b.sent(wire.TypeData)) + len(b.sentBack(wire.TypeData)); n != 0 {
		t.Fatalf("%d DATA frames crossed b", n)
	}
	if up, down := dataBytes(a.received(wire.TypeData)), dataBytes(a.sentBack(wire.TypeData)); up < int64(want) || down < int64(want) {
		t.Fatalf("DATA on a: %d up, %d down; want at least %d each", up, down, want)
	}
	la := liveOf(ds, "a")
	if ds.State != rendr.StateOpen || len(la) != 1 || la[0].Gen != 1 || len(liveOf(ds, "b")) != 0 ||
		ds.Rejoins != 0 || ds.NoPathEpisodes != 0 || len(ps.Carriers) != 1 || ps.Carriers[0].ID != la[0].ID ||
		ps.NoPathEpisodes != 0 {
		t.Fatalf("after %v of refusals: dialer %+v, passive %+v", window, ds, ps)
	}
	endClean(t, dc, pc)
	e.close()
}
