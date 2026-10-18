package l4

import (
	"context"
	"io"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestForwardZeroAllocs_L41_L54 (§A12.6, M4-D36): forwarding costs no
// allocation per chunk. A Forward pair — the ingress on the dialer Conn,
// the egress on the passive Conn, each over an in-memory TargetPipe — runs
// over a warmed carrier/tcp loopback session (rendr-owned TCP: the
// session's own steady state allocates nothing, as the root package's
// TestSteadyStateZeroAllocs_L41_L54 proves); at least 1,000 round trips of
// 32 KiB each way (at least 4,000 chunks through the four pumps) and 50
// PING intervals cost at most 40 allocations in total, counted raw
// (runtime.MemStats.Mallocs, every goroutine, GC off, one P), so a buffer
// allocated per Read or per Write (one per chunk) exceeds the bound.
// Asserted in the non-race lane; the race lane logs the figure.
func TestForwardZeroAllocs_L41_L54(t *testing.T) {
	cfg := rendr.Config{PingBusy: 10 * time.Millisecond}
	d, err := rendr.NewRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, err := rendr.NewRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	l, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}})
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{tcp.Carrier("direct", "tcp", l.Addr().String(), tcp.Options{})}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accepted := make(chan *rendr.Conn, 1)
	go func() {
		pend, err := ln.Accept(ctx)
		if err != nil {
			accepted <- nil
			return
		}
		c, _ := pend.Confirm()
		accepted <- c
	}()
	dc, err := Dial(ctx, peer, kitTarget, rendr.DialOptions{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	pc := <-accepted
	if pc == nil {
		t.Fatal("Accept/Confirm failed")
	}

	cli, srv := rendrtest.TargetPipe(64 << 10)   // the client's socket
	tcli, tsrv := rendrtest.TargetPipe(64 << 10) // the target's socket
	fctx, fcancel := context.WithCancel(context.Background())
	in := forwardAsync(fctx, dc, srv)
	out := forwardAsync(fctx, pc, tcli)

	const chunk = 32 << 10
	up, down := make([]byte, chunk), make([]byte, chunk)
	if _, err := io.ReadFull(rendrtest.PRNG(54), up); err != nil {
		t.Fatal(err)
	}
	copy(down, up)
	rbuf := make([]byte, chunk)
	round := func() {
		if _, err := cli.Write(up); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		if _, err := io.ReadFull(tsrv, rbuf); err != nil {
			t.Fatalf("target Read: %v", err)
		}
		if _, err := tsrv.Write(down); err != nil {
			t.Fatalf("target Write: %v", err)
		}
		if _, err := io.ReadFull(cli, rbuf); err != nil {
			t.Fatalf("client Read: %v", err)
		}
	}
	const warm, maxAllocs = 256, 40
	for range warm {
		round()
	}
	minRounds, minWindow := 1000, 50*cfg.PingBusy
	if raceEnabled {
		minRounds, minWindow = warm, 0
	}
	mallocs, rounds, el := countMallocs(minRounds, minWindow, round)
	if string(rbuf) != string(down) {
		t.Fatal("the last round delivered other bytes")
	}
	t.Logf("%d allocations in %d round trips of %d bytes each way (%v)", mallocs, rounds, chunk, el)
	if rounds < minRounds || el < minWindow {
		t.Fatalf("load: %d rounds in %v", rounds, el)
	}
	if raceEnabled {
		t.Log("race lane: not asserted")
	} else if mallocs > maxAllocs {
		t.Fatalf("%d allocations in %d steady-state round trips (%d chunks) over %v, want at most %d", mallocs, rounds, 4*rounds, el, maxAllocs)
	}

	// A clean end: the client FINs, the target answers with its FIN.
	cli.CloseWrite()
	if _, err := io.ReadFull(tsrv, rbuf[:1]); err != io.EOF {
		t.Fatalf("target: %v, want the client's FIN", err)
	}
	tsrv.CloseWrite()
	if _, err := io.ReadFull(cli, rbuf[:1]); err != io.EOF {
		t.Fatalf("client: %v, want the target's FIN", err)
	}
	want := int64(warm+settleRuns(minRounds)+rounds) * chunk
	checkClean(t, "ingress", <-in, want, want)
	checkClean(t, "egress", <-out, want, want)
	fcancel()
	for _, c := range []*rendr.Conn{dc, pc} {
		select {
		case <-c.Done():
		case <-time.After(30 * time.Second):
			t.Fatalf("session not done: %+v", c.Status())
		}
	}
}

// countMallocs runs f at least n times and for at least window, with the
// garbage collector off and one P (as testing.AllocsPerRun), and returns
// the raw number of heap allocations of every goroutine during the window,
// the runs and the window's duration. Like testing.AllocsPerRun it first
// runs f at one P outside the window (settleRuns(n) times): the switch to
// one P drops every sync.Pool's per-P cache, and the pools' refill is no
// steady-state allocation (M6 I1: on Linux workers it put 20–42 of them
// into the window of TestPortForwardZeroAllocs_L54, bound 40).
func countMallocs(n int, window time.Duration, f func()) (mallocs uint64, runs int, el time.Duration) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	for range settleRuns(n) {
		f()
	}
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	for runs < n || time.Since(start) < window {
		f()
		runs++
	}
	el = time.Since(start)
	runtime.ReadMemStats(&m1)
	return m1.Mallocs - m0.Mallocs, runs, el
}

// settleRuns is how many times countMallocs(n, …) runs f before its
// window; the callers' byte and datagram accounting adds them.
func settleRuns(n int) int { return max(n/100, 16) }
