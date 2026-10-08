package packet

import (
	"context"
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The real-socket part of the package (M2 design §A8.5, §A8.6): two
// Runtimes joined by carrier/udp on loopback — one rendr-owned listening
// socket on the passive through FromPacketConn, a single-factory Peer on
// the dialer (no probe carriers) — outside synctest bubbles, on Linux and
// Windows alike. Every test closes both Runtimes and checks for leaks with
// rendrtest.AssertNoLeak (never with t.Parallel).

// udpPair is one packet session over carrier/udp on loopback.
type udpPair struct {
	d, p   *rendr.Runtime
	dc, pc *rendr.PacketConn
}

// newUDPPair builds the Runtimes (ov goes to both), the listening socket
// and the Peer, and opens one confirmed packet session.
func newUDPPair(tb testing.TB, ov testhooks.Overrides) *udpPair {
	tb.Helper()
	dov, pov := ov, ov
	u := &udpPair{d: newRuntime(tb, rendr.Config{}, &dov), p: newRuntime(tb, rendr.Config{}, &pov)}
	tb.Cleanup(func() { u.d.Close(); u.p.Close() })
	sock, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		tb.Fatalf("udp.Listen: %v", err)
	}
	ln, err := u.p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}})
	if err != nil {
		sock.Close()
		tb.Fatalf("Listen: %v", err)
	}
	peer, err := u.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{udp.Carrier("udp", "udp4", sock.LocalAddr().String(), udp.Options{})}})
	if err != nil {
		tb.Fatalf("NewPeer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type dialed struct {
		c   *rendr.PacketConn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := peer.DialPacket(ctx, rendr.DialOptions{})
		ch <- dialed{c, err}
	}()
	pp, err := ln.AcceptPacket(ctx)
	if err != nil {
		tb.Fatalf("AcceptPacket: %v", err)
	}
	if u.pc, err = pp.Confirm(); err != nil {
		tb.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		tb.Fatalf("DialPacket: %v", r.err)
	}
	u.dc = r.c
	return u
}

// close ends the session from both sides, closes both Runtimes (the
// passive's closes its listening socket) and requires that nothing is
// left: no session, no buffered byte, nothing abandoned.
func (u *udpPair) close(tb testing.TB) {
	tb.Helper()
	u.dc.Close()
	u.pc.Close()
	for _, c := range []*rendr.PacketConn{u.dc, u.pc} {
		select {
		case <-c.Done():
		case <-time.After(30 * time.Second):
			tb.Fatalf("a session did not end within 30 s: %+v", c.Status())
		}
	}
	u.d.Close()
	u.p.Close()
	for _, rt := range []*rendr.Runtime{u.d, u.p} {
		if st := rt.Status(); sessionsOf(rt) != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 {
			tb.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
}

// pump moves n 1000-byte test datagrams from w to r as fast as WriteTo
// accepts them, keeping at most window of them ahead of the highest seq r
// read (a closed loop: the queues never overflow on a healthy path; a
// writer waiting longer than a second goes on, so losses cannot stall it).
// It returns how many distinct datagrams r read and the time it took; a
// damaged datagram or an error other than r's read deadline fails tb. It
// is BenchmarkPacketLoopback's driver; the allocation gate's warm-up runs
// it too.
func pump(tb testing.TB, w, r *rendr.PacketConn, seed uint64, n, window int) (got int, el time.Duration) {
	tb.Helper()
	var high atomic.Int64 // highest seq read + 1
	var stop atomic.Bool  // the reader gave up
	werr := make(chan error, 1)
	start := time.Now()
	go func() {
		buf := make([]byte, 1000)
		for i := range n {
			for t0 := time.Now(); int64(i)-high.Load() >= int64(window) && time.Since(t0) < time.Second; {
				runtime.Gosched()
			}
			if stop.Load() {
				break
			}
			if _, err := w.WriteTo(rendrtest.PacketPayload(buf, seed, uint64(i), len(buf), time.Now()), nil); err != nil {
				werr <- err
				return
			}
		}
		werr <- nil
	}()
	v := rendrtest.NewPacketVerifier(seed)
	buf := make([]byte, r.MaxPayload()+1)
	seen := make([]bool, n)
	for got < n {
		if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			tb.Fatal(err)
		}
		m, _, err := r.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			stop.Store(true)
			break // the writer finished (or stalled for good): the rest is lost
		}
		if err != nil {
			tb.Fatalf("pump: ReadFrom: %v", err)
		}
		if err := v.Add(buf[:m], time.Now()); err != nil {
			tb.Fatalf("pump: %v", err)
		}
		s := seqOf(buf)
		if s >= uint64(n) || seen[s] {
			tb.Fatalf("pump: seq %d read again or beyond the %d written", s, n)
		}
		seen[s] = true
		got++
		if int64(s)+1 > high.Load() {
			high.Store(int64(s) + 1)
		}
	}
	el = time.Since(start)
	if err := <-werr; err != nil {
		tb.Fatalf("pump: WriteTo: %v", err)
	}
	if err := r.SetReadDeadline(time.Time{}); err != nil {
		tb.Fatal(err)
	}
	return got, el
}

// TestPacketSteadyStateZeroAllocs_L41_L54 (M2 design §A8.5; M1's Y4 for
// packets): the steady state of a packet session costs no allocation end
// to end. Over a warmed carrier/udp loopback pair driven only through the
// public API, at least 4,000 rounds — a 1000-byte WriteTo on the dialer,
// its ReadFrom on the passive, the passive's WriteTo of it back and the
// dialer's ReadFrom: the queues, Fill, the datagram writer and reader, the
// shared socket's demultiplexer, the dedup window, and the PING, PONG, MTU
// probe and PACK traffic on the carrier — cost at most 40 allocations in
// total. The window is counted raw (runtime.MemStats.Mallocs, every
// goroutine), not per run (an allocation per PING or PACK would pass
// AllocsPerRun's integer division unseen); GC is off during it and one P
// runs; PacketPing is 10 ms (a testhooks override) and the window lasts
// at least 50 of them, so an allocation per PING, per PONG or per MTU probe
// alone exceeds the bound; the control frames written by both ends prove
// that the PING cadence ran in the window. Asserted in the non-race lane;
// the race lane runs a short window and logs the figure.
func TestPacketSteadyStateZeroAllocs_L41_L54(t *testing.T) {
	check := rendrtest.AssertNoLeak(t)
	ov := testhooks.Overrides{PacketPing: 10 * time.Millisecond}
	u := newUDPPair(t, ov)
	dc, pc := u.dc, u.pc

	// Warm-up: the benchmark's driver both ways (pools, rings, windows),
	// then plain rounds.
	for i, c := range [][2]*rendr.PacketConn{{dc, pc}, {pc, dc}} {
		if got, _ := pump(t, c[0], c[1], uint64(10+i), 512, 64); got < 500 {
			t.Fatalf("warm-up pump %d: %d of 512 datagrams arrived on loopback", i, got)
		}
	}
	for _, c := range []*rendr.PacketConn{dc, pc} {
		if err := c.SetReadDeadline(time.Now().Add(time.Minute)); err != nil { // one timer, set outside the window
			t.Fatal(err)
		}
	}
	wbuf := rendrtest.PacketPayload(make([]byte, 1000), 41, 0, 1000, time.Now())
	rbuf := make([]byte, 2048)
	round := func() {
		if n, err := dc.WriteTo(wbuf, nil); n != len(wbuf) || err != nil {
			t.Fatalf("dialer WriteTo = %d, %v", n, err)
		}
		n, _, err := pc.ReadFrom(rbuf)
		if n != len(wbuf) || err != nil {
			t.Fatalf("passive ReadFrom = %d, %v (a datagram lost on loopback?)", n, err)
		}
		if n, err := pc.WriteTo(rbuf[:n], nil); n != len(wbuf) || err != nil {
			t.Fatalf("passive WriteTo = %d, %v", n, err)
		}
		if n, _, err := dc.ReadFrom(rbuf); n != len(wbuf) || err != nil {
			t.Fatalf("dialer ReadFrom = %d, %v (a datagram lost on loopback?)", n, err)
		}
	}
	const warm, maxAllocs = 256, 40
	for range warm {
		round()
	}
	minRounds, minWindow := 100*maxAllocs, 50*ov.PacketPing
	if raceEnabled {
		minRounds, minWindow = warm, 0 // the race lane only logs the figure
	}
	c0, q0 := dc.Status().Carriers[0], pc.Status().Carriers[0]
	mallocs, rounds, el := countMallocs(minRounds, minWindow, round)
	c1, q1 := dc.Status().Carriers[0], pc.Status().Carriers[0]
	if string(rbuf[:len(wbuf)]) != string(wbuf) {
		t.Fatal("the last round delivered other bytes")
	}
	ds, ps := dc.Status(), pc.Status()
	if rounds < minRounds || el < minWindow || len(ds.Carriers) != 1 || c1.ID != c0.ID || c1.State != rendr.CarrierActive ||
		len(ps.Carriers) != 1 || q1.ID != q0.ID || q1.State != rendr.CarrierActive ||
		drops(ds.Packet)+drops(ps.Packet) != 0 || ds.Packet.Received < uint64(rounds) || ps.Packet.Received < uint64(rounds) {
		t.Fatalf("load: %d rounds in %v; dialer %+v %+v; passive %+v", rounds, el, ds, *ds.Packet, *ps.Packet)
	}
	// Stimulus: the PING cadence ran in the window. Besides one DGRAM per
	// round, each carrier wrote its PACKs, its PINGs (MTU probes included)
	// and its PONGs to the peer's PINGs. PACKs alone are at most one per
	// PackEvery datagrams plus one per PacketPing (the delay timer) and one
	// of each at the edges, so with T = window/PacketPing both ends without
	// the PING cadence write at most 2·rounds/PackEvery + 2·T + 4 control
	// frames, and with it about 2·T more (a PING and a PONG per end per
	// PacketPing). The bound sits halfway: an allocation per PING, PONG or
	// MTU probe cannot pass for want of PINGs in the window.
	const packEvery = 256 // the default PackEvery (§A5.5)
	ticks := uint64(el / ov.PacketPing)
	ctlD := c1.Frames - c0.Frames - uint64(rounds)
	ctlP := q1.Frames - q0.Frames - uint64(rounds)
	want := 2*uint64(rounds)/packEvery + 3*ticks + 4
	t.Logf("%d allocations in %d round trips of 1000 bytes (%v); control frames: dialer %d, passive %d (stimulus bound %d); dialer retransmissions %d",
		mallocs, rounds, el, ctlD, ctlP, want, c1.Retransmits-c0.Retransmits)
	if !raceEnabled && ctlD+ctlP < want {
		t.Fatalf("stimulus: %d control frames (dialer %d, passive %d) in a %v window, want ≥ %d: the PING cadence did not run", ctlD+ctlP, ctlD, ctlP, el, want)
	}
	if raceEnabled {
		t.Logf("race lane: not asserted")
	} else if mallocs > maxAllocs {
		t.Fatalf("%d allocations in %d steady-state round trips over %v, want at most %d", mallocs, rounds, el, maxAllocs)
	}
	u.close(t)
	check()
}

// countMallocs runs f at least n times and for at least window, with the
// garbage collector off and one P (as testing.AllocsPerRun), and returns
// the raw number of heap allocations of every goroutine during the window,
// the runs and the window's duration. A GC runs first, so that no pool is
// moved to its victim cache during the window.
func countMallocs(n int, window time.Duration, f func()) (mallocs uint64, runs int, el time.Duration) {
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	for range 16 { // refill what the GC took from the pools
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

// BenchmarkPacketLoopback (M2 design §A8.5): the packet rate of one
// session over carrier/udp on loopback, 1000-byte datagrams, each
// direction (up: dialer → passive), with at most 256 datagrams in flight
// (pump). It reports the delivered datagrams per second and the share
// lost. Recorded on the Linux performance lane only, never on the
// Windows host (B1.6's perf/pps-ceiling is the M2 exit figure).
func BenchmarkPacketLoopback(b *testing.B) {
	for _, dir := range []string{"up", "down"} {
		b.Run(dir, func(b *testing.B) {
			u := newUDPPair(b, testhooks.Overrides{})
			w, r := u.dc, u.pc
			if dir == "down" {
				w, r = u.pc, u.dc
			}
			pump(b, w, r, 1, 1024, 256)
			b.SetBytes(1000)
			b.ReportAllocs()
			b.ResetTimer()
			got, el := pump(b, w, r, 2, b.N, 256)
			b.StopTimer()
			b.ReportMetric(float64(got)/el.Seconds(), "datagrams/s")
			b.ReportMetric(100*float64(b.N-got)/float64(b.N), "lost%")
			u.close(b)
		})
	}
}
