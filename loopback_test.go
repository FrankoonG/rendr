package rendr_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The real-loopback group (design §11.1, R19): two Runtimes joined by the
// built-in TCP carrier over 127.0.0.1, outside synctest bubbles, on Linux
// and Windows alike. Between them a relay forwards every connection byte
// for byte; it can reset all the connections it carries (SO_LINGER 0, so
// each rendr end sees a TCP RST), and it reports every connection that
// ended in an error other than its own reset — a TCP RST sent by a rendr
// end (ECONNRESET on Linux, WSAECONNRESET on Windows) included. Every test
// of the group is a leak oracle (L52, L66; design §0.14 B11): it takes
// rendrtest.AssertNoLeak's baseline first and runs its check once both
// Runtimes, their listeners and the relay are closed, so a goroutine (or,
// on Linux, an fd) that a carrier, a session or a Runtime left behind
// fails the test.

// relay is a TCP forwarder between a dialer and a passive listener.
type relay struct {
	t      testing.TB
	ln     net.Listener
	target string
	mu     sync.Mutex
	pairs  map[*relayPair]struct{}
	closed bool
	wg     sync.WaitGroup
	conns  atomic.Int64 // connections forwarded
	resets atomic.Int64 // connections the relay reset
	errs   atomic.Int64 // connections that ended in an error the relay did not cause
	lastEr atomic.Value // the last such error (error)
}

type relayPair struct {
	a, b  *net.TCPConn // dialer side, passive side
	reset atomic.Bool
}

func newRelay(t testing.TB, target string) *relay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{t: t, ln: ln, target: target, pairs: make(map[*relayPair]struct{})}
	r.wg.Go(r.acceptLoop)
	t.Cleanup(r.close)
	return r
}

// addr is the address the dialer's factory connects to.
func (r *relay) addr() string { return r.ln.Addr().String() }

func (r *relay) acceptLoop() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		b, err := net.Dial("tcp", r.target)
		if err != nil {
			c.Close()
			continue
		}
		p := &relayPair{a: c.(*net.TCPConn), b: b.(*net.TCPConn)}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			p.a.Close()
			p.b.Close()
			return
		}
		r.pairs[p] = struct{}{}
		r.mu.Unlock()
		r.conns.Add(1)
		r.wg.Go(func() { r.serve(p) })
	}
}

// serve pumps both directions; an EOF is passed on as a half-close, so
// that the relay itself never closes a socket with unread data. Once both
// directions ended in a FIN, a TCP RST that a rendr end sends afterwards —
// closing its socket with unread bytes, or before it read the relay's
// FIN — arrives on a socket nobody reads any more: after rstWait each
// socket is read once more (past its FIN a read returns at once), and any
// error other than EOF or a timeout counts. Then the sockets are closed.
func (r *relay) serve(p *relayPair) {
	var wg sync.WaitGroup
	var failed atomic.Bool
	fail := func(err error) {
		failed.Store(true)
		r.lastEr.Store(err)
	}
	pump := func(dst, src *net.TCPConn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil && !p.reset.Load() {
			fail(err)
			// Pass the failure on: the other end must not wait forever.
			dst.SetLinger(0)
			dst.Close()
			src.Close()
			return
		}
		if err := dst.CloseWrite(); err != nil && !p.reset.Load() {
			fail(err)
		}
	}
	wg.Add(2)
	go pump(p.b, p.a)
	go pump(p.a, p.b)
	wg.Wait()
	if !failed.Load() && !p.reset.Load() {
		time.Sleep(rstWait)
		for _, c := range []*net.TCPConn{p.a, p.b} {
			c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			var b [1]byte
			if _, err := c.Read(b[:]); err != io.EOF && !p.reset.Load() && !isTimeout(err) {
				fail(fmt.Errorf("after both FINs: %v", err))
			}
		}
	}
	if failed.Load() {
		r.errs.Add(1)
	}
	p.a.Close()
	p.b.Close()
	r.mu.Lock()
	delete(r.pairs, p)
	r.mu.Unlock()
}

// rstWait is how long the relay keeps a connection open after both FINs
// to catch a late TCP RST from a rendr end (loopback delivers it at once).
const rstWait = 25 * time.Millisecond

// isTimeout reports a deadline expiry.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// reset aborts every connection the relay carries: SO_LINGER 0 and Close
// on both sockets, so the dialer's and the passive's carrier each get a
// TCP RST. It returns how many connections it reset.
func (r *relay) reset() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for p := range r.pairs {
		if p.reset.CompareAndSwap(false, true) {
			for _, c := range []*net.TCPConn{p.a, p.b} {
				c.SetLinger(0)
				c.Close()
			}
			n++
			r.resets.Add(1)
		}
	}
	return n
}

// idle waits until every connection the relay forwarded has ended.
func (r *relay) idle(within time.Duration) {
	r.t.Helper()
	deadline := time.Now().Add(within)
	for {
		r.mu.Lock()
		n := len(r.pairs)
		r.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("%d relayed connections still open after %v", n, within)
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *relay) close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.ln.Close()
	r.reset()
	r.wg.Wait()
}

// loopPair is a dialer and a passive Runtime joined through a relay.
type loopPair struct {
	d, p  *rendr.Runtime
	ln    *rendr.Listener
	peer  *rendr.Peer
	relay *relay
}

func newLoopPair(t testing.TB, cfg rendr.Config) *loopPair {
	t.Helper()
	d, err := rendr.NewRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p, err := rendr.NewRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	l, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}})
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	r := newRelay(t, l.Addr().String())
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{tcp.Carrier("relay", "tcp", r.addr(), tcp.Options{})}})
	if err != nil {
		t.Fatal(err)
	}
	return &loopPair{d: d, p: p, ln: ln, peer: peer, relay: r}
}

// open dials one session and confirms it.
func (lp *loopPair) open(t testing.TB) (dc, pc *rendr.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type res struct {
		c   *rendr.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := lp.peer.Dial(ctx, rendr.DialOptions{})
		ch <- res{c, err}
	}()
	p, err := lp.ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	pc, err = p.Confirm()
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("Dial: %v", r.err)
	}
	return r.c, pc
}

// close closes both Runtimes (each closes its Listeners and their
// net.Listeners) and the relay, joining its goroutines, and requires that
// nothing is left: no session, no buffered byte (R7), nothing abandoned.
// The test's leak check runs after it (design §0.14 B11).
func (lp *loopPair) close(t testing.TB) {
	t.Helper()
	lp.d.Close()
	lp.p.Close()
	if lp.relay != nil {
		lp.relay.close()
	}
	for _, rt := range []*rendr.Runtime{lp.d, lp.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 || st.Handshakes != 0 {
			t.Fatalf("Runtime %v after Close: %+v", rt.InstanceID(), st)
		}
	}
}

// waitEnded polls (real time) until c's session ended.
func waitEnded(t testing.TB, c *rendr.Conn, within time.Duration) rendr.SessionStatus {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		st := c.Status()
		if st.State == rendr.StateEnded {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %v not ended after %v: %+v", c.ID(), within, st)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestLoopbackRSTNeverEOF_L02: on real TCP carriers a reset never looks
// like an end of stream (L02, R19; Linux and Windows): the passive sends
// 16 MiB and its FIN while the relay resets the session's TCP connection
// (SO_LINGER 0: both rendr ends see a TCP RST) four times — the last time
// with the passive's data and FIN already written. The dialer's Read
// returns every byte intact and io.EOF exactly at the end, never an error
// or an early EOF; each reset is one death migration and one redial
// (stimulus proof: four resets, four deaths, five carriers).
func TestLoopbackRSTNeverEOF_L02(t *testing.T) {
	check := rendrtest.AssertNoLeak(t)
	lp := newLoopPair(t, rendr.Config{})
	dc, pc := lp.open(t)
	const total = 16 << 20
	sent := make(chan error, 1)
	go func() {
		_, err := io.Copy(onlyWriter{pc}, io.LimitReader(rendrtest.PRNG(2), total))
		if err == nil {
			err = pc.CloseWrite()
		}
		sent <- err
	}()
	marks := []int64{2 << 20, 6 << 20, 11 << 20, 15 << 20}
	v := rendrtest.NewVerifier(2, total)
	buf := make([]byte, 64<<10)
	var got int64
	for {
		if len(marks) > 0 && got >= marks[0] {
			if n := lp.relay.reset(); n < 1 {
				t.Fatalf("reset no connection at %d bytes", got)
			}
			marks = marks[1:]
		}
		n, err := dc.Read(buf)
		if n > 0 {
			v.Write(buf[:n])
			got += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read after %d bytes: %v (resets %d)", got, err, lp.relay.resets.Load())
		}
	}
	if err := v.Done(io.EOF); err != nil {
		t.Fatalf("after %d bytes: %v", got, err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("passive send: %v", err)
	}
	st := dc.Status()
	if lp.relay.resets.Load() < 4 || st.Migrations.Death < 4 || st.NoPathEpisodes < 4 || lp.relay.conns.Load() < 5 {
		t.Fatalf("stimulus: %d resets, %d relayed connections, dialer %+v", lp.relay.resets.Load(), lp.relay.conns.Load(), st)
	}
	t.Logf("16 MiB with 4 resets: dialer migrations %+v, %d episodes, %d carriers", st.Migrations, st.NoPathEpisodes, lp.relay.conns.Load())
	dc.Close()
	pc.Close()
	waitEnded(t, dc, 30*time.Second)
	waitEnded(t, pc, 30*time.Second)
	lp.close(t)
	check()
}

// TestLoopbackCloseWithUnreadNoReset_L05: closing never resets a TCP
// carrier that still holds unread bytes (L05 teardown order, R19; Linux
// and Windows). 200 times: the dialer writes 1 MiB and Closes at once,
// while the passive application has not read any of it; then the passive
// reads exactly the 1 MiB and EOF and closes. Every session ends cleanly
// (io.EOF) on both ends without a carrier death, migration or redial, and
// the relay sees every connection end in a FIN on both sides — no TCP RST
// (ECONNRESET) at all.
func TestLoopbackCloseWithUnreadNoReset_L05(t *testing.T) {
	check := rendrtest.AssertNoLeak(t)
	lp := newLoopPair(t, rendr.Config{})
	const rounds, size = 200, 1 << 20
	msg := make([]byte, size)
	if _, err := io.ReadFull(rendrtest.PRNG(5), msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, size+1)
	for i := range rounds {
		dc, pc := lp.open(t)
		if n, err := dc.Write(msg); n != size || err != nil {
			t.Fatalf("round %d: Write = %d, %v", i, n, err)
		}
		if err := dc.Close(); err != nil {
			t.Fatalf("round %d: Close: %v", i, err)
		}
		n, err := io.ReadFull(pc, buf[:size])
		if err != nil || n != size || string(buf[:size]) != string(msg) {
			t.Fatalf("round %d: the passive read %d bytes, %v", i, n, err)
		}
		if n, err := pc.Read(buf); n != 0 || err != io.EOF {
			t.Fatalf("round %d: after the data: (%d, %v), want EOF", i, n, err)
		}
		pc.Close()
		for _, c := range []*rendr.Conn{dc, pc} {
			st := waitEnded(t, c, 30*time.Second)
			if st.Err != io.EOF || st.Migrations != (rendr.MigrationCounts{}) || st.Rejoins != 0 || st.NoPathEpisodes != 0 {
				t.Fatalf("round %d: %v ended %+v", i, st.Role, st)
			}
			for _, cs := range st.Carriers {
				if cs.DeathCause != rendr.CauseNone && cs.DeathCause != rendr.CauseRetired {
					t.Fatalf("round %d: %v carrier %d died: %v %s", i, st.Role, cs.ID, cs.DeathCause, cs.DeathDetail)
				}
			}
		}
		if n := lp.relay.errs.Load(); n != 0 {
			t.Fatalf("round %d: %d relayed connections ended in an error: %v", i, n, lp.relay.lastEr.Load())
		}
	}
	lp.relay.idle(10 * time.Second) // every relayed connection ended
	if n, c := lp.relay.errs.Load(), lp.relay.conns.Load(); n != 0 || c != rounds {
		t.Fatalf("%d of %d relayed connections ended in an error (%v); want 0 of %d", n, c, lp.relay.lastEr.Load(), rounds)
	}
	lp.close(t)
	check()
}

// onlyWriter hides io.ReaderFrom so that io.Copy uses plain Writes.
type onlyWriter struct{ io.Writer }

// TestSteadyStateZeroAllocs_L41_L54 (design §12.2, V4): the steady state of
// a session costs no allocation end to end. Over a warmed carrier/tcp
// loopback pair driven only through the public API (rendr-owned TCP conns:
// vectored writes, the poller's deadline timers reset in place), at least
// 4000 rounds of a 64 KiB Write on the dialer and the 64 KiB Read on the
// passive — the application copies, the carrier batch writes, the reader's
// frame decode, and the ACK, PING and PONG traffic on both carriers — cost
// at most 40 allocations in total. The window is counted raw
// (runtime.MemStats.Mallocs, every goroutine), not per run: the integer
// division of testing.AllocsPerRun reports 0 for anything below one
// allocation per round, so a PING or an ACK that allocated once per
// interval would pass unseen. GC is off during the window (no pool is
// cleared mid-window), one P runs (as in AllocsPerRun: no cross-P pool
// refills), PingBusy is at its lowest setting (10 ms) and the window lasts
// at least 50 PING intervals: an allocation per PING or per PONG exceeds
// the bound, while the few one-off runtime allocations stay well below it.
// Asserted in the non-race lane; the race lane runs a short window and
// logs the figure.
func TestSteadyStateZeroAllocs_L41_L54(t *testing.T) {
	check := rendrtest.AssertNoLeak(t)
	cfg := rendr.Config{PingBusy: 10 * time.Millisecond}
	d, err := rendr.NewRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p, err := rendr.NewRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
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
	lp := &loopPair{d: d, p: p, ln: ln, peer: peer}
	dc, pc := lp.open(t)

	wbuf := make([]byte, 64<<10)
	if _, err := io.ReadFull(rendrtest.PRNG(54), wbuf); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, 64<<10)
	round := func() {
		if n, err := dc.Write(wbuf); n != len(wbuf) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
		if n, err := io.ReadFull(pc, rbuf); n != len(rbuf) || err != nil {
			t.Fatalf("Read = %d, %v", n, err)
		}
	}
	const warm, maxAllocs = 256, 40
	for range warm { // pools, rings, the poller's timers, ACK and PING state
		round()
	}
	// The window lasts at least 4000 rounds and 50 PING intervals: each
	// carrier PINGs at least every PingBusy while it sends or receives DATA
	// and the other answers every PING, so an allocation per PING (or per
	// PONG) alone adds at least 2 × 49 > maxAllocs. The bound does not grow
	// with the rounds a fast machine fits into the window.
	minRounds, minWindow := 100*maxAllocs, 50*cfg.PingBusy
	if loopbackRace {
		minRounds, minWindow = warm, 0 // the race lane only logs the figure
	}
	f0 := dc.Status().Carriers[0].Frames
	mallocs, rounds, el := countMallocs(minRounds, minWindow, round)
	frames := dc.Status().Carriers[0].Frames - f0
	if string(rbuf) != string(wbuf) {
		t.Fatal("the last round delivered other bytes")
	}
	st := dc.Status()
	if st.TxBytes != uint64(warm+rounds)*64<<10 || len(st.Carriers) != 1 || rounds < minRounds || el < minWindow {
		t.Fatalf("load: %d rounds in %v, dialer status %+v", rounds, el, st)
	}
	t.Logf("%d allocations in %d rounds of 64 KiB (%v; the dialer's carrier wrote %d frames)", mallocs, rounds, el, frames)
	if loopbackRace {
		t.Logf("race lane: not asserted")
	} else if mallocs > maxAllocs {
		t.Fatalf("%d allocations in %d steady-state round trips over %v, want at most %d", mallocs, rounds, el, maxAllocs)
	}
	dc.Close()
	pc.Close()
	waitEnded(t, dc, 30*time.Second)
	waitEnded(t, pc, 30*time.Second)
	lp.close(t)
	check()
}

// countMallocs runs f at least n times and for at least window, with the
// garbage collector off and one P (as testing.AllocsPerRun), and returns
// the raw number of heap allocations of every goroutine during the window,
// the runs and the window's duration.
func countMallocs(n int, window time.Duration, f func()) (mallocs uint64, runs int, el time.Duration) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
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
