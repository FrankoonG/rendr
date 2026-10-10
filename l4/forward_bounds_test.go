package l4

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP4: Forward's bounds and its conduct toward the conns it is handed:
// backpressure (L15), concurrent closers (L03), validated counts (L42),
// goroutines (L52), interface use (L57) and deadlines (M4-D40, R1-23).

// TestForwardBackpressure_L15 (§A9): a target that reads 1 MiB/s holds
// back a client that writes 8 MiB as fast as it can: the bytes the client
// handed over and the target has not read stay below 2 × Window + 128 KiB
// (bytes in transit: the two session windows, two pump buffers and the
// pipes); the memory the two Runtimes account for (Status.BufferedBytes)
// stays below that bound plus the core's own per-carrier buffers (one
// write scratch of at most the 512 KiB class and one 16 KiB reader stage
// per carrier and Runtime), which a transit count cannot see; the client's
// Writes advance at the target's pace, and every byte arrives in order.
func TestForwardBackpressure_L15(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const window, total, pipe = 256 << 10, 8 << 20, 16 << 10
		w := newWorld(t, worldOpts{window: window})
		d, p := w.open(rendr.DialOptions{})
		cli, srv := rendrtest.TargetPipe(pipe)
		tcli, tsrv := rendrtest.TargetPipe(pipe)
		in := forwardAsync(context.Background(), d, srv)
		out := forwardAsync(context.Background(), p, tcli)
		var written, read atomic.Int64
		go func() { // the client: as fast as the session accepts
			src, buf := rendrtest.PRNG(1), make([]byte, 16<<10)
			for written.Load() < total {
				src.Read(buf)
				n, err := cli.Write(buf)
				written.Add(int64(n))
				if err != nil {
					return
				}
			}
			cli.CloseWrite()
		}()
		type got struct {
			n   int64
			sum [32]byte
			err error
		}
		slow := make(chan got, 1)
		go func() { // the target: 16 KiB every 15.625 ms = 1 MiB/s
			h, b := newSum(), make([]byte, 16<<10)
			for {
				k, err := io.ReadFull(tsrv, b)
				h.Write(b[:k])
				read.Add(int64(k))
				if err != nil {
					slow <- got{read.Load(), h.sum(), err}
					return
				}
				time.Sleep(time.Second / 64)
			}
		}()
		bound := int64(2*window + 128<<10)
		// One link: one carrier per Runtime, each with at most one write
		// scratch (512 KiB class) and one reader stage (16 KiB class).
		const classSlack = 64
		memBound := bound + 2*(512<<10+classSlack) + 2*(16<<10+classSlack)
		var peak, bufPeak int64
		for range 6 {
			time.Sleep(500 * time.Millisecond)
			synctest.Wait()
			held := written.Load() - read.Load()
			peak = max(peak, held)
			if held > bound {
				t.Fatalf("%d bytes held between the client and the target, want at most %d", held, bound)
			}
			// The Runtimes' accounting adds the carriers' write scratches
			// and reader stages (core memory outside Forward) to the
			// bytes in transit.
			bufPeak = max(bufPeak, w.d.Status().BufferedBytes+w.p.Status().BufferedBytes)
			if bufPeak > memBound {
				t.Fatalf("the Runtimes account %d buffered bytes, want at most %d", bufPeak, memBound)
			}
		}
		if el := 3 * time.Second; written.Load() > int64(el.Seconds()*(1<<20))+bound || read.Load() < 2<<20 {
			t.Fatalf("load: after %v the client wrote %d and the target read %d bytes; want the target's pace", el, written.Load(), read.Load())
		}
		g := <-slow
		if g.err != io.EOF || g.n != total || g.sum != prngSum(1, total) {
			t.Fatalf("target read %d bytes (SHA ok: %v), then %v", g.n, g.sum == prngSum(1, total), g.err)
		}
		t.Logf("peak held %d bytes (bound %d); the Runtimes' BufferedBytes peaked at %d (bound %d)", peak, bound, bufPeak, memBound)
		tsrv.CloseWrite()
		checkClean(t, "ingress", <-in, total, 0)
		checkClean(t, "egress", <-out, 0, total)
		cli.Close()
		tsrv.Close()
		waitDone(t, d, time.Minute)
		waitDone(t, p, time.Minute)
		w.shutdown()
	})
}

// TestForwardConcurrentClose_L03 (§A7.3): while bytes move both ways, the
// application closes the session, the client resets its socket and the
// target's Forward is cancelled, at different instants per iteration: both
// Forwards return, neither ends clean, the target is released, and the
// client's Read ends with a reset (or net.ErrClosed after its own close),
// never EOF.
func TestForwardConcurrentClose_L03(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{n: 4})
		for i := range 60 {
			ch := w.chain(rendrtest.TargetEcho(), 0)
			pumped := make(chan error, 1)
			go func() { pumped <- writePRNG(ch.client, uint64(i), 64<<20) }()
			readEnd := make(chan error, 1)
			go func() { _, _, err := readAll(ch.client); readEnd <- err }()
			time.Sleep(time.Duration(i%6) * 7 * time.Millisecond)
			var wg sync.WaitGroup
			closers := []func(){
				func() { ch.d.Close() },
				func() { ch.cancelOut() },
				func() { ch.client.SetLinger(0); ch.client.Close() },
			}
			first := i % len(closers)
			for k := range closers {
				wg.Go(func() {
					time.Sleep(time.Duration((k-first+len(closers))%len(closers)) * time.Millisecond)
					closers[k]()
				})
			}
			wg.Wait()
			in, out := ch.results()
			if in.Clean || out.Clean {
				t.Fatalf("iteration %d: a clean end after the resets: ingress %+v, egress %+v", i, in, out)
			}
			// The client's Read ends with the reset Forward sent, or with
			// net.ErrClosed where the client's own close came first.
			if err := <-readEnd; !isReset(err) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("iteration %d: the client's Read ended with %v, want a reset (or its own close)", i, err)
			}
			<-pumped
			synctest.Wait()
			if c := ch.target.Counts().Conns[0]; c.Open {
				t.Fatalf("iteration %d: target connection %+v: want it released", i, c)
			}
			ch.end(t)
		}
		w.shutdown()
	})
}

// scriptedConn makes local misbehave once: its first Write or Read returns
// the scripted count and error.
type scriptedConn struct {
	net.Conn
	mu    sync.Mutex
	write bool // script the first Write (else the first Read)
	n     func(l int) int
	err   error
	used  bool
}

// CloseWrite and SetLinger pass through to the wrapped conn.
func (s *scriptedConn) CloseWrite() error {
	return s.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (s *scriptedConn) SetLinger(sec int) error {
	return s.Conn.(interface{ SetLinger(int) error }).SetLinger(sec)
}

func (s *scriptedConn) take() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used {
		return false
	}
	s.used = true
	return true
}

func (s *scriptedConn) Write(b []byte) (int, error) {
	if s.write && len(b) > 0 && s.take() {
		k := s.n(len(b))
		if k > 0 && k <= len(b) {
			s.Conn.Write(b[:k])
		}
		return k, s.err
	}
	return s.Conn.Write(b)
}

func (s *scriptedConn) Read(b []byte) (int, error) {
	if !s.write && s.take() {
		return s.n(len(b)), s.err
	}
	return s.Conn.Read(b)
}

var errScripted = errors.New("scripted write error")

// emptyReadConn's Reads return (0, nil), up to emptyReadGuard of them;
// after that (a pump that spins on) they fail with errSpinGuard.
type emptyReadConn struct {
	net.Conn
	reads atomic.Int64
}

const emptyReadGuard = 100 * maxEmptyReads

var errSpinGuard = errors.New("empty-read guard: the pump kept reading")

func (e *emptyReadConn) Read([]byte) (int, error) {
	if e.reads.Add(1) > emptyReadGuard {
		return 0, errSpinGuard
	}
	return 0, nil
}

func (e *emptyReadConn) CloseWrite() error {
	return e.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (e *emptyReadConn) SetLinger(sec int) error {
	return e.Conn.(interface{ SetLinger(int) error }).SetLinger(sec)
}

// TestForwardShortWrites_L42 (§A7.1, L42): a short Write without an error
// that made progress is continued; no progress, an invalid count or a short
// write with an error is a failure of local: the session is reset toward
// the peer (AbortReset) and local is reset.
func TestForwardShortWrites_L42(t *testing.T) {
	cases := []struct {
		name string
		n    func(l int) int
		err  error
		ok   bool
		want error
	}{
		{"len-3 nil", func(l int) int { return l - 3 }, nil, true, nil},
		{"0 nil", func(int) int { return 0 }, nil, false, io.ErrShortWrite},
		{"-1 nil", func(int) int { return -1 }, nil, false, errBadCount},
		{"len+1 nil", func(l int) int { return l + 1 }, nil, false, errBadCount},
		{"len-1 err", func(l int) int { return l - 1 }, errScripted, false, errScripted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newWorld(t, worldOpts{})
				tg := rendrtest.NewTarget(rendrtest.TargetSink(), 0)
				d, p := w.open(rendr.DialOptions{})
				tconn, err := tg.Dial(context.Background(), kitTarget)
				if err != nil {
					t.Fatal(err)
				}
				local := &scriptedConn{Conn: tconn, write: true, n: tc.n, err: tc.err}
				out := forwardAsync(context.Background(), p, local)
				const size = 64 << 10
				if err := writePRNG(d, 1, size); err != nil {
					t.Fatalf("Write: %v", err)
				}
				d.CloseWrite()
				_, _, rerr := readAll(d)
				r := <-out
				synctest.Wait()
				c := tg.Counts().Conns[0]
				if tc.ok {
					if rerr != io.EOF || c.BytesIn != size || c.SHAIn != prngSum(1, size) {
						t.Fatalf("dialer read %v; target %+v: want every byte delivered, then EOF", rerr, c)
					}
					checkClean(t, "egress", r, 0, size)
				} else {
					if code, remote, ok := abortCode(rerr); !ok || code != AbortReset || !remote {
						t.Fatalf("dialer Read: %v, want *AbortError{AbortReset, Remote}", rerr)
					}
					if r.Clean || !errors.Is(r.LocalErr, tc.want) || !c.RSTIn {
						t.Fatalf("egress Forward %+v, target %+v: want LocalErr %v and a reset", r, c, tc.want)
					}
				}
				d.Close()
				waitDone(t, d, time.Minute)
				tg.Close()
				w.shutdown()
			})
		})
	}
}

// TestForwardBadCountsFromLocal_L42 (§A7.1, L42): a local Read that
// returns a count outside [0, len(p)], and a local whose Reads keep
// returning (0, nil), are failures of local: nothing of them reaches the
// session, the session is reset toward the peer, local is reset; the pump
// does not spin (exactly maxEmptyReads Reads).
func TestForwardBadCountsFromLocal_L42(t *testing.T) {
	for _, tc := range []struct {
		name  string
		local func(c net.Conn) net.Conn
		want  error
	}{
		{"len+1", func(c net.Conn) net.Conn {
			return &scriptedConn{Conn: c, n: func(l int) int { return l + 1 }}
		}, errBadCount},
		{"-1", func(c net.Conn) net.Conn {
			return &scriptedConn{Conn: c, n: func(int) int { return -1 }}
		}, errBadCount},
		// (0, nil) forever: io.ErrNoProgress after maxEmptyReads Reads;
		// the conn's own guard ends a pump that spins on regardless.
		{"0 nil forever", func(c net.Conn) net.Conn { return &emptyReadConn{Conn: c} }, io.ErrNoProgress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newWorld(t, worldOpts{})
				d, p := w.open(rendr.DialOptions{})
				tcli, tsrv := rendrtest.TargetPipe(0)
				local := tc.local(tcli)
				spy := &spyConn{Conn: local}
				out := forwardAsync(context.Background(), p, spy)
				n, _, err := readAll(d)
				if code, remote, ok := abortCode(err); n != 0 || !ok || code != AbortReset || !remote {
					t.Fatalf("dialer read %d bytes, then %v; want none, then *AbortError{AbortReset, Remote}", n, err)
				}
				r := <-out
				if r.Clean || !errors.Is(r.LocalErr, tc.want) || r.ToSession != 0 {
					t.Fatalf("Forward: %+v, want LocalErr %v and nothing sent", r, tc.want)
				}
				if e, ok := local.(*emptyReadConn); ok {
					if k := e.reads.Load(); k != maxEmptyReads {
						t.Fatalf("local was read %d times, want %d", k, maxEmptyReads)
					}
				}
				if _, _, closes, _ := spy.snapshot(); closes != 1 {
					t.Fatalf("local closed %d times, want once", closes)
				}
				tsrv.Close()
				d.Close()
				waitDone(t, d, time.Minute)
				w.shutdown()
			})
		})
	}
}

// TestForwardGoroutines_L52 (§A9): 1,000 forwarded connections cost at most
// three goroutines each (two pumps and the caller), +20; once they ended,
// the goroutine count is back at its value before the world. The counts
// are the bubble's own (bubbleGoroutines): goroutines of other tests of
// the binary that start or end meanwhile — the real-socket rows' — are not
// the forwards'; the row proves it by ending one such goroutine halfway
// (the process-wide count failed the pool's l4 sweep 2 times in 600).
func TestForwardGoroutines_L52(t *testing.T) {
	outside := make(chan struct{})
	outsideDone := make(chan struct{})
	go func() { <-outside; close(outsideDone) }() // not in the bubble
	synctest.Test(t, func(t *testing.T) {
		const n = 1000
		synctest.Wait()
		base0 := bubbleGoroutines()
		w := newWorld(t, worldOpts{n: n})
		type conn struct {
			d, p *rendr.Conn
			cli  *rendrtest.TargetConn
		}
		cs := make([]conn, n)
		for i := range cs {
			cs[i].d, cs[i].p = w.open(rendr.DialOptions{})
		}
		time.Sleep(5 * time.Second) // the actors park
		synctest.Wait()
		base := bubbleGoroutines()
		ctx, cancel := context.WithCancel(context.Background())
		res := make([]<-chan ForwardResult, n)
		for i := range cs {
			var srv *rendrtest.TargetConn
			cs[i].cli, srv = rendrtest.TargetPipe(1 << 10)
			res[i] = forwardAsync(ctx, cs[i].p, srv)
		}
		time.Sleep(5 * time.Second)
		synctest.Wait()
		live := bubbleGoroutines()
		close(outside) // a goroutine outside the bubble ends meanwhile
		<-outsideDone
		if live > base+3*n+20 || live < base+3*n {
			t.Fatalf("%d goroutines with %d forwards, %d before: want %d per forward (+20)", live, n, base, 3)
		}
		// Every forward is alive: one byte crosses each.
		for i := range cs {
			if _, err := cs[i].d.Write([]byte{byte(i)}); err != nil {
				t.Fatalf("forward %d: Write: %v", i, err)
			}
			var b [1]byte
			if _, err := io.ReadFull(cs[i].cli, b[:]); err != nil || b[0] != byte(i) {
				t.Fatalf("forward %d: read %v, %v", i, b, err)
			}
		}
		cancel()
		for i := range cs {
			if r := <-res[i]; r.Clean || !errors.Is(r.SessionErr, context.Canceled) {
				t.Fatalf("forward %d: %+v", i, r)
			}
			cs[i].d.Close()
		}
		for i := range cs {
			waitDone(t, cs[i].d, time.Minute)
			waitDone(t, cs[i].p, time.Minute)
		}
		w.shutdown()
		synctest.Wait()
		if after := bubbleGoroutines(); after != base0 {
			t.Fatalf("%d goroutines after the forwards and the world ended, %d before", after, base0)
		}
	})
}

// plainConn is an embedder's conn: the net.Conn methods only, plus
// ReadFrom and WriteTo that Forward must never call (L57: no interface
// upgrades of embedder conns).
type plainConn struct {
	inner    net.Conn
	upgrades atomic.Int32
	closes   atomic.Int32
}

func (c *plainConn) Read(b []byte) (int, error)         { return c.inner.Read(b) }
func (c *plainConn) Write(b []byte) (int, error)        { return c.inner.Write(b) }
func (c *plainConn) Close() error                       { c.closes.Add(1); return c.inner.Close() }
func (c *plainConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *plainConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *plainConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *plainConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *plainConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
func (c *plainConn) ReadFrom(r io.Reader) (int64, error) {
	c.upgrades.Add(1)
	return 0, errors.New("ReadFrom called")
}
func (c *plainConn) WriteTo(w io.Writer) (int64, error) {
	c.upgrades.Add(1)
	return 0, errors.New("WriteTo called")
}

// TestForwardEmbedderConnNoUpgrade_L57 (§A7.1): Forward calls only the
// net.Conn methods of a conn that offers neither CloseWrite nor SetLinger
// (never its ReadFrom or WriteTo): a clean exchange closes it once, plainly;
// a reset closes it once, plainly.
func TestForwardEmbedderConnNoUpgrade_L57(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const req, resp = 4 << 10, 64 << 10
		for _, reset := range []bool{false, true} {
			tg := rendrtest.NewTarget(rendrtest.TargetReqResp(req, resp), 0)
			d, p := w.open(rendr.DialOptions{})
			tconn, err := tg.Dial(context.Background(), kitTarget)
			if err != nil {
				t.Fatal(err)
			}
			local := &plainConn{inner: tconn}
			out := forwardAsync(context.Background(), p, local)
			if err := writePRNG(d, 1, req); err != nil {
				t.Fatal(err)
			}
			d.CloseWrite()
			if reset {
				d.Abort(testAbort, "test")
			} else if n, sum, err := readAll(d); err != io.EOF || n != resp || sum != prngSum(0, resp) {
				t.Fatalf("dialer read %d bytes (SHA ok: %v), then %v", n, sum == prngSum(0, resp), err)
			}
			r := <-out
			if r.Clean == reset || local.closes.Load() != 1 || local.upgrades.Load() != 0 {
				t.Fatalf("reset %v: Forward %+v; %d Closes, %d ReadFrom/WriteTo calls", reset, r, local.closes.Load(), local.upgrades.Load())
			}
			d.Close()
			waitDone(t, d, time.Minute)
			waitDone(t, p, time.Minute)
			tg.Close()
		}
		w.shutdown()
	})
}

// TestForwardSetsNoDeadlines (§A7.5, M4-D40, R1-23): Forward sets no
// deadline on either conn during a transfer (the embedder's own stay
// intact; silence is bounded by the idle limit); a clean end sets none; a
// reset sets exactly one, SetDeadline(now), right before its Close.
func TestForwardSetsNoDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const size = 1 << 20
		d, p := w.open(rendr.DialOptions{})
		tg := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		tconn, err := tg.Dial(context.Background(), kitTarget)
		if err != nil {
			t.Fatal(err)
		}
		cli, srv := rendrtest.TargetPipe(0)
		inSpy, outSpy := &spyConn{Conn: srv}, &spyConn{Conn: tconn}
		in := forwardAsync(context.Background(), d, fullSpy{inSpy})
		out := forwardAsync(context.Background(), p, fullSpy{outSpy})
		go writePRNG(cli, 1, size)
		buf := make([]byte, size)
		if _, err := io.ReadFull(cli, buf); err != nil {
			t.Fatalf("echo: %v", err)
		}
		for _, s := range []*spyConn{inSpy, outSpy} {
			if dl, _, _, _ := s.snapshot(); len(dl) != 0 {
				t.Fatalf("%d deadline calls during the transfer, want none", len(dl))
			}
		}
		cli.CloseWrite()
		if _, _, err := readAll(cli); err != io.EOF {
			t.Fatalf("client: %v", err)
		}
		checkClean(t, "ingress", <-in, size, size)
		checkClean(t, "egress", <-out, size, size)
		for _, s := range []*spyConn{inSpy, outSpy} {
			if dl, l0, closes, _ := s.snapshot(); len(dl) != 0 || l0 != 0 || closes != 1 {
				t.Fatalf("clean end: %d deadline calls, %d SetLinger(0), %d Closes; want one plain Close", len(dl), l0, closes)
			}
		}
		cli.Close()
		waitDone(t, d, time.Minute)
		waitDone(t, p, time.Minute)
		tg.Close()

		// The reset path: one SetDeadline(now) right before the reset.
		d, p = w.open(rendr.DialOptions{})
		cli, srv = rendrtest.TargetPipe(0)
		spy := &spyConn{Conn: srv}
		res := forwardAsync(context.Background(), d, fullSpy{spy})
		if err := writePRNG(cli, 1, 4<<10); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if dl, _, _, _ := spy.snapshot(); len(dl) != 0 {
			t.Fatalf("%d deadline calls during the transfer, want none", len(dl))
		}
		p.Abort(testAbort, "test")
		r := <-res
		dl, l0, closes, _ := spy.snapshot()
		if len(dl) != 1 || dl[0].After(spy.closedAt) || l0 != 1 || closes != 1 || r.Clean {
			t.Fatalf("reset: deadlines %v (closed at %v), %d SetLinger(0), %d Closes; want one SetDeadline(now) before the reset", dl, spy.closedAt, l0, closes)
		}
		cli.Close()
		waitDone(t, d, time.Minute)
		waitDone(t, p, time.Minute)
		w.shutdown()
	})
}

// bubbleGoroutines counts the goroutines of the calling goroutine's
// synctest bubble: the goroutine dump marks each with its bubble, and the
// caller's own record comes first.
func bubbleGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	tag := ""
	count := 0
	for _, line := range strings.Split(string(buf), "\n") {
		if !strings.HasPrefix(line, "goroutine ") || !strings.HasSuffix(line, "]:") {
			continue
		}
		i := strings.Index(line, ", synctest bubble ")
		if i < 0 {
			continue
		}
		b := line[i : len(line)-2]
		if tag == "" {
			tag = b // the caller's own record is the first
		}
		if b == tag {
			count++
		}
	}
	return count
}
