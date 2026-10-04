package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRuntimeCloseJoinsEverything (M1a carried issue, design §6.8, L52):
// Runtime.Close with an event worker, a pull source, unfinished silent
// handshakes, live sessionless carriers and a blocked Accept: the Accept
// returns net.ErrClosed, the source is closed once, every silent handshake
// is closed at once (not at its deadline), every probe carrier gets
// GOAWAY then CLOSE, Close returns within its ≈ 2 s bound, nothing is
// abandoned, every counter is back to zero, later calls return
// net.ErrClosed, and the bubble ends with no goroutine left.
func TestRuntimeCloseJoinsEverything(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var events atomic.Int32
		rt := wpTestRuntime(t, Config{OnEvent: func(Event) { events.Add(1) }}, nil)
		src := newFakeListener()
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromListener(src)}})
		pushed := wpListen(t, rt, ListenConfig{})

		var silent []*wpDialer
		for i := range 3 {
			silent = append(silent, wpConnect(t, pushed, wpInst(0x31), uint32(i+1)))
		}
		var probes []*wpDialer
		for i := range 2 {
			probes = append(probes, pushProbe(t, rt, src, wpInst(byte(0x40+i)), uint32(10+i)))
		}
		accepted := make(chan error, 1)
		go func() {
			_, err := ln.Accept(context.Background())
			accepted <- err
		}()
		synctest.Wait()
		st := rt.Status()
		if st.Handshakes != 3 || st.Sessionless != 2 || st.BufferedBytes == 0 {
			t.Fatalf("before Close: %+v", st)
		}

		var wg sync.WaitGroup
		start := time.Now()
		for _, d := range silent {
			wg.Go(func() {
				var b [1]byte
				if n, err := d.nc.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) || time.Since(start) != 0 {
					t.Errorf("silent handshake at Close: (%d, %v) after %v", n, err, time.Since(start))
				}
				d.close()
			})
		}
		for _, d := range probes {
			wg.Go(func() {
				d.expect(wire.TypeGoAway)
				d.expect(wire.TypeClose)
				d.close()
			})
		}
		if err := rt.Close(); err != nil {
			t.Fatal(err)
		}
		if el := time.Since(start); el > 2500*time.Millisecond {
			t.Fatalf("Close took %v", el)
		}
		wg.Wait()
		if err := <-accepted; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Accept: %v", err)
		}
		if src.closes.Load() != 1 {
			t.Fatalf("source closed %d times", src.closes.Load())
		}
		wpNoState(t, rt)
		if st := rt.Status(); st.Abandoned != 0 || st.CallbackPanics != 0 {
			t.Fatalf("after Close: %+v", st)
		}
		if _, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{(&countingFactory{name: "f"}).carrier()}}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("NewPeer after Close: %v", err)
		}
		if _, err := rt.Listen(ListenConfig{}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Listen after Close: %v", err)
		}
		a, _ := net.Pipe()
		if err := pushed.Handle(a); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle after Close: %v", err)
		}
		start = time.Now()
		if err := rt.Close(); err != nil || time.Since(start) != 0 {
			t.Fatalf("second Close: %v after %v", err, time.Since(start))
		}
		if events.Load() != 0 {
			t.Fatalf("%d events without a session", events.Load())
		}
	})

	// With live sessions and Dials in flight (design §6.8 step 7): a selector
	// and a bond session carrying data over two factories (probing runs), a
	// Dial whose OPEN waits for the passive application, and a Dial whose
	// factory hangs until its context ends. Runtime.Close of the dialer
	// returns within its bound; both in-flight Dials return net.ErrClosed;
	// every session ends locally with net.ErrClosed and at the passive with
	// AbortError(GoingAway); the pending OPEN is withdrawn (Confirm:
	// ErrSessionLost). After the passive's own Close no rendr goroutine is
	// left, without advancing time (synctest.Wait only).
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		for _, l := range e.links {
			l.SetDelay(time.Millisecond, 0)
		}
		peer := e.peer()
		sel, selP := e2eOpen(t, peer, e.ln, DialOptions{Mode: ModeSelector})
		bond, bondP := e2eOpen(t, peer, e.ln, DialOptions{Mode: ModeBond})
		e2eExchange(t, sel, selP, 256<<10, 1)
		e2eExchange(t, bond, bondP, 256<<10, 2)
		pending := e2eDialAsync(context.Background(), peer, DialOptions{})
		pc, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		hang := rendrtest.NewLink(rendrtest.LinkConfig{Name: "hang", Accept: e.ln.Handle})
		t.Cleanup(hang.Close)
		hang.SetDial(rendrtest.DialHang)
		hung := e2eDialAsync(context.Background(), e.peer(hang), DialOptions{})
		synctest.Wait()
		if st := e.d.Status(); st.Sessions.Open != 2 || e.d.dial.running() != 2 {
			t.Fatalf("before Close: %+v, %d Dials in flight", st, e.d.dial.running())
		}

		eff := e.d.eff
		bound := max(min(time.Second, eff.cfg.DeadMax)+eff.timing.AbandonWait, 2*eff.timing.AbandonWait) + closeSlack
		start := time.Now()
		e.d.Close()
		if el := time.Since(start); el > bound {
			t.Fatalf("Runtime.Close took %v, bound %v", el, bound)
		}
		for i, res := range []<-chan dialResult{pending, hung} {
			if r := <-res; r.c != nil || !errors.Is(r.err, net.ErrClosed) {
				t.Fatalf("in-flight Dial %d at Close: %v, %v", i, r.c, r.err)
			}
		}
		for _, c := range []*Conn{sel, bond} {
			if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("dialer Read after Runtime.Close: %v", err)
			}
		}
		time.Sleep(10 * time.Millisecond) // the RSTs and GOAWAYs cross the links
		for _, c := range []*Conn{selP, bondP} {
			var ae *AbortError
			if _, err := c.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
				t.Fatalf("passive Read after the dialer's Runtime.Close: %v", err)
			}
		}
		if c, err := pc.Confirm(); c != nil || !errors.Is(err, ErrSessionLost) {
			t.Fatalf("Confirm of the withdrawn OPEN: %v, %v", c, err)
		}
		if st := e.d.Status(); st.Abandoned != 0 || st.BufferedBytes != 0 {
			t.Fatalf("dialer after Close: %+v", st)
		}
		e.p.Close()
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 {
			t.Fatalf("rendr goroutines left after both Close calls: %v", left)
		}
		e.close()
	})
}

// TestEventCallbackMayClose_L53: OnEvent may call Runtime.Close (and any
// other method) without deadlock: the Close called from the callback never
// waits for the callback itself, a concurrent Close from another goroutine
// returns once the first one finished, a nested Close from the callback
// returns at once, events queued before the Close are still delivered in
// Seq order, and later events are discarded without being counted.
func TestEventCallbackMayClose_L53(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var (
			rt       *Runtime
			mu       sync.Mutex
			seen     []uint64
			closeErr = make(chan error, 2)
		)
		rt = wpTestRuntime(t, Config{OnEvent: func(ev Event) {
			mu.Lock()
			seen = append(seen, ev.Seq)
			mu.Unlock()
			if ev.Seq == 2 {
				closeErr <- rt.Close()
				_ = rt.Status()
				closeErr <- rt.Close() // nested: returns at once
			}
		}}, nil)
		for i := range 5 {
			rt.ev.Emit(session.Event{Kind: session.EventCarrierUp, Session: wpSID(i), Carrier: uint32(i + 1), Time: time.Now()})
		}
		other := make(chan error, 1)
		go func() {
			synctest.Wait()
			other <- rt.Close()
		}()
		for range 2 {
			if err := <-closeErr; err != nil {
				t.Fatal(err)
			}
		}
		if err := <-other; err != nil {
			t.Fatal(err)
		}
		rt.ev.Emit(session.Event{Kind: session.EventSessionEnd}) // after Close: discarded, not a drop
		synctest.Wait()
		mu.Lock()
		got := append([]uint64(nil), seen...)
		mu.Unlock()
		if len(got) != 5 {
			t.Fatalf("delivered %v, want Seq 1..5", got)
		}
		for i, s := range got {
			if s != uint64(i+1) {
				t.Fatalf("delivered %v, want Seq 1..5 in order", got)
			}
		}
		if st := rt.Status(); st.EventsDropped != 0 || st.CallbackPanics != 0 || st.Abandoned != 0 {
			t.Fatalf("status %+v", st)
		}
	})

	// With a real session: the callback closes the dialer Runtime when the
	// session's only carrier goes down (the link refuses redials). That
	// Close shuts the session down and returns (it never waits for the
	// callback it runs in); the events the actor emitted meanwhile — the
	// NoPathStart of the same death step and the SessionEnd of the shutdown
	// — are delivered after the callback, in Seq order; a later Close from
	// the test returns at once.
	synctest.Test(t, func(t *testing.T) {
		var (
			e        *e2ePair
			mu       sync.Mutex
			evs      []Event
			closeErr = make(chan error, 1)
		)
		e = e2eNew(t, Config{OnEvent: func(ev Event) {
			mu.Lock()
			evs = append(evs, ev)
			mu.Unlock()
			if ev.Kind == EventCarrierDown {
				closeErr <- e.d.Close()
			}
		}}, Config{}, nil, ListenConfig{}, "a")
		link := e.links[0]
		dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
		link.SetRefuse(true)
		if n := link.Kill(); n != 1 {
			t.Fatalf("killed %d carriers", n)
		}
		if err := <-closeErr; err != nil {
			t.Fatal(err)
		}
		if err := e.d.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, err := dc.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after the callback's Close: %v", err)
		}
		mu.Lock()
		got := append([]Event(nil), evs...)
		mu.Unlock()
		want := []EventKind{EventCarrierUp, EventCarrierDown, EventNoPathStart, EventSessionEnd}
		if len(got) != len(want) {
			t.Fatalf("events %+v, want kinds %v", got, want)
		}
		for i, ev := range got {
			if ev.Kind != want[i] || ev.Seq != uint64(i+1) || ev.Session != dc.ID() {
				t.Fatalf("event %d: %+v, want %v (Seq %d)", i, ev, want[i], i+1)
			}
		}
		if !errors.Is(got[3].Err, net.ErrClosed) || got[1].Cause != CauseTransportError {
			t.Fatalf("CarrierDown %+v, SessionEnd %+v", got[1], got[3])
		}
		if st := e.d.Status(); st.EventsDropped != 0 || st.CallbackPanics != 0 || st.Abandoned != 0 {
			t.Fatalf("dialer %+v", st)
		}
		sc.Close()
		e.close()
	})
}

// TestPassiveConnCloseIndividually (M1a carried issue, design §11.5): a
// passive Conn is closed and aborted on its own, like a dialer's. Closing
// one passive session wakes its blocked Read with net.ErrClosed at once and
// finishes it cleanly with its dialer (which reads EOF); closing another
// while its dialer keeps sending resets that dialer (AbortError(Closed,
// Remote)); a third session of the same Runtimes is not affected and
// still echoes.
func TestPassiveConnCloseIndividually(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		peer := e.peer()
		d1, p1 := e2eOpen(t, peer, e.ln, DialOptions{})
		d2, p2 := e2eOpen(t, peer, e.ln, DialOptions{})
		d3, p3 := e2eOpen(t, peer, e.ln, DialOptions{Mode: ModeBond})

		blocked := make(chan error, 1)
		go func() {
			_, err := p1.Read(make([]byte, 16))
			blocked <- err
		}()
		synctest.Wait()
		start := time.Now()
		if err := p1.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-blocked; !errors.Is(err, net.ErrClosed) || time.Since(start) != 0 {
			t.Fatalf("blocked passive Read at Close: %v after %v", err, time.Since(start))
		}
		if n, err := d1.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("dialer Read after the passive's Close: (%d, %v), want EOF", n, err)
		}
		d1.Close()
		e2eDone(t, p1, 30*time.Second)
		e2eDone(t, d1, 30*time.Second)
		if st := p1.Status(); st.Err != io.EOF {
			t.Fatalf("passive session after its Close: %+v", st)
		}

		stop := make(chan struct{})
		sendErr := make(chan error, 1)
		go func() {
			buf := make([]byte, 32<<10)
			for {
				if _, err := d2.Write(buf); err != nil {
					sendErr <- err
					return
				}
				select {
				case <-stop:
					sendErr <- nil
					return
				default:
				}
			}
		}()
		if _, err := io.ReadFull(p2, make([]byte, 64<<10)); err != nil {
			t.Fatal(err)
		}
		p2.Close()
		var ae *AbortError
		if err := <-sendErr; !errors.As(err, &ae) || ae.Code != AbortClosed || !ae.Remote {
			t.Fatalf("the dialer still sending to a closed passive: %v", err)
		}
		close(stop)

		e2eExchange(t, d3, p3, 1<<20, 9)
		e2eFinish(t, d3, p3)
		e2eDone(t, p2, 30*time.Second)
		e.close()
	})
}

// TestPeerCloseJoinsProbes (M1a carried issue, design §11.5): Peer.Close
// stops the health layer and joins it before returning: the probe
// carriers of both factories retire (the passive holds no sessionless
// carrier afterwards), no probe goroutine of the Peer is left and its
// status reports no probing; the Peer's session keeps working; a later
// Dial of the Peer returns net.ErrClosed.
func TestPeerCloseJoinsProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		for _, l := range e.links {
			l.SetDelay(time.Millisecond, 0)
		}
		peer := e.peer()
		dc, sc := e2eOpen(t, peer, e.ln, DialOptions{})
		time.Sleep(3 * time.Second) // probe samples arrive
		st := peer.Status()
		if !st.Probing || len(st.Factories) != 2 || e.p.Status().Sessionless != 2 {
			t.Fatalf("before Peer.Close: %+v, %d sessionless carriers", st, e.p.Status().Sessionless)
		}
		for _, f := range st.Factories {
			if f.ProbeCarrier == 0 || f.Samples == 0 {
				t.Fatalf("factory %+v has no probe carrier or no sample", f)
			}
		}
		start := time.Now()
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
		eff := e.d.eff
		if el, bound := time.Since(start), max(min(time.Second, eff.cfg.DeadMax)+eff.timing.AbandonWait, 2*eff.timing.AbandonWait); el > bound {
			t.Fatalf("Peer.Close took %v, bound %v", el, bound)
		}
		synctest.Wait() // goroutines that are exiting finish; time does not advance
		_, left := rendrGoroutines()
		for fn, n := range left {
			if strings.Contains(fn, "healthRun") {
				t.Fatalf("%d %s goroutines after Peer.Close", n, fn)
			}
		}
		if st := peer.Status(); st.Probing {
			t.Fatalf("still probing after Close: %+v", st)
		}
		time.Sleep(10 * time.Millisecond) // the probes' CLOSE crosses the links
		synctest.Wait()
		if n := e.p.Status().Sessionless; n != 0 {
			t.Fatalf("%d probe carriers left at the passive", n)
		}
		e2eExchange(t, dc, sc, 512<<10, 4)
		if c, err := peer.Dial(context.Background(), DialOptions{}); c != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Dial after Peer.Close: %v, %v", c, err)
		}
		e2eFinish(t, dc, sc)
		e.close()
	})
}

// TestCloseConcurrentCallers: concurrent Runtime.Close calls all return
// nil, and none returns before the shutdown finished (its handshake
// joined, the Runtime marked closed).
func TestCloseConcurrentCallers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		d := wpConnect(t, ln, wpInst(0x51), 1)
		eof := make(chan struct{})
		go func() {
			d.expectEOF()
			close(eof)
		}()
		synctest.Wait()
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if err := rt.Close(); err != nil {
					t.Error(err)
				}
				if !isClosed(rt.closed) || rt.hsg.running() != 0 {
					t.Error("a Close returned before the shutdown finished")
				}
			})
		}
		wg.Wait()
		<-eof
		d.close()
		wpNoState(t, rt)
	})
}

// malConn is a malicious embedder conn for the bounded-close tests (L52):
// its Read ignores deadlines and Close until released, and its Close may
// block until released too.
type malConn struct {
	release    chan struct{} // unblocks Read (and Close when blockClose)
	blockClose bool
	readGate   chan struct{} // closed by Close when Read honours Close
	honourRead bool          // Read returns once Close was called
	writeOK    bool          // Write succeeds at once (else it blocks until released)
	once       sync.Once
	freeOnce   sync.Once
	closes     atomic.Int32
}

func newMalConn(honourRead, blockClose bool) *malConn {
	return &malConn{release: make(chan struct{}), readGate: make(chan struct{}), honourRead: honourRead, blockClose: blockClose}
}

func (c *malConn) Read([]byte) (int, error) {
	if c.honourRead {
		select {
		case <-c.release:
		case <-c.readGate:
		}
	} else {
		<-c.release
	}
	return 0, io.EOF
}
func (c *malConn) Write(p []byte) (int, error) {
	if c.writeOK {
		return len(p), nil
	}
	<-c.release
	return 0, io.ErrClosedPipe
}

func (c *malConn) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.readGate) })
	if c.blockClose {
		<-c.release
	}
	return nil
}

func (c *malConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *malConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *malConn) SetDeadline(time.Time) error      { return nil }
func (c *malConn) SetReadDeadline(time.Time) error  { return nil }
func (c *malConn) SetWriteDeadline(time.Time) error { return nil }

// free returns every blocked call (idempotent: tests also register it as a
// cleanup, so a failed test still ends its bubble).
func (c *malConn) free() { c.freeOnce.Do(func() { close(c.release) }) }

// TestMaliciousConnsCloseBounded_L52: Runtime.Close returns within its
// bound (≈ 2 s) whatever the embedder's conns do, counts exactly the
// goroutines stuck in embedder code in Status.Abandoned when it returns, and
// leaves no other rendr goroutine (L52). Handshakes hold three malicious
// conns — one whose Read ignores deadlines and Close, one whose Read honours
// only Close, one whose Close blocks — each closed exactly once. A session
// lane's CLOSE is stuck behind a write that ignores deadlines and Close
// (C24): the lane is killed at the close bound and its writer, stuck in
// the embedder's Write, is the only goroutine left. When the embedder calls
// finally return, the pool empties.
func TestMaliciousConnsCloseBounded_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: 500 * time.Millisecond})
		ln := wpListen(t, rt, ListenConfig{})
		deaf := newMalConn(false, false)     // Read ignores deadlines and Close: the handshake goroutine is stuck
		closeOnly := newMalConn(true, false) // Read returns at Close: released by Close's drain
		stuckClose := newMalConn(true, true) // Close blocks: the guarded closer goroutine is stuck
		for _, c := range []*malConn{deaf, closeOnly, stuckClose} {
			t.Cleanup(c.free)
			if err := ln.Handle(c); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		start := time.Now()
		rt.Close()
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("Close took %v", el)
		}
		// Stuck: the deaf conn's handshake goroutine (in Read) and the
		// stuck-Close conn's guarded closer (in Close).
		if st := rt.Status(); st.Abandoned != 2 {
			t.Fatalf("abandoned %d, want 2", st.Abandoned)
		}
		for i, c := range []*malConn{deaf, closeOnly, stuckClose} {
			if n := c.closes.Load(); n != 1 {
				t.Fatalf("conn %d closed %d times by Close", i, n)
			}
		}
		for _, c := range []*malConn{deaf, stuckClose} {
			c.free()
		}
		synctest.Wait()
		if st := rt.Status(); st.Abandoned != 0 || st.Handshakes != 0 {
			t.Fatalf("after the embedder calls returned: %+v", st)
		}
		for i, c := range []*malConn{deaf, closeOnly, stuckClose} {
			if n := c.closes.Load(); n != 1 {
				t.Fatalf("conn %d closed %d times", i, n)
			}
		}
		closeOnly.free()
	})

	// The session lane (C24).
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		link := e.links[0]
		t.Cleanup(link.Release)
		dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
		e2eExchange(t, dc, sc, 64<<10, 1)
		link.BlockWrites(rendrtest.Down, rendrtest.BlockHard) // the passive's conns: writes ignore deadlines and Close
		if _, err := sc.Write(make([]byte, 256<<10)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n := link.Stats().Session.WritesBlocked; n != 1 {
			t.Fatalf("stimulus: %d writes blocked, want the lane's batch", n)
		}
		eff := e.p.eff
		bound := max(min(time.Second, eff.cfg.DeadMax)+eff.timing.AbandonWait, 2*eff.timing.AbandonWait) + closeSlack
		start := time.Now()
		e.p.Close()
		if el := time.Since(start); el > bound {
			t.Fatalf("Runtime.Close took %v, bound %v", el, bound)
		}
		if n := e.p.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d at Close's return, want the writer stuck in the embedder's Write", n)
		}
		e.d.Close()
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 1 || left["github.com/FrankoonG/rendr/v2/internal/carrier.(*Conn).writeLoop"] != 1 {
			t.Fatalf("rendr goroutines after both Close calls: %v, want only the stuck writer", left)
		}
		link.Release()
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 || e.p.Status().Abandoned != 0 {
			t.Fatalf("after the Write returned: %v, abandoned %d", left, e.p.Status().Abandoned)
		}
		e.close()
	})

	// A dial attempt stuck in a deaf conn's Read (deadlines and Close
	// ignored) when Runtime.Close cancels its Dial: the Dial returns
	// net.ErrClosed at once and its session withdraws in the background;
	// Close joins that withdrawing session (C25, §6.8 step 7) — it returns
	// once the session gave up on the attempt, 2·AbandonWait after the
	// cancellation (X2) — and the stuck attempt is counted in
	// Status.Abandoned when Close returns. The conn is closed exactly once.
	synctest.Test(t, func(t *testing.T) {
		const wait = 500 * time.Millisecond
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: wait})
		deaf := newMalConn(false, false)
		deaf.writeOK = true
		t.Cleanup(deaf.free)
		p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "deaf", Dial: func(context.Context) (net.Conn, error) {
			return deaf, nil
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		res := e2eDialAsync(context.Background(), p, DialOptions{})
		synctest.Wait() // the attempt waits in the conn's Read for a PREFACE_ACK
		start := time.Now()
		rt.Close()
		el := time.Since(start)
		if r := <-res; r.c != nil || !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("Dial at Close: %v, %v", r.c, r.err)
		}
		bound := max(min(time.Second, rt.eff.cfg.DeadMax)+wait, 2*wait) + closeSlack
		if el < 2*wait || el > bound {
			t.Fatalf("Runtime.Close returned after %v; want it to join the withdrawing session (≥ %v, ≤ %v)", el, 2*wait, bound)
		}
		if n := rt.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d at Close's return, want the attempt stuck in Read", n)
		}
		deaf.free()
		synctest.Wait()
		if n := rt.Status().Abandoned; n != 0 || deaf.closes.Load() != 1 {
			t.Fatalf("after the Read returned: abandoned %d, conn closed %d times", n, deaf.closes.Load())
		}
		wpNoState(t, rt)
	})
}

// TestPassiveRuntimeCloseGoesAway (design §6.8, D21): when the passive
// Runtime closes, its open session sends RST(GoingAway) and GOAWAY: the
// dialer's session ends with AbortError(GoingAway, Remote) instead of
// redialling, and its Peer records the instance as gone away. A restarted
// passive (a new instance behind the same carrier factory) is not in that
// set and accepts the next Dial of the same Peer.
func TestPassiveRuntimeCloseGoesAway(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := wpTestRuntime(t, Config{}, nil)
		p1 := wpTestRuntime(t, Config{}, nil)
		var route atomic.Pointer[Listener]
		route.Store(wpListen(t, p1, ListenConfig{}))
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(c net.Conn) error { return route.Load().Handle(c) }})
		t.Cleanup(link.Close)
		peer, err := d.NewPeer(PeerConfig{Carriers: []Carrier{e2eCarrier(link)}})
		if err != nil {
			t.Fatal(err)
		}
		dc, sc := e2eOpen(t, peer, route.Load(), DialOptions{})
		e2eExchange(t, dc, sc, 64<<10, 1)
		p1.Close()
		e2eDone(t, dc, 10*time.Second)
		var ae *AbortError
		if _, err := dc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
			t.Fatalf("dialer Read after the passive's Runtime.Close: %v", err)
		}
		if st := dc.Status(); st.Migrations != (MigrationCounts{}) || st.NoPathEpisodes != 0 {
			t.Fatalf("the dialer tried to recover from GOAWAY: %+v", st)
		}
		if !peer.goneAway(p1.InstanceID()) {
			t.Fatal("the Peer did not record the instance that went away")
		}
		wpNoState(t, p1)

		p2 := wpTestRuntime(t, Config{}, nil)
		route.Store(wpListen(t, p2, ListenConfig{}))
		dc2, sc2 := e2eOpen(t, peer, route.Load(), DialOptions{})
		if dc2.PeerInstance() != p2.InstanceID() {
			t.Fatalf("the new session reached %v, want the restarted instance %v", dc2.PeerInstance(), p2.InstanceID())
		}
		e2eExchange(t, dc2, sc2, 64<<10, 2)
		e2eFinish(t, dc2, sc2)
		d.Close()
		p2.Close()
		wpNoState(t, d)
		wpNoState(t, p2)
	})
}
