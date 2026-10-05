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
// net.ErrClosed, and the bubble ends with no goroutine left. Further
// cases: live sessions and Dials in flight; admission refusals in flight.
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

	// With admission refusals in flight (design §6.8 step 7, L52): a
	// scripted dialer's OPEN (mode 7) is refused BAD_REQUEST and one of
	// its JOINs UNKNOWN_SESSION, but the dialer never reads the answers, so
	// both refusals block in their write on the unbuffered pipes; a third
	// refusal (BAD_REQUEST) is read at once, and its carrier then waits in
	// the L05 drain for the dialer's EOF. Close gives the refusals still in
	// flight the close bound, min(1 s, DeadMax), then cuts them — each
	// dialer sees its conn closed — and joins their carriers: it returns
	// exactly at that bound with nothing abandoned, and no rendr goroutine
	// outlives it.
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		mute := wpConnect(t, ln, wpInst(0x61), 1)
		mute.hello(rt)
		mute.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 7, nil))
		muteJoin := wpConnect(t, ln, wpInst(0x61), 2)
		muteJoin.hello(rt)
		muteJoin.send(wire.TypeJoin, 0, wpJoin(wpSID(2), 1, 0))
		reader := wpConnect(t, ln, wpInst(0x61), 3)
		reader.hello(rt)
		reader.send(wire.TypeOpen, 0, wpOpen(wpSID(3), wire.KindStream, 7, nil))
		reader.expectOpenAck(wire.StatusBadRequest, wire.CodeBadMode)
		synctest.Wait()
		if _, by := rendrGoroutines(); by["github.com/FrankoonG/rendr/v2/internal/carrier.(*Conn).closer"] != 3 {
			t.Fatalf("stimulus: refusals in flight %v, want 3 carrier closers", by)
		}
		start := time.Now()
		rt.Close()
		if el, kill := time.Since(start), min(time.Second, rt.eff.cfg.DeadMax); el != kill {
			t.Fatalf("Runtime.Close took %v, want the close bound %v", el, kill)
		}
		for i, d := range []*wpDialer{mute, muteJoin, reader} {
			var b [1]byte
			if n, err := d.nc.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("dialer %d after Close: (%d, %v), want its conn closed", i+1, n, err)
			}
			d.close()
		}
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 {
			t.Fatalf("rendr goroutines after Close returned: %v", left)
		}
		if st := rt.Status(); st.Abandoned != 0 || rt.hsg.running() != 0 {
			t.Fatalf("after Close: %+v, %d handshake goroutines", st, rt.hsg.running())
		}
		wpNoState(t, rt)
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
			queued   = make(chan struct{}) // all five events are in the queue
		)
		rt = wpTestRuntime(t, Config{OnEvent: func(ev Event) {
			mu.Lock()
			seen = append(seen, ev.Seq)
			mu.Unlock()
			if ev.Seq == 2 {
				// The Close below must find events 3..5 queued: the worker
				// runs concurrently with the Emit loop.
				<-queued
				closeErr <- rt.Close()
				_ = rt.Status()
				closeErr <- rt.Close() // nested: returns at once
			}
		}}, nil)
		for i := range 5 {
			rt.ev.Emit(session.Event{Kind: session.EventCarrierUp, Session: wpSID(i), Carrier: uint32(i + 1), Time: time.Now()})
		}
		close(queued)
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
// the embedder's Write, is the only goroutine left. Further cases: a dial
// attempt stuck in a deaf conn's Read, an admission refusal stuck in the
// embedder's Write, a PREFACE_ACK refusal stuck in the embedder's Write,
// a handshake conn whose deadline setters wait for its Read (closed at
// once: its Close does not wait for its SetDeadline), and a handshake conn
// whose SetDeadline at its close never returns (joined and counted by
// Close). When the embedder calls finally return, the pool empties.
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

	// An admission refusal whose write ignores deadlines and Close: the
	// conn passes the handshake, but its OPEN_ACK(BAD_REQUEST) write blocks
	// in the embedder. Runtime.Close gives the refusal the close bound, cuts
	// it (the conn is closed: the dialer sees EOF), and AbandonWait later
	// counts the goroutine stuck in the embedder's Write in Status.Abandoned
	// before it returns. When the Write finally returns nothing is left and
	// the conn was closed exactly once.
	synctest.Test(t, func(t *testing.T) {
		const wait = 500 * time.Millisecond
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: wait})
		ln := wpListen(t, rt, ListenConfig{})
		a, b := net.Pipe()
		sw := &stuckWriteConn{Conn: a, release: make(chan struct{})}
		t.Cleanup(sw.free)
		if err := ln.Handle(sw); err != nil {
			t.Fatal(err)
		}
		d := &wpDialer{t: t, nc: b, inst: wpInst(0x65), id: 1, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
		t.Cleanup(d.close)
		d.hello(rt)
		d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 7, nil))
		synctest.Wait()
		if n := sw.writes.Load(); n != 2 {
			t.Fatalf("stimulus: %d writes, want the PREFACE_ACK and the stuck refusal", n)
		}
		start := time.Now()
		rt.Close()
		kill := min(time.Second, rt.eff.cfg.DeadMax)
		if el := time.Since(start); el != kill+wait {
			t.Fatalf("Runtime.Close took %v, want the close bound %v plus AbandonWait %v", el, kill, wait)
		}
		if n := rt.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d at Close's return, want the refusal stuck in the embedder's Write", n)
		}
		d.expectEOF()
		sw.free()
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 || rt.Status().Abandoned != 0 || sw.closes.Load() != 1 {
			t.Fatalf("after the Write returned: %v, abandoned %d, conn closed %d times", left, rt.Status().Abandoned, sw.closes.Load())
		}
		wpNoState(t, rt)
	})

	// A PREFACE_ACK refusal whose write ignores deadlines and Close (design
	// §0.11 Z3 and note 2): another major's PREFACE is answered
	// PREFACE_ACK(VERSION), written inline on the handshake goroutine and in
	// its slot, and that write blocks in the embedder. Past the handshake
	// deadline, the drain bound and AbandonWait the carrier's last resort
	// closes the conn (once; the dialer sees EOF instead of an answer), which
	// does not end the Write. Runtime.Close then gives the handshake the
	// close bound and counts the goroutine stuck in the Write in
	// Status.Abandoned before it returns, exactly once: by the handshake
	// group's join, not by the carrier's last resort as well (that counted 2
	// for 1). When the Write finally returns nothing is left and the conn was
	// closed exactly once. The exact Close duration and the attribution of
	// the count pin the current design: Z3's optional follow-up (counting a
	// stuck ReadHello refusal before Runtime.Close, as goWatched does) would
	// also end the goroutine's membership of the handshake group, so Close
	// would no longer wait for it, and must update both.
	synctest.Test(t, func(t *testing.T) {
		const wait = 500 * time.Millisecond
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: wait})
		ln := wpListen(t, rt, ListenConfig{})
		a, b := net.Pipe()
		sw := &stuckWriteConn{Conn: a, release: make(chan struct{})}
		sw.writes.Store(1) // every Write blocks: the refusal is the conn's first
		t.Cleanup(sw.free)
		if err := ln.Handle(sw); err != nil {
			t.Fatal(err)
		}
		d := &wpDialer{t: t, nc: b, inst: wpInst(0x66), id: 1, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
		t.Cleanup(d.close)
		p := wpPreface(d.inst, d.id)
		p[4] = 3 // another major: PREFACE_ACK(VERSION)

		// The write returns once the handshake read the PREFACE.
		if _, err := d.nc.Write(wpRecrc(p)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n, st := sw.writes.Load(), rt.Status(); n != 2 || st.Handshakes != 1 {
			t.Fatalf("stimulus: %d writes, %d handshake slots; want the refusal stuck in its write, in its slot", n-1, st.Handshakes)
		}
		time.Sleep(rt.eff.cfg.Handshake.Timeout + time.Second + wait) // past the refusal's last resort
		synctest.Wait()
		if n, st := sw.closes.Load(), rt.Status(); n != 1 || st.Handshakes != 1 {
			t.Fatalf("stimulus: conn closed %d times by the last resort, %d handshake slots; want closed once, the Write still stuck in its slot", n, st.Handshakes)
		}
		d.expectEOF()
		start := time.Now()
		rt.Close()
		kill := min(time.Second, rt.eff.cfg.DeadMax)
		if el := time.Since(start); el != kill+wait {
			t.Fatalf("Runtime.Close took %v, want the close bound %v plus AbandonWait %v", el, kill, wait)
		}
		if n := rt.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d at Close's return, want the refusal stuck in the embedder's Write counted once", n)
		}
		sw.free()
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 || rt.Status().Abandoned != 0 || sw.closes.Load() != 1 {
			t.Fatalf("after the Write returned: %v, abandoned %d, conn closed %d times", left, rt.Status().Abandoned, sw.closes.Load())
		}
		wpNoState(t, rt)
	})

	// A handshake conn whose deadline setters wait for a Read in progress
	// and whose Close ends that Read (design §0.14 B3): a websocket adapter
	// that honours gorilla's one-reader rule. The handshake waits in its
	// Read for a PREFACE that never comes. Runtime.Close's drain calls
	// SetDeadline(now) and Close on separate members of the handshake
	// group, so the Close does not wait behind the SetDeadline: the conn is
	// closed exactly once, while the Read is still in progress, and Close
	// returns within AbandonWait with nothing abandoned, no handshake slot
	// held and no rendr goroutine left. Before B3 the Close waited for the
	// SetDeadline, which waited for the Read, which ended only at the
	// handshake deadline: Close returned after its close bound with the
	// conn still open and both goroutines counted in Status.Abandoned.
	synctest.Test(t, func(t *testing.T) {
		const wait = 500 * time.Millisecond
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: wait})
		ln := wpListen(t, rt, ListenConfig{})
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() }) // a failed test still ends its bubble
		lc := newG4LockedConn(a)
		if err := ln.Handle(lc); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n, st := lc.inCall.Load(), rt.Status(); n != 1 || st.Handshakes != 1 {
			t.Fatalf("stimulus: %d calls in progress, %d handshake slots; want the handshake's Read, in its slot", n, st.Handshakes)
		}
		start := time.Now()
		rt.Close()
		el := time.Since(start)
		if n := lc.closes.Load(); n != 1 || el > wait {
			t.Fatalf("Runtime.Close took %v (bound %v), conn closed %d times; want once, within AbandonWait", el, wait, n)
		}
		if !lc.callAtClose.Load() {
			t.Fatal("the conn was closed only after the handshake's Read had ended")
		}
		if st := rt.Status(); st.Abandoned != 0 || st.Handshakes != 0 {
			t.Fatalf("after Close: %+v", st)
		}
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 || lc.closes.Load() != 1 || rt.Status().Abandoned != 0 {
			t.Fatalf("rendr goroutines left: %v; conn closed %d times, abandoned %d", left, lc.closes.Load(), rt.Status().Abandoned)
		}
		wpNoState(t, rt)
	})

	// A handshake conn whose SetDeadline(now) at its close never returns
	// until released (it ignores Close), while its Close works (design
	// §0.14 B3, L52). Runtime.Close's drain runs SetDeadline and Close on
	// separate watched members of the handshake group: the Close ends the
	// handshake's Read at once, and Close's join waits for the stuck
	// SetDeadline member until its watch counts it, AbandonWait after it
	// started, so Close returns then with it in Status.Abandoned. The failed
	// handshake's own close (ReadHello's) calls SetDeadline(now) too, on a
	// guarded goroutine its own watch counts at the same moment: exactly two
	// goroutines are counted once both watches ran. When the calls return
	// the pool empties and no rendr goroutine is left; the embedder's Close
	// ran once. A SetDeadline outside the handshake group would let Close
	// return at once, before any count.
	synctest.Test(t, func(t *testing.T) {
		const wait = 500 * time.Millisecond
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: wait})
		ln := wpListen(t, rt, ListenConfig{})
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() }) // a failed test still ends its bubble
		sd := &g4StuckDeadlineConn{Conn: a, release: make(chan struct{})}
		t.Cleanup(sd.free)
		if err := ln.Handle(sd); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n, st := sd.sets.Load(), rt.Status(); n != 1 || st.Handshakes != 1 {
			t.Fatalf("stimulus: %d SetDeadline calls, %d handshake slots; want the handshake deadline set, the handshake reading in its slot", n, st.Handshakes)
		}
		start := time.Now()
		rt.Close()
		el := time.Since(start)
		if n := rt.Status().Abandoned; el != wait || n < 1 {
			t.Fatalf("Runtime.Close took %v and returned with %d abandoned; want it to join the drain's stuck SetDeadline until it was counted, AbandonWait (%v)", el, n, wait)
		}
		synctest.Wait()
		if n, k, st := sd.closes.Load(), sd.sets.Load(), rt.Status(); n != 1 || k != 3 || st.Abandoned != 2 || st.Handshakes != 0 {
			t.Fatalf("conn closed %d times, %d SetDeadline calls, abandoned %d, %d handshake slots; want closed once, the drain's and ReadHello's SetDeadline(now) stuck and counted", n, k, st.Abandoned, st.Handshakes)
		}
		sd.free()
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 || rt.Status().Abandoned != 0 || sd.closes.Load() != 1 {
			t.Fatalf("after the SetDeadline calls returned: rendr goroutines %v, abandoned %d, conn closed %d times", left, rt.Status().Abandoned, sd.closes.Load())
		}
		wpNoState(t, rt)
	})
}

// g4StuckDeadlineConn passes its first SetDeadline — the handshake
// deadline ReadHello sets — to the wrapped conn; every later one, a close's
// SetDeadline(now), blocks until freed and ignores Close. Its Close closes
// the wrapped conn (L52, design §0.14 B3).
type g4StuckDeadlineConn struct {
	net.Conn
	release  chan struct{}
	freeOnce sync.Once
	sets     atomic.Int32
	closes   atomic.Int32
}

func (c *g4StuckDeadlineConn) SetDeadline(t time.Time) error {
	if c.sets.Add(1) == 1 {
		return c.Conn.SetDeadline(t)
	}
	<-c.release
	return nil
}

func (c *g4StuckDeadlineConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// free returns every blocked SetDeadline (idempotent).
func (c *g4StuckDeadlineConn) free() { c.freeOnce.Do(func() { close(c.release) }) }

// stuckWriteConn passes the handshake — reads, and its first write (the
// PREFACE_ACK), go through to a net.Pipe — but blocks every later Write,
// ignoring deadlines and Close, until freed (L52).
type stuckWriteConn struct {
	net.Conn
	writes   atomic.Int32
	closes   atomic.Int32
	release  chan struct{}
	freeOnce sync.Once
}

func (c *stuckWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) > 1 {
		<-c.release
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

func (c *stuckWriteConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func (c *stuckWriteConn) free() { c.freeOnce.Do(func() { close(c.release) }) }

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

// TestCloseDrainIsFinal_L52 (design §6.8 step 5, L52): no handshake starts
// after Runtime.Close drained the handshake slots. A Handle that counted
// its handshake before Close closed the Listener but takes its slot only
// after the drain (the window between Listener.Handle's two halves,
// widened here) gets no slot: its conn is closed at once, exactly once,
// on the handshake's own membership of the group Close joins. Close
// returns as soon as that close returned — no handshake waits for its
// deadline, none is abandoned or still holds a slot — and no rendr
// goroutine outlives it.
func TestCloseDrainIsFinal_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		a, b := net.Pipe()
		c := &countConn{Conn: a}
		if !ln.beginHandshake() { // Handle's first half: the handshake is counted
			t.Fatal("beginHandshake refused on an open Listener")
		}
		start := time.Now()
		closed := make(chan error, 1)
		go func() { closed <- rt.Close() }()
		synctest.Wait() // Close drained the slots and waits for the counted handshake
		select {
		case err := <-closed:
			t.Fatalf("Close returned (%v) while a counted handshake was still starting", err)
		default:
		}
		rt.startHandshake(ln, c, time.Now()) // Handle's second half, after the drain
		var buf [1]byte
		if n, err := b.Read(buf[:]); n != 0 || !errors.Is(err, io.EOF) || time.Since(start) != 0 {
			t.Fatalf("the conn of a handshake started after the drain: (%d, %v) after %v, want closed at once", n, err, time.Since(start))
		}
		if err := <-closed; err != nil || time.Since(start) != 0 {
			t.Fatalf("Close = %v after %v, want at once", err, time.Since(start))
		}
		synctest.Wait()
		if st := rt.Status(); st.Handshakes != 0 || st.Abandoned != 0 || c.closes.Load() != 1 {
			t.Fatalf("after Close: %+v, conn closed %d times", st, c.closes.Load())
		}
		if n, left := rendrGoroutines(); n != 0 {
			t.Fatalf("rendr goroutines after Close: %v", left)
		}
		b.Close()
	})
}

// TestEvictedCloseCounted_L52 (D20, L52): the Close of an evicted
// handshake's conn that never returns is counted in Status.Abandoned
// AbandonWait after the eviction while the Runtime runs — not only by a
// later Runtime.Close — so a stuck embedder Close is visible to the
// abandoned-call pool's fail-fast at once. It is counted exactly once:
// Runtime.Close neither waits for it nor counts it again, and when the
// embedder's Close returns the pool is empty. The conn is closed once.
func TestEvictedCloseCounted_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const wait = 500 * time.Millisecond
		rt := wpTestRuntime(t, Config{Handshake: HandshakeLimits{MaxConcurrent: 1}}, &testhooks.Overrides{AbandonWait: wait})
		ln := wpListen(t, rt, ListenConfig{})
		stuck := newMalConn(true, true) // its Read returns at Close; its Close blocks until freed
		t.Cleanup(stuck.free)
		if err := ln.Handle(stuck); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		d := wpConnect(t, ln, wpInst(0x62), 2) // the only slot is taken: stuck is evicted
		synctest.Wait()
		if st := rt.Status(); st.HandshakeEvictions != 1 || st.Abandoned != 0 || stuck.closes.Load() != 1 {
			t.Fatalf("after the eviction: %+v, stuck conn closed %d times", st, stuck.closes.Load())
		}
		time.Sleep(wait)
		synctest.Wait()
		if n := rt.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d AbandonWait after the eviction, want the stuck Close", n)
		}
		start := time.Now()
		rt.Close()
		if el := time.Since(start); el != 0 {
			t.Fatalf("Runtime.Close took %v: it waited for a closer that was already counted", el)
		}
		if n := rt.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d after Runtime.Close, want the one stuck Close counted once", n)
		}
		stuck.free()
		synctest.Wait()
		if st := rt.Status(); st.Abandoned != 0 || stuck.closes.Load() != 1 {
			t.Fatalf("after the Close returned: %+v, conn closed %d times", st, stuck.closes.Load())
		}
		d.close()
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 {
			t.Fatalf("rendr goroutines left: %v", left)
		}
	})
}

// TestCloseDeliversSessionEnds_L53 (design §6.8 W14): Runtime.Close joins
// the sessions it shut down before it closes the event queue, so the
// SessionEnd of every session Close ended is delivered — also when a
// session reaches its end decision only after Close reached its join. The
// actors of three sessions are held (Hooks.DeathObserved) when their
// carrier dies; Close then runs on a goroutine of its own (not the event
// callback) and is still waiting when the actors are released. Every
// session's events are delivered, its last one a SessionEnd with
// net.ErrClosed, all in Seq order with nothing dropped.
func TestCloseDeliversSessionEnds_L53(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 3
		release := make(chan struct{})
		var releaseOnce sync.Once
		free := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(free)
		var held atomic.Int32
		hooks := &testhooks.Hooks{DeathObserved: func(uint32) {
			held.Add(1)
			<-release
		}}
		var log eventLog
		d := wpTestRuntime(t, Config{OnEvent: log.add}, &testhooks.Overrides{Hooks: hooks})
		p := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, p, ListenConfig{})
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: ln.Handle})
		t.Cleanup(link.Close)
		peer, err := d.NewPeer(PeerConfig{Carriers: []Carrier{e2eCarrier(link)}})
		if err != nil {
			t.Fatal(err)
		}
		ids := map[SessionID]bool{}
		var ends []*Conn
		for range n {
			dc, sc := e2eOpen(t, peer, ln, DialOptions{})
			ids[dc.ID()] = true
			ends = append(ends, sc)
		}
		link.SetRefuse(true)
		if k := link.Kill(); k != n {
			t.Fatalf("killed %d carriers, want %d", k, n)
		}
		synctest.Wait()
		if h := held.Load(); h != n {
			t.Fatalf("stimulus: %d actors held in their death step, want %d", h, n)
		}
		closed := make(chan struct{})
		go func() {
			d.Close()
			close(closed)
		}()
		synctest.Wait() // Close posted the shutdowns and waits in its join
		select {
		case <-closed:
			t.Fatal("Runtime.Close returned while every session's actor was held")
		default:
		}
		free()
		<-closed
		evs := log.all()
		last := map[SessionID]Event{}
		for i, ev := range evs {
			if ev.Seq != uint64(i+1) || !ids[ev.Session] {
				t.Fatalf("event %d: %+v (want Seq %d of one of the sessions)", i, ev, i+1)
			}
			last[ev.Session] = ev
		}
		for id := range ids {
			ev, ok := last[id]
			if !ok || ev.Kind != EventSessionEnd || !errors.Is(ev.Err, net.ErrClosed) {
				t.Fatalf("session %v: last event %+v, want its SessionEnd (net.ErrClosed): %+v", id, ev, evs)
			}
		}
		if st := d.Status(); st.EventsDropped != 0 || st.Abandoned != 0 {
			t.Fatalf("dialer %+v", st)
		}
		for _, sc := range ends {
			sc.Close()
		}
		p.Close()
		link.Close()
		wpNoState(t, d)
		wpNoState(t, p)
	})
}

// g4LockedConn wraps a net.Conn the way a websocket adapter that honours
// gorilla's one-reader and one-writer rule does (design §0.14 B3): Read
// holds the read lock and Write the write lock for the whole call, and the
// deadline setters are read or write methods — SetReadDeadline takes the
// read lock, SetWriteDeadline the write lock, SetDeadline both — so a
// setter waits while a Read or Write is in progress. A deadline set before
// a call applies to it (it goes to the wrapped conn), and Close, which may
// be called at any time, closes the wrapped conn and so ends a Read or
// Write in progress. The locks are 1-slot channels: a waiting setter is
// durably blocked in a synctest bubble.
type g4LockedConn struct {
	net.Conn
	rd, wr chan struct{}
	inCall atomic.Int32 // Reads and Writes in progress

	closes      atomic.Int32
	callAtClose atomic.Bool // a Read or Write was in progress at the first Close
}

func newG4LockedConn(nc net.Conn) *g4LockedConn {
	return &g4LockedConn{Conn: nc, rd: make(chan struct{}, 1), wr: make(chan struct{}, 1)}
}

func (c *g4LockedConn) Read(p []byte) (int, error) {
	c.rd <- struct{}{}
	defer func() { <-c.rd }()
	c.inCall.Add(1)
	defer c.inCall.Add(-1)
	return c.Conn.Read(p)
}

func (c *g4LockedConn) Write(p []byte) (int, error) {
	c.wr <- struct{}{}
	defer func() { <-c.wr }()
	c.inCall.Add(1)
	defer c.inCall.Add(-1)
	return c.Conn.Write(p)
}

func (c *g4LockedConn) SetReadDeadline(t time.Time) error {
	c.rd <- struct{}{}
	defer func() { <-c.rd }()
	return c.Conn.SetReadDeadline(t)
}

func (c *g4LockedConn) SetWriteDeadline(t time.Time) error {
	c.wr <- struct{}{}
	defer func() { <-c.wr }()
	return c.Conn.SetWriteDeadline(t)
}

func (c *g4LockedConn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if werr := c.SetWriteDeadline(t); err == nil {
		err = werr
	}
	return err
}

func (c *g4LockedConn) Close() error {
	if c.closes.Add(1) == 1 {
		c.callAtClose.Store(c.inCall.Load() > 0)
	}
	return c.Conn.Close()
}

// TestG4LockedConnCarrierEndsClosed_L52 (design §0.14 B3, L51, L52):
// carriers whose conns' deadline setters wait for a Read in progress, and
// whose Close ends that Read, end while the Runtimes run, on a path that
// stays silent; the reader of a carrier reads with no deadline. Each such
// conn is closed exactly once, while its reader's Read is still in
// progress, Status.Abandoned stays at zero, and Runtime.Close leaves no
// rendr goroutine. Cases: an open selector session over a link that is
// blackholed after an exchange — the passive's carrier dies of
// ping_timeout, and its close then reaches the dialer — and a pending
// session whose silent dialer stops sending after its OPEN,
// refused at AcceptTimeout (its carrier retires: OPEN_ACK, CLOSE, then the
// drain bound). Before B3 the carrier's closer called Close only after
// SetDeadline returned, which waited for the Read, which never ended: the
// conn stayed open, its reader and closer were counted in Status.Abandoned
// and outlived Runtime.Close until the path closed, and 128 such ends
// filled the abandoned-call pool.
func TestG4LockedConnCarrierEndsClosed_L52(t *testing.T) {
	const wait = 500 * time.Millisecond
	t.Run("silent-path death", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// The dialer's death deadline is a minute: the passive's carrier
			// dies of ping_timeout first. A Link shuts a carrier when either
			// end closes, so its close then reaches the dialer as EOF.
			dov := &testhooks.Overrides{AbandonWait: wait, DeadMin: time.Minute, DeadMax: time.Minute}
			pov := &testhooks.Overrides{AbandonWait: wait}
			e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, dov), p: wpTestRuntime(t, Config{}, pov)}
			e.ln = wpListen(t, e.p, ListenConfig{})
			passive := make(chan *g4LockedConn, 16) // every carrier the link hands to the passive
			dialed := make(chan *g4LockedConn, 64)  // every carrier the dialer's factory made
			link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "ws", Accept: func(nc net.Conn) error {
				lc := newG4LockedConn(nc)
				passive <- lc
				return e.ln.Handle(lc)
			}})
			e.links = append(e.links, link)
			t.Cleanup(link.Close)
			p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "ws", Dial: func(ctx context.Context) (net.Conn, error) {
				nc, err := link.Dial(ctx)
				if err != nil {
					return nil, err
				}
				lc := newG4LockedConn(nc)
				dialed <- lc
				return lc, nil
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			dc, sc := e2eOpen(t, p, e.ln, DialOptions{})
			e2eExchange(t, dc, sc, 64<<10, 1)
			dlc, plc := <-dialed, <-passive
			link.SetBlackhole(true) // nothing arrives any more; nothing is closed
			time.Sleep(30 * time.Second)
			synctest.Wait()
			if st := sc.Status(); len(st.Carriers) == 0 || st.Carriers[0].DeathCause != CausePingTimeout {
				t.Fatalf("stimulus: passive carriers %+v, want the first dead of ping_timeout", st.Carriers)
			}
			if n := plc.closes.Load(); n != 1 || !plc.callAtClose.Load() {
				t.Fatalf("the passive's dead carrier: conn closed %d times (Read in progress then: %v); want once, while its reader waited", n, plc.callAtClose.Load())
			}
			// The close reached the dialer (EOF): its carrier died and its
			// conn was closed once as well.
			if st := dc.Status(); len(st.Carriers) == 0 || st.Carriers[0].DeathCause != CauseTransportError || dlc.closes.Load() != 1 {
				t.Fatalf("dialer carriers %+v, conn closed %d times; want the first dead of the passive's close (EOF), closed once", st.Carriers, dlc.closes.Load())
			}
			for _, rt := range []*Runtime{e.p, e.d} {
				if n := rt.Status().Abandoned; n != 0 {
					t.Fatalf("abandoned %d after the carriers died", n)
				}
			}
			e.close()
			synctest.Wait()
			if n, left := rendrGoroutines(); n != 0 {
				t.Fatalf("rendr goroutines after both Close calls: %v", left)
			}
			for _, rt := range []*Runtime{e.d, e.p} {
				if n := rt.Status().Abandoned; n != 0 {
					t.Fatalf("abandoned %d after Close", n)
				}
			}
			for _, ch := range []chan *g4LockedConn{dialed, passive} {
				for len(ch) > 0 {
					if lc := <-ch; lc.closes.Load() != 1 {
						t.Fatalf("a later carrier's conn was closed %d times", lc.closes.Load())
					}
				}
			}
		})
	})
	t.Run("pending session refused at AcceptTimeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: wait})
			ln := wpListen(t, rt, ListenConfig{AcceptTimeout: time.Second})
			passive := make(chan *g4LockedConn, 1)
			link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "ws", Accept: func(nc net.Conn) error {
				lc := newG4LockedConn(nc)
				passive <- lc
				return ln.Handle(lc)
			}})
			t.Cleanup(link.Close)
			nc, err := link.Dial(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			d := &wpDialer{t: t, nc: nc, inst: wpInst(0x67), id: 1, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
			d.hello(rt)
			d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 1, nil))
			synctest.Wait() // the application never accepts; the dialer sends nothing more
			plc := <-passive
			if n, st := plc.inCall.Load(), rt.Status(); n != 1 || st.Sessions.Pending != 1 {
				t.Fatalf("stimulus: %d calls in progress, %d pending sessions; want the held carrier's Read, one pending session", n, st.Sessions.Pending)
			}
			d.expectOpenAck(wire.StatusCapacity, wire.CodeAcceptTimeout)
			d.expect(wire.TypeClose) // then the dialer neither sends nor closes
			time.Sleep(time.Second)  // past the retirement's drain bound
			synctest.Wait()
			if n := plc.closes.Load(); n != 1 || !plc.callAtClose.Load() {
				t.Fatalf("the refused carrier's conn closed %d times (Read in progress then: %v); want once, while its reader waited", n, plc.callAtClose.Load())
			}
			if st := rt.Status(); st.Abandoned != 0 || st.Sessions.Pending != 0 {
				t.Fatalf("after the refusal: %+v", st)
			}
			d.expectEOF()
			rt.Close()
			synctest.Wait()
			if n, left := rendrGoroutines(); n != 0 || rt.Status().Abandoned != 0 || plc.closes.Load() != 1 {
				t.Fatalf("after Close: rendr goroutines %v, abandoned %d, conn closed %d times", left, rt.Status().Abandoned, plc.closes.Load())
			}
			d.close()
			link.Close()
			wpNoState(t, rt)
		})
	})
}

// TestG4LockedConnWithdrawnDial_L49_L52 (design §0.14 B3, L49, L52):
// Runtime.Close while a Dial's OPEN is pending on the passive, whose
// application never accepts, over a conn whose deadline setters wait for a
// Read in progress and whose Close ends that Read. Close withdraws the
// Dial; the attempt's withdrawal unblocks the handshake's response Read
// with SetDeadline(now) on a goroutine of its own, which waits behind that
// Read, and closes the conn when the handshake has not left it 1 s (the
// carrier's drain bound) later, without the best-effort RST: the passive
// reads EOF. The conn is closed exactly once, while the Read is in
// progress; Runtime.Close returns 1 s after it began with nothing
// abandoned; no rendr goroutine is left after both Runtimes closed. Before
// the fix the withdrawal's own goroutine was held in that SetDeadline
// until its last resort (AbandonWait + 3 s), so the session gave up on the
// attempt at 2·AbandonWait and Close returned after 2 s with the attempt
// counted in Status.Abandoned (a transient count for every such Dial).
func TestG4LockedConnWithdrawnDial_L49_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const drainBound = time.Second // the carrier's drain bound (production AbandonWait is 1 s too)
		e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, nil), p: wpTestRuntime(t, Config{}, nil)}
		e.ln = wpListen(t, e.p, ListenConfig{}) // nothing accepts: the OPEN stays pending
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "ws", Accept: e.ln.Handle})
		e.links = append(e.links, link)
		t.Cleanup(link.Close)
		dialed := make(chan *g4LockedConn, 16) // every carrier the dialer's factory made
		p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "ws", Dial: func(ctx context.Context) (net.Conn, error) {
			nc, err := link.Dial(ctx)
			if err != nil {
				return nil, err
			}
			lc := newG4LockedConn(nc)
			dialed <- lc
			return lc, nil
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		res := e2eDialAsync(context.Background(), p, DialOptions{})
		synctest.Wait() // the OPEN is pending; the attempt waits in its response Read
		if n, st := len(dialed), e.p.Status(); n != 1 || st.Sessions.Pending != 1 {
			t.Fatalf("stimulus: %d carriers dialed, %d pending sessions; want one OPEN, pending", n, st.Sessions.Pending)
		}
		dlc := <-dialed
		if n := dlc.inCall.Load(); n != 1 {
			t.Fatalf("stimulus: %d calls in progress, want the attempt's response Read", n)
		}
		start := time.Now()
		e.d.Close()
		el := time.Since(start)
		if r := <-res; r.c != nil || !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("Dial at Close: %v, %v", r.c, r.err)
		}
		if n := e.d.Status().Abandoned; el != drainBound || n != 0 {
			t.Fatalf("Runtime.Close took %v and returned with %d abandoned; want %v and nothing abandoned", el, n, drainBound)
		}
		if n := dlc.closes.Load(); n != 1 || !dlc.callAtClose.Load() {
			t.Fatalf("the attempt's conn closed %d times (Read in progress then: %v); want once, while the Read waited", n, dlc.callAtClose.Load())
		}
		e.close() // both Runtimes hold nothing and abandoned nothing
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 || dlc.closes.Load() != 1 {
			t.Fatalf("rendr goroutines after both Close calls: %v; the attempt's conn closed %d times", left, dlc.closes.Load())
		}
	})
}
