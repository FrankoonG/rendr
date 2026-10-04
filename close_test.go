package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
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
	once       sync.Once
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
func (c *malConn) Write([]byte) (int, error) { <-c.release; return 0, io.ErrClosedPipe }

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

// free returns every blocked call.
func (c *malConn) free() { close(c.release) }

// TestMaliciousConnsCloseBounded_L52 (the handshake part; the session-lane
// part follows the session actor): Runtime.Close returns within its bound
// although handshakes hold malicious embedder conns — one whose Read
// ignores deadlines and Close, one whose Read honours only Close, one
// whose Close blocks — and counts exactly the goroutines stuck in embedder
// code in Status.Abandoned; each conn is closed at most once; when the
// embedder calls finally return, the pool empties.
func TestMaliciousConnsCloseBounded_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: 500 * time.Millisecond})
		ln := wpListen(t, rt, ListenConfig{})
		deaf := newMalConn(false, false)     // Read ignores deadlines and Close: the handshake goroutine is stuck
		closeOnly := newMalConn(true, false) // Read returns at Close: released by Close's drain
		stuckClose := newMalConn(true, true) // Close blocks: the guarded closer goroutine is stuck
		for _, c := range []*malConn{deaf, closeOnly, stuckClose} {
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
}
