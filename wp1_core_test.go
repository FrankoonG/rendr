package rendr

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP1 (m4-design §A2.1, §A5.4, §A12.1): the root side of Conn.Abort,
// Conn.SetIdleTimeout and PendingConn.Context. Helpers start with "c4".

// c4PendingExit is one way a pending session leaves StatePending.
type c4PendingExit struct {
	name     string
	deadline bool // AcceptTimeout ended it: Err is DeadlineExceeded
	exit     func(t *testing.T, rt *Runtime, ln *Listener, pc *PendingConn, d *wpDialer)
}

func c4PendingExits() []c4PendingExit {
	return []c4PendingExit{
		{name: "Confirm", exit: func(t *testing.T, _ *Runtime, _ *Listener, pc *PendingConn, _ *wpDialer) {
			if _, err := pc.Confirm(); err != nil {
				t.Fatalf("Confirm: %v", err)
			}
		}},
		{name: "Reject", exit: func(t *testing.T, _ *Runtime, _ *Listener, pc *PendingConn, _ *wpDialer) {
			if err := pc.Reject(4000, "no"); err != nil {
				t.Fatalf("Reject: %v", err)
			}
		}},
		{name: "AcceptTimeout", deadline: true, exit: func(*testing.T, *Runtime, *Listener, *PendingConn, *wpDialer) {
			time.Sleep(c4AcceptTimeout)
		}},
		{name: "withdrawal", exit: func(t *testing.T, _ *Runtime, _ *Listener, _ *PendingConn, d *wpDialer) {
			d.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), ""))
		}},
		{name: "Listener.Close", exit: func(t *testing.T, _ *Runtime, ln *Listener, _ *PendingConn, _ *wpDialer) {
			ln.Close()
		}},
		{name: "Runtime.Close", exit: func(t *testing.T, rt *Runtime, _ *Listener, _ *PendingConn, _ *wpDialer) {
			rt.Close()
		}},
	}
}

const c4AcceptTimeout = 2 * time.Second

// c4Pending admits one stream OPEN from a scripted dialer on ln and
// accepts it. The dialer's carrier is read in the background until the
// passive ends it (the returned channel closes then).
func c4Pending(t *testing.T, rt *Runtime, ln *Listener, sid int) (*PendingConn, *wpDialer, time.Time, <-chan struct{}) {
	t.Helper()
	d := wpConnect(t, ln, wpInst(0x4c), uint32(sid))
	d.hello(rt)
	admitted := time.Now()
	d.send(wire.TypeOpen, 0, wpOpen(wpSID(sid), wire.KindStream, 1, nil))
	pc, err := ln.Accept(t.Context())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		d.drain()
	}()
	return pc, d, admitted, drained
}

// TestPendingContextDone (M4-D22, R1-8): each of the six exits from the
// pending phase closes the pending context's Done exactly once, at the
// exit (the AcceptTimeout one at the Deadline); Err is nil before, then
// context.DeadlineExceeded for AcceptTimeout and context.Canceled for every
// other exit; Deadline is the AcceptTimeout instant throughout; every call
// returns the same context; AfterFunc callbacks and derived contexts
// follow it once, and a stopped callback never runs.
func TestPendingContextDone(t *testing.T) {
	for _, x := range c4PendingExits() {
		t.Run(x.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				ln := wpListen(t, rt, ListenConfig{AcceptTimeout: c4AcceptTimeout})
				pc, d, admitted, drained := c4Pending(t, rt, ln, 1)
				ctx := pc.Context()
				if ctx != pc.Context() {
					t.Fatal("two calls returned different contexts")
				}
				dl, ok := ctx.Deadline()
				if !ok || dl.Before(admitted.Add(c4AcceptTimeout)) || dl.After(time.Now().Add(c4AcceptTimeout)) {
					t.Fatalf("Deadline %v (%v), want the AcceptTimeout instant, %v after the admission", dl.Sub(admitted), ok, c4AcceptTimeout)
				}
				if err := ctx.Err(); err != nil {
					t.Fatalf("Err while pending: %v", err)
				}
				var ran, stopped atomic.Int32
				context.AfterFunc(ctx, func() { ran.Add(1) })
				stop := context.AfterFunc(ctx, func() { stopped.Add(1) })
				if !stop() || stop() {
					t.Fatal("stop: want true once, then false")
				}
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				timed, cancelT := context.WithTimeout(ctx, time.Hour) // later than the parent's deadline
				defer cancelT()
				synctest.Wait()
				select {
				case <-ctx.Done():
					t.Fatal("Done closed while pending")
				default:
				}

				x.exit(t, rt, ln, pc, d)
				synctest.Wait()
				select {
				case <-ctx.Done():
				default:
					t.Fatalf("Done still open after %s", x.name)
				}
				want := context.Canceled
				if x.deadline {
					want = context.DeadlineExceeded
					if now := time.Now(); !now.Equal(dl) {
						t.Fatalf("AcceptTimeout ended the pending phase %v off its Deadline", now.Sub(dl))
					}
				}
				if err := ctx.Err(); err != want {
					t.Fatalf("Err after %s: %v, want %v", x.name, err, want)
				}
				if dl2, ok2 := ctx.Deadline(); dl2 != dl || !ok2 {
					t.Fatalf("Deadline changed to %v (%v)", dl2, ok2)
				}
				if ran.Load() != 1 || stopped.Load() != 0 {
					t.Fatalf("AfterFunc ran %d times, the stopped one %d; want 1 and 0", ran.Load(), stopped.Load())
				}
				for _, c := range []context.Context{child, timed} {
					if err := c.Err(); err != want {
						t.Fatalf("a derived context's Err: %v, want %v", err, want)
					}
				}
				// Registered after the exit through the context's AfterFunc
				// method, as the context package does when the session leaves
				// pending between its Done check and that call (with Done
				// already closed, context.AfterFunc starts f itself and never
				// calls the method): f runs once on its own goroutine and stop
				// reports false.
				var late atomic.Int32
				af, ok := pc.Context().(interface{ AfterFunc(func()) func() bool })
				if !ok {
					t.Fatal("the pending context has no AfterFunc method")
				}
				stopLate := af.AfterFunc(func() { late.Add(1) })
				synctest.Wait()
				if late.Load() != 1 {
					t.Fatalf("an AfterFunc registered after the exit ran %d times, want 1", late.Load())
				}
				if stopLate() {
					t.Fatal("stop of an AfterFunc registered after the exit reported true")
				}
				rt.Close()
				d.close()
				<-drained
				synctest.Wait()
			})
		})
	}
}

// c4PropagateGoroutines counts the goroutines the context package started
// to watch a parent that has no AfterFunc method.
func c4PropagateGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return bytes.Count(buf[:n], []byte("created by context.(*cancelCtx).propagateCancel"))
		}
		buf = make([]byte, 2*len(buf))
	}
}

// TestPendingContextNoGoroutine (M4-D22, R1-8): context.AfterFunc and the
// contexts WithCancel, WithDeadline (earlier and later than the pending
// deadline) and WithTimeout derive from the pending context start no
// goroutine; they are cancelled through the session's registrations when
// the pending phase ends.
func TestPendingContextNoGoroutine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{AcceptTimeout: c4AcceptTimeout})
		pc, d, _, drained := c4Pending(t, rt, ln, 1)
		ctx := pc.Context()
		synctest.Wait()
		before := c4PropagateGoroutines()
		var ran atomic.Int32
		context.AfterFunc(ctx, func() { ran.Add(1) })
		derived := make([]context.Context, 0, 4)
		c1, cancel1 := context.WithCancel(ctx)
		defer cancel1()
		c2, cancel2 := context.WithDeadline(ctx, time.Now().Add(time.Second))
		defer cancel2()
		c3, cancel3 := context.WithDeadline(ctx, time.Now().Add(time.Hour))
		defer cancel3()
		c4, cancel4 := context.WithTimeout(c1, time.Minute) // a grandchild
		defer cancel4()
		derived = append(derived, c1, c2, c3, c4)
		synctest.Wait()
		if n := c4PropagateGoroutines() - before; n != 0 {
			t.Fatalf("%d goroutines started to watch the pending context, want 0", n)
		}
		if _, err := pc.Confirm(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if ran.Load() != 1 {
			t.Fatalf("AfterFunc ran %d times, want 1", ran.Load())
		}
		for i, c := range derived {
			if err := c.Err(); err != context.Canceled {
				t.Fatalf("derived context %d: Err %v, want context.Canceled", i, err)
			}
		}
		rt.Close()
		d.close()
		<-drained
		synctest.Wait()
	})
}

// TestConnAbortReservedCode (M4-D20): an Abort code below 256 is rendr's:
// Abort returns an error and does nothing (no RST on the wire, the session
// keeps working both ways); a code of 256 or more resets the session and
// reaches the peer as *AbortError{code, msg, Remote}.
func TestConnAbortReservedCode(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		defer e.close()
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		dc, pc := mxOpen(t, p, e.ln, DialOptions{})
		for _, code := range []AbortCode{0, AbortClosed, AbortWithdrawn, 255} {
			if err := dc.Abort(code, "reserved"); err == nil {
				t.Fatalf("Abort(%d): nil, want an error", code)
			}
		}
		e2eExchange(t, dc, pc, 64<<10, 1)
		e2eExchange(t, pc, dc, 64<<10, 2)
		synctest.Wait()
		if n := len(mxFrames(taps.tap(t, 0), rendrtest.Up, rendrtest.FrameRst, 1)); n != 0 {
			t.Fatalf("%d RST frames after refused Aborts, want none", n)
		}
		if st := dc.Status(); st.State != StateOpen {
			t.Fatalf("state %v after refused Aborts, want open", st.State)
		}
		if err := dc.Abort(256, "first application code"); err != nil {
			t.Fatalf("Abort(256): %v", err)
		}
		var b [1]byte
		_, err := pc.Read(b[:])
		var ae *AbortError
		if !errors.As(err, &ae) || ae.Code != 256 || ae.Msg != "first application code" || !ae.Remote {
			t.Fatalf("the peer's Read: %v, want *AbortError{256, msg, Remote}", err)
		}
		if _, err := dc.Write(b[:]); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after Abort: %v, want net.ErrClosed", err)
		}
		e2eDone(t, dc, 5*time.Second)
		e2eDone(t, pc, 5*time.Second)
		if n := len(mxFrames(taps.tap(t, 0), rendrtest.Up, rendrtest.FrameRst, 1)); n != 1 {
			t.Fatalf("%d RST frames, want 1", n)
		}
	})
}

// TestConnSetIdleTimeout (M4-D21): Conn.SetIdleTimeout applies the
// Runtime's clamp floor (testhooks.MinIdleTimeout lowers it) and expires
// a quiet session at the new limit: ErrIdleTimeout here, AbortIdle at the
// peer.
func TestConnSetIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := &testhooks.Overrides{MinIdleTimeout: time.Second}
		e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
		defer e.close()
		dc, pc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
		opened := time.Now()
		if err := dc.SetIdleTimeout(100 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		e2eDone(t, dc, 10*time.Second)
		if el := time.Since(opened); el < time.Second || el > 3*time.Second {
			t.Fatalf("the session ended %v after the open, want about 1 s (the lowered floor)", el)
		}
		if err := dc.Status().Err; !errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("end error %v, want ErrIdleTimeout", err)
		}
		e2eDone(t, pc, 5*time.Second)
		var ae *AbortError
		if err := pc.Status().Err; !errors.As(err, &ae) || ae.Code != AbortIdle || !ae.Remote {
			t.Fatalf("the peer's end error %v, want *AbortError{AbortIdle, Remote}", err)
		}
		if err := dc.SetIdleTimeout(time.Minute); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SetIdleTimeout after the end: %v, want net.ErrClosed", err)
		}
	})
}
