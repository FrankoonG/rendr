package rendr

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP1 (m6-design §A2.1, §A16.1; M6-D6): the root side of
// PendingPacket.Context, the packet twin of M4's PendingConn.Context.
// Helpers start with "c6".

// c6PendingPacket is a pending packet session accepted on ln with the way
// its dialer withdraws it, either a scripted dialer on a stream carrier or
// a real DialPacket over a datagram carrier.
type c6PendingPacket struct {
	pp       *PendingPacket
	admitted time.Time // no later than the passive admitted the OPEN
	accepted time.Time // no earlier than it
	withdraw func()    // the dialer withdraws its OPEN (RST(Withdrawn))
	finish   func()    // ends the dialer side and joins it (after the test closed rt)
}

// c6PendingVia names the two carrier kinds a pending packet session is
// tested on and builds one on rt and ln.
var c6PendingVia = []struct {
	name string
	open func(t *testing.T, rt *Runtime, ln *Listener) c6PendingPacket
}{
	{"stream carrier", c6PendingScripted},
	{"datagram carrier", c6PendingDialed},
}

// c6PendingScripted admits a packet OPEN (no cmtu offer, MaxPayload 1127)
// from a scripted dialer on a stream carrier pushed into ln and accepts
// it; the carrier is read in the background until the passive ends it.
func c6PendingScripted(t *testing.T, rt *Runtime, ln *Listener) c6PendingPacket {
	t.Helper()
	d := wpConnect(t, ln, wpInst(0x6c), 1)
	d.hello(rt)
	admitted := time.Now()
	d.send(wire.TypeOpen, 0, wdPacketOpen(wpSID(61), 1, 0, 1127))
	pp, err := ln.AcceptPacket(t.Context())
	if err != nil {
		t.Fatalf("AcceptPacket: %v", err)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		d.drain()
	}()
	return c6PendingPacket{
		pp: pp, admitted: admitted, accepted: time.Now(),
		withdraw: func() { d.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), "")) },
		finish: func() {
			d.close()
			<-drained
		},
	}
}

// c6PendingDialed dials a packet session from a second Runtime over a
// DatagramLink whose passive ends enter ln through HandlePacket and
// accepts it; cancelling the dial's context withdraws it.
func c6PendingDialed(t *testing.T, rt *Runtime, ln *Listener) c6PendingPacket {
	t.Helper()
	drt := wpTestRuntime(t, Config{}, nil)
	link := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "pend", Accept: ln.HandlePacket})
	t.Cleanup(func() { link.Close() })
	p, err := drt.NewPeer(PeerConfig{Carriers: []Carrier{peDatagramCarrier(link, 1400)}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	admitted := time.Now()
	dialed := make(chan peDialed, 1)
	go func() {
		c, err := p.DialPacket(ctx, DialOptions{})
		dialed <- peDialed{c, err}
	}()
	pp, err := ln.AcceptPacket(t.Context())
	if err != nil {
		t.Fatalf("AcceptPacket: %v", err)
	}
	return c6PendingPacket{
		pp: pp, admitted: admitted, accepted: time.Now(),
		withdraw: cancel,
		finish: func() {
			cancel()
			if r := <-dialed; r.c != nil {
				r.c.Close()
			}
			drt.Close()
			link.Close()
		},
	}
}

// c6PendingExit is one way a pending packet session leaves StatePending.
type c6PendingExit struct {
	name     string
	deadline bool // AcceptTimeout ended it: Err is DeadlineExceeded
	exit     func(t *testing.T, rt *Runtime, ln *Listener, p c6PendingPacket)
}

func c6PendingExits() []c6PendingExit {
	return []c6PendingExit{
		{name: "Confirm", exit: func(t *testing.T, _ *Runtime, _ *Listener, p c6PendingPacket) {
			if _, err := p.pp.Confirm(); err != nil {
				t.Fatalf("Confirm: %v", err)
			}
		}},
		{name: "Reject", exit: func(t *testing.T, _ *Runtime, _ *Listener, p c6PendingPacket) {
			if err := p.pp.Reject(4000, "no"); err != nil {
				t.Fatalf("Reject: %v", err)
			}
		}},
		{name: "AcceptTimeout", deadline: true, exit: func(*testing.T, *Runtime, *Listener, c6PendingPacket) {
			time.Sleep(c4AcceptTimeout)
		}},
		{name: "withdrawal", exit: func(_ *testing.T, _ *Runtime, _ *Listener, p c6PendingPacket) {
			p.withdraw()
		}},
		{name: "Listener.Close", exit: func(_ *testing.T, _ *Runtime, ln *Listener, _ c6PendingPacket) {
			ln.Close()
		}},
		{name: "Runtime.Close", exit: func(_ *testing.T, rt *Runtime, _ *Listener, _ c6PendingPacket) {
			rt.Close()
		}},
	}
}

// TestPendingPacketContext_L49_L50 (M6-D6, R1-19; L49, L50; m6-design
// Appendix C A-3): PendingPacket.Context has PendingConn.Context's
// contract on a pending packet session, over a stream and over a datagram
// carrier. Each of the six exits from the pending phase closes Done
// exactly once, at the exit (the AcceptTimeout one at the Deadline); Err
// is nil before, then context.DeadlineExceeded for AcceptTimeout and
// context.Canceled for every other exit; Deadline is the AcceptTimeout
// instant throughout; every call returns the same context, without
// allocating; context.AfterFunc and the contexts WithCancel, WithDeadline
// (earlier and later than the pending deadline) and WithTimeout derive
// from it start no goroutine, and they follow it once (a stopped callback
// never runs; one registered after the exit runs once); its String names
// PendingPacket, and PendingConn's still names PendingConn.
func TestPendingPacketContext_L49_L50(t *testing.T) {
	for _, via := range c6PendingVia {
		for _, x := range c6PendingExits() {
			t.Run(via.name+"/"+x.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					rt := wpTestRuntime(t, Config{}, nil)
					ln := wpListen(t, rt, ListenConfig{AcceptTimeout: c4AcceptTimeout})
					p := via.open(t, rt, ln)
					c6CheckPendingContext(t, x, rt, ln, p)
					rt.Close()
					p.finish()
					synctest.Wait()
				})
			})
		}
	}
	t.Run("String", func(t *testing.T) {
		if s := fmt.Sprint((&PendingConn{}).Context()); s != "rendr.PendingConn.Context" {
			t.Fatalf("PendingConn's context is %q, want rendr.PendingConn.Context", s)
		}
	})
}

// c6Sink keeps a context alive past AllocsPerRun's function, so that the
// conversion to the interface cannot be optimised away.
var c6Sink context.Context

// c6CheckPendingContext runs TestPendingPacketContext_L49_L50's checks on
// p's pending context around the exit x.
func c6CheckPendingContext(t *testing.T, x c6PendingExit, rt *Runtime, ln *Listener, p c6PendingPacket) {
	t.Helper()
	pp := p.pp
	ctx := pp.Context()
	if ctx != pp.Context() {
		t.Fatal("two calls returned different contexts")
	}
	if n := testing.AllocsPerRun(10, func() { c6Sink = pp.Context() }); n != 0 {
		t.Fatalf("Context allocates %v times per call, want 0", n)
	}
	c6Sink = nil
	if s := fmt.Sprint(ctx); s != "rendr.PendingPacket.Context" {
		t.Fatalf("the context's String is %q, want rendr.PendingPacket.Context", s)
	}
	dl, ok := ctx.Deadline()
	if !ok || dl.Before(p.admitted.Add(c4AcceptTimeout)) || dl.After(p.accepted.Add(c4AcceptTimeout)) {
		t.Fatalf("Deadline %v after the dial (%v), want the AcceptTimeout instant, %v after the admission", dl.Sub(p.admitted), ok, c4AcceptTimeout)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("Err while pending: %v", err)
	}

	synctest.Wait()
	before := c4PropagateGoroutines()
	var ran, stopped atomic.Int32
	context.AfterFunc(ctx, func() { ran.Add(1) })
	stop := context.AfterFunc(ctx, func() { stopped.Add(1) })
	if !stop() || stop() {
		t.Fatal("stop: want true once, then false")
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	early, cancelE := context.WithDeadline(ctx, time.Now().Add(c4AcceptTimeout/2))
	defer cancelE()
	late, cancelL := context.WithDeadline(ctx, time.Now().Add(time.Hour))
	defer cancelL()
	timed, cancelT := context.WithTimeout(child, time.Hour) // a grandchild
	defer cancelT()
	synctest.Wait()
	if n := c4PropagateGoroutines() - before; n != 0 {
		t.Fatalf("%d goroutines started to watch the pending context, want 0", n)
	}
	select {
	case <-ctx.Done():
		t.Fatal("Done closed while pending")
	default:
	}

	x.exit(t, rt, ln, p)
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
	for i, c := range []context.Context{child, late, timed} {
		if err := c.Err(); err != want {
			t.Fatalf("derived context %d: Err %v, want %v", i, err, want)
		}
	}
	// The child whose own deadline comes before the pending one expired
	// there when AcceptTimeout is the exit; every other exit comes first.
	wantEarly := context.Canceled
	if x.deadline {
		wantEarly = context.DeadlineExceeded
	}
	if err := early.Err(); err != wantEarly {
		t.Fatalf("the earlier-deadline child: Err %v, want %v", err, wantEarly)
	}
	// Registered after the exit through the context's AfterFunc method (as
	// the context package does when the session leaves pending between its
	// Done check and that call): f runs once on its own goroutine and stop
	// reports false.
	var lateRan atomic.Int32
	af, ok := pp.Context().(interface{ AfterFunc(func()) func() bool })
	if !ok {
		t.Fatal("the pending context has no AfterFunc method")
	}
	stopLate := af.AfterFunc(func() { lateRan.Add(1) })
	synctest.Wait()
	if lateRan.Load() != 1 {
		t.Fatalf("an AfterFunc registered after the exit ran %d times, want 1", lateRan.Load())
	}
	if stopLate() {
		t.Fatal("stop of an AfterFunc registered after the exit reported true")
	}
	if ran.Load() != 1 {
		t.Fatalf("the first AfterFunc ran %d times after the exit, want once", ran.Load())
	}
}
