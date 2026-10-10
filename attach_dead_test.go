package rendr

import (
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestMuxViewDeadBeforeStartReachesSession_R2_12 (M3 design R2-12,
// §A5.7 item 6, §A10.3; DGDOWN): a MUX trunk's death that catches a
// session's view attached-pending — the OPEN answered OK, the attach
// checked the view alive, the session has not started it — reaches that
// session when it starts the view after the death. Every Start of a
// carrier runs inside an actor step (attachLocked under handleLocked), and
// the reapDead of that same step reads the view's Death, which reports the
// trunk's death record whether or not the view is attached yet; the death
// step records the carrier's end like any other (one EventCarrierDown with
// the trunk's ID and cause, its row dead in Status), and the session
// recovers on a new trunk. The late Start's doorbell ring
// (Conn.startView) is defensive at this level: without it the same step
// still reaps the view (mutant r12b passes here), and
// TestDgTrunkDeathReachesEveryViewState pins the ring at carrier level.
//
// Session A is open on the stream trunk of link a. Session B's Dial takes
// the live trunk (a new view, its OPEN answered OK); in B's attach, right
// before the view's Start (Hooks.BeforeAttachStart), the link is killed
// and the hook returns only once A recorded the trunk's death (premise: the
// trunk's death record is set before B's Start). PASS: B's Dial succeeds;
// B emits EventCarrierUp and then exactly one EventCarrierDown for the
// trunk, with transport_error, dated at or after A's; B's Status lists the
// trunk dead with transport_error; A records its own CarrierDown; both
// sessions recover on another carrier within 10 s and exchange 32 KiB
// each way, verified; a clean end. Observed with a view's Death that does
// not report its trunk's death before the view is attached: B keeps the
// dead view as its live carrier.
func TestMuxViewDeadBeforeStartReachesSession_R2_12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var (
			armed  atomic.Bool
			caught atomic.Uint32 // the carrier B's attach was about to start
			a      *Conn         // session A's dialer end
			e      *e2ePair
			mu     sync.Mutex
			evs    []Event
		)
		hooks := &testhooks.Hooks{BeforeAttachStart: func(_ [16]byte, cid uint32) {
			if !armed.CompareAndSwap(true, false) {
				return
			}
			caught.Store(cid)
			e.links[0].Kill()
			for deadline := time.Now().Add(5 * time.Second); !mxDeadRow(a, CarrierID(cid)); time.Sleep(time.Millisecond) {
				if !time.Now().Before(deadline) {
					t.Errorf("premise: session A did not record the death of trunk %d within 5 s of the kill", cid)
					return
				}
			}
		}}
		dcfg := Config{OnEvent: func(ev Event) {
			mu.Lock()
			evs = append(evs, ev)
			mu.Unlock()
		}}
		e = e2eNew(t, dcfg, Config{}, &testhooks.Overrides{Hooks: hooks}, ListenConfig{}, "a")
		p := e.mxPeer(e2eCarrier(e.links[0]))
		var ap *Conn
		a, ap = e2eOpen(t, p, e.ln, DialOptions{})
		e2eExchange(t, a, ap, 32<<10, 1)
		trunk := mxCarrier(t, a, "a").ID

		armed.Store(true)
		b, bp := e2eOpen(t, p, e.ln, DialOptions{})
		if armed.Load() || CarrierID(caught.Load()) != trunk {
			t.Fatalf("stimulus: B's attach started carrier %d, want a view of A's trunk %d caught before its Start", caught.Load(), trunk)
		}
		onOther := func(c *Conn) bool {
			live := liveCarriers(c.Status())
			return len(live) == 1 && live[0].ID != trunk
		}
		for deadline := time.Now().Add(10 * time.Second); !onOther(a) || !onOther(b); time.Sleep(time.Millisecond) {
			if !time.Now().Before(deadline) {
				t.Fatalf("10 s after the kill: A lists %+v, B lists %+v; want both on one live carrier other than trunk %d (B's view, started after the trunk's death, did not reach B)",
					liveCarriers(a.Status()), liveCarriers(b.Status()), trunk)
			}
		}
		e2eExchange(t, a, ap, 32<<10, 2)
		e2eExchange(t, b, bp, 32<<10, 3)
		synctest.Wait()

		mu.Lock()
		var aDown, bUp, bDown []Event
		for _, ev := range evs {
			if ev.Carrier != trunk {
				continue
			}
			switch {
			case ev.Session == a.ID() && ev.Kind == EventCarrierDown:
				aDown = append(aDown, ev)
			case ev.Session == b.ID() && ev.Kind == EventCarrierUp:
				bUp = append(bUp, ev)
			case ev.Session == b.ID() && ev.Kind == EventCarrierDown:
				bDown = append(bDown, ev)
			}
		}
		mu.Unlock()
		if len(aDown) != 1 {
			t.Fatalf("session A: %d EventCarrierDown for trunk %d, want 1", len(aDown), trunk)
		}
		if len(bUp) != 1 || len(bDown) != 1 {
			t.Fatalf("session B: %d EventCarrierUp and %d EventCarrierDown for trunk %d, want 1 each: the view started after the trunk's death did not reach its session", len(bUp), len(bDown), trunk)
		}
		if d := bDown[0]; d.Cause != CauseTransportError || d.Seq < bUp[0].Seq || d.Time.Before(aDown[0].Time) {
			t.Fatalf("session B's EventCarrierDown %+v (up %+v, A's down %+v), want transport_error after its EventCarrierUp, dated at or after A's", d, bUp[0], aDown[0])
		}
		var row *CarrierStatus
		for _, cs := range b.Status().Carriers {
			if cs.ID == trunk {
				row = &cs
			}
		}
		if row == nil || row.State != CarrierDead || row.DeathCause != CauseTransportError {
			t.Fatalf("session B's Status row of trunk %d: %+v, want dead with transport_error", trunk, row)
		}
		e2eFinish(t, a, ap)
		e2eFinish(t, b, bp)
		e.close()
	})
}

// mxDeadRow reports whether c lists carrier id dead.
func mxDeadRow(c *Conn, id CarrierID) bool {
	for _, cs := range c.Status().Carriers {
		if cs.ID == id && cs.State == CarrierDead {
			return true
		}
	}
	return false
}
