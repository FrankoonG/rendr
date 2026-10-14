package carrier

import (
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// The dialer reader's exit against its idle release (R1-5 rule 3; B2-2 of
// M5's second review wave): the reader's partDone — and with it the
// carrier's Done — follows a release in flight, and no firing re-arms the
// timer behind an exit, as the passive Source's reader does (srcidle).

// gatedDepth is a fakeBatch whose idle release can be held: relGate, once
// set, holds the release function — after the release's CAS (parked →
// releasing), before the slots and the header's charge go back — until it
// closes; parksGate holds the next parks call until it closes, which with
// the read parked is the idle-release firing's (the reader calls parks
// around its reads only); holdings counts the holding calls, which only a
// firing makes.
type gatedDepth struct {
	*fakeBatch
	relGate, parksGate atomic.Pointer[chan struct{}]
	holdings           atomic.Int64
}

func (g *gatedDepth) onRelease(f func(*ioHdr)) {
	g.fakeBatch.onRelease(func(h *ioHdr) {
		if c := g.relGate.Load(); c != nil {
			<-*c
		}
		f(h)
	})
}

func (g *gatedDepth) parks() uint64 {
	if c := g.parksGate.Swap(nil); c != nil {
		<-*c
	}
	return g.fakeBatch.parks()
}

func (g *gatedDepth) holding() bool {
	g.holdings.Add(1)
	return g.fakeBatch.holding()
}

var _ depthIO = (*gatedDepth)(nil)

// gatedRig is depthRig with a gatedDepth: a dialer carrier over the
// harness's link reading through it at MaxBatch 32, started, a raw peer,
// and a gate opener the cleanup runs as well.
func gatedRig(t *testing.T) (s *dgSide, p *rawPeer, g *gatedDepth, gate chan struct{}, open func()) {
	s, p = rawPair(t, 1200, true)
	g = &gatedDepth{fakeBatch: newFakeBatch(s.io, DefaultMaxBatch)}
	prev := dgBatchOf
	dgBatchOf = func(io PacketIO) BatchIO {
		if f, ok := io.(*fakeIO); ok && f == g.fakeIO {
			return g
		}
		return prev(io)
	}
	gate = make(chan struct{})
	var once sync.Once
	open = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() {
		open()
		dgBatchOf = prev
	})
	s.start(StartOptions{})
	synctest.Wait()
	return s, p, g, gate, open
}

// held32 fails the test unless the reader holds the extras of depth 32:
// 31 slots on Env.Budget and the header on Env.Stages above base, sbase.
func held32(t *testing.T, s *dgSide, base, sbase int64, what string) {
	t.Helper()
	if b, st := s.env.Budget.Used()-base, s.env.Stages.Used()-sbase; b != 31*slotSize() || st != 32*hdrPerMsg {
		t.Fatalf("%s: Budget %+d, Stages %+d; want the extras of depth 32 held (31 × %d, %d)", what, b, st, slotSize(), 32*hdrPerMsg)
	}
}

// TestDgramReaderExitWaitsForIdleRelease (R1-5 rule 3; B2-2): a burst of
// 64 grows the depth to 32 — 31 slots on Env.Budget, the header on
// Env.Stages — and the read parks holding them. Two periods later the
// idle release takes them by its CAS and is held before it returns them
// (gatedDepth.relGate). The carrier is killed meanwhile: its reader exits,
// but it waits for the release in flight, so the carrier is not Done while
// the released extras are still charged; once the release returned them
// it is Done with both accounts at exactly 0 (Status.BufferedBytes 0 after
// Runtime.Close). Mutant: endDepth without relMu (Done with +65,472 B on
// the Budget and +6,144 B in Stages until the timer's goroutine returns
// them).
func TestDgramReaderExitWaitsForIdleRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, g, gate, open := gatedRig(t)
		bud, stg := s.env.Budget, s.env.Stages
		base, sbase := bud.Used(), stg.Used()
		injectBurst(s.io, p.io.addr, p.burst(0, 64, 100))
		synctest.Wait()
		held32(t, s, base, sbase, "stimulus: after a burst of 64")
		g.relGate.Store(&gate)
		time.Sleep(2*batchIdleRelease + time.Millisecond)
		synctest.Wait()
		if g.state.Load() != fbReleasing {
			t.Fatalf("stimulus: state %d two periods later, want an idle release in flight (releasing)", g.state.Load())
		}
		held32(t, s, base, sbase, "stimulus: the release in flight")
		s.c.Kill(CauseLocalClose, "test: the carrier ends while its idle release runs")
		synctest.Wait()
		select {
		case <-s.c.Done():
			t.Fatalf("the carrier was Done while its reader's released extras were still charged: Budget %+d, Stages %+d",
				bud.Used()-base, stg.Used()-sbase)
		default:
		}
		open()
		synctest.Wait()
		hWait(t, s.c)
		if b, st := bud.Used(), stg.Used(); b != 0 || st != 0 {
			t.Fatalf("at Done: Budget %d, Stages %d; want 0 (the release in flight returned its charges first)", b, st)
		}
		if g.fakeBatch.holding() {
			t.Fatal("at Done: the reader still holds extras")
		}
	})
}

// TestDgramReaderNoFiringAfterDone (R1-5 rule 3; B2-2): no idle-release
// firing runs behind a carrier that is Done. After a burst of 64 the read
// parks holding the extras of depth 32; the first firing, a period later,
// waits in parks (gatedDepth.parksGate) before it decides. The carrier is
// killed meanwhile: the reader exits and waits for that firing, which —
// the read parked since the extras were taken — re-arms the timer; the
// exit then stops it, so after Done no firing reaches the transport
// (gatedDepth.holdings unchanged over three periods) and nothing is
// charged. Mutant: endDepth without relMu (a firing a period after Done).
// TestDgramReaderExitStopsIdleTimer pins the order inside the exit.
func TestDgramReaderNoFiringAfterDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, g, gate, open := gatedRig(t)
		base, sbase := s.env.Budget.Used(), s.env.Stages.Used()
		injectBurst(s.io, p.io.addr, p.burst(0, 64, 100))
		synctest.Wait()
		held32(t, s, base, sbase, "stimulus: after a burst of 64")
		g.parksGate.Store(&gate)
		time.Sleep(batchIdleRelease + time.Millisecond)
		synctest.Wait()
		if g.parksGate.Load() != nil {
			t.Fatal("stimulus: no idle-release firing waits in parks")
		}
		s.c.Kill(CauseLocalClose, "test: the carrier ends while an idle-release firing runs")
		synctest.Wait()
		fired := g.holdings.Load()
		open()
		synctest.Wait()
		hWait(t, s.c)
		time.Sleep(3 * batchIdleRelease)
		synctest.Wait()
		if n := g.holdings.Load() - fired; n != 0 {
			t.Fatalf("the idle release fired after the carrier's Done (%d holding calls): the firing in progress during the exit re-armed the timer after the exit stopped it", n)
		}
		if b, st := s.env.Budget.Used(), s.env.Stages.Used(); b != 0 || st != 0 || g.fakeBatch.holding() {
			t.Fatalf("after Done: Budget %d, Stages %d, holding %v; want nothing", b, st, g.fakeBatch.holding())
		}
	})
}

// depthReader returns the depth state of a dialer reader over a
// gatedDepth as dgReadLoop starts it (startDepth) on an unstarted carrier
// — no reader goroutine: the test drives it — holding the extras of depth
// 2 (grow: a slot on Env.Budget, the header on Env.Stages, lent, the idle
// release armed) and parked once since it took them, so a firing a period
// later finds the read parked. base and sbase are the accounts before.
func depthReader(t *testing.T) (rd *dgReader, g *gatedDepth, env *Env, base, sbase int64) {
	ia, _ := newFakeIOPair(t, 1200)
	env = dgEnv()
	c := dgConn(env, ia, 1200, true)
	g = &gatedDepth{fakeBatch: newFakeBatch(ia, DefaultMaxBatch)}
	base, sbase = env.Budget.Used(), env.Stages.Used()
	rd = &dgReader{}
	rd.startDepth(c, g)
	rd.grow(2)
	if rd.hdr == nil || !g.fakeBatch.held() || !rd.armed.Load() {
		t.Fatal("stimulus: no extras lent, or the idle release not armed")
	}
	g.fakeBatch.nparks.Add(1)
	g.fakeBatch.state.Store(fbParked)
	return rd, g, env, base, sbase
}

// TestDgramReaderExitStopsIdleTimer (R1-5 rule 3; B2-2), the order inside
// the reader's exit, driven on the reader's depth state (depthReader):
//
//   - rearm-in-flight: the first firing waits in parks (holding relMu)
//     when the read returns and the reader exits; the exit waits for it,
//     the firing — the read parked since the extras were taken — re-arms
//     the timer, and the exit stops it after that: no timer is armed once
//     endDepth returned, and the extras and their charges are back.
//     Mutant: endDepth stopping the timer before it takes relMu.
//   - fired-at-exit: the timer fires while the exit holds relMu (its
//     goroutine waits for it), and runs once the exit set ended: it
//     touches nothing — no holding call, the extras untouched, no re-arm.
//     Mutant: idleFire without the ended check.
func TestDgramReaderExitStopsIdleTimer(t *testing.T) {
	t.Run("rearm-in-flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rd, g, env, base, sbase := depthReader(t)
			gate := make(chan struct{})
			g.parksGate.Store(&gate)
			time.Sleep(batchIdleRelease + time.Millisecond)
			synctest.Wait()
			if g.parksGate.Load() != nil {
				t.Fatal("stimulus: no idle-release firing waits in parks")
			}
			g.fakeBatch.state.Store(fbHeld) // the read returned: the reader took its extras back
			exited := make(chan struct{})
			go func() {
				rd.endDepth()
				close(exited)
			}()
			synctest.Wait()
			select {
			case <-exited:
				t.Fatal("the reader's exit did not wait for the firing in progress (relMu)")
			default:
			}
			close(gate)
			synctest.Wait()
			<-exited
			if rd.idleT.Stop() {
				t.Fatal("the idle-release timer is armed after the reader's exit: the firing in progress re-armed it after the exit stopped it")
			}
			if b, st := env.Budget.Used(), env.Stages.Used(); b != base || st != sbase || g.fakeBatch.holding() {
				t.Fatalf("after the exit: Budget %+d, Stages %+d, holding %v; want the extras back", b-base, st-sbase, g.fakeBatch.holding())
			}
		})
	})
	t.Run("fired-at-exit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rd, g, env, base, sbase := depthReader(t)
			rd.relMu <- struct{}{} // the exit's critical section (endDepth) holds relMu …
			time.Sleep(batchIdleRelease + time.Millisecond)
			synctest.Wait() // … when the timer fires: its firing waits for relMu
			calls := g.holdings.Load()
			rd.ended = true
			rd.idleT.Stop()
			<-rd.relMu
			synctest.Wait()
			if n := g.holdings.Load() - calls; n != 0 || !g.fakeBatch.holding() || rd.idleT.Stop() {
				t.Fatalf("a firing after the exit set ended: %d holding calls, extras held %v; want it to touch nothing and re-arm nothing", n, g.fakeBatch.holding())
			}
			rd.endDepth()
			if b, st := env.Budget.Used(), env.Stages.Used(); b != base || st != sbase {
				t.Fatalf("after the exit: Budget %+d, Stages %+d; want the extras back", b-base, st-sbase)
			}
		})
	})
}
