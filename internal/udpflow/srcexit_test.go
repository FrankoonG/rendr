package udpflow

import (
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
)

// The reader's exit against an idle-release firing in progress (srcidle's
// relMu; the second review wave's B2-1): no timer is left armed behind a
// Source that ended.

// parkGateReader is a fakeReader whose Parks holds its next caller, once a
// gate is set, until the gate closes. With the gate set while the read is
// parked holding its extras, that caller is the idle-release firing (the
// reader goroutine calls Parks only when it takes its extras, arm), held
// there with relMu before it decides to re-arm.
type parkGateReader struct {
	*fakeReader
	gate atomic.Pointer[chan struct{}]
}

func (r *parkGateReader) Parks() uint64 {
	if g := r.gate.Swap(nil); g != nil {
		<-*g
	}
	return r.fakeReader.Parks()
}

// parkGateSock is a fakeSock whose Source reads through a parkGateReader.
type parkGateSock struct {
	*fakeSock
	rd atomic.Pointer[parkGateReader]
}

func (c *parkGateSock) newReader(release func(*udpsocket.Batch)) srcReader {
	r := &parkGateReader{fakeReader: c.fakeSock.newReader(release).(*fakeReader)}
	c.rd.Store(r)
	return r
}

// TestSourceExitStopsIdleTimer (R1-5 rule 3 as srcidle applies it; B2-1 of
// the second review wave): the reader's exit leaves no idle-release timer
// armed and no firing that acts after it.
//
//   - rearm-in-flight: the read at depth 32 holds its extras and parks; the
//     first firing, a period later, takes relMu and waits in Parks
//     (parkGateReader). The Source is aborted meanwhile: the read ends, and
//     the exit waits for that firing, which — the read parked since the
//     extras were taken — re-arms the timer. Once Done has closed, the timer
//     is stopped: endIdle stops it under relMu, after the firing that held
//     relMu re-armed it. Mutant: endIdle stops the timer before it takes
//     relMu (a stray firing, up to a period after Done, keeps the reader and
//     the Source reachable).
//   - fired-at-exit: on the reader's state (hold, a park; no read loop) the
//     timer fires while the exit's critical section holds relMu, and its
//     firing runs once the exit set ended: it touches nothing — no Holding
//     call, the extras untouched, no re-arm. Mutant: idleFire without the
//     ended check.
func TestSourceExitStopsIdleTimer(t *testing.T) {
	t.Run("rearm-in-flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := testEnv(1 << 30)
			c := &parkGateSock{fakeSock: newFakeSock(32)}
			s := newSeamSource(env, c.fakeSock, c, seamDgram, Limits{})
			// Source.Run's body, with its reader at hand.
			s.mu.Lock()
			s.run = runRunning
			s.mu.Unlock()
			r := &reader{s: s, admit: func(f *Flow) { f.Close() }}
			go func() {
				defer r.exit()
				r.loopOwned()
			}()
			synctest.Wait()
			rd := c.rd.Load()
			hb, hs := srcHold(env)
			if rd == nil || !rd.Holding() || rd.Parks() != 1 || env.Budget.Used() != hb || env.Stages.Used() != hs {
				t.Fatalf("stimulus: the first read does not wait at depth 32 holding its extras (%s)", heldBytes(env))
			}
			gate := make(chan struct{})
			var opened sync.Once
			open := func() { opened.Do(func() { close(gate) }) }
			defer open()
			rd.gate.Store(&gate)
			time.Sleep(batchIdleRelease)
			synctest.Wait()
			if rd.gate.Load() != nil {
				t.Fatal("stimulus: no idle-release firing waits in Parks")
			}
			s.Abort()
			synctest.Wait()
			select {
			case <-s.Done():
				t.Fatal("Done while an idle-release firing was in progress: the exit must wait for it (srcidle)")
			default:
			}
			open()
			synctest.Wait()
			<-s.Done()
			if r.idleT.Stop() {
				t.Fatal("the idle-release timer is still armed after Done: the firing in progress during the reader's exit re-armed it after the exit stopped it")
			}
			if u := buffered(env); u != 0 || rd.Holding() {
				t.Fatalf("after Done: BufferedBytes %d (%s), holding %v", u, heldBytes(env), rd.Holding())
			}
		})
	})
	t.Run("fired-at-exit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := testEnv(1 << 30)
			c := &parkGateSock{fakeSock: newFakeSock(32)}
			s := newSeamSource(env, c.fakeSock, c, seamDgram, Limits{})
			r := &reader{s: s}
			r.startDepth()
			rd := c.rd.Load()
			r.hold() // the extras of a read at depth 32: the Batch, the timer armed
			if rd == nil || !r.held || !r.armed.Load() {
				t.Fatal("stimulus: no extras held, or the idle release not armed")
			}
			// The read parked holding them; then the exit's critical section
			// (endIdle) holds relMu …
			rd.park()
			r.relMu <- struct{}{}
			time.Sleep(batchIdleRelease)
			synctest.Wait() // … when the timer fires: its firing waits for relMu
			calls := rd.holdings.Load()
			r.ended = true
			r.idleT.Stop()
			<-r.relMu
			synctest.Wait()
			if n := rd.holdings.Load() - calls; n != 0 || !rd.Holding() || rd.releases.Load() != 0 || r.idleT.Stop() {
				t.Fatalf("a firing after the exit set ended: %d Holding calls, holding %v, %d releases; want it to touch nothing and re-arm nothing",
					n, rd.Holding(), rd.releases.Load())
			}
			r.endIdle()
			if u := buffered(env); u != 0 {
				t.Fatalf("after the exit: BufferedBytes %d (%s)", u, heldBytes(env))
			}
		})
	})
}
