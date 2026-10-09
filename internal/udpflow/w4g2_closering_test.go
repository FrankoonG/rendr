package udpflow

import (
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestFlowCloseDropsRing_W4L2 (W4-L2-1; invariant 4): a flow whose inbox
// once burst to the full Limits.Inbox keeps its grown ring only until it
// closes. Close releases the queued buffers (the Budget is back to zero),
// drops the ring itself — so a record that still references the closed
// *Flow pins no inbox — and Removed reports the removal; a datagram for
// the closed flow is dropped (a tombstone), and its reader gets
// net.ErrClosed, never a stale datagram.
func TestFlowCloseDropsRing_W4L2(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		if f == nil {
			t.Fatal("no flow admitted")
		}
		readOne(t, f, time.Second)
		f.Release()
		if f.Removed() {
			t.Fatal("a live flow reports Removed")
		}
		// Nobody reads: the inbox grows its ring to the full Inbox.
		for i := range DefaultInbox {
			h.c.send(dg(1, pingFrame(uint32(i+2))), udpAddr(2, 1000))
		}
		synctest.Wait()
		f.mu.Lock()
		grown, queued := len(f.ring), f.n
		f.mu.Unlock()
		if grown != DefaultInbox || queued != DefaultInbox || env.Budget.Used() == 0 {
			t.Fatalf("the burst: ring %d, queued %d, budget %d; want %d queued in a full ring, charged",
				grown, queued, env.Budget.Used(), DefaultInbox)
		}

		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		ring, n := f.ring, f.n
		f.mu.Unlock()
		if ring != nil || n != 0 {
			t.Fatalf("after Close: ring of %d entries (%d queued) still held, want none", len(ring), n)
		}
		if !f.Removed() {
			t.Fatal("a closed flow does not report Removed")
		}
		if used := env.Budget.Used(); used != 0 {
			t.Fatalf("after Close: Budget holds %d bytes", used)
		}
		if st := h.s.Stats(); st.Flows != 0 {
			t.Fatalf("after Close: Stats %+v, want no flow", st)
		}
		dropped := env.Dgram.Dropped.Load()
		h.c.send(dg(1, pingFrame(9999)), udpAddr(2, 1000))
		synctest.Wait()
		if env.Dgram.Dropped.Load() != dropped+1 || env.Budget.Used() != 0 {
			t.Fatalf("a datagram for the closed flow: dropped %d (before %d), budget %d", env.Dgram.Dropped.Load(), dropped, env.Budget.Used())
		}
		if _, _, _, err := f.ReadDatagram(nil); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadDatagram after Close: %v, want net.ErrClosed", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("a second Close: %v", err)
		}
	})
}
