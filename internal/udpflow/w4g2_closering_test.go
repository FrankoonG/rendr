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
// burst to the full Limits.Inbox holds its grown storage — pooled blocks,
// each charged to Stages (inboxtime) — only until it closes. Close
// releases the queued buffers (the Budget is back to zero) and every block
// with its charge (Stages back to zero), drops its first block — so a
// record that still references the closed *Flow pins no inbox — and
// Removed reports the removal; a datagram for the closed flow is dropped
// (a tombstone), and its reader gets net.ErrClosed, never a stale
// datagram. (Before inboxtime the row read the ring's length; the rule is
// unchanged, and the block list's capacity and charge replace it.)
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
		// Nobody reads: the inbox grows its storage to the full Inbox.
		for i := range DefaultInbox {
			h.c.send(dg(1, pingFrame(uint32(i+2))), udpAddr(2, 1000))
		}
		synctest.Wait()
		f.mu.Lock()
		grown, blocks, queued := inboxStorageLocked(f)
		f.mu.Unlock()
		if grown < DefaultInbox || queued != DefaultInbox || env.Budget.Used() == 0 || env.Stages.Used() != int64(blocks)*blockBytes {
			t.Fatalf("the burst: storage %d entries in %d pooled blocks, queued %d, Budget %d, Stages %d; want %d queued, charged, and the blocks' %d B each in Stages",
				grown, blocks, queued, env.Budget.Used(), env.Stages.Used(), DefaultInbox, blockBytes)
		}

		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		head, tail, base, n := f.head, f.tail, f.base, f.n
		f.mu.Unlock()
		if head != nil || tail != nil || base != nil || n != 0 {
			t.Fatalf("after Close: inbox blocks still held (%d queued), want none", n)
		}
		if !f.Removed() {
			t.Fatal("a closed flow does not report Removed")
		}
		if used := env.Budget.Used(); used != 0 {
			t.Fatalf("after Close: Budget holds %d bytes", used)
		}
		if used := env.Stages.Used(); used != 0 {
			t.Fatalf("after Close: Stages holds %d bytes (the inbox blocks' charges)", used)
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
