package session

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketFallbackWake_L08: the bond's fallback wake for a head no live
// lane can place (pktWakeDgramLocked) stays out of the way when the
// minimum share's lane, woken and counted, can place it. A bond of a
// 1425-byte member A (DgramMax 1400, never served: the minimum share's
// choice) and a faster 1125-byte member B (DgramMax 1100); every datagram
// is 1,200 bytes. With more queued than one batch covers, the walk skips
// the counted A and finds no other lane for the head; the fallback must
// not then wake B, which can only defer the head to A (directed wakes,
// L08). A places the datagrams.
func TestPacketFallbackWake_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{mode: ModeBond})
		la, pa := dpAddLane(s, 1, true, true)
		lb, pb := dpAddLane(s, 2, true, true)
		pa.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond; f.budget = 1425 })
		pb.set(func(f *dpPort) { f.srtt = time.Millisecond; f.budget = 1125 })
		dpIdle(la)
		dpIdle(lb)
		now := time.Now()
		s.mu.Lock()
		s.pktRecomputeLocked()
		lb.lastDgramAt = now // served; A never placed: the minimum share's choice
		s.refreshOrderLocked(now, true)
		s.mu.Unlock()
		wa, wb := pa.wakeCount(), pb.wakeCount()
		const n = 1200
		for i := 1; i <= 100; i++ {
			if i == 70 {
				// A went idle again without placing (its writer has not
				// run): the next WriteTo wakes and counts it, and the
				// queue (70) exceeds what one batch covers.
				s.mu.Lock()
				la.idle = true
				s.mu.Unlock()
			}
			dpWrite(t, s, uint64(i), n)
		}
		if got := pa.wakeCount() - wa; got != 2 {
			t.Fatalf("A woken %d times, want 2 (stimulus: the minimum share woke and counted it twice)", got)
		}
		if got := pb.wakeCount() - wb; got != 0 {
			t.Fatalf("B, which cannot carry a %d-byte datagram, was woken %d times", n, got)
		}
		// B places nothing (it defers the head to A); A places them all.
		if fs := dpFrames(dpFill(lb, time.Now())); dpCount(fs, wire.TypeDgram) != 0 {
			t.Fatalf("B placed %v", fs)
		}
		var seqs []uint64
		for range 8 {
			for _, f := range dpFrames(dpFill(la, time.Now())) {
				if f.typ == wire.TypeDgram {
					if len(f.body) != n {
						t.Fatalf("DGRAM %d of %d bytes, want %d", f.seq, len(f.body), n)
					}
					seqs = append(seqs, f.seq)
				}
			}
		}
		if len(seqs) != 100 {
			t.Fatalf("A placed %d datagrams, want 100", len(seqs))
		}
		for i, q := range seqs {
			if i > 0 && q != seqs[i-1]+1 {
				t.Fatalf("A placed seqs %v, not in order", seqs)
			}
		}
		if c := dpCtr(s).DropTooLarge; c != 0 {
			t.Fatalf("DropTooLarge %d, want 0", c)
		}
		dpEnd(s, io.EOF)
	})
}
