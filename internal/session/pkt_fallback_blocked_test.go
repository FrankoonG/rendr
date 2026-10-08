package session

import (
	"bytes"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketFallbackWriteBlocked_L08: the bond's fallback wake
// (pktWakeDataLocked) is taken only when no live data lane could ever carry
// the head, so a head that only a briefly write-blocked member can carry
// is not handed to a smaller member whose Fill drops it as too large
// (M2-D45: the head is left to another live data lane that can carry it;
// L37: DropTooLarge is for a head no live member can carry). A bond of a
// 1425-byte member A (DgramMax 1400) and a faster 1125-byte member B
// (DgramMax 1100); every datagram is 1,200 bytes. A's batch write is
// blocked (WriteBlocked, as the watchdog reports it after PingBusy) while
// 20 datagrams are written 3 ms apart; B's writer runs whenever it is
// woken. B is never woken for them. When A's write returns, A's writer
// fills again: every datagram still younger than MaxAge goes out on A, in
// order and intact; one older than MaxAge counts as DropAge (a data lane
// that can carry it exists), never DropTooLarge.
//
// extra-fill records the M2-D45 trade-off (pktOtherCarrierLocked): Fill
// cannot tell B, the smaller member of a mixed-budget bond, from a lane
// whose own budget shrank (TestPacketShrinkDropsAtOnce_L37), so when B
// fills for another reason while A is blocked — here one Fill after the
// 10th write, as B's PACK duty or a control frame would run it — it drops
// the 10 queued heads as DropTooLarge; the 10 written after it wait for A.
func TestPacketFallbackWriteBlocked_L08(t *testing.T) {
	for _, tc := range []struct {
		name      string
		blocked   time.Duration // from the first write to A's write returning
		extraFill int           // B fills once after this many writes (0: never)
		kept      int           // datagrams younger than MaxAge (100 ms) then
	}{
		{"60ms", 60 * time.Millisecond, 0, 20},
		// Written at 0, 3, …, 57 ms; at 150 ms those written before 50 ms
		// (17) are older than MaxAge; the last 3 (51, 54, 57 ms) are not.
		{"150ms", 150 * time.Millisecond, 0, 3},
		{"extra-fill", 60 * time.Millisecond, 10, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				testFallbackWriteBlocked(t, tc.blocked, tc.extraFill, tc.kept)
			})
		})
	}
}

func testFallbackWriteBlocked(t *testing.T, blocked time.Duration, extraFill, kept int) {
	const (
		total = 20
		n     = 1200
		gap   = 3 * time.Millisecond
	)
	s := dpSession(dpOpt{mode: ModeBond})
	la, pa := dpAddLane(s, 1, true, true)
	lb, pb := dpAddLane(s, 2, true, true)
	pa.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond; f.budget = 1425 })
	pb.set(func(f *dpPort) { f.srtt = time.Millisecond; f.budget = 1125 })
	dpIdle(la)
	dpIdle(lb)
	s.mu.Lock()
	s.pktRecomputeLocked()
	s.refreshOrderLocked(time.Now(), true)
	s.mu.Unlock()
	if got := dpLocked(s, func(_ *stream, pk *packet) int { return pk.dgMax }); got != 1400 {
		t.Fatalf("dgMax %d, want 1400 (A's DgramMax)", got)
	}

	start := time.Now()
	pa.set(func(f *dpPort) { f.blocked = true }) // A's batch write is blocked
	callsA := pa.callCount()
	wb := pb.wakeCount()
	wb0 := wb
	bDgrams := 0
	runB := func() { // B's writer: it runs when woken, until it places nothing
		for pb.wakeCount() != wb {
			wb = pb.wakeCount()
			for range 64 {
				b := dpFill(lb, time.Now())
				fs := dpFrames(b)
				b.ReleaseRefs()
				bDgrams += dpCount(fs, wire.TypeDgram)
				if len(fs) == 0 {
					break
				}
			}
		}
	}
	for i := 1; i <= total; i++ {
		dpWrite(t, s, uint64(i), n)
		runB()
		if i == extraFill {
			// B fills for a reason of its own (PACK duty, a control frame):
			// it cannot carry a head and drops each as too large.
			b := dpFill(lb, time.Now())
			fs := dpFrames(b)
			b.ReleaseRefs()
			bDgrams += dpCount(fs, wire.TypeDgram)
			if c := dpCtr(s); c.DropTooLarge != uint64(extraFill) {
				t.Fatalf("stimulus: B's extra Fill dropped %d heads, want the %d queued (counters %+v)", c.DropTooLarge, extraFill, c)
			}
		}
		if i < total {
			time.Sleep(gap)
		}
	}
	// Stimulus: every WriteTo saw A blocked and B too small for the head.
	if pa.callCount() == callsA {
		t.Fatal("stimulus: A's WriteBlocked was never consulted")
	}
	if a := dpCtr(s); a.Sent != 0 {
		t.Fatalf("stimulus: %d datagrams placed while A was blocked, want 0", a.Sent)
	}
	time.Sleep(blocked - time.Since(start))
	pa.set(func(f *dpPort) { f.blocked = false }) // A's write returns
	runB()

	// A's writer loops into its next Fill.
	var ids []uint64
	for range 8 {
		b := dpFill(la, time.Now())
		for _, f := range dpFrames(b) {
			if f.typ != wire.TypeDgram {
				continue
			}
			if !bytes.Equal(f.body, dpPayload(dpID(f.body), n)) {
				t.Fatalf("DGRAM %d: body corrupted", f.seq)
			}
			ids = append(ids, dpID(f.body))
		}
		b.ReleaseRefs()
	}
	if bDgrams != 0 {
		t.Fatalf("B placed %d DGRAMs larger than its DgramMax", bDgrams)
	}
	ctr := dpCtr(s)
	if ctr.DropTooLarge != uint64(extraFill) {
		t.Fatalf("DropTooLarge %d, want %d: A can carry every head and only B's extra Fill drops them (counters %+v)", ctr.DropTooLarge, extraFill, ctr)
	}
	if got := pb.wakeCount() - wb0; got != 0 {
		t.Fatalf("B, which cannot carry a %d-byte datagram, was woken %d times", n, got)
	}
	if len(ids) != kept {
		t.Fatalf("A placed %d datagrams %v, want the %d younger than MaxAge", len(ids), ids, kept)
	}
	for i, id := range ids {
		if want := uint64(total - kept + 1 + i); id != want {
			t.Fatalf("A placed ids %v, want %d..%d in order", ids, total-kept+1, total)
		}
	}
	if age := total - extraFill - kept; ctr.Sent != uint64(kept) || ctr.DropAge != uint64(age) || ctr.DropNoPath != 0 || ctr.DropQueue != 0 {
		t.Fatalf("counters %+v, want Sent %d DropAge %d", ctr, kept, age)
	}
	dpEnd(s, io.EOF)
}
