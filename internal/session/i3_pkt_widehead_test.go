package session

import (
	"bytes"
	"io"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketWideHeadFill_W4REL5: a head queued above the smallest live
// datagram member's DgramMax (pdesc.wide, a mixed-budget bond) is left by
// the smaller member's Fill to a member that can carry it at all, even one
// that cannot place it now; it is dropped as DropTooLarge only when no
// live member can carry it any more. A bond of A (DgramMax 1400) and B
// (DgramMax 1100); a 1200-byte datagram, then a 100-byte one.
//
// blocked: A's write is blocked. B's Fill places nothing and drops
// nothing (the 100-byte datagram does not overtake the head); once A's
// write returns, A places both in order and intact.
//
// shrunk: A's budget shrinks below the head before B fills. No live
// member can carry the head: B drops it at once and places the 100-byte
// datagram (L37's rule still holds for a wide head).
func TestPacketWideHeadFill_W4REL5(t *testing.T) {
	if sz := unsafe.Sizeof(pdesc{}); sz != 32 {
		t.Fatalf("pdesc is %d bytes, want 32: the wide flag must fit the padding", sz)
	}
	for _, tc := range []struct {
		name   string
		blockA bool
	}{
		{"blocked", true},
		{"shrunk", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
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
				if mx, mn := dpLocked(s, func(_ *stream, pk *packet) int { return pk.dgMax }), dpLocked(s, func(_ *stream, pk *packet) int { return pk.dgMin }); mx != 1400 || mn != 1100 {
					t.Fatalf("stimulus: dgMax %d, dgMin %d; want 1400, 1100", mx, mn)
				}
				if tc.blockA {
					pa.set(func(f *dpPort) { f.blocked = true })
				}
				dpWrite(t, s, 1, 1200)
				dpWrite(t, s, 2, 100)
				if w := dpLocked(s, func(_ *stream, pk *packet) bool { return pk.tx.front().wide }); !w {
					t.Fatal("stimulus: the 1200-byte head is not marked wide")
				}
				if !tc.blockA {
					pa.set(func(f *dpPort) { f.budget = 500 })
				}
				b := dpFill(lb, time.Now())
				fs := dpFrames(b)
				b.ReleaseRefs()
				c := dpCtr(s)
				if !tc.blockA {
					if dpCount(fs, wire.TypeDgram) != 1 || len(fs[len(fs)-1].body) != 100 || c.DropTooLarge != 1 || c.Sent != 1 {
						t.Fatalf("B placed %v, counters %+v; want the 100-byte datagram, DropTooLarge 1, Sent 1", fs, c)
					}
					dpEnd(s, io.EOF)
					return
				}
				if dpCount(fs, wire.TypeDgram) != 0 || c.DropTooLarge != 0 || c.Sent != 0 {
					t.Fatalf("B placed %v, counters %+v; want nothing placed or dropped", fs, c)
				}
				pa.set(func(f *dpPort) { f.blocked = false })
				b = dpFill(la, time.Now())
				var ids []uint64
				for _, f := range dpFrames(b) {
					if f.typ != wire.TypeDgram {
						continue
					}
					id := dpID(f.body)
					if want := map[uint64]int{1: 1200, 2: 100}[id]; !bytes.Equal(f.body, dpPayload(id, want)) {
						t.Fatalf("DGRAM %d (id %d): body corrupted", f.seq, id)
					}
					ids = append(ids, id)
				}
				b.ReleaseRefs()
				if c = dpCtr(s); len(ids) != 2 || ids[0] != 1 || ids[1] != 2 || c.Sent != 2 || c.DropTooLarge != 0 || c.DropAge != 0 {
					t.Fatalf("A placed ids %v, counters %+v; want 1, 2 and Sent 2", ids, c)
				}
				dpEnd(s, io.EOF)
			})
		})
	}
}
