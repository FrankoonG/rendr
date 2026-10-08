package session

import (
	"bytes"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketCappedStreamLaneWoken_L32: a bond's stream member at its
// capacity is still woken, once, for a datagram queued for it, so that its
// Fill marks the batch cap-blocked and the PONG that frees capacity wakes
// its writer (M1's wake policy does the same for stream DATA). The walk
// used to skip such a lane: when its previous Fill had emptied the queue
// (no cap-blocked mark), nothing woke it when capacity freed, and the
// datagrams waited for a later WriteTo or aged out (DropAge) — the
// steady-state losses of TestPacketStreamLaneCapacity_L32 at GOMAXPROCS=2.
// Waking it never lets it place beyond its capacity, and a lane already
// marked is not woken again in the same episode.
func TestPacketCappedStreamLaneWoken_L32(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{mode: ModeBond, maxPayload: 4000})
		ld, pd := dpAddLane(s, 1, true, true)
		lst, pst := dpAddLane(s, 2, true, false)
		dpIdle(ld)
		dpIdle(lst)
		pst.set(func(f *dpPort) { f.capacity, f.inflight = 4000, 4000 }) // no spare capacity
		wd, ws := pd.wakeCount(), pst.wakeCount()

		dpWrite(t, s, 1, 3000) // txBig: only the stream lane can carry it
		if pd.wakeCount() != wd || pst.wakeCount() != ws+1 {
			t.Fatalf("a txBig datagram for a capped stream lane woke the datagram lane %d times and the stream lane %d times; want 0 and 1",
				pd.wakeCount()-wd, pst.wakeCount()-ws)
		}
		b := dpFill(lst, time.Now())
		if fs := dpFrames(b); dpCount(fs, wire.TypeDgram) != 0 || !b.CapBlocked() {
			t.Fatalf("the capped stream lane placed %v (cap-blocked %v); want nothing placed and the batch cap-blocked", fs, b.CapBlocked())
		}
		b.ReleaseRefs()

		// A second datagram in the same episode: the lane is marked, its
		// PONG will wake it; no further wake.
		dpWrite(t, s, 2, 3000)
		if pst.wakeCount() != ws+1 {
			t.Fatalf("the marked stream lane was woken again (%d wakes)", pst.wakeCount()-ws)
		}

		// Capacity frees (the PONG wakes the writer): both go out in order.
		pst.set(func(f *dpPort) { f.capacity, f.inflight = 8000, 0 })
		b = dpFill(lst, time.Now())
		var ids []uint64
		for _, f := range dpFrames(b) {
			if f.typ != wire.TypeDgram {
				continue
			}
			if !bytes.Equal(f.body, dpPayload(dpID(f.body), 3000)) {
				t.Fatalf("DGRAM %d: body corrupted", f.seq)
			}
			ids = append(ids, dpID(f.body))
		}
		b.ReleaseRefs()
		if c := dpCtr(s); len(ids) != 2 || ids[0] != 1 || ids[1] != 2 || c.Sent != 2 || c.DropAge+c.DropTooLarge != 0 {
			t.Fatalf("the stream lane placed ids %v, counters %+v; want 1, 2 and Sent 2", ids, c)
		}
		if pd.wakeCount() != wd {
			t.Fatalf("the datagram lane was woken %d times for txBig", pd.wakeCount()-wd)
		}
		dpEnd(s, io.EOF)
	})
}
