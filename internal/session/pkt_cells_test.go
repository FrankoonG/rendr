package session

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketRaceCellsBounded (M5 review A1/A2 mechanism; invariant 4): a
// race session's placement-count cells stay bounded under carrier churn. A
// stable datagram member and 200 datagram members joining one after the
// other each place 64 datagrams, then the churning member dies with every
// placement written (no hand-back: its record keeps its cells, since a
// hand-back could still come). The pool holds at most the placement
// records of the live members and of the maxDying latest dead ones (recLen
// cells each), plus the queue; at the end every placement is in Sent and
// every copy in Race.Copies. Mutants: a dead lane's record never released
// (its cells pinned for the session's life); a descriptor's reference not
// dropped when it leaves the ring.
func TestPacketRaceCellsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, ls := hbRace(t, time.Second, 1)
		stable := ls[0]
		const rounds, per = 200, 64
		maxCells := 0
		for r := range rounds {
			l := hbRaceLane(s, uint32(10+r))
			dpIdle(l)
			for i := range per {
				dpWrite(t, s, uint64(r*per+i), 100)
			}
			for _, m := range []*lane{stable, l} {
				n := 0
				for range 8 { // the writer self-continues until a Fill appends nothing
					b := dpFill(m, time.Now())
					k := b.Len()
					for i := range k {
						if b.Frame(i).Header.Type == wire.TypeDgram {
							n++
						}
					}
					b.ReleaseRefs()
					if k == 0 {
						break
					}
				}
				if n != per {
					t.Fatalf("round %d: a member placed %d datagrams, want %d", r, n, per)
				}
			}
			dpKill(s, l)
			cells := dpLocked(s, func(_ *stream, pk *packet) int { return len(pk.tx.cells) })
			maxCells = max(maxCells, cells)
		}
		bound := int((maxDying + 3) * recLen)
		if maxCells > bound {
			t.Fatalf("the cell pool grew to %d cells over %d member deaths, want ≤ %d (live and maxDying dead records)", maxCells, rounds, bound)
		}
		t.Logf("cell pool high-water %d over %d member deaths (bound %d)", maxCells, rounds, bound)
		c := dpCtr(s)
		copies := dpLocked(s, func(_ *stream, pk *packet) uint64 { return pk.copies })
		if c.Sent != rounds*per || copies != rounds*per || hbDrops(c) != 0 {
			t.Fatalf("%+v with Race.Copies %d, want every datagram Sent once and copied once", c, copies)
		}
		dpEnd(s, io.EOF)
	})
}
