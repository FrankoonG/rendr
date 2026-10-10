package carrier

import (
	"slices"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestDatagramJumpStalePongNoProof_L14_L43: a PONG proves a forward jump
// only while the PING it answers is outstanding (m3 W2). The fseq window
// compares in u32 serial arithmetic (L14), so a datagram of the peer's own
// direction captured 2^31 + 5000 frames ago reads a window or more ahead.
// Replayed with the PONG to a PING this incarnation sent and saw answered,
// it is dropped and counted — both its frames — its DGRAM never reaches
// the endpoint, the window does not move, and the next genuine DGRAM is
// delivered (before the fix the replay moved the window to the old fseq
// and every genuine frame after it was late until ping_timeout). The
// control row: a genuine jump after an outage, whose datagram carries the
// PONG to the PING the carrier asked for and which is still outstanding,
// is taken; the same id with another nonce is not.
func TestDatagramJumpStalePongNoProof_L14_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		// The earlier exchange: the carrier's first PING, answered.
		_, pings := fjPings(p.read(), false)
		if len(pings) == 0 {
			t.Fatal("stimulus: the carrier wrote no PING after its start")
		}
		old := pings[0]
		if old.ID == 0 || old.Nonce != s.c.salt^uint64(old.ID) {
			t.Fatalf("stimulus: PING %+v is not a PING of this incarnation", old)
		}
		p.send(pingFrame(wire.TypePong, old))
		synctest.Wait()
		fjSettle(p)
		if s.c.pingOutstanding(old.ID, old.Nonce) {
			t.Fatalf("stimulus: PING %d is still outstanding after its PONG", old.ID)
		}
		p.send(dgramFrame(1, 100))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{1}) {
			t.Fatalf("delivered %v before the replay, want [1]", got)
		}
		p.read()
		d0 := s.c.Stats().Dropped

		// The replay: fseq top − (2^31 + 5000), serial arithmetic.
		top := p.fseq - 1
		stale := &rawPeer{io: p.io, fseq: top - (1<<31 + 5000)}
		if d := stale.fseq - top; int32(d) <= 0 || d < wire.FseqWindowBits {
			t.Fatalf("stimulus: the replayed fseq %d is not a window or more ahead of %d", stale.fseq, top)
		}
		stale.send(pingFrame(wire.TypePong, old), dgramFrame(100, 100))
		synctest.Wait()
		if d := s.c.Stats().Dropped - d0; d != 2 {
			t.Fatalf("dropped %d frames of the replayed datagram, want both", d)
		}
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{1}) {
			t.Fatalf("delivered %v, want [1]: the stale PONG proved the jump", got)
		}
		p.send(dgramFrame(2, 100))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{1, 2}) {
			t.Fatalf("delivered %v, want [1 2]: the window moved, the genuine DGRAM was late", got)
		}
		if d := s.c.Stats().Dropped - d0; d != 2 {
			t.Fatalf("dropped %d, want the 2 replayed frames only", d)
		}

		// The control: a genuine jump with the PONG to an outstanding PING.
		// The replay asked for a PING of the carrier (dgJumpClaim).
		_, asked := fjPings(p.read(), false)
		if len(asked) == 0 {
			t.Fatal("stimulus: the carrier asked for no PING after the unproven jump")
		}
		ours := asked[len(asked)-1]
		if !s.c.pingOutstanding(ours.ID, ours.Nonce) {
			t.Fatalf("stimulus: PING %d is not outstanding", ours.ID)
		}
		p.fseq += 5000 // lost in the outage
		// Its id with another nonce (another incarnation's PONG) proves
		// nothing.
		p.send(dgramFrame(50, 100), pingFrame(wire.TypePong, wire.Ping{ID: ours.ID, Nonce: ours.Nonce ^ 1}))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{1, 2}) {
			t.Fatalf("delivered %v, want [1 2]: a PONG with the outstanding id and another nonce proved the jump", got)
		}
		if d := s.c.Stats().Dropped - d0; d != 4 {
			t.Fatalf("dropped %d, want the 2 replayed and the 2 wrong-nonce frames", d)
		}
		p.send(dgramFrame(3, 100), pingFrame(wire.TypePong, ours), dgramFrame(4, 100))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{1, 2, 3, 4}) {
			t.Fatalf("delivered %v, want [1 2 3 4]: the PONG to an outstanding PING did not prove the jump", got)
		}
		if d := s.c.Stats().Dropped - d0; d != 4 {
			t.Fatalf("dropped %d, want the 4 unproven frames only", d)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}
