package rendr

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// End-to-end rows of a mixed packet bond whose stream member joins after
// the OPEN (C4-F2; L37, M2-D43, M2-D45): the passive reports the joined
// stream member as a member once its JOIN_ACK is placed, but routes data on
// it only from the dialer's SCHED that lists it (plan:147). A datagram only
// a stream lane can carry, written in that window, waits for the member
// within Packet.MaxAge instead of being dropped as too large; when the
// member dies first, it is dropped and counted (DropTooLarge, L37); when
// the SCHED does not come within MaxAge, it ages out (DropAge). Helpers
// start with "cf".

// cfBond is a bond Peer of one raw datagram factory (MTU 1400, budget
// 1375) and one stream factory whose dials wait for gate, with both links
// at the given one-way delay, opened as a packet session (MaxPayload
// 65,507: a stream factory exists). The OPEN rides the datagram carrier;
// the stream carrier dials once gate closes and JOINs.
type cfBond struct {
	e      *pePair
	sl     *rendrtest.Link
	gate   chan struct{}
	dc, pc *PacketConn
}

func cfOpen(t *testing.T, pcfg Config, delay time.Duration) *cfBond {
	t.Helper()
	b := &cfBond{gate: make(chan struct{})}
	b.e = peNew(t, Config{}, pcfg, nil, 0, "udp")
	b.e.links[0].SetDelay(rendrtest.Up, delay, 0)
	b.e.links[0].SetDelay(rendrtest.Down, delay, 0)
	b.sl = rendrtest.NewLink(rendrtest.LinkConfig{Name: "tcp", Accept: b.e.ln.Handle})
	b.sl.SetDelay(delay, 0)
	t.Cleanup(func() { b.sl.Close() })
	tcp := StreamCarrier{Name: "tcp", Dial: func(ctx context.Context) (net.Conn, error) {
		select {
		case <-b.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return b.sl.Dial(ctx)
	}}
	p := b.e.peer(peDatagramCarrier(b.e.links[0], 1400), tcp)
	b.dc, b.pc = peOpen(t, p, b.e.ln, DialOptions{Mode: ModeBond})
	if b.dc.MaxPayload() != 65507 || b.pc.MaxPayload() != 65507 {
		t.Fatalf("MaxPayload %d / %d, want 65,507", b.dc.MaxPayload(), b.pc.MaxPayload())
	}
	if n := len(peLive(b.pc)); n != 1 {
		t.Fatalf("the passive has %d live carriers before the stream dial, want 1 (the OPEN carrier)", n)
	}
	return b
}

// streamMember waits (1 ms polls, virtual) until the passive's Status lists
// a stream carrier as a member and returns that snapshot.
func (b *cfBond) streamMember(t *testing.T) SessionStatus {
	t.Helper()
	return b.streamMemberOf(t, b.pc)
}

// streamMemberOf opens the stream dial gate and waits (1 ms polls,
// virtual) until c's Status lists a stream carrier as a member.
func (b *cfBond) streamMemberOf(t *testing.T, c *PacketConn) SessionStatus {
	t.Helper()
	close(b.gate)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := c.Status()
		for _, cs := range st.Carriers {
			if cs.Kind == KindStream && cs.State == CarrierMember {
				return st
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the passive never listed the stream member")
		}
		time.Sleep(time.Millisecond)
	}
}

// write writes datagrams seq first…first+n−1 of seed on c: every even seq
// big bytes (only a stream carrier can carry it), every odd one small.
func cfWrite(t *testing.T, c *PacketConn, seed, first uint64, n, big, small int) {
	t.Helper()
	buf := make([]byte, big)
	for i := range uint64(n) {
		size := small
		if (first+i)%2 == 0 {
			size = big
		}
		if _, err := c.WriteTo(rendrtest.PacketPayload(buf, seed, first+i, size, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo seq %d: %v", first+i, err)
		}
	}
}

func (b *cfBond) end(t *testing.T) {
	t.Helper()
	peEnd(t, b.dc, b.pc)
	b.sl.Close()
	b.e.close()
}

// TestPacketBigAwaitsSchedE2E_L37 (C4-F2): right after the passive lists
// the joined stream member, and before the dialer's SCHED that lists it is
// applied, the passive's application writes 8 datagrams of 60,000 B
// (above the datagram member's budget) between 8 of 1,000 B. All 16 reach
// the dialer intact and exactly once; the big ones ride the stream member;
// nothing is dropped as too large.
func TestPacketBigAwaitsSchedE2E_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// 10 ms RTT: the SCHED comes about 10 ms after the member is listed, and
		// the new stream member's first capacity rounds fit in MaxAge (100 ms).
		b := cfOpen(t, Config{}, 5*time.Millisecond)
		st := b.streamMember(t)
		cfWrite(t, b.pc, 7, 0, 16, 60000, 1000)
		// Stimulus: every write happened before the SCHED that routes the
		// stream member was applied (routing and Status change in one
		// critical section, L27).
		if after := b.pc.Status(); after.SchedEpoch != st.SchedEpoch {
			t.Fatalf("INVALID: the passive applied SCHED %d → %d before the writes ended", st.SchedEpoch, after.SchedEpoch)
		}
		v := peRecv(t, b.dc, 7, 16, time.Second)
		r := v.Result()
		ps := b.pc.Status()
		if r.Unique != 16 || r.Duplicates != 0 || r.Corrupt != 0 || r.BadSize != 0 {
			t.Fatalf("dialer received %+v; passive counters %+v", r, *ps.Packet)
		}
		if ps.SchedEpoch == st.SchedEpoch {
			t.Fatal("the passive never applied a later SCHED: the stream member was routed without one")
		}
		if c := ps.Packet; c.DropTooLarge != 0 || c.DropAge != 0 || c.DropQueue != 0 || c.Sent != 16 {
			t.Fatalf("passive counters %+v; want 16 sent, nothing dropped", *c)
		}
		var tcpTx uint64
		for _, cs := range ps.Carriers {
			if cs.Kind == KindStream {
				tcpTx += cs.TxBytes
			}
		}
		if tcpTx < 8*60000 {
			t.Fatalf("the stream member carried %d payload bytes, want the 8 big datagrams (≥ %d)", tcpTx, 8*60000)
		}
		b.end(t)
	})
}

// TestPacketBigHeldMemberDiesE2E_L37: the stream member the big datagrams
// wait for dies before any SCHED routes it (its link is killed and
// refuses redials): no carrier can carry them any more, so they are
// dropped and counted as too large at once (L37) while the small ones are
// delivered; WriteTo of a big one afterwards is dropped the same way.
func TestPacketBigHeldMemberDiesE2E_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := cfOpen(t, Config{}, 20*time.Millisecond)
		st := b.streamMember(t)
		cfWrite(t, b.pc, 9, 0, 8, 60000, 1000)
		if after := b.pc.Status(); after.SchedEpoch != st.SchedEpoch {
			t.Fatalf("INVALID: the passive applied SCHED %d → %d before the writes ended", st.SchedEpoch, after.SchedEpoch)
		}
		b.sl.SetRefuse(true)
		b.sl.Kill()
		peWait(t, time.Second, "the passive's stream member died", func() bool {
			for _, cs := range peLive(b.pc) {
				if cs.Kind == KindStream {
					return false
				}
			}
			return true
		})
		cfWrite(t, b.pc, 9, 8, 2, 60000, 1000)
		v := peRecv(t, b.dc, 9, 5, 500*time.Millisecond)
		r := v.Result()
		c := *b.pc.Status().Packet
		if r.Unique != 5 || r.Duplicates != 0 || r.Corrupt != 0 || r.BadSize != 0 {
			t.Fatalf("dialer received %+v, want the 5 small datagrams; passive counters %+v", r, c)
		}
		if c.DropTooLarge != 5 || c.Sent != 5 || c.DropAge != 0 || c.DropQueue != 0 || c.DropNoPath != 0 {
			t.Fatalf("passive counters %+v; want 5 sent and the 5 big ones DropTooLarge", c)
		}
		b.end(t)
	})
}

// TestPacketBigHeldAgesE2E_L37: the SCHED that would route the stream
// member does not come (its link stalls while the JOIN_ACK is in flight):
// the big datagrams waiting for it age out within Packet.MaxAge (DropAge,
// M2-D35) — the wait is bounded, they are neither held longer nor counted
// as too large — and once the link resumes the member is routed and later
// big datagrams ride it.
func TestPacketBigHeldAgesE2E_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pcfg := Config{}
		pcfg.Packet.MaxAge = 50 * time.Millisecond
		b := cfOpen(t, pcfg, 20*time.Millisecond)
		st := b.streamMember(t)
		b.sl.SetStall(true)
		cfWrite(t, b.pc, 11, 0, 8, 60000, 1000)
		if after := b.pc.Status(); after.SchedEpoch != st.SchedEpoch {
			t.Fatalf("INVALID: the passive applied SCHED %d → %d before the writes ended", st.SchedEpoch, after.SchedEpoch)
		}
		time.Sleep(60 * time.Millisecond) // MaxAge + 10 ms, the SCHED still held
		ps := b.pc.Status()
		if ps.SchedEpoch != st.SchedEpoch {
			t.Fatalf("INVALID: SCHED %d → %d applied during the stall", st.SchedEpoch, ps.SchedEpoch)
		}
		if c := *ps.Packet; c.DropAge != 4 || c.DropTooLarge != 0 || c.Sent != 4 || c.DropQueue != 0 {
			t.Fatalf("passive counters %+v at MaxAge + 10 ms; want the 4 big ones DropAge, 4 sent", c)
		}
		b.sl.SetStall(false)
		peWait(t, 5*time.Second, "the passive applied the SCHED", func() bool { return b.pc.Status().SchedEpoch != st.SchedEpoch })
		cfWrite(t, b.pc, 11, 8, 4, 60000, 1000)
		v := peRecv(t, b.dc, 11, 8, time.Second)
		r := v.Result()
		c := *b.pc.Status().Packet
		if r.Unique != 8 || r.Duplicates != 0 || r.Corrupt != 0 || r.BadSize != 0 {
			t.Fatalf("dialer received %+v, want the first 4 small and the 4 later; passive counters %+v", r, c)
		}
		if c.DropAge != 4 || c.DropTooLarge != 0 || c.Sent != 8 {
			t.Fatalf("passive counters %+v; want 8 sent, the first 4 big DropAge", c)
		}
		b.end(t)
	})
}

// TestPacketBigDialerAtAttachE2E_L37: the dialer side of C4-F2. The dialer
// decides its own data lanes: a stream member is a data lane in the same
// step that its Status lists it (attachLocked, L27), so 8 datagrams of
// 60,000 B written right after its Status lists the member — between 8 of
// 1,000 B — all reach the passive intact and exactly once, the big ones on
// the stream member, nothing dropped.
func TestPacketBigDialerAtAttachE2E_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := cfOpen(t, Config{}, 5*time.Millisecond)
		b.streamMemberOf(t, b.dc)
		cfWrite(t, b.dc, 13, 0, 16, 60000, 1000)
		v := peRecv(t, b.pc, 13, 16, time.Second)
		r := v.Result()
		ds := b.dc.Status()
		if r.Unique != 16 || r.Duplicates != 0 || r.Corrupt != 0 || r.BadSize != 0 {
			t.Fatalf("passive received %+v; dialer counters %+v", r, *ds.Packet)
		}
		if c := ds.Packet; c.DropTooLarge != 0 || c.DropAge != 0 || c.DropQueue != 0 || c.Sent != 16 {
			t.Fatalf("dialer counters %+v; want 16 sent, nothing dropped", *c)
		}
		var tcpTx uint64
		for _, cs := range ds.Carriers {
			if cs.Kind == KindStream {
				tcpTx += cs.TxBytes
			}
		}
		if tcpTx < 8*60000 {
			t.Fatalf("the stream member carried %d payload bytes, want the 8 big datagrams (≥ %d)", tcpTx, 8*60000)
		}
		b.end(t)
	})
}
