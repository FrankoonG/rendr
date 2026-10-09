package rendr

import (
	"testing"
	"testing/synctest"
	"time"
)

// pkMembers returns the frame budgets of c's live member carriers.
func pkMembers(c *PacketConn) []int {
	var mtus []int
	for _, cs := range c.Status().Carriers {
		if cs.DeathCause == CauseNone && cs.State == CarrierMember {
			mtus = append(mtus, cs.MTU)
		}
	}
	return mtus
}

// pkExchange writes n datagrams of exactly MaxPayload bytes, each with its
// own pattern, from a to b and requires each to arrive intact, then a's
// counters to show n sent and none refused as too large.
func pkExchange(t *testing.T, side string, a, b *PacketConn, n int) {
	t.Helper()
	size := a.MaxPayload()
	msg := make([]byte, size)
	buf := make([]byte, size+1)
	for i := range n {
		for j := range msg {
			msg[j] = byte(i*31 + j)
		}
		if w, err := a.WriteTo(msg, nil); err != nil || w != size {
			t.Fatalf("%s: WriteTo(%d bytes) #%d: %d, %v", side, size, i, w, err)
		}
		b.SetReadDeadline(time.Now().Add(time.Second))
		r, _, err := b.ReadFrom(buf)
		if err != nil || r != size || string(buf[:r]) != string(msg) {
			t.Fatalf("%s: datagram #%d of %d bytes: %d bytes, %v", side, i, size, r, err)
		}
	}
	if c := *a.Status().Packet; c.Sent != uint64(n) || c.DropTooLarge != 0 {
		t.Fatalf("%s: sender counters %+v, want %d sent and no DropTooLarge", side, c, n)
	}
}

// TestMuxDatagramJoinBudget_L37 (M3-D24, §A3.3; L37): a packet JOIN placed
// on a live datagram trunk offers the trunk's current budget in
// JOIN.rxNext (patchViewOffer), and neither end calls SetBudget on that
// view (the trunk's budget is fixed once it started). Two bond packet
// sessions on one Peer of two datagram factories: the second session's
// OPEN and JOIN both ride the first session's trunks (two fast paths, no
// factory call: stimulus). Both of its members run at the trunks' budget
// on both ends, and datagrams of its MaxPayload cross both ways intact.
func TestMuxDatagramJoinBudget_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		p := h.peer(h.carrier("h1", 1, nil), h.carrier("h2", 2, nil))
		d1, p1 := peOpen(t, p, h.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 5*time.Second, "session 1's two members", func() bool { return len(pkMembers(d1)) == 2 && len(pkMembers(p1)) == 2 })
		d2, p2 := peOpen(t, p, h.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 5*time.Second, "session 2's two members", func() bool { return len(pkMembers(d2)) == 2 && len(pkMembers(p2)) == 2 })
		if m := h.d.Status().Mux; m.Carriers != 2 || m.Views != 4 || m.FastPaths != 2 {
			t.Fatalf("dialer Mux %+v, want session 2's OPEN and JOIN on session 1's two trunks", m)
		}
		budget := pkMembers(d1)[0]
		for _, s := range []struct {
			side string
			c    *PacketConn
		}{{"dialer 1", d1}, {"passive 1", p1}, {"dialer 2", d2}, {"passive 2", p2}} {
			for _, mtu := range pkMembers(s.c) {
				if mtu != budget {
					t.Fatalf("%s: member budgets %v, want %d (the trunks')", s.side, pkMembers(s.c), budget)
				}
			}
		}
		if mp := d2.MaxPayload(); mp <= 0 || mp > budget-25 || mp != p2.MaxPayload() || mp != d1.MaxPayload() {
			t.Fatalf("MaxPayload %d/%d (session 1 %d) on trunks of budget %d", mp, p2.MaxPayload(), d1.MaxPayload(), budget)
		}
		pkExchange(t, "dialer 2 → passive 2", d2, p2, 16)
		pkExchange(t, "passive 2 → dialer 2", p2, d2, 16)
		for _, c := range []*PacketConn{d1, p1, d2, p2} {
			c.Close()
		}
		h.close()
	})
}
