package session

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Status of packet sessions (M2 design §A7.2; M2-D61; Revision 1, R1-31)
// and the self-load gauge of their carriers (M2-D26; R1-33).

// TestPacketStatusSnapshot: a packet session's Status reports its kind,
// its MaxPayload and its packet counters — Sent, Received, PeerReceived
// (from the peer's PACKs) — and counts datagram payload bytes in TxBytes,
// RxBytes and DeliveredBytes; the byte-stream fields (AckedBytes,
// RetransmittedBytes, Window, PeerWindow) are 0. A stream session reports
// no packet counters. In the report a carrier's refused DGRAMs move from
// Sent to DropTooLarge, so the send-side identity holds over public fields
// (R1-31).
func TestPacketStatusSnapshot(t *testing.T) {
	t.Run("refused DGRAMs count in DropTooLarge (R1-31)", func(t *testing.T) {
		for _, tc := range []struct {
			ctr     PacketCounters
			refused uint64
			sent    uint64
			tooBig  uint64
		}{
			{PacketCounters{Sent: 10, DropTooLarge: 1}, 0, 10, 1},
			{PacketCounters{Sent: 10, DropTooLarge: 1}, 3, 7, 4},
			{PacketCounters{Sent: 2}, 5, 0, 2}, // a carrier read after the session: never below 0
		} {
			r := pktReport(tc.ctr, tc.refused)
			if r.Sent != tc.sent || r.DropTooLarge != tc.tooBig {
				t.Fatalf("pktReport(%+v, %d) = Sent %d DropTooLarge %d; want %d, %d", tc.ctr, tc.refused, r.Sent, r.DropTooLarge, tc.sent, tc.tooBig)
			}
			if r.Sent+r.DropTooLarge != tc.ctr.Sent+tc.ctr.DropTooLarge {
				t.Fatalf("pktReport changed the sum Sent + DropTooLarge: %+v", r)
			}
		}
	})

	t.Run("dead carriers' refused DGRAMs count once (R1-31)", func(t *testing.T) {
		// More dead carriers than the dead-lane history keeps (8), with a
		// Refused count each: settled before their record is evicted, or
		// evicted before they settle. Either way every carrier's count is
		// in its record or in refusedGone exactly once, and Status moves
		// all of them from Sent to DropTooLarge.
		const n = maxDeadLanes + 3
		refused := func(i int) uint64 { return uint64(i + 1) }
		var total uint64
		for i := range n {
			total += refused(i)
		}
		for _, settleFirst := range []bool{true, false} {
			s := dpSession(dpOpt{})
			a := &actor{s: s}
			conns := make([]*carrier.Conn, n)
			s.mu.Lock()
			for i := range conns {
				conns[i] = &carrier.Conn{} // an identity only: no method that needs a carrier runs on it
				l := &lane{s: s, c: conns[i], port: dpNewPort(uint32(i+1), true), id: uint32(i + 1), state: LaneDead}
				a.removeLaneLocked(l, carrier.CauseLocalClose, "", time.Now())
				if settleFirst {
					a.settleStatsLocked(conns[i], carrier.Stats{Refused: refused(i)})
				}
			}
			if !settleFirst {
				if a.refusedGone != 0 {
					s.mu.Unlock()
					t.Fatalf("evicted unsettled records counted %d", a.refusedGone)
				}
				for i, c := range conns {
					a.settleStatsLocked(c, carrier.Stats{Refused: refused(i)})
				}
			}
			var inRecords uint64
			for _, d := range a.dead {
				inRecords += d.stats.Refused
			}
			gone := a.refusedGone
			a.publishLocked(time.Now())
			s.pk.ctr = PacketCounters{Sent: 100, DropTooLarge: 1}
			s.mu.Unlock()
			if want := refused(0) + refused(1) + refused(2); gone != want || gone+inRecords != total {
				t.Fatalf("settle first %v: refusedGone %d, in the records %d; want %d and %d in all", settleFirst, gone, inRecords, want, total)
			}
			if got := s.snap.Load().refusedGone; got != gone {
				t.Fatalf("settle first %v: published refusedGone %d, want %d", settleFirst, got, gone)
			}
			st := s.status()
			if st.Packet.Sent != 100-total || st.Packet.DropTooLarge != 1+total {
				t.Fatalf("settle first %v: Sent %d DropTooLarge %d; want %d, %d", settleFirst, st.Packet.Sent, st.Packet.DropTooLarge, 100-total, 1+total)
			}
		}
	})

	t.Run("end to end", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			l := wpLink(w, "p1", 1250)
			a, b := wpOpen(w, wpSpec(w, ModeSelector, 1400, l), nil)
			const n, size = 40, 500
			for i := range uint64(n) {
				dpWrite(t, a, i, size)
				dpWrite(t, b, 1000+i, size)
			}
			buf := make([]byte, 2000)
			for _, s := range []*Session{a, b} {
				for range n {
					if k, err := s.ReadFrom(buf); k != size || err != nil {
						t.Fatalf("%v: ReadFrom = %d, %v", s.Role(), k, err)
					}
				}
			}
			time.Sleep(2 * time.Second) // two PacketPing (1 s): the PACKs reported every datagram
			for _, s := range []*Session{a, b} {
				st := s.Status()
				if st.Kind != wire.KindDatagram || st.MaxPayload != 1250 || st.Packet == nil {
					t.Fatalf("%v: Kind %v MaxPayload %d Packet %v; want a packet session of 1250", s.Role(), st.Kind, st.MaxPayload, st.Packet)
				}
				p := *st.Packet
				if p.Sent != n || p.Received != n || p.PeerReceived != n || p.Duplicates != 0 ||
					p.DropQueue+p.DropAge+p.DropTooLarge+p.DropNoPath+p.DropRecvQueue+p.DropLate != 0 {
					t.Fatalf("%v: counters %+v; want %d sent, received and reported by the peer, no drops", s.Role(), p, n)
				}
				if st.TxBytes != n*size || st.RxBytes != n*size || st.DeliveredBytes != n*size {
					t.Fatalf("%v: TxBytes %d RxBytes %d DeliveredBytes %d; want %d each", s.Role(), st.TxBytes, st.RxBytes, st.DeliveredBytes, n*size)
				}
				if st.AckedBytes+st.RetransmittedBytes != 0 || st.Window != 0 || st.PeerWindow != 0 {
					t.Fatalf("%v: stream fields AckedBytes %d Retransmitted %d Window %d PeerWindow %d; want 0", s.Role(), st.AckedBytes, st.RetransmittedBytes, st.Window, st.PeerWindow)
				}
			}
			ls := w.link("s1")
			sa, sb := w.open(ModeSelector, nil, ls)
			for _, s := range []*Session{sa, sb} {
				if st := s.Status(); st.Kind != wire.KindStream || st.Packet != nil || st.MaxPayload != 0 {
					t.Fatalf("stream session %v: Kind %v Packet %v MaxPayload %d", s.Role(), st.Kind, st.Packet, st.MaxPayload)
				}
			}
		})
	})
}

// TestPacketSelectorNoGauge (M2-D26, R1-33): a datagram carrier starts
// without a self-load gauge — nothing is submitted on it, so a packet
// selector on datagram carriers has no self-load gauge — while a stream
// carrier, also one of a packet session (where DGRAM bytes are DATA),
// keeps its factory's gauge as in M1.
func TestPacketSelectorNoGauge(t *testing.T) {
	g := []*carrier.Gauge{carrier.NewGauge(), carrier.NewGauge()}
	a := &actor{d: &dialer{gauges: g}}
	if got := a.laneGauge(wire.KindDatagram, 0); got != nil {
		t.Fatal("a datagram carrier starts with a self-load gauge")
	}
	if got := a.laneGauge(wire.KindStream, 1); got != g[1] {
		t.Fatal("a stream carrier lost its factory's gauge")
	}
	if got := (&actor{d: &dialer{}}).laneGauge(wire.KindStream, 0); got != nil {
		t.Fatal("a gauge without a health layer")
	}
}
