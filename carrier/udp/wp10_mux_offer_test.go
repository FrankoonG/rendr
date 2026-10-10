package udp

import (
	"errors"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// The factory MTU against the interface clamp on a shared carrier (W4
// L3-1 with rendr mux, M3-D24): the second packet session of a Peer opens
// as a view of the first session's live udp trunk (the pool's fast path,
// no factory call). Its OPEN must lower its pmtu to the trunk's budget
// exactly as the dialled first OPEN did, else the passive accepts a
// MaxPayload the shared carrier cannot carry.

// TestUDPClampedMuxFastPathOffer: factory MTU 3,991 (unclamped), every
// socket clamped to 1,463 bytes at Dial. Two selector packet sessions on
// one Peer, the second while the first lives: one trunk, two views, one
// fast path (stimulus). Both sessions fix the same MaxPayload, at most the
// trunk's budget − 25 on both ends, and datagrams of exactly that size
// cross both ways on the second session, none refused as too large (load
// and integrity). 2,000 bytes of metadata, which no REL slot of the live
// trunk carries, dial a carrier of their own through the pool and end
// with ErrMetadataTooLarge (poolFactories' openFit record).
func TestUDPClampedMuxFastPathOffer(t *testing.T) {
	defer wp5NoLeak(t)()
	wp5Swap(t, &sysInterfaceTable, offerTable)
	e := newOfferPair(t)
	defer e.end()
	c := Carrier("u", "udp4", e.addr, Options{MaxDatagram: 4000})
	c.MTU = 4000 - flowHeaderLen // the factory budget Carrier reports when it cannot clamp in advance
	p := e.peer(c)

	d1, p1 := e.open(p)
	defer closePair(t, d1, p1)
	d2, p2 := e.open(p)
	defer closePair(t, d2, p2)
	if m := e.d.Status().Mux; m.Carriers != 1 || m.Views != 2 || m.FastPaths != 1 {
		t.Fatalf("dialer Mux %+v, want the second session as a view of the first one's trunk (stimulus)", m)
	}
	const clamped = offerMTU - 28 - flowHeaderLen
	for _, s := range []struct {
		side string
		c    *rendr.PacketConn
	}{{"dialer 1", d1}, {"passive 1", p1}, {"dialer 2", d2}, {"passive 2", p2}} {
		mtu := liveMTU(t, s.side, s.c)
		if mtu != clamped {
			t.Fatalf("%s: carrier MTU %d, want the clamped %d (stimulus)", s.side, mtu, clamped)
		}
		if mp := s.c.MaxPayload(); mp > mtu-25 || mp < 512 {
			t.Fatalf("%s: MaxPayload %d on a carrier of MTU %d: want 512 … %d", s.side, mp, mtu, mtu-25)
		}
	}
	if d2.MaxPayload() != d1.MaxPayload() || p2.MaxPayload() != d2.MaxPayload() {
		t.Fatalf("MaxPayload: session 1 %d/%d, session 2 %d/%d, want one value", d1.MaxPayload(), p1.MaxPayload(), d2.MaxPayload(), p2.MaxPayload())
	}
	exchangeMax(t, "dialer 2 → passive 2", d2, p2, 8)
	exchangeMax(t, "passive 2 → dialer 2", p2, d2, 8)

	const grace = 2 * time.Second
	start := time.Now()
	_, err := p.DialPacket(wp5Ctx(t), rendr.DialOptions{Metadata: make([]byte, 2000), NoPathGrace: grace})
	if el := time.Since(start); !errors.Is(err, rendr.ErrMetadataTooLarge) || errors.Is(err, rendr.ErrNoPath) || el > grace+2*time.Second {
		t.Fatalf("DialPacket with 2000 bytes of metadata beside a live trunk: %v after %v, want ErrMetadataTooLarge within NoPathGrace + 2 s", err, el)
	}
}
