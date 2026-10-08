package udp

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// The factory MTU against the interface clamp (W4 L3-1; R1-16, M2-D49,
// M2-D52): a socket's MaxDatagram is lowered to the interface MTU, so a
// factory MTU taken from the unclamped option is more than its carriers
// carry. The OPEN's metadata check, the MaxPayload offer and the race's
// OPEN filter must follow what the carrier carries, else WriteTo accepts
// datagrams that every carrier then refuses (DropTooLarge), and metadata
// that no carrier can carry ends in ErrNoPath after NoPathGrace instead of
// ErrMetadataTooLarge.

// offerMTU is the fake interface MTU of the loopback address.
const offerMTU = 1500

// offerTable is an interface table in which the IPv4 loopback address sits
// on an interface of MTU offerMTU (the rows that can lower below only, as
// interfaceTable reports them).
func offerTable(_ context.Context, below int) ([]ifaceMTU, error) {
	if offerMTU >= below {
		return nil, nil
	}
	return []ifaceMTU{{mtu: offerMTU, addrs: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}}}, nil
}

// offerPair is a dialer and a passive Runtime, the passive listening on one
// udp.Listen socket of the loopback address with MaxDatagram 4000.
type offerPair struct {
	t    *testing.T
	d, p *rendr.Runtime
	ln   *rendr.Listener
	addr string // the passive socket's address
}

func newOfferPair(t *testing.T) *offerPair {
	t.Helper()
	e := &offerPair{t: t}
	var err error
	if e.d, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.d.Close() })
	if e.p, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.p.Close() })
	ls, err := Listen("udp4", "127.0.0.1:0", Options{MaxDatagram: 4000})
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ls.LocalAddr().String()
	if e.ln, err = e.p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(ls)}}); err != nil { // owns ls
		ls.Close()
		t.Fatal(err)
	}
	return e
}

// end closes both Runtimes (before the leak check, which runs ahead of
// the test's cleanups).
func (e *offerPair) end() {
	e.d.Close()
	e.p.Close()
}

// peer returns a Peer of the dialer Runtime over factory c.
func (e *offerPair) peer(c rendr.DatagramCarrier) *rendr.Peer {
	e.t.Helper()
	p, err := e.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{c}})
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// open dials one selector packet session on p and accepts it.
func (e *offerPair) open(p *rendr.Peer) (dc, pc *rendr.PacketConn) {
	t := e.t
	t.Helper()
	type dialed struct {
		c   *rendr.PacketConn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.DialPacket(wp5Ctx(t), rendr.DialOptions{})
		ch <- dialed{c, err}
	}()
	pp, err := e.ln.AcceptPacket(wp5Ctx(t))
	if err != nil {
		t.Fatalf("AcceptPacket: %v", err)
	}
	if pc, err = pp.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		pc.Close()
		t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// liveMTU returns the frame budget of c's one live carrier.
func liveMTU(t *testing.T, side string, c *rendr.PacketConn) int {
	t.Helper()
	var live []rendr.CarrierStatus
	for _, cs := range c.Status().Carriers {
		if cs.DeathCause == rendr.CauseNone {
			live = append(live, cs)
		}
	}
	if len(live) != 1 {
		t.Fatalf("%s: %d live carriers, want 1: %+v", side, len(live), c.Status().Carriers)
	}
	return live[0].MTU
}

// exchangeMax sends n datagrams of MaxPayload bytes from a to b, one at a
// time, each with its own pattern, and requires that each arrives intact;
// then a's counters must show n sent and nothing refused as too large.
func exchangeMax(t *testing.T, side string, a, b *rendr.PacketConn, n int) {
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
		_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
		r, _, err := b.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%s: datagram #%d of %d bytes not delivered: %v (sender %+v)", side, i, size, err, *a.Status().Packet)
		}
		if !bytes.Equal(buf[:r], msg) {
			t.Fatalf("%s: datagram #%d arrived as %d bytes, not the %d sent", side, i, r, size)
		}
	}
	if c := *a.Status().Packet; c.Sent != uint64(n) || c.DropTooLarge != 0 {
		t.Fatalf("%s: sender counters %+v, want %d sent and no DropTooLarge", side, c, n)
	}
}

// closePair closes both sessions and waits for their ends.
func closePair(t *testing.T, dc, pc *rendr.PacketConn) {
	t.Helper()
	dc.Close()
	pc.Close()
	for _, ch := range []<-chan struct{}{dc.Done(), pc.Done()} {
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
			t.Fatal("a session did not end within 30 s of its Close")
		}
	}
}

// checkOffer opens a packet session on p and requires a MaxPayload that
// both ends' carriers carry — MaxPayload ≤ CarrierStatus.MTU − 25 on both
// ends — and datagrams of exactly MaxPayload bytes delivered intact both
// ways, none refused as too large (load and integrity).
func checkOffer(t *testing.T, e *offerPair, p *rendr.Peer) {
	t.Helper()
	dc, pc := e.open(p)
	defer closePair(t, dc, pc)
	for _, s := range []struct {
		side string
		c    *rendr.PacketConn
	}{{"dialer", dc}, {"passive", pc}} {
		mtu := liveMTU(t, s.side, s.c)
		if mtu != offerMTU-28-flowHeaderLen {
			t.Fatalf("%s: carrier MTU %d, want the clamped %d (stimulus)", s.side, mtu, offerMTU-28-flowHeaderLen)
		}
		if mp := s.c.MaxPayload(); mp > mtu-25 || mp < 512 {
			t.Fatalf("%s: MaxPayload %d on a carrier of MTU %d: want 512 … %d", s.side, mp, mtu, mtu-25)
		}
	}
	if dc.MaxPayload() != pc.MaxPayload() {
		t.Fatalf("MaxPayload %d (dialer) and %d (passive) differ", dc.MaxPayload(), pc.MaxPayload())
	}
	exchangeMax(t, "dialer → passive", dc, pc, 8)
	exchangeMax(t, "passive → dialer", pc, dc, 8)
}

// TestUDPClampedFactoryOffer: both ends use MaxDatagram 4000 on a loopback
// address whose interface MTU is 1500, so every socket carries 1,472-byte
// UDP payloads. udp.Carrier for a literal address clamps its MTU as Dial
// will: DialPacket with 2,000 bytes of metadata, more than a clamped
// carrier's OPEN can carry, returns ErrMetadataTooLarge at once (within
// 100 ms) instead of ErrNoPath after NoPathGrace; without metadata the
// session's MaxPayload fits both ends' carriers and datagrams of that size
// arrive intact both ways.
func TestUDPClampedFactoryOffer(t *testing.T) {
	defer wp5NoLeak(t)()
	wp5Swap(t, &sysInterfaceTable, offerTable)
	e := newOfferPair(t)
	defer e.end()
	c := Carrier("u", "udp4", e.addr, Options{MaxDatagram: 4000})
	p := e.peer(c)

	start := time.Now()
	_, err := p.DialPacket(wp5Ctx(t), rendr.DialOptions{Metadata: make([]byte, 2000)})
	if el := time.Since(start); !errors.Is(err, rendr.ErrMetadataTooLarge) || el > 100*time.Millisecond {
		t.Fatalf("DialPacket with 2000 bytes of metadata: %v after %v, want ErrMetadataTooLarge within 100 ms", err, el)
	}
	checkOffer(t, e, p)
}

// TestUDPClampedAtDialOffer: the interface clamp appears only when Dial
// runs (a host name, or a route that changed after udp.Carrier returned),
// so the factory MTU is the unclamped 3,991 bytes. The OPEN's MaxPayload
// offer follows the carrier's clamped cmtu offer, so the session's
// MaxPayload still fits both ends' carriers and datagrams of that size
// arrive intact; 2,000 bytes of metadata, which the factory MTU admits but
// no clamped carrier carries, end DialPacket with ErrMetadataTooLarge once
// NoPathGrace passed (no OPEN ever left), not with a bare ErrNoPath.
func TestUDPClampedAtDialOffer(t *testing.T) {
	defer wp5NoLeak(t)()
	wp5Swap(t, &sysInterfaceTable, offerTable)
	e := newOfferPair(t)
	defer e.end()
	c := Carrier("u", "udp4", e.addr, Options{MaxDatagram: 4000})
	c.MTU = 4000 - flowHeaderLen // the factory budget Carrier reports when it cannot clamp in advance
	p := e.peer(c)
	checkOffer(t, e, p)

	const grace = 3 * time.Second
	start := time.Now()
	_, err := p.DialPacket(wp5Ctx(t), rendr.DialOptions{Metadata: make([]byte, 2000), NoPathGrace: grace})
	if el := time.Since(start); !errors.Is(err, rendr.ErrMetadataTooLarge) || errors.Is(err, rendr.ErrNoPath) || el > grace+2*time.Second {
		t.Fatalf("DialPacket with 2000 bytes of metadata: %v after %v, want ErrMetadataTooLarge within NoPathGrace + 2 s", err, el)
	}
}
