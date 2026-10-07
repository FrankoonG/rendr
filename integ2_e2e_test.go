package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// End-to-end rows of packet sessions that the wave-2 work packages left for
// integration 2 (M2 design §A11.4 step 4): two Runtimes joined by
// rendrtest.DatagramLinks (passive end: Listener.HandlePacket, or a
// transport of a chosen receive limit) or a DatagramHub (passive:
// FromPacketConn), inside synctest bubbles. Helpers start with "pe".

// peDatagramCarrier is the DatagramCarrier of a DatagramLink.
func peDatagramCarrier(l *rendrtest.DatagramLink, mtu int) DatagramCarrier {
	return DatagramCarrier{Name: l.Name(), Dial: l.Dial, MTU: mtu}
}

// pePair is two Runtimes, the passive's Listener and the datagram links
// between them.
type pePair struct {
	t     testing.TB
	d, p  *Runtime
	ln    *Listener
	links []*rendrtest.DatagramLink

	mu  sync.Mutex
	ios []*wdIO // the passive transports of a limited link, in order
}

// peNew builds both Runtimes and one push-only Listener on the passive,
// plus one DatagramLink per name whose passive ends enter the Listener
// through HandlePacket (limit 0) or through a transport of receive limit
// limit that records the limits the admission sets (wdIO).
func peNew(t testing.TB, dcfg, pcfg Config, ov *testhooks.Overrides, limit int, names ...string) *pePair {
	t.Helper()
	e := &pePair{t: t, d: wpTestRuntime(t, dcfg, ov), p: wpTestRuntime(t, pcfg, ov)}
	e.ln = wpListen(t, e.p, ListenConfig{})
	for _, n := range names {
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: n, Queue: 8192, Accept: e.accept(limit)})
		e.links = append(e.links, l)
		t.Cleanup(func() { l.Close() })
	}
	return e
}

// accept returns a DatagramLink Accept into e's Listener (see peNew).
func (e *pePair) accept(limit int) func(pc net.PacketConn, peer net.Addr) error {
	return func(pc net.PacketConn, peer net.Addr) error {
		if limit == 0 {
			return e.ln.HandlePacket(pc, peer)
		}
		pio, err := carrier.NewPacketIO(&e.p.cenv, pc, peer, limit)
		if err != nil {
			return err
		}
		io := &wdIO{PacketIO: pio}
		if !e.ln.beginHandshake() {
			return net.ErrClosed
		}
		e.mu.Lock()
		e.ios = append(e.ios, io)
		e.mu.Unlock()
		e.p.startHandshakeDatagram(e.ln, io, time.Now())
		return nil
	}
}

// limits returns the last receive limit set on every limited passive
// transport so far.
func (e *pePair) limits() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]int, len(e.ios))
	for i, io := range e.ios {
		out[i] = io.lastLimit()
	}
	return out
}

// peer returns a Peer of the dialer over cs.
func (e *pePair) peer(cs ...Carrier) *Peer {
	e.t.Helper()
	p, err := e.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		e.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// close closes both Runtimes and the links and requires that nothing is
// left: no session, handshake, flow, source or buffered byte.
func (e *pePair) close() {
	e.t.Helper()
	e.d.Close()
	e.p.Close()
	for _, l := range e.links {
		l.Close()
	}
	for _, rt := range []*Runtime{e.d, e.p} {
		peNoState(e.t, rt)
	}
}

// peNoState is wpNoState plus the datagram state (flows, sources,
// admitting quota) and abandoned goroutines.
func peNoState(t testing.TB, rt *Runtime) {
	t.Helper()
	wpNoState(t, rt)
	if st := rt.Status(); st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || st.Datagram.Admitting != 0 {
		t.Fatalf("state left: abandoned %d, datagram %+v", st.Abandoned, st.Datagram)
	}
}

// peDial dials a packet session on its own goroutine.
func peDial(p *Peer, o DialOptions) <-chan peDialed {
	ch := make(chan peDialed, 1)
	go func() {
		c, err := p.DialPacket(context.Background(), o)
		ch <- peDialed{c, err}
	}()
	return ch
}

type peDialed struct {
	c   *PacketConn
	err error
}

// peAccept accepts and confirms one packet session on ln.
func peAccept(t testing.TB, ln *Listener) (*PendingPacket, *PacketConn) {
	t.Helper()
	pp, err := ln.AcceptPacket(context.Background())
	if err != nil {
		t.Fatalf("AcceptPacket: %v", err)
	}
	pc, err := pp.Confirm()
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	return pp, pc
}

// peOpen dials a packet session on p and confirms it on ln.
func peOpen(t testing.TB, p *Peer, ln *Listener, o DialOptions) (dc, pc *PacketConn) {
	t.Helper()
	ch := peDial(p, o)
	_, pc = peAccept(t, ln)
	r := <-ch
	if r.err != nil {
		t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// peSend writes n test datagrams of size bytes (seed, seqs from first) on
// c, one per millisecond.
func peSend(t testing.TB, c *PacketConn, seed, first uint64, n, size int) {
	t.Helper()
	buf := make([]byte, size)
	for i := range n {
		if _, err := c.WriteTo(rendrtest.PacketPayload(buf, seed, first+uint64(i), size, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

// peRecv reads until n datagrams arrived or within passed without one,
// verifying each; it returns the verifier.
func peRecv(t testing.TB, c *PacketConn, seed uint64, n int, within time.Duration) *rendrtest.PacketVerifier {
	t.Helper()
	v := rendrtest.NewPacketVerifier(seed)
	buf := make([]byte, wire.MaxDatagram)
	for i := 0; i < n; i++ {
		c.SetReadDeadline(time.Now().Add(within))
		k, _, err := c.ReadFrom(buf)
		if err != nil {
			break
		}
		if err := v.Add(buf[:k], time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	c.SetReadDeadline(time.Time{})
	return v
}

// peEnd closes both ends (dc first) and waits for both Done.
func peEnd(t testing.TB, dc, pc *PacketConn) {
	t.Helper()
	dc.Close()
	pc.Close()
	for _, ch := range []<-chan struct{}{dc.Done(), pc.Done()} {
		select {
		case <-ch:
		case <-time.After(time.Minute):
			t.Fatal("a session did not end within a minute of its Close")
		}
	}
}

// peLive returns the attached live carriers of c's status (active or
// member: OPEN_ACK or JOIN_ACK exchanged).
func peLive(c *PacketConn) []CarrierStatus {
	var out []CarrierStatus
	for _, cs := range c.Status().Carriers {
		if cs.State == CarrierActive || cs.State == CarrierMember {
			out = append(out, cs)
		}
	}
	return out
}

// peWait polls cond every 10 ms (virtual) for at most within.
func peWait(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPacketShortBufferE2E_L36: ReadFrom into a buffer shorter than the
// datagram returns (len(p), RemoteAddr, io.ErrShortBuffer) with the
// datagram's prefix and discards its rest; the next datagram is intact
// (§A7.1; the WP8 review's surviving mutant). Datagram boundaries are kept
// for 5, 11 and 257 bytes end to end.
func TestPacketShortBufferE2E_L36(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a")
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400)), e.ln, DialOptions{})
		msgs := [][]byte{bytes.Repeat([]byte{1}, 37), bytes.Repeat([]byte{2}, 5), bytes.Repeat([]byte{3}, 11), bytes.Repeat([]byte{4}, 257)}
		for _, m := range msgs {
			if n, err := dc.WriteTo(m, pc.LocalAddr()); n != len(m) || err != nil {
				t.Fatalf("WriteTo = %d, %v", n, err)
			}
		}
		b := make([]byte, 7)
		n, addr, err := pc.ReadFrom(b)
		if n != 7 || !errors.Is(err, io.ErrShortBuffer) || addr != pc.RemoteAddr() || !bytes.Equal(b, msgs[0][:7]) {
			t.Fatalf("short read = %d, %v, %v (%x); want 7, %v, io.ErrShortBuffer", n, addr, err, b, pc.RemoteAddr())
		}
		big := make([]byte, 2048)
		for _, m := range msgs[1:] {
			n, addr, err := pc.ReadFrom(big)
			if err != nil || addr != pc.RemoteAddr() || !bytes.Equal(big[:n], m) {
				t.Fatalf("ReadFrom = %d, %v, %v; want the %d-byte datagram", n, addr, err, len(m))
			}
		}
		if st := pc.Status(); st.Packet.Received != 4 || st.DeliveredBytes != 7+5+11+257 {
			t.Fatalf("passive status %+v", *st.Packet)
		}
		peEnd(t, dc, pc)
		e.close()
	})
}

// TestPacketEndE2E_L40: the end of a packet session through the real
// actors (§A5.6), in both orders. The side that closes: later calls return
// net.ErrClosed. The peer: ReadFrom returns every datagram that arrived,
// then io.EOF (never before); WriteTo returns net.ErrClosed. Both sessions
// end (Done) without an error and the Runtimes hold nothing afterwards.
func TestPacketEndE2E_L40(t *testing.T) {
	for _, dialerCloses := range []bool{true, false} {
		name := "passive closes"
		if dialerCloses {
			name = "dialer closes"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := peNew(t, Config{}, Config{}, nil, 0, "a")
				e.links[0].SetDelay(rendrtest.Up, 5*time.Millisecond, 3*time.Millisecond)
				e.links[0].SetDelay(rendrtest.Down, 5*time.Millisecond, 3*time.Millisecond)
				dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400)), e.ln, DialOptions{})
				closer, peer := dc, pc
				if !dialerCloses {
					closer, peer = pc, dc
				}
				buf := make([]byte, 300)
				for i := range 50 {
					closer.WriteTo(rendrtest.PacketPayload(buf, 5, uint64(i), 300, time.Now()), nil)
				}
				if err := closer.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := closer.WriteTo([]byte{1}, nil); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("WriteTo after Close: %v", err)
				}
				if _, _, err := closer.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ReadFrom after Close: %v", err)
				}
				v := rendrtest.NewPacketVerifier(5)
				for {
					n, _, err := peer.ReadFrom(buf)
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatalf("the peer's ReadFrom: %v", err)
					}
					v.Add(buf[:n], time.Now())
				}
				if r := v.Result(); r.Unique != 50 || r.Duplicates+r.Corrupt != 0 {
					t.Fatalf("before io.EOF: %+v", r)
				}
				if _, err := peer.WriteTo([]byte{1}, nil); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("the peer's WriteTo after the peer's close: %v", err)
				}
				peer.Close()
				for _, c := range []*PacketConn{dc, pc} {
					select {
					case <-c.Done():
					case <-time.After(5 * time.Second):
						t.Fatal("a session did not end")
					}
					if st := c.Status(); st.State != StateEnded || st.Err != io.EOF {
						t.Fatalf("after a clean end: state %v, err %v (want io.EOF, M1's clean end)", st.State, st.Err)
					}
				}
				e.close()
			})
		})
	}
}

// TestDialPacketMaxPayloadE2E_L37: the M2-D49 table end to end (the
// session's MaxPayload once OPEN_ACK fixed it, both ends equal), and its
// L37 worked example: datagram factories of MTU 1125 and 1425 against a
// passive Packet.MaxPayload of 1250. Bond with a stream factory offers
// 65,507 and gets 1250; datagrams above 1100 ride only the 1425 member and
// none goes to the stream carrier while it lives; a member that dies later
// never changes the limit (TestPacketCapacityAgreement_L37 below).
func TestDialPacketMaxPayloadE2E_L37(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       Mode
		mtus       []int // 0: a stream factory
		dmax, pmax int   // Packet.MaxPayload of the dialer and the passive (0: default)
		want       int
	}{
		{"selector, two datagram factories", ModeSelector, []int{1125, 1425}, 0, 0, 1100},
		{"selector, datagram and stream", ModeSelector, []int{1400, 0}, 0, 0, 1375},
		{"bond, datagram and stream: the passive's limit", ModeBond, []int{1425, 0}, 0, 1250, 1250},
		{"bond, datagram only", ModeBond, []int{1125, 1425}, 0, 1250, 1100},
		{"stream only", ModeSelector, []int{0}, 2000, 0, 2000},
		{"the dialer's own limit", ModeSelector, []int{1400}, 800, 0, 800},
		{"the passive's own limit", ModeSelector, []int{1400}, 0, 600, 600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dcfg, pcfg := Config{}, Config{}
				dcfg.Packet.MaxPayload, pcfg.Packet.MaxPayload = tc.dmax, tc.pmax
				var names []string
				for i := range tc.mtus {
					names = append(names, string(rune('a'+i)))
				}
				e := peNew(t, dcfg, pcfg, nil, 0, names...)
				var cs []Carrier
				var streams []*rendrtest.Link
				for i, m := range tc.mtus {
					if m == 0 {
						l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "s" + names[i], Accept: e.ln.Handle})
						t.Cleanup(l.Close)
						streams = append(streams, l)
						cs = append(cs, e2eCarrier(l))
						continue
					}
					cs = append(cs, peDatagramCarrier(e.links[i], m))
				}
				ch := peDial(e.peer(cs...), DialOptions{Mode: tc.mode})
				pp, err := e.ln.AcceptPacket(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if pp.MaxPayload() != tc.want {
					t.Fatalf("PendingPacket.MaxPayload %d, want %d", pp.MaxPayload(), tc.want)
				}
				pc, err := pp.Confirm()
				if err != nil {
					t.Fatal(err)
				}
				r := <-ch
				if r.err != nil {
					t.Fatalf("DialPacket: %v", r.err)
				}
				dc := r.c
				if dc.MaxPayload() != tc.want || pc.MaxPayload() != tc.want || dc.Status().MaxPayload != tc.want {
					t.Fatalf("MaxPayload dialer %d passive %d, want %d", dc.MaxPayload(), pc.MaxPayload(), tc.want)
				}
				// The limit holds both ways: tc.want passes, one more is refused.
				if _, err := dc.WriteTo(make([]byte, tc.want+1), nil); !errors.Is(err, ErrPacketTooLarge) {
					t.Fatalf("WriteTo of MaxPayload+1: %v", err)
				}
				peSend(t, dc, 3, 0, 3, tc.want)
				if v := peRecv(t, pc, 3, 3, time.Second); v.Result().Unique != 3 {
					t.Fatalf("datagrams of MaxPayload: %+v", v.Result())
				}
				peEnd(t, dc, pc)
				for _, l := range streams {
					l.Close()
				}
				e.close()
			})
		})
	}
}

// TestPacketCapacityAgreement_L37: §A5.4's worked example. A bond over
// datagram factories of MTU 1125 and 1425 and a stream factory, against a
// passive Packet.MaxPayload of 1250: MaxPayload 1250; 1200-byte datagrams
// ride the 1425 member only — the 1125 member cannot, and none goes to the
// stream carrier's tx queue for big datagrams (txBig) while that member
// lives (the minimum share of R1-19 may still place one on the stream
// member). When the 1425 member's path dies for good, the
// limit stays 1250 and 1200-byte datagrams continue on the stream carrier
// (plan:632: a carrier that dies later never changes the session's limit).
func TestPacketCapacityAgreement_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pcfg := Config{}
		pcfg.Packet.MaxPayload = 1250
		e := peNew(t, Config{}, pcfg, nil, 0, "small", "big")
		sl := rendrtest.NewLink(rendrtest.LinkConfig{Name: "tcp", Accept: e.ln.Handle})
		defer sl.Close()
		p := e.peer(peDatagramCarrier(e.links[0], 1125), peDatagramCarrier(e.links[1], 1425), e2eCarrier(sl))
		dc, pc := peOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		if dc.MaxPayload() != 1250 || pc.MaxPayload() != 1250 {
			t.Fatalf("MaxPayload %d / %d, want 1250", dc.MaxPayload(), pc.MaxPayload())
		}
		peWait(t, 5*time.Second, "three members", func() bool { return len(peLive(dc)) == 3 })
		tx := func() map[string]uint64 {
			m := map[string]uint64{}
			for _, cs := range dc.Status().Carriers {
				m[cs.Name] += cs.TxBytes
			}
			return m
		}
		before := tx()
		peSend(t, dc, 4, 0, 200, 1200)
		if v := peRecv(t, pc, 4, 200, time.Second); v.Result().Unique != 200 {
			t.Fatalf("1200-byte datagrams: %+v; dialer %+v; passive %+v; carriers %+v", v.Result(), *dc.Status().Packet, *pc.Status().Packet, dc.Status().Carriers)
		}
		after := tx()
		big, small, tcp := after["big"]-before["big"], after["small"]-before["small"], after["tcp"]-before["tcp"]
		if small != 0 || big+tcp != 200*1200 || big < 190*1200 {
			t.Fatalf("1200-byte datagrams per carrier %v → %v: want them on the 1425 member (the stream member at most its minimum share)", before, after)
		}
		// The big member's path dies for good.
		e.links[1].Refuse(true)
		e.links[1].Kill()
		peWait(t, 5*time.Second, "the big member died", func() bool {
			for _, cs := range peLive(dc) {
				if cs.Name == "big" {
					return false
				}
			}
			return true
		})
		if dc.MaxPayload() != 1250 || pc.MaxPayload() != 1250 {
			t.Fatalf("MaxPayload changed with a member's death: %d / %d", dc.MaxPayload(), pc.MaxPayload())
		}
		peSend(t, dc, 6, 0, 100, 1200)
		if v := peRecv(t, pc, 6, 100, time.Second); v.Result().Unique != 100 {
			t.Fatalf("1200-byte datagrams after the big member died: %+v (dialer %+v)", v.Result(), *dc.Status().Packet)
		}
		peEnd(t, dc, pc)
		sl.Close()
		e.close()
	})
}

// TestPacketLogicalAddrE2E_L38: the end-to-end half of L38. The logical
// addresses (LocalAddr, RemoteAddr, ReadFrom's address) never change across
// carrier deaths and migrations, on both ends, and every factory call of
// the session — the first carrier and every redial — sees the session's ID
// in its DialInfo (the token reaches the factory unchanged).
func TestPacketLogicalAddrE2E_L38(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a", "b")
		var mu sync.Mutex
		var infos []DialInfo
		cs := make([]Carrier, 2)
		for i, l := range e.links {
			dial := l.Dial
			cs[i] = DatagramCarrier{Name: l.Name(), MTU: 1400, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
				if di, ok := CarrierDialInfo(ctx); ok && !di.Probe {
					mu.Lock()
					infos = append(infos, di)
					mu.Unlock()
				}
				return dial(ctx)
			}}
		}
		dc, pc := peOpen(t, e.peer(cs...), e.ln, DialOptions{})
		addrs := []net.Addr{dc.LocalAddr(), dc.RemoteAddr(), pc.LocalAddr(), pc.RemoteAddr()}
		if dc.LocalAddr() != pc.RemoteAddr() || dc.RemoteAddr() != pc.LocalAddr() {
			t.Fatalf("addresses do not mirror: %v", addrs)
		}
		buf := make([]byte, 64)
		for round := range 4 {
			e.links[round%2].Kill()
			time.Sleep(2 * time.Second)
			if _, err := dc.WriteTo([]byte{byte(round)}, pc.LocalAddr()); err != nil {
				t.Fatalf("round %d: WriteTo to the logical address: %v", round, err)
			}
			pc.SetReadDeadline(time.Now().Add(time.Second))
			_, from, err := pc.ReadFrom(buf)
			if err != nil || from != dc.LocalAddr() {
				t.Fatalf("round %d: ReadFrom = %v, %v; want the dialer's logical address", round, from, err)
			}
			now := []net.Addr{dc.LocalAddr(), dc.RemoteAddr(), pc.LocalAddr(), pc.RemoteAddr()}
			for i := range now {
				if now[i] != addrs[i] {
					t.Fatalf("round %d: address %d moved from %v to %v", round, i, addrs[i], now[i])
				}
			}
		}
		if st := dc.Status(); st.Migrations.Death < 4 {
			t.Fatalf("stimulus: %d death migrations, want 4", st.Migrations.Death)
		}
		mu.Lock()
		if len(infos) < 5 {
			t.Fatalf("stimulus: %d session factory calls, want ≥ 5", len(infos))
		}
		for _, di := range infos {
			if di.Session != dc.ID() || di.Kind != KindDatagram || di.Carrier == 0 {
				t.Fatalf("DialInfo %+v, want session %v", di, dc.ID())
			}
		}
		mu.Unlock()
		peEnd(t, dc, pc)
		e.close()
	})
}

// TestPassiveBudgetJoinE2E_L37: the end-to-end halves of
// TestPassiveBudgetNegotiated_L37 and WP6b's X7. Behind a passive transport
// of limit 1152 (a QUIC-like one), a bond of two datagram factories of MTU
// 1400: the OPEN carrier and the JOIN carrier both get cmtu_acc 1152 — the
// passive's session transports' receive limits are lowered to 1152 (the
// health layer's probe carriers keep MinFrameBudget) and the
// dialer's carriers report MTU 1152 (Join calls SetBudget on a datagram
// carrier) — and the session's MaxPayload is 1152 − 25 (the dialer meant
// its datagram carriers to carry everything: M2-D49), the same in
// PendingPacket.MaxPayload and on both ends.
func TestPassiveBudgetJoinE2E_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 1152, "a", "b")
		ch := peDial(e.peer(peDatagramCarrier(e.links[0], 1400), peDatagramCarrier(e.links[1], 1400)), DialOptions{Mode: ModeBond})
		pp, err := e.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if pp.MaxPayload() != 1127 {
			t.Fatalf("PendingPacket.MaxPayload %d, want 1127", pp.MaxPayload())
		}
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		dc := r.c
		peWait(t, 5*time.Second, "both members", func() bool { return len(peLive(dc)) == 2 && len(peLive(pc)) == 2 })
		if dc.MaxPayload() != 1127 {
			t.Fatalf("MaxPayload %d, want 1127", dc.MaxPayload())
		}
		for _, cs := range peLive(dc) {
			if cs.MTU != 1152 || cs.Kind != KindDatagram {
				t.Fatalf("dialer carrier %+v, want MTU 1152", cs)
			}
		}
		for _, cs := range peLive(pc) {
			if cs.MTU != 1152 {
				t.Fatalf("passive carrier %+v, want MTU 1152", cs)
			}
		}
		n1152 := 0
		for _, l := range e.limits() {
			switch l {
			case 1152:
				n1152++
			case wire.MinFrameBudget: // a probe carrier
			default:
				t.Fatalf("passive receive limits %v: %d is neither cmtu_acc nor a probe's", e.limits(), l)
			}
		}
		if n1152 != 2 {
			t.Fatalf("passive receive limits %v, want two of 1152 (OPEN and JOIN)", e.limits())
		}
		peSend(t, dc, 7, 0, 50, 1127)
		if v := peRecv(t, pc, 7, 50, time.Second); v.Result().Unique != 50 {
			t.Fatalf("datagrams of MaxPayload: %+v", v.Result())
		}
		peEnd(t, dc, pc)
		e.close()
	})
}

// TestPacketAccountingIdentityE2E: §A7.2's identities end to end with a
// refusing link (R1-31). The session's only path refuses datagrams above
// 800 bytes (MTURefuse: a *DatagramTooLargeError), so its carrier shrinks
// its budget and counts the datagram it refused (Refused) — DropTooLarge,
// not Sent — and later datagrams above the new budget count DropTooLarge
// too. Afterwards accepted = Sent + DropQueue + DropAge + DropNoPath +
// DropTooLarge with nothing queued, and Received = returned by ReadFrom +
// DropRecvQueue on the peer.
func TestPacketAccountingIdentityE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "b")
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400)), e.ln, DialOptions{})
		e.links[0].SetMTU(800, rendrtest.MTURefuse)
		var read uint64
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
				read++
			}
		}()
		buf := make([]byte, 1300)
		var accepted uint64
		for i := range 3000 {
			size := 100 + i*7%1200
			if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, 8, uint64(i), size, time.Now()), nil); err != nil {
				t.Fatal(err)
			}
			accepted++
			if i%10 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		time.Sleep(2 * time.Second)
		dc.Close()
		<-done
		pc.Close()
		<-dc.Done()
		<-pc.Done()
		tp, rp := dc.Status().Packet, pc.Status().Packet
		var refused uint64
		for _, cs := range dc.Status().Carriers {
			if cs.Name == "b" && cs.MTU < 1400 {
				refused++
			}
		}
		if tp.DropTooLarge == 0 || refused == 0 || e.links[0].Stats().All.Oversize == 0 {
			t.Fatalf("stimulus: DropTooLarge %d, shrunk carriers %d, link refusals %d", tp.DropTooLarge, refused, e.links[0].Stats().All.Oversize)
		}
		if sum := tp.Sent + tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge; sum != accepted {
			t.Fatalf("accepted %d ≠ %d = %+v", accepted, sum, *tp)
		}
		if rp.Received != read+rp.DropRecvQueue || rp.Received > tp.Sent {
			t.Fatalf("Received %d, read %d, DropRecvQueue %d, peer Sent %d", rp.Received, read, rp.DropRecvQueue, tp.Sent)
		}
		t.Logf("dialer %+v; passive %+v", *tp, *rp)
		e.close()
	})
}

// TestPackRelWrappedE2E_L12: a packet session's end signalling travels in
// REL over real datagram carriers (M2-D39, §A5.5): the passive's PACK that
// confirms the dialer's FIN is reliable. Its first copy is dropped on the
// link; the REL sublayer resends it (the passive carrier's Retransmits
// rise), and both sessions end within a second of the dialer's Close.
func TestPackRelWrappedE2E_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a")
		l := e.links[0]
		l.SetDelay(rendrtest.Up, 10*time.Millisecond, 0)
		l.SetDelay(rendrtest.Down, 10*time.Millisecond, 0)
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(l, 1400)), e.ln, DialOptions{})
		peSend(t, dc, 9, 0, 20, 200)
		peRecv(t, pc, 9, 20, time.Second)
		time.Sleep(2 * time.Second) // the cadence PACKs are out
		retx0 := pc.Status().Carriers[0].Retransmits
		dropped0 := l.Stats().All.Lost
		l.DropNext(rendrtest.Down, rendrtest.FramePack, 1)
		start := time.Now()
		dc.Close()
		go func() {
			buf := make([]byte, 64)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					pc.Close()
					return
				}
			}
		}()
		for _, c := range []*PacketConn{dc, pc} {
			select {
			case <-c.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the session did not end")
			}
		}
		if l.Stats().All.Lost == dropped0 {
			t.Fatal("stimulus: no PACK was dropped")
		}
		var retx uint64
		for _, cs := range pc.Status().Carriers {
			retx += cs.Retransmits
		}
		if retx <= retx0 {
			t.Fatalf("the dropped PACK was not resent by REL (Retransmits %d → %d)", retx0, retx)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("the end took %v after the dialer's Close", d)
		}
		e.close()
	})
}
