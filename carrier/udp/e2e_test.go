package udp_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// End-to-end rows of carrier/udp (WP12; M2 design §A8.6 and Revision 1,
// R1-34): two Runtimes on loopback, the dialer on udp.Carrier, the passive
// on one udp.Listen socket through rendr.FromPacketConn. Between them an
// e2eRelay on loopback: the dialer's peer address is the relay's front
// socket, and the passive sees each dialer socket as one upstream socket of
// the relay, so a test can send from either side's true peer address
// (empty datagrams) or hold one datagram and send it from a foreign
// address. Real sockets, outside synctest bubbles; every test checks for
// leaks after its last cleanup.

// e2eRelay forwards datagrams between dialer sockets (clients of front)
// and the server, one upstream socket per client.
type e2eRelay struct {
	front  *net.UDPConn
	server *net.UDPAddr

	mu  sync.Mutex
	ups map[netip.AddrPort]*e2eUp

	// hold, when set, is offered every server → client datagram; one it
	// returns true for is not forwarded (the relay hands a copy to held).
	hold atomic.Pointer[func(b []byte) bool]
	held chan []byte

	wg sync.WaitGroup
}

// e2eUp is the relay's upstream socket of one client.
type e2eUp struct {
	client netip.AddrPort
	u      *net.UDPConn
}

func newE2ERelay(t *testing.T, server net.Addr) *e2eRelay {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &e2eRelay{front: front, server: server.(*net.UDPAddr), ups: map[netip.AddrPort]*e2eUp{}, held: make(chan []byte, 1)}
	r.wg.Add(1)
	go r.frontLoop()
	t.Cleanup(r.close)
	return r
}

func (r *e2eRelay) addr() string { return r.front.LocalAddr().String() }

// frontLoop forwards client → server through the client's upstream socket.
func (r *e2eRelay) frontLoop() {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := r.front.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if up := r.upstream(from); up != nil {
			_, _ = up.u.Write(buf[:n])
		}
	}
}

// upstream returns the client's upstream socket, opening it on first use.
func (r *e2eRelay) upstream(client netip.AddrPort) *e2eUp {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ups == nil {
		return nil // closed
	}
	if up := r.ups[client]; up != nil {
		return up
	}
	u, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, r.server)
	if err != nil {
		return nil
	}
	up := &e2eUp{client: client, u: u}
	r.ups[client] = up
	r.wg.Add(1)
	go r.backLoop(up)
	return up
}

// backLoop forwards server → client from the front socket (the client's
// peer address), offering each datagram to hold first.
func (r *e2eRelay) backLoop(up *e2eUp) {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, err := up.u.Read(buf)
		if err != nil {
			return
		}
		if h := r.hold.Load(); h != nil && (*h)(buf[:n]) {
			r.hold.Store(nil)
			r.held <- bytes.Clone(buf[:n])
			continue
		}
		_, _ = r.front.WriteToUDPAddrPort(buf[:n], up.client)
	}
}

// toClient sends b to client from the front socket: from the client's own
// peer address.
func (r *e2eRelay) toClient(t *testing.T, b []byte, client netip.AddrPort) {
	t.Helper()
	if n, err := r.front.WriteToUDPAddrPort(b, client); err != nil || n != len(b) {
		t.Fatalf("relay → client: %d, %v", n, err)
	}
}

// toServer sends b to the server from client's upstream socket: from the
// address at which the server knows that client.
func (r *e2eRelay) toServer(t *testing.T, b []byte, client netip.AddrPort) {
	t.Helper()
	r.mu.Lock()
	up := r.ups[client]
	r.mu.Unlock()
	if up == nil {
		t.Fatalf("no upstream socket of %v", client)
	}
	if n, err := up.u.Write(b); err != nil || n != len(b) {
		t.Fatalf("relay → server: %d, %v", n, err)
	}
}

func (r *e2eRelay) close() {
	r.mu.Lock()
	ups := r.ups
	r.ups = nil
	r.mu.Unlock()
	_ = r.front.Close()
	for _, up := range ups {
		_ = up.u.Close()
	}
	r.wg.Wait()
}

// e2ePair is two Runtimes joined by one datagram path, with one open
// packet session: carrier/udp through an e2eRelay (newE2EPair), or two
// plain loopback sockets used as embedder conns (newE2EEmbedderPair).
type e2ePair struct {
	t      *testing.T
	d, p   *rendr.Runtime
	relay  *e2eRelay // nil on the embedder path
	dc, pc *rendr.PacketConn
	client netip.AddrPort // the dialer session carrier's socket address
	server netip.AddrPort // the passive's socket address

	// toDialer and toPassive send b from the other side's true address.
	toDialer, toPassive func(b []byte)

	downs [2]atomic.Int64 // EventCarrierDown of a session carrier: dialer, passive
}

// newE2ERuntimes creates the pair's two Runtimes.
func newE2ERuntimes(t *testing.T) *e2ePair {
	t.Helper()
	e := &e2ePair{t: t}
	ev := func(i int) func(rendr.Event) {
		return func(x rendr.Event) {
			if x.Kind == rendr.EventCarrierDown && x.Session != (rendr.SessionID{}) {
				e.downs[i].Add(1)
			}
		}
	}
	var err error
	if e.d, err = rendr.NewRuntime(rendr.Config{OnEvent: ev(0)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.d.Close() })
	if e.p, err = rendr.NewRuntime(rendr.Config{OnEvent: ev(1)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.p.Close() })
	return e
}

// newE2EPair opens one selector packet session over udp.Carrier through a
// relay to a udp.Listen socket.
func newE2EPair(t *testing.T) *e2ePair {
	t.Helper()
	e := newE2ERuntimes(t)
	ls, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := e.p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(ls)}}) // owns ls
	if err != nil {
		ls.Close()
		t.Fatal(err)
	}
	e.relay = newE2ERelay(t, ls.LocalAddr())
	c := udp.Carrier("u", "udp4", e.relay.addr(), udp.Options{})
	var mu sync.Mutex
	var session []netip.AddrPort // local addresses of the session carriers' sockets
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			mu.Lock()
			session = append(session, e2eAddrPort(pc.LocalAddr()))
			mu.Unlock()
		}
		return pc, a, err
	}
	e.open(ln, c)
	mu.Lock()
	defer mu.Unlock()
	if len(session) != 1 {
		t.Fatalf("%d session carriers dialled, want 1", len(session))
	}
	e.client = session[0]
	e.server = e2eAddrPort(ls.LocalAddr())
	e.toDialer = func(b []byte) { e.relay.toClient(t, b, e.client) }
	e.toPassive = func(b []byte) { e.relay.toServer(t, b, e.client) }
	return e
}

// newE2EEmbedderPair opens one selector packet session over two plain
// loopback sockets used as embedder conns: the dialer's through a
// rendr.DatagramCarrier, the passive's through Listener.HandlePacket. Both
// carriers read through rendr's embedder adapter (NewPacketIO), where the
// reader's spin guard applies (R1-27).
func newE2EEmbedderPair(t *testing.T) *e2ePair {
	t.Helper()
	e := newE2ERuntimes(t)
	loop := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	ds, err := net.ListenUDP("udp4", loop)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := net.ListenUDP("udp4", loop)
	if err != nil {
		ds.Close()
		t.Fatal(err)
	}
	for _, u := range []*net.UDPConn{ds, ps} {
		_ = u.SetReadBuffer(4 << 20) // a burst waits in the kernel
	}
	ln, err := e.p.Listen(rendr.ListenConfig{})
	if err != nil {
		ds.Close()
		ps.Close()
		t.Fatal(err)
	}
	if err := ln.HandlePacket(ps, ds.LocalAddr()); err != nil { // owns ps
		ds.Close()
		ps.Close()
		t.Fatal(err)
	}
	var once atomic.Bool
	c := rendr.DatagramCarrier{Name: "e", MTU: 1400, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		if once.Swap(true) {
			return nil, nil, errors.New("the embedder socket is in use")
		}
		return ds, ps.LocalAddr(), nil
	}}
	t.Cleanup(func() {
		if !once.Swap(true) { // never dialled: still the test's
			ds.Close()
		}
	})
	e.open(ln, c)
	e.client, e.server = e2eAddrPort(ds.LocalAddr()), e2eAddrPort(ps.LocalAddr())
	send := func(from *net.UDPConn, to netip.AddrPort) func([]byte) {
		return func(b []byte) {
			if n, err := from.WriteToUDPAddrPort(b, to); err != nil || n != len(b) {
				t.Fatalf("send to %v: %d, %v", to, n, err)
			}
		}
	}
	e.toDialer, e.toPassive = send(ps, e.client), send(ds, e.server)
	return e
}

// open dials one selector packet session over c and accepts it on ln.
func (e *e2ePair) open(ln *rendr.Listener, c rendr.Carrier) {
	t := e.t
	t.Helper()
	peer, err := e.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{c}})
	if err != nil {
		t.Fatal(err)
	}
	type dialed struct {
		c   *rendr.PacketConn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := peer.DialPacket(context.Background(), rendr.DialOptions{})
		ch <- dialed{c, err}
	}()
	pp, err := ln.AcceptPacket(context.Background())
	if err != nil {
		t.Fatalf("AcceptPacket: %v", err)
	}
	if e.pc, err = pp.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("DialPacket: %v", r.err)
	}
	e.dc = r.c
}

// e2eAddrPort is a loopback socket's address, IPv4 unmapped.
func e2eAddrPort(a net.Addr) netip.AddrPort {
	ap := a.(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// carrier returns the dialer's one live session carrier.
func (e *e2ePair) carrier() rendr.CarrierStatus {
	e.t.Helper()
	var live []rendr.CarrierStatus
	for _, cs := range e.dc.Status().Carriers {
		if cs.DeathCause == rendr.CauseNone {
			live = append(live, cs)
		}
	}
	if len(live) != 1 {
		e.t.Fatalf("the dialer session has %d live carriers, want 1: %+v", len(live), e.dc.Status().Carriers)
	}
	return live[0]
}

// end closes both sessions and both Runtimes and requires that nothing is
// left.
func (e *e2ePair) end() {
	e.t.Helper()
	e.dc.Close()
	e.pc.Close()
	for _, ch := range []<-chan struct{}{e.dc.Done(), e.pc.Done()} {
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
			e.t.Fatal("a session did not end within 30 s of its Close")
		}
	}
	e.d.Close()
	e.p.Close()
	for _, rt := range []*rendr.Runtime{e.d, e.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.BufferedBytes != 0 ||
			st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 {
			e.t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
}

// e2eSide reads and verifies datagrams of one direction until its conn
// fails.
type e2eSide struct {
	v    *rendrtest.PacketVerifier
	verr atomic.Value
	done chan struct{}
}

func e2eReceive(c *rendr.PacketConn, seed uint64) *e2eSide {
	s := &e2eSide{v: rendrtest.NewPacketVerifier(seed), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		buf := make([]byte, 2048)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if err := s.v.Add(buf[:n], time.Now()); err != nil {
				s.verr.CompareAndSwap(nil, err)
			}
		}
	}()
	return s
}

// e2eSettle polls cond every 5 ms for at most within.
func e2eSettle(within time.Duration, cond func() bool) {
	deadline := time.Now().Add(within)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// e2eWait polls cond every 5 ms for at most within.
func e2eWait(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

const e2eSize = 400 // bytes of every test datagram

// TestUDPZeroLengthIsNotDeath_L42: on a raw-UDP datagram carrier an empty
// datagram is a counted drop, never a carrier death (PA-18; L42 "长度为 0 …
// 杀掉该承载" amended for datagrams), and a burst of datagrams that hand
// nothing over never starves the carrier. Two paths: carrier/udp (rendr's
// own sockets: udp.Carrier through a relay to a udp.Listen socket via
// FromPacketConn) and embedder conns (plain loopback sockets through
// DatagramCarrier and Listener.HandlePacket, read by rendr's adapter).
// While a packet session moves 400-byte datagrams both ways, one each way
// every millisecond, each side's socket receives a burst of 400 empty
// datagrams from its true peer address, then 100 empty and 100 non-empty
// datagrams from a foreign address; on carrier/udp the dialer also receives
// 200 datagrams of its flow header alone from its peer. Every burst is far
// longer than the reader's spin-guard run (64 reads that hand nothing
// over): rendr's own socket reads it without a pause, the embedder adapter
// with a fixed 1-ms pause per 64 reads — the doubling 5-to-100-ms back-off
// these bursts once met left both carriers to die with ping_timeout
// (R1-27 as amended by WP12).
//
// Stimulus: the dialer carrier's Dropped and the passive's
// Status.Datagram.Dropped grow by at least the injected counts. Load and
// integrity: every datagram of both directions arrives exactly once and
// intact. No carrier death: no CarrierDown on either side, the same
// carrier before and after, no migration.
func TestUDPZeroLengthIsNotDeath_L42(t *testing.T) {
	for _, tc := range []struct {
		name string
		pair func(*testing.T) *e2ePair
	}{{"udp.Carrier", newE2EPair}, {"embedder", newE2EEmbedderPair}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			zeroLengthRow(t, tc.pair(t))
		})
	}
}

func zeroLengthRow(t *testing.T, e *e2ePair) {
	foreign, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()

	// carrier/udp: learn the flow header from a passive → dialer datagram.
	hdr := make(chan []byte, 1)
	if e.relay != nil {
		hold := func(b []byte) bool {
			if len(b) > 9 {
				select {
				case hdr <- bytes.Clone(b[:9]):
				default:
				}
			}
			return false // forwarded as usual
		}
		e.relay.hold.Store(&hold)
	}
	up, down := e2eReceive(e.pc, 1), e2eReceive(e.dc, 2)
	before := e.carrier()
	pBefore := e.p.Status().Datagram.Dropped

	const n = 1500 // per direction, one each way every millisecond
	const (
		empties  = 400 // to each side, from its peer
		foreigns = 100 // to each side from a foreign address, empty and again non-empty
		headers  = 200 // carrier/udp: to the dialer, its flow header alone
	)
	headerToDialer := 0
	junk := bytes.Repeat([]byte{0xee}, 64)
	fromForeign := func(b []byte, to netip.AddrPort) {
		if _, err := foreign.WriteToUDPAddrPort(b, to); err != nil {
			t.Fatal(err)
		}
	}
	var sendErr error
	bufU, bufD := make([]byte, e2eSize), make([]byte, e2eSize)
	for seq := uint64(0); seq < n; seq++ {
		now := time.Now()
		if _, err := e.dc.WriteTo(rendrtest.PacketPayload(bufU, 1, seq, e2eSize, now), nil); err != nil && sendErr == nil {
			sendErr = err
		}
		if _, err := e.pc.WriteTo(rendrtest.PacketPayload(bufD, 2, seq, e2eSize, now), nil); err != nil && sendErr == nil {
			sendErr = err
		}
		switch seq {
		case 300: // bursts in the middle of the traffic
			for range empties {
				e.toDialer(nil)
			}
			for range empties {
				e.toPassive(nil)
			}
		case 600:
			for _, b := range [][]byte{nil, junk} {
				for range foreigns {
					fromForeign(b, e.client)
					fromForeign(b, e.server)
				}
			}
			if e.relay == nil {
				break
			}
			var flowHdr []byte
			select {
			case flowHdr = <-hdr:
			default:
				t.Fatal("no passive → dialer datagram passed the relay")
			}
			e.relay.hold.Store(nil)
			for range headers {
				e.toDialer(flowHdr)
			}
			headerToDialer = headers
		}
		time.Sleep(time.Millisecond)
	}
	if sendErr != nil {
		t.Fatalf("WriteTo: %v", sendErr)
	}
	for _, x := range []struct {
		name string
		s    *e2eSide
	}{{"dialer → passive", up}, {"passive → dialer", down}} {
		e2eSettle(10*time.Second, func() bool { return x.s.v.Result().Unique == n })
		res := x.s.v.Result()
		if e := x.s.verr.Load(); e != nil || res.Corrupt+res.BadSize+res.Duplicates != 0 || len(res.Missing) != 0 {
			t.Errorf("%s: %v; %+v", x.name, e, res)
		}
	}
	if e.downs[0].Load() != 0 || e.downs[1].Load() != 0 {
		var deaths []string
		for _, cs := range append(e.dc.Status().Carriers, e.pc.Status().Carriers...) {
			if cs.DeathCause != rendr.CauseNone {
				deaths = append(deaths, cs.DeathCause.String()+" "+cs.DeathDetail)
			}
		}
		t.Fatalf("a carrier died: CarrierDown dialer %d, passive %d: %q", e.downs[0].Load(), e.downs[1].Load(), deaths)
	}
	after := e.carrier()
	if after.ID != before.ID {
		t.Fatalf("the session carrier changed: %d → %d", before.ID, after.ID)
	}
	if m := e.dc.Status().Migrations; m != (rendr.MigrationCounts{}) {
		t.Errorf("migrations %+v, want none", m)
	}
	if got, want := after.Dropped-before.Dropped, uint64(empties+2*foreigns+headerToDialer); got < want {
		t.Errorf("stimulus: the dialer carrier dropped %d datagrams, want ≥ %d injected", got, want)
	}
	if got, want := e.p.Status().Datagram.Dropped-pBefore, uint64(empties+2*foreigns); got < want {
		t.Errorf("stimulus: the passive dropped %d datagrams, want ≥ %d injected", got, want)
	}
	t.Logf("dialer carrier Dropped +%d, passive Datagram.Dropped +%d; max gap up %v, down %v",
		after.Dropped-before.Dropped, e.p.Status().Datagram.Dropped-pBefore, up.v.Result().MaxGap, down.v.Result().MaxGap)
	e.end()
	<-up.done
	<-down.done
}

// TestUDPDialerForeignSource_L59: a dialer carrier accepts datagrams only
// from its peer's address (L59 "dialer 一侧丢弃源地址不符的数据报";
// §A6.4). The relay holds one passive → dialer datagram that carries a
// DGRAM and sends that exact datagram from a foreign socket on the same
// IP address (another port): a valid flow header, a fresh fseq, a valid
// CRC — accepted had it come from the peer. It is dropped and counted
// (Dropped + 1 exactly), its datagram is not delivered, and the carrier
// lives. Then the same bytes from the peer's address are accepted: the
// held datagram arrives, so the foreign copy consumed nothing (no window
// slot). Load and integrity: every datagram arrives exactly once, intact.
func TestUDPDialerForeignSource_L59(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	e := newE2EPair(t)
	foreign, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	down := e2eReceive(e.dc, 2)
	before := e.carrier()

	const n, heldSeq = 300, 150
	buf := make([]byte, e2eSize)
	send := func(from, to uint64) {
		for seq := from; seq < to; seq++ {
			b := rendrtest.PacketPayload(buf, 2, seq, e2eSize, time.Now())
			if seq == heldSeq {
				want := bytes.Clone(b)
				hold := func(d []byte) bool { return bytes.Contains(d, want) }
				e.relay.hold.Store(&hold)
			}
			if _, err := e.pc.WriteTo(b, nil); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	send(0, heldSeq+1)
	var held []byte
	select {
	case held = <-e.relay.held:
	case <-time.After(5 * time.Second):
		t.Fatal("the datagram of seq 150 never passed the relay")
	}
	if n, err := foreign.WriteToUDPAddrPort(held, e.client); err != nil || n != len(held) {
		t.Fatalf("foreign send: %d, %v", n, err)
	}
	send(heldSeq+1, n)
	e2eWait(t, 5*time.Second, "every datagram but the held one", func() bool { return down.v.Result().Unique >= n-1 })
	time.Sleep(100 * time.Millisecond) // the foreign copy had every chance
	res := down.v.Result()
	if res.Unique != n-1 || len(res.Missing) != 1 || res.Missing[0] != (rendrtest.SeqRange{From: heldSeq, To: heldSeq}) {
		t.Fatalf("the foreign copy was delivered: %+v, want only seq %d missing", res, heldSeq)
	}
	mid := e.carrier()
	if mid.ID != before.ID || mid.Dropped-before.Dropped != 1 {
		t.Fatalf("stimulus: carrier %d → %d, Dropped +%d; want the same carrier and exactly the foreign datagram dropped",
			before.ID, mid.ID, mid.Dropped-before.Dropped)
	}

	// The same bytes from the peer's address are a valid datagram.
	e.relay.toClient(t, held, e.client)
	e2eWait(t, 5*time.Second, "the held datagram from the peer", func() bool { return down.v.Result().Unique == n })
	res = down.v.Result()
	if e := down.verr.Load(); e != nil || res.Corrupt+res.BadSize+res.Duplicates != 0 || len(res.Missing) != 0 {
		t.Errorf("integrity: %v; %+v", e, res)
	}
	after := e.carrier()
	if after.ID != before.ID || after.Dropped != mid.Dropped || after.Rebinds != 0 ||
		e.downs[0].Load() != 0 || e.downs[1].Load() != 0 {
		t.Errorf("after the peer's copy: carrier %d, Dropped %d (was %d), Rebinds %d, CarrierDown %d/%d",
			after.ID, after.Dropped, mid.Dropped, after.Rebinds, e.downs[0].Load(), e.downs[1].Load())
	}
	if st := e.p.Status().Datagram; st.Rebinds != 0 {
		t.Errorf("the passive rebound a flow: %+v", st)
	}
	e.end()
	<-down.done
}
