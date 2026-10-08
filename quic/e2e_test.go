package quic

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// End-to-end rows of the quic module with two Runtimes (WP12; M2 design
// §A8.6, Revision 1, R1-34): the dialer's Peer has one QUIC factory of the
// kind under test, the passive serves one rendr Listener from a quic
// Listener (through qeTap, which records the carriers it hands over), and
// a qeRelay on loopback may sit between them to black-hole the path. Real
// sockets, outside synctest bubbles; every test checks for leaks after
// its last cleanup.

// qeRelay forwards UDP datagrams between clients of its front socket and
// a server, one upstream socket per client (so the server sees one address
// per dialer carrier), each direction delayed by delay; while blackhole is
// set it drops both directions.
type qeRelay struct {
	front     *net.UDPConn
	server    *net.UDPAddr
	delay     time.Duration
	blackhole atomic.Bool
	dropped   atomic.Uint64

	mu  sync.Mutex
	ups map[netip.AddrPort]*net.UDPConn
	wg  sync.WaitGroup
}

func newQERelay(t *testing.T, server net.Addr, delay time.Duration) *qeRelay {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &qeRelay{front: front, server: server.(*net.UDPAddr), delay: delay, ups: map[netip.AddrPort]*net.UDPConn{}}
	r.wg.Add(1)
	go r.frontLoop()
	t.Cleanup(r.close)
	return r
}

func (r *qeRelay) frontLoop() {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := r.front.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if r.blackhole.Load() {
			r.dropped.Add(1)
			continue
		}
		if u := r.upstream(from); u != nil {
			r.later(buf[:n], func(b []byte) { _, _ = u.Write(b) })
		}
	}
}

func (r *qeRelay) upstream(client netip.AddrPort) *net.UDPConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ups == nil {
		return nil
	}
	if u := r.ups[client]; u != nil {
		return u
	}
	u, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, r.server)
	if err != nil {
		return nil
	}
	r.ups[client] = u
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := u.Read(buf)
			if err != nil {
				return
			}
			if r.blackhole.Load() {
				r.dropped.Add(1)
				continue
			}
			r.later(buf[:n], func(b []byte) { _, _ = r.front.WriteToUDPAddrPort(b, client) })
		}
	}()
	return u
}

// later sends a copy of b by send after the relay's delay.
func (r *qeRelay) later(b []byte, send func([]byte)) {
	if r.delay <= 0 {
		send(b)
		return
	}
	c := append([]byte(nil), b...)
	r.wg.Add(1)
	time.AfterFunc(r.delay, func() {
		defer r.wg.Done()
		send(c)
	})
}

// upstreamOf returns the address at which the server sees client.
func (r *qeRelay) upstreamOf(client netip.AddrPort) (netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u := r.ups[client]; u != nil {
		return u.LocalAddr().(*net.UDPAddr).AddrPort(), true
	}
	return netip.AddrPort{}, false
}

func (r *qeRelay) close() {
	r.mu.Lock()
	ups := r.ups
	r.ups = nil
	r.mu.Unlock()
	_ = r.front.Close()
	for _, u := range ups {
		_ = u.Close()
	}
	r.wg.Wait()
}

// qeTap is the handoff between a quic Listener and the rendr Listener: it
// records every carrier it hands over.
type qeTap struct {
	rl *rendr.Listener
	mu sync.Mutex
	qc []*qgo.Conn // passive connections, in hand-over order
}

func (h *qeTap) Handle(c net.Conn) error {
	h.add(c.(*streamConn).qc)
	return h.rl.Handle(c)
}

func (h *qeTap) HandlePacket(pc net.PacketConn, peer net.Addr) error {
	h.add(pc.(*dgramConn).qc)
	return h.rl.HandlePacket(pc, peer)
}

func (h *qeTap) add(qc *qgo.Conn) {
	h.mu.Lock()
	h.qc = append(h.qc, qc)
	h.mu.Unlock()
}

// from returns the passive connection whose peer is at addr.
func (h *qeTap) from(addr netip.AddrPort) *qgo.Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, qc := range h.qc {
		if ra, ok := qc.RemoteAddr().(*net.UDPAddr); ok && ra.AddrPort() == addr {
			return qc
		}
	}
	return nil
}

// qeEnv is two Runtimes, the passive's rendr Listener served by a quic
// Listener (restartable with the same stateless reset key), and the relay
// in front of it, where the dialer's factories dial.
type qeEnv struct {
	t        *testing.T
	d, p     *rendr.Runtime
	rl       *rendr.Listener
	srv, cli *tls.Config
	key      qgo.StatelessResetKey
	addr     string // the quic Listener's address
	tap      *qeTap
	relay    *qeRelay

	mu     sync.Mutex
	ls     []*Listener      // every quic Listener served, the current last
	served []chan error     // their Serve results
	downs  [2][]rendr.Event // CarrierDown of session carriers: dialer, passive
	dqc    []*qgo.Conn      // the dialer's session connections, in dial order
	dlocal []netip.AddrPort // their local addresses
}

func newQEEnv(t *testing.T, delay time.Duration) *qeEnv {
	t.Helper()
	e := &qeEnv{t: t}
	e.srv, e.cli = testTLS(t)
	if _, err := rand.Read(e.key[:]); err != nil {
		t.Fatal(err)
	}
	ev := func(i int) func(rendr.Event) {
		return func(x rendr.Event) {
			if x.Kind == rendr.EventCarrierDown && x.Session != (rendr.SessionID{}) {
				e.mu.Lock()
				e.downs[i] = append(e.downs[i], x)
				e.mu.Unlock()
			}
		}
	}
	var err error
	if e.d, err = rendr.NewRuntime(rendr.Config{OnEvent: ev(0)}); err != nil {
		t.Fatal(err)
	}
	if e.p, err = rendr.NewRuntime(rendr.Config{OnEvent: ev(1)}); err != nil {
		t.Fatal(err)
	}
	if e.rl, err = e.p.Listen(rendr.ListenConfig{}); err != nil {
		t.Fatal(err)
	}
	e.tap = &qeTap{rl: e.rl}
	e.serve("127.0.0.1:0")
	e.addr = e.listener().Addr().String()
	e.relay = newQERelay(t, e.listener().Addr(), delay)
	t.Cleanup(e.close)
	return e
}

// serve opens a quic Listener at addr and serves the rendr Listener.
func (e *qeEnv) serve(addr string) {
	e.t.Helper()
	l, err := Listen("udp4", addr, Options{TLS: e.srv, StatelessResetKey: &e.key})
	if err != nil {
		e.t.Fatal(err)
	}
	ch := make(chan error, 1)
	go func() { ch <- l.serve(e.tap) }()
	e.mu.Lock()
	e.ls = append(e.ls, l)
	e.served = append(e.served, ch)
	e.mu.Unlock()
}

func (e *qeEnv) listener() *Listener {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ls[len(e.ls)-1]
}

// restart ends the quic Listener as a crashed process would — its
// transport and socket closed, no CONNECTION_CLOSE — and serves a new one
// at the same address with the same stateless reset key.
func (e *qeEnv) restart() {
	e.t.Helper()
	l := e.listener()
	_ = l.tr.Close()
	_ = l.udp.Close()
	e.serve(e.addr)
}

// dialAddr is where the dialer's factories dial: the relay.
func (e *qeEnv) dialAddr() string { return e.relay.front.LocalAddr().String() }

// record notes a session connection of the dialer (probe carriers are not
// recorded).
func (e *qeEnv) record(ctx context.Context, qc *qgo.Conn) {
	if di, ok := rendr.CarrierDialInfo(ctx); ok && !di.Probe {
		ap := qc.LocalAddr().(*net.UDPAddr).AddrPort()
		e.mu.Lock()
		e.dqc = append(e.dqc, qc)
		e.dlocal = append(e.dlocal, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		e.mu.Unlock()
	}
}

// factory returns the dialer's factory of kind (with QUIC options o).
func (e *qeEnv) factory(kind rendr.Kind, o Options) rendr.Carrier {
	e.t.Helper()
	o.TLS = e.cli
	if kind == rendr.KindStream {
		c, err := StreamCarrier("qs", e.dialAddr(), o)
		if err != nil {
			e.t.Fatal(err)
		}
		dial := c.Dial
		c.Dial = func(ctx context.Context) (net.Conn, error) {
			nc, err := dial(ctx)
			if err == nil {
				e.record(ctx, nc.(*streamConn).qc)
			}
			return nc, err
		}
		return c
	}
	c, err := DatagramCarrier("qd", e.dialAddr(), o)
	if err != nil {
		e.t.Fatal(err)
	}
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if err == nil {
			e.record(ctx, pc.(*dgramConn).qc)
		}
		return pc, a, err
	}
	return c
}

// session returns the dialer's i-th session connection and its passive
// counterpart.
func (e *qeEnv) session(i int) (dqc, pqc *qgo.Conn) {
	e.t.Helper()
	e.mu.Lock()
	dqc, local := e.dqc[i], e.dlocal[i]
	e.mu.Unlock()
	at, ok := e.relay.upstreamOf(local)
	if !ok {
		e.t.Fatalf("the relay has no upstream socket of %v", local)
	}
	if pqc = e.tap.from(at); pqc == nil {
		e.t.Fatalf("no passive connection from %v", at)
	}
	return dqc, pqc
}

func (e *qeEnv) sessions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.dqc)
}

// down returns side's CarrierDown events of session carriers so far.
func (e *qeEnv) down(side int) []rendr.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]rendr.Event(nil), e.downs[side]...)
}

// close closes both Runtimes and every quic Listener and requires that
// nothing is left.
func (e *qeEnv) close() {
	e.t.Helper()
	e.d.Close()
	e.p.Close()
	e.mu.Lock()
	ls, served := e.ls, e.served
	e.mu.Unlock()
	for i, l := range ls {
		_ = l.Close()
		if err := <-served[i]; !errors.Is(err, net.ErrClosed) && i == len(ls)-1 {
			e.t.Errorf("Serve returned %v, want net.ErrClosed", err)
		}
		select {
		case <-l.Done():
		case <-time.After(10 * time.Second):
			e.t.Errorf("quic Listener %d: Done not closed after Runtime.Close", i)
		}
	}
	for _, rt := range []*rendr.Runtime{e.d, e.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 {
			e.t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
}

// qeWait polls cond every 5 ms for at most within.
func qeWait(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// qeDone waits for ch.
func qeDone(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s did not end within 30 s", what)
	}
}

// qeOpen opens one session of kind and returns both ends (a *rendr.Conn
// or a *rendr.PacketConn).
func (e *qeEnv) qeOpen(kind rendr.Kind, o Options) (d, p any) {
	e.t.Helper()
	peer, err := e.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{e.factory(kind, o)}})
	if err != nil {
		e.t.Fatal(err)
	}
	type res struct {
		c   any
		err error
	}
	ch := make(chan res, 1)
	go func() {
		if kind == rendr.KindStream {
			c, err := peer.Dial(context.Background(), rendr.DialOptions{})
			ch <- res{c, err}
			return
		}
		c, err := peer.DialPacket(context.Background(), rendr.DialOptions{})
		ch <- res{c, err}
	}()
	if kind == rendr.KindStream {
		ps, err := e.rl.Accept(context.Background())
		if err == nil {
			p, err = ps.Confirm()
		}
		if err != nil {
			e.t.Fatalf("Accept: %v", err)
		}
	} else {
		pp, err := e.rl.AcceptPacket(context.Background())
		if err == nil {
			p, err = pp.Confirm()
		}
		if err != nil {
			e.t.Fatalf("AcceptPacket: %v", err)
		}
	}
	r := <-ch
	if r.err != nil {
		e.t.Fatalf("dial: %v", r.err)
	}
	return r.c, p
}

// qeStream moves total bytes dialer → passive → dialer (the passive
// echoes), 32 KiB every 10 ms, and compares SHA-256 digests.
type qeStream struct {
	d, p     *rendr.Conn
	total    int
	src      []byte
	got      chan []byte
	werr     chan error
	echoDone chan error
}

// startQEStream starts the transfer; the passive's echo ends at the
// dialer's FIN, or after total bytes when passiveCloses (it then closes
// first).
func startQEStream(d, p *rendr.Conn, total int, seed uint64, passiveCloses bool) *qeStream {
	s := &qeStream{d: d, p: p, total: total, src: make([]byte, total),
		got: make(chan []byte, 1), werr: make(chan error, 1), echoDone: make(chan error, 1)}
	rng := mrand.New(mrand.NewPCG(seed, 7))
	for i := range s.src {
		s.src[i] = byte(rng.Uint32())
	}
	go func() {
		var err error
		if passiveCloses {
			_, err = io.CopyN(p, p, int64(total))
		} else {
			_, err = io.Copy(p, p)
		}
		p.Close()
		s.echoDone <- err
	}()
	go func() {
		b, _ := io.ReadAll(io.LimitReader(d, int64(total)))
		s.got <- b
	}()
	go func() {
		for off := 0; off < total; off += 32 << 10 {
			if _, err := d.Write(s.src[off:min(off+32<<10, total)]); err != nil {
				s.werr <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		s.werr <- nil
	}()
	return s
}

// check waits for the transfer and compares the digests.
func (s *qeStream) check(t *testing.T) {
	t.Helper()
	if err := <-s.werr; err != nil {
		t.Fatalf("stream Write: %v", err)
	}
	var b []byte
	select {
	case b = <-s.got:
	case <-time.After(60 * time.Second):
		t.Fatal("the echo did not complete within 60 s")
	}
	if sha256.Sum256(b) != sha256.Sum256(s.src) {
		t.Fatalf("integrity: the echo differs (%d of %d bytes, SHA-256 mismatch)", len(b), s.total)
	}
}

// qePackets sends rate datagrams per second each way until halt and
// verifies every one.
type qePackets struct {
	d, p     *rendr.PacketConn
	rate     int
	start    time.Time
	up, down *rendrtest.PacketVerifier
	acc      [2]atomic.Uint64 // accepted by WriteTo: dialer, passive
	stop     chan struct{}
	gens     sync.WaitGroup
	readers  sync.WaitGroup
	verr     atomic.Value
}

func startQEPackets(d, p *rendr.PacketConn, rate int) *qePackets {
	q := &qePackets{d: d, p: p, rate: rate, start: time.Now(), stop: make(chan struct{}),
		up: rendrtest.NewPacketVerifier(21), down: rendrtest.NewPacketVerifier(22)}
	gen := func(c *rendr.PacketConn, seed uint64, n *atomic.Uint64) {
		defer q.gens.Done()
		buf := make([]byte, 1100)
		tk := time.NewTicker(time.Millisecond)
		defer tk.Stop()
		var seq uint64
		for {
			select {
			case <-q.stop:
				return
			case now := <-tk.C:
				for due := uint64(now.Sub(q.start).Seconds() * float64(rate)); seq < due; seq++ {
					b := rendrtest.PacketPayload(buf, seed, seq, rendrtest.PacketHeaderLen+int(seq*53%1000), now)
					if _, err := c.WriteTo(b, nil); err != nil {
						q.verr.CompareAndSwap(nil, err)
						return
					}
					n.Add(1)
				}
			}
		}
	}
	recv := func(c *rendr.PacketConn, v *rendrtest.PacketVerifier) {
		defer q.readers.Done()
		buf := make([]byte, 2048)
		for {
			k, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if err := v.Add(buf[:k], time.Now()); err != nil {
				q.verr.CompareAndSwap(nil, err)
			}
		}
	}
	q.gens.Add(2)
	q.readers.Add(2)
	go gen(d, 21, &q.acc[0])
	go gen(p, 22, &q.acc[1])
	go recv(p, q.up)
	go recv(d, q.down)
	return q
}

// halt stops the generators and lets the datagrams in flight arrive.
func (q *qePackets) halt() {
	close(q.stop)
	q.gens.Wait()
	time.Sleep(500 * time.Millisecond)
}

// check verifies both directions: no corrupt, resized or duplicate
// datagram; every loss outside [from, to] (the injection and the
// recovery) a counted drop, and at least 90 % of the datagrams sent
// outside it received; the send side adds up.
func (q *qePackets) check(t *testing.T, from, to time.Time, ctr *Counters) {
	t.Helper()
	if e := q.verr.Load(); e != nil {
		t.Errorf("application error: %v", e)
	}
	ds, ps := q.d.Status(), q.p.Status()
	for _, x := range []struct {
		name   string
		v      *rendrtest.PacketVerifier
		acc    uint64
		tx, rx *rendr.PacketCounters
	}{
		{"dialer → passive", q.up, q.acc[0].Load(), ds.Packet, ps.Packet},
		{"passive → dialer", q.down, q.acc[1].Load(), ps.Packet, ds.Packet},
	} {
		res := x.v.Result()
		if res.Corrupt+res.BadSize+res.Duplicates != 0 {
			t.Errorf("%s: corrupt %d, resized %d, duplicates %d", x.name, res.Corrupt, res.BadSize, res.Duplicates)
		}
		lo, hi := from.Add(-100*time.Millisecond), to.Add(500*time.Millisecond)
		seqAt := func(at time.Time) uint64 { return uint64(max(at.Sub(q.start), 0).Seconds() * float64(q.rate)) }
		inWin := min(seqAt(hi), x.acc) - min(seqAt(lo), x.acc)
		if res.Unique < (x.acc-inWin)*9/10 {
			t.Errorf("load: %s received %d of %d (%d sent around the injection)", x.name, res.Unique, x.acc, inWin)
		}
		var away uint64
		for _, m := range res.Missing {
			at := q.start.Add(time.Duration(m.From) * time.Second / time.Duration(q.rate))
			if at.Before(lo) || at.After(hi) {
				away += m.To - m.From + 1
			}
		}
		counted := x.tx.DropQueue + x.tx.DropAge + x.tx.DropNoPath + x.tx.DropTooLarge + x.rx.DropRecvQueue +
			ctr.IngressDrops.Load() + ctr.EgressDrops.Load()
		if away > counted {
			t.Errorf("%s: %d datagrams lost away from the injection, %d counted (missing %v)", x.name, away, counted, res.Missing)
		}
		if sum := x.tx.Sent + x.tx.DropQueue + x.tx.DropAge + x.tx.DropNoPath + x.tx.DropTooLarge; sum != x.acc {
			t.Errorf("%s: accepted %d differs from the send-side sum %d (%+v)", x.name, x.acc, sum, *x.tx)
		}
		t.Logf("%s: accepted %d, unique %d, missing %v", x.name, x.acc, res.Unique, res.Missing)
	}
}

// qeEnder is what qeEnd needs of a session end.
type qeEnder interface {
	Close() error
	Done() <-chan struct{}
}

// qeEnd closes both ends of a session (d first) and waits for both.
func qeEnd(t *testing.T, d, p any) {
	t.Helper()
	for _, c := range []any{d, p} {
		_ = c.(qeEnder).Close()
	}
	for _, c := range []any{d, p} {
		qeDone(t, c.(qeEnder).Done(), "a session")
	}
}

// qeStatus returns the session status of c.
func qeStatus(c any) rendr.SessionStatus {
	if s, ok := c.(*rendr.Conn); ok {
		return s.Status()
	}
	return c.(*rendr.PacketConn).Status()
}

// TestQUICErrorsAreDeathE2E_L01 is the end-to-end half of
// TestQUICErrorsAreDeath_L01 (L01: any QUIC error enters failover; the
// original error is diagnosis only, from context.Cause): two Runtimes, a
// session of each kind over its QUIC factory through a loopback relay
// (stream: 4 MiB echoed; DATAGRAM: 1,000 datagrams per second each way),
// and while it runs one QUIC error ends the session's connection — the
// passive application's CloseWithError(7), QUIC's own idle timeout (an
// explicit 1-s IdleTimeout and a black-holed relay), a stateless reset
// from a restarted passive listener (same key). Stimulus: the dialer's
// carrier ends with transport_error (never ping_timeout: rendr's death
// deadline is 3 s) and its DeathDetail carries the connection's close
// cause, of the expected QUIC error type; the passive's carrier dies too.
// Failover: the session moves to a new connection (a death migration or a
// rejoin) and goes on. The application sees no error; integrity: the
// stream's SHA-256, every datagram's seq and content, losses only around
// the injection or counted.
func TestQUICErrorsAreDeathE2E_L01(t *testing.T) {
	type row struct {
		name   string
		idle   time.Duration
		inject func(e *qeEnv, pqc *qgo.Conn)
		heal   func(e *qeEnv)
		want   func(cause error) bool
		// passive: how the passive's carrier ends (CauseNone: any end; with
		// the black hole it may retire, replaced by the dialer's rejoin,
		// before its own QUIC idle timer fires)
		passive rendr.Cause
	}
	rows := []row{
		{"application close", 0,
			func(_ *qeEnv, pqc *qgo.Conn) { _ = pqc.CloseWithError(7, "bye") },
			nil,
			func(c error) bool {
				var ae *qgo.ApplicationError
				return errors.As(c, &ae) && ae.ErrorCode == 7 && ae.Remote
			}, rendr.CauseTransportError},
		{"idle timeout", time.Second,
			func(e *qeEnv, _ *qgo.Conn) { e.relay.blackhole.Store(true) },
			func(e *qeEnv) { e.relay.blackhole.Store(false) },
			func(c error) bool { return errors.As(c, new(*qgo.IdleTimeoutError)) }, rendr.CauseNone},
		{"stateless reset", 0,
			func(e *qeEnv, _ *qgo.Conn) { e.restart() },
			nil,
			func(c error) bool { return errors.As(c, new(*qgo.StatelessResetError)) }, rendr.CauseTransportError},
	}
	t.Cleanup(rendrtest.AssertNoLeak(t))
	for _, kind := range []rendr.Kind{rendr.KindStream, rendr.KindDatagram} {
		for _, r := range rows {
			t.Run(kind.String()+"/"+r.name, func(t *testing.T) {
				e := newQEEnv(t, 0)
				var ctr Counters
				d, p := e.qeOpen(kind, Options{IdleTimeout: r.idle, Counters: &ctr})
				var str *qeStream
				var pkt *qePackets
				if kind == rendr.KindStream {
					str = startQEStream(d.(*rendr.Conn), p.(*rendr.Conn), 4<<20, 3, false)
				} else {
					pkt = startQEPackets(d.(*rendr.PacketConn), p.(*rendr.PacketConn), 1000)
				}
				time.Sleep(700 * time.Millisecond)
				dqc, pqc := e.session(0)
				var pid rendr.CarrierID
				for _, cs := range qeStatus(p).Carriers {
					pid = cs.ID // the passive's one carrier
				}
				injected := time.Now()
				r.inject(e, pqc)
				qeWait(t, 10*time.Second, "the dialer's carrier ended", func() bool { return len(e.down(0)) > 0 })
				if r.heal != nil {
					r.heal(e)
				}
				qeWait(t, 15*time.Second, "a new session connection", func() bool { return e.sessions() > 1 })
				qeWait(t, 15*time.Second, "a live carrier again", func() bool {
					for _, cs := range qeStatus(d).Carriers {
						if cs.DeathCause == rendr.CauseNone && (cs.State == rendr.CarrierActive || cs.State == rendr.CarrierMember) {
							return true
						}
					}
					return false
				})
				recovered := time.Now()
				if str != nil {
					str.check(t)
					_ = d.(*rendr.Conn).CloseWrite()
					if err := <-str.echoDone; err != nil {
						t.Errorf("the passive's echo: %v", err)
					}
				} else {
					time.Sleep(2 * time.Second) // traffic on the new carrier
					pkt.halt()
					// The passive keeps sending on its old carrier until the
					// dialer's rejoin reaches it: losses up to 1 s after the
					// dialer's recovery are in flight on a dead path.
					pkt.check(t, injected, recovered.Add(time.Second), &ctr)
				}

				// The death and its diagnosis.
				cause := context.Cause(dqc.Context())
				if !r.want(cause) {
					t.Errorf("the dialer connection ended by %T %v", cause, cause)
				}
				ev := e.down(0)[0]
				if ev.Cause != rendr.CauseTransportError {
					t.Errorf("the dialer's carrier ended by %v, want transport_error", ev.Cause)
				}
				var detail string
				for _, cs := range qeStatus(d).Carriers {
					if cs.ID == ev.Carrier {
						detail = cs.DeathDetail
					}
				}
				if cause == nil || !strings.Contains(detail, cause.Error()) {
					t.Errorf("the dead carrier's detail %q does not carry the QUIC cause %v", detail, cause)
				}
				var pcs rendr.CarrierStatus
				qeWait(t, 10*time.Second, "the passive's carrier ended", func() bool {
					for _, cs := range qeStatus(p).Carriers {
						if cs.ID == pid {
							pcs = cs
						}
					}
					return pcs.DeathCause != rendr.CauseNone
				})
				if r.passive != rendr.CauseNone && pcs.DeathCause != r.passive {
					t.Errorf("the passive's carrier ended by %v %q, want %v", pcs.DeathCause, pcs.DeathDetail, r.passive)
				}
				st := qeStatus(d)
				if st.Migrations.Death+st.Rejoins == 0 || st.Err != nil && !errors.Is(st.Err, io.EOF) { // io.EOF: the stream ended cleanly
					t.Errorf("failover: migrations %+v, rejoins %d, err %v", st.Migrations, st.Rejoins, st.Err)
				}
				t.Logf("detail %q after %v; recovered %v after the injection; migrations %+v rejoins %d; relay dropped %d",
					detail, ev.Time.Sub(injected), recovered.Sub(injected), st.Migrations, st.Rejoins, e.relay.dropped.Load())
				qeEnd(t, d, p)
			})
		}
	}
}

// TestQUICRetireBothSidesRetired (M2 design §A6.3; integration 1, K4):
// sessions of each kind over QUIC (through a relay with a 20-ms one-way
// delay) end cleanly, closed first by either side, and their carrier ends
// as retired on both sides (no CarrierDown event: the session ended
// first). On a stream carrier the CLOSE exchange completes on both sides
// ("CLOSE exchange complete"), never cut short by QUIC's CONNECTION_CLOSE,
// which discards what the receiver has not read yet: the side that writes
// the second CLOSE closes its connection only after the stream adapter's
// linger (clamp(2·srtt + 50 ms, 50 ms, 500 ms), ended early by the peer's
// own close), so the first closer reads that CLOSE. Without the linger the
// second CLOSE is often lost with the connection (the first closer then
// ends by "read ended after CLOSE"), so four sessions run per stream row.
// A datagram carrier's retirement may end either way (R1-4: its CLOSE is
// REL-acknowledged). The dialer's connection — and with it its UDP socket
// — is released within the linger's bound of the session's end (K4).
func TestQUICRetireBothSidesRetired(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	for _, kind := range []rendr.Kind{rendr.KindStream, rendr.KindDatagram} {
		for _, passiveFirst := range []bool{false, true} {
			name := kind.String() + "/dialer closes"
			if passiveFirst {
				name = kind.String() + "/passive closes"
			}
			t.Run(name, func(t *testing.T) {
				e := newQEEnv(t, 20*time.Millisecond)
				rounds := 4
				if kind == rendr.KindDatagram {
					rounds = 1
				}
				for i := range rounds {
					retireOnce(t, e, kind, passiveFirst, i)
				}
				if n0, n1 := len(e.down(0)), len(e.down(1)); n0+n1 != 0 {
					t.Errorf("CarrierDown events: dialer %d, passive %d; want none", n0, n1)
				}
			})
		}
	}
}

// retireOnce runs session i of TestQUICRetireBothSidesRetired.
func retireOnce(t *testing.T, e *qeEnv, kind rendr.Kind, passiveFirst bool, i int) {
	t.Helper()
	d, p := e.qeOpen(kind, Options{})
	dqc, _ := e.session(i)
	released, ended := make(chan time.Time, 1), make(chan time.Time, 1)
	go func() { <-dqc.Context().Done(); released <- time.Now() }()
	go func() { <-d.(qeEnder).Done(); ended <- time.Now() }()
	if kind == rendr.KindStream {
		dc := d.(*rendr.Conn)
		s := startQEStream(dc, p.(*rendr.Conn), 128<<10, uint64(i), passiveFirst)
		s.check(t)
		if passiveFirst {
			if n, err := dc.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Errorf("the dialer's Read after the passive's Close: %d, %v; want io.EOF", n, err)
			}
		}
		dc.Close()
		if err := <-s.echoDone; err != nil {
			t.Errorf("the passive's echo: %v", err)
		}
	} else {
		dc, pc := d.(*rendr.PacketConn), p.(*rendr.PacketConn)
		q := startQEPackets(dc, pc, 500)
		time.Sleep(time.Second)
		q.halt()
		var ctr Counters
		q.check(t, time.Now(), time.Now(), &ctr)
		first := dc
		if passiveFirst {
			first = pc
		}
		first.Close()
		q.readers.Wait() // the peer's ReadFrom ended with io.EOF, the closer's with net.ErrClosed
	}
	qeEnd(t, d, p)
	for side, c := range []any{d, p} {
		cs := qeStatus(c).Carriers
		if len(cs) != 1 || cs[0].DeathCause != rendr.CauseRetired {
			t.Errorf("session %d, side %d: carriers %+v, want one, retired", i, side, cs)
		} else if kind == rendr.KindStream && cs[0].DeathDetail != "retired: CLOSE exchange complete" {
			t.Errorf("session %d, side %d: the retirement ended by %q, want the CLOSE exchange complete", i, side, cs[0].DeathDetail)
		}
	}
	var at time.Time
	select {
	case at = <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the dialer's QUIC connection was not released within 5 s of the session's end")
	}
	// The linger's clamp is 500 ms; 100 ms more covers scheduling.
	if took := at.Sub(<-ended); took > 600*time.Millisecond {
		t.Errorf("the dialer's connection was released %v after its session ended, beyond the 500-ms linger (+100 ms)", took)
	} else {
		t.Logf("session %d: the dialer's connection was released %v after its session ended (%v)", i, took, context.Cause(dqc.Context()))
	}
}
