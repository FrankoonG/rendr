package rendr

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// More end-to-end rows of integration 2: raw-UDP flows over a DatagramHub
// (FromPacketConn), admission quotas, ownership and close, held carriers,
// rebinding, the response tail, probes and SCHED over REL.

// peHub is two Runtimes whose passive listens on a DatagramHub's socket
// (wrapped by wrap, if set).
type peHub struct {
	t    testing.TB
	d, p *Runtime
	ln   *Listener
	hub  *rendrtest.DatagramHub
}

func peNewHub(t testing.TB, cfg Config, lc ListenConfig, wrap func(net.PacketConn) net.PacketConn) *peHub {
	t.Helper()
	h := &peHub{t: t, d: wpTestRuntime(t, cfg, nil), p: wpTestRuntime(t, cfg, nil)}
	h.hub = rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "hub", Queue: 8192})
	t.Cleanup(func() { h.hub.Close() })
	pc := h.hub.PacketConn()
	if wrap != nil {
		pc = wrap(pc)
	}
	lc.Sources = append(lc.Sources, FromPacketConn(pc))
	h.ln = wpListen(t, h.p, lc)
	return h
}

// carrier returns a datagram factory of client host n (wrapped by lc).
func (h *peHub) carrier(name string, n int, lc *lastPC) DatagramCarrier {
	dial := h.hub.DialFrom(n)
	if lc != nil {
		dial = lc.wrap(dial)
	}
	return DatagramCarrier{Name: name, Dial: dial, MTU: 1223}
}

func (h *peHub) peer(cs ...Carrier) *Peer {
	h.t.Helper()
	p, err := h.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		h.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

func (h *peHub) close() {
	h.t.Helper()
	h.d.Close()
	h.p.Close()
	h.hub.Close()
	peNoState(h.t, h.d)
	peNoState(h.t, h.p)
}

// lastPC records the conns a datagram factory returned, so a test can
// close one under rendr (an embedder-closed conn) and count Close calls.
type lastPC struct {
	mu  sync.Mutex
	pcs []*countPC
}

func (l *lastPC) wrap(dial func(context.Context) (net.PacketConn, net.Addr, error)) func(context.Context) (net.PacketConn, net.Addr, error) {
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c := &countPC{PacketConn: pc}
		l.mu.Lock()
		l.pcs = append(l.pcs, c)
		l.mu.Unlock()
		return c, a, nil
	}
}

func (l *lastPC) last() *countPC {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pcs) == 0 {
		return nil
	}
	return l.pcs[len(l.pcs)-1]
}

// TestPacketOpenPoolsFlood_L48: the flood half of TestPacketOpenPools_L48
// (R1-21). A packet session runs over a FromPacketConn socket; then a
// flood — valid packet OPEN and JOIN first datagrams, bad CRCs and random
// bytes, a quarter of it from the session's own source IP address —
// arrives while nobody accepts (Accept stalls, so the flood's OPENs keep
// that address's OPEN quota full). The session's carrier is closed under
// rendr: its failover JOIN from the same address completes within 1 s and
// datagrams flow again; the flows stay bounded.
func TestPacketOpenPoolsFlood_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		lc := &lastPC{}
		dc, pc := peOpen(t, h.peer(h.carrier("h0", 0, lc)), h.ln, DialOptions{})
		stop := h.hub.Flood(4000, rendrtest.FloodMix{Random: 1, BadCRC: 1, Preface: 4, Join: 2})
		time.Sleep(2 * time.Second)
		st := h.p.Status()
		if st.Datagram.Admitting < 32 || st.AcceptBacklog[1] == 0 {
			t.Fatalf("stimulus: the flood's OPENs fill no quota (admitting %d, packet backlog %d)", st.Datagram.Admitting, st.AcceptBacklog[1])
		}
		killed := lc.last()
		killed.Close()
		start := time.Now()
		peWait(t, time.Second, "the failover JOIN", func() bool {
			live := peLive(dc)
			return len(live) == 1 && dc.Status().Rejoins == 1
		})
		t.Logf("failover JOIN completed %v after the kill; flows %d, admitting %d", time.Since(start), h.p.Status().Datagram.Flows, h.p.Status().Datagram.Admitting)
		peSend(t, dc, 10, 0, 50, 500)
		if v := peRecv(t, pc, 10, 50, time.Second); v.Result().Unique != 50 {
			t.Fatalf("after the failover: %+v", v.Result())
		}
		stop()
		peEnd(t, dc, pc)
		h.close()
	})
}

// TestPacketOpenAckPerCarrierE2E (R1-5, M2-D11): a bond whose passive
// confirms after JoinStagger has two OPEN carriers of different budgets
// (1200 and 1400); each is answered with its own cmtu_acc, both attach and
// neither is killed; the session's MaxPayload is the smaller budget − 25.
func TestPacketOpenAckPerCarrierE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a", "b")
		var downs atomic.Int32
		ch := peDial(e.peer(peDatagramCarrier(e.links[0], 1200), peDatagramCarrier(e.links[1], 1400)), DialOptions{Mode: ModeBond})
		pp, err := e.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Second) // past JoinStagger: the second factory's OPEN is there too
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		dc := r.c
		peWait(t, time.Second, "both OPEN carriers attached", func() bool { return len(peLive(dc)) == 2 })
		mtus := map[string]int{}
		for _, cs := range peLive(dc) {
			mtus[cs.Name] = cs.MTU
		}
		if mtus["a"] != 1200 || mtus["b"] != 1400 {
			t.Fatalf("carrier budgets %v, want a 1200, b 1400", mtus)
		}
		for _, cs := range dc.Status().Carriers {
			if cs.State == CarrierDead {
				downs.Add(1)
			}
		}
		if downs.Load() != 0 || dc.Status().Rejoins != 0 {
			t.Fatalf("a carrier died or was replaced: %+v", dc.Status().Carriers)
		}
		if dc.MaxPayload() != 1175 || pc.MaxPayload() != 1175 {
			t.Fatalf("MaxPayload %d / %d, want 1175", dc.MaxPayload(), pc.MaxPayload())
		}
		peEnd(t, dc, pc)
		e.close()
	})
}

// TestPacketSelectorNoGaugeE2E (M2-D26, R1-33) on started datagram lanes:
// nothing is submitted on a datagram carrier (Inflight stays 0 under
// load), while a packet session's stream carrier counts its DGRAM bytes in
// flight.
func TestPacketSelectorNoGaugeE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a")
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400)), e.ln, DialOptions{})
		go func() {
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 1000)
		for i := range 2000 {
			dc.WriteTo(buf, nil)
			if i%5 == 0 {
				time.Sleep(time.Millisecond)
				if cs := dc.Status().Carriers[0]; cs.Inflight != 0 {
					t.Fatalf("a datagram carrier reports %d bytes in flight", cs.Inflight)
				}
			}
		}
		peEnd(t, dc, pc)

		sl := rendrtest.NewLink(rendrtest.LinkConfig{Name: "s", Accept: e.ln.Handle})
		defer sl.Close()
		sl.SetDelay(20*time.Millisecond, 0)
		dc, pc = peOpen(t, e.peer(e2eCarrier(sl)), e.ln, DialOptions{})
		var inflight int
		for range 200 {
			dc.WriteTo(buf, nil)
			inflight = max(inflight, dc.Status().Carriers[0].Inflight)
			time.Sleep(time.Millisecond)
		}
		if inflight == 0 {
			t.Fatal("a stream carrier of a packet session never had DGRAM bytes in flight")
		}
		peEnd(t, dc, pc)
		sl.Close()
		e.close()
	})
}

// TestPacketAdmittingReleasedE2E_L48 (M2-D59; the WP8 review's surviving
// mutants): a packet session's raw-UDP flow counts against its source's
// admitting quota until Confirm writes its OPEN_ACK(OK) — through
// Registry.Opened, not a direct call — and a bond member's JOIN flow
// leaves the quota at once; with every carrier attached Admitting is 0.
func TestPacketAdmittingReleasedE2E_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		ch := peDial(h.peer(h.carrier("h0", 0, nil), h.carrier("h1", 1, nil)), DialOptions{Mode: ModeBond})
		pp, err := h.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if a := h.p.Status().Datagram.Admitting; a < 1 {
			t.Fatalf("a pending session's OPEN flow: Admitting %d, want ≥ 1", a)
		}
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		peWait(t, 5*time.Second, "both members", func() bool { return len(peLive(r.c)) == 2 })
		time.Sleep(100 * time.Millisecond)
		if ds := h.p.Status().Datagram; ds.Admitting != 0 || ds.Flows < 2 {
			t.Fatalf("after Confirm and the JOIN: %+v, want Admitting 0", ds)
		}
		peEnd(t, r.c, pc)
		h.close()
	})
}

// TestRuntimeCloseOpenPacketSession: the open-session half of
// TestRuntimeCloseSourcesLast. The passive Runtime closes while a packet
// session over its FromPacketConn socket is open: the session's
// RST(GoingAway) travels over the socket before it closes, so the
// dialer's ReadFrom ends with *AbortError(AbortGoingAway), within the close
// bound; nothing is left on either side.
func TestRuntimeCloseOpenPacketSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		dc, _ := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
		res := make(chan error, 1)
		go func() {
			buf := make([]byte, 64)
			_, _, err := dc.ReadFrom(buf)
			res <- err
		}()
		start := time.Now()
		h.p.Close()
		var err error
		select {
		case err = <-res:
		case <-time.After(5 * time.Second):
			t.Fatal("the dialer's ReadFrom did not end within 5 s of the passive's Runtime.Close")
		}
		var ae *AbortError
		if !errors.As(err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
			t.Fatalf("the dialer's ReadFrom: %v, want *AbortError(AbortGoingAway) from the peer", err)
		}
		t.Logf("the dialer saw %v after %v", err, time.Since(start))
		<-dc.Done()
		h.close()
	})
}

// TestOpenKindMismatchOpenSession: the open-session row of
// TestOpenKindMismatchRefused. A stream OPEN with an open packet session's
// key (its dialer instance and SID) is refused BAD_REQUEST CodeBadKind on
// its own carrier and never attached; the packet session keeps working.
func TestOpenKindMismatchOpenSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a")
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400)), e.ln, DialOptions{})
		w := wpConnect(t, e.ln, [16]byte(e.d.InstanceID()), 77)
		w.hello(e.p)
		w.send(wire.TypeOpen, 0, wpOpen([16]byte(dc.ID()), wire.KindStream, 1, nil))
		w.expectOpenAck(wire.StatusBadRequest, wire.CodeBadKind)
		w.close()
		peSend(t, dc, 11, 0, 20, 300)
		if v := peRecv(t, pc, 11, 20, time.Second); v.Result().Unique != 20 {
			t.Fatalf("the packet session after the refused OPEN: %+v", v.Result())
		}
		if n := len(pc.Status().Carriers); n != 1 {
			t.Fatalf("the passive session has %d carriers, want 1", n)
		}
		peEnd(t, dc, pc)
		e.close()
	})
}

// TestPacketFactoryMisbehaviour_L51: a datagram factory that errs, hangs
// (with or without honouring ctx), returns nil conns or a nil address,
// panics, calls runtime.Goexit or succeeds late cannot hurt the session:
// DialPacket succeeds through the healthy factory, the session works, a
// late conn is closed, and both Runtimes close with nothing left (the
// bubble's end proves every goroutine exited); a call that ignores ctx
// is abandoned and counted while it hangs (L51), and leaves the count
// when it returns.
func TestPacketFactoryMisbehaviour_L51(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    rendrtest.DialBehavior
	}{
		{"error", rendrtest.DialError}, {"hang", rendrtest.DialHang}, {"hang forever", rendrtest.DialHangForever},
		{"nil, nil", rendrtest.DialNilNil}, {"panic", rendrtest.DialPanic}, {"Goexit", rendrtest.DialGoexit},
		{"late success", rendrtest.DialLateSuccess}, {"nil address", rendrtest.DialNilAddr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := peNew(t, Config{}, Config{}, nil, 0, "bad", "good")
				e.links[0].SetDialBehavior(tc.b)
				p := e.peer(peDatagramCarrier(e.links[0], 1400), peDatagramCarrier(e.links[1], 1400))
				dc, pc := peOpen(t, p, e.ln, DialOptions{})
				peSend(t, dc, 12, 0, 20, 300)
				if v := peRecv(t, pc, 12, 20, time.Second); v.Result().Unique != 20 {
					t.Fatalf("%+v", v.Result())
				}
				time.Sleep(15 * time.Second) // dial attempts on the bad factory time out
				abandoned := e.d.Status().Abandoned
				e.links[0].SetDialBehavior(rendrtest.DialNormal)
				e.links[0].Release()
				peEnd(t, dc, pc)
				want := 0
				if tc.b == rendrtest.DialHangForever || tc.b == rendrtest.DialLateSuccess { // both ignore ctx
					want = 1
				}
				if abandoned != want {
					t.Fatalf("Abandoned %d while the bad factory hung, want %d", abandoned, want)
				}
				e.close()
			})
		})
	}
}

// TestPacketCloseJoins_L52: Runtime.Close of a dialer with an open packet
// bond under load joins every goroutine of its sessions and carriers
// (Abandoned 0, Done closed; the bubble ends only when every goroutine
// exited) and both Runtimes are left empty.
func TestPacketCloseJoins_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a", "b")
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400), peDatagramCarrier(e.links[1], 1400)), e.ln, DialOptions{Mode: ModeBond})
		peWait(t, 5*time.Second, "both members", func() bool { return len(peLive(dc)) == 2 })
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			buf := make([]byte, 700)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := dc.WriteTo(buf, nil); err != nil {
					return
				}
				time.Sleep(100 * time.Microsecond)
			}
		}()
		time.Sleep(time.Second)
		e.d.Close()
		close(stop)
		select {
		case <-dc.Done():
		default:
			t.Fatal("the dialer session's Done is open after Runtime.Close")
		}
		if st := e.d.Status(); st.Abandoned != 0 {
			t.Fatalf("Runtime.Close abandoned %d goroutines", st.Abandoned)
		}
		<-pc.Done()
		wg.Wait()
		e.close()
	})
}

// xorPC is a foreign net.PacketConn (not carrier/udp's): it XORs every
// datagram it reads and writes, so a peer that does the same can talk to
// rendr only if rendr uses the conn's own ReadFrom and WriteTo (L57).
type xorPC struct {
	net.PacketConn
	skip int         // bytes left as they are (the raw-UDP flow header on the shared socket)
	odd  chan []byte // datagrams to hand out from a non-UDPAddr source
}

func xorBytes(b []byte) {
	for i := range b {
		b[i] ^= 0x5a
	}
}

func (x *xorPC) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-x.odd:
		return copy(p, b), panicAddr{}, nil
	default:
	}
	n, a, err := x.PacketConn.ReadFrom(p)
	if n > x.skip {
		xorBytes(p[x.skip:n])
	}
	return n, a, err
}

func (x *xorPC) WriteTo(p []byte, a net.Addr) (int, error) {
	b := bytes.Clone(p)
	if len(b) > x.skip {
		xorBytes(b[x.skip:])
	}
	return x.PacketConn.WriteTo(b, a)
}

// TestFromPacketConnForeign_L57: a FromPacketConn socket that is not
// carrier/udp's is used through its methods only: an XOR wrapper on both
// ends carries a packet session (rendr reads and writes through the
// wrapper); a datagram from a source that is no *net.UDPAddr is dropped
// and counted without any method of its address being called; a Listen
// that fails (the same socket twice) never closes the caller's conn.
func TestFromPacketConnForeign_L57(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var x *xorPC
		h := peNewHub(t, Config{}, ListenConfig{}, func(pc net.PacketConn) net.PacketConn {
			x = &xorPC{PacketConn: pc, skip: wire.FlowHeaderLen, odd: make(chan []byte, 1)}
			return x
		})
		dial := h.hub.Dial
		p := h.peer(DatagramCarrier{Name: "x", MTU: 1223, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			pc, a, err := dial(ctx)
			if err != nil {
				return nil, nil, err
			}
			return &xorPC{PacketConn: pc}, a, nil
		}})
		dc, pc := peOpen(t, p, h.ln, DialOptions{})
		peSend(t, dc, 13, 0, 30, 400)
		if v := peRecv(t, pc, 13, 30, time.Second); v.Result().Unique != 30 {
			t.Fatalf("over the XOR conn: %+v", v.Result())
		}
		before := h.p.Status().Datagram.Dropped
		x.odd <- bytes.Repeat([]byte{1}, 40)
		peSend(t, dc, 13, 30, 5, 400) // a read after the odd one
		peRecv(t, pc, 13, 5, time.Second)
		if after := h.p.Status().Datagram.Dropped; after <= before {
			t.Fatalf("a datagram from a non-UDPAddr source was not dropped (Dropped %d → %d)", before, after)
		}
		peEnd(t, dc, pc)

		c := &countPC{PacketConn: h.hub.PacketConn()}
		if _, err := h.p.Listen(ListenConfig{Sources: []Source{FromPacketConn(c), FromPacketConn(c)}}); err == nil {
			t.Fatal("Listen with one socket twice succeeded")
		}
		if c.closes.Load() != 0 {
			t.Fatalf("a failed Listen closed the caller's conn %d times", c.closes.Load())
		}
		h.close()
	})
}

// stuckPC is a foreign socket whose ReadFrom ignores Close: after Close it
// blocks until release (L50: an embedder conn that does not unblock).
type stuckPC struct {
	net.PacketConn
	closed  chan struct{}
	release chan struct{}
	closes  atomic.Int32
	once    sync.Once
}

func (s *stuckPC) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		<-s.release
	}
	return n, a, err
}

func (s *stuckPC) Close() error {
	s.closes.Add(1)
	s.once.Do(func() { close(s.closed) })
	return s.PacketConn.Close()
}

// TestPacketSourceIgnoresClose_L50: Runtime.Close with an open packet
// session over a FromPacketConn socket whose ReadFrom ignores Close: the
// session ends (the dialer sees AbortGoingAway), the socket is closed
// exactly once, and Runtime.Close returns within its bound although the
// demux goroutine stays blocked in the embedder's ReadFrom; once that
// returns, the source is gone.
func TestPacketSourceIgnoresClose_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var s *stuckPC
		h := peNewHub(t, Config{}, ListenConfig{}, func(pc net.PacketConn) net.PacketConn {
			s = &stuckPC{PacketConn: pc, closed: make(chan struct{}), release: make(chan struct{})}
			return s
		})
		dc, _ := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
		start := time.Now()
		h.p.Close()
		took := time.Since(start)
		if took > 10*time.Second {
			t.Fatalf("Runtime.Close took %v with a socket that ignores Close", took)
		}
		if n := s.closes.Load(); n != 1 {
			t.Fatalf("the socket was closed %d times, want 1", n)
		}
		select {
		case <-dc.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the dialer session did not end")
		}
		var ae *AbortError
		if err := dc.Status().Err; !errors.As(err, &ae) || ae.Code != AbortGoingAway {
			t.Fatalf("the dialer's end: %v, want AbortGoingAway", err)
		}
		close(s.release)
		peWait(t, 5*time.Second, "the source ended", func() bool { return h.p.Status().Datagram.Sources == 0 })
		t.Logf("Runtime.Close returned after %v", took)
		h.close()
	})
}

// TestSharedSocketClosedOnceE2E_L50: Listener.Close keeps the flows of an
// open packet session (the socket stays open and the session works); the
// socket closes once its last flow ended, exactly once, and Runtime.Close
// closes nothing again.
func TestSharedSocketClosedOnceE2E_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c *countPC
		h := peNewHub(t, Config{}, ListenConfig{}, func(pc net.PacketConn) net.PacketConn {
			c = &countPC{PacketConn: pc}
			return c
		})
		dc, pc := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
		h.ln.Close()
		time.Sleep(time.Second)
		if c.closes.Load() != 0 {
			t.Fatal("Listener.Close closed the socket of an open session")
		}
		peSend(t, dc, 14, 0, 20, 300)
		if v := peRecv(t, pc, 14, 20, time.Second); v.Result().Unique != 20 {
			t.Fatalf("after Listener.Close: %+v", v.Result())
		}
		peEnd(t, dc, pc)
		peWait(t, 5*time.Second, "the socket closed after the last flow", func() bool { return c.closes.Load() == 1 })
		h.close()
		if n := c.closes.Load(); n != 1 {
			t.Fatalf("the socket was closed %d times, want 1", n)
		}
	})
}

// TestHeldCarrierRepeatsH2E2E: the H2-repeat half of
// TestHeldDatagramCarrier (M2-D22, R1-8). While a packet OPEN's carrier is
// held (no Confirm yet), a duplicate of its H1 is answered with the same H2
// bytes and creates no state; at Confirm the verdict follows.
func TestHeldCarrierRepeatsH2E2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		w := newWDLink(t, rt, ln, 0)
		d := w.dial(wpInst(0xc1), 9)
		d.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(9), 1, 1400, 1375))
		h2 := d.read(time.Second)
		if !wire.IsPreface(h2) {
			t.Fatalf("no H2: %x", h2)
		}
		time.Sleep(500 * time.Millisecond)
		for range 2 {
			if _, err := d.pc.WriteTo(d.h1, d.peer); err != nil {
				t.Fatal(err)
			}
			again := d.read(time.Second)
			for again != nil && !wire.IsPreface(again) { // a held carrier's PONG or RACK may come first
				again = d.read(time.Second)
			}
			if !bytes.Equal(again, h2) {
				t.Fatalf("the repeated H2 differs:\n%x\n%x", again, h2)
			}
		}
		if st := rt.Status(); st.Sessions.Pending != 1 || st.AcceptBacklog != [2]int{0, 1} {
			t.Fatalf("the duplicate H1 created state: %+v", st)
		}
		pp, err := ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		go pp.Confirm()
		d.expectOpenAck(wire.StatusOK, 0)
		d.close()
		rt.Close()
	})
}

// TestRebindWhileHeld_L59: the held and between-H1-and-H3 rows of
// TestRebindNonce_L59 (R1-14). A packet session's dialer moves to a new
// address while its passive carrier is held (no Confirm for 3 s). Between
// H1 and H2 (the H2 went to the old address): the passive learns the new
// address from the dialer's resent H1 (a byte-identical copy from a
// candidate source), challenges it from the held writer, the dialer's
// Establish answers, the rebind commits and the verdict reaches the new
// address — DialPacket succeeds at Confirm and the carrier counts one
// rebind. After H2 the dialer sends nothing until the verdict (its H1 is
// acknowledged), so nothing reveals the move: the verdict goes to the old
// address, the attempt ends at Handshake.Timeout and the Dial's next
// carrier opens the session (no rebind; integration 2, known limitation
// K5). Either way datagrams then flow both ways.
func TestRebindWhileHeld_L59(t *testing.T) {
	for _, tc := range []struct {
		name   string
		h2Lost bool // the rebind happens while H2 is in flight (between H1 and H2)
	}{{"between H1 and H2", true}, {"after H2, held", false}} {
		t.Run(tc.name, func(t *testing.T) { rebindWhileHeld(t, tc.h2Lost) })
	}
}

func rebindWhileHeld(t *testing.T, h2Lost bool) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		h.hub.SetDelay(rendrtest.Down, 50*time.Millisecond, 0)
		start := time.Now()
		ch := peDial(h.peer(h.carrier("h0", 0, nil)), DialOptions{})
		pp, err := h.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !h2Lost {
			time.Sleep(time.Second)
		}
		h.hub.Rebind(0)
		time.Sleep(3 * time.Second)
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		var r peDialed
		select {
		case r = <-ch:
		case <-time.After(15 * time.Second):
			t.Fatal("DialPacket did not complete after the rebind")
		}
		t.Logf("DialPacket returned %v after its start (%v)", time.Since(start), r.err)
		if r.err != nil {
			t.Fatalf("DialPacket: %v", r.err)
		}
		dc := r.c
		peSend(t, dc, 15, 0, 20, 300)
		if v := peRecv(t, pc, 15, 20, time.Second); v.Result().Unique != 20 {
			t.Fatalf("up: %+v", v.Result())
		}
		peSend(t, pc, 16, 0, 20, 300)
		if v := peRecv(t, dc, 16, 20, time.Second); v.Result().Unique != 20 {
			t.Fatalf("down: %+v", v.Result())
		}
		want := uint64(0)
		if h2Lost {
			want = 1
			if d := time.Since(start); d > 4*time.Second {
				t.Fatalf("DialPacket took %v: the rebind was not found before the verdict", d)
			}
		}
		var rebinds uint64
		for _, cs := range pc.Status().Carriers {
			rebinds += cs.Rebinds
		}
		if rebinds != want || h.p.Status().Datagram.Rebinds != want {
			t.Fatalf("rebinds: carriers %+v, Runtime %d; want %d", pc.Status().Carriers, h.p.Status().Datagram.Rebinds, want)
		}
		peEnd(t, dc, pc)
		h.close()
	})
}

// peFrames decodes the frames of a captured datagram (REL payloads
// unwrapped: their inner type is reported).
func peFrames(t testing.TB, b []byte) []wire.Type {
	t.Helper()
	if wire.IsPreface(b) {
		b = b[wire.PrefaceLen:]
	}
	var out []wire.Type
	for len(b) > 0 {
		f, n, err := wire.DecodeFrame(b)
		if err != nil {
			t.Fatalf("a captured frame: %v", err)
		}
		if f.Type == wire.TypeRel {
			if h, _, err := wire.ParseRel(f.Payload); err == nil {
				out = append(out, h.Type)
			}
		} else {
			out = append(out, f.Type)
		}
		b = b[n:]
	}
	return out
}

// TestEstablishResponseTailE2E (R1-1, R1-8): a packet OPEN held longer than
// PacketPing gets its verdict with the carrier's first PING packed behind
// it in the same datagram; the dialer walks that tail before its first
// read and answers the PING at once, so the passive's carrier has an RTT
// sample within one round trip, without a PING retry.
func TestEstablishResponseTailE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a")
		l := e.links[0]
		l.SetDelay(rendrtest.Up, 10*time.Millisecond, 0)
		l.SetDelay(rendrtest.Down, 10*time.Millisecond, 0)
		ch := peDial(e.peer(peDatagramCarrier(l, 1400)), DialOptions{})
		pp, err := e.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second) // held past PacketPing: a PING is due at the verdict
		capt := l.CaptureNext(rendrtest.Down, rendrtest.FrameOpenAck)
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		resp := <-capt
		types := peFrames(t, resp)
		hasPing := false
		for _, ty := range types {
			hasPing = hasPing || ty == wire.TypePing
		}
		if !hasPing {
			t.Fatalf("stimulus: the response datagram carries %v, no PING behind the OPEN_ACK", types)
		}
		time.Sleep(60 * time.Millisecond) // one round trip and a little
		if cs := pc.Status().Carriers[0]; cs.SRTT == 0 || cs.Retransmits != 0 {
			t.Fatalf("the tail's PING was not answered at once: passive carrier %+v", cs)
		}
		peEnd(t, r.c, pc)
		e.close()
	})
}

// TestEmbedderClosedConnIsDeathE2E_L01: the session-level half of
// TestEmbedderClosedConnIsDeath_L01. The embedder closes the conn its
// factory returned while the session runs: that carrier dies at once with
// transport_error, the session fails over once and the application sees
// nothing; rendr's own later Close of that conn is harmless.
func TestEmbedderClosedConnIsDeathE2E_L01(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		lc := &lastPC{}
		dc, pc := peOpen(t, h.peer(h.carrier("h0", 0, lc)), h.ln, DialOptions{})
		victim := lc.last()
		victim.PacketConn.Close() // the embedder's own Close, behind rendr's back
		peWait(t, 100*time.Millisecond, "the carrier's death", func() bool {
			for _, cs := range dc.Status().Carriers {
				if cs.State == CarrierDead {
					return cs.DeathCause == CauseTransportError
				}
			}
			return false
		})
		peWait(t, 5*time.Second, "the failover", func() bool { return len(peLive(dc)) == 1 && dc.Status().Rejoins == 1 })
		peSend(t, dc, 17, 0, 20, 300)
		if v := peRecv(t, pc, 17, 20, time.Second); v.Result().Unique != 20 {
			t.Fatalf("after the failover: %+v", v.Result())
		}
		if st := dc.Status(); st.Err != nil || st.Migrations.Death != 1 {
			t.Fatalf("the session after one embedder close: err %v, migrations %+v", st.Err, st.Migrations)
		}
		peEnd(t, dc, pc)
		if victim.closes.Load() != 1 {
			t.Fatalf("rendr closed the dead conn %d times, want once", victim.closes.Load())
		}
		h.close()
	})
}

// TestDatagramProbesE2E: a Peer with two datagram factories probes both
// paths with datagram probe carriers (H1p/H2p, sessionless on the
// passive) from its first Dial on; the packet session keeps carriers of
// its own — a probe carrier is never adopted — and the probes go on
// beside it.
func TestDatagramProbesE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a", "b")
		p := e.peer(peDatagramCarrier(e.links[0], 1400), peDatagramCarrier(e.links[1], 1400))
		dc, pc := peOpen(t, p, e.ln, DialOptions{}) // the first Dial starts probing
		time.Sleep(3 * time.Second)
		if n := e.p.Status().Sessionless; n != 2 {
			t.Fatalf("the passive holds %d sessionless carriers, want 2 probe carriers", n)
		}
		for _, l := range e.links {
			if st := l.Stats(); st.Probe.Sent == 0 {
				t.Fatalf("link %s: no probe datagrams: %+v", l.Name(), st)
			}
		}
		if n := len(dc.Status().Carriers); n != 1 {
			t.Fatalf("the session has %d carriers, want 1 (a probe carrier is never adopted)", n)
		}
		probe0 := e.links[0].Stats().Probe.Sent + e.links[1].Stats().Probe.Sent
		time.Sleep(3 * time.Second)
		if e.links[0].Stats().Probe.Sent+e.links[1].Stats().Probe.Sent == probe0 {
			t.Fatal("the probes stopped once a session opened")
		}
		if s := e.links[0].Stats().Session.Sent + e.links[1].Stats().Session.Sent; s == 0 {
			t.Fatal("the session took no carrier of its own")
		}
		peEnd(t, dc, pc)
		e.close()
	})
}

// TestPacketSchedOverRelE2E_L45: a packet selector's SCHED travels in REL
// on datagram lanes: after a death migration its first copy is dropped on
// the link, the REL sublayer resends it (the dialer carrier's Retransmits
// rise), the passive applies and echoes it, and the epochs converge within
// a second.
func TestPacketSchedOverRelE2E_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := peNew(t, Config{}, Config{}, nil, 0, "a", "b")
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400), peDatagramCarrier(e.links[1], 1400)), e.ln, DialOptions{})
		time.Sleep(3 * time.Second)
		lost0 := e.links[1].Stats().All.Lost
		e.links[1].DropNext(rendrtest.Up, rendrtest.FrameSched, 1)
		e.links[0].Kill()
		peWait(t, 3*time.Second, "the migration to b", func() bool {
			for _, cs := range peLive(dc) {
				if cs.Name == "b" && cs.State == CarrierActive {
					return true
				}
			}
			return false
		})
		start := time.Now()
		peWait(t, time.Second, "SCHED converged", func() bool {
			st := dc.Status()
			return st.SchedEchoed == st.SchedEpoch && pc.Status().SchedEpoch == st.SchedEpoch
		})
		if e.links[1].Stats().All.Lost == lost0 {
			t.Fatal("stimulus: the SCHED was not dropped")
		}
		var retx uint64
		for _, cs := range peLive(dc) {
			retx += cs.Retransmits
		}
		if retx == 0 {
			t.Fatal("the dropped SCHED was not resent by REL")
		}
		t.Logf("converged %v after the migration; epoch %d", time.Since(start), dc.Status().SchedEpoch)
		peEnd(t, dc, pc)
		e.close()
	})
}

// TestPacketPassiveQueueFromConfigE2E_L40 (the WP8 review's surviving
// mutant: Params.Packet follows Config.Packet on the passive): a passive
// whose Packet.Queue is 64 KiB and whose application does not read keeps
// at most 64 KiB of datagrams and counts the rest DropRecvQueue; the
// dialer's WriteTo never blocks.
func TestPacketPassiveQueueFromConfigE2E_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pcfg := Config{}
		pcfg.Packet.Queue = 64 << 10
		e := peNew(t, Config{}, pcfg, nil, 0, "a")
		dc, pc := peOpen(t, e.peer(peDatagramCarrier(e.links[0], 1400)), e.ln, DialOptions{})
		buf := make([]byte, 1000)
		for i := range 300 {
			start := time.Now()
			if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, 18, uint64(i), 1000, start), nil); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > 0 {
				t.Fatalf("WriteTo blocked for %v", d)
			}
			if i%10 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		time.Sleep(time.Second)
		st := pc.Status().Packet
		if st.Received != 300 || st.DropRecvQueue == 0 {
			t.Fatalf("passive %+v, want 300 received and receive-queue drops", *st)
		}
		v := peRecv(t, pc, 18, 300, 100*time.Millisecond)
		got := v.Result().Unique
		if got+st.DropRecvQueue != 300 || got > 65 {
			t.Fatalf("read %d after the stall, DropRecvQueue %d: want at most 64 KiB (65 datagrams) kept", got, st.DropRecvQueue)
		}
		peEnd(t, dc, pc)
		e.close()
	})
}
