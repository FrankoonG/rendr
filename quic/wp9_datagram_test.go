package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// TestDatagramLimitProbe_L37 pins the upstream behaviour the attach-time
// budget probe relies on (A12 risk 14): quic-go refuses an oversize
// DATAGRAM before queueing it and reports its current limit — 1163 at the
// 1200-byte packet floor, at least DatagramBudget — and refuses every
// DATAGRAM when the peer did not enable them.
func TestDatagramLimitProbe_L37(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	noPMTUD := func(server bool) *qgo.Config {
		return quicConfig(&qgo.Config{DisablePathMTUDiscovery: true}, 0, server, true)
	}
	cli, srv := rawPair(t, noPMTUD(false), noPMTUD(true))
	for name, qc := range map[string]*qgo.Conn{"dialer": cli, "passive": srv} {
		n, err := datagramLimit(qc)
		if err != nil || n != 1200-37 || n < DatagramBudget {
			t.Errorf("%s: limit %d, %v; want quic-go's 1163 at the 1200-byte floor", name, n, err)
		}
	}
	err := cli.SendDatagram(oversize[:])
	if tl := (*qgo.DatagramTooLargeError)(nil); !errors.As(err, &tl) || errors.Is(err, &qgo.DatagramTooLargeError{}) {
		t.Errorf("oversize: %v (errors.As must find it; its Is compares the limit)", err)
	}
	if err := cli.SendDatagram([]byte("marker")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if b, err := srv.ReceiveDatagram(ctx); err != nil || string(b) != "marker" {
		t.Errorf("first datagram %q, %v: a refused oversize datagram was queued", b, err)
	}

	_, srv2 := rawPair(t, quicConfig(nil, 0, false, false), nil) // a stream dialer: no DATAGRAM support
	if n, err := datagramLimit(srv2); err == nil {
		t.Errorf("a peer without DATAGRAM support: limit %d", n)
	}
}

// TestQUICDatagramBudget_L37: 1152-byte datagrams travel both ways; a
// larger WriteTo is refused with rendr's DatagramTooLargeError (the carrier
// lives); a connection whose limit is below the budget is refused at
// attach on both ends.
func TestQUICDatagramBudget_L37(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("both ways", func(t *testing.T) {
		cli, srv, _ := dgramPair(t, Options{}, Options{})
		full := bytes.Repeat([]byte{0xa5}, DatagramBudget)
		buf := make([]byte, DatagramBudget+1)
		for _, dir := range []struct{ w, r *dgramConn }{{cli, srv}, {srv, cli}} {
			if n, err := dir.w.WriteTo(full, nil); n != DatagramBudget || err != nil {
				t.Fatalf("WriteTo(1152): %d, %v", n, err)
			}
			if n, _, err := dir.r.ReadFrom(buf); n != DatagramBudget || err != nil || !bytes.Equal(buf[:n], full) {
				t.Fatalf("ReadFrom: %d, %v", n, err)
			}
		}
		n, err := cli.WriteTo(oversize[:], nil)
		var tl *rendr.DatagramTooLargeError
		if n != 0 || !errors.As(err, &tl) || tl.Max < DatagramBudget || !errors.Is(err, rendr.ErrDatagramTooLarge) {
			t.Fatalf("WriteTo(16384): %d, %v; want a rendr.DatagramTooLargeError with Max >= 1152", n, err)
		}
		if _, err := cli.WriteTo([]byte("after"), nil); err != nil {
			t.Fatal(err)
		}
		if n, _, err := srv.ReadFrom(buf); err != nil || string(buf[:n]) != "after" {
			t.Fatalf("after the refusal: %q, %v", buf[:n], err)
		}
	})
	t.Run("below the budget", func(t *testing.T) {
		probeLimit = func(*qgo.Conn) (int, error) { return DatagramBudget - 1, nil }
		t.Cleanup(func() { probeLimit = datagramLimit })
		l, f := serveFake(t, Options{})
		dc, err := DatagramCarrier("q", l.Addr().String(), clientOptions(t))
		if err != nil {
			t.Fatal(err)
		}
		if pc, _, err := dc.Dial(dialCtx(t)); err == nil {
			pc.Close()
			t.Fatal("the dialer attached a carrier below the budget")
		}
		qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
		if err != nil {
			t.Fatal(err)
		}
		defer qc.CloseWithError(0, "")
		if err := qc.SendDatagram([]byte("first")); err != nil {
			t.Fatal(err)
		}
		if code, remote := closeCode(t, qc); code != codeBudget || !remote {
			t.Errorf("closed with %d (remote %v), want codeBudget", code, remote)
		}
		if s := l.Stats(); s.BudgetRefused != 1 || s.Datagrams != 0 || len(f.packets) != 0 {
			t.Errorf("stats %+v", s)
		}
	})
}

// queued is the number of datagrams in d's ingress queue.
func queued(d *dgramConn) int {
	d.in.mu.Lock()
	defer d.in.mu.Unlock()
	return d.in.n
}

// seqDatagram is datagram i: its sequence number and a body derived from it.
func seqDatagram(i, size int) []byte {
	b := make([]byte, size)
	binary.BigEndian.PutUint32(b, uint32(i))
	for j := 4; j < size; j++ {
		b[j] = byte(i*7 + j)
	}
	return b
}

// sendGated writes count datagrams in groups of 16 and waits after each
// group until the passive's pump took them all over (queued or dropped):
// quic-go's silent 128-entry queue never overflows, so every loss is the
// ingress queue's own, counted.
func sendGated(t *testing.T, cli, srv *dgramConn, ctr *Counters, count, size int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if _, err := cli.WriteTo(seqDatagram(i, size), nil); err != nil {
			t.Fatal(err)
		}
		if i%16 == 15 || i == count-1 {
			eventually(t, "the pump took the group over", func() bool {
				return queued(srv)+int(ctr.IngressDrops.Load()) == i+1
			})
		}
	}
}

// TestQUICDatagramPump_L46: with the consumer paused, the pump keeps
// draining quic-go's 128-entry queue into the ingress queue — 512
// datagrams arrive in order — and the byte bound drops exactly the
// overflow, counted (Options.Counters and ListenerStats.DatagramDrops).
func TestQUICDatagramPump_L46(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	for _, tc := range []struct {
		name  string
		bytes int
		want  int
	}{
		{"512 in order", 0, 512},
		{"byte bound", 64 << 10, (64 << 10) / 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctr := &Counters{}
			cli, srv, l := dgramPair(t, Options{DatagramQueueBytes: tc.bytes, Counters: ctr}, Options{})
			sendGated(t, cli, srv, ctr, 512, 1000)
			buf := make([]byte, DatagramBudget+1)
			for i := 0; i < tc.want; i++ {
				n, _, err := srv.ReadFrom(buf)
				if err != nil || !bytes.Equal(buf[:n], seqDatagram(i, 1000)) {
					t.Fatalf("datagram %d: %d bytes, seq %d, %v", i, n, binary.BigEndian.Uint32(buf), err)
				}
			}
			if q, drops := queued(srv), ctr.IngressDrops.Load(); q != 0 || drops != uint64(512-tc.want) || l.Stats().DatagramDrops != drops {
				t.Errorf("left %d, drops %d (listener %d), want 0 and %d", q, drops, l.Stats().DatagramDrops, 512-tc.want)
			}
		})
	}
}

// TestQUICDatagramWriteCopies_L46: WriteTo copies, so a caller reusing its
// buffer at once never changes what is sent; and datagrams waiting in the
// ingress queue are never changed by later arrivals (the queue owns
// quic-go's fresh slices; ReadFrom copies into the caller's buffer).
func TestQUICDatagramWriteCopies_L46(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	ctr := &Counters{}
	cli, srv, _ := dgramPair(t, Options{Counters: ctr}, Options{})
	reused := make([]byte, 600)
	for i := 0; i < 200; i++ {
		copy(reused, seqDatagram(i, 600))
		if _, err := cli.WriteTo(reused, nil); err != nil {
			t.Fatal(err)
		}
		for j := range reused {
			reused[j] = 0xff // overwritten while the datagram may still be queued
		}
		if i%16 == 15 || i == 199 {
			eventually(t, "the pump took the group over", func() bool { return queued(srv)+int(ctr.IngressDrops.Load()) == i+1 })
		}
	}
	retained := make([]byte, 601)
	n, _, err := srv.ReadFrom(retained)
	if err != nil || !bytes.Equal(retained[:n], seqDatagram(0, 600)) {
		t.Fatalf("datagram 0: %v", err)
	}
	buf := make([]byte, 601)
	for i := 1; i < 200; i++ {
		if n, _, err := srv.ReadFrom(buf); err != nil || !bytes.Equal(buf[:n], seqDatagram(i, 600)) {
			t.Fatalf("datagram %d changed while queued: seq %d, %v", i, binary.BigEndian.Uint32(buf), err)
		}
	}
	if !bytes.Equal(retained[:n], seqDatagram(0, 600)) || ctr.IngressDrops.Load() != 0 {
		t.Errorf("the retained datagram changed, or drops %d", ctr.IngressDrops.Load())
	}
}

// rateRelay forwards UDP datagrams between one QUIC client and a server:
// server to client freely, client to server at most perSec once limited
// (a path that drains about that many packets per second).
type rateRelay struct {
	pc      *net.UDPConn
	server  netip.AddrPort
	perSec  float64
	limited atomic.Bool
	done    chan struct{}
}

func newRateRelay(t *testing.T, server net.Addr, perSec float64) *rateRelay {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &rateRelay{pc: pc, server: server.(*net.UDPAddr).AddrPort(), perSec: perSec, done: make(chan struct{})}
	go r.run()
	t.Cleanup(func() { _ = pc.Close(); <-r.done })
	return r
}

func (r *rateRelay) run() {
	defer close(r.done)
	buf := make([]byte, 2048)
	var client netip.AddrPort
	tokens, last := 1.0, time.Now()
	for {
		n, from, err := r.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if from == r.server {
			_, _ = r.pc.WriteToUDPAddrPort(buf[:n], client)
			continue
		}
		client = from
		if r.limited.Load() {
			now := time.Now()
			tokens = min(tokens+now.Sub(last).Seconds()*r.perSec, 2)
			last = now
			if tokens < 1 {
				continue // dropped by the narrow path
			}
			tokens--
		}
		_, _ = r.pc.WriteToUDPAddrPort(buf[:n], r.server)
	}
}

// relayPair dials a datagram carrier through a rateRelay to a served
// Listener and returns both adapters once the passive has the carrier.
func relayPair(t *testing.T, perSec float64, ctr *Counters) (cli, srv *dgramConn, relay *rateRelay) {
	t.Helper()
	l, f := serveFake(t, Options{})
	relay = newRateRelay(t, l.Addr(), perSec)
	dc, err := DatagramCarrier("q", relay.pc.LocalAddr().String(), Options{TLS: clientOptions(t).TLS, Counters: ctr})
	if err != nil {
		t.Fatal(err)
	}
	pc, _, err := dc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	cli = pc.(*dgramConn)
	t.Cleanup(func() { _ = cli.Close() })
	if _, err := cli.WriteTo([]byte("classify"), nil); err != nil {
		t.Fatal(err)
	}
	srv = f.packet(t)
	t.Cleanup(func() { _ = srv.Close() })
	if _, _, err := srv.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	return cli, srv, relay
}

// TestQUICDatagramEgressNeverBlocks (R1-9): over a path that carries
// about 20 packets per second, 1 kpps offered for 10 s — QUIC's congestion
// control sends far less and SendDatagram blocks — yet WriteTo never
// waits: the egress queue drops (counted) instead, the connection stays
// alive, and an error met by a queued datagram is returned by the next
// WriteTo. A datagram that waited longer than 250 ms is dropped, not sent.
func TestQUICDatagramEgressNeverBlocks(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("never blocks", func(t *testing.T) {
		ctr := &Counters{}
		cli, srv, relay := relayPair(t, 20, ctr)
		relay.limited.Store(true)
		p := make([]byte, 1000)
		var calls, slow int
		var longest time.Duration
		tick := time.NewTicker(10 * time.Millisecond)
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); <-tick.C {
			for range 10 {
				start := time.Now()
				n, err := cli.WriteTo(p, nil)
				d := time.Since(start)
				if n != len(p) || err != nil {
					t.Fatalf("WriteTo %d: %d, %v", calls, n, err)
				}
				calls++
				longest = max(longest, d)
				if d >= time.Millisecond {
					slow++
				}
			}
		}
		tick.Stop()
		t.Logf("%d WriteTo calls, %d took >= 1 ms, longest %v; egress drops %d", calls, slow, longest, ctr.EgressDrops.Load())
		if slow > calls/100 || longest > 100*time.Millisecond {
			t.Errorf("WriteTo waited: %d of %d calls >= 1 ms, longest %v", slow, calls, longest)
		}
		if ctr.EgressDrops.Load() == 0 {
			t.Error("no egress drops although the path carries 2% of the offered rate")
		}
		if err := context.Cause(cli.qc.Context()); err != nil {
			t.Fatalf("the connection died: %v", err)
		}
		relay.limited.Store(false)
		_ = srv.qc.CloseWithError(9, "bye")
		var werr error
		eventually(t, "WriteTo returns the connection's error", func() bool {
			_, werr = cli.WriteTo([]byte("x"), nil)
			return werr != nil
		})
		if ae := (*qgo.ApplicationError)(nil); !errors.As(werr, &ae) || ae.ErrorCode != 9 || !ae.Remote {
			t.Errorf("WriteTo after the peer's close: %v", werr)
		}
	})
	t.Run("stale datagrams dropped", func(t *testing.T) {
		ctr := &Counters{}
		cli, srv, relay := relayPair(t, 0, ctr)
		var stale, fresh atomic.Int64
		read := make(chan struct{})
		go func() { // the passive counts what arrives, by sequence range
			defer close(read)
			buf := make([]byte, DatagramBudget+1)
			for {
				n, _, err := srv.ReadFrom(buf)
				if err != nil {
					return
				}
				switch seq := binary.BigEndian.Uint32(buf[:n]); {
				case seq >= 1000:
					fresh.Add(1)
				case seq >= 100:
					stale.Add(1)
				}
			}
		}()
		relay.limited.Store(true) // a black hole: no ACK returns, the sender blocks in SendDatagram
		for i := range 100 {
			_, _ = cli.WriteTo(seqDatagram(i, 1000), nil)
		}
		eventually(t, "the sender is blocked", func() bool { cli.out.mu.Lock(); defer cli.out.mu.Unlock(); return cli.out.n > 0 })
		for i := 100; i < 400; i++ {
			if _, err := cli.WriteTo(seqDatagram(i, 1000), nil); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(300 * time.Millisecond) // every queued datagram is older than 250 ms now
		relay.limited.Store(false)
		eventually(t, "the sender drained the queue", func() bool { cli.out.mu.Lock(); defer cli.out.mu.Unlock(); return cli.out.n == 0 })
		for i := 1000; i < 1010; i++ {
			_, _ = cli.WriteTo(seqDatagram(i, 1000), nil)
		}
		eventually(t, "fresh datagrams arrive", func() bool { return fresh.Load() > 0 })
		_ = srv.Close()
		<-read
		t.Logf("%d of the 300 stale datagrams arrived, %d fresh; egress drops %d", stale.Load(), fresh.Load(), ctr.EgressDrops.Load())
		if stale.Load() > 64 || ctr.EgressDrops.Load() < 200 {
			t.Errorf("%d datagrams older than 250 ms were sent (egress drops %d)", stale.Load(), ctr.EgressDrops.Load())
		}
	})
}

// TestQUICErrorsAreDeath_L01 (adapter half): every QUIC error reaches the
// core as the conn's error, detailed by the connection's close cause —
// the peer's application close, QUIC's own idle timeout (an explicit
// short IdleTimeout) and a dial whose handshake times out. Timeouts of a
// dead connection are never deadline errors (closedError).
func TestQUICErrorsAreDeath_L01(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("application close", func(t *testing.T) {
		cli, srv, _ := dgramPair(t, Options{}, Options{})
		_ = srv.qc.CloseWithError(7, "bye")
		_, _, err := cli.ReadFrom(make([]byte, 64))
		if ae := (*qgo.ApplicationError)(nil); !errors.As(err, &ae) || ae.ErrorCode != 7 || !ae.Remote ||
			err.Error() != context.Cause(cli.qc.Context()).Error() {
			t.Errorf("ReadFrom after the peer's close: %v (cause %v)", err, context.Cause(cli.qc.Context()))
		}
		sc, ss, _ := streamPair(t, Options{}, Options{})
		_ = ss.(*streamConn).qc.CloseWithError(7, "bye")
		if _, err := sc.Read(make([]byte, 8)); !errors.As(err, new(*qgo.ApplicationError)) {
			t.Errorf("stream Read after the peer's close: %v", err)
		}
	})
	t.Run("idle timeout", func(t *testing.T) {
		start := time.Now()
		cli, _, _ := dgramPair(t, Options{}, Options{IdleTimeout: 300 * time.Millisecond})
		_, _, err := cli.ReadFrom(make([]byte, 64))
		var ne net.Error
		if !errors.As(err, new(*qgo.IdleTimeoutError)) || !errors.Is(err, net.ErrClosed) || !errors.As(err, &ne) || ne.Timeout() {
			t.Errorf("ReadFrom at QUIC's idle timeout: %v (a deadline error to the core: %v)", err, ne != nil && ne.Timeout())
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("idle timeout after %v", d)
		}
		sc, _, _ := streamPair(t, Options{}, Options{IdleTimeout: 300 * time.Millisecond})
		if _, err := sc.Read(make([]byte, 8)); !errors.As(err, new(*qgo.IdleTimeoutError)) || !errors.As(err, &ne) || ne.Timeout() {
			t.Errorf("stream Read at QUIC's idle timeout: %v", err)
		}
	})
	t.Run("handshake timeout on dial", func(t *testing.T) {
		silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer silent.Close()
		o := clientOptions(t)
		o.Config = &qgo.Config{HandshakeIdleTimeout: 200 * time.Millisecond}
		dc, err := DatagramCarrier("q", silent.LocalAddr().String(), o)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, _, err = dc.Dial(context.Background())
		if !errors.As(err, new(*qgo.IdleTimeoutError)) && !errors.As(err, new(*qgo.HandshakeTimeoutError)) {
			t.Errorf("dial to a silent peer: %v", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("dial returned after %v", d)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, _, err := dc.Dial(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("dial bounded by its context: %v", err)
		}
	})
}
