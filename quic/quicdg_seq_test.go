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

// framed is the DATAGRAM payload a carrier sends as its datagram number
// seq: the 4-byte big-endian sequence number, then the datagram.
func framed(seq uint32, datagram string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, seq), datagram...)
}

// TestQUICDatagramPumpStallRefusedTakesNoSeq (KL-19): a datagram quic-go
// refused as too large is counted in the sender's EgressDrops and takes no
// sequence number, so the receiver's gap count stays exactly quic-go's
// receive-queue overflow and nothing is counted twice. Stimulus: the
// receiver's pump is held, the sender writes 200 datagrams, then one of
// 1600 bytes above quic-go's limit (the sender's limit raised past it),
// the next WriteTo reports the refusal with quic-go's limit less the
// sequence number, the pump is
// released and one more datagram follows. Integrity: delivered +
// IngressDrops + EgressDrops == written, IngressDrops quic-go's overflow
// (71 or 72).
func TestQUICDatagramPumpStallRefusedTakesNoSeq(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	w, r, ft, wc, rc := stallPair(t, true)
	parked, release := holdPump(t, r)
	const burst = 200
	writeTraced(t, w, ft, 0, burst)
	kept := pinnedRcvQueue + parked()
	w.max.Store(2000) // past any quic-go limit (at most 1500-byte packets): the sender's SendDatagram refuses it
	if _, err := w.WriteTo(make([]byte, 1600), nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "quic-go refused the oversize datagram", func() bool { return wc.EgressDrops.Load() == 1 })
	var tl *rendr.DatagramTooLargeError
	if _, err := w.WriteTo(seqDatagram(burst, 1000), nil); !errors.As(err, &tl) || tl.Max < DatagramBudget || tl.Max >= 1600 || int64(tl.Max) != w.max.Load() {
		t.Fatalf("the next WriteTo returned %v (limit now %d), want the refusal with quic-go's limit less the sequence number", err, w.max.Load())
	}
	release()
	eventually(t, "the pump drained quic-go's queue", func() bool { return queued(r) == kept })
	if _, err := w.WriteTo(seqDatagram(burst, 1000), nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the trailing datagram arrived", func() bool { return queued(r) == kept+1 })
	seqs := readSeqs(t, r, kept+1)
	if seqs[kept-1] != kept-1 || seqs[kept] != burst {
		t.Fatalf("delivered %v", seqs)
	}
	written := uint64(burst + 2) // the burst, the refused one, the trailing one
	in, eg := rc.IngressDrops.Load(), wc.EgressDrops.Load()
	if in != uint64(burst-kept) || eg != 1 || uint64(len(seqs))+in+eg != written {
		t.Errorf("IngressDrops %d, EgressDrops %d, delivered %d of %d: want %d and 1", in, eg, len(seqs), written, burst-kept)
	}
}

// dropRelay forwards UDP datagrams between one QUIC client and a server
// and, once armed, drops the client's next packet of at least 1000 bytes
// (one carrying a 1000-byte DATAGRAM): a loss in the network.
type dropRelay struct {
	pc      *net.UDPConn
	server  netip.AddrPort
	arm     atomic.Bool
	dropped atomic.Int64
	done    chan struct{}
}

func newDropRelay(t *testing.T, server net.Addr) *dropRelay {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &dropRelay{pc: pc, server: server.(*net.UDPAddr).AddrPort(), done: make(chan struct{})}
	go r.run()
	t.Cleanup(func() { _ = pc.Close(); <-r.done })
	return r
}

func (r *dropRelay) run() {
	defer close(r.done)
	buf := make([]byte, 2048)
	var client netip.AddrPort
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
		if n >= 1000 && r.arm.CompareAndSwap(true, false) {
			r.dropped.Add(1)
			continue
		}
		_, _ = r.pc.WriteToUDPAddrPort(buf[:n], r.server)
	}
}

// TestQUICDatagramNetworkLossNotClaimed (KL-19): a gap the network made
// while the pump kept up is no quic-go drop and is not counted in
// IngressDrops. Stimulus: 200 datagrams, each read before the next is
// written (the pump finds quic-go's queue empty between them, after more
// than 128 in all), then one dropped by the path, then one more. Load and
// integrity: the 201 that crossed are delivered intact and in order,
// IngressDrops and EgressDrops stay 0 - the one loss is a transport loss
// no counter claims.
func TestQUICDatagramNetworkLossNotClaimed(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	rc, wc := &Counters{}, &Counters{}
	l, f := serveFake(t, Options{Counters: rc})
	relay := newDropRelay(t, l.Addr())
	dc, err := DatagramCarrier("q", relay.pc.LocalAddr().String(), Options{TLS: clientOptions(t).TLS, Counters: wc})
	if err != nil {
		t.Fatal(err)
	}
	pc, _, err := dc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	w := pc.(*dgramConn)
	t.Cleanup(func() { _ = w.Close() })
	if _, err := w.WriteTo([]byte("classify"), nil); err != nil {
		t.Fatal(err)
	}
	r := f.packet(t)
	t.Cleanup(func() { _ = r.Close() })
	_ = r.SetReadDeadline(time.Now().Add(4 * testEventuallyTime))
	if _, _, err := r.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	var got []int
	for i := range 200 {
		if _, err := w.WriteTo(seqDatagram(i, 1000), nil); err != nil {
			t.Fatal(err)
		}
		got = append(got, readSeqs(t, r, 1)...)
	}
	relay.arm.Store(true)
	if _, err := w.WriteTo(seqDatagram(200, 1000), nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the path dropped datagram 200", func() bool { return relay.dropped.Load() == 1 })
	if _, err := w.WriteTo(seqDatagram(201, 1000), nil); err != nil {
		t.Fatal(err)
	}
	got = append(got, readSeqs(t, r, 1)...)
	for k, s := range got {
		if want := map[bool]int{true: k, false: 201}[k < 200]; s != want {
			t.Fatalf("delivered datagram %d is seq %d, want %d", k, s, want)
		}
	}
	if in, eg := rc.IngressDrops.Load(), wc.EgressDrops.Load(); in != 0 || eg != 0 {
		t.Errorf("IngressDrops %d, EgressDrops %d: a network loss while the pump kept up was claimed", in, eg)
	}
}

// TestQUICRxSeqAttribution (KL-19): rxSeq counts a gap only when quic-go's
// queue may have overflowed - at least 128 datagrams taken since the pump
// last found it empty, or the first datagram after such a run - and in
// uint32 serial arithmetic; a reordered datagram counts nothing.
func TestQUICRxSeqAttribution(t *testing.T) {
	const e = -1 // the pump found quic-go's queue empty
	run := func(from, n int) []int {
		var s []int
		for i := range n {
			s = append(s, from+i)
		}
		return s
	}
	cat := func(parts ...[]int) []int {
		var s []int
		for _, p := range parts {
			s = append(s, p...)
		}
		return s
	}
	for _, c := range []struct {
		name   string
		next   uint32
		events []int
		want   uint64
	}{
		{"in order", 0, []int{e, 0, 1, e, 2, 3}, 0},
		{"first datagram lost on a short run", 0, []int{e, 3}, 0},
		{"network gap on a short run", 0, []int{e, 0, 1, e, 5}, 0},
		{"gap after 127 since empty", 0, cat([]int{e}, run(0, 127), []int{200}), 0},
		{"gap after 128 since empty", 0, cat([]int{e}, run(0, 128), []int{200}), 72},
		{"gap after the run and an empty queue", 0, cat([]int{e}, run(0, 128), []int{e, 200}), 72},
		{"lag ends with the next datagram", 0, cat([]int{e}, run(0, 128), []int{e, 128, e, 300}), 0},
		{"gaps all through a long run", 0, cat([]int{e}, run(0, 128), []int{130, 140}), 11},
		{"reordered inside a lag", 0, cat([]int{e}, run(0, 128), []int{130, 129, 131}), 2},
		{"serial wrap", 0xffffff00, cat([]int{e}, run(0xffffff00-(1<<32), 128), []int{5}), 133},
	} {
		s := rxSeq{next: c.next}
		var got uint64
		for _, ev := range c.events {
			if ev == e {
				s.empty()
				continue
			}
			got += s.take(uint32(int64(ev)))
		}
		if got != c.want {
			t.Errorf("%s: counted %d, want %d", c.name, got, c.want)
		}
	}
}

// TestQUICDatagramSeqWire_L37 pins the DATAGRAM payload (golden vectors):
// a dialer carrier sends each datagram after its 4-byte big-endian number
// counted from 0 - the full budget included - and a passive carrier
// delivers what follows a peer's number; a DATAGRAM shorter than the
// number ends the connection with codeMalformed after the datagrams before
// it; a short first DATAGRAM ends it with codeMalformed before any carrier
// is handed to rendr (counted in ListenerStats.BadKind).
func TestQUICDatagramSeqWire_L37(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("dialer sends", func(t *testing.T) {
		srvTLS, _ := testTLS(t)
		srvTLS.NextProtos = []string{ALPN}
		str := rawTransport(t)
		ln, err := str.Listen(srvTLS, quicConfig(nil, 0, true, true))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		dc, err := DatagramCarrier("q", str.Conn.LocalAddr().String(), clientOptions(t))
		if err != nil {
			t.Fatal(err)
		}
		pc, _, err := dc.Dial(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		srv, err := ln.Accept(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = srv.CloseWithError(0, "") })
		full := bytes.Repeat([]byte{0x5a}, DatagramBudget)
		for _, want := range [][]byte{
			{0, 0, 0, 0, 'a', 'b'},
			{0, 0, 0, 1},
			append([]byte{0, 0, 0, 2}, full...),
		} {
			if _, err := pc.WriteTo(want[seqLen:], nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), testEventuallyTime)
			b, err := srv.ReceiveDatagram(ctx)
			cancel()
			if err != nil || !bytes.Equal(b, want) {
				t.Fatalf("DATAGRAM % x (%d bytes), %v; want % x", b[:min(len(b), 8)], len(b), err, want[:min(len(want), 8)])
			}
		}
	})
	t.Run("passive receives", func(t *testing.T) {
		l, f := serveFake(t, Options{})
		qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
		for _, b := range [][]byte{{0, 0, 0, 7, 'x'}, {0, 0, 0, 8}, {0, 0, 0, 9, 'y', 'z'}, {0, 0, 0}} {
			if err := qc.SendDatagram(b); err != nil {
				t.Fatal(err)
			}
		}
		d := f.packet(t)
		t.Cleanup(func() { _ = d.Close() })
		buf := make([]byte, DatagramBudget+1)
		_ = d.SetReadDeadline(time.Now().Add(testEventuallyTime))
		for _, want := range []string{"x", "", "yz"} {
			if n, _, err := d.ReadFrom(buf); err != nil || string(buf[:n]) != want {
				t.Fatalf("ReadFrom: %q, %v; want %q", buf[:n], err, want)
			}
		}
		if _, _, err := d.ReadFrom(buf); !errors.Is(err, errMalformed) {
			t.Fatalf("after the short DATAGRAM ReadFrom returned %v, want errMalformed", err)
		}
		if code, remote := closeCode(t, qc); code != codeMalformed || !remote {
			t.Errorf("closed with %d (remote %v), want codeMalformed", code, remote)
		}
	})
	t.Run("short first DATAGRAM", func(t *testing.T) {
		l, f := serveFake(t, Options{})
		qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
		if err := qc.SendDatagram([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if code, remote := closeCode(t, qc); code != codeMalformed || !remote {
			t.Errorf("closed with %d (remote %v), want codeMalformed", code, remote)
		}
		// The Listener counts BadKind before it closes the connection.
		if s := l.Stats(); s.BadKind != 1 || s.Datagrams != 0 || len(f.packets) != 0 {
			t.Errorf("a short first DATAGRAM: %+v, %d carriers handed; want BadKind 1 and none handed", s, len(f.packets))
		}
	})
}

// TestQUICDatagramSeqBudget_L37: the attach-time probe needs room for
// DatagramBudget after the sequence number, and the carrier's limit is
// quic-go's limit less the sequence number.
func TestQUICDatagramSeqBudget_L37(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Cleanup(func() { probeLimit = datagramLimit })
	l, _ := serveFake(t, Options{})
	dc, err := DatagramCarrier("q", l.Addr().String(), clientOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	probeLimit = func(*qgo.Conn) (int, error) { return DatagramBudget + seqLen - 1, nil }
	if pc, _, err := dc.Dial(dialCtx(t)); err == nil {
		_ = pc.Close()
		t.Fatalf("a DATAGRAM limit of %d (no room for the sequence number) was accepted", DatagramBudget+seqLen-1)
	}
	probeLimit = func(*qgo.Conn) (int, error) { return DatagramBudget + seqLen, nil }
	pc, _, err := dc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	var tl *rendr.DatagramTooLargeError
	if _, err := pc.WriteTo(make([]byte, DatagramBudget+1), nil); !errors.As(err, &tl) || tl.Max != DatagramBudget {
		t.Fatalf("WriteTo(%d): %v; want a DatagramTooLargeError with Max %d", DatagramBudget+1, err, DatagramBudget)
	}
	if _, err := pc.WriteTo(make([]byte, DatagramBudget), nil); err != nil {
		t.Fatalf("WriteTo(%d): %v", DatagramBudget, err)
	}
}

// TestQUICDatagramAcceptNoAlloc: taking a received DATAGRAM over - the
// sequence check and the move to the ingress queue - and reading it
// allocate nothing in steady state.
func TestQUICDatagramAcceptNoAlloc(t *testing.T) {
	d := &dgramConn{sinks: []*Counters{{}}}
	d.in.ring, d.in.max, d.in.wake = make([][]byte, ingressInit), 1<<20, make(chan struct{}, 1)
	b := framed(0, "payload")
	var seq uint32
	allocs := testing.AllocsPerRun(1000, func() {
		binary.BigEndian.PutUint32(b, seq)
		seq++
		if !d.accept(b) {
			t.Fatal("accept failed")
		}
		if got, err := d.in.pop(); err != nil || string(got) != "payload" {
			t.Fatalf("pop: %q, %v", got, err)
		}
	})
	if allocs != 0 {
		t.Errorf("%v allocations per datagram, want 0", allocs)
	}
}

// TestQUICDatagramAcceptAfterCloseCountsNothing (KL-19): once the
// carrier's ingress queue failed (Close, or the connection ended), the
// DATAGRAMs the pump still drains from quic-go's queue are discarded and
// counted nowhere, and the pump stops - even when rx lags and the next one
// shows a gap. Stimulus: rx after a run of 128 (lag set), the queue
// failed, a DATAGRAM 72 ahead. Integrity: accept reports the end, nothing
// is counted or queued.
func TestQUICDatagramAcceptAfterCloseCountsNothing(t *testing.T) {
	c := &Counters{}
	d := &dgramConn{sinks: []*Counters{c}}
	d.in.ring, d.in.max, d.in.wake = make([][]byte, ingressInit), 1<<20, make(chan struct{}, 1)
	for i := range uint32(quicRcvQueue) {
		if !d.accept(framed(i, "x")) {
			t.Fatal("accept failed")
		}
		_, _ = d.in.pop()
	}
	if !d.rx.lag {
		t.Fatal("rx does not lag after a run of 128")
	}
	d.in.fail(net.ErrClosed, true)
	if d.accept(framed(200, "x")) {
		t.Error("accept after the ingress queue failed did not stop the pump")
	}
	if in, n := c.IngressDrops.Load(), d.in.n; in != 0 || n != 0 {
		t.Errorf("after close: IngressDrops %d, %d queued; want 0 and 0", in, n)
	}
}

// TestQUICOldALPNRefused_KL19: the sequence number changed the DATAGRAM
// encapsulation, so the ALPN changed with it and a peer of the earlier
// encapsulation ("rendr/2") is refused at the TLS handshake in both
// directions — never handed to rendr, never misparsed. Stimulus: a raw
// quic-go client offering only "rendr/2" dials a Listener, and a datagram
// carrier dials a raw server that offers only "rendr/2". Integrity: both
// handshakes fail with a TLS alert (a QUIC crypto error), the Listener
// hands over no carrier and counts none, the raw server accepts nothing.
func TestQUICOldALPNRefused_KL19(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const old = "rendr/2"
	if ALPN == old {
		t.Fatalf("ALPN is still %q", old)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	crypto := func(err error) bool {
		var te *qgo.TransportError
		return errors.As(err, &te) && te.ErrorCode.IsCryptoError()
	}

	l, f := serveFake(t, Options{})
	cli := rawClientTLS(t)
	cli.NextProtos = []string{old}
	if qc, err := rawTransport(t).Dial(ctx, l.Addr(), cli, quicConfig(nil, 0, false, true)); err == nil {
		_ = qc.CloseWithError(0, "")
		t.Fatalf("a %q client completed the handshake", old)
	} else if !crypto(err) {
		t.Errorf("dial with ALPN %q: %v, want a TLS alert", old, err)
	}
	if s := l.Stats(); s.Streams != 0 || s.Datagrams != 0 || len(f.packets) != 0 || len(f.streams) != 0 {
		t.Errorf("a %q client reached rendr: %+v", old, s)
	}

	srvTLS, _ := testTLS(t)
	srvTLS.NextProtos = []string{old}
	str := rawTransport(t)
	ln, err := str.Listen(srvTLS, quicConfig(nil, 0, true, true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	dc, err := DatagramCarrier("q", str.Conn.LocalAddr().String(), clientOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if pc, _, err := dc.Dial(ctx); err == nil {
		_ = pc.Close()
		t.Fatalf("a datagram carrier dialed a %q server", old)
	} else if !crypto(err) {
		t.Errorf("Dial of a %q server: %v, want a TLS alert", old, err)
	}
	actx, acancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer acancel()
	if qc, err := ln.Accept(actx); err == nil {
		_ = qc.CloseWithError(0, "")
		t.Errorf("the %q server accepted a connection", old)
	}
}
