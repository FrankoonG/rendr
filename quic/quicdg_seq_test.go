package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
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
// (one carrying a 1000-byte DATAGRAM): a loss in the network. While block
// is set it drops every client packet: a path that carries nothing.
type dropRelay struct {
	pc      *net.UDPConn
	server  netip.AddrPort
	arm     atomic.Bool
	block   atomic.Bool
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
		if r.block.Load() || n >= 1000 && r.arm.CompareAndSwap(true, false) {
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

// TestQUICDatagramEgressDropTakesNoSeq (KL-19): a datagram the egress
// queue dropped for its age takes no sequence number, so the receiver
// never reads the sender's own drops as gaps (counted twice: EgressDrops
// at the sender, IngressDrops at the receiver during a lag). Stimulus: a
// dialer carrier's path to a raw quic-go server carries nothing while 200
// datagrams of 1000 bytes are written - quic-go takes what its congestion
// window and its 32-frame send queue hold, the rest waits in the egress
// queue until every datagram there is older than egressAge - then the
// path returns, the sender works the egress queue off (quic-go's probes
// make room), and fresh datagrams follow one at a time until five arrived
// (a fresh one that aged out while quic-go recovered is dropped too).
// Integrity: every datagram written took a number or is counted in
// EgressDrops (some are), and every DATAGRAM arrived intact; the numbers
// the server receives after the path returned are consecutive, and the
// last fresh datagram carries the number right after those of every
// DATAGRAM the dialer's quic-go sent before it (traced).
func TestQUICDatagramEgressDropTakesNoSeq(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	srvTLS, _ := testTLS(t)
	srvTLS.NextProtos = []string{ALPN}
	str := rawTransport(t)
	ln, err := str.Listen(srvTLS, quicConfig(nil, 0, true, true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	relay := newDropRelay(t, str.Conn.LocalAddr())
	ft, ctr := &frameTracer{}, &Counters{}
	dc, err := DatagramCarrier("q", relay.pc.LocalAddr().String(),
		Options{TLS: clientOptions(t).TLS, Config: &qgo.Config{Tracer: ft.trace}, Counters: ctr})
	if err != nil {
		t.Fatal(err)
	}
	pc, _, err := dc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	w := pc.(*dgramConn)
	t.Cleanup(func() { _ = w.Close() })
	srv, err := ln.Accept(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}

	// The server records each DATAGRAM's number and its seqDatagram index.
	type rcvd struct {
		num uint32
		idx int
	}
	var mu sync.Mutex
	var got []rcvd
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			b, err := srv.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			r := rcvd{idx: -1} // -1: not an intact seqDatagram after a number
			if len(b) == seqLen+1000 && bytes.Equal(b[seqLen:], seqDatagram(int(binary.BigEndian.Uint32(b[seqLen:])), 1000)) {
				r.num, r.idx = binary.BigEndian.Uint32(b), int(binary.BigEndian.Uint32(b[seqLen:]))
			}
			mu.Lock()
			got = append(got, r)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = srv.CloseWithError(0, ""); <-recvDone })
	received := func() []rcvd {
		mu.Lock()
		defer mu.Unlock()
		return append([]rcvd(nil), got...)
	}

	const burst, fresh = 200, 5
	written := 0
	write := func(i int) {
		t.Helper()
		if _, err := w.WriteTo(seqDatagram(i, 1000), nil); err != nil {
			t.Fatal(err)
		}
		written++
	}
	write(0) // number 0
	eventually(t, "the first datagram arrived", func() bool { return len(received()) == 1 })
	relay.block.Store(true)
	for i := 1; i <= burst; i++ {
		write(i)
	}
	lastWrite := time.Now()
	eventually(t, "every datagram the egress queue holds is older than egressAge", func() bool { return time.Since(lastWrite) > egressAge })
	relay.block.Store(false)
	// No WriteTo until the sender took every queued datagram (a WriteTo
	// would drop the stale ones itself): it hands quic-go a datagram each
	// time a probe makes room and drops the rest for their age.
	eventually(t, "the sender worked the egress queue off", func() bool { _, _, n := egressHeld(w); return n == 0 })
	if ctr.EgressDrops.Load() == 0 {
		t.Fatal("no datagram aged out in the egress queue during the outage")
	}
	freshArrived := func() int {
		r := received()
		n := 0
		for _, x := range r[1:] {
			if x.idx >= 1000 {
				n++
			}
		}
		return n
	}
	idx := 1000
	for deadline := time.Now().Add(4 * testEventuallyTime); freshArrived() < fresh; idx++ {
		if time.Now().After(deadline) {
			t.Fatalf("%d of the fresh datagrams arrived after the path returned", freshArrived())
		}
		write(idx)
		want := idx
		start := time.Now()
		for time.Since(start) < 2*egressAge { // its arrival, or long enough for it to age out
			if r := received(); r[len(r)-1].idx == want {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	final := idx
	write(final) // quic-go recovered: sent at once, after every datagram it holds
	eventually(t, "the last fresh datagram arrived", func() bool { r := received(); return r[len(r)-1].idx == final })

	r := received()
	sent := ft.sentDatagrams.Load()
	drops := ctr.EgressDrops.Load()
	t.Logf("written %d, DATAGRAMs sent %d, EgressDrops %d, received %d (numbers %d … %d after the path returned)",
		written, sent, drops, len(r), r[1].num, r[len(r)-1].num)
	if uint64(sent)+drops != uint64(written) {
		t.Fatalf("EgressDrops %d and %d DATAGRAMs sent of %d written: want every datagram numbered or counted", drops, sent, written)
	}
	for k, x := range r {
		if x.idx < 0 || k == 0 && (x.num != 0 || x.idx != 0) {
			t.Fatalf("DATAGRAM %d received is not intact or not number 0 first: %+v", k, x)
		}
	}
	for k := 2; k < len(r); k++ { // r[1:]: everything after the first arrived after the path returned
		if r[k].num != r[k-1].num+1 {
			t.Fatalf("after the path returned the numbers jump from %d to %d (datagrams %d and %d): a dropped datagram took a number",
				r[k-1].num, r[k].num, r[k-1].idx, r[k].idx)
		}
	}
	if x := r[len(r)-1]; x.num != uint32(sent)-1 {
		t.Errorf("the last fresh datagram has number %d, want %d: the number after the %d DATAGRAMs quic-go sent before it",
			x.num, sent-1, sent-1)
	}
}

// TestQUICRxSeqAttribution (KL-19): rxSeq counts a gap only when quic-go's
// queue may have overflowed - at least 128 datagrams taken since the pump
// last found it empty, or the first datagram after such a run - and in
// uint32 serial arithmetic; a reordered datagram counts nothing, counts
// toward the run (it never starts a lag on a short run) and leaves the lag
// to the datagram that shows the gap, also after the drain. Rows also pin
// the documented inexact counts (Counters.IngressDrops): in order, a
// network loss inside a lag counts too (an upper bound); on a reordering
// path (the limitation rows), a drop whose gap a datagram showed before
// the lag counts nothing, and a late datagram at or above the next
// expected number that arrives after the drain ends the lag, so the drops
// numbered above it count nothing.
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
		// In order, quic-go dropped nothing and the network lost 128: the
		// loss counts like a drop (an upper bound).
		{"network loss inside a lag counts", 0, cat([]int{e}, run(0, 128), []int{e, 129}), 1},
		{"lag ends with the next datagram", 0, cat([]int{e}, run(0, 128), []int{e, 128, e, 300}), 0},
		{"gaps all through a long run", 0, cat([]int{e}, run(0, 128), []int{130, 140}), 11},
		{"reordered inside a lag", 0, cat([]int{e}, run(0, 128), []int{130, 129, 131}), 2},
		{"reordered on a short run", 0, []int{e, 0, 1, 3, 2, 5}, 0},
		{"reordered datagram completes the run", 0, cat([]int{e}, run(0, 126), []int{127, 126, 200}), 72},
		// quic-go kept 0 … 99 and 101 … 128 and dropped 129 … 138; 100,
		// delayed in the network, arrives after the drain.
		{"straggler behind after the drain", 0, cat([]int{e}, run(0, 100), run(101, 28), []int{e, 100, 139}), 10},
		// quic-go dropped 50, which arrived late into the full queue; 51
		// showed its gap at the 51st datagram of the run.
		{"limitation: gap shown before the lag", 0, cat([]int{e}, run(0, 50), run(51, 78), []int{e, 129}), 0},
		// quic-go dropped 129 and 130; 128, delayed, arrives after the
		// drain as the next expected number and ends the lag.
		{"limitation: next expected after the drain", 0, cat([]int{e}, run(0, 128), []int{e, 128, 131}), 0},
		// quic-go dropped 128, 130 and 131; 129, delayed, arrives after
		// the drain above the next expected number: its own gap (128)
		// counts, and it ends the lag, so 130 and 131 count nothing.
		{"limitation: late datagram above next after the drain", 0, cat([]int{e}, run(0, 128), []int{e, 129, 132}), 1},
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

// TestQUICDatagramStragglerAfterStallCounted (KL-19): a datagram the
// network delayed past a stall, arriving after the pump drained quic-go's
// queue, leaves the lag to the next datagram, so the drops whose gap that
// one shows are counted. Stimulus: a raw quic-go client numbers its own
// DATAGRAMs; the passive's pump is held while seqs 1 … 140 except 100
// arrive (quic-go keeps 128 and drops the rest), then released; once it
// found quic-go's queue empty and waits, seq 100 arrives, then seq 141.
// Integrity: quic-go handled every DATAGRAM; the delivered datagrams are
// intact and in order - the head of the burst, 100, 141 - and
// IngressDrops is exactly quic-go's drops.
func TestQUICDatagramStragglerAfterStallCounted(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	ft, rc := &frameTracer{}, &Counters{}
	l, f := serveFake(t, Options{Config: &qgo.Config{Tracer: ft.trace}, Counters: rc})
	qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	numbered := func(seqs ...int) [][]byte { // DATAGRAM seq carries seqDatagram(seq, 1000)
		var ps [][]byte
		for _, s := range seqs {
			ps = append(ps, framed(uint32(s), string(seqDatagram(s, 1000))))
		}
		return ps
	}
	rawSendTraced(t, qc, ft, numbered(0)...)
	r := f.packet(t)
	t.Cleanup(func() { _ = r.Close() })
	if s := readSeqs(t, r, 1); s[0] != 0 {
		t.Fatalf("first datagram seq %d", s[0])
	}

	var burst []int
	for s := 1; s <= 140; s++ {
		if s != 100 {
			burst = append(burst, s)
		}
	}
	parked, release := holdPump(t, r)
	rawSendTraced(t, qc, ft, numbered(burst...)...)
	kept := pinnedRcvQueue + parked() // what the pump took as the hold began, and quic-go's queue
	release()
	eventually(t, "the pump drained quic-go's queue", func() bool { return queued(r) == kept })
	eventually(t, "the pump found quic-go's queue empty and waits", pumpWaits)
	rawSendTraced(t, qc, ft, numbered(100)...)
	eventually(t, "the pump took the straggler", func() bool { return queued(r) == kept+1 })
	rawSendTraced(t, qc, ft, numbered(141)...)
	eventually(t, "the trailing datagram arrived", func() bool { return queued(r) == kept+2 })

	seqs := readSeqs(t, r, kept+2)
	want := append(append([]int(nil), burst[:kept]...), 100, 141)
	for k := range want {
		if seqs[k] != want[k] {
			t.Fatalf("delivered %v: datagram %d is seq %d, want %d", seqs, k, seqs[k], want[k])
		}
	}
	if handled := ft.rcvDatagrams.Load(); handled != int64(len(burst)+3) {
		t.Fatalf("quic-go handled %d DATAGRAMs, %d were sent", handled, len(burst)+3)
	}
	drops := uint64(len(burst) - kept) // seqs burst[kept] … 140
	if in := rc.IngressDrops.Load(); in != drops {
		t.Errorf("IngressDrops %d, quic-go dropped %d (seqs %d … 140): want them counted from 141's gap", in, drops, burst[kept])
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
// allocate nothing in steady state (asserted in the non-race lane, §A10.3).
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
	if !raceEnabled && allocs != 0 {
		t.Errorf("%v allocations per datagram, want 0", allocs)
	}
}

// TestQUICDatagramSendNoAlloc: one step of the send loop - framing a
// datagram after its sequence number, handing it to quic-go (a stub here)
// and classifying the result - allocates nothing, so a sent datagram costs
// rendr no allocation in steady state (quic-go's own copy aside; asserted
// in the non-race lane, §A10.3).
// Integrity: each accepted datagram goes out framed after the next number;
// one refused as too large, or failed otherwise, takes none and is
// reported (the refusal with quic-go's limit).
func TestQUICDatagramSendNoAlloc(t *testing.T) {
	s := &sender{framed: make([]byte, seqLen, seqLen+DatagramBudget)}
	p := seqDatagram(7, 1000)
	last := make([]byte, 0, seqLen+DatagramBudget)
	var refuse error
	send := func(b []byte) error {
		if refuse != nil {
			return refuse
		}
		last = append(last[:0], b...)
		return nil
	}
	allocs := testing.AllocsPerRun(1000, func() {
		if tl, err := s.step(send, p); tl != nil || err != nil {
			t.Fatalf("step: %v, %v", tl, err)
		}
	})
	if !raceEnabled && allocs != 0 {
		t.Errorf("%v allocations per sent datagram, want 0", allocs)
	}
	const steps = 1001 // AllocsPerRun's warm-up run and 1000
	if s.seq != steps || binary.BigEndian.Uint32(last) != steps-1 || !bytes.Equal(last[seqLen:], p) {
		t.Fatalf("after %d steps: next number %d, last DATAGRAM number %d (payload intact %v)",
			steps, s.seq, binary.BigEndian.Uint32(last), bytes.Equal(last[seqLen:], p))
	}
	refuse = &qgo.DatagramTooLargeError{MaxDatagramPayloadSize: 1100}
	if tl, err := s.step(send, p); tl == nil || tl.MaxDatagramPayloadSize != 1100 || !errors.Is(err, refuse) || s.seq != steps {
		t.Errorf("a too-large refusal: %v, %v, next number %d; want the refusal, no number taken", tl, err, s.seq)
	}
	refuse = net.ErrClosed
	if tl, err := s.step(send, p); tl != nil || !errors.Is(err, net.ErrClosed) || s.seq != steps {
		t.Errorf("a failed send: %v, %v, next number %d; want the error, no number taken", tl, err, s.seq)
	}
	refuse = nil
	if tl, err := s.step(send, p); tl != nil || err != nil || binary.BigEndian.Uint32(last) != steps || s.seq != steps+1 {
		t.Errorf("the next accepted datagram: %v, %v, number %d; want %d", tl, err, binary.BigEndian.Uint32(last), steps)
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
