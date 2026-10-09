package quic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestQUICSmoke_CA is the QUIC half of the checkpoint C-A smoke (M2 design
// §A11.4 step 4, integration 2), in real time on loopback: two Runtimes,
// one Peer with a QUIC DATAGRAM factory and a QUIC stream factory, the
// passive behind one quic.Listener serving one rendr Listener. A packet
// session (on the DATAGRAM carrier) and a stream session (on the stream
// carrier) run at the same time; each loses its carrier once (the dialer's
// conn is closed under rendr: an embedder-closed conn, transport_error)
// and goes on. Integrity: every datagram verified (seq, size, CRC, body;
// no duplicate; losses only right after the kill or counted as drops) and every stream byte
// exact; the PacketCounters add up (§A7.2). Clean end: both sessions end by
// Close, both Runtimes close with no session, handshake or buffered byte
// left, the quic Listener's Done closes, and no goroutine is left.
func TestQUICSmoke_CA(t *testing.T) {
	g0 := runtime.NumGoroutine()
	srv, cli := testTLS(t)
	d, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		t.Fatal(err)
	}
	rl, err := p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var qctr Counters // the adapters' own datagram drops (transport losses)
	ql, err := Listen("udp4", "127.0.0.1:0", Options{TLS: srv, Counters: &qctr})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- ql.Serve(rl) }()
	addr := ql.Addr().String()

	dc, err := DatagramCarrier("qd", addr, Options{TLS: cli, Counters: &qctr})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := StreamCarrier("qs", addr, Options{TLS: cli})
	if err != nil {
		t.Fatal(err)
	}
	var lastPC atomic.Pointer[net.PacketConn]
	dialPC := dc.Dial
	dc.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dialPC(ctx)
		if err == nil {
			lastPC.Store(&pc)
		}
		return pc, a, err
	}
	var lastNC atomic.Pointer[net.Conn]
	dialNC := sc.Dial
	sc.Dial = func(ctx context.Context) (net.Conn, error) {
		nc, err := dialNC(ctx)
		if err == nil {
			lastNC.Store(&nc)
		}
		return nc, err
	}
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{dc, sc}})
	if err != nil {
		t.Fatal(err)
	}

	// The passive accepts one session of each kind.
	type accepted struct {
		pkt *rendr.PacketConn
		str *rendr.Conn
	}
	acc := make(chan accepted, 1)
	go func() {
		var a accepted
		pp, err := rl.AcceptPacket(context.Background())
		if err == nil {
			a.pkt, err = pp.Confirm()
		}
		if err != nil {
			t.Errorf("packet accept: %v", err)
		}
		ps, err := rl.Accept(context.Background())
		if err == nil {
			a.str, err = ps.Confirm()
		}
		if err != nil {
			t.Errorf("stream accept: %v", err)
		}
		acc <- a
	}()
	dpkt, err := peer.DialPacket(context.Background(), rendr.DialOptions{})
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	if mp := dpkt.MaxPayload(); mp != DatagramBudget-25 {
		t.Fatalf("MaxPayload %d, want %d (the DATAGRAM budget)", mp, DatagramBudget-25)
	}
	if cs := dpkt.Status().Carriers; len(cs) != 1 || cs[0].Kind != rendr.KindDatagram || cs[0].Name != "qd" {
		t.Fatalf("the packet session did not open on the DATAGRAM factory: %+v", cs)
	}
	dstr, err := peer.Dial(context.Background(), rendr.DialOptions{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	a := <-acc
	if a.pkt == nil || a.str == nil {
		t.FailNow()
	}

	// Traffic: 2,000 datagrams per second each way for 4 s; 4 MiB on the
	// stream session, echoed back.
	const (
		rate   = 2000
		run    = 4 * time.Second
		killAt = 1500 * time.Millisecond
		total  = 4 << 20
	)
	var wg sync.WaitGroup
	up, down := rendrtest.NewPacketVerifier(11), rendrtest.NewPacketVerifier(12)
	var upAcc, downAcc, upRead, downRead atomic.Uint64
	gen := func(c *rendr.PacketConn, seed uint64, n *atomic.Uint64, start time.Time) {
		defer wg.Done()
		buf := make([]byte, 1200)
		for seq := uint64(0); ; seq++ {
			at := start.Add(time.Duration(seq) * time.Second / rate)
			if at.Sub(start) >= run {
				return
			}
			time.Sleep(time.Until(at))
			b := rendrtest.PacketPayload(buf, seed, seq, rendrtest.PacketHeaderLen+int(seq*53%1100), time.Now())
			if _, err := c.WriteTo(b, nil); err != nil {
				t.Errorf("WriteTo: %v", err)
				return
			}
			n.Add(1)
		}
	}
	readErrs := make(chan error, 2)
	recv := func(c *rendr.PacketConn, v *rendrtest.PacketVerifier, n *atomic.Uint64) {
		buf := make([]byte, 2048)
		for {
			k, _, err := c.ReadFrom(buf)
			if err != nil {
				readErrs <- err
				return
			}
			n.Add(1)
			if err := v.Add(buf[:k], time.Now()); err != nil {
				t.Errorf("verify: %v", err)
			}
		}
	}
	go recv(a.pkt, up, &upRead)
	go recv(dpkt, down, &downRead)
	echoDone := make(chan error, 1)
	go func() { // the passive echoes the stream back
		_, err := io.Copy(a.str, a.str)
		a.str.Close() // the dialer's FIN arrived: end the passive's half too
		echoDone <- err
	}()
	src := make([]byte, total)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range src {
		src[i] = byte(rng.Uint32())
	}
	got := make(chan []byte, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(dstr, total))
		if err != nil {
			t.Errorf("stream read: %v", err)
		}
		got <- b
	}()
	start := time.Now()
	wg.Add(2)
	go gen(dpkt, 11, &upAcc, start)
	go gen(a.pkt, 12, &downAcc, start)
	wrote := make(chan error, 1)
	go func() {
		for off := 0; off < total; off += 64 << 10 {
			if _, err := dstr.Write(src[off : off+64<<10]); err != nil {
				wrote <- err
				return
			}
			time.Sleep(time.Millisecond * 40)
		}
		wrote <- nil
	}()

	time.Sleep(time.Until(start.Add(killAt)))
	pcp, ncp := lastPC.Load(), lastNC.Load()
	if pcp == nil || ncp == nil {
		t.Fatal("no carrier to kill")
	}
	(*pcp).Close()
	(*ncp).Close()
	wg.Wait()
	if err := <-wrote; err != nil {
		t.Fatalf("stream write: %v", err)
	}
	if b := <-got; !bytes.Equal(b, src) {
		t.Fatalf("the stream echo differs (%d of %d bytes)", len(b), total)
	}
	time.Sleep(time.Second) // drain the datagrams

	// Clean end: the dialer closes both sessions.
	dps0 := dpkt.Status()
	dpkt.Close()
	dstr.Close()
	endAt := time.Now()
	for _, ch := range []<-chan struct{}{dpkt.Done(), a.pkt.Done(), dstr.Done()} {
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
			t.Fatal("a session did not end within 30 s of its Close")
		}
	}
	<-a.str.Done()
	t.Logf("both sessions ended %v after their Close", time.Since(endAt))
	if err := <-echoDone; err != nil {
		t.Errorf("echo: %v", err)
	}
	for range 2 {
		<-readErrs
	}
	dps, pps := dpkt.Status(), a.pkt.Status()
	if dps0.Err != nil {
		t.Fatalf("the packet session failed: %v", dps0.Err)
	}
	if dps.Rejoins+dps.Migrations.Death == 0 || dstr.Status().Migrations.Death+dstr.Status().Rejoins == 0 {
		t.Errorf("stimulus: the kills moved nothing: packet %+v, stream %+v", dps.Migrations, dstr.Status().Migrations)
	}
	for _, x := range []struct {
		name     string
		v        *rendrtest.PacketVerifier
		acc      uint64
		read     uint64
		tx, rx   *rendr.PacketCounters
		readDone bool
	}{
		{"dialer → passive", up, upAcc.Load(), upRead.Load(), dps.Packet, pps.Packet, true},
		{"passive → dialer", down, downAcc.Load(), downRead.Load(), pps.Packet, dps.Packet, false},
	} {
		res := x.v.Result()
		if res.Corrupt+res.BadSize+res.Duplicates != 0 {
			t.Errorf("%s: corrupt %d, resized %d, duplicates %d", x.name, res.Corrupt, res.BadSize, res.Duplicates)
		}
		if res.Unique < x.acc*9/10 {
			t.Errorf("%s: %d of %d datagrams received", x.name, res.Unique, x.acc)
		}
		// Losses away from the kill must be counted: the session's queue
		// drops or the QUIC adapters' own (a host stall under -race).
		var away uint64
		for _, m := range res.Missing {
			at := time.Duration(m.From) * time.Second / rate
			if at < killAt-100*time.Millisecond || at > killAt+3*time.Second {
				away += m.To - m.From + 1
			}
		}
		counted := x.tx.DropQueue + x.tx.DropAge + x.tx.DropNoPath + x.tx.DropTooLarge + x.rx.DropRecvQueue +
			qctr.IngressDrops.Load() + qctr.EgressDrops.Load()
		if away > counted {
			t.Errorf("%s: %d datagrams lost away from the kill at %v, %d counted (missing %v)", x.name, away, killAt, counted, res.Missing)
		}
		if sum := x.tx.Sent + x.tx.DropQueue + x.tx.DropAge + x.tx.DropNoPath + x.tx.DropTooLarge; sum != x.acc {
			t.Errorf("%s: accepted %d ≠ the send-side sum %d (%+v)", x.name, x.acc, sum, *x.tx)
		}
		if x.readDone && x.rx.Received != x.read+x.rx.DropRecvQueue {
			t.Errorf("%s: Received %d ≠ read %d + DropRecvQueue %d", x.name, x.rx.Received, x.read, x.rx.DropRecvQueue)
		}
		t.Logf("%s: accepted %d, unique %d, missing %v; tx %+v", x.name, x.acc, res.Unique, res.Missing, *x.tx)
	}
	t.Logf("packet: migrations %+v rejoins %d; stream: migrations %+v rejoins %d", dps.Migrations, dps.Rejoins,
		dstr.Status().Migrations, dstr.Status().Rejoins)

	d.Close()
	p.Close()
	ql.Close()
	select {
	case <-ql.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the quic Listener's Done did not close")
	}
	if err := <-served; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve returned %v, want net.ErrClosed", err)
	}
	for _, rt := range []*rendr.Runtime{d, p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 {
			t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > g0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > g0 {
		buf := make([]byte, 1<<20)
		t.Fatalf("%d goroutines left, %d before:\n%s", g, g0, buf[:runtime.Stack(buf, true)])
	}
}
