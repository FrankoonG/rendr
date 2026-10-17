package rendr_test

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The I/O counters of Status.Datagram (M5 design §A2.1, §A10.1 WP4;
// M5-D17, R1-2): real loopback sockets, outside synctest bubbles; helpers
// carry the sio prefix.

// sioBatching reports whether this build batches rendr's own UDP sockets
// (Linux amd64 and arm64, M5-D8).
var sioBatching = runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")

// sioRounds is the datagrams of the ping-pong exchange.
const sioRounds = 200

// TestStatusDatagramIOCounters (§A10.1 WP4; M5-D17, R1-2; L57): the six
// I/O counters of Status.Datagram count rendr's own UDP sockets and
// nothing else. A selector packet session exchanges sioRounds test
// datagrams ping-pong — the dialer writes one, the passive echoes it, the
// dialer reads the echo before it writes the next — so every datagram is
// a datagram of its own on the wire and none is lost unseen (each echo is
// verified: seq, size, CRC-32C, body).
//
// Arm "carrier/udp" (udp.Carrier to a udp.Listen socket adopted by
// FromPacketConn): first a one-way burst (sioBurst) tells the send
// counters from the receive counters — the dialer's SentDatagrams and the
// passive's RecvDatagrams grow by at least the burst, the opposite
// counters by much less; then, after the ping-pong, on both Runtimes calls
// and datagrams in both directions,
// at least sioRounds datagrams each way, each call moving at least one
// datagram, no fallback and no refused charge, counters that never go back
// between a snapshot during the session and the final one; one datagram
// per call where the build does not batch; and, once both Runtimes closed,
// the dialer received no more datagrams than the passive sent. Arm
// "embedder" (plain loopback sockets through a DatagramCarrier and
// Listener.HandlePacket): the same exchange leaves all six counters 0 —
// embedder sockets are not counted.
func TestStatusDatagramIOCounters(t *testing.T) {
	t.Run("carrier/udp", func(t *testing.T) {
		t.Cleanup(rendrtest.AssertNoLeak(t))
		d, p := sioRuntimes(t)
		ls, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(ls)}}) // owns ls
		if err != nil {
			ls.Close()
			t.Fatal(err)
		}
		dc, pc := sioOpen(t, d, ln, udp.Carrier("u", "udp4", ls.LocalAddr().String(), udp.Options{}))
		sioBurst(t, d, p, dc, pc)
		sioPingPong(t, dc, pc)
		mid := [2]rendr.DatagramStatus{d.Status().Datagram, p.Status().Datagram}
		sioEnd(t, d, p, dc, pc)
		fin := [2]rendr.DatagramStatus{d.Status().Datagram, p.Status().Datagram}
		for i, name := range []string{"dialer", "passive"} {
			s := fin[i]
			t.Logf("%s: send %d calls / %d datagrams, recv %d calls / %d datagrams, fallbacks %d, charge refused %d",
				name, s.SendCalls, s.SentDatagrams, s.RecvCalls, s.RecvDatagrams, s.BatchFallbacks, s.ChargeRefused)
			if s.SendCalls == 0 || s.RecvCalls == 0 || s.SentDatagrams < sioRounds || s.RecvDatagrams < sioRounds {
				t.Errorf("%s: %+v: want calls in both directions and at least %d datagrams each way", name, s, sioRounds)
			}
			if s.SentDatagrams < s.SendCalls || s.RecvDatagrams < s.RecvCalls {
				t.Errorf("%s: %+v: a counted call moves at least one datagram", name, s)
			}
			if !sioBatching && (s.SentDatagrams != s.SendCalls || s.RecvDatagrams != s.RecvCalls) {
				t.Errorf("%s (%s/%s, no batching): %+v: want one datagram per call", name, runtime.GOOS, runtime.GOARCH, s)
			}
			if s.BatchFallbacks != 0 || s.ChargeRefused != 0 {
				t.Errorf("%s: BatchFallbacks %d, ChargeRefused %d on loopback with the default budget, want 0", name, s.BatchFallbacks, s.ChargeRefused)
			}
			m := mid[i]
			if s.SendCalls < m.SendCalls || s.SentDatagrams < m.SentDatagrams || s.RecvCalls < m.RecvCalls || s.RecvDatagrams < m.RecvDatagrams {
				t.Errorf("%s: counters went back: %+v after %+v", name, s, m)
			}
		}
		// The passive's listening socket counts every datagram it writes, so
		// the dialer cannot have received more.
		if fin[0].RecvDatagrams > fin[1].SentDatagrams {
			t.Errorf("the dialer received %d datagrams, the passive sent %d", fin[0].RecvDatagrams, fin[1].SentDatagrams)
		}
	})

	t.Run("embedder", func(t *testing.T) {
		t.Cleanup(rendrtest.AssertNoLeak(t))
		d, p := sioRuntimes(t)
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
		ln, err := p.Listen(rendr.ListenConfig{})
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
		dc, pc := sioOpen(t, d, ln, c)
		sioPingPong(t, dc, pc)
		sioEnd(t, d, p, dc, pc)
		for i, rt := range []*rendr.Runtime{d, p} {
			s := rt.Status().Datagram
			if s.SendCalls != 0 || s.SentDatagrams != 0 || s.RecvCalls != 0 || s.RecvDatagrams != 0 || s.BatchFallbacks != 0 || s.ChargeRefused != 0 {
				t.Errorf("Runtime %d over embedder sockets: %+v, want every I/O counter 0", i, s)
			}
		}
	})
}

// sioRuntimes creates a dialer and a passive Runtime, closed by a cleanup
// as well.
func sioRuntimes(t *testing.T) (d, p *rendr.Runtime) {
	t.Helper()
	var err error
	if d, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if p, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return d, p
}

// sioOpen dials one selector packet session over c and confirms it on ln.
func sioOpen(t *testing.T, d *rendr.Runtime, ln *rendr.Listener, c rendr.Carrier) (dc, pc *rendr.PacketConn) {
	t.Helper()
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{c}})
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pp, err := ln.AcceptPacket(ctx)
	if err == nil {
		pc, err = pp.Confirm()
	}
	if err != nil {
		t.Fatalf("AcceptPacket: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// sioBurst writes sioRounds test datagrams of 700 … 999 bytes from dc in
// groups of 50, each group read and verified on pc before the next is
// written. Every datagram is above half the carrier's MTU (1,223 bytes), so
// no two share a UDP datagram. Between a snapshot before the burst and one
// after the last read, the dialer's SentDatagrams and the passive's
// RecvDatagrams grow by at least the datagrams read, and the dialer's
// RecvDatagrams and the passive's SentDatagrams — the passive's
// acknowledgements and keepalives only — by less than half of that. A
// group that loopback loses part of is given up after 2 s; at least 90 %
// must arrive.
func sioBurst(t *testing.T, d, p *rendr.Runtime, dc, pc *rendr.PacketConn) {
	t.Helper()
	const group = 50
	snap := func() [2]rendr.DatagramStatus {
		return [2]rendr.DatagramStatus{d.Status().Datagram, p.Status().Datagram}
	}
	before := snap()
	v := rendrtest.NewPacketVerifier(0xb0)
	out := make([]byte, 1024)
	in := make([]byte, 2048)
	for seq := uint64(0); seq < sioRounds; {
		for end := seq + group; seq < end; seq++ {
			if _, err := dc.WriteTo(rendrtest.PacketPayload(out, 0xb0, seq, 700+int(seq*37%300), time.Now()), nil); err != nil {
				t.Fatalf("burst WriteTo seq %d: %v", seq, err)
			}
		}
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		for v.Result().Unique+v.Result().Duplicates < seq {
			n, _, err := pc.ReadFrom(in)
			if err != nil {
				break // lost on loopback: judged below
			}
			if err := v.Add(in[:n], time.Now()); err != nil {
				t.Fatalf("burst: %v", err)
			}
		}
	}
	_ = pc.SetReadDeadline(time.Time{})
	r := v.Result()
	if r.Unique < sioRounds*9/10 || r.Corrupt != 0 || r.BadSize != 0 || r.Duplicates != 0 {
		t.Fatalf("burst: %+v, want at least %d of %d distinct and intact", r, sioRounds*9/10, sioRounds)
	}
	// A call's counters move at its return, which may follow the peer's
	// read of its datagrams: wait (5 s at most) until both cover the burst.
	got := r.Unique
	var after [2]rendr.DatagramStatus
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		after = snap()
		if after[0].SentDatagrams-before[0].SentDatagrams >= got && after[1].RecvDatagrams-before[1].RecvDatagrams >= got || time.Now().After(deadline) {
			break
		}
	}
	dSent, pRecv := after[0].SentDatagrams-before[0].SentDatagrams, after[1].RecvDatagrams-before[1].RecvDatagrams
	dRecv, pSent := after[0].RecvDatagrams-before[0].RecvDatagrams, after[1].SentDatagrams-before[1].SentDatagrams
	t.Logf("burst of %d datagrams (%d read): dialer sent %d, received %d; passive sent %d, received %d", sioRounds, got, dSent, dRecv, pSent, pRecv)
	if dSent < got || pRecv < got {
		t.Errorf("burst: the dialer's SentDatagrams grew by %d, the passive's RecvDatagrams by %d: want at least the %d datagrams read", dSent, pRecv, got)
	}
	if dRecv >= got/2 || pSent >= got/2 {
		t.Errorf("burst: the dialer's RecvDatagrams grew by %d, the passive's SentDatagrams by %d: want fewer than %d (control datagrams only)", dRecv, pSent, got/2)
	}
}

// sioPingPong sends sioRounds test datagrams from dc; pc echoes each one
// and dc verifies the echo before it sends the next. A datagram lost on
// loopback is sent again after 200 ms (the same seq; the verifier counts
// a late echo as a duplicate).
func sioPingPong(t *testing.T, dc, pc *rendr.PacketConn) {
	t.Helper()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], nil); err != nil {
				return
			}
		}
	}()
	v := rendrtest.NewPacketVerifier(0x510)
	out := make([]byte, 1024)
	in := make([]byte, 2048)
	deadline := time.Now().Add(30 * time.Second)
	for seq := uint64(0); seq < sioRounds; seq++ {
		size := rendrtest.PacketHeaderLen + int(seq*37%977)
		for got := false; !got; {
			if time.Now().After(deadline) {
				t.Fatalf("the ping-pong did not finish within 30 s (at seq %d)", seq)
			}
			if _, err := dc.WriteTo(rendrtest.PacketPayload(out, 0x510, seq, size, time.Now()), nil); err != nil {
				t.Fatalf("WriteTo seq %d: %v", seq, err)
			}
			_ = dc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			for {
				n, _, err := dc.ReadFrom(in)
				if err != nil {
					break // resend
				}
				if err := v.Add(in[:n], time.Now()); err != nil {
					t.Fatalf("echo: %v", err)
				}
				if r := v.Result(); r.Unique == seq+1 {
					got = true
					break
				}
			}
		}
	}
	_ = dc.SetReadDeadline(time.Time{})
	if r := v.Result(); r.Unique != sioRounds || r.Corrupt != 0 || r.BadSize != 0 {
		t.Fatalf("echoes %+v, want %d distinct and intact", r, sioRounds)
	}
	pc.Close()
	<-echoDone
}

// sioEnd closes both sessions and both Runtimes and requires that
// nothing is left.
func sioEnd(t *testing.T, d, p *rendr.Runtime, dc, pc *rendr.PacketConn) {
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
	d.Close()
	p.Close()
	for _, rt := range []*rendr.Runtime{d, p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.BufferedBytes != 0 ||
			st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 {
			t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
}
