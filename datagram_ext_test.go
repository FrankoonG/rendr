package rendr_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestIdleUDPSourceBufferedBytes (R-C3-2; plan:774, as M5's R1-4 amends
// it for a batching socket): the real-socket half of
// TestIdleSourceBufferedBytes. Two udp.Listen sockets as FromPacketConn
// sources whose readers run — each read and dropped junk datagrams, so
// each holds its read buffer — while no session or carrier exists:
//
//   - MaxBatch 1 (a plain socket on every target): Status.BufferedBytes is
//     0, the read buffer charged to nothing while the source waits;
//   - the default MaxBatch: 0 where rendr does not batch; on Linux amd64
//     and arm64 each source holds its extra receive slots and its Batch
//     from its first read on and while datagrams arrive (R1-4 rule 2,
//     R1-5; internal/udpflow's TestFlowOwnedSocketCharge pins the
//     amount), so BufferedBytes is positive and does not move while more
//     junk is read and dropped; once the junk stops, the sources' idle
//     release returns the extras and BufferedBytes is 0 again within
//     2 × batchIdleRelease (plan:774; srcidle,
//     TestIdlePacketListenerBufferedBytesZero_plan774).
//
// Runtime.Close returns everything: BufferedBytes 0.
func TestIdleUDPSourceBufferedBytes(t *testing.T) {
	for _, arm := range []struct {
		name     string
		maxBatch int
	}{{"plain", 1}, {"default", 0}} {
		t.Run(arm.name, func(t *testing.T) {
			rt, err := rendr.NewRuntime(rendr.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close()
			var srcs []rendr.Source
			var addrs []net.Addr
			for range 2 {
				pc, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{MaxBatch: arm.maxBatch})
				if err != nil {
					t.Fatalf("udp.Listen: %v", err)
				}
				srcs = append(srcs, rendr.FromPacketConn(pc))
				addrs = append(addrs, pc.LocalAddr())
			}
			if _, err := rt.Listen(rendr.ListenConfig{Sources: srcs}); err != nil {
				t.Fatalf("Listen: %v", err)
			}
			junk, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer junk.Close()
			// Stimulus: both readers run (the sources dropped want junk
			// datagrams).
			drop := func(want uint64) {
				t.Helper()
				deadline := time.Now().Add(10 * time.Second)
				for rt.Status().Datagram.Dropped < want {
					if time.Now().After(deadline) {
						t.Fatalf("the sources dropped %d junk datagrams, want %d", rt.Status().Datagram.Dropped, want)
					}
					for _, a := range addrs {
						_, _ = junk.WriteTo([]byte("junk"), a)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			drop(2)
			st := rt.Status()
			if st.Datagram.Sources != 2 || st.Datagram.Flows != 0 {
				t.Fatalf("two idle udp.Listen sources: sources %d, flows %d, want 2, 0", st.Datagram.Sources, st.Datagram.Flows)
			}
			switch {
			case arm.maxBatch == 1 || !sioBatching:
				if st.BufferedBytes != 0 {
					t.Fatalf("two idle udp.Listen sources (MaxBatch %d, no batching): BufferedBytes %d, want 0", arm.maxBatch, st.BufferedBytes)
				}
			default:
				if st.BufferedBytes <= 0 {
					t.Fatalf("two idle batching udp.Listen sources: BufferedBytes %d, want their extra slots and Batches", st.BufferedBytes)
				}
				drop(st.Datagram.Dropped + 20)
				if b := rt.Status().BufferedBytes; b != st.BufferedBytes {
					t.Fatalf("two idle batching sources: BufferedBytes %d after more junk, %d before; junk must cost nothing", b, st.BufferedBytes)
				}
			}
			idleZero(t, rt, "two udp.Listen sources once the junk stopped")
			rt.Close()
			if st := rt.Status(); st.Datagram.Sources != 0 || st.BufferedBytes != 0 {
				t.Fatalf("after Close: %+v", st)
			}
		})
	}
}

// The idle release of rendr's own UDP sockets, seen from Status (M5 work
// item srcidle; plan:774; M5 design R1-4 and R1-5 as the delegate's F-1
// decision amends them): real loopback sockets, outside synctest bubbles.

const (
	// idleRelease is the readers' shared idle-release period,
	// udpsocket.IdleRelease (1 s): internal/udpflow's and
	// internal/carrier's batchIdleRelease take it as their default, and
	// each package's TestBatchIdleReleaseShared pins it there. A batching
	// reader returns its extras within 2 × idleRelease of its last
	// datagram.
	idleRelease = udpsocket.IdleRelease
	// idleSlack is this row's scheduling allowance on top of
	// 2 × idleRelease (a real-socket row on a loaded host; the bound
	// itself is proved exactly by internal/udpflow's
	// TestIdlePacketListenerBufferedBytesZeroSeam_plan774 and
	// internal/carrier's TestBatchMemoryBounded_L16 in synctest bubbles).
	idleSlack = time.Second
)

// idleIO is what moves on a Runtime's own UDP sockets: one changes with
// every datagram they send or read.
func idleIO(rt *rendr.Runtime) [2]uint64 {
	d := rt.Status().Datagram
	return [2]uint64{d.RecvDatagrams + d.SentDatagrams, d.RecvCalls + d.SendCalls}
}

// idleZero waits until rt's Status.BufferedBytes is exactly 0 and fails
// if it is not within 2 × idleRelease + idleSlack of the last datagram
// rt's own sockets moved (or of since, when none moved since then) — the
// I/O counters are sampled every 5 ms, and a change restarts the bound —
// or not within 30 s at all. It returns the time from the last datagram
// to 0.
func idleZero(t *testing.T, rt *rendr.Runtime, what string) time.Duration {
	t.Helper()
	start := time.Now()
	last, io := start, idleIO(rt)
	for {
		st := rt.Status()
		now := time.Now()
		if st.BufferedBytes == 0 {
			return now.Sub(last)
		}
		if n := idleIO(rt); n != io {
			last, io = now, n
		}
		if now.Sub(last) > 2*idleRelease+idleSlack || now.Sub(start) > 30*time.Second {
			t.Fatalf("%s: BufferedBytes %d %v after the last datagram (%v after the wait began), want 0 within 2 × %v (plan:774); %s",
				what, st.BufferedBytes, now.Sub(last).Round(time.Millisecond), now.Sub(start).Round(time.Millisecond), idleRelease, idleState(st))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// idleState names what a Status says is alive.
func idleState(st rendr.Status) string {
	return fmt.Sprintf("sessions %+v, sessionless %d, mux carriers %d, sources %d, flows %d, recv %d datagrams in %d calls",
		st.Sessions, st.Sessionless, st.Mux.Carriers, st.Datagram.Sources, st.Datagram.Flows, st.Datagram.RecvDatagrams, st.Datagram.RecvCalls)
}

// idleEnded waits (30 s at most) until rt has no live session, no
// sessionless carrier, no mux carrier and no raw-UDP flow.
func idleEnded(t *testing.T, rt *rendr.Runtime, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned == 0 && st.Sessionless == 0 && st.Mux.Carriers == 0 && st.Datagram.Flows == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not ended within 30 s of the sessions' end: %s", what, idleState(st))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestIdlePacketListenerBufferedBytesZero_plan774 (plan:774; F-1; M5
// design R1-4, R1-5): Status.BufferedBytes of a Runtime with no session
// open is exactly 0 within 2 × batchIdleRelease of the last datagram its
// own sockets moved, with every Listener and Peer still alive.
//
//   - Listener: a passive Runtime whose Listener adopted a carrier/udp
//     Listen socket (the default MaxBatch: a reader of depth 32 on Linux
//     amd64 and arm64) — before any datagram arrived, after junk
//     datagrams were read and dropped, and after a selector packet session
//     over that socket exchanged sioRounds verified datagrams and ended
//     (the Listener and its source stay open: Datagram.Sources 1);
//   - dialer: the session's dialer Runtime, its Peer open, once the
//     session and its datagram carrier ended (the dialer reader's extras
//     and slot 0 went back with the carrier).
//
// While datagrams arrive the batching reader holds and counts its extras
// (internal/udpflow's TestFlowOwnedSocketCharge pins the amount); this row
// pins that they do not outlive the traffic. On every other target the
// sockets read one datagram per call and the row holds at once. Runtime
// Close then leaves nothing.
func TestIdlePacketListenerBufferedBytesZero_plan774(t *testing.T) {
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
	listening := func(what string) {
		t.Helper()
		if st := p.Status(); st.Datagram.Sources != 1 {
			t.Fatalf("%s: %s, want the Listener's source alive", what, idleState(st))
		}
		idleZero(t, p, what)
	}
	listening("a listening socket that never read a datagram")

	// Junk read and dropped.
	junk, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer junk.Close()
	for deadline := time.Now().Add(10 * time.Second); p.Status().Datagram.Dropped < 3; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the source dropped %d junk datagrams, want 3", p.Status().Datagram.Dropped)
		}
		_, _ = junk.WriteTo([]byte("junk"), ls.LocalAddr())
	}
	listening("a listening socket after junk")

	// A packet session over the socket, then its end.
	dc, pc := sioOpen(t, d, ln, udp.Carrier("u", "udp4", ls.LocalAddr().String(), udp.Options{}))
	sioPingPong(t, dc, pc) // closes pc
	dc.Close()
	for _, ch := range []<-chan struct{}{dc.Done(), pc.Done()} {
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
			t.Fatal("a session did not end within 30 s of its Close")
		}
	}
	if st := d.Status().Datagram; st.RecvDatagrams < sioRounds {
		t.Fatalf("stimulus: the dialer read %d datagrams, want at least %d", st.RecvDatagrams, sioRounds)
	}
	idleEnded(t, d, "the dialer")
	idleEnded(t, p, "the passive")
	t.Logf("dialer: BufferedBytes 0 %v after its last datagram", idleZero(t, d, "the dialer after its session and carrier ended").Round(time.Millisecond))
	listening("a listening socket after a packet session ended")

	d.Close()
	p.Close()
	for _, rt := range []*rendr.Runtime{d, p} {
		if st := rt.Status(); st.BufferedBytes != 0 || st.Datagram.Sources != 0 {
			t.Errorf("after Runtime.Close: BufferedBytes %d; %s", st.BufferedBytes, idleState(st))
		}
	}
}

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
