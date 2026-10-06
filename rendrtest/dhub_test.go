package rendrtest

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The hub's tests need internal/wire's flow header and REL codecs: they
// pass from integration 1 on.

// hDial dials one client of h and returns its conn and the passive
// socket's address it was given.
func hDial(t testing.TB, h *DatagramHub) (net.PacketConn, net.Addr) {
	t.Helper()
	pc, peer, err := h.Dial(context.Background())
	if err != nil || pc == nil || peer == nil {
		t.Fatalf("Dial = (%v, %v, %v)", pc, peer, err)
	}
	return pc, peer
}

// hWire prefixes rendr bytes with the flow header of flow.
func hWire(flow uint64, b []byte) []byte {
	h := make([]byte, wire.FlowHeaderLen, wire.FlowHeaderLen+len(b))
	wire.PutFlowHeader(h, flow)
	return append(h, b...)
}

// hFlow splits a datagram the passive socket read.
func hFlow(t testing.TB, d []byte) (uint64, []byte) {
	t.Helper()
	flow, rest, err := wire.ParseFlowHeader(d)
	if err != nil {
		t.Fatalf("flow header of %x: %v", d, err)
	}
	return flow, rest
}

// TestDatagramHubFlowHeader_L58: every client conn puts a fresh non-zero
// flow ID in front of every datagram it writes to the passive socket (and
// only there) and strips it from what it reads; the socket sees each
// client's address (a *net.UDPAddr: clients share one IP address, each on
// its own port); a reply with another flow ID or a bad flow header never
// reaches the client; MTU bounds the datagram on the wire, flow header
// included; dials and carriers are counted.
func TestDatagramHubFlowHeader_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "flow", MTU: 1000})
		defer h.Close()
		sock := h.PacketConn()
		a, aPeer := hDial(t, h)
		b, bPeer := hDial(t, h)
		if aPeer != sock.LocalAddr() || bPeer != sock.LocalAddr() {
			t.Fatalf("peers %v, %v; want the socket's address %v", aPeer, bPeer, sock.LocalAddr())
		}
		au, bu := a.LocalAddr().(*net.UDPAddr), b.LocalAddr().(*net.UDPAddr)
		if !au.IP.Equal(bu.IP) || au.Port == bu.Port {
			t.Fatalf("client addresses %v and %v: want one IP address, two ports", au, bu)
		}
		dSend(t, a, []byte("from a"), aPeer)
		dSend(t, b, dH1Session(1, false), bPeer)
		dSend(t, a, []byte("to nowhere"), fakeAddr(9, 9))
		gotA, srcA := dRecv(t, sock)
		gotB, srcB := dRecv(t, sock)
		flowA, restA := hFlow(t, gotA)
		flowB, restB := hFlow(t, gotB)
		if string(restA) != "from a" || !bytes.Equal(restB, dH1Session(1, false)) || flowA == flowB || srcA != a.LocalAddr() || srcB != b.LocalAddr() {
			t.Fatalf("socket read %q from %v (flow %x) and %x from %v (flow %x)", restA, srcA, flowA, restB, srcB, flowB)
		}
		dSend(t, sock, hWire(flowB, []byte("for b")), srcA)
		dSend(t, sock, []byte{1, 2, 3}, srcA)
		dSend(t, sock, hWire(flowA, []byte("reply a")), srcA)
		dSend(t, sock, hWire(flowB, []byte("reply b")), srcB)
		if got, from := dRecv(t, a); string(got) != "reply a" || from != aPeer {
			t.Fatalf("a read %q from %v", got, from)
		}
		if got, from := dRecv(t, b); string(got) != "reply b" || from != bPeer {
			t.Fatalf("b read %q from %v", got, from)
		}
		dNothing(t, a, time.Second)
		var tl *wire.DatagramTooLargeError
		if n, err := a.WriteTo(make([]byte, 992), aPeer); n != 0 || !errors.As(err, &tl) || tl.Max != 991 {
			t.Fatalf("client WriteTo above the MTU = (%d, %v), want a refusal with Max 991", n, err)
		}
		dSend(t, a, make([]byte, 991), aPeer)
		if got, _ := dRecv(t, sock); len(got) != 1000 {
			t.Fatalf("the socket read %d bytes, want 1000", len(got))
		}
		if n, err := sock.WriteTo(make([]byte, 1001), srcA); n != 0 || !errors.As(err, &tl) || tl.Max != 1000 {
			t.Fatalf("socket WriteTo above the MTU = (%d, %v), want a refusal with Max 1000", n, err)
		}
		st := h.Stats()
		if st.Dials != 2 || st.Carriers != 2 || st.Session != (DatagramCounts{Sent: 2, Delivered: 2}) {
			t.Fatalf("Dials %d, Carriers %d, session %+v", st.Dials, st.Carriers, st.Session)
		}
		if want := (DatagramCounts{Sent: 8, Delivered: 5, Lost: 3, Oversize: 2}); st.All != want {
			t.Fatalf("all %+v, want %+v", st.All, want)
		}
	})
}

// TestDatagramHubRebind_L59: after Rebind the passive socket sees the
// client's later datagrams from a new address (one IP address, a new
// port) while the client's conn keeps its LocalAddr; a reply to the old
// address is lost — also one already on its way — and a reply to the new
// one arrives; Rebind is counted.
func TestDatagramHubRebind_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "rebind"})
		defer h.Close()
		sock := h.PacketConn()
		a, peer := hDial(t, h)
		local := a.LocalAddr()
		dSend(t, a, []byte("one"), peer)
		d, oldAddr := dRecv(t, sock)
		flow, _ := hFlow(t, d)
		h.SetDelay(Down, 50*time.Millisecond, 0)
		dSend(t, sock, hWire(flow, []byte("on its way")), oldAddr)
		h.Rebind(0)
		dSend(t, a, []byte("two"), peer)
		_, newAddr := dRecv(t, sock)
		ou, nu := oldAddr.(*net.UDPAddr), newAddr.(*net.UDPAddr)
		if !ou.IP.Equal(nu.IP) || ou.Port == nu.Port || a.LocalAddr() != local {
			t.Fatalf("old %v, new %v, local %v (was %v)", ou, nu, a.LocalAddr(), local)
		}
		dSend(t, sock, hWire(flow, []byte("to old")), oldAddr)
		dSend(t, sock, hWire(flow, []byte("to new")), newAddr)
		if got, _ := dRecv(t, a); string(got) != "to new" {
			t.Fatalf("a read %q", got)
		}
		dNothing(t, a, time.Second)
		if st := h.Stats(); st.Rebinds != 1 || st.All.Lost != 2 {
			t.Fatalf("Rebinds %d, Lost %d; want 1, 2", st.Rebinds, st.All.Lost)
		}
		defer func() {
			if recover() == nil {
				t.Fatal("Rebind of an unknown client did not panic")
			}
		}()
		h.Rebind(1)
	})
}

// TestDatagramHubSpoofReplay_L59: Spoof puts a datagram into the passive
// socket from a fresh foreign address; Replay re-delivers exactly the k-th
// datagram a client sent — flow header included — from another fresh
// foreign address, and moves nothing: replies to the client's address
// still arrive. The hub keeps a client's first 16 datagrams. Spoofed counts
// both, Injected the replays (in the client's class).
func TestDatagramHubSpoofReplay_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "replay"})
		defer h.Close()
		sock := h.PacketConn()
		a, peer := hDial(t, h)
		sent := [][]byte{dH1Session(1, false), []byte("d1"), []byte("d2")}
		var wires [][]byte
		var addrA net.Addr
		for _, b := range sent {
			dSend(t, a, b, peer)
			w, from := dRecv(t, sock)
			wires, addrA = append(wires, w), from
		}
		h.Spoof([]byte("spoof"))
		got, spoofFrom := dRecv(t, sock)
		if string(got) != "spoof" || sameAddr(spoofFrom, addrA.(*net.UDPAddr)) {
			t.Fatalf("spoof %q from %v", got, spoofFrom)
		}
		h.Replay(0, 1)
		h.Replay(0, 0)
		var from []net.Addr
		for _, k := range []int{1, 0} {
			got, f := dRecv(t, sock)
			if !bytes.Equal(got, wires[k]) {
				t.Fatalf("replay of datagram %d: %x, want %x", k, got, wires[k])
			}
			from = append(from, f)
		}
		known := []net.Addr{addrA, spoofFrom, sock.LocalAddr()}
		for _, f := range from {
			u, ok := f.(*net.UDPAddr)
			if !ok || slices.ContainsFunc(known, func(a net.Addr) bool { return sameAddr(a, u) }) {
				t.Fatalf("a replay came from %v", f)
			}
			known = append(known, f)
		}
		flow, _ := hFlow(t, wires[0])
		dSend(t, sock, hWire(flow, []byte("still here")), addrA)
		if got, _ := dRecv(t, a); string(got) != "still here" {
			t.Fatalf("a read %q", got)
		}
		b, peerB := hDial(t, h)
		for i := range 20 {
			dSend(t, b, []byte{byte(i)}, peerB)
		}
		h.Replay(1, 15)
		for range 21 {
			dRecv(t, sock)
		}
		st := h.Stats()
		if st.Spoofed != 4 || st.Session.Injected != 2 || st.All.Injected != 3 {
			t.Fatalf("Spoofed %d, Injected %d (session %d); want 4, 3, 2", st.Spoofed, st.All.Injected, st.Session.Injected)
		}
		for _, bad := range [][2]int{{1, 16}, {0, 3}, {2, 0}, {-1, 0}} {
			func() {
				defer func() {
					if recover() == nil {
						t.Fatalf("Replay(%d, %d) did not panic", bad[0], bad[1])
					}
				}()
				h.Replay(bad[0], bad[1])
			}()
		}
	})
}

// floodClass classifies one flood datagram the passive socket read.
func floodClass(t *testing.T, d []byte) (class string, flow uint64) {
	flow, rest, err := wire.ParseFlowHeader(d)
	if err != nil || !wire.IsPreface(rest) {
		return "random", 0
	}
	pre, err := wire.ParsePreface(rest[:wire.PrefaceLen])
	if err != nil || pre.Kind != wire.KindDatagram || pre.CarrierID == 0 {
		t.Fatalf("flood datagram %x: preface %+v, %v", d, pre, err)
	}
	f := rest[wire.PrefaceLen:]
	typ, payload, size, ok := frameAt(f)
	if !ok || size != len(f) || typ != FrameRel || mustHeader(t, f).Fseq != wire.PrefaceFseq(rest) {
		t.Fatalf("flood datagram %x: not exactly one REL at the PREFACE's fseq", d)
	}
	rh, inner, err := wire.ParseRel(payload)
	if err != nil || rh.Cseq != wire.FirstCseq {
		t.Fatalf("flood REL %+v: %v", rh, err)
	}
	if wire.CRC(f[:size-wire.TrailerLen]) != wire.Trailer(f[size-wire.TrailerLen:]) {
		if rh.Type != wire.TypeOpen {
			t.Fatalf("a bad-CRC flood datagram carries %v", rh.Type)
		}
		return "badcrc", flow
	}
	switch rh.Type {
	case wire.TypeOpen:
		o, err := wire.ParseOpen(inner, 0)
		if err != nil || o.Kind != wire.KindDatagram || o.Mode != 1 || o.Window != floodCMTU || o.PMTU != floodCMTU-wire.DgramOverhead || o.SID == ([16]byte{}) {
			t.Fatalf("flood OPEN %+v: %v", o, err)
		}
		return "open", flow
	case wire.TypeJoin:
		j, err := wire.ParseJoin(inner)
		if err != nil || j.RxNext != floodCMTU || j.Mode != 1 {
			t.Fatalf("flood JOIN %+v: %v", j, err)
		}
		return "join", flow
	}
	t.Fatalf("a flood REL carries %v", rh.Type)
	return "", 0
}

// mustHeader decodes a frame header without validating its type.
func mustHeader(t *testing.T, f []byte) wire.Header {
	t.Helper()
	if len(f) < wire.HeaderLen {
		t.Fatal("short header")
	}
	var h wire.Header
	h.Type, h.Flags = wire.Type(f[0]), f[1]
	h.Len = uint32(f[2])<<16 | uint32(f[3])<<8 | uint32(f[4])
	h.Fseq = uint32(f[5])<<24 | uint32(f[6])<<16 | uint32(f[7])<<8 | uint32(f[8])
	h.Handle = uint32(f[9])<<24 | uint32(f[10])<<16 | uint32(f[11])<<8 | uint32(f[12])
	return h
}

// TestDatagramHubFlood_L58: Flood delivers exactly rate datagrams per
// second to the passive socket, in the mix's shares — random bytes, valid
// first datagrams (REL{FirstCseq, OPEN of a packet session} or JOIN, at the
// PREFACE's fseq, CRC valid) and the same OPEN with a bad CRC — with fresh
// flow IDs, from rotating addresses: one in four from the clients' IP
// address (on a port no client has: R1-21's flood from the victim's own
// address) unless it is a valid JOIN, which never comes from there (it
// would take the victim's own JOIN quota); the rest from three other IP
// addresses; stop ends it and waits for it; Close stops every flood. Each
// datagram counts as Spoofed.
func TestDatagramHubFlood_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "flood", Queue: 4096})
		defer h.Close() // a failed assertion must not leave a flood running in the bubble
		sock := h.PacketConn()
		a, _ := hDial(t, h)
		client := a.LocalAddr().(*net.UDPAddr)
		got := dCollect(sock, 1<<30)
		stop := h.Flood(1000, FloodMix{Random: 25, BadCRC: 25, Preface: 25, Join: 25})
		time.Sleep(999*time.Millisecond + 500*time.Microsecond)
		stop()
		stop() // idempotent
		time.Sleep(time.Second)
		if n := h.Stats().Spoofed; n != 1000 {
			t.Fatalf("Spoofed %d after one second at 1000/s", n)
		}
		h.Flood(5000, FloodMix{}) // left running: Close stops it
		h.Flood(0, FloodMix{})()  // no rate: nothing
		time.Sleep(10 * time.Millisecond)
		// The flood's timer fires at this instant too: let its batch in and the
		// collector read it, or Close would drop datagrams already Spoofed.
		synctest.Wait()
		h.Close()
		as := got()
		if n := h.Stats().Spoofed; len(as) != int(n) || n <= 1000 {
			t.Fatalf("read %d datagrams, Spoofed %d: the second flood sent nothing, or a datagram was lost", len(as), n)
		}
		classes := map[string]int{}
		flows := map[uint64]bool{}
		ips := map[string]int{}
		for i, a := range as[:1000] {
			c, flow := floodClass(t, a.b)
			classes[c]++
			if flow != 0 {
				if flows[flow] {
					t.Fatalf("flow ID %x reused", flow)
				}
				flows[flow] = true
			}
			u, ok := a.from.(*net.UDPAddr)
			if !ok {
				t.Fatalf("source %v", a.from)
			}
			ips[u.IP.String()]++
			if onClient := u.IP.Equal(client.IP); onClient != (i%4 == 0 && c != "join") || onClient && (u.Port < floodPortBase || u.Port == client.Port) {
				t.Fatalf("datagram %d (%s) from %v", i, c, u)
			}
		}
		for _, c := range []string{"random", "badcrc", "open", "join"} {
			if classes[c] < 180 || classes[c] > 320 {
				t.Fatalf("classes %v", classes)
			}
		}
		if len(ips) != 4 {
			t.Fatalf("source IP addresses %v, want 4", ips)
		}
	})
}

// TestDatagramHubDialFrom_L58: DialFrom(n) dials clients of host n: they
// share host n's IP address, which no client of another host has, and work
// as Dial's — host 0's — do (flow header, replies, Rebind on the same
// address); a Flood's first share comes from host 0's address only, never
// from another host's (R1-21: a session dialled from another host is
// outside the flooded quota). DialFrom panics for a host outside 0–255.
func TestDatagramHubDialFrom_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "hosts"})
		defer h.Close()
		sock := h.PacketConn()
		a, _ := hDial(t, h)
		b, peerB, err := h.DialFrom(1)(context.Background())
		if err != nil || peerB != sock.LocalAddr() {
			t.Fatalf("DialFrom(1) = (%v, %v, %v)", b, peerB, err)
		}
		c, _, err := h.DialFrom(0)(context.Background())
		if err != nil {
			t.Fatalf("DialFrom(0): %v", err)
		}
		au, bu, cu := a.LocalAddr().(*net.UDPAddr), b.LocalAddr().(*net.UDPAddr), c.LocalAddr().(*net.UDPAddr)
		if au.IP.Equal(bu.IP) || !au.IP.Equal(cu.IP) || au.Port == cu.Port {
			t.Fatalf("host 0: %v and %v, host 1: %v", au, cu, bu)
		}
		dSend(t, b, []byte("from b"), peerB)
		d, from := dRecv(t, sock)
		flow, rest := hFlow(t, d)
		if string(rest) != "from b" || from != b.LocalAddr() {
			t.Fatalf("socket read %q from %v", rest, from)
		}
		dSend(t, sock, hWire(flow, []byte("to b")), from)
		if got, _ := dRecv(t, b); string(got) != "to b" {
			t.Fatalf("b read %q", got)
		}
		h.Rebind(1) // b, in Dial order
		dSend(t, b, []byte("moved"), peerB)
		if _, moved := dRecv(t, sock); !moved.(*net.UDPAddr).IP.Equal(bu.IP) || moved.(*net.UDPAddr).Port == bu.Port {
			t.Fatalf("b moved from %v to %v, want a new port of host 1", bu, moved)
		}
		got := dCollect(sock, 1<<30)
		h.Flood(1000, FloodMix{Random: 1, Preface: 1, Join: 1})
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		h.Close()
		host0 := 0
		for _, x := range got() {
			switch u := x.from.(*net.UDPAddr); {
			case u.IP.Equal(bu.IP):
				t.Fatalf("a flood datagram came from host 1: %v", u)
			case u.IP.Equal(au.IP):
				host0++
			}
		}
		if host0 == 0 {
			t.Fatal("no flood datagram came from host 0")
		}
		for _, n := range []int{-1, 256} {
			func() {
				defer func() {
					if recover() == nil {
						t.Fatalf("DialFrom(%d) did not panic", n)
					}
				}()
				h.DialFrom(n)
			}()
		}
	})
}

// TestDatagramHubLossDelayQueue: SetDelay and SetLoss act per direction on
// every client; each client and direction holds at most Queue datagrams
// that were written and not yet read (more are lost); the passive socket
// holds at most Queue foreign datagrams nobody has read — more are dropped,
// uncounted for a Spoof, as the client's loss for a Replay — and reading
// frees room.
func TestDatagramHubLossDelayQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "path", Queue: 4})
		defer h.Close()
		sock := h.PacketConn()
		a, peer := hDial(t, h)
		h.SetDelay(Up, 30*time.Millisecond, 0)
		h.SetDelay(Down, 10*time.Millisecond, 0)
		start := time.Now()
		dSend(t, a, []byte("up"), peer)
		d, from := dRecv(t, sock)
		if time.Since(start) != 30*time.Millisecond {
			t.Fatalf("up after %v", time.Since(start))
		}
		flow, _ := hFlow(t, d)
		dSend(t, sock, hWire(flow, []byte("down")), from)
		dRecv(t, a)
		if time.Since(start) != 40*time.Millisecond {
			t.Fatalf("down after %v", time.Since(start)-30*time.Millisecond)
		}
		h.SetLoss(Up, 1)
		dSend(t, a, []byte("lost"), peer)
		h.SetLoss(Up, 0)
		h.SetLoss(Down, 1)
		dSend(t, sock, hWire(flow, []byte("lost too")), from)
		h.SetLoss(Down, 0)
		dNothing(t, a, time.Second)
		dNothing(t, sock, time.Second)
		for i := range 6 {
			dSend(t, a, []byte{byte(i)}, peer)
		}
		b, peerB := hDial(t, h)
		dSend(t, b, []byte("b has its own room"), peerB)
		for range 5 {
			dRecv(t, sock)
		}
		dNothing(t, sock, time.Second)
		if st := h.Stats().All; st.Lost != 2+2 || st.Delivered != 2+5 {
			t.Fatalf("Lost %d, Delivered %d; want 4, 7", st.Lost, st.Delivered)
		}

		for i := range 6 {
			h.Spoof([]byte{byte(i)})
		}
		h.Replay(0, 0)
		if st := h.Stats(); st.Spoofed != 4 || st.All.Injected != 1 || st.All.Lost != 4+1 {
			t.Fatalf("socket full: Spoofed %d, Injected %d, Lost %d; want 4, 1, 5", st.Spoofed, st.All.Injected, st.All.Lost)
		}
		for i := range 4 {
			if got, _ := dRecv(t, sock); got[0] != byte(i) {
				t.Fatalf("foreign datagram %d is %d", i, got[0])
			}
		}
		dNothing(t, sock, time.Second)
		h.Replay(0, 0)
		if got, _ := dRecv(t, sock); !bytes.Equal(got, hWire(flow, []byte("up"))) {
			t.Fatalf("replay after reading: %x", got)
		}
		if st := h.Stats(); st.Spoofed != 5 || st.All.Injected != 2 || st.All.Lost != 5 {
			t.Fatalf("after reading: Spoofed %d, Injected %d, Lost %d; want 5, 2, 5", st.Spoofed, st.All.Injected, st.All.Lost)
		}
	})
}

// TestDatagramHubClose: Close returns with readers blocked on the socket
// and on a client and a flood running; the readers get net.ErrClosed, the
// flood is joined, later Dials fail (counted), Spoof and Flood do nothing,
// and a second Close is harmless.
func TestDatagramHubClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "close"})
		a, _ := hDial(t, h)
		h.Flood(100, FloodMix{Random: 1})
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, pc := range []net.PacketConn{a, h.PacketConn()} {
			wg.Go(func() {
				for {
					if _, _, err := pc.ReadFrom(make([]byte, 64)); err != nil {
						errs <- err
						return
					}
				}
			})
		}
		time.Sleep(50 * time.Millisecond)
		if err := h.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		wg.Wait()
		for range 2 {
			if err := <-errs; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("blocked ReadFrom: %v", err)
			}
		}
		spoofed := h.Stats().Spoofed
		h.Spoof([]byte("late"))
		h.Flood(100, FloodMix{})()
		if _, _, err := h.Dial(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Dial after Close: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := h.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		st := h.Stats()
		if st.Spoofed != spoofed || st.Dials != 2 || st.DialFailures != 1 {
			t.Fatalf("Spoofed %d (was %d), Dials %d, DialFailures %d", st.Spoofed, spoofed, st.Dials, st.DialFailures)
		}
		if _, _, err := NewDatagramHub(DatagramHubConfig{}).Dial(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial with a done context: %v", err)
		}
	})
}

// TestDatagramHubNoLeak_L66: on the real clock, a hub with clients,
// readers and running floods leaves no goroutine behind once Close
// returned and the test joined its own readers (AssertNoLeak covers the
// flood pumps; the hub starts no other goroutine).
func TestDatagramHubNoLeak_L66(t *testing.T) {
	check := AssertNoLeak(t)
	h := NewDatagramHub(DatagramHubConfig{Name: "noleak"})
	h.SetDelay(Up, 2*time.Millisecond, time.Millisecond)
	a, peer := hDial(t, h)
	var wg sync.WaitGroup
	for _, pc := range []net.PacketConn{a, h.PacketConn()} {
		wg.Go(func() {
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
			}
		})
	}
	stop := h.Flood(2000, FloodMix{Random: 1, Preface: 1})
	h.Flood(1000, FloodMix{Join: 1})
	for i := range 20 {
		dSend(t, a, dBytes(100, i), peer)
	}
	time.Sleep(30 * time.Millisecond)
	stop()
	h.Close()
	wg.Wait()
	check()
}
