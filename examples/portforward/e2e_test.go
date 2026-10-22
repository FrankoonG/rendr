package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/l4"
)

// udpTarget is a loopback UDP echo target that records the source address
// of every datagram it received.
type udpTarget struct {
	c    *net.UDPConn
	mu   sync.Mutex
	srcs map[netip.AddrPort]int
}

func newUDPTarget(t *testing.T) *udpTarget {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	u := &udpTarget{c: c, srcs: map[netip.AddrPort]int{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, a, err := c.ReadFromUDPAddrPort(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				continue // ICMP-class noise (Windows reports it on reads)
			}
			u.mu.Lock()
			u.srcs[a]++
			u.mu.Unlock()
			c.WriteToUDPAddrPort(buf[:n], a)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return u
}

func (u *udpTarget) addr() string { return u.c.LocalAddr().String() }

// received returns the datagrams received from each source.
func (u *udpTarget) received() map[netip.AddrPort]int {
	u.mu.Lock()
	defer u.mu.Unlock()
	m := make(map[netip.AddrPort]int, len(u.srcs))
	for k, v := range u.srcs {
		m[k] = v
	}
	return m
}

// tcpTarget is a loopback TCP echo target (half-close aware) that counts
// its connections.
type tcpTarget struct {
	ln    *net.TCPListener
	conns atomic.Int64
}

func newTCPTarget(t *testing.T) *tcpTarget {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	tt := &tcpTarget{ln: ln}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			tt.conns.Add(1)
			wg.Go(func() {
				io.Copy(c, c)
				c.CloseWrite()
				io.Copy(io.Discard, c)
				c.Close()
			})
		}
	})
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return tt
}

func (tt *tcpTarget) addr() string { return tt.ln.Addr().String() }

// udpClient is one client application socket connected to an ingress.
type udpClient struct {
	c      *net.UDPConn
	seq    uint32
	resent int
}

func dialClient(t *testing.T, addr string) *udpClient {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("ingress address %q: %v", addr, err)
	}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		t.Fatalf("dial the ingress: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return &udpClient{c: c}
}

// payload is datagram seq of n ≥ 4 bytes: seq, then bytes drawn from seq.
func payload(seq uint32, n int) []byte {
	p := make([]byte, n)
	binary.BigEndian.PutUint32(p, seq)
	r := mrand.New(mrand.NewPCG(uint64(seq), uint64(n)))
	for i := 4; i < n; i++ {
		p[i] = byte(r.Uint32())
	}
	return p
}

// send writes the next datagram of n bytes and returns it.
func (u *udpClient) send(t *testing.T, n int) []byte {
	t.Helper()
	u.seq++
	p := payload(u.seq, n)
	if _, err := u.c.Write(p); err != nil {
		t.Fatalf("send %d bytes: %v", n, err)
	}
	return p
}

// roundTrip sends the next datagram of n bytes and waits for its echo,
// which must be whole; without an echo within 1 s it is sent again (UDP
// may lose one), at most 4 more times. Echoes of earlier datagrams (late
// copies) are skipped.
func (u *udpClient) roundTrip(t *testing.T, n int) {
	t.Helper()
	p := u.send(t, n)
	buf := make([]byte, 65536)
	for try := 0; try < 5; try++ {
		if try > 0 {
			u.resent++
			if _, err := u.c.Write(p); err != nil {
				t.Fatalf("resend %d bytes: %v", n, err)
			}
		}
		u.c.SetReadDeadline(time.Now().Add(time.Second))
		for {
			m, err := u.c.Read(buf)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			if err != nil {
				t.Fatalf("read the echo of datagram %d: %v", u.seq, err)
			}
			if m < 4 || binary.BigEndian.Uint32(buf) > u.seq {
				t.Fatalf("an echo of %d bytes that was never sent (datagram %d pending)", m, u.seq)
			}
			if binary.BigEndian.Uint32(buf) < u.seq {
				continue
			}
			if !bytes.Equal(buf[:m], p) {
				t.Fatalf("datagram %d: %d bytes came back altered (sent %d)", u.seq, m, n)
			}
			return
		}
	}
	t.Fatalf("no echo of datagram %d (%d bytes) after 5 sends", u.seq, n)
}

// tcpEcho sends n random bytes through the TCP ingress at addr, half-closes
// and checks that exactly those bytes come back, then the end.
func tcpEcho(t *testing.T, addr string, n int) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial the TCP ingress: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	p := make([]byte, n)
	rand.Read(p)
	werr := make(chan error, 1)
	go func() {
		_, err := c.Write(p)
		if err == nil {
			err = c.(*net.TCPConn).CloseWrite()
		}
		werr <- err
	}()
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, p) {
		t.Fatalf("TCP echo: %d of %d bytes back (equal %v), %v", len(got), n, bytes.Equal(got, p), err)
	}
	if err := <-werr; err != nil {
		t.Fatalf("TCP write: %v", err)
	}
}

// tcpRefused checks that a connection to the TCP ingress at addr is reset
// without a byte (ServeTCP never ends a refused connection cleanly). The
// reset can reach the socket before the client's write: Linux then reports
// it to that write, once, and the read sees the end of the stream (M6 I3:
// a race-unit pass under host load read "0 bytes, EOF", run
// 20261022-211620-0824), so a reset the write reported counts as well.
func tcpRefused(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial the TCP ingress: %v", err)
	}
	defer c.Close()
	_, werr := c.Write([]byte("ping"))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	n, err := c.Read(b[:])
	if reset := errors.Is(err, errConnReset) || errors.Is(werr, errConnReset) && errors.Is(err, io.EOF); n != 0 || !reset {
		t.Fatalf("a refused connection: %d bytes, %v (the write: %v); want a reset without data", n, err, werr)
	}
}

// relayPair is a TCP proxy and a UDP relay on one loopback port in front
// of a server's carrier address, which the client's carriers cross; kill
// ends every carrier crossing it at once: the TCP ones with a reset of
// both legs, the UDP ones by dropping their datagrams both ways from then
// on. A redialled carrier crosses it afresh.
type relayPair struct {
	tl      net.Listener
	uc      *net.UDPConn
	to      *net.UDPAddr
	mu      sync.Mutex
	legs    []*net.TCPConn                  // both legs of every live proxied connection
	open    int                             // proxied connections whose client leg still reads
	changed chan struct{}                   // closed and replaced when open falls
	ups     map[netip.AddrPort]*net.UDPConn // every client source's upstream socket
	dead    map[netip.AddrPort]bool         // the sources kill dropped
	wg      sync.WaitGroup
}

func newRelayPair(t *testing.T, to string) *relayPair {
	t.Helper()
	ta, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		t.Fatal(err)
	}
	r := &relayPair{to: ta, changed: make(chan struct{}), ups: map[netip.AddrPort]*net.UDPConn{}, dead: map[netip.AddrPort]bool{}}
	for try := 0; r.uc == nil; try++ {
		if r.tl, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if r.uc, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(r.tl.Addr().String()))); err != nil {
			r.tl.Close()
			if try == 9 {
				t.Fatalf("relay pair: %v", err)
			}
		}
	}
	r.wg.Go(r.acceptTCP)
	r.wg.Go(r.relayUDP)
	t.Cleanup(func() {
		r.tl.Close()
		r.uc.Close()
		r.mu.Lock()
		for _, c := range r.legs {
			c.Close()
		}
		for _, u := range r.ups {
			u.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return r
}

func (r *relayPair) addr() string { return r.tl.Addr().String() }

func (r *relayPair) acceptTCP() {
	for {
		a, err := r.tl.Accept()
		if err != nil {
			return
		}
		b, err := net.Dial("tcp", r.to.String())
		if err != nil {
			a.Close()
			continue
		}
		r.mu.Lock()
		r.legs = append(r.legs, a.(*net.TCPConn), b.(*net.TCPConn))
		r.open++
		r.mu.Unlock()
		for _, p := range [][2]net.Conn{{a, b}, {b, a}} {
			r.wg.Go(func() {
				io.Copy(p[0], p[1])
				p[0].Close()
				p[1].Close()
				if p[1] == a { // the client leg's reads ended
					r.mu.Lock()
					r.open--
					close(r.changed)
					r.changed = make(chan struct{})
					r.mu.Unlock()
				}
			})
		}
	}
}

// waitNoClient waits up to d until no proxied connection's client leg is
// open any more.
func (r *relayPair) waitNoClient(t *testing.T, d time.Duration) {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		r.mu.Lock()
		n, ch := r.open, r.changed
		r.mu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			t.Fatalf("%d carrier connections of the client still open %v after its stop", n, d)
		}
	}
}

func (r *relayPair) relayUDP() {
	buf := make([]byte, 65536)
	for {
		n, src, err := r.uc.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		r.mu.Lock()
		up, dead := r.ups[src], r.dead[src]
		if err == nil && !dead && up == nil {
			if up, err = net.DialUDP("udp", nil, r.to); err == nil {
				r.ups[src] = up
				r.wg.Go(func() { r.replies(src, up) })
			}
		}
		r.mu.Unlock()
		if err == nil && !dead {
			up.Write(buf[:n])
		}
	}
}

// replies relays what the server sends to the upstream socket up of the
// source src back to src, until kill drops src.
func (r *relayPair) replies(src netip.AddrPort, up *net.UDPConn) {
	buf := make([]byte, 65536)
	for {
		n, err := up.Read(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		r.mu.Lock()
		dead := r.dead[src]
		r.mu.Unlock()
		if err == nil && !dead {
			r.uc.WriteToUDPAddrPort(buf[:n], src)
		}
	}
}

// kill resets every proxied TCP connection and drops every UDP source seen
// so far; it returns how many of each it ended.
func (r *relayPair) kill() (tcpConns, udpSources int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.legs {
		c.SetLinger(0)
		c.Close()
	}
	tcpConns = len(r.legs) / 2
	r.legs = nil
	for src := range r.ups {
		if !r.dead[src] {
			r.dead[src] = true
			udpSources++
		}
	}
	return tcpConns, udpSources
}

// statusRe matches a status line of kind (e.g. "client: status udp")
// holding every one of parts, in order.
func statusRe(kind string, parts ...string) *regexp.Regexp {
	s := regexp.QuoteMeta(kind) + `:`
	for _, p := range parts {
		// The space before p may have been taken by the previous part's end.
		s += `(?:[^\n]* )?` + regexp.QuoteMeta(p) + `(?:[ ;\n]|$)`
	}
	return regexp.MustCompile(s)
}

// TestPortForwardExampleE2E (M6-D31, M6-D34, §A4): the two subcommands on
// loopback carriers, with real UDP and TCP targets. Each row proves its
// stimulus (the forward's traffic or refusal in the status lines), its
// load (hundreds of datagrams over two flows, 1 MiB over TCP) and its
// integrity (every echo byte-exact, nothing at a refused target).
func TestPortForwardExampleE2E(t *testing.T) {
	old := statusEvery
	statusEvery = 20 * time.Millisecond
	t.Cleanup(func() { statusEvery = old })

	// allow: the -allow targets are forwarded — two UDP clients of one
	// forward are two flows with one egress source each, demultiplexed by
	// their source — and the unlisted ones are refused (CodeNotAllowed),
	// nothing reaching them.
	t.Run("allow", func(t *testing.T) {
		t.Parallel()
		ut, ut2, tt, tt2 := newUDPTarget(t), newUDPTarget(t), newTCPTarget(t), newTCPTarget(t)
		// The UDP entry is another spelling of the client's target; the TCP
		// target is a name in another case than its entry.
		ua := ut.c.LocalAddr().(*net.UDPAddr)
		mapped := "[::ffff:" + ua.IP.String() + "]:" + strconv.Itoa(ua.Port)
		_, tport, _ := net.SplitHostPort(tt.addr())
		tname := "LOCALHOST:" + tport
		srv, addr := startServer(t, "-udp", "-allow", mapped, "-allow", "LocalHost:"+tport)
		cli, local := startClient(t, addr, []string{"udp:" + ut.addr(), "tcp:" + tname, "udp:" + ut2.addr(), "tcp:" + tt2.addr()})
		a, b := dialClient(t, local["udp:"+ut.addr()]), dialClient(t, local["udp:"+ut.addr()])
		sizes := []int{4, 5, 11, 257, 1000, 1198}
		for i := range 150 {
			a.roundTrip(t, sizes[i%len(sizes)])
			b.roundTrip(t, sizes[(i+3)%len(sizes)])
		}
		srcs := ut.received()
		if len(srcs) != 2 {
			t.Fatalf("the target saw sources %v, want two (one per flow)", srcs)
		}
		for src, n := range srcs {
			if n < 150 || n > 150+a.resent+b.resent {
				t.Fatalf("source %v sent %d datagrams, want 150 (+%d resent)", src, n, a.resent+b.resent)
			}
		}
		tcpEcho(t, local["tcp:"+tname], 1<<20)
		dialClient(t, local["udp:"+ut2.addr()]).send(t, 64)
		tcpRefused(t, local["tcp:"+tt2.addr()])
		cli.out.wait(t, statusRe("client: status udp", "Opened=2", "Failed=1", "ByCode(not allowed)=1"), 15*time.Second)
		cli.out.wait(t, statusRe("client: status tcp", "Accepted=2", "Failed=1", "ByCode(not allowed)=1"), 15*time.Second)
		srv.out.wait(t, statusRe("server: status l4", "Confirmed=1", "ByCode(not allowed)=1", "UDP.Confirmed=2", "UDP.ByCode(not allowed)=1"), 15*time.Second)
		if n := len(ut2.received()); n != 0 || tt2.conns.Load() != 0 || tt.conns.Load() != 1 {
			t.Fatalf("an unlisted target was reached (%d UDP sources, %d TCP connections) or the listed one not once (%d)", n, tt2.conns.Load(), tt.conns.Load())
		}
		// Nothing was too large: the UDP lines carry no TooLarge sentence.
		if out := cli.out.String(); strings.Contains(out, "datagrams up to") {
			t.Fatalf("a TooLarge sentence without an oversize datagram: %q", out)
		}
		cli.stop(t, "client")
		srv.stop(t, "server")
	})

	// deny-all: a server without -allow refuses every target.
	t.Run("deny-all", func(t *testing.T) {
		t.Parallel()
		ut, tt := newUDPTarget(t), newTCPTarget(t)
		srv, addr := startServer(t, "-udp")
		cli, local := startClient(t, addr, []string{"udp:" + ut.addr(), "tcp:" + tt.addr()})
		dialClient(t, local["udp:"+ut.addr()]).send(t, 64)
		tcpRefused(t, local["tcp:"+tt.addr()])
		cli.out.wait(t, statusRe("client: status udp", "Failed=1", "ByCode(not allowed)=1"), 15*time.Second)
		cli.out.wait(t, statusRe("client: status tcp", "Failed=1", "ByCode(not allowed)=1"), 15*time.Second)
		srv.out.wait(t, statusRe("server: status l4", "ByCode(not allowed)=1", "UDP.ByCode(not allowed)=1"), 15*time.Second)
		if n := len(ut.received()); n != 0 || tt.conns.Load() != 0 {
			t.Fatalf("a target was reached: %d UDP sources, %d TCP connections", n, tt.conns.Load())
		}
		cli.stop(t, "client")
		srv.stop(t, "server")
	})

	// allow-any: every target is forwarded (the hook without its list), here
	// through the second of the server's two -rendr addresses (one Listener
	// each).
	t.Run("allow-any", func(t *testing.T) {
		t.Parallel()
		ut, tt := newUDPTarget(t), newTCPTarget(t)
		srv := start(t, "server", "-rendr", "127.0.0.1:0", "-rendr", "127.0.0.1:0", "-udp", "-allow-any")
		addr := srv.out.waitN(t, serverLine, 2, 10*time.Second)[1][1]
		cli, local := startClient(t, addr, []string{"udp:" + ut.addr(), "tcp:" + tt.addr()})
		c := dialClient(t, local["udp:"+ut.addr()])
		for i := range 40 {
			c.roundTrip(t, 4+i*29)
		}
		tcpEcho(t, local["tcp:"+tt.addr()], 64<<10)
		cli.stop(t, "client")
		srv.stop(t, "server")
	})

	// too-large: a datagram above the path's budget is dropped and counted,
	// the status line names both sizes and the remedy, and -max-datagram
	// 1472 on both ends carries 1,438-byte datagrams.
	t.Run("too-large", func(t *testing.T) {
		t.Parallel()
		ut, ut2 := newUDPTarget(t), newUDPTarget(t)
		srv, addr := startServer(t, "-udp", "-allow-any", "-max-datagram", "1472")
		def := udp.DefaultMaxDatagram - 34
		cli, local := startClient(t, addr, []string{"udp:" + ut.addr()})
		c := dialClient(t, local["udp:"+ut.addr()])
		c.roundTrip(t, 4)
		c.send(t, 1300)
		c.roundTrip(t, def) // the reader handled the 1300 bytes before it
		m := cli.out.wait(t, regexp.MustCompile(`client: status udp:[^\n]* TooLarge=1 TooLargeMax=1300 MaxPayload=(\d+)[^\n]*; datagrams up to 1300 bytes dropped; this path carries (\d+) \(raise -max-datagram on both ends\)`), 15*time.Second)
		if m[1] != strconv.Itoa(def) || m[2] != m[1] {
			t.Fatalf("MaxPayload %s, the line says %s; want %d", m[1], m[2], def)
		}
		for src, n := range ut.received() {
			if n != 2+c.resent {
				t.Fatalf("the target got %d datagrams from %v, want 2 (+%d resent): the oversize one crossed", n, src, c.resent)
			}
		}
		cli2, local2 := startClient(t, addr, []string{"udp:" + ut2.addr()}, "-max-datagram", "1472")
		c2 := dialClient(t, local2["udp:"+ut2.addr()])
		c2.roundTrip(t, 1300)
		c2.roundTrip(t, 1438)
		c2.send(t, 1439)
		c2.roundTrip(t, 4)
		cli2.out.wait(t, regexp.MustCompile(`client: status udp:[^\n]* MaxPayload=1438[^\n]*; datagrams up to 1439 bytes dropped; this path carries 1438 \(raise -max-datagram on both ends\)`), 15*time.Second)
		cli.stop(t, "client")
		cli2.stop(t, "client")
		srv.stop(t, "server")
	})

	// carrier-death (R1-44's proof, in process): the carriers of a live UDP
	// flow and a live TCP connection are killed (a relay between the ends
	// resets the TCP ones and drops the UDP ones); each client status line
	// names its kind's death by cause, and the server's line names both;
	// the flow and the connection go on over redialled carriers, every byte
	// intact, the flow still one source at its target; the client's stop
	// closes every carrier it redialled.
	t.Run("carrier-death", func(t *testing.T) {
		t.Parallel()
		ut, tt := newUDPTarget(t), newTCPTarget(t)
		srv, addr := startServer(t, "-udp", "-allow-any")
		rp := newRelayPair(t, addr)
		// Two paths through the relay: each Peer then keeps a sessionless
		// probe carrier per path, which only Runtime.Close ends.
		cli, local := startClient(t, rp.addr(), []string{"udp:" + ut.addr(), "tcp:" + tt.addr()}, "-rendr", rp.addr())
		u := dialClient(t, local["udp:"+ut.addr()])
		for range 20 {
			u.roundTrip(t, 512)
		}
		c, err := net.Dial("tcp", local["tcp:"+tt.addr()])
		if err != nil {
			t.Fatalf("dial the TCP ingress: %v", err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(60 * time.Second))
		echo := func(n int) {
			p := make([]byte, n)
			rand.Read(p)
			werr := make(chan error, 1)
			go func() { _, err := c.Write(p); werr <- err }()
			got := make([]byte, n)
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, p) || <-werr != nil {
				t.Fatalf("TCP echo of %d bytes across the carriers: equal %v, %v", n, bytes.Equal(got, p), err)
			}
		}
		echo(64 << 10)
		if nt, nu := rp.kill(); nt == 0 || nu == 0 {
			t.Fatalf("the relay carried %d TCP connections and %d UDP sources, want both kinds", nt, nu)
		}
		for _, w := range []struct {
			p  *proc
			re string
		}{
			{cli, `client: status tcp:[^\n]* CarrierDeaths\(transport_error\)=[1-9][^\n]*`},
			{cli, `client: status udp:[^\n]* CarrierDeaths\(ping_timeout\)=[1-9][^\n]*`}, // dropped datagrams: no transport error
			{srv, `server: status l4:[^\n]* CarrierDeaths\(ping_timeout\)=[1-9][^\n]* CarrierDeaths\(transport_error\)=[1-9][^\n]*`},
		} {
			t.Log(w.p.out.wait(t, regexp.MustCompile(w.re), 20*time.Second)[0])
		}
		for range 20 {
			u.roundTrip(t, 512)
		}
		echo(64 << 10)
		if srcs := ut.received(); len(srcs) != 1 {
			t.Fatalf("the UDP target saw sources %v, want one: the flow did not survive its carrier", srcs)
		}
		// Each line counts its own Runtime's deaths: the TCP carriers were
		// reset, the UDP ones timed out.
		for _, l := range regexp.MustCompile(`client: status (?:tcp:[^\n]*ping_timeout|udp:[^\n]*transport_error)[^\n]*`).FindAllString(cli.out.String(), -1) {
			t.Fatalf("a client line counts the other kind's death: %s", l)
		}
		c.Close()
		cli.stop(t, "client")
		// The client closed its Runtimes: its TCP carriers, the probe ones
		// included, are gone while the server still runs.
		rp.waitNoClient(t, 3*time.Second)
		srv.stop(t, "server")
	})

	// server-restart: a stopped server's Runtime.Close tells the client's
	// carriers it went away over its carrier sockets, which close only
	// after it, so a server restarted on the same address is reached at
	// once: a new UDP flow's first datagram is echoed without a resend
	// (the client's old UDP carrier would otherwise wait for its ping
	// timeout, about 4 s), and a new TCP connection forwards.
	t.Run("server-restart", func(t *testing.T) {
		t.Parallel()
		ut, tt := newUDPTarget(t), newTCPTarget(t)
		srv, addr := startServer(t, "-udp", "-allow-any")
		cli, local := startClient(t, addr, []string{"udp:" + ut.addr(), "tcp:" + tt.addr()})
		u := dialClient(t, local["udp:"+ut.addr()])
		for range 5 {
			u.roundTrip(t, 512)
		}
		tcpEcho(t, local["tcp:"+tt.addr()], 4<<10)
		srv.stop(t, "server")
		srv2 := start(t, "server", "-rendr", addr, "-udp", "-allow-any")
		srv2.out.wait(t, serverLine, 10*time.Second)
		u2 := dialClient(t, local["udp:"+ut.addr()]) // a new flow
		t0 := time.Now()
		if u2.roundTrip(t, 512); u2.resent != 0 {
			t.Fatalf("the first echo after the restart took %v and %d resends, want none: the client's carriers missed the GOAWAY", time.Since(t0), u2.resent)
		}
		tcpEcho(t, local["tcp:"+tt.addr()], 4<<10)
		cli.stop(t, "client")
		srv2.stop(t, "server")
	})

	// udp-off: a server without -udp never serves a flow (the dialer's open
	// ends with ErrCapacity at the AcceptTimeout) and still forwards TCP.
	// racebudget (M6 I1, R1-37): it waits out the 10-s AcceptTimeout, so
	// it runs outside -race only (the non-race unit lane); under -race the
	// path is l4's TestPortForwardOldPassive_L49 (synctest, both lanes).
	if !raceEnabled {
		t.Run("udp-off", func(t *testing.T) {
			t.Parallel()
			ut, tt := newUDPTarget(t), newTCPTarget(t)
			srv, addr := startServer(t, "-allow-any")
			cli, local := startClient(t, addr, []string{"udp:" + ut.addr(), "tcp:" + tt.addr()})
			dialClient(t, local["udp:"+ut.addr()]).send(t, 64)
			tcpEcho(t, local["tcp:"+tt.addr()], 64<<10)
			cli.out.wait(t, regexp.MustCompile(`client: status udp:[^\n]* Failed=1[^\n]* LastErr="[^"\n]*capacity`), 25*time.Second)
			if n := len(ut.received()); n != 0 {
				t.Fatalf("the UDP target was reached from %d sources", n)
			}
			cli.stop(t, "client")
			srv.stop(t, "server")
		})
	}

	// mode: -mode is every session's Mode, selector by default (seen by a
	// test passive on the example's carriers).
	t.Run("mode", func(t *testing.T) {
		t.Parallel()
		addr, modes := startModePassive(t)
		for _, mode := range []string{"", "race", "bond"} {
			ut, tt := newUDPTarget(t), newTCPTarget(t)
			args := []string{"-rendr", addr} // a second path to the same listener
			if mode != "" {
				args = append(args, "-mode", mode)
			}
			cli, local := startClient(t, addr, []string{"udp:" + ut.addr(), "tcp:" + tt.addr()}, args...)
			dialClient(t, local["udp:"+ut.addr()]).roundTrip(t, 64)
			tcpEcho(t, local["tcp:"+tt.addr()], 4<<10)
			want := rendr.ModeSelector
			if mode != "" {
				want = map[string]rendr.Mode{"race": rendr.ModeRace, "bond": rendr.ModeBond}[mode]
			}
			for _, target := range []string{ut.addr(), tt.addr()} {
				if got := modes(target); len(got) != 1 || got[0] != want {
					t.Fatalf("-mode %q: the sessions to %s had modes %v, want [%v]", mode, target, got, want)
				}
			}
			cli.stop(t, "client")
		}
	})
}

// startModePassive runs an l4 Server (UDP on) on the example's carrier
// pair and records the Mode of every session by its target.
func startModePassive(t *testing.T) (string, func(target string) []rendr.Mode) {
	t.Helper()
	rt, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tl, ul, err := listenPair("127.0.0.1:0", options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := rt.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(tl), rendr.FromPacketConn(ul)}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string][]rendr.Mode{}
	note := func(md []byte, parse func([]byte) (l4.Request, error), mode rendr.Mode) {
		if r, err := parse(md); err == nil {
			mu.Lock()
			seen[r.Addr] = append(seen[r.Addr], mode)
			mu.Unlock()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &l4.Server{UDP: true}
	var wg sync.WaitGroup
	wg.Go(func() {
		for p, err := ln.AcceptPacket(ctx); err == nil; p, err = ln.AcceptPacket(ctx) {
			note(p.Metadata(), l4.ParseUDPMetadata, p.Mode())
			wg.Go(func() { s.HandleUDP(ctx, p) })
		}
	})
	wg.Go(func() {
		for p, err := ln.Accept(ctx); err == nil; p, err = ln.Accept(ctx) {
			note(p.Metadata(), l4.ParseMetadata, p.Mode())
			wg.Go(func() { s.Handle(ctx, p) })
		}
	})
	t.Cleanup(func() { cancel(); wg.Wait(); rt.Close() })
	return tl.Addr().String(), func(target string) []rendr.Mode {
		mu.Lock()
		defer mu.Unlock()
		return append([]rendr.Mode(nil), seen[target]...)
	}
}
