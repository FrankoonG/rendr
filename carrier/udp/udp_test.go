package udp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Real-socket tests of carrier/udp (WP5; M2 design §A8.6): outside synctest
// bubbles, each a leak oracle (wp5NoLeak). The socket-option halves per OS
// are sockopt_*_test.go.

// wp5NoLeak takes rendrtest.AssertNoLeak's baseline and returns its check,
// to be deferred first so that it runs after every other deferred close.
// The check is skipped once the test failed: a failed test may leave its
// goroutines behind, and its failure is the report.
func wp5NoLeak(t *testing.T) func() {
	t.Helper()
	check := rendrtest.AssertNoLeak(t)
	return func() {
		if !t.Failed() {
			check()
		}
	}
}

// wp5Ctx returns a context for one test's dials.
func wp5Ctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// wp5Family is one address family of the loopback tests.
type wp5Family struct {
	network, host string
	v6            bool
}

var wp5Families = []wp5Family{{"udp4", "127.0.0.1", false}, {"udp6", "::1", true}}

// wp5Listen listens on the loopback address of fam with o; ok is false (and
// the reason logged) when the host has no IPv6 loopback.
func wp5Listen(t *testing.T, fam wp5Family, o Options) (s *carrier.OwnedUDPSocket, ok bool) {
	t.Helper()
	pc, err := Listen(fam.network, net.JoinHostPort(fam.host, "0"), o)
	if err != nil {
		if fam.v6 {
			t.Logf("no IPv6 loopback listener: %v", err)
			return nil, false
		}
		t.Fatalf("Listen(%s): %v", fam.network, err)
	}
	s, isOwned := pc.(*carrier.OwnedUDPSocket)
	if !isOwned {
		pc.Close()
		t.Fatalf("Listen returned %T, not rendr-owned", pc)
	}
	return s, true
}

// wp5Dial dials address with o and returns the rendr-owned token.
func wp5Dial(t *testing.T, network, address string, o Options) (*carrier.OwnedUDP, net.Addr) {
	t.Helper()
	pc, peer, err := Carrier("wp5", network, address, o).Dial(wp5Ctx(t))
	if err != nil {
		t.Fatalf("Dial(%s, %s): %v", network, address, err)
	}
	tok, isOwned := pc.(*carrier.OwnedUDP)
	if !isOwned {
		pc.Close()
		t.Fatalf("Dial returned %T, not rendr-owned", pc)
	}
	return tok, peer
}

// wp5AP returns a socket's local address.
func wp5AP(c interface{ LocalAddr() net.Addr }) netip.AddrPort {
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// wp5Sockopt reads an integer socket option through SyscallConn.
func wp5Sockopt(t *testing.T, c interface {
	SyscallConn() (syscall.RawConn, error)
}, level, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = wp5Getsockopt(fd, level, opt) }); err != nil || serr != nil {
		t.Fatalf("getsockopt(%d, %d): %v, %v", level, opt, err, serr)
	}
	return v
}

// wp5Flow parses the raw-UDP flow header as M2 design §A3.4 freezes it
// (ver u8 = 2 · flow u64 big-endian).
func wp5Flow(d []byte) (uint64, bool) {
	if len(d) < 9 || d[0] != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint64(d[1:9]), true
}

// wp5Exchange sends one datagram of size bytes (the flow header included)
// from the dialer token to the listening token and the listener's reply
// back, and checks both arrive whole, from the right source, with the
// dialer's flow header.
func wp5Exchange(t *testing.T, o *carrier.OwnedUDP, s *carrier.OwnedUDPSocket, size int) {
	t.Helper()
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i)
	}
	if err := o.WriteDatagram(b); err != nil {
		t.Fatalf("WriteDatagram(%d bytes): %v", size, err)
	}
	p := make([]byte, s.MaxDatagram()+1)
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, src, ev, err := s.ReadAddrPort(p)
	if err != nil || ev != carrier.ReadOK || n != size || src != wp5AP(o) || !bytes.Equal(p[9:n], b[9:]) {
		t.Fatalf("listener read %d bytes from %v (event %d, %v); want %d from %v", n, src, ev, err, size, wp5AP(o))
	}
	if f, ok := wp5Flow(p[:n]); !ok || f != o.Flow() || f == 0 {
		t.Fatalf("datagram header % x, want version 2 and flow %#x", p[:9], o.Flow())
	}
	copy(p[9:n], bytes.Repeat([]byte{0x5a}, n-9))
	if err := s.WriteAddrPort(p[:n], src); err != nil {
		t.Fatalf("WriteAddrPort: %v", err)
	}
	buf := make([]byte, o.ReadSize())
	o.SetReadDeadline(time.Now().Add(10 * time.Second))
	data, key, ev, err := o.ReadDatagram(buf)
	if err != nil || ev != carrier.ReadOK || key.AP != wp5AP(s) || !bytes.Equal(data, p[9:n]) {
		t.Fatalf("dialer read %d bytes from %v (event %d, %v); want the reply from %v", len(data), key.AP, ev, err, wp5AP(s))
	}
}

// TestUDPCarrierRoundTrip: Listen and the factory's Dial hand out the
// rendr-owned tokens; the factory's MTU is MaxDatagram − 9; every Dial
// draws a fresh non-zero flow ID (L58: a redial never reuses one), binds an
// ephemeral port on the loopback address of the peer's family, returns the
// peer as a *net.UDPAddr, and its datagrams carry the flow header both ways
// on IPv4 and IPv6.
func TestUDPCarrierRoundTrip(t *testing.T) {
	defer wp5NoLeak(t)()
	for _, fam := range wp5Families {
		s, ok := wp5Listen(t, fam, Options{})
		if !ok {
			continue
		}
		if s.MaxDatagram() != DefaultMaxDatagram {
			t.Errorf("%s listener: MaxDatagram %d, want %d", fam.network, s.MaxDatagram(), DefaultMaxDatagram)
		}
		f := Carrier("loop-"+fam.network, "udp", s.LocalAddr().String(), Options{})
		if f.Name != "loop-"+fam.network || f.MTU != DefaultMaxDatagram-wire.FlowHeaderLen || f.Dial == nil {
			t.Fatalf("Carrier = %q MTU %d", f.Name, f.MTU)
		}
		flows := map[uint64]bool{}
		for range 3 {
			o, peer := wp5Dial(t, "udp", s.LocalAddr().String(), Options{})
			if ua, isUDP := peer.(*net.UDPAddr); !isUDP || ua.AddrPort() != wp5AP(s) {
				t.Errorf("Dial returned peer %v (%T), want %v", peer, peer, wp5AP(s))
			}
			local := wp5AP(o).Addr()
			if !local.IsLoopback() || local.Is6() != fam.v6 || wp5AP(o).Port() == 0 {
				t.Errorf("%s dialer bound %v, want an ephemeral port on the family's loopback address", fam.network, wp5AP(o))
			}
			if o.Limit() != DefaultMaxDatagram-wire.FlowHeaderLen || o.Headroom() != wire.FlowHeaderLen {
				t.Errorf("dialer Limit %d Headroom %d", o.Limit(), o.Headroom())
			}
			if o.Flow() == 0 || flows[o.Flow()] {
				t.Errorf("flow ID %#x is zero or reused", o.Flow())
			}
			flows[o.Flow()] = true
			wp5Exchange(t, o, s, 100)
			wp5Exchange(t, o, s, DefaultMaxDatagram)
			o.Close()
		}
		s.Close()
	}
}

// TestUDPLoopbackOnly: without AllowNonLoopback, Listen and the factory
// refuse every non-loopback address — an empty host (all interfaces), the
// unspecified addresses, broadcast, multicast — with ErrNonLoopback before
// any socket is opened; loopback literals and a loopback host name pass, and
// a host name binds and dials as the net package resolves it (IPv4
// preferred); AllowNonLoopback lifts the check; other networks are not UDP.
// The pure checks: a host name passes only if every address it resolves to
// is loopback, and the bind hook refuses any non-loopback address the net
// package is about to bind (a name that resolves differently the second
// time is refused, not bound).
func TestUDPLoopbackOnly(t *testing.T) {
	defer wp5NoLeak(t)()
	ctx := wp5Ctx(t)
	refused := []struct{ network, host string }{
		{"udp", ""},
		{"udp", net.IPv4zero.String()},
		{"udp4", net.IPv4bcast.String()},
		{"udp4", net.IPv4allsys.String()},
		{"udp6", net.IPv6unspecified.String()},
	}
	for _, r := range refused {
		listenAt, dialTo := net.JoinHostPort(r.host, "0"), net.JoinHostPort(r.host, "9")
		if pc, err := Listen(r.network, listenAt, Options{}); !errors.Is(err, ErrNonLoopback) {
			if pc != nil {
				pc.Close()
			}
			t.Errorf("Listen(%s, %s) = %v, want ErrNonLoopback", r.network, listenAt, err)
		}
		if pc, _, err := Carrier("x", r.network, dialTo, Options{}).Dial(ctx); !errors.Is(err, ErrNonLoopback) {
			if pc != nil {
				pc.Close()
			}
			t.Errorf("Dial(%s, %s) = %v, want ErrNonLoopback", r.network, dialTo, err)
		}
	}
	for _, network := range []string{"tcp", "ip", "unixgram"} {
		var une net.UnknownNetworkError
		if pc, err := Listen(network, "127.0.0.1:0", Options{}); !errors.As(err, &une) {
			if pc != nil {
				pc.Close()
			}
			t.Errorf("Listen(%s) = %v, want an unknown-network error", network, err)
		}
		if pc, _, err := Carrier("x", network, "127.0.0.1:9", Options{}).Dial(ctx); !errors.As(err, &une) {
			if pc != nil {
				pc.Close()
			}
			t.Errorf("Dial(%s) = %v, want an unknown-network error", network, err)
		}
	}

	// Loopback passes, by literal and by name.
	s4, _ := wp5Listen(t, wp5Families[0], Options{})
	defer s4.Close()
	port := strconv.Itoa(int(wp5AP(s4).Port()))
	for _, address := range []string{net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("localhost", port)} {
		o, _ := wp5Dial(t, "udp", address, Options{})
		wp5Exchange(t, o, s4, 64)
		o.Close()
	}
	byName, err := Listen("udp", "localhost:0", Options{})
	if err != nil {
		t.Fatalf("Listen(localhost): %v", err)
	}
	ref, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		byName.Close()
		t.Fatalf("net.ListenPacket(localhost): %v", err)
	}
	got, want := wp5AP(byName).Addr(), wp5AP(ref).Addr()
	byName.Close()
	ref.Close()
	if !got.IsLoopback() || got.Is4() != want.Is4() {
		t.Errorf("Listen(localhost) bound %v, net.ListenPacket bound %v", got, want)
	}

	// AllowNonLoopback lifts the check: a wildcard listen, a non-loopback
	// peer (bound to the unspecified address of its family).
	any4, err := Listen("udp4", net.JoinHostPort(net.IPv4zero.String(), "0"), Options{AllowNonLoopback: true})
	if err != nil {
		t.Fatalf("Listen(wildcard, AllowNonLoopback): %v", err)
	}
	if a := wp5AP(any4).Addr(); !a.IsUnspecified() {
		t.Errorf("wildcard listen bound %v", a)
	}
	any4.Close()
	far := net.JoinHostPort(net.IPv4allsys.String(), "9")
	if pc, _, err := Carrier("x", "udp4", far, Options{AllowNonLoopback: true}).Dial(ctx); errors.Is(err, ErrNonLoopback) {
		t.Errorf("AllowNonLoopback still refused %s", far)
	} else if err == nil {
		if a := wp5AP(pc.(*carrier.OwnedUDP)).Addr(); !a.IsUnspecified() || !a.Is4() {
			t.Errorf("a non-loopback peer's socket bound %v, want the IPv4 unspecified address", a)
		}
		pc.Close()
	} else {
		t.Logf("no route to a non-loopback address on this host: %v", err)
	}
	// A dial needs a peer to send to, whatever the option says.
	for _, address := range []string{":9", net.JoinHostPort(net.IPv4zero.String(), "9")} {
		if pc, _, err := Carrier("x", "udp", address, Options{AllowNonLoopback: true}).Dial(ctx); err == nil || errors.Is(err, ErrNonLoopback) {
			if pc != nil {
				pc.Close()
			}
			t.Errorf("Dial(%s, AllowNonLoopback) = %v, want an address error", address, err)
		}
	}
	// A family mismatch finds no address.
	if pc, _, err := Carrier("x", "udp6", net.JoinHostPort("127.0.0.1", port), Options{}).Dial(ctx); err == nil {
		pc.Close()
		t.Error("udp6 dialed an IPv4 address")
	}

	t.Run("checks", func(t *testing.T) {
		lo4, lo6 := netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()
		far := netip.MustParseAddr(net.IPv4allsys.String()) // any non-loopback address
		sets := []struct {
			ips []netip.Addr
			ok  bool
		}{
			{[]netip.Addr{lo4}, true},
			{[]netip.Addr{lo6, lo4}, true},
			{[]netip.Addr{netip.AddrFrom16(lo4.As16())}, true}, // IPv4-mapped loopback
			{nil, false},
			{[]netip.Addr{lo4, far}, false},
			{[]netip.Addr{far, lo6}, false},
			{[]netip.Addr{netip.IPv6Unspecified()}, false},
		}
		for _, s := range sets {
			if err := checkAddrs("name:1", s.ips); (err == nil) != s.ok || (err != nil && !errors.Is(err, ErrNonLoopback)) {
				t.Errorf("checkAddrs(%v) = %v, want ok %v", s.ips, err, s.ok)
			}
		}
		hook := map[string]bool{
			"127.0.0.1:0":                        true,
			"[::1]:443":                          true,
			"[::ffff:127.0.0.1]:80":              true,
			netip.AddrPortFrom(far, 80).String(): false,
			netip.AddrPortFrom(netip.IPv4Unspecified(), 80).String(): false,
			"[::]:80":        false,
			"not-an-address": false,
		}
		for addr, ok := range hook {
			if err := checkAddr(addr); (err == nil) != ok || (err != nil && !errors.Is(err, ErrNonLoopback)) {
				t.Errorf("checkAddr(%q) = %v, want ok %v", addr, err, ok)
			}
		}
		for _, r := range []struct {
			network string
			ips     []netip.Addr
			want    netip.Addr
			ok      bool
		}{
			{"udp", []netip.Addr{lo6, lo4}, lo4, true}, // IPv4 preferred
			{"udp", []netip.Addr{lo6}, lo6, true},
			{"udp4", []netip.Addr{lo6, netip.AddrFrom16(lo4.As16())}, lo4, true}, // unmapped
			{"udp6", []netip.Addr{lo4, lo6}, lo6, true},
			{"udp6", []netip.Addr{lo4}, netip.Addr{}, false},
			{"udp4", nil, netip.Addr{}, false},
		} {
			if got, ok := pickAddr(r.network, r.ips); got != r.want || ok != r.ok {
				t.Errorf("pickAddr(%s, %v) = %v, %v; want %v, %v", r.network, r.ips, got, ok, r.want, r.ok)
			}
		}
	})
}

// TestUDPOptions: MaxDatagram 0 selects DefaultMaxDatagram, 546–65,507 is
// accepted, anything else makes the factory's MTU 0 (which NewPeer
// rejects) and fails Listen and Dial; a negative socket buffer fails them
// too. Nothing is opened for a refused configuration (the leak check).
func TestUDPOptions(t *testing.T) {
	defer wp5NoLeak(t)()
	ctx := wp5Ctx(t)
	for _, r := range []struct {
		max, mtu int
	}{
		{0, DefaultMaxDatagram - 9},
		{546, 537},
		{wire.MaxDatagram, wire.MaxDatagram - 9},
		{545, 0},
		{wire.MaxDatagram + 1, 0},
		{-1, 0},
	} {
		o := Options{MaxDatagram: r.max}
		f := Carrier("x", "udp4", "127.0.0.1:9", o)
		if f.MTU != r.mtu {
			t.Errorf("MaxDatagram %d: MTU %d, want %d", r.max, f.MTU, r.mtu)
		}
		pc, lerr := Listen("udp4", "127.0.0.1:0", o)
		if lerr == nil {
			if got := pc.(*carrier.OwnedUDPSocket).MaxDatagram(); got != r.mtu+9 {
				t.Errorf("MaxDatagram %d: the listener carries %d", r.max, got)
			}
			pc.Close()
		}
		dc, _, derr := f.Dial(ctx)
		if derr == nil {
			dc.Close()
		}
		if (r.mtu == 0) != (lerr != nil) || (r.mtu == 0) != (derr != nil) {
			t.Errorf("MaxDatagram %d: Listen %v, Dial %v", r.max, lerr, derr)
		}
	}
	for _, o := range []Options{{ReadBuffer: -1}, {WriteBuffer: -1}} {
		if pc, err := Listen("udp4", "127.0.0.1:0", o); err == nil {
			pc.Close()
			t.Errorf("Listen accepted %+v", o)
		}
		if pc, _, err := Carrier("x", "udp4", "127.0.0.1:9", o).Dial(ctx); err == nil {
			pc.Close()
			t.Errorf("Dial accepted %+v", o)
		}
	}
}

// TestUDPDontFragment: Listen and Dial sockets refuse fragmentation with
// probe semantics on both families (M2-D66; Linux IP_PMTUDISC_PROBE /
// IPV6_PMTUDISC_PROBE, Windows IP_DONTFRAGMENT / IPV6_DONTFRAG): a datagram
// that does not fit is lost, never fragmented (L37). A plain socket reads
// another value through the same probe, so the readings are real. Datagrams
// up to the listener's MaxDatagram still cross loopback.
func TestUDPDontFragment(t *testing.T) {
	defer wp5NoLeak(t)()
	for _, fam := range wp5Families {
		s, ok := wp5Listen(t, fam, Options{MaxDatagram: wire.MaxDatagram})
		if !ok {
			continue
		}
		o, _ := wp5Dial(t, fam.network, s.LocalAddr().String(), Options{MaxDatagram: s.MaxDatagram()})
		level, opt, want, observed := wp5DF(fam.v6)
		if observed {
			for name, c := range map[string]interface {
				SyscallConn() (syscall.RawConn, error)
			}{"listener": s, "dialer": o} {
				if v := wp5Sockopt(t, c, level, opt); v != want {
					t.Errorf("%s %s socket: don't-fragment option reads %d, want %d", fam.network, name, v, want)
				}
			}
			ip := net.IPv4(127, 0, 0, 1)
			if fam.v6 {
				ip = net.IPv6loopback
			}
			ctl, err := net.ListenUDP(fam.network, &net.UDPAddr{IP: ip})
			if err != nil {
				t.Fatalf("control socket: %v", err)
			}
			if v := wp5Sockopt(t, ctl, level, opt); v == want {
				t.Errorf("%s control socket reads %d as well: the probe is broken", fam.network, v)
			}
			ctl.Close()
		} else {
			t.Logf("don't-fragment is not set or observed on this platform")
		}
		wp5Exchange(t, o, s, s.MaxDatagram())
		o.Close()
		s.Close()
	}
}

// TestUDPBuffers: Listen and Dial sockets get 4 MiB receive and 1 MiB send
// buffers by default and Options' sizes otherwise (M2-D66), best effort:
// exactly on Windows; on Linux through SO_RCVBUFFORCE/SO_SNDBUFFORCE when
// the process may, else capped at rmem_max/wmem_max (wp5BufferWant). The
// default differs from a plain socket's, so the readings are real.
func TestUDPBuffers(t *testing.T) {
	defer wp5NoLeak(t)()
	for _, o := range []Options{{}, {ReadBuffer: 256 << 10, WriteBuffer: 128 << 10}} {
		r, w, err := o.buffers()
		if err != nil {
			t.Fatal(err)
		}
		wantR, wantW := wp5BufferWant(t, r, true), wp5BufferWant(t, w, false)
		s, _ := wp5Listen(t, wp5Families[0], o)
		d, _ := wp5Dial(t, "udp4", s.LocalAddr().String(), o)
		if wantR < 0 {
			t.Logf("socket buffers are not observed on this platform")
		} else {
			for name, c := range map[string]interface {
				SyscallConn() (syscall.RawConn, error)
			}{"listener": s, "dialer": d} {
				if v := wp5Sockopt(t, c, wp5SolSocket, wp5SoRcvbuf); v != wantR {
					t.Errorf("%+v %s: SO_RCVBUF %d, want %d", o, name, v, wantR)
				}
				if v := wp5Sockopt(t, c, wp5SolSocket, wp5SoSndbuf); v != wantW {
					t.Errorf("%+v %s: SO_SNDBUF %d, want %d", o, name, v, wantW)
				}
			}
			if o == (Options{}) {
				ctl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				if v := wp5Sockopt(t, ctl, wp5SolSocket, wp5SoRcvbuf); v == wantR {
					t.Errorf("a plain socket's SO_RCVBUF is %d as well: the default was not observed", v)
				}
				ctl.Close()
			}
		}
		wp5Exchange(t, d, s, 200)
		d.Close()
		s.Close()
	}
}
