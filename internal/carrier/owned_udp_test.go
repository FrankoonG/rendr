package carrier

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Tests of the raw-UDP ownership tokens (WP5): real loopback sockets
// outside synctest bubbles (M2 design §A8.6), each a leak oracle
// (g10NoLeak), plus the error classification over injected errnos. The
// per-OS halves are owned_udp_unix_test.go and owned_udp_windows_test.go.

// wp5Flow is the flow ID of the tests' dialer tokens; wp5MaxDatagram is
// carrier/udp's DefaultMaxDatagram (which this package cannot import).
const (
	wp5Flow        uint64 = 0x0123456789abcdef
	wp5MaxDatagram        = 1232
)

// wp5Listen opens a plain UDP socket on the loopback address of network
// ("udp4" or "udp6"); ok is false when the host has no such loopback.
func wp5Listen(t testing.TB, network string) (u *net.UDPConn, ok bool) {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		ip = net.IPv6loopback
	}
	u, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		if network == "udp6" {
			t.Logf("no IPv6 loopback socket: %v", err)
			return nil, false
		}
		t.Fatalf("listen %s: %v", network, err)
	}
	return u, true
}

// wp5AP returns a socket's local address.
func wp5AP(u interface{ LocalAddr() net.Addr }) netip.AddrPort {
	return u.LocalAddr().(*net.UDPAddr).AddrPort()
}

// wp5Header is the raw-UDP flow header as M2 design §A3.4 freezes it:
// ver u8 = 2 · flow u64 big-endian.
func wp5Header(flow uint64) []byte {
	h := make([]byte, 9, 9+8)
	h[0] = 2
	binary.BigEndian.PutUint64(h[1:], flow)
	return h
}

// wp5Datagram returns a datagram of exactly size bytes: the flow header of
// flow (truncated when size < 9) and a pattern after it.
func wp5Datagram(flow uint64, size int) []byte {
	d := make([]byte, max(size, 9))
	copy(d, wp5Header(flow))
	for i := 9; i < len(d); i++ {
		d[i] = byte(i*7 + 1)
	}
	return d[:size]
}

// wp5Send writes d from u to dst as one datagram.
func wp5Send(t testing.TB, u *net.UDPConn, d []byte, dst netip.AddrPort) {
	t.Helper()
	if n, err := u.WriteToUDPAddrPort(d, dst); err != nil || n != len(d) {
		t.Fatalf("send %d bytes: %d, %v", len(d), n, err)
	}
}

// wp5Read reads the next datagram through the dialer token with a 10-s
// deadline.
func wp5Read(t testing.TB, o *OwnedUDP, buf []byte) ([]byte, PeerKey, ReadEvent) {
	t.Helper()
	if err := o.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, key, ev, err := o.ReadDatagram(buf)
	if err != nil {
		t.Fatalf("ReadDatagram: %v", err)
	}
	return data, key, ev
}

// wp5ReadSocket reads the next datagram through the listening token with a
// 10-s deadline.
func wp5ReadSocket(t testing.TB, s *OwnedUDPSocket, p []byte) (int, netip.AddrPort, ReadEvent) {
	t.Helper()
	if err := s.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, src, ev, err := s.ReadAddrPort(p)
	if err != nil {
		t.Fatalf("ReadAddrPort: %v", err)
	}
	return n, src, ev
}

// TestOwnedUDPTruncation_L58: a datagram longer than the receive limit is
// dropped as ReadTruncated, never delivered in part and never a socket
// error, and the next datagram reads normally (L58). Both tokens read into
// exactly MaxDatagram + 1 bytes of a larger caller buffer (R1-6), so a
// datagram of exactly MaxDatagram is whole and one byte more fills the
// buffer — truncated on every OS by the max+1 rule; a much longer one is
// cut by the OS, which reports it by MSG_TRUNC on Linux and WSAEMSGSIZE on
// Windows (the "os" subtest pins that raw behaviour and its mapping). A
// max-sized read buffer fails the first row: the whole maximum datagram
// would fill it.
func TestOwnedUDPTruncation_L58(t *testing.T) {
	const maxDatagram = 1232
	buf := make([]byte, 70000) // larger than any ReadSize: the tokens must read into their first ReadSize bytes only
	t.Run("dialer", func(t *testing.T) {
		defer g10NoLeak(t)()
		raw, _ := wp5Listen(t, "udp4")
		defer raw.Close()
		du, _ := wp5Listen(t, "udp4")
		o := NewOwnedUDP(du, wp5AP(raw), wp5Flow, maxDatagram)
		defer o.Close()
		if o.ReadSize() != maxDatagram+1 {
			t.Fatalf("ReadSize %d, want MaxDatagram + 1 = %d", o.ReadSize(), maxDatagram+1)
		}
		dst := wp5AP(o)
		rows := []struct {
			size int
			ev   ReadEvent
		}{
			{maxDatagram, ReadOK},             // the largest datagram: whole
			{maxDatagram + 1, ReadTruncated},  // fills the max+1 buffer
			{5000, ReadTruncated},             // cut by the OS (MSG_TRUNC, WSAEMSGSIZE)
			{wire.MaxDatagram, ReadTruncated}, // the largest UDP payload
			{100, ReadOK},                     // the socket reads on
		}
		for _, r := range rows {
			d := wp5Datagram(wp5Flow, r.size)
			wp5Send(t, raw, d, dst)
			data, _, ev := wp5Read(t, o, buf)
			if ev != r.ev {
				t.Fatalf("%d-byte datagram: event %d, want %d", r.size, ev, r.ev)
			}
			if ev == ReadOK && !bytes.Equal(data, d[9:]) {
				t.Fatalf("%d-byte datagram: %d rendr bytes delivered, want %d intact", r.size, len(data), len(d)-9)
			}
			if ev != ReadOK && data != nil {
				t.Fatalf("%d-byte datagram: %d bytes handed over with event %d", r.size, len(data), ev)
			}
		}
		// A lowered receive limit (R1-6) moves the boundary with it.
		o.SetLimit(600)
		for _, r := range []struct {
			size int
			ev   ReadEvent
		}{{9 + 600, ReadOK}, {9 + 601, ReadTruncated}, {9 + 600, ReadOK}} {
			wp5Send(t, raw, wp5Datagram(wp5Flow, r.size), dst)
			if data, _, ev := wp5Read(t, o, buf); ev != r.ev || (ev == ReadOK && len(data) != r.size-9) {
				t.Fatalf("limit 600, %d-byte datagram: event %d with %d bytes, want %d", r.size, ev, len(data), r.ev)
			}
		}
	})
	t.Run("listener", func(t *testing.T) {
		defer g10NoLeak(t)()
		raw, _ := wp5Listen(t, "udp4")
		defer raw.Close()
		su, _ := wp5Listen(t, "udp4")
		s := NewOwnedUDPSocket(su, maxDatagram)
		defer s.Close()
		dst := wp5AP(s)
		for _, p := range [][]byte{buf[:maxDatagram+1], buf} { // exactly the required length, and longer
			for _, r := range []struct {
				size int
				ev   ReadEvent
			}{{maxDatagram, ReadOK}, {maxDatagram + 1, ReadTruncated}, {5000, ReadTruncated}, {100, ReadOK}} {
				d := wp5Datagram(wp5Flow, r.size)
				wp5Send(t, raw, d, dst)
				n, src, ev := wp5ReadSocket(t, s, p)
				if ev != r.ev {
					t.Fatalf("buffer %d, %d-byte datagram: event %d, want %d", len(p), r.size, ev, r.ev)
				}
				if ev == ReadOK && (n != r.size || src != wp5AP(raw) || !bytes.Equal(p[:n], d)) {
					t.Fatalf("buffer %d, %d-byte datagram: %d bytes from %v", len(p), r.size, n, src)
				}
			}
		}
	})
	t.Run("os", func(t *testing.T) {
		defer g10NoLeak(t)()
		raw, _ := wp5Listen(t, "udp4")
		defer raw.Close()
		rx, _ := wp5Listen(t, "udp4")
		defer rx.Close()
		wp5Send(t, raw, wp5Datagram(wp5Flow, 5000), wp5AP(rx))
		small := make([]byte, 100)
		rx.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _, flags, src, err := rx.ReadMsgUDPAddrPort(small, nil)
		wp5CheckOSTruncation(t, n, len(small), flags, err)
		o := &OwnedUDP{peer: wp5AP(raw), limit: maxDatagram, recv: maxDatagram - 9}
		if data, _, ev, rerr := o.readResult(small, n, flags, src, err); ev != ReadTruncated || data != nil || rerr != nil {
			t.Fatalf("the OS truncation maps to event %d, %d bytes, %v; want ReadTruncated", ev, len(data), rerr)
		}
		s := &OwnedUDPSocket{limit: maxDatagram}
		if _, _, ev, rerr := s.readResult(small, n, flags, src, err); ev != ReadTruncated || rerr != nil {
			t.Fatalf("listener: the OS truncation maps to event %d, %v; want ReadTruncated", ev, rerr)
		}
	})
}

// TestOwnedUDPEnvelope_L58: the dialer token writes the frozen flow header
// (M2 design §A3.4) in front of the rendr bytes and hands over only
// datagrams of its own flow from exactly its peer, on IPv4 and IPv6: an
// empty datagram or the header alone is ReadEmpty, a short header, another
// version or another flow ReadBadEnvelope (L58), any other source
// ReadForeign (L59: the dialer drops foreign sources) — each dropped
// without ending the reads. An IPv4-mapped peer compares as IPv4. The
// net.PacketConn view (diagnostics) strips and adds the header.
func TestOwnedUDPEnvelope_L58(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			defer g10NoLeak(t)()
			raw, ok := wp5Listen(t, network)
			if !ok {
				return
			}
			defer raw.Close()
			foreign, _ := wp5Listen(t, network)
			defer foreign.Close()
			du, _ := wp5Listen(t, network)
			peer := wp5AP(raw)
			given := peer
			if network == "udp4" {
				given = netip.AddrPortFrom(netip.AddrFrom16(peer.Addr().As16()), peer.Port()) // IPv4-mapped
			}
			o := NewOwnedUDP(du, given, wp5Flow, wp5MaxDatagram)
			defer o.Close()
			wp5Envelope(t, o, raw, foreign, peer)
		})
	}
}

// wp5Envelope runs TestOwnedUDPEnvelope_L58's rows for the dialer token o
// whose peer is raw.
func wp5Envelope(t *testing.T, o *OwnedUDP, raw, foreign *net.UDPConn, peer netip.AddrPort) {
	dst := wp5AP(o)
	buf := make([]byte, o.ReadSize())

	// The written header, whatever b[:9] held before.
	b := append(bytes.Repeat([]byte{0xee}, 9), "rendr bytes"...)
	if err := o.WriteDatagram(b); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, 100)
	n, from, err := raw.ReadFromUDPAddrPort(got)
	if err != nil || from != dst || !bytes.Equal(got[:n], append(wp5Header(wp5Flow), "rendr bytes"...)) {
		t.Fatalf("the peer read % x from %v (%v), want header ‖ rendr bytes from %v", got[:n], from, err, dst)
	}

	header := wp5Header(wp5Flow)
	other := wp5Header(wp5Flow + 1)
	version := wp5Header(wp5Flow)
	version[0] = 3
	rows := []struct {
		name string
		from *net.UDPConn
		d    []byte
		ev   ReadEvent
	}{
		{"empty", raw, nil, ReadEmpty},
		{"header only", raw, header, ReadEmpty},
		{"short header", raw, header[:5], ReadBadEnvelope},
		{"version 3", raw, append(version, 1, 2, 3), ReadBadEnvelope},
		{"another flow", raw, append(other, 1, 2, 3), ReadBadEnvelope},
		{"foreign source", foreign, append(wp5Header(wp5Flow), 1, 2, 3), ReadForeign},
		{"valid", raw, append(wp5Header(wp5Flow), 1, 2, 3), ReadOK},
	}
	for _, r := range rows {
		wp5Send(t, r.from, r.d, dst)
		data, key, ev := wp5Read(t, o, buf)
		if ev != r.ev {
			t.Fatalf("%s: event %d, want %d", r.name, ev, r.ev)
		}
		if key.AP != wp5AP(r.from) {
			t.Fatalf("%s: source %v, want %v", r.name, key.AP, wp5AP(r.from))
		}
		if (ev == ReadOK) != (data != nil) || (ev == ReadOK && !bytes.Equal(data, []byte{1, 2, 3})) {
			t.Fatalf("%s: handed over % x", r.name, data)
		}
	}

	// The net.PacketConn view: ReadFrom skips what ReadDatagram drops and
	// returns the rendr bytes from the peer's address; WriteTo adds the
	// header.
	wp5Send(t, foreign, append(wp5Header(wp5Flow), 9), dst)
	wp5Send(t, raw, append(other, 8), dst)
	wp5Send(t, raw, append(wp5Header(wp5Flow), "hello"...), dst)
	o.SetReadDeadline(time.Now().Add(10 * time.Second))
	p := make([]byte, 16)
	n, addr, err := o.ReadFrom(p)
	if err != nil || string(p[:n]) != "hello" || addr.(*net.UDPAddr).AddrPort() != peer {
		t.Fatalf("ReadFrom = %q from %v, %v; want \"hello\" from %v", p[:n], addr, err, peer)
	}
	if n, err := o.WriteTo([]byte("world"), net.UDPAddrFromAddrPort(peer)); n != 5 || err != nil {
		t.Fatalf("WriteTo = %d, %v", n, err)
	}
	n, _, err = raw.ReadFromUDPAddrPort(got)
	if err != nil || !bytes.Equal(got[:n], append(wp5Header(wp5Flow), "world"...)) {
		t.Fatalf("WriteTo sent % x, %v", got[:n], err)
	}
	if _, err := o.WriteTo([]byte("x"), &net.TCPAddr{}); err == nil {
		t.Fatal("WriteTo accepted a non-UDP address")
	}
}
