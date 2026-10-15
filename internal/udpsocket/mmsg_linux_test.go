//go:build linux && (amd64 || arm64)

package udpsocket

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The real-kernel rows of WP1 (§A10.1): sendmmsg and recvmmsg on loopback
// sockets through the Go netpoller. They run on the Linux lanes (race,
// non-race at -cpu 1,4, sweep) of I1; the Windows host compiles them.

// TestMmsgHdrLayout: mmsghdr matches the kernel's struct mmsghdr on the
// accelerated targets.
func TestMmsgHdrLayout(t *testing.T) {
	var h mmsghdr
	if s, o := unsafe.Sizeof(h), unsafe.Offsetof(h.len); s != 64 || o != 56 || unsafe.Sizeof(h.hdr) != 56 {
		t.Fatalf("mmsghdr: size %d, len at %d, msghdr %d; want 64, 56, 56", s, o, unsafe.Sizeof(h.hdr))
	}
	if unsafe.Sizeof(unix.RawSockaddrInet6{}) != unix.SizeofSockaddrInet6 || unix.SizeofSockaddrInet4 > unix.SizeofSockaddrInet6 {
		t.Fatal("sockaddr sizes")
	}
	b := NewBatch(3)
	for i := range b.sys.hdrs {
		if h := b.sys.hdrs[i].hdr; h.Iov != &b.sys.iovs[i] || h.Iovlen != 1 {
			t.Fatalf("header %d: iov %p len %d; want iovec %d, 1", i, h.Iov, h.Iovlen, i)
		}
	}
}

// TestMmsgProbeReal (M5-D15): on the lane's kernel (no sandbox) both fd −1
// calls fail with EBADF, so sockets start in ModeBatch; MaxBatch 1 stays
// plain.
func TestMmsgProbeReal(t *testing.T) {
	seams(t)
	if s, r := probe(callSend), probe(callRecv); s != syscall.EBADF || r != syscall.EBADF {
		t.Fatalf("probe: %v, %v; want EBADF, EBADF", s, r)
	}
	if c := newConn(t, listen4(t), 32, nil); c.Mode() != ModeBatch {
		t.Fatalf("mode %v; want batch", c.Mode())
	}
	if c := newConn(t, listen4(t), 1, nil); c.Mode() != ModePlain {
		t.Fatalf("MaxBatch 1: mode %v", c.Mode())
	}
}

// TestMmsgSendOrder: 64 datagrams in one WriteBatch leave in one sendmmsg
// call and arrive in order; a batched read returns them in order with
// their source.
func TestMmsgSendOrder(t *testing.T) {
	seams(t)
	rxu, txu := listen4(t), listen4(t)
	var ctr Counters
	tx := newConn(t, txu, 64, &ctr)
	if n, err := tx.WriteBatch(NewBatch(64), msgs(addrOf(rxu), 0, 64)); n != 64 || err != nil {
		t.Fatalf("WriteBatch: %d, %v", n, err)
	}
	if sc, s, _, _, _ := ctr.Load(); sc != 1 || s != 64 {
		t.Fatalf("%s; want one call of 64", counters(&ctr))
	}
	var rctr Counters
	rx := newConn(t, rxu, 64, &rctr)
	rxu.SetReadDeadline(time.Now().Add(10 * time.Second))
	rs := slots(64, 64)
	b := NewBatch(64)
	var got []string
	for len(got) < 64 {
		n, err := rx.ReadBatch(b, rs)
		if err != nil {
			t.Fatalf("ReadBatch after %d: %v", len(got), err)
		}
		for _, m := range rs[:n] {
			if m.Addr != addrOf(txu) || m.Trunc {
				t.Fatalf("datagram %d: %+v; want from %v, whole", len(got), m, addrOf(txu))
			}
			got = append(got, string(m.Buf[:m.N]))
		}
	}
	if !eqStrings(got, seq(0, 64)) {
		t.Fatalf("received %q; want 0 … 63 in order", got)
	}
	if _, _, rc, rd, _ := rctr.Load(); rd != 64 || rc < 1 || rc > 64 {
		t.Fatalf("%s", counters(&rctr))
	}
}

// TestMmsgPartialEAGAIN (R1-9): on a real loopback socket the sendmmsg
// seam writes 7 of 16 for real, then reports EAGAIN once (loopback never
// fills a send buffer), then writes the rest for real. The callback
// returns to the netpoller once and is woken by the socket's writability;
// every datagram arrives once and in order, in 2 counted calls.
func TestMmsgPartialEAGAIN(t *testing.T) {
	seams(t)
	rxu, txu := listen4(t), listen4(t)
	var ctr Counters
	tx := newConn(t, txu, 32, &ctr)
	txu.SetWriteDeadline(time.Now().Add(10 * time.Second)) // a lost wake fails, never hangs
	calls, eagain := 0, 0
	sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) {
		calls++
		switch calls {
		case 1:
			return sendmmsg(fd, b, k, min(n, 7))
		case 2:
			eagain++
			return 0, syscall.EAGAIN
		}
		return sendmmsg(fd, b, k, n)
	}
	if n, err := tx.WriteBatch(NewBatch(32), msgs(addrOf(rxu), 0, 16)); n != 16 || err != nil {
		t.Fatalf("WriteBatch: %d, %v", n, err)
	}
	if got := collect(t, rxu, 16); !eqStrings(got, seq(0, 16)) {
		t.Fatalf("received %q; want 0 … 15 once, in order", got)
	}
	expectNone(t, rxu, 20*time.Millisecond)
	if sc, s, _, _, _ := ctr.Load(); sc != 2 || s != 16 || eagain != 1 || calls != 3 {
		t.Fatalf("%s, %d EAGAIN, %d seam calls; want 2 calls, 16 datagrams, 1, 3", counters(&ctr), eagain, calls)
	}
}

// TestMmsgErrorIndex_L42: a batch whose 5th datagram exceeds what the
// route carries (more than an IPv4 UDP payload): n = 4 with EMSGSIZE for
// message 4 — the kernel reports it at the second call — and the first 4
// arrived. A count outside the range asked, through the seam, is
// ErrInvalidCount at the message the call started from.
func TestMmsgErrorIndex_L42(t *testing.T) {
	seams(t)
	rxu, txu := listen4(t), listen4(t)
	var ctr Counters
	tx := newConn(t, txu, 32, &ctr)
	ms := msgs(addrOf(rxu), 0, 8)
	ms[4].Buf = make([]byte, 65508)
	b := NewBatch(32)
	n, err := tx.WriteBatch(b, ms)
	if n != 4 || errno(err) != syscall.EMSGSIZE {
		t.Fatalf("WriteBatch: n %d, err %v; want 4 and EMSGSIZE", n, err)
	}
	if n, err := tx.WriteBatch(b, ms[5:]); n != 3 || err != nil {
		t.Fatalf("WriteBatch of 5 … 7: %d, %v", n, err)
	}
	if got := collect(t, rxu, 7); !eqStrings(got, []string{"0", "1", "2", "3", "5", "6", "7"}) {
		t.Fatalf("received %q", got)
	}
	if sc, s, _, _, _ := ctr.Load(); sc != 2 || s != 7 {
		t.Fatalf("%s; want 2 calls, 7 datagrams", counters(&ctr))
	}
	sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) { return n + 1, nil }
	if n, err := tx.WriteBatch(b, msgs(addrOf(rxu), 0, 4)); n != 0 || !errors.Is(err, ErrInvalidCount) {
		t.Fatalf("count above n: %d, %v", n, err)
	}
}

// TestMmsgCountChecks_L42: the per-message checks of the Linux calls — a
// datagram reported sent with another length ends the count before it
// with ErrInvalidCount; a receive count outside [1, n] or a length beyond
// its slot is ErrInvalidCount.
func TestMmsgCountChecks_L42(t *testing.T) {
	b := NewBatch(4)
	b.ms = msgs(netip.MustParseAddrPort("127.0.0.1:9"), 0, 4)
	for i := range b.ms {
		b.sys.hdrs[i].len = uint32(len(b.ms[i].Buf))
	}
	if cnt, err := b.sys.sent(b, 0, 4, 4); cnt != 4 || err != nil {
		t.Fatalf("whole datagrams: %d, %v", cnt, err)
	}
	b.sys.hdrs[2].len = 0
	if cnt, err := b.sys.sent(b, 0, 4, 4); cnt != 2 || err != ErrInvalidCount {
		t.Fatalf("message 2 short: %d, %v; want 2, ErrInvalidCount", cnt, err)
	}
	b.ms = slots(4, 8)
	b.sys.prepRecv(b.ms)
	for _, cnt := range []int{0, 5, -1} {
		if _, err := b.sys.received(b, cnt, 4); err != ErrInvalidCount {
			t.Fatalf("receive count %d: %v", cnt, err)
		}
	}
	b.sys.hdrs[1].len = 9
	if _, err := b.sys.received(b, 2, 4); err != ErrInvalidCount {
		t.Fatalf("length beyond the slot: %v", err)
	}
}

// TestMmsgDeadlines_L06: deadlines keep their net.Conn meaning through
// RawConn: an expired read or write deadline fails at once; a read
// deadline expiring while the reader is parked wakes it with a timeout,
// as does one set while it is parked; a datagram wakes a parked batched
// reader (a Conn's and a Reader's); a write stalled in EAGAIN ends at its
// deadline with the messages before it reported sent.
func TestMmsgDeadlines_L06(t *testing.T) {
	seams(t)
	rxu, txu := listen4(t), listen4(t)
	rx := newConn(t, rxu, 32, nil)
	tx := newConn(t, txu, 32, nil)
	b := NewBatch(32)
	rs := slots(32, 64)
	timeout := func(err error) bool {
		var ne net.Error
		return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
	}

	rxu.SetReadDeadline(time.Now().Add(-time.Second))
	if n, err := rx.ReadBatch(b, rs); n != 0 || !timeout(err) {
		t.Fatalf("expired read deadline: %d, %v", n, err)
	}
	start := time.Now()
	rxu.SetReadDeadline(start.Add(100 * time.Millisecond))
	if n, err := rx.ReadBatch(b, rs); n != 0 || !timeout(err) || time.Since(start) < 90*time.Millisecond {
		t.Fatalf("read deadline: %d, %v after %v", n, err, time.Since(start))
	}
	rxu.SetReadDeadline(time.Time{})

	// Gates: the seam signals the reader's first EAGAIN (it is parking).
	parked := make(chan struct{}, 1)
	recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) {
		cnt, err := recvmmsg(fd, b, n)
		if err == syscall.EAGAIN {
			select {
			case parked <- struct{}{}:
			default:
			}
		}
		return cnt, err
	}
	type result struct {
		n   int
		err error
	}
	drain := func() {
		select {
		case <-parked:
		default:
		}
	}
	done := make(chan result, 1)
	drain()
	go func() { n, err := rx.ReadBatch(b, rs); done <- result{n, err} }()
	<-parked
	rxu.SetReadDeadline(time.Now())
	if r := <-done; r.n != 0 || !timeout(r.err) {
		t.Fatalf("deadline set while parked: %+v", r)
	}
	rxu.SetReadDeadline(time.Time{})

	for _, rd := range []struct {
		name string
		read func() (int, error)
	}{
		{"Conn", func() (int, error) { return rx.ReadBatch(b, rs) }},
		{"Reader", func() func() (int, error) {
			r := NewReader(rx, func(*Batch) {})
			r.Hold(NewBatch(32))
			return func() (int, error) { return r.ReadBatch(rs) }
		}()},
	} {
		drain()
		go func() { n, err := rd.read(); done <- result{n, err} }()
		<-parked
		if _, err := txu.WriteToUDPAddrPort([]byte("wake"), addrOf(rxu)); err != nil {
			t.Fatal(err)
		}
		if r := <-done; r.n != 1 || r.err != nil || string(rs[0].Buf[:rs[0].N]) != "wake" {
			t.Fatalf("%s: a datagram while parked: %+v", rd.name, r)
		}
	}

	txu.SetWriteDeadline(time.Now().Add(-time.Second))
	if n, err := tx.WriteBatch(b, msgs(addrOf(rxu), 0, 8)); n != 0 || !timeout(err) {
		t.Fatalf("expired write deadline: %d, %v", n, err)
	}
	expectNone(t, rxu, 20*time.Millisecond)
	sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) {
		if k == 0 {
			return sendmmsg(fd, b, k, min(n, 3))
		}
		return 0, syscall.EAGAIN // a full send buffer that never drains
	}
	start = time.Now()
	txu.SetWriteDeadline(start.Add(100 * time.Millisecond))
	if n, err := tx.WriteBatch(b, msgs(addrOf(rxu), 0, 8)); n != 3 || !timeout(err) || time.Since(start) < 90*time.Millisecond {
		t.Fatalf("stalled write: %d, %v after %v; want 3 and the deadline", n, err, time.Since(start))
	}
	if got := collect(t, rxu, 3); !eqStrings(got, seq(0, 3)) {
		t.Fatalf("received %q", got)
	}
}

// TestMmsgTruncation_L42: M2's truncation rule in a batch: the slot is
// one byte longer than the limit; a datagram that fills it (MSG_TRUNC, or
// exactly the slot's length) is Trunc and the batch continues.
func TestMmsgTruncation_L42(t *testing.T) {
	seams(t)
	rxu, txu := listen4(t), listen4(t)
	rx := newConn(t, rxu, 32, nil)
	sizes := []int{10, 2000, 10, 1001, 1000}
	for i, s := range sizes {
		p := make([]byte, s)
		p[0] = byte(i)
		if _, err := txu.WriteToUDPAddrPort(p, addrOf(rxu)); err != nil {
			t.Fatal(err)
		}
	}
	rxu.SetReadDeadline(time.Now().Add(10 * time.Second))
	rs := slots(8, 1001)
	b := NewBatch(8)
	var got []Msg
	for len(got) < len(sizes) {
		n, err := rx.ReadBatch(b, rs)
		if err != nil {
			t.Fatalf("ReadBatch after %d: %v", len(got), err)
		}
		for _, m := range rs[:n] {
			got = append(got, Msg{N: m.N, Trunc: m.Trunc, Buf: []byte{m.Buf[0]}})
		}
	}
	want := []struct {
		n     int
		trunc bool
	}{{10, false}, {1001, true}, {10, false}, {1001, true}, {1000, false}}
	for i, w := range want {
		if got[i].N != w.n || got[i].Trunc != w.trunc || got[i].Buf[0] != byte(i) {
			t.Fatalf("datagram %d: N %d Trunc %v first byte %d; want %d %v %d", i, got[i].N, got[i].Trunc, got[i].Buf[0], w.n, w.trunc, i)
		}
	}
}

// TestMmsgAddrFamilies: destinations and sources on IPv4, IPv6 and
// dual-stack sockets are encoded and decoded as the net package does
// (an IPv4-mapped destination on an IPv4 socket is unmapped; an IPv4 peer
// of a dual-stack socket reads as IPv4-mapped, exactly as
// ReadMsgUDPAddrPort returns it); an address the socket cannot send to is
// that message's error, shaped as the plain path's; decoding allocates
// nothing.
func TestMmsgAddrFamilies(t *testing.T) {
	seams(t)
	listen := func(network, addr string) *net.UDPConn {
		t.Helper()
		u, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
		if err != nil {
			t.Fatalf("%s %s: %v (the Linux lanes need IPv6 loopback)", network, addr, err)
		}
		t.Cleanup(func() { u.Close() })
		return u
	}
	// read returns the next want datagrams of u, read in batches.
	read := func(u *net.UDPConn, want int) []Msg {
		t.Helper()
		c := newConn(t, u, 32, nil)
		u.SetReadDeadline(time.Now().Add(10 * time.Second))
		var got []Msg
		for len(got) < want {
			rs := slots(max(2, want-len(got)), 64) // at least 2: a one-slot read is plain
			n, err := c.ReadBatch(NewBatch(32), rs)
			if n < 1 || err != nil {
				t.Fatalf("ReadBatch after %d: %d, %v", len(got), n, err)
			}
			got = append(got, rs[:n]...)
		}
		return got
	}

	v4a, v4b := listen("udp4", "127.0.0.1:0"), listen("udp4", "127.0.0.1:0")
	c4 := newConn(t, v4a, 32, nil)
	ms := []Msg{
		{Buf: []byte("a"), Addr: addrOf(v4b)},
		{Buf: []byte("b"), Addr: netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), addrOf(v4b).Port())},
		{Buf: []byte("c"), Addr: netip.MustParseAddrPort("[::1]:9")},
	}
	n, err := c4.WriteBatch(NewBatch(4), ms)
	var ae *net.AddrError
	var oe *net.OpError
	if n != 2 || !errors.As(err, &ae) || !errors.As(err, &oe) || oe.Op != "write" {
		t.Fatalf("IPv4 socket: n %d, err %#v; want 2 and the address error wrapped as WriteToUDPAddrPort wraps it", n, err)
	}
	// The same shape as the plain path's (the Net field aside: a UDPConn
	// does not say whether it was opened as "udp" or "udp4").
	_, perr := v4a.WriteToUDPAddrPort([]byte("c"), ms[2].Addr)
	var pae *net.AddrError
	var poe *net.OpError
	if !errors.As(perr, &poe) || !errors.As(perr, &pae) || *pae != *ae || poe.Op != oe.Op || poe.Addr.String() != oe.Addr.String() || poe.Source.String() != oe.Source.String() {
		t.Fatalf("batch error %#v; the plain path returns %#v", err, perr)
	}
	// A batch whose first message cannot be addressed sends nothing and
	// returns the same shape (the error before any sendmmsg).
	n, err = c4.WriteBatch(NewBatch(4), []Msg{ms[2], ms[0]})
	var fae *net.AddrError
	var foe *net.OpError
	if n != 0 || !errors.As(err, &foe) || !errors.As(err, &fae) || *fae != *pae || foe.Op != poe.Op || foe.Addr.String() != poe.Addr.String() {
		t.Fatalf("first message unaddressable: n %d, err %#v; want 0 and %#v", n, err, perr)
	}
	for i, m := range read(v4b, 2) {
		if want := []string{"a", "b"}[i]; string(m.Buf[:m.N]) != want || m.Addr != addrOf(v4a) {
			t.Fatalf("IPv4: %q from %v; want %q from %v", m.Buf[:m.N], m.Addr, want, addrOf(v4a))
		}
	}

	v6a, v6b := listen("udp6", "[::1]:0"), listen("udp6", "[::1]:0")
	c6 := newConn(t, v6a, 32, nil)
	if n, err := c6.WriteBatch(NewBatch(4), msgs(addrOf(v6b), 0, 2)); n != 2 || err != nil {
		t.Fatalf("IPv6: %d, %v", n, err)
	}
	for _, m := range read(v6b, 2) {
		if m.Addr != addrOf(v6a) {
			t.Fatalf("IPv6 source %v; want %v", m.Addr, addrOf(v6a))
		}
	}

	dual := listen("udp", "[::]:0")
	dualPort := addrOf(dual).Port()
	cd := newConn(t, dual, 32, nil)
	v4c := listen("udp4", "127.0.0.1:0")
	if n, err := cd.WriteBatch(NewBatch(4), msgs(addrOf(v4c), 0, 2)); n != 2 || err != nil {
		t.Fatalf("dual-stack to IPv4: %d, %v", n, err)
	}
	for _, m := range read(v4c, 2) {
		if m.Addr.Port() != dualPort || !m.Addr.Addr().Is4() {
			t.Fatalf("IPv4 peer of the dual-stack socket saw %v", m.Addr)
		}
	}
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dualPort)
	if _, err := v4c.WriteToUDPAddrPort([]byte("p"), to); err != nil {
		t.Fatal(err)
	}
	if _, err := v4c.WriteToUDPAddrPort([]byte("q"), to); err != nil {
		t.Fatal(err)
	}
	dual.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 16)
	_, _, _, plain, err := dual.ReadMsgUDPAddrPort(buf, nil) // "p", as the net package reports its source
	if err != nil {
		t.Fatal(err)
	}
	if m := read(dual, 1)[0]; m.Addr != plain || !m.Addr.Addr().Is4In6() || string(m.Buf[:m.N]) != "q" {
		t.Fatalf("dual-stack source %v (%q); want %v as ReadMsgUDPAddrPort reports it", m.Addr, m.Buf[:m.N], plain)
	}

	for _, ap := range []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1"),
		netip.MustParseAddrPort("198.51.100.3:65535"),
		netip.MustParseAddrPort("[::1]:4660"),
		netip.MustParseAddrPort("[2001:db8::7]:32768"),
		netip.MustParseAddrPort("[::ffff:192.0.2.1]:80"),
	} {
		var sa unix.RawSockaddrInet6
		fam := unix.AF_INET6
		if ap.Addr().Is4() {
			fam = unix.AF_INET
		}
		if _, err := encodeAddr(&sa, fam, ap); err != nil {
			t.Fatalf("encode %v: %v", ap, err)
		}
		if p := (*[2]byte)(unsafe.Pointer(&sa.Port)); uint16(p[0])<<8|uint16(p[1]) != ap.Port() {
			t.Fatalf("%v: port bytes %v not in network order", ap, p)
		}
		if got := decodeAddr(&sa); got != ap {
			t.Fatalf("round trip %v → %v", ap, got)
		}
		if a := testing.AllocsPerRun(100, func() { _ = decodeAddr(&sa) }); a != 0 && !raceEnabled {
			t.Fatalf("decoding %v: %v allocations", ap, a)
		}
	}
	if _, err := encodeAddr(new(unix.RawSockaddrInet6), unix.AF_INET6, netip.AddrPort{}); err == nil {
		t.Fatal("encoding the zero address: no error")
	}
}

// TestMmsgZonedAddr (L41, L55): a zoned IPv6 source decodes as the net
// package names it (the interface's name; an unknown scope's decimal
// index) and a zoned destination encodes its interface's index, through
// the zone table: after warm-up neither allocates nor dumps the
// interfaces. A batch to a zoned destination goes out through sendmmsg.
func TestMmsgZonedAddr(t *testing.T) {
	seams(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("the Linux lanes have lo: %v", err)
	}
	var fetches int
	interfacesFn = func() ([]net.Interface, error) {
		fetches++
		return net.Interfaces()
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone(lo.Name), 4660)
	var sa unix.RawSockaddrInet6
	if _, err := encodeAddr(&sa, unix.AF_INET6, want); err != nil || sa.Scope_id != uint32(lo.Index) {
		t.Fatalf("encode %v: scope %d, %v; want %d", want, sa.Scope_id, err, lo.Index)
	}
	if got := decodeAddr(&sa); got != want {
		t.Fatalf("decode: %v; want %v", got, want)
	}
	unknown := sa
	unknown.Scope_id = 999999
	if got := decodeAddr(&unknown); got.Addr().Zone() != "999999" {
		t.Fatalf("unknown scope decoded as %v; want zone 999999", got)
	}
	for range 1000 {
		decodeAddr(&sa)
		encodeAddr(&sa, unix.AF_INET6, want)
	}
	if fetches > 2 { // the first lookup, and at most one miss (999999)
		t.Fatalf("%d interface fetches for 2,000 zoned lookups", fetches)
	}
	if !raceEnabled {
		if a := testing.AllocsPerRun(100, func() { decodeAddr(&sa); encodeAddr(&sa, unix.AF_INET6, want) }); a != 0 {
			t.Fatalf("%v allocations per zoned encode and decode", a)
		}
	}

	// A real batch to [::1%lo]: the scope is ignored for a non-link-local
	// address, so it arrives.
	u6a, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("the Linux lanes need IPv6 loopback: %v", err)
	}
	defer u6a.Close()
	u6b, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer u6b.Close()
	c := newConn(t, u6a, 32, nil)
	dst := netip.AddrPortFrom(addrOf(u6b).Addr().WithZone(lo.Name), addrOf(u6b).Port())
	if n, err := c.WriteBatch(NewBatch(4), msgs(dst, 0, 3)); n != 3 || err != nil {
		t.Fatalf("WriteBatch to %v: %d, %v", dst, n, err)
	}
	if got := collect(t, u6b, 3); !eqStrings(got, seq(0, 3)) {
		t.Fatalf("received %q", got)
	}
}
