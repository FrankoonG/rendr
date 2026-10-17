package rendrtest

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The contract of UDPSocketHub (M6 design §A2.3, §A16.1 row WP3): the
// socket demultiplexes by source and replies to exactly the addressed
// client; boundaries kept; zero-length datagrams; read injection; queue
// bounds per client and direction; source reuse after a client's Close;
// deadlines, Close and counters; durable blocking inside a synctest
// bubble; no allocation in steady state.

// udpSocket is l4.UDPSocket's method set (rendrtest imports no l4: the hub
// socket satisfies it structurally, and l4's tests assert the real one).
type udpSocket interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	LocalAddr() net.Addr
	SetReadDeadline(t time.Time) error
	Close() error
}

var _ udpSocket = (*HubSocket)(nil)

// hubSrc is client source k: a documentation address and a distinct port.
func hubSrc(k int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), uint16(20000+k))
}

// hubRecv reads one datagram from s.
func hubRecv(t *testing.T, s *HubSocket) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 64<<10)
	n, src, err := s.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort: %v", err)
	}
	return buf[:n], src
}

// hubQuiet asserts that nothing is readable at s within d.
func hubQuiet(t *testing.T, s *HubSocket, d time.Duration) {
	t.Helper()
	s.SetReadDeadline(time.Now().Add(d))
	if n, src, err := s.ReadFromUDPAddrPort(make([]byte, 64<<10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFromUDPAddrPort = %d from %v, %v; want a timeout (nothing readable)", n, src, err)
	}
	s.SetReadDeadline(time.Time{})
}

func hubSend(t *testing.T, s *HubSocket, b []byte, to netip.AddrPort) {
	t.Helper()
	if n, err := s.WriteToUDPAddrPort(b, to); n != len(b) || err != nil {
		t.Fatalf("WriteToUDPAddrPort(%d bytes, %v) = %d, %v", len(b), to, n, err)
	}
}

type hubResult struct {
	b   []byte
	src netip.AddrPort
	err error
	at  time.Time
}

func hubReadAsync(s *HubSocket) <-chan hubResult {
	ch := make(chan hubResult, 1)
	go func() {
		buf := make([]byte, 64<<10)
		n, src, err := s.ReadFromUDPAddrPort(buf)
		ch <- hubResult{buf[:n], src, err, time.Now()}
	}()
	return ch
}

func hubBlocked(t *testing.T, ch <-chan hubResult) {
	t.Helper()
	synctest.Wait()
	select {
	case r := <-ch:
		t.Fatalf("ReadFromUDPAddrPort returned %d bytes, %v; want it blocked", len(r.b), r.err)
	default:
	}
}

func TestUDPSocketHubContract(t *testing.T) {
	// 64 clients at once: the socket reads every datagram with its
	// client's source; a reply to a source reaches that client and no
	// other.
	t.Run("demux-by-source", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const clients, per = 64, 3
			h := NewUDPSocketHub(UDPSocketHubConfig{})
			s := h.Socket()
			cs := make([]*DatagramConn, clients)
			for i := range cs {
				cs[i] = h.Client(hubSrc(i))
			}
			for k := range per {
				for i, c := range cs {
					dpWrite(t, c, dpData(byte(i), k, 40+i))
				}
			}
			var srcs []netip.AddrPort
			for range clients * per {
				d, src := hubRecv(t, s)
				i, k := dpKey(d)
				if src != hubSrc(int(i)) || !bytes.Equal(d, dpData(i, k, 40+int(i))) {
					t.Fatalf("datagram of client %d from %v; want it intact from %v", i, src, hubSrc(int(i)))
				}
				srcs = append(srcs, src)
			}
			hubQuiet(t, s, time.Millisecond)
			for k, src := range srcs { // every reply after every read: a socket that answered its last source would fail
				i := int(src.Port()) - 20000
				hubSend(t, s, dpData(byte(i), 100+k, 30), src)
			}
			for i, c := range cs {
				c.SetReadDeadline(time.Now().Add(time.Second)) // a misrouted reply fails here
				for range per {
					if tag, _ := dpKey(dpRecv(t, c)); int(tag) != i {
						t.Fatalf("client %d got client %d's reply", i, tag)
					}
				}
				dpQuiet(t, c, time.Millisecond)
			}
			got := h.Counts()
			if got.Reads != clients*per || got.Writes != clients*per || got.Dropped != 0 || len(got.Clients) != clients {
				t.Fatalf("Counts = reads %d, writes %d, dropped %d, %d clients", got.Reads, got.Writes, got.Dropped, len(got.Clients))
			}
			for i := range cs {
				if c := got.Clients[hubSrc(i)]; c != (DatagramConnCounts{In: per, Out: per}) {
					t.Fatalf("client %d counts %+v", i, c)
				}
			}
		})
	})

	// Boundaries and zero-length datagrams both ways; the caller's buffer
	// is copied.
	t.Run("boundaries", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sizes := []int{0, 1, 5, 1400, 9000, 65507}
			h := NewUDPSocketHub(UDPSocketHubConfig{})
			s, c := h.Socket(), h.Client(hubSrc(1))
			scratch := make([]byte, 64<<10)
			for k, n := range sizes {
				dpWrite(t, c, append(scratch[:0], dpData(1, k, n)...))
			}
			clear(scratch)
			for k, n := range sizes {
				if d, src := hubRecv(t, s); !bytes.Equal(d, dpData(1, k, n)) || src != hubSrc(1) {
					t.Fatalf("datagram %d: %d bytes from %v; want %d intact from %v", k, len(d), src, n, hubSrc(1))
				}
			}
			for k, n := range sizes {
				hubSend(t, s, append(scratch[:0], dpData(2, k, n)...), hubSrc(1))
			}
			clear(scratch)
			for k, n := range sizes {
				if d := dpRecv(t, c); !bytes.Equal(d, dpData(2, k, n)) {
					t.Fatalf("reply %d: %d bytes; want %d intact", k, len(d), n)
				}
			}
			long := dpData(3, 0, 100)
			dpWrite(t, c, long)
			dpWrite(t, c, []byte("next"))
			buf := make([]byte, 10)
			if n, src, err := s.ReadFromUDPAddrPort(buf); n != 10 || err != nil || src != hubSrc(1) || !bytes.Equal(buf, long[:10]) {
				t.Fatalf("truncated socket read = %d from %v, %v; want 10 bytes, nil (Linux truncation)", n, src, err)
			}
			if d, _ := hubRecv(t, s); string(d) != "next" {
				t.Fatalf("after a truncated read: %q; want the next datagram", d)
			}
		})
	})

	// The socket is unconnected (RemoteAddr is an untyped nil, as a
	// connected-socket check through interface{ RemoteAddr() net.Addr }
	// needs) and loopback by default; a client's addresses are its source
	// and the socket's.
	t.Run("addresses", func(t *testing.T) {
		h := NewUDPSocketHub(UDPSocketHubConfig{})
		var rc interface{ RemoteAddr() net.Addr } = h.Socket()
		if rc.RemoteAddr() != nil {
			t.Fatalf("RemoteAddr = %#v; want nil", rc.RemoteAddr())
		}
		u, ok := h.Socket().LocalAddr().(*net.UDPAddr)
		if !ok || !u.IP.IsLoopback() || u.Port == 0 || u.Network() != "udp" {
			t.Fatalf("default LocalAddr = %#v; want a loopback *net.UDPAddr", h.Socket().LocalAddr())
		}
		at := netip.MustParseAddrPort("[2001:db8::1]:5353")
		h2 := NewUDPSocketHub(UDPSocketHubConfig{Addr: at})
		c := h2.Client(hubSrc(2))
		if h2.Socket().LocalAddr().String() != at.String() || c.RemoteAddr() != h2.Socket().LocalAddr() {
			t.Fatalf("configured socket %v, client remote %v; want %v", h2.Socket().LocalAddr(), c.RemoteAddr(), at)
		}
		if cu, ok := c.LocalAddr().(*net.UDPAddr); !ok || cu.AddrPort() != hubSrc(2) {
			t.Fatalf("client LocalAddr = %#v; want %v", c.LocalAddr(), hubSrc(2))
		}
	})

	// InjectRead: the socket's next n reads return the error as given,
	// consuming nothing; it wakes a waiting read; a passed deadline comes
	// first; nil or n < 1 clears.
	t.Run("read-injection", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := NewUDPSocketHub(UDPSocketHubConfig{})
			s, c := h.Socket(), h.Client(hubSrc(3))
			e := errors.New("wsaeconnreset")
			dpWrite(t, c, []byte("d"))
			h.InjectRead(e, 3)
			buf := make([]byte, 16)
			for i := range 3 {
				if n, src, err := s.ReadFromUDPAddrPort(buf); n != 0 || src.IsValid() || err != e {
					t.Fatalf("injected read %d = %d from %v, %v; want 0, none, %v", i, n, src, err, e)
				}
			}
			if d, src := hubRecv(t, s); string(d) != "d" || src != hubSrc(3) {
				t.Fatal("the injected reads consumed the queued datagram")
			}
			h.InjectRead(e, 1)
			s.SetReadDeadline(time.Now())
			if _, _, err := s.ReadFromUDPAddrPort(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read past the deadline with an injection = %v; want the timeout first", err)
			}
			s.SetReadDeadline(time.Time{})
			if _, _, err := s.ReadFromUDPAddrPort(buf); err != e {
				t.Fatalf("the injection after the timeout = %v; want %v", err, e)
			}
			h.InjectRead(e, 5)
			h.InjectRead(nil, 5)
			h.InjectRead(e, 0)
			dpWrite(t, c, []byte("x"))
			if d, _ := hubRecv(t, s); string(d) != "x" {
				t.Fatal("a cleared injection still fired")
			}
			ch := hubReadAsync(s)
			hubBlocked(t, ch)
			h.InjectRead(e, 1)
			if r := <-ch; r.err != e {
				t.Fatalf("a waiting read woken by InjectRead returned %v; want %v", r.err, e)
			}
			if got := h.Counts(); got.Reads != 2 {
				t.Fatalf("Reads = %d; want 2 (injected reads move no datagram)", got.Reads)
			}
		})
	})

	// Queue bounds each client's datagrams toward the socket and the
	// socket's toward each client; beyond it a datagram is dropped and
	// counted; reading frees room.
	t.Run("queue-bounds", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := NewUDPSocketHub(UDPSocketHubConfig{Queue: 4})
			s, a, b := h.Socket(), h.Client(hubSrc(4)), h.Client(hubSrc(5))
			for k := range 10 {
				dpWrite(t, a, dpData(4, k, 20))
			}
			for k := range 4 {
				dpWrite(t, b, dpData(5, k, 20))
			}
			if got := h.Counts().Dropped; got != 6 {
				t.Fatalf("Dropped toward the socket = %d; want 6 (a's 4 + b's 4 fit: a bound per client)", got)
			}
			for range 8 {
				hubRecv(t, s)
			}
			hubQuiet(t, s, time.Millisecond)
			dpWrite(t, a, dpData(4, 10, 20))
			if d, src := hubRecv(t, s); src != hubSrc(4) || !bytes.Equal(d, dpData(4, 10, 20)) {
				t.Fatal("after reading, a's new datagram is not delivered")
			}
			for k := range 10 {
				hubSend(t, s, dpData(6, k, 20), hubSrc(4))
			}
			for k := range 4 {
				if d := dpRecv(t, a); !bytes.Equal(d, dpData(6, k, 20)) {
					t.Fatalf("reply %d is not the %dth sent (tail drop keeps the first ones)", k, k)
				}
			}
			dpQuiet(t, a, time.Millisecond)
			dpCounts(t, a, DatagramConnCounts{In: 4, Out: 11, Dropped: 6})
			if got := h.Counts(); got.Clients[hubSrc(4)] != a.Counts() || got.Writes != 10 || got.Reads != 9 {
				t.Fatalf("Counts = %+v", got)
			}
		})
	})

	// A closed client's source can be used again; what it sent before its
	// Close stays readable; replies to its source then go to nobody
	// (Dropped) until a new client takes it; its counters accumulate per
	// source. A second live client or an invalid source panics.
	t.Run("source-reuse", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := NewUDPSocketHub(UDPSocketHubConfig{})
			s, src := h.Socket(), hubSrc(6)
			c1 := h.Client(src)
			dpWrite(t, c1, []byte("before"))
			hubSend(t, s, []byte("unread"), src)
			if err := c1.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := c1.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("second Close = %v; want net.ErrClosed", err)
			}
			if _, err := c1.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Write after Close = %v", err)
			}
			if d, from := hubRecv(t, s); string(d) != "before" || from != src {
				t.Fatalf("got %q from %v; want the datagram sent before the Close", d, from)
			}
			hubSend(t, s, []byte("nobody"), src)
			c2 := h.Client(src)
			hubSend(t, s, []byte("new"), src)
			if d := dpRecv(t, c2); string(d) != "new" {
				t.Fatalf("the new client got %q; want only what was sent after it existed", d)
			}
			dpWrite(t, c2, []byte("again"))
			if d, from := hubRecv(t, s); string(d) != "again" || from != src {
				t.Fatalf("got %q from %v", d, from)
			}
			if got := h.Counts().Clients[src]; got != (DatagramConnCounts{In: 1, Out: 2, Dropped: 2}) {
				t.Fatalf("counts of %v = %+v; want both clients' sums (the unread one and the one to nobody dropped)", src, got)
			}
			expectHubPanic(t, func() { h.Client(src) })
			expectHubPanic(t, func() { h.Client(netip.AddrPort{}) })
		})
	})

	// A datagram to a source without a client is lost but the write
	// succeeds (UDP to a closed port); an invalid address fails the write.
	t.Run("write-to-nobody", func(t *testing.T) {
		h := NewUDPSocketHub(UDPSocketHubConfig{})
		s, to := h.Socket(), netip.MustParseAddrPort("203.0.113.9:53")
		hubSend(t, s, []byte("q"), to)
		if n, err := s.WriteToUDPAddrPort([]byte("q"), netip.AddrPort{}); n != 0 || err == nil {
			t.Fatalf("write to an invalid address = %d, %v; want an error", n, err)
		}
		if got := h.Counts(); got.Writes != 1 || got.Clients[to] != (DatagramConnCounts{Dropped: 1}) {
			t.Fatalf("Counts = %+v; want one write, dropped toward %v", got, to)
		}
	})

	// Deadlines as net.Conn on the socket: a timeout at the instant; a
	// stop deadline set while a read waits wakes it at once.
	t.Run("deadlines", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := NewUDPSocketHub(UDPSocketHubConfig{})
			s, c := h.Socket(), h.Client(hubSrc(7))
			t0 := time.Now()
			s.SetReadDeadline(t0.Add(40 * time.Millisecond))
			_, _, err := s.ReadFromUDPAddrPort(make([]byte, 8))
			var ne net.Error
			if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() || time.Since(t0) != 40*time.Millisecond {
				t.Fatalf("read = %v at %v; want a timeout at 40ms", err, time.Since(t0))
			}
			s.SetReadDeadline(time.Time{})
			ch := hubReadAsync(s)
			time.Sleep(10 * time.Millisecond)
			hubBlocked(t, ch)
			s.SetReadDeadline(time.Now())
			if r := <-ch; !errors.Is(r.err, os.ErrDeadlineExceeded) || r.at.Sub(t0) != 50*time.Millisecond {
				t.Fatalf("waiting read after the stop deadline = %v at %v; want a timeout at once", r.err, r.at.Sub(t0))
			}
			s.SetReadDeadline(time.Time{})
			ch = hubReadAsync(s)
			time.Sleep(10 * time.Millisecond)
			hubBlocked(t, ch)
			dpWrite(t, c, []byte("wake"))
			if r := <-ch; string(r.b) != "wake" || r.src != hubSrc(7) || r.at.Sub(t0) != 60*time.Millisecond {
				t.Fatalf("waiting read got %q from %v at %v; want the datagram at once", r.b, r.src, r.at.Sub(t0))
			}
		})
	})

	// Close of the socket: its waiting read returns at once, its later
	// calls fail; the clients' queued and later datagrams toward it are
	// dropped and counted; a second Close fails. Close of a client wakes
	// its waiting Read, and replies to it are then dropped. The hub starts
	// no goroutine: the bubble ends with the readers.
	t.Run("close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := NewUDPSocketHub(UDPSocketHubConfig{})
			s, c, d := h.Socket(), h.Client(hubSrc(8)), h.Client(hubSrc(9))
			rc := dpReadAsync(c)
			dpBlocked(t, rc)
			t0 := time.Now()
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if r := <-rc; !errors.Is(r.err, net.ErrClosed) || r.at != t0 {
				t.Fatalf("a client's waiting Read after its Close = %v", r.err)
			}
			hubSend(t, s, []byte("gone"), hubSrc(8))
			ch := hubReadAsync(s)
			hubBlocked(t, ch)
			dpWrite(t, d, []byte("first"))
			if r := <-ch; string(r.b) != "first" || r.src != hubSrc(9) || r.at != t0 {
				t.Fatalf("waiting read got %q from %v, %v; want the datagram at once", r.b, r.src, r.err)
			}
			for range 3 {
				dpWrite(t, d, []byte("queued"))
			}
			hubRecv(t, s)
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if _, _, err := s.ReadFromUDPAddrPort(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after Close = %v", err)
			}
			if _, err := s.WriteToUDPAddrPort([]byte("x"), hubSrc(9)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after Close = %v", err)
			}
			if err := s.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("SetReadDeadline after Close = %v", err)
			}
			if err := s.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("second Close = %v", err)
			}
			dpWrite(t, d, []byte("late")) // UDP to a closed port: the write succeeds
			got := h.Counts()
			if got.Reads != 2 || got.Dropped != 3 || got.Clients[hubSrc(8)].Dropped != 1 || got.Clients[hubSrc(9)].Out != 5 {
				t.Fatalf("Counts = %+v; want 2 reads, d's 2 queued and 1 late datagram dropped, the reply to the closed client dropped", got)
			}

			h2 := NewUDPSocketHub(UDPSocketHubConfig{})
			ch = hubReadAsync(h2.Socket())
			hubBlocked(t, ch)
			t1 := time.Now()
			h2.Socket().Close()
			if r := <-ch; !errors.Is(r.err, net.ErrClosed) || r.at != t1 {
				t.Fatalf("the waiting read after Close = %v; want net.ErrClosed at once", r.err)
			}
		})
	})

	// A client is a DatagramConn: its own injections and deadlines work as
	// a pipe end's.
	t.Run("client-conn", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := NewUDPSocketHub(UDPSocketHubConfig{})
			s, c := h.Socket(), h.Client(hubSrc(10))
			e := errors.New("econnrefused")
			c.InjectWrite(e, 1)
			if n, err := c.Write([]byte("x")); n != 0 || err != e {
				t.Fatalf("injected Write = %d, %v", n, err)
			}
			hubQuiet(t, s, time.Millisecond)
			c.Inject(e, true)
			hubSend(t, s, []byte("r"), hubSrc(10))
			for range 2 {
				if _, err := c.Read(make([]byte, 8)); err != e {
					t.Fatalf("injected Read = %v", err)
				}
			}
			c.Inject(nil, false)
			if d := dpRecv(t, c); string(d) != "r" {
				t.Fatalf("got %q", d)
			}
			dpCounts(t, c, DatagramConnCounts{In: 1, Injected: 3})
		})
	})

	// Outside any bubble: concurrent clients and an echoing socket keep
	// every datagram whole and addressed (the race detector's row). A lost
	// or misrouted echo fails at a client's 10-s read deadline; the socket
	// is closed at the end, which ends the echo loop.
	t.Run("real-clock-concurrent", func(t *testing.T) {
		const clients, per = 16, 200
		h := NewUDPSocketHub(UDPSocketHubConfig{})
		s := h.Socket()
		echo := make(chan error, 1)
		go func() {
			buf := make([]byte, 2048)
			for {
				n, src, err := s.ReadFromUDPAddrPort(buf)
				if err == nil {
					_, err = s.WriteToUDPAddrPort(buf[:n], src)
				}
				if err != nil {
					echo <- err
					return
				}
			}
		}()
		var wg sync.WaitGroup
		for i := range clients {
			c := h.Client(hubSrc(100 + i))
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			wg.Go(func() {
				buf := make([]byte, 2048)
				for k := range per {
					want := dpData(byte(i), k, 64+k%9)
					if _, err := c.Write(want); err != nil {
						t.Errorf("Write: %v", err)
						return
					}
					if n, err := c.Read(buf); err != nil || !bytes.Equal(buf[:n], want) {
						t.Errorf("client %d: echo %d = %d bytes, %v; want it intact", i, k, n, err)
						return
					}
				}
			})
		}
		wg.Wait()
		s.Close()
		if err := <-echo; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("echo: %v; want it ended by the Close", err)
		}
		if got := h.Counts(); got.Reads != clients*per || got.Writes != clients*per || got.Dropped != 0 {
			t.Fatalf("Counts = %+v", got)
		}
	})

	// Steady state allocates nothing: client → socket → client.
	t.Run("steady-state-allocs", func(t *testing.T) {
		h := NewUDPSocketHub(UDPSocketHubConfig{})
		s, c := h.Socket(), h.Client(hubSrc(11))
		w, r := dpData(11, 0, 1400), make([]byte, 64<<10)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		s.SetReadDeadline(time.Now().Add(10 * time.Second))
		bad := 0 // rounds that did not echo w intact (no allocation to count them)
		round := func() {
			c.Write(w)
			n, src, err := s.ReadFromUDPAddrPort(r)
			s.WriteToUDPAddrPort(r[:n], src)
			if m, err2 := c.Read(r); err != nil || err2 != nil || m != len(w) || r[3] != w[3] {
				bad++
			}
		}
		round()
		if n := testing.AllocsPerRun(1000, round); n != 0 || bad != 0 {
			t.Fatalf("%.1f allocations per round trip, %d rounds not echoed; want 0 and 0", n, bad)
		}
	})
}

func expectHubPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	f()
}
