package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP5 (m6-design §A6, §A16.1; M6-D16 … M6-D20, R1-10 … R1-12, R1-14,
// R1-17, R1-38): the Server's UDP flows.

// TestServeStreamOnlyWithoutUDP_L50 (M6-D16, M4-D35, PA-89; L50): without
// UDP, Serve never calls AcceptPacket. Alone on its Listener, a UDP flow's
// OPEN waits in the packet backlog until the AcceptTimeout answers
// CAPACITY (DialUDP: ErrCapacity), with no hook call and no UDP counter
// moving, while a TCP connection is served beside it; with an embedder's
// own AcceptPacket loop on the same Listener every packet session reaches
// that loop; HandleUDP on a Server without UDP rejects CodeBadCommand.
func TestServeStreamOnlyWithoutUDP_L50(t *testing.T) {
	t.Run("alone", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{streams: true, acceptTimeout: time.Second})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
			hl := newHookLog(suMixedHook(ts, echo.Dial))
			s := &Server{Dial: hl.dial}
			sv := suServe(w, s)
			start := time.Now()
			res := suDialAsync(context.Background(), w, pfTarget, pfData(20, 1), rendr.DialOptions{})
			c, err := Dial(context.Background(), w.speer, kitTarget, rendr.DialOptions{})
			if err != nil {
				t.Fatalf("TCP Dial: %v", err)
			}
			ping(t, c, 100)
			r := suRecv(t, res, time.Minute)
			if el := r.at.Sub(start); !errors.Is(r.err, rendr.ErrCapacity) || el < time.Second || el > 1200*time.Millisecond {
				t.Fatalf("DialUDP: %v after %v, want ErrCapacity at the 1 s AcceptTimeout", r.err, el)
			}
			if calls, _, _, _ := hl.snapshot(); calls != 1 || ts.calls() != 0 {
				t.Fatalf("%d hook calls (%d UDP), want the TCP connection's only", calls, ts.calls())
			}
			st := s.Status()
			if st.Confirmed != 1 || st.Rejected != 0 {
				t.Fatalf("TCP status %+v", st)
			}
			if u := st.UDP; u.Confirmed+u.Rejected+u.Lost+u.Unconfirmed != 0 || u.Dialing+u.Live != 0 || len(u.ByCode) != 0 {
				t.Fatalf("UDP status moved: %+v", u)
			}
			c.Close()
			sv.stop(t)
			w.shutdown()
		})
	})
	t.Run("embedder loop", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{streams: true})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
			hl := newHookLog(suMixedHook(ts, echo.Dial))
			s := &Server{Dial: hl.dial}
			sv := suServe(w, s)
			const n = 8
			// The embedder's own loop: it confirms the first n packet sessions
			// and hands the next one to HandleUDP (which must refuse it: the
			// Server has no UDP).
			ectx, ecancel := context.WithCancel(context.Background())
			var got atomic.Int32
			var mu sync.Mutex
			var served []*rendr.PacketConn
			loop := make(chan struct{})
			go func() {
				defer close(loop)
				for {
					p, err := w.ln.AcceptPacket(ectx)
					if err != nil {
						return
					}
					if got.Add(1) > n {
						s.HandleUDP(ectx, p)
						continue
					}
					if pc, err := p.Confirm(); err == nil {
						mu.Lock()
						served = append(served, pc)
						mu.Unlock()
					}
				}
			}()
			var pcs []*rendr.PacketConn
			for i := range n {
				pcs = append(pcs, suDial(t, w, pfTarget, pfData(10, byte(i))))
			}
			c, err := Dial(context.Background(), w.speer, kitTarget, rendr.DialOptions{})
			if err != nil {
				t.Fatalf("TCP Dial: %v", err)
			}
			ping(t, c, 100)
			r := suRecv(t, suDialAsync(context.Background(), w, pfTarget, nil, rendr.DialOptions{}), time.Minute)
			wantReject(t, r.err, CodeBadCommand)
			if g := got.Load(); g != n+1 {
				t.Fatalf("the embedder's loop got %d packet sessions, want %d", g, n+1)
			}
			if calls, _, _, _ := hl.snapshot(); calls != 1 || ts.calls() != 0 {
				t.Fatalf("%d hook calls (%d UDP), want the TCP connection's only", calls, ts.calls())
			}
			// The Server counts a refusal after sending it (Server.reject), so the
			// dialer can see the refusal before Status counts it.
			waitFor(t, time.Minute, "the Server counts the refusal", func() bool { return s.Status().UDP.Rejected != 0 })
			if u := s.Status().UDP; u.Rejected != 1 || u.ByCode[CodeBadCommand] != 1 || u.Confirmed != 0 {
				t.Fatalf("UDP status %+v", u)
			}
			for _, pc := range pcs {
				pc.Close()
			}
			mu.Lock()
			for _, pc := range served {
				pc.Close()
			}
			mu.Unlock()
			c.Close()
			ecancel()
			<-loop
			sv.stop(t)
			suUnits(t, s)
			w.shutdown()
		})
	})
}

// TestServerUDPConfirmsAfterSocket (M6-D16, M6-D18; §A6.1): the session
// is confirmed only after the target socket is ready and the first
// datagram's write returned: with a hook that takes a second and a first
// Write that takes 100 ms, DialUDP returns after both (a Confirm before
// the write would answer the dialer while the write still runs); the flow
// then carries datagrams both ways and the counters follow it.
func TestServerUDPConfirmsAfterSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSUWorld(t, suOpts{})
		ts := newSUTargets(rendrtest.DatagramPipeConfig{})
		var wrote atomic.Int64 // the instant the first datagram's Write returned
		ts.wrap = func(srv, _ *rendrtest.DatagramConn, _ Request) net.Conn {
			return &suWriteSpy{DatagramConn: srv, first: &wrote, slow: 100 * time.Millisecond}
		}
		var ready atomic.Int64
		s := &Server{UDP: true, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
			time.Sleep(time.Second) // a target socket that takes a second
			c, err := ts.dial(ctx, r)
			ready.Store(time.Now().UnixNano())
			return c, err
		}}
		sv := suServe(w, s)
		start := time.Now()
		first := pfData(40, 7)
		r := suRecv(t, suDialAsync(context.Background(), w, pfTarget, first, rendr.DialOptions{}), time.Minute)
		if r.err != nil {
			t.Fatalf("DialUDP: %v", r.err)
		}
		if el := r.at.Sub(start); el < time.Second+100*time.Millisecond || ready.Load() == 0 || wrote.Load() == 0 ||
			r.at.UnixNano() < ready.Load() || r.at.UnixNano() < wrote.Load() {
			t.Fatalf("DialUDP returned after %v, before the socket was ready or the first datagram's write returned", el)
		}
		target := ts.next(t, time.Second)
		pfExpect(t, target, first)
		pc := r.pc
		up := pfData(300, 9)
		pc.WriteTo(up, nil)
		pfExpect(t, target, up)
		down := pfData(500, 3)
		pfSend(t, target, down)
		if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, down) {
			t.Fatalf("the reply: %d bytes, %v", len(got), err)
		}
		u := s.Status().UDP
		if u.Confirmed != 1 || u.Live != 1 || u.FirstSent != 1 || u.ToTarget != 2 || u.FromTarget != 1 || u.MaxPayload != pc.MaxPayload() {
			t.Fatalf("UDP status %+v (MaxPayload %d)", u, pc.MaxPayload())
		}
		pc.Close()
		waitFor(t, time.Minute, "the flow ends", func() bool { return s.Status().UDP.Live == 0 })
		if u := s.Status().UDP; u.Ended.PeerClosed != 1 || u.Ended != (FlowEnds{PeerClosed: 1}) {
			t.Fatalf("ends %+v", u.Ended)
		}
		if st := s.Status(); st.Confirmed != 0 || st.Live != 0 {
			t.Fatalf("TCP status moved: %+v", st)
		}
		sv.stop(t)
		suUnits(t, s)
		w.shutdown()
	})
}

// suNoDeadline is a target socket that ignores deadlines (its writes
// always go out) and counts its Close calls.
type suNoDeadline struct {
	net.Conn
	closes atomic.Int32
}

func (c *suNoDeadline) SetDeadline(time.Time) error      { return nil }
func (c *suNoDeadline) SetWriteDeadline(time.Time) error { return nil }

func (c *suNoDeadline) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// suWithdrawOnWrite is a target socket whose first Write sends the
// datagram, then withdraws the dialer's DialUDP and returns once the
// withdrawal reached the passive (a few link delays later): the session
// is decided between the first datagram's write and Confirm.
type suWithdrawOnWrite struct {
	*rendrtest.DatagramConn
	withdraw func()
	n        atomic.Int32
	closes   atomic.Int32
}

func (c *suWithdrawOnWrite) Write(b []byte) (int, error) {
	n, err := c.DatagramConn.Write(b)
	if c.n.Add(1) == 1 {
		c.withdraw()
		time.Sleep(4 * pfOneWay)
	}
	return n, err
}

func (c *suWithdrawOnWrite) Close() error {
	c.closes.Add(1)
	return c.DatagramConn.Close()
}

// suWriteSpy is a Server end whose first Write takes slow and records the
// instant it returned.
type suWriteSpy struct {
	*rendrtest.DatagramConn
	first *atomic.Int64
	slow  time.Duration
	n     atomic.Int32
}

func (c *suWriteSpy) Write(b []byte) (int, error) {
	if c.n.Add(1) > 1 {
		return c.DatagramConn.Write(b)
	}
	time.Sleep(c.slow)
	n, err := c.DatagramConn.Write(b)
	c.first.Store(time.Now().UnixNano())
	return n, err
}

// TestServerUDPHookSeesCmd (M6-D17, R1-14; §A6.2): the hook sees a UDP
// flow's request — Cmd CmdUDP, the address, the first datagram that rode
// the OPEN and the dialer's metadata as App. Without a hook the default
// dialer serves the flow: dialUDP is called with the address (TCP keeps
// dialTCP) and the Server requests UDPBuffer for the socket's receive and
// send buffers (1 MiB when 0 or negative, a set value as given); over real
// loopback sockets the default dialer's conn is a connected "udp" socket
// and the flow round-trips.
func TestServerUDPHookSeesCmd(t *testing.T) {
	t.Run("hook", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			s := &Server{UDP: true, Dial: ts.dial}
			sv := suServe(w, s)
			first, app := pfData(29, 0x30), []byte("app-token")
			pc := suDialWith(t, w, "dns.test:53", first, rendr.DialOptions{Metadata: app})
			pfExpect(t, ts.next(t, time.Second), first)
			ts.mu.Lock()
			r := ts.reqs[0]
			ts.mu.Unlock()
			if r.Cmd != CmdUDP || r.Addr != "dns.test:53" || !bytes.Equal(r.First, first) || !bytes.Equal(r.App, app) {
				t.Fatalf("the hook saw %+v", r)
			}
			pc.Close()
			sv.stop(t)
			w.shutdown()
		})
	})
	for _, row := range []struct {
		name string
		buf  int
		want int
	}{{"default buffer", 0, 1 << 20}, {"negative buffer", -1, 1 << 20}, {"4 MiB", 4 << 20, 4 << 20}} {
		t.Run("default dialer/"+row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{streams: true})
				var mu sync.Mutex
				var addrs []string
				var conns []*suBufConn
				apps := make(chan *rendrtest.DatagramConn, 4)
				suSetDialUDP(t, func(ctx context.Context, addr string) (net.Conn, error) {
					srv, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
					c := &suBufConn{DatagramConn: srv}
					mu.Lock()
					addrs = append(addrs, addr)
					conns = append(conns, c)
					mu.Unlock()
					apps <- app
					return c, nil
				})
				var tcpAddrs atomic.Int32
				echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
				old := dialTCP
				dialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
					tcpAddrs.Add(1)
					return echo.Dial(ctx, addr)
				}
				t.Cleanup(func() { dialTCP = old })
				s := &Server{UDP: true, UDPBuffer: row.buf}
				sv := suServe(w, s)
				first := pfData(12, 5)
				pc := suDial(t, w, pfTarget, first)
				var target *rendrtest.DatagramConn
				select {
				case target = <-apps:
				case <-time.After(time.Second):
					t.Fatal("the flow was not dialled with dialUDP")
				}
				pfExpect(t, target, first)
				done := suEcho(target)
				suRoundTrip(t, pc, pfData(200, 6))
				c, err := Dial(context.Background(), w.speer, kitTarget, rendr.DialOptions{})
				if err != nil {
					t.Fatalf("TCP Dial: %v", err)
				}
				ping(t, c, 100)
				mu.Lock()
				gotAddrs, rd, wr := append([]string(nil), addrs...), []int(nil), []int(nil)
				if len(conns) == 1 {
					rd, wr = conns[0].requests()
				}
				mu.Unlock()
				if len(gotAddrs) != 1 || gotAddrs[0] != pfTarget || tcpAddrs.Load() != 1 {
					t.Fatalf("dialUDP calls %q, dialTCP calls %d", gotAddrs, tcpAddrs.Load())
				}
				if len(rd) != 1 || rd[0] != row.want || len(wr) != 1 || wr[0] != row.want {
					t.Fatalf("buffer requests: read %v, write %v; want %d each", rd, wr, row.want)
				}
				pc.Close()
				c.Close()
				<-done
				sv.stop(t)
				w.shutdown()
			})
		})
	}
	t.Run("real sockets", func(t *testing.T) {
		echo := suRealEcho(t)
		w := newSUWorld(t, suOpts{})
		var mu sync.Mutex
		var seen []net.Conn
		orig := dialUDP
		suSetDialUDP(t, func(ctx context.Context, addr string) (net.Conn, error) {
			c, err := orig(ctx, addr)
			if err == nil {
				mu.Lock()
				seen = append(seen, c)
				mu.Unlock()
			}
			return c, err
		})
		s := &Server{UDP: true}
		sv := suServe(w, s)
		first := pfData(33, 2)
		pc := suDial(t, w, echo.String(), first)
		if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, first) {
			t.Fatalf("the first datagram's echo: %d bytes, %v", len(got), err)
		}
		suRoundTrip(t, pc, pfData(1000, 4))
		mu.Lock()
		if len(seen) != 1 {
			t.Fatalf("%d default dials", len(seen))
		}
		uc, ok := seen[0].(*net.UDPConn)
		mu.Unlock()
		if !ok || uc.LocalAddr().Network() != "udp" || uc.RemoteAddr() == nil || uc.RemoteAddr().String() != echo.String() {
			t.Fatalf("the default dialer's conn %T is not a udp socket connected to the target", seen[0])
		}
		pc.Close()
		waitFor(t, 10*time.Second, "the flow ends", func() bool { return s.Status().UDP.Live == 0 })
		if u := s.Status().UDP; u.Confirmed != 1 || u.FirstSent != 1 || u.ToTarget != 2 || u.FromTarget != 2 {
			t.Fatalf("UDP status %+v", u)
		}
		sv.stop(t)
		w.shutdown()
	})
}

// suDialWith opens a flow with o and fails on an error.
func suDialWith(t testing.TB, w *suWorld, addr string, first []byte, o rendr.DialOptions) *rendr.PacketConn {
	t.Helper()
	r := suRecv(t, suDialAsync(context.Background(), w, addr, first, o), time.Minute)
	if r.err != nil {
		t.Fatalf("DialUDP %s: %v", addr, r.err)
	}
	return r.pc
}

// suRealEcho is a loopback UDP echo socket (real, outside bubbles) closed
// at the test's end; it returns its address.
func suRealEcho(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue // an ICMP-class error of an earlier reply
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return pc.LocalAddr()
}

// TestServerUDPHookConnCheck_L51 (M6-D17, R1-11; L51): a hook's conn for a
// UDP flow is accepted iff its RemoteAddr is non-nil and it implements
// net.PacketConn or reports a LocalAddr whose Network is udp, udp4 or
// udp6. A TCP conn, an unconnected ListenUDP socket, a wrapper whose
// LocalAddr is nil and one whose Network is "foo" are each closed once and
// answered CodeDialFailed with LastErr naming the check; a wrapper that
// reports "udp" with a RemoteAddr and a connected *net.UDPConn carry the
// flow; a conn whose LocalAddr panics, or calls runtime.Goexit, is closed
// once and answered CodeDialFailed at once, counted in Panics, and the
// process and the Server live (the next rows are served). Real loopback
// sockets, outside bubbles.
func TestServerUDPHookConnCheck_L51(t *testing.T) {
	echo := suRealEcho(t)
	type closer interface {
		net.Conn
		closes() int32
	}
	rows := []struct {
		name   string
		conn   func(t *testing.T) (closer, *rendrtest.DatagramConn) // the hook's conn; a pipe's target end when it has one
		ok     bool
		panics uint64
	}{
		{"tcp conn", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if c, err := ln.Accept(); err == nil {
					io.Copy(io.Discard, c) // until the refused conn's close
					c.Close()
				}
			}()
			t.Cleanup(func() { ln.Close(); <-done })
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			return &suCount{Conn: c}, nil
		}, false, 0},
		{"unconnected ListenUDP", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			return &suUDPCount{UDPConn: c}, nil
		}, false, 0},
		{"nil LocalAddr", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			srv, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			return &suCount{Conn: srv, local: func() net.Addr { return nil }}, app
		}, false, 0},
		{"network foo", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			srv, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			return &suCount{Conn: srv, local: func() net.Addr { return suAddr("foo") }}, app
		}, false, 0},
		{"panicking LocalAddr", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			srv, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			return &suCount{Conn: srv, local: func() net.Addr { panic("LocalAddr") }}, app
		}, false, 1},
		{"Goexit in LocalAddr", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			srv, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			return &suCount{Conn: srv, local: func() net.Addr { runtime.Goexit(); return nil }}, app
		}, false, 1},
		{"udp wrapper", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			srv, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			return &suCount{Conn: srv, local: func() net.Addr { return suAddr("udp") }}, app
		}, true, 0},
		{"connected UDPConn", func(t *testing.T) (closer, *rendrtest.DatagramConn) {
			c, err := net.DialUDP("udp", nil, echo.(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			return &suUDPCount{UDPConn: c}, nil
		}, true, 0},
	}
	// One world and one Server for every row (a passive Runtime's Close
	// takes a second of real time after a refused packet session).
	w := newSUWorld(t, suOpts{})
	var next atomic.Pointer[net.Conn] // the conn the hook returns for the next flow
	s := &Server{UDP: true, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
		if c := next.Swap(nil); c != nil {
			return *c, nil
		}
		return nil, errors.New("one flow per row")
	}}
	sv := suServe(w, s)
	var accepted, refused uint64 // the rows that ran (-run may select some)
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if row.ok {
				accepted++
			} else {
				refused++
			}
			conn, app := row.conn(t)
			var nc net.Conn = conn
			next.Store(&nc)
			panics := s.Status().Panics
			start := time.Now()
			r := suRecv(t, suDialAsync(context.Background(), w, echo.String(), nil, rendr.DialOptions{}), time.Minute)
			st := s.Status()
			if !row.ok {
				wantReject(t, r.err, CodeDialFailed)
				if el := time.Since(start); el > time.Second {
					t.Fatalf("refused after %v, want at once", el)
				}
				waitFor(t, 10*time.Second, "the hook call ends", func() bool { return s.Status().Hooks == 0 })
				if n := conn.closes(); n != 1 {
					t.Fatalf("the refused conn was closed %d times", n)
				}
				if st := s.Status(); st.Panics-panics != row.panics || st.LastErr == nil || row.panics == 0 && !errors.Is(st.LastErr, errNotDatagram) {
					t.Fatalf("status %+v", st)
				}
				if row.panics != 0 {
					// LastErr names what the check met.
					want := "panicked in its datagram check: LocalAddr"
					if strings.HasPrefix(row.name, "Goexit") {
						want = "called runtime.Goexit in its datagram check"
					}
					if e := s.Status().LastErr.Error(); !strings.Contains(e, want) {
						t.Fatalf("LastErr %q, want it to say %q", e, want)
					}
				}
				return
			}
			if r.err != nil {
				t.Fatalf("DialUDP: %v (last error %v)", r.err, st.LastErr)
			}
			var done <-chan struct{}
			if app != nil {
				done = suEcho(app)
			}
			suRoundTrip(t, r.pc, pfData(100, 1))
			r.pc.Close()
			waitFor(t, 10*time.Second, "the flow ends", func() bool { return s.Status().UDP.Live == 0 })
			if n := conn.closes(); n != 1 || s.Status().Panics != panics {
				t.Fatalf("the accepted conn was closed %d times; panics %d → %d", n, panics, s.Status().Panics)
			}
			if done != nil {
				<-done
			}
		})
	}
	if u := s.Status().UDP; u.Confirmed != accepted || u.Rejected != refused || u.ByCode[CodeDialFailed] != refused {
		t.Fatalf("UDP status %+v", u)
	}
	sv.stop(t)
	w.shutdown()
}

// suCount counts Close calls on a conn; local, when set, replaces its
// LocalAddr. It hides every method but net.Conn's.
type suCount struct {
	net.Conn
	local func() net.Addr
	n     atomic.Int32
}

func (c *suCount) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local()
	}
	return c.Conn.LocalAddr()
}

func (c *suCount) Close() error {
	c.n.Add(1)
	return c.Conn.Close()
}

func (c *suCount) closes() int32 { return c.n.Load() }

// suUDPCount counts Close calls on a *net.UDPConn and keeps its method
// set (it is a net.PacketConn).
type suUDPCount struct {
	*net.UDPConn
	n atomic.Int32
}

func (c *suUDPCount) Close() error {
	c.n.Add(1)
	return c.UDPConn.Close()
}

func (c *suUDPCount) closes() int32 { return c.n.Load() }

// suAddr is a net.Addr whose Network is the string.
type suAddr string

func (a suAddr) Network() string { return string(a) }
func (a suAddr) String() string  { return "192.0.2.1:9" }

// TestServerUDPFirstSeedsClass (R1-10, M6-D9; L72): a flow whose only
// client datagram is the first (it rode the OPEN) and whose target then
// streams for 5 s is a stream at both ends under both rules: the passive,
// whose tracker HandleUDP seeded with the first datagram's write, lives
// past its Short limit and ends at its Stream limit after the last
// datagram (ErrIdleTimeout there, AbortIdle at the dialer, whose own
// forward — seeded as the ingress's tracker is — reports Stream).
func TestServerUDPFirstSeedsClass(t *testing.T) {
	const s = time.Second
	for _, rule := range []promoteMode{promoteOnReply, promoteActive} {
		t.Run(map[promoteMode]string{promoteOnReply: "reply rule", promoteActive: "active rule"}[rule], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, rule)
				w := newSUWorld(t, suOpts{})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				srv := &Server{UDP: true, Dial: ts.dial, UDPIdle: FlowIdle{Short: 10 * s, Stream: 40 * s}}
				sv := suServe(w, srv)
				first := pfData(30, 1)
				sent := time.Now()
				pc := suDial(t, w, pfTarget, first)
				client, cliLocal := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{Queue: 1024})
				in := make(chan PacketResult, 1)
				go func() {
					in <- forwardPacket(context.Background(), pc, cliLocal, FlowIdle{Short: 10 * s, Stream: 60 * s}, flowSeed{at: sent, dir: towardSession}, nil)
				}()
				target := ts.next(t, time.Second)
				pfExpect(t, target, first)
				var last time.Time
				for i := range 50 {
					pfSend(t, target, pfData(200, byte(i)))
					last = time.Now()
					time.Sleep(100 * time.Millisecond)
				}
				for range 50 {
					pfRecv(t, client)
				}
				var res PacketResult
				select {
				case res = <-in:
				case <-time.After(time.Hour):
					t.Fatal("the flow did not end")
				}
				el := time.Since(last)
				if !pfAbortIdle(res.SessionErr) || !res.Stream || el < 40*s || el > 40*s+s+100*time.Millisecond {
					t.Fatalf("the dialer's forward ended %v after the last datagram: %+v; want the passive's 40-s Stream limit (AbortIdle) and a stream", el, res)
				}
				waitFor(t, time.Minute, "the passive's flow ends", func() bool { return srv.Status().UDP.Live == 0 })
				if u := srv.Status().UDP; u.Ended != (FlowEnds{Idle: 1}) || u.FirstSent != 1 || u.FromTarget != 50 {
					t.Fatalf("UDP status %+v", u)
				}
				sv.stop(t)
				suUnits(t, srv)
				w.shutdown()
			})
		})
	}
}

// TestServerUDPIdleReachesForward (M6-D20, R1-22; plan:277): the Server's
// UDPIdle reaches every served flow's forward: an unanswered flow (its
// first datagram only) ends at the passive at UDPIdle.Short — 12 s when
// set, 30 s (DefaultFlowShortIdle) when zero — after the open
// (ErrIdleTimeout there, AbortIdle at the dialer), not at the dialer's
// 180 s.
func TestServerUDPIdleReachesForward(t *testing.T) {
	for _, row := range []struct {
		name string
		idle FlowIdle
		want time.Duration
	}{{"12 s", FlowIdle{Short: 12 * time.Second}, 12 * time.Second}, {"default", FlowIdle{}, DefaultFlowShortIdle}} {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				s := &Server{UDP: true, Dial: ts.dial, UDPIdle: row.idle}
				sv := suServe(w, s)
				start := time.Now()
				pc := suDial(t, w, pfTarget, pfData(16, 1))
				pfRecv(t, ts.next(t, time.Second))
				buf := make([]byte, 2048)
				_, _, err := pc.ReadFrom(buf)
				el := time.Since(start)
				if !pfAbortIdle(err) || el < row.want || el > row.want+time.Second+100*time.Millisecond {
					t.Fatalf("the dialer read %v after %v; want AbortIdle at the passive's %v", err, el, row.want)
				}
				waitFor(t, time.Minute, "the passive's flow ends", func() bool { return s.Status().UDP.Live == 0 })
				if u := s.Status().UDP; u.Ended != (FlowEnds{Idle: 1}) {
					t.Fatalf("ends %+v", u.Ended)
				}
				pc.Close()
				sv.stop(t)
				suUnits(t, s)
				w.shutdown()
			})
		})
	}
}

// TestServerUDPRejectCodes_L51 (M6-D17, M4-D30; L51): a UDP flow's dial
// outcomes are answered as a TCP connection's: the scripted refusals and
// failures by their codes, a hanging dial CodeTimeout at the 1-s budget, a
// hook that ignores ctx or returns late CodeTimeout at the budget + 1 s
// (abandoned; the late conn closed once), a panic, a Goexit and (nil, nil)
// CodeDialFailed (the first two counted in Panics). Counted in UDP's
// ByCode, never in the TCP counters.
func TestServerUDPRejectCodes_L51(t *testing.T) {
	rows := []struct {
		name    string
		outcome rendrtest.DialOutcome
		code    RejectCode
		at      time.Duration // when the refusal leaves (from the call)
		panics  uint64
	}{
		{"refused", rendrtest.OutcomeRefuse(), CodeRefused, 0, 0},
		{"net unreachable", rendrtest.OutcomeNetUnreachable(), CodeNetUnreachable, 0, 0},
		{"host unreachable", rendrtest.OutcomeHostUnreachable(), CodeHostUnreachable, 0, 0},
		{"dns not found", rendrtest.OutcomeDNSNotFound(), CodeDNSNotFound, 0, 0},
		{"dns failure", rendrtest.OutcomeDNSFailure(), CodeDNSFailure, 0, 0},
		{"hang", rendrtest.OutcomeHang(), CodeTimeout, time.Second, 0},
		{"ignores ctx", rendrtest.OutcomeIgnoreCtx(20 * time.Second), CodeTimeout, 2 * time.Second, 0},
		{"late conn", rendrtest.OutcomeLate(20 * time.Second), CodeTimeout, 2 * time.Second, 0},
		{"panic", rendrtest.OutcomePanic(), CodeDialFailed, 0, 1},
		{"goexit", rendrtest.OutcomeGoexit(), CodeDialFailed, 0, 1},
		{"nil nil", rendrtest.OutcomeNilNil(), CodeDialFailed, 0, 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{})
				dial, counts := rendrtest.ScriptedDial(row.outcome)
				hl := newHookLog(hookOf(dial))
				s := &Server{UDP: true, Dial: hl.dial, DialTimeout: time.Second}
				sv := suServe(w, s)
				r := suRecv(t, suDialAsync(context.Background(), w, pfTarget, pfData(10, 1), rendr.DialOptions{}), time.Minute)
				wantReject(t, r.err, row.code)
				hl.mu.Lock()
				el := r.at.Sub(hl.starts[0])
				hl.mu.Unlock()
				if el < row.at || el > row.at+50*time.Millisecond {
					t.Fatalf("refused %v after the call, want %v", el, row.at)
				}
				if row.at > time.Second {
					if st := s.Status(); st.Abandoned != 1 || st.Hooks != 1 {
						t.Fatalf("status while abandoned %+v", st)
					}
				}
				waitFor(t, time.Minute, "the hook call ends", func() bool { return s.Status().Hooks == 0 })
				// The Server counts a refusal after sending it (Server.reject), so the
				// dialer can see the refusal before Status counts it.
				waitFor(t, time.Minute, "the Server counts the refusal", func() bool { return s.Status().UDP.Rejected != 0 })
				st := s.Status()
				if st.Panics != row.panics || st.Abandoned != 0 || st.LastErr == nil || counts.Unclosed() != 0 {
					t.Fatalf("status %+v; %d conns open", st, counts.Unclosed())
				}
				if u := st.UDP; u.Rejected != 1 || u.ByCode[row.code] != 1 || u.Confirmed != 0 || u.FirstSent != 0 || st.Rejected != 0 || len(st.ByCode) != 0 {
					t.Fatalf("counters: UDP %+v, TCP rejected %d %v", u, st.Rejected, st.ByCode)
				}
				sv.stop(t)
				suUnits(t, s)
				w.shutdown()
			})
		})
	}
}

// TestServerUDPHookCapPerKind_L51 (M6-D17, R1-12; L51): the cap of 192
// running hook calls is per kind. With 192 UDP calls running (held, past
// their budget: abandoned), the 193rd UDP flow is refused CodeCapacity at
// once without a hook call while a TCP connection still calls the hook and
// is served; and the same with the kinds swapped. When the held calls
// return, Hooks and Abandoned go back to 0.
func TestServerUDPHookCapPerKind_L51(t *testing.T) {
	for _, held := range []uint8{CmdUDP, CmdConnect} {
		name := map[uint8]string{CmdUDP: "UDP held", CmdConnect: "TCP held"}[held]
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{streams: true, n: 2 * maxHookCalls, backlog: 512})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
				gate := make(chan struct{})
				var calls [2]atomic.Int32 // [0] UDP, [1] TCP
				kind := func(cmd uint8) int { return map[uint8]int{CmdUDP: 0, CmdConnect: 1}[cmd] }
				s := &Server{UDP: true, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
					calls[kind(r.Cmd)].Add(1)
					if r.Addr == "held.test:1" {
						<-gate // ignores ctx: abandoned at its budget + 1 s, still running
						return nil, errors.New("held")
					}
					if r.Cmd == CmdUDP {
						return ts.dial(ctx, r)
					}
					return echo.Dial(ctx, r.Addr)
				}}
				sv := suServe(w, s)
				open := func(cmd uint8, addr string) <-chan error {
					res := make(chan error, 1)
					go func() {
						var err error
						if cmd == CmdUDP {
							var pc *rendr.PacketConn
							if pc, err = DialUDP(context.Background(), w.peer, addr, nil, rendr.DialOptions{}); err == nil {
								pc.Close()
							}
						} else {
							var c *rendr.Conn
							if c, err = Dial(context.Background(), w.speer, addr, rendr.DialOptions{}); err == nil {
								c.Close()
							}
						}
						res <- err
					}()
					return res
				}
				var heldRes []<-chan error
				for range maxHookCalls {
					heldRes = append(heldRes, open(held, "held.test:1"))
				}
				waitFor(t, 5*time.Second, "the held calls run", func() bool { return calls[kind(held)].Load() == maxHookCalls })
				synctest.Wait()
				if st := s.Status(); st.Hooks != maxHookCalls {
					t.Fatalf("premise: %d hook calls running", st.Hooks)
				}
				start := time.Now()
				err := <-open(held, kitTarget)
				wantReject(t, err, CodeCapacity)
				// At once: long before the held calls' budget (the 193rd flow's
				// open may dial a new datagram trunk first).
				if el := time.Since(start); el > 500*time.Millisecond || calls[kind(held)].Load() != maxHookCalls {
					t.Fatalf("the refusal took %v; %d calls of the held kind", el, calls[kind(held)].Load())
				}
				other := uint8(CmdUDP)
				if held == CmdUDP {
					other = CmdConnect
				}
				if err := <-open(other, kitTarget); err != nil {
					t.Fatalf("the other kind at the held kind's cap: %v", err)
				}
				if calls[kind(other)].Load() != 1 {
					t.Fatalf("the other kind's hook calls: %d", calls[kind(other)].Load())
				}
				for _, r := range heldRes {
					wantReject(t, <-r, CodeTimeout) // at the budget + 1 s, abandoned
				}
				if st := s.Status(); st.Hooks != maxHookCalls || st.Abandoned != maxHookCalls {
					t.Fatalf("status while abandoned %+v", st)
				}
				close(gate)
				waitFor(t, time.Minute, "the held calls return", func() bool { st := s.Status(); return st.Hooks == 0 && st.Abandoned == 0 })
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// TestServerUDPKindMismatch_L44 (M6-D1, R1-8; L44): the kind check is the
// parser: a packet session with CmdConnect metadata is refused
// CodeBadCommand, as is a stream session with CmdUDP metadata (Handle's
// v2.0.0 ParseMetadata); non-L4 packet metadata is CodeBadRequest and a
// version-2 one CodeBadVersion. No hook is called; each kind counts its
// own refusals.
func TestServerUDPKindMismatch_L44(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSUWorld(t, suOpts{streams: true})
		ts := newSUTargets(rendrtest.DatagramPipeConfig{})
		echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		hl := newHookLog(suMixedHook(ts, echo.Dial))
		s := &Server{UDP: true, Dial: hl.dial}
		sv := suServe(w, s)
		connect, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: kitTarget})
		if err != nil {
			t.Fatal(err)
		}
		udp, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: pfTarget, First: pfData(8, 1)})
		if err != nil {
			t.Fatal(err)
		}
		v2 := append([]byte(nil), udp...)
		v2[2] = 2
		for _, row := range []struct {
			name string
			md   []byte
			code RejectCode
		}{{"CmdConnect", connect, CodeBadCommand}, {"not L4", []byte("hello"), CodeBadRequest}, {"version 2", v2, CodeBadVersion}} {
			_, err := w.peer.DialPacket(context.Background(), rendr.DialOptions{Metadata: row.md})
			if e := checkReject(err, row.code); e != nil {
				t.Fatalf("packet session, %s: %v", row.name, e)
			}
		}
		_, err = w.speer.Dial(context.Background(), rendr.DialOptions{Metadata: udp})
		wantReject(t, err, CodeBadCommand)
		if calls, _, _, _ := hl.snapshot(); calls != 0 {
			t.Fatalf("%d hook calls", calls)
		}
		// The Server counts a refusal after sending it (Server.reject), so the
		// dialer can see the refusal before Status counts it.
		waitFor(t, time.Minute, "the Server counts the refusals", func() bool { st := s.Status(); return st.UDP.Rejected >= 3 && st.Rejected >= 1 })
		st := s.Status()
		if u := st.UDP; u.Rejected != 3 || u.ByCode[CodeBadCommand] != 1 || u.ByCode[CodeBadRequest] != 1 || u.ByCode[CodeBadVersion] != 1 {
			t.Fatalf("UDP status %+v", u)
		}
		if st.Rejected != 1 || st.ByCode[CodeBadCommand] != 1 || len(st.ByCode) != 1 {
			t.Fatalf("TCP status %+v", st)
		}
		sv.stop(t)
		suUnits(t, s)
		w.shutdown()
	})
}

// TestServerUDPMaxFlows_L48 (M6-D19; L48): MaxFlows bounds the flows a
// Server dials for or forwards; one beyond is refused CodeCapacity at once
// without a hook call; a unit is released at every end (a flow's end, a
// withdrawn dial); TCP's MaxConns neither counts flows nor is counted by
// them. MaxFlows 0 or less is DefaultMaxFlows.
func TestServerUDPMaxFlows_L48(t *testing.T) {
	for _, v := range []int{0, -1} {
		if got := (&Server{MaxFlows: v}).maxFlows(); got != DefaultMaxFlows {
			t.Fatalf("MaxFlows %d: %d, want %d", v, got, DefaultMaxFlows)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		w := newSUWorld(t, suOpts{streams: true})
		ts := newSUTargets(rendrtest.DatagramPipeConfig{})
		echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		hang, _ := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
		hl := newHookLog(func(ctx context.Context, r Request) (net.Conn, error) {
			switch {
			case r.Addr == "hang.test:1":
				return hang(ctx, r.Addr)
			case r.Cmd == CmdUDP:
				return ts.dial(ctx, r)
			}
			return echo.Dial(ctx, r.Addr)
		})
		s := &Server{UDP: true, Dial: hl.dial, MaxFlows: 3, MaxConns: 1}
		sv := suServe(w, s)
		var pcs []*rendr.PacketConn
		var echoes []<-chan struct{}
		for i := range 2 {
			pcs = append(pcs, suDial(t, w, pfTarget, nil))
			echoes = append(echoes, suEcho(ts.next(t, time.Second)))
			suRoundTrip(t, pcs[i], pfData(50, byte(i)))
		}
		hctx, hcancel := context.WithCancel(context.Background())
		hangCh := suDialAsync(hctx, w, "hang.test:1", nil, rendr.DialOptions{})
		waitFor(t, time.Minute, "the third flow dials", func() bool { return s.Status().UDP.Dialing == 1 })
		synctest.Wait()
		calls, _, _, _ := hl.snapshot()
		// TCP is bounded by MaxConns only: one connection is served beside
		// the three flows, a second is refused by MaxConns.
		c, err := Dial(context.Background(), w.speer, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("TCP Dial beside three flows: %v", err)
		}
		ping(t, c, 100)
		_, err = Dial(context.Background(), w.speer, kitTarget, rendr.DialOptions{})
		wantReject(t, err, CodeCapacity)
		start := time.Now()
		r := suRecv(t, suDialAsync(context.Background(), w, pfTarget, nil, rendr.DialOptions{}), time.Minute)
		wantReject(t, r.err, CodeCapacity)
		if el := time.Since(start); el > 100*time.Millisecond {
			t.Fatalf("the refusal took %v, want at once", el)
		}
		if c2, _, _, _ := hl.snapshot(); c2 != calls+1 {
			t.Fatalf("hook calls %d → %d: one for the TCP connection only", calls, c2)
		}
		// A flow's end frees its unit.
		pcs[0].Close()
		<-echoes[0]
		waitFor(t, time.Minute, "the flow ends", func() bool { return s.Status().UDP.Live == 1 })
		suUnitsAt(t, s, 2)
		pcs[0] = suDial(t, w, pfTarget, nil)
		echoes[0] = suEcho(ts.next(t, time.Second))
		suRoundTrip(t, pcs[0], pfData(60, 3))
		// A withdrawn dial frees its unit.
		hcancel()
		if r := suRecv(t, hangCh, time.Minute); !errors.Is(r.err, context.Canceled) {
			t.Fatalf("the withdrawn DialUDP: %v", r.err)
		}
		suUnitsAt(t, s, 2)
		pc := suDial(t, w, pfTarget, nil)
		done := suEcho(ts.next(t, time.Second))
		suRoundTrip(t, pc, pfData(70, 4))
		st := s.Status()
		if u := st.UDP; u.Confirmed != 4 || u.Rejected != 1 || u.ByCode[CodeCapacity] != 1 || u.Lost != 1 || u.Live != 3 {
			t.Fatalf("UDP status %+v", u)
		}
		if st.Confirmed != 1 || st.Rejected != 1 || st.ByCode[CodeCapacity] != 1 || st.Live != 1 {
			t.Fatalf("TCP status %+v", st)
		}
		pc.Close()
		<-done
		for i, p := range pcs {
			p.Close()
			<-echoes[i]
		}
		c.Close()
		sv.stop(t)
		suUnits(t, s)
		w.shutdown()
	})
}

// suUnitsAt waits until n MaxFlows units of s are taken.
func suUnitsAt(t testing.TB, s *Server, n int64) {
	t.Helper()
	waitFor(t, time.Minute, "the UDP units", func() bool { return s.udp.units.Load() == n })
}

// TestServerUDPFirstSentOnce_L47 (M6-D18, §A3.3; L47): the target receives
// the first datagram exactly once, before Confirm — also when the OPEN is
// retransmitted after a lost OPEN_ACK, and when a second carrier sends its
// own OPEN — and its reply, queued in the target socket before Confirm,
// reaches the dialer after the open (a lost OPEN_ACK may lose that reply
// with it, A-11: the row then sends one after the open).
func TestServerUDPFirstSentOnce_L47(t *testing.T) {
	shapes := []struct {
		name   string
		links  int
		mode   rendr.Mode
		lost   bool // the first OPEN_ACK dropped: the OPEN is retransmitted
		second bool // link 0's answers delayed beyond JoinStagger: a second OPEN on link 1
	}{
		{"plain", 1, rendr.ModeSelector, false, false},
		{"lost OPEN_ACK", 1, rendr.ModeSelector, true, false},
		{"second OPEN/race", 2, rendr.ModeRace, false, true},
		{"second OPEN/selector", 2, rendr.ModeSelector, false, true},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{links: sh.links})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				reply := pfData(90, 0x44)
				var writes atomic.Int32
				var wroteAt atomic.Int64
				ts.wrap = func(srv, app *rendrtest.DatagramConn, _ Request) net.Conn {
					return &suReplyOnFirst{DatagramConn: srv, app: app, writes: &writes, at: &wroteAt, reply: reply}
				}
				s := &Server{UDP: true, Dial: ts.dial}
				sv := suServe(w, s)
				if sh.lost {
					w.links[0].DropNext(rendrtest.Down, rendrtest.FrameOpenAck, 1)
				}
				var open1 <-chan []byte
				if sh.second {
					w.links[0].SetDelay(rendrtest.Down, 1500*time.Millisecond, 0)
					open1 = w.links[1].CaptureNext(rendrtest.Up, rendrtest.FrameOpen)
				}
				first := pfData(64, 0x5A)
				r := suRecv(t, suDialAsync(context.Background(), w, pfTarget, first, rendr.DialOptions{Mode: sh.mode}), time.Minute)
				if r.err != nil {
					t.Fatalf("DialUDP: %v", r.err)
				}
				pc := r.pc
				if sh.second {
					select {
					case b := <-open1:
						if !bytes.Contains(b, first) {
							t.Fatal("stimulus: the second carrier's OPEN lacks the first datagram")
						}
					default:
						t.Fatal("stimulus: no OPEN on the second carrier before the open completed")
					}
					w.links[0].SetDelay(rendrtest.Down, pfOneWay, 0)
				}
				if sh.lost {
					if st := w.links[0].Stats(); st.Session.Lost == 0 {
						t.Fatalf("stimulus: no OPEN_ACK dropped: %+v", st)
					}
				}
				if wroteAt.Load() == 0 || r.at.UnixNano() < wroteAt.Load() {
					t.Fatal("the first datagram was not written before the open completed")
				}
				target := ts.next(t, time.Second)
				got, err := pfRecvPC(t, pc)
				switch {
				case err == nil && bytes.Equal(got, reply):
				case sh.lost && errors.Is(err, os.ErrDeadlineExceeded):
					t.Log("the reply queued before Confirm was lost with the OPEN_ACK (A-11)")
				default:
					t.Fatalf("the queued reply: %d bytes, %v", len(got), err)
				}
				after := pfData(20, 0x45)
				pfSend(t, target, after)
				if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, after) {
					t.Fatalf("a reply after the open: %d bytes, %v", len(got), err)
				}
				pfNone(t, target)
				if n := writes.Load(); n != 1 || target.Counts().In != 1 || ts.calls() != 1 {
					t.Fatalf("%d writes to the target socket, the target read %d, %d hook calls; want the first once", n, target.Counts().In, ts.calls())
				}
				if u := s.Status().UDP; u.FirstSent != 1 || u.Confirmed != 1 {
					t.Fatalf("UDP status %+v", u)
				}
				pc.Close()
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// suReplyOnFirst is a Server end whose first Write (the first datagram,
// before Confirm) is read by the target application at once, which
// answers it: the reply waits in the socket until the forward reads it.
type suReplyOnFirst struct {
	*rendrtest.DatagramConn
	app    *rendrtest.DatagramConn // the target application's end
	writes *atomic.Int32
	at     *atomic.Int64
	reply  []byte
}

func (c *suReplyOnFirst) Write(b []byte) (int, error) {
	n, err := c.DatagramConn.Write(b)
	if c.writes.Add(1) == 1 && err == nil {
		c.at.Store(time.Now().UnixNano())
		buf := make([]byte, 2048)
		if k, rerr := c.app.Read(buf); rerr == nil && bytes.Equal(buf[:k], b) {
			c.app.Write(c.reply)
		}
	}
	return n, err
}

// TestServerUDPStatusSeparate (M6-D19, R1-38; F49): UDP flows never move a
// TCP counter and TCP connections never move a UDP one: with two TCP
// connections and one refused beside three UDP flows and two refused, each
// kind's Confirmed, Rejected and ByCode are its own, exactly. SessionDrops
// sums the ended flows' session drops: a target socket that stops taking
// datagrams makes the passive session's receive queue drop (DropRecvQueue);
// at the flow's end SessionDrops is exactly the datagrams sent and never
// delivered, while nothing else dropped any.
func TestServerUDPStatusSeparate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pcfg := rendr.Config{}
		pcfg.Packet.Queue = 64 << 10
		w := newSUWorld(t, suOpts{streams: true, pcfg: pcfg})
		ts := newSUTargets(rendrtest.DatagramPipeConfig{Queue: 4096})
		gate := make(chan struct{})
		ts.wrap = func(srv, _ *rendrtest.DatagramConn, r Request) net.Conn {
			if r.Addr == "gated.test:1" {
				return &suGatedWrite{DatagramConn: srv, gate: gate}
			}
			return srv
		}
		echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		refuse, _ := rendrtest.ScriptedDial(rendrtest.OutcomeRefuse())
		s := &Server{UDP: true, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
			switch {
			case r.Addr == "refuse.test:1":
				return refuse(ctx, r.Addr)
			case r.Cmd == CmdUDP:
				return ts.dial(ctx, r)
			}
			return echo.Dial(ctx, r.Addr)
		}}
		sv := suServe(w, s)
		var conns []*rendr.Conn
		for range 2 {
			c, err := Dial(context.Background(), w.speer, kitTarget, rendr.DialOptions{})
			if err != nil {
				t.Fatalf("TCP Dial: %v", err)
			}
			echoRoundTrip(t, c, 4<<10, 1)
			conns = append(conns, c)
		}
		_, err := Dial(context.Background(), w.speer, "refuse.test:1", rendr.DialOptions{})
		wantReject(t, err, CodeRefused)
		var pcs []*rendr.PacketConn
		var echoes []<-chan struct{}
		for i := range 2 {
			pcs = append(pcs, suDial(t, w, pfTarget, pfData(10, byte(i))))
			echoes = append(echoes, suEcho(ts.next(t, time.Second)))
			pfRecvPC(t, pcs[i]) // the first datagram's echo
		}
		for range 2 {
			r := suRecv(t, suDialAsync(context.Background(), w, "refuse.test:1", nil, rendr.DialOptions{}), time.Minute)
			wantReject(t, r.err, CodeRefused)
		}
		// The gated flow: its target takes nothing until the gate opens.
		gpc := suDial(t, w, "gated.test:1", nil)
		gtarget := ts.next(t, time.Second)
		const n = 200
		for i := range n {
			if _, err := gpc.WriteTo(pfData(1000, byte(i)), nil); err != nil {
				t.Fatalf("WriteTo %d: %v", i, err)
			}
		}
		time.Sleep(time.Second)
		close(gate)
		got := 0
		for {
			gtarget.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := gtarget.Read(make([]byte, 2048)); err != nil {
				break
			}
			got++
		}
		gtarget.SetReadDeadline(time.Time{})
		dst := gpc.Status()
		gpc.Close()
		waitFor(t, time.Minute, "the gated flow's session drops are summed", func() bool { return s.Status().UDP.SessionDrops != 0 })
		synctest.Wait()
		u := s.Status().UDP
		if got == 0 || got == n || u.SessionDrops != uint64(n-got) {
			t.Fatalf("stimulus or sum: %d of %d datagrams delivered; SessionDrops %d, want %d", got, n, u.SessionDrops, n-got)
		}
		if d, l := packetDrops(dst.Packet), w.links[0].Stats().Session.Lost; d != 0 || l != 0 || gtarget.Counts().Dropped != 0 {
			t.Fatalf("drops elsewhere: the dialer's session %d, the link %d, the target pipe %d", d, l, gtarget.Counts().Dropped)
		}
		for i, pc := range pcs {
			pc.Close()
			<-echoes[i]
		}
		for _, c := range conns {
			c.Close()
		}
		waitFor(t, time.Minute, "every flow and connection ends", func() bool {
			st := s.Status()
			return st.Live == 0 && st.UDP.Live == 0
		})
		st := s.Status()
		if st.Confirmed != 2 || st.Rejected != 1 || st.Unconfirmed != 0 || st.Lost != 0 || len(st.ByCode) != 1 || st.ByCode[CodeRefused] != 1 {
			t.Fatalf("TCP status %+v", st)
		}
		u = st.UDP
		if u.Confirmed != 3 || u.Rejected != 2 || u.Unconfirmed != 0 || u.Lost != 0 || len(u.ByCode) != 1 || u.ByCode[CodeRefused] != 2 ||
			u.FirstSent != 2 || u.Ended != (FlowEnds{PeerClosed: 3}) {
			t.Fatalf("UDP status %+v", u)
		}
		sv.stop(t)
		suUnits(t, s)
		w.shutdown()
	})
}

// suGatedWrite is a Server end whose Writes wait for the gate: a target
// socket whose sends block.
type suGatedWrite struct {
	*rendrtest.DatagramConn
	gate <-chan struct{}
}

func (c *suGatedWrite) Write(b []byte) (int, error) {
	<-c.gate
	return c.DatagramConn.Write(b)
}

// TestServerUDPPendingEnds_L49_L50 (M6 design §A6.5, M4-D31; L49, L50):
// the pending phase's ends during a UDP flow's dial — the dialer's
// withdrawal, the AcceptTimeout, Listener.Close, Runtime.Close — cancel
// the dial through the pending context; no Reject is sent (Lost) and a
// conn that arrives late is closed once. When the session is decided
// after the socket was dialled, the socket is closed once (Unconfirmed):
// decided before the first datagram's write, nothing is written (even
// through a conn that ignores deadlines); decided after it, Confirm fails
// and FirstSent counts the datagram the target received (§A5.4). Serve's ctx during
// the dial answers CodeDialFailed and ends live flows (Stopped) at once.
// After
// Listener.Close confirmed flows run to their ends, and Serve returns
// net.ErrClosed after them.
func TestServerUDPPendingEnds_L49_L50(t *testing.T) {
	t.Run("withdrawal", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
			hl := newHookLog(hookOf(dial))
			s := &Server{UDP: true, Dial: hl.dial}
			sv := suServe(w, s)
			ctx, cancel := context.WithCancel(context.Background())
			ch := suDialAsync(ctx, w, pfTarget, pfData(10, 1), rendr.DialOptions{})
			waitFor(t, time.Minute, "the hook is called", func() bool { return counts.Calls() == 1 })
			time.Sleep(100 * time.Millisecond)
			cancelled := time.Now()
			cancel()
			if r := suRecv(t, ch, time.Minute); !errors.Is(r.err, context.Canceled) || r.at.Sub(cancelled) > time.Millisecond {
				t.Fatalf("DialUDP after cancel: %v after %v", r.err, r.at.Sub(cancelled))
			}
			waitFor(t, time.Minute, "the dial ends", func() bool { return s.Status().UDP.Dialing == 0 })
			_, _, _, returns := hl.snapshot()
			if len(returns) != 1 || returns[0].Sub(cancelled) > 100*time.Millisecond {
				t.Fatalf("the target dial returned %v after the withdrawal (want ≤ 100 ms)", returns)
			}
			if u := s.Status().UDP; u.Lost != 1 || u.Rejected != 0 || u.Confirmed != 0 || u.Unconfirmed != 0 || u.FirstSent != 0 {
				t.Fatalf("UDP status %+v", u)
			}
			sv.stop(t)
			suUnits(t, s)
			w.shutdown()
		})
	})
	t.Run("AcceptTimeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{acceptTimeout: 2 * time.Second})
			dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeLate(5 * time.Second))
			s := &Server{UDP: true, Dial: hookOf(dial), DialTimeout: 30 * time.Second}
			sv := suServe(w, s)
			r := suRecv(t, suDialAsync(context.Background(), w, pfTarget, nil, rendr.DialOptions{}), time.Minute)
			if !errors.Is(r.err, rendr.ErrCapacity) {
				t.Fatalf("DialUDP: %v, want the AcceptTimeout's ErrCapacity", r.err)
			}
			waitFor(t, time.Minute, "the late conn arrives", func() bool { return s.Status().Hooks == 0 })
			if u := s.Status().UDP; u.Lost != 1 || u.Rejected != 0 || counts.Unclosed() != 0 {
				t.Fatalf("UDP status %+v; %d conns open", u, counts.Unclosed())
			}
			sv.stop(t)
			suUnits(t, s)
			w.shutdown()
		})
	})
	for _, end := range []string{"Listener.Close", "Runtime.Close"} {
		t.Run(end, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				var late *suCount
				s := &Server{UDP: true, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
					<-ctx.Done() // the pending phase ended; a socket arrives anyway, with the error
					c, _ := ts.dial(context.Background(), r)
					late = &suCount{Conn: c}
					return late, ctx.Err()
				}}
				sv := suServe(w, s)
				ch := suDialAsync(context.Background(), w, pfTarget, pfData(10, 1), rendr.DialOptions{})
				waitFor(t, time.Minute, "the dial runs", func() bool { return s.Status().UDP.Dialing == 1 })
				if end == "Listener.Close" {
					w.ln.Close()
				} else {
					w.p.Close()
				}
				r := suRecv(t, ch, time.Minute)
				if r.err == nil {
					t.Fatal("DialUDP succeeded")
				}
				if err := sv.wait(t, time.Minute); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Serve: %v", err)
				}
				waitFor(t, time.Minute, "the hook returns", func() bool { return s.Status().Hooks == 0 })
				if u := s.Status().UDP; u.Lost != 1 || u.Rejected != 0 || u.Confirmed != 0 || late == nil || late.closes() != 1 {
					t.Fatalf("UDP status %+v; the late conn closed %d times", u, late.closes())
				}
				suUnits(t, s)
				w.shutdown()
			})
		})
	}
	t.Run("decided before the first write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			var sockp atomic.Pointer[suNoDeadline]
			ctx, cancel := context.WithCancel(context.Background())
			s := &Server{UDP: true, Dial: func(hctx context.Context, r Request) (net.Conn, error) {
				cancel()      // the dialer withdraws ...
				<-hctx.Done() // ... and the pending phase has ended when the socket is ready
				c, err := ts.dial(context.Background(), r)
				sock := &suNoDeadline{Conn: c}
				sockp.Store(sock)
				return sock, err
			}}
			sv := suServe(w, s)
			if r := suRecv(t, suDialAsync(ctx, w, pfTarget, pfData(25, 9), rendr.DialOptions{}), time.Minute); !errors.Is(r.err, context.Canceled) {
				t.Fatalf("DialUDP: %v", r.err)
			}
			waitFor(t, time.Minute, "the flow is decided", func() bool { return s.Status().UDP.Unconfirmed == 1 })
			ts.mu.Lock()
			out := ts.srv[0].Counts().Out
			ts.mu.Unlock()
			if u, sock := s.Status().UDP, sockp.Load(); u.FirstSent != 0 || out != 0 || u.Confirmed != 0 || u.Lost != 0 || u.Rejected != 0 || sock.closes.Load() != 1 {
				t.Fatalf("UDP status %+v; the socket sent %d datagrams and was closed %d times", u, out, sock.closes.Load())
			}
			sv.stop(t)
			suUnits(t, s)
			w.shutdown()
		})
	})
	t.Run("Confirm fails after the first write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			ctx, cancel := context.WithCancel(context.Background())
			var sockp atomic.Pointer[suWithdrawOnWrite]
			ts.wrap = func(srv, _ *rendrtest.DatagramConn, _ Request) net.Conn {
				c := &suWithdrawOnWrite{DatagramConn: srv, withdraw: cancel}
				sockp.Store(c)
				return c
			}
			s := &Server{UDP: true, Dial: ts.dial}
			sv := suServe(w, s)
			if r := suRecv(t, suDialAsync(ctx, w, pfTarget, pfData(25, 9), rendr.DialOptions{}), time.Minute); !errors.Is(r.err, context.Canceled) {
				t.Fatalf("DialUDP: %v", r.err)
			}
			waitFor(t, time.Minute, "the flow is decided", func() bool { return s.Status().UDP.Unconfirmed == 1 })
			ts.mu.Lock()
			out := ts.srv[0].Counts().Out
			ts.mu.Unlock()
			if u, sock := s.Status().UDP, sockp.Load(); u.FirstSent != 1 || out != 1 || u.Confirmed != 0 || u.Lost != 0 || u.Rejected != 0 || sock.closes.Load() != 1 {
				t.Fatalf("UDP status %+v; the socket sent %d datagrams and was closed %d times", u, out, sock.closes.Load())
			}
			sv.stop(t)
			suUnits(t, s)
			w.shutdown()
		})
	})
	t.Run("Serve stops", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			hang, _ := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
			s := &Server{UDP: true, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
				if r.Addr == "hang.test:1" {
					return hang(ctx, r.Addr)
				}
				return ts.dial(ctx, r)
			}}
			sv := suServe(w, s)
			pc := suDial(t, w, pfTarget, nil)
			done := suEcho(ts.next(t, time.Second))
			suRoundTrip(t, pc, pfData(30, 1))
			ch := suDialAsync(context.Background(), w, "hang.test:1", nil, rendr.DialOptions{})
			waitFor(t, time.Minute, "the dial runs", func() bool { return s.Status().UDP.Dialing == 1 })
			// Serve returns at once: a stopped flow's handler does not wait
			// for its session's end (the dialer has not closed it).
			start := time.Now()
			if err := sv.stop(t); !errors.Is(err, context.Canceled) || time.Since(start) > 0 {
				t.Fatalf("Serve: %v after %v", err, time.Since(start))
			}
			wantReject(t, suRecv(t, ch, time.Minute).err, CodeDialFailed)
			if _, err := pfRecvPC(t, pc); !errors.Is(err, io.EOF) {
				t.Fatalf("the stopped flow at the dialer: %v, want io.EOF", err)
			}
			<-done
			if u := s.Status().UDP; u.Ended != (FlowEnds{Stopped: 1}) || u.ByCode[CodeDialFailed] != 1 || u.Live != 0 {
				t.Fatalf("UDP status %+v", u)
			}
			pc.Close()
			suUnits(t, s)
			w.shutdown()
		})
	})
	t.Run("Listener.Close keeps flows", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			s := &Server{UDP: true, Dial: ts.dial}
			sv := suServe(w, s)
			var pcs []*rendr.PacketConn
			var echoes []<-chan struct{}
			for i := range 3 {
				pcs = append(pcs, suDial(t, w, pfTarget, nil))
				echoes = append(echoes, suEcho(ts.next(t, time.Second)))
				suRoundTrip(t, pcs[i], pfData(40, byte(i)))
			}
			w.ln.Close()
			time.Sleep(5 * time.Second)
			select {
			case err := <-sv.done:
				t.Fatalf("Serve returned %v while flows run", err)
			default:
			}
			for i, pc := range pcs {
				suRoundTrip(t, pc, pfData(400, byte(10+i)))
				pc.Close()
				<-echoes[i]
			}
			if err := sv.wait(t, time.Minute); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Serve: %v", err)
			}
			if u := s.Status().UDP; u.Ended != (FlowEnds{PeerClosed: 3}) || u.Confirmed != 3 || u.Live != 0 {
				t.Fatalf("UDP status %+v", u)
			}
			suUnits(t, s)
			w.shutdown()
		})
	})
}
