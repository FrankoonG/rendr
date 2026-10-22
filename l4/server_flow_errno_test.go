//go:build unix || windows

package l4

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP5: the errno and socket-option rows of the Server's UDP flows
// (M6-D18, M6-D34, R1-17).

// suAccessErrnos are the errnos M4's table maps to CodeNotAllowed: the
// Windows number on every OS, EACCES and EPERM where this OS names them.
func suAccessErrnos() []pfErrno {
	out := []pfErrno{{"WSAEACCES", syscall.Errno(10013)}}
	for _, e := range pfSymNoise() {
		if e.name == "EACCES" || e.name == "EPERM" {
			out = append(out, e)
		}
	}
	return out
}

// suWriteNoise are the errnos a first datagram's write counts as noise:
// the noise rows of §A7.2 except the access errnos, and the "message too
// long" errnos (a write's size class is noise, M6-D15).
func suWriteNoise() []pfErrno {
	access := suAccessErrnos()
	var out []pfErrno
	for _, e := range append(pfNoiseErrnos(), pfSizeErrnos()...) {
		if !slices.ContainsFunc(access, func(a pfErrno) bool { return a.name == e.name }) {
			out = append(out, e)
		}
	}
	return out
}

// suWriteErr is an errno as the net package returns it from a Write.
func suWriteErr(e error) error {
	return &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("write", e)}
}

// TestServerUDPFirstWriteErrors (M6-D18, R1-17; L58): the first datagram's
// write is classified before Confirm. An errno M4's table maps to
// CodeNotAllowed (EACCES, EPERM, WSAEACCES: a directed broadcast on
// Windows, a netfilter drop on output) refuses the flow CodeNotAllowed; an
// error that is not an errno, an errno of the fatal set and an invalid
// count refuse it CodeDialFailed — the target socket closed once, nothing
// confirmed. Every other errno (ECONNREFUSED, WSAECONNRESET, EMSGSIZE …)
// is noise: TargetNoise counts it, FirstSent does not, and the flow is
// confirmed and carries the next datagram.
func TestServerUDPFirstWriteErrors(t *testing.T) {
	type row struct {
		name  string
		err   error // the first Write's error (nil: a short count)
		short bool
		code  RejectCode // 0: noise, the flow confirmed
	}
	var rows []row
	for _, e := range suAccessErrnos() {
		rows = append(rows, row{e.name, e.err, false, CodeNotAllowed}, row{e.name + " in OpError", suWriteErr(e.err), false, CodeNotAllowed})
	}
	for _, e := range suWriteNoise() {
		rows = append(rows, row{e.name, suWriteErr(e.err), false, 0})
	}
	for _, e := range pfFatalErrnos() {
		rows = append(rows, row{e.name, suWriteErr(e.err), false, CodeDialFailed})
	}
	rows = append(rows,
		row{"not an errno", errors.New("an embedder tunnel's own failure"), false, CodeDialFailed},
		row{"net.ErrClosed", net.ErrClosed, false, CodeDialFailed},
		row{"short count", nil, true, CodeDialFailed})
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				var sock *suCount
				ts.wrap = func(srv, _ *rendrtest.DatagramConn, _ Request) net.Conn {
					if r.short {
						sock = &suCount{Conn: &suShortWrite{DatagramConn: srv}}
					} else {
						srv.InjectWrite(r.err, 1)
						sock = &suCount{Conn: srv}
					}
					return sock
				}
				s := &Server{UDP: true, Dial: ts.dial}
				sv := suServe(w, s)
				res := suRecv(t, suDialAsync(context.Background(), w, pfTarget, pfData(40, 1), rendr.DialOptions{}), time.Minute)
				target := ts.next(t, time.Second)
				u := s.Status().UDP
				if r.code != 0 {
					wantReject(t, res.err, r.code)
					if sock.closes() != 1 || u.Confirmed != 0 || u.FirstSent != 0 || u.TargetNoise != 0 || u.ByCode[r.code] != 1 {
						t.Fatalf("UDP status %+v; the socket closed %d times", u, sock.closes())
					}
					if st := s.Status(); st.LastErr == nil || r.err != nil && !errors.Is(st.LastErr, r.err) {
						t.Fatalf("LastErr %v, want the write's %v", st.LastErr, r.err)
					}
				} else {
					if res.err != nil {
						t.Fatalf("DialUDP: %v", res.err)
					}
					if u.Confirmed != 1 || u.FirstSent != 0 || u.TargetNoise != 1 || u.ToTarget != 0 {
						t.Fatalf("UDP status %+v", u)
					}
					d := pfData(60, 2)
					res.pc.WriteTo(d, nil)
					pfExpect(t, target, d)
					// The forward counts a datagram after its write returns,
					// so the target can read it first (M6 I3: a race-unit run
					// read ToTarget 0 in 2 of 3 passes on one worker, run
					// 20261022-225138-fa5f).
					synctest.Wait()
					if u := s.Status().UDP; u.ToTarget != 1 || u.TargetNoise != 1 {
						t.Fatalf("UDP status after a datagram %+v", u)
					}
					res.pc.Close()
				}
				sv.stop(t)
				suUnits(t, s)
				w.shutdown()
			})
		})
	}
}

// suShortWrite is a target socket whose first Write reports one byte less
// than it was given and sends nothing (an invalid count, L42).
type suShortWrite struct {
	*rendrtest.DatagramConn
	n int
}

func (c *suShortWrite) Write(b []byte) (int, error) {
	if c.n++; c.n == 1 {
		return len(b) - 1, nil
	}
	return c.DatagramConn.Write(b)
}

// TestServerUDPBroadcastNotAllowed (M6-D34, R1-17; §A10): a directed
// broadcast target is refused CodeNotAllowed wherever the OS refuses it:
// Linux at the connect (EACCES without SO_BROADCAST), Windows at the first
// write (WSAEACCES) when a first datagram rode the OPEN; without one the
// Windows flow opens and each write counts TargetNoise. The connect and
// write paths run on every OS with the errno each OS reports. The default
// dialer's socket has SO_BROADCAST off, which Go turns on for every IPv4
// datagram socket. That subrow uses a real loopback socket and sends
// nothing. On Linux the default dialer also dials a real broadcast route;
// a broken dialer's socket is closed before anything is written.
func TestServerUDPBroadcastNotAllowed(t *testing.T) {
	// The connect's errno: this OS's EACCES where it names one, else the
	// Windows number.
	access := suAccessErrnos()[0]
	for _, e := range suAccessErrnos() {
		if e.name == "EACCES" {
			access = e
		}
	}
	firsts := []struct {
		name  string
		first []byte
	}{{"first datagram", pfData(20, 1)}, {"no first datagram", nil}}
	t.Run("at the connect", func(t *testing.T) {
		for _, f := range firsts {
			first := f.first
			t.Run(f.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					w := newSUWorld(t, suOpts{})
					suSetDialUDP(t, func(ctx context.Context, addr string) (net.Conn, error) {
						return nil, &net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("connect", access.err)}
					})
					s := &Server{UDP: true}
					sv := suServe(w, s)
					r := suRecv(t, suDialAsync(context.Background(), w, "192.0.2.255:9", first, rendr.DialOptions{}), time.Minute)
					wantReject(t, r.err, CodeNotAllowed)
					sv.stop(t)
					suUnits(t, s)
					w.shutdown()
				})
			})
		}
	})
	t.Run("at the first write", func(t *testing.T) {
		for _, f := range firsts {
			first := f.first
			t.Run(f.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					w := newSUWorld(t, suOpts{})
					var target *rendrtest.DatagramConn
					suSetDialUDP(t, func(ctx context.Context, addr string) (net.Conn, error) {
						srv, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
						srv.InjectWrite(suWriteErr(syscall.Errno(10013)), 1<<20) // every send refused
						target = app
						return srv, nil
					})
					s := &Server{UDP: true}
					sv := suServe(w, s)
					r := suRecv(t, suDialAsync(context.Background(), w, "192.0.2.255:9", first, rendr.DialOptions{}), time.Minute)
					if first != nil {
						wantReject(t, r.err, CodeNotAllowed)
					} else {
						if r.err != nil {
							t.Fatalf("DialUDP without a first datagram: %v", r.err)
						}
						for i := range 3 {
							r.pc.WriteTo(pfData(30, byte(i)), nil)
						}
						waitFor(t, time.Minute, "the writes are refused", func() bool { return s.Status().UDP.TargetNoise == 3 })
						if u := s.Status().UDP; u.Live != 1 || u.ToTarget != 0 || target.Counts().In != 0 {
							t.Fatalf("UDP status %+v; the target read %d", u, target.Counts().In)
						}
						r.pc.Close()
					}
					sv.stop(t)
					suUnits(t, s)
					w.shutdown()
				})
			})
		}
	})
	t.Run("default dialer clears SO_BROADCAST", func(t *testing.T) {
		// The premise: Go's own UDP socket has SO_BROADCAST on.
		plain, err := net.Dial("udp", "127.0.0.1:9")
		if err != nil {
			t.Fatalf("premise: %v", err)
		}
		defer plain.Close()
		if v := suSockopt(t, plain, syscall.SOL_SOCKET, syscall.SO_BROADCAST); v == 0 {
			t.Fatal("premise: Go's UDP socket has SO_BROADCAST off; the row proves nothing")
		}
		c, err := dialUDP(context.Background(), "127.0.0.1:9") // connect only: nothing is sent
		if err != nil {
			t.Fatalf("dialUDP: %v", err)
		}
		defer c.Close()
		if v := suSockopt(t, c, syscall.SOL_SOCKET, syscall.SO_BROADCAST); v != 0 {
			t.Fatalf("the default dialer's socket has SO_BROADCAST %d, want 0", v)
		}
		// IPv6 has no broadcast: the Control lets an IPv6 socket connect.
		if c6, err := dialUDP(context.Background(), "[::1]:9"); err == nil {
			c6.Close()
		} else if errors.Is(err, ErrDenied) {
			t.Fatalf("dialUDP [::1]: %v", err)
		}
	})
	if raceEnabled {
		// racebudget (M6 I1, R1-37): about 2 s of real time on Linux; the
		// kernel's EACCES runs in the non-race unit and sweep lanes, and
		// the race lane keeps the default dialer's SO_BROADCAST rows above.
		return
	}
	t.Run("linux broadcast route", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("platform row: only Linux refuses a broadcast connect without SO_BROADCAST; the Windows path is the first-write row above")
		}
		addr := suBroadcastRoute(t)
		// The default dialer runs as it is. A socket it connects to the
		// broadcast (a broken dialer) is closed here before the first datagram
		// is written, and the row fails: nothing is broadcast.
		var breach atomic.Bool
		orig := dialUDP
		suSetDialUDP(t, func(ctx context.Context, a string) (net.Conn, error) {
			c, err := orig(ctx, a)
			if err == nil {
				c.Close()
				breach.Store(true)
				return nil, errors.New("the default dialer connected a broadcast target")
			}
			return c, err
		})
		for _, f := range firsts {
			first := f.first
			w := newSUWorld(t, suOpts{})
			s := &Server{UDP: true}
			sv := suServe(w, s)
			r := suRecv(t, suDialAsync(context.Background(), w, addr, first, rendr.DialOptions{}), time.Minute)
			if breach.Load() {
				t.Fatalf("the default dialer connected a socket to the broadcast %s (SO_BROADCAST on)", addr)
			}
			wantReject(t, r.err, CodeNotAllowed)
			if st := s.Status(); !errors.Is(st.LastErr, syscall.EACCES) {
				t.Fatalf("LastErr %v, want the connect's EACCES", st.LastErr)
			}
			sv.stop(t)
			w.shutdown()
		}
	})
}

// suBroadcastRoute returns a "host:port" (port 9, discard) whose UDP
// connect this host refuses with EACCES when SO_BROADCAST is off: the
// loopback broadcast 127.255.255.255 where the local table routes it as a
// broadcast, else the directed broadcast of an IPv4 interface subnet
// (computed here, never written down). The probe turns SO_BROADCAST off
// itself, independently of the dialer under test, and only connects:
// nothing is sent.
func suBroadcastRoute(t *testing.T) string {
	t.Helper()
	d := &net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = suSetsockopt(syscall.SetsockoptInt, fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
		}); err != nil {
			return err
		}
		return serr
	}}
	refused := func(a string) bool {
		c, err := d.Dial("udp", a)
		if err == nil {
			c.Close()
		}
		return errors.Is(err, syscall.EACCES)
	}
	if a := "127.255.255.255:9"; refused(a) {
		return a
	}
	addrs, _ := net.InterfaceAddrs()
	for _, ia := range addrs {
		n, ok := ia.(*net.IPNet)
		if !ok || n.IP.To4() == nil || n.IP.IsLoopback() {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones >= 31 {
			continue
		}
		b := n.IP.To4().Mask(n.Mask)
		for i := range b {
			b[i] |= ^n.Mask[len(n.Mask)-4+i]
		}
		if a := net.JoinHostPort(b.String(), "9"); refused(a) {
			return a
		}
	}
	t.Fatal("premise: no broadcast route refused a UDP connect with EACCES")
	return ""
}

// suSockopt reads the int socket option level/opt of c's socket.
func suSockopt(t testing.TB, c net.Conn, level, opt int) int {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("%T has no socket", c)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) { v, gerr = suGetsockopt(syscall.GetsockoptInt, fd, level, opt) }); err != nil || gerr != nil {
		t.Fatalf("getsockopt: %v, %v", err, gerr)
	}
	return v
}

// suGetsockopt and suSetsockopt call get or set (syscall.GetsockoptInt,
// syscall.SetsockoptInt: an int descriptor on Unix, a syscall.Handle on
// Windows) on fd.
func suGetsockopt[H ~int | ~uintptr](get func(H, int, int) (int, error), fd uintptr, level, opt int) (int, error) {
	return get(H(fd), level, opt)
}

func suSetsockopt[H ~int | ~uintptr](set func(H, int, int, int) error, fd uintptr, level, opt, v int) error {
	return set(H(fd), level, opt, v)
}

// suWildcardToLoopback reports whether Go's net package dials the loopback
// for an unspecified target address on this OS (net/ipsock_posix.go), so
// that the Control sees 127.0.0.1 or ::1 instead.
var suWildcardToLoopback = runtime.GOOS == "windows" || runtime.GOOS == "aix" || runtime.GOOS == "openbsd"

// TestServerUDPResolvedTargetRefused (M6-D34; §A10): the metadata rules
// refuse multicast, limited-broadcast and unspecified addresses as
// literals, and a name may resolve to one. The default UDP dialer's Control
// sees each resolved address before the connect and refuses such an
// address with an error wrapping ErrDenied (CodeNotAllowed). There is one
// exception: where Go dials the loopback for an unspecified address, the
// Control sees, and allows, the loopback, as it allows a literal 127.0.0.1
// target. Real sockets, outside bubbles. Every refusal happens before the
// connect, so nothing is sent.
func TestServerUDPResolvedTargetRefused(t *testing.T) {
	refused := []string{"239.255.0.1:9", "[ff02::1]:9", "[ff05::2]:9", "255.255.255.255:9", "[::ffff:239.255.0.1]:9", "[::ffff:255.255.255.255]:9"}
	unspecified := []string{"0.0.0.0:9", "[::]:9"}
	t.Run("dialUDP", func(t *testing.T) {
		for _, a := range append(refused, unspecified...) {
			c, err := dialUDP(context.Background(), a)
			if err == nil {
				ra := c.RemoteAddr()
				c.Close()
				if ap, perr := netip.ParseAddrPort(ra.String()); suWildcardToLoopback && slices.Contains(unspecified, a) && perr == nil && ap.Addr().IsLoopback() {
					continue // dialled as the loopback, as a literal loopback target
				}
				t.Fatalf("dialUDP %s connected to %v", a, ra)
			}
			if !errors.Is(err, ErrDenied) || classify(err) != CodeNotAllowed {
				t.Fatalf("dialUDP %s: %v (%v), want ErrDenied and CodeNotAllowed", a, err, classify(err))
			}
		}
		c, err := dialUDP(context.Background(), "127.0.0.1:9")
		if err != nil {
			t.Fatalf("dialUDP of an allowed address: %v", err)
		}
		c.Close()
	})
	t.Run("through HandleUDP", func(t *testing.T) {
		echo := suRealEcho(t)
		// The names' resolution: the wrapper maps each .test name to its
		// address and hands that to the default dialer, as the resolver does.
		// A socket the dialer connects for a refused name (a broken dialer)
		// is closed here before anything is written, and the row fails: no
		// multicast or broadcast datagram ever leaves this host.
		names := map[string]string{"mcast.test": "239.255.0.1", "mcast6.test": "ff05::2", "bcast.test": "255.255.255.255", "echo.test": "127.0.0.1"}
		_, echoPort, _ := net.SplitHostPort(echo.String())
		var breach atomic.Pointer[string]
		orig := dialUDP
		suSetDialUDP(t, func(ctx context.Context, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if ip, ok := names[host]; ok {
				addr = net.JoinHostPort(ip, port)
			}
			c, err := orig(ctx, addr)
			if err == nil && host != "echo.test" {
				c.Close()
				breach.Store(&addr)
				return nil, errors.New("the default dialer connected a refused target")
			}
			return c, err
		})
		w := newSUWorld(t, suOpts{})
		s := &Server{UDP: true}
		sv := suServe(w, s)
		want := uint64(0)
		for _, name := range []string{"mcast.test", "mcast6.test", "bcast.test"} {
			for _, first := range [][]byte{pfData(20, 1), nil} {
				r := suRecv(t, suDialAsync(context.Background(), w, name+":9", first, rendr.DialOptions{}), time.Minute)
				if b := breach.Load(); b != nil {
					t.Fatalf("%s: the default dialer connected a socket to %s", name, *b)
				}
				wantReject(t, r.err, CodeNotAllowed)
				want++
				st := s.Status()
				if !errors.Is(st.LastErr, errResolvedTarget) || st.UDP.ByCode[CodeNotAllowed] != want || st.UDP.FirstSent != 0 {
					t.Fatalf("%s: LastErr %v; UDP status %+v", name, st.LastErr, st.UDP)
				}
			}
		}
		// An allowed name is served through the same dialer.
		first := pfData(30, 2)
		pc := suDial(t, w, net.JoinHostPort("echo.test", echoPort), first)
		if got, err := pfRecvPC(t, pc); err != nil || string(got) != string(first) {
			t.Fatalf("the allowed name's echo: %d bytes, %v", len(got), err)
		}
		pc.Close()
		waitFor(t, 10*time.Second, "the flow ends", func() bool { return s.Status().UDP.Live == 0 })
		if u := s.Status().UDP; u.Confirmed != 1 || u.Rejected != want {
			t.Fatalf("UDP status %+v", u)
		}
		sv.stop(t)
		suUnits(t, s)
		w.shutdown()
	})
}

// TestServerUDPSessionDropsFinal (R1-38): SessionDrops holds a flow
// session's final drop counts: datagrams the target sent that the passive
// session still held when the flow ended (here: no carrier, then a fatal
// error of the target socket ends the forward) are counted by the session
// after the forward returned — its MaxFlows unit is released at once —
// and HandleUDP adds them once the session has ended. Meanwhile its
// goroutine is the only handler left; the wait is at most Linger plus the
// carrier joins, and the handler returns once the session ended.
func TestServerUDPSessionDropsFinal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSUWorld(t, suOpts{})
		ts := newSUTargets(rendrtest.DatagramPipeConfig{})
		var sock *rendrtest.DatagramConn
		ts.wrap = func(srv, _ *rendrtest.DatagramConn, _ Request) net.Conn {
			sock = srv
			return srv
		}
		s := &Server{UDP: true, Dial: ts.dial}
		sv := suServe(w, s)
		pc := suDial(t, w, pfTarget, nil)
		target := ts.next(t, time.Second)
		d := pfData(50, 1)
		pc.WriteTo(d, nil)
		pfExpect(t, target, d)
		// No carrier from now on: the passive session queues what the target
		// sends.
		w.links[0].Refuse(true)
		w.links[0].Kill()
		time.Sleep(time.Second)
		const n = 10
		for i := range n {
			pfSend(t, target, pfData(80, byte(i)))
		}
		synctest.Wait() // the forward handed every datagram to the session
		if u := s.Status().UDP; u.FromTarget != n {
			t.Fatalf("premise: %d datagrams from the target reached the session", u.FromTarget)
		}
		sock.Inject(suWriteErr(syscall.Errno(10009)), true) // WSAEBADF: the forward ends at once
		waitFor(t, time.Minute, "the forward ends", func() bool { return s.Status().UDP.Live == 0 })
		suUnits(t, s)
		ended := time.Now()
		if u := s.Status().UDP; u.Ended != (FlowEnds{Local: 1}) || u.SessionDrops != 0 {
			t.Fatalf("UDP status at the forward's end %+v", u)
		}
		// The handler outlives its unit while the session ends: one
		// goroutine, past serveFlow.
		synctest.Wait()
		if all, serving := suHandlers(); all != 1 || serving != 0 {
			t.Fatalf("%d HandleUDP goroutines (%d in serveFlow) while the session ends, want 1 (0)", all, serving)
		}
		waitFor(t, time.Minute, "the session's final drops", func() bool { return s.Status().UDP.SessionDrops == n })
		// The wait is bounded by the passive's Linger (the kit's 10 s) and
		// the carrier joins (about 2 s).
		if el := time.Since(ended); el > 12*time.Second {
			t.Fatalf("the handler waited %v for the session's end, want at most Linger + 2 s", el)
		}
		synctest.Wait()
		if u := s.Status().UDP; u.SessionDrops != n {
			t.Fatalf("SessionDrops %d, want the %d datagrams the session still held", u.SessionDrops, n)
		}
		if all, _ := suHandlers(); all != 0 {
			t.Fatalf("%d HandleUDP goroutines after the session ended", all)
		}
		pc.Close()
		sv.stop(t)
		w.shutdown()
	})
}

// TestServerUDPFirstWriteBlocked_L52 (M6-D18; L52, L49): a first-datagram
// Write that blocks (an embedder's datagram conn whose send waits) never
// holds the handler: the dialer's withdrawal, the AcceptTimeout and
// Serve's ctx each set the conn's write deadline, which ends the Write;
// the conn is closed once; the withdrawal and the AcceptTimeout count as
// a failed Confirm (Unconfirmed, no Reject: §A6.5), Serve's stop answers
// CodeDialFailed and Serve returns at once. While the write blocks, the
// flow shows in Status as Dialing.
func TestServerUDPFirstWriteBlocked_L52(t *testing.T) {
	for _, end := range []string{"withdrawal", "AcceptTimeout", "Serve stops"} {
		t.Run(end, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSUWorld(t, suOpts{acceptTimeout: 2 * time.Second})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				var sockp atomic.Pointer[suBlockWrite]
				ts.wrap = func(srv, _ *rendrtest.DatagramConn, _ Request) net.Conn {
					c := &suBlockWrite{DatagramConn: srv, wake: make(chan struct{}, 1)}
					sockp.Store(c)
					return c
				}
				s := &Server{UDP: true, Dial: ts.dial}
				sv := suServe(w, s)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ch := suDialAsync(ctx, w, pfTarget, pfData(20, 1), rendr.DialOptions{})
				waitFor(t, time.Minute, "the first write blocks", func() bool { c := sockp.Load(); return c != nil && c.writes.Load() == 1 })
				sock := sockp.Load()
				synctest.Wait()
				if u := s.Status().UDP; u.Dialing != 1 || u.Live != 0 {
					t.Fatalf("UDP status while the first write blocks %+v: the flow counts as Dialing until Confirm", u)
				}
				start := time.Now()
				switch end {
				case "withdrawal":
					cancel()
				case "Serve stops":
					if err := sv.stop(t); !errors.Is(err, context.Canceled) || time.Since(start) > 0 {
						t.Fatalf("Serve: %v after %v", err, time.Since(start))
					}
				}
				r := suRecv(t, ch, time.Minute)
				waitFor(t, time.Minute, "the handler ends", func() bool { return s.udp.units.Load() == 0 })
				u := s.Status().UDP
				switch end {
				case "Serve stops":
					wantReject(t, r.err, CodeDialFailed)
					if u.ByCode[CodeDialFailed] != 1 || u.Lost != 0 {
						t.Fatalf("UDP status %+v", u)
					}
				default:
					if r.err == nil {
						t.Fatal("DialUDP succeeded")
					}
					if u.Unconfirmed != 1 || u.Lost != 0 || u.Rejected != 0 {
						t.Fatalf("UDP status %+v", u)
					}
				}
				// The AcceptTimeout ends the write 2 s after the admission (the
				// write began right after it).
				if el := time.Since(start); end == "AcceptTimeout" && el > 2*time.Second+50*time.Millisecond || end != "AcceptTimeout" && el > 10*time.Millisecond {
					t.Fatalf("the blocked write held the handler %v past its end", el)
				}
				if sock.closes.Load() != 1 || u.Confirmed != 0 || u.FirstSent != 0 {
					t.Fatalf("the socket closed %d times; UDP status %+v", sock.closes.Load(), u)
				}
				if end != "Serve stops" {
					sv.stop(t)
				}
				w.shutdown()
			})
		})
	}
}

// suBlockWrite is a target socket whose Writes block until its write
// deadline is set to a passed instant (then os.ErrDeadlineExceeded).
type suBlockWrite struct {
	*rendrtest.DatagramConn
	mu     sync.Mutex
	dl     time.Time
	wake   chan struct{}
	writes atomic.Int32
	closes atomic.Int32
}

func (c *suBlockWrite) deadline(t time.Time) {
	c.mu.Lock()
	c.dl = t
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *suBlockWrite) SetWriteDeadline(t time.Time) error { c.deadline(t); return nil }

func (c *suBlockWrite) SetDeadline(t time.Time) error {
	c.deadline(t)
	return c.DatagramConn.SetReadDeadline(t)
}

func (c *suBlockWrite) Write(b []byte) (int, error) {
	c.writes.Add(1)
	for {
		c.mu.Lock()
		dl := c.dl
		c.mu.Unlock()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, &net.OpError{Op: "write", Net: "udp", Err: os.ErrDeadlineExceeded}
		}
		<-c.wake
	}
}

func (c *suBlockWrite) Close() error {
	c.closes.Add(1)
	c.deadline(time.Now())
	return c.DatagramConn.Close()
}
