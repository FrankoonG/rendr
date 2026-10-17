//go:build !plan9

package l4

import (
	"context"
	"errors"
	"net"
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

// M6 WP5: the errno rows of the Server's UDP flows (M6-D18, M6-D34, R1-17).

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
// write paths run on every OS with the errno each OS reports; on Linux a
// real broadcast route is dialled by the default dialer as well.
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
	t.Run("linux broadcast route", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("platform row: only Linux refuses a broadcast connect without SO_BROADCAST; the Windows path is the first-write row above")
		}
		addr := suBroadcastRoute(t)
		for _, f := range firsts {
			first := f.first
			w := newSUWorld(t, suOpts{})
			s := &Server{UDP: true}
			sv := suServe(w, s)
			r := suRecv(t, suDialAsync(context.Background(), w, addr, first, rendr.DialOptions{}), time.Minute)
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
// connect this host refuses with EACCES: the loopback broadcast
// 127.255.255.255 where the local table routes it as a broadcast, else the
// directed broadcast of an IPv4 interface subnet (computed here, never
// written down). Nothing is sent: the connect is refused.
func suBroadcastRoute(t *testing.T) string {
	t.Helper()
	refused := func(a string) bool {
		c, err := net.Dial("udp", a)
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

// TestServerUDPSessionDropsFinal (R1-38): SessionDrops holds a flow
// session's final drop counts: datagrams the target sent that the passive
// session still held when the flow ended (here: no carrier, then a fatal
// error of the target socket ends the forward) are counted by the session
// after the forward returned — its MaxFlows unit is released at once —
// and HandleUDP adds them once the session has ended.
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
		if u := s.Status().UDP; u.Ended != (FlowEnds{Local: 1}) || u.SessionDrops != 0 {
			t.Fatalf("UDP status at the forward's end %+v", u)
		}
		waitFor(t, time.Minute, "the session's final drops", func() bool { return s.Status().UDP.SessionDrops == n })
		synctest.Wait()
		if u := s.Status().UDP; u.SessionDrops != n {
			t.Fatalf("SessionDrops %d, want the %d datagrams the session still held", u.SessionDrops, n)
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
// CodeDialFailed and Serve returns at once.
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
