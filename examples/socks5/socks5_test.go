package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The in-process rows of M4 design §A10.3 (synctest; the front end on a
// pipeListener, the passive's targets from rendrtest).

// readToEnd reads c to its end: the bytes and the error that ended it.
func readToEnd(c net.Conn) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4<<10)
	for {
		k, err := c.Read(buf)
		out = append(out, buf[:k]...)
		if err != nil {
			return out, err
		}
	}
}

// isReset reports a connection reset (a TargetPipe's or a real socket's).
func isReset(err error) bool {
	return errors.Is(err, rendrtest.ErrReset) || errors.Is(err, errConnReset)
}

// methodOK is the no-auth method reply.
var methodOK = []byte{socksVersion, methodNoAuth}

// Outcomes of a parser row.
const (
	outClosed  = iota // closed without a reply (after the method reply when the greeting was valid)
	outReply          // a reply with REP rep, then the clean end (FIN)
	outTimeout        // closed at the handshake deadline
)

// TestSocks5Parser_L44 runs the rows of §A10.3's table (R1-10, R1-11):
// strict versions and fields, exact reads, the deadline, the REP of each
// malformed request, and l4's address grammar behind the domain form.
func TestSocks5Parser_L44(t *testing.T) {
	req := func(q request) []byte { return appendRequest(append([]byte(nil), greeting...), q) }
	raw := func(b ...byte) []byte { return append(append([]byte(nil), greeting...), b...) }
	rows := []struct {
		name    string
		in      []byte
		oneByte bool // write in 1-byte writes
		out     int
		method  bool // the method reply precedes the outcome
		rep     byte
	}{
		{name: "socks4 greeting", in: []byte{4, 1, 0, 80, 192, 0, 2, 1, 0}, out: outClosed},
		{name: "http", in: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), out: outClosed},
		{name: "nmethods 0", in: []byte{socksVersion, 0}, out: outClosed},
		{name: "request version 4", in: raw(4, cmdConnect, 0, atypIPv4, 192, 0, 2, 1, 0, 80), out: outClosed, method: true},
		{name: "split greeting", in: req(connectReq("split.test", 80)), oneByte: true, out: outReply, method: true, rep: repSuccess},
		{name: "silent", in: nil, out: outTimeout},
		{name: "half a greeting", in: []byte{socksVersion, 3, methodNoAuth}, out: outTimeout},
		{name: "half a request", in: raw(socksVersion, cmdConnect, 0, atypDomain, 9, 'a'), out: outTimeout, method: true},
		{name: "rsv 1", in: raw(socksVersion, cmdConnect, 1, atypIPv4, 192, 0, 2, 1, 0, 80), out: outReply, method: true, rep: repFailure},
		{name: "atyp 2", in: raw(socksVersion, cmdConnect, 0, 2, 192, 0, 2, 1, 0, 80), out: outReply, method: true, rep: repBadAddress},
		{name: "atyp 5", in: raw(socksVersion, cmdConnect, 0, 5, 192, 0, 2, 1, 0, 80), out: outReply, method: true, rep: repBadAddress},
		{name: "domain len 0", in: req(connectReq("", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "NUL", in: req(connectReq("a\x00b.test", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "space", in: req(connectReq("a b.test", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "percent", in: req(connectReq("a%b.test", 80)), out: outReply, method: true, rep: repBadAddress},
		// A name never changes meaning on its way to l4 (rc7): "[A000]",
		// joined with its port, once travelled as A000 (FuzzSocks5Request_L44).
		{name: "brackets [A000]", in: req(connectReq("[A000]", 12336)), out: outReply, method: true, rep: repBadAddress},
		{name: "brackets around a name", in: req(connectReq("[ok.test]", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "brackets around IPv4", in: req(connectReq("[192.0.2.1]", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "brackets around IPv6", in: req(connectReq("[2001:db8::1]", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "one bracket", in: req(connectReq("ok.test]", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "colon", in: req(connectReq("a:b.test", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "host and port", in: req(connectReq("ok.test:80", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "tab", in: req(connectReq("a\tb.test", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "newline", in: req(connectReq("a\nb.test", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "slash", in: req(connectReq("a/b.test", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "numeric 127.1", in: req(connectReq("127.1", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "numeric 0x7f.1", in: req(connectReq("0x7f.1", 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "port 0", in: req(connectReq("ok.test", 0)), out: outReply, method: true, rep: repBadAddress},
		{name: "domain 254 with the trailing dot", in: req(connectReq(longName(253)+".", 80)), out: outReply, method: true, rep: repSuccess},
		{name: "domain 255", in: req(connectReq(longName(255), 80)), out: outReply, method: true, rep: repBadAddress},
		{name: "ipv4", in: req(request{cmd: cmdConnect, atyp: atypIPv4, addr: []byte{192, 0, 2, 1}, port: 80}), out: outReply, method: true, rep: repSuccess},
		{name: "ipv6", in: req(request{cmd: cmdConnect, atyp: atypIPv6, addr: net.ParseIP("2001:db8::1"), port: 443}), out: outReply, method: true, rep: repSuccess},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newStack(t, stackOpts{})
				c := s.connect()
				defer c.Close()
				start := time.Now()
				if r.oneByte {
					for i := range r.in {
						if _, err := c.Write(r.in[i : i+1]); err != nil {
							t.Fatalf("write byte %d: %v", i, err)
						}
						synctest.Wait()
					}
				} else if len(r.in) > 0 {
					if _, err := c.Write(r.in); err != nil {
						t.Fatalf("write: %v", err)
					}
				}
				var want []byte
				if r.method {
					want = append(want, methodOK...)
				}
				if r.out == outReply {
					want = append(want, reply(r.rep)...)
				}
				if r.rep == repSuccess && r.out == outReply {
					if _, err := io.ReadFull(c, make([]byte, len(want))); err != nil {
						t.Fatalf("read the replies: %v", err)
					}
					// The echo target answers: the connection works.
					if _, err := c.Write([]byte("ping")); err != nil {
						t.Fatalf("write: %v", err)
					}
					var b [4]byte
					if _, err := io.ReadFull(c, b[:]); err != nil || string(b[:]) != "ping" {
						t.Fatalf("echo: %q, %v", b, err)
					}
					return
				}
				got, err := readToEnd(c)
				if !bytes.Equal(got, want) {
					t.Fatalf("client read % x, want % x (then %v)", got, want, err)
				}
				switch r.out {
				case outReply:
					if err != io.EOF {
						t.Fatalf("after the reply: %v, want io.EOF (the failure reply is drained, L05)", err)
					}
				default:
					if err != io.EOF && !isReset(err) {
						t.Fatalf("end: %v, want a close", err)
					}
				}
				if el := time.Since(start); (r.out == outTimeout) != (el >= handshakeTimeout) || el > handshakeTimeout+drainTime {
					t.Fatalf("closed after %v (handshake deadline %v)", el, handshakeTimeout)
				}
				if st := s.srv.Status(); st.Confirmed+st.Rejected != 0 || s.target.Counts().Accepted != 0 {
					t.Fatalf("the passive saw the request: %+v, target %+v", st, s.target.Counts())
				}
			})
		})
	}
	t.Run("ip literal in domain form", ipLiteralRows)
}

// longName is a valid-looking name of n bytes: labels of at most 63 bytes
// joined by dots (n > 253 is too long for l4's grammar).
func longName(n int) string {
	var b strings.Builder
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strings.Repeat("a", min(63, n-b.Len())))
	}
	return b.String()
}

// ipLiteralRows are TestSocks5Parser_L44's R1-10 rows: an IP literal in
// ATYP 3 is a valid CONNECT and its OPEN carries the address type (1 or
// 4), captured on the link.
func ipLiteralRows(t *testing.T) {
	for _, r := range []struct {
		name string
		atyp byte
	}{{"192.0.2.1", atypIPv4}, {"2001:db8::1", atypIPv6}, {"::ffff:192.0.2.1", atypIPv4}} {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newStack(t, stackOpts{})
				warm := s.connect()
				if rep, err := socksConnect(warm, connectReq("warm.test", 80), nil); err != nil || rep != repSuccess {
					t.Fatalf("warm-up CONNECT: REP %d, %v", rep, err)
				}
				defer warm.Close()
				open := s.links[0].CaptureNextFrame(rendrtest.Up, rendrtest.FrameOpen)
				c := s.connect()
				defer c.Close()
				if rep, err := socksConnect(c, connectReq(r.name, 80), nil); err != nil || rep != repSuccess {
					t.Fatalf("CONNECT %s: REP %d, %v", r.name, rep, err)
				}
				var frame []byte
				select {
				case frame = <-open:
				default:
					t.Fatal("no OPEN captured on the link")
				}
				f, _, err := wire.DecodeFrame(frame)
				if err != nil || f.Type != wire.TypeOpen {
					t.Fatalf("captured frame: type %v, %v", f.Type, err)
				}
				o, err := wire.ParseOpen(f.Payload, wire.MaxMetadata)
				if err != nil {
					t.Fatalf("captured OPEN: %v", err)
				}
				if md := o.Metadata; len(md) < 6 || md[0] != 'L' || md[1] != '4' || md[4] != r.atyp {
					t.Fatalf("OPEN metadata % x, want L4 atyp %d", o.Metadata, r.atyp)
				}
			})
		})
	}
}

// TestSocks5NoAcceptableMethod (R1-13): a greeting without method 0 is
// answered 05 FF, then the drain and a clean close, also with bytes sent
// after it.
func TestSocks5NoAcceptableMethod(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newStack(t, stackOpts{})
		c := s.connect()
		defer c.Close()
		if _, err := c.Write(append([]byte{socksVersion, 1, 0x02}, bytes.Repeat([]byte{7}, 8<<10)...)); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := readToEnd(c)
		if !bytes.Equal(got, []byte{socksVersion, methodNone}) || err != io.EOF {
			t.Fatalf("client read % x then %v, want 05 ff then io.EOF", got, err)
		}
	})
}

// TestSocks5BadCommand: BIND and UDP ASSOCIATE are answered REP 07 and no
// session is opened.
func TestSocks5BadCommand(t *testing.T) {
	for _, cmd := range []byte{2, 3} {
		t.Run(fmt.Sprint("cmd", cmd), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newStack(t, stackOpts{})
				c := s.connect()
				defer c.Close()
				q := request{cmd: cmd, atyp: atypIPv4, addr: []byte{192, 0, 2, 1}, port: 80}
				if _, err := c.Write(appendRequest(append([]byte(nil), greeting...), q)); err != nil {
					t.Fatalf("write: %v", err)
				}
				got, err := readToEnd(c)
				if want := append(append([]byte(nil), methodOK...), reply(repBadCommand)...); !bytes.Equal(got, want) || err != io.EOF {
					t.Fatalf("client read % x then %v, want % x then io.EOF", got, err, want)
				}
				if st := s.srv.Status(); st.Confirmed+st.Rejected != 0 {
					t.Fatalf("a session was opened: %+v", st)
				}
			})
		})
	}
}

// TestSocks5ReplyAfterConfirm (M4-D45, plan:662): while the Server's hook
// holds the target dial, the client has the method reply and nothing more;
// the success reply follows the release.
func TestSocks5ReplyAfterConfirm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		defer target.Close()
		s := newStack(t, stackOpts{dial: func(ctx context.Context, r l4.Request) (net.Conn, error) {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return target.Dial(ctx, r.Addr)
		}})
		c := s.connect()
		defer c.Close()
		if _, err := c.Write(appendRequest(append([]byte(nil), greeting...), connectReq("held.test", 80))); err != nil {
			t.Fatalf("write: %v", err)
		}
		var m [2]byte
		if _, err := io.ReadFull(c, m[:]); err != nil || m != [2]byte(methodOK) {
			t.Fatalf("method reply % x, %v", m, err)
		}
		got := make(chan []byte, 1)
		go func() {
			b := make([]byte, 10)
			n, _ := io.ReadFull(c, b)
			got <- b[:n]
		}()
		time.Sleep(time.Second) // the OPEN crossed; the hook holds the dial (budget 5 s)
		if st := s.srv.Status(); st.Dialing != 1 {
			t.Fatalf("stimulus: the hook is not holding the dial: %+v", st)
		}
		select {
		case b := <-got:
			t.Fatalf("the client read % x before the target connected", b)
		default:
		}
		close(release)
		if b := <-got; !bytes.Equal(b, reply(repSuccess)) {
			t.Fatalf("reply % x, want % x", b, reply(repSuccess))
		}
	})
}

// TestSocks5ReplyCodes: every §A8.2 row. The Server's outcomes travel
// end to end (ScriptedDial and the hook's ErrDenied); the codes and errors
// no Server sends to this front end map through repOf.
func TestSocks5ReplyCodes(t *testing.T) {
	e2e := []struct {
		name string
		out  rendrtest.DialOutcome
		deny bool
		rep  byte
	}{
		{name: "refused", out: rendrtest.OutcomeRefuse(), rep: repRefused},
		{name: "net unreachable", out: rendrtest.OutcomeNetUnreachable(), rep: repNetUnreachable},
		{name: "host unreachable", out: rendrtest.OutcomeHostUnreachable(), rep: repHostUnreachable},
		{name: "dns not found", out: rendrtest.OutcomeDNSNotFound(), rep: repHostUnreachable},
		{name: "dns failure", out: rendrtest.OutcomeDNSFailure(), rep: repHostUnreachable},
		{name: "timeout", out: rendrtest.OutcomeHang(), rep: repHostUnreachable},
		{name: "panic", out: rendrtest.OutcomePanic(), rep: repFailure},
		{name: "denied", deny: true, rep: repNotAllowed},
	}
	for _, r := range e2e {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newStack(t, stackOpts{dial: func(ctx context.Context, q l4.Request) (net.Conn, error) {
					if r.deny {
						return nil, fmt.Errorf("policy: %w", l4.ErrDenied)
					}
					d, _ := rendrtest.ScriptedDial(r.out)
					return d(ctx, q.Addr)
				}})
				c := s.connect()
				defer c.Close()
				rep, err := socksConnect(c, connectReq("codes.test", 80), nil)
				if err != nil || rep != r.rep {
					t.Fatalf("REP %d, %v; want %d", rep, err, r.rep)
				}
				if rest, err := readToEnd(c); len(rest) != 0 || err != io.EOF {
					t.Fatalf("after the reply % x then %v, want io.EOF", rest, err)
				}
			})
		})
	}
	reject := func(c l4.RejectCode) error { return &rendr.RejectError{Code: uint32(c), Msg: c.String()} }
	unit := []struct {
		err error
		rep byte
	}{
		{reject(l4.CodeNotAllowed), repNotAllowed},
		{reject(l4.CodeNetUnreachable), repNetUnreachable},
		{reject(l4.CodeHostUnreachable), repHostUnreachable},
		{reject(l4.CodeTimeout), repHostUnreachable},
		{reject(l4.CodeDNSNotFound), repHostUnreachable},
		{reject(l4.CodeDNSFailure), repHostUnreachable},
		{reject(l4.CodeRefused), repRefused},
		{reject(l4.CodeBadCommand), repBadCommand},
		{reject(l4.CodeBadAddress), repBadAddress},
		{fmt.Errorf("x: %w", l4.ErrBadAddress), repBadAddress},
		{reject(l4.CodeBadRequest), repFailure},
		{reject(l4.CodeBadVersion), repFailure},
		{reject(l4.CodeCapacity), repFailure},
		{reject(l4.CodeDialFailed), repFailure},
		{&rendr.RejectError{Code: 0x1234}, repFailure},
		{rendr.ErrCapacity, repFailure},
		{rendr.ErrNoPath, repFailure},
		{rendr.ErrSessionLost, repFailure},
		{rendr.ErrVersion, repFailure},
		{rendr.ErrProtocol, repFailure},
		{context.Canceled, repFailure},
		{context.DeadlineExceeded, repFailure},
	}
	for _, u := range unit {
		if got := repOf(u.err); got != u.rep {
			t.Errorf("repOf(%v) = %d, want %d", u.err, got, u.rep)
		}
	}
}

// TestSocks5TargetReset (M4-D37, invariant 1): the target resets in the
// middle of its response; the SOCKS client reads a prefix of the response
// (the reset discards what was in flight), then a reset, never io.EOF.
func TestSocks5TargetReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 256 << 10
		target := rendrtest.NewTarget(rendrtest.TargetRSTAfter(n), 0)
		defer target.Close()
		s := newStack(t, stackOpts{dial: func(ctx context.Context, r l4.Request) (net.Conn, error) { return target.Dial(ctx, r.Addr) }})
		c := s.connect()
		defer c.Close()
		if rep, err := socksConnect(c, connectReq("reset.test", 80), nil); err != nil || rep != repSuccess {
			t.Fatalf("CONNECT: REP %d, %v", rep, err)
		}
		got, sum, err := readAll(c)
		if got > n || sum != prngSum(0, got) {
			t.Fatalf("client read %d bytes (a prefix of the response: %v), want at most %d", got, sum == prngSum(0, got), n)
		}
		if !isReset(err) {
			t.Fatalf("after the target's reset the client read %v, want a connection reset", err)
		}
		if tc := target.Counts(); tc.RSTOut != 1 {
			t.Fatalf("stimulus: the target did not reset: %+v", tc)
		}
	})
}

// TestSocks5OptimisticDataPreserved (§A9): bytes the client sends with its
// request, before the reply, reach the target first and in order: the
// reader's residue, then the socket.
func TestSocks5OptimisticDataPreserved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newStack(t, stackOpts{})
		c := s.connect().(*rendrtest.TargetConn)
		defer c.Close()
		const n = 20 << 10 // beyond the 4 KiB reader: residue and socket
		var payload bytes.Buffer
		io.CopyN(&payload, rendrtest.PRNG(5), n)
		msg := appendRequest(append([]byte(nil), greeting...), connectReq("echo.test", 80))
		wrote := make(chan error, 1)
		go func() {
			_, err := c.Write(append(msg, payload.Bytes()...))
			if err == nil {
				err = c.CloseWrite()
			}
			wrote <- err
		}()
		var b [12]byte
		if _, err := io.ReadFull(c, b[:]); err != nil || !bytes.Equal(b[:], append(append([]byte(nil), methodOK...), reply(repSuccess)...)) {
			t.Fatalf("replies % x, %v", b, err)
		}
		got, sum, err := readAll(c)
		if err != io.EOF || got != n || sum != prngSum(5, n) {
			t.Fatalf("echo: %d bytes (SHA ok %v), then %v; want %d, then io.EOF", got, sum == prngSum(5, n), err, n)
		}
		if err := <-wrote; err != nil {
			t.Fatalf("client write: %v", err)
		}
		if tc := s.target.Counts().Conns[0]; tc.BytesIn != n || tc.SHAIn != prngSum(5, n) || !tc.FINIn {
			t.Fatalf("target read %d bytes (SHA ok %v), FIN %v; want %d", tc.BytesIn, tc.SHAIn == prngSum(5, n), tc.FINIn, n)
		}
	})
}

// TestSocks5HalfCloseE2E_L04 (L04's M4 rerun): for each address type the
// client writes a 64 KiB request and half-closes; the target reads to EOF,
// answers 4 MiB and FINs; the client reads every byte, then io.EOF. In the
// stuck variant the request is held on carrier A and the session moves to
// B: the target still sees every byte before its EOF.
func TestSocks5HalfCloseE2E_L04(t *testing.T) {
	const req, resp = 64 << 10, 4 << 20
	rows := []struct {
		name  string
		q     request
		stuck bool
	}{
		{name: "ipv4", q: request{cmd: cmdConnect, atyp: atypIPv4, addr: []byte{192, 0, 2, 1}, port: 80}},
		{name: "ipv6", q: request{cmd: cmdConnect, atyp: atypIPv6, addr: net.ParseIP("2001:db8::1"), port: 80}},
		{name: "domain", q: connectReq("half.test", 80)},
		{name: "stuck on A", q: connectReq("half.test", 80), stuck: true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				target := rendrtest.NewTarget(rendrtest.TargetHalf(resp), 0)
				defer target.Close()
				o := stackOpts{dial: func(ctx context.Context, q l4.Request) (net.Conn, error) { return target.Dial(ctx, q.Addr) }}
				if r.stuck {
					o.links, o.rate = 2, 4<<20
				}
				s := newStack(t, o)
				c := s.connect().(*rendrtest.TargetConn)
				defer c.Close()
				if rep, err := socksConnect(c, r.q, nil); err != nil || rep != repSuccess {
					t.Fatalf("CONNECT: REP %d, %v", rep, err)
				}
				var stuck *rendrtest.Link
				if r.stuck {
					if stuck = s.activeLink(s.conn(0)); stuck == nil {
						t.Fatalf("no active carrier: %+v", s.conn(0).Status())
					}
					stuck.SetStall(true)
				}
				if err := writePRNG(c, 1, req); err != nil {
					t.Fatalf("client write: %v", err)
				}
				if err := c.CloseWrite(); err != nil {
					t.Fatalf("client CloseWrite: %v", err)
				}
				got, sum, err := readAll(c)
				if err != io.EOF || got != resp || sum != prngSum(0, resp) {
					t.Fatalf("client read %d bytes (SHA ok %v), then %v; want %d, then io.EOF", got, sum == prngSum(0, resp), err, resp)
				}
				tc := target.Counts().Conns[0]
				if tc.BytesIn != req || tc.SHAIn != prngSum(1, req) || !tc.FINIn {
					t.Fatalf("target read %d bytes (SHA ok %v), FIN %v; want %d", tc.BytesIn, tc.SHAIn == prngSum(1, req), tc.FINIn, req)
				}
				if r.stuck {
					if st := stuck.Stats(); st.Session.Held == 0 {
						t.Fatalf("stimulus: carrier A held nothing: %+v", st)
					}
					if m := s.conn(0).Status().Migrations.Death; m == 0 {
						t.Fatalf("stimulus: no death migration: %+v", s.conn(0).Status())
					}
				}
			})
		})
	}
}

// TestSocks5CarrierKill_L10: 16 MiB from the target while the carrier is
// killed twice: the client reads every byte (SHA) and io.EOF, no error.
func TestSocks5CarrierKill_L10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 16 << 20
		target := rendrtest.NewTarget(rendrtest.TargetGen(n, 3), 0)
		defer target.Close()
		s := newStack(t, stackOpts{links: 2, rate: 8 << 20, dial: func(ctx context.Context, q l4.Request) (net.Conn, error) { return target.Dial(ctx, q.Addr) }})
		c := s.connect().(*rendrtest.TargetConn)
		defer c.Close()
		if rep, err := socksConnect(c, connectReq("gen.test", 80), nil); err != nil || rep != repSuccess {
			t.Fatalf("CONNECT: REP %d, %v", rep, err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		type result struct {
			n   int64
			sum [32]byte
			err error
		}
		pr := &progressReader{r: c}
		done := make(chan result, 1)
		go func() {
			k, sum, err := readAll(pr)
			done <- result{k, sum, err}
		}()
		killed := 0
		for _, at := range []int64{4 << 20, 10 << 20} {
			for pr.n.Load() < at {
				time.Sleep(10 * time.Millisecond)
			}
			l := s.activeLink(s.conn(0))
			if l == nil {
				t.Fatalf("no active carrier at %d bytes", at)
			}
			if l.Kill() == 0 {
				t.Fatalf("stimulus: the kill at %d bytes found no carrier", at)
			}
			killed++
		}
		res := <-done
		if res.err != io.EOF || res.n != n || res.sum != prngSum(3, n) {
			t.Fatalf("client read %d bytes (SHA ok %v), then %v; want %d, then io.EOF", res.n, res.sum == prngSum(3, n), res.err, n)
		}
		if m := s.conn(0).Status().Migrations.Death; m < uint64(killed) {
			t.Fatalf("stimulus: %d death migrations after %d kills", m, killed)
		}
	})
}

// progressReader counts the bytes read through it.
type progressReader struct {
	r io.Reader
	n atomic.Int64
}

func (p *progressReader) Read(b []byte) (int, error) {
	k, err := p.r.Read(b)
	p.n.Add(int64(k))
	return k, err
}

// TestSocks5AcceptErrorBackoff: a failing Accept (EMFILE) does not stop
// the front end; it retries after 5, 10 and 20 ms and serves the next
// connection.
func TestSocks5AcceptErrorBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newStack(t, stackOpts{})
		synctest.Wait() // the front end waits in Accept
		for range 3 {
			s.pl.errs <- &net.OpError{Op: "accept", Net: "tcp", Err: errTooManyFiles}
		}
		start := time.Now()
		synctest.Wait() // the first error taken: the front end backs off
		c := s.connect()
		defer c.Close()
		if el := time.Since(start); el != 35*time.Millisecond {
			t.Fatalf("the connection was accepted after %v, want 35ms (5+10+20 ms of backoff)", el)
		}
		if rep, err := socksConnect(c, connectReq("after.test", 80), nil); err != nil || rep != repSuccess {
			t.Fatalf("CONNECT after the errors: REP %d, %v", rep, err)
		}
	})
}
