package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
)

// The SOCKS5 subset of RFC 1928 this front end speaks: version 5, the
// no-authentication method, CONNECT; every reply carries BND = 0.0.0.0:0.
const (
	socksVersion = 5
	methodNoAuth = 0x00
	methodNone   = 0xFF
	cmdConnect   = 1
	atypIPv4     = 1
	atypDomain   = 3
	atypIPv6     = 4
)

// Reply codes (REP).
const (
	repSuccess         = 0x00
	repFailure         = 0x01
	repNotAllowed      = 0x02
	repNetUnreachable  = 0x03
	repHostUnreachable = 0x04
	repRefused         = 0x05
	repBadCommand      = 0x07
	repBadAddress      = 0x08
)

// Bounds (M4-D46, L48; L05).
const (
	maxHandshakes    = 256              // handshakes at once; a newcomer beyond is closed at once
	handshakeTimeout = 10 * time.Second // the greeting and the request together
	readerSize       = 4 << 10          // optimistic bytes read ahead; the rest waits in the socket
	drainTime        = time.Second      // a failure reply's drain: at most this long
	drainMax         = 64 << 10         // and at most this many bytes
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = 100 * time.Millisecond
)

// errHandshake ends a connection without a reply: a version other than 5,
// or a greeting without methods.
var errHandshake = errors.New("socks5: not a SOCKS5 greeting or request")

// tcpConn is a client connection: a *net.TCPConn, or an in-memory conn of
// the same shape in tests.
type tcpConn interface {
	net.Conn
	CloseWrite() error
	SetLinger(sec int) error
}

// front is the client's SOCKS5 front end: it accepts SOCKS connections,
// runs each handshake under the bounds above and forwards each CONNECT
// over the session dial opens.
type front struct {
	dial    func(ctx context.Context, addr string) (*rendr.Conn, error)
	logf    func(format string, v ...any)
	timeout time.Duration  // the handshake deadline
	slots   chan struct{}  // one per running handshake
	wg      sync.WaitGroup // one per accepted connection
}

func newFront(dial func(context.Context, string) (*rendr.Conn, error), logf func(string, ...any)) *front {
	return &front{dial: dial, logf: logf, timeout: handshakeTimeout, slots: make(chan struct{}, maxHandshakes)}
}

// serve accepts from ln until ctx is done or ln is closed, handles each
// connection on its own goroutine and returns after every one ended: nil
// after ctx ended it, else Accept's net.ErrClosed. Every other Accept error
// (EMFILE, for example; a TCP listener fails for good only once closed) is
// retried after a backoff of 5 ms → 100 ms. Cancelling ctx closes ln, ends
// running handshakes at once and resets forwarded connections.
func (f *front) serve(ctx context.Context, ln net.Listener) error {
	defer f.wg.Wait()
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		switch {
		case ctx.Err() != nil:
			if c != nil {
				c.Close()
			}
			return nil
		case errors.Is(err, net.ErrClosed):
			return err
		case err != nil:
			backoff = min(max(2*backoff, acceptBackoffMin), acceptBackoffMax)
			f.logf("accept: %v (retrying in %v)", err, backoff)
			t := time.NewTimer(backoff)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
			}
			continue
		}
		backoff = 0
		tc, ok := c.(tcpConn)
		if !ok {
			c.Close()
			continue
		}
		select {
		case f.slots <- struct{}{}:
		default:
			c.Close() // the handshake bound: a newcomer beyond it is closed at once
			continue
		}
		f.wg.Go(func() { f.handle(ctx, tc) })
	}
}

// handshakes returns how many handshakes are running.
func (f *front) handshakes() int { return len(f.slots) }

// handle serves one SOCKS connection that holds a handshake slot: the
// greeting and the request within the deadline, then the dial; the reply
// is written only after dial returned (the session was confirmed or
// rejected); a failure reply is followed by the drain (failReply), a
// success by Forward with the bytes the client sent ahead.
func (f *front) handle(ctx context.Context, c tcpConn) {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(f.timeout))
	br := bufio.NewReaderSize(c, readerSize)
	req, fail, err := handshake(br, c)
	if err != nil || fail != nil {
		if fail != nil {
			failReply(c, fail)
		} else {
			c.Close()
		}
		<-f.slots
		return
	}
	<-f.slots
	c.SetDeadline(time.Time{})
	addr := req.hostport()
	rc, err := f.dial(ctx, addr)
	if err != nil {
		f.logf("CONNECT %s: %v", addr, err)
		failReply(c, reply(repOf(err)))
		return
	}
	if !stop() { // ctx ended during the dial: c is closed
		rc.Abort(l4.AbortShutdown, "SOCKS front end stopping")
		rc.Close()
		return
	}
	if _, err := c.Write(reply(repSuccess)); err != nil {
		rc.Abort(l4.AbortReset, "SOCKS client failed")
		rc.Close()
		c.Close()
		return
	}
	l4.Forward(ctx, rc, &clientConn{tcpConn: c, r: br})
}

// failReply writes a failure reply, half-closes and drains what the client
// sent (at most drainMax bytes for at most drainTime) before the Close, so
// unread optimistic bytes do not turn the Close into a reset that destroys
// the reply (L05).
func failReply(c tcpConn, b []byte) {
	c.SetDeadline(time.Now().Add(drainTime))
	if _, err := c.Write(b); err == nil && c.CloseWrite() == nil {
		io.CopyN(io.Discard, c, drainMax)
	}
	c.Close()
}

// request is a parsed SOCKS5 request.
type request struct {
	cmd, atyp byte
	addr      []byte // 4 or 16 bytes, or the domain's bytes as given
	port      uint16
}

// hostport is the request's destination as l4.Dial takes it; l4 applies
// its address grammar (a bad name or port 0 is l4.ErrBadAddress; an IP
// literal in domain form travels as that address; a name in square
// brackets, which the host:port form would read as what they enclose, is
// l4.ErrBadAddress too), so a name never changes meaning on its way.
func (q request) hostport() string {
	host := string(q.addr)
	if q.atyp != atypDomain {
		ip, _ := netip.AddrFromSlice(q.addr)
		host = ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(q.port)))
}

// handshake reads the greeting and the request from r with exact reads (r
// keeps what the client sent beyond them) and writes the method reply to
// w. It returns the request; or fail, the failure reply to send before the
// drain; or err, when the connection is closed without a reply (a read or
// write failure, a version other than 5, a greeting without methods).
func handshake(r *bufio.Reader, w io.Writer) (req request, fail []byte, err error) {
	var buf [255 + 2]byte // the longest field: a 255-byte domain and the port
	if _, err = io.ReadFull(r, buf[:2]); err != nil {
		return req, nil, err
	}
	if buf[0] != socksVersion || buf[1] == 0 {
		return req, nil, errHandshake
	}
	methods := buf[:buf[1]]
	if _, err = io.ReadFull(r, methods); err != nil {
		return req, nil, err
	}
	if bytes.IndexByte(methods, methodNoAuth) < 0 {
		return req, []byte{socksVersion, methodNone}, nil
	}
	if _, err = w.Write([]byte{socksVersion, methodNoAuth}); err != nil {
		return req, nil, err
	}
	if _, err = io.ReadFull(r, buf[:4]); err != nil {
		return req, nil, err
	}
	switch req.cmd, req.atyp = buf[1], buf[3]; {
	case buf[0] != socksVersion:
		return req, nil, errHandshake
	case req.cmd != cmdConnect:
		return req, reply(repBadCommand), nil
	case req.atyp != atypIPv4 && req.atyp != atypDomain && req.atyp != atypIPv6:
		return req, reply(repBadAddress), nil
	case buf[2] != 0:
		return req, reply(repFailure), nil
	}
	n := 4
	switch req.atyp {
	case atypIPv6:
		n = 16
	case atypDomain:
		if _, err = io.ReadFull(r, buf[:1]); err != nil {
			return req, nil, err
		}
		n = int(buf[0])
	}
	if _, err = io.ReadFull(r, buf[:n+2]); err != nil {
		return req, nil, err
	}
	req.addr = bytes.Clone(buf[:n])
	req.port = uint16(buf[n])<<8 | uint16(buf[n+1])
	return req, nil, nil
}

// reply is the reply with code rep and BND = 0.0.0.0:0.
func reply(rep byte) []byte {
	return []byte{socksVersion, rep, 0, atypIPv4, 0, 0, 0, 0, 0, 0}
}

// repOf maps a dial error to its REP (M4 design §A8.2).
func repOf(err error) byte {
	if errors.Is(err, l4.ErrBadAddress) {
		return repBadAddress
	}
	code, ok := l4.CodeOf(err)
	if !ok {
		return repFailure
	}
	switch code {
	case l4.CodeNotAllowed:
		return repNotAllowed
	case l4.CodeNetUnreachable:
		return repNetUnreachable
	case l4.CodeHostUnreachable, l4.CodeTimeout, l4.CodeDNSNotFound, l4.CodeDNSFailure:
		return repHostUnreachable
	case l4.CodeRefused:
		return repRefused
	case l4.CodeBadCommand:
		return repBadCommand
	case l4.CodeBadAddress:
		return repBadAddress
	}
	return repFailure
}

// clientConn is the client connection handed to Forward: it reads the
// bytes the handshake's reader took ahead first, then the socket.
// CloseWrite, SetLinger and the deadlines are the socket's, so half-close
// and reset reach the client.
type clientConn struct {
	tcpConn
	r *bufio.Reader // nil once drained
}

func (c *clientConn) Read(p []byte) (int, error) {
	if c.r != nil {
		if c.r.Buffered() > 0 {
			return c.r.Read(p)
		}
		c.r = nil
	}
	return c.tcpConn.Read(p)
}
