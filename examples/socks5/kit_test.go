package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The test kit (M4 design §A10.3): a stack is the example's two halves in
// one process — a dialer Runtime with a Peer and the SOCKS5 front end, a
// passive Runtime with a Listener and an l4.Server — joined by
// rendrtest.Links. The front end listens on an in-memory pipeListener
// (synctest rows; the client is a rendrtest.TargetPipe end) or on real
// loopback TCP (real-socket rows, outside bubbles). The Server's Dial hook
// is the row's: a rendrtest.Target, a ScriptedDial or a blocking hook.

// kitOneWay is the links' one-way delay.
const kitOneWay = 5 * time.Millisecond

// kitOverrides shortens the core's timings as the l4 kits do.
func kitOverrides() testhooks.Overrides {
	return testhooks.Overrides{
		DeadMin:          time.Second,
		DeadMax:          2 * time.Second,
		WriteStall:       time.Second,
		PingIdle:         500 * time.Millisecond,
		ProbeInterval:    200 * time.Millisecond,
		ProbeFresh:       2 * time.Second,
		SelectorDwell:    time.Second,
		SelectorCooldown: 2 * time.Second,
		NoPathGrace:      15 * time.Second,
		RetireGrace:      500 * time.Millisecond,
		Linger:           10 * time.Second,
		RetainSlack:      2 * time.Second,
	}
}

// stackOpts configures a stack.
type stackOpts struct {
	links     int                                                       // paths (0: 1)
	rate      float64                                                   // the links' rate per direction (0: unlimited)
	delay     time.Duration                                             // the links' one-way delay (0: kitOneWay; < 0: none)
	dial      func(ctx context.Context, r l4.Request) (net.Conn, error) // the Server's Dial hook (nil: a TargetEcho)
	real      bool                                                      // the front end listens on loopback TCP
	n         int                                                       // sessions at once (sizes the handshake and backlog limits)
	hsTimeout time.Duration                                             // the front end's handshake deadline (0: handshakeTimeout)
}

// stack is one row's dialer, passive, links, Server and front end.
type stack struct {
	t      testing.TB
	d, p   *rendr.Runtime
	ln     *rendr.Listener
	links  []*rendrtest.Link
	peer   *rendr.Peer
	srv    *l4.Server
	front  *front
	pl     *pipeListener // the in-memory front listener (nil when real)
	tl     net.Listener  // the loopback front listener (nil unless real)
	cancel context.CancelFunc
	done   sync.WaitGroup // Serve and the front end
	once   sync.Once
	target *rendrtest.Target // the default hook's target
	mu     sync.Mutex
	conns  []*rendr.Conn // the dialer Conns the front end's dials returned
}

func newStack(t testing.TB, o stackOpts) *stack {
	t.Helper()
	s := &stack{t: t}
	n := max(o.n, 1)
	cfg := rendr.Config{}
	cfg.Handshake.MaxConcurrent = max(2*n, 64)
	s.d, s.p = kitRuntime(t, cfg), kitRuntime(t, cfg)
	t.Cleanup(s.shutdown)
	ln, err := s.p.Listen(rendr.ListenConfig{AcceptBacklog: max(2*n, 16)})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	s.ln = ln
	var cs []rendr.Carrier
	for i := range max(o.links, 1) {
		name := string(rune('a' + i))
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: ln.Handle})
		switch {
		case o.delay == 0:
			l.SetDelay(kitOneWay, 0)
		case o.delay > 0:
			l.SetDelay(o.delay, 0)
		}
		if o.rate > 0 {
			l.SetRate(o.rate)
		}
		s.links = append(s.links, l)
		cs = append(cs, rendr.StreamCarrier{Name: name, Dial: l.Dial})
	}
	if s.peer, err = s.d.NewPeer(rendr.PeerConfig{Carriers: cs}); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	s.srv = &l4.Server{Dial: o.dial}
	if o.dial == nil {
		s.target = rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		s.srv.Dial = func(ctx context.Context, r l4.Request) (net.Conn, error) { return s.target.Dial(ctx, r.Addr) }
	}
	s.front = newFront(func(ctx context.Context, addr string) (*rendr.Conn, error) {
		c, err := l4.Dial(ctx, s.peer, addr, rendr.DialOptions{})
		if c != nil {
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
		}
		return c, err
	}, func(string, ...any) {})
	if o.hsTimeout > 0 {
		s.front.timeout = o.hsTimeout
	}
	var fl net.Listener
	if o.real {
		if s.tl, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatalf("listen: %v", err)
		}
		fl = s.tl
	} else {
		s.pl = newPipeListener()
		fl = s.pl
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done.Go(func() { s.srv.Serve(ctx, s.ln) })
	s.done.Go(func() { s.front.serve(ctx, fl) })
	return s
}

func kitRuntime(t testing.TB, cfg rendr.Config) *rendr.Runtime {
	t.Helper()
	ov := kitOverrides()
	v, err := testhooks.NewRuntime(cfg, &ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// shutdown stops the front end and the Server (resetting what they
// forward), then closes the Peer, both Runtimes, the links and the
// default target (once).
func (s *stack) shutdown() {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
			s.done.Wait()
		}
		s.peer.Close()
		s.d.Close()
		s.p.Close()
		for _, l := range s.links {
			l.Close()
		}
		if s.target != nil {
			s.target.Close()
		}
	})
}

// connect opens a client connection to the front end: a TargetPipe end
// (in memory) or a loopback TCP conn (real).
func (s *stack) connect() net.Conn {
	s.t.Helper()
	if s.pl != nil {
		return s.pl.connect()
	}
	c, err := net.Dial("tcp", s.tl.Addr().String())
	if err != nil {
		s.t.Fatalf("connect: %v", err)
	}
	return c
}

// conn returns the i-th dialer Conn the front end opened.
func (s *stack) conn(i int) *rendr.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.conns) {
		s.t.Fatalf("the front end opened %d sessions, want more than %d", len(s.conns), i)
	}
	return s.conns[i]
}

// activeLink returns the link that carries c's data, or nil.
func (s *stack) activeLink(c *rendr.Conn) *rendrtest.Link {
	for _, cs := range c.Status().Carriers {
		if cs.State == rendr.CarrierActive {
			for _, l := range s.links {
				if l.Name() == cs.Name {
					return l
				}
			}
		}
	}
	return nil
}

// pipeListener is an in-memory net.Listener whose connections are
// TargetPipes; it can also fail Accept with a scripted error.
type pipeListener struct {
	ch   chan net.Conn
	errs chan error
	done chan struct{}
	once sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{ch: make(chan net.Conn), errs: make(chan error, 4), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case err := <-l.errs:
		return nil, err
	default:
	}
	select {
	case c := <-l.ch:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// connect hands the server end of a new TargetPipe to Accept and returns
// the client end; after Close the server end is closed at once.
func (l *pipeListener) connect() *rendrtest.TargetConn {
	cli, srv := rendrtest.TargetPipe(0)
	select {
	case l.ch <- srv:
	case <-l.done:
		srv.Close()
	}
	return cli
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// SOCKS5 client side (the test's own encoder, RFC 1928).

// greeting is a no-auth greeting.
var greeting = []byte{socksVersion, 1, methodNoAuth}

// appendRequest appends the encoding of q (the parser's inverse).
func appendRequest(dst []byte, q request) []byte {
	dst = append(dst, socksVersion, q.cmd, 0, q.atyp)
	if q.atyp == atypDomain {
		dst = append(dst, byte(len(q.addr)))
	}
	dst = append(dst, q.addr...)
	return append(dst, byte(q.port>>8), byte(q.port))
}

// connectReq is a CONNECT request for the domain name:port.
func connectReq(name string, port uint16) request {
	return request{cmd: cmdConnect, atyp: atypDomain, addr: []byte(name), port: port}
}

// socksConnect writes the greeting and q in one write (with extra bytes
// after them) and reads the method reply and the reply; it returns REP.
func socksConnect(c net.Conn, q request, extra []byte) (byte, error) {
	msg := appendRequest(append([]byte(nil), greeting...), q)
	if _, err := c.Write(append(msg, extra...)); err != nil {
		return 0, err
	}
	var b [12]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	if b[0] != socksVersion || b[1] != methodNoAuth || b[2] != socksVersion || b[4] != 0 || b[5] != atypIPv4 || [6]byte(b[6:]) != [6]byte{} {
		return 0, errors.New("unexpected reply bytes")
	}
	return b[3], nil
}

// readAll reads r to its end and returns the bytes' count and SHA-256 and
// the error that ended it (io.EOF at a FIN).
func readAll(r io.Reader) (int64, [32]byte, error) {
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := r.Read(buf)
		h.Write(buf[:k])
		n += int64(k)
		if err != nil {
			var sum [32]byte
			h.Sum(sum[:0])
			return n, sum, err
		}
	}
}

// prngSum is the SHA-256 of the first n bytes of PRNG(seed).
func prngSum(seed uint64, n int64) [32]byte {
	h := sha256.New()
	io.CopyN(h, rendrtest.PRNG(seed), n)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// writePRNG writes n bytes of PRNG(seed) to w in 16 KiB Writes.
func writePRNG(w io.Writer, seed uint64, n int64) error {
	src, buf := rendrtest.PRNG(seed), make([]byte, 16<<10)
	for n > 0 {
		k := int(min(n, int64(len(buf))))
		src.Read(buf[:k])
		if _, err := w.Write(buf[:k]); err != nil {
			return err
		}
		n -= int64(k)
	}
	return nil
}
