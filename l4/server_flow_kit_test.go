package l4

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The test kit of the Server's UDP side (M6 design §A6, §A16.1, WP5);
// helpers start with "su". An suWorld is two Runtimes — the dialer d and
// the passive p with one push-only Listener whose AcceptBacklog and
// AcceptTimeout a row needs — joined by rendrtest.DatagramLinks (peer, a
// Peer of DatagramCarriers: the UDP flows) and, when a row needs TCP
// beside them, one rendrtest.Link (speer, a Peer of one StreamCarrier: the
// M6-D33 shape of two Peers). A row's targets are DatagramPipes that
// suTargets' hook hands out: the Server gets one end, the row's target
// application the other. Everything is created inside the synctest bubble
// that uses it (or outside every bubble) and closed before it ends.

// suOpts configures an suWorld.
type suOpts struct {
	links         int                        // datagram links (0: 1)
	streams       bool                       // a stream link and speer too
	backlog       int                        // AcceptBacklog (0: max(2n, 16))
	acceptTimeout time.Duration              // AcceptTimeout (0: the default 10 s)
	n             int                        // sessions at once (sizes the handshake and backlog limits)
	dcfg, pcfg    rendr.Config               // the dialer's and the passive's Config
	ov            func(*testhooks.Overrides) // edits both Runtimes' overrides
}

// suWorld is one row's Runtimes, links and Peers.
type suWorld struct {
	t     testing.TB
	d, p  *rendr.Runtime
	ln    *rendr.Listener
	links []*rendrtest.DatagramLink
	slink *rendrtest.Link
	peer  *rendr.Peer // datagram factories: UDP flows
	speer *rendr.Peer // a stream factory: TCP connections (nil unless streams)
	once  sync.Once
}

func newSUWorld(t testing.TB, o suOpts) *suWorld {
	t.Helper()
	w := &suWorld{t: t}
	n := max(o.n, 1)
	ov := kitOverrides(worldOpts{})
	// The production NoPathGrace: an opening dial waits that long for its
	// answer, so the Server's dial budget (up to the AcceptTimeout) is what
	// ends it, not the kit's shortened 5 s.
	ov.NoPathGrace = 15 * time.Second
	if o.ov != nil {
		o.ov(&ov)
	}
	dcfg, pcfg := o.dcfg, o.pcfg
	dcfg.Handshake.MaxConcurrent = max(dcfg.Handshake.MaxConcurrent, 2*n, 64)
	pcfg.Handshake.MaxConcurrent = max(pcfg.Handshake.MaxConcurrent, 2*n, 64)
	w.d = kitRuntime(t, dcfg, ov)
	w.p = kitRuntime(t, pcfg, ov)
	t.Cleanup(w.shutdown)
	backlog := o.backlog
	if backlog == 0 {
		backlog = max(2*n, 16)
	}
	ln, err := w.p.Listen(rendr.ListenConfig{AcceptBacklog: backlog, AcceptTimeout: o.acceptTimeout})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	var cs []rendr.Carrier
	for i := range max(o.links, 1) {
		name := "d" + string(rune('a'+i))
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: name, MTU: pfMTU, Accept: ln.HandlePacket})
		l.SetDelay(rendrtest.Up, pfOneWay, 0)
		l.SetDelay(rendrtest.Down, pfOneWay, 0)
		w.links = append(w.links, l)
		cs = append(cs, rendr.DatagramCarrier{Name: name, MTU: pfMTU, Dial: l.Dial})
	}
	if w.peer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: cs}); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if o.streams {
		w.slink = rendrtest.NewLink(rendrtest.LinkConfig{Name: "s", Accept: ln.Handle})
		w.slink.SetDelay(kitOneWay, 0)
		sc := []rendr.Carrier{rendr.StreamCarrier{Name: "s", Dial: w.slink.Dial}}
		if w.speer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: sc}); err != nil {
			t.Fatalf("NewPeer (stream): %v", err)
		}
	}
	return w
}

// shutdown closes the Peers, the Runtimes and the links (once).
func (w *suWorld) shutdown() {
	w.once.Do(func() {
		w.peer.Close()
		if w.speer != nil {
			w.speer.Close()
		}
		w.d.Close()
		w.p.Close()
		for _, l := range w.links {
			l.Close()
		}
		if w.slink != nil {
			w.slink.Close()
		}
	})
}

// suServe runs s.Serve on w's Listener with a cancellable ctx.
func suServe(w *suWorld, s *Server) *served {
	ctx, cancel := context.WithCancel(context.Background())
	sv := &served{s: s, cancel: cancel, done: make(chan error, 1)}
	go func() {
		err := s.Serve(ctx, w.ln)
		sv.ended.Store(time.Now().UnixNano())
		sv.done <- err
	}()
	return sv
}

// udpRes is one DialUDP's outcome.
type udpRes struct {
	pc  *rendr.PacketConn
	err error
	at  time.Time // when DialUDP returned
}

// suDialAsync runs DialUDP(ctx, w.peer, addr, first, o) on its own
// goroutine.
func suDialAsync(ctx context.Context, w *suWorld, addr string, first []byte, o rendr.DialOptions) <-chan udpRes {
	res := make(chan udpRes, 1)
	go func() {
		pc, err := DialUDP(ctx, w.peer, addr, first, o)
		res <- udpRes{pc, err, time.Now()}
	}()
	return res
}

// suRecv waits up to d (virtual) for a DialUDP's outcome.
func suRecv(t testing.TB, ch <-chan udpRes, d time.Duration) udpRes {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(d):
		t.Fatalf("DialUDP did not return within %v", d)
	}
	return udpRes{}
}

// suDial opens a flow and fails on an error.
func suDial(t testing.TB, w *suWorld, addr string, first []byte) *rendr.PacketConn {
	t.Helper()
	r := suRecv(t, suDialAsync(context.Background(), w, addr, first, rendr.DialOptions{}), time.Minute)
	if r.err != nil {
		t.Fatalf("DialUDP %s: %v", addr, r.err)
	}
	return r.pc
}

// suTargets is a Dial hook that hands every UDP flow a fresh DatagramPipe:
// the Server gets one end (through wrap, if set), the row's target
// application the other (next). It records every request (First and App
// copied) and the Server's ends.
type suTargets struct {
	cfg  rendrtest.DatagramPipeConfig
	wrap func(srv, app *rendrtest.DatagramConn, r Request) net.Conn // the conn the hook returns (nil: srv)

	mu   sync.Mutex
	reqs []Request
	srv  []*rendrtest.DatagramConn
	apps chan *rendrtest.DatagramConn // the target ends, in call order
}

func newSUTargets(cfg rendrtest.DatagramPipeConfig) *suTargets {
	return &suTargets{cfg: cfg, apps: make(chan *rendrtest.DatagramConn, 1024)}
}

func (ts *suTargets) dial(ctx context.Context, r Request) (net.Conn, error) {
	srv, app := rendrtest.NewDatagramPipe(ts.cfg)
	cp := r
	cp.First = append([]byte(nil), r.First...)
	cp.App = append([]byte(nil), r.App...)
	ts.mu.Lock()
	ts.reqs = append(ts.reqs, cp)
	ts.srv = append(ts.srv, srv)
	ts.mu.Unlock()
	ts.apps <- app
	if ts.wrap != nil {
		return ts.wrap(srv, app, r), nil
	}
	return srv, nil
}

// calls returns how many flows the hook dialled.
func (ts *suTargets) calls() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.reqs)
}

// next returns the next flow's target end within d (virtual).
func (ts *suTargets) next(t testing.TB, d time.Duration) *rendrtest.DatagramConn {
	t.Helper()
	select {
	case c := <-ts.apps:
		return c
	case <-time.After(d):
		t.Fatalf("no target dialled within %v", d)
	}
	return nil
}

// suEcho returns every datagram c reads to its sender until c fails (its
// pipe closed); the channel is closed then.
func suEcho(c net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if _, err := c.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return done
}

// suRoundTrip writes d on pc and requires the echo target to return it.
func suRoundTrip(t testing.TB, pc *rendr.PacketConn, d []byte) {
	t.Helper()
	if _, err := pc.WriteTo(d, nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	got, err := pfRecvPC(t, pc)
	if err != nil || string(got) != string(d) {
		t.Fatalf("echo: %d bytes, %v; want the %d-byte datagram", len(got), err, len(d))
	}
}

// suMixedHook dials UDP flows with ts and TCP connections with tcp.
func suMixedHook(ts *suTargets, tcp func(context.Context, string) (net.Conn, error)) func(context.Context, Request) (net.Conn, error) {
	return func(ctx context.Context, r Request) (net.Conn, error) {
		if r.Cmd == CmdUDP {
			return ts.dial(ctx, r)
		}
		return tcp(ctx, r.Addr)
	}
}

// suBufConn is a Server end that records the buffer sizes requested on it
// (the default UDP dialer's, R1-14).
type suBufConn struct {
	*rendrtest.DatagramConn
	mu          sync.Mutex
	read, write []int
}

func (c *suBufConn) SetReadBuffer(n int) error {
	c.mu.Lock()
	c.read = append(c.read, n)
	c.mu.Unlock()
	return nil
}

func (c *suBufConn) SetWriteBuffer(n int) error {
	c.mu.Lock()
	c.write = append(c.write, n)
	c.mu.Unlock()
	return nil
}

func (c *suBufConn) requests() (read, write []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.read...), append([]int(nil), c.write...)
}

// suSetDialUDP replaces the default UDP dialer for the rest of the test.
func suSetDialUDP(t testing.TB, dial func(ctx context.Context, addr string) (net.Conn, error)) {
	old := dialUDP
	dialUDP = dial
	t.Cleanup(func() { dialUDP = old })
}

// suUnits fails unless every MaxFlows unit of s was released.
func suUnits(t testing.TB, s *Server) {
	t.Helper()
	waitFor(t, time.Minute, "every UDP unit released", func() bool { return s.udp.units.Load() == 0 })
}
