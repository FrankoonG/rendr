package l4

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The test kit of ForwardPacket and DialUDP (M6 design §A16.1, WP4);
// helpers start with "pf". A pfWorld is two Runtimes — the dialer d and
// the passive p with one push-only Listener — joined by
// rendrtest.DatagramLinks whose Accept is the current Listener's
// HandlePacket (restart moves it to a new Runtime's Listener: a peer
// restart behind the same paths), and a Peer of DatagramCarriers over the
// links. A packet session is opened with DialPacket (dial) or DialUDP and
// confirmed on the passive by hand (the Server is WP5's): serve runs
// HandleUDP's steps — decode the UDP metadata, write a first datagram that
// rode the OPEN once to the target, Confirm, then the forward seeded with
// it (R1-10). A pfChain is one forwarded flow: a client's DatagramPipe and
// ForwardPacket on the dialer, ForwardPacket and a target's DatagramPipe
// on the passive. Everything is created inside the synctest bubble that
// uses it and closed before the bubble ends.

// The kit's paths and target.
const (
	pfOneWay = 5 * time.Millisecond // each direction of each link
	pfMTU    = 1400                 // the factories' MTU: MaxPayload 1,375
	pfTarget = "192.0.2.10:5000"    // the address the flows name (the targets ignore it)
	pfWithin = time.Second          // how long a datagram may take through the kit
)

// pfOpts configures a pfWorld.
type pfOpts struct {
	links      int                        // datagram links (0: 1)
	mtu        int                        // the factories' and links' MTU (0: pfMTU)
	dcfg, pcfg rendr.Config               // the dialer's and the passive's Config
	ov         func(*testhooks.Overrides) // edits both Runtimes' overrides (the kit's shortened timings)
}

// pfWorld is one test's Runtimes, links and Peer.
type pfWorld struct {
	t     testing.TB
	ov    testhooks.Overrides
	d, p  *rendr.Runtime
	ln    *rendr.Listener
	cur   atomic.Pointer[rendr.Listener] // where the links' new carriers go
	links []*rendrtest.DatagramLink
	peer  *rendr.Peer
	later []*rendr.Runtime // restarted passives
	once  sync.Once
}

func newPFWorld(t testing.TB, o pfOpts) *pfWorld {
	t.Helper()
	w := &pfWorld{t: t, ov: kitOverrides(worldOpts{})}
	if o.ov != nil {
		o.ov(&w.ov)
	}
	w.d = kitRuntime(t, o.dcfg, w.ov)
	w.p = kitRuntime(t, o.pcfg, w.ov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	w.cur.Store(ln)
	mtu := o.mtu
	if mtu == 0 {
		mtu = pfMTU
	}
	var cs []rendr.Carrier
	for i := range max(o.links, 1) {
		name := "d" + string(rune('a'+i))
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: name, MTU: mtu, Accept: w.handle})
		l.SetDelay(rendrtest.Up, pfOneWay, 0)
		l.SetDelay(rendrtest.Down, pfOneWay, 0)
		w.links = append(w.links, l)
		cs = append(cs, rendr.DatagramCarrier{Name: name, MTU: mtu, Dial: l.Dial})
	}
	if w.peer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: cs}); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	return w
}

// handle is the links' Accept: the current Listener's HandlePacket.
func (w *pfWorld) handle(pc net.PacketConn, peer net.Addr) error {
	return w.cur.Load().HandlePacket(pc, peer)
}

// restart puts a new passive Runtime (another InstanceID, no GOAWAY from
// the old one) behind the links: their next carriers reach its Listener.
func (w *pfWorld) restart() {
	w.t.Helper()
	p2 := kitRuntime(w.t, rendr.Config{}, w.ov)
	w.later = append(w.later, p2)
	ln, err := p2.Listen(rendr.ListenConfig{})
	if err != nil {
		w.t.Fatalf("Listen: %v", err)
	}
	w.cur.Store(ln)
}

// shutdown closes the Peer, the Runtimes and the links (once).
func (w *pfWorld) shutdown() {
	w.once.Do(func() {
		w.peer.Close()
		w.d.Close()
		w.p.Close()
		for _, rt := range w.later {
			rt.Close()
		}
		for _, l := range w.links {
			l.Close()
		}
	})
}

// dial opens one packet session with DialPacket and confirms it on the
// passive.
func (w *pfWorld) dial(o rendr.DialOptions) (dc, pc *rendr.PacketConn) {
	w.t.Helper()
	var perr error
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		pend, err := w.ln.AcceptPacket(context.Background())
		if err != nil {
			perr = err
			return
		}
		pc, perr = pend.Confirm()
	}()
	dc, err := w.peer.DialPacket(context.Background(), o)
	<-accepted
	if err != nil || perr != nil {
		w.t.Fatalf("open: DialPacket %v, AcceptPacket/Confirm %v", err, perr)
	}
	return dc, pc
}

// pfServed is a flow served by pfWorld.serve.
type pfServed struct {
	pc  *rendr.PacketConn   // the passive session (nil when err is set)
	req Request             // its decoded request
	err error               // AcceptPacket's, the decode's, the first write's or Confirm's
	res <-chan PacketResult // the forward's result
}

// serve accepts one packet session as HandleUDP does: it decodes the UDP
// metadata, writes a first datagram that rode the OPEN once to local,
// confirms, and forwards the flow with idle, the tracker seeded with that
// write (R1-10). The channel yields the flow once it is forwarded (or the
// error that stopped it, local then closed).
func (w *pfWorld) serve(local net.Conn, idle FlowIdle) <-chan pfServed {
	out := make(chan pfServed, 1)
	go func() {
		var s pfServed
		pend, err := w.ln.AcceptPacket(context.Background())
		if err == nil {
			s.req, err = ParseUDPMetadata(pend.Metadata())
			if err != nil {
				pend.Reject(uint32(CodeBadRequest), "test")
			}
		}
		var seed flowSeed
		if err == nil && len(s.req.First) > 0 {
			seed = flowSeed{at: time.Now(), dir: towardLocal}
			if _, err = local.Write(s.req.First); err != nil {
				pend.Reject(uint32(CodeDialFailed), "test")
			}
		}
		if err == nil {
			s.pc, err = pend.Confirm()
		}
		if s.err = err; err != nil {
			local.Close()
			out <- s
			return
		}
		res := make(chan PacketResult, 1)
		s.res = res
		out <- s
		res <- forwardPacket(context.Background(), s.pc, local, idle, seed, nil)
	}()
	return out
}

// pfForward runs forwardPacket on its own goroutine; the channel yields
// the result.
func pfForward(ctx context.Context, pc packetSession, local net.Conn, idle FlowIdle) <-chan PacketResult {
	res := make(chan PacketResult, 1)
	go func() { res <- forwardPacket(ctx, pc, local, idle, flowSeed{}, nil) }()
	return res
}

// pfChainOpts configures a pfChain; the zero value is the defaults.
type pfChainOpts struct {
	dial            rendr.DialOptions
	idleIn, idleOut FlowIdle                               // the dialer's and the passive's classes
	pipe            rendrtest.DatagramPipeConfig           // both pipes
	wrapIn, wrapOut func(packetSession) packetSession      // wrap the sessions the forwards see
	localIn         func(*rendrtest.DatagramConn) net.Conn // wrap the dialer forward's local end
	localOut        func(*rendrtest.DatagramConn) net.Conn // the passive's
}

// pfChain is one forwarded flow: client ↔ ForwardPacket(dc) ⇄ session ⇄
// ForwardPacket(pc) ↔ target.
type pfChain struct {
	dc, pc              *rendr.PacketConn
	client, target      *rendrtest.DatagramConn // the applications' ends
	cliLocal, tgtLocal  *rendrtest.DatagramConn // the forwards' ends
	in, out             <-chan PacketResult     // the dialer's forward, the passive's
	cancelIn, cancelOut context.CancelFunc
}

func (w *pfWorld) chain(o pfChainOpts) *pfChain {
	w.t.Helper()
	ch := &pfChain{}
	ch.dc, ch.pc = w.dial(o.dial)
	ch.client, ch.cliLocal = rendrtest.NewDatagramPipe(o.pipe)
	ch.tgtLocal, ch.target = rendrtest.NewDatagramPipe(o.pipe)
	var sin, sout packetSession = ch.dc, ch.pc
	if o.wrapIn != nil {
		sin = o.wrapIn(sin)
	}
	if o.wrapOut != nil {
		sout = o.wrapOut(sout)
	}
	var lin, lout net.Conn = ch.cliLocal, ch.tgtLocal
	if o.localIn != nil {
		lin = o.localIn(ch.cliLocal)
	}
	if o.localOut != nil {
		lout = o.localOut(ch.tgtLocal)
	}
	var inCtx, outCtx context.Context
	inCtx, ch.cancelIn = context.WithCancel(context.Background())
	outCtx, ch.cancelOut = context.WithCancel(context.Background())
	ch.in = pfForward(inCtx, sin, lin, o.idleIn)
	ch.out = pfForward(outCtx, sout, lout, o.idleOut)
	return ch
}

// results cancels both forwards and waits for their results.
func (ch *pfChain) results() (in, out PacketResult) {
	ch.cancelIn()
	ch.cancelOut()
	return <-ch.in, <-ch.out
}

// pfData returns n bytes tagged with tag: every datagram of a row is told
// apart by its tag and its length.
func pfData(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = tag + byte(i*7)
	}
	return b
}

// pfSend writes b as one datagram to c.
func pfSend(t testing.TB, c net.Conn, b []byte) {
	t.Helper()
	if n, err := c.Write(b); n != len(b) || err != nil {
		t.Fatalf("Write of %d bytes = %d, %v", len(b), n, err)
	}
}

// pfRecv reads the next datagram from c within pfWithin.
func pfRecv(t testing.TB, c net.Conn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(pfWithin))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 64<<10)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return buf[:n]
}

// pfExpect reads the next datagram from c and requires it to be want.
func pfExpect(t testing.TB, c net.Conn, want []byte) {
	t.Helper()
	if got := pfRecv(t, c); !bytes.Equal(got, want) {
		t.Fatalf("read a %d-byte datagram, want the %d-byte one tagged %#x", len(got), len(want), tagOf(want))
	}
}

// pfNone requires that no datagram arrives at c within pfWithin.
func pfNone(t testing.TB, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(pfWithin))
	defer c.SetReadDeadline(time.Time{})
	if n, err := c.Read(make([]byte, 64<<10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %d, %v; want no datagram", n, err)
	}
}

// pfRecvPC reads the next datagram from the session pc within pfWithin.
func pfRecvPC(t testing.TB, pc *rendr.PacketConn) ([]byte, error) {
	t.Helper()
	pc.SetReadDeadline(time.Now().Add(pfWithin))
	defer pc.SetReadDeadline(time.Time{})
	buf := make([]byte, 64<<10)
	n, _, err := pc.ReadFrom(buf)
	return buf[:n], err
}

func tagOf(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// pfRule selects the promotion rule for the rest of the test (R1-7).
func pfRule(t testing.TB, r promoteMode) {
	old := ruleForTest.Swap(uint32(r))
	t.Cleanup(func() { ruleForTest.Store(old) })
}

// pfIdleSpy records the SetIdleTimeout calls a forward makes on its
// session.
type pfIdleSpy struct {
	packetSession
	mu    sync.Mutex
	calls []time.Duration
}

func (s *pfIdleSpy) SetIdleTimeout(d time.Duration) error {
	s.mu.Lock()
	s.calls = append(s.calls, d)
	s.mu.Unlock()
	return s.packetSession.SetIdleTimeout(d)
}

func (s *pfIdleSpy) snapshot() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.calls...)
}
