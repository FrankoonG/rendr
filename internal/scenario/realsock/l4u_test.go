package realsock

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The L4 UDP rows of the real-socket group (M6 design §A16.3, §A13; WP10):
// two Runtimes joined by carrier/udp on loopback (and carrier/tcp where a
// row forwards TCP too), an l4.Server with UDP serving the passive's
// Listener, an l4.PortForward on the dialer's Peer, and real UDP clients
// and targets (net.ListenUDP, net.DialUDP), outside synctest bubbles,
// through the public API. A row that rests on one OS's socket behaviour
// says so and is skipped elsewhere with the reason. Every test registers
// rendrtest.AssertNoLeak first (its check runs after every other cleanup,
// once both Runtimes are closed), closes both Runtimes and never runs in
// parallel. Bounds are real-time bounds (l4uWait: loopback answers within
// milliseconds, the rest is a busy host's or the race detector's slack);
// waits poll a condition, never sleep for one. Each row takes well under a
// second on loopback, the race lane included (R1-37: ≤ 10 s for all of
// them). Helpers carry the l4u prefix: the package's other files belong to
// other work packages (the l4r and ms helpers used here are theirs).

// l4uWait bounds every wait of these rows: an open, a loopback exchange, a
// counter's move.
const l4uWait = 5 * time.Second

// l4uDgram returns test datagram seq of size bytes (at least 12): the seq,
// the size, then bytes drawn from the seq — the same bytes every time.
func l4uDgram(seq uint64, size int) []byte {
	b := make([]byte, size)
	binary.BigEndian.PutUint64(b, seq)
	binary.BigEndian.PutUint32(b[8:], uint32(size))
	x := seq*0x9e3779b97f4a7c15 | 1
	for i := 12; i < size; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
	return b
}

// l4uSeqOf returns the seq of b and whether b is exactly test datagram seq
// of its length: nothing cut, merged or changed.
func l4uSeqOf(b []byte) (uint64, bool) {
	if len(b) < 12 {
		return 0, false
	}
	seq := binary.BigEndian.Uint64(b)
	return seq, bytes.Equal(b, l4uDgram(seq, len(b)))
}

// l4uDesc describes a received datagram for a failure message.
func l4uDesc(b []byte) string {
	if seq, ok := l4uSeqOf(b); ok {
		return fmt.Sprintf("datagram %d (%d B)", seq, len(b))
	}
	return fmt.Sprintf("a damaged or foreign datagram of %d B", len(b))
}

// l4uNet is one row's fixture: the dialer Runtime d with its Peer and the
// PortForward on it, the passive Runtime p with its Listener and the
// l4.Server serving it.
type l4uNet struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	peer     *rendr.Peer
	srv      *l4.Server
	pf       *l4.PortForward
	ctx      context.Context // the serves' ctx (Server.Serve's too)
	cancel   context.CancelFunc
	served   chan error // Server.Serve's result
	serveErr error
	serves   []*l4uServe
	live0    int64
	once     sync.Once
}

// l4uOpts configure an l4uNet; the zero value is the default fixture.
type l4uOpts struct {
	maxDatagram int                   // carrier/udp's MaxDatagram on both ends (0: DefaultMaxDatagram)
	stream      bool                  // also carrier/tcp on both ends, for ServeTCP's stream sessions
	srv         *l4.Server            // nil: &l4.Server{UDP: true}
	pf          func(*l4.PortForward) // edits the PortForward
}

// l4uServe is one PortForward serve: done closes when it returned err.
type l4uServe struct {
	name string
	done chan struct{}
	err  error
}

// running reports whether the serve has not returned.
func (s *l4uServe) running() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// newL4uNet builds the fixture and starts the Server. A cleanup closes
// everything as well, so that a failed test leaves nothing behind.
func newL4uNet(t testing.TB, o l4uOpts) *l4uNet {
	t.Helper()
	n := &l4uNet{t: t, srv: o.srv, served: make(chan error, 1), live0: testhooks.LiveSessions.Load()}
	if n.srv == nil {
		n.srv = &l4.Server{UDP: true}
	}
	var err error
	if n.d, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	if n.p, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		n.d.Close()
		t.Fatal(err)
	}
	t.Cleanup(n.shutdown)
	uo := udpOpts()
	uo.MaxDatagram = o.maxDatagram
	us, err := udp.Listen("udp4", "127.0.0.1:0", uo)
	if err != nil {
		t.Fatal(err)
	}
	socks := []io.Closer{us}
	srcs := []rendr.Source{rendr.FromPacketConn(us)}
	cs := []rendr.Carrier{udp.Carrier("u", "udp4", us.LocalAddr().String(), uo)}
	if o.stream {
		tl, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
		if err != nil {
			us.Close()
			t.Fatal(err)
		}
		socks = append(socks, tl)
		srcs = append(srcs, rendr.FromListener(tl))
		cs = append(cs, tcp.Carrier("t", "tcp", tl.Addr().String(), tcp.Options{}))
	}
	if n.ln, err = n.p.Listen(rendr.ListenConfig{Sources: srcs}); err != nil {
		for _, s := range socks { // a failed Listen leaves them to the caller
			s.Close()
		}
		t.Fatal(err)
	}
	if n.peer, err = n.d.NewPeer(rendr.PeerConfig{Carriers: cs}); err != nil {
		t.Fatal(err)
	}
	n.pf = &l4.PortForward{Peer: n.peer}
	if o.pf != nil {
		o.pf(n.pf)
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	go func() { n.served <- n.srv.Serve(n.ctx, n.ln) }()
	return n
}

// serveUDP runs n.pf.ServeUDP(n.ctx, sock, target) until the fixture closes.
func (n *l4uNet) serveUDP(sock l4.UDPSocket, target string) *l4uServe {
	s := &l4uServe{name: "ServeUDP " + target, done: make(chan struct{})}
	n.serves = append(n.serves, s)
	go func() { defer close(s.done); s.err = n.pf.ServeUDP(n.ctx, sock, target) }()
	return s
}

// serveTCP runs n.pf.ServeTCP(n.ctx, ln, target) until the fixture closes.
func (n *l4uNet) serveTCP(ln net.Listener, target string) *l4uServe {
	s := &l4uServe{name: "ServeTCP " + target, done: make(chan struct{})}
	n.serves = append(n.serves, s)
	go func() { defer close(s.done); s.err = n.pf.ServeTCP(n.ctx, ln, target) }()
	return s
}

// shutdown stops the fixture (idempotent): the serves' ctx ends, the
// PortForward serves return (every flow ended), both Runtimes close and
// Server.Serve returns.
func (n *l4uNet) shutdown() {
	n.once.Do(func() {
		if n.cancel == nil { // Serve never started
			if n.peer != nil {
				n.peer.Close()
			}
			n.d.Close()
			n.p.Close()
			return
		}
		n.cancel()
		for _, s := range n.serves {
			select {
			case <-s.done:
			case <-time.After(10 * time.Second):
				n.t.Errorf("%s did not return within 10 s of its ctx's end", s.name)
			}
		}
		n.peer.Close()
		n.d.Close()
		n.p.Close()
		select {
		case n.serveErr = <-n.served:
		case <-time.After(10 * time.Second):
			n.t.Errorf("l4.Server.Serve did not return within 10 s of its ctx's end and Runtime.Close")
		}
	})
}

// close stops the fixture and requires that every serve ran until the stop
// and that nothing is left: no session, handshake, flow, actor, buffered
// byte or carrier on either Runtime, no flow or connection at the Server
// or the PortForward, and the session registry back at its start.
func (n *l4uNet) close() {
	n.t.Helper()
	n.shutdown()
	for _, s := range n.serves {
		if !errors.Is(s.err, context.Canceled) {
			n.t.Errorf("%s returned %v, want context.Canceled at the stop", s.name, s.err)
		}
	}
	if !errors.Is(n.serveErr, context.Canceled) {
		n.t.Errorf("l4.Server.Serve returned %v, want context.Canceled at the stop", n.serveErr)
	}
	for _, rt := range []*rendr.Runtime{n.d, n.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 ||
			st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			n.t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
	if s := n.srv.Status(); s.Dialing != 0 || s.Live != 0 || s.Hooks != 0 || s.Abandoned != 0 || s.UDP.Dialing != 0 || s.UDP.Live != 0 {
		n.t.Errorf("Server state left after Serve returned: %+v", s)
	}
	if f := n.pf.Status(); f.UDP.Flows != 0 || f.UDP.Opening != 0 || f.UDP.Held != 0 || f.TCP.Live != 0 || len(n.pf.Flows()) != 0 {
		n.t.Errorf("PortForward state left after its serves returned: %+v, flows %+v", f, n.pf.Flows())
	}
	msUntil(n.t, 10*time.Second, "the session registry back at its start", func() bool {
		return testhooks.LiveSessions.Load() == n.live0
	})
}

// live requires that the PortForward opened exactly flows UDP flows, each
// once, that all of them are open and none ended, failed, was replaced or
// evicted, and that the Server confirmed as many, forwards them all and
// ended none: carrier and socket events never re-opened a flow.
func (n *l4uNet) live(flows int) {
	n.t.Helper()
	f, s := n.pf.Status().UDP, n.srv.Status().UDP
	if f.Opened != uint64(flows) || f.Flows != flows || f.Failed != 0 || f.Replaced != 0 || f.Evicted != 0 || f.Ended != (l4.FlowEnds{}) {
		n.t.Errorf("ingress: %d flows opened, %d open, %d failed, %d replaced, %d evicted, ended %+v; want %d opened and open, nothing else",
			f.Opened, f.Flows, f.Failed, f.Replaced, f.Evicted, f.Ended, flows)
	}
	if s.Confirmed != uint64(flows) || s.Live != flows || s.Rejected != 0 || s.Ended != (l4.FlowEnds{}) {
		n.t.Errorf("Server: %d flows confirmed, %d live, %d rejected, ended %+v; want %d confirmed and live, nothing else",
			s.Confirmed, s.Live, s.Rejected, s.Ended, flows)
	}
}

// l4uBuffers gives a test socket 1-MiB buffers, so that a 60,000-byte
// datagram fits on every OS.
func l4uBuffers(c *net.UDPConn) {
	c.SetReadBuffer(1 << 20)
	c.SetWriteBuffer(1 << 20)
}

// l4uListen opens a UDP socket on network and address (l4uBuffers); a
// cleanup closes it (a second Close is harmless: ServeUDP closes what it
// owns).
func l4uListen(t testing.TB, network, address string) *net.UDPConn {
	t.Helper()
	a, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatalf("premise: %v", err)
	}
	c, err := net.ListenUDP(network, a)
	if err != nil {
		t.Fatalf("premise: ListenUDP %s %s: %v", network, address, err)
	}
	l4uBuffers(c)
	t.Cleanup(func() { c.Close() })
	return c
}

// l4uClient is a client socket connected to an ingress; a reader goroutine
// queues every datagram it receives.
type l4uClient struct {
	t    testing.TB
	c    *net.UDPConn
	rx   chan []byte
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func newL4uClient(t testing.TB, network string, to net.Addr) *l4uClient {
	t.Helper()
	c, err := net.DialUDP(network, nil, to.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("premise: DialUDP %s %v: %v", network, to, err)
	}
	l4uBuffers(c)
	cl := &l4uClient{t: t, c: c, rx: make(chan []byte, 256), stop: make(chan struct{}), done: make(chan struct{})}
	go cl.read()
	t.Cleanup(cl.close)
	return cl
}

func (cl *l4uClient) read() {
	defer close(cl.done)
	for {
		b := make([]byte, 64<<10)
		n, err := cl.c.Read(b)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue // an ICMP report of a datagram this client sent (Linux): the rows judge datagrams
		}
		select {
		case cl.rx <- b[:n]:
		case <-cl.stop:
			return
		}
	}
}

// close closes the socket and joins the reader (idempotent).
func (cl *l4uClient) close() {
	cl.once.Do(func() {
		close(cl.stop)
		cl.c.Close()
		<-cl.done
	})
}

// addr is the client socket's own address.
func (cl *l4uClient) addr() netip.AddrPort {
	return cl.c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// send sends test datagram seq of size bytes.
func (cl *l4uClient) send(seq uint64, size int) {
	cl.t.Helper()
	if _, err := cl.c.Write(l4uDgram(seq, size)); err != nil {
		cl.t.Fatalf("client: send datagram %d (%d B): %v", seq, size, err)
	}
}

// expect requires that the next datagram the client receives, within
// l4uWait, is exactly test datagram seq of size bytes.
func (cl *l4uClient) expect(seq uint64, size int) {
	cl.t.Helper()
	select {
	case b := <-cl.rx:
		if got, ok := l4uSeqOf(b); !ok || got != seq || len(b) != size {
			cl.t.Fatalf("client: received %s, want datagram %d (%d B) next", l4uDesc(b), seq, size)
		}
	case <-time.After(l4uWait):
		cl.t.Fatalf("client: datagram %d (%d B) not received within %v", seq, size, l4uWait)
	}
}

// exchange sends datagram seq of size bytes and requires its echo next.
func (cl *l4uClient) exchange(seq uint64, size int) {
	cl.t.Helper()
	cl.send(seq, size)
	cl.expect(seq, size)
}

// gotFrom consumes what arrived and reports whether it held an intact
// datagram whose seq is at least from (a damaged one fails the test).
func (cl *l4uClient) gotFrom(from uint64) bool {
	cl.t.Helper()
	for {
		select {
		case b := <-cl.rx:
			seq, ok := l4uSeqOf(b)
			if !ok {
				cl.t.Fatalf("client: received %s", l4uDesc(b))
			}
			if seq >= from {
				return true
			}
		default:
			return false
		}
	}
}

// l4uDrive runs step every 10 ms until cond holds, for at most l4uWait,
// and returns how many steps ran.
func l4uDrive(t testing.TB, what string, cond func() bool, step func()) int {
	t.Helper()
	deadline := time.Now().Add(l4uWait)
	steps := 0
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v (%d datagrams sent): %s", l4uWait, steps, what)
		}
		step()
		steps++
		time.Sleep(10 * time.Millisecond)
	}
	return steps
}

// l4uTarget is a UDP target socket: a reader goroutine records each
// datagram's source and length and, while echo is on, returns it to its
// source.
type l4uTarget struct {
	c    *net.UDPConn
	echo atomic.Bool
	mu   sync.Mutex
	srcs map[netip.AddrPort]int // datagrams per source
	lens []int                  // every datagram's length, in arrival order
	err  error                  // the read error that stopped the reader (net.ErrClosed excepted)
	done chan struct{}
	once sync.Once
}

// newL4uTarget opens an echoing target on network and address.
func newL4uTarget(t testing.TB, network, address string) *l4uTarget {
	t.Helper()
	return l4uTargetOn(t, l4uListen(t, network, address))
}

// l4uTargetOn makes an echoing target of c; a cleanup closes it.
func l4uTargetOn(t testing.TB, c *net.UDPConn) *l4uTarget {
	tg := &l4uTarget{c: c, srcs: map[netip.AddrPort]int{}, done: make(chan struct{})}
	tg.echo.Store(true)
	go tg.serve()
	t.Cleanup(tg.close)
	return tg
}

func (tg *l4uTarget) serve() {
	defer close(tg.done)
	b := make([]byte, 64<<10)
	for {
		n, src, err := tg.c.ReadFromUDPAddrPort(b)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				tg.mu.Lock()
				tg.err = err
				tg.mu.Unlock()
			}
			return
		}
		tg.mu.Lock()
		tg.srcs[src]++
		tg.lens = append(tg.lens, n)
		tg.mu.Unlock()
		if tg.echo.Load() {
			tg.c.WriteToUDPAddrPort(b[:n], src)
		}
	}
}

// close closes the socket and joins the reader (idempotent).
func (tg *l4uTarget) close() {
	tg.once.Do(func() {
		tg.c.Close()
		<-tg.done
	})
}

func (tg *l4uTarget) addr() string { return tg.c.LocalAddr().String() }

// seen returns the datagrams per source, every datagram's length in
// arrival order and the reader's error.
func (tg *l4uTarget) seen() (map[netip.AddrPort]int, []int, error) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	srcs := make(map[netip.AddrPort]int, len(tg.srcs))
	for a, k := range tg.srcs {
		srcs[a] = k
	}
	return srcs, slices.Clone(tg.lens), tg.err
}

// only returns the one source the target heard: the flow's egress socket.
func (tg *l4uTarget) only(t testing.TB) netip.AddrPort {
	t.Helper()
	srcs, _, err := tg.seen()
	if len(srcs) != 1 || err != nil {
		t.Fatalf("target: sources %v (read error %v), want exactly one egress socket", srcs, err)
	}
	for a := range srcs {
		return a
	}
	panic("unreachable")
}

// pushTo sends b from the target to dst.
func (tg *l4uTarget) pushTo(t testing.TB, dst netip.AddrPort, b []byte) {
	t.Helper()
	if _, err := tg.c.WriteToUDPAddrPort(b, dst); err != nil {
		t.Fatalf("target: send %s to %v: %v", l4uDesc(b), dst, err)
	}
}

// l4uWrites counts how the Sizes row's egress sockets send.
type l4uWrites struct{ write, writeTo atomic.Int64 }

// l4uEgress is an egress socket of the Sizes row: the connected UDP socket
// its Server's Dial hook made, counting the calls that send.
type l4uEgress struct {
	*net.UDPConn
	w *l4uWrites
}

func (e *l4uEgress) Write(b []byte) (int, error) {
	e.w.write.Add(1)
	return e.UDPConn.Write(b)
}

func (e *l4uEgress) WriteTo(b []byte, a net.Addr) (int, error) {
	e.w.writeTo.Add(1)
	return e.UDPConn.WriteTo(b, a)
}

// dial is the Sizes row's Dial hook: a UDP socket connected to the target,
// as the default dialer makes one, wrapped in an l4uEgress.
func (w *l4uWrites) dial(ctx context.Context, r l4.Request) (net.Conn, error) {
	if r.Cmd != l4.CmdUDP {
		return nil, fmt.Errorf("%w: this hook dials UDP targets only", l4.ErrDenied)
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", r.Addr)
	if err != nil {
		return nil, err
	}
	return &l4uEgress{UDPConn: c.(*net.UDPConn), w: w}, nil
}

// TestL4URealSizes_L37_L71 (M6 design §A16.3, §A4.1; L37, L57, L71): the
// size rules of one flow end to end over carrier/udp on loopback, at its
// default MaxDatagram (1,232: MaxPayload 1,198) and at the recipe for a
// 1,500-byte path (1,472 on both ends: 1,438). Stimulus: a client datagram
// of MaxPayload + 1 at the ingress and a target datagram of MaxPayload + 1
// at the passive's egress socket, each between two that fit. Load:
// datagrams of exactly MaxPayload both ways. Integrity: every datagram that
// fits arrives once, whole and in order; neither oversize one arrives in
// any form (the next datagram each end receives is the one sent after it),
// and each is counted where it was dropped (the ingress's TooLarge and
// TooLargeMax, the Server's TooLarge) while the flow lives (one session, no
// end); the target hears one egress socket, which sent every datagram with
// Write and never with WriteTo (L57: a connected socket refuses WriteTo).
func TestL4URealSizes_L37_L71(t *testing.T) {
	for _, b := range []struct{ maxDatagram, maxPayload int }{{udp.DefaultMaxDatagram, 1198}, {1472, 1438}} {
		t.Run("MaxDatagram="+strconv.Itoa(b.maxDatagram), func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			var w l4uWrites
			n := newL4uNet(t, l4uOpts{maxDatagram: b.maxDatagram, srv: &l4.Server{UDP: true, Dial: w.dial}})
			tg := newL4uTarget(t, "udp4", "127.0.0.1:0")
			ing := l4uListen(t, "udp4", "127.0.0.1:0")
			n.serveUDP(ing, tg.addr())
			cl := newL4uClient(t, "udp4", ing.LocalAddr())
			mp := b.maxPayload
			cl.exchange(1, 64) // the flow opens (the datagram rides the OPEN)
			if f, s := n.pf.Status().UDP.MaxPayload, n.srv.Status().UDP.MaxPayload; f != mp || s != mp {
				t.Fatalf("premise: the flow's MaxPayload is %d at the ingress and %d at the passive, want %d", f, s, mp)
			}

			// Client → target: MaxPayload passes; MaxPayload + 1 is dropped
			// and counted at the ingress; the next datagram is delivered.
			cl.exchange(2, mp)
			cl.send(3, mp+1)
			cl.exchange(4, mp)
			if u := n.pf.Status().UDP; u.TooLarge != 1 || u.TooLargeMax != mp+1 {
				t.Errorf("ingress: TooLarge %d, TooLargeMax %d after one client datagram of %d B, want 1 and %d", u.TooLarge, u.TooLargeMax, mp+1, mp+1)
			}

			// Target → client: the same at the passive's egress socket.
			tg.echo.Store(false)
			egress := tg.only(t)
			tg.pushTo(t, egress, l4uDgram(5, mp))
			cl.expect(5, mp)
			tg.pushTo(t, egress, l4uDgram(6, mp+1))
			tg.pushTo(t, egress, l4uDgram(7, 64))
			cl.expect(7, 64)
			if s := n.srv.Status().UDP; s.TooLarge != 1 {
				t.Errorf("Server: TooLarge %d after one target datagram of %d B, want 1", s.TooLarge, mp+1)
			}

			srcs, lens, err := tg.seen()
			if want := []int{64, mp, mp}; !slices.Equal(lens, want) || len(srcs) != 1 || err != nil {
				t.Errorf("target: datagram lengths %v from %v (read error %v), want %v from one egress socket", lens, srcs, err, want)
			}
			if wr, wt := w.write.Load(), w.writeTo.Load(); wr != 3 || wt != 0 {
				t.Errorf("egress socket: %d Write and %d WriteTo calls for 3 datagrams, want 3 and 0", wr, wt)
			}
			n.live(1)
			n.close()
		})
	}
}

// TestL4URealConnectedICMP_L58_L73 (M6 design §A16.3, §A13, M6-D15; L58,
// L73): Linux reports an ICMP port unreachable on a connected UDP socket.
// Stimulus: the target's port closes under a live flow, and the client
// keeps sending until the passive's egress socket (connected by the default
// dialer) returned ECONNREFUSED on a Read or Write. Load: a datagram every
// 10 ms. Integrity: the error is counted TargetNoise and nothing else; once
// the port opens again, the client's datagrams reach the new socket and
// come back, from the same egress socket, on the same flow (one session,
// no end at either side). The other ICMP classes need nft or raw sockets
// (lesson/l4u-edges step 4, R1-2).
func TestL4URealConnectedICMP_L58_L73(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux socket behaviour: a connected UDP socket reports ICMP port unreachable as ECONNREFUSED (on Windows: TestL4URealConnectedICMPWindows_L73)")
	}
	l4uConnectedICMP(t, true)
}

// TestL4URealConnectedICMPWindows_L73 (M6 design §A16.3, §A13; L73): the
// same stimulus on Windows produces no error, because the net package
// switches SIO_UDP_CONNRESET and SIO_UDP_NETRESET off on the sockets it
// makes. Stimulus proof: at least 20 datagrams were written to the closed
// port, and a probe socket with SIO_UDP_CONNRESET on, connected to the
// same port, is told the port is unreachable (this host's loopback answers
// with ICMP). Integrity: TargetNoise never moves, and the flow resumes as
// on Linux.
func TestL4URealConnectedICMPWindows_L73(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows socket behaviour: Go switches SIO_UDP_CONNRESET and SIO_UDP_NETRESET off (on Linux: TestL4URealConnectedICMP_L58_L73)")
	}
	l4uConnectedICMP(t, false)
}

// l4uConnectedICMP is the body of both ICMP rows; reported says whether
// the OS reports the closed port on the egress socket.
func l4uConnectedICMP(t *testing.T, reported bool) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	n := newL4uNet(t, l4uOpts{})
	tg := newL4uTarget(t, "udp4", "127.0.0.1:0")
	addr := tg.addr()
	ing := l4uListen(t, "udp4", "127.0.0.1:0")
	n.serveUDP(ing, addr)
	cl := newL4uClient(t, "udp4", ing.LocalAddr())
	cl.exchange(1, 64)
	egress := tg.only(t)

	tg.close() // the port is closed: a datagram to it draws ICMP port unreachable
	base := n.srv.Status().UDP
	seq := uint64(2)
	send := func() { cl.send(seq, 64); seq++ }
	if reported {
		k := l4uDrive(t, "the egress socket reported the closed port (TargetNoise)", func() bool {
			return n.srv.Status().UDP.TargetNoise > base.TargetNoise
		}, send)
		t.Logf("TargetNoise %d after %d datagrams to the closed port", n.srv.Status().UDP.TargetNoise-base.TargetNoise, k)
	} else {
		l4uDrive(t, "20 datagrams written to the closed port", func() bool {
			return n.srv.Status().UDP.ToTarget >= base.ToTarget+20
		}, send)
		errno, err := l4uProbeConnReset(addr)
		if err != nil {
			t.Fatalf("premise: the closed port draws no ICMP report on this host's loopback: %v", err)
		}
		t.Logf("probe with SIO_UDP_CONNRESET on: %v (%d)", errno, uintptr(errno))
		if s := n.srv.Status().UDP; s.TargetNoise != base.TargetNoise {
			t.Errorf("TargetNoise %d → %d: the egress socket reported the closed port (SIO_UDP_CONNRESET on?)", base.TargetNoise, s.TargetNoise)
		}
	}

	tg2 := newL4uTarget(t, "udp4", addr) // the port opens again
	from := seq
	l4uDrive(t, "an echo through the re-opened port", func() bool { return cl.gotFrom(from) }, send)
	if src := tg2.only(t); src != egress {
		t.Errorf("the re-opened target hears %v, want the flow's egress socket %v", src, egress)
	}
	if !reported {
		if s := n.srv.Status().UDP; s.TargetNoise != base.TargetNoise {
			t.Errorf("TargetNoise %d → %d after the port re-opened", base.TargetNoise, s.TargetNoise)
		}
	}
	n.live(1)
	n.close()
}

// l4uProbeConnReset shows that a datagram to addr draws an ICMP report on
// this host: from a socket connected to addr with Winsock's
// SIO_UDP_CONNRESET on (l4uConnResetOn), it sends a datagram every 50 ms
// until a Write or Read fails with an errno (the port unreachable), for at
// most l4uWait, and returns that errno.
func l4uProbeConnReset(addr string) (syscall.Errno, error) {
	ra, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return 0, err
	}
	c, err := net.DialUDP("udp4", nil, ra)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if err := l4uConnResetOn(c); err != nil {
		return 0, err
	}
	b := make([]byte, 64)
	var en syscall.Errno
	for deadline := time.Now().Add(l4uWait); time.Now().Before(deadline); {
		if _, err := c.Write(b); err != nil {
			if errors.As(err, &en) {
				return en, nil
			}
			return 0, err
		}
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := c.Read(b)
		switch {
		case errors.As(err, &en):
			return en, nil
		case err == nil:
			return 0, fmt.Errorf("a datagram arrived from %s, whose port should be closed", addr)
		case !errors.Is(err, os.ErrDeadlineExceeded):
			return 0, err
		}
	}
	return 0, fmt.Errorf("no ICMP report within %v", l4uWait)
}

// TestL4URealOversize_L58 (M6 design §A16.3, §A13, §A4.3; L58): a 60,000-
// byte datagram against MaxPayload 1,198, both ways. Stimulus: the target
// sends one to the flow's egress socket, whose read buffer is MaxPayload +
// 1 bytes — Linux truncates it into the buffer, Windows fails the read
// WSAEMSGSIZE — and the client sends one to the ingress, which reads
// whole datagrams (64 KiB). Integrity: each is dropped and counted exactly
// once (the Server's TooLarge; the ingress's TooLarge and TooLargeMax
// 60,000), nothing of it arrives at the far end in any form (the next
// datagram each end receives is the one sent after it), and the flow lives
// (one session, no end).
func TestL4URealOversize_L58(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	n := newL4uNet(t, l4uOpts{})
	tg := newL4uTarget(t, "udp4", "127.0.0.1:0")
	ing := l4uListen(t, "udp4", "127.0.0.1:0")
	n.serveUDP(ing, tg.addr())
	cl := newL4uClient(t, "udp4", ing.LocalAddr())
	cl.exchange(1, 64)
	egress := tg.only(t)

	tg.echo.Store(false)
	tg.pushTo(t, egress, l4uDgram(2, 60000))
	tg.pushTo(t, egress, l4uDgram(3, 64))
	cl.expect(3, 64)
	if s := n.srv.Status().UDP; s.TooLarge != 1 || s.TargetNoise != 0 {
		t.Errorf("Server: TooLarge %d, TargetNoise %d after one 60,000-byte target datagram, want 1 and 0", s.TooLarge, s.TargetNoise)
	}

	tg.echo.Store(true)
	cl.send(4, 60000)
	cl.exchange(5, 64)
	if u := n.pf.Status().UDP; u.TooLarge != 1 || u.TooLargeMax != 60000 || u.ReadNoise != 0 {
		t.Errorf("ingress: TooLarge %d, TooLargeMax %d, ReadNoise %d after one 60,000-byte client datagram, want 1, 60000 and 0", u.TooLarge, u.TooLargeMax, u.ReadNoise)
	}
	if _, lens, err := tg.seen(); !slices.Equal(lens, []int{64, 64}) || err != nil {
		t.Errorf("target: datagram lengths %v (read error %v), want [64 64]", lens, err)
	}
	n.live(1)
	n.close()
}

// TestL4URealDualStack (M6 design §A16.3, §A13): an ingress on the IPv6
// wildcard of a dual-stack socket. Stimulus: an IPv4 client (127.0.0.1)
// and an IPv6 client (::1) send to it. Integrity: every datagram of each
// comes back intact; the IPv4 client's flow is one entry keyed as the
// socket reports its source, ::ffff:127.0.0.1 and its port, and the IPv6
// client's another; two sessions, both open, none ended. The wildcard bind
// runs off Windows only (as examples/portforward's wildcard rows): on a
// Windows host it may raise a firewall prompt.
func TestL4URealDualStack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("binds the IPv6 wildcard, which may raise the firewall prompt of a Windows host (examples/portforward's wildcard rows run off Windows too); the Linux lanes run this row")
	}
	t.Cleanup(rendrtest.AssertNoLeak(t))
	n := newL4uNet(t, l4uOpts{pf: func(f *l4.PortForward) { f.AllowNonLoopback = true }})
	tg := newL4uTarget(t, "udp4", "127.0.0.1:0")
	ing := l4uListen(t, "udp", "[::]:0")
	la := ing.LocalAddr().(*net.UDPAddr)
	if la.IP.To4() != nil || !la.IP.IsUnspecified() {
		t.Fatalf("premise: the ingress socket is bound to %v, not the IPv6 wildcard", la)
	}
	n.serveUDP(ing, tg.addr())
	v4 := newL4uClient(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: la.Port})
	for seq := uint64(1); seq <= 5; seq++ {
		v4.exchange(seq, 200)
	}
	v6 := newL4uClient(t, "udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: la.Port})
	for seq := uint64(11); seq <= 12; seq++ {
		v6.exchange(seq, 200)
	}

	a4 := v4.addr()
	want4 := netip.AddrPortFrom(netip.AddrFrom16(a4.Addr().Unmap().As16()), a4.Port())
	want6 := v6.addr()
	flows := n.pf.Flows()
	got := map[netip.AddrPort]l4.FlowState{}
	for _, f := range flows {
		got[f.Client] = f.State
	}
	if len(flows) != 2 || got[want4] != l4.FlowOpen || got[want6] != l4.FlowOpen {
		t.Errorf("flows %+v, want two open ones keyed %v (the IPv4 client, as the dual-stack socket reports it) and %v", flows, want4, want6)
	}
	if srcs, _, err := tg.seen(); len(srcs) != 2 || err != nil {
		t.Errorf("target: sources %v (read error %v), want two egress sockets", srcs, err)
	}
	n.live(2)
	n.close()
}

// l4uDNS is a fake DNS server for one name that has only an AAAA record:
// it answers an AAAA query for the name with addr, any other query for it
// with no record (NOERROR, an empty answer) and a query for another name
// with NXDOMAIN. While it runs, net.DefaultResolver uses the Go resolver
// and sends every query here (its Dial), so the l4 Server's default dialer
// resolves through it; a cleanup restores the resolver.
type l4uDNS struct {
	c           *net.UDPConn
	name        string // lower case, with the root's dot
	addr        netip.Addr
	aaaa, other atomic.Int64 // queries for name: AAAA, and the rest
	done        chan struct{}
}

// newL4uDNS starts the fake. Call it before any goroutine that may resolve
// starts (the fixture): it writes net.DefaultResolver's fields.
func newL4uDNS(t testing.TB, name string, addr netip.Addr) *l4uDNS {
	t.Helper()
	d := &l4uDNS{c: l4uListen(t, "udp4", "127.0.0.1:0"), name: strings.ToLower(name) + ".", addr: addr, done: make(chan struct{})}
	go d.serve()
	r := net.DefaultResolver
	preferGo, dial := r.PreferGo, r.Dial
	r.PreferGo = true
	r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if !strings.HasPrefix(network, "udp") {
			return nil, fmt.Errorf("the fake DNS serves UDP only, not %s", network)
		}
		return (&net.Dialer{}).DialContext(ctx, "udp4", d.c.LocalAddr().String())
	}
	t.Cleanup(func() {
		r.PreferGo, r.Dial = preferGo, dial
		d.c.Close()
		<-d.done
	})
	return d
}

func (d *l4uDNS) serve() {
	defer close(d.done)
	b := make([]byte, 1500)
	for {
		n, src, err := d.c.ReadFromUDPAddrPort(b)
		if err != nil {
			return
		}
		if resp := d.answer(b[:n]); resp != nil {
			d.c.WriteToUDPAddrPort(resp, src)
		}
	}
}

// answer returns the response to query q, nil for a malformed query: the
// header (QR, AA and RA set, RD as asked), the question as asked and, for
// an AAAA query for the name, one AAAA record.
func (d *l4uDNS) answer(q []byte) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil
	}
	var name strings.Builder
	i := 12
	for {
		if i >= len(q) {
			return nil
		}
		l := int(q[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(q) {
			return nil
		}
		name.WriteString(strings.ToLower(string(q[i : i+l])))
		name.WriteByte('.')
		i += l
	}
	if i+4 > len(q) {
		return nil
	}
	qtype, qclass := binary.BigEndian.Uint16(q[i:]), binary.BigEndian.Uint16(q[i+2:])
	i += 4
	flags := uint16(0x8000|0x0400|0x0080) | binary.BigEndian.Uint16(q[2:])&0x0100
	var an uint16
	switch {
	case name.String() != d.name:
		flags |= 3 // NXDOMAIN
	case qtype == 28 && qclass == 1:
		an = 1
		d.aaaa.Add(1)
	default:
		d.other.Add(1)
	}
	r := append([]byte(nil), q[:2]...)
	r = binary.BigEndian.AppendUint16(r, flags)
	r = binary.BigEndian.AppendUint16(r, 1)
	r = binary.BigEndian.AppendUint16(r, an)
	r = binary.BigEndian.AppendUint32(r, 0) // NSCOUNT, ARCOUNT
	r = append(r, q[12:i]...)
	if an == 1 {
		r = append(r, 0xc0, 12) // the question's name
		r = binary.BigEndian.AppendUint16(r, 28)
		r = binary.BigEndian.AppendUint16(r, 1)
		r = binary.BigEndian.AppendUint32(r, 60)
		r = binary.BigEndian.AppendUint16(r, 16)
		a := d.addr.As16()
		r = append(r, a[:]...)
	}
	return r
}

// TestL4URealIPv6Target (M6 design §A16.3, §A3.1): UDP targets reached over
// IPv6 by the Server's default dialer: an IPv6 literal ([::1]:port) and a
// name in the .test zone whose only record is AAAA ::1, which the passive
// resolves (the dialer resolves nothing) through a fake DNS server.
// Stimulus: one flow to each. Integrity: every datagram comes back intact;
// the target hears two egress sockets, both from ::1; the fake answered
// the name's AAAA query (the name was resolved there, to its only
// address); two sessions, both open, none ended.
func TestL4URealIPv6Target(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const name = "aaaa-only.rendr.test"
	dns := newL4uDNS(t, name, netip.IPv6Loopback())
	n := newL4uNet(t, l4uOpts{})
	tg := newL4uTarget(t, "udp6", "[::1]:0")
	_, port, _ := net.SplitHostPort(tg.addr())
	for i, target := range []string{tg.addr(), net.JoinHostPort(name, port)} {
		ing := l4uListen(t, "udp4", "127.0.0.1:0")
		n.serveUDP(ing, target)
		cl := newL4uClient(t, "udp4", ing.LocalAddr())
		for k := range 3 {
			cl.exchange(uint64(10*i+k), 300)
		}
	}
	srcs, _, err := tg.seen()
	v6 := 0
	for a := range srcs {
		if a.Addr() == netip.IPv6Loopback() {
			v6++
		}
	}
	if len(srcs) != 2 || v6 != 2 || err != nil {
		t.Errorf("target: sources %v (read error %v), want two egress sockets on ::1", srcs, err)
	}
	if dns.aaaa.Load() == 0 {
		t.Errorf("the fake DNS answered no AAAA query for %s (%d other queries): the name was not resolved through it", name, dns.other.Load())
	}
	t.Logf("fake DNS: %d AAAA and %d other queries for %s", dns.aaaa.Load(), dns.other.Load(), name)
	n.live(2)
	n.close()
}

// l4uSamePort opens a TCP listener and a UDP socket on one loopback port (a
// few tries: the UDP port of a fresh TCP port may be in use).
func l4uSamePort(t testing.TB) (net.Listener, *net.UDPConn) {
	t.Helper()
	for try := 0; ; try++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("premise: %v", err)
		}
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ln.Addr().(*net.TCPAddr).Port})
		if err == nil {
			l4uBuffers(u)
			t.Cleanup(func() { ln.Close(); u.Close() })
			return ln, u
		}
		ln.Close()
		if try == 9 {
			t.Fatalf("premise: no loopback port free for TCP and UDP at once in 10 tries: %v", err)
		}
	}
}

// l4uTCPEcho serves ln: every connection gets back what it sent, then a
// FIN. It returns the count of accepted connections; a cleanup stops it.
func l4uTCPEcho(t testing.TB, ln net.Listener) *atomic.Int64 {
	var accepted atomic.Int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Go(func() {
				defer c.Close()
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			})
		}
	})
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return &accepted
}

// TestL4URealTCPUDPSamePort (M6 design §A16.3, §A8.7): a TCP and a UDP
// forward on the same ingress port number to one target port number, at
// once, over one Peer (carrier/tcp for the stream session, carrier/udp
// for the flow). Stimulus: a TCP connection sends half of its bytes and
// holds the rest until the UDP flow made 10 round trips, so both are in
// progress at once; the UDP flow keeps its round trips going until the
// TCP transfer ended. Load: 8 MiB echoed over TCP (1 MiB under the race
// detector), 1,000-byte UDP round trips. Integrity: the TCP echo is every
// byte of the PRNG stream in order, then a FIN; every UDP datagram comes
// back intact and in order; the target accepted one TCP connection and
// heard one UDP egress socket; the PortForward and the Server counted one
// of each kind (TCP Accepted and Confirmed 1, UDP flows 1) and no failure.
func TestL4URealTCPUDPSamePort(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	n := newL4uNet(t, l4uOpts{stream: true})
	tl, tu := l4uSamePort(t)
	accepted := l4uTCPEcho(t, tl)
	tg := l4uTargetOn(t, tu)
	target := tl.Addr().String()
	il, iu := l4uSamePort(t)
	n.serveTCP(il, target)
	n.serveUDP(iu, target)

	tc, err := net.Dial("tcp4", il.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tc.Close() })
	cl := newL4uClient(t, "udp4", iu.LocalAddr())
	cl.exchange(1, 64)

	size := int64(8 << 20)
	if msRace {
		size = 1 << 20
	}
	const seed = 61
	half, gate, tcpDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	openGate := sync.OnceFunc(func() { close(gate) })
	var sendErr, readErr error
	var read [32]byte
	var got atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		src := rendrtest.PRNG(seed)
		_, sendErr = io.CopyN(tc, src, size/2)
		close(half)
		if sendErr != nil {
			return
		}
		<-gate
		if _, sendErr = io.CopyN(tc, src, size-size/2); sendErr == nil {
			sendErr = tc.(*net.TCPConn).CloseWrite()
		}
	})
	wg.Go(func() {
		defer close(tcpDone)
		read, readErr = l4rRecv(tc, size, seed, &got)
	})
	finished := false
	defer func() { // a failed row releases and joins both goroutines
		if !finished {
			openGate()
			tc.Close()
			wg.Wait()
		}
	}()
	<-half
	seq, during := uint64(2), 0
	deadline := time.Now().Add(30 * time.Second)
	for running := true; running; {
		select {
		case <-tcpDone:
			running = false
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the TCP transfer did not end within 30 s (%d of %d bytes echoed)", got.Load(), size)
		}
		cl.exchange(seq, 1000)
		seq++
		if during < 10 && got.Load() < size {
			if during++; during == 10 {
				openGate() // the TCP sender resumes
			}
		}
	}
	openGate()
	wg.Wait()
	finished = true
	if sendErr != nil || readErr != nil || read != l4rPRNGSum(size, seed) {
		t.Errorf("TCP: send %v, read %v, SHA-256 read %x want %x", sendErr, readErr, read[:8], l4rPRNGSum(size, seed))
	}
	if during < 10 {
		t.Errorf("stimulus: %d UDP round trips while the TCP transfer was in progress, want 10", during)
	}
	t.Logf("%d UDP round trips, %d of them before the TCP transfer resumed; %d TCP bytes echoed", seq-2, during, got.Load())
	tc.Close()
	msUntil(t, l4uWait, "the TCP connection ended at the PortForward", func() bool { return n.pf.Status().TCP.Live == 0 })

	if f := n.pf.Status().TCP; f.Accepted != 1 || f.Refused != 0 || f.Failed != 0 {
		t.Errorf("PortForward TCP: Accepted %d, Refused %d, Failed %d, want 1, 0, 0", f.Accepted, f.Refused, f.Failed)
	}
	if s := n.srv.Status(); s.Confirmed != 1 || s.Rejected != 0 {
		t.Errorf("Server TCP: Confirmed %d, Rejected %d, want 1 and 0", s.Confirmed, s.Rejected)
	}
	if a := accepted.Load(); a != 1 {
		t.Errorf("the target accepted %d TCP connections, want 1", a)
	}
	if srcs, _, err := tg.seen(); len(srcs) != 1 || err != nil {
		t.Errorf("target: UDP sources %v (read error %v), want one egress socket", srcs, err)
	}
	n.live(1)
	n.close()
}

// TestL4URealIngressReadNoiseWindows_L73 (M6 design §A16.3, §A13, M6-D25;
// L73): an ingress socket that reports ICMP. Go switches Winsock's
// SIO_UDP_CONNRESET off on its sockets; the row switches it back on for
// the ingress socket (l4uConnResetOn, the test only). Stimulus: client A's
// flow opens, A's socket closes, and the target sends to A's flow until
// the ingress's reply to A's closed port drew an ICMP port unreachable and
// the socket's next ReadFrom failed (WSAECONNRESET). Integrity: the error
// is counted ReadNoise and backed off, ServeUDP keeps running, and client
// B's datagram, sent after it, opens a flow and comes back intact; both
// flows open, none ended.
func TestL4URealIngressReadNoiseWindows_L73(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows socket behaviour: Winsock's SIO_UDP_CONNRESET (Linux reports nothing on an unconnected socket without IP_RECVERR)")
	}
	t.Cleanup(rendrtest.AssertNoLeak(t))
	n := newL4uNet(t, l4uOpts{})
	tg := newL4uTarget(t, "udp4", "127.0.0.1:0")
	ing := l4uListen(t, "udp4", "127.0.0.1:0")
	if err := l4uConnResetOn(ing); err != nil {
		t.Fatalf("premise: SIO_UDP_CONNRESET on the ingress socket: %v", err)
	}
	sv := n.serveUDP(ing, tg.addr())
	a := newL4uClient(t, "udp4", ing.LocalAddr())
	a.exchange(1, 64)
	egressA := tg.only(t)
	a.close() // A's port is closed: a reply to it draws ICMP port unreachable

	tg.echo.Store(false)
	base := n.pf.Status().UDP
	seq := uint64(2)
	k := l4uDrive(t, "the ingress socket's read reported A's closed port (ReadNoise)", func() bool {
		return n.pf.Status().UDP.ReadNoise > base.ReadNoise
	}, func() { tg.pushTo(t, egressA, l4uDgram(seq, 64)); seq++ })
	u := n.pf.Status().UDP
	t.Logf("ReadNoise %d, WriteNoise %d, ToClient %d after %d replies to A's closed port", u.ReadNoise-base.ReadNoise, u.WriteNoise-base.WriteNoise, u.ToClient-base.ToClient, k)
	if u.ToClient == base.ToClient && u.WriteNoise == base.WriteNoise {
		t.Errorf("stimulus: no reply was written toward A's closed port")
	}
	if !sv.running() {
		t.Fatalf("ServeUDP returned %v on the reset", sv.err)
	}

	tg.echo.Store(true)
	b := newL4uClient(t, "udp4", ing.LocalAddr())
	b.exchange(100, 64)
	if !sv.running() {
		t.Fatalf("ServeUDP returned %v", sv.err)
	}
	n.live(2)
	n.close()
}
