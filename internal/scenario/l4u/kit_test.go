package l4u

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of package l4u (M6 design §A16.2). A world is two Runtimes
// — the dialer d (the ingress side) and the passive p with one push-only
// Listener — joined by rendrtest DatagramLinks (and stream Links where a
// row needs stream members) whose Accept is the Listener's HandlePacket
// (Handle for the stream Links). The passive runs an l4.Server{UDP: true}
// whose HandleUDP serves every packet session the Listener's AcceptPacket
// returns — what Server.Serve's packet loop does — on the kit's own accept
// loop, which records every session ID it is handed, so that a session
// published twice is seen (L47). The Server's Dial hook gives every flow a
// rendrtest.DatagramPipe, its "egress socket", whose address is unique per
// call (the source address the target sees), and runs the target
// application registered for the request's port on the pipe's other end.
// An ingress is one PortForward.ServeUDP on a rendrtest.UDPSocketHub
// toward one target; the hub's clients are the client applications, each
// with its own source address. Every datagram factory records the conn of
// each session carrier by its CarrierID, so that a row can close one under
// rendr (the gold cases' local close, F10). Both Runtimes' events are
// recorded. Everything is created inside the synctest bubble that uses it
// and closed before the bubble ends; the bubble itself fails if a
// goroutine outlives it, and close checks that neither Runtime, the Server
// nor a PortForward holds state and that the session registry is back
// where it was (M3 design R1-24).

const (
	oneWay = 10 * time.Millisecond // every link's one-way delay: 20 ms RTT
	// kitMTU is the datagram factories' frame budget: carrier/udp's at
	// MaxDatagram 1,472 (a 1,500-byte IPv4 path, the L4U-1472
	// configuration of F86) less its 9-byte flow header, so MaxPayload is
	// 1,438 (§A4.1); the links carry datagrams up to 1,500 bytes.
	kitMTU     = 1463
	kitLinkMTU = 1500
	// kitPayload is a session's MaxPayload over kitMTU (§A4.1: MTU − 25).
	kitPayload = kitMTU - 25
	// kitDeadMax is the zero Config's DeadMax (the rows use the default
	// timing unless they say otherwise).
	kitDeadMax = 4 * time.Second
)

// Documentation addresses of the targets (198.51.100.0/24) and the
// clients (192.0.2.0/24); the hub sockets are loopback (the PortForward's
// default).
var targetHost = netip.MustParseAddr("198.51.100.10")

// netipLoopback is 127.0.0.1:port.
func netipLoopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
}

// targetAddr is the target address of port.
func targetAddr(port uint16) string { return netip.AddrPortFrom(targetHost, port).String() }

// clientSrc is the source address of client i: 16 addresses × 40,000
// ports (F87's tuple pool shape, so that up to 640,000 clients are
// unique).
func clientSrc(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + i/40000%16)}), uint16(20000+i%40000))
}

// linkSpec is one path of a world; its name is also the factory's name.
type linkSpec struct {
	name   string
	stream bool // a rendrtest.Link and a StreamCarrier (else a DatagramLink and a DatagramCarrier)
	mtu    int  // datagram: the factory's frame budget (0: kitMTU)
	queue  int  // datagram: the link's Queue (0: 16,384)
}

// worldOpts configures a world.
type worldOpts struct {
	dcfg, pcfg rendr.Config        // OnEvent is set by the world
	dov, pov   testhooks.Overrides // the dialer's and the passive's
	listen     rendr.ListenConfig
	// srv configures the passive's Server (nil: the zero Server; UDP and
	// Dial are set by the world).
	srv func(*l4.Server)
	// pipeQueue is every target pipe's Queue (0: the pipe's 256).
	pipeQueue int
	// dialDelay is how long the Server's Dial hook takes before it returns
	// (0: at once), the passive's own work between an OPEN's arrival and
	// its Confirm (a real target's connect).
	dialDelay time.Duration
}

// targetApp is a target application: it serves one flow on its pipe end
// and returns when the flow ended (the pipe closed); the kit closes the end
// after it returned.
type targetApp func(e *egress)

// egress is one flow at the target: the Server's Dial call that made it,
// its pipe and what the target application sees.
type egress struct {
	n     int                     // the call's number, from 0
	addr  string                  // Request.Addr
	first []byte                  // a copy of Request.First (nil: none rode the OPEN)
	src   netip.AddrPort          // the egress socket's address: what the target sees as the flow's source
	conn  *rendrtest.DatagramConn // the target application's end
	local *rendrtest.DatagramConn // the Server's end (its egress socket)
}

// world is one scenario's Runtimes, Listener, Server, links and ingresses.
type world struct {
	t        testing.TB
	o        worldOpts
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	srv      *l4.Server
	dlinks   map[string]*rendrtest.DatagramLink
	slinks   map[string]*rendrtest.Link
	specs    []linkSpec
	dev, pev *eventLog

	serveCancel context.CancelFunc
	acceptDone  chan struct{}
	handlers    sync.WaitGroup // HandleUDP calls
	apps        sync.WaitGroup // target applications

	live0, parked0 int64
	shutOnce       sync.Once
	// quit is closed first by shutdown: paced traffic goroutines stop at
	// once, so that a row that failed mid-traffic ends cleanly.
	quit chan struct{}

	mu        sync.Mutex
	targets   map[uint16]targetApp
	egresses  []*egress
	published map[rendr.SessionID]int // PendingPackets per session ID
	conns     map[rendr.CarrierID]net.PacketConn
	ingresses []*ingress
	peers     []*rendr.Peer
}

// newWorld builds the Runtimes, the Listener, the links, the Server and
// its accept loop. A cleanup shuts everything down if the test fails
// before close.
func newWorld(t testing.TB, o worldOpts, specs ...linkSpec) *world {
	t.Helper()
	w := &world{t: t, o: o, specs: specs, dlinks: map[string]*rendrtest.DatagramLink{}, slinks: map[string]*rendrtest.Link{},
		dev: &eventLog{}, pev: &eventLog{}, quit: make(chan struct{}), acceptDone: make(chan struct{}),
		targets: map[uint16]targetApp{}, published: map[rendr.SessionID]int{}, conns: map[rendr.CarrierID]net.PacketConn{},
		live0: testhooks.LiveSessions.Load(), parked0: testhooks.ParkedSessions.Load()}
	o.dcfg.OnEvent, o.pcfg.OnEvent = w.dev.add, w.pev.add
	w.d = newRuntime(t, o.dcfg, &o.dov)
	w.p = newRuntime(t, o.pcfg, &o.pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(o.listen)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for _, s := range specs {
		if s.stream {
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: s.name, Accept: ln.Handle})
			l.SetDelay(oneWay, 0)
			w.slinks[s.name] = l
			continue
		}
		q := s.queue
		if q == 0 {
			q = 16384
		}
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: s.name, MTU: kitLinkMTU, Queue: q, Accept: ln.HandlePacket})
		for _, d := range bothDirs {
			l.SetDelay(d, oneWay, 0)
		}
		w.dlinks[s.name] = l
	}
	w.srv = &l4.Server{}
	if o.srv != nil {
		o.srv(w.srv)
	}
	w.srv.UDP = true
	w.srv.Dial = w.dialTarget
	ctx, cancel := context.WithCancel(context.Background())
	w.serveCancel = cancel
	go w.acceptLoop(ctx)
	return w
}

// newRuntime builds a Runtime through testhooks (unclamped overrides).
func newRuntime(t testing.TB, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// bothDirs are the two directions of a link (Up: dialer → passive).
var bothDirs = []rendrtest.Dir{rendrtest.Up, rendrtest.Down}

// acceptLoop hands every packet session of the Listener to HandleUDP on
// its own goroutine (Server.Serve's packet loop) and records its ID.
func (w *world) acceptLoop(ctx context.Context) {
	defer close(w.acceptDone)
	for {
		pp, err := w.ln.AcceptPacket(ctx)
		if err != nil {
			return
		}
		w.mu.Lock()
		w.published[pp.ID()]++
		w.mu.Unlock()
		w.handlers.Add(1)
		go func() {
			defer w.handlers.Done()
			w.srv.HandleUDP(ctx, pp)
		}()
	}
}

// target registers app for the flows toward port.
func (w *world) target(port uint16, app targetApp) {
	w.mu.Lock()
	w.targets[port] = app
	w.mu.Unlock()
}

// dialTarget is the Server's Dial hook: a DatagramPipe whose Server end
// reports a fresh egress address, with the target application of the
// request's port on the other end.
func (w *world) dialTarget(_ context.Context, r l4.Request) (net.Conn, error) {
	if r.Cmd != l4.CmdUDP {
		return nil, fmt.Errorf("scenario: a %#x request on the UDP kit", r.Cmd)
	}
	if w.o.dialDelay > 0 {
		time.Sleep(w.o.dialDelay)
	}
	ap, err := netip.ParseAddrPort(r.Addr)
	if err != nil {
		return nil, fmt.Errorf("scenario: target %q: %w", r.Addr, err)
	}
	w.mu.Lock()
	app := w.targets[ap.Port()]
	if app == nil {
		w.mu.Unlock()
		return nil, fmt.Errorf("scenario: no target application on port %d", ap.Port())
	}
	n := len(w.egresses)
	e := &egress{n: n, addr: r.Addr, src: egressSrc(n)}
	if len(r.First) > 0 {
		e.first = slices.Clone(r.First)
	}
	e.local, e.conn = rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{Queue: w.o.pipeQueue,
		AddrA: net.UDPAddrFromAddrPort(e.src), AddrB: net.UDPAddrFromAddrPort(ap)})
	w.egresses = append(w.egresses, e)
	w.apps.Add(1)
	w.mu.Unlock()
	go func() {
		defer w.apps.Done()
		defer e.conn.Close()
		app(e)
	}()
	return e.local, nil
}

// egressSrc is the egress address of the n-th target dial (the passive
// host's source address and a port of its own per flow).
func egressSrc(n int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(100 + n/50000)}), uint16(10000+n%50000))
}

// egressesOf returns the target dials so far toward port (0: all).
func (w *world) egressesOf(port uint16) []*egress {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*egress
	for _, e := range w.egresses {
		if ap, _ := netip.ParseAddrPort(e.addr); port == 0 || ap.Port() == port {
			out = append(out, e)
		}
	}
	return out
}

// dials returns how many target dials the Server made.
func (w *world) dials() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.egresses)
}

// publishedTwice returns the session IDs AcceptPacket returned more than
// once, and how many sessions it returned.
func (w *world) publishedTwice() (twice []rendr.SessionID, sessions int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, n := range w.published {
		if n > 1 {
			twice = append(twice, id)
		}
	}
	return twice, len(w.published)
}

// carrier returns the factory of link s: a DatagramCarrier whose Dial
// records the conn of every session carrier (not of probe carriers) by
// CarrierID, or a StreamCarrier.
func (w *world) carrier(s linkSpec) rendr.Carrier {
	if s.stream {
		l := w.slinks[s.name]
		return rendr.StreamCarrier{Name: s.name, Dial: l.Dial}
	}
	l := w.dlinks[s.name]
	mtu := s.mtu
	if mtu == 0 {
		mtu = kitMTU
	}
	return rendr.DatagramCarrier{Name: s.name, MTU: mtu, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := l.Dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			w.mu.Lock()
			w.conns[di.Carrier] = pc
			w.mu.Unlock()
		}
		return pc, a, err
	}}
}

// peer returns a dialer Peer over the links named, in that order.
func (w *world) peer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, n := range names {
		cs = append(cs, w.carrier(w.spec(n)))
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	w.mu.Lock()
	w.peers = append(w.peers, p)
	w.mu.Unlock()
	return p
}

// spec returns the spec of the link named name.
func (w *world) spec(name string) linkSpec {
	for _, s := range w.specs {
		if s.name == name {
			return s
		}
	}
	w.t.Fatalf("no link %q", name)
	return linkSpec{}
}

// dlink returns the datagram link named name.
func (w *world) dlink(name string) *rendrtest.DatagramLink {
	if l := w.dlinks[name]; l != nil {
		return l
	}
	w.t.Fatalf("no datagram link %q", name)
	return nil
}

// localClose closes the dialer's conn of carrier id under rendr: the gold
// cases' carrier close (F10; M2-D74). It fails the test unless the carrier
// was registered and its Close returned nil.
func (w *world) localClose(id rendr.CarrierID) {
	w.t.Helper()
	w.mu.Lock()
	pc := w.conns[id]
	w.mu.Unlock()
	if pc == nil {
		w.t.Fatalf("stimulus: carrier %d has no registered conn", id)
	}
	if err := pc.Close(); err != nil {
		w.t.Fatalf("stimulus: closing carrier %d's conn: %v", id, err)
	}
}

// ingress is one PortForward.ServeUDP on its own hub toward one target.
type ingress struct {
	w      *world
	pf     *l4.PortForward
	hub    *rendrtest.UDPSocketHub
	target string
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	ret    error

	mu      sync.Mutex
	clients []*rendrtest.DatagramConn
}

// forward starts pf.ServeUDP on a new hub (cfg) toward target.
func (w *world) forward(pf *l4.PortForward, target string, cfg rendrtest.UDPSocketHubConfig) *ingress {
	in := &ingress{w: w, pf: pf, hub: rendrtest.NewUDPSocketHub(cfg), target: target, done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	go func() { in.done <- pf.ServeUDP(ctx, in.hub.Socket(), target) }()
	w.mu.Lock()
	w.ingresses = append(w.ingresses, in)
	w.mu.Unlock()
	return in
}

// client returns a client application's socket with source src; the kit
// closes it at shutdown unless the row closed it.
func (in *ingress) client(src netip.AddrPort) *rendrtest.DatagramConn {
	c := in.hub.Client(src)
	in.mu.Lock()
	in.clients = append(in.clients, c)
	in.mu.Unlock()
	return c
}

// stop cancels ServeUDP and returns its result, failing the test unless it
// returned within a minute (L52: every flow ended and joined).
func (in *ingress) stop() error {
	in.once.Do(func() {
		in.cancel()
		select {
		case in.ret = <-in.done:
		case <-time.After(time.Minute):
			in.ret = fmt.Errorf("ServeUDP toward %s did not return within a minute of its cancel: %+v", in.target, in.pf.Status().UDP)
			in.w.t.Error(in.ret)
		}
	})
	return in.ret
}

// shutdown closes quit, stops every ingress, closes the clients, the
// Peers, both Runtimes (the dialer first), stops the accept loop and waits
// for the handlers and the target applications, then closes the links
// (once; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.shutOnce.Do(func() {
		close(w.quit)
		w.mu.Lock()
		ins, peers := slices.Clone(w.ingresses), slices.Clone(w.peers)
		w.mu.Unlock()
		for _, in := range ins {
			in.stop()
		}
		for _, in := range ins {
			in.mu.Lock()
			for _, c := range in.clients {
				c.Close()
			}
			in.mu.Unlock()
		}
		for _, p := range peers {
			p.Close()
		}
		w.d.Close()
		w.p.Close()
		w.serveCancel()
		<-w.acceptDone
		joined := make(chan struct{})
		go func() {
			w.handlers.Wait()
			w.apps.Wait()
			close(joined)
		}()
		select {
		case <-joined:
		case <-time.After(time.Minute):
			w.t.Errorf("HandleUDP calls or target applications still running a minute after Runtime.Close: %+v", w.srv.Status().UDP)
			<-joined
		}
		for _, l := range w.dlinks {
			l.Close()
		}
		for _, l := range w.slinks {
			l.Close()
		}
	})
}

// close shuts the world down and requires that every ServeUDP returned
// ctx's cancel, that the Server and the PortForwards hold no flow, that
// neither Runtime holds a session, a handshake, a sessionless or shared
// carrier, a datagram flow, an actor or a buffered byte any more, that
// nothing was abandoned, that no session was published twice, and that
// the session registry is back at its value before the world (R1-24).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, in := range w.ingresses {
		if !errors.Is(in.ret, context.Canceled) {
			w.t.Fatalf("ServeUDP toward %s returned %v, want context.Canceled at its stop", in.target, in.ret)
		}
		if st := in.pf.Status().UDP; st.Flows != 0 || st.Opening != 0 || st.Held != 0 {
			w.t.Fatalf("PortForward state left after its stop: %+v", plainF(st))
		}
	}
	if st := w.srv.Status(); st.UDP.Dialing != 0 || st.UDP.Live != 0 || st.Hooks != 0 || st.Abandoned != 0 {
		w.t.Fatalf("Server state left after Runtime.Close: %+v", plainS(st))
	}
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} || st.Mux.Carriers != 0 || st.Mux.Views != 0 ||
			st.Datagram.Flows != 0 || st.Datagram.Admitting != 0 {
			w.t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
	if twice, _ := w.publishedTwice(); len(twice) != 0 {
		w.t.Fatalf("L47: %d sessions were published twice by AcceptPacket: %v", len(twice), twice)
	}
	if l, p := testhooks.LiveSessions.Load()-w.live0, testhooks.ParkedSessions.Load()-w.parked0; l != 0 || p != 0 {
		w.t.Fatalf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
	}
}

// noViolation fails when a carrier of either Runtime ended with
// protocol_violation.
func (w *world) noViolation() {
	w.t.Helper()
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventCarrierDown) {
			if ev.Cause == rendr.CauseProtocolViolation {
				w.t.Fatalf("%s carrier %d ended with protocol_violation: %+v", side(i), ev.Carrier, ev)
			}
		}
	}
}

// plainF is st without LastErr (for messages).
func plainF(st l4.UDPForwardStatus) l4.UDPForwardStatus {
	st.LastErr = nil
	return st
}

// plainS is st without LastErr (for messages).
func plainS(st l4.ServerStatus) l4.ServerStatus {
	st.LastErr = nil
	return st
}

// side names end i: 0 the dialer, 1 the passive.
func side(i int) string { return [2]string{"dialer", "passive"}[i] }

// eventLog records Config.OnEvent calls.
type eventLog struct {
	mu  sync.Mutex
	evs []rendr.Event
}

func (l *eventLog) add(ev rendr.Event) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

// of returns the recorded events of kind k.
func (l *eventLog) of(k rendr.EventKind) []rendr.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []rendr.Event
	for _, ev := range l.evs {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// downOf returns the EventCarrierDown events of carrier id (one per
// session that held a lane on it).
func (l *eventLog) downOf(id rendr.CarrierID) []rendr.Event {
	var out []rendr.Event
	for _, ev := range l.of(rendr.EventCarrierDown) {
		if ev.Carrier == id {
			out = append(out, ev)
		}
	}
	return out
}

// waitFor polls cond every millisecond of virtual time until it holds,
// failing after within.
func waitFor(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out after %v waiting for %s", within, what)
		}
		time.Sleep(time.Millisecond)
	}
}

// sleepUntil sleeps until at (no-op when it passed).
func sleepUntil(at time.Time) {
	if d := time.Until(at); d > 0 {
		time.Sleep(d)
	}
}

// pace sleeps until at, or until quit is closed; it reports whether at
// was reached (false: the world is shutting down).
func pace(quit <-chan struct{}, at time.Time) bool {
	d := time.Until(at)
	if d <= 0 {
		select {
		case <-quit:
			return false
		default:
			return true
		}
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-tm.C:
		return true
	case <-quit:
		return false
	}
}

// Status helpers.

// liveOf returns the attached live carriers (active or member).
func liveOf(st rendr.SessionStatus) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive || c.State == rendr.CarrierMember {
			out = append(out, c)
		}
	}
	return out
}

// activeOf returns the active carrier of a selector session.
func activeOf(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// carrierOf returns the latest row of carrier id (live or among the recent
// dead).
func carrierOf(st rendr.SessionStatus, id rendr.CarrierID) (rendr.CarrierStatus, bool) {
	for i := len(st.Carriers) - 1; i >= 0; i-- {
		if c := st.Carriers[i]; c.ID == id {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// flowOf returns the PortForward's flow of client src.
func flowOf(pf *l4.PortForward, src netip.AddrPort) (l4.FlowInfo, bool) {
	for _, fi := range pf.Flows() {
		if fi.Client == src {
			return fi, true
		}
	}
	return l4.FlowInfo{}, false
}
