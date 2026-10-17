package l4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The test kit of PortForward.ServeUDP (M6 design §A16.1, WP6); helpers
// start with "pw". A pwWorld is a pfWorld (two Runtimes joined by
// rendrtest.DatagramLinks, a Peer of DatagramCarriers over them) with a
// rendrtest.UDPSocketHub as the ingress socket — its clients are the
// client applications, each with its own source address — a PortForward
// serving the hub's socket, and a kit passive (pwPassive) on the passive
// Runtime's Listener. The kit passive serves every packet session as
// HandleUDP does (the Server is WP5's; m6-design §A6.1): it decodes the
// UDP metadata, asks the row whether to refuse it or to make it wait
// (decide, gate), gives the flow a target DatagramPipe, writes a first
// datagram that rode the OPEN once to the target, confirms, and forwards
// the flow seeded with that write (R1-10). Each served flow is one pwFlow
// (its id is the "egress socket" the target sees), whose target
// application is the row's (echo by default). Everything is created inside
// the synctest bubble that uses it and closed before the bubble ends.

// pwOpts configures a pwWorld.
type pwOpts struct {
	pf              pfOpts
	pfwd            func(*PortForward) // sets the PortForward up (its Peer is the kit's)
	passiveIdle     FlowIdle           // the kit passive's classes (zero: idle expiry off there, unless passiveDefaults)
	passiveDefaults bool               // the kit passive uses the default classes
	backlog         int                // the passive Listener's AcceptBacklog (0: 1,024)
	acceptTimeout   time.Duration
	noAccept        bool                                   // no AcceptPacket loop: a passive that never serves packet sessions (PA-89)
	target          func(fl *pwFlow)                       // the target application of every flow (nil: pwEcho)
	decide          func(n int, r Request) RejectCode      // a non-zero code refuses the n-th OPEN (from 0)
	gate            func(n int, r Request) <-chan struct{} // a non-nil channel holds the n-th OPEN pending until it is closed
	hub             rendrtest.UDPSocketHubConfig
	wrap            func(UDPSocket) UDPSocket // wraps the hub's socket for ServeUDP
}

// pwWorld is one row's world.
type pwWorld struct {
	*pfWorld
	t      testing.TB
	hub    *rendrtest.UDPSocketHub
	sock   UDPSocket
	pf     *PortForward
	pas    *pwPassive
	cancel context.CancelFunc
	served chan error
	ret    error
	once   sync.Once
	ports  int
}

func newPWWorld(t testing.TB, o pwOpts) *pwWorld {
	t.Helper()
	w := &pwWorld{pfWorld: newPFWorld(t, o.pf), t: t}
	backlog := o.backlog
	if backlog == 0 {
		backlog = 1024
	}
	ln, err := w.p.Listen(rendr.ListenConfig{AcceptBacklog: backlog, AcceptTimeout: o.acceptTimeout})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	w.cur.Store(ln) // the links' new carriers reach this Listener
	idle := o.passiveIdle
	if idle == (FlowIdle{}) && !o.passiveDefaults {
		idle = FlowIdle{Short: -1}
	}
	w.pas = &pwPassive{ln: ln, idle: idle, target: o.target, decide: o.decide, gate: o.gate}
	if w.pas.target == nil {
		w.pas.target = pwEcho
	}
	if !o.noAccept {
		w.pas.wg.Add(1)
		go w.pas.loop()
	}
	w.hub = rendrtest.NewUDPSocketHub(o.hub)
	w.sock = w.hub.Socket()
	if o.wrap != nil {
		w.sock = o.wrap(w.sock)
	}
	w.pf = &PortForward{}
	if o.pfwd != nil {
		o.pfwd(w.pf)
	}
	w.pf.Peer = w.peer
	t.Cleanup(w.close)
	return w
}

// serve starts ServeUDP on the hub's socket toward pfTarget.
func (w *pwWorld) serve() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.served = make(chan error, 1)
	go func() { w.served <- w.pf.ServeUDP(ctx, w.sock, pfTarget) }()
}

// stop cancels ServeUDP and returns its result.
func (w *pwWorld) stop() error {
	w.t.Helper()
	if w.served == nil {
		return nil
	}
	w.cancel()
	w.ret = <-w.served
	w.served = nil
	return w.ret
}

// close stops the PortForward, closes the world and waits for the kit
// passive's goroutines (once).
func (w *pwWorld) close() {
	w.once.Do(func() {
		w.stop()
		w.shutdown()
		w.pas.wg.Wait()
	})
}

// client returns a hub client with a fresh loopback source address.
func (w *pwWorld) client() *rendrtest.DatagramConn {
	w.ports++
	return w.hub.Client(pwSrc(w.ports))
}

// pwSrc is the i-th kit client source address.
func pwSrc(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(20000+i))
}

// pwPassive is the kit passive: it serves every packet session of its
// Listener as HandleUDP does (see the kit's comment).
type pwPassive struct {
	ln     *rendr.Listener
	idle   FlowIdle
	target func(*pwFlow)
	decide func(int, Request) RejectCode
	gate   func(int, Request) <-chan struct{}
	wg     sync.WaitGroup

	mu        sync.Mutex
	flows     []*pwFlow // confirmed, in order
	opens     int       // packet sessions AcceptPacket returned
	rejects   int
	firstSent int
}

// pwFlow is one flow the kit passive confirmed.
type pwFlow struct {
	id      int
	req     Request // its request (First is a copy)
	pc      *rendr.PacketConn
	app     *rendrtest.DatagramConn // the target application's end of its pipe
	local   *rendrtest.DatagramConn // the passive forward's end (a row injects its local errors there)
	res     chan PacketResult       // the passive forward's result (once)
	rxMu    sync.Mutex
	rx      [][]byte // what the target application received (pwEcho, pwSink record)
	rxCount atomic.Int64
}

// received returns copies of what the target received so far.
func (fl *pwFlow) received() [][]byte {
	fl.rxMu.Lock()
	defer fl.rxMu.Unlock()
	return append([][]byte(nil), fl.rx...)
}

func (fl *pwFlow) record(b []byte) {
	fl.rxMu.Lock()
	fl.rx = append(fl.rx, bytes.Clone(b))
	fl.rxMu.Unlock()
	fl.rxCount.Add(1)
}

// pwEcho is the default target: it records and answers every datagram
// with the same bytes.
func pwEcho(fl *pwFlow) {
	buf := make([]byte, 64<<10)
	for {
		n, err := fl.app.Read(buf)
		if err != nil {
			return
		}
		fl.record(buf[:n])
		fl.app.Write(buf[:n])
	}
}

// pwSink is a target that records and never answers.
func pwSink(fl *pwFlow) {
	buf := make([]byte, 64<<10)
	for {
		n, err := fl.app.Read(buf)
		if err != nil {
			return
		}
		fl.record(buf[:n])
	}
}

func (p *pwPassive) loop() {
	defer p.wg.Done()
	for n := 0; ; n++ {
		pend, err := p.ln.AcceptPacket(context.Background())
		if err != nil {
			return
		}
		p.mu.Lock()
		p.opens++
		p.mu.Unlock()
		p.wg.Add(1)
		go p.serveOne(n, pend)
	}
}

func (p *pwPassive) serveOne(n int, pend *rendr.PendingPacket) {
	defer p.wg.Done()
	req, err := ParseUDPMetadata(pend.Metadata())
	if err != nil {
		pend.Reject(uint32(CodeBadRequest), CodeBadRequest.String())
		return
	}
	req.First = bytes.Clone(req.First)
	if p.decide != nil {
		if code := p.decide(n, req); code != 0 {
			p.mu.Lock()
			p.rejects++
			p.mu.Unlock()
			pend.Reject(uint32(code), code.String())
			return
		}
	}
	if p.gate != nil {
		if g := p.gate(n, req); g != nil {
			select {
			case <-g:
			case <-pend.Context().Done():
				return
			}
		}
	}
	local, app := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{Queue: 1024})
	var seed flowSeed
	if len(req.First) > 0 {
		seed = flowSeed{at: time.Now(), dir: towardLocal}
		local.Write(req.First)
		p.mu.Lock()
		p.firstSent++
		p.mu.Unlock()
	}
	pc, err := pend.Confirm()
	if err != nil {
		local.Close()
		return
	}
	fl := &pwFlow{req: req, pc: pc, app: app, local: local, res: make(chan PacketResult, 1)}
	p.mu.Lock()
	fl.id = len(p.flows)
	p.flows = append(p.flows, fl)
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.target(fl)
	}()
	fl.res <- forwardPacket(context.Background(), pc, local, p.idle, seed, nil)
}

// snapshot returns the kit passive's counters and flows.
func (p *pwPassive) snapshot() (opens, rejects, firstSent int, flows []*pwFlow) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opens, p.rejects, p.firstSent, append([]*pwFlow(nil), p.flows...)
}

// flowOf returns the confirmed flow whose target received a datagram
// tagged tag first (nil: none).
func (p *pwPassive) flowOf(tag byte) *pwFlow {
	_, _, _, flows := p.snapshot()
	for _, fl := range flows {
		if rx := fl.received(); len(rx) > 0 && tagOf(rx[0]) == tag {
			return fl
		}
	}
	return nil
}

// pwFlowGoroutines counts the PortForward flow goroutines (udpServe.flow)
// alive in the process: the bound of R1-5 (one per table entry).
func pwFlowGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "l4.(*udpServe).flow(") {
			count++
		}
	}
	return count
}

// pwEntries returns the table entries of every running ServeUDP of f by
// state.
func pwEntries(f *PortForward) (n int, by map[FlowState]int) {
	by = map[FlowState]int{}
	for _, fi := range f.Flows() {
		n++
		by[fi.State]++
	}
	return n, by
}

// pwUnits checks the MaxFlows units against the tables: one unit per
// entry, and the opening units against the opening entries.
func pwUnits(t testing.TB, f *PortForward) {
	t.Helper()
	f.mu.Lock()
	n, opening := 0, 0
	for s := range f.serves {
		s.tab.mu.Lock()
		for _, e := range s.tab.m {
			n++
			if e.state == FlowOpening {
				opening++
			}
		}
		s.tab.mu.Unlock()
	}
	f.mu.Unlock()
	if u, o := f.flows.Load(), f.opening.Load(); u != int64(n) || o != int64(opening) {
		t.Fatalf("MaxFlows units %d for %d entries, opening units %d for %d opening entries", u, n, o, opening)
	}
}

// pwStatus is f.Status().UDP.
func pwStatus(f *PortForward) UDPForwardStatus { return f.Status().UDP }

// pwRecvWithin reads the next datagram from c within d; ok is false at
// the deadline.
func pwRecvWithin(c net.Conn, d time.Duration) (b []byte, ok bool, err error) {
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 64<<10)
	n, err := c.Read(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return buf[:n], true, nil
}

// pwTagged returns n bytes whose first byte is tag and whose second and
// third bytes number the datagram (k), so a row tells its datagrams apart.
func pwTagged(n int, tag byte, k int) []byte {
	b := pfData(max(n, 3), tag)[:n]
	if n >= 3 {
		b[1], b[2] = byte(k>>8), byte(k)
	}
	return b
}

// pwSeq is the number pwTagged put into b.
func pwSeq(b []byte) int {
	if len(b) < 3 {
		return -1
	}
	return int(b[1])<<8 | int(b[2])
}

// pwCountSock wraps a UDPSocket: it counts reads and Closes, can block
// writes to one client until released, and can fail writes to one client
// with an error.
type pwCountSock struct {
	UDPSocket
	reads, closes atomic.Int64
	mu            sync.Mutex
	block         netip.AddrPort // writes to it block until released
	release       chan struct{}
	blocked       int
	failTo        netip.AddrPort // writes to it return failErr (when set)
	failErr       error
}

func (s *pwCountSock) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	s.reads.Add(1)
	return s.UDPSocket.ReadFromUDPAddrPort(b)
}

// failWrites makes every write to addr return err.
func (s *pwCountSock) failWrites(addr netip.AddrPort, err error) {
	s.mu.Lock()
	s.failTo, s.failErr = addr, err
	s.mu.Unlock()
}

func (s *pwCountSock) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	s.mu.Lock()
	if s.failErr != nil && addr == s.failTo {
		err := s.failErr
		s.mu.Unlock()
		return 0, err
	}
	if s.release != nil && addr == s.block {
		rel := s.release
		s.blocked++
		s.mu.Unlock()
		<-rel
		return len(b), nil // the datagram is lost, as a blocked socket's would be
	}
	s.mu.Unlock()
	return s.UDPSocket.WriteToUDPAddrPort(b, addr)
}

func (s *pwCountSock) Close() error {
	s.closes.Add(1)
	return s.UDPSocket.Close()
}

// blockWrites makes writes to addr block until the returned func is
// called.
func (s *pwCountSock) blockWrites(addr netip.AddrPort) (release func()) {
	s.mu.Lock()
	s.block, s.release = addr, make(chan struct{})
	rel := s.release
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.release = nil
		s.mu.Unlock()
		close(rel)
	}
}

func (s *pwCountSock) blockedWrites() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocked
}

// pwDialHook replaces dialIngress for the rest of the test: wrap gets
// every session it opens and the first datagram its open carried (nil when
// none rode the OPEN).
func pwDialHook(t testing.TB, wrap func(first []byte, s ingressSession) ingressSession) {
	old := dialIngress
	dialIngress = func(ctx context.Context, p *rendr.Peer, addr string, first []byte, o rendr.DialOptions) (ingressSession, error) {
		pc, err := old(ctx, p, addr, first, o)
		if err != nil {
			return nil, err
		}
		return wrap(first, pc), nil
	}
	t.Cleanup(func() { dialIngress = old })
}

// pwCloseCount wraps a flow's session and counts its Close calls.
type pwCloseCount struct {
	ingressSession
	closes atomic.Int64
}

func (s *pwCloseCount) Close() error {
	s.closes.Add(1)
	return s.ingressSession.Close()
}

// pwCountCloses wraps every session the ingress opens for the rest of the
// test (pwDialHook); check requires that each was closed exactly once
// (§A5.4) and reports how many there were.
func pwCountCloses(t testing.TB) (check func() int) {
	var mu sync.Mutex
	var all []*pwCloseCount
	pwDialHook(t, func(_ []byte, s ingressSession) ingressSession {
		c := &pwCloseCount{ingressSession: s}
		mu.Lock()
		all = append(all, c)
		mu.Unlock()
		return c
	})
	return func() int {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		for i, c := range all {
			if n := c.closes.Load(); n != 1 {
				t.Fatalf("session %d of %d closed %d times, want exactly once", i, len(all), n)
			}
		}
		return len(all)
	}
}

// pwDescribe renders a status for failure messages.
func pwDescribe(st UDPForwardStatus) string {
	return fmt.Sprintf("%+v", st)
}

// pwNoneAll requires that no further datagram reaches any of cs within
// pfWithin (one wait for all of them).
func pwNoneAll(t testing.TB, cs ...*rendrtest.DatagramConn) {
	t.Helper()
	time.Sleep(pfWithin)
	for i, c := range cs {
		if b, ok, err := pwRecvWithin(c, time.Millisecond); ok || err != nil {
			t.Fatalf("client %d read a further %d-byte datagram (%v)", i, len(b), err)
		}
	}
}
