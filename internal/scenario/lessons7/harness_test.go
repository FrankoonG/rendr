package lessons7

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of lessons7 (its own fixture, R1-23). A world is two
// Runtimes — the dialer d and the passive p with one Listener — built with
// testhooks.NewRuntime. The passive listens on a rendrtest.DatagramHub's
// socket through rendr.FromPacketConn (raw-UDP flows: rebinding, floods),
// seen through a tap that decodes every datagram it reads and writes; and
// it takes rendrtest.DatagramLink carriers through HandlePacket, each end
// of which is a tapped conn as well. Everything is created inside the
// synctest bubble that uses it and closed before the bubble ends. Only the
// public API is used; internal packages appear only as testhooks
// (Overrides) and wire (sizes and the decoding of tapped datagrams).

// worldOpts configures a world.
type worldOpts struct {
	// ov goes to both Runtimes (counter presets must be equal, L14).
	ov testhooks.Overrides
	// dcfg and pcfg are the dialer's and the passive's Config (OnEvent is
	// the world's event log).
	dcfg, pcfg rendr.Config
	// lc is the passive Listener's configuration (the hub's source is
	// added).
	lc rendr.ListenConfig
	// hubDown is the hub's one-way delay toward the dialer, hubUp toward
	// the passive.
	hubUp, hubDown time.Duration
	// noHubTap passes the hub's socket to FromPacketConn as it is (a flood
	// would fill the tap's log).
	noHubTap bool
}

// world is one scenario's two Runtimes, its hub and its links.
type world struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	hub      *rendrtest.DatagramHub
	tap      *tapPC // the passive's hub socket (nil with noHubTap)
	links    []*rendrtest.DatagramLink
	dconns   connLog // the dialer's carrier conns, in dial order
	pconns   connLog // the passive's DatagramLink conns, in accept order
	dev, pev *eventLog
}

// newWorld builds the Runtimes, the hub and the Listener on its socket. A
// cleanup shuts everything down if the test fails before close.
func newWorld(t testing.TB, o worldOpts) *world {
	t.Helper()
	w := &world{t: t, dev: &eventLog{}, pev: &eventLog{}}
	dov, pov := o.ov, o.ov
	dcfg, pcfg := o.dcfg, o.pcfg
	dcfg.OnEvent, pcfg.OnEvent = w.dev.add, w.pev.add
	w.d = newRuntime(t, dcfg, &dov)
	w.p = newRuntime(t, pcfg, &pov)
	w.hub = rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "hub", Queue: 8192})
	w.hub.SetDelay(rendrtest.Up, o.hubUp, 0)
	w.hub.SetDelay(rendrtest.Down, o.hubDown, 0)
	t.Cleanup(w.shutdown)
	var pc net.PacketConn = w.hub.PacketConn()
	if !o.noHubTap {
		w.tap = newTap(pc)
		w.tap.flowHdr = true
		pc = w.tap
	}
	lc := o.lc
	lc.Sources = append(lc.Sources, rendr.FromPacketConn(pc))
	ln, err := w.p.Listen(lc)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
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

// hubCarrier is a DatagramCarrier of the hub's dialing host n with frame
// budget 1223 (carrier/udp's default); every conn it returns is tapped and
// logged in dconns.
func (w *world) hubCarrier(name string, host int) rendr.DatagramCarrier {
	dial := w.hub.DialFrom(host)
	return rendr.DatagramCarrier{Name: name, MTU: 1223, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		tp := newTap(pc)
		w.dconns.add(tp)
		return tp, a, nil
	}}
}

// addLink adds a DatagramLink whose carriers are handed to the passive
// Listener's HandlePacket; both ends of each are tapped.
func (w *world) addLink(name string, delay time.Duration) (*rendrtest.DatagramLink, rendr.DatagramCarrier) {
	l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: name, Queue: 16384,
		Accept: func(pc net.PacketConn, peer net.Addr) error {
			tp := newTap(pc)
			w.pconns.add(tp)
			return w.ln.HandlePacket(tp, peer)
		}})
	for _, d := range bothDirs {
		l.SetDelay(d, delay, 0)
	}
	w.links = append(w.links, l)
	return l, rendr.DatagramCarrier{Name: name, MTU: 1200, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := l.Dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		tp := newTap(pc)
		w.dconns.add(tp)
		return tp, a, nil
	}}
}

// bothDirs are the two directions of a datagram path.
var bothDirs = []rendrtest.Dir{rendrtest.Up, rendrtest.Down}

// peer returns a dialer Peer over cs.
func (w *world) peer(cs ...rendr.Carrier) *rendr.Peer {
	w.t.Helper()
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// dialed is the result of a DialPacket.
type dialed struct {
	c   *rendr.PacketConn
	err error
	at  time.Time // when it returned
}

// dial starts a DialPacket over p.
func dial(p *rendr.Peer, o rendr.DialOptions) <-chan dialed {
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.DialPacket(context.Background(), o)
		ch <- dialed{c, err, time.Now()}
	}()
	return ch
}

// open dials one packet session over p and confirms it on the passive:
// its dialer and passive ends.
func (w *world) open(p *rendr.Peer, o rendr.DialOptions) (dc, pc *rendr.PacketConn) {
	w.t.Helper()
	ch := dial(p, o)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pp, err := w.ln.AcceptPacket(ctx)
	if err != nil {
		w.t.Fatalf("AcceptPacket: %v", err)
	}
	pc, err = pp.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// shutdown closes both Runtimes (the dialer first), the hub and every link
// (idempotent; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.d.Close()
	w.p.Close()
	w.hub.Close()
	for _, l := range w.links {
		l.Close()
	}
}

// close shuts the world down and requires that neither Runtime holds a
// session, a handshake, a sessionless carrier, a datagram flow or source,
// an admitting flow or a buffered byte any more and that nothing was
// abandoned (L52).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} ||
			st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || st.Datagram.Admitting != 0 {
			w.t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
}

// noViolation fails when a carrier of either Runtime ended with
// protocol_violation.
func (w *world) noViolation() {
	w.t.Helper()
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventCarrierDown) {
			if ev.Cause == rendr.CauseProtocolViolation {
				w.t.Fatalf("%s carrier %d ended with protocol_violation: %+v", [2]string{"dialer", "passive"}[i], ev.Carrier, ev)
			}
		}
	}
}

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

// waitFor polls cond every millisecond of virtual time until it holds,
// failing after within. Polling only waits for the sessions' own timers;
// the bubble makes it deterministic.
func waitFor(t testing.TB, within time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(within)
	for !cond() {
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out after %v waiting for %s", within, what)
		}
		time.Sleep(time.Millisecond)
	}
	return time.Since(start)
}

// waitDone waits until both sessions ended and requires the clean end of a
// packet session (Err io.EOF, M2-D40) on both.
func waitDone(t testing.TB, within time.Duration, cs ...*rendr.PacketConn) {
	t.Helper()
	timeout := time.After(within)
	for _, c := range cs {
		select {
		case <-c.Done():
		case <-timeout:
			t.Fatalf("a session did not end within %v: %+v", within, c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || st.Err != io.EOF {
			t.Fatalf("%v session ended %v with %v, want io.EOF", st.Role, st.State, st.Err)
		}
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

// oneLive returns the session's only live carrier and fails otherwise.
func oneLive(t testing.TB, what string, c *rendr.PacketConn) rendr.CarrierStatus {
	t.Helper()
	live := liveOf(c.Status())
	if len(live) != 1 {
		t.Fatalf("%s: %d live carriers, want 1: %+v", what, len(live), c.Status().Carriers)
	}
	return live[0]
}

// carrierOf returns the carrier with ID id.
func carrierOf(st rendr.SessionStatus, id rendr.CarrierID) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.ID == id {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// drops is the sum of a PacketCounters' send-side drop counters.
func drops(c *rendr.PacketCounters) uint64 {
	return c.DropQueue + c.DropAge + c.DropTooLarge + c.DropNoPath
}

// Packet traffic: a flow writes test datagrams on one PacketConn and reads
// them on another, recording when each seq was accepted by WriteTo and when
// it arrived, so that losses can be placed in time.

// sizeOf is the size of test datagram k: 24 … 1000 bytes.
func sizeOf(k int) int { return rendrtest.PacketHeaderLen + k*37%977 }

// flow is one direction of packet traffic: one datagram every pace.
type flow struct {
	seed uint64
	pace time.Duration
	w    *rendr.PacketConn
	v    *rendrtest.PacketVerifier

	stop         chan struct{}
	wdone, rdone chan struct{}
	accepted     atomic.Int64 // WriteTo calls that returned (len, nil)
	read         atomic.Int64 // datagrams ReadFrom returned
	werr, rerr   error

	mu      sync.Mutex
	wrote   []time.Time // by seq: when WriteTo accepted it
	arrived []time.Time // by seq: when ReadFrom first returned it (zero: never)
	bad     error       // the first verification failure
}

// startFlow writes on wc and reads on rc, each on its own goroutine.
func startFlow(wc, rc *rendr.PacketConn, seed uint64, pace time.Duration) *flow {
	f := &flow{seed: seed, pace: pace, w: wc, v: rendrtest.NewPacketVerifier(seed), stop: make(chan struct{}),
		wdone: make(chan struct{}), rdone: make(chan struct{})}
	go f.writer()
	go f.reader(rc)
	return f
}

func (f *flow) writer() {
	defer close(f.wdone)
	buf := make([]byte, wire.MaxDatagram)
	for k := 0; ; k++ {
		at := time.Now()
		size := sizeOf(k)
		m, err := f.w.WriteTo(rendrtest.PacketPayload(buf, f.seed, uint64(k), size, at), nil)
		if err != nil {
			f.werr = fmt.Errorf("WriteTo of seq %d: %w", k, err)
			return
		}
		if m != size {
			f.werr = fmt.Errorf("WriteTo returned %d for a %d-byte datagram", m, size)
			return
		}
		f.mu.Lock()
		f.wrote = append(f.wrote, at)
		f.mu.Unlock()
		f.accepted.Add(1)
		select {
		case <-f.stop:
			return
		case <-time.After(f.pace):
		}
	}
}

func (f *flow) reader(rc *rendr.PacketConn) {
	defer close(f.rdone)
	buf := make([]byte, wire.MaxDatagram+1)
	for {
		n, _, err := rc.ReadFrom(buf)
		if err != nil {
			f.rerr = err
			return
		}
		now := time.Now()
		verr := f.v.Add(buf[:n], now)
		f.mu.Lock()
		if verr != nil && f.bad == nil {
			f.bad = verr
		}
		if verr == nil {
			seq := int(binary.BigEndian.Uint64(buf[:8]))
			if seq >= len(f.arrived) {
				f.arrived = append(f.arrived, make([]time.Time, seq+1-len(f.arrived))...)
			}
			if f.arrived[seq].IsZero() {
				f.arrived[seq] = now
			}
		}
		f.mu.Unlock()
		f.read.Add(1)
	}
}

// halt stops the writer and waits for it; a WriteTo error fails the test.
func (f *flow) halt(t testing.TB, what string) {
	t.Helper()
	select {
	case <-f.stop:
	default:
		close(f.stop)
	}
	select {
	case <-f.wdone:
	case <-time.After(time.Minute):
		t.Fatalf("%s: the writer did not stop", what)
	}
	if f.werr != nil {
		t.Fatalf("%s: %v", what, f.werr)
	}
}

// waitReader waits until the reader ended with want (io.EOF: the peer's
// clean end; net.ErrClosed: this side's Close) and checks what it got.
func (f *flow) waitReader(t testing.TB, within time.Duration, want error, what string) rendrtest.PacketResult {
	t.Helper()
	select {
	case <-f.rdone:
	case <-time.After(within):
		t.Fatalf("%s: the reader did not end within %v (%d datagrams read)", what, within, f.read.Load())
	}
	if !errors.Is(f.rerr, want) {
		t.Fatalf("%s: the reader ended with %v, want %v", what, f.rerr, want)
	}
	return f.check(t, what)
}

// check requires that every datagram returned so far was intact and was
// returned at most once.
func (f *flow) check(t testing.TB, what string) rendrtest.PacketResult {
	t.Helper()
	res := f.v.Result()
	f.mu.Lock()
	bad := f.bad
	f.mu.Unlock()
	if bad != nil || res.Corrupt+res.BadSize != 0 {
		t.Fatalf("%s: a damaged datagram (%v): %+v", what, bad, res)
	}
	if res.Duplicates != 0 {
		t.Fatalf("%s: %d datagrams returned twice: %+v", what, res.Duplicates, res)
	}
	return res
}

// lostIn returns the accepted datagrams that never arrived, split by
// whether WriteTo accepted them inside one of the closed intervals ws.
func (f *flow) lostIn(ws ...[2]time.Time) (inside, outside []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, at := range f.wrote {
		if k < len(f.arrived) && !f.arrived[k].IsZero() {
			continue
		}
		in := false
		for _, w := range ws {
			in = in || !at.Before(w[0]) && !at.After(w[1])
		}
		if in {
			inside = append(inside, k)
		} else {
			outside = append(outside, k)
		}
	}
	return inside, outside
}

// arrivedIn counts the arrivals inside [from, to).
func (f *flow) arrivedIn(from, to time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.arrived {
		if !a.IsZero() && !a.Before(from) && a.Before(to) {
			n++
		}
	}
	return n
}

// writtenIn counts the accepted datagrams written inside [from, to).
func (f *flow) writtenIn(from, to time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, at := range f.wrote {
		if !at.Before(from) && at.Before(to) {
			n++
		}
	}
	return n
}

// endPair ends a session whose flows were halted: the dialer closes, the
// passive's reader gets io.EOF after every datagram, the passive closes,
// the dialer's reader gets net.ErrClosed, both sessions end cleanly.
func endPair(t testing.TB, dc, pc *rendr.PacketConn, up, down *flow) {
	t.Helper()
	dc.Close()
	if up != nil {
		up.waitReader(t, 10*time.Second, io.EOF, "dialer → passive")
	}
	pc.Close()
	if down != nil {
		down.waitReader(t, 10*time.Second, net.ErrClosed, "passive → dialer")
	}
	waitDone(t, 10*time.Second, dc, pc)
}

// burst writes n test datagrams of seed on c, one every 2 ms, and reads
// them on r: every one must arrive intact within a second of the last.
func burst(t testing.TB, c, r *rendr.PacketConn, seed uint64, n int, what string) {
	t.Helper()
	go func() {
		buf := make([]byte, wire.MaxDatagram)
		for k := range n {
			if _, err := c.WriteTo(rendrtest.PacketPayload(buf, seed, uint64(k), sizeOf(k), time.Now()), nil); err != nil {
				return // the read below times out and reports it
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	v := rendrtest.NewPacketVerifier(seed)
	rb := make([]byte, wire.MaxDatagram+1)
	_ = r.SetReadDeadline(time.Now().Add(time.Second + time.Duration(n)*2*time.Millisecond))
	defer r.SetReadDeadline(time.Time{})
	for v.Result().Unique < uint64(n) {
		m, _, err := r.ReadFrom(rb)
		if err != nil {
			t.Fatalf("%s: ReadFrom after %d of %d: %v (sender %+v)", what, v.Result().Unique, n, err, c.Status().Packet)
		}
		if err := v.Add(rb[:m], time.Now()); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	if res := v.Result(); res.Duplicates+res.Corrupt+res.BadSize != 0 || len(res.Missing) != 0 {
		t.Fatalf("%s: %+v", what, res)
	}
}

// The tap: a net.PacketConn wrapper that decodes every datagram it reads
// and writes (rendr's raw-UDP flow header first when it carries one). It
// changes nothing about the conn.

// tapFrame is one decoded frame: its type, its fseq and, inside a REL, the
// inner type and payload; PING and PONG keep their id.
type tapFrame struct {
	typ   wire.Type
	fseq  uint32
	inner wire.Type // a REL's inner frame type
	body  []byte    // a REL's inner payload (copied)
	id    uint32    // PING and PONG id
	nonce uint64    // PING and PONG nonce
}

// tapDgram is one datagram through the tap.
type tapDgram struct {
	at      time.Time
	addr    netip.AddrPort // the destination of a write, the source of a read
	flow    uint64         // its flow ID (0 without a flow header)
	preface bool           // it starts with a PREFACE or PREFACE_ACK
	frames  []tapFrame
}

// types lists the frame types (a REL's inner type in its place).
func (d tapDgram) types() []wire.Type {
	out := make([]wire.Type, 0, len(d.frames))
	for _, f := range d.frames {
		if f.typ == wire.TypeRel {
			out = append(out, f.inner)
		} else {
			out = append(out, f.typ)
		}
	}
	return out
}

// tapPC is the tap.
type tapPC struct {
	net.PacketConn
	flowHdr bool // datagrams carry a flow header (the hub's passive socket)

	mu     sync.Mutex
	reads  []tapDgram
	writes []tapDgram
	top    map[uint64]uint32 // per flow: the newest frame fseq read
}

func newTap(pc net.PacketConn) *tapPC {
	return &tapPC{PacketConn: pc, top: make(map[uint64]uint32)}
}

func (p *tapPC) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := p.PacketConn.ReadFrom(b)
	if err == nil && n <= len(b) {
		d := p.decode(b[:n], a)
		p.mu.Lock()
		p.reads = append(p.reads, d)
		for _, f := range d.frames {
			if t, ok := p.top[d.flow]; !ok || int32(f.fseq-t) > 0 {
				p.top[d.flow] = f.fseq
			}
		}
		p.mu.Unlock()
	}
	return n, a, err
}

func (p *tapPC) WriteTo(b []byte, a net.Addr) (int, error) {
	d := p.decode(b, a)
	n, err := p.PacketConn.WriteTo(b, a)
	if err == nil {
		p.mu.Lock()
		p.writes = append(p.writes, d)
		p.mu.Unlock()
	}
	return n, err
}

// decode decodes datagram b to or from a; what does not decode ends the
// frame list.
func (p *tapPC) decode(b []byte, a net.Addr) tapDgram {
	d := tapDgram{at: time.Now()}
	if ua, ok := a.(*net.UDPAddr); ok {
		d.addr = ua.AddrPort()
	}
	if p.flowHdr {
		flow, rest, err := wire.ParseFlowHeader(b)
		if err != nil {
			return d
		}
		d.flow, b = flow, rest
	}
	if wire.IsPreface(b) {
		d.preface, b = true, b[wire.PrefaceLen:]
	}
	for len(b) > 0 {
		f, n, err := wire.DecodeFrame(b)
		if err != nil {
			break
		}
		tf := tapFrame{typ: f.Type, fseq: f.Fseq}
		switch f.Type {
		case wire.TypeRel:
			if h, inner, err := wire.ParseRel(f.Payload); err == nil {
				tf.inner, tf.body = h.Type, append([]byte(nil), inner...)
			}
		case wire.TypePing, wire.TypePong:
			if pg, err := wire.ParsePing(f.Payload); err == nil {
				tf.id, tf.nonce = pg.ID, pg.Nonce
			}
		}
		d.frames = append(d.frames, tf)
		b = b[n:]
	}
	return d
}

// snapshot returns copies of the datagrams read and written so far.
func (p *tapPC) snapshot() (reads, writes []tapDgram) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]tapDgram(nil), p.reads...), append([]tapDgram(nil), p.writes...)
}

// writesSince returns the datagrams written at or after from.
func (p *tapPC) writesSince(from time.Time) []tapDgram {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []tapDgram
	for _, d := range p.writes {
		if !d.at.Before(from) {
			out = append(out, d)
		}
	}
	return out
}

// topOf returns the newest frame fseq read on flow and whether one was.
func (p *tapPC) topOf(flow uint64) (uint32, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.top[flow]
	return t, ok
}

// lastReadFrom returns the last datagram read from addr.
func (p *tapPC) lastReadFrom(addr netip.AddrPort) (tapDgram, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.reads) - 1; i >= 0; i-- {
		if p.reads[i].addr == addr {
			return p.reads[i], true
		}
	}
	return tapDgram{}, false
}

// connLog records tapped conns in creation order.
type connLog struct {
	mu  sync.Mutex
	pcs []*tapPC
}

func (l *connLog) add(p *tapPC) {
	l.mu.Lock()
	l.pcs = append(l.pcs, p)
	l.mu.Unlock()
}

// all returns the recorded conns.
func (l *connLog) all() []*tapPC {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*tapPC(nil), l.pcs...)
}

// last returns the newest recorded conn (nil: none).
func (l *connLog) last() *tapPC {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pcs) == 0 {
		return nil
	}
	return l.pcs[len(l.pcs)-1]
}
