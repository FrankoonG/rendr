package packet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of package packet (its own fixture, R1-23). A world is two
// Runtimes — the dialer d and the passive p with one push-only Listener —
// built with testhooks.NewRuntime and joined by rendrtest.DatagramLinks
// whose Accept is the Listener's HandlePacket, so every carrier goes
// through the whole datagram handshake and admission. An acceptor takes
// every PendingPacket the Listener offers and counts it (one session must
// mean one PendingPacket: the M2 analogue of msess's "one exit socket",
// O-45). The dialer's datagram factories record every session carrier's
// conn by its CarrierID (rendr.CarrierDialInfo), so that a test can close
// one under rendr: the gold cases' local close (F10, M2-D74). Everything is
// created inside the synctest bubble that uses it and closed before the
// bubble ends. Only the public API is used; internal packages appear only
// as testhooks (Overrides).

// worldOpts configures a world.
type worldOpts struct {
	// ov goes to both Runtimes (counter presets must be equal, L14).
	ov testhooks.Overrides
	// oneWay is every link's one-way delay in both directions.
	oneWay time.Duration
	// mtu is every datagram factory's frame budget (0: 1223, carrier/udp's
	// default MaxDatagram 1232 less its 9-byte flow header, so MaxPayload
	// is 1198 as on the pool).
	mtu int
}

// world is one scenario's two Runtimes and links.
type world struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	links    []*rendrtest.DatagramLink
	dev, pev *eventLog
	mtu      int

	acceptCh   chan *rendr.PendingPacket
	stopAccept context.CancelFunc
	acceptDone chan struct{}
	shutOnce   sync.Once

	mu      sync.Mutex
	conns   map[rendr.CarrierID]net.PacketConn // the dialer's session carrier conns
	pending int                                // PendingPackets the Listener offered
}

// newWorld builds the Runtimes, the Listener, its acceptor and one
// DatagramLink per name. A cleanup shuts everything down if the test fails
// before close.
func newWorld(t testing.TB, o worldOpts, names ...string) *world {
	t.Helper()
	w := &world{t: t, dev: &eventLog{}, pev: &eventLog{}, mtu: o.mtu, conns: map[rendr.CarrierID]net.PacketConn{},
		acceptCh: make(chan *rendr.PendingPacket, 1), acceptDone: make(chan struct{})}
	if w.mtu == 0 {
		w.mtu = 1223
	}
	dov, pov := o.ov, o.ov
	w.d = newRuntime(t, rendr.Config{OnEvent: w.dev.add}, &dov)
	w.p = newRuntime(t, rendr.Config{OnEvent: w.pev.add}, &pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	ctx, cancel := context.WithCancel(context.Background())
	w.stopAccept = cancel
	go w.acceptor(ctx)
	for _, n := range names {
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: n, Accept: w.ln.HandlePacket, Queue: 16384})
		for _, d := range bothDirs {
			l.SetDelay(d, o.oneWay, 0)
		}
		w.links = append(w.links, l)
	}
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

// acceptor takes every PendingPacket: the first waiting one goes to open,
// any other is counted and rejected.
func (w *world) acceptor(ctx context.Context) {
	defer close(w.acceptDone)
	for {
		pp, err := w.ln.AcceptPacket(ctx)
		if err != nil {
			return
		}
		w.mu.Lock()
		w.pending++
		w.mu.Unlock()
		select {
		case w.acceptCh <- pp:
		default:
			pp.Reject(0, "unexpected")
		}
	}
}

// pendings returns how many PendingPackets the Listener offered.
func (w *world) pendings() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pending
}

// bothDirs are the two directions of a datagram link (Up: dialer →
// passive, A → B; Down: passive → dialer, B → A).
var bothDirs = []rendrtest.Dir{rendrtest.Up, rendrtest.Down}

// link returns the link named name.
func (w *world) link(name string) *rendrtest.DatagramLink {
	for _, l := range w.links {
		if l.Name() == name {
			return l
		}
	}
	w.t.Fatalf("no link %q", name)
	return nil
}

// carrier is the DatagramCarrier of l; its Dial records the conn of every
// session carrier (not of probe carriers) by CarrierID.
func (w *world) carrier(l *rendrtest.DatagramLink) rendr.DatagramCarrier {
	return rendr.DatagramCarrier{Name: l.Name(), MTU: w.mtu, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := l.Dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			w.mu.Lock()
			w.conns[di.Carrier] = pc
			w.mu.Unlock()
		}
		return pc, a, err
	}}
}

// localClose closes the dialer's conn of carrier id under rendr: the gold
// cases' carrier.close (F10; M2-D74, PA-23). It fails the test unless the
// carrier was registered and its Close returned nil.
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

// peer returns a dialer Peer over the links named, in that order.
func (w *world) peer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, n := range names {
		cs = append(cs, w.carrier(w.link(n)))
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// open dials one packet session over p and confirms it on the passive: its
// dialer and passive ends.
func (w *world) open(p *rendr.Peer, o rendr.DialOptions) (dc, pc *rendr.PacketConn) {
	w.t.Helper()
	type dialed struct {
		c   *rendr.PacketConn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.DialPacket(context.Background(), o)
		ch <- dialed{c, err}
	}()
	var pp *rendr.PendingPacket
	select {
	case pp = <-w.acceptCh:
	case <-time.After(30 * time.Second):
		w.t.Fatal("no PendingPacket within 30 s")
	}
	pc, err := pp.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// shutdown stops the acceptor and closes both Runtimes (the dialer first)
// and every link (once; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.shutOnce.Do(func() {
		w.stopAccept()
		<-w.acceptDone
		w.d.Close()
		w.p.Close()
		for _, l := range w.links {
			l.Close()
		}
	})
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
		if sessionsOf(rt) != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 ||
			st.AcceptBacklog != [2]int{} || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || st.Datagram.Admitting != 0 {
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
				w.t.Fatalf("%s carrier %d ended with protocol_violation: %+v", side(i), ev.Carrier, ev)
			}
		}
	}
}

// sessionLost is the number of session-carrier datagrams every link lost
// (both directions, rendr's control datagrams included).
func (w *world) sessionLost() uint64 {
	var n uint64
	for _, l := range w.links {
		n += l.Stats().Session.Lost
	}
	return n
}

// side names end i: 0 the dialer (A), 1 the passive (B).
func side(i int) string { return [2]string{"dialer", "passive"}[i] }

// sessionsOf is the number of live sessions of rt.
func sessionsOf(rt *rendr.Runtime) int {
	sc := rt.Status().Sessions
	return sc.Open + sc.Pending + sc.Lingering + sc.Orphaned
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

// downOf returns the EventCarrierDown of carrier id, if any.
func (l *eventLog) downOf(id rendr.CarrierID) (rendr.Event, bool) {
	for _, ev := range l.of(rendr.EventCarrierDown) {
		if ev.Carrier == id {
			return ev, true
		}
	}
	return rendr.Event{}, false
}

// migrations returns the EventMigrations in [from, to) for which keep
// holds.
func (l *eventLog) migrations(from, to time.Time, keep func(rendr.Event) bool) []rendr.Event {
	var out []rendr.Event
	for _, ev := range l.of(rendr.EventMigration) {
		if !ev.Time.Before(from) && ev.Time.Before(to) && keep(ev) {
			out = append(out, ev)
		}
	}
	return out
}

// isQuality keeps quality migrations.
func isQuality(ev rendr.Event) bool { return ev.Cause == rendr.CauseQuality }

// waitFor polls cond every millisecond of virtual time until it holds,
// failing after within. Polling only waits for the sessions' own timers;
// the bubble makes it deterministic.
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

// Status helpers.

// activeOf returns the carrier the session reports active.
func activeOf(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
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

// liveNamed returns the live carrier of factory name (dialer side).
func liveNamed(st rendr.SessionStatus, name string) (rendr.CarrierStatus, bool) {
	for _, c := range liveOf(st) {
		if c.Name == name {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// drops is the sum of a PacketCounters' send-side drop counters.
func drops(c *rendr.PacketCounters) uint64 {
	return c.DropQueue + c.DropAge + c.DropTooLarge + c.DropNoPath
}

// Packet traffic. A flow writes test datagrams (rendrtest.PacketPayload) on
// one PacketConn at a fixed rate in 10-ms send slots (F8) and reads them on
// another, recording when WriteTo accepted each seq and when it first
// arrived, so that losses and arrival gaps can be placed in time. The
// reader reads into a buffer of MaxPayload + 1 bytes: io.ErrShortBuffer
// there means rendr delivered more than its own limit (B1.0), and every
// ReadFrom must report the session's RemoteAddr (L38).

// sendSlot is the generator's send slot (F8).
const sendSlot = 10 * time.Millisecond

// flowCfg configures a flow.
type flowCfg struct {
	name string // "A → B" or "B → A"
	seed uint64
	rate int // datagrams per second
	size int // bytes per datagram (0: 1000, F4)
}

// flow is one direction of packet traffic.
type flow struct {
	cfg   flowCfg
	w, r  *rendr.PacketConn
	v     *rendrtest.PacketVerifier
	start time.Time

	stop         chan struct{}
	wdone, rdone chan struct{}
	accepted     atomic.Int64 // WriteTo calls that returned (len, nil)
	read         atomic.Int64 // datagrams ReadFrom returned
	werr, rerr   error
	maxCall      time.Duration // the longest WriteTo call (NonBlockingWrite)

	mu      sync.Mutex
	wrote   []time.Time // by seq: when WriteTo accepted it
	arrived []time.Time // by seq: when ReadFrom first returned it (zero: never)
	order   []time.Time // first arrivals, in arrival order
	bad     error       // the first integrity failure
}

// startFlow writes on wc and reads on rc, each on its own goroutine.
func startFlow(wc, rc *rendr.PacketConn, cfg flowCfg) *flow {
	if cfg.size == 0 {
		cfg.size = 1000
	}
	f := &flow{cfg: cfg, w: wc, r: rc, v: rendrtest.NewPacketVerifier(cfg.seed), start: time.Now(),
		stop: make(chan struct{}), wdone: make(chan struct{}), rdone: make(chan struct{})}
	go f.writer()
	go f.reader()
	return f
}

func (f *flow) writer() {
	defer close(f.wdone)
	buf := make([]byte, f.cfg.size)
	seq := 0
	for k := 1; ; k++ {
		due := int(time.Since(f.start) * time.Duration(f.cfg.rate) / time.Second)
		for ; seq < due; seq++ {
			at := time.Now()
			m, err := f.w.WriteTo(rendrtest.PacketPayload(buf, f.cfg.seed, uint64(seq), f.cfg.size, at), nil)
			f.maxCall = max(f.maxCall, time.Since(at))
			if err != nil {
				f.werr = fmt.Errorf("%s: WriteTo of seq %d: %w", f.cfg.name, seq, err)
				return
			}
			if m != f.cfg.size {
				f.werr = fmt.Errorf("%s: WriteTo returned %d for a %d-byte datagram", f.cfg.name, m, f.cfg.size)
				return
			}
			f.mu.Lock()
			f.wrote = append(f.wrote, at)
			f.mu.Unlock()
			f.accepted.Add(1)
		}
		select {
		case <-f.stop:
			return
		case <-time.After(time.Until(f.start.Add(time.Duration(k) * sendSlot))):
		}
	}
}

func (f *flow) reader() {
	defer close(f.rdone)
	buf := make([]byte, f.r.MaxPayload()+1)
	want := f.r.RemoteAddr()
	for {
		n, addr, err := f.r.ReadFrom(buf)
		now := time.Now()
		if errors.Is(err, io.ErrShortBuffer) {
			f.fail(fmt.Errorf("%s: ReadFrom into MaxPayload + 1 = %d bytes returned io.ErrShortBuffer", f.cfg.name, len(buf)))
			continue
		}
		if err != nil {
			f.rerr = err
			return
		}
		if addr != want {
			f.fail(fmt.Errorf("%s: ReadFrom reported %v, RemoteAddr is %v (L38)", f.cfg.name, addr, want))
		}
		if verr := f.v.Add(buf[:n], now); verr != nil {
			f.fail(fmt.Errorf("%s: %w", f.cfg.name, verr))
		} else {
			seq := int(seqOf(buf))
			f.mu.Lock()
			if seq >= len(f.arrived) {
				f.arrived = append(f.arrived, make([]time.Time, seq+1-len(f.arrived))...)
			}
			if f.arrived[seq].IsZero() {
				f.arrived[seq] = now
				f.order = append(f.order, now)
			}
			f.mu.Unlock()
		}
		f.read.Add(1)
	}
}

// seqOf is the seq of a test datagram.
func seqOf(b []byte) uint64 {
	var s uint64
	for _, c := range b[:8] {
		s = s<<8 | uint64(c)
	}
	return s
}

// fail records the first integrity failure.
func (f *flow) fail(err error) {
	f.mu.Lock()
	if f.bad == nil {
		f.bad = err
	}
	f.mu.Unlock()
}

// halt stops the writer and waits for it; a WriteTo error fails the test.
func (f *flow) halt(t testing.TB) {
	t.Helper()
	select {
	case <-f.stop:
	default:
		close(f.stop)
	}
	select {
	case <-f.wdone:
	case <-time.After(time.Minute):
		t.Fatalf("%s: the writer did not stop (%d accepted)", f.cfg.name, f.accepted.Load())
	}
	if f.werr != nil {
		t.Fatal(f.werr)
	}
}

// waitReader waits until the reader ended with want (io.EOF: the peer's
// clean end; net.ErrClosed: this side's Close).
func (f *flow) waitReader(t testing.TB, within time.Duration, want error) {
	t.Helper()
	select {
	case <-f.rdone:
	case <-time.After(within):
		t.Fatalf("%s: the reader did not end within %v (%d datagrams read)", f.cfg.name, within, f.read.Load())
	}
	if !errors.Is(f.rerr, want) {
		t.Fatalf("%s: the reader ended with %v, want %v", f.cfg.name, f.rerr, want)
	}
}

// integrity requires PacketIntegrity (B1.0; L36, L38, L39): every datagram
// returned intact, with its exact size and the session's address, at most
// once, never more than MaxPayload.
func (f *flow) integrity(t testing.TB) rendrtest.PacketResult {
	t.Helper()
	res := f.v.Result()
	f.mu.Lock()
	bad := f.bad
	f.mu.Unlock()
	if bad != nil || res.Corrupt+res.BadSize+res.Duplicates != 0 {
		t.Fatalf("%s: integrity (%v): %+v", f.cfg.name, bad, res)
	}
	return res
}

// nonBlocking requires that no WriteTo call took 100 ms or more (B1.0
// NonBlockingWrite, L40).
func (f *flow) nonBlocking(t testing.TB) {
	t.Helper()
	if f.maxCall >= 100*time.Millisecond {
		t.Fatalf("%s: a WriteTo call took %v, want < 100 ms", f.cfg.name, f.maxCall)
	}
}

// loss is one accepted datagram that never arrived.
type loss struct {
	seq   int
	wrote time.Time
}

// losses returns every accepted datagram that has not arrived, in seq
// order.
func (f *flow) losses() []loss {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []loss
	for k, at := range f.wrote {
		if k >= len(f.arrived) || f.arrived[k].IsZero() {
			out = append(out, loss{k, at})
		}
	}
	return out
}

// ratio is the share of accepted datagrams that arrived (DeliveryRatio).
func (f *flow) ratio() float64 {
	n := f.accepted.Load()
	if n == 0 {
		return 0
	}
	return float64(n-int64(len(f.losses()))) / float64(n)
}

// firstArrivalWrittenFrom returns the earliest arrival of a datagram
// written at or after at (zero: none arrived).
func (f *flow) firstArrivalWrittenFrom(at time.Time) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	var first time.Time
	for k, w := range f.wrote {
		if w.Before(at) || k >= len(f.arrived) || f.arrived[k].IsZero() {
			continue
		}
		if a := f.arrived[k]; first.IsZero() || a.Before(first) {
			first = a
		}
	}
	return first
}

// gapFrom returns the longest arrival gap that starts in [from, to] or
// spans from (F9: exact gaps between consecutive arrivals; the last
// arrival's gap runs to end), and where it starts.
func (f *flow) gapFrom(from, to, end time.Time) (gap time.Duration, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, a := range f.order {
		next := end
		if i+1 < len(f.order) {
			next = f.order[i+1]
		}
		if a.After(to) || !next.After(from) {
			continue
		}
		if g := next.Sub(a); g > gap {
			gap, at = g, a
		}
	}
	return gap, at
}

// maxGap returns the longest interval in [from, to] without an arrival
// (the ends count as arrivals).
func (f *flow) maxGap(from, to time.Time) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	gap, last := time.Duration(0), from
	for _, a := range f.order {
		if a.Before(from) || a.After(to) {
			continue
		}
		gap = max(gap, a.Sub(last))
		last = a
	}
	return max(gap, to.Sub(last))
}

// delays returns the one-way delays of the datagrams written in [from, to)
// that arrived, sorted.
func (f *flow) delays(from, to time.Time) []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []time.Duration
	for k, w := range f.wrote {
		if w.Before(from) || !w.Before(to) || k >= len(f.arrived) || f.arrived[k].IsZero() {
			continue
		}
		out = append(out, f.arrived[k].Sub(w))
	}
	slices.Sort(out)
	return out
}

// endClean ends a session as F21: both generators stop; 1 s later, once
// every accepted datagram was sent or counted as a send-side drop and every
// datagram received was read, A (the dialer) closes; B reads until io.EOF,
// which must come after every datagram B accepted, then closes; both
// sessions end within Linger with io.EOF. up is A → B, down B → A.
func endClean(t testing.TB, dc, pc *rendr.PacketConn, up, down *flow) {
	t.Helper()
	for _, f := range []*flow{up, down} {
		select {
		case <-f.rdone:
			t.Fatalf("%s: the reader ended with %v before the clean end", f.cfg.name, f.rerr)
		default:
		}
	}
	up.halt(t)
	down.halt(t)
	time.Sleep(time.Second)
	waitFor(t, 10*time.Second, "the accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.Sent+drops(ds) == uint64(up.accepted.Load()) && ps.Sent+drops(ps) == uint64(down.accepted.Load()) &&
			ps.Received == uint64(up.read.Load()) && ds.Received == uint64(down.read.Load())
	})
	dc.Close()
	up.waitReader(t, 10*time.Second, io.EOF)
	if ps := pc.Status().Packet; ps.Received != uint64(up.read.Load()) || ps.DropRecvQueue+ps.DropLate != 0 {
		t.Fatalf("B read %d datagrams before io.EOF, accepted %+v", up.read.Load(), *ps)
	}
	pc.Close()
	down.waitReader(t, 10*time.Second, net.ErrClosed)
	timeout := time.After(30 * time.Second) // Linger
	for _, c := range []*rendr.PacketConn{dc, pc} {
		select {
		case <-c.Done():
		case <-timeout:
			t.Fatalf("a session did not end within Linger: %+v", c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || st.Err != io.EOF {
			t.Fatalf("%v session ended %v with %v, want io.EOF", st.Role, st.State, st.Err)
		}
	}
}

// attribution requires that every loss on the wire was counted somewhere
// (B1.0: "no counter moved" is FAIL): the datagrams sent and not received,
// both directions, are at most what the links lost on session carriers;
// and nothing was dropped on the receive side or as a duplicate.
func attribution(t testing.TB, w *world, dc, pc *rendr.PacketConn) {
	t.Helper()
	ds, ps := dc.Status().Packet, pc.Status().Packet
	for i, c := range []*rendr.PacketCounters{ds, ps} {
		if c.Duplicates+c.DropRecvQueue+c.DropLate != 0 {
			t.Fatalf("%s: receive-side drops %+v", side(i), *c)
		}
	}
	wire := (ds.Sent - ps.Received) + (ps.Sent - ds.Received)
	if lost := w.sessionLost(); wire > lost {
		t.Fatalf("%d datagrams were sent and not received, but the links lost only %d session datagrams (A %+v, B %+v)",
			wire, lost, *ds, *ps)
	}
}
