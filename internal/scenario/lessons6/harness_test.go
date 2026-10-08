package lessons6

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of lessons6 (its own fixture, R1-23). A world is two
// Runtimes — the dialer d and the passive p with one push-only Listener —
// built with testhooks.NewRuntime and joined by rendrtest.DatagramLinks
// whose Accept is the Listener's HandlePacket (and rendrtest.Links whose
// Accept is its Handle), so every carrier goes through the whole
// handshake and admission. Everything is created inside the synctest
// bubble that uses it and closed before the bubble ends. Only the public
// API is used; internal packages appear only as testhooks (Overrides) and
// wire (sizes).

// worldOpts configures a world.
type worldOpts struct {
	// ov goes to both Runtimes (counter presets must be equal, L14).
	ov testhooks.Overrides
	// dcfg and pcfg are the dialer's and the passive's Config (OnEvent is
	// the world's event log).
	dcfg, pcfg rendr.Config
}

// world is one scenario's two Runtimes and links.
type world struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	links    []*rendrtest.DatagramLink
	slinks   []*rendrtest.Link
	dev, pev *eventLog
}

// newWorld builds the Runtimes, the Listener and one DatagramLink per name.
// A cleanup shuts everything down if the test fails before close.
func newWorld(t testing.TB, o worldOpts, names ...string) *world {
	t.Helper()
	w := &world{t: t, dev: &eventLog{}, pev: &eventLog{}}
	dov, pov := o.ov, o.ov
	dcfg, pcfg := o.dcfg, o.pcfg
	dcfg.OnEvent, pcfg.OnEvent = w.dev.add, w.pev.add
	w.d = newRuntime(t, dcfg, &dov)
	w.p = newRuntime(t, pcfg, &pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for _, n := range names {
		w.addLink(n)
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

// addLink adds a DatagramLink whose carriers are handed to the passive
// Listener. Its queue holds 16,384 datagrams per direction: no scenario
// here comes near it.
func (w *world) addLink(name string) *rendrtest.DatagramLink {
	l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: name, Accept: w.ln.HandlePacket, Queue: 16384})
	w.links = append(w.links, l)
	return l
}

// addStreamLink adds a stream Link whose carriers are handed to the passive
// Listener's Handle.
func (w *world) addStreamLink(name string, buffer int) *rendrtest.Link {
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: w.ln.Handle, Buffer: buffer})
	w.slinks = append(w.slinks, l)
	return l
}

// bothDirs are the two directions of a datagram link.
var bothDirs = []rendrtest.Dir{rendrtest.Up, rendrtest.Down}

// dgCarrier is the DatagramCarrier of l with frame budget mtu.
func dgCarrier(l *rendrtest.DatagramLink, mtu int) rendr.DatagramCarrier {
	return rendr.DatagramCarrier{Name: l.Name(), MTU: mtu, Dial: l.Dial}
}

// stCarrier is the StreamCarrier of l.
func stCarrier(l *rendrtest.Link) rendr.StreamCarrier {
	return rendr.StreamCarrier{Name: l.Name(), Dial: l.Dial}
}

// peer returns a dialer Peer over cs (configuration order breaks ranking
// ties).
func (w *world) peer(cs ...rendr.Carrier) *rendr.Peer {
	w.t.Helper()
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

// shutdown closes both Runtimes (the dialer first) and every link
// (idempotent; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.d.Close()
	w.p.Close()
	for _, l := range w.links {
		l.Close()
	}
	for _, l := range w.slinks {
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

// downOf returns the EventCarrierDown of carrier id, if any.
func (l *eventLog) downOf(id rendr.CarrierID) (rendr.Event, bool) {
	for _, ev := range l.of(rendr.EventCarrierDown) {
		if ev.Carrier == id {
			return ev, true
		}
	}
	return rendr.Event{}, false
}

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

// deadOf returns the dead carriers the session reports.
func deadOf(st rendr.SessionStatus) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierDead {
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

// isTimeout reports whether err is a deadline error as net.Conn has it.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
}

// Packet traffic: a flow writes test datagrams on one PacketConn and reads
// them on another, recording when each seq was accepted by WriteTo and when
// it arrived, so that losses can be placed in time.

// sizeOf is the size of test datagram k: 24 … 1000 bytes.
func sizeOf(k int) int { return rendrtest.PacketHeaderLen + k*37%977 }

// flowCfg configures a flow.
type flowCfg struct {
	seed  uint64
	n     int           // datagrams to write (0: until stop)
	burst int           // datagrams per tick (0: 1)
	pace  time.Duration // between ticks
	size  func(k int) int
}

// flow is one direction of packet traffic.
type flow struct {
	cfg flowCfg
	w   *rendr.PacketConn
	v   *rendrtest.PacketVerifier

	stop         chan struct{}
	wdone, rdone chan struct{}
	accepted     atomic.Int64 // WriteTo calls that returned (len, nil)
	extra        atomic.Int64 // datagrams the test wrote on the same conn outside the flow
	read         atomic.Int64 // datagrams ReadFrom returned
	werr, rerr   error
	maxCall      time.Duration
	rend         time.Time

	mu      sync.Mutex
	wrote   []time.Time // by seq: when WriteTo accepted it
	arrived []time.Time // by seq: when ReadFrom first returned it (zero: never)
	bad     error       // the first verification failure
}

// startFlow writes on wc and reads on rc, each on its own goroutine.
func startFlow(wc, rc *rendr.PacketConn, cfg flowCfg) *flow {
	if cfg.size == nil {
		cfg.size = sizeOf
	}
	cfg.burst = max(cfg.burst, 1)
	f := &flow{cfg: cfg, w: wc, v: rendrtest.NewPacketVerifier(cfg.seed), stop: make(chan struct{}),
		wdone: make(chan struct{}), rdone: make(chan struct{})}
	go f.writer()
	go f.reader(rc)
	return f
}

func (f *flow) writer() {
	defer close(f.wdone)
	buf := make([]byte, wire.MaxDatagram)
	for k := 0; f.cfg.n == 0 || k < f.cfg.n; {
		for i := 0; i < f.cfg.burst && (f.cfg.n == 0 || k < f.cfg.n); i, k = i+1, k+1 {
			at := time.Now()
			size := f.cfg.size(k)
			m, err := f.w.WriteTo(rendrtest.PacketPayload(buf, f.cfg.seed, uint64(k), size, at), nil)
			f.maxCall = max(f.maxCall, time.Since(at))
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
		}
		select {
		case <-f.stop:
			return
		case <-time.After(f.cfg.pace):
		}
	}
}

func (f *flow) reader(rc *rendr.PacketConn) {
	defer close(f.rdone)
	buf := make([]byte, wire.MaxDatagram+1)
	for {
		n, _, err := rc.ReadFrom(buf)
		if err != nil {
			f.rerr, f.rend = err, time.Now()
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
	f.waitWriter(t, time.Minute, what)
}

// waitWriter waits for the writer; a WriteTo error fails the test.
func (f *flow) waitWriter(t testing.TB, within time.Duration, what string) {
	t.Helper()
	select {
	case <-f.wdone:
	case <-time.After(within):
		t.Fatalf("%s: the writer did not finish within %v (%d accepted)", what, within, f.accepted.Load())
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

// arrivedCount returns how many distinct accepted datagrams arrived.
func (f *flow) arrivedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k := range f.wrote {
		if k < len(f.arrived) && !f.arrived[k].IsZero() {
			n++
		}
	}
	return n
}

// writtenBetween counts the accepted datagrams written in [from, to).
func (f *flow) writtenBetween(from, to time.Time) int {
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

// firstArrivalWrittenFrom returns the earliest arrival of a datagram
// written at or after t (zero: none arrived).
func (f *flow) firstArrivalWrittenFrom(t time.Time) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	var first time.Time
	for k, at := range f.wrote {
		if at.Before(t) || k >= len(f.arrived) || f.arrived[k].IsZero() {
			continue
		}
		if a := f.arrived[k]; first.IsZero() || a.Before(first) {
			first = a
		}
	}
	return first
}

// maxArrivalGap returns the longest interval in [from, to] without an
// arrival (the ends count as arrivals).
func (f *flow) maxArrivalGap(from, to time.Time) time.Duration {
	f.mu.Lock()
	var ts []time.Time
	for _, a := range f.arrived {
		if !a.IsZero() && !a.Before(from) && !a.After(to) {
			ts = append(ts, a)
		}
	}
	f.mu.Unlock()
	slicesSortTimes(ts)
	gap, last := time.Duration(0), from
	for _, a := range ts {
		gap = max(gap, a.Sub(last))
		last = a
	}
	return max(gap, to.Sub(last))
}

// slicesSortTimes sorts ts ascending.
func slicesSortTimes(ts []time.Time) {
	slices.SortFunc(ts, func(a, b time.Time) int { return a.Compare(b) })
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

// settle waits until both directions' accounting settled: every datagram
// accepted on either end was sent or counted as a drop, and the peer
// received every one it read plus none in flight (Received stable).
func settle(t testing.TB, dc, pc *rendr.PacketConn, up, down *flow) {
	t.Helper()
	waitFor(t, 30*time.Second, "the accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		ok := true
		if up != nil {
			ok = ok && ds.Sent+drops(ds) == uint64(up.accepted.Load()+up.extra.Load()) && ps.Received == uint64(up.read.Load())
		}
		if down != nil {
			ok = ok && ps.Sent+drops(ps) == uint64(down.accepted.Load()+down.extra.Load()) && ds.Received == uint64(down.read.Load())
		}
		return ok
	})
	time.Sleep(500 * time.Millisecond)
}
