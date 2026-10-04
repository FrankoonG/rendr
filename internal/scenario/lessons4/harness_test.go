package lessons4

import (
	"cmp"
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
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit (design §11.1, §11.2; V12, AA3). A world is two Runtimes —
// the dialer d and the passive p with one push-only Listener — built with
// testhooks.NewRuntime and joined by rendrtest.Links whose Accept is the
// Listener's Handle, so every carrier goes through the whole handshake and
// admission. Everything is created inside the synctest bubble that uses it
// and closed before the bubble ends. Only the public API is used; the
// internal packages appear only as testhooks (Overrides) and wire (frame
// parsing in the taps).

// worldOpts configures a world. Every Link keeps rendrtest's default 2 MiB
// buffer per direction (the buffer-loss model of L10/L61).
type worldOpts struct {
	// ov goes to both Runtimes (counter presets must be equal, L14); only
	// the dialer's copy gets dHooks.
	ov     testhooks.Overrides
	dHooks *testhooks.Hooks
	// pTune, if set, changes the passive's copy of ov: a per-side timing
	// such as a death deadline, never a counter preset.
	pTune func(*testhooks.Overrides)
	// dcfg and pcfg are the dialer's and the passive's Config (OnEvent is
	// the world's event log).
	dcfg, pcfg rendr.Config
	// tap wraps every passive carrier conn in a frame tap (world.taps).
	tap bool
}

// world is one scenario's two Runtimes and Links.
type world struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	links    []*rendrtest.Link
	dev, pev *eventLog
	taps     *tapSet
	lastPeer *rendr.Peer // the Peer peer built last
}

// newWorld builds the Runtimes, the Listener and one Link per name. A
// cleanup shuts everything down if the test fails before close.
func newWorld(t testing.TB, o worldOpts, names ...string) *world {
	t.Helper()
	w := &world{t: t, dev: &eventLog{}, pev: &eventLog{}, taps: &tapSet{}}
	dov, pov := o.ov, o.ov
	dov.Hooks, pov.Hooks = o.dHooks, nil
	if o.pTune != nil {
		o.pTune(&pov)
	}
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
		w.addLink(n, o.tap)
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

// addLink adds a Link whose carriers are handed to the passive Listener
// (through a frame tap when tap is set).
func (w *world) addLink(name string, tap bool) {
	accept := func(c net.Conn) error {
		if tap {
			c = w.taps.wrap(name, c)
		}
		return w.ln.Handle(c)
	}
	w.links = append(w.links, rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: accept}))
}

// link returns the Link called name.
func (w *world) link(name string) *rendrtest.Link {
	for _, l := range w.links {
		if l.Name() == name {
			return l
		}
	}
	w.t.Fatalf("no link %q", name)
	return nil
}

// dialWrap wraps the conns a factory returns (nil: none).
type dialWrap func(link string, c net.Conn) net.Conn

// peer returns a dialer Peer over links in this order (configuration order
// breaks ranking ties); wrap, if not nil, wraps every conn a factory dials.
func (w *world) peer(wrap dialWrap, links ...*rendrtest.Link) *rendr.Peer {
	w.t.Helper()
	cs := make([]rendr.Carrier, len(links))
	for i, l := range links {
		dial := l.Dial
		if wrap != nil {
			name := l.Name()
			dial = func(ctx context.Context) (net.Conn, error) {
				c, err := l.Dial(ctx)
				if err != nil {
					return nil, err
				}
				return wrap(name, c), nil
			}
		}
		cs[i] = rendr.StreamCarrier{Name: l.Name(), Dial: dial}
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	w.lastPeer = p
	return p
}

// dialResult is the outcome of an asynchronous Dial.
type dialResult struct {
	c   *rendr.Conn
	err error
}

// dialAsync dials on its own goroutine.
func dialAsync(p *rendr.Peer, o rendr.DialOptions) <-chan dialResult {
	ch := make(chan dialResult, 1)
	go func() {
		c, err := p.Dial(context.Background(), o)
		ch <- dialResult{c, err}
	}()
	return ch
}

// pending waits for the next pending session on the passive Listener.
func (w *world) pending() *rendr.PendingConn {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pc, err := w.ln.Accept(ctx)
	if err != nil {
		w.t.Fatalf("Accept: %v", err)
	}
	return pc
}

// confirm confirms pc and waits for the dialer's result.
func (w *world) confirm(pc *rendr.PendingConn, res <-chan dialResult) (dc, sc *rendr.Conn) {
	w.t.Helper()
	sc, err := pc.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-res
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.c, sc
}

// open dials one session over p and confirms it on the passive: its dialer
// and passive ends.
func (w *world) open(p *rendr.Peer, o rendr.DialOptions) (dc, sc *rendr.Conn) {
	w.t.Helper()
	res := dialAsync(p, o)
	return w.confirm(w.pending(), res)
}

// shutdown closes both Runtimes (the dialer first) and every Link
// (idempotent; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.d.Close()
	w.p.Close()
	for _, l := range w.links {
		l.Close()
	}
}

// close shuts the world down and requires that neither Runtime holds a
// session, a handshake, a sessionless carrier or a buffered byte any more
// and that nothing was abandoned (L52; R7).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} {
			w.t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
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

// all returns every recorded event.
func (l *eventLog) all() []rendr.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.evs)
}

// waitFor polls cond every millisecond of virtual time until it holds,
// failing after within. Polling only waits for the session's own timers to
// run; the bubble makes it deterministic.
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

// waitEnded waits until c's session ended.
func waitEnded(t testing.TB, c *rendr.Conn, within time.Duration) {
	t.Helper()
	waitFor(t, within, "the session end", func() bool { return c.Status().State == rendr.StateEnded })
}

// endClean half-closes both ends, requires io.EOF on both, closes both and
// waits until both sessions ended cleanly (Err io.EOF).
func endClean(t testing.TB, a, b *rendr.Conn) {
	t.Helper()
	for _, c := range []*rendr.Conn{a, b} {
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	for _, c := range []*rendr.Conn{a, b} {
		var x [1]byte
		if n, err := c.Read(x[:]); n != 0 || err != io.EOF {
			t.Fatalf("Read after the peer's FIN: (%d, %v), want EOF", n, err)
		}
	}
	for _, c := range []*rendr.Conn{a, b} {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for _, c := range []*rendr.Conn{a, b} {
		waitEnded(t, c, time.Minute)
		if st := c.Status(); st.Err != io.EOF {
			t.Fatalf("%v session %v ended with %v, want io.EOF", st.Role, c.ID(), st.Err)
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

// dataCarriers returns the carriers that may carry DATA (active or member).
func dataCarriers(st rendr.SessionStatus) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive || c.State == rendr.CarrierMember {
			out = append(out, c)
		}
	}
	return out
}

// memberOn returns the live data carrier of factory name (dialer side).
func memberOn(st rendr.SessionStatus, name string) (rendr.CarrierStatus, bool) {
	for _, c := range dataCarriers(st) {
		if c.Name == name {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// Application data.

// flowOpts shapes one direction of application data.
type flowOpts struct {
	chunk      int           // bytes per Write (default 64 KiB)
	pace       time.Duration // pause between Writes (an application-limited flow)
	closeWrite bool          // CloseWrite after the last byte
	eof        bool          // the reader requires io.EOF right after the n bytes
	clearAfter bool          // the writer zeroes its buffer after every Write (L43)
}

// flow is n bytes of PRNG(seed) written on one Conn and verified on
// another, each side on its own goroutine.
type flow struct {
	n          int64
	seed       uint64
	sent, got  atomic.Int64
	wdone      chan struct{}
	rdone      chan struct{}
	werr, rerr error

	mu     sync.Mutex
	reads  []readMark // every read that returned data, in order
	first  time.Time
	maxGap time.Duration // longest pause between two reads that returned data
	gapEnd time.Time     // when that pause ended
}

// readMark is the time a read returned data and the total delivered then.
type readMark struct {
	at  time.Time
	got int64
}

// startFlow writes n bytes of PRNG(seed) on wc and verifies them on rc.
func startFlow(wc, rc net.Conn, n int64, seed uint64, o flowOpts) *flow {
	f := &flow{n: n, seed: seed, wdone: make(chan struct{}), rdone: make(chan struct{})}
	if o.chunk <= 0 {
		o.chunk = 64 << 10
	}
	go func() {
		defer close(f.wdone)
		f.werr = f.write(wc, o)
	}()
	go func() {
		defer close(f.rdone)
		f.rerr = f.read(rc, o)
	}()
	return f
}

func (f *flow) write(c net.Conn, o flowOpts) error {
	src := rendrtest.PRNG(f.seed)
	buf := make([]byte, o.chunk)
	for done := int64(0); done < f.n; {
		k := int(min(int64(len(buf)), f.n-done))
		src.Read(buf[:k])
		m, err := c.Write(buf[:k])
		if m > 0 {
			done += int64(m)
			f.sent.Store(done)
		}
		if o.clearAfter {
			clear(buf[:k])
		}
		if err != nil {
			return fmt.Errorf("write after %d of %d bytes: %w", done, f.n, err)
		}
		if m != k {
			return fmt.Errorf("short write %d of %d without error", m, k)
		}
		if o.pace > 0 {
			time.Sleep(o.pace)
		}
	}
	if o.closeWrite {
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			if err := cw.CloseWrite(); err != nil {
				return fmt.Errorf("CloseWrite: %w", err)
			}
		}
	}
	return nil
}

func (f *flow) read(c net.Conn, o flowOpts) error {
	v := rendrtest.NewVerifier(f.seed, f.n)
	buf := make([]byte, 64<<10)
	var got int64
	for got < f.n {
		k, err := c.Read(buf[:min(int64(len(buf)), f.n-got)])
		if k > 0 {
			got += int64(k)
			f.got.Store(got)
			f.mark(got)
			if _, werr := v.Write(buf[:k]); werr != nil {
				return v.Done(err)
			}
		}
		if err != nil {
			return v.Done(err)
		}
	}
	if o.eof {
		var x [1]byte
		if k, err := c.Read(x[:]); k != 0 || err != io.EOF {
			return fmt.Errorf("after %d bytes: Read (%d, %v), want EOF", f.n, k, err)
		}
	}
	return v.Done(io.EOF)
}

// mark records a read that returned data (the reader goroutine only writes).
func (f *flow) mark(got int64) {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reads) == 0 {
		f.first = now
	} else if gap := now.Sub(f.reads[len(f.reads)-1].at); gap > f.maxGap {
		f.maxGap, f.gapEnd = gap, now
	}
	f.reads = append(f.reads, readMark{now, got})
}

// gap returns the longest pause between two reads that returned data, and
// when it ended.
func (f *flow) gap() (time.Duration, time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxGap, f.gapEnd
}

// firstReadAfter returns the first read that returned data after t.
func (f *flow) firstReadAfter(t time.Time) (readMark, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.reads {
		if m.at.After(t) {
			return m, true
		}
	}
	return readMark{}, false
}

// reached returns the first read after which the reader had at least k
// bytes.
func (f *flow) reached(k int64) (readMark, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, _ := slices.BinarySearchFunc(f.reads, k, func(m readMark, k int64) int { return cmp.Compare(m.got, k) })
	if i == len(f.reads) {
		return readMark{}, false
	}
	return f.reads[i], true
}

// lastReadBefore returns the last read that returned data before t.
func (f *flow) lastReadBefore(t time.Time) (readMark, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.reads) - 1; i >= 0; i-- {
		if f.reads[i].at.Before(t) {
			return f.reads[i], true
		}
	}
	return readMark{}, false
}

// wait waits for both sides of the flow and fails on any error: a write
// error, a short or corrupted stream, an early EOF.
func (f *flow) wait(t testing.TB, within time.Duration, what string) {
	t.Helper()
	timeout := time.After(within)
	for _, ch := range []chan struct{}{f.wdone, f.rdone} {
		select {
		case <-ch:
		case <-timeout:
			t.Fatalf("%s: not done after %v (sent %d, received %d of %d)", what, within, f.sent.Load(), f.got.Load(), f.n)
		}
	}
	if f.werr != nil {
		t.Fatalf("%s: writer: %v", what, f.werr)
	}
	if f.rerr != nil {
		t.Fatalf("%s: reader: %v", what, f.rerr)
	}
}

// Frame taps: a conn wrapper that follows the rendr byte stream one side
// reads — the 40-byte PREFACE (or PREFACE_ACK), then frames of HeaderLen +
// len + TrailerLen bytes — so a test can prove where a fault landed (a
// partial frame in a reader) and count frames by type (SCHED epochs).

// framer parses a rendr byte stream incrementally.
type framer struct {
	pre    int
	hdr    [wire.HeaderLen]byte
	hn     int
	in     bool
	h      wire.Header
	rest   int // payload + trailer bytes of the current frame still to come
	pay    []byte
	count  [256]int
	epochs []uint32 // SCHED epochs, in arrival order
	bytes  int64
	lost   bool // a header did not parse (an injected splice): framing lost
}

func (f *framer) feed(p []byte) {
	f.bytes += int64(len(p))
	for len(p) > 0 && !f.lost {
		switch {
		case f.pre < wire.PrefaceLen:
			k := min(wire.PrefaceLen-f.pre, len(p))
			f.pre += k
			p = p[k:]
		case !f.in:
			k := copy(f.hdr[f.hn:], p)
			f.hn += k
			p = p[k:]
			if f.hn < wire.HeaderLen {
				continue
			}
			f.hn = 0
			h, err := wire.ParseHeader(f.hdr[:])
			if err != nil {
				f.lost = true
				return
			}
			f.h, f.in, f.rest = h, true, int(h.Len)+wire.TrailerLen
			f.pay = f.pay[:0]
		default:
			k := min(f.rest, len(p))
			if f.h.Type == wire.TypeSched {
				f.pay = append(f.pay, p[:k]...)
			}
			f.rest -= k
			p = p[k:]
			if f.rest > 0 {
				continue
			}
			f.in = false
			f.count[f.h.Type]++
			if f.h.Type == wire.TypeSched {
				if s, err := wire.ParseSched(f.pay[:len(f.pay)-wire.TrailerLen]); err == nil {
					f.epochs = append(f.epochs, s.Epoch)
				}
			}
		}
	}
}

// midFrame reports that the stream stopped inside a frame (a partial
// header or a partial payload).
func (f framer) midFrame() bool {
	return f.pre == wire.PrefaceLen && !f.lost && (f.hn > 0 || f.in)
}

// tapConn is a carrier conn whose Reads go through a framer. It counts
// Close calls (L52: every carrier is closed exactly once).
type tapConn struct {
	net.Conn
	link   string
	mu     sync.Mutex
	rx     framer
	closes atomic.Int32
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && n <= len(p) {
		c.mu.Lock()
		c.rx.feed(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *tapConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// snapshot returns a copy of the framer state.
func (c *tapConn) snapshot() framer {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.rx
	f.epochs = slices.Clone(c.rx.epochs)
	f.pay = nil
	return f
}

// tapSet holds every tap of a world, in creation order.
type tapSet struct {
	mu   sync.Mutex
	taps []*tapConn
}

func (s *tapSet) wrap(link string, c net.Conn) net.Conn {
	tc := &tapConn{Conn: c, link: link}
	s.mu.Lock()
	s.taps = append(s.taps, tc)
	s.mu.Unlock()
	return tc
}

// all returns the taps (of link, or of every link when link is "").
func (s *tapSet) all(link string) []*tapConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*tapConn
	for _, c := range s.taps {
		if link == "" || c.link == link {
			out = append(out, c)
		}
	}
	return out
}

// errInjected is the error of scripted embedder failures.
var errInjected = errors.New("lessons4: injected conn failure")

// mib formats a byte count in MiB for messages.
func mib(n int64) string { return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20)) }
