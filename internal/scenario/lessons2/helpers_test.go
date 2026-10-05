package lessons2

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of this package (design §11.1, §11.4): a dialer and a
// passive Runtime built with testhooks.NewRuntime inside the caller's
// synctest bubble, joined by paths. A path is one dialer carrier factory:
// a rendrtest.Link whose far end is routed (by default into the passive's
// push-only Listener) and whose conns are tapped on both ends, so that a
// test can prove which frames crossed which carrier (stimulus proofs) and
// how often a conn was closed.

// env is one test's pair of Runtimes, the passive's Listener, the event
// logs of both Runtimes and the paths between them. Build it inside the
// bubble that uses it; close (or the cleanup) shuts it down.
type env struct {
	t     *testing.T
	d, p  *rendr.Runtime // dialer, passive
	ln    *rendr.Listener
	dev   *evlog // the dialer's events
	pev   *evlog // the passive's events
	paths []*path
}

// newEnv builds both Runtimes with the same overrides (counter presets must
// be identical on both ends, L14) and one push-only Listener on the passive.
// Per-side settings go into dcfg and pcfg (design §10.5). Both Runtimes
// record their events.
func newEnv(t *testing.T, dcfg, pcfg rendr.Config, ov *testhooks.Overrides) *env {
	t.Helper()
	return newEnvSplit(t, dcfg, pcfg, ov, ov)
}

// newEnvSplit is newEnv with separate overrides per side, for hooks that
// must observe one side only; the two values must hold the same counter
// presets (none in this package).
func newEnvSplit(t *testing.T, dcfg, pcfg rendr.Config, dov, pov *testhooks.Overrides) *env {
	t.Helper()
	e := &env{t: t, dev: new(evlog), pev: new(evlog)}
	dcfg.OnEvent, pcfg.OnEvent = e.dev.add, e.pev.add
	e.d = buildRuntime(t, dcfg, dov)
	e.p = buildRuntime(t, pcfg, pov)
	t.Cleanup(e.shut) // also when the test failed; idempotent
	ln, err := e.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	e.ln = ln
	return e
}

// buildRuntime builds a Runtime through testhooks (overrides unclamped).
func buildRuntime(t *testing.T, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	rt, ok := v.(*rendr.Runtime)
	if !ok {
		t.Fatalf("testhooks.NewRuntime returned %T", v)
	}
	return rt
}

// shut closes both Runtimes (the dialer first), then every link (which
// releases blocked writes and hanging dials). Idempotent.
func (e *env) shut() {
	e.d.Close()
	e.p.Close()
	for _, p := range e.paths {
		p.link.Close()
	}
}

// close shuts everything down and requires that neither Runtime keeps a
// live session, a reservation, a handshake, a sessionless carrier, a
// buffered byte (R7) or an abandoned goroutine.
func (e *env) close() {
	e.t.Helper()
	e.shut()
	synctest.Wait() // goroutines released by the links' Close leave the abandoned pool
	noState(e.t, "dialer", e.d)
	noState(e.t, "passive", e.p)
}

// noState requires an idle, closed Runtime.
func noState(t *testing.T, name string, rt *rendr.Runtime) {
	t.Helper()
	st := rt.Status()
	s := st.Sessions
	if s.Open+s.Pending+s.Lingering+s.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 ||
		st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} {
		t.Fatalf("%s Runtime after Close: %+v", name, st)
	}
}

// peer returns a dialer Peer over ps, in that order (the order breaks
// ranking ties).
func (e *env) peer(ps ...*path) *rendr.Peer {
	e.t.Helper()
	cs := make([]rendr.Carrier, len(ps))
	for i, p := range ps {
		cs[i] = p.carrier()
	}
	peer, err := e.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		e.t.Fatalf("NewPeer: %v", err)
	}
	return peer
}

// dialResult is the outcome of an asynchronous Dial.
type dialResult struct {
	c   *rendr.Conn
	err error
}

// goDial dials on its own goroutine.
func goDial(ctx context.Context, p *rendr.Peer, o rendr.DialOptions) <-chan dialResult {
	ch := make(chan dialResult, 1)
	go func() {
		c, err := p.Dial(ctx, o)
		ch <- dialResult{c, err}
	}()
	return ch
}

// open dials peer with o and confirms the session on the passive's
// Listener: the two ends of one session.
func (e *env) open(peer *rendr.Peer, o rendr.DialOptions) (dc, pc *rendr.Conn) {
	e.t.Helper()
	res := goDial(context.Background(), peer, o)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pend, err := e.ln.Accept(ctx)
	if err != nil {
		e.t.Fatalf("Accept: %v", err)
	}
	pc, err = pend.Confirm()
	if err != nil {
		e.t.Fatalf("Confirm: %v", err)
	}
	select {
	case r := <-res:
		if r.err != nil {
			e.t.Fatalf("Dial: %v", r.err)
		}
		return r.c, pc
	case <-time.After(30 * time.Second):
		e.t.Fatalf("Dial did not return after Confirm")
	}
	return nil, nil
}

// path is one carrier factory of the dialer over a rendrtest.Link. Every
// conn it hands out (dialer end) and every far end it routes (passive end)
// is a tconn, so frames and closes are observable per carrier.
type path struct {
	name string
	link *rendrtest.Link
	far  atomic.Pointer[farEnd]

	// early makes the factory a DialEarly factory: the first frame (OPEN,
	// JOIN or PING) is known when the factory is called, so a hanging call
	// can still be classified as a session or a probe dial.
	early bool
	// gate, if set, runs before the link dial of every factory call (call
	// numbers from 1; first is the first bytes of a DialEarly call); an
	// error fails the call. Set it before the path is used.
	gate func(ctx context.Context, call int64, first []byte) error

	calls    atomic.Int64 // factory calls
	inflight atomic.Int64 // factory calls running
	peak     atomic.Int64 // largest inflight seen
	slow     atomic.Pointer[slowWrite]

	mu     sync.Mutex
	dconns []*tconn   // dialer ends, in creation order
	pconns []*tconn   // passive ends, in creation order
	log    []dialCall // every factory call
}

// farEnd is where a path routes the passive end of a new carrier.
type farEnd struct{ accept func(net.Conn) error }

// dialCall records one factory call.
type dialCall struct {
	n     int64
	at    time.Time
	first wire.Type // DialEarly factories: the first frame's type; else 0
}

// path adds a path whose Link delays each direction by oneWay; its far end
// is the passive's Listener.
func (e *env) path(name string, oneWay time.Duration) *path {
	p := &path{name: name}
	p.link = rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: p.accept})
	p.link.SetDelay(oneWay, 0)
	p.setFar(e.ln.Handle)
	e.paths = append(e.paths, p)
	return p
}

// setFar routes the passive ends of new carriers to accept.
func (p *path) setFar(accept func(net.Conn) error) { p.far.Store(&farEnd{accept}) }

// accept is the Link's Accept: tap the passive end and route it.
func (p *path) accept(c net.Conn) error {
	tc := &tconn{Conn: c, p: p}
	p.mu.Lock()
	p.pconns = append(p.pconns, tc)
	p.mu.Unlock()
	return p.far.Load().accept(tc)
}

// carrier is the path's StreamCarrier.
func (p *path) carrier() rendr.StreamCarrier {
	sc := rendr.StreamCarrier{Name: p.name, Dial: func(ctx context.Context) (net.Conn, error) { return p.dial(ctx, nil) }}
	if p.early {
		sc.DialEarly = func(ctx context.Context, first []byte) (net.Conn, error) { return p.dial(ctx, first) }
	}
	return sc
}

// dial is the factory: count, record, gate, then dial the Link and tap the
// conn it returns.
func (p *path) dial(ctx context.Context, first []byte) (net.Conn, error) {
	n := p.calls.Add(1)
	cur := p.inflight.Add(1)
	defer p.inflight.Add(-1)
	for pk := p.peak.Load(); cur > pk && !p.peak.CompareAndSwap(pk, cur); pk = p.peak.Load() {
	}
	rec := dialCall{n: n, at: time.Now()}
	if len(first) > wire.PrefaceLen {
		rec.first = wire.Type(first[wire.PrefaceLen])
	}
	p.mu.Lock()
	p.log = append(p.log, rec)
	p.mu.Unlock()
	if p.gate != nil {
		if err := p.gate(ctx, n, first); err != nil {
			return nil, err
		}
	}
	var (
		c   net.Conn
		err error
	)
	if first != nil {
		c, err = p.link.DialEarly(ctx, first)
	} else {
		c, err = p.link.Dial(ctx)
	}
	if err != nil || c == nil {
		return c, err
	}
	tc := &tconn{Conn: c, p: p, dialer: true}
	if first != nil {
		tc.out.feed(first)
	}
	p.mu.Lock()
	p.dconns = append(p.dconns, tc)
	p.mu.Unlock()
	return tc, nil
}

// callsSince returns the factory calls made at or after since whose first frame
// is t (any type when t is 0).
func (p *path) callsSince(since time.Time, t wire.Type) []dialCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []dialCall
	for _, c := range p.log {
		if !c.at.Before(since) && (t == 0 || c.first == t) {
			out = append(out, c)
		}
	}
	return out
}

// sessionConns returns the dialer ends (dialer) or the passive ends of the
// path's carriers whose first frame is OPEN or JOIN (session carriers).
func (p *path) sessionConns(dialer bool) []*tconn {
	p.mu.Lock()
	cs := p.pconns
	if dialer {
		cs = p.dconns
	}
	cs = append([]*tconn(nil), cs...)
	p.mu.Unlock()
	var out []*tconn
	for _, c := range cs {
		if t := c.firstFrame(); t == wire.TypeOpen || t == wire.TypeJoin {
			out = append(out, c)
		}
	}
	return out
}

// sent returns the frames of type t the dialer wrote on the path's session
// carriers.
func (p *path) sent(t wire.Type) []frameRec {
	var out []frameRec
	for _, c := range p.sessionConns(true) {
		out = append(out, c.out.list(t)...)
	}
	return out
}

// received returns the frames of type t the passive read on the path's
// session carriers.
func (p *path) received(t wire.Type) []frameRec {
	var out []frameRec
	for _, c := range p.sessionConns(false) {
		out = append(out, c.in.list(t)...)
	}
	return out
}

// sentBack returns the frames of type t the passive wrote on the path's
// session carriers.
func (p *path) sentBack(t wire.Type) []frameRec {
	var out []frameRec
	for _, c := range p.sessionConns(false) {
		out = append(out, c.out.list(t)...)
	}
	return out
}

// tconn is a tapped carrier end: it records the frames written through it
// (out) and read through it (in) and counts its Close calls. It offers only
// the net.Conn methods, like any embedder conn.
type tconn struct {
	net.Conn
	p       *path
	dialer  bool // the dialer's end (else the passive's)
	out, in tap
	closes  atomic.Int32
}

func (c *tconn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && n <= len(b) && c.out.feed(b[:n]) && c.dialer {
		c.p.holdIfArmed()
	}
	return n, err
}

func (c *tconn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && n <= len(b) {
		c.in.feed(b[:n])
	}
	return n, err
}

func (c *tconn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// firstFrame is the type of the carrier's first frame (OPEN or JOIN:
// session; PING: probe), 0 until it crossed.
func (c *tconn) firstFrame() wire.Type {
	t := &c.out
	if !c.dialer {
		t = &c.in
	}
	if f, ok := t.first(); ok {
		return f.typ
	}
	return 0
}

// slowWrite makes the next dialer Write that carries DATA return late (L17):
// its bytes go to the link at once, the call returns hold later.
type slowWrite struct {
	hold     time.Duration
	armed    atomic.Bool
	started  chan struct{} // closed once the slow write handed its bytes over
	returned chan struct{} // closed when it returned
}

func newSlowWrite(hold time.Duration) *slowWrite {
	s := &slowWrite{hold: hold, started: make(chan struct{}), returned: make(chan struct{})}
	s.armed.Store(true)
	return s
}

// holdIfArmed holds the calling Write (which just carried DATA) when the
// path's slow write is armed; one Write in all takes it.
func (p *path) holdIfArmed() {
	s := p.slow.Load()
	if s == nil || !s.armed.CompareAndSwap(true, false) {
		return
	}
	close(s.started)
	time.Sleep(s.hold)
	close(s.returned)
}

// tap parses one direction of a carrier byte stream: the 40-byte PREFACE
// (or PREFACE_ACK), then frames of HeaderLen + len + TrailerLen bytes. It
// records every frame with the time it crossed.
type tap struct {
	mu     sync.Mutex
	pre    int
	hdr    [wire.HeaderLen]byte
	hn     int
	cur    frameRec
	rest   int // body bytes (payload + trailer) of cur still to come; 0 between frames
	pos    int // body bytes of cur seen
	pfx    [8]byte
	lost   bool // a length beyond MaxFramePayload: framing lost
	frames []frameRec
}

// frameRec is one frame seen by a tap.
type frameRec struct {
	at    time.Time
	typ   wire.Type
	flags uint8
	n     int    // payload length
	off   uint64 // DATA and FIN: the stream offset
	b0    byte   // the first payload byte (OPEN_ACK and JOIN_ACK: the status)
}

// feed parses b and reports whether a DATA frame started in it.
func (t *tap) feed(b []byte) (data bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for len(b) > 0 && !t.lost {
		switch {
		case t.pre < wire.PrefaceLen:
			k := min(wire.PrefaceLen-t.pre, len(b))
			t.pre += k
			b = b[k:]
		case t.rest == 0:
			k := copy(t.hdr[t.hn:], b)
			t.hn += k
			b = b[k:]
			if t.hn < wire.HeaderLen {
				continue
			}
			t.hn = 0
			n := int(t.hdr[2])<<16 | int(t.hdr[3])<<8 | int(t.hdr[4])
			if n > wire.MaxFramePayload {
				t.lost = true
				return data
			}
			t.cur = frameRec{at: now, typ: wire.Type(t.hdr[0]), flags: t.hdr[1], n: n}
			t.rest, t.pos = n+wire.TrailerLen, 0
			data = data || t.cur.typ == wire.TypeData
		default:
			k := min(t.rest, len(b))
			if t.pos < len(t.pfx) && t.pos < t.cur.n {
				copy(t.pfx[t.pos:min(len(t.pfx), t.cur.n)], b[:k])
			}
			t.pos += k
			t.rest -= k
			b = b[k:]
			if t.rest == 0 {
				if (t.cur.typ == wire.TypeData || t.cur.typ == wire.TypeFin) && t.cur.n >= 8 {
					t.cur.off = binary.BigEndian.Uint64(t.pfx[:])
				}
				if t.cur.n > 0 {
					t.cur.b0 = t.pfx[0]
				}
				t.frames = append(t.frames, t.cur)
			}
		}
	}
	return data
}

// list returns the complete frames of type t.
func (t *tap) list(typ wire.Type) []frameRec {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []frameRec
	for _, f := range t.frames {
		if f.typ == typ {
			out = append(out, f)
		}
	}
	return out
}

// first returns the first complete frame.
func (t *tap) first() (frameRec, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.frames) == 0 {
		return frameRec{}, false
	}
	return t.frames[0], true
}

// lastBefore returns the latest complete frame that crossed before t0.
func (t *tap) lastBefore(t0 time.Time) (frameRec, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.frames) - 1; i >= 0; i-- {
		if t.frames[i].at.Before(t0) {
			return t.frames[i], true
		}
	}
	return frameRec{}, false
}

// dataFramesBelow counts the DATA frames the dialer wrote on the session
// carriers of ps whose stream offset is below end.
func dataFramesBelow(end uint64, ps ...*path) int {
	n := 0
	for _, p := range ps {
		for _, f := range p.sent(wire.TypeData) {
			if f.off < end {
				n++
			}
		}
	}
	return n
}

// dataBytes sums the stream bytes of DATA frames (payload minus the offset).
func dataBytes(fs []frameRec) int64 {
	var n int64
	for _, f := range fs {
		n += int64(f.n - wire.DataPrefixLen)
	}
	return n
}

// evlog records Config.OnEvent calls.
type evlog struct {
	mu  sync.Mutex
	evs []rendr.Event
}

func (l *evlog) add(ev rendr.Event) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

// of returns the recorded events of kind k.
func (l *evlog) of(k rendr.EventKind) []rendr.Event {
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

// opResult is the outcome of an asynchronous Read or Write.
type opResult struct {
	n   int
	err error
	at  time.Time
}

// goOp runs f on its own goroutine.
func goOp(f func() (int, error)) <-chan opResult {
	ch := make(chan opResult, 1)
	go func() {
		n, err := f()
		ch <- opResult{n, err, time.Now()}
	}()
	return ch
}

// await waits for an asynchronous call, failing t after within.
func await(t *testing.T, ch <-chan opResult, within time.Duration, what string) opResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(within):
		t.Fatalf("%s: no result within %v", what, within)
	}
	return opResult{}
}

// running reports whether the asynchronous call has not returned yet. It
// waits for the bubble to settle first, so a call that could return at
// this instant has.
func running(ch <-chan opResult) bool {
	synctest.Wait()
	return len(ch) == 0
}

// waitFor polls cond every step of virtual time until it holds and returns
// the time waited; it fails t after within.
func waitFor(t *testing.T, within, step time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) >= within {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(step)
	}
	return time.Since(start)
}

// waitEnded waits until the session of c ended.
func waitEnded(t *testing.T, c *rendr.Conn, within time.Duration) {
	t.Helper()
	waitFor(t, within, 5*time.Millisecond, "session end", func() bool { return c.Status().State == rendr.StateEnded })
}

// liveOf returns the live (active or member) carriers of st named name ("":
// any).
func liveOf(st rendr.SessionStatus, name string) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if (c.State == rendr.CarrierActive || c.State == rendr.CarrierMember) && (name == "" || c.Name == name) {
			out = append(out, c)
		}
	}
	return out
}

// activeOf returns the active carrier of st.
func activeOf(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// deadOf returns the dead carriers of st named name.
func deadOf(st rendr.SessionStatus, name string) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierDead && c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// prngBytes returns n bytes of PRNG(seed).
func prngBytes(seed uint64, n int) []byte {
	b := make([]byte, n)
	rendrtest.PRNG(seed).Read(b)
	return b
}

// writePRNG writes n bytes of PRNG(seed) to w in 64 KiB calls.
func writePRNG(w io.Writer, n int64, seed uint64) error {
	src := rendrtest.PRNG(seed)
	buf := make([]byte, 64<<10)
	for left := n; left > 0; {
		k := min(int64(len(buf)), left)
		src.Read(buf[:k])
		m, err := w.Write(buf[:k])
		left -= int64(m)
		if err != nil {
			return fmt.Errorf("write after %d of %d bytes: %w", n-left, n, err)
		}
	}
	return nil
}

// readPRNG reads exactly n bytes from r and verifies them against
// PRNG(seed).
func readPRNG(r io.Reader, n int64, seed uint64) error {
	v := rendrtest.NewVerifier(seed, n)
	buf := make([]byte, 64<<10)
	for got := int64(0); got < n; {
		k, err := r.Read(buf[:min(int64(len(buf)), n-got)])
		if k < 0 || k > len(buf) {
			return fmt.Errorf("invalid read count %d", k)
		}
		if k > 0 {
			if _, werr := v.Write(buf[:k]); werr != nil {
				return werr
			}
			got += int64(k)
		}
		if err != nil && got < n {
			return fmt.Errorf("read after %d of %d bytes: %w", got, n, err)
		}
	}
	return nil
}

// exchange moves n bytes of PRNG(seed) from a to b and n bytes of
// PRNG(seed+1) from b to a at the same time and verifies both (no FIN).
func exchange(t *testing.T, a, b *rendr.Conn, n int64, seed uint64) {
	t.Helper()
	errs := make(chan error, 4)
	for _, d := range []struct {
		w, r *rendr.Conn
		seed uint64
	}{{a, b, seed}, {b, a, seed + 1}} {
		go func() { errs <- writePRNG(d.w, n, d.seed) }()
		go func() { errs <- readPRNG(d.r, n, d.seed) }()
	}
	for range 4 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("exchange of %d bytes: %v", n, err)
			}
		case <-time.After(time.Minute):
			t.Fatalf("exchange of %d bytes: no progress within a minute", n)
		}
	}
}

// xfer moves n bytes of PRNG(seed) from w to r on two goroutines: the
// writer half-closes w after the last byte; the reader accepts io.EOF only
// after exactly n matching bytes (L64) and closes mark channels as it
// crosses the given byte counts (deterministic load gates).
type xfer struct {
	n            int64
	wrote, got   atomic.Int64
	werr, rerr   error         // set before wdone, rdone close
	wdone, rdone chan struct{} // closed when the writer, the reader ended
	marks        []int64
	reached      []chan struct{}
}

func startXfer(w, r *rendr.Conn, n int64, seed uint64, marks ...int64) *xfer {
	x := &xfer{n: n, wdone: make(chan struct{}), rdone: make(chan struct{}), marks: marks}
	for range marks {
		x.reached = append(x.reached, make(chan struct{}))
	}
	go func() {
		defer close(x.wdone)
		x.werr = writePRNG(countWriter{w, &x.wrote}, n, seed)
		if x.werr == nil {
			x.werr = w.CloseWrite()
		}
	}()
	go func() {
		defer close(x.rdone)
		x.rerr = x.read(r, seed)
	}()
	return x
}

// countWriter counts the bytes a Write accepted.
type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func (x *xfer) read(r io.Reader, seed uint64) error {
	v := rendrtest.NewVerifier(seed, x.n)
	buf := make([]byte, 64<<10)
	next := 0
	for {
		k, err := r.Read(buf)
		if k < 0 || k > len(buf) {
			return fmt.Errorf("invalid read count %d", k)
		}
		if k > 0 {
			if _, werr := v.Write(buf[:k]); werr != nil {
				return werr
			}
			g := x.got.Add(int64(k))
			for ; next < len(x.marks) && g >= x.marks[next]; next++ {
				close(x.reached[next])
			}
		}
		if err != nil {
			return v.Done(err)
		}
	}
}

// waitMark waits until the reader crossed mark i.
func (x *xfer) waitMark(t *testing.T, i int, within time.Duration) {
	t.Helper()
	select {
	case <-x.reached[i]:
		return
	case <-x.rdone:
	case <-time.After(within):
		t.Fatalf("transfer: %d bytes not reached within %v (read %d)", x.marks[i], within, x.got.Load())
	}
	select {
	case <-x.reached[i]:
	default:
		t.Fatalf("transfer ended before %d bytes: %v", x.marks[i], x.rerr)
	}
}

// wait waits for both ends of the transfer: the writer wrote and
// half-closed, the reader verified exactly n bytes and io.EOF.
func (x *xfer) wait(t *testing.T, within time.Duration) {
	t.Helper()
	timeout := time.After(within)
	for _, d := range []struct {
		done chan struct{}
		err  *error
	}{{x.wdone, &x.werr}, {x.rdone, &x.rerr}} {
		select {
		case <-d.done:
			if *d.err != nil {
				t.Fatalf("transfer of %d bytes: %v", x.n, *d.err)
			}
		case <-timeout:
			t.Fatalf("transfer of %d bytes: not done within %v (wrote %d, read %d)", x.n, within, x.wrote.Load(), x.got.Load())
		}
	}
}

// endClean ends a session whose data was all read: CloseWrite on both ends
// (idempotent), io.EOF on both, Close on both; both ends must then reach
// StateEnded with io.EOF (the clean end, D4).
func endClean(t *testing.T, a, b *rendr.Conn) {
	t.Helper()
	both := []*rendr.Conn{a, b}
	for _, c := range both {
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	for _, c := range both {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		var x [1]byte
		if n, err := c.Read(x[:]); n != 0 || err != io.EOF {
			t.Fatalf("%v: Read after the peer's FIN = (%d, %v), want io.EOF", c.Status().Role, n, err)
		}
	}
	for _, c := range both {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for _, c := range both {
		waitEnded(t, c, 30*time.Second)
		if st := c.Status(); st.Err != io.EOF {
			t.Fatalf("%v ended with %v, want a clean end (io.EOF): %+v", st.Role, st.Err, st)
		}
	}
}

// isTerminal requires err to be the session error want (errors.Is), never
// io.EOF, and a net.Error whose Timeout is false (plan §6).
func isTerminal(err, want error) bool {
	var ne net.Error
	return err != nil && err != io.EOF && errors.Is(err, want) && errors.As(err, &ne) && !ne.Timeout()
}

// errRefused is a factory failure (a refused connection).
var errRefused = errors.New("lessons2: connection refused")

// junkEnd is a far end that is not a rendr instance (L20: a misconfigured
// forwarding): it reads the first bytes a dialer sends, answers with an
// HTTP error and closes. It counts the carriers that reached it by the
// type of their first frame (the byte after the 40-byte PREFACE), so a
// test can prove which attempts it refused.
type junkEnd struct{ open, join, ping atomic.Int64 }

// accept is the far end's Accept.
func (j *junkEnd) accept(c net.Conn) error {
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	if n > wire.PrefaceLen {
		switch wire.Type(buf[wire.PrefaceLen]) {
		case wire.TypeOpen:
			j.open.Add(1)
		case wire.TypeJoin:
			j.join.Add(1)
		case wire.TypePing:
			j.ping.Add(1)
		}
	}
	c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	return nil
}
