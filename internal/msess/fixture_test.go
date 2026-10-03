package msess_test

// The test fixture is the only code in the tests that touches the msess
// API. Tests dial through fixture.dial, read session state through the
// fixture's adapters, control carriers through *link and observe the far end
// through *farEnd. When the session API changes, only this file (and the
// tunables below) needs to follow.
//
// Carriers: every Dial on a link creates an in-memory carrier whose two
// directions pass through pumps that can add delay/jitter, cap bandwidth,
// blackhole (100% loss: bytes vanish, nothing closes), stall (bytes held,
// not lost, like a QUIC path under 100% loss), be killed (both ends closed)
// or corrupt (flip one byte). Every control has a counter so a test can
// prove its stimulus actually happened. Carriers are classified by their
// HELLO kind: the Prober keeps a probe carrier on every link, so stimulus
// proofs count session carriers only (linkStats.Session, carrierLog).
//
// Far end: the server's target dialer returns one end of an in-memory
// connection attached to an in-process behaviour: echo, gen:N (N PRNG
// bytes, then close) or stall (read until FIN, then hold the socket);
// packet sessions get an in-memory datagram echo.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/msess"
)

// ---------------------------------------------------------------- tunables

// tun holds the shortened time scales of the test binary. They are package
// globals read by long-lived goroutines, so they are set exactly once.
var tun = struct {
	DeadMin, ProbeEvery, ProbeFresh, SwitchDwell, SwitchCooldown time.Duration
	Orphan, RetireGrace, PingIdle, Linger, StreamIdle            time.Duration
}{
	DeadMin:        1 * time.Second,
	ProbeEvery:     200 * time.Millisecond,
	ProbeFresh:     2 * time.Second,
	SwitchDwell:    1 * time.Second,
	SwitchCooldown: 2 * time.Second,
	Orphan:         5 * time.Second,
	RetireGrace:    500 * time.Millisecond,
	PingIdle:       1 * time.Second,
	Linger:         10 * time.Second,
	StreamIdle:     20 * time.Second,
}

func TestMain(m *testing.M) {
	msess.DeadMin = tun.DeadMin
	msess.ProbeEvery = tun.ProbeEvery
	msess.ProbeFresh = tun.ProbeFresh
	msess.SwitchDwell = tun.SwitchDwell
	msess.SwitchCooldown = tun.SwitchCooldown
	msess.OrphanBudget = tun.Orphan
	msess.RetireGrace = tun.RetireGrace
	msess.PingIdle = tun.PingIdle
	msess.LingerBudget = tun.Linger
	msess.StreamIdle = tun.StreamIdle
	os.Exit(m.Run())
}

// quietLog: session goroutines outlive tests, so never log through t.
func quietLog(format string, args ...any) {
	if os.Getenv("RENDR_TEST_LOG") != "" {
		log.Printf(format, args...)
	}
}

// ---------------------------------------------------------------- fixture

type mode int

const (
	selector mode = iota + 1
	bond
)

func (m mode) msess() msess.Mode {
	if m == bond {
		return msess.ModeBond
	}
	return msess.ModeSelector
}

// target names a far-end behaviour.
type target string

func echo() target            { return "echo:1" }
func gen(n int64) target      { return target(fmt.Sprintf("gen:%d", n)) }
func stall() target           { return "stall:1" }
func unreachable() target     { return "unreachable:1" }
func packetEcho() target      { return "udp-echo:1" }
func (t target) kind() string { k, _, _ := strings.Cut(string(t), ":"); return k }

type dialOpts struct {
	target      target
	grace       time.Duration // 0 = default
	packet      bool          // datagram session
	pipelined   bool          // the HELLO travels in the carrier open request
	noProbeWait bool          // dial the first ranked path without waiting for probes
}

type fixtureConfig struct {
	links       []string
	maxSessions int // 0 = server default
}

type fixture struct {
	t         *testing.T
	srv       *msess.Server
	pr        *msess.Prober
	links     []*link
	far       *farEnd
	closeOnce sync.Once
}

func newFixture(t *testing.T, names ...string) *fixture {
	return newFixtureCfg(t, fixtureConfig{links: names})
}

func newFixtureCfg(t *testing.T, cfg fixtureConfig) *fixture {
	t.Helper()
	far := newFarEnd()
	srv := msess.NewServer(msess.ServerConfig{DialTarget: far.dialStream, DialPacketTarget: far.dialPacket,
		MaxSessions: cfg.maxSessions, Logf: quietLog})
	f := &fixture{t: t, srv: srv, pr: msess.NewProber(quietLog), far: far}
	for _, n := range cfg.links {
		f.links = append(f.links, newLink(n, srv.Handle))
	}
	t.Cleanup(f.close)
	return f
}

// close tears the fixture down (idempotent; also run by t.Cleanup): the
// Prober stops first so it opens no new probe carriers, then every link is
// shut, then the server and the far end.
func (f *fixture) close() {
	f.closeOnce.Do(func() {
		f.pr.Close()
		for _, l := range f.links {
			l.cleanup()
		}
		f.srv.Close()
		f.far.close()
	})
}

func (f *fixture) link(name string) *link {
	for _, l := range f.links {
		if l.name == name {
			return l
		}
	}
	f.t.Fatalf("no link %s", name)
	return nil
}

func (f *fixture) paths(pipelined bool) []msess.Path {
	out := make([]msess.Path, len(f.links))
	for i, l := range f.links {
		out[i] = l.path(pipelined)
	}
	return out
}

// dial opens one application connection over every link of the fixture.
func (f *fixture) dial(m mode, o dialOpts) (net.Conn, error) {
	if o.target == "" {
		o.target = echo()
	}
	cfg := msess.DialConfig{Mode: m.msess(), Target: string(o.target), Paths: f.paths(o.pipelined),
		Prober: f.pr, Grace: o.grace, NoProbeWait: o.noProbeWait, Logf: quietLog}
	var c *msess.Conn
	var err error
	if o.packet {
		c, err = msess.DialPacket(context.Background(), cfg)
	} else {
		c, err = msess.Dial(context.Background(), cfg)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (f *fixture) mustDial(m mode, o dialOpts) net.Conn {
	f.t.Helper()
	c, err := f.dial(m, o)
	if err != nil {
		f.t.Fatalf("dial: %v", err)
	}
	return c
}

// ---------------------------------------------------------------- adapters

// activePath: the link name of the selector's active carrier ("" if none).
func activePath(c net.Conn) string {
	for _, s := range c.(*msess.Conn).Subflows() {
		if s.Active {
			return s.Path
		}
	}
	return ""
}

// activeSub: the selector's active subflow (ID 0 and "" if none).
func activeSub(c net.Conn) (uint32, string) {
	for _, s := range c.(*msess.Conn).Subflows() {
		if s.Active {
			return s.ID, s.Path
		}
	}
	return 0, ""
}

// sessionDone is closed once the session has fully ended.
func sessionDone(c net.Conn) <-chan struct{} { return c.(*msess.Conn).Done() }

// serverSessions: sessions the server side still holds.
func (f *fixture) serverSessions() int { return f.srv.Stats().Sessions }

func isTargetDialError(err error) bool {
	var de *msess.DialError
	return errors.As(err, &de)
}

func isUnsupported(err error) bool { return errors.Is(err, msess.ErrUnsupported) }
func isBusy(err error) bool        { return errors.Is(err, msess.ErrBusy) }

// ---------------------------------------------------------------- links

type chunk struct {
	b  []byte
	at time.Time
}

// HELLO kinds as seen on the wire (byte 4 of the HELLO). Session carriers
// are open, join and open-packet; probe carriers belong to the Prober.
const (
	helloOpen       = 1
	helloJoin       = 2
	helloProbe      = 3
	helloOpenPacket = 4
)

// faultCounts is what a set of carriers saw; tests use it to prove a
// stimulus.
type faultCounts struct {
	Killed    int64 // carriers closed by kill()
	Bytes     int64 // bytes forwarded (both directions)
	Dropped   int64 // bytes discarded by the blackhole
	Held      int64 // chunks held back by a stall
	Corrupted int64 // bytes flipped
	MaxDelay  time.Duration
}

// linkStats: link-wide counters (session and probe carriers) and the same
// counters restricted to session carriers. The Prober keeps a probe carrier
// on every link, so a link-wide counter can move without the fault ever
// touching a session: stimulus proofs must use Session.
type linkStats struct {
	faultCounts
	Session   faultCounts
	Throttled int64 // bytes passed through the rate limiter
}

type counters struct {
	killed, bytes, dropped, held, corrupted, maxDelay atomic.Int64
}

func (k *counters) snap() faultCounts {
	return faultCounts{Killed: k.killed.Load(), Bytes: k.bytes.Load(), Dropped: k.dropped.Load(),
		Held: k.held.Load(), Corrupted: k.corrupted.Load(), MaxDelay: time.Duration(k.maxDelay.Load())}
}

type link struct {
	name   string
	exit   string
	accept func(net.Conn) // server side of a new carrier

	mu        sync.Mutex
	delay     time.Duration
	jitter    time.Duration
	rate      float64 // bytes/s, 0 = unlimited
	blackhole bool
	stalled   bool
	refuse    bool
	legacy    bool          // far end closes on HELLO (does not speak the protocol)
	closed    bool          // fixture cleanup: no new carriers
	carriers  []*carrier    // live carriers
	history   []*carrier    // every carrier ever created, in creation order
	deadOpens []net.Conn    // both pipe ends of every live dead (blackholed) open
	quit      chan struct{} // closed by cleanup

	all, sess counters
	throttled atomic.Int64
}

func newLink(name string, accept func(net.Conn)) *link {
	return &link{name: name, exit: "X", accept: accept, quit: make(chan struct{})}
}

type carrier struct {
	l       *link
	seq     int      // creation order on its link
	a, b    net.Conn // a: client side far end, b: server side far end
	closed  atomic.Bool
	corrupt atomic.Bool
	kind    atomic.Int32 // HELLO kind, 0 until the HELLO crossed
	head    []byte       // HELLO prefix seen so far (up pump reader only)
	up      atomic.Int64 // bytes delivered client -> server
	down    atomic.Int64 // bytes delivered server -> client
	held    atomic.Int64 // chunks held by a stall
}

// session reports whether the carrier belongs to a session (not a probe).
func (c *carrier) session() bool {
	k := c.kind.Load()
	return k == helloOpen || k == helloJoin || k == helloOpenPacket
}

// count applies f to the link-wide counters and, for a session carrier, to
// the session counters.
func (l *link) count(c *carrier, f func(*counters)) {
	f(&l.all)
	if c.session() {
		f(&l.sess)
	}
}

func (l *link) stats() linkStats {
	return linkStats{faultCounts: l.all.snap(), Session: l.sess.snap(), Throttled: l.throttled.Load()}
}

// carrierInfo is a snapshot of one carrier for per-carrier assertions.
type carrierInfo struct {
	seq      int
	kind     int32
	up, down int64
	held     int64
}

// carrierLog lists every carrier the link created, in creation order.
func (l *link) carrierLog() []carrierInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]carrierInfo, len(l.history))
	for i, c := range l.history {
		out[i] = carrierInfo{seq: c.seq, kind: c.kind.Load(), up: c.up.Load(), down: c.down.Load(), held: c.held.Load()}
	}
	return out
}

// nextSeq is the seq the next carrier of the link will get.
func (l *link) nextSeq() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.history)
}

// set configures one-way delay, jitter and a bandwidth cap (Mbit/s, 0 = none).
func (l *link) set(delay, jitter time.Duration, rateMbit float64) {
	l.mu.Lock()
	l.delay, l.jitter, l.rate = delay, jitter, rateMbit*1e6/8
	l.mu.Unlock()
}

// setRefuse: new carrier opens fail.
func (l *link) setRefuse(v bool) {
	l.mu.Lock()
	l.refuse = v
	l.mu.Unlock()
}

// setStall: bytes are held (not lost) until un-stalled.
func (l *link) setStall(v bool) {
	l.mu.Lock()
	l.stalled = v
	l.mu.Unlock()
}

// setBlackhole: bytes vanish; nothing closes.
func (l *link) setBlackhole(v bool) {
	l.mu.Lock()
	l.blackhole = v
	l.mu.Unlock()
}

func (l *link) setLegacy(v bool) {
	l.mu.Lock()
	l.legacy = v
	l.mu.Unlock()
}

// kill closes every current carrier of the link (both ends), including
// dead opens on a blackholed link.
func (l *link) kill() {
	l.mu.Lock()
	cs := append([]*carrier(nil), l.carriers...)
	dead := l.deadOpens
	l.deadOpens = nil
	l.mu.Unlock()
	for _, c := range cs {
		if c.close() {
			l.count(c, func(k *counters) { k.killed.Add(1) })
		}
	}
	for _, d := range dead {
		d.Close()
	}
}

// cleanup stops the link for good: no new carriers, every current one
// closed, every timer goroutine of the link released.
func (l *link) cleanup() {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.quit)
	}
	l.mu.Unlock()
	l.kill()
}

// corruptNext flips one byte in the next chunk of every current carrier.
func (l *link) corruptNext() {
	l.mu.Lock()
	for _, c := range l.carriers {
		c.corrupt.Store(true)
	}
	l.mu.Unlock()
}

// close closes both ends and drops the carrier from the live list.
func (c *carrier) close() bool {
	if !c.closed.CompareAndSwap(false, true) {
		return false
	}
	c.a.Close()
	c.b.Close()
	l := c.l
	l.mu.Lock()
	for i, x := range l.carriers {
		if x == c {
			l.carriers = append(l.carriers[:i], l.carriers[i+1:]...)
			break
		}
	}
	l.mu.Unlock()
	return true
}

func (l *link) path(pipelined bool) msess.Path {
	p := msess.Path{Name: l.name, Exit: l.exit, Dial: func(ctx context.Context) (net.Conn, error) {
		return l.open(ctx, nil)
	}}
	if pipelined {
		p.Open = func(ctx context.Context, hello []byte) (net.Conn, error) { return l.open(ctx, hello) }
	}
	return p
}

// open creates a carrier. hello != nil: the server's handler gets the HELLO
// in front of the stream and the client never writes it.
func (l *link) open(ctx context.Context, hello []byte) (net.Conn, error) {
	l.mu.Lock()
	refuse, legacy, bh, closed := l.refuse, l.legacy, l.blackhole, l.closed
	l.mu.Unlock()
	if refuse || closed {
		return nil, errors.New("link refused")
	}
	if bh {
		// a dead link: the stream "opens" (lazily, QUIC-style) but nothing
		// arrives; it stays open 20 s past the dial unless killed
		cc, far := net.Pipe()
		l.mu.Lock()
		l.deadOpens = append(l.deadOpens, cc, far)
		l.mu.Unlock()
		go func() { io.Copy(io.Discard, far) }()
		go func() {
			select {
			case <-ctx.Done():
				select {
				case <-time.After(20 * time.Second):
				case <-l.quit:
				}
			case <-l.quit:
			}
			far.Close()
		}()
		return cc, nil
	}
	clientEnd, a := net.Pipe()
	b, serverEnd := net.Pipe()
	c := &carrier{l: l, a: a, b: b}
	if len(hello) > 4 {
		c.kind.Store(int32(hello[4]))
	}
	l.mu.Lock()
	c.seq = len(l.history)
	l.history = append(l.history, c)
	l.carriers = append(l.carriers, c)
	l.mu.Unlock()
	go l.pump(c, a, b, true)
	go l.pump(c, b, a, false)
	switch {
	case legacy:
		go func() {
			buf := make([]byte, 64)
			serverEnd.Read(buf)
			serverEnd.Close()
		}()
	case hello != nil:
		go l.accept(&prefixed{Conn: serverEnd, head: hello})
	default:
		go l.accept(serverEnd)
	}
	return clientEnd, nil
}

type prefixed struct {
	net.Conn
	head []byte
}

func (c *prefixed) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// classify records the carrier's HELLO kind from the first client -> server
// bytes. It runs before those bytes are forwarded, and the server answers
// only after the HELLO crossed, so the kind is known before any
// server -> client byte is counted.
func (c *carrier) classify(p []byte) {
	if c.kind.Load() != 0 || len(c.head) >= 5 {
		return
	}
	c.head = append(c.head, p[:min(len(p), 5-len(c.head))]...)
	if len(c.head) == 5 {
		c.kind.Store(int32(c.head[4]))
	}
}

// pump forwards src→dst through a timed queue (latency without
// serialising throughput) and a token bucket. up: client -> server.
func (l *link) pump(c *carrier, src, dst net.Conn, up bool) {
	q := make(chan chunk, 4096)
	go func() {
		defer close(q)
		for {
			buf := make([]byte, 16<<10)
			n, err := src.Read(buf)
			if n > 0 {
				if up {
					c.classify(buf[:n])
				}
				l.mu.Lock()
				d := l.delay
				if l.jitter > 0 {
					d += time.Duration(rand.Int63n(int64(2*l.jitter))) - l.jitter
					if d < 0 {
						d = 0
					}
				}
				bh := l.blackhole
				l.mu.Unlock()
				if bh {
					l.count(c, func(k *counters) { k.dropped.Add(int64(n)) })
				} else {
					l.count(c, func(k *counters) {
						for {
							m := k.maxDelay.Load()
							if int64(d) <= m || k.maxDelay.CompareAndSwap(m, int64(d)) {
								break
							}
						}
					})
					q <- chunk{buf[:n], time.Now().Add(d)}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	var lastAt time.Time
	for ch := range q {
		at := ch.at
		if at.Before(lastAt) {
			at = lastAt // a byte stream never reorders
		}
		lastAt = at
		if w := time.Until(at); w > 0 {
			time.Sleep(w)
		}
		for counted := false; ; {
			l.mu.Lock()
			st := l.stalled
			l.mu.Unlock()
			if !st || c.closed.Load() {
				break
			}
			if !counted {
				l.count(c, func(k *counters) { k.held.Add(1) })
				c.held.Add(1)
				counted = true
			}
			time.Sleep(20 * time.Millisecond)
		}
		l.mu.Lock()
		rate, bh := l.rate, l.blackhole
		l.mu.Unlock()
		if bh {
			l.count(c, func(k *counters) { k.dropped.Add(int64(len(ch.b))) })
			continue
		}
		if rate > 0 {
			time.Sleep(time.Duration(float64(len(ch.b)) / rate * float64(time.Second)))
			l.throttled.Add(int64(len(ch.b)))
		}
		if len(ch.b) > 0 && c.corrupt.CompareAndSwap(true, false) {
			ch.b[len(ch.b)/2] ^= 0xFF
			l.count(c, func(k *counters) { k.corrupted.Add(1) })
		}
		if _, err := dst.Write(ch.b); err != nil {
			c.close()
			return
		}
		l.count(c, func(k *counters) { k.bytes.Add(int64(len(ch.b))) })
		if up {
			c.up.Add(int64(len(ch.b)))
		} else {
			c.down.Add(int64(len(ch.b)))
		}
	}
	c.close()
}

// ---------------------------------------------------------------- far end

// farEnd implements the server's target dialers in-process.
type farEnd struct {
	open        atomic.Int64 // stream targets the server has not closed yet
	packetDials atomic.Int64 // packet targets opened by the server
	sockets     atomic.Int64 // identity counter for packet targets
	quit        chan struct{}
	quitOnce    sync.Once
}

func newFarEnd() *farEnd { return &farEnd{quit: make(chan struct{})} }

func (fe *farEnd) close() { fe.quitOnce.Do(func() { close(fe.quit) }) }

const targetBuffer = 256 << 10

func (fe *farEnd) dialStream(ctx context.Context, addr string) (net.Conn, error) {
	kind, arg, _ := strings.Cut(addr, ":")
	var handler func(c *memConn)
	switch kind {
	case "echo":
		handler = func(c *memConn) {
			io.Copy(c, c)
			c.CloseWrite()
			io.Copy(io.Discard, c)
			c.Close()
		}
	case "gen":
		n, err := strconv.ParseInt(arg, 10, 64)
		if err != nil {
			return nil, err
		}
		handler = func(c *memConn) {
			go io.Copy(io.Discard, c)
			io.Copy(c, io.LimitReader(prng(7), n))
			c.Close()
		}
	case "stall":
		// reads until the client's FIN, then neither answers nor closes
		handler = func(c *memConn) {
			io.Copy(io.Discard, c)
			<-fe.quit
			c.Close()
		}
	case "unreachable":
		return nil, errors.New("connect: no route to host")
	default:
		return nil, fmt.Errorf("unknown target %q", addr)
	}
	exitEnd, farEnd := memPipe(targetBuffer, "exit", addr)
	fe.open.Add(1)
	exitEnd.onClose = func() { fe.open.Add(-1) }
	go handler(farEnd)
	return exitEnd, nil
}

// dialPacket: an in-memory UDP echo; "IDENTP" is answered with the identity
// of the target socket (proves the server kept one socket across path
// changes).
func (fe *farEnd) dialPacket(ctx context.Context, addr string) (net.Conn, error) {
	fe.packetDials.Add(1)
	id := fmt.Sprintf("sock-%d", fe.sockets.Add(1))
	exitEnd, farEnd := msgPipe(1024, id, addr)
	go func() {
		defer farEnd.Close()
		buf := make([]byte, 65535)
		for {
			n, err := farEnd.Read(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "IDENTP" {
				farEnd.Write([]byte("IDENTP " + id))
				continue
			}
			farEnd.Write(buf[:n])
		}
	}()
	go func() {
		select {
		case <-exitEnd.done: // the server dropped the socket
		case <-fe.quit:
		}
		exitEnd.Close()
		farEnd.Close()
	}()
	return exitEnd, nil
}

// waitFor polls cond until it holds or within passes; it reports the time
// taken and whether cond held.
func waitFor(within time.Duration, cond func() bool) (time.Duration, bool) {
	start := time.Now()
	for {
		if cond() {
			return time.Since(start), true
		}
		if time.Since(start) >= within {
			return time.Since(start), false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
