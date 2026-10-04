package scenario

// The test fixture is the only code in the tests that touches the rendr
// API (design §11.3). Tests dial through fixture.dial, read session state
// through the fixture's adapters, control carriers through *link and
// observe the far end through *farEnd. The test bodies are the M1a ones,
// unchanged; this file is their M1b backend.
//
// Each fixture has two Runtimes built by testhooks.NewRuntime with one
// Overrides value made from tun (counter presets and timings are identical
// on both ends, L14). The dialer has a Peer over every link and a second
// Peer whose factories use DialEarly (pipelined dials). The passive has one
// push-only Listener and every link's Accept is its Handle, so each carrier
// goes through the passive handshake and admission. A per-side limit
// (fixtureConfig.maxSessions) goes only into the passive's Config, never
// into the shared Overrides (design §10.5): MaxSessions counts both roles.
//
// Carriers: every Dial on a link creates a rendrtest.Link carrier whose two
// directions pass through pumps that add delay/jitter, cap bandwidth,
// blackhole (bytes vanish, nothing closes), stall (bytes held, not lost,
// like a QUIC path under 100% loss), kill (both ends closed, buffered bytes
// lost) or corrupt one chunk. Every control has a counter so a test can
// prove its stimulus happened. A Peer with two or more links keeps a probe
// carrier on every link, so stimulus proofs count session carriers only
// (linkStats.Session, carrierLog); a carrier is classified by its first
// frame after the PREFACE (OPEN or JOIN: session, PING: probe).
//
// Far end: an accept loop on the passive Listener routes every new session
// on its OPEN metadata (the target): echo, gen:N (N bytes of PRNG(7), then
// close) and stall (read until FIN, then hold the conn until teardown) run
// as rendrtest behaviours on the passive Conn; an unreachable target is
// rejected the way a relay reports a failed target dial. far.open counts
// the sessions the far end took and has not finished with (from Confirm to
// the end of the behaviour).
//
// The bodies run on real time, and in sequence they take about two minutes.
// Every fixture therefore runs its test in parallel with the others, at most
// parallelFixtures at once, except the tests in serialTests.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// ---------------------------------------------------------------- tunables

// tun holds the shortened time scales of the fixture (design §11.3); one
// Overrides value built from it configures both Runtimes. Everything else
// keeps its default (PingBusy 50 ms, JoinStagger 1 s, DialWait 800 ms,
// DialTimeout 10 s, no IdleTimeout).
var tun = struct {
	DeadMin, DeadMax, WriteStall, PingIdle   time.Duration
	ProbeInterval, ProbeFresh                time.Duration
	SelectorDwell, SelectorCooldown          time.Duration
	Orphan, RetireGrace, Linger, RetainSlack time.Duration // Orphan: NoPathGrace
}{
	DeadMin:          1 * time.Second,
	DeadMax:          2 * time.Second,
	WriteStall:       1 * time.Second,
	PingIdle:         500 * time.Millisecond,
	ProbeInterval:    200 * time.Millisecond,
	ProbeFresh:       2 * time.Second,
	SelectorDwell:    1 * time.Second,
	SelectorCooldown: 2 * time.Second,
	Orphan:           5 * time.Second,
	RetireGrace:      500 * time.Millisecond,
	Linger:           10 * time.Second,
	RetainSlack:      2 * time.Second,
}

// overrides is the testhooks value of both Runtimes of a fixture.
func overrides() testhooks.Overrides {
	return testhooks.Overrides{
		DeadMin:          tun.DeadMin,
		DeadMax:          tun.DeadMax,
		WriteStall:       tun.WriteStall,
		PingIdle:         tun.PingIdle,
		ProbeInterval:    tun.ProbeInterval,
		ProbeFresh:       tun.ProbeFresh,
		SelectorDwell:    tun.SelectorDwell,
		SelectorCooldown: tun.SelectorCooldown,
		NoPathGrace:      tun.Orphan,
		RetireGrace:      tun.RetireGrace,
		Linger:           tun.Linger,
		RetainSlack:      tun.RetainSlack,
	}
}

// quietLog: far-end diagnostics, printed only when RENDR_TEST_LOG is set.
func quietLog(format string, args ...any) {
	if os.Getenv("RENDR_TEST_LOG") != "" {
		log.Printf(format, args...)
	}
}

// ---------------------------------------------------------------- parallelism

// parallelFixtures bounds how many parallel tests hold a fixture at once,
// independent of GOMAXPROCS and -parallel: half the CPUs, at least 2 and at
// most 8, so that real-time timing noise stays low on small workers and the
// host stays lightly loaded.
var parallelFixtures = min(8, max(2, runtime.NumCPU()/2))

var fixtureSlots = make(chan struct{}, parallelFixtures)

// serialTests run alone (the parallel tests are paused in t.Parallel
// meanwhile, before their fixtures exist):
//   - TestHalfCloseAndCleanFinish compares the process's goroutine count
//     with a baseline settled before its fixture exists, so no other test
//     may run beside it;
//   - TestSelectorFailoverRacesPastStalledCandidate requires the initial
//     carrier on p1 (1 ms one way) rather than p2 (2 ms): Dial ranks by the
//     first probe sample of each path (plan §3.9), and beside other
//     fixtures under -race the scheduling noise of one real-time sample
//     exceeded that 2 ms RTT margin (once in three shuffled iterations).
var serialTests = map[string]bool{
	"TestHalfCloseAndCleanFinish":                   true,
	"TestSelectorFailoverRacesPastStalledCandidate": true,
}

// ---------------------------------------------------------------- fixture

type mode int

const (
	selector mode = iota + 1
	bond
)

func (m mode) rendrMode() rendr.Mode {
	if m == bond {
		return rendr.ModeBond
	}
	return rendr.ModeSelector
}

// target names a far-end behaviour; it travels as the OPEN metadata.
type target string

func echo() target            { return "echo:1" }
func gen(n int64) target      { return target(fmt.Sprintf("gen:%d", n)) }
func stall() target           { return "stall:1" }
func unreachable() target     { return "unreachable:1" }
func (t target) kind() string { k, _, _ := strings.Cut(string(t), ":"); return k }

type dialOpts struct {
	target      target
	grace       time.Duration // 0 = the fixture's NoPathGrace (tun.Orphan)
	pipelined   bool          // the PREFACE and OPEN travel in the carrier open request (DialEarly)
	noProbeWait bool          // accepted and ignored: Dial waits for probe samples only while probing cold-starts (≤ DialWait)
}

type fixtureConfig struct {
	links       []string
	maxSessions int // 0 = default; the passive Runtime's Config.MaxSessions only
}

type fixture struct {
	t         *testing.T
	dialer    *rendr.Runtime
	passive   *rendr.Runtime
	peer      *rendr.Peer // factories dial with Dial
	early     *rendr.Peer // factories dial with DialEarly (pipelined)
	links     []*link
	far       *farEnd
	closeOnce sync.Once
}

func newFixture(t *testing.T, names ...string) *fixture {
	return newFixtureCfg(t, fixtureConfig{links: names})
}

func newFixtureCfg(t *testing.T, cfg fixtureConfig) *fixture {
	t.Helper()
	if !serialTests[t.Name()] {
		t.Parallel()
		fixtureSlots <- struct{}{}
		t.Cleanup(func() { <-fixtureSlots }) // after f.close (cleanups run last-in first-out)
	}
	f := &fixture{t: t, far: newFarEnd()}
	t.Cleanup(f.close)
	ov := overrides()
	f.dialer = newRuntime(t, rendr.Config{}, &ov)
	f.passive = newRuntime(t, rendr.Config{MaxSessions: cfg.maxSessions}, &ov)
	ln, err := f.passive.Listen(rendr.ListenConfig{}) // push-only: carriers arrive through Handle
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	f.far.serve(ln)
	plain := make([]rendr.Carrier, len(cfg.links))
	early := make([]rendr.Carrier, len(cfg.links))
	for i, n := range cfg.links {
		l := &link{name: n, l: rendrtest.NewLink(rendrtest.LinkConfig{Name: n, Accept: ln.Handle})}
		f.links = append(f.links, l)
		plain[i] = rendr.StreamCarrier{Name: n, Dial: l.l.Dial}
		early[i] = rendr.StreamCarrier{Name: n, Dial: l.l.Dial, DialEarly: l.l.DialEarly}
	}
	// A Peer probes only once it is used, so the Peer a test does not dial
	// through adds no carriers.
	if f.peer, err = f.dialer.NewPeer(rendr.PeerConfig{Carriers: plain}); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if f.early, err = f.dialer.NewPeer(rendr.PeerConfig{Carriers: early}); err != nil {
		t.Fatalf("NewPeer (DialEarly): %v", err)
	}
	return f
}

// newRuntime builds a Runtime with the fixture's unclamped overrides.
func newRuntime(t *testing.T, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// close tears the fixture down (idempotent; also run by t.Cleanup): the far
// end releases its stalled behaviours, the dialer Runtime closes (its
// sessions are reset and its Peers stop probing), then the passive Runtime
// (its Listener closes, so the accept loop ends), then every link, which
// joins its pumps; finally the far end's goroutines are joined.
func (f *fixture) close() {
	f.closeOnce.Do(func() {
		f.far.stop()
		for _, rt := range []*rendr.Runtime{f.dialer, f.passive} {
			if rt != nil {
				rt.Close()
			}
		}
		for _, l := range f.links {
			l.l.Close()
		}
		if !f.far.wait(10 * time.Second) {
			f.t.Errorf("fixture: far-end goroutines still running 10 s after teardown")
		}
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

// dial opens one application connection over every link of the fixture.
func (f *fixture) dial(m mode, o dialOpts) (net.Conn, error) {
	if o.target == "" {
		o.target = echo()
	}
	p := f.peer
	if o.pipelined {
		p = f.early
	}
	c, err := p.Dial(context.Background(), rendr.DialOptions{
		Mode:        m.rendrMode(),
		Metadata:    []byte(o.target),
		NoPathGrace: o.grace,
	})
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

// activeCarrier is the selector's active carrier of c, as the session's
// scheduler published it (ok false if there is none).
func activeCarrier(c net.Conn) (rendr.CarrierStatus, bool) {
	for _, cs := range c.(*rendr.Conn).Status().Carriers {
		if cs.State == rendr.CarrierActive {
			return cs, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// activePath: the link name of the selector's active carrier ("" if none).
func activePath(c net.Conn) string {
	cs, _ := activeCarrier(c)
	return cs.Name
}

// activeSub: the selector's active carrier (ID 0 and "" if none).
func activeSub(c net.Conn) (uint32, string) {
	cs, ok := activeCarrier(c)
	if !ok {
		return 0, ""
	}
	return uint32(cs.ID), cs.Name
}

// sessionDonePoll and sessionDoneMax bound the Status poll that stands in
// for a Done channel.
const (
	sessionDonePoll = 10 * time.Millisecond
	sessionDoneMax  = time.Minute
)

// sessionDone is closed once the session has fully ended: the Conn's Done
// channel when it has one, else a Status poll until StateEnded. The poll
// ends at the latest with the fixture (Runtime.Close ends every session) and
// gives up after sessionDoneMax (the channel then never closes).
func sessionDone(c net.Conn) <-chan struct{} {
	if d, ok := c.(interface{ Done() <-chan struct{} }); ok {
		return d.Done()
	}
	rc := c.(*rendr.Conn)
	ch := make(chan struct{})
	go func() {
		deadline := time.Now().Add(sessionDoneMax)
		for rc.Status().State != rendr.StateEnded {
			if !time.Now().Before(deadline) {
				return
			}
			time.Sleep(sessionDonePoll)
		}
		close(ch)
	}()
	return ch
}

// serverSessions: sessions the passive Runtime still holds.
func (f *fixture) serverSessions() int {
	s := f.passive.Status().Sessions
	return s.Open + s.Pending + s.Lingering + s.Orphaned
}

// isTargetDialError: the far end refused the session (a target it could
// not reach).
func isTargetDialError(err error) bool {
	var re *rendr.RejectError
	return errors.As(err, &re)
}

// isBusy: the peer refused the session for capacity.
func isBusy(err error) bool { return errors.Is(err, rendr.ErrCapacity) }

// ---------------------------------------------------------------- links

// helloJoin is the carrierInfo.kind of a carrier whose first frame is a
// JOIN (a session carrier attached to an existing session).
const helloJoin = int32(wire.TypeJoin)

// faultCounts is what a set of carriers saw; tests use it to prove a
// stimulus.
type faultCounts struct {
	Killed    int64 // carriers closed by kill()
	Bytes     int64 // bytes the far ends read (both directions)
	Dropped   int64 // bytes discarded by the blackhole
	Held      int64 // chunks held back by a stall
	Corrupted int64 // chunks corrupted by corruptNext()
	MaxDelay  time.Duration
}

func faultCountsOf(c rendrtest.Counts) faultCounts {
	return faultCounts{Killed: c.Killed, Bytes: c.Bytes, Dropped: c.Dropped, Held: c.Held,
		Corrupted: c.Corrupted, MaxDelay: c.MaxDelay}
}

// linkStats: link-wide counters (session and probe carriers) and the same
// counters restricted to session carriers. A Peer with two or more links
// keeps a probe carrier on every link, so a link-wide counter can move
// without the fault ever touching a session: stimulus proofs must use
// Session.
type linkStats struct {
	faultCounts
	Session   faultCounts
	Throttled int64 // bytes passed through the rate limiter
}

// carrierInfo is a snapshot of one carrier for per-carrier assertions.
type carrierInfo struct {
	seq      int
	kind     int32 // the wire type of the carrier's first frame (0 until it crossed)
	up, down int64 // bytes the far end read in each direction
	held     int64 // chunks held by a stall
}

// link is a thin adapter over a rendrtest.Link (design §11.3, V12).
type link struct {
	name string
	l    *rendrtest.Link
}

// set configures one-way delay, jitter and a bandwidth cap (Mbit/s, 0 = none).
func (l *link) set(delay, jitter time.Duration, rateMbit float64) {
	l.l.SetDelay(delay, jitter)
	l.l.SetRate(rateMbit * 1e6 / 8)
}

// setRefuse: new carrier opens fail.
func (l *link) setRefuse(v bool) { l.l.SetRefuse(v) }

// setStall: bytes are held (not lost) until un-stalled.
func (l *link) setStall(v bool) { l.l.SetStall(v) }

// setBlackhole: bytes vanish; nothing closes.
func (l *link) setBlackhole(v bool) { l.l.SetBlackhole(v) }

// kill closes every current carrier of the link (both ends), including
// dials made while it was blackholed.
func (l *link) kill() { l.l.Kill() }

// corruptNext flips one byte in the next dialer-to-passive chunk of every
// current carrier.
func (l *link) corruptNext() { l.l.CorruptNext(rendrtest.Up) }

func (l *link) stats() linkStats {
	s := l.l.Stats()
	return linkStats{faultCounts: faultCountsOf(s.All), Session: faultCountsOf(s.Session), Throttled: s.Throttled}
}

// carrierLog lists every carrier the link created, in creation order.
func (l *link) carrierLog() []carrierInfo {
	cs := l.l.Carriers()
	out := make([]carrierInfo, len(cs))
	for i, c := range cs {
		out[i] = carrierInfo{seq: c.Seq, kind: int32(c.First), up: c.Up, down: c.Down, held: c.Held}
	}
	return out
}

// nextSeq is the seq the next carrier of the link will get.
func (l *link) nextSeq() int { return l.l.NextSeq() }

// ---------------------------------------------------------------- far end

// farEnd is the passive application: it accepts every session and runs the
// behaviour its target names on the passive Conn.
type farEnd struct {
	open     atomic.Int64  // sessions taken and not finished with (Confirm through the end of the behaviour)
	quit     chan struct{} // closed by stop: stalled behaviours let go
	stopOnce sync.Once
	wg       sync.WaitGroup // the accept loop and every session handler
}

func newFarEnd() *farEnd { return &farEnd{quit: make(chan struct{})} }

func (fe *farEnd) stop() { fe.stopOnce.Do(func() { close(fe.quit) }) }

// serve runs the accept loop until the Listener closes.
func (fe *farEnd) serve(ln *rendr.Listener) {
	fe.wg.Add(1)
	go func() {
		defer fe.wg.Done()
		for {
			pc, err := ln.Accept(context.Background())
			if err != nil {
				return // net.ErrClosed: the Listener closed with its Runtime
			}
			fe.wg.Add(1)
			go fe.handle(pc)
		}
	}()
}

// handle routes one pending session on its target: a reachable target is
// confirmed and its behaviour runs on the passive Conn; an unreachable one
// is rejected.
func (fe *farEnd) handle(pc *rendr.PendingConn) {
	defer fe.wg.Done()
	t := target(pc.Metadata())
	b, code, err := fe.behaviour(t)
	if err != nil {
		if rerr := pc.Reject(code, err.Error()); rerr != nil {
			quietLog("far end: reject %s: %v", t, rerr)
		}
		return
	}
	fe.open.Add(1)
	defer fe.open.Add(-1)
	c, err := pc.Confirm()
	if err != nil {
		quietLog("far end: confirm %s: %v", t, err)
		return
	}
	if err := b(c); err != nil {
		quietLog("far end: %s: %v", t, err)
	}
}

// behaviour maps a target to its behaviour, or to the reject code and
// message of a target the far end cannot serve.
func (fe *farEnd) behaviour(t target) (rendrtest.Behaviour, uint32, error) {
	_, arg, _ := strings.Cut(string(t), ":")
	switch t.kind() {
	case "echo":
		return rendrtest.Echo(), 0, nil
	case "gen":
		n, err := strconv.ParseInt(arg, 10, 64)
		if err != nil {
			return nil, 2, fmt.Errorf("bad target %q: %v", t, err)
		}
		return rendrtest.Gen(n, 7), 0, nil
	case "stall":
		return rendrtest.Stall(fe.quit), 0, nil
	case "unreachable":
		return nil, 1, errors.New("connect: no route to host")
	}
	return nil, 2, fmt.Errorf("unknown target %q", t)
}

// wait joins the accept loop and every handler; false if they are still
// running after within.
func (fe *farEnd) wait(within time.Duration) bool {
	done := make(chan struct{})
	go func() {
		fe.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(within)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
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
