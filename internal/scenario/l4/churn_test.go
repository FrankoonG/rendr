package l4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The L4 churn (M4 design §A12.2; G6-l4, L52, R1-3): every outcome class
// of a forwarded connection at once, with carrier kills, and nothing left
// behind.

const (
	churnSpan    = 60 * time.Second
	churnIdle    = 30 * time.Second // the ingress's session idle of the stall and noread classes (R1-3, R1-14)
	churnEcho    = 16 << 10
	churnRST     = 64 << 10
	churnKill    = 5 * time.Second
	churnDeadMax = 4 * time.Second // the zero Config's DeadMax
	churnWait    = 5 * time.Second // W: the settle window before the final Status checks
	churnRate    = 32 << 20        // each Link's rate per direction
	churnBuffer  = 2 << 20         // each Link's buffer per direction (the default)
	// churnRSTInFlight bounds how long the passive's RST of a reset
	// connection can still be on its way: the Link's full buffer at its
	// rate plus the one-way delay (72.5 ms), with room for the passive's
	// carrier writer queue.
	churnRSTInFlight = 250 * time.Millisecond
	// churnRSTLostMax caps the reset connections whose RST a kill took
	// down (see runRST): about one per run is observed.
	churnRSTLostMax = 5
	// churnStage is a live stream carrier's reader stage in BufferedBytes
	// (the Status doc: carrier.BigData plus the size class's slack).
	churnStage = carrier.BigData + carrier.ClassSlack
	// churnPoll is the step of the idle classes' progress poll.
	churnPoll = 10 * time.Millisecond
)

// churnMix is the class mix of TestL4ChurnNoLeak_L52 (2,000 connections).
var churnMix = []struct {
	class string
	n     int
}{
	{"refused", 200},  // 10 %: the target refuses: l4.Dial returns CodeRefused
	{"syn", 100},      // 5 %: a dropped SYN: CodeTimeout at the Server's 5-s dial budget
	{"dns", 100},      // 5 %: the name does not resolve: CodeDNSFailure
	{"rst", 100},      // 5 %: the target resets mid-response
	{"stall", 100},    // 5 %: through the ingress, the client CloseWrites, then Closes; the target stalls: stall-idle
	{"erefused", 100}, // 5 %: EarlyReturn through the ingress, refused: the refusal is the session's error
	{"noread", 100},   // 5 %: through the ingress with a 30-s idle; the target never reads: idle-released
	{"echo", 550},     // echo 16 KiB each way
	{"echoe", 550},    // the same with EarlyReturn
}

// churn is one run's state.
type churn struct {
	t     *testing.T
	w     *world
	peer  *rendr.Peer
	start time.Time

	echo, rst, stall, noread *rendrtest.Target
	stallSpy, noreadSpy      *spies
	refusedN, synN, dnsN     *rendrtest.DialCounts
	wg                       sync.WaitGroup
	mu                       sync.Mutex
	stallRel, noreadRel      []time.Duration
	rstLost                  int // rst connections whose RST a kill took down (ErrSessionLost)
	kills                    []churnKillRec
	earlyPending             int // EarlyReturn ingresses whose l4.Dial returned StatePending
	earlyFresh, earlyBytes   int // echoe sessions that used a fresh trunk (handle 1); of them, with EarlyBytes > 0
}

// churnKillRec is one Link kill of the churn.
type churnKillRec struct {
	name string
	at   time.Time
}

// TestL4ChurnNoLeak_L52 (G6-l4, L52): 2,000 L4 connections started over
// 60 virtual s (one every 30 ms, the classes interleaved) on one Peer of
// two factories p1, p2 (default Props: rendr mux; Window 256 KiB on both
// Runtimes so the never-reading class holds little), served by one
// l4.Server whose Dial hook routes by class (churnMix): 10 % refused, 5 %
// dropped SYN, 5 % DNS failure, 5 % reset mid-response, 5 % stall through
// the ingress (idle 30 s), 5 % EarlyReturn and refused, 5 % never-reading
// target (idle 30 s), the rest echo 16 KiB each way (half with
// EarlyReturn).
//
// Stimulus: a Link kill every 5 s (alternating p1, p2; a Link without an
// open session carrier at that instant gives its turn to the other), each
// ending a session carrier. Every EarlyReturn l4.Dial returns StatePending
// (the opening deferred to the first use); on these default Props most
// early sessions open on the mux fast path, where the OPEN carries no
// EARLY (M4-D17): EarlyBytes > 0 only on a session that used a fresh
// trunk of its own (handle 1).
//
// PASS: every designed outcome exact — refusals with their code (and the
// dropped SYN at the 5-s budget, + 1 s), resets mid-response as a reset at
// the client after a PRNG prefix and *AbortError{l4.AbortReset} from the
// peer (or, at most churnRSTLostMax times, ErrSessionLost from a JOIN's
// UNKNOWN_SESSION when a kill took the passive's RST down: see runRST),
// the stall and never-reading classes released at the idle limit (in
// [30 s − the poll step, 30 s + DeadMax + 1 s] after the session's last
// progress, ErrIdleTimeout at the ingress, *AbortError{AbortIdle} from the
// peer at the passive, the target reset once), every echo intact and
// clean; the Server's counters exactly the mix (confirmed, rejected per
// code, nothing unconfirmed, lost or panicked) and the targets' (accepted,
// reset, FIN, none open); W after the last connection with the Peer open,
// no session and BufferedBytes at most one reader stage per open carrier;
// after the Peer closed and W, no Server handler, hook call or live
// connection, no session and BufferedBytes == 0 on both Runtimes; nothing
// left after Runtime.Close (Status, the session registry, and no
// goroutine: the bubble ends only when every goroutine of it exited,
// synctest's AssertNoLeak).
func TestL4ChurnNoLeak_L52(t *testing.T) {
	synctest.Test(t, runChurn)
}

func runChurn(t *testing.T) {
	// Window 256 KiB (the fixture's zero Config otherwise): it bounds what
	// each never-reading connection holds (amendment to A12.2).
	cfg := rendr.Config{Window: 256 << 10}
	w := newWorld(t, worldOpts{dcfg: cfg, pcfg: cfg}, linkSpec{name: "p1", rate: churnRate, buffer: churnBuffer},
		linkSpec{name: "p2", rate: churnRate, buffer: churnBuffer})
	s := &churn{t: t, w: w, peer: w.peer("p1", "p2"), start: time.Now()}
	s.echo = w.target("echo", rendrtest.TargetEcho())
	w.handle("echoe", s.echo.Dial)
	s.rst = w.target("rst", rendrtest.TargetRSTAfter(churnRST))
	s.stall = w.target("stall", rendrtest.TargetStall())
	s.stallSpy = w.spied("stall", s.stall)
	s.noread = w.target("noread", rendrtest.TargetNoRead())
	s.noreadSpy = w.spied("noread", s.noread)
	s.refusedN = w.scripted("refused", rendrtest.OutcomeRefuse())
	w.handle("erefused", w.routes["refused"])
	s.synN = w.scripted("syn", rendrtest.OutcomeHang())
	s.dnsN = w.scripted("dns", rendrtest.OutcomeDNSFailure())

	var classes []string
	for _, m := range churnMix {
		for range m.n {
			classes = append(classes, m.class)
		}
	}
	// Interleave the classes (a fixed permutation: stride 7 over the list).
	var order []string
	for k := range 7 {
		for i := k; i < len(classes); i += 7 {
			order = append(order, classes[i])
		}
	}
	every := churnSpan / time.Duration(len(order))
	for i, class := range order {
		addr := fmt.Sprintf("%s-%d.test:80", class, i)
		s.wg.Go(func() {
			if pace(w.quit, s.start.Add(time.Duration(i)*every)) {
				s.run(class, addr, uint64(1000+i))
			}
		})
	}

	kills := 0
	for at := churnKill; at <= churnSpan; at += churnKill {
		sleepUntil(s.start.Add(at))
		name := [2]string{"p1", "p2"}[kills%2]
		if _, open := sessionCarriers(w.link(name)); open == 0 {
			name = [2]string{"p2", "p1"}[kills%2]
		}
		l := w.link(name)
		before := l.Stats().Session.Killed
		s.mu.Lock()
		s.kills = append(s.kills, churnKillRec{name: name, at: time.Now()})
		s.mu.Unlock()
		l.Kill()
		if l.Stats().Session.Killed == before {
			// Not Fatalf: the connections' goroutines must be joined first.
			t.Errorf("stimulus: the kill at +%v of %s ended no session carrier", at, name)
			break
		}
		kills++
	}
	s.wg.Wait()
	if t.Failed() {
		t.FailNow()
	}

	// The Server's account: exactly the mix.
	waitFor(t, 10*time.Second, "no Server handler, hook call or connection", func() bool {
		st := w.srv.Status()
		return st.Dialing == 0 && st.Live == 0 && st.Hooks == 0 && st.Abandoned == 0
	})
	st := w.srv.Status()
	const confirmed = 550 + 550 + 100 + 100 + 100
	if st.Confirmed != confirmed || st.Rejected != 500 || st.ByCode[l4.CodeRefused] != 300 || st.ByCode[l4.CodeTimeout] != 100 ||
		st.ByCode[l4.CodeDNSFailure] != 100 || len(st.ByCode) != 3 || st.Unconfirmed != 0 || st.Lost != 0 || st.Panics != 0 {
		t.Fatalf("Server %+v (by code %v); want %d confirmed, 300 CodeRefused, 100 CodeTimeout, 100 CodeDNSFailure and nothing else",
			plain(st), st.ByCode, confirmed)
	}
	for _, r := range []struct {
		name   string
		counts *rendrtest.DialCounts
		calls  int64
	}{{"refused", s.refusedN, 300}, {"syn", s.synN, 100}, {"dns", s.dnsN, 100}} {
		if r.counts.Calls() != r.calls || r.counts.Unclosed() != 0 {
			t.Fatalf("%s hook: %d calls, %d unclosed; want %d, 0", r.name, r.counts.Calls(), r.counts.Unclosed(), r.calls)
		}
	}
	// The targets: every connection accepted once and ended as its class
	// designs; none open.
	for _, r := range []struct {
		name                    string
		tg                      *rendrtest.Target
		accepted, rstIn, rstOut int
		finIn                   int // -1: not checked
	}{
		{"echo", s.echo, 1100, 0, 0, 1100},
		{"rst", s.rst, 100, 0, 100, -1},
		{"stall", s.stall, 100, 100, 0, 100},
		{"noread", s.noread, 100, 100, 0, -1},
	} {
		waitFor(t, 10*time.Second, r.name+" targets closed", func() bool { return r.tg.Counts().Open == 0 })
		c := r.tg.Counts()
		if c.Accepted != r.accepted || c.RSTIn != r.rstIn || c.RSTOut != r.rstOut || (r.finIn >= 0 && c.FINIn != r.finIn) {
			t.Fatalf("%s targets %+v; want %d accepted, %d reset in, %d reset out, %d FIN in, none open",
				r.name, totals(c), r.accepted, r.rstIn, r.rstOut, r.finIn)
		}
	}

	s.mu.Lock()
	rstLost, earlyPending := s.rstLost, s.earlyPending
	s.mu.Unlock()
	if rstLost > churnRSTLostMax {
		t.Fatalf("%d reset connections lost their RST with a killed carrier, want at most %d", rstLost, churnRSTLostMax)
	}
	if earlyPending != 550+100 {
		t.Fatalf("stimulus: %d EarlyReturn ingresses returned StatePending from l4.Dial, want all 650", earlyPending)
	}

	// W after the last connection with the Peer still open: no session, and
	// nothing buffered beyond the reader stages of the carriers still open
	// (its trunks and probes; one stage per live carrier and Runtime), so a
	// session buffer that only a carrier's teardown would release is caught
	// here.
	time.Sleep(churnWait)
	before := openCarriers(w)
	ds, ps := w.d.Status(), w.p.Status()
	open := max(before, openCarriers(w))
	for _, rs := range []rendr.Status{ds, ps} {
		sc := rs.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || rs.BufferedBytes > int64(open*churnStage) || rs.Handshakes != 0 || rs.Abandoned != 0 {
			t.Fatalf("Runtime %v after the churn and W with the Peer open (%d carriers open): %+v, want no session and BufferedBytes ≤ %d",
				rs.Instance, open, rs, open*churnStage)
		}
	}

	// After the Peer closed (its probes and trunks) and W: no session and
	// no buffered byte on either Runtime while they still run.
	for _, p := range w.peers {
		p.Close()
	}
	time.Sleep(churnWait)
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		rs := rt.Status()
		sc := rs.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || rs.BufferedBytes != 0 || rs.Handshakes != 0 || rs.Abandoned != 0 {
			t.Fatalf("Runtime %v after the churn and W: %+v, want no session and BufferedBytes 0", rt.InstanceID(), rs)
		}
	}
	s.mu.Lock()
	t.Logf("2,000 connections, %d kills in %v virtual; stall released %v–%v, noread %v–%v after the last progress; "+
		"%d resets lost with a killed carrier; EarlyReturn: %d pending at Dial, %d echoe sessions on a fresh trunk, %d with EarlyBytes; "+
		"with the Peer open: %d carriers, buffered %d and %d; Server %+v",
		kills, time.Since(s.start), minOf(s.stallRel), maxOf(s.stallRel), minOf(s.noreadRel), maxOf(s.noreadRel),
		s.rstLost, s.earlyPending, s.earlyFresh, s.earlyBytes, open, ds.BufferedBytes, ps.BufferedBytes, plain(st))
	s.mu.Unlock()
	w.noViolation()
	w.close()
}

// openCarriers counts the carriers of the world's Links still open.
func openCarriers(w *world) int {
	n := 0
	for _, l := range w.links {
		for _, c := range l.Carriers() {
			if !c.Closed {
				n++
			}
		}
	}
	return n
}

// sessionCarriers counts a Link's carriers that carried a session (their
// first frame after the PREFACE was an OPEN or a JOIN) and those of them
// still open.
func sessionCarriers(l *rendrtest.Link) (all, open int) {
	for _, c := range l.Carriers() {
		if c.Session {
			all++
			if !c.Closed {
				open++
			}
		}
	}
	return all, open
}

func minOf(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	m := ds[0]
	for _, d := range ds {
		m = min(m, d)
	}
	return m
}

func maxOf(ds []time.Duration) time.Duration {
	m := time.Duration(0)
	for _, d := range ds {
		m = max(m, d)
	}
	return m
}

// run runs one connection of class to addr and checks its outcome.
func (s *churn) run(class, addr string, seed uint64) {
	var err error
	switch class {
	case "echo", "echoe":
		err = s.runEcho(addr, seed, class == "echoe")
	case "refused":
		err = s.runRefused(addr, l4.CodeRefused)
	case "dns":
		err = s.runRefused(addr, l4.CodeDNSFailure)
	case "syn":
		start := time.Now()
		err = s.runRefused(addr, l4.CodeTimeout)
		if took := time.Since(start); err == nil && (took < l4.DefaultDialTimeout || took > l4.DefaultDialTimeout+time.Second) {
			err = fmt.Errorf("CodeTimeout after %v, want the dial budget %v (+ 1 s)", took, l4.DefaultDialTimeout)
		}
	case "rst":
		err = s.runRST(addr)
	case "stall":
		err = s.runStall(addr)
	case "erefused":
		err = s.runEarlyRefused(addr)
	case "noread":
		err = s.runNoRead(addr)
	default:
		err = fmt.Errorf("no class %q", class)
	}
	if err != nil {
		s.t.Errorf("%s: %v", addr, err)
	}
}

// runEcho: 16 KiB of PRNG(seed) each way with a half-close through an
// ingress Forward; early: EarlyReturn. Stimulus of the early half: l4.Dial
// returned StatePending (the opening deferred to the first use; without
// EarlyReturn it returns StateOpen), and early bytes only on a session that
// opened on a fresh trunk of its own (handle 1): on the mux fast path the
// OPEN carries no EARLY (M4-D17), so EarlyBytes stays 0 there.
func (s *churn) runEcho(addr string, seed uint64, early bool) error {
	in, err := s.w.ingress(s.peer, addr, rendr.DialOptions{EarlyReturn: early}, 0)
	if err != nil {
		return fmt.Errorf("ingress: %w", err)
	}
	defer in.cli.Close()
	if want := map[bool]rendr.State{false: rendr.StateOpen, true: rendr.StatePending}[early]; in.dialed != want {
		return fmt.Errorf("stimulus: l4.Dial (EarlyReturn %v) returned a Conn in state %v, want %v", early, in.dialed, want)
	}
	if early {
		s.mu.Lock()
		s.earlyPending++
		s.mu.Unlock()
	}
	rx := startReceiver(in.cli, seed, churnEcho)
	tx := startSender(in.cli, in.quit, seed, churnEcho, churnEcho, 0, in.cli.CloseWrite)
	if err := tx.check(2 * time.Minute); err != nil {
		return err
	}
	if err := rx.check(2 * time.Minute); err != nil {
		return err
	}
	res, err := in.result(time.Minute)
	if err != nil {
		return err
	}
	if !res.Clean || res.ToSession != churnEcho || res.ToLocal != churnEcho {
		return fmt.Errorf("ingress Forward %+v, want a clean end with %d bytes each way", res, churnEcho)
	}
	st := in.c.Status()
	fresh := false
	for _, cs := range st.Carriers {
		fresh = fresh || cs.Handle == 1
	}
	switch {
	case !early && st.EarlyBytes != 0:
		return fmt.Errorf("EarlyBytes %d without EarlyReturn", st.EarlyBytes)
	case st.EarlyBytes > churnEcho:
		return fmt.Errorf("EarlyBytes %d, more than the %d bytes written", st.EarlyBytes, churnEcho)
	case st.EarlyBytes > 0 && !fresh:
		return fmt.Errorf("EarlyBytes %d on a session that only used shared trunks (M4-D17: no EARLY on the fast path): %+v", st.EarlyBytes, st.Carriers)
	}
	if early && fresh {
		s.mu.Lock()
		s.earlyFresh++
		if st.EarlyBytes > 0 {
			s.earlyBytes++
		}
		s.mu.Unlock()
	}
	return nil
}

// runRefused: l4.Dial returns the refusal code.
func (s *churn) runRefused(addr string, code l4.RejectCode) error {
	c, err := l4.Dial(context.Background(), s.peer, addr, rendr.DialOptions{})
	if c != nil {
		c.Close()
	}
	return checkRejectKilled(err, code)
}

// runRST: the target resets after 64 KiB: the client reads a PRNG(0)
// prefix, then a reset — never io.EOF.
func (s *churn) runRST(addr string) error {
	in, err := s.w.ingress(s.peer, addr, rendr.DialOptions{}, 0)
	if err != nil {
		return fmt.Errorf("ingress: %w", err)
	}
	defer in.cli.Close()
	tx := startSender(in.cli, in.quit, 3, 1<<10, 1<<10, 0, nil)
	rx := startReceiver(in.cli, 0, churnRST)
	// The request races the target's response and reset: a Write after the
	// reset reached the client fails with it.
	if err := tx.check(time.Minute); err != nil && !isReset(err) {
		return err
	}
	select {
	case <-rx.done:
	case <-time.After(time.Minute):
		return fmt.Errorf("the client's reads did not end: %d bytes", rx.got.Load())
	}
	if rx.bad || !isReset(rx.readErr) || rx.got.Load() > churnRST {
		return fmt.Errorf("the client read %d bytes (a PRNG(0) prefix: %v), ended by %v; want at most %d, then a reset", rx.got.Load(), !rx.bad, rx.readErr, churnRST)
	}
	res, err := in.result(time.Minute)
	if err != nil {
		return err
	}
	if code, remote, ok := abortOf(res.SessionErr); !res.Clean && ok && code == l4.AbortReset && remote {
		return nil
	}
	// The passive's RST travels once, on the carrier the session had then.
	// When a kill takes it down with that carrier, the dialer's JOIN finds
	// the passive's tombstone and the session is lost (plan §5:
	// UNKNOWN_SESSION → ErrSessionLost); the client still sees a reset.
	// This outcome is accepted only with that exact mechanism (and capped
	// in the run; open item: whether an RST must survive a carrier death).
	if !res.Clean && errors.Is(res.SessionErr, rendr.ErrSessionLost) {
		if err := s.rstLostByKill(in, res.SessionErr); err != nil {
			return fmt.Errorf("ingress Forward %+v, want the peer's *AbortError{l4.AbortReset}; ErrSessionLost without its RST lost to a kill: %v", res, err)
		}
		s.mu.Lock()
		s.rstLost++
		s.mu.Unlock()
		return nil
	}
	return fmt.Errorf("ingress Forward %+v, want the peer's *AbortError{l4.AbortReset}", res)
}

// rstLostByKill is nil when a reset connection's session was lost because
// a kill took the passive's RST down: the dialer's error is the JOIN's
// UNKNOWN_SESSION answer; the passive ended locally (its Forward's
// Conn.Abort: net.ErrClosed) at pe; a Link was killed at k within
// churnRSTInFlight after pe (the RST still on its way); and the dialer's
// session lost a carrier of that Link to the kill (transport_error, at or
// after k).
func (s *churn) rstLostByKill(in *ingress, serr error) error {
	if !strings.Contains(serr.Error(), "UNKNOWN_SESSION") {
		return fmt.Errorf("the loss %q is not a JOIN's UNKNOWN_SESSION answer", serr)
	}
	id := in.c.ID()
	var pe rendr.Event
	if !eventually(time.Second, func() bool { var ok bool; pe, ok = endOf(s.w.pev, id); return ok }) {
		return errors.New("no passive EventSessionEnd")
	}
	if _, _, remote := abortOf(pe.Err); remote || !errors.Is(pe.Err, net.ErrClosed) {
		return fmt.Errorf("the passive ended with %v, want its own Abort (net.ErrClosed)", pe.Err)
	}
	st := in.c.Status()
	s.mu.Lock()
	kills := slices.Clone(s.kills)
	s.mu.Unlock()
	for _, k := range kills {
		if k.at.Before(pe.Time) || k.at.Sub(pe.Time) > churnRSTInFlight {
			continue
		}
		for _, ev := range s.w.dev.of(rendr.EventCarrierDown) {
			if ev.Session != id || ev.Cause != rendr.CauseTransportError || ev.Time.Before(k.at) {
				continue
			}
			if cs, ok := carrierOf(st, ev.Carrier); ok && cs.Name == k.name {
				return nil
			}
		}
		return fmt.Errorf("the kill of %s at +%v (%v after the passive's end) took down no carrier of the session: %+v",
			k.name, k.at.Sub(s.start), k.at.Sub(pe.Time), st.Carriers)
	}
	return fmt.Errorf("no kill within %v after the passive's end at +%v", churnRSTInFlight, pe.Time.Sub(s.start))
}

// runStall (R1-3): the client writes 1 KiB, half-closes, and Closes 1 s
// later (unobservable); the target stalls: released at the idle limit
// counted from the session's last progress, the acknowledgement of the
// request (the idle clock's last sBase advance; a later acknowledgement of
// the FIN can only move it later), observed by a 1-ms poll.
func (s *churn) runStall(addr string) error {
	in, err := s.w.ingress(s.peer, addr, rendr.DialOptions{}, churnIdle)
	if err != nil {
		return fmt.Errorf("ingress: %w", err)
	}
	if err := writePRNG(in.cli, 6, 1<<10); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := in.cli.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	if !eventually(10*time.Second, func() bool { st := in.c.Status(); return st.TxBytes == 1<<10 && st.AckedBytes == 1<<10 }) {
		return fmt.Errorf("the request was not acknowledged within 10 s: %+v", in.c.Status())
	}
	quiet := time.Now()
	time.Sleep(time.Second) // the FIN and its ACK cross
	in.cli.Close()          // unobservable: nothing unread, the FIN already sent
	res, err := in.result(churnIdle + time.Minute)
	if err != nil {
		return err
	}
	released := time.Since(quiet)
	if !errors.Is(res.SessionErr, rendr.ErrIdleTimeout) || res.Clean {
		return fmt.Errorf("ingress Forward %+v, want ErrIdleTimeout", res)
	}
	if err := s.idleReleased(s.stallSpy, in, quiet, released, time.Millisecond); err != nil {
		return err
	}
	s.mu.Lock()
	s.stallRel = append(s.stallRel, released)
	s.mu.Unlock()
	return nil
}

// idleReleased checks a release at the idle limit after the last progress
// at quiet (observed by a poll of step poll: the true instant is at most
// one step earlier), the passive's end by the dialer's RST(Idle) (R1-3
// rule 2: *AbortError{AbortIdle} from the peer), and the target's one
// reset in the same window.
func (s *churn) idleReleased(sp *spies, in *ingress, quiet time.Time, released, poll time.Duration) error {
	lo, hi := churnIdle-poll, churnIdle+churnDeadMax+time.Second
	if released < lo || released > hi {
		return fmt.Errorf("released %v after the last progress, want the idle limit %v (- %v, + DeadMax + 1 s)", released, churnIdle, poll)
	}
	var pe rendr.Event
	if !eventually(time.Second, func() bool { var ok bool; pe, ok = endOf(s.w.pev, in.c.ID()); return ok }) {
		return errors.New("the passive session did not end within 1 s of the dialer's")
	}
	if code, remote, ok := abortOf(pe.Err); !ok || !remote || code != rendr.AbortIdle {
		return fmt.Errorf("the passive ended with %v, want the peer's *AbortError{AbortIdle}", pe.Err)
	}
	spy := sp.of(in.addr)
	if spy == nil {
		return errors.New("no target connection")
	}
	if !eventually(time.Second, func() bool { _, _, closes, _ := spy.state(); return closes > 0 }) {
		return errors.New("the target connection was not closed within 1 s of the session's end")
	}
	_, at, closes, reset := spy.state()
	if el := at.Sub(quiet); closes != 1 || !reset || el < lo || el > hi+time.Second {
		return fmt.Errorf("target closed %d times (reset %v) %v after the last progress; want one reset at the idle limit", closes, reset, el)
	}
	return nil
}

// runEarlyRefused: EarlyReturn through the ingress; the target refuses:
// the client's 1-KiB request is accepted at once, the session's refusal
// (CodeRefused) is the ingress Forward's session error, and the client
// sees a reset — never io.EOF.
func (s *churn) runEarlyRefused(addr string) error {
	in, err := s.w.ingress(s.peer, addr, rendr.DialOptions{EarlyReturn: true}, 0)
	if err != nil {
		return fmt.Errorf("ingress (EarlyReturn): %w", err)
	}
	defer in.cli.Close()
	if in.dialed != rendr.StatePending {
		return fmt.Errorf("stimulus: l4.Dial with EarlyReturn returned a Conn in state %v, want StatePending", in.dialed)
	}
	s.mu.Lock()
	s.earlyPending++
	s.mu.Unlock()
	if err := writePRNG(in.cli, 5, 1<<10); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	n, rerr := in.cli.Read(make([]byte, 1))
	if n != 0 || !isReset(rerr) {
		return fmt.Errorf("the client's Read returned (%d, %v), want a reset", n, rerr)
	}
	res, err := in.result(time.Minute)
	if err != nil {
		return err
	}
	if res.Clean {
		return fmt.Errorf("ingress Forward %+v, want the refusal", res)
	}
	return checkRejectKilled(res.SessionErr, l4.CodeRefused)
}

// runNoRead: the target never reads; the client writes until its Writes
// stop; the session idles out 30 s after its last progress and both
// sockets are reset. The last progress is the last change of the dialer's
// TxBytes (a Write commit) or AckedBytes (a delivery acknowledged),
// observed by a poll every churnPoll.
func (s *churn) runNoRead(addr string) error {
	in, err := s.w.ingress(s.peer, addr, rendr.DialOptions{}, churnIdle)
	if err != nil {
		return fmt.Errorf("ingress: %w", err)
	}
	defer in.cli.Close()
	last := time.Now()
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		var tx, acked uint64
		for {
			st := in.c.Status()
			if st.TxBytes != tx || st.AckedBytes != acked {
				tx, acked, last = st.TxBytes, st.AckedBytes, time.Now()
			}
			if st.State == rendr.StateEnded {
				return
			}
			time.Sleep(churnPoll)
		}
	}()
	var wrote int64
	buf := make([]byte, 4<<10)
	src := rendrtest.PRNG(8)
	for {
		src.Read(buf)
		k, err := in.cli.Write(buf)
		wrote += int64(k)
		if err != nil {
			if !isReset(err) {
				<-polled
				return fmt.Errorf("the client's Write ended with %v, want a reset", err)
			}
			break
		}
	}
	<-polled
	released := time.Since(last)
	if moved := in.c.Status().TxBytes; moved == 0 || wrote < 256<<10 {
		return fmt.Errorf("load: the client wrote %d bytes, the dialer accepted %d", wrote, moved)
	}
	res, err := in.result(time.Minute)
	if err != nil {
		return err
	}
	if !errors.Is(res.SessionErr, rendr.ErrIdleTimeout) || res.Clean {
		return fmt.Errorf("ingress Forward %+v, want ErrIdleTimeout", res)
	}
	if err := s.idleReleased(s.noreadSpy, in, last, released, churnPoll); err != nil {
		return err
	}
	s.mu.Lock()
	s.noreadRel = append(s.noreadRel, released)
	s.mu.Unlock()
	return nil
}

// writePRNG writes n bytes of PRNG(seed) to wr in one Write.
func writePRNG(wr io.Writer, seed uint64, n int) error {
	b := make([]byte, n)
	rendrtest.PRNG(seed).Read(b)
	_, err := wr.Write(b)
	return err
}

// TestL4RuntimeCloseMidTransfer (L52): 50 forwarded echo connections on
// one Peer of two factories, each sending 8 MiB paced over 60 s (and
// verifying the echo) when the passive Runtime is closed 2 s in.
//
// Stimulus/load: before the Close every connection has moved bytes both
// ways (the client read part of its echo; the target read from it).
//
// PASS: every client's Read ends with a reset — never io.EOF — after an
// intact prefix of its echo, and its next Write fails with a reset; every
// ingress Forward ends uncleanly with a session error; every target
// connection is reset (RSTIn == 50) and none is open; Serve returns
// net.ErrClosed; nothing left after Runtime.Close of the dialer.
func TestL4RuntimeCloseMidTransfer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n, size, span = 50, 8 << 20, 60 * time.Second
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", rate: 32 << 20}, linkSpec{name: "p2", rate: 32 << 20})
		peer := w.peer("p1", "p2")
		echo := w.target("echo", rendrtest.TargetEcho())
		var es []*echoConn
		for i := range n {
			in := w.mustIngress(peer, fmt.Sprintf("echo-%d.test:80", i), rendr.DialOptions{}, 0)
			es = append(es, startEcho(in, rendr.ModeSelector, uint64(300+i), size, span))
		}
		time.Sleep(2 * time.Second)
		for i, e := range es {
			if e.rx.got.Load() == 0 {
				t.Fatalf("load: connection %d read no echo byte before the Close", i)
			}
		}
		if c := echo.Counts(); c.Accepted != n || c.Open != n || c.BytesIn == 0 {
			t.Fatalf("load: target %+v before the Close, want %d open connections that read", totals(c), n)
		}
		w.p.Close()
		for i, e := range es {
			select {
			case <-e.rx.done:
			case <-time.After(time.Minute):
				t.Fatalf("connection %d: the client's reads did not end after Runtime.Close", i)
			}
			if e.rx.bad || !isReset(e.rx.readErr) {
				t.Fatalf("connection %d: the client's Read ended with %v after %d intact bytes (bad %v), want a reset, never io.EOF",
					i, e.rx.readErr, e.rx.got.Load(), e.rx.bad)
			}
			if err := e.tx.check(time.Minute); !isReset(err) {
				t.Fatalf("connection %d: the client's Writes ended with %v, want a reset", i, err)
			}
			res, err := e.in.result(time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if res.Clean || res.SessionErr == nil {
				t.Fatalf("connection %d: ingress Forward %+v, want an unclean end with a session error", i, res)
			}
		}
		waitFor(t, 10*time.Second, "every target connection closed", func() bool { return echo.Counts().Open == 0 })
		if c := echo.Counts(); c.RSTIn != n || c.FINIn != 0 {
			t.Fatalf("target %+v after Runtime.Close, want %d connections reset and no FIN", totals(c), n)
		}
		for _, e := range es {
			e.in.cli.Close()
		}
		w.close()
	})
}
