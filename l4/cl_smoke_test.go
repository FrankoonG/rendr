package l4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The checkpoint C-L smoke (M4 design §A15.3 row I1, R1-3, R1-22): 500 L4
// connections between two Runtimes over two rendrtest Links in one
// synctest bubble, served by an l4.Server whose Dial hook picks a target by
// the connection's class, while the Link carrying the data is killed
// every 10 s. TestL4Smoke_CL is the row; the SOCKS5 half of the smoke is
// examples/socks5's TestSocks5Smoke_CL.
//
// Classes (the address's first label names the class and the index):
//
//   - echo (190): through an ingress Forward; 16 KiB each way, half-close,
//     the echo intact up to io.EOF, both Forwards clean.
//   - gen (96): through an ingress Forward; the client half-closes at once
//     and reads 128 KiB of PRNG(7) up to io.EOF.
//   - bulk (4): gen of 32 MiB (16 MiB under -race) started 0.5 s before
//     each kill: the kill lands mid-transfer (the stimulus proof) and the
//     client still reads every byte up to io.EOF; the session counts a
//     death migration.
//   - refused (40): the hook refuses (ECONNREFUSED): l4.Dial returns the
//     refusal CodeRefused.
//   - syn (30): the hook hangs (a dropped SYN): l4.Dial returns CodeTimeout
//     at the Server's 5-s dial budget.
//   - linger (40): the l4.Dial Conn held directly writes a 1-KiB request,
//     half-closes, and Closes 2.5 s later; the target stalls. The target is
//     reset Linger + one one-way delay after the Close (± 2 ms, R1-22) and
//     the dialer session ends Linger after it.
//   - idle (40): through an ingress Forward whose session idles out at 30 s
//     (R1-3); the client writes 1 KiB, half-closes, and Closes 1 s later
//     (unobservable); the target stalls. The dialer ends ErrIdleTimeout and
//     the target is reset at the idle limit (−1 s, + DeadMax + 1 s) after
//     the last byte, not earlier.
//   - rst (40): through an ingress Forward; the target resets after 64 KiB
//     (mid-response): the client reads a PRNG(0) prefix, then a reset, never
//     io.EOF.
//   - noread (10): through an ingress Forward with a 30-s idle; the target
//     never reads: the client's Writes stop, the session idles out, and both
//     sockets are reset.
//   - live (10): echo connections still open at the end; Runtime.Close of
//     the passive resets every one of them (never io.EOF) and their targets.
//
// After the run nothing is left: no Server handler, hook call or target
// connection, no session or buffered byte in either Runtime, the session
// registry back at its start (R1-24), and no goroutine (the bubble ends
// only when every goroutine of it exited).
func TestL4Smoke_CL(t *testing.T) {
	synctest.Test(t, runL4Smoke)
}

// clKills are the instants (from the start) of the Link kills.
var clKills = []time.Duration{5 * time.Second, 15 * time.Second, 25 * time.Second, 35 * time.Second}

// clQuiet is the window in which no connection of the spread classes
// starts, so the linger class's RST frames (sent at 18.5–19.3 s) do not
// queue behind other traffic on the shared trunk.
var clQuiet = [2]time.Duration{17 * time.Second, 20 * time.Second}

// clSmoke is one run's state.
type clSmoke struct {
	t     *testing.T
	w     *world
	start time.Time

	echo, gen, bulk, stall, idle, rst, noread, live *rendrtest.Target
	refuse, hang                                    func(context.Context, string) (net.Conn, error)
	refuseN, hangN                                  *rendrtest.DialCounts

	mu    sync.Mutex
	spies map[string]*spyConn // the target conns of the linger, idle and noread classes, by address

	wg       sync.WaitGroup
	bulkRead [4]atomic.Int64 // bytes the bulk clients read so far
	bulkConn [4]atomic.Pointer[rendr.Conn]
}

// hook is the Server's Dial hook: the class is the address's first label
// up to its '-'.
func (s *clSmoke) hook(ctx context.Context, r Request) (net.Conn, error) {
	class, _, _ := strings.Cut(r.Addr, "-")
	var tg *rendrtest.Target
	spy := false
	switch class {
	case "echo":
		tg = s.echo
	case "gen":
		tg = s.gen
	case "bulk":
		tg = s.bulk
	case "linger":
		tg, spy = s.stall, true
	case "idle":
		tg, spy = s.idle, true
	case "rst":
		tg = s.rst
	case "noread":
		tg, spy = s.noread, true
	case "live":
		tg = s.live
	case "refused":
		return s.refuse(ctx, r.Addr)
	case "syn":
		return s.hang(ctx, r.Addr)
	default:
		return nil, fmt.Errorf("smoke: no class for %q", r.Addr)
	}
	c, err := tg.Dial(ctx, r.Addr)
	if err != nil || !spy {
		return c, err
	}
	sp := &spyConn{Conn: c}
	s.mu.Lock()
	s.spies[r.Addr] = sp
	s.mu.Unlock()
	return fullSpy{sp}, nil
}

// spy returns the recorded target conn of addr.
func (s *clSmoke) spy(addr string) *spyConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spies[addr]
}

// ingress dials addr and starts the dialer side's Forward over a TargetPipe;
// it returns the client end, the Conn and Forward's result. idle > 0 sets
// the session's idle limit.
func (s *clSmoke) ingress(addr string, idle time.Duration) (*rendrtest.TargetConn, *rendr.Conn, <-chan ForwardResult, error) {
	c, err := Dial(context.Background(), s.w.peer, addr, rendr.DialOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	if idle > 0 {
		if err := c.SetIdleTimeout(idle); err != nil {
			return nil, nil, nil, err
		}
	}
	cli, srv := rendrtest.TargetPipe(0)
	return cli, c, forwardAsync(context.Background(), c, srv), nil
}

// at sleeps until d after the start.
func (s *clSmoke) at(d time.Duration) {
	if w := time.Until(s.start.Add(d)); w > 0 {
		time.Sleep(w)
	}
}

// launch runs f on its own goroutine at d after the start.
func (s *clSmoke) launch(d time.Duration, f func()) {
	s.wg.Go(func() {
		s.at(d)
		f()
	})
}

const (
	clEchoN   = 16 << 10
	clGenN    = 128 << 10
	clGenSeed = 7
	clRSTN    = 64 << 10
	clIdle    = 30 * time.Second
	clLinger  = 10 * time.Second // the kit's Linger
)

func runL4Smoke(t *testing.T) {
	live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
	bulkN := int64(32 << 20)
	if raceEnabled {
		bulkN = 16 << 20 // the same timeline: the kill still lands mid-transfer
	}
	s := &clSmoke{t: t, start: time.Now(), spies: make(map[string]*spyConn)}
	s.w = newSrvWorld(t, srvOpts{worldOpts: worldOpts{links: 2, window: 1 << 20, n: 500, rate: 16 << 20}})
	s.echo = rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
	s.gen = rendrtest.NewTarget(rendrtest.TargetGen(clGenN, clGenSeed), 0)
	s.bulk = rendrtest.NewTarget(rendrtest.TargetGen(bulkN, 5), 0)
	s.stall = rendrtest.NewTarget(rendrtest.TargetStall(), 0)
	s.idle = rendrtest.NewTarget(rendrtest.TargetStall(), 0)
	s.rst = rendrtest.NewTarget(rendrtest.TargetRSTAfter(clRSTN), 0)
	s.noread = rendrtest.NewTarget(rendrtest.TargetNoRead(), 0)
	s.live = rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
	s.refuse, s.refuseN = rendrtest.ScriptedDial(rendrtest.OutcomeRefuse())
	s.hang, s.hangN = rendrtest.ScriptedDial(rendrtest.OutcomeHang())
	srv := &Server{Dial: s.hook}
	sv := serve(s.w, srv)

	// The spread classes, one start every 80 ms outside the quiet window.
	var spread []string
	for range 190 {
		spread = append(spread, "echo")
	}
	for range 96 {
		spread = append(spread, "gen")
	}
	for range 40 {
		spread = append(spread, "rst", "refused")
	}
	for range 30 {
		spread = append(spread, "syn")
	}
	// Interleave the classes (a fixed permutation: stride 7 over the list).
	order := make([]string, 0, len(spread))
	for k := range 7 {
		for i := k; i < len(spread); i += 7 {
			order = append(order, spread[i])
		}
	}
	when := time.Duration(0)
	for i, class := range order {
		if when >= clQuiet[0] && when < clQuiet[1] {
			when = clQuiet[1]
		}
		addr := fmt.Sprintf("%s-%d.test:80", class, i)
		switch class {
		case "echo":
			s.launch(when, func() { s.runEcho(addr, uint64(100+i)) })
		case "gen":
			s.launch(when, func() { s.runGen(addr) })
		case "rst":
			s.launch(when, func() { s.runRST(addr) })
		case "refused":
			s.launch(when, func() { s.runRefused(addr) })
		case "syn":
			s.launch(when, func() { s.runSyn(addr) })
		}
		when += 80 * time.Millisecond
	}
	for k, kill := range clKills {
		s.launch(kill-500*time.Millisecond, func() { s.runBulk(k, bulkN) })
	}
	for j := range 40 {
		s.launch(6*time.Second+time.Duration(j)*20*time.Millisecond, func() { s.runLinger(fmt.Sprintf("linger-%d.test:80", j)) })
		s.launch(2*time.Second+time.Duration(j)*50*time.Millisecond, func() { s.runIdle(fmt.Sprintf("idle-%d.test:80", j)) })
	}
	for j := range 10 {
		s.launch(10*time.Second+time.Duration(j)*50*time.Millisecond, func() { s.runNoRead(fmt.Sprintf("noread-%d.test:80", j)) })
	}
	type liveConn struct {
		cli *rendrtest.TargetConn
		res <-chan ForwardResult
	}
	lives := make([]liveConn, 10)
	for j := range lives {
		s.launch(38*time.Second+time.Duration(j)*20*time.Millisecond, func() {
			cli, _, res, err := s.ingress(fmt.Sprintf("live-%d.test:80", j), 0)
			if err != nil {
				t.Errorf("live %d: Dial: %v", j, err)
				return
			}
			if err := writePRNG(cli, 9, 4<<10); err != nil {
				t.Errorf("live %d: write: %v", j, err)
			}
			buf := make([]byte, 4<<10)
			if _, err := io.ReadFull(cli, buf); err != nil {
				t.Errorf("live %d: echo: %v", j, err)
			}
			lives[j] = liveConn{cli, res}
		})
	}

	// The kills: the Link carrying bulk session k, while it is mid-transfer.
	for k, kill := range clKills {
		s.at(kill)
		c := s.bulkConn[k].Load()
		if c == nil {
			t.Fatalf("kill %d: the bulk session is not open", k)
		}
		if got := s.bulkRead[k].Load(); got == 0 || got >= bulkN {
			t.Fatalf("stimulus: kill %d: the bulk client read %d of %d bytes, want it mid-transfer", k, got, bulkN)
		}
		l := s.w.activeLink(c)
		if l == nil {
			t.Fatalf("kill %d: no active carrier: %+v", k, c.Status())
		}
		if l.Kill() == 0 {
			t.Fatalf("stimulus: kill %d of link %s ended no carrier", k, l.Name())
		}
	}
	s.wg.Wait() // every class's connection has ended (the live ones are held)

	// Runtime.Close of the passive: every live connection is reset, never
	// io.EOF, and so is every live target; Serve returns.
	if st := srv.Status(); st.Live != 10 {
		t.Fatalf("before Runtime.Close: %d live connections, want 10: %+v", st.Live, st)
	}
	s.w.p.Close()
	for j, lc := range lives {
		if lc.cli == nil {
			continue
		}
		if _, err := lc.cli.Read(make([]byte, 1)); !isReset(err) {
			t.Errorf("live %d: client Read after Runtime.Close: %v, want a reset", j, err)
		}
		if r := <-lc.res; r.Clean || r.SessionErr == nil {
			t.Errorf("live %d: ingress Forward %+v, want an unclean end", j, r)
		}
		lc.cli.Close()
	}
	if err := sv.wait(t, time.Minute); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve returned %v, want net.ErrClosed", err)
	}
	synctest.Wait() // the targets' behaviours notice their resets and close
	if c := s.live.Counts(); c.Accepted != 10 || c.RSTIn != 10 || c.FINIn != 0 {
		t.Errorf("live targets after Runtime.Close: %+v, want 10 reset", clTotals(c))
	}

	// The Server's account.
	st := srv.Status()
	if st.Dialing != 0 || st.Live != 0 || st.Hooks != 0 || st.Abandoned != 0 {
		t.Errorf("Server state left: %+v", st)
	}
	const connected = 190 + 96 + 4 + 40 + 40 + 40 + 10 + 10
	if st.Confirmed != connected || st.Rejected != 70 || st.ByCode[CodeRefused] != 40 || st.ByCode[CodeTimeout] != 30 ||
		st.Unconfirmed != 0 || st.Lost != 0 || st.Panics != 0 {
		t.Errorf("Server counters %+v, want %d confirmed, 40 CodeRefused, 30 CodeTimeout and nothing else", st, connected)
	}
	if s.refuseN.Calls() != 40 || s.hangN.Calls() != 30 || s.hangN.Unclosed() != 0 || s.refuseN.Unclosed() != 0 {
		t.Errorf("scripted dials: refused %d calls, hang %d calls (want 40, 30), unclosed %d, %d",
			s.refuseN.Calls(), s.hangN.Calls(), s.refuseN.Unclosed(), s.hangN.Unclosed())
	}

	// The targets: every connection accepted once and ended as its class
	// designs; none open.
	for _, row := range []struct {
		name               string
		tg                 *rendrtest.Target
		accepted, rst, fin int // RSTIn and FINIn totals
	}{
		{"echo", s.echo, 190, 0, 190},
		{"gen", s.gen, 96, 0, 96},
		{"bulk", s.bulk, 4, 0, 4},
		{"linger", s.stall, 40, 40, 40},
		{"idle", s.idle, 40, 40, 40},
		{"noread", s.noread, 10, 10, -1},
		{"rst", s.rst, 40, 0, -1},
	} {
		c := row.tg.Counts()
		if c.Accepted != row.accepted || c.Open != 0 || c.RSTIn != row.rst || (row.fin >= 0 && c.FINIn != row.fin) {
			t.Errorf("%s targets: %+v; want %d accepted, %d reset in, %d FIN in, none open", row.name, clTotals(c), row.accepted, row.rst, row.fin)
		}
	}
	if c := s.rst.Counts(); c.RSTOut != 40 {
		t.Errorf("rst targets: %+v, want 40 resets out", clTotals(c))
	}

	// Nothing left in either Runtime after Close.
	s.w.shutdown()
	for _, tg := range []*rendrtest.Target{s.echo, s.gen, s.bulk, s.stall, s.idle, s.rst, s.noread, s.live} {
		tg.Close()
	}
	for _, rt := range []*rendr.Runtime{s.w.d, s.w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 {
			t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
	if l, p := testhooks.LiveSessions.Load()-live0, testhooks.ParkedSessions.Load()-parked0; l != 0 || p != 0 {
		t.Errorf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
	}
	t.Logf("C-L smoke: %d connections in %v virtual; Server %+v", connected+70, time.Since(s.start), clStatus(srv.Status()))
}

// clTotals is c without its per-connection records (for messages).
func clTotals(c rendrtest.TargetCounts) rendrtest.TargetCounts {
	c.Conns = nil
	return c
}

// clStatus is st without LastErr (for the log).
func clStatus(st ServerStatus) ServerStatus {
	st.LastErr = nil
	return st
}

// runEcho: 16 KiB of PRNG(seed) each way with a half-close, through an
// ingress Forward.
func (s *clSmoke) runEcho(addr string, seed uint64) {
	t := s.t
	cli, _, res, err := s.ingress(addr, 0)
	if err != nil {
		t.Errorf("%s: Dial: %v", addr, err)
		return
	}
	defer cli.Close()
	werr := make(chan error, 1)
	go func() {
		err := writePRNG(cli, seed, clEchoN)
		if err == nil {
			err = cli.CloseWrite()
		}
		werr <- err
	}()
	n, sum, err := readAll(cli)
	if e := <-werr; e != nil {
		t.Errorf("%s: write: %v", addr, e)
	}
	if err != io.EOF || n != clEchoN || sum != prngSum(seed, clEchoN) {
		t.Errorf("%s: echo %d of %d bytes (intact %v), end %v; want all, then io.EOF", addr, n, clEchoN, sum == prngSum(seed, clEchoN), err)
	}
	if r := <-res; !r.Clean || r.ToSession != clEchoN || r.ToLocal != clEchoN {
		t.Errorf("%s: ingress Forward %+v, want a clean end with %d bytes each way", addr, r, clEchoN)
	}
}

// runGen: the client half-closes at once and reads 128 KiB of PRNG(7).
func (s *clSmoke) runGen(addr string) {
	t := s.t
	cli, _, res, err := s.ingress(addr, 0)
	if err != nil {
		t.Errorf("%s: Dial: %v", addr, err)
		return
	}
	defer cli.Close()
	if err := cli.CloseWrite(); err != nil {
		t.Errorf("%s: CloseWrite: %v", addr, err)
	}
	n, sum, err := readAll(cli)
	if err != io.EOF || n != clGenN || sum != prngSum(clGenSeed, clGenN) {
		t.Errorf("%s: read %d of %d bytes (intact %v), end %v; want all, then io.EOF", addr, n, clGenN, sum == prngSum(clGenSeed, clGenN), err)
	}
	if r := <-res; !r.Clean {
		t.Errorf("%s: ingress Forward %+v, want a clean end", addr, r)
	}
}

// runBulk: the gen of bulk session k; the kill k lands while it runs.
func (s *clSmoke) runBulk(k int, n int64) {
	t := s.t
	addr := fmt.Sprintf("bulk-%d.test:80", k)
	cli, c, res, err := s.ingress(addr, 0)
	if err != nil {
		t.Errorf("%s: Dial: %v", addr, err)
		return
	}
	defer cli.Close()
	s.bulkConn[k].Store(c)
	if err := cli.CloseWrite(); err != nil {
		t.Errorf("%s: CloseWrite: %v", addr, err)
	}
	got, sum, err := readAll(clCounting{cli, &s.bulkRead[k]})
	if err != io.EOF || got != n || sum != prngSum(5, n) {
		t.Errorf("%s: read %d of %d bytes (intact %v), end %v; want all, then io.EOF", addr, got, n, sum == prngSum(5, n), err)
	}
	if r := <-res; !r.Clean {
		t.Errorf("%s: ingress Forward %+v, want a clean end", addr, r)
	}
	if m := c.Status().Migrations.Death; m == 0 {
		t.Errorf("stimulus: %s: no death migration after the kill: %+v", addr, c.Status())
	}
}

// clEventually polls cond every millisecond (virtual) for up to d; the
// caller's checks report a failure (it may run off the test goroutine).
func clEventually(d time.Duration, cond func() bool) {
	for end := time.Now().Add(d); !cond() && time.Now().Before(end); {
		time.Sleep(time.Millisecond)
	}
}

// clCounting counts the bytes read through it.
type clCounting struct {
	r io.Reader
	n *atomic.Int64
}

func (c clCounting) Read(b []byte) (int, error) {
	k, err := c.r.Read(b)
	c.n.Add(int64(k))
	return k, err
}

// runRST: the target resets after 64 KiB: a prefix, then a reset.
func (s *clSmoke) runRST(addr string) {
	t := s.t
	cli, _, res, err := s.ingress(addr, 0)
	if err != nil {
		t.Errorf("%s: Dial: %v", addr, err)
		return
	}
	defer cli.Close()
	if err := writePRNG(cli, 3, 1<<10); err != nil {
		t.Errorf("%s: write: %v", addr, err)
	}
	n, sum, err := readAll(cli)
	if !isReset(err) || n > clRSTN || sum != prngSum(0, n) {
		t.Errorf("%s: read %d bytes (a PRNG(0) prefix %v), end %v; want at most %d, then a reset", addr, n, sum == prngSum(0, n), err, clRSTN)
	}
	r := <-res
	if code, remote, ok := abortCode(r.SessionErr); r.Clean || !ok || code != AbortReset || !remote {
		t.Errorf("%s: ingress Forward %+v, want *AbortError{AbortReset, Remote}", addr, r)
	}
}

// runRefused: the hook refuses.
func (s *clSmoke) runRefused(addr string) {
	c, err := Dial(context.Background(), s.w.peer, addr, rendr.DialOptions{})
	if e := clReject(err, CodeRefused); e != nil {
		s.t.Errorf("%s: %v", addr, e)
		if c != nil {
			c.Close()
		}
	}
}

// runSyn: the hook hangs; the Server answers CodeTimeout at its 5-s budget.
func (s *clSmoke) runSyn(addr string) {
	start := time.Now()
	c, err := Dial(context.Background(), s.w.peer, addr, rendr.DialOptions{})
	took := time.Since(start)
	if e := clReject(err, CodeTimeout); e != nil {
		s.t.Errorf("%s: %v", addr, e)
		if c != nil {
			c.Close()
		}
		return
	}
	if took < DefaultDialTimeout || took > DefaultDialTimeout+time.Second {
		s.t.Errorf("%s: CodeTimeout after %v, want the dial budget %v (+ 1 s)", addr, took, DefaultDialTimeout)
	}
}

// clReject is checkReject, except that the message may also be empty: an
// OPEN retried after a kill took its OPEN_ACK down is answered by the
// passive's tombstone, and on a view of a shared trunk that answer is a
// fixed-size refusal record without the message (M3-D12); the code is the
// contract (l4's package doc).
func clReject(err error, code RejectCode) error {
	var re *rendr.RejectError
	if errors.As(err, &re) && re.Msg == "" {
		if got, ok := CodeOf(err); ok && got == code {
			return nil
		}
	}
	return checkReject(err, code)
}

// runLinger: the l4.Dial Conn held directly; request, half-close, Close
// 2.5 s later; the stalled target is reset at Close + Linger + d (R1-22).
func (s *clSmoke) runLinger(addr string) {
	t := s.t
	c, err := Dial(context.Background(), s.w.peer, addr, rendr.DialOptions{})
	if err != nil {
		t.Errorf("%s: Dial: %v", addr, err)
		return
	}
	if err := writePRNG(c, 4, 1<<10); err != nil {
		t.Errorf("%s: write: %v", addr, err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Errorf("%s: CloseWrite: %v", addr, err)
	}
	time.Sleep(2500 * time.Millisecond)
	sp := s.spy(addr)
	if sp == nil {
		t.Errorf("%s: no target connection", addr)
		c.Close()
		return
	}
	if _, _, closes, _ := sp.snapshot(); closes != 0 || c.Status().AckedBytes != 1<<10 {
		t.Errorf("stimulus: %s: before the Close the target was closed %d times, %d bytes acknowledged", addr, closes, c.Status().AckedBytes)
	}
	closed := time.Now()
	c.Close()
	select {
	case <-c.Done():
	case <-time.After(2 * clLinger):
		t.Errorf("%s: the dialer session not done %v after its Close", addr, 2*clLinger)
		return
	}
	// The dialer sends its RST(Linger) at Linger; its Done follows its
	// view's DETACH exchange, one round trip later.
	if el := time.Since(closed); el < clLinger || el > clLinger+2*kitOneWay+2*time.Millisecond {
		t.Errorf("%s: the dialer session done %v after its Close, want Linger %v (+ one round trip + 2 ms)", addr, el, clLinger)
	}
	clEventually(time.Second, func() bool { _, _, closes, _ := sp.snapshot(); return closes > 0 })
	_, l0, closes, _ := sp.snapshot()
	sp.mu.Lock()
	el := sp.closedAt.Sub(closed)
	sp.mu.Unlock()
	if closes != 1 || l0 != 1 || el < clLinger+kitOneWay || el > clLinger+kitOneWay+2*time.Millisecond {
		t.Errorf("%s: target closed %d times (%d SetLinger(0)) %v after the Close; want one reset at Linger + d = %v (+ 2 ms)",
			addr, closes, l0, el, clLinger+kitOneWay)
	}
}

// runIdle: R1-3 through an ingress Forward with a 30-s idle limit: the
// client half-closes, then Closes (unobservable); the target stalls.
func (s *clSmoke) runIdle(addr string) {
	t := s.t
	cli, _, res, err := s.ingress(addr, clIdle)
	if err != nil {
		t.Errorf("%s: Dial: %v", addr, err)
		return
	}
	if err := writePRNG(cli, 6, 1<<10); err != nil {
		t.Errorf("%s: write: %v", addr, err)
	}
	cli.CloseWrite()
	time.Sleep(time.Second) // the request, its FIN and their ACKs cross
	quiet := time.Now()
	cli.Close() // unobservable: nothing unread, FIN already sent
	sp := s.spy(addr)
	if sp == nil {
		t.Errorf("%s: no target connection", addr)
		return
	}
	r := <-res
	released := time.Since(quiet)
	if released < clIdle-time.Second || released > clIdle+2*time.Second+time.Second {
		t.Errorf("%s: released %v after the last byte, want the idle limit %v (−1 s, + DeadMax + 1 s)", addr, released, clIdle)
	}
	if !errors.Is(r.SessionErr, rendr.ErrIdleTimeout) {
		t.Errorf("%s: ingress Forward %+v, want ErrIdleTimeout", addr, r)
	}
	clEventually(time.Second, func() bool { _, _, closes, _ := sp.snapshot(); return closes > 0 })
	_, l0, closes, _ := sp.snapshot()
	sp.mu.Lock()
	el := sp.closedAt.Sub(quiet)
	sp.mu.Unlock()
	if closes != 1 || l0 != 1 || el < clIdle-time.Second || el > clIdle+3*time.Second {
		t.Errorf("%s: target closed %d times (%d SetLinger(0)) %v after the last byte; want one reset at the idle limit", addr, closes, l0, el)
	}
}

// runNoRead: the target never reads; the client's Writes stop, the session
// idles out at 30 s and both sockets are reset.
func (s *clSmoke) runNoRead(addr string) {
	t := s.t
	cli, c, res, err := s.ingress(addr, clIdle)
	if err != nil {
		t.Errorf("%s: Dial: %v", addr, err)
		return
	}
	defer cli.Close()
	var last time.Time
	var wrote int64
	buf := make([]byte, 4<<10)
	src := rendrtest.PRNG(8)
	for {
		src.Read(buf)
		k, err := cli.Write(buf)
		wrote += int64(k)
		if err != nil {
			if !isReset(err) {
				t.Errorf("%s: client Write ended with %v, want a reset", addr, err)
			}
			break
		}
		last = time.Now()
	}
	released := time.Since(last)
	if moved := c.Status().TxBytes; moved == 0 || wrote < 1<<20 {
		t.Errorf("load: %s: the client wrote %d bytes, the dialer sent %d", addr, wrote, moved)
	}
	if released < clIdle-time.Second || released > clIdle+3*time.Second {
		t.Errorf("%s: reset %v after the client's last progress, want the idle limit %v (−1 s, + DeadMax + 1 s)", addr, released, clIdle)
	}
	r := <-res
	if !errors.Is(r.SessionErr, rendr.ErrIdleTimeout) {
		t.Errorf("%s: ingress Forward %+v, want ErrIdleTimeout", addr, r)
	}
	sp := s.spy(addr)
	if sp == nil {
		t.Errorf("%s: no target connection", addr)
		return
	}
	clEventually(time.Second, func() bool { _, _, closes, _ := sp.snapshot(); return closes > 0 })
	if _, l0, closes, _ := sp.snapshot(); closes != 1 || l0 != 1 {
		t.Errorf("%s: target closed %d times (%d SetLinger(0)); want one reset", addr, closes, l0)
	}
}
