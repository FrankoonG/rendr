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

// The checkpoint C-E smoke (M4 design §A15.3 row I2): 500 EarlyReturn L4
// connections between two Runtimes in one synctest bubble. Each client
// writes a 4-KiB request at once, so it is the session's early data. Three
// Peers of the dialer reach the passive's one Listener over their own
// rendrtest Links:
//
//   - fresh: one carrier per session (Props.CheapSubflow), so every
//     session's first flight carries its request (EARLY);
//   - mux: carriers shared (rendr mux): after the trunk's first session,
//     sessions open on the live trunk without early data (the fast path,
//     M4-D17);
//   - kill: one carrier per session, and the passive application kills that
//     carrier as soon as the session's OPEN was admitted, after its first
//     flight; the dialer redials and sends the request again from offset 0,
//     and the passive takes each byte once (L10, L47).
//
// The passive application hands most sessions to an l4.Server whose Dial
// hook connects to an echo rendrtest.Target or refuses; it handles the
// "conn" classes itself, as Handle does (dial the target, Confirm,
// Forward), to read the passive Conn's EarlyBytes; and it never decides the
// AcceptTimeout classes.
//
// Classes (the address's first label: class, then the index):
//
//   - fe (70), me (83): echo through the l4.Server, the client behind an
//     ingress Forward (R1-15: Forward's hold lets the request ride the
//     first flight); the echo intact up to io.EOF, Forward clean.
//   - fc (40), mc (40): echo through the conn application, the client on
//     the l4.Dial Conn directly.
//   - fr (84), mr (83): the hook refuses (ECONNREFUSED): the client's next
//     Read and Write return *RejectError CodeRefused (plan:663); no target
//     connection; the passive application never read the request.
//   - fa (25), ma (25): never decided: the Listener's AcceptTimeout (3 s)
//     answers CAPACITY: the client's Read returns ErrCapacity about 3 s
//     after its Write; the held PendingConn's Confirm then fails.
//   - kill (50): echo through the l4.Server behind an ingress Forward on
//     the kill Peer, one session at a time.
//
// EarlyBytes proofs: every fresh and kill session sent its whole request
// as early data (dialer EarlyBytes 4,096), and every fc session's passive
// took it before the verdict; a mux session reports 4,096 only when it
// dialled the trunk (at most as many as the mux Link's carrier dials) and
// 0 on the fast path, on both ends. Afterwards both Runtimes'
// BufferedBytes are back at their baseline once the Peers closed their
// carriers, and Runtime.Close leaves nothing: no session, handshake,
// actor, Server state or target connection, the session registry back at
// its start (R1-24), and no goroutine (the bubble ends only when every
// goroutine of it exited).
func TestL4Smoke_CE(t *testing.T) {
	synctest.Test(t, runCESmoke)
}

const (
	ceReq           = 4 << 10 // each client's request: its early data
	ceAcceptTimeout = 3 * time.Second
	ceSpacing       = 40 * time.Millisecond // between two starts of the spread classes
)

// ceClasses are the spread classes and their counts; kill runs apart.
var ceClasses = []struct {
	name string
	n    int
}{
	{"fe", 70}, {"me", 83}, {"fc", 40}, {"mc", 40}, {"fr", 84}, {"mr", 83}, {"fa", 25}, {"ma", 25},
}

// ceKills is the kill class's count.
const ceKills = 50

// ceSmoke is one run's state.
type ceSmoke struct {
	t     *testing.T
	start time.Time

	d, p                *rendr.Runtime
	ln                  *rendr.Listener
	fresh, mux, kill    *rendrtest.Link
	pFresh, pMux, pKill *rendr.Peer
	srv                 *Server
	echo                *rendrtest.Target
	refuse              func(context.Context, string) (net.Conn, error)
	refuseN             *rendrtest.DialCounts

	wg   sync.WaitGroup // the clients
	apps sync.WaitGroup // the accept loop and its handlers

	mu         sync.Mutex
	held       []*rendr.PendingConn // the AcceptTimeout classes' sessions, never decided
	passive    map[string]uint64    // conn classes: the passive EarlyBytes at the verdict
	appErrs    []error
	killed     []int // the carriers each kill ended
	muxEarly   atomic.Int64
	muxFast    atomic.Int64
	freshEarly atomic.Int64 // fresh and kill sessions that sent their request early
}

// ceClass is the class of a target address.
func ceClass(addr string) string {
	class, _, _ := strings.Cut(addr, "-")
	return class
}

// hook is the Server's Dial hook: refusals for fr and mr, else the echo
// target.
func (s *ceSmoke) hook(ctx context.Context, r Request) (net.Conn, error) {
	switch ceClass(r.Addr) {
	case "fr", "mr":
		return s.refuse(ctx, r.Addr)
	}
	return s.echo.Dial(ctx, r.Addr)
}

// acceptLoop is the passive application.
func (s *ceSmoke) acceptLoop(ctx context.Context) {
	for {
		pc, err := s.ln.Accept(ctx)
		if err != nil {
			return
		}
		r, err := ParseMetadata(pc.Metadata())
		if err != nil {
			s.fail(fmt.Errorf("metadata: %v", err))
			pc.Reject(uint32(CodeBadRequest), CodeBadRequest.String())
			continue
		}
		switch ceClass(r.Addr) {
		case "fa", "ma":
			s.mu.Lock()
			s.held = append(s.held, pc)
			s.mu.Unlock()
		case "fc", "mc":
			s.apps.Go(func() { s.handleConn(ctx, pc, r.Addr) })
		case "kill":
			// The OPEN was admitted: the first flight has arrived. Its
			// carrier (the kill Link's only one) dies now.
			n := s.kill.Kill()
			s.mu.Lock()
			s.killed = append(s.killed, n)
			s.mu.Unlock()
			s.apps.Go(func() { s.srv.Handle(ctx, pc) })
		default:
			s.apps.Go(func() { s.srv.Handle(ctx, pc) })
		}
	}
}

// handleConn is Handle's sequence for the conn classes, recording the
// passive's EarlyBytes at the verdict. The target's connect takes 1 ms,
// as a real one takes time (a zero-time connect could confirm before the
// carrier reader handed over the early DATA that arrived with the OPEN).
func (s *ceSmoke) handleConn(ctx context.Context, pc *rendr.PendingConn, addr string) {
	time.Sleep(time.Millisecond)
	tc, err := s.echo.Dial(ctx, addr)
	if err != nil {
		s.fail(fmt.Errorf("%s: target: %v", addr, err))
		pc.Reject(uint32(CodeDialFailed), CodeDialFailed.String())
		return
	}
	sc, err := pc.Confirm()
	if err != nil {
		s.fail(fmt.Errorf("%s: Confirm: %v", addr, err))
		tc.Close()
		return
	}
	s.mu.Lock()
	s.passive[addr] = sc.Status().EarlyBytes
	s.mu.Unlock()
	Forward(ctx, sc, tc)
}

func (s *ceSmoke) fail(err error) {
	s.mu.Lock()
	s.appErrs = append(s.appErrs, err)
	s.mu.Unlock()
}

// newCEPeer adds a Link named name to the passive's Listener and a dialer
// Peer over it.
func (s *ceSmoke) newCEPeer(name string, dedicated bool) (*rendrtest.Link, *rendr.Peer) {
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: s.ln.Handle})
	l.SetDelay(kitOneWay, 0)
	p, err := s.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.StreamCarrier{Name: name, Dial: l.Dial, Props: rendr.Props{CheapSubflow: dedicated}}}})
	if err != nil {
		s.t.Fatalf("NewPeer %s: %v", name, err)
	}
	return l, p
}

func runCESmoke(t *testing.T) {
	live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
	s := &ceSmoke{t: t, start: time.Now(), passive: map[string]uint64{}}
	cfg := rendr.Config{}
	cfg.Handshake.MaxConcurrent = 1024
	ov := kitOverrides(worldOpts{})
	s.d = kitRuntime(t, cfg, ov)
	s.p = kitRuntime(t, cfg, ov)
	base := [2]int64{s.d.Status().BufferedBytes, s.p.Status().BufferedBytes}
	ln, err := s.p.Listen(rendr.ListenConfig{AcceptBacklog: 256, AcceptTimeout: ceAcceptTimeout})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	s.ln = ln
	s.fresh, s.pFresh = s.newCEPeer("fresh", true)
	s.mux, s.pMux = s.newCEPeer("mux", false)
	s.kill, s.pKill = s.newCEPeer("kill", true)
	s.echo = rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
	s.refuse, s.refuseN = rendrtest.ScriptedDial(rendrtest.OutcomeRefuse())
	s.srv = &Server{Dial: s.hook}
	ctx, cancel := context.WithCancel(context.Background())
	s.apps.Go(func() { s.acceptLoop(ctx) })

	// The spread classes, interleaved (stride 7 over the class list).
	var spread []string
	for _, c := range ceClasses {
		for range c.n {
			spread = append(spread, c.name)
		}
	}
	var order []string
	for k := range 7 {
		for i := k; i < len(spread); i += 7 {
			order = append(order, spread[i])
		}
	}
	for i, class := range order {
		addr := fmt.Sprintf("%s-%d.test:80", class, i)
		when := time.Duration(i) * ceSpacing
		s.wg.Go(func() {
			time.Sleep(when)
			s.run(class, addr, uint64(1000+i))
		})
	}
	// The kill class, one session at a time beside the spread.
	s.wg.Go(func() {
		for j := range ceKills {
			s.runEcho(s.pKill, fmt.Sprintf("kill-%d.test:80", j), uint64(j), true)
		}
	})
	s.wg.Wait()

	// The AcceptTimeout classes' sessions were answered CAPACITY: a late
	// decision fails.
	s.mu.Lock()
	held := s.held
	s.mu.Unlock()
	if len(held) != 50 {
		t.Errorf("%d undecided sessions, want 50", len(held))
	}
	for _, pc := range held {
		if c, err := pc.Confirm(); !errors.Is(err, rendr.ErrCapacity) {
			t.Errorf("Confirm after AcceptTimeout: %v, %v; want ErrCapacity", c, err)
		}
	}

	// The Server's account and the targets.
	st := s.srv.Status()
	if st.Dialing != 0 || st.Live != 0 || st.Hooks != 0 || st.Abandoned != 0 {
		t.Errorf("Server state left: %+v", st)
	}
	const viaServer = 70 + 83 + ceKills
	if st.Confirmed != viaServer || st.Rejected != 167 || st.ByCode[CodeRefused] != 167 ||
		st.Unconfirmed != 0 || st.Lost != 0 || st.Panics != 0 {
		t.Errorf("Server counters %+v, want %d confirmed, 167 CodeRefused and nothing else", clStatus(st), viaServer)
	}
	if s.refuseN.Calls() != 167 || s.refuseN.Unclosed() != 0 {
		t.Errorf("refusing dials: %d calls (want 167), %d unclosed", s.refuseN.Calls(), s.refuseN.Unclosed())
	}
	synctest.Wait()
	const echoes = viaServer + 80
	if c := s.echo.Counts(); c.Accepted != echoes || c.Open != 0 || c.FINIn != echoes || c.RSTIn != 0 {
		t.Errorf("echo targets: %+v; want %d accepted, each ended by a FIN, none open", clTotals(c), echoes)
	}

	// The kills: one carrier after each first flight; each session dialled
	// again.
	s.mu.Lock()
	killed := s.killed
	s.mu.Unlock()
	if len(killed) != ceKills {
		t.Errorf("stimulus: %d kills, want %d", len(killed), ceKills)
	}
	for j, n := range killed {
		if n == 0 {
			t.Errorf("stimulus: kill %d ended no carrier", j)
		}
	}
	if d := s.kill.Stats().Dials; d < 2*ceKills {
		t.Errorf("stimulus: the kill Link had %d carrier dials, want at least %d (a redial per killed first flight)", d, 2*ceKills)
	}

	// EarlyBytes: the fresh and kill sessions sent their requests early;
	// the passive took the fc requests before the verdict; mux sessions
	// sent early data only on the trunks they dialled.
	if n := s.freshEarly.Load(); n != 70+40+ceKills {
		t.Errorf("%d fresh and kill echo sessions sent their request as early data, want every one (%d)", n, 70+40+ceKills)
	}
	s.mu.Lock()
	for addr, n := range s.passive {
		switch ceClass(addr) {
		case "fc":
			if n != ceReq {
				t.Errorf("%s: passive EarlyBytes %d at the verdict, want %d", addr, n, ceReq)
			}
		case "mc":
			if n != 0 && n != ceReq {
				t.Errorf("%s: passive EarlyBytes %d, want 0 or %d", addr, n, ceReq)
			}
		}
	}
	if len(s.passive) != 80 {
		t.Errorf("%d conn-class sessions confirmed, want 80", len(s.passive))
	}
	errs := s.appErrs
	s.mu.Unlock()
	for _, err := range errs {
		t.Errorf("passive application: %v", err)
	}
	muxDials := s.mux.Stats().Dials
	if e, f := s.muxEarly.Load(), s.muxFast.Load(); e > muxDials || e+f != 83+40 || f == 0 {
		t.Errorf("mux echo sessions: %d sent early data, %d none (fast path); want at most one per trunk dial (%d) and the rest on the fast path", e, f, muxDials)
	}

	// Both BufferedBytes back to their baseline once the Peers closed their
	// carriers (a retiring carrier's reader stage is released within its
	// close bound).
	for _, p := range []*rendr.Peer{s.pFresh, s.pMux, s.pKill} {
		p.Close()
	}
	clEventually(5*time.Second, func() bool {
		return s.d.Status().BufferedBytes == base[0] && s.p.Status().BufferedBytes == base[1]
	})
	for i, rt := range []*rendr.Runtime{s.d, s.p} {
		st := rt.Status()
		sc := st.Sessions
		if st.BufferedBytes != base[i] || sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 {
			t.Errorf("Runtime %d after every connection ended: %d buffered bytes (baseline %d), sessions %+v", i, st.BufferedBytes, base[i], sc)
		}
	}

	// Nothing left after Runtime.Close.
	cancel()
	s.d.Close()
	s.p.Close()
	s.apps.Wait()
	for _, l := range []*rendrtest.Link{s.fresh, s.mux, s.kill} {
		l.Close()
	}
	s.echo.Close()
	for _, rt := range []*rendr.Runtime{s.d, s.p} {
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
	t.Logf("C-E smoke: 500 connections in %v virtual; mux: %d trunk dials, %d early, %d fast path; kill Link dials %d; Server %+v",
		time.Since(s.start), muxDials, s.muxEarly.Load(), s.muxFast.Load(), s.kill.Stats().Dials, clStatus(s.srv.Status()))
}

// run starts the connection of a spread class.
func (s *ceSmoke) run(class, addr string, seed uint64) {
	switch class {
	case "fe":
		s.runEcho(s.pFresh, addr, seed, true)
	case "me":
		s.runEcho(s.pMux, addr, seed, true)
	case "fc":
		s.runEcho(s.pFresh, addr, seed, false)
	case "mc":
		s.runEcho(s.pMux, addr, seed, false)
	case "fr":
		s.runRejected(s.pFresh, addr, seed)
	case "mr":
		s.runRejected(s.pMux, addr, seed)
	case "fa":
		s.runAcceptTimeout(s.pFresh, addr, seed)
	case "ma":
		s.runAcceptTimeout(s.pMux, addr, seed)
	}
}

// ceDial dials addr with EarlyReturn; Dial returns at once.
func (s *ceSmoke) ceDial(p *rendr.Peer, addr string) *rendr.Conn {
	start := time.Now()
	c, err := Dial(context.Background(), p, addr, rendr.DialOptions{EarlyReturn: true})
	if err != nil {
		s.t.Errorf("%s: Dial: %v", addr, err)
		return nil
	}
	if d := time.Since(start); d != 0 || c.Status().State != rendr.StatePending {
		s.t.Errorf("%s: EarlyReturn Dial took %v, state %v; want an immediate return, pending", addr, d, c.Status().State)
	}
	return c
}

// runEcho: the request, a half-close and the echo up to io.EOF, through an
// ingress Forward (forward) or on the Conn; then the EarlyBytes proofs.
func (s *ceSmoke) runEcho(p *rendr.Peer, addr string, seed uint64, forward bool) {
	t := s.t
	c := s.ceDial(p, addr)
	if c == nil {
		return
	}
	var rw io.ReadWriter = c
	closeWrite := c.CloseWrite
	var res <-chan ForwardResult
	if forward {
		cli, srv := rendrtest.TargetPipe(0)
		defer cli.Close()
		res = forwardAsync(context.Background(), c, srv)
		rw, closeWrite = cli, cli.CloseWrite
	}
	if err := writePRNG(rw, seed, ceReq); err != nil {
		t.Errorf("%s: request: %v", addr, err)
	} else if err := closeWrite(); err != nil {
		t.Errorf("%s: CloseWrite: %v", addr, err)
	}
	n, sum, err := readAll(rw)
	if err != io.EOF || n != ceReq || sum != prngSum(seed, ceReq) {
		t.Errorf("%s: echo %d of %d bytes (intact %v), end %v; want all, then io.EOF", addr, n, ceReq, sum == prngSum(seed, ceReq), err)
	}
	if res != nil {
		if r := <-res; !r.Clean || r.ToSession != ceReq || r.ToLocal != ceReq {
			t.Errorf("%s: ingress Forward %+v, want a clean end with %d bytes each way", addr, r, ceReq)
		}
	} else {
		c.Close()
	}
	select {
	case <-c.Done():
	case <-time.After(time.Minute):
		t.Errorf("%s: session not done a minute after the echo: %+v", addr, c.Status())
		return
	}
	early := c.Status().EarlyBytes
	switch {
	case p == s.pMux && early == 0:
		s.muxFast.Add(1)
	case p == s.pMux && early == ceReq:
		s.muxEarly.Add(1)
	case p != s.pMux && early == ceReq:
		s.freshEarly.Add(1)
	default:
		t.Errorf("%s: dialer EarlyBytes %d, want %d (or 0 on the mux fast path)", addr, early, ceReq)
	}
}

// runRejected: the request is written early; the refusal is the next
// Read's and the next Write's error.
func (s *ceSmoke) runRejected(p *rendr.Peer, addr string, seed uint64) {
	t := s.t
	c := s.ceDial(p, addr)
	if c == nil {
		return
	}
	defer c.Close()
	if err := writePRNG(c, seed, ceReq); err != nil {
		t.Errorf("%s: early Write: %v, want it accepted before the answer", addr, err)
	}
	n, err := c.Read(make([]byte, 1))
	if e := clReject(err, CodeRefused); n != 0 || e != nil {
		t.Errorf("%s: Read %d bytes: %v", addr, n, e)
	}
	if _, err := c.Write(make([]byte, 1)); !errors.Is(err, rendr.ErrRejected) {
		t.Errorf("%s: Write after the refusal: %v, want the refusal", addr, err)
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Errorf("%s: Done not closed after the refusal", addr)
	}
}

// runAcceptTimeout: the request is written early; nobody decides, so the
// Listener's AcceptTimeout answers: the next Read returns ErrCapacity.
func (s *ceSmoke) runAcceptTimeout(p *rendr.Peer, addr string, seed uint64) {
	t := s.t
	c := s.ceDial(p, addr)
	if c == nil {
		return
	}
	defer c.Close()
	start := time.Now()
	if err := writePRNG(c, seed, ceReq); err != nil {
		t.Errorf("%s: early Write: %v", addr, err)
	}
	n, err := c.Read(make([]byte, 1))
	el := time.Since(start)
	if n != 0 || !errors.Is(err, rendr.ErrCapacity) {
		t.Errorf("%s: Read %d bytes, %v; want ErrCapacity (AcceptTimeout)", addr, n, err)
	}
	if el < ceAcceptTimeout || el > ceAcceptTimeout+time.Second {
		t.Errorf("%s: the AcceptTimeout answer after %v, want %v (+ 1 s)", addr, el, ceAcceptTimeout)
	}
}
