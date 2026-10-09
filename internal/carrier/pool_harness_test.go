package carrier

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Harness of the WP9 pool tests (M3 design §A5.8, §A5.9): a passive end
// reachable through a factory's Dial — every call is a net.Pipe whose far
// end runs the production passive handshake (ReadHello) and starts the
// passive trunk, answering handle 1 and every admitted view — and a pool
// over factories of such servers. Results are attached the way the
// session attaches them: Start, then the pool's publication hook that
// Conn.Start runs on view 1 of a fresh trunk (poolStarted; see the WP9
// contract note). Everything runs inside testing/synctest bubbles.

// poolServer is the passive end of one or more factories.
type poolServer struct {
	env *Env

	dials atomic.Int32 // factory calls

	mu sync.Mutex
	// gate, when set, holds every factory call until it is closed (or the
	// call's context ends).
	gate chan struct{}
	// dialErr, when set, is every factory call's error (after the gate).
	dialErr error
	// hang, when set, makes a factory call wait for it ignoring its
	// context (a hung factory, L20).
	hang chan struct{}
	// honorHang: the first factory call waits until its context ends.
	honorHang bool
	// status1 answers handle 1 of each accepted carrier (nil: OK).
	status1 func(n int) wire.AckStatus
	// wrap wraps the dialer's end of each pipe (n counts from 1).
	wrap func(n int, nc net.Conn) net.Conn
	// offer is the DATA every admitted view sends after its OK response.
	offer uint64

	trunks []*Conn  // passive view 1s, in accept order
	views  []*mView // passive views admitted on started trunks
}

// newPoolServer returns a passive end with its own instance and mod
// applied to its Env.
func newPoolServer(mod func(*Env)) *poolServer {
	_, env := phEnvs()
	env.DBufs = NewDatagramBufPool()
	env.Dgram = &DgramStats{}
	env.Stages = NewBudget(1 << 30)
	if mod != nil {
		mod(env)
	}
	s := &poolServer{env: env}
	env.Admit = func(v *Conn, h wire.Header, p []byte) {
		mv := &mView{c: v, ep: &dEP{}, src: newVSource(env), bell: &hBell{}, done: &hBell{}}
		mv.src.resp, mv.src.respSt = respTypeOf(h.Type), wire.StatusOK
		s.mu.Lock()
		mv.src.offer(s.offer)
		s.views = append(s.views, mv)
		s.mu.Unlock()
		mv.ep.fill = mv.src.fill
		v.OnDone(mv.done)
		v.Start(mv.ep, mv.bell, StartOptions{})
	}
	return s
}

// factory returns a mux-eligible factory of the server with index idx.
func (s *poolServer) factory(name string, idx int) Factory {
	return Factory{Index: idx, Name: name, Mux: true, Dial: s.dial}
}

func (s *poolServer) dial(ctx context.Context) (net.Conn, error) {
	n := int(s.dials.Add(1))
	s.mu.Lock()
	gate, derr, hang, honor, wrap := s.gate, s.dialErr, s.hang, s.honorHang && n == 1, s.wrap
	s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if honor {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if hang != nil {
		<-hang
		return nil, net.ErrClosed
	}
	if derr != nil {
		return nil, derr
	}
	a, b := net.Pipe()
	go s.accept(b)
	if wrap != nil {
		return wrap(n, a), nil
	}
	return a, nil
}

// accept runs the passive handshake on nc and starts the trunk; its view
// 1 answers handle 1 (Hold: the response is its first frame).
func (s *poolServer) accept(nc net.Conn) {
	h, err := ReadHello(s.env, nc, time.Now().Add(10*time.Second), 4096, nil)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.trunks = append(s.trunks, h.Conn)
	n := len(s.trunks)
	st1 := s.status1
	s.mu.Unlock()
	st := wire.StatusOK
	if st1 != nil {
		st = st1(n)
	}
	src := newVSource(s.env)
	src.resp, src.respSt = respTypeOf(h.First.Type), st
	ep := &dEP{}
	ep.fill = src.fill
	h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true})
}

func (s *poolServer) setGate(g chan struct{}) {
	s.mu.Lock()
	s.gate = g
	s.mu.Unlock()
}

func (s *poolServer) accepted() []*Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Conn(nil), s.trunks...)
}

func (s *poolServer) admitted() []*mView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*mView(nil), s.views...)
}

// poolT is one pool test: the dialer Env, the pool, its servers and every
// carrier either side produced (killed and joined at the end).
type poolT struct {
	t    testing.TB
	env  *Env
	p    *Pool
	srv  *poolServer
	mu   sync.Mutex
	ests []*Established
}

// newPoolT returns a pool over one factory ("p0") of a new server; dmod
// and pmod change the dialer's and the passive's Env.
func newPoolT(t testing.TB, dmod, pmod func(*Env)) *poolT {
	env, _ := phEnvs()
	env.DBufs = NewDatagramBufPool()
	env.Dgram = &DgramStats{}
	env.Stages = NewBudget(1 << 30)
	if dmod != nil {
		dmod(env)
	}
	srv := newPoolServer(pmod)
	pt := &poolT{t: t, env: env, srv: srv}
	pt.p = NewPool(env, []Factory{srv.factory("p0", 0)})
	t.Cleanup(pt.close)
	return pt
}

// close kills every carrier of both sides and waits for each trunk's Done.
func (pt *poolT) close() {
	pt.mu.Lock()
	ests := append([]*Established(nil), pt.ests...)
	pt.mu.Unlock()
	var ts []*trunk
	for _, e := range ests {
		e.Conn.KillTrunk(CauseLocalClose, "test end")
		ts = append(ts, e.Conn.trunk)
	}
	for _, c := range pt.srv.accepted() {
		c.KillTrunk(CauseLocalClose, "test end")
		ts = append(ts, c.trunk)
	}
	for _, t := range ts {
		select {
		case <-t.tdone:
		case <-time.After(time.Minute):
			pt.t.Errorf("trunk %d not done at the test's end", t.id)
		}
	}
}

// payload returns the first frame of session sid.
func poolPayload(kind wire.Type, sid byte) []byte {
	if kind == wire.TypeJoin {
		return mJoinPayload(sid)
	}
	return mOpenPayload(sid, false)
}

// attempt runs one attempt of session sid (sess = sid) on factory f with a
// fresh CarrierID; inst is the bound instance of a JOIN.
func (pt *poolT) attempt(ctx context.Context, f int, kind wire.Type, sid byte, inst [16]byte) (*Established, error) {
	return pt.attemptOn(ctx, pt.p, f, kind, sid, inst)
}

func (pt *poolT) attemptOn(ctx context.Context, p *Pool, f int, kind wire.Type, sid byte, inst [16]byte) (*Established, error) {
	est, err := p.Attempt(ctx, f, pt.env.IDs.Next(), kind, poolPayload(kind, sid), nil, inst, uintptr(sid))
	if est != nil {
		pt.mu.Lock()
		pt.ests = append(pt.ests, est)
		pt.mu.Unlock()
	}
	return est, err
}

// poolRes is one attempt's result.
type poolRes struct {
	sid byte
	est *Established
	err error
	at  time.Time
}

// goAttempt runs an attempt on its own goroutine; its result goes to ch.
func (pt *poolT) goAttempt(ctx context.Context, kind wire.Type, sid byte, ch chan<- poolRes) {
	go func() {
		est, err := pt.attempt(ctx, 0, kind, sid, [16]byte{})
		ch <- poolRes{sid: sid, est: est, err: err, at: time.Now()}
	}()
}

// attach starts an attempt's carrier as a session does: Start with an
// endpoint, then — on view 1 of a fresh trunk — the publication hook
// Conn.Start runs (poolStarted).
func (pt *poolT) attach(est *Established) *mView {
	mv := &mView{c: est.Conn, ep: &dEP{}, src: newVSource(pt.env), bell: &hBell{}, done: &hBell{}}
	mv.ep.fill = mv.src.fill
	est.Conn.OnDone(mv.done)
	est.Conn.Start(mv.ep, mv.bell, StartOptions{})
	if est.Fresh {
		est.Conn.poolStarted()
	}
	return mv
}

// isOK reports an OK response.
func isOK(est *Established) bool {
	if est == nil {
		return false
	}
	st, _, ok := responseStatus(est.Resp, est.Payload)
	return ok && st == wire.StatusOK
}

// collect receives n results from ch (virtual time bound).
func collect(t testing.TB, ch <-chan poolRes, n int) []poolRes {
	t.Helper()
	out := make([]poolRes, 0, n)
	for len(out) < n {
		select {
		case r := <-ch:
			out = append(out, r)
		case <-time.After(time.Minute):
			t.Fatalf("%d of %d attempts returned", len(out), n)
		}
	}
	return out
}

// pending reports how many results ch holds without blocking.
func pendingResults(ch chan poolRes) int { return len(ch) }

// listed returns the published trunks (view 1) of factory f.
func (p *Pool) listed(f int) []*Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*Conn(nil), p.trunks[f]...)
}

// inFlight reports whether factory f has a dial in flight.
func (p *Pool) inFlight(f int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dialing[f] != nil
}

// usable reports whether the pool would put a stream OPEN of session sess
// on trunk c (view 1) now.
func (p *Pool) usable(c *Conn, sess uintptr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := c.trunk.factory
	saved := p.trunks[f]
	p.trunks[f] = []*Conn{c}
	got := p.pickLocked(f, wire.TypeData, [16]byte{}, sess, nil)
	p.trunks[f] = saved
	return got == c
}
