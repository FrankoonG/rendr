package carrier

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Test harness of the Peer health layer: a Health whose factories dial
// rendrtest.Link paths (buffered in-memory links, so two rendr ends can
// complete a handshake, design §0.8 V1) to a real rendr passive end —
// ReadHello and a sessionless carrier (design §6.4) — all in virtual time.
// Names use the pr prefix (V16: h* is taken in this package; WP3b's tests
// use ph and lr).

// prParams are the plan §4 defaults with a fixed jitter source: u = 0.5
// makes every backoff exactly min(0.5 s·2ⁿ, BackoffMax).
func prParams() HealthParams {
	return HealthParams{
		Interval:      2 * time.Second,
		Fresh:         10 * time.Second,
		BackoffMax:    4 * time.Second,
		DialWait:      800 * time.Millisecond,
		IdleStop:      5 * time.Minute,
		LoadThreshold: 64 << 10,
		Agg:           sched.DefaultAggParams(),
		Rand:          func() float64 { return 0.5 },
	}
}

// prPassive is the passive end: every carrier a link hands to it runs the
// real passive handshake and, for a PING first frame, becomes a
// sessionless carrier that answers PINGs — or is refused (CLOSE(capacity)
// while the test says the sessionless pool is full, or a link's own
// refusal), or is ended right after its start while the test drops a
// link's carriers.
type prPassive struct {
	env *Env

	mu       sync.Mutex
	conns    []*Conn // every passive carrier past PREFACE_ACK(OK), in arrival order
	links    []int   // the link index of each
	capacity bool    // refuse new probe carriers with CLOSE(capacity) (plan §3.5)
	delay    time.Duration
	drop     map[int]prDrop   // per link: end every carrier after its start
	refuse   map[int]prRefuse // per link: refuse every carrier
	refused  map[int]int      // per link: carriers refused
}

// prDrop ends a passive carrier after it answered the establishment PING.
type prDrop struct {
	after  time.Duration // after Start
	retire bool          // CLOSE (a planned end) instead of a kill
}

// prRefuse refuses a probe carrier: with a non-OK PREFACE_ACK status, or
// with a CLOSE or GOAWAY answer instead of the establishment PONG.
type prRefuse struct {
	status wire.PrefaceStatus // non-OK: the PREFACE_ACK
	answer wire.Type          // TypeClose or TypeGoAway: the first frame's answer
	reason uint8              // the answer's reason
}

func newPrPassive() *prPassive {
	env := hEnv()
	env.Local = hPassiveInst
	return &prPassive{env: env, drop: make(map[int]prDrop), refuse: make(map[int]prRefuse), refused: make(map[int]int)}
}

// accept returns the Accept function of link i.
func (p *prPassive) accept(i int) func(net.Conn) error {
	return func(nc net.Conn) error {
		p.mu.Lock()
		refuse := p.refuse[i]
		if refuse.status != wire.PrefaceOK || refuse.answer != 0 {
			p.refused[i]++
		}
		p.mu.Unlock()
		var gate Gate
		if refuse.status != wire.PrefaceOK {
			gate = func(*wire.Preface) wire.PrefaceStatus { return refuse.status }
		}
		h, err := ReadHello(p.env, nc, time.Now().Add(10*time.Second), 0, gate)
		if err != nil {
			return nil // ReadHello closed nc
		}
		p.mu.Lock()
		p.conns = append(p.conns, h.Conn)
		p.links = append(p.links, i)
		capacity, delay, drop := p.capacity, p.delay, p.drop[i]
		p.mu.Unlock()
		if h.First.Type != wire.TypePing {
			h.Conn.Kill(CauseProtocolViolation, "test passive takes probe carriers only")
			return nil
		}
		if capacity {
			refuse = prRefuse{answer: wire.TypeClose, reason: uint8(wire.CloseCapacity)}
		}
		if refuse.answer != 0 {
			var b [wire.ReasonLen]byte
			wire.PutReason(b[:], refuse.reason)
			h.Conn.WriteAndClose(refuse.answer, 0, 0, b[:], time.Time{})
			return nil
		}
		if delay > 0 {
			time.Sleep(delay) // handshake processing: the establishment PONG is late (D26)
		}
		h.Conn.Start(nil, nil, StartOptions{Sessionless: true})
		if drop.after > 0 {
			time.Sleep(drop.after)
			if drop.retire {
				h.Conn.Retire(wire.CloseRetire)
			} else {
				h.Conn.Kill(CauseLocalClose, "test drops the carrier")
			}
		}
		return nil
	}
}

func (p *prPassive) setCapacity(on bool) {
	p.mu.Lock()
	p.capacity = on
	p.mu.Unlock()
}

func (p *prPassive) setDelay(d time.Duration) {
	p.mu.Lock()
	p.delay = d
	p.mu.Unlock()
}

// setDrop makes link i's new carriers end d.after their start (zero: never).
func (p *prPassive) setDrop(i int, d prDrop) {
	p.mu.Lock()
	p.drop[i] = d
	p.mu.Unlock()
}

// setRefuse makes the passive refuse link i's new carriers (zero: accept).
func (p *prPassive) setRefuse(i int, r prRefuse) {
	p.mu.Lock()
	p.refuse[i] = r
	p.mu.Unlock()
}

// refusals returns how many carriers of link i were refused.
func (p *prPassive) refusals(i int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refused[i]
}

// on returns the passive carriers of link i, oldest first.
func (p *prPassive) on(i int) []*Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*Conn
	for k, c := range p.conns {
		if p.links[k] == i {
			out = append(out, c)
		}
	}
	return out
}

// close kills every passive carrier and joins it.
func (p *prPassive) close() {
	p.mu.Lock()
	cs := append([]*Conn(nil), p.conns...)
	p.mu.Unlock()
	for _, c := range cs {
		c.Kill(CauseLocalClose, "test end")
		<-c.Done()
	}
}

// prRig is a Health over n links to one passive end. Every link starts
// with a 10 ms one-way delay (a 20 ms probe RTT).
type prRig struct {
	t     testing.TB
	env   *Env
	pas   *prPassive
	links []*rendrtest.Link
	h     *Health
	start time.Time
}

// newPrRig builds the rig inside the caller's bubble; edit may adjust the
// dialer's Env and the parameters first. A cleanup closes the Health, the
// passive carriers and the links, in that order (the probe carriers'
// CLOSE exchange needs the other two).
func newPrRig(t testing.TB, n int, edit func(env *Env, p *HealthParams)) *prRig {
	return newPrRigDial(t, n, edit, nil)
}

// newPrRigDial is newPrRig with factory i dialling dial(i, link) when dial
// is non-nil (a conn wrapper around the link's own Dial).
func newPrRigDial(t testing.TB, n int, edit func(env *Env, p *HealthParams), dial func(i int, l *rendrtest.Link) func(context.Context) (net.Conn, error)) *prRig {
	t.Helper()
	r := &prRig{t: t, env: hEnv(), pas: newPrPassive()}
	p := prParams()
	if edit != nil {
		edit(r.env, &p)
	}
	fs := make([]Factory, n)
	for i := range n {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: fmt.Sprintf("path%d", i), Accept: r.pas.accept(i)})
		l.SetDelay(10*time.Millisecond, 0)
		r.links = append(r.links, l)
		fs[i] = Factory{Index: i, Name: l.Name(), Dial: l.Dial}
		if dial != nil {
			fs[i].Dial = dial(i, l)
		}
	}
	r.h = NewHealth(r.env, fs, p)
	r.start = time.Now()
	t.Cleanup(func() {
		r.h.Close()
		r.pas.close()
		for _, l := range r.links {
			l.Close()
		}
	})
	return r
}

// until sleeps to start + d (virtual time) and lets the bubble settle.
func (r *prRig) until(d time.Duration) {
	r.t.Helper()
	if w := time.Until(r.start.Add(d)); w > 0 {
		time.Sleep(w)
	}
	synctest.Wait()
}

// since is the virtual time elapsed since the rig started.
func (r *prRig) since() time.Duration { return time.Since(r.start) }

// probe returns factory i's current probe carrier (white-box).
func (r *prRig) probe(i int) *Conn {
	r.h.mu.Lock()
	defer r.h.mu.Unlock()
	return r.h.fac[i].conn
}

// prRank ranks a snapshot's factories at now (as the session actor does
// for Dial and death failover, design §7.3, §7.8).
func prRank(s *Snapshot, now time.Time) []int {
	cs := make([]sched.Candidate, len(s.Sum))
	for i := range cs {
		cs[i] = sched.Candidate{Index: i, Ev: s.Evidence(i, now), Failed: s.Failed[i]}
	}
	return sched.Rank(cs, nil)
}

// prGate holds one probe attempt inside Establish right after its
// handshake succeeded: Establish then clears the handshake deadline with
// SetDeadline(zero time), the only such call on a dialer conn, which blocks
// on the gate while it is armed (one hit; later calls pass).
type prGate struct {
	mu      sync.Mutex
	armed   bool
	hit     chan struct{} // closed when an attempt reached the gate
	release chan struct{} // closed by open: the held attempt continues
}

func newPrGate() *prGate {
	return &prGate{armed: true, hit: make(chan struct{}), release: make(chan struct{})}
}

// dial wraps a link's Dial so that its conns pass through the gate.
func (g *prGate) dial(l *rendrtest.Link) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		nc, err := l.Dial(ctx)
		if err != nil {
			return nil, err
		}
		return prGateConn{Conn: nc, g: g}, nil
	}
}

// open releases the held attempt.
func (g *prGate) open() { close(g.release) }

// held reports whether an attempt reached the gate.
func (g *prGate) held() bool {
	select {
	case <-g.hit:
		return true
	default:
		return false
	}
}

type prGateConn struct {
	net.Conn
	g *prGate
}

func (c prGateConn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		c.g.mu.Lock()
		armed := c.g.armed
		c.g.armed = false
		c.g.mu.Unlock()
		if armed {
			close(c.g.hit)
			<-c.g.release
		}
	}
	return c.Conn.SetDeadline(t)
}

// prGoexitConn runs runtime.Goexit in the first Read of any conn sharing
// its counter: inside Establish, on a probe attempt's own goroutine (L51).
type prGoexitConn struct {
	net.Conn
	n *atomic.Int32 // Goexits run
}

func (c prGoexitConn) Read(b []byte) (int, error) {
	if c.n.CompareAndSwap(0, 1) {
		runtime.Goexit()
	}
	return c.Conn.Read(b)
}
