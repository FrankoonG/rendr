package carrier

import (
	"fmt"
	"net"
	"sync"
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
// Names use the ph prefix (V16: h* is taken in this package).

// phParams are the plan §4 defaults with a fixed jitter source: u = 0.5
// makes every backoff exactly min(0.5 s·2ⁿ, BackoffMax).
func phParams() HealthParams {
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

// phPassive is the passive end: every carrier a link hands to it runs the
// real passive handshake and, for a PING first frame, becomes a
// sessionless carrier that answers PINGs — or is refused with
// CLOSE(capacity) while the test says the sessionless pool is full.
type phPassive struct {
	env *Env

	mu       sync.Mutex
	conns    []*Conn // every passive carrier, in arrival order
	links    []int   // the link index of each
	capacity bool    // refuse new probe carriers with CLOSE(capacity) (plan §3.5)
	delay    time.Duration
}

func newPhPassive() *phPassive {
	env := hEnv()
	env.Local = hPassiveInst
	return &phPassive{env: env}
}

// accept returns the Accept function of link i.
func (p *phPassive) accept(i int) func(net.Conn) error {
	return func(nc net.Conn) error {
		h, err := ReadHello(p.env, nc, time.Now().Add(10*time.Second), 0, nil)
		if err != nil {
			return nil // ReadHello closed nc
		}
		p.mu.Lock()
		p.conns = append(p.conns, h.Conn)
		p.links = append(p.links, i)
		capacity, delay := p.capacity, p.delay
		p.mu.Unlock()
		if h.First.Type != wire.TypePing {
			h.Conn.Kill(CauseProtocolViolation, "test passive takes probe carriers only")
			return nil
		}
		if capacity {
			var b [wire.ReasonLen]byte
			wire.PutReason(b[:], uint8(wire.CloseCapacity))
			h.Conn.WriteAndClose(wire.TypeClose, 0, 0, b[:], time.Time{})
			return nil
		}
		if delay > 0 {
			time.Sleep(delay) // handshake processing: the establishment PONG is late (D26)
		}
		h.Conn.Start(nil, nil, StartOptions{Sessionless: true})
		return nil
	}
}

func (p *phPassive) setCapacity(on bool) {
	p.mu.Lock()
	p.capacity = on
	p.mu.Unlock()
}

func (p *phPassive) setDelay(d time.Duration) {
	p.mu.Lock()
	p.delay = d
	p.mu.Unlock()
}

// on returns the passive carriers of link i, oldest first.
func (p *phPassive) on(i int) []*Conn {
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
func (p *phPassive) close() {
	p.mu.Lock()
	cs := append([]*Conn(nil), p.conns...)
	p.mu.Unlock()
	for _, c := range cs {
		c.Kill(CauseLocalClose, "test end")
		<-c.Done()
	}
}

// phRig is a Health over n links to one passive end. Every link starts
// with a 10 ms one-way delay (a 20 ms probe RTT).
type phRig struct {
	t     testing.TB
	env   *Env
	pas   *phPassive
	links []*rendrtest.Link
	h     *Health
	start time.Time
}

// newPhRig builds the rig inside the caller's bubble; edit may adjust the
// dialer's Env and the parameters first. A cleanup closes the Health, the
// passive carriers and the links, in that order (the probe carriers'
// CLOSE exchange needs the other two).
func newPhRig(t testing.TB, n int, edit func(env *Env, p *HealthParams)) *phRig {
	t.Helper()
	r := &phRig{t: t, env: hEnv(), pas: newPhPassive()}
	p := phParams()
	if edit != nil {
		edit(r.env, &p)
	}
	fs := make([]Factory, n)
	for i := range n {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: fmt.Sprintf("path%d", i), Accept: r.pas.accept(i)})
		l.SetDelay(10*time.Millisecond, 0)
		r.links = append(r.links, l)
		fs[i] = Factory{Index: i, Name: l.Name(), Dial: l.Dial}
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
func (r *phRig) until(d time.Duration) {
	r.t.Helper()
	if w := time.Until(r.start.Add(d)); w > 0 {
		time.Sleep(w)
	}
	synctest.Wait()
}

// since is the virtual time elapsed since the rig started.
func (r *phRig) since() time.Duration { return time.Since(r.start) }

// probe returns factory i's current probe carrier (white-box).
func (r *phRig) probe(i int) *Conn {
	r.h.mu.Lock()
	defer r.h.mu.Unlock()
	return r.h.fac[i].conn
}

// phRank ranks a snapshot's factories at now (as the session actor does
// for Dial and death failover, design §7.3, §7.8).
func phRank(s *Snapshot, now time.Time) []int {
	cs := make([]sched.Candidate, len(s.Sum))
	for i := range cs {
		cs[i] = sched.Candidate{Index: i, Ev: s.Evidence(i, now), Failed: s.Failed[i]}
	}
	return sched.Rank(cs, nil)
}
