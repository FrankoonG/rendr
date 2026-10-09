package carrier

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Pool is one Peer's set of dialer MUX trunks (M3 design §A5.8, §A5.9;
// M3-D16 … M3-D20). It is the fast path of the Peer's OPENs and JOINs: an
// attempt on a mux-eligible factory (Factory.Mux) takes a usable live trunk
// of that factory (a new view, no factory call), else waits for the
// factory's dial already in flight (coalescing: one dial per factory, not
// one per session), else dials itself with wire.OptMux. A pool never
// crosses Peers, keeps no idle trunk, never pre-dials, and closes a trunk
// at its last view.
//
// Lifecycle of a trunk in the pool: the claimant's Establish returns view 1
// of a fresh MUX trunk (Established.Fresh); the factory's dial stays "in
// flight" for later attempts until the session starts view 1 (Conn.Start
// calls poolStarted), which publishes the trunk in trunks[f] and releases
// the waiters to open their views on it (M3-D19). A fresh trunk that dies
// unstarted (the opening race was lost, a check failed, the session ended)
// releases the waiters to retry at once. A published trunk leaves the pool
// when its view count reaches zero: it is sealed and retired with CLOSE
// (§A5.9); its other ends (a dead trunk) leave the same way, as each
// view's Done closes.
//
// Locks: mu is per Pool and never taken under a session lock, Conn.mu or
// trunk.mx; it may take trunk.mx (Pool.mu → trunk.mx) to allocate a view.
type Pool struct {
	env *Env
	fs  []Factory // the Peer's factory snapshot; immutable

	dialTimeout time.Duration // bound of a coalesced wait (M3-D18)

	mu      sync.Mutex
	trunks  [][]*Conn       // per factory: view 1 of each published trunk, oldest first
	dialing []*dialWait     // per factory: the dial in flight that later attempts wait for (nil: none)
	full    map[*trunk]bool // published trunks that answered CAPACITY CodeMuxFull, until a view leaves (§A5.8)
	closed  bool
	stats   PoolStats
}

// dialWait is one factory's dial in flight: its waiters block on done; err
// and release are set before done closes (M3-D18, R1-8). Exactly one party
// closes done: the claimant when its result is not a fresh trunk, else
// whoever settles the fresh trunk (its publication or its death), each
// under Pool.mu.
type dialWait struct {
	done    chan struct{}
	err     error // the claimant's failure, counted once by each waiter (a transport or PREFACE failure)
	release bool  // the waiters retry at once without a failure (a session-level refusal, no mux, a discarded fresh trunk, a cancelled claimant)

	f     int   // the factory slot
	fresh *Conn // view 1 of the claimant's fresh trunk awaiting its Start (M3-D19); nil while dialing and once settled
}

// PoolStats are a Pool's counters (rendr.Status.Mux, dialer side).
type PoolStats struct {
	Carriers  int    // published trunks that are not closed
	Views     int    // views on them that are not gone
	FastPaths uint64 // OPENs and JOINs placed on a live trunk instead of dialling
	Coalesced uint64 // attempts that waited for another attempt's dial of the same factory
	MuxFull   uint64 // CAPACITY CodeMuxFull answers received
}

// NewPool returns the Pool of a Peer with factory snapshot fs.
func NewPool(env *Env, fs []Factory) *Pool {
	return &Pool{
		env:         env,
		fs:          append([]Factory(nil), fs...),
		dialTimeout: env.Timing.withDefaults().DialTimeout,
		trunks:      make([][]*Conn, len(fs)),
		dialing:     make([]*dialWait, len(fs)),
	}
}

// Attempt opens one carrier of factory f for a session (M3-D16): for a
// factory that is not mux-eligible it is Establish (M2); otherwise a fast
// path view on a usable trunk (M3-D17), a coalesced wait for the factory's
// dial in flight (bounded by ctx, M3-D18), or its own Establish with
// wire.OptMux, whose fresh trunk (Established.Fresh) the pool publishes
// when the session starts view 1 (M3-D19). cid is the CarrierID reserved
// for a dial (released when a fast path or a wait serves the attempt);
// kind and payload are the first frame (OPEN or JOIN); check verifies the
// PREFACE_ACK as for Establish; inst is the session's bound instance for a
// JOIN (zero for an OPEN); sess identifies the session (one unreaped view
// per trunk, R1-6). Errors are Establish's; a fast path that fails before
// its first frame was placed continues with a dial and counts no failure.
//
// Further contracts of this implementation: a fast path refused with
// CAPACITY CodeMuxFull (the trunk is then full until a view leaves) or,
// for an OPEN, CodeListenerClosed (the trunk takes no further OPEN, R1-10)
// is a carrier refusal without penalty: the attempt continues with a dial
// (or a wait, or another trunk) instead of returning the refusal. A
// coalesced wait that outlasts Timing.DialTimeout fails like an attempt
// that hit its DialTimeout (a path failure, L20). After Close every
// attempt dials a dedicated carrier (no OptMux).
func (p *Pool) Attempt(ctx context.Context, f int, cid uint32, kind wire.Type, payload []byte, check func(*wire.PrefaceAck) error, inst [16]byte, sess uintptr) (*Established, error) {
	fac := p.fs[f]
	if !fac.Mux || (kind != wire.TypeOpen && kind != wire.TypeJoin) {
		return Establish(ctx, p.env, fac, cid, kind, payload, check)
	}
	dk := sessionDataType(kind, payload)
	var (
		skip    []*trunk    // trunks this attempt does not try again (openView failed, refused, died)
		timer   *time.Timer // the coalesced wait's DialTimeout (from the first wait)
		counted bool        // Coalesced counted for this attempt
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			fac.Mux = false // no fresh MUX trunk once the pool stopped publishing
			return Establish(ctx, p.env, fac, cid, kind, payload, check)
		}
		if c := p.pickLocked(f, dk, inst, sess, skip); c != nil {
			v, err := c.openView(kind, payload, sess)
			if err != nil {
				// E3: the trunk died (or sealed, or filled) between the usable
				// check and the allocation; this attempt continues without it.
				p.mu.Unlock()
				skip = append(skip, c.trunk)
				continue
			}
			p.stats.FastPaths++
			p.mu.Unlock()
			est, err := v.awaitResponse(ctx, check)
			if retry := p.fastPathRetry(ctx, v, est, err); retry {
				skip = append(skip, c.trunk) // a refusal or a death: never the same trunk again in this attempt
				continue
			}
			p.releaseCID(cid)
			return est, err
		}
		if w := p.dialing[f]; w != nil {
			if !counted {
				p.stats.Coalesced++
				counted = true
			}
			p.mu.Unlock()
			if timer == nil {
				timer = time.NewTimer(p.dialTimeout)
			}
			select {
			case <-w.done:
				if w.release || w.err == nil {
					continue // published (it is usable now) or released: retry at once
				}
				p.releaseCID(cid)
				return nil, w.err
			case <-ctx.Done():
				p.releaseCID(cid)
				return nil, &EstablishError{Stage: "dial", Cause: CauseLocalClose, Err: context.Cause(ctx)}
			case <-timer.C:
				p.releaseCID(cid)
				return nil, &EstablishError{Stage: "dial", Cause: CauseTransportError, Err: fmt.Errorf("%w (waiting for the factory's dial in flight)", errDialTimeout)}
			}
		}
		w := &dialWait{done: make(chan struct{}), f: f}
		p.dialing[f] = w
		p.mu.Unlock()
		est, err := Establish(ctx, p.env, fac, cid, kind, payload, check)
		p.claimed(ctx, w, est, err, sess)
		return est, err
	}
}

// sessionDataType returns the data frame type of the session an attempt
// is for (usableFor's kind, M3-D24): wire.TypeDgram for a packet session,
// wire.TypeData for a stream session. An OPEN carries the session kind; a
// JOIN does not, and needs no kind check: every trunk of a factory has the
// factory's kind, and a stream session dials no datagram factory, so a
// JOIN is treated as a packet session's (no trunk excluded by kind).
func sessionDataType(kind wire.Type, payload []byte) wire.Type {
	if kind == wire.TypeOpen {
		if o, err := wire.ParseOpen(payload, len(payload)); err == nil && o.Kind == wire.KindStream {
			return wire.TypeData
		}
	}
	return wire.TypeDgram
}

// pickLocked returns view 1 of the trunk of factory f a new view of session
// sess goes on (M3-D17): among the usable published trunks the one with the
// most views below the cap, then the oldest; nil when none is usable.
func (p *Pool) pickLocked(f int, dk wire.Type, inst [16]byte, sess uintptr, skip []*trunk) *Conn {
	var best *Conn
	bestN := -1
next:
	for _, c := range p.trunks[f] {
		for _, s := range skip {
			if s == c.trunk {
				continue next
			}
		}
		if p.full[c.trunk] || !c.usableFor(dk, inst, sess) {
			continue
		}
		if n := c.viewCount(); n > bestN {
			best, bestN = c, n
		}
	}
	return best
}

// fastPathRetry classifies a fast path's result: true when the attempt
// continues (a carrier refusal without penalty — CodeMuxFull, or
// CodeListenerClosed for an OPEN, R1-10 — or a trunk that ended before the
// view's first frame was placed); false when the result is the attempt's.
func (p *Pool) fastPathRetry(ctx context.Context, v *Conn, est *Established, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if err == nil {
		st, code, ok := responseStatus(est.Resp, est.Payload)
		if !ok || st != wire.StatusCapacity {
			return false
		}
		switch {
		case code == wire.CodeMuxFull:
			p.mu.Lock()
			p.stats.MuxFull++
			if p.full == nil {
				p.full = make(map[*trunk]bool)
			}
			p.full[v.trunk] = true // until a view leaves (viewGone)
			p.mu.Unlock()
			return true
		case code == wire.CodeListenerClosed && est.Resp.Type == wire.TypeOpenAck:
			return true
		}
		return false
	}
	var ee *EstablishError
	if !errors.As(err, &ee) || ee.Cause != CauseTransportError {
		return false // a check failure (the view ended, never the trunk) is the attempt's result
	}
	v.mx.Lock()
	unplaced := v.state == viewGone && !v.vx.refused && !v.vx.respGot
	v.mx.Unlock()
	return unplaced
}

// responseStatus returns the status and code of a response frame (OPEN_ACK
// or JOIN_ACK); ok is false for any other frame or a malformed payload.
func responseStatus(h wire.Header, p []byte) (st wire.AckStatus, code uint32, ok bool) {
	switch h.Type {
	case wire.TypeOpenAck:
		a, err := wire.ParseOpenAck(p)
		return a.Status, a.Code, err == nil
	case wire.TypeJoinAck:
		a, err := wire.ParseJoinAck(p)
		return a.Status, 0, err == nil
	}
	return 0, 0, false
}

// claimed settles the claimant's dial w with its Establish result (M3-D18,
// M3-D19, R1-8): an OK response on a MUX trunk keeps w in flight until the
// session starts or discards the fresh trunk; anything else ends w at once
// — the waiters fail with a transport or PREFACE failure, and retry at
// once after any other outcome (a session-level refusal of handle 1, a
// trunk without mux, a check of the claimant's own session, the claimant
// cancelled by its own session; a DialTimeout expiry stays a failure).
func (p *Pool) claimed(ctx context.Context, w *dialWait, est *Established, err error, sess uintptr) {
	if est != nil {
		est.Fresh = false
	}
	p.mu.Lock()
	if err == nil && est.Conn.Mux() {
		if st, _, ok := responseStatus(est.Resp, est.Payload); ok && st == wire.StatusOK {
			c := est.Conn
			est.Fresh = true
			c.owner = p
			c.bindSession(sess)
			f := w.f
			c.onViewDone(func(v *Conn) { p.viewGone(f, c, v) })
			w.fresh = c
			p.mu.Unlock()
			go p.watchFresh(w, c)
			return
		}
	}
	if p.dialing[w.f] == w {
		p.dialing[w.f] = nil
	}
	if err != nil && !claimantReleases(ctx, err) {
		w.err = err
	} else {
		w.release = true
	}
	p.mu.Unlock()
	close(w.done)
}

// claimantReleases reports whether a failed claimant releases its waiters
// instead of failing them (R1-8): its own context ended other than by a
// deadline (withdrawal, its session ending), or its own session's check
// rejected the PREFACE_ACK (a bound instance or the gone-away set: other
// sessions decide for themselves).
func claimantReleases(ctx context.Context, err error) bool {
	if errors.Is(err, ErrWithdrawn) || errors.Is(err, context.Canceled) {
		return true
	}
	if ctx.Err() != nil && !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return true
	}
	var ee *EstablishError
	return errors.As(err, &ee) && ee.Cause == CauseInstanceMismatch
}

// watchFresh settles a fresh trunk that dies before its session starts it
// (M3-D19: discarded, its waiters retry at once). It returns once w is
// settled either way.
func (p *Pool) watchFresh(w *dialWait, c *Conn) {
	select {
	case <-w.done:
	case <-c.dying:
		p.settle(w, c)
	}
}

// poolStarted is called by Conn.Start on view 1 of a dialer trunk once the
// trunk runs: the trunk's pool publishes it (M3-D19). A no-op on a trunk
// no pool owns, and idempotent.
func (c *Conn) poolStarted() {
	if c.trunk != nil && c.owner != nil {
		c.owner.settle(nil, c)
	}
}

// settle ends the in-flight state of fresh trunk c (view 1): published when
// it runs, else discarded; either way its waiters retry at once (they find
// the published trunk usable). w is c's dialWait when the caller knows it.
// Idempotent.
func (p *Pool) settle(w *dialWait, c *Conn) {
	p.mu.Lock()
	if w == nil {
		for _, d := range p.dialing {
			if d != nil && d.fresh == c {
				w = d
				break
			}
		}
	}
	if w == nil || w.fresh != c {
		p.mu.Unlock()
		return
	}
	if p.dialing[w.f] == w {
		p.dialing[w.f] = nil
	}
	w.fresh, w.release = nil, true
	if c.death.Load() == nil && c.ms.started.Load() {
		if c.viewCount() > 0 {
			p.trunks[w.f] = append(p.trunks[w.f], c)
		} else {
			// Every view ended before the publication (view 1 killed or
			// retired right after its Start): close at zero (M3-D20).
			c.seal()
			c.retireTrunk(wire.CloseRetire)
		}
	}
	p.mu.Unlock()
	close(w.done)
}

// viewGone is the trunk's view hook (onViewDone): view v of trunk c (view
// 1) of factory f ended. A view that leaves (not a handle refused at its
// opening) ends the trunk's CodeMuxFull mark. At zero views a published
// trunk leaves the pool, is sealed and retired with CLOSE (M3-D20,
// §A5.9). The count and the view allocation both change under Pool.mu, so
// an openView racing the close either counted first (no close) or finds
// the trunk gone and dials.
func (p *Pool) viewGone(f int, c, v *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v.mx.Lock()
	refused := v.vx.refused
	v.mx.Unlock()
	if !refused {
		delete(p.full, c.trunk)
	}
	ts := p.trunks[f]
	i := 0
	for i < len(ts) && ts[i] != c {
		i++
	}
	if i == len(ts) || c.viewCount() > 0 {
		return // not published (still in flight, or discarded), or views remain
	}
	copy(ts[i:], ts[i+1:])
	ts[len(ts)-1] = nil
	p.trunks[f] = ts[:len(ts)-1]
	delete(p.full, c.trunk)
	c.seal()
	c.retireTrunk(wire.CloseRetire)
}

// releaseCID returns the CarrierID reserved for a dial the attempt did not
// make.
func (p *Pool) releaseCID(cid uint32) {
	if p.env.IDs != nil && cid != 0 {
		p.env.IDs.Release(cid)
	}
}

// Close stops publishing and fast paths (Peer.Close keeps the pool's
// trunks until their last views end; Runtime.Close joins them).
// Idempotent.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

// Stats returns a snapshot of the pool's counters.
func (p *Pool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats
	for _, ts := range p.trunks {
		for _, c := range ts {
			if c.death.Load() != nil {
				continue
			}
			s.Carriers++
			s.Views += c.viewCount()
		}
	}
	return s
}
