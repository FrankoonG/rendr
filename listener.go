package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Source is where a Listener gets carriers from. The set is closed:
// FromListener (stream carriers) and FromPacketConn (raw-UDP datagram
// carriers).
type Source interface{ isSource() }

type listenerSource struct{ l net.Listener }

func (listenerSource) isSource() {}

// FromListener is a pull source: one accept goroutine per source hands every
// accepted conn to the handshake. Ownership of l moves to the Listener, which
// closes it exactly once on Close; l must therefore be given to one Listener
// only, once (Listen rejects a ListenConfig that repeats it). Temporary
// accept errors (EMFILE) back off 5 ms → 100 ms; one failing source never
// stops another.
func FromListener(l net.Listener) Source { return listenerSource{l: l} }

// ListenConfig configures a Listener.
type ListenConfig struct {
	Sources       []Source      // may be empty: a push-only listener fed by Handle and HandlePacket
	AcceptBacklog int           // 128; 1–65536: pending sessions of this Listener, per session kind (stream: Accept; packet: AcceptPacket)
	AcceptTimeout time.Duration // 10 s; 0.1 s–60 s: then OPEN_ACK(CAPACITY, accept timeout)
}

// Accept-loop backoff on temporary errors (L50).
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = 100 * time.Millisecond
)

// errNilConn: Handle was given no conn.
var errNilConn = errors.New("rendr: Handle: nil conn")

// listenSources validates a ListenConfig's sources: every one must come
// from FromListener with a non-nil net.Listener or from FromPacketConn with
// a non-nil net.PacketConn, and no listener or socket may appear twice (it
// would get two accept or demux loops and two Closes, while both promise
// exactly one).
func listenSources(srcs []Source) ([]net.Listener, []net.PacketConn, error) {
	var (
		out        = make([]net.Listener, 0, len(srcs))
		pout       []net.PacketConn
		lidx, pidx []int // the srcs index of each element of out and pout
	)
	for i, s := range srcs {
		switch v := s.(type) {
		case listenerSource:
			if v.l == nil {
				break
			}
			for j, prev := range out {
				if sameValue(prev, v.l) {
					return nil, nil, fmt.Errorf("rendr: Listen: source %d repeats the net.Listener of source %d", i, lidx[j])
				}
			}
			out, lidx = append(out, v.l), append(lidx, i)
			continue
		case packetSource:
			if v.pc == nil {
				break
			}
			for j, prev := range pout {
				if sameValue(prev, v.pc) {
					return nil, nil, fmt.Errorf("rendr: Listen: source %d repeats the net.PacketConn of source %d", i, pidx[j])
				}
			}
			pout, pidx = append(pout, v.pc), append(pidx, i)
			continue
		}
		return nil, nil, fmt.Errorf("rendr: Listen: source %d is neither FromListener of a non-nil net.Listener nor FromPacketConn of a non-nil net.PacketConn", i)
	}
	return out, pout, nil
}

// sameValue reports whether a and b are the same interface value; an
// implementation whose dynamic type is not comparable is never the same.
func sameValue[T any](a, b T) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return any(a) == any(b)
}

// Listener admits carriers and hands new sessions to the application for
// Confirm or Reject: stream sessions through Accept, packet sessions
// through AcceptPacket, each kind with its own backlog. Carriers of
// sessions that already exist (JOIN, duplicate OPEN) are routed by the
// Runtime, so a carrier may arrive on any source or Listener of the
// Runtime.
type Listener struct {
	rt    *Runtime
	cfg   ListenConfig // normalized
	env   session.Env  // the Env of the sessions this Listener admits (Registry: lnRegistry)
	srcs  []net.Listener
	psrcs []*udpflow.Source // FromPacketConn sources (listener_pkt.go)
	loops *group            // accept loops and source closes

	// mu guards the admission state; a leaf (design §3.2). The ownership of
	// a pending session is either in its kind's queue or with the
	// application (L50): Accept and AcceptPacket unlink it, Close refuses
	// every session still pending.
	mu      sync.Mutex
	closed  bool
	q       [numKinds]pendQueue            // per session kind: [kindIdxStream] Accept, [kindIdxPacket] AcceptPacket
	pending map[*session.Session]*pendItem // sessions holding a backlog slot (queued or accepted, undecided)
	done    chan struct{}                  // closed by Close
}

// Session kinds as indices of the per-kind admission state
// (Listener.q, Status.AcceptBacklog; M2 design §A5.14).
const (
	kindIdxStream = 0
	kindIdxPacket = 1
	numKinds      = 2
)

// kindIdx is the index of a session or OPEN kind.
func kindIdx(k wire.CarrierKind) int {
	if k == wire.KindDatagram {
		return kindIdxPacket
	}
	return kindIdxStream
}

// pendQueue is the backlog of one session kind of a Listener (guarded by
// Listener.mu, except sig).
type pendQueue struct {
	reserved   int           // backlog slots reserved by admissions in progress
	n          int           // sessions of this kind holding a backlog slot
	head, tail *pendItem     // queued sessions in admission order (head = oldest)
	sig        chan struct{} // cap 1: wakes one Accept (or AcceptPacket)
}

// pendItem is one session holding a backlog slot of its Listener.
type pendItem struct {
	s          *session.Session
	k          int // kind index
	prev, next *pendItem
	queued     bool        // linked in the queue (not yet returned by Accept)
	shut       atomic.Bool // the Listener closed while the session held its slot
}

func newListener(rt *Runtime, cfg ListenConfig, srcs []net.Listener) *Listener {
	ln := &Listener{
		rt:      rt,
		cfg:     cfg,
		srcs:    srcs,
		loops:   newGroup(),
		pending: make(map[*session.Session]*pendItem),
		done:    make(chan struct{}),
	}
	for k := range ln.q {
		ln.q[k].sig = make(chan struct{}, 1)
	}
	ln.env = session.Env{
		Carrier:  &rt.cenv,
		Events:   rt.ev, // a nil *eventQueue discards every event
		Registry: lnRegistry{ln},
		Rand:     rt.eff.rand,
		Hooks:    rt.eff.hooks,
	}
	return ln
}

// start launches one accept loop per stream source and one demux loop per
// packet source.
func (ln *Listener) start() {
	for _, l := range ln.srcs {
		ln.loops.add()
		go ln.acceptLoop(l)
	}
	ln.startPacketSources()
}

// Handle pushes one embedder-accepted carrier into the handshake and
// returns at once (the handshake runs on its own goroutine bounded by
// Handshake.Timeout). It returns net.ErrClosed after Close; c is then closed.
func (ln *Listener) Handle(c net.Conn) error {
	if c == nil {
		return errNilConn
	}
	if !ln.beginHandshake() {
		carrier.CloseConn(&ln.rt.cenv, c)
		return net.ErrClosed
	}
	ln.rt.startHandshake(ln, c, time.Now())
	return nil
}

// beginHandshake counts one more handshake unless the Listener is closed.
// The check and the count share the Listener's lock with Close, so a
// closed Listener never starts a handshake that Runtime.Close would miss.
func (ln *Listener) beginHandshake() bool {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.closed {
		return false
	}
	ln.rt.hsg.add()
	return true
}

// acceptLoop hands every conn l accepts to the handshake (no blocking I/O
// here, L48). Temporary errors back off 5 ms → 100 ms; a permanent error
// stops this source only (L50); Close ends the loop. A panic in Accept is
// a permanent error of the source; a runtime.Goexit ends the loop through
// its deferred accounting.
func (ln *Listener) acceptLoop(l net.Listener) {
	defer ln.loops.done(ln.rt.abandon)
	var delay time.Duration
	for {
		nc, err := acceptOne(l)
		if err != nil || nc == nil {
			if nc != nil {
				carrier.CloseConn(&ln.rt.cenv, nc) // (conn, err): the conn is closed once
			}
			if ln.isClosed() || (err != nil && !temporary(err)) {
				return
			}
			delay = min(max(2*delay, acceptBackoffMin), acceptBackoffMax)
			if !ln.pause(delay) {
				return
			}
			continue
		}
		delay = 0
		if !ln.beginHandshake() {
			carrier.CloseConn(&ln.rt.cenv, nc)
			return
		}
		ln.rt.startHandshake(ln, nc, time.Now())
	}
}

// acceptOne calls l.Accept with a panic turned into an error (L51).
func acceptOne(l net.Listener) (nc net.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			nc, err = nil, fmt.Errorf("rendr: listener Accept panicked: %v", r)
		}
	}()
	return l.Accept()
}

// temporary reports an accept error worth retrying: a net.Error whose
// Temporary or Timeout is true (EMFILE, ENFILE, ECONNABORTED, ...).
func temporary(err error) bool {
	var t interface{ Temporary() bool }
	if errors.As(err, &t) && t.Temporary() {
		return true
	}
	var to interface{ Timeout() bool }
	return errors.As(err, &to) && to.Timeout()
}

// pause sleeps d unless the Listener closes first (false).
func (ln *Listener) pause(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ln.done:
		return false
	}
}

// Accept returns the next pending stream session, in admission order,
// skipping sessions that were withdrawn or timed out. It returns exactly one
// of (*PendingConn, nil) or (nil, err): ctx.Err() when ctx ends (the queue is
// untouched), net.ErrClosed after Close. Packet sessions wait for
// AcceptPacket.
func (ln *Listener) Accept(ctx context.Context) (*PendingConn, error) {
	it, err := ln.next(ctx, kindIdxStream)
	if err != nil {
		return nil, err
	}
	return &PendingConn{s: it.s, rt: ln.rt, it: it}, nil
}

// next returns the oldest pending session of kind k that is still pending
// (Accept, AcceptPacket).
func (ln *Listener) next(ctx context.Context, k int) (*pendItem, error) {
	q := &ln.q[k]
	for {
		if err := ctx.Err(); err != nil {
			ln.passSignal(k)
			return nil, err
		}
		ln.mu.Lock()
		if ln.closed {
			ln.mu.Unlock()
			return nil, net.ErrClosed
		}
		if it := q.head; it != nil {
			ln.unlinkLocked(it)
			more := q.head != nil
			ln.mu.Unlock()
			if more {
				ln.signal(k) // another Accept may take the next one
			}
			if it.s.State() != session.StatePending {
				continue // withdrawn or timed out: its Registry.Ended frees the slot
			}
			return it, nil
		}
		ln.mu.Unlock()
		select {
		case <-q.sig:
		case <-ctx.Done():
			ln.passSignal(k)
			return nil, ctx.Err()
		case <-ln.done:
			return nil, net.ErrClosed
		}
	}
}

// signal wakes one Accept of kind k (cap-1 token; a stale token only
// causes a re-check).
func (ln *Listener) signal(k int) {
	select {
	case ln.q[k].sig <- struct{}{}:
	default:
	}
}

// passSignal hands a wakeup on to another Accept of kind k when sessions
// are queued: an Accept that leaves without taking one may have consumed
// the token.
func (ln *Listener) passSignal(k int) {
	ln.mu.Lock()
	more := ln.q[k].head != nil
	ln.mu.Unlock()
	if more {
		ln.signal(k)
	}
}

// Close stops the sources (closing every FromListener listener exactly
// once, bounded; a FromPacketConn socket stops admitting and closes once
// its last flow ended, M2-D58) and makes Accept, AcceptPacket, Handle and
// HandlePacket return net.ErrClosed; Confirm and Reject of a PendingConn
// or PendingPacket it refused return net.ErrClosed. The OPENs it can no
// longer take are answered by where they arrive:
//
//   - Every session that is still pending, and every OPEN that arrives
//     afterwards as the first frame of a carrier of its own — a dedicated
//     carrier, or handle 1 of a new rendr mux trunk — whose handshake on
//     this Listener completes after Close, is answered
//     OPEN_ACK(CAPACITY, CodeBacklog): the dialer's Dial returns
//     ErrCapacity.
//   - An OPEN for a new handle on a live rendr mux trunk this Listener
//     accepted (a view of a carrier other sessions share) is answered
//     OPEN_ACK(CAPACITY, CodeListenerClosed) (M3-D63, R1-10;
//     TestMuxOpenAfterListenerClose_L50). That is a carrier refusal without
//     penalty: that dial attempt does not OPEN on that trunk again and goes
//     on with another live trunk of the same factory or a new carrier of
//     it, so the Dial does not return ErrCapacity from that answer. No
//     lasting mark is kept: each later attempt, of this Dial or another,
//     is refused there once more while the trunk lives. Where the new
//     carrier reaches another Listener of the Runtime, the session is
//     admitted there as usual; where it reaches only this Listener's
//     closed source (its Handle and HandlePacket refuse it), the carrier
//     fails as a path failure, the session redials, and the Dial returns
//     ErrNoPath once its NoPathGrace ran out.
//
// JOINs on the live trunks this Listener accepted are still admitted.
// Confirmed sessions are not affected (their carriers may arrive through
// any Listener), and the Runtime keeps admitting through its other
// Listeners. A Listener's Close is not the instance going away, so it
// never answers GOING_AWAY, which makes a dialer's Peer stop OPENing to
// the whole instance; only Runtime.Close does. Idempotent.
func (ln *Listener) Close() error {
	if refuse := ln.shut(); len(refuse) > 0 {
		st, code := ln.refusal() // GOING_AWAY only when Runtime.Close runs concurrently
		for _, s := range refuse {
			s.RefusePending(st, code)
		}
	}
	ln.loops.wait(time.Now().Add(ln.rt.eff.timing.AbandonWait), ln.rt.abandon)
	ln.rt.mu.Lock()
	delete(ln.rt.listeners, ln)
	ln.rt.mu.Unlock()
	return nil
}

// shut closes the Listener once: Accept, AcceptPacket, Handle and
// HandlePacket fail from now on, every FromListener source is closed on a
// guarded goroutine (an embedder Close may block or panic, L50/L51), every
// FromPacketConn source stops admitting (its socket closes after its last
// flow, M2-D58), and the sessions holding a backlog slot are marked and
// returned for the caller to refuse (Listener.Close; Runtime.Close shuts
// them down instead). Later calls return nothing.
func (ln *Listener) shut() []*session.Session {
	ln.mu.Lock()
	if ln.closed {
		ln.mu.Unlock()
		return nil
	}
	ln.closed = true
	close(ln.done)
	refuse := make([]*session.Session, 0, len(ln.pending))
	for s, it := range ln.pending {
		it.shut.Store(true) // before the refusal: a Confirm that loses to it sees the mark
		refuse = append(refuse, s)
	}
	ln.mu.Unlock()
	for _, l := range ln.srcs {
		ln.loops.add()
		go func() {
			defer ln.loops.done(ln.rt.abandon)
			defer func() { _ = recover() }()
			_ = l.Close()
		}()
	}
	for _, src := range ln.psrcs {
		src.Stop()
	}
	return refuse
}

// refusal is the answer to an OPEN this Listener cannot take any more
// (design §6.2, §6.8): GOING_AWAY while the Runtime closes — the whole
// instance goes away and the dialer's Peer never OPENs to it again (D21) —
// else CAPACITY(CodeBacklog) once this Listener closed: the Runtime keeps
// running, so the instance must not be recorded as gone away. StatusOK
// while the Listener admits.
func (ln *Listener) refusal() (wire.AckStatus, uint32) {
	switch {
	case ln.rt.closing.Load():
		return wire.StatusGoingAway, 0
	case ln.isClosed():
		return wire.StatusCapacity, wire.CodeBacklog
	}
	return wire.StatusOK, 0
}

// viewRefusal is refusal for an OPEN; view reports an OPEN for a new handle
// on a live MUX trunk this Listener accepted (M3-D63, R1-10): there a
// closed Listener answers CAPACITY CodeListenerClosed — a carrier refusal
// after which that dial attempt does not OPEN on that trunk again and
// takes another live trunk or dials instead (the dial then reaches the
// closed listening socket), without touching its Peer's gone-away set or
// marking the trunk for later attempts; JOINs on the trunk are still
// admitted.
func (ln *Listener) viewRefusal(view bool) (wire.AckStatus, uint32) {
	st, code := ln.refusal()
	if view && st == wire.StatusCapacity {
		code = wire.CodeListenerClosed
	}
	return st, code
}

func (ln *Listener) isClosed() bool {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	return ln.closed
}

// reserveResult is the outcome of a backlog reservation.
type reserveResult uint8

const (
	reserveOK reserveResult = iota
	reserveClosed
	reserveFull
)

// reserve takes a backlog slot of kind k for an OPEN being admitted (design
// §6.2); each session kind has its own AcceptBacklog (plan §4).
func (ln *Listener) reserve(k int) reserveResult {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	q := &ln.q[k]
	switch {
	case ln.closed:
		return reserveClosed
	case q.n+q.reserved >= ln.cfg.AcceptBacklog:
		return reserveFull
	}
	q.reserved++
	return reserveOK
}

// unreserve returns a slot of kind k whose admission created no session.
func (ln *Listener) unreserve(k int) {
	ln.mu.Lock()
	ln.q[k].reserved--
	ln.mu.Unlock()
}

// bind turns a reservation of kind k into the slot of session s; it runs
// before s.Start, so the session's Registry calls always find it.
func (ln *Listener) bind(s *session.Session, k int) {
	ln.mu.Lock()
	ln.q[k].reserved--
	ln.q[k].n++
	ln.pending[s] = &pendItem{s: s, k: k}
	ln.mu.Unlock()
	ln.rt.backlog[k].Add(1)
}

// enqueue makes the started session s available to its kind's Accept and
// wakes one. A session that already ended is skipped; on a closed Listener
// it is refused instead (refusal: CAPACITY, or GOING_AWAY while the Runtime
// closes), as Close may have run before its slot was bound; RefusePending
// of a session that was already refused or shut down does nothing.
func (ln *Listener) enqueue(s *session.Session) {
	ln.mu.Lock()
	it := ln.pending[s]
	if it == nil || it.queued {
		ln.mu.Unlock()
		return
	}
	if ln.closed {
		ln.mu.Unlock()
		s.RefusePending(ln.refusal())
		return
	}
	q := &ln.q[it.k]
	it.prev = q.tail
	if q.tail != nil {
		q.tail.next = it
	} else {
		q.head = it
	}
	q.tail = it
	it.queued = true
	ln.mu.Unlock()
	ln.signal(it.k)
}

// leavePending frees the backlog slot of s (Registry.Opened or Ended).
func (ln *Listener) leavePending(s *session.Session) {
	if h := ln.rt.eff.hooks; h != nil && h.LeavePending != nil {
		h.LeavePending(s.ID())
	}
	ln.mu.Lock()
	it := ln.pending[s]
	if it != nil {
		delete(ln.pending, s)
		ln.q[it.k].n--
		if it.queued {
			ln.unlinkLocked(it)
		}
	}
	ln.mu.Unlock()
	if it != nil {
		ln.rt.backlog[it.k].Add(-1)
	}
}

func (ln *Listener) unlinkLocked(it *pendItem) {
	q := &ln.q[it.k]
	if it.prev != nil {
		it.prev.next = it.next
	} else {
		q.head = it.next
	}
	if it.next != nil {
		it.next.prev = it.prev
	} else {
		q.tail = it.prev
	}
	it.prev, it.next, it.queued = nil, nil, false
}

// PendingConn is an admitted OPEN waiting for the application's decision.
// It holds a backlog slot until Confirm, Reject or AcceptTimeout.
type PendingConn struct {
	s  *session.Session
	rt *Runtime
	it *pendItem // its backlog slot: marked when the Listener closed
}

// ID returns the session ID.
func (p *PendingConn) ID() SessionID { return SessionID(p.s.ID()) }

// Mode returns the mode requested by the dialer.
func (p *PendingConn) Mode() Mode { return Mode(p.s.Mode()) }

// Metadata returns the dialer's OPEN metadata (owned by the PendingConn; do
// not modify).
func (p *PendingConn) Metadata() []byte { return p.s.Metadata() }

// PeerInstance returns the dialer's InstanceID.
func (p *PendingConn) PeerInstance() InstanceID { return InstanceID(p.s.PeerInstance()) }

// Confirm accepts the session: OPEN_ACK(OK) goes out on every carrier that
// carried this OPEN, and the returned *Conn is the passive end. Errors:
// ErrSessionLost if the dialer withdrew, ErrCapacity if AcceptTimeout already
// answered, net.ErrClosed after Listener.Close or Runtime.Close, an error for
// a second decision.
func (p *PendingConn) Confirm() (*Conn, error) {
	if err := p.s.Confirm(); err != nil {
		return nil, decisionErr(p.it, err)
	}
	return newConn(p.rt, p.s), nil
}

// Reject refuses the session with OPEN_ACK(REJECTED, code, msg); msg is
// truncated to 255 bytes. The dialer's Dial returns *RejectError{code, msg};
// a retried OPEN gets the same answer. On this side the session ends with an
// error matching ErrRejected (its EventSessionEnd). Errors as for Confirm.
func (p *PendingConn) Reject(code uint32, msg string) error {
	return decisionErr(p.it, p.s.Reject(code, msg))
}

// decisionErr is the error of a Confirm or Reject of the session holding
// backlog slot it: the session's own, except that a session its Listener's
// Close refused — answered CAPACITY, so that the dialer does not take the
// instance for gone away — reports net.ErrClosed like every call on a
// closed Listener (design §9).
func decisionErr(it *pendItem, err error) error {
	if err != nil && it != nil && it.shut.Load() && errors.Is(err, ErrCapacity) {
		return net.ErrClosed
	}
	return err
}
