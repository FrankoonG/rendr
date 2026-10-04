package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Source is where a Listener gets carriers from. The set is closed: M1 has
// FromListener; M2 adds FromPacketConn.
type Source interface{ isSource() }

type listenerSource struct{ l net.Listener }

func (listenerSource) isSource() {}

// FromListener is a pull source: one accept goroutine per source hands every
// accepted conn to the handshake. Ownership of l moves to the Listener, which
// closes it exactly once on Close. Temporary accept errors (EMFILE) back off
// 5 ms → 100 ms; one failing source never stops another (L50).
func FromListener(l net.Listener) Source { return listenerSource{l: l} }

// ListenConfig configures a Listener.
type ListenConfig struct {
	Sources       []Source      // may be empty: a push-only listener fed by Handle
	AcceptBacklog int           // 128; 1–65536: pending stream sessions of this Listener
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
// from FromListener with a non-nil net.Listener.
func listenSources(srcs []Source) ([]net.Listener, error) {
	out := make([]net.Listener, 0, len(srcs))
	for i, s := range srcs {
		ls, ok := s.(listenerSource)
		if !ok || ls.l == nil {
			return nil, fmt.Errorf("rendr: Listen: source %d is not FromListener of a non-nil net.Listener", i)
		}
		out = append(out, ls.l)
	}
	return out, nil
}

// Listener admits carriers and hands new stream sessions to the application
// for Confirm or Reject. Carriers of sessions that already exist (JOIN,
// duplicate OPEN) are routed by the Runtime, so a carrier may arrive on any
// source or Listener of the Runtime (L50).
type Listener struct {
	rt    *Runtime
	cfg   ListenConfig // normalized
	env   session.Env  // the Env of the sessions this Listener admits (Registry: lnRegistry)
	srcs  []net.Listener
	loops *group // accept loops and source closes

	// mu guards the admission state; a leaf (design §3.2). The ownership of
	// a pending session is either in the queue or with the application
	// (L50): Accept unlinks it, Close refuses every session still pending.
	mu         sync.Mutex
	closed     bool
	reserved   int                            // backlog slots reserved by admissions in progress
	pending    map[*session.Session]*pendItem // sessions holding a backlog slot (queued or accepted, undecided)
	head, tail *pendItem                      // queued sessions in admission order (head = oldest)
	qsig       chan struct{}                  // cap 1: wakes one Accept
	done       chan struct{}                  // closed by Close
}

// pendItem is one session holding a backlog slot of its Listener.
type pendItem struct {
	s          *session.Session
	prev, next *pendItem
	queued     bool // linked in the queue (not yet returned by Accept)
}

func newListener(rt *Runtime, cfg ListenConfig, srcs []net.Listener) *Listener {
	ln := &Listener{
		rt:      rt,
		cfg:     cfg,
		srcs:    srcs,
		loops:   newGroup(),
		pending: make(map[*session.Session]*pendItem),
		qsig:    make(chan struct{}, 1),
		done:    make(chan struct{}),
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

// start launches one accept loop per source.
func (ln *Listener) start() {
	for _, l := range ln.srcs {
		ln.loops.add()
		go ln.acceptLoop(l)
	}
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
// untouched), net.ErrClosed after Close.
func (ln *Listener) Accept(ctx context.Context) (*PendingConn, error) {
	for {
		if err := ctx.Err(); err != nil {
			ln.passSignal()
			return nil, err
		}
		ln.mu.Lock()
		if ln.closed {
			ln.mu.Unlock()
			return nil, net.ErrClosed
		}
		if it := ln.head; it != nil {
			ln.unlinkLocked(it)
			more := ln.head != nil
			ln.mu.Unlock()
			if more {
				ln.signal() // another Accept may take the next one
			}
			if it.s.State() != session.StatePending {
				continue // withdrawn or timed out: its Registry.Ended frees the slot
			}
			return &PendingConn{s: it.s, rt: ln.rt}, nil
		}
		ln.mu.Unlock()
		select {
		case <-ln.qsig:
		case <-ctx.Done():
			ln.passSignal()
			return nil, ctx.Err()
		case <-ln.done:
			return nil, net.ErrClosed
		}
	}
}

// signal wakes one Accept (cap-1 token; a stale token only causes a re-check).
func (ln *Listener) signal() {
	select {
	case ln.qsig <- struct{}{}:
	default:
	}
}

// passSignal hands a wakeup on to another Accept when sessions are queued:
// an Accept that leaves without taking one may have consumed the token.
func (ln *Listener) passSignal() {
	ln.mu.Lock()
	more := ln.head != nil
	ln.mu.Unlock()
	if more {
		ln.signal()
	}
}

// Close stops the sources (closing every FromListener listener exactly
// once, bounded), answers every pending session OPEN_ACK(GOING_AWAY), and
// makes Accept and Handle return net.ErrClosed. Confirmed sessions are not
// affected. Idempotent.
func (ln *Listener) Close() error {
	for _, s := range ln.shut() {
		s.RefusePending(wire.StatusGoingAway, 0)
	}
	ln.loops.wait(time.Now().Add(ln.rt.eff.timing.AbandonWait), ln.rt.abandon)
	ln.rt.mu.Lock()
	delete(ln.rt.listeners, ln)
	ln.rt.mu.Unlock()
	return nil
}

// shut closes the Listener once: Accept and Handle fail from now on, every
// source is closed on a guarded goroutine (an embedder Close may block or
// panic, L50/L51), and the sessions holding a backlog slot are returned for
// the caller to refuse with GOING_AWAY. Later calls return nothing.
func (ln *Listener) shut() []*session.Session {
	ln.mu.Lock()
	if ln.closed {
		ln.mu.Unlock()
		return nil
	}
	ln.closed = true
	close(ln.done)
	refuse := mapKeys(ln.pending)
	ln.mu.Unlock()
	for _, l := range ln.srcs {
		ln.loops.add()
		go func() {
			defer ln.loops.done(ln.rt.abandon)
			defer func() { _ = recover() }()
			_ = l.Close()
		}()
	}
	return refuse
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

// reserve takes a backlog slot for an OPEN being admitted (design §6.2).
func (ln *Listener) reserve() reserveResult {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	switch {
	case ln.closed:
		return reserveClosed
	case len(ln.pending)+ln.reserved >= ln.cfg.AcceptBacklog:
		return reserveFull
	}
	ln.reserved++
	return reserveOK
}

// unreserve returns a slot whose admission created no session.
func (ln *Listener) unreserve() {
	ln.mu.Lock()
	ln.reserved--
	ln.mu.Unlock()
}

// bind turns a reservation into the slot of session s; it runs before
// s.Start, so the session's Registry calls always find it.
func (ln *Listener) bind(s *session.Session) {
	ln.mu.Lock()
	ln.reserved--
	ln.pending[s] = &pendItem{s: s}
	ln.mu.Unlock()
	ln.rt.backlog.Add(1)
}

// enqueue makes the started session s available to Accept and wakes one.
// A session that already ended is skipped; on a closed Listener it is
// refused with GOING_AWAY instead (Close may have run before its slot was
// bound; RefusePending of a session Close already refused does nothing).
func (ln *Listener) enqueue(s *session.Session) {
	ln.mu.Lock()
	it := ln.pending[s]
	if it == nil || it.queued {
		ln.mu.Unlock()
		return
	}
	if ln.closed {
		ln.mu.Unlock()
		s.RefusePending(wire.StatusGoingAway, 0)
		return
	}
	it.prev = ln.tail
	if ln.tail != nil {
		ln.tail.next = it
	} else {
		ln.head = it
	}
	ln.tail = it
	it.queued = true
	ln.mu.Unlock()
	ln.signal()
}

// leavePending frees the backlog slot of s (Registry.Opened or Ended).
func (ln *Listener) leavePending(s *session.Session) {
	ln.mu.Lock()
	it := ln.pending[s]
	if it != nil {
		delete(ln.pending, s)
		if it.queued {
			ln.unlinkLocked(it)
		}
	}
	ln.mu.Unlock()
	if it != nil {
		ln.rt.backlog.Add(-1)
	}
}

func (ln *Listener) unlinkLocked(it *pendItem) {
	if it.prev != nil {
		it.prev.next = it.next
	} else {
		ln.head = it.next
	}
	if it.next != nil {
		it.next.prev = it.prev
	} else {
		ln.tail = it.prev
	}
	it.prev, it.next, it.queued = nil, nil, false
}

// PendingConn is an admitted OPEN waiting for the application's decision.
// It holds a backlog slot until Confirm, Reject or AcceptTimeout.
type PendingConn struct {
	s  *session.Session
	rt *Runtime
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
		return nil, err
	}
	return newConn(p.rt, p.s), nil
}

// Reject refuses the session with OPEN_ACK(REJECTED, code, msg); msg is
// truncated to 255 bytes. The dialer's Dial returns *RejectError{code, msg};
// a retried OPEN gets the same answer. Errors as for Confirm.
func (p *PendingConn) Reject(code uint32, msg string) error {
	return p.s.Reject(code, msg)
}
