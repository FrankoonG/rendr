package l4

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// The ingress's bounds and timings (M6-D25 … M6-D29; constants, R1-15:
// no criterion needs them configurable).
const (
	// ingressReadBuf is the reader's buffer: every UDP datagram fits, so
	// an oversize one is measured, never truncated (M6-D25, L71).
	ingressReadBuf = 64 << 10
	// ingressOpeningMax bounds the flows in the opening stage per
	// PortForward (M6-D27): beyond it a new client's datagram is
	// DropOpening.
	ingressOpeningMax = 256
	// ingressQueueLen and ingressQueueBytes bound an opening flow's queue
	// (each copy charged at its pool class, R1-15), beside its first
	// datagram's own copy; ingressQueueAge drops what waited longer at the
	// flush.
	ingressQueueLen   = 8
	ingressQueueBytes = 16 << 10
	ingressQueueAge   = time.Second
	// ingressOpenBound bounds one DialUDP (R1-3): the default packet
	// AcceptTimeout (10 s) plus 2 s, so a passive that never accepts is
	// seen as ErrCapacity and a classified dial failure reaches the
	// ingress.
	ingressOpenBound = 12 * time.Second
	// ingressHold is how long a refused source is held (M6-D28), and
	// ingressReopenHold the age of a flow under which its PeerClosed end
	// holds the source too (the reopen rate limit, R1-2).
	ingressHold       = 5 * time.Second
	ingressReopenHold = 5 * time.Second
	// ingressSample entries of a full table are sampled for a victim
	// (M6-D29); under promoteActive an open flow that never became a
	// stream is one once its last datagram is ingressEvictIdle old.
	ingressSample    = 8
	ingressEvictIdle = time.Second
	// ingressSettle bounds how long a flow that the stop closed waits for
	// its session's end (Done) before it reads the session's drop counters
	// (R1-38): the largest Packet.MaxAge (2 s), within which a session
	// without a carrier has dropped every datagram it still held, plus
	// 100 ms.
	ingressSettle = 2*time.Second + 100*time.Millisecond
)

// flowTable is one ServeUDP socket's table: the flows by client address
// (M6-D24) under one mutex. No call into rendr or the socket is made under
// it (M6-D26, R1-13).
type flowTable struct {
	mu      sync.Mutex
	m       map[netip.AddrPort]*ingressFlow
	stopped bool // the serve is stopping: no flow becomes open or held
}

// ingressFlow is one table entry: a client's flow, opening, open or held.
// Exactly one goroutine belongs to it (udpServe.flow, M6-D26).
type ingressFlow struct {
	client netip.AddrPort
	since  time.Duration // its first datagram, as an offset from the serve's base
	last   atomic.Int64  // its latest datagram in either direction, an offset from the base (ns)
	class  flowClass
	done   chan struct{} // closed once when an eviction removes it (R1-5)

	// closeOnce closes the flow's session exactly once (§A5.4): at its
	// goroutine's end, or earlier by an eviction or the stop, which close
	// it only to wake the goroutine (closeSession).
	closeOnce sync.Once

	// first is the pooled copy of the first datagram when it rides the
	// OPEN, else nil. Written before the goroutine starts; only the
	// goroutine uses it from then on (it moves it to firstQ when the open
	// went without it, R1-4).
	first []byte

	// Under the table's mutex:
	state   FlowState
	gone    bool             // removed from the table (its MaxFlows unit handed on or released)
	evicted bool             // removed to make room (M6-D29)
	peerEnd bool             // its WriteTo met the far end's close (replace): its end is PeerClosed, whatever ReadFrom reports after a local close
	pc      ingressSession   // the session once open
	opened  time.Duration    // when DialUDP returned (the reopen rate limit)
	firstQ  *queuedDatagram  // the first datagram's own copy when it does not ride (R1-9): it heads the queue, uncharged
	q       []queuedDatagram // the opening queue (charged copies), oldest first
	qBytes  int              // the queue's charge
}

// queuedDatagram is a datagram of an opening flow (a pooled copy).
type queuedDatagram struct {
	b      []byte
	at     time.Duration // its arrival, as an offset from the base
	charge int           // its pool class (0 for the first datagram's own copy)
}

// The pool classes of the opening stage's copies (R1-15).
var ingressClasses = [...]int{512, 2 << 10, 16 << 10, 64 << 10}

var ingressPools [len(ingressClasses)]sync.Pool

// ingressClass is the index of the smallest class that holds n bytes.
func ingressClass(n int) int {
	for i, c := range ingressClasses {
		if n <= c {
			return i
		}
	}
	return len(ingressClasses) - 1
}

// ingressCopy returns a pooled copy of b (b is at most ingressReadBuf).
func ingressCopy(b []byte) []byte {
	i := ingressClass(len(b))
	if v, _ := ingressPools[i].Get().(*[]byte); v != nil {
		return append((*v)[:0], b...)
	}
	buf := make([]byte, len(b), ingressClasses[i])
	copy(buf, b)
	return buf
}

// ingressFree returns a copy made by ingressCopy to its pool.
func ingressFree(b []byte) {
	if b == nil {
		return
	}
	i := ingressClass(cap(b))
	if cap(b) != ingressClasses[i] {
		return
	}
	ingressPools[i].Put(&b)
}

// push queues a copy of b on the opening entry e (the table's mutex held):
// at most ingressQueueLen copies and ingressQueueBytes of charge, the
// oldest dropped to make room; a datagram whose class alone exceeds the
// charge bound is dropped. It returns the datagrams dropped.
func (e *ingressFlow) push(b []byte, at time.Duration) (dropped int) {
	charge := ingressClasses[ingressClass(len(b))]
	if charge > ingressQueueBytes {
		return 1
	}
	for len(e.q) > 0 && (len(e.q) == ingressQueueLen || e.qBytes+charge > ingressQueueBytes) {
		old := e.q[0]
		copy(e.q, e.q[1:])
		e.q = e.q[:len(e.q)-1]
		e.qBytes -= old.charge
		ingressFree(old.b)
		dropped++
	}
	e.q = append(e.q, queuedDatagram{b: ingressCopy(b), at: at, charge: charge})
	e.qBytes += charge
	return dropped
}

// takeQueue empties e's queue (the table's mutex held) and returns its
// datagrams in arrival order: the first datagram's copy, then the queue.
func (e *ingressFlow) takeQueue() []queuedDatagram {
	var out []queuedDatagram
	if e.firstQ != nil {
		out = append(out, *e.firstQ)
		e.firstQ = nil
	}
	out = append(out, e.q...)
	clear(e.q)
	e.q, e.qBytes = e.q[:0], 0
	return out
}

// closeSession closes pc, e's session, the first time it is called for e
// (Close returns at once; the goroutine leaves ReadFrom with
// net.ErrClosed).
func (e *ingressFlow) closeSession(pc ingressSession) {
	e.closeOnce.Do(func() { pc.Close() })
}

// freeQueue returns q's copies to their pools.
func freeQueue(q []queuedDatagram) {
	for _, d := range q {
		ingressFree(d.b)
	}
}

// setState moves e to st (the table's mutex held), keeping the gauges:
// the opening stage's units (PortForward.opening), the open and held
// counts.
func (s *udpServe) setState(e *ingressFlow, st FlowState) {
	s.leaveState(e)
	e.state = st
	switch st {
	case FlowOpen:
		s.f.udp.open.Add(1)
	case FlowHeld:
		s.f.udp.held.Add(1)
	}
}

// leaveState releases e's gauge of its current state.
func (s *udpServe) leaveState(e *ingressFlow) {
	switch e.state {
	case FlowOpening:
		s.f.opening.Add(-1)
	case FlowOpen:
		s.f.udp.open.Add(-1)
	case FlowHeld:
		s.f.udp.held.Add(-1)
	}
}

// remove takes e out of the table (the mutex held): its gauge released,
// gone set. Its MaxFlows unit is the caller's: released, or handed to a
// newcomer that takes e's place.
func (s *udpServe) remove(e *ingressFlow) {
	if e.gone {
		return
	}
	s.leaveState(e)
	e.state = 0
	e.gone = true
	if s.tab.m[e.client] == e {
		delete(s.tab.m, e.client)
	}
}

// victim picks the entry a newcomer may replace in a full table (M6-D29;
// the mutex held): among at most ingressSample entries (Go's map
// iteration starts at a random place), a held entry first; under
// promoteActive (O-1 (a)) else the least recently active open flow that
// never became a stream and whose last datagram is at least
// ingressEvictIdle old. Opening flows and streams never are victims; under
// promoteOnReply only held entries are. nil: none.
func (s *udpServe) victim(now time.Duration) *ingressFlow {
	var best *ingressFlow
	var bestLast int64
	cutoff := int64(now - ingressEvictIdle)
	n := 0
	for _, e := range s.tab.m {
		if n++; n > ingressSample {
			break
		}
		switch {
		case e.state == FlowHeld:
			return e
		case s.rule == promoteActive && e.state == FlowOpen && !e.class.isStream():
			if l := e.last.Load(); l <= cutoff && (best == nil || l < bestLast) {
				best, bestLast = e, l
			}
		}
	}
	return best
}
