package rendr

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// abandoner is the part of carrier.AbandonPool the event queue uses when a
// stuck OnEvent outlives its join bound (L52).
type abandoner interface {
	Adopt()
	Leave()
}

var (
	_ session.EventSink = (*eventQueue)(nil) // the Runtime's session.Env.Events
	_ abandoner         = (*carrier.AbandonPool)(nil)
)

// eventQueue delivers events to Config.OnEvent (design §10.3; L53): a
// bounded ring (256) fed by Emit from any goroutine and drained by exactly
// one worker that calls the callback serially with no rendr lock held. Seq
// is assigned under the queue lock, so Seq order is enqueue order (F9); a
// full ring drops the new event and counts it, so producers never block.
// A callback panic is recovered and counted; a callback runtime.Goexit is
// counted too and the dying worker starts its replacement first (D22), so
// there is always exactly one worker. Once closed, the queue accepts no
// event: a later Emit is discarded with no Seq and is not counted as a
// drop (EventsDropped means the ring was full). A nil *eventQueue, or one
// without a callback, discards every event.
type eventQueue struct {
	fn    func(Event)
	hooks *testhooks.Hooks

	mu        sync.Mutex // evMu: a leaf (design §3.2); nothing is called under it but Hooks.EventEnqueued
	ring      []Event
	head, n   int
	seq       uint64
	closed    bool
	exited    bool          // the worker drained the closed ring and exited
	abandoned abandoner     // claimed by a join that timed out
	adopted   bool          // that join's Adopt returned: the exiting worker owes the Leave
	signal    chan struct{} // cap 1: wakes the worker
	done      chan struct{} // closed when the worker exited

	dropped atomic.Uint64
	panics  atomic.Uint64
	worker  atomic.Uint64 // goroutine id of the current worker (join's self check)
}

// newEventQueue returns a queue of size slots and starts its worker; with
// fn == nil it returns nil (no goroutine, events discarded).
func newEventQueue(fn func(Event), size int, hooks *testhooks.Hooks) *eventQueue {
	if fn == nil {
		return nil
	}
	q := &eventQueue{
		fn:     fn,
		hooks:  hooks,
		ring:   make([]Event, max(size, 1)),
		signal: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	go q.run()
	return q
}

// Emit implements session.EventSink: it converts ev, assigns the next Seq
// and enqueues it, or drops and counts it when the ring is full (a dropped
// event still consumes its Seq, so gaps show drops). Hooks.EventEnqueued
// runs with the queue lock held, in Seq order, for every event that got a
// Seq. After close the event is discarded before it gets a Seq: it is not
// a drop of a full queue and is not counted. Emit never blocks on the
// worker.
func (q *eventQueue) Emit(ev session.Event) {
	if q == nil {
		return
	}
	e := eventFrom(ev)
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.seq++
	e.Seq = q.seq
	if q.n == len(q.ring) {
		q.dropped.Add(1)
	} else {
		q.ring[(q.head+q.n)%len(q.ring)] = e
		q.n++
	}
	if q.hooks != nil && q.hooks.EventEnqueued != nil {
		q.hooks.EventEnqueued(e.Seq)
	}
	q.mu.Unlock()
	select {
	case q.signal <- struct{}{}:
	default:
	}
}

// run is the worker loop. It exits (closing done) once the queue is closed
// and empty. A replacement started after a Goexit runs the same loop.
func (q *eventQueue) run() {
	q.worker.Store(goid())
	for {
		q.mu.Lock()
		for q.n == 0 {
			if q.closed {
				// Only the first exit closes done and leaves the abandoned
				// pool. With exactly one worker that is every exit; the
				// check only keeps a broken invariant from crashing the
				// embedding process with a double close (L51).
				first := !q.exited
				q.exited = true
				var pool abandoner
				if first && q.adopted {
					pool = q.abandoned
				}
				q.mu.Unlock()
				if first {
					close(q.done)
				}
				if pool != nil {
					pool.Leave()
				}
				return
			}
			q.mu.Unlock()
			<-q.signal
			q.mu.Lock()
		}
		ev := q.ring[q.head]
		q.ring[q.head] = Event{} // drop the references (Err) held by the slot
		q.head = (q.head + 1) % len(q.ring)
		q.n--
		q.mu.Unlock()
		q.call(ev)
	}
}

// call invokes the callback once. A panic of any value is recovered and
// counted; this worker continues with the next event. A runtime.Goexit
// cannot be stopped: it is counted, a replacement worker is started before
// this goroutine finishes unwinding, and the replacement continues with the
// next event (D22).
//
// The two are told apart by control flow, never by recover's value, which
// is nil for a Goexit and, under GODEBUG=panicnil=1 (an embedder's choice),
// for panic(nil) as well: the inner function's deferred recover stops any
// panic, after which the statement following the inner call runs; a Goexit
// is not stopped, so that statement never runs and the outer deferred
// function sees neither a normal return nor a recovered panic. (The same
// double-defer scheme as golang.org/x/sync/singleflight.)
func (q *eventQueue) call(ev Event) {
	normal, recovered := false, false
	defer func() {
		if normal {
			return
		}
		q.panics.Add(1)
		if !recovered {
			go q.run() // runtime.Goexit: this goroutine is ending
		}
	}()
	func() {
		defer func() {
			if !normal {
				_ = recover() // stops a panic of any value; no effect on a Goexit
			}
		}()
		q.fn(ev)
		normal = true
	}()
	recovered = !normal // reached only if the callback returned or its panic was recovered
}

// close stops accepting events; the worker delivers what is queued and
// exits. Idempotent.
func (q *eventQueue) close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	select {
	case q.signal <- struct{}{}:
	default:
	}
}

// join closes the queue (if close was not called yet), waits up to bound
// for the worker to deliver what is queued and exit, and reports whether it
// did. A worker still inside the callback after bound is adopted by pool
// (Status.Abandoned) once, and leaves it when it finally exits (L52).
// Called from inside the callback (OnEvent called Runtime.Close), join
// returns false at once and adopts nothing: the worker exits after the
// callback returns, and waiting for it from itself would only burn the
// bound.
//
// Adopt is called with no lock held (evMu is a leaf, design §3.2) and is
// still ordered before the matching Leave: join first claims the adoption
// under the lock, then adopts, then marks it complete under the lock. A
// worker that exits after the mark leaves the pool itself; one that exits
// between the claim and the mark does not, and join leaves for it.
func (q *eventQueue) join(bound time.Duration, pool abandoner) bool {
	if q == nil {
		return true
	}
	q.close()
	if goid() == q.worker.Load() {
		return false
	}
	t := time.NewTimer(bound)
	defer t.Stop()
	select {
	case <-q.done:
		return true
	case <-t.C:
	}
	q.mu.Lock()
	switch {
	case q.exited:
		q.mu.Unlock()
		return true
	case q.abandoned != nil || pool == nil:
		q.mu.Unlock() // already adopted by an earlier join, or nothing to count it in
		return false
	}
	q.abandoned = pool // the claim
	q.mu.Unlock()
	pool.Adopt()
	q.mu.Lock()
	exited := q.exited
	q.adopted = !exited
	q.mu.Unlock()
	if exited {
		pool.Leave() // the worker exited after the claim, before the mark
		return true
	}
	return false
}

// counters returns Status.EventsDropped and Status.CallbackPanics.
func (q *eventQueue) counters() (dropped, panics uint64) {
	if q == nil {
		return 0, 0
	}
	return q.dropped.Load(), q.panics.Load()
}

// queued returns the events waiting for the worker (tests).
func (q *eventQueue) queued() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// goid returns the current goroutine's id, parsed from the header of its
// stack trace ("goroutine 18 [running]:"). It is used only to recognize a
// join from inside the callback; it is not on any frequent path.
func goid() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	const prefix = "goroutine "
	if len(b) < len(prefix) || string(b[:len(prefix)]) != prefix {
		return 0
	}
	var id uint64
	for _, c := range b[len(prefix):] {
		if c < '0' || c > '9' {
			break
		}
		id = id*10 + uint64(c-'0')
	}
	return id
}
