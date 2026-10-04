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
// there is always exactly one worker. A nil *eventQueue, or one without a
// callback, discards every event.
type eventQueue struct {
	fn    func(Event)
	hooks *testhooks.Hooks

	mu        sync.Mutex // evMu: a leaf
	ring      []Event
	head, n   int
	seq       uint64
	closed    bool
	exited    bool          // the worker drained the closed ring and exited
	abandoned abandoner     // set by join on timeout; the worker leaves it at exit
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
// and enqueues it, or drops and counts it when the ring is full or the
// queue is closed (a dropped event still consumes its Seq, so gaps show
// drops). Hooks.EventEnqueued runs with the queue lock held, in Seq order,
// for every event that got a Seq. Emit never blocks on the worker.
func (q *eventQueue) Emit(ev session.Event) {
	if q == nil {
		return
	}
	e := eventFrom(ev)
	q.mu.Lock()
	q.seq++
	e.Seq = q.seq
	if q.closed || q.n == len(q.ring) {
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
				q.exited = true
				pool := q.abandoned
				q.mu.Unlock()
				close(q.done)
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

// call invokes the callback once. A panic is recovered and counted; the
// worker continues with the next event. A runtime.Goexit cannot be
// stopped: it is counted, a replacement worker is started before this
// goroutine finishes unwinding, and the replacement continues with the
// next event (D22).
func (q *eventQueue) call(ev Event) {
	returned := false
	defer func() {
		if returned {
			return
		}
		if r := recover(); r != nil {
			q.panics.Add(1)
			return
		}
		q.panics.Add(1) // runtime.Goexit: recover() is nil and the call did not return
		go q.run()
	}()
	q.fn(ev)
	returned = true
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
// (Status.Abandoned) and leaves it when it finally exits (L52). Called from
// inside the callback (OnEvent called Runtime.Close), join returns false at
// once and adopts nothing: the worker exits after the callback returns, and
// waiting for it from itself would only burn the bound.
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
	defer q.mu.Unlock()
	if q.exited {
		return true
	}
	if q.abandoned == nil && pool != nil {
		q.abandoned = pool
		pool.Adopt() // under the lock: ordered before the worker's Leave
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
