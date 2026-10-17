package rendr

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// evqEvent is the i-th test event: every field encodes i so that the
// delivered value can be checked byte for byte.
func evqEvent(i int) session.Event {
	var sid [16]byte
	binary.BigEndian.PutUint64(sid[8:], uint64(i))
	return session.Event{
		Kind:    session.EventMigration,
		Session: sid,
		Carrier: uint32(i),
		From:    uint32(i) + 1,
		To:      uint32(i) + 2,
		Cause:   carrier.CauseQuality,
		Err:     evqErr{i},
		Time:    time.Unix(int64(i), 0),
	}
}

type evqErr struct{ i int }

func (evqErr) Error() string { return "test event error" }

// evqCheck asserts that ev is the converted evqEvent(i) carrying Seq seq.
func evqCheck(t *testing.T, ev Event, i int, seq uint64) {
	t.Helper()
	want := eventFrom(evqEvent(i))
	want.Seq = seq
	if ev != want {
		t.Fatalf("event %d: got %+v, want %+v", i, ev, want)
	}
}

type evqPool struct{ adopted, left atomic.Int32 }

func (p *evqPool) Adopt() { p.adopted.Add(1) }
func (p *evqPool) Leave() { p.left.Add(1) }

// TestEventQueueBoundedAndOrdered_L53 is L53's test: the callback blocks
// on the first event; 257 more events are emitted. The producer never
// blocks (a blocking Emit would deadlock the bubble), the ring holds
// exactly 256, exactly one event — the newest — is dropped and counted,
// and after the callback is released every queued event is delivered
// once, in Seq order, with its content intact; the Seq gap is the drop.
// EventEnqueued saw every Seq in order, the dropped one included.
func TestEventQueueBoundedAndOrdered_L53(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var seqs []uint64 // written under evMu by the only producer
		hooks := &testhooks.Hooks{EventEnqueued: func(seq uint64) { seqs = append(seqs, seq) }}
		blocked, release := make(chan struct{}), make(chan struct{})
		var got []Event // worker-only until join
		first := true
		q := newEventQueue(func(ev Event) {
			if first {
				first = false
				close(blocked)
				<-release
			}
			got = append(got, ev)
		}, defEventQueue, hooks)

		q.Emit(evqEvent(1))
		<-blocked // stimulus: the callback is blocked inside event 1
		start := time.Now()
		for i := 2; i <= 258; i++ {
			q.Emit(evqEvent(i))
		}
		if time.Since(start) != 0 {
			t.Fatal("Emit waited")
		}
		if n := q.queued(); n != 256 {
			t.Fatalf("ring holds %d events, want 256 (the load was not reached)", n)
		}
		if d, p := q.counters(); d != 1 || p != 0 {
			t.Fatalf("dropped %d panics %d, want 1 and 0", d, p)
		}
		close(release)
		q.close()
		if !q.join(time.Second, nil) {
			t.Fatal("worker did not drain and exit")
		}
		if len(got) != 257 {
			t.Fatalf("delivered %d events, want 257", len(got))
		}
		for i, ev := range got {
			evqCheck(t, ev, i+1, uint64(i+1))
		}
		if len(seqs) != 258 {
			t.Fatalf("EventEnqueued ran %d times, want 258", len(seqs))
		}
		for i, s := range seqs {
			if s != uint64(i+1) {
				t.Fatalf("EventEnqueued #%d got Seq %d", i, s)
			}
		}
	})
}

// TestEventCallbackPanicCounted_L51_L53 feeds 100 events to a callback that
// panics (a value, nil, a runtime error) or calls runtime.Goexit on 80 of
// them. Every fault is counted in CallbackPanics; every event is still
// delivered exactly once and in order; a Goexit is survived by a
// replacement worker, never two callbacks run at once, the worker is idle
// and working between the two batches, and no goroutine outlives the
// bubble (the replaced workers exited).
func TestEventCallbackPanicCounted_L51_L53(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var running, overlap atomic.Int32
		var delivered []uint64 // handed from worker to replacement by the go statement
		q := newEventQueue(func(ev Event) {
			if running.Add(1) != 1 {
				overlap.Add(1)
			}
			defer running.Add(-1)
			delivered = append(delivered, ev.Seq)
			switch ev.Carrier % 5 {
			case 1:
				panic("callback panic")
			case 2:
				runtime.Goexit()
			case 3:
				panic(nil) // *runtime.PanicNilError since Go 1.21
			case 4:
				var m map[int]int
				m[0] = 1 // runtime error
			}
		}, 128, nil)

		for i := 1; i <= 50; i++ {
			q.Emit(evqEvent(i))
		}
		synctest.Wait() // the (replacement) worker drained the batch and sleeps
		if len(delivered) != 50 {
			t.Fatalf("first batch: %d delivered", len(delivered))
		}
		if _, p := q.counters(); p != 40 {
			t.Fatalf("first batch: %d faults counted, want 40", p)
		}
		for i := 51; i <= 100; i++ {
			q.Emit(evqEvent(i))
		}
		q.close()
		if !q.join(time.Second, nil) {
			t.Fatal("worker did not exit")
		}
		if len(delivered) != 100 {
			t.Fatalf("delivered %d events, want 100", len(delivered))
		}
		for i, s := range delivered {
			if s != uint64(i+1) {
				t.Fatalf("delivery %d has Seq %d: order or exactly-once broken", i, s)
			}
		}
		if d, p := q.counters(); d != 0 || p != 80 {
			t.Fatalf("dropped %d faults %d, want 0 and 80", d, p)
		}
		if overlap.Load() != 0 {
			t.Fatalf("%d callbacks overlapped: more than one worker ran", overlap.Load())
		}
	})
}

// TestEventCallbackPanicNilCounted_L51_L53 runs a callback's panic(nil)
// under GODEBUG=panicnil=1, which an embedder may set through a godebug
// block in its go.mod, a //go:debug directive or the environment: recover()
// then returns nil, exactly as it does for a runtime.Goexit. The queue must
// still classify the fault as a recovered panic — this worker continues, no
// replacement starts — so every event is delivered exactly once and in
// order, never two callbacks run at once, every fault is counted, and the
// worker exits exactly once (a second worker would also close done, and
// that double close would crash the embedding process).
func TestEventCallbackPanicNilCounted_L51_L53(t *testing.T) {
	godebug := "panicnil=1"
	if old := os.Getenv("GODEBUG"); old != "" {
		godebug = old + "," + godebug // the last setting wins
	}
	t.Setenv("GODEBUG", godebug) // the runtime re-reads GODEBUG on Setenv
	// Stimulus: the setting is in effect, recover() yields nil for panic(nil).
	if r := recoveredPanicNil(); r != nil {
		t.Fatalf("GODEBUG=panicnil=1 is not in effect: recover() returned %T", r)
	}
	synctest.Test(t, func(t *testing.T) {
		var running, overlap atomic.Int32
		var delivered []uint64 // worker-only until join (a second worker would race on it)
		q := newEventQueue(func(ev Event) {
			if running.Add(1) != 1 {
				overlap.Add(1)
			}
			defer running.Add(-1)
			delivered = append(delivered, ev.Seq)
			if ev.Carrier%2 == 1 {
				panic(nil)
			}
			// A second worker, if one existed, would take the next event
			// while this callback sleeps: the overlap check would see it.
			time.Sleep(time.Millisecond)
		}, 64, nil)
		for i := 1; i <= 40; i++ {
			q.Emit(evqEvent(i))
		}
		q.close()
		if !q.join(time.Second, nil) {
			t.Fatal("worker did not exit")
		}
		synctest.Wait() // a stray second worker would still be running here
		if overlap.Load() != 0 {
			t.Fatalf("%d callbacks overlapped: a panic(nil) started a second worker", overlap.Load())
		}
		if len(delivered) != 40 {
			t.Fatalf("delivered %d events, want 40", len(delivered))
		}
		for i, s := range delivered {
			if s != uint64(i+1) {
				t.Fatalf("delivery %d has Seq %d: order or exactly-once broken", i, s)
			}
		}
		if d, p := q.counters(); d != 0 || p != 20 {
			t.Fatalf("dropped %d faults %d, want 0 and 20 (one per panic(nil))", d, p)
		}
	})
}

// recoveredPanicNil returns what recover() yields for panic(nil): a
// *runtime.PanicNilError by default, nil under GODEBUG=panicnil=1.
func recoveredPanicNil() (r any) {
	defer func() { r = recover() }()
	panic(nil)
}

// TestEventQueueJoinFromCallback: a callback may call Runtime.Close, which
// closes the queue and joins the worker. From inside the callback the join
// must return at once (it cannot wait for itself), adopt nothing, and the
// worker must still exit once the callback returns.
func TestEventQueueJoinFromCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := &evqPool{}
		var q *eventQueue
		var inner, called bool
		var innerWait time.Duration
		q = newEventQueue(func(ev Event) {
			called = true
			q.close()
			start := time.Now()
			inner = q.join(time.Hour, pool)
			innerWait = time.Since(start)
		}, 8, nil)
		q.Emit(evqEvent(1))
		if !q.join(time.Hour, pool) {
			t.Fatal("outer join failed")
		}
		if !called || inner || innerWait != 0 {
			t.Fatalf("inner join: called %v returned %v after %v, want false at once", called, inner, innerWait)
		}
		if pool.adopted.Load() != 0 || pool.left.Load() != 0 {
			t.Fatalf("abandon pool touched: %d/%d", pool.adopted.Load(), pool.left.Load())
		}
	})
}

// TestEventQueueStuckCallbackAbandoned_L52: a callback that never returns
// bounds the join (exactly the bound, in virtual time); the worker is
// adopted by the abandoned-call pool once and leaves it when the callback
// finally returns, after delivering the event queued behind it.
func TestEventQueueStuckCallbackAbandoned_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := &evqPool{}
		entered, release := make(chan struct{}), make(chan struct{})
		var got []uint64
		first := true
		q := newEventQueue(func(ev Event) {
			if first {
				first = false
				close(entered)
				<-release
			}
			got = append(got, ev.Seq)
		}, 8, nil)
		q.Emit(evqEvent(1))
		<-entered
		q.Emit(evqEvent(2))
		q.close()
		start := time.Now()
		if q.join(time.Second, pool) {
			t.Fatal("joined a worker stuck in its callback")
		}
		if waited := time.Since(start); waited != time.Second {
			t.Fatalf("join waited %v, want exactly the 1s bound", waited)
		}
		if pool.adopted.Load() != 1 || pool.left.Load() != 0 {
			t.Fatalf("pool adopted %d left %d, want 1 and 0", pool.adopted.Load(), pool.left.Load())
		}
		if q.join(0, pool) || pool.adopted.Load() != 1 {
			t.Fatal("a second join adopted the worker again")
		}
		close(release)
		synctest.Wait()
		if pool.left.Load() != 1 {
			t.Fatalf("the returning worker left the pool %d times, want 1", pool.left.Load())
		}
		if !q.join(time.Second, pool) || pool.adopted.Load() != 1 {
			t.Fatal("join after the exit")
		}
		if len(got) != 2 || got[0] != 1 || got[1] != 2 {
			t.Fatalf("delivered %v, want [1 2]", got)
		}
	})
}

// evqOrderPool is an abandoned-call pool whose Adopt and Leave run test
// code (the adoption-window test below).
type evqOrderPool struct{ adopt, leave func() }

func (p *evqOrderPool) Adopt() { p.adopt() }
func (p *evqOrderPool) Leave() { p.leave() }

// TestEventQueueWorkerExitsDuringAdopt_L52 drives the window between join's
// claim of a stuck worker and the end of its Adopt, which runs with no lock
// held (evMu is a leaf): Adopt itself releases the stuck callback and lets
// the worker drain and exit before Adopt returns. The worker must not
// leave the pool for an adoption that has not completed; join leaves for
// it instead, so the pool sees exactly one Adopt followed by one Leave and
// join reports that the worker is gone.
func TestEventQueueWorkerExitsDuringAdopt_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var delivered int
		q := newEventQueue(func(ev Event) {
			if ev.Seq == 1 {
				close(entered)
				<-release
			}
			delivered++
		}, 8, nil)
		var adopted, left int
		exitedInWindow := false
		pool := &evqOrderPool{
			adopt: func() {
				close(release)
				<-q.done        // the worker drains and exits inside the window ...
				synctest.Wait() // ... and finishes; a premature Leave would have run by now
				exitedInWindow = true
				adopted++ // the count lands last, like an Adopt that has not returned
			},
			leave: func() {
				if left >= adopted {
					t.Error("Leave ran before the matching Adopt returned")
				}
				left++
			},
		}
		q.Emit(evqEvent(1))
		<-entered // stimulus: the worker is stuck in its callback
		q.Emit(evqEvent(2))
		start := time.Now()
		if !q.join(time.Second, pool) {
			t.Fatal("join must report the worker that exited during Adopt")
		}
		if waited := time.Since(start); waited != time.Second {
			t.Fatalf("join waited %v, want the 1s bound before adopting", waited)
		}
		synctest.Wait()
		if !exitedInWindow || adopted != 1 || left != 1 {
			t.Fatalf("exit in the window %v, adopted %d, left %d: want true, 1, 1", exitedInWindow, adopted, left)
		}
		if delivered != 2 {
			t.Fatalf("delivered %d events, want 2", delivered)
		}
		if !q.join(0, pool) || adopted != 1 || left != 1 {
			t.Fatal("a join after the exit touched the pool")
		}
	})
}

// TestEventQueueClosedAndNil: events after close — before and after the
// worker exited — are discarded: not delivered, not counted in
// EventsDropped (which means a full ring), given no Seq and no
// EventEnqueued; and a nil queue — the Runtime without OnEvent — discards
// everything with no goroutine.
func TestEventQueueClosedAndNil(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var got []Event
		var hooked []uint64 // appended under evMu by this goroutine's Emits
		hooks := &testhooks.Hooks{EventEnqueued: func(seq uint64) { hooked = append(hooked, seq) }}
		q := newEventQueue(func(ev Event) { got = append(got, ev) }, 4, hooks)
		q.Emit(evqEvent(1))
		synctest.Wait()
		q.close()
		q.close() // idempotent
		q.Emit(evqEvent(2))
		if !q.join(time.Second, nil) {
			t.Fatal("join")
		}
		q.Emit(evqEvent(3))
		if d, _ := q.counters(); d != 0 || len(got) != 1 {
			t.Fatalf("dropped %d delivered %d, want 0 and 1", d, len(got))
		}
		evqCheck(t, got[0], 1, 1)
		if q.seq != 1 || !slices.Equal(hooked, []uint64{1}) {
			t.Fatalf("Seq %d and EventEnqueued %v after two post-close events, want 1 and [1]", q.seq, hooked)
		}
	})
	// join without a prior close still drains and joins.
	synctest.Test(t, func(t *testing.T) {
		var got int
		q := newEventQueue(func(Event) { got++ }, 4, nil)
		q.Emit(evqEvent(1))
		if !q.join(time.Second, nil) || got != 1 {
			t.Fatalf("join without close: delivered %d", got)
		}
	})
	if q := newEventQueue(nil, 256, nil); q != nil {
		t.Fatal("a queue without callback was created")
	}
	var q *eventQueue
	q.Emit(evqEvent(1))
	q.close()
	if !q.join(0, nil) {
		t.Fatal("nil join")
	}
	if d, p := q.counters(); d != 0 || p != 0 {
		t.Fatal("nil counters")
	}
	var sink session.EventSink = q // a nil *eventQueue is a valid sink
	sink.Emit(evqEvent(2))
}

// TestGoroutineID checks the helper join uses to recognize its own worker.
func TestGoroutineID(t *testing.T) {
	a, b := goid(), goid()
	if a == 0 || a != b {
		t.Fatalf("goid unstable or zero: %d %d", a, b)
	}
	other := make(chan uint64)
	go func() { other <- goid() }()
	if o := <-other; o == 0 || o == a {
		t.Fatalf("another goroutine has id %d (this one %d)", o, a)
	}
}

// TestEventFromKeepsErr checks that Err survives the conversion (errors.Is
// on the delivered value).
func TestEventFromKeepsErr(t *testing.T) {
	ev := eventFrom(session.Event{Kind: session.EventSessionEnd, Err: ErrNoPath})
	if ev.Kind != EventSessionEnd || !errors.Is(ev.Err, ErrNoPath) {
		t.Fatalf("converted %+v", ev)
	}
}
