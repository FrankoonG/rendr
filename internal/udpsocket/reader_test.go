package udpsocket

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

// readerRig is a Reader over a forced-ModeBatch Conn with a fake netpoller
// (onWait runs while the callback is parked) and a fake recvmmsg (next).
type readerRig struct {
	r        *Reader
	released []*Batch
	onWait   func() error
	next     func(b *Batch, n int) (int, error)
	calls    []int // the capacity of the header of each recvmmsg call
}

func newReaderRig(t *testing.T) *readerRig {
	t.Helper()
	forceBatch(t, newProbe(syscall.EBADF, syscall.EBADF))
	c := newConn(t, listen4(t), 32, nil)
	g := &readerRig{}
	g.r = NewReader(c, func(b *Batch) { g.released = append(g.released, b) })
	c.rawRead = func(f func(uintptr) bool) error {
		for !f(0) {
			if g.onWait != nil {
				if err := g.onWait(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) {
		g.calls = append(g.calls, b.Cap())
		return g.next(b, n)
	}
	return g
}

// fill is a recvmmsg that returns n datagrams of one byte.
func fill(b *Batch, n int) (int, error) {
	for i := range n {
		b.ms[i].N, b.ms[i].Trunc = 1, false
	}
	return n, nil
}

// eagainThen returns a fake recvmmsg that reports EAGAIN k times, then
// fills.
func eagainThen(k int) func(b *Batch, n int) (int, error) {
	return func(b *Batch, n int) (int, error) {
		if k > 0 {
			k--
			return 0, syscall.EAGAIN
		}
		return fill(b, n)
	}
}

// TestReaderKeepsExtrasAcrossParks (R1-5 rule 3, deterministic): an idle
// reader reads one datagram through its fixed header; once it holds a
// Batch it reads at depth K and keeps the extras across any number of
// parks; an idle release succeeds only while the reader is parked and has
// not parked again since the timer's previous firing, after which the
// woken callback reads one datagram into slot 0 and never touches the
// released Batch. A Hold during the release is refused; Drop takes the
// extras back.
func TestReaderKeepsExtrasAcrossParks(t *testing.T) {
	g := newReaderRig(t)
	r := g.r
	ms := slots(8, 16)

	g.next = fill
	if n, err := r.ReadBatch(ms); n != 1 || err != nil || !eqInts(g.calls, []int{1}) || r.Held() || r.Holding() {
		t.Fatalf("idle reader: n %d err %v headers %v held %v; want one datagram through the fixed header", n, err, g.calls, r.Held())
	}

	b8 := NewBatch(8)
	if old, ok := r.Hold(b8); old != nil || !ok || !r.Held() || !r.Holding() {
		t.Fatalf("Hold: %v %v held %v", old, ok, r.Held())
	}
	for i := range 6 {
		g.calls = nil
		g.next = eagainThen(1)
		seq := r.Parks()
		g.onWait = func() error {
			if r.Held() || !r.Holding() || r.Parks() != seq+1 {
				t.Errorf("park %d: held %v holding %v parks %d; want parked with the extras", i, r.Held(), r.Holding(), r.Parks())
			}
			if r.TryRelease(seq) { // the timer's previous firing saw seq: the reader parked since
				t.Errorf("park %d: released although the reader parked again since the timer's last firing", i)
			}
			return nil
		}
		if n, err := r.ReadBatch(ms); n != 8 || err != nil || !eqInts(g.calls, []int{8, 8}) || !r.Held() {
			t.Fatalf("park %d: n %d err %v headers %v held %v; want depth 8 kept across the park", i, n, err, g.calls, r.Held())
		}
	}
	if len(g.released) != 0 || r.Parks() != 6 {
		t.Fatalf("released %d, parks %d; want 0 and 6", len(g.released), r.Parks())
	}

	// The reader stays parked across a whole period: the timer releases.
	g.calls = nil
	g.next = func(b *Batch, n int) (int, error) {
		if b == b8 && len(g.released) > 0 {
			t.Error("recvmmsg with the released Batch")
		}
		return eagainThen(0)(b, n)
	}
	first := true
	g.onWait = func() error {
		if !first {
			return nil
		}
		first = false
		if !r.TryRelease(r.Parks()) {
			t.Error("no release of a reader parked since the last firing")
		}
		return nil
	}
	g.next = func(b *Batch, n int) (int, error) {
		if first {
			return 0, syscall.EAGAIN
		}
		if b == b8 {
			t.Error("recvmmsg with the released Batch")
		}
		return fill(b, n)
	}
	r.release = func(b *Batch) {
		if old, ok := r.Hold(NewBatch(8)); ok || old != nil {
			t.Error("Hold succeeded during the release")
		}
		if b.ms != nil {
			t.Error("the released Batch still references the reader's slots")
		}
		g.released = append(g.released, b)
	}
	if n, err := r.ReadBatch(ms); n != 1 || err != nil || !eqInts(g.calls, []int{8, 1}) || r.Held() || r.Holding() {
		t.Fatalf("after the release: n %d err %v headers %v held %v; want one datagram through the fixed header", n, err, g.calls, r.Held())
	}
	if len(g.released) != 1 || g.released[0] != b8 {
		t.Fatalf("released %v; want b8 once", g.released)
	}
	if r.TryRelease(r.Parks()) || len(g.released) != 1 {
		t.Fatal("a second release of an idle reader")
	}

	// A read error (the deadline) while parked with the extras: the reader
	// keeps them.
	b16 := NewBatch(16)
	if _, ok := r.Hold(b16); !ok {
		t.Fatal("Hold after the release refused")
	}
	g.next = eagainThen(1)
	g.onWait = func() error { return os.ErrDeadlineExceeded }
	if n, err := r.ReadBatch(ms); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !r.Held() {
		t.Fatalf("deadline while parked: n %d err %v held %v; want the error and the extras kept", n, err, r.Held())
	}
	// The same, but the timer released during the park and the pool handed
	// the Batch to another user at once: the ending read must not touch it
	// (R1-5: no use after release).
	g.next = eagainThen(1)
	g.onWait = func() error {
		r.TryRelease(r.Parks())
		return os.ErrDeadlineExceeded
	}
	other := slots(2, 4) // the next user's slots
	r.release = func(b *Batch) {
		g.released = append(g.released, b)
		b.prepRecv(other)
	}
	if n, err := r.ReadBatch(ms); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || r.Held() || len(g.released) != 2 || g.released[1] != b16 {
		t.Fatalf("deadline after a release: n %d err %v held %v released %d", n, err, r.Held(), len(g.released))
	}
	if len(b16.ms) != 2 || &b16.ms[0] != &other[0] || b16.end != 2 {
		t.Fatalf("the released Batch was changed after the release: ms %d end %d; want the next user's 2 slots", len(b16.ms), b16.end)
	}

	b4 := NewBatch(4)
	r.release = func(b *Batch) { g.released = append(g.released, b) }
	if _, ok := r.Hold(b4); !ok {
		t.Fatal("Hold refused")
	}
	b32 := NewBatch(32)
	if old, ok := r.Hold(b32); old != b4 || !ok {
		t.Fatalf("Hold while held: old %p ok %v; want b4 back", old, ok)
	}
	if d := r.Drop(); d != b32 || r.Held() || r.Drop() != nil {
		t.Fatalf("Drop: %p held %v", d, r.Held())
	}
}

// TestReaderReleasesAtDepthOne (R1-5 rule 3 and 5): a reader holding
// extras whose depth fell to 1 (one slot) still reads through them, so its
// park counts and the idle release returns them; the next read uses the
// fixed header. Hold refuses a nil Batch or one of Cap 1.
func TestReaderReleasesAtDepthOne(t *testing.T) {
	g := newReaderRig(t)
	r := g.r
	if old, ok := r.Hold(nil); ok || old != nil || r.Holding() {
		t.Fatal("Hold(nil) accepted")
	}
	if _, ok := r.Hold(NewBatch(1)); ok || r.Holding() {
		t.Fatal("Hold of a Batch of Cap 1 accepted")
	}
	b2 := NewBatch(2)
	if _, ok := r.Hold(b2); !ok {
		t.Fatal("Hold refused")
	}
	ms := slots(1, 16)
	g.next = eagainThen(1)
	g.onWait = func() error {
		seq := r.Parks()        // the timer's firing records the sequence …
		if !r.TryRelease(seq) { // … and the next one finds the reader still parked
			t.Error("no release of a reader parked at depth 1 with extras")
		}
		return nil
	}
	if n, err := r.ReadBatch(ms); n != 1 || err != nil {
		t.Fatalf("ReadBatch: %d, %v", n, err)
	}
	if r.Parks() != 1 || len(g.released) != 1 || g.released[0] != b2 || r.Holding() || !eqInts(g.calls, []int{2, 1}) {
		t.Fatalf("parks %d, released %d, holding %v, headers %v; want 1 park, b2 released, the read redone through the fixed header [2 1]", r.Parks(), len(g.released), r.Holding(), g.calls)
	}
}

// TestReaderReleaseRace (R1-5, M5-D61; meant for -race): the idle-release
// timer fires concurrently with the wakes of a reader that parks and wakes
// 10,000 times, re-taking a Batch whenever it lost its extras. No Batch is
// released twice, the callback never reads with a released Batch, the
// reader never changes a released Batch (the pool hands it to a next user
// at once), a read at depth K ≥ 2 is reported only with the extras held,
// and both outcomes of the race happen (stimulus: releases, reads that
// lost the CAS to the release, and reads ended by the deadline after a
// release during their park).
func TestReaderReleaseRace(t *testing.T) {
	forceBatch(t, newProbe(syscall.EBADF, syscall.EBADF))
	c := newConn(t, listen4(t), 32, nil)
	var mu sync.Mutex
	released := map[*Batch]*atomic.Bool{}
	state := func(b *Batch) *atomic.Bool {
		mu.Lock()
		defer mu.Unlock()
		return released[b]
	}
	var doubles, uses, releases, lost, deep, deadlines, deadReleased atomic.Int64
	other := slots(2, 4) // the slots of the user the pool hands a released Batch to
	var handed []*Batch
	var r *Reader
	r = NewReader(c, func(b *Batch) {
		if !state(b).CompareAndSwap(false, true) {
			doubles.Add(1)
		}
		releases.Add(1)
		b.prepRecv(other)
		mu.Lock()
		handed = append(handed, b)
		mu.Unlock()
	})
	wake := make(chan error)
	stop := make(chan struct{})
	heldAtStart, eagain := false, false
	c.rawRead = func(f func(uintptr) bool) error {
		for !f(0) {
			if err := <-wake; err != nil {
				if heldAtStart && !r.Holding() {
					deadReleased.Add(1)
				}
				return err
			}
		}
		return nil
	}
	recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) {
		if b.Cap() > 1 && state(b).Load() {
			uses.Add(1)
		}
		if eagain = !eagain; eagain {
			return 0, syscall.EAGAIN
		}
		if b.Cap() == 1 && heldAtStart {
			lost.Add(1)
		}
		for i := range n {
			b.ms[i].N = 1
		}
		runtime.Gosched()
		if b.Cap() > 1 && state(b).Load() {
			uses.Add(1)
		}
		return n, nil
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the wakes: a park lasts 1 to 4 turns of the scheduler; every 7th ends in the deadline
		defer wg.Done()
		for i := 0; ; i++ {
			var werr error
			if i%7 == 3 {
				werr = os.ErrDeadlineExceeded
			}
			select {
			case wake <- werr:
			case <-stop:
				return
			}
			for range 1 + i%4 {
				runtime.Gosched()
			}
		}
	}()
	go func() { // the idle-release timer
		defer wg.Done()
		var last uint64
		for {
			select {
			case <-stop:
				return
			default:
			}
			seq := r.Parks()
			if seq == last {
				r.TryRelease(seq)
			}
			last = seq
			runtime.Gosched()
		}
	}()
	ms := slots(8, 16)
	for i := range 10000 {
		if !r.Held() {
			nb := NewBatch(8)
			mu.Lock()
			released[nb] = new(atomic.Bool)
			mu.Unlock()
			r.Hold(nb) // refused while a release is still returning the previous extras
		}
		heldAtStart = r.Held()
		n, err := r.ReadBatch(ms)
		if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			deadlines.Add(1)
			continue
		}
		if err != nil || n < 1 {
			close(stop)
			wg.Wait()
			t.Fatalf("read %d: n %d, err %v", i, n, err)
		}
		if n > 1 {
			deep.Add(1)
			if !r.Held() {
				t.Errorf("read %d: %d datagrams reported without the extras", i, n)
			}
		}
	}
	close(stop)
	wg.Wait()
	changed := 0
	for _, b := range handed {
		if len(b.ms) != 2 || &b.ms[0] != &other[0] || b.end != 2 {
			changed++
		}
	}
	if d := r.Drop(); d != nil {
		state(d).Store(true)
	}
	t.Logf("releases %d, lost CAS %d, deep reads %d, deadlines %d (%d after a release during the park)", releases.Load(), lost.Load(), deep.Load(), deadlines.Load(), deadReleased.Load())
	if doubles.Load() != 0 || uses.Load() != 0 || changed != 0 {
		t.Fatalf("%d double releases, %d reads with a released Batch, %d released Batches changed by the reader", doubles.Load(), uses.Load(), changed)
	}
	if releases.Load() == 0 || lost.Load() == 0 || deep.Load() == 0 || deadReleased.Load() == 0 {
		t.Fatalf("stimulus: %d releases, %d reads that lost the CAS, %d deep reads, %d deadlines after a release; want each > 0", releases.Load(), lost.Load(), deep.Load(), deadReleased.Load())
	}
}
