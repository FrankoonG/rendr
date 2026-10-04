package session

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// stChunkSet returns the session's current send chunks.
func stChunkSet(s *Session) map[*carrier.Buf]bool {
	return stLocked(s, func(st *stream) map[*carrier.Buf]bool {
		m := make(map[*carrier.Buf]bool, st.chunks.n)
		for i := range st.chunks.n {
			m[st.chunks.at(i)] = true
		}
		return m
	})
}

// TestAckDuringWriteNoChunkReuse_L17_L43: an ACK that acknowledges chunks
// while a carrier write still reads them drops only the session's
// references. A sibling session writing through the same pool meanwhile
// never receives those chunks, the in-progress write's bytes keep their
// CRC (the receiver's check would pass), and the memory returns to the
// pool when the write releases its references — not at the ACK. Under
// -race, a reused chunk would be reported as a race between the sibling's
// copy and this write's read. Likewise an ACK that brings the front up to
// the committed end while an application Write copies into the reserved
// rest of the tail chunk keeps that chunk (F5: the idle drop waits for
// sBase == resEnd).
func TestAckDuringWriteNoChunkReuse_L17_L43(t *testing.T) {
	t.Run("carrier write", testAckDuringCarrierWrite)
	t.Run("application copy", testAckDuringAppCopy)
}

func testAckDuringCarrierWrite(t *testing.T) {
	pool, budget := carrier.NewBufPool(), carrier.NewBudget(1<<30)
	a := stSession(stOpt{pool: pool, budget: budget, window: 4 << 20})
	al, _ := stAddLane(a, 1, true)
	sib := stSession(stOpt{pool: pool, budget: budget, window: 4 << 20})
	stAddLane(sib, 1, true)
	for _, s := range []*Session{a, sib} {
		s.mu.Lock()
		s.peerWindowLocked(4 << 20)
		s.mu.Unlock()
	}
	msg := stPattern(0, 256<<10)
	if n, err := a.Write(msg); n != len(msg) || err != nil {
		t.Fatal(err)
	}
	// The carrier writer took its references and is inside its write.
	inWrite := carrier.NewBatch(0)
	inWrite.Reset(time.Now())
	al.Fill(nil, inWrite)
	type body struct {
		chunk *carrier.Buf
		b     []byte
		crc   uint32
	}
	var bodies []body
	for i := range inWrite.Len() {
		f := inWrite.Frame(i)
		if f.Header.Type == wire.TypeData {
			bodies = append(bodies, body{f.Chunk, f.Body, wire.CRC(f.Body)})
		}
	}
	if len(bodies) != 4 {
		t.Fatalf("the write holds %d DATA frames, want 4 chunks of 64 KiB", len(bodies))
	}
	usedInWrite := budget.Used()

	// The peer acknowledges everything mid-write.
	if err := stSendAck(al, 0, uint64(len(msg)), 4<<20); err != nil {
		t.Fatal(err)
	}
	if n := len(stChunkSet(a)); n != 0 {
		t.Fatalf("%d chunks still in the ring after a full ACK (idle drop)", n)
	}
	if budget.Used() != usedInWrite {
		t.Fatal("chunks returned to the pool while a write still references them")
	}

	var wg sync.WaitGroup
	wg.Add(2)
	crcBad := make(chan int, len(bodies))
	go func() { // the write reading its bytes (writev / coalescing copy)
		defer wg.Done()
		for range 20 {
			for i, b := range bodies {
				if wire.CRC(b.b) != b.crc {
					crcBad <- i
					return
				}
			}
		}
	}()
	var sibChunks map[*carrier.Buf]bool
	go func() { // the sibling writes through the same pool
		defer wg.Done()
		_, _ = sib.Write(stPattern(1<<30, 1<<20))
		sibChunks = stChunkSet(sib)
	}()
	wg.Wait()
	close(crcBad)
	if i, bad := <-crcBad; bad {
		t.Fatalf("frame %d changed under the in-progress write (the receiver's CRC would fail)", i)
	}
	if len(sibChunks) < 16 {
		t.Fatalf("the sibling holds %d chunks, want 16 (stimulus)", len(sibChunks))
	}
	for _, b := range bodies {
		if sibChunks[b.chunk] {
			t.Fatal("the sibling received a chunk the in-progress write still reads")
		}
	}
	before := budget.Used()
	inWrite.ReleaseRefs() // the write returned
	if freed := before - budget.Used(); freed != 4*(chunkSize+carrier.ClassSlack) {
		t.Fatalf("the write's release freed %d bytes, want the 4 acknowledged chunks", freed)
	}
	stEnd(a, errClosed)
	stEnd(sib, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// stChurnPool takes n chunk-class buffers from pool on a new goroutine and
// scribbles over them, as a sibling session's Write would; release returns
// them after the goroutine finished. A chunk released while still being
// copied into would be handed out here (a -race report, corrupted bytes).
func stChurnPool(pool *carrier.BufPool, budget *carrier.Budget, n int) (release func()) {
	var wg sync.WaitGroup
	var bufs []*carrier.Buf
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range n {
			b := pool.Get(chunkSize, budget)
			for i := range b.B {
				b.B[i] = 0x5a
			}
			bufs = append(bufs, b)
		}
	}()
	return func() {
		wg.Wait()
		for _, b := range bufs {
			b.Release()
		}
	}
}

func testAckDuringAppCopy(t *testing.T) {
	pool, budget := carrier.NewBufPool(), carrier.NewBudget(1<<30)
	p := stNewPair(stOpt{pool: pool, budget: budget}, stOpt{}, 1)
	first, second := stPattern(0, 1000), stPattern(1000, 3000)
	if n, err := p.a.Write(first); n != len(first) || err != nil {
		t.Fatal(err)
	}
	p.pump(false) // [0,1000) arrives; the ACK of the Read below stays delayed
	stReadN(t, p.b, len(first))
	var once sync.Once
	release := func() {}
	stSetCopyHook(t, p.a, func() {
		once.Do(func() {
			used := budget.Used()
			// The peer's ACK of everything sent arrives during the copy.
			if err := stSendAck(p.al[0], 0, uint64(len(first)), 1<<20); err != nil {
				t.Errorf("ACK: %v", err)
			}
			st := stLocked(p.a, func(st *stream) [4]uint64 {
				return [4]uint64{st.sBase, st.end, st.resEnd, uint64(st.chunks.n)}
			})
			if st != [4]uint64{1000, 1000, 4000, 1} {
				t.Errorf("during the copy sBase/end/resEnd/chunks = %v, want 1000, 1000, 4000, 1: the tail chunk must stay", st)
			}
			if u := budget.Used(); u != used {
				t.Errorf("the ACK released %d bytes under the Write's copy", used-u)
			}
			release = stChurnPool(pool, budget, 4)
		})
	})
	if n, err := p.a.Write(second); n != len(second) || err != nil {
		t.Fatalf("Write racing the ACK = (%d, %v)", n, err)
	}
	release()
	if t.Failed() {
		t.FailNow() // a dropped tail chunk would make Fill dereference a nil ring slot
	}
	p.pump(true)
	if got := stReadN(t, p.b, len(second)); !bytes.Equal(got, second) {
		t.Fatal("the round copied during the ACK arrived corrupted")
	}
	if len(p.errs) != 0 {
		t.Fatalf("violations: %v", p.errs)
	}
	p.close(t)
}

// TestEndDuringWriteCopy_L07 (F7, the Write side): the session ends (the
// actor's no-path expiry) while a Write copies its second round outside
// the lock. Nothing is released under the copy — the Budget is unchanged
// and a sibling taking chunks from the same pool on another goroutine
// cannot receive one being copied into (-race would see it) — the Write
// returns its first round's bytes with ErrNoPath (the round being copied
// is not counted), and the copier releases every chunk at its commit.
// Ends at random points of unsynchronized Writes keep the same accounting.
func TestEndDuringWriteCopy_L07(t *testing.T) {
	const round = 256 << 10
	msg := stPattern(0, round+44<<10) // two rounds
	pool, budget := carrier.NewBufPool(), carrier.NewBudget(1<<30)
	s := stSession(stOpt{pool: pool, budget: budget})
	rounds := 0
	release := func() {}
	stSetCopyHook(t, s, func() {
		if rounds++; rounds != 2 {
			return
		}
		used := budget.Used()
		stEnd(s, ErrNoPath)
		if u := budget.Used(); u != used {
			t.Errorf("the end released %d bytes of chunks under the Write's copy", used-u)
		}
		release = stChurnPool(pool, budget, 8)
	})
	n, err := s.Write(msg)
	release()
	if n != round || !errors.Is(err, ErrNoPath) {
		t.Fatalf("Write ended during its second round = (%d, %v), want (%d, ErrNoPath)", n, err, round)
	}
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the Write returned: the copier did not release the chunks", u)
	}

	for i := range 200 {
		pool, budget := carrier.NewBufPool(), carrier.NewBudget(1<<30)
		s := stSession(stOpt{pool: pool, budget: budget})
		var wg sync.WaitGroup
		var r stIO
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.n, r.err = s.Write(msg)
		}()
		go func() {
			defer wg.Done()
			for range i % 8 {
				runtime.Gosched()
			}
			stEnd(s, ErrNoPath)
			stChurnPool(pool, budget, 2)()
		}()
		wg.Wait()
		if !(r.err == nil && r.n == len(msg)) && !(errors.Is(r.err, ErrNoPath) && r.n%round == 0 && r.n < len(msg)) {
			t.Fatalf("run %d: Write racing the end = (%d, %v)", i, r.n, r.err)
		}
		if u := budget.Used(); u != 0 {
			t.Fatalf("run %d: Budget.Used = %d after the end", i, u)
		}
	}
}

// TestConcurrentWritersNoInterleave_L41: 64 goroutines write records
// concurrently, some larger than one 256 KiB round; the peer reads one
// byte stream in which every record is contiguous and intact, each exactly
// once.
func TestConcurrentWritersNoInterleave_L41(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const writers = 64
		p := stNewPair(stOpt{window: 1 << 20}, stOpt{window: 1 << 20}, 1)
		stop := make(chan struct{})
		var link sync.WaitGroup
		p.runPair(&link, stop)
		defer func() {
			select {
			case <-stop:
			default:
				close(stop)
			}
			link.Wait()
		}()

		var total int
		sizes := make([][]int, writers)
		for w := range writers {
			rng := rand.New(rand.NewPCG(41, uint64(w)))
			for range 2 {
				n := 1 + rng.IntN(48<<10)
				if rng.IntN(16) == 0 {
					n = 256<<10 + rng.IntN(200<<10) // several rounds
				}
				sizes[w] = append(sizes[w], n)
				total += stRecHead + n
			}
		}
		got := stReadAsync(p.b, total)
		var wg sync.WaitGroup
		errs := make(chan error, writers)
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for seq, n := range sizes[w] {
					rec := stPutRecord(w, seq, stRecordBody(w, seq, n))
					if k, err := p.a.Write(rec); k != len(rec) || err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("Write: %v", err)
		}
		_ = p.a.CloseWrite()
		r := <-got
		if r.err != nil {
			t.Fatal(r.err)
		}
		if _, err := p.b.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("after all records: %v, want io.EOF", err)
		}
		seen := make(map[[2]int]bool)
		for b := r.b; len(b) > 0; {
			w, seq, n := stCheckRecord(t, b)
			if seen[[2]int{w, seq}] || w >= writers || seq >= len(sizes[w]) || n != sizes[w][seq] {
				t.Fatalf("record (%d, %d, %d) duplicated or unknown", w, seq, n)
			}
			seen[[2]int{w, seq}] = true
			b = b[stRecHead+n:]
		}
		if len(seen) != 2*writers {
			t.Fatalf("%d records, want %d", len(seen), 2*writers)
		}
		if errs := p.errors(); len(errs) != 0 {
			t.Fatalf("violations: %v", errs)
		}
		close(stop)
		link.Wait()
		p.close(t)
	})
}
