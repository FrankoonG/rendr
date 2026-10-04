package session

import (
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// chunkSet returns the session's current send chunks.
func chunkSet(s *Session) map[*carrier.Buf]bool {
	return locked(s, func(st *stream) map[*carrier.Buf]bool {
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
// copy and this write's read.
func TestAckDuringWriteNoChunkReuse_L17_L43(t *testing.T) {
	pool, budget := carrier.NewBufPool(), carrier.NewBudget(1<<30)
	a := newTestSession(sopt{pool: pool, budget: budget, window: 4 << 20})
	al, _ := addLane(a, 1, true)
	sib := newTestSession(sopt{pool: pool, budget: budget, window: 4 << 20})
	addLane(sib, 1, true)
	for _, s := range []*Session{a, sib} {
		s.mu.Lock()
		s.peerWindowLocked(4 << 20)
		s.mu.Unlock()
	}
	msg := pattern(0, 256<<10)
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
	if err := sendAck(al, 0, uint64(len(msg)), 4<<20); err != nil {
		t.Fatal(err)
	}
	if n := len(chunkSet(a)); n != 0 {
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
		_, _ = sib.Write(pattern(1<<30, 1<<20))
		sibChunks = chunkSet(sib)
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
	endSession(a, errClosed)
	endSession(sib, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// TestConcurrentWritersNoInterleave_L41: 64 goroutines write records
// concurrently, some larger than one 256 KiB round; the peer reads one
// byte stream in which every record is contiguous and intact, each exactly
// once.
func TestConcurrentWritersNoInterleave_L41(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const writers = 64
		p := newPair(sopt{window: 1 << 20}, sopt{window: 1 << 20}, 1)
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
				total += recHead + n
			}
		}
		got := readAsync(p.b, total)
		var wg sync.WaitGroup
		errs := make(chan error, writers)
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for seq, n := range sizes[w] {
					rec := putRecord(w, seq, recordBody(w, seq, n))
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
			w, seq, n := checkRecord(t, b)
			if seen[[2]int{w, seq}] || w >= writers || seq >= len(sizes[w]) || n != sizes[w][seq] {
				t.Fatalf("record (%d, %d, %d) duplicated or unknown", w, seq, n)
			}
			seen[[2]int{w, seq}] = true
			b = b[recHead+n:]
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
