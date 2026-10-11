package carrier

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// M5 pktloss rows of the datagram writer: the DGRAMs a round placed and
// never wrote go back to their endpoint (DgramReturner) when the round
// ends the carrier, and nothing is written on a carrier whose death record
// a round finds. Every row runs in the harness's three transport settings
// (TestMain: MaxBatch 32, MaxBatch 1, off).

// uEP is a dEP that takes back unwritten DGRAMs (DgramReturner): it records
// each one and releases its reference.
type uEP struct {
	dEP
	umu  sync.Mutex
	back []dgRec
}

func (e *uEP) Unsent(c *Conn, seq uint64, p []byte, buf *Buf) {
	e.umu.Lock()
	e.back = append(e.back, dgRec{seq: seq, n: len(p), byRef: buf != nil})
	e.umu.Unlock()
	buf.Release()
}

func (e *uEP) returned() []dgRec {
	e.umu.Lock()
	defer e.umu.Unlock()
	return append([]dgRec(nil), e.back...)
}

// chunkFill returns a Fill that places DGRAMs of size bytes, their bodies
// in chunk (referenced as a session's queue chunk is), for the session seqs
// from *seq on while *n > 0 and the batch takes them.
func chunkFill(n *atomic.Int32, seq *atomic.Uint64, chunk *Buf, size int) func(c *Conn, b *Batch) {
	return func(c *Conn, b *Batch) {
		for n.Load() > 0 {
			s := seq.Load()
			off := int(s%32) * size
			if !b.AddDgram(wire.SessionHandle, s, chunk.B[off:off+size], chunk) {
				return
			}
			seq.Add(1)
			n.Add(-1)
		}
	}
}

// TestDgramUnsentReturned_L39 (L39: only data in flight on a dead carrier
// may be lost): a round of 12 DGRAMs whose carrier ends in it.
//
//   - write-error: the transport fails the write of the 5th DGRAM
//     datagram (a fatal error): datagrams 0 … 3 reach the peer, and 4 … 11
//     — the failed one and every one never given to the transport — go
//     back to the endpoint, in seq order, each with a reference of its own.
//   - dead-before-write: the carrier is killed in Hooks.BeforeWrite of the
//     5th DGRAM datagram: no datagram write is attempted on it after the
//     kill, the datagrams the transport took before reach the peer, and
//     every other one goes back.
//
// In both, the peer's datagrams and the returned ones are disjoint and
// cover the round, and the chunk's references are exactly the test's own
// once the carrier is done (none kept, none released twice). Mutants: no
// hand-back (the suffix is lost); a hand-back from the wrong frame (a
// datagram both delivered and returned, or neither); no death check before
// a write (a write attempted after the kill).
func TestDgramUnsentReturned_L39(t *testing.T) {
	for _, kill := range []bool{false, true} {
		name := "write-error"
		if kill {
			name = "dead-before-write"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const size, total = 100, 12
				a, b := dgPair(t, 1200)
				u := &uEP{}
				bud := NewBudget(1 << 30)
				chunk := NewBufPool().Get(ChunkSize, bud)
				var n atomic.Int32
				var seq atomic.Uint64
				u.setFill(chunkFill(&n, &seq, chunk, size))
				var k, attempts, deadWrites atomic.Int32
				if kill {
					a.env.Hooks = &testhooks.Hooks{BeforeWrite: func(_ uint32, _, bytes int) {
						if bytes >= size && k.Add(1) == 5 {
							a.c.Kill(CauseLocalClose, "test: killed before the write")
						}
					}}
				}
				a.io.setOut(func(d []byte) error {
					if len(d) < size {
						return nil
					}
					attempts.Add(1)
					if dead, _, _, _ := a.c.Death(); dead {
						deadWrites.Add(1)
					}
					if !kill && attempts.Load() == 5 {
						return errNotNoise
					}
					return nil
				})
				a.c.Start(u, a.bell, StartOptions{})
				b.start(StartOptions{})
				synctest.Wait()
				n.Store(total)
				a.c.Wake()
				hWait(t, a.c)
				synctest.Wait()

				got := seqsOf(b.ep)
				back := u.returned()
				var bseq []uint64
				for _, r := range back {
					if !r.byRef || r.n != size {
						t.Fatalf("returned %+v, want %d bytes with a reference", r, size)
					}
					bseq = append(bseq, r.seq)
				}
				w := len(got)
				if !slices.Equal(got, upTo(w)) || !slices.Equal(bseq, upTo(total)[w:]) {
					t.Fatalf("delivered %v and returned %v, want a prefix delivered and the rest returned in order", got, bseq)
				}
				if kill {
					if w > 4 || deadWrites.Load() != 0 || int(attempts.Load()) != w || hCause(a.c) != CauseLocalClose {
						t.Fatalf("delivered %d, %d DGRAM writes attempted (%d after the kill), death %v: want no write after the kill",
							w, attempts.Load(), deadWrites.Load(), hCause(a.c))
					}
				} else if w != 4 || hCause(a.c) != CauseTransportError {
					t.Fatalf("delivered %v, death %v: want 0 … 3 and transport_error", got, hCause(a.c))
				}
				if r := chunk.refs.Load(); r != 1 {
					t.Fatalf("the chunk holds %d references after the carrier ended, want the test's 1", r)
				}
				chunk.Release()
				if used := bud.Used(); used != 0 {
					t.Fatalf("budget %d after the last release", used)
				}
			})
		})
	}
}

// TestDgramUnsentNotReturnedOnBadCount_L42: a batched write that reports
// an invalid count (L42) ends the carrier and returns nothing — which of
// the call's datagrams left is unknown, and a datagram returned that did
// leave would be sent twice — and the chunk's references still balance.
func TestDgramUnsentNotReturnedOnBadCount_L42(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size = 100
		a, b, fa := wp2Pair(t, 1200, 8)
		u := &uEP{}
		bud := NewBudget(1 << 30)
		chunk := NewBufPool().Get(ChunkSize, bud)
		var n atomic.Int32
		var seq atomic.Uint64
		u.setFill(chunkFill(&n, &seq, chunk, size))
		a.c.Start(u, a.bell, StartOptions{})
		b.start(StartOptions{})
		synctest.Wait()
		fa.setReport(func(k int) int { return k - 1 })
		n.Store(8)
		a.c.Wake()
		hWait(t, a.c)
		synctest.Wait()
		if hCause(a.c) != CauseTransportError {
			t.Fatalf("death %v, want transport_error on the count", hCause(a.c))
		}
		if back := u.returned(); len(back) != 0 {
			t.Fatalf("returned %v after an invalid count, want nothing", back)
		}
		if r := chunk.refs.Load(); r != 1 {
			t.Fatalf("the chunk holds %d references after the carrier ended, want the test's 1", r)
		}
		chunk.Release()
	})
}
