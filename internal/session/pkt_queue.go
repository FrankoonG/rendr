package session

import (
	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The packed datagram queue (M2-D32, M2 design §A5.2): one per direction
// (tx, txBig, rx). Every method runs with Session.mu held; nothing here
// allocates except the rare descriptor-ring doubling (at most
// log2(Queue/64) − 6 times per session).
//
// Chunk bookkeeping. Datagrams below BigData are copied into the newest
// 64 KiB chunk; a new chunk opens when the newest lacks room. Chunk
// numbers are absolute and never decrease along the queue (an ext
// datagram carries the newest chunk's number at its push), so the chunks
// still needed are exactly those from the head descriptor's chunk to the
// newest: popping the head releases every chunk below the new head's, and
// an empty queue releases them all. The ring holds the queue's own
// reference on each chunk; a batch (AddDgram) or a ReadFrom holding bytes
// of a chunk takes its own.
//
// Chunk ring size: every chunk except the head descriptor's and the
// newest is closed and still wholly queued; a chunk closes only when a
// datagram below BigData did not fit, so it holds more than ChunkSize −
// BigData bytes, all charged. Hence at most Queue/(ChunkSize − BigData) + 2
// chunks are ever needed; the ring has one spare slot, and push evicts
// while it is full (a guard: it cannot happen within the bound).

// pdescInit is the initial descriptor ring (a power of two).
const pdescInit = 64

// init sets the bounds (max bytes of charge, maxN descriptors) and makes
// the rings.
func (q *pring) init(max int64, maxN int) {
	q.max, q.maxN = max, maxN
	q.desc = make([]pdesc, min(pdescInit, ceilPow2(maxN)))
	q.chunks = make([]*carrier.Buf, max/(carrier.ChunkSize-carrier.BigData)+3)
}

// ceilPow2 returns the smallest power of two ≥ n (n ≥ 1).
func ceilPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// pcharge is a datagram's charge against Queue (Q5).
func pcharge(n uint32) int64 {
	return max(int64(n), pktChargeMin)
}

// front returns the head descriptor (q.n > 0).
func (q *pring) front() *pdesc {
	return &q.desc[q.head]
}

// back returns the tail descriptor (q.n > 0).
func (q *pring) back() *pdesc {
	return &q.desc[(q.head+q.n-1)&(len(q.desc)-1)]
}

// chunkAt returns the chunk with absolute number c (held by the ring).
func (q *pring) chunkAt(c uint32) *carrier.Buf {
	i := q.chead + int(c-q.cbase)
	if i >= len(q.chunks) {
		i -= len(q.chunks)
	}
	return q.chunks[i]
}

// data returns d's bytes and the Buf holding them (its chunk, or ext).
func (q *pring) data(d *pdesc) ([]byte, *carrier.Buf) {
	if d.ext != nil {
		return d.ext.B[:d.n], d.ext
	}
	c := q.chunkAt(d.chunk)
	return c.B[d.off : d.off+d.n], c
}

// push enqueues a datagram of n bytes enqueued at at (ns since the
// session's base). With ext non-nil, ext.B is exactly the datagram and its
// reference moves to the queue; otherwise slot is the chunk room the
// caller copies the datagram into (under the same lock section). Before
// it, the oldest datagrams are evicted while the queue's charge or count
// would exceed its bounds (drop-oldest, M2-D33/M2-D37); evicted counts
// them. A chunk the pool refuses evicts the head once and is tried again;
// a second refusal drops the new datagram: ok is false (and slot nil). ext
// is always taken (ok true).
func (q *pring) push(n int, at int64, ext *carrier.Buf, pool *carrier.BufPool, budget *carrier.Budget) (slot []byte, evicted int, ok bool) {
	c := pcharge(uint32(n))
	for q.n > 0 && (q.charge+c > q.max || q.n >= q.maxN) {
		q.evict()
		evicted++
	}
	var chunk uint32
	var off int
	if ext == nil {
		if q.cn == 0 || q.tail+n > carrier.ChunkSize {
			for q.cn == len(q.chunks) && q.n > 0 {
				q.evict()
				evicted++
			}
			buf := pool.TryGet(carrier.ChunkSize, budget)
			if buf == nil && q.n > 0 {
				q.evict()
				evicted++
				buf = pool.TryGet(carrier.ChunkSize, budget)
			}
			if buf == nil {
				return nil, evicted, false
			}
			i := q.chead + q.cn
			if i >= len(q.chunks) {
				i -= len(q.chunks)
			}
			q.chunks[i] = buf
			q.cn++
			q.tail = 0
		}
		chunk = q.cbase + uint32(q.cn-1)
		off = q.tail
		q.tail += n
		slot = q.chunkAt(chunk).B[off : off+n]
	} else {
		chunk = q.cbase + uint32(q.cn)
		if q.cn > 0 {
			chunk--
		}
	}
	if q.n == len(q.desc) {
		q.grow()
	}
	q.desc[(q.head+q.n)&(len(q.desc)-1)] = pdesc{chunk: chunk, off: uint32(off), n: uint32(n), at: at, ext: ext}
	q.n++
	q.charge += c
	q.bytes += int64(n)
	return slot, evicted, true
}

// grow doubles the descriptor ring (rare: never beyond maxN rounded up to
// a power of two).
func (q *pring) grow() {
	d := make([]pdesc, 2*len(q.desc))
	for i := range q.n {
		d[i] = q.desc[(q.head+i)&(len(q.desc)-1)]
	}
	q.desc, q.head = d, 0
}

// pop removes the head descriptor and returns it; its ext reference (if
// any) moves to the caller. A caller that still needs the bytes of a
// chunk datagram references the chunk before (the pop may release it).
func (q *pring) pop() pdesc {
	d := q.desc[q.head]
	q.desc[q.head] = pdesc{}
	q.head = (q.head + 1) & (len(q.desc) - 1)
	q.n--
	q.charge -= pcharge(d.n)
	q.bytes -= int64(d.n)
	q.trim()
	return d
}

// popRef pops the head and returns its bytes with a reference the caller
// releases: its chunk referenced once more, or its ext moved.
func (q *pring) popRef() ([]byte, *carrier.Buf) {
	data, buf := q.data(q.front())
	if q.front().ext == nil {
		buf.Ref()
	}
	q.pop()
	return data, buf
}

// evict drops the head datagram.
func (q *pring) evict() {
	d := q.pop()
	d.ext.Release()
}

// trim releases the chunks no queued datagram needs any more: every chunk
// once the queue is empty, else the chunks below the head's.
func (q *pring) trim() {
	if q.n == 0 {
		for q.cn > 0 {
			q.releaseFront()
		}
		q.tail = 0
		return
	}
	keep := q.desc[q.head].chunk
	for q.cn > 0 && int32(keep-q.cbase) > 0 {
		q.releaseFront()
	}
}

// releaseFront releases the oldest chunk of the ring.
func (q *pring) releaseFront() {
	q.chunks[q.chead].Release()
	q.chunks[q.chead] = nil
	q.chead++
	if q.chead == len(q.chunks) {
		q.chead = 0
	}
	q.cbase++
	q.cn--
}

// releaseAll drops every queued datagram and every chunk and returns how
// many datagrams were queued. The rings keep their capacity.
func (q *pring) releaseAll() int {
	n := q.n
	for q.n > 0 {
		q.evict()
	}
	return n
}
