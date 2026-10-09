package carrier

import (
	"fmt"
	"testing"
	"time"
)

// WP DRR tests of the MUX writer's rotation and deficit rules (M3 design
// §A5.3 and R1-1 rule 4 as amended by WP DRR): rounds serve the least
// recently served views first, whatever order wakes and PONGs push them
// in; a call stopped by the shared capacity cap keeps the view's deficit
// and ends the round; an interactive view among backlogged ones is served
// in the round after its wake. Each drives a goroutine-less trunk round by
// round (bareMuxTrunk), so every number is deterministic.

// capPool is the shared capacity of a test trunk's views: payload calls
// place 16-KiB DATA frames while left > 0 and the call's quota allows, and
// mark the batch cap-blocked when left ran out with data still to send
// (the session's capacity line, Capacity − Inflight − Taken, M3-D11).
type capPool struct {
	chunk  *Buf
	left   int
	calls  int              // payload calls in the round
	order  []uint32         // the handles of the round's payload calls, in call order
	served map[uint32]int   // payload bytes placed per handle in the round
	rooms  map[uint32][]int // Room at the start of each payload call, per handle
}

func (p *capPool) reset(left int) {
	p.left, p.calls, p.order = left, 0, p.order[:0]
	p.served, p.rooms = map[uint32]int{}, map[uint32][]int{}
}

// capEP is one view's endpoint over a capPool; avail < 0 is a view that is
// always backlogged. frame > 0 places whole frames of that size only (a
// datagram is never cut).
type capEP struct {
	hEP
	pool  *capPool
	avail int
	frame int
}

func (e *capEP) Fill(c *Conn, b *Batch) {
	if b.ControlOnly() {
		return
	}
	p, h := e.pool, c.Handle()
	p.calls++
	p.order = append(p.order, h)
	p.rooms[h] = append(p.rooms[h], b.Room())
	for e.avail != 0 {
		if p.left <= 0 {
			b.MarkCapBlocked()
			return
		}
		n := min(16<<10, p.left, b.Room())
		if e.frame > 0 {
			if min(p.left, b.Room()) < e.frame {
				return
			}
			n = e.frame
		}
		if e.avail > 0 {
			n = min(n, e.avail)
		}
		if n <= 0 || !b.AddData(h, 0, p.chunk.B[:n], p.chunk, false) {
			return
		}
		p.left -= n
		p.served[h] += n
		if e.avail > 0 {
			e.avail -= n
		}
	}
}

// capTrunk returns a goroutine-less MUX trunk with n views (handles 1 … n)
// over one capPool, and a function that runs one writer round: the pool
// refilled to left, a PONG (the watermark moved) when pong, the views of
// wake (indexes) woken in that order, then fillRound into a fresh batch of
// budget bytes.
func capTrunk(n, budget int) (*Conn, []*Conn, []*capEP, *capPool, func(left int, pong bool, wake ...int)) {
	env := hEnv()
	pool := &capPool{chunk: env.Bufs.Get(ChunkSize, nil)}
	c, views := bareMuxTrunk(env, &nopConn{}, n, nil)
	eps := make([]*capEP, n)
	for i, v := range views {
		eps[i] = &capEP{pool: pool, avail: -1}
		v.ep = eps[i]
	}
	b := NewBatch(budget)
	round := func(left int, pong bool, wake ...int) {
		pool.reset(left)
		if pong {
			c.mu.Lock()
			c.st.pongMark++
			c.mu.Unlock()
		}
		for _, i := range wake {
			views[i].Wake()
		}
		b.Reset(time.Now())
		c.fillRound(b)
		b.Reset(time.Time{})
	}
	return c, views, eps, pool, round
}

// TestMuxDRRRotationAfterCapStop (§A5.3, R1-1 rule 4 amended; L15): four
// backlogged views share a trunk whose capacity a PONG refills by one
// quantum, so the cap stops every round after one view. Between PONGs the
// views' producers wake some or all of them, in a different order every
// time (the session marks a lane idle after a call that placed nothing, so
// its next write wakes it); a woken view finds the cap exhausted. PASS: the PONG rounds serve the views in a strict round
// robin — any 4 consecutive PONG rounds serve each view once. On m3
// (8a9b989) two of the four views were served alternately and the other
// two never: the ring kept the previous rounds' order and the start
// rotated over it (in the scenario, one view was served at 6 of 7
// consecutive PONGs while another waited: TestMuxCapLimitedSharesFair).
func TestMuxDRRRotationAfterCapStop(t *testing.T) {
	const q, n, pongs = defMuxQuantum, 4, 64
	_, _, _, pool, round := capTrunk(n, 256<<10)
	round(0, false, 0, 1, 2, 3) // every view ready and cap-blocked
	perms := [][]int{{3, 2, 1, 0}, {3}, {1, 3, 0, 2}, {2, 0}, {2, 0, 3, 1}, {1}, {0, 1, 2, 3}, {3, 1}}
	var order []uint32
	for r := 0; r < pongs; r++ {
		round(q, true)
		if len(pool.served) != 1 {
			t.Fatalf("PONG %d: the round served %v, want one view (one quantum of capacity)", r, pool.served)
		}
		for h, x := range pool.served {
			if x != q {
				t.Fatalf("PONG %d: view %d placed %d bytes, want one quantum %d", r, h, x, q)
			}
			order = append(order, h)
		}
		// The producers' wakes, in an order that changes every time.
		round(0, false, perms[r%len(perms)]...)
		if len(pool.served) != 0 {
			t.Fatalf("PONG %d: a round at the exhausted cap placed %v", r, pool.served)
		}
	}
	for i := 0; i+n <= len(order); i++ {
		seen := map[uint32]bool{}
		for _, h := range order[i : i+n] {
			seen[h] = true
		}
		if len(seen) != n {
			t.Fatalf("PONG rounds %d…%d served views %v, want each of the %d views once (served order %v)", i, i+n-1, order[i:i+n], n, order)
		}
	}
}

// TestMuxDRRDeficitKeptAtCapStop (§A5.3 amended): a turn the capacity cap
// cuts keeps its deficit and its place. View 1 places 40 KiB of its
// 64-KiB quantum before the cap; it is then called again at the exhausted
// cap (the round's second pass, and the next round) and places nothing.
// PASS: at the next PONG view 1 is called first, with a quota of the
// 24 KiB its turn had left (64 KiB in all for the turn), then view 2 gets
// its quantum. m3 (8a9b989) set the deficit of every call that placed
// nothing to 0 (A5.3's v.deficit = used > 0 ? max(q − used, 0) : 0).
func TestMuxDRRDeficitKeptAtCapStop(t *testing.T) {
	const q = defMuxQuantum
	_, views, _, pool, round := capTrunk(2, 256<<10)
	round(40<<10, false, 0, 1)
	if pool.served[1] != 40<<10 || pool.served[2] != 0 {
		t.Fatalf("round 1 placed %v, want 40 KiB of view 1 only (then the cap)", pool.served)
	}
	round(0, false, 0, 1) // both stopped at the exhausted cap
	if len(pool.served) != 0 || len(pool.rooms[1]) == 0 {
		t.Fatalf("round 2 at the exhausted cap: placed %v, view 1's calls %v; want nothing placed and view 1 called", pool.served, pool.rooms[1])
	}
	if d := views[0].deficit; d != 24<<10 {
		t.Fatalf("view 1's deficit after calls the cap stopped is %d, want the 24 KiB its turn had left", d)
	}
	round(1<<20, true)
	if len(pool.order) < 2 || pool.order[0] != 1 || pool.order[1] != 2 {
		t.Fatalf("after the PONG the payload calls ran in the order %v, want view 1 (its cut turn) then view 2", pool.order)
	}
	if r1, r2 := pool.rooms[1], pool.rooms[2]; r1[0] != 24<<10 || r2[0] != q {
		t.Fatalf("after the PONG: quotas of view 1 %v and view 2 %v, want first 24 KiB (the rest of view 1's turn) and %d", r1, r2, q)
	}
}

// TestMuxDRRTurnCutByBatchEnd (§A5.3 amended; M3-D10): three backlogged
// views share a trunk whose batch holds two and a half quanta, so every
// round's batch ends inside a view's turn. PASS: over 12 rounds every view
// places within one quantum of the others (the cut turn is finished first
// in the next round; it neither goes to the back nor gains a quantum).
// With service order alone (a cut turn stamped like a finished one) the
// cut view goes behind the others, is cut again in every round and gets
// half the rate of the other two.
func TestMuxDRRTurnCutByBatchEnd(t *testing.T) {
	const q, rounds = defMuxQuantum, 12
	_, _, _, pool, round := capTrunk(3, 5*q/2)
	total := map[uint32]int{}
	for r := 0; r < rounds; r++ {
		round(1<<30, false, 0, 1, 2)
		for h, x := range pool.served {
			total[h] += x
		}
	}
	lo, hi := total[1], total[1]
	for _, x := range total {
		lo, hi = min(lo, x), max(hi, x)
	}
	if len(total) != 3 || hi-lo > q {
		t.Fatalf("over %d rounds the views placed %v bytes, want all three within one quantum (%d) of each other", rounds, total, q)
	}
}

// TestMuxDRRCutTurnTooSmallStaysReady (§A5.3 amended; R1-1): a view that
// places whole 20-KiB frames (a datagram is never cut) on a batch of
// 62 KiB places three per round, and its turn is cut with 4 KiB left —
// less than a frame. PASS: the rest of the turn places nothing, the turn
// ends there, and the view stays ready: without any further wake (its
// session marked itself idle after the call that placed nothing, so its
// producers would not wake it) it places three frames in each of the
// next 8 rounds.
func TestMuxDRRCutTurnTooSmallStaysReady(t *testing.T) {
	_, _, eps, pool, round := capTrunk(2, 62<<10)
	eps[0].frame = 20 << 10
	eps[1].avail = 0
	round(1<<30, false, 0, 1)
	for r := 1; r <= 8; r++ {
		if pool.served[1] != 60<<10 {
			t.Fatalf("round %d: view 1 placed %d bytes, want three 20-KiB frames (it has data and no wake came)", r, pool.served[1])
		}
		round(1<<30, false)
	}
}

// TestMuxDRREchoWithinOneRound (§A5.3 fairness bound: an interactive
// view's frame waits at most one round of other views' payload; L15):
// three backlogged views and an echo view share a trunk whose batch holds
// two quanta. A producer writes 1 KiB to the echo view and wakes it during
// a backlogged view's payload call (round r), at phases of the rotation
// that vary. PASS: the echo's bytes leave by round r + 1, all 40 times
// (in round r when the echo was still in the round's scratch, behind the
// producer's view).
// m3 (8a9b989) left the echo behind two quanta of other views whenever the
// rotating start fell two places before it.
func TestMuxDRREchoWithinOneRound(t *testing.T) {
	const q, writes = defMuxQuantum, 40
	_, views, eps, pool, round := capTrunk(4, 2*q)
	echo := eps[3]
	echo.avail = 0
	prod := &injectEP{capEP: eps[0]}
	views[0].ep = prod
	n, firedAt := 0, -1
	var late []string
	for r := 0; n < writes; r++ {
		if r > 400 {
			t.Fatalf("%d echo writes in %d rounds", n, r)
		}
		if firedAt < 0 && (r%3 == 1 || r%7 == 2) {
			prod.fn = func() {
				firedAt = r
				echo.avail = 1 << 10
				views[3].Wake()
			}
		}
		round(1<<30, false, 0, 1, 2)
		if firedAt >= 0 && firedAt < r {
			n++
			if echo.avail != 0 { // placed in round r, or already in firedAt (a call after the wake)
				late = append(late, fmt.Sprintf("woken in round %d, round %d placed %v", firedAt, r, pool.served))
			}
			firedAt = -1
		}
	}
	if len(late) > 0 {
		t.Fatalf("%d of %d echo writes were not placed in the round after their wake: %v", len(late), writes, late)
	}
}

// injectEP is a capEP whose next payload call first runs fn once: a
// producer of another view writing during this view's call.
type injectEP struct {
	*capEP
	fn func()
}

func (e *injectEP) Fill(c *Conn, b *Batch) {
	if f := e.fn; f != nil && !b.ControlOnly() {
		e.fn = nil
		f()
	}
	e.capEP.Fill(c, b)
}
