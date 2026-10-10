package carrier

import (
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestMuxViewCountersAgainstTrunk_R2_18 (M3 design R2-18, §A10.2; the
// CarrierStatus godoc): on a MUX trunk each view's Stats count the
// view's own traffic — TxBytes the payload its session's Fill placed and
// the trunk wrote, RxBytes the payload the trunk delivered to it — while
// the trunk's own counters (trunk.st.txBytes, trunk.rxBytes) count every
// view's: once every byte arrived, on each role, the views' TxBytes add
// up to the trunk's TxBytes and their RxBytes to its RxBytes, a view's
// TxBytes on one end equals its RxBytes on the other, and every view
// reports the same MTU (a trunk field). Rows: a stream trunk (DATA) and a
// datagram trunk (DGRAM), three views each (view 1, which first sends
// alone on the trunk, and two opened ones), each direction of each view
// with a different amount, so a view reporting the trunk's figure,
// another view's or its peer's, or missing the one-view round's, fails.
//
// Load: every amount crossed (the receiving endpoints saw exactly the
// bytes offered on their handle). PASS as above, on both roles.
func TestMuxViewCountersAgainstTrunk_R2_18(t *testing.T) {
	// Payload per handle (1, 2, 3) placed by the dialer's and the
	// passive's views.
	dAmt := map[uint32]int{1: 40_000, 2: 70_000, 3: 130_000}
	pAmt := map[uint32]int{1: 50_000, 2: 20_000, 3: 90_000}
	t.Run("stream", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, p := muxPair(t, nil)
			mvCountersRows(t, d, p, dAmt, pAmt, false)
		})
	})
	t.Run("datagram", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, p, _, _ := dgMuxPair(t, 1200, nil)
			mvCountersRows(t, d, p, dAmt, pAmt, true)
		})
	})
}

// mvDgramSize is the DGRAM payload size of the datagram row: a multiple
// fits every amount exactly.
const mvDgramSize = 1000

// mvAlone is the payload each end's view 1 places while it is the
// trunk's only view (the one-view round, oneViewFill), before views 2
// and 3 open; part of dAmt[1] and pAmt[1].
const mvAlone = 10_000

func mvCountersRows(t *testing.T, d, p *muxSide, dAmt, pAmt map[uint32]int, dgram bool) {
	handles := []uint32{1, 2, 3}
	sides := []struct {
		name string
		s    *muxSide
		amt  map[uint32]int
	}{{"dialer", d, dAmt}, {"passive", p, pAmt}}
	type dgSrc struct {
		left atomic.Int64
		seq  uint64
	}
	dgs := map[*mView]*dgSrc{}
	// send makes mv's Fill place n more payload bytes.
	send := func(mv *mView, n int) {
		if !dgram {
			mv.src.offer(uint64(n))
		} else {
			g := dgs[mv]
			if g == nil {
				g = &dgSrc{}
				dgs[mv] = g
				body := make([]byte, mvDgramSize)
				mv.src.mu.Lock()
				mv.src.hook = func(c *Conn, b *Batch) {
					for g.left.Load() > 0 && b.AddDgram(c.Handle(), g.seq, body, nil) {
						g.seq++
						g.left.Add(-1)
					}
				}
				mv.src.mu.Unlock()
			}
			g.left.Add(int64(n / mvDgramSize))
		}
		mv.c.Wake()
	}
	got := func(mv *mView) int {
		if dgram {
			k := 0
			for _, r := range mv.ep.datagrams() {
				k += r.n
			}
			return k
		}
		return int(mv.ep.rxBytes.Load())
	}

	// View 1 alone on the trunk (no view table yet).
	send(d.v1, mvAlone)
	send(p.v1, mvAlone)
	for deadline := time.Now().Add(30 * time.Second); got(d.v1) != mvAlone || got(p.v1) != mvAlone; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("load: view 1 alone: %d and %d of %d bytes crossed within 30 s", got(p.v1), got(d.v1), mvAlone)
		}
	}
	if d.c.ms.multi.Load() || p.c.ms.multi.Load() {
		t.Fatal("premise: a view table exists before views 2 and 3 open")
	}
	for _, sid := range []byte{2, 3} {
		d.open(t, wire.TypeOpen, sid)
	}
	synctest.Wait()
	for _, sd := range sides {
		for _, h := range handles {
			mv := sd.s.view(h)
			if mv == nil {
				t.Fatalf("premise: %s has no view %d", sd.name, h)
			}
			n := sd.amt[h]
			if h == 1 {
				n -= mvAlone
			}
			send(mv, n)
		}
	}

	// Load: every byte crossed, on every handle, both ways.
	deadline := time.Now().Add(30 * time.Second)
	for {
		synctest.Wait()
		var missing []string
		for i, sd := range sides {
			peer := sides[1-i]
			for _, h := range handles {
				if g, w := got(peer.s.view(h)), sd.amt[h]; g != w {
					missing = append(missing, fmt.Sprintf("%s view %d received %d of %d", peer.name, h, g, w))
				}
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("load: not every byte crossed within 30 s: %v", missing)
		}
		time.Sleep(10 * time.Millisecond)
	}
	synctest.Wait()

	for i, sd := range sides {
		peer := sides[1-i]
		tr := sd.s.c.trunk
		tr.mu.Lock()
		trTx := tr.st.txBytes
		tr.mu.Unlock()
		trRx := tr.rxBytes.Load()
		var sumTx, sumRx uint64
		mtu := -1
		for _, h := range handles {
			st := sd.s.view(h).c.Stats()
			if st.Handle != h || st.Shared != 3 {
				t.Fatalf("premise: %s view %d Stats Handle %d Shared %d, want %d and 3", sd.name, h, st.Handle, st.Shared, h)
			}
			if st.TxBytes != uint64(sd.amt[h]) || st.RxBytes != uint64(peer.amt[h]) {
				t.Errorf("%s view %d: TxBytes %d RxBytes %d, want its own traffic %d and %d (trunk: %d and %d)",
					sd.name, h, st.TxBytes, st.RxBytes, sd.amt[h], peer.amt[h], trTx, trRx)
			}
			if pst := peer.s.view(h).c.Stats(); st.TxBytes != pst.RxBytes {
				t.Errorf("%s view %d TxBytes %d, %s view %d RxBytes %d: want equal", sd.name, h, st.TxBytes, peer.name, h, pst.RxBytes)
			}
			if mtu >= 0 && st.MTU != mtu {
				t.Errorf("%s view %d MTU %d, view 1's %d: the trunk's field differs between views", sd.name, h, st.MTU, mtu)
			}
			mtu = st.MTU
			sumTx += st.TxBytes
			sumRx += st.RxBytes
		}
		if sumTx != trTx || sumRx != trRx {
			t.Errorf("%s: Σ views TxBytes %d RxBytes %d, trunk TxBytes %d RxBytes %d: want equal", sd.name, sumTx, sumRx, trTx, trRx)
		}
		if dgram && mtu <= 0 || !dgram && mtu != 0 {
			t.Errorf("%s: MTU %d on a %s trunk", sd.name, mtu, map[bool]string{false: "stream", true: "datagram"}[dgram])
		}
	}
}
