package udpsocket

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// TestCountersSnapshotOrder (M5 design R3-32, A2.1): while calls of one
// datagram each are being counted on several goroutines, no Load shows
// fewer datagrams than calls in either direction — the datagram count is
// added before the call count and loaded after it. Stimulus: the writers'
// counts all land (calls = datagrams = writers × adds at the end), and the
// reader took snapshots while they ran. The exported AddSend and AddRecv
// count as the Conn's own paths do, and a nil Counters counts nothing.
// Mutant: the call count added first (a snapshot then shows datagrams =
// calls − 1; seen with GOMAXPROCS ≥ 2).
func TestCountersSnapshotOrder(t *testing.T) {
	var c Counters
	writers := max(2, runtime.GOMAXPROCS(0))
	const adds = 200000
	var wg sync.WaitGroup
	var done atomic.Bool
	var snaps, bad atomic.Int64
	var first [4]uint64
	var once sync.Once
	wg.Go(func() {
		for !done.Load() {
			sc, sent, rc, recvd, _ := c.Load()
			snaps.Add(1)
			if sent < sc || recvd < rc {
				bad.Add(1)
				once.Do(func() { first = [4]uint64{sc, sent, rc, recvd} })
			}
		}
	})
	var ww sync.WaitGroup
	for range writers {
		ww.Go(func() {
			for i := range adds {
				if i%2 == 0 {
					c.addSend(1, 1)
					c.addRecv(1, 1)
				} else {
					c.AddSend(1, 1)
					c.AddRecv(1, 1)
				}
			}
		})
	}
	ww.Wait()
	done.Store(true)
	wg.Wait()
	sc, sent, rc, recvd, fb := c.Load()
	if want := uint64(writers * adds); sc != want || sent != want || rc != want || recvd != want || fb != 0 {
		t.Fatalf("stimulus: final counters %d/%d/%d/%d, fallbacks %d; want %d each, 0", sc, sent, rc, recvd, fb, want)
	}
	if snaps.Load() == 0 {
		t.Fatal("stimulus: no snapshot was taken while the calls were counted")
	}
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d of %d snapshots showed fewer datagrams than calls; the first: send %d calls / %d datagrams, recv %d calls / %d datagrams",
			n, snaps.Load(), first[0], first[1], first[2], first[3])
	}

	var nilc *Counters
	nilc.AddSend(1, 1) // must not panic
	nilc.AddRecv(1, 1)
	var z Counters
	z.AddSend(0, 5) // no call: nothing counted
	z.AddRecv(-1, 5)
	if sc, sent, rc, recvd, _ := z.Load(); sc != 0 || sent != 0 || rc != 0 || recvd != 0 {
		t.Fatalf("calls ≤ 0 counted: %d/%d/%d/%d", sc, sent, rc, recvd)
	}
}
