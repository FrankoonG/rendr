//go:build !race

package udpflow

// The inbox blocks' zero-allocation gate (inboxtime; §A10.3; L41, L54):
// asserted in the non-race lane only, as alloc_test.go's gates — the race
// detector makes sync.Pool drop items on purpose.

import (
	"runtime"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestFlowInboxBlocksZeroAllocs_L41 (F-6: "steady state allocates nothing
// per datagram"): four batched reads of 32 datagrams of a flow whose read
// buffer bound is 16 MiB queue 128 datagrams — its first block and two
// pooled ones — and its ReadDatagrams calls drain them, the drained blocks
// going back to the Source's pool; in steady state the cycle allocates
// nothing, and afterwards the inbox is back on its first block and nothing
// stays charged. Mutant: a block allocated per growth instead of pooled.
func TestFlowInboxBlocksZeroAllocs_L41(t *testing.T) {
	idlePeriod(t, time.Hour) // no idle-release firing inside the window
	env := testEnv(1 << 30)
	c := &loopSock{max: 32, from: apOf(2, 1000)}
	s := newSeamSource(env, c, c, seamDgram, Limits{})
	s.setReadBuffer(16 << 20)
	var f *Flow
	r := &reader{s: s, admit: func(g *Flow) { f = g }}
	r.startDepth() // as loopOwned: the reads go through the reader's word
	s.route(r, h1(1, wire.TypeOpen, 1), c.from, nil, false)
	if f == nil {
		t.Fatal("no flow admitted")
	}
	f.Admitted()
	readOne(t, f, time.Second)
	if err := f.SetReadDeadline(time.Time{}); err != nil { // the cycles may outlast readOne's deadline
		t.Fatal(err)
	}
	for i := range 32 {
		c.ds = append(c.ds, dg(1, pingFrame(uint32(2+i))))
	}
	const reads = 4
	rs := make([]carrier.ReadResult, 32)
	cycle := func() {
		for range reads {
			if !r.readOwned() {
				t.Fatal("the read failed")
			}
		}
		f.mu.Lock()
		_, pooled, queued := inboxStorageLocked(f)
		f.mu.Unlock()
		if queued != reads*32 || pooled != pooledFor(reads*32) {
			t.Fatalf("stimulus: %d queued in %d pooled blocks, want %d in %d", queued, pooled, reads*32, pooledFor(reads*32))
		}
		for got := 0; got < reads*32; {
			n, err := f.ReadDatagrams(rs)
			if err != nil {
				t.Fatalf("ReadDatagrams after %d: %v", got, err)
			}
			got += n
		}
		f.Release()
	}
	runtime.GC() // before the warm-up, never inside the window (pool victim caches)
	for range 50 {
		cycle()
	}
	if a := testing.AllocsPerRun(1000, cycle); a != 0 {
		t.Fatalf("%v allocations per cycle of %d datagrams through the inbox's blocks", a, reads*32)
	}
	idleInbox(t, f, "after the cycles")
	f.Close()
	r.exit()
	<-s.Done()
	if u := buffered(env); u != 0 {
		t.Fatalf("%d bytes buffered after the end", u)
	}
}
