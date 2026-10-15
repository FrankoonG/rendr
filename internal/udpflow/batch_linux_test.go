//go:build linux && (amd64 || arm64)

package udpflow

// Real-socket rows of the batched Source on Linux amd64/arm64, where a
// udpsocket.Conn reads with recvmmsg (M5 design §A10.1, §A10.3; they run
// in the pool's lanes, the Windows host only compiles them).

import (
	"runtime"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// batchingSource returns a started-or-not real Source whose socket batches,
// failing the test when the kernel or a sandbox refused the batch calls.
func batchingSource(t *testing.T, env *carrier.Env) *realSource {
	t.Helper()
	rs := newRealSourceIO(t, 1232, env, Limits{}, defaultMaxBatch)
	if m := rs.s.bio.Mode(); m != udpsocket.ModeBatch {
		t.Fatalf("the socket is in mode %d: recvmmsg is refused on this host", m)
	}
	return rs
}

// TestSourceDrainsQueued_L54 (R1-7, B0.2 item 5): 32 datagrams queued on
// the socket before the Source reads move in one recvmmsg.
func TestSourceDrainsQueued_L54(t *testing.T) {
	env := testEnv(1 << 30)
	rs := batchingSource(t, env)
	const id = 0x5151
	rs.send(h1(id, wire.TypeOpen, 1))
	for i := range 31 {
		rs.send(dg(id, pingFrame(uint32(2+i))))
	}
	rs.start()
	f := rs.flow()
	for i := range 32 {
		b, _, ev := readOne(t, f, realWait)
		if ev != carrier.ReadOK || (i > 0 && pingSeq(b) != uint32(1+i)) {
			t.Fatalf("datagram %d: event %d", i, ev)
		}
	}
	if _, _, calls, dgrams, _ := env.Dgram.IO.Load(); calls != 1 || dgrams != 32 {
		t.Fatalf("RecvCalls %d, RecvDatagrams %d; want one call of 32", calls, dgrams)
	}
}

// TestSourceBatchZeroAllocs_L54_L58 (§A10.3): on Linux loopback, 10,000
// datagrams in bursts of 32 read by the batched Source, routed into a
// flow's inbox and drained with ReadDatagrams allocate nothing (raw
// MemStats.Mallocs process-wide, as M2's owned-socket gate) and are all
// counted (a call moves several only when they are queued: the reader may
// keep pace with the sender, so that is TestSourceDrainsQueued_L54's row).
func TestSourceBatchZeroAllocs_L54_L58(t *testing.T) {
	env := testEnv(1 << 30)
	rs := batchingSource(t, env)
	if err := rs.u.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
	rs.start()
	const id = 0x5252
	rs.send(h1(id, wire.TypeOpen, 1))
	f := rs.flow()
	readOne(t, f, realWait)
	f.Admitted()
	if err := f.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	out := dg(id, pingFrame(2))
	rs2 := make([]carrier.ReadResult, 32)
	burst := func() {
		for range 32 {
			if _, err := rs.cl.WriteToUDPAddrPort(out, rs.dst); err != nil {
				t.Fatal(err)
			}
		}
		for got := 0; got < 32; {
			n, err := f.ReadDatagrams(rs2)
			if err != nil {
				t.Fatal(err)
			}
			got += n
		}
		f.Release()
	}
	runtime.GC() // before the warm-up, never inside the window (pool victim caches)
	for range 20 {
		burst()
	}
	const bursts = 10000 / 32
	_, _, calls0, dgrams0, _ := env.Dgram.IO.Load()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for range bursts {
		burst()
	}
	runtime.ReadMemStats(&m1)
	if d := m1.Mallocs - m0.Mallocs; d > 40 && !raceEnabled {
		t.Fatalf("%d allocations for %d datagrams, want ≤ 40", d, bursts*32)
	}
	_, _, calls1, dgrams1, _ := env.Dgram.IO.Load()
	if c, n := calls1-calls0, dgrams1-dgrams0; n != bursts*32 || c == 0 || c > n {
		t.Fatalf("%d datagrams in %d receive calls, want %d in at most as many", n, c, bursts*32)
	}
}
