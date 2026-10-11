package udpsocket

import (
	"syscall"
	"testing"
	"time"
)

// The allocation gates of the batch calls (§A10.3; L41, L54, L55, R1-13).
// On Linux amd64/arm64 they run the real sendmmsg/recvmmsg on loopback
// sockets; on every other target (the Windows host) ModeBatch is driven
// through fake calls, which still runs the RawConn plumbing, the bound
// callbacks and the counters. The non-race lane asserts zero allocations;
// the race lane runs the same loops without the assertion.

const allocDatagrams = 10000

// TestBatchSendZeroAllocs_L41_L55: a batched write of 32 datagrams
// allocates nothing in steady state — the RawConn callback is the method
// value bound in NewBatch, never a closure per call (R1-13) — over 10,000
// datagrams after warm-up.
func TestBatchSendZeroAllocs_L41_L55(t *testing.T) {
	seams(t)
	if !accelerated {
		forceBatch(t, newProbe(syscall.EBADF, syscall.EBADF))
		sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) { return n, nil }
	}
	var ctr Counters
	c := newConn(t, listen4(t), 32, &ctr)
	if c.Mode() != ModeBatch {
		t.Fatalf("mode %v; want batch", c.Mode())
	}
	ms := msgs(addrOf(listen4(t)), 0, 32) // the receiver never reads: the kernel drops what does not fit
	b := NewBatch(32)
	send := func() {
		if n, err := c.WriteBatch(b, ms); n != len(ms) || err != nil {
			t.Fatalf("WriteBatch: %d, %v", n, err)
		}
	}
	send()
	runs := allocDatagrams / len(ms)
	a := testing.AllocsPerRun(runs, send)
	if sc, s, _, _, _ := ctr.Load(); s != uint64((runs+2)*len(ms)) || sc < uint64(runs+2) {
		t.Fatalf("%s after %d writes of %d", counters(&ctr), runs+2, len(ms))
	}
	if !raceEnabled && a != 0 {
		t.Fatalf("%v allocations per batched write of %d datagrams", a, len(ms))
	}
}

// TestBatchRecvZeroAllocs_L54: batched reads — a Conn's ReadBatch with a
// Batch (the passive Source's reader) and a Reader holding its extras
// (the dialer's reader) — allocate nothing in steady state, the source
// address decoded without allocation, over 10,000 datagrams each.
func TestBatchRecvZeroAllocs_L54(t *testing.T) {
	seams(t)
	if !accelerated {
		forceBatch(t, newProbe(syscall.EBADF, syscall.EBADF))
		sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) { return n, nil }
		recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) {
			for i := range n {
				b.ms[i].N = 1
			}
			return n, nil
		}
	}
	rxu, txu := listen4(t), listen4(t)
	var ctr Counters
	rx := newConn(t, rxu, 32, &ctr)
	tx := newConn(t, txu, 32, nil)
	if rx.Mode() != ModeBatch || tx.Mode() != ModeBatch {
		t.Fatalf("modes %v %v; want batch", rx.Mode(), tx.Mode())
	}
	rxu.SetReadDeadline(time.Now().Add(time.Minute)) // a lost datagram fails, never hangs
	out := msgs(addrOf(rxu), 0, 32)
	wb, rb := NewBatch(32), NewBatch(32)
	rs := slots(32, 64)
	r := NewReader(rx, func(*Batch) {})
	if _, ok := r.Hold(NewBatch(32)); !ok {
		t.Fatal("Hold refused")
	}
	src := addrOf(txu)
	for _, reader := range []struct {
		name string
		read func() (int, error)
	}{
		{"Conn", func() (int, error) { return rx.ReadBatch(rb, rs) }},
		{"Reader", func() (int, error) { return r.ReadBatch(rs) }},
	} {
		round := func() {
			if n, err := tx.WriteBatch(wb, out); n != len(out) || err != nil {
				t.Fatalf("WriteBatch: %d, %v", n, err)
			}
			for got := 0; got < len(out); {
				n, err := reader.read()
				if err != nil {
					t.Fatalf("%s.ReadBatch after %d: %v", reader.name, got, err)
				}
				if accelerated && rs[0].Addr != src {
					t.Fatalf("%s: source %v; want %v", reader.name, rs[0].Addr, src)
				}
				got += n
			}
		}
		round()
		_, _, rc0, rd0, _ := ctr.Load()
		a := testing.AllocsPerRun(allocDatagrams/len(out), round)
		_, _, rc1, rd1, _ := ctr.Load()
		if rd1-rd0 != uint64((allocDatagrams/len(out)+1)*len(out)) || rc1-rc0 > rd1-rd0 {
			t.Fatalf("%s: %d receive calls for %d datagrams", reader.name, rc1-rc0, rd1-rd0)
		}
		t.Logf("%s: %d receive calls for %d datagrams", reader.name, rc1-rc0, rd1-rd0)
		if !raceEnabled && a != 0 {
			t.Fatalf("%s: %v allocations per round of %d datagrams", reader.name, a, len(out))
		}
	}
}
