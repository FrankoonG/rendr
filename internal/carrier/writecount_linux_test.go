//go:build linux && (amd64 || arm64)

package carrier

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
)

// TestDgramUnsentNotReturnedOnSendmmsgCount_L42 (L42, L39; A3 of M5's
// second review wave; Linux amd64/arm64, where rendr's own sockets batch):
// a dialer carrier over rendr's own loopback socket (OwnedUDP, MaxBatch 32)
// toward a raw receiver writes a round of 40 DGRAMs. The sendmmsg of the
// round's first call, given 32 datagrams, reports 33
// (udpsocket.SetSendCount: the kernel sent the 32); udpsocket returns
// ErrInvalidCount for the call and the carrier dies with transport_error.
// None of the 32 goes back to the session (DgramReturner) — the receiver
// reads every one of them, so one handed back would be sent twice — while
// the 8 of the round's second call, which no call was given, do; no DGRAM
// both reaches the receiver and goes back. Mutant: dgOutcome without the
// identity (all 40 go back, 32 of them already received).
func TestDgramUnsentNotReturnedOnSendmmsgCount_L42(t *testing.T) {
	defer g10NoLeak(t)()
	const size, total, first = 100, 40, 32
	raw, _ := wp5Listen(t, "udp4")
	defer raw.Close()
	if err := raw.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
	du, _ := wp5Listen(t, "udp4")
	o := NewOwnedUDPBatch(du, wp5AP(raw), wp5Flow, wp5MaxDatagram, first)
	env := wp2Env()
	c := dgConn(env, o, 1200, true)
	u := &uEP{}
	bud := NewBudget(1 << 30)
	chunk := NewBufPool().Get(ChunkSize, bud)
	var n atomic.Int32
	var seq atomic.Uint64
	u.setFill(chunkFill(&n, &seq, chunk, size))
	var armed, lied atomic.Bool
	var given atomic.Int32
	restore := udpsocket.SetSendCount(func(cnt, want int) int {
		if armed.Load() && lied.CompareAndSwap(false, true) {
			given.Store(int32(want))
			return want + 1
		}
		return cnt
	})
	defer restore()
	c.Start(u, &hBell{}, StartOptions{})
	defer func() {
		c.Kill(CauseLocalClose, "test end")
		<-c.Done()
	}()

	// received reads the raw receiver until wait passes without a datagram
	// and returns the DGRAM seqs it read, in order.
	buf := make([]byte, 2048)
	received := func(wait time.Duration) []uint64 {
		var out []uint64
		for {
			if err := raw.SetReadDeadline(time.Now().Add(wait)); err != nil {
				t.Fatal(err)
			}
			k, err := raw.Read(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return out
			}
			if err != nil {
				t.Fatalf("raw read: %v", err)
			}
			if k < 9 || !bytes.Equal(buf[:9], wp5Header(wp5Flow)) {
				t.Fatal("a datagram without the flow's header")
			}
			out = append(out, dgramSeqsOf(buf[9:k])...)
		}
	}
	if got := received(200 * time.Millisecond); len(got) != 0 {
		t.Fatalf("DGRAMs %v before the round", got)
	}
	armed.Store(true)
	n.Store(total)
	c.Wake()
	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the carrier did not end on the invalid count")
	}
	if !lied.Load() || given.Load() != first {
		t.Fatalf("stimulus: misreported %v, the call was given %d datagrams; want a sendmmsg of %d misreported", lied.Load(), given.Load(), first)
	}
	if _, cause, detail, _ := c.Death(); cause != CauseTransportError || !strings.Contains(detail, udpsocket.ErrInvalidCount.Error()) {
		t.Fatalf("death %v %q, want transport_error on the invalid count", cause, detail)
	}
	got := received(500 * time.Millisecond)
	var back []uint64
	for _, r := range u.returned() {
		if !r.byRef || r.n != size {
			t.Fatalf("returned %+v, want %d bytes with a reference", r, size)
		}
		back = append(back, r.seq)
	}
	if !slices.Equal(got, upTo(first)) {
		t.Fatalf("the receiver read DGRAMs %v, want 0 … %d once each (the misreporting sendmmsg sent them)", got, first-1)
	}
	if want := seqRange(first, total); !slices.Equal(back, want) {
		t.Fatalf("returned %v, want %v: none of the misreporting call's datagrams, every one after it, in order", back, want)
	}
	if r := chunk.refs.Load(); r != 1 {
		t.Fatalf("the chunk holds %d references after the carrier ended, want the test's 1", r)
	}
	chunk.Release()
	if used := bud.Used(); used != 0 {
		t.Fatalf("budget %d after the last release", used)
	}
}
