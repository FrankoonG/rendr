package carrier

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestOwnedUDPUnboundCounted (R1-2 rule 1, M5 design R3-31): a dialer
// token's single calls before it binds its Conn — the datagram handshake,
// and every call if the bind failed — are counted in the Runtime's
// DgramStats.IO once count(env) ran, as a Conn counts its own: a write
// that sent its datagram is one send call of one datagram; a read that
// returned a datagram (ReadDatagram, and readDepth without the batched
// I/O) is one receive call of one datagram; a read that ended at the
// deadline counts nothing. The calls keep the plain path's errors and
// allocate nothing. A token that never ran count counts nothing. Real
// loopback sockets, every OS. Mutants: the unbound write, read or
// readDepth uncounted; a deadline counted.
func TestOwnedUDPUnboundCounted(t *testing.T) {
	raw, _ := wp5Listen(t, "udp4")
	defer raw.Close()
	du, _ := wp5Listen(t, "udp4")
	o := NewOwnedUDP(du, wp5AP(raw), wp5Flow, wp5MaxDatagram)
	defer o.Close()
	env := dgEnv()
	load := func() [4]uint64 {
		sc, sent, rc, recvd, _ := env.Dgram.IO.Load()
		return [4]uint64{sc, sent, rc, recvd}
	}

	// Not counted before count(env) (a token outside a dial).
	b := make([]byte, wire.FlowHeaderLen+4)
	if err := o.WriteDatagram(b); err != nil {
		t.Fatal(err)
	}
	if got := load(); got != [4]uint64{} {
		t.Fatalf("counters %v before count, want all 0", got)
	}

	o.count(env)
	for range 3 {
		if err := o.WriteDatagram(b); err != nil {
			t.Fatal(err)
		}
	}
	if o.bat.Load() != nil {
		t.Fatal("stimulus: the token bound")
	}
	if got := load(); got != [4]uint64{3, 3, 0, 0} {
		t.Fatalf("counters %v after 3 unbound writes, want send 3/3", got)
	}
	if n := testing.AllocsPerRun(20, func() { _ = o.WriteDatagram(b) }); n != 0 {
		t.Fatalf("an unbound counted write allocates %.1f times", n)
	}
	sc0 := load()[0]

	// Reads: the peer answers with datagrams of the flow.
	for range 2 {
		d := append(wp5Header(wp5Flow), 1, 2, 3)
		if _, err := raw.WriteToUDPAddrPort(d, wp5AP(du)); err != nil {
			t.Fatal(err)
		}
	}
	_ = o.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, o.ReadSize())
	if data, _, ev, err := o.ReadDatagram(buf); err != nil || ev != ReadOK || len(data) != 3 {
		t.Fatalf("ReadDatagram: %d bytes, event %d, %v", len(data), ev, err)
	}
	slot := &Buf{B: make([]byte, o.ReadSize())}
	if n, _, err := o.readDepth(slot, nil); err != nil || n != 1 {
		t.Fatalf("readDepth unbound: %d, %v", n, err)
	}
	if data, _, ev := o.result(0); ev != ReadOK || len(data) != 3 {
		t.Fatalf("readDepth's datagram: %d bytes, event %d", len(data), ev)
	}
	if got := load(); got != [4]uint64{sc0, sc0, 2, 2} {
		t.Fatalf("counters %v after 2 unbound reads, want recv 2/2", got)
	}
	_ = o.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, _, _, err := o.ReadDatagram(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("an empty socket: %v, want the deadline", err)
	}
	if got := load(); got != [4]uint64{sc0, sc0, 2, 2} {
		t.Fatalf("counters %v after a read that timed out, want unchanged", got)
	}
}
