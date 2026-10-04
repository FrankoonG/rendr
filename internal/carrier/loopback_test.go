package carrier

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Real-loopback tests (outside synctest bubbles, real time): the OwnedTCP
// write path and the carrier half of the steady-state allocation gate.

// tcpPair returns a connected pair of loopback TCP conns (127.0.0.1).
func tcpPair(t testing.TB) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			acc <- nil
			return
		}
		acc <- c
	}()
	client, err = net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server = <-acc
	if server == nil {
		t.Fatal("accept failed")
	}
	for _, c := range []*net.TCPConn{client, server} {
		c.SetNoDelay(true)
		c.SetKeepAlive(false)
	}
	return client, server
}

// waitFor polls cond in real time (outside bubbles only).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestVectoredWriteOnOwnedTCP_L41 (D3, P2): on rendr's own TCP socket (the
// OwnedTCP token) every batch goes out as one vectored write that
// references the send chunks — no coalescing copy — and the receiver
// parses an intact stream; a planned retirement ends with CloseWrite (an
// orderly FIN after our CLOSE, not a reset).
func TestVectoredWriteOnOwnedTCP_L41(t *testing.T) {
	env := hEnv()
	cl, sv := tcpPair(t)
	own := NewOwnedTCP(cl)
	c := hConn(env, own)
	if c.owned != own {
		t.Fatal("the OwnedTCP token was not recognized")
	}
	p := startPeer(sv, env.Presets.firstFseq())
	defer p.close()
	p.keep()
	p.autoPong(nil)
	src := newSource(env, ChunkSize, false)
	defer src.chunk.Release()
	const total = 8 << 20
	src.offer(total)
	c.Start(src, &hBell{}, StartOptions{})
	waitFor(t, "the transfer", func() bool { return p.dataBytes() == total })
	c.Retire(wire.CloseRetire)
	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("retirement did not finish")
	}
	<-p.done
	hCheckData(t, p, total)
	if dead, cause, detail, _ := c.Death(); !dead || cause != CauseRetired {
		t.Fatalf("death %v %v %s", dead, cause, detail)
	}
	if c.wr.vectored == 0 || c.wr.coalesced != 0 {
		t.Fatalf("write shapes on OwnedTCP: vectored %d coalesced %d", c.wr.vectored, c.wr.coalesced)
	}
	fr := p.received()
	if last := fr[len(fr)-1]; last.Type != wire.TypeClose {
		t.Fatalf("last frame %v, want CLOSE", last.Type)
	}
	if err := p.readErr(); !errors.Is(err, io.EOF) {
		t.Fatalf("the receiver ended with %v, want an orderly EOF", err)
	}
}

// allocEP fills every round with one ACK and four 64 KiB DATA frames that
// reference one chunk, allocating nothing.
type allocEP struct {
	chunk *Buf
	ack   wire.Ack
	off   uint64
}

func (e *allocEP) Handle() uint32 { return wire.SessionHandle }

func (e *allocEP) Fill(c *Conn, b *Batch) {
	e.ack.Delivered++
	b.AddAck(wire.SessionHandle, 0, &e.ack)
	for range 4 {
		if !b.AddData(wire.SessionHandle, e.off, e.chunk.B[:ChunkSize], e.chunk, false) {
			return
		}
		e.off += ChunkSize
	}
}

func (e *allocEP) Data(*Conn, uint64, []byte, *Buf) error   { return nil }
func (e *allocEP) Control(*Conn, wire.Header, []byte) error { return nil }
func (e *allocEP) WriteBlocked(*Conn)                       {}

// TestSteadyStateZeroAllocs_L41_L54 (carrier half, §12.2): one writer
// round — Fill, carrier control, seal, stall window and watchdog, the
// per-batch write deadline and one vectored write of 256 KiB of DATA over
// an OwnedTCP loopback pair — allocates nothing. The count is asserted in
// the non-race lane only (the race detector instruments allocations).
func TestSteadyStateZeroAllocs_L41_L54(t *testing.T) {
	env := hEnv()
	cl, sv := tcpPair(t)
	defer sv.Close()
	go func() { // the receiver discards everything (no allocation per read)
		buf := make([]byte, 1<<20)
		for {
			if _, err := sv.Read(buf); err != nil {
				return
			}
		}
	}()
	c := hConn(env, NewOwnedTCP(cl))
	ep := &allocEP{chunk: env.Bufs.Get(ChunkSize, nil)}
	defer ep.chunk.Release()
	c.ep = ep
	c.writerInit()
	round := func() {
		if !c.writeRound(&c.wr) {
			_, cause, detail, _ := c.Death()
			t.Fatalf("writer round ended the carrier: %v %s", cause, detail)
		}
	}
	for range 20 { // warm up: the first PING, the poller's deadline timer, the iovec pool
		round()
	}
	allocs := testing.AllocsPerRun(100, round)
	frames := c.Stats().Frames
	c.Kill(CauseLocalClose, "test end")
	<-c.Done()
	if frames < 120*5 || c.wr.vectored < 120 {
		t.Fatalf("%d frames in %d vectored writes", frames, c.wr.vectored)
	}
	if carrierRace {
		t.Logf("race lane: %v allocations per round (not asserted)", allocs)
		return
	}
	if allocs != 0 {
		t.Fatalf("%v allocations per writer round", allocs)
	}
}

// BenchmarkCarrierStream (perf lane, §12.4): one carrier writes DATA over
// an OwnedTCP loopback pair to a second carrier whose endpoint drops the
// payloads; the sender's Fill respects the capacity cap like a session's.
// It reports MB/s of DATA payload delivered end to end, PINGs and PONGs
// included.
func BenchmarkCarrierStream(b *testing.B) {
	env := hEnv()
	cl, sv := tcpPair(b)
	tx := hConn(env, NewOwnedTCP(cl))
	rx := hConn(env, NewOwnedTCP(sv))
	src := newSource(env, ChunkSize, true)
	defer src.chunk.Release()
	sink := &hEP{}
	rx.Start(sink, &hBell{}, StartOptions{})
	tx.Start(src, &hBell{}, StartOptions{})
	const step = 1 << 20
	b.SetBytes(step)
	b.ResetTimer()
	src.offer(uint64(b.N) * step)
	tx.Wake()
	for sink.rxBytes.Load() < int64(b.N)*step {
		time.Sleep(100 * time.Microsecond)
	}
	b.StopTimer()
	tx.Kill(CauseLocalClose, "bench end")
	<-tx.Done()
	<-rx.Done()
}
