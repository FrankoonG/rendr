package carrier

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Real-loopback tests (outside synctest bubbles, real time): the OwnedTCP
// write path and the carrier half of the steady-state allocation gate.
// Each is a leak oracle (L52, L66; design §0.14 B11): it takes a goroutine
// (and, on Linux, fd) baseline first and checks it once its carriers, the
// peer and both sockets are closed (g10NoLeak).

// g10NoLeak takes rendrtest.AssertNoLeak's baseline and returns its check,
// to be deferred first so that it runs after every other deferred close.
// The check is skipped once the test failed: a failed test may leave its
// goroutines behind, and its failure is the report.
func g10NoLeak(t *testing.T) func() {
	t.Helper()
	check := rendrtest.AssertNoLeak(t)
	return func() {
		if !t.Failed() {
			check()
		}
	}
}

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
	defer g10NoLeak(t)()
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
// reference one chunk, and takes received DATA like a session (a big
// payload's Buf is released, a small one is not retained), allocating
// nothing.
type allocEP struct {
	chunk *Buf
	ack   wire.Ack
	off   uint64
	rx    struct{ big, small int }
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

func (e *allocEP) Data(_ *Conn, _ uint64, _ []byte, buf *Buf) error {
	if buf != nil {
		e.rx.big++
		buf.Release()
	} else {
		e.rx.small++
	}
	return nil
}
func (e *allocEP) Control(*Conn, wire.Header, []byte) error { return nil }
func (e *allocEP) WriteBlocked(*Conn)                       {}

// TestCarrierRoundZeroAllocs_L41_L54 is the carrier half of design §12.2's
// allocation gate, over an OwnedTCP loopback pair. Writer: one round —
// carrier control with a PING and a PONG, Fill, seal, stall window and
// watchdog, the per-batch write deadline and one vectored write of an ACK
// and 256 KiB of DATA — allocates nothing. Reader: one group of frames — a
// 64 KiB DATA read straight into a pooled Buf and handed over by reference,
// a 1000-byte DATA, a PING and a PONG matching a committed PING record —
// allocates nothing. Both carriers feed a self-load gauge as a dialer
// session carrier of a multi-factory Peer does (§8.2: in-flight, backlog and
// the volume counters of every batch and DATA frame). The counts are
// asserted in the non-race lane only (the race detector instruments
// allocations and makes sync.Pool drop items).
// The §11.4 name TestSteadyStateZeroAllocs_L41_L54 is left to the
// end-to-end gate (session Write → Read over lanes on real carriers), so
// the name-based coverage gate (W17) cannot pass on a half.
func TestCarrierRoundZeroAllocs_L41_L54(t *testing.T) {
	t.Run("writer", func(t *testing.T) {
		defer g10NoLeak(t)()
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
		g := NewGauge()
		c.opts.Gauge, c.st.gauge = g, g
		c.writerInit()
		round := func() {
			// Every round also carries a PING (requested, the records of
			// earlier rounds answered) and a PONG for the peer's latest PING.
			c.mu.Lock()
			c.st.head, c.st.n = 0, 0
			c.st.pingReq = true
			c.st.pong, c.st.pongDue = wire.Ping{ID: 9, Nonce: 99}, true
			c.mu.Unlock()
			if !c.writeRound(&c.wr) {
				_, cause, detail, _ := c.Death()
				t.Fatalf("writer round ended the carrier: %v %s", cause, detail)
			}
			if !c.wr.ping {
				t.Fatal("a round without its PING")
			}
		}
		for range 20 { // warm up: the poller's deadline timer, the iovec pool
			round()
		}
		allocs := testing.AllocsPerRun(100, round)
		st := c.Stats()
		c.Kill(CauseLocalClose, "test end")
		<-c.Done()
		if st.Frames < 121*7 || c.wr.vectored < 121 {
			t.Fatalf("%d frames in %d vectored writes, want 7 per round", st.Frames, c.wr.vectored)
		}
		if tx := g.read(0).tx; tx != st.TxBytes || tx < 121*256<<10 {
			t.Fatalf("gauge counted %d DATA bytes written, carrier %d", tx, st.TxBytes)
		}
		if carrierRace {
			t.Logf("race lane: %v allocations per round (not asserted)", allocs)
			return
		}
		if allocs != 0 {
			t.Fatalf("%v allocations per writer round", allocs)
		}
	})
	t.Run("reader", func(t *testing.T) {
		defer g10NoLeak(t)()
		env := hEnv()
		cl, sv := tcpPair(t)
		defer sv.Close()
		c := hConn(env, NewOwnedTCP(cl))
		ep := &allocEP{}
		c.ep = ep
		g := NewGauge()
		c.opts.Gauge, c.st.gauge = g, g
		c.rd.stage = env.Bufs.Get(BigData, env.Budget)
		const groups = 20 + 1 + 100
		var stream []byte
		fseq := env.Presets.firstFseq()
		frame := func(t wire.Type, handle uint32, payload []byte) {
			stream = wire.AppendFrame(stream, wire.Header{Type: t, Fseq: fseq, Handle: handle}, payload)
			fseq++
		}
		var off uint64
		for i := range uint32(groups) {
			frame(wire.TypeData, wire.SessionHandle, dataPayload(off, ChunkSize))
			off += ChunkSize
			frame(wire.TypeData, wire.SessionHandle, dataPayload(off, 1000))
			off += 1000
			frame(wire.TypePing, 0, pingPayload(wire.Ping{ID: i}))
			frame(wire.TypePong, 0, pingPayload(wire.Ping{ID: i + 1, Nonce: c.salt ^ uint64(i+1)}))
		}
		written := make(chan error, 1)
		go func() { _, err := sv.Write(stream); written <- err }()
		var id uint32
		group := func() {
			id++ // the PING record this group's PONG answers, committed just now
			c.mu.Lock()
			c.st.push(pingRecord{id: id, nonce: c.salt ^ uint64(id), committedAt: time.Now()})
			c.mu.Unlock()
			for range 4 {
				if !c.readFrame(&c.rd) {
					_, cause, detail, _ := c.Death()
					t.Fatalf("the reader stopped: %v %s", cause, detail)
				}
			}
		}
		for range 20 { // warm up: the receive-buffer class pool
			group()
		}
		allocs := testing.AllocsPerRun(100, group)
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		records, sampled := c.st.n, c.st.rttSeen
		c.mu.Unlock()
		if ep.rx.big != groups || ep.rx.small != groups || records != 0 || !sampled || c.Stats().RxBytes != off {
			t.Fatalf("delivered %d big and %d small payloads (%d bytes), %d PING records left (RTT sampled %v)", ep.rx.big, ep.rx.small, c.Stats().RxBytes, records, sampled)
		}
		if rx := g.read(0).rx; rx != off {
			t.Fatalf("gauge counted %d DATA bytes received, want %d", rx, off)
		}
		c.rd.stage.Release()
		c.Kill(CauseLocalClose, "test end")
		<-c.Done()
		if env.Budget.Used() != 0 {
			t.Fatalf("budget %d after every buffer was released", env.Budget.Used())
		}
		if carrierRace {
			t.Logf("race lane: %v allocations per group (not asserted)", allocs)
			return
		}
		if allocs != 0 {
			t.Fatalf("%v allocations per group of received frames", allocs)
		}
	})
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
