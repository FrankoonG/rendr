package udpflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// concPayload is datagram j of round r of flow i in
// TestSourceWriteBatchConcurrentFlows: the flow index (2 bytes), r, j and
// a fill of a length that differs per datagram.
func concPayload(i, r, j int) []byte {
	b := make([]byte, wire.FlowHeaderLen+4+(i*31+r*7+j*13)%150)
	p := b[wire.FlowHeaderLen:]
	binary.BigEndian.PutUint16(p, uint16(i))
	p[2], p[3] = byte(r), byte(j)
	for k := 4; k < len(p); k++ {
		p[k] = byte(i + r + j + k)
	}
	return b
}

// TestSourceWriteBatchConcurrentFlows (§A4.5, R1-14; run under -race too):
// 64 flows of one real socket write batches of 8 concurrently. Every
// datagram reaches the client exactly once and whole — none split, merged
// or carrying another flow's header — and the Runtime's counters equal the
// datagrams written; a socket that does not batch makes one call per
// datagram.
func TestSourceWriteBatchConcurrentFlows(t *testing.T) {
	env := testEnv(1 << 30)
	rs := newRealSourceIO(t, 1232, env, Limits{PerSource: 64}, defaultMaxBatch)
	rs.start()
	if err := rs.cl.SetReadBuffer(8 << 20); err != nil {
		t.Fatal(err)
	}
	const flows, rounds, per = 64, 4, 8
	const total = flows * rounds * per
	fs := make([]*Flow, flows)
	idx := make(map[uint64]int, flows)
	for i := range flows {
		id := uint64(0x1000 + i)
		rs.send(h1(id, wire.TypeOpen, uint32(i+1)))
		f := rs.flow()
		if f.ID() != id {
			t.Fatalf("flow %x admitted, want %x", f.ID(), id)
		}
		readOne(t, f, realWait)
		f.Admitted()
		fs[i], idx[id] = f, i
	}

	done := make(chan error, 1)
	go func() {
		seen := make([]bool, total)
		buf := make([]byte, 2048)
		for range total {
			if err := rs.cl.SetReadDeadline(time.Now().Add(realWait)); err != nil {
				done <- err
				return
			}
			n, from, err := rs.cl.ReadFromUDPAddrPort(buf)
			if err != nil {
				done <- err
				return
			}
			id, rest, err := wire.ParseFlowHeader(buf[:n])
			i, ok := idx[id]
			if err != nil || !ok || len(rest) < 4 || from != rs.dst {
				done <- fmt.Errorf("a datagram of %d bytes from %v: flow %x (%v)", n, from, id, err)
				return
			}
			r, j := int(rest[2]), int(rest[3])
			want := concPayload(i, r, j)
			if int(binary.BigEndian.Uint16(rest)) != i || r >= rounds || j >= per || !bytes.Equal(buf[:n], append(fs[i].hdr[:], want[wire.FlowHeaderLen:]...)) {
				done <- fmt.Errorf("flow %d: datagram (%d, %d) of %d bytes is not the one written", i, r, j, n)
				return
			}
			k := (i*rounds+r)*per + j
			if seen[k] {
				done <- fmt.Errorf("flow %d: datagram (%d, %d) arrived twice", i, r, j)
				return
			}
			seen[k] = true
		}
		done <- nil
	}()

	var wg sync.WaitGroup
	errs := make(chan error, flows)
	for i, f := range fs {
		wg.Go(func() {
			for r := range rounds {
				ds := make([][]byte, per)
				for j := range ds {
					ds[j] = concPayload(i, r, j)
				}
				if n, err := f.WriteDatagrams(ds); n != per || err != nil {
					errs <- fmt.Errorf("flow %d round %d: WriteDatagrams %d, %v", i, r, n, err)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	calls, sent, _, _, _ := env.Dgram.IO.Load()
	if sent != total || calls == 0 || calls > sent {
		t.Fatalf("SendCalls %d, SentDatagrams %d; want %d datagrams in at most as many calls", calls, sent, total)
	}
	if rs.s.bio.Mode() != udpsocket.ModeBatch && calls != sent {
		t.Fatalf("a socket that does not batch: %d calls for %d datagrams", calls, sent)
	}
}

// loopSock is an allocation-free sockIO for the step gate: every read
// returns the same datagrams, every write succeeds.
type loopSock struct {
	max  int
	ds   [][]byte
	from netip.AddrPort
}

func (c *loopSock) ReadBatch(_ *udpsocket.Batch, ms []udpsocket.Msg) (int, error) {
	n := min(len(ms), len(c.ds))
	for i := range n {
		m := &ms[i]
		m.N = copy(m.Buf, c.ds[i])
		m.Trunc, m.Addr = m.N == len(m.Buf), c.from
	}
	return n, nil
}

func (c *loopSock) WriteBatch(_ *udpsocket.Batch, ms []udpsocket.Msg) (int, error) {
	return len(ms), nil
}

// newReader implements readerIO: a loopReader.
func (c *loopSock) newReader(release func(*udpsocket.Batch)) srcReader {
	r := &loopReader{c: c}
	r.release = release
	return r
}

// loopReader is loopSock's srcReader: udpsocket.Reader's word (fakeWord)
// over a socket that always has datagrams, so a read never waits —
// allocation-free. releaseNext (the reader goroutine's) makes the next
// read holding its extras wait a whole period first: it parks, and the
// idle release takes the parked extras (TryRelease) before the read
// callback runs again.
type loopReader struct {
	fakeWord
	c           *loopSock
	releaseNext bool
}

// ReadBatch reads up to len(ms) datagrams while the reader holds (or takes
// back) its extras, else one, into ms[0].
func (r *loopReader) ReadBatch(ms []udpsocket.Msg) (int, error) {
	if r.releaseNext && r.Held() {
		r.releaseNext = false
		r.park()
		r.TryRelease(r.Parks())
	}
	if !r.unpark() {
		ms = ms[:1]
	}
	return r.c.ReadBatch(nil, ms)
}

func (c *loopSock) Mode() udpsocket.Mode                   { return udpsocket.ModeBatch }
func (c *loopSock) MaxBatch() int                          { return c.max }
func (c *loopSock) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *loopSock) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (c *loopSock) Close() error                           { return nil }
func (c *loopSock) LocalAddr() net.Addr                    { return udpAddr(1, 4000) }
func (c *loopSock) SetDeadline(time.Time) error            { return nil }
func (c *loopSock) SetReadDeadline(time.Time) error        { return nil }
func (c *loopSock) SetWriteDeadline(time.Time) error       { return nil }

// TestSourceBatchStepZeroAllocs_L54 (§A10.3, the seam half of
// TestSourceBatchZeroAllocs_L54_L58; every OS): one batched read of 32
// datagrams of a known flow — the slots refilled, each datagram routed into
// the inbox without a copy, the one wake — then the flow's ReadDatagrams
// and Release, and a WriteDatagrams of 8, allocate nothing in steady
// state; afterwards nothing stays charged.
func TestSourceBatchStepZeroAllocs_L54(t *testing.T) {
	env := testEnv(1 << 30)
	c := &loopSock{max: 32, from: apOf(2, 1000)}
	s := newSeamSource(env, c, c, seamDgram, Limits{})
	var f *Flow
	r := &reader{s: s, admit: func(g *Flow) { f = g }}
	r.startDepth() // as loopOwned: the reads go through the reader's word
	s.route(r, h1(1, wire.TypeOpen, 1), c.from, nil, false)
	if f == nil {
		t.Fatal("no flow admitted")
	}
	f.Admitted()
	readOne(t, f, time.Second)
	for i := range 32 {
		c.ds = append(c.ds, dg(1, pingFrame(uint32(2+i))))
	}
	rs := make([]carrier.ReadResult, 32)
	ds := make([][]byte, 8)
	for i := range ds {
		ds[i] = make([]byte, wire.FlowHeaderLen+40)
	}
	step := func() {
		if !r.readOwned() {
			t.Fatal("the read failed")
		}
		if n, err := f.ReadDatagrams(rs); n != 32 || err != nil {
			t.Fatalf("ReadDatagrams: %d, %v", n, err)
		}
		f.Release()
		if n, err := f.WriteDatagrams(ds); n != len(ds) || err != nil {
			t.Fatalf("WriteDatagrams: %d, %v", n, err)
		}
	}
	runtime.GC()
	for range 50 {
		step()
	}
	if a := testing.AllocsPerRun(1000, step); a != 0 && !raceEnabled {
		t.Fatalf("%v allocations per read of 32 datagrams", a)
	}
	f.Close()
	r.exit()
	<-s.Done()
	if u := buffered(env); u != 0 {
		t.Fatalf("%d bytes buffered after the end", u)
	}
}
