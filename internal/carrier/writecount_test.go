package carrier

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// An invalid write count (L42) on the datagram writer (A3 of M5's second
// review wave): a transport that misreported a write's count may have sent
// the datagrams of that call, so the writer hands none of them back to
// their session (DgramReturner) — one handed back would be sent twice —
// while the round's datagrams after that call, which no call was given,
// go back as after any fatal write. Every adapter reports such a count as
// an error of one identity (ErrWriteCount, or udpsocket.ErrInvalidCount
// from the batch calls).

// TestWriteCountIdentity_L42: every invalid write count the datagram
// transports report is one identity for the writer (isWriteCount): the
// embedder adapter's (*countError of a Write or WriteTo), rendr's own
// sockets' (udpWriteResult and the PacketConn view of a dialer socket), a
// batched write's (errBatchCount) and the batch calls' own
// udpsocket.ErrInvalidCount, also wrapped; a read's count, noise, a size
// refusal and any other error are not. Mutants: countError without its Is
// method; errUDPWriteCount another error than ErrWriteCount.
func TestWriteCountIdentity_L42(t *testing.T) {
	counts := []struct {
		name string
		err  error
	}{
		{"embedder WriteTo (len+1, nil)", &countError{"WriteTo", 101, 100}},
		{"embedder WriteTo (0, nil)", &countError{"WriteTo", 0, 100}},
		{"embedder Write (-1, nil)", &countError{"Write", -1, 100}},
		{"own dialer socket", udpWriteResult(99, 100, nil, false)},
		{"own listening socket", udpWriteResult(101, 100, nil, true)},
		{"a dialer socket's PacketConn view", viewWriteResult(0, 100, nil)},
		{"a batched write's count", errBatchCount},
		{"sendmmsg", udpsocket.ErrInvalidCount},
		{"sendmmsg, wrapped", fmt.Errorf("write: %w", udpsocket.ErrInvalidCount)},
	}
	for _, c := range counts {
		if !isWriteCount(c.err) {
			t.Errorf("%s: %v is not an invalid write count to the writer", c.name, c.err)
		}
	}
	others := []struct {
		name string
		err  error
	}{
		{"embedder ReadFrom", &countError{"ReadFrom", 101, 100}},
		{"embedder Read", &countError{"Read", -1, 100}},
		{"noise", ErrNoise},
		{"too large", errUDPTooLarge},
		{"a transport error", errNotNoise},
		{"a closed socket", net.ErrClosed},
	}
	for _, c := range others {
		if isWriteCount(c.err) {
			t.Errorf("%s: %v taken for an invalid write count", c.name, c.err)
		}
	}
}

// cntPC is an embedder net.PacketConn over one end of the harness's link
// (f, a fakeIO): a read returns the end's next datagram from peer, a write
// is delivered to the other end and then reports the count lie returns for
// it — the true one, len(p), unless the conn misreports.
type cntPC struct {
	f    *fakeIO
	peer net.Addr
	lie  func(p []byte, n int) int
}

func (c *cntPC) ReadFrom(p []byte) (int, net.Addr, error) {
	data, _, ev, err := c.f.ReadDatagram(p)
	switch {
	case err != nil:
		return 0, nil, err
	case ev != ReadOK:
		return 0, nil, fmt.Errorf("cntPC: read event %d", ev)
	}
	return len(data), c.peer, nil
}

func (c *cntPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.f.WriteDatagram(p); err != nil {
		return 0, err
	}
	return c.lie(p, len(p)), nil
}

func (c *cntPC) Close() error                      { return c.f.Close() }
func (c *cntPC) LocalAddr() net.Addr               { return net.UDPAddrFromAddrPort(c.f.addr.AP) }
func (c *cntPC) SetDeadline(t time.Time) error     { return c.f.SetDeadline(t) }
func (c *cntPC) SetReadDeadline(t time.Time) error { return c.f.SetReadDeadline(t) }
func (c *cntPC) SetWriteDeadline(time.Time) error  { return nil }

// dgramSeqsOf returns the session seqs of the DGRAMs in rendr bytes d.
func dgramSeqsOf(d []byte) []uint64 {
	var out []uint64
	fs, _ := dgDecode(d)
	for _, f := range fs {
		if f.Type == wire.TypeDgram {
			if s, _, err := wire.ParseDgram(f.Payload); err == nil {
				out = append(out, s)
			}
		}
	}
	return out
}

// pioBatch drives the embedder adapter (packetIO) through the writer's
// batched path in the harness's batched settings (MaxBatch 32 and 1), as
// fakeBatch drives fakeIO: a WriteDatagrams call writes each datagram with
// the adapter's WriteDatagram, stopping at the first error — the adapter's
// own, a *countError for an invalid count — and records the DGRAM seqs it
// was given; a read moves one datagram.
type pioBatch struct {
	*packetIO
	max   int
	mu    sync.Mutex
	calls [][]uint64
}

func (p *pioBatch) MaxBatch() int { return p.max }

func (p *pioBatch) WriteDatagrams(ds [][]byte) (int, error) {
	var seqs []uint64
	for _, d := range ds {
		seqs = append(seqs, dgramSeqsOf(d)...)
	}
	p.mu.Lock()
	p.calls = append(p.calls, seqs)
	p.mu.Unlock()
	for i, d := range ds {
		if err := p.WriteDatagram(d); err != nil {
			return i, err
		}
	}
	return len(ds), nil
}

func (p *pioBatch) ReadDatagrams(rs []ReadResult) (int, error) {
	data, src, ev, err := p.ReadDatagram(rs[0].buf.B)
	if err != nil {
		return 0, err
	}
	rs[0].Data, rs[0].Src, rs[0].Ev = data, src, ev
	return 1, nil
}

// lastOfCall returns the last DGRAM seq of the WriteDatagrams call that
// was given seq m (false: none was).
func (p *pioBatch) lastOfCall(m uint64) (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.calls {
		if slices.Contains(c, m) {
			return c[len(c)-1], true
		}
	}
	return 0, false
}

// seqRange returns from … to−1.
func seqRange(from, to uint64) []uint64 {
	var out []uint64
	for s := from; s < to; s++ {
		out = append(out, s)
	}
	return out
}

// TestDgramUnsentNotReturnedOnAdapterCount_L42 (L42, L39; M5 pktloss as A3
// of the second review wave corrects it): a dialer carrier over the
// embedder adapter (NewPacketIO), whose conn delivers every datagram and
// reports (len+1, nil) — or (0, nil) — for the one that carries DGRAM 4 of
// a round of 40. The adapter reports the count as an error of its own
// (*countError); the carrier dies with transport_error. Which of the
// datagrams of the call that carried DGRAM 4 left is unknown — here
// DGRAM 4 did — so none of them goes back to the session (DgramReturner):
// handed back, DGRAM 4 would be sent twice. The datagrams after that call,
// which no call was given, do go back, in order, each with a reference of
// its own; DGRAMs 0 … 4 reach the peer once; nothing reaches the peer and
// goes back as well. In the harness's three settings: off — one
// WriteDatagram per datagram, so DGRAMs 5 … 39 go back; MaxBatch 1 — the
// batched path, one datagram per call, the same; MaxBatch 32 — a call of
// 32 carried DGRAM 4, so only the 8 of the round's second call go back.
// Mutants: dgOutcome without the identity (DGRAM 4 handed back);
// countError without its Is method.
func TestDgramUnsentNotReturnedOnAdapterCount_L42(t *testing.T) {
	for _, lie := range []struct {
		name  string
		count func(n int) int
	}{
		{"len+1", func(n int) int { return n + 1 }},
		{"zero", func(int) int { return 0 }},
	} {
		t.Run(lie.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const size, total, m = 100, 40, 4
				ia, ib := newFakeIOPair(t, 1200)
				aenv, benv := dgEnv(), dgEnv()
				var lied atomic.Int32
				pc := &cntPC{f: ia, peer: net.UDPAddrFromAddrPort(ib.addr.AP), lie: func(p []byte, n int) int {
					if slices.Contains(dgramSeqsOf(p), m) && lied.Add(1) == 1 {
						return lie.count(n)
					}
					return n
				}}
				pio, err := newPacketIO(aenv, pc, pc.peer, 1200)
				if err != nil {
					t.Fatal(err)
				}
				var pb *pioBatch
				if mb := int(dgTestMaxBatch.Load()); mb > 0 {
					pb = &pioBatch{packetIO: pio, max: mb}
					prev := dgBatchOf
					dgBatchOf = func(io PacketIO) BatchIO {
						if io == PacketIO(pio) {
							return pb
						}
						return prev(io)
					}
					t.Cleanup(func() { dgBatchOf = prev })
				}
				a := dgConn(aenv, pio, 1200, true)
				b := dgConn(benv, ib, 1200, false)
				bep := &dEP{}
				t.Cleanup(func() {
					for _, c := range []*Conn{a, b} {
						c.Kill(CauseLocalClose, "test cleanup")
						<-c.Done()
					}
				})
				u := &uEP{}
				bud := NewBudget(1 << 30)
				chunk := NewBufPool().Get(ChunkSize, bud)
				var n atomic.Int32
				var seq atomic.Uint64
				u.setFill(chunkFill(&n, &seq, chunk, size))
				a.Start(u, &hBell{}, StartOptions{})
				b.Start(bep, &hBell{}, StartOptions{})
				synctest.Wait()
				n.Store(total)
				a.Wake()
				hWait(t, a)
				synctest.Wait()

				if lied.Load() != 1 {
					t.Fatalf("stimulus: the conn misreported %d writes of DGRAM %d, want 1", lied.Load(), m)
				}
				if _, cause, detail, _ := a.Death(); cause != CauseTransportError || !strings.Contains(detail, "invalid count") {
					t.Fatalf("death %v %q, want transport_error on the invalid count", cause, detail)
				}
				last := uint64(m) // the last DGRAM of the call that carried DGRAM m
				if pb != nil {
					var ok bool
					if last, ok = pb.lastOfCall(m); !ok {
						t.Fatalf("no WriteDatagrams call was given DGRAM %d (calls %v)", m, pb.calls)
					}
				}
				if last+1 >= total {
					t.Fatalf("stimulus: the call that carried DGRAM %d ended the round (last DGRAM %d of %d): no later datagram to hand back", m, last, total)
				}
				got := seqsOf(bep)
				var back []uint64
				for _, r := range u.returned() {
					if !r.byRef || r.n != size {
						t.Fatalf("returned %+v, want %d bytes with a reference", r, size)
					}
					back = append(back, r.seq)
				}
				if slices.Contains(back, m) {
					t.Fatalf("DGRAM %d, which the conn sent and misreported, went back to the session (it would be sent twice): returned %v", m, back)
				}
				if !slices.Equal(got, upTo(m+1)) {
					t.Fatalf("delivered %v, want 0 … %d once each (DGRAM %d left before its count was misreported)", got, m, m)
				}
				if want := seqRange(last+1, total); !slices.Equal(back, want) {
					t.Fatalf("returned %v, want %v: the round's datagrams after the misreporting call (its last DGRAM %d), in order", back, want, last)
				}
				for _, s := range back {
					if slices.Contains(got, s) {
						t.Fatalf("DGRAM %d both reached the peer and went back", s)
					}
				}
				if r := chunk.refs.Load(); r != 1 {
					t.Fatalf("the chunk holds %d references after the carrier ended, want the test's 1", r)
				}
				chunk.Release()
				if used := bud.Used(); used != 0 {
					t.Fatalf("budget %d after the last release", used)
				}
			})
		})
	}
}

// TestDgramUnsentAfterBadBatchCount_L42 (L42, L39; A3 of the second review
// wave): a batched write whose count has a shape it cannot have — here a
// call of 8 that delivered all 8 and reported 7 without an error
// (errBatchCount) — ends the carrier; none of that call's datagrams goes
// back (they all left), and the round's 4 datagrams after it, which no
// call was given, go back in order instead of being lost uncounted. The
// peer's datagrams and the returned ones are disjoint and cover the
// round. (TestDgramUnsentNotReturnedOnBadCount_L42 is the round whose
// datagrams all lie in the misreporting call.) Mutant: errBatchCount
// handing nothing back.
func TestDgramUnsentAfterBadBatchCount_L42(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size, total, call = 100, 12, 8
		a, b, fa := wp2Pair(t, 1200, call)
		u := &uEP{}
		bud := NewBudget(1 << 30)
		chunk := NewBufPool().Get(ChunkSize, bud)
		var n atomic.Int32
		var seq atomic.Uint64
		u.setFill(chunkFill(&n, &seq, chunk, size))
		a.c.Start(u, a.bell, StartOptions{})
		b.start(StartOptions{})
		synctest.Wait()
		mark := len(fa.writeCalls())
		fa.setReport(func(k int) int { return k - 1 })
		n.Store(total)
		a.c.Wake()
		hWait(t, a.c)
		synctest.Wait()
		if calls := fa.writeCalls()[mark:]; !slices.Equal(calls, []int{call}) {
			t.Fatalf("stimulus: WriteDatagrams calls %v, want one of %d (then the carrier died)", calls, call)
		}
		if _, cause, detail, _ := a.c.Death(); cause != CauseTransportError || !strings.Contains(detail, "invalid count") {
			t.Fatalf("death %v %q, want transport_error on the count", cause, detail)
		}
		var back []uint64
		for _, r := range u.returned() {
			if !r.byRef || r.n != size {
				t.Fatalf("returned %+v, want %d bytes with a reference", r, size)
			}
			back = append(back, r.seq)
		}
		if got := seqsOf(b.ep); !slices.Equal(got, upTo(call)) {
			t.Fatalf("delivered %v, want the misreporting call's 0 … %d", got, call-1)
		}
		if want := seqRange(call, total); !slices.Equal(back, want) {
			t.Fatalf("returned %v, want %v: none of the misreporting call's datagrams, every later one", back, want)
		}
		if r := chunk.refs.Load(); r != 1 {
			t.Fatalf("the chunk holds %d references after the carrier ended, want the test's 1", r)
		}
		chunk.Release()
	})
}

var (
	_ net.PacketConn = (*cntPC)(nil)
	_ BatchIO        = (*pioBatch)(nil)
)
