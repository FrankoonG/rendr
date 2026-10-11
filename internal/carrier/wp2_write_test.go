package carrier

import (
	"bytes"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// M5 WP2 rows of the send path of a datagram carrier (M5 design §A4.3,
// §A4.8, §A8, §A10.1): the writer packs a round's datagrams into its arena
// and flushes them through the transport's BatchIO (here a fakeBatch over
// the harness's in-memory link: a WriteDatagrams call is one fake call, its
// datagrams delivered in order).

// wp2Pair returns a (dialer) writing and reading through a fakeBatch of
// max datagrams per call, and b (passive) over the harness's link.
func wp2Pair(t testing.TB, cmtu, max int) (a, b *dgSide, fa *fakeBatch) {
	a, b = dgPair(t, cmtu)
	fa = newFakeBatch(a.io, max)
	useBatch(t, fa)
	return a, b, fa
}

// burstFill returns a Fill that places DGRAMs of size(seq) bytes for the
// session seqs from *seq on while *n > 0 and the batch takes them;
// pack(seq), if set, places an unreliable PACK before each DGRAM.
func burstFill(n *atomic.Int32, seq *atomic.Uint64, size func(uint64) int, pack bool) func(c *Conn, b *Batch) {
	body := make([]byte, wire.MaxPacketPayload)
	for i := range body {
		body[i] = byte(i * 7)
	}
	return func(c *Conn, b *Batch) {
		for n.Load() > 0 {
			s := seq.Load()
			if pack && !b.AddPack(wire.SessionHandle, 0, &wire.Pack{HighestSeq: s, Received: s + 1}, false) {
				return
			}
			if !b.AddDgram(wire.SessionHandle, s, body[:size(s)], nil) {
				return
			}
			seq.Add(1)
			n.Add(-1)
		}
	}
}

// fixed returns a size function of n bytes.
func fixed(n int) func(uint64) int { return func(uint64) int { return n } }

// seqsOf returns the seqs an endpoint received, in order.
func seqsOf(e *dEP) []uint64 {
	var out []uint64
	for _, r := range e.datagrams() {
		out = append(out, r.seq)
	}
	return out
}

// upTo returns 0 … n−1.
func upTo(n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = uint64(i)
	}
	return out
}

// settle starts both carriers of a pair and lets the first PING exchange
// complete.
func settle(a, b *dgSide, oa StartOptions) {
	a.start(oa)
	b.start(StartOptions{})
	synctest.Wait()
}

// TestDgramWriterTakesBacklog_L55 (R1-7): the frames of 20 datagrams are
// queued before the writer wakes; it sends them in exactly ⌈20 / MaxBatch⌉
// WriteDatagrams calls (20 calls at MaxBatch 1), in order and complete.
// Mutant: a writer that flushes per datagram although a backlog is queued.
func TestDgramWriterTakesBacklog_L55(t *testing.T) {
	for _, max := range []int{1, 4, 32} {
		t.Run(itoa(max), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b, fa := wp2Pair(t, 1200, max)
				var n atomic.Int32
				var seq atomic.Uint64
				a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
				settle(a, b, StartOptions{})
				mark := len(fa.writeCalls())
				n.Store(20)
				a.c.Wake()
				synctest.Wait()
				calls := fa.writeCalls()[mark:]
				var want []int
				for left := 20; left > 0; left -= max {
					want = append(want, min(left, max))
				}
				if !slices.Equal(calls, want) {
					t.Fatalf("WriteDatagrams calls %v, want %v", calls, want)
				}
				if got := seqsOf(b.ep); !slices.Equal(got, upTo(20)) {
					t.Fatalf("delivered %v", got)
				}
			})
		})
	}
}

// TestDgramBatchNoWait_L55: a lone datagram leaves within the writer wake
// that found it — no waiting to fill a batch (L55): it is written at the
// instant of the wake, in a call of its own. Mutant: the writer waits 1 ms
// for more frames.
func TestDgramBatchNoWait_L55(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, fa := wp2Pair(t, 1200, 32)
		var n atomic.Int32
		var seq atomic.Uint64
		a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
		settle(a, b, StartOptions{})
		a.io.setRec(true)
		mark := len(fa.writeCalls())
		t0 := time.Now()
		n.Store(1)
		a.c.Wake()
		synctest.Wait()
		ws := a.io.recorded()
		if len(ws) != 1 || !ws[0].at.Equal(t0) || !slices.Equal(fa.writeCalls()[mark:], []int{1}) {
			t.Fatalf("writes %d (at %v, wake at %v), calls %v; want one datagram at the wake, in one call", len(ws), func() any {
				if len(ws) > 0 {
					return ws[0].at
				}
				return nil
			}(), t0, fa.writeCalls()[mark:])
		}
		if got := seqsOf(b.ep); !slices.Equal(got, []uint64{0}) {
			t.Fatalf("delivered %v", got)
		}
	})
}

// TestDgramBatchOrder_L55: 150 DGRAMs of varied sizes over three rounds,
// flushed four per call: the datagrams leave in packing order and the peer
// receives every seq once, in order (L55: commit order kept).
func TestDgramBatchOrder_L55(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, fa := wp2Pair(t, 1200, 4)
		var n atomic.Int32
		var seq atomic.Uint64
		size := func(s uint64) int { return 20 + int(s*37%900) }
		a.ep.setFill(burstFill(&n, &seq, size, false))
		settle(a, b, StartOptions{})
		a.io.setRec(true)
		mark := len(fa.writeCalls())
		n.Store(150)
		a.c.Wake()
		synctest.Wait()
		var sent []uint64
		for _, w := range a.io.recorded() {
			fs, ok := dgDecode(w.b)
			if !ok {
				t.Fatal("a written datagram does not decode")
			}
			for _, f := range fs {
				if f.Type == wire.TypeDgram {
					s, body, _ := wire.ParseDgram(f.Payload)
					if len(body) != size(s) {
						t.Fatalf("DGRAM %d carries %d bytes, want %d", s, len(body), size(s))
					}
					sent = append(sent, s)
				}
			}
		}
		if !slices.Equal(sent, upTo(150)) {
			t.Fatalf("written seqs %v", sent)
		}
		if got := seqsOf(b.ep); !slices.Equal(got, upTo(150)) {
			t.Fatalf("delivered %v", got)
		}
		total := 0
		for _, k := range fa.writeCalls()[mark:] {
			if k < 1 || k > 4 {
				t.Fatalf("a call of %d datagrams with MaxBatch 4", k)
			}
			total += k
		}
		if total != len(a.io.recorded()) {
			t.Fatalf("%d datagrams in the calls, %d written", total, len(a.io.recorded()))
		}
	})
}

// TestDgramBatchPartial_L55: a call writes 7 of 16 datagrams and then
// fails fatally: the carrier dies (transport_error, never retried on it,
// L42), the 7 reach the peer exactly once and nothing of the 16 is written
// twice or after the death (L55: only the written prefix completes).
func TestDgramBatchPartial_L55(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, fa := wp2Pair(t, 1200, 16)
		var n atomic.Int32
		var seq atomic.Uint64
		a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
		settle(a, b, StartOptions{})
		mark := len(fa.writeCalls())
		fa.setScript(0, func(call int, ds [][]byte) (int, error) {
			if call == mark {
				return 7, errNotNoise
			}
			return len(ds), nil
		})
		w0 := a.io.nwrites.Load()
		n.Store(16)
		a.c.Wake()
		hWait(t, a.c)
		synctest.Wait()
		if _, cause, detail, _ := a.c.Death(); cause != CauseTransportError || !strings.Contains(detail, "write:") {
			t.Fatalf("death %v %q, want transport_error on the write", cause, detail)
		}
		if w := a.io.nwrites.Load() - w0; w != 7 {
			t.Fatalf("%d datagrams written, want the 7 the call wrote", w)
		}
		if got := seqsOf(b.ep); !slices.Equal(got, upTo(7)) {
			t.Fatalf("delivered %v, want 0 … 6 once each", got)
		}
		if calls := fa.writeCalls()[mark:]; !slices.Equal(calls, []int{16}) {
			t.Fatalf("calls %v, want the one call of 16", calls)
		}
	})
}

// TestDgramBatchScratchReleased_L55: after a round — written, and killed
// by a fatal write mid-flush — the arena is back in its pool (the stage
// account at its pre-round value), the batch keeps no slot of it, and
// every chunk the round's DGRAMs referenced is back at its pre-round
// reference count (L55: a reset clears the scratch's references; the
// arena holds copies, never a chunk reference). Mutant: arena slots kept
// after a kill.
func TestDgramBatchScratchReleased_L55(t *testing.T) {
	for _, kill := range []bool{false, true} {
		name := "written"
		if kill {
			name = "killed"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, _ := dgPair(t, 1200)
				fa := newFakeBatch(a.io, 8)
				chunk := a.env.Bufs.Get(ChunkSize, nil)
				defer chunk.Release()
				var seq uint64
				a.c.ep, a.c.pep = a.ep, a.ep
				a.c.mu.Lock()
				a.c.st.pingSent = true // no PING: the cadence is far away
				a.c.st.lastCommit = time.Now()
				a.c.mu.Unlock()
				a.c.writerInit()
				a.c.wr.bio = fa
				defer func() {
					a.c.wr.dscratch.Release()
					a.c.wr.dscratch = nil
					a.c.wr.timer.Stop()
					a.c.wd1.Stop()
					a.c.wd2.Stop()
				}()
				if kill {
					fa.setScript(0, func(call int, ds [][]byte) (int, error) { return 3, errNotNoise })
				}
				a.ep.setFill(func(c *Conn, b *Batch) {
					for range 20 {
						if !b.AddDgram(wire.SessionHandle, seq, chunk.B[:200], chunk) {
							return
						}
						seq++
					}
				})
				refs := chunk.refs.Load()
				stages := a.env.Stages.Used()
				ok := a.c.writeRound(&a.c.wr)
				if ok == kill {
					t.Fatalf("round returned %v", ok)
				}
				w := &a.c.wr
				if w.arena != nil || a.env.Stages.Used() != stages {
					t.Fatalf("arena %v, stage account %d, want released (%d)", w.arena != nil, a.env.Stages.Used(), stages)
				}
				if w.b.flushLen() != 0 || slices.ContainsFunc(w.b.fl[:cap(w.b.fl)], func(s []byte) bool { return s != nil }) {
					t.Fatal("the batch keeps a slot of the arena")
				}
				if r := chunk.refs.Load(); r != refs {
					t.Fatalf("chunk references %d after the round, want %d", r, refs)
				}
				if len(fa.writeCalls()) == 0 {
					t.Fatal("no batched write")
				}
			})
		})
	}
}

// TestDgramBatchCountOnce_L55: the carrier's counters move only at the
// return of the call that wrote a datagram, once per written index (L55:
// a late completion counts at most once; L63): entering each call they
// hold exactly the datagrams earlier calls wrote; a call that wrote 3 of 8
// and lost the 4th to noise counts 3 written and 1 dropped, and the flush
// goes on with the rest. Mutant: counters bumped before the call returns.
func TestDgramBatchCountOnce_L55(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, fa := wp2Pair(t, 1200, 8)
		var n atomic.Int32
		var seq atomic.Uint64
		a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
		settle(a, b, StartOptions{})
		s0 := a.c.Stats()
		mark := len(fa.writeCalls())
		var entry []uint64
		var txEntry []uint64
		fa.setScript(0, func(call int, ds [][]byte) (int, error) {
			s := a.c.Stats()
			entry = append(entry, s.Datagrams-s0.Datagrams)
			txEntry = append(txEntry, s.TxBytes-s0.TxBytes)
			if call == mark {
				return 3, ErrNoise
			}
			return len(ds), nil
		})
		n.Store(20)
		a.c.Wake()
		synctest.Wait()
		if calls := fa.writeCalls()[mark:]; !slices.Equal(calls, []int{8, 4, 8, 4}) {
			t.Fatalf("calls %v, want [8 4 8 4]: the flush goes on after the lost datagram", calls)
		}
		// Datagrams count at each call's return; DGRAM bytes are committed
		// with the round (M2: under Conn.mu after its last write).
		if !slices.Equal(entry, []uint64{0, 3, 7, 15}) || !slices.Equal(txEntry, []uint64{0, 0, 0, 0}) {
			t.Fatalf("counters entering each call: datagrams %v, bytes %v; want [0 3 7 15] and [0 0 0 0]", entry, txEntry)
		}
		s := a.c.Stats()
		if s.Datagrams-s0.Datagrams != 19 || s.TxBytes-s0.TxBytes != 1900 || s.Dropped-s0.Dropped != 1 {
			t.Fatalf("datagrams %d, bytes %d, dropped %d; want 19, 1900, 1", s.Datagrams-s0.Datagrams, s.TxBytes-s0.TxBytes, s.Dropped-s0.Dropped)
		}
		want := slices.Delete(upTo(20), 3, 4)
		if got := seqsOf(b.ep); !slices.Equal(got, want) {
			t.Fatalf("delivered %v", got)
		}
	})
}

// TestDgramBatchNoiseContinues: a datagram lost to noise inside a flush
// (ErrNoise at index 5 of 12) is dropped and counted, the carrier lives,
// and the rest of the flush follows in the next call (M2's outcome
// mapping, M5-D12).
func TestDgramBatchNoiseContinues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, fa := wp2Pair(t, 1200, 12)
		var n atomic.Int32
		var seq atomic.Uint64
		a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
		settle(a, b, StartOptions{})
		d0 := a.c.Stats().Dropped
		mark := len(fa.writeCalls())
		fa.setScript(0, func(call int, ds [][]byte) (int, error) {
			if call == mark {
				return 5, ErrNoise
			}
			return len(ds), nil
		})
		n.Store(12)
		a.c.Wake()
		synctest.Wait()
		if dead, cause, detail, _ := a.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
		if calls := fa.writeCalls()[mark:]; !slices.Equal(calls, []int{12, 6}) {
			t.Fatalf("calls %v, want [12 6]", calls)
		}
		if d := a.c.Stats().Dropped - d0; d != 1 {
			t.Fatalf("dropped %d, want 1", d)
		}
		if got := seqsOf(b.ep); !slices.Equal(got, slices.Delete(upTo(12), 5, 6)) {
			t.Fatalf("delivered %v", got)
		}
	})
}

// TestDgramBatchRefusedTooLarge: index 2 of a flush is refused as too
// large with a size the path carries (Max 550): the budget shrinks to it
// (M2-D25), Refused counts the refused datagram's DGRAM, and the rest of
// the round is packed again under the new budget — a PACK and its DGRAM,
// one datagram of 562 bytes before, now travel apart — while a refusal
// without a size (Max 0) lowers nothing and the flush goes on with the
// datagrams already packed.
func TestDgramBatchRefusedTooLarge(t *testing.T) {
	for _, max := range []int{550, 0} {
		t.Run("max"+itoa(max), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b, fa := wp2Pair(t, 1200, 32)
				var n atomic.Int32
				var seq atomic.Uint64
				a.ep.setFill(burstFill(&n, &seq, fixed(500), true))
				settle(a, b, StartOptions{})
				a.io.setRec(true)
				r0 := a.c.Stats().Refused
				mark := len(fa.writeCalls())
				fa.setScript(0, func(call int, ds [][]byte) (int, error) {
					if call == mark {
						return 2, &wire.DatagramTooLargeError{Max: max}
					}
					return len(ds), nil
				})
				n.Store(10)
				a.c.Wake()
				synctest.Wait()
				if dead, cause, detail, _ := a.c.Death(); dead {
					t.Fatalf("carrier died: %v %q", cause, detail)
				}
				if r := a.c.Stats().Refused - r0; r != 1 {
					t.Fatalf("Refused %d, want 1", r)
				}
				if got := seqsOf(b.ep); !slices.Equal(got, slices.Delete(upTo(10), 2, 3)) {
					t.Fatalf("delivered %v", got)
				}
				ws := a.io.recorded()
				calls := fa.writeCalls()[mark:]
				if max == 0 {
					if a.c.MTU() != 1200 || !slices.Equal(calls, []int{10, 7}) || len(ws) != 9 {
						t.Fatalf("budget %d, calls %v, %d written; want 1200, [10 7], 9", a.c.MTU(), calls, len(ws))
					}
					return
				}
				if a.c.MTU() != 550 || !slices.Equal(calls, []int{10, 14}) || len(ws) != 16 {
					t.Fatalf("budget %d, calls %v, %d written; want 550, [10 14] and 16 datagrams", a.c.MTU(), calls, len(ws))
				}
				for _, w := range ws[2:] {
					if len(w.b) > 550 {
						t.Fatalf("a %d-byte datagram after the budget shrank to 550", len(w.b))
					}
				}
			})
		})
	}
}

// TestBatchedWriteErrorIsCarrierDeath_L01 (invariant 1): a fatal error at
// message 5 of 12 ends the carrier with transport_error — a carrier death
// for its session to survive (the dEP holds no error) — and nothing that
// would end the peer's stream or session: the peer received the 5
// datagrams before it and no FIN, RST or CLOSE.
func TestBatchedWriteErrorIsCarrierDeath_L01(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, fa := wp2Pair(t, 1200, 12)
		var n atomic.Int32
		var seq atomic.Uint64
		a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
		settle(a, b, StartOptions{})
		mark := len(fa.writeCalls())
		fa.setScript(0, func(call int, ds [][]byte) (int, error) {
			if call == mark {
				return 5, errNotNoise
			}
			return len(ds), nil
		})
		n.Store(12)
		a.c.Wake()
		hWait(t, a.c)
		synctest.Wait()
		if _, cause, detail, _ := a.c.Death(); cause != CauseTransportError || !strings.Contains(detail, errNotNoise.Error()) {
			t.Fatalf("death %v %q, want transport_error with the write's error", cause, detail)
		}
		if got := seqsOf(b.ep); !slices.Equal(got, upTo(5)) {
			t.Fatalf("delivered %v", got)
		}
		for _, h := range b.ep.controls() {
			if h.Type == wire.TypeFin || h.Type == wire.TypeRst || h.Type == wire.TypeClose {
				t.Fatalf("the peer's endpoint saw %v", h.Type)
			}
		}
		if dead, _, _, _ := b.c.Death(); dead {
			t.Fatal("the peer's carrier ended at once")
		}
	})
}

// TestBatchedKillMidBatch_L39 (invariant 2): the carrier is killed between
// two batch calls of a round: the first call's 4 datagrams reach the peer
// once each, the killed call writes nothing, and no datagram is delivered
// twice (L39).
func TestBatchedKillMidBatch_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, fa := wp2Pair(t, 1200, 4)
		var n atomic.Int32
		var seq atomic.Uint64
		a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
		settle(a, b, StartOptions{})
		mark := len(fa.writeCalls())
		fa.setScript(0, func(call int, ds [][]byte) (int, error) {
			if call == mark+1 {
				a.c.Kill(CauseLocalClose, "test: killed between two batch calls")
				return 0, net.ErrClosed
			}
			return len(ds), nil
		})
		w0 := a.io.nwrites.Load()
		n.Store(12)
		a.c.Wake()
		hWait(t, a.c)
		synctest.Wait()
		if got := seqsOf(b.ep); !slices.Equal(got, upTo(4)) {
			t.Fatalf("delivered %v, want 0 … 3 once each", got)
		}
		if w := a.io.nwrites.Load() - w0; w != 4 {
			t.Fatalf("%d datagrams written, want 4", w)
		}
	})
}

// TestDgramBatchPingCommit_L23: the datagram carrying the round's PING
// ends its flush, so the PING commits at the return of the call that wrote
// it (L23): with 1 ms per datagram on the fake clock the PING commits 1 ms
// after the round starts, not when the round's 20 datagrams are out, and
// the RTT sample from its PONG (5 ms later) equals the per-datagram path's.
// Mutant: the PING's datagram does not end its batch.
func TestDgramBatchPingCommit_L23(t *testing.T) {
	run := func(t *testing.T, batched bool) (calls []int, commits []time.Time, pongs []time.Duration, t0 time.Time) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			var fa *fakeBatch
			if batched {
				fa = newFakeBatch(a.io, 32)
				fa.setScript(time.Millisecond, nil)
				useBatch(t, fa)
			} else {
				noBatch(t, a.io)
				a.io.setOut(func([]byte) error { time.Sleep(time.Millisecond); return nil })
			}
			b.io.setDelay(5 * time.Millisecond)
			var n atomic.Int32
			var seq atomic.Uint64
			n.Store(20)
			a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
			obs := &hObserver{}
			t0 = time.Now()
			settle(a, b, StartOptions{Observer: obs})
			time.Sleep(50 * time.Millisecond)
			commits, pongs = obs.snapshot()
			if fa != nil {
				calls = fa.writeCalls()
			}
			if got := seqsOf(b.ep); !slices.Equal(got, upTo(20)) {
				t.Fatalf("delivered %v", got)
			}
		})
		return calls, commits, pongs, t0
	}
	calls, commits, pongs, t0 := run(t, true)
	if len(calls) < 2 || calls[0] != 1 || calls[1] != 19 {
		t.Fatalf("first calls %v, want [1 19 …]: the PING's datagram ends its flush", calls)
	}
	if len(commits) == 0 || commits[0].Sub(t0) != time.Millisecond {
		t.Fatalf("PING commits %v (round at %v), want the first 1 ms after the round started", commits, t0)
	}
	// The PONG comes back through the peer's 5 ms FIFO link behind the
	// peer's own first PING: it arrives 10 ms after the round started.
	_, lcommits, lpongs, l0 := run(t, false)
	if len(pongs) == 0 || len(lpongs) == 0 || pongs[0] != lpongs[0] || pongs[0] != 9*time.Millisecond || lcommits[0].Sub(l0) != commits[0].Sub(t0) {
		t.Fatalf("RTT samples %v (per-datagram path %v), commits %v / %v; want the same 9 ms sample", pongs, lpongs, commits[0].Sub(t0), lcommits[0].Sub(l0))
	}
}

// noBatch makes dgBatchOf return nil for f for the rest of the test (the
// per-datagram path of M2, as for a QUIC or embedder conn).
func noBatch(t testing.TB, f *fakeIO) {
	prev := dgBatchOf
	dgBatchOf = func(io PacketIO) BatchIO {
		if io == PacketIO(f) {
			return nil
		}
		return prev(io)
	}
	t.Cleanup(func() { dgBatchOf = prev })
}

// TestDgramBatchOnOffSame_L55 (L55: batching on and off are the same
// wire): one frame sequence — DGRAMs of varied sizes, unreliable PACKs
// packed with them, reliable FINs as RELs, over several rounds — is
// written with MaxBatch 1 and with the default 32; the datagrams written
// (their boundaries and every frame; a PING's and PONG's random nonce and
// clock masked) are byte-identical.
func TestDgramBatchOnOffSame_L55(t *testing.T) {
	run := func(t *testing.T, max int) [][]byte {
		var out [][]byte
		synctest.Test(t, func(t *testing.T) {
			a, b, _ := wp2Pair(t, 1200, max)
			var n atomic.Int32
			var seq atomic.Uint64
			var fins atomic.Int32
			var finNext atomic.Uint64
			fill := burstFill(&n, &seq, func(s uint64) int { return 1 + int(s*131%1100) }, false)
			ff := finFill(&fins, &finNext)
			packs := 0
			var on atomic.Bool // after the first PING exchange: its timing is the scheduler's
			a.ep.setFill(func(c *Conn, bt *Batch) {
				if !on.Load() {
					return
				}
				ff(c, bt)
				if packs < 40 && bt.AddPack(wire.SessionHandle, 0, &wire.Pack{HighestSeq: uint64(packs), Received: uint64(packs + 1)}, false) {
					packs++
				}
				fill(c, bt)
			})
			settle(a, b, StartOptions{})
			a.io.setRec(true)
			on.Store(true)
			for r := range 6 {
				n.Store(int32(30 + 17*r))
				fins.Store(2)
				a.c.Wake()
				synctest.Wait()
				time.Sleep(time.Millisecond)
			}
			for _, w := range a.io.recorded() {
				out = append(out, maskPings(t, w.b))
			}
			if len(seqsOf(b.ep)) != int(seq.Load()) {
				t.Fatalf("%d DGRAMs delivered of %d", len(seqsOf(b.ep)), seq.Load())
			}
		})
		return out
	}
	off, on := run(t, 1), run(t, 32)
	if len(off) == 0 || len(off) != len(on) {
		t.Fatalf("%d datagrams with MaxBatch 1, %d with 32", len(off), len(on))
	}
	for i := range off {
		if !bytes.Equal(off[i], on[i]) {
			fo, _ := dgDecode(off[i])
			fn, _ := dgDecode(on[i])
			t.Fatalf("datagram %d differs between MaxBatch 1 and 32:\n%v\n%v", i, frameTypes(fo), frameTypes(fn))
		}
	}
}

// maskPings returns rendr bytes d with every PING and PONG payload zeroed
// (their nonces are random per carrier, their clocks per run).
func maskPings(t testing.TB, d []byte) []byte {
	t.Helper()
	fs, ok := dgDecode(d)
	if !ok {
		t.Fatal("a written datagram does not decode")
	}
	var out []byte
	for _, f := range fs {
		p := f.Payload
		if f.Type == wire.TypePing || f.Type == wire.TypePong {
			p = make([]byte, len(p))
		}
		out = wire.AppendFrame(out, f.Header, p)
	}
	return out
}

// itoa formats a small int for subtest names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// frameTypes lists the frames' types and fseqs (failure messages).
func frameTypes(fs []wire.Frame) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Type.String()+"/"+itoa(int(f.Fseq)))
	}
	return out
}

// TestDgBatchHarnessSeam: the harness's in-memory transport reaches its
// carriers through the batched paths — the writer's flushes and the
// dialer reader's depth — with the MaxBatch of the current setting, or
// through the per-datagram path at "off" (TestMain runs the package in
// each setting).
func TestDgBatchHarnessSeam(t *testing.T) {
	f, _ := newFakeIOPair(1200)
	bio := dgBatchOf(f)
	n := int(dgTestMaxBatch.Load())
	if n == 0 {
		if bio != nil {
			t.Fatalf("setting off, yet the harness's transport has a BatchIO (%T)", bio)
		}
		return
	}
	fb, ok := bio.(*fakeBatch)
	if !ok || fb.MaxBatch() != n || fb.fakeIO != f {
		t.Fatalf("the harness's transport reaches its carriers as %T, want a fakeBatch of %d", bio, n)
	}
	if _, ok := bio.(depthIO); !ok {
		t.Fatal("the harness's batched transport has no depth")
	}
	t.Logf("M2/M3 datagram rows of this package run with MaxBatch %d", n)
}

// TestDgramBatchCountOutOfRange_L42: a batched write that reports a count
// outside the datagrams it was given, fewer without an error, or all of
// them with an error (an error of no datagram), ends the carrier
// (transport_error): never retried on it (L42), and never a panic of the
// writer.
func TestDgramBatchCountOutOfRange_L42(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    func(k int) int // nil: the full count, with ErrNoise
	}{{"short", func(k int) int { return k - 1 }}, {"over", func(k int) int { return k + 1 }}, {"negative", func(int) int { return -1 }}, {"full-with-error", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b, fa := wp2Pair(t, 1200, 8)
				var n atomic.Int32
				var seq atomic.Uint64
				a.ep.setFill(burstFill(&n, &seq, fixed(100), false))
				settle(a, b, StartOptions{})
				mark := len(fa.writeCalls())
				if tc.n != nil {
					fa.setReport(tc.n)
				} else {
					fa.setScript(0, func(_ int, ds [][]byte) (int, error) { return len(ds), ErrNoise })
				}
				n.Store(8)
				a.c.Wake()
				hWait(t, a.c)
				if _, cause, detail, _ := a.c.Death(); cause != CauseTransportError || !strings.Contains(detail, "invalid count") {
					t.Fatalf("death %v %q, want transport_error on the count", cause, detail)
				}
				if calls := fa.writeCalls()[mark:]; len(calls) != 1 {
					t.Fatalf("calls %v after the bad count, want the one", calls)
				}
			})
		})
	}
}
