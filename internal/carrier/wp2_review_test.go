package carrier

import (
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// M5 WP2 rows added at review: the depth rule's halving, a partly granted
// growth, the fallback's return of the extras (§A4.4; R1-4, M5-D13,
// M5-D15), the reader of a flow-like BatchIO (ReadSize 0, its own
// buffers: dgReadBatch, §A4.5), and a rebind inside one batch (L55: on and
// off behave the same, L59).

// injectItems queues items in f's inbox in one critical section and wakes
// its reader once (injectBurst with a source and a forced event per item).
func injectItems(f *fakeIO, items ...dgItem) {
	f.mu.Lock()
	for _, it := range items {
		s := &f.ring[(f.head+f.n)%len(f.ring)]
		s.b = append(s.b[:0], it.b...)
		s.src, s.ev, s.err = it.src, it.ev, it.err
		f.n++
	}
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// flowFake is a BatchIO with ReadSize 0 over a fakeIO, as udpflow.Flow
// over rendr's own socket: ReadDatagrams hands out buffers of its own —
// valid until the next call or Release — waits for the first datagram,
// takes up to min(len(rs), MaxBatch) queued ones (events included) and
// ends a call at its first ReadCandidate. It counts the buffers handed out
// and not yet released (held), the calls and the Releases.
type flowFake struct {
	*fakeIO
	max  int
	bufs [][]byte

	mu       sync.Mutex
	held     int   // buffers of the latest call not released yet
	calls    []int // the results of each call
	releases int
	early    int // calls made while buffers of the previous one were held
}

func (a *flowFake) ReadSize() int { return 0 }
func (a *flowFake) MaxBatch() int { return a.max }

func (a *flowFake) ReadDatagram([]byte) ([]byte, PeerKey, ReadEvent, error) {
	panic("flowFake: the carrier reads a BatchIO through ReadDatagrams")
}

func (a *flowFake) Release() {
	a.mu.Lock()
	a.held = 0
	a.releases++
	a.mu.Unlock()
}

func (a *flowFake) WriteDatagrams(ds [][]byte) (int, error) {
	for i, d := range ds {
		if err := a.fakeIO.WriteDatagram(d); err != nil {
			return i, err
		}
	}
	return len(ds), nil
}

// next reports whether the inbox's head is a datagram or a read event (not
// a scripted error), which a call takes without waiting.
func (a *flowFake) next() bool {
	f := a.fakeIO
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n > 0 && f.ring[f.head].err == nil
}

func (a *flowFake) ReadDatagrams(rs []ReadResult) (int, error) {
	a.mu.Lock()
	if a.held != 0 {
		a.early++
	}
	a.mu.Unlock()
	k := min(len(rs), a.max)
	n := 0
	for n < k && (n == 0 || a.next()) {
		if len(a.bufs) == n {
			a.bufs = append(a.bufs, make([]byte, a.fakeIO.ReadSize()))
		}
		data, src, ev, err := a.fakeIO.ReadDatagram(a.bufs[n])
		if err != nil {
			return 0, err // n is 0: next() never takes a scripted error
		}
		rs[n] = ReadResult{Data: data, Src: src, Ev: ev}
		n++
		if ev == ReadCandidate {
			break // a call ends at its first candidate (BatchIO)
		}
	}
	a.mu.Lock()
	a.held = n
	a.calls = append(a.calls, n)
	a.mu.Unlock()
	return n, nil
}

// stats returns the held buffers, the calls and the Releases.
func (a *flowFake) stats() (held int, calls []int, releases, early int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.held, slices.Clone(a.calls), a.releases, a.early
}

var _ BatchIO = (*flowFake)(nil)

// flowSide starts a passive carrier whose transport is a flowFake over
// the first end of a link, with a raw peer on the other end.
func flowSide(t *testing.T) (*dgSide, *rawPeer, *flowFake) {
	ia, ib := newFakeIOPair(1200)
	ff := &flowFake{fakeIO: ia, max: DefaultMaxBatch}
	s := &dgSide{env: dgEnv(), io: ia, ep: &dEP{}, bell: &hBell{}}
	s.c = dgConn(s.env, ff, 1200, false)
	p := &rawPeer{io: ib, fseq: s.env.Presets.firstFseq()}
	t.Cleanup(func() {
		s.c.Kill(CauseLocalClose, "test cleanup")
		<-s.c.Done()
	})
	s.start(StartOptions{})
	return s, p, ff
}

// TestDgramReadFlowBatch (§A4.5, M5-D14): a transport with ReadSize 0
// hands out its own buffers. A burst of 20 is read in calls of at most
// flowReadDepth (8, 8, 4) and delivered in order, with one Release per
// call before the next call; a call of [DGRAM, noise, empty, DGRAM,
// DGRAM] delivers its three datagrams in order and counts one read error
// and one drop, as M2's per-datagram path does; and the buffers go back
// before any pause — the noise back-off, and the spin guard after 64
// consecutive drops — so no buffer of the transport waits out a pause.
// Mutant: the pause taken while the call's results are handled.
func TestDgramReadFlowBatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, ff := flowSide(t)
		synctest.Wait()
		injectBurst(s.io, p.io.addr, p.burst(0, 20, 100))
		synctest.Wait()
		held, calls, rel, early := ff.stats()
		if !slices.Equal(calls, []int{8, 8, 4}) || rel != 3 || early != 0 || held != 0 {
			t.Fatalf("calls %v, Releases %d, calls with buffers held %d, held %d; want [8 8 4], 3, 0, 0", calls, rel, early, held)
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(20)) {
			t.Fatalf("delivered %v", got)
		}

		errs, drops := s.env.Dgram.ReadErrors.Load(), s.env.Dgram.Dropped.Load()
		injectItems(s.io,
			dgItem{b: p.datagram(dgramFrame(20, 100)), src: p.io.addr},
			dgItem{ev: ReadNoise},
			dgItem{ev: ReadEmpty},
			dgItem{b: p.datagram(dgramFrame(21, 100)), src: p.io.addr},
			dgItem{b: p.datagram(dgramFrame(22, 100)), src: p.io.addr})
		synctest.Wait() // the reader sleeps its back-off now
		held, calls, _, _ = ff.stats()
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(23)) || held != 0 || calls[len(calls)-1] != 5 {
			t.Fatalf("in the noise back-off: delivered %v, buffers held %d, last call %d; want 0 … 22, 0, 5", got, held, calls[len(calls)-1])
		}
		if e, d := s.env.Dgram.ReadErrors.Load()-errs, s.env.Dgram.Dropped.Load()-drops; e != 1 || d != 1 {
			t.Fatalf("read errors +%d, drops +%d; want +1, +1", e, d)
		}
		time.Sleep(noiseMax)
		synctest.Wait()

		empties := make([]dgItem, spinIdle, spinIdle+1)
		for i := range empties {
			empties[i] = dgItem{ev: ReadEmpty}
		}
		injectItems(s.io, append(empties, dgItem{b: p.datagram(dgramFrame(23, 100)), src: p.io.addr})...)
		synctest.Wait() // the spin guard's pause
		held, _, _, _ = ff.stats()
		if got := len(seqsOf(s.ep)); held != 0 || got != 23 {
			t.Fatalf("in the spin guard's pause: buffers held %d, delivered %d; want 0, 23 (the pause after %d drops)", held, got, spinIdle)
		}
		time.Sleep(2 * spinPause)
		synctest.Wait()
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(24)) {
			t.Fatalf("delivered %v after the pause", got)
		}
		if _, _, _, early = ff.stats(); early != 0 {
			t.Fatalf("%d calls while the previous call's buffers were held", early)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDgramBatchRebindSame_L55 (L55 on and off the same; L59): a passive
// carrier's challenge to a new source B is in flight; then one batch
// arrives — B's answer, a DGRAM from B, a DGRAM from the old peer A. One
// datagram per call, the answer commits the rebind, B's DGRAM is then the
// peer's, and A's is a candidate that creates a challenge to A. The depth
// path (fakeBatch at MaxBatch 32) and a flow's batched path (flowFake) end
// the same way: Rebinds 1, the peer B, a challenge created for A — never a
// fresh one to the peer just committed, retargeted or not — and every
// DGRAM delivered. Mutant: a batched read goes on past a candidate (events
// decided before the commit).
func TestDgramBatchRebindSame_L55(t *testing.T) {
	for _, mode := range []string{"off", "depth", "flow"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ia, ib := newFakeIOPair(1200)
				ia.rebind = true
				var pio PacketIO = ia
				prev := dgBatchOf
				switch mode {
				case "off":
					dgBatchOf = func(io PacketIO) BatchIO {
						if io == PacketIO(ia) {
							return nil
						}
						return prev(io)
					}
				case "depth":
					fb := newFakeBatch(ia, DefaultMaxBatch)
					dgBatchOf = func(io PacketIO) BatchIO {
						if io == PacketIO(ia) {
							return fb
						}
						return prev(io)
					}
				case "flow":
					pio = &flowFake{fakeIO: ia, max: DefaultMaxBatch}
				}
				t.Cleanup(func() { dgBatchOf = prev })
				s := &dgSide{env: dgEnv(), io: ia, ep: &dEP{}, bell: &hBell{}}
				s.c = dgConn(s.env, pio, 1200, false)
				p := &rawPeer{io: ib, fseq: s.env.Presets.firstFseq()}
				t.Cleanup(func() {
					s.c.Kill(CauseLocalClose, "test cleanup")
					<-s.c.Done()
				})
				s.start(StartOptions{})
				for range 5 { // an RTT sample: the RTO well under a second
					time.Sleep(20 * time.Millisecond)
					rebindAnswer(p)
				}
				synctest.Wait()
				a, b := ib.addr, fakeAddr(9)
				chal := func() (active bool, cand PeerKey, nonce uint64, moved bool) {
					s.c.mu.Lock()
					defer s.c.mu.Unlock()
					ch := &s.c.dg.chal
					return ch.active && !s.c.chalExpiredLocked(time.Now()), ch.cand, ch.nonce, ch.moved
				}
				s.c.mu.Lock()
				rto := s.c.relRTOLocked()
				s.c.mu.Unlock()

				ia.inject(b, p.datagram(dgramFrame(0, 100)))
				synctest.Wait()
				if on, cand, _, _ := chal(); !on || cand != b {
					t.Fatalf("challenge active %v to %v, want one to B (stimulus)", on, cand)
				}
				time.Sleep(max(rto, chalSpacingMin) + 10*time.Millisecond) // a new challenge may be created
				synctest.Wait()
				on, cand, nonce, _ := chal()
				if !on || cand != b {
					t.Fatalf("challenge active %v to %v after the spacing, want still the one to B (stimulus)", on, cand)
				}
				injectItems(ia,
					dgItem{b: p.datagram(pingFrame(wire.TypePong, wire.Ping{Nonce: nonce})), src: b},
					dgItem{b: p.datagram(dgramFrame(1, 100)), src: b},
					dgItem{b: p.datagram(dgramFrame(2, 100)), src: a})
				synctest.Wait()
				on, cand, _, moved := chal()
				if r := s.c.Stats().Rebinds; r != 1 || ia.cur != b || !on || cand != a || moved {
					t.Fatalf("rebinds %d, peer %v, challenge active %v to %v (retargeted %v); want 1, B, one created for A", r, ia.cur, on, cand, moved)
				}
				if got := seqsOf(s.ep); !slices.Equal(got, upTo(3)) {
					t.Fatalf("delivered %v", got)
				}
				if dead, cause, detail, _ := s.c.Death(); dead {
					t.Fatalf("carrier died: %v %q", cause, detail)
				}
			})
		})
	}
}

// depthRig starts a dialer carrier read through a fakeBatch of MaxBatch 32
// and returns it with its Budget and Stages baselines.
func depthRig(t *testing.T) (s *dgSide, p *rawPeer, fb *fakeBatch, base, sbase int64) {
	s, p = rawPair(t, 1200, true)
	fb = newFakeBatch(s.io, DefaultMaxBatch)
	useBatch(t, fb)
	s.start(StartOptions{})
	synctest.Wait()
	return s, p, fb, s.env.Budget.Used(), s.env.Stages.Used()
}

// TestDgramReadHalvesDepth_L16 (M5-D13, §A4.4; R1-4): after a queued burst
// of 64 grew the depth to 32 (31 slots charged), a call that parked and
// returned one datagram — fewer than 32/4 — halves it: Env.Budget drops by
// exactly 16 slots and the next burst's first call reads 16. Mutants: no
// halving; the halving without releasing the slots.
func TestDgramReadHalvesDepth_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, fb, base, _ := depthRig(t)
		bud := s.env.Budget
		injectBurst(s.io, p.io.addr, p.burst(0, 64, 100))
		synctest.Wait()
		if calls := fb.readCalls(); !slices.Equal(calls, []int{1, 2, 4, 8, 16, 32, 1}) || bud.Used()-base != 31*slotSize() {
			t.Fatalf("calls %v, slots charged %d; want [1 2 4 8 16 32 1], 31 × %d (stimulus)", calls, bud.Used()-base, slotSize())
		}
		injectBurst(s.io, p.io.addr, p.burst(64, 1, 100))
		synctest.Wait()
		if got := bud.Used() - base; got != 15*slotSize() {
			t.Fatalf("after a parked call of 1 at depth 32: slots charged %d, want 15 × %d (16 released)", got, slotSize())
		}
		mark := len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(65, 20, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, []int{16, 4}) {
			t.Fatalf("the next burst of 20 in calls %v, want [16 4]: depth 16", calls)
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(85)) {
			t.Fatalf("delivered %v", got)
		}
	})
}

// TestDgramReadPartialGrowthRefused_L16 (R1-4, invariant 4): at depth 2,
// with Env.Budget room for one more slot only, a full call's growth to 4
// gets one slot and is refused the next: the depth stays 2, ChargeRefused
// counts the attempt once, and the slot it got goes back — Env.Budget and
// Env.Stages at their values before the attempt. Mutant: the refusal
// keeps the slots granted before it.
func TestDgramReadPartialGrowthRefused_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, fb, base, _ := depthRig(t)
		bud, stg := s.env.Budget, s.env.Stages
		injectBurst(s.io, p.io.addr, p.burst(0, 1, 100))
		synctest.Wait()
		if bud.Used()-base != slotSize() {
			t.Fatalf("slots charged %d at depth 2, want one of %d (stimulus)", bud.Used()-base, slotSize())
		}
		charge := bud.Max() - bud.Used() - slotSize() - slotSize()/2 // room for one slot
		bud.Acquire(charge)
		defer bud.Release(charge)
		before, sBefore := bud.Used(), stg.Used()
		refused := s.env.Dgram.ChargeRefused.Load()
		mark := len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(1, 2, 100))
		synctest.Wait()
		if r := s.env.Dgram.ChargeRefused.Load() - refused; r != 1 {
			t.Fatalf("ChargeRefused +%d, want +1", r)
		}
		if bud.Used() != before || stg.Used() != sBefore {
			t.Fatalf("after the refused growth: Budget %+d, Stages %+d; want both unchanged", bud.Used()-before, stg.Used()-sBefore)
		}
		injectBurst(s.io, p.io.addr, p.burst(3, 3, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, []int{2, 2, 1}) {
			t.Fatalf("calls %v, want [2 2 1]: the depth stays 2", calls)
		}
		if bud.Used() != before || stg.Used() != sBefore {
			t.Fatalf("after the second refusal: Budget %+d, Stages %+d", bud.Used()-before, stg.Used()-sBefore)
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(6)) {
			t.Fatalf("delivered %v", got)
		}
	})
}

// TestDgramReadFallbackReturnsExtras_L16 (M5-D15, R1-4): a reader that
// holds the extras of depth 32 when its socket stops batching (MaxBatch
// falls to 1) gives them back after its next call — slots, header and
// charges: Env.Budget and Env.Stages at their baselines, nothing held —
// and reads one datagram per call from then on. Mutant: the depth rule
// without the fallback's branch (the reader would halve, and keep extras
// for the carrier's life).
func TestDgramReadFallbackReturnsExtras_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p, fb, base, sbase := depthRig(t)
		bud, stg := s.env.Budget, s.env.Stages
		injectBurst(s.io, p.io.addr, p.burst(0, 64, 100))
		synctest.Wait()
		if !fb.holding() || bud.Used() == base || stg.Used() == sbase {
			t.Fatal("no extras held after the burst (stimulus)")
		}
		fb.setMax(1)
		injectBurst(s.io, p.io.addr, p.burst(64, 1, 100))
		synctest.Wait()
		if fb.holding() || bud.Used() != base || stg.Used() != sbase {
			t.Fatalf("after the fallback: holding %v, Budget %+d, Stages %+d; want nothing held", fb.holding(), bud.Used()-base, stg.Used()-sbase)
		}
		mark := len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(65, 5, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, []int{1, 1, 1, 1, 1}) {
			t.Fatalf("calls %v after the fallback, want five of one", calls)
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(70)) {
			t.Fatalf("delivered %v", got)
		}
	})
}
