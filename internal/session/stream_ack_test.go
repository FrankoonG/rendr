package session

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestDelayedAckSurvivesDutyMove_L08 (C30): the ACK duty moves to a lane
// that is already up to date (its ackSent equals ackGen) while a delayed ACK
// is armed but not yet bumped. The move still wakes that lane, its writer
// timer re-arms for ackDelayAt, and the ACK leaves on it exactly at
// ackDelayAt — not at the next 64 KiB or urgent bump.
func TestDelayedAckSurvivesDutyMove_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const delay = 20 * time.Millisecond
		s := newTestSession(sopt{role: RolePassive, ackDelay: delay})
		la, pa := addLane(s, 1, false)
		lb, pb := addLane(s, 2, true)
		pa.set(func(f *fakePort) { f.srtt = 10 * time.Millisecond })
		pb.set(func(f *fakePort) { f.srtt = 5 * time.Millisecond })
		s.mu.Lock()
		s.peerWindowLocked(1 << 20)
		s.refreshOrderLocked(time.Now(), true)
		s.st.ackLane = nil
		s.ensureAckLaneLocked()
		s.mu.Unlock()

		type rec struct {
			lane uint32
			at   time.Time
			ack  wire.Ack
		}
		var mu sync.Mutex
		var acks []rec
		var block [3]atomic.Bool // block[id]: the lane's next DATA write hangs
		release := [3]chan struct{}{nil, make(chan struct{}), make(chan struct{})}
		sink := func(id uint32) func(b *carrier.Batch) error {
			return func(b *carrier.Batch) error {
				fs := frames(b)
				mu.Lock()
				for _, f := range fs {
					if f.typ == wire.TypeAck {
						acks = append(acks, rec{id, time.Now(), f.ack})
					}
				}
				mu.Unlock()
				if count(fs, wire.TypeData) > 0 && block[id].Load() {
					<-release[id] // a Hard-blocked embedder write
				}
				return nil
			}
		}
		ackCount := func(id uint32) int {
			mu.Lock()
			defer mu.Unlock()
			n := 0
			for _, r := range acks {
				if r.lane == id {
					n++
				}
			}
			return n
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		runWriter(&wg, la, pa, stop, sink(1))
		runWriter(&wg, lb, pb, stop, sink(2))
		var once [3]sync.Once
		defer func() {
			// Unblock and join every writer, also when the test fails.
			once[1].Do(func() { close(release[1]) })
			once[2].Do(func() { close(release[2]) })
			close(stop)
			wg.Wait()
			endSession(s, errClosed)
		}()
		synctest.Wait()
		if d := locked(s, func(st *stream) *lane { return st.ackLane }); d != lb {
			t.Fatal("the lowest-srtt lane B does not hold the ACK duty")
		}
		// The first DATA after the attaches is acknowledged at once (L19)
		// and its delayed ACK fires: nothing is pending afterwards.
		if err := lb.Data(nil, 0, pattern(0, 100), nil); err != nil {
			t.Fatal(err)
		}
		readN(t, s, 100)
		time.Sleep(2 * delay)
		synctest.Wait()

		// B's write blocks: the watchdog moves the duty to A, which sends the
		// current ACK. Then B's write returns.
		block[2].Store(true)
		if n, err := s.Write(pattern(0, 1000)); n != 1000 || err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		pb.set(func(f *fakePort) { f.blocked = true })
		lb.WriteBlocked(nil)
		synctest.Wait()
		block[2].Store(false)
		pb.set(func(f *fakePort) { f.blocked = false })
		once[2].Do(func() { close(release[2]) })
		synctest.Wait()
		gen, bSent, duty := locked(s, func(st *stream) uint64 { return st.ackGen }), lb.ackSent, locked(s, func(st *stream) *lane { return st.ackLane })
		if duty != la || gen != la.ackSent || gen != bSent {
			t.Fatalf("setup: duty=%v gen=%d A.sent=%d B.sent=%d; want the duty on A and both lanes up to date", duty == la, gen, la.ackSent, bSent)
		}

		// A delivery arms the delayed ACK on the duty lane A (no bump yet).
		if err := la.Data(nil, 100, pattern(100, 500), nil); err != nil {
			t.Fatal(err)
		}
		readN(t, s, 500)
		at := locked(s, func(st *stream) time.Time { return st.ackDelayAt })
		if at.IsZero() || at.Sub(time.Now()) != delay || locked(s, func(st *stream) uint64 { return st.ackGen }) != gen {
			t.Fatalf("ACK delay not armed as expected: at=%v gen moved=%v", at, locked(s, func(st *stream) uint64 { return st.ackGen }) != gen)
		}

		// A's carrier write blocks; PingBusy later the watchdog reports it.
		route(s, la, true)
		route(s, lb, false)
		block[1].Store(true)
		if n, err := s.Write(pattern(1000, 1000)); n != 1000 || err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(5 * time.Millisecond) // inside the 20 ms delay
		before, wakes := ackCount(2), pb.wakeCount()
		pa.set(func(f *fakePort) { f.blocked = true })
		la.WriteBlocked(nil)
		if locked(s, func(st *stream) *lane { return st.ackLane }) != lb {
			t.Fatal("the duty did not move off the blocked lane")
		}
		if pb.wakeCount() == wakes {
			t.Fatal("the new duty lane was not woken although a delayed ACK is armed (C30)")
		}
		synctest.Wait()
		if ackCount(2) != before {
			t.Fatal("an ACK left before ackDelayAt")
		}
		time.Sleep(time.Until(at))
		synctest.Wait()
		mu.Lock()
		var got *rec
		for i := range acks {
			if acks[i].lane == 2 && acks[i].at.Equal(at) {
				got = &acks[i]
			}
		}
		mu.Unlock()
		if got == nil || got.ack.Delivered != 600 {
			t.Fatalf("no ACK(600) on the new duty lane at ackDelayAt (got %+v)", got)
		}
	})
}

// sentSender returns a dialer of the given mode with n lanes (all data
// lanes in bond mode, lane 1 active otherwise) that has written and sent
// total bytes; the peer window covers them.
func sentSender(t testing.TB, mode Mode, n, total int) (*Session, []*lane, []*fakePort) {
	t.Helper()
	s := newTestSession(sopt{mode: mode, window: 8 << 20})
	var ls []*lane
	var ps []*fakePort
	for i := range n {
		l, p := addLane(s, uint32(i+1), mode == ModeBond || i == 0)
		ls, ps = append(ls, l), append(ps, p)
	}
	s.mu.Lock()
	s.peerWindowLocked(8 << 20)
	s.mu.Unlock()
	if k, err := s.Write(pattern(0, total)); k != total || err != nil {
		t.Fatalf("Write = (%d, %v)", k, err)
	}
	for sent := 0; sent < total; {
		moved := 0
		for _, l := range ls {
			fs, b := fill(l, time.Now())
			b.ReleaseRefs()
			for _, f := range fs {
				moved += f.n
			}
		}
		if moved == 0 {
			t.Fatalf("Fill stalled after %d of %d bytes", sent, total)
		}
		sent += moved
	}
	return s, ls, ps
}

// TestAckMergeMonotonic_L13: ACKs from different carriers merge by max —
// a late lower ACK changes nothing — and eight goroutines delivering their
// own monotonic ACK sequences in random interleavings always end at the
// maximum of both the front and the advertised edge.
func TestAckMergeMonotonic_L13(t *testing.T) {
	const total = 4 << 20
	s, ls, _ := sentSender(t, ModeBond, 8, total)
	if err := sendAck(ls[0], 0, 5, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := sendAck(ls[1], 0, 4, 1<<20); err != nil {
		t.Fatalf("a lower ACK on another carrier is not a violation: %v", err)
	}
	if err := sendAck(ls[2], 0, 5, 1<<20); err != nil {
		t.Fatal(err)
	}
	if b := locked(s, func(st *stream) uint64 { return st.sBase }); b != 5 {
		t.Fatalf("sBase = %d after ACK 5, a late 4 and a duplicate 5; want 5", b)
	}

	for run := range 20 {
		s, ls, _ := sentSender(t, ModeBond, 8, total)
		var maxDel, maxEdge atomic.Uint64
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, len(ls))
		for i, l := range ls {
			rng := rand.New(rand.NewPCG(uint64(run), uint64(i)))
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				var d uint64
				for range 50 {
					d = min(total, d+uint64(rng.IntN(total/40)))
					w := uint32(rng.IntN(8 << 20))
					if err := sendAck(l, 0, d, w); err != nil {
						errs <- err
						return
					}
					for m := maxDel.Load(); d > m && !maxDel.CompareAndSwap(m, d); m = maxDel.Load() {
					}
					e := d + uint64(w)
					for m := maxEdge.Load(); e > m && !maxEdge.CompareAndSwap(m, e); m = maxEdge.Load() {
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("run %d: per-carrier monotonic ACKs reported a violation: %v", run, err)
		}
		got := locked(s, func(st *stream) [2]uint64 { return [2]uint64{st.sBase, st.peerLimit} })
		if got[0] != maxDel.Load() || got[1] != max(maxEdge.Load(), 8<<20) {
			t.Fatalf("run %d: front %d edge %d, want the maxima %d and %d", run, got[0], got[1], maxDel.Load(), max(maxEdge.Load(), 8<<20))
		}
		for _, l := range ls {
			if len(l.infl.s) > 0 && l.infl.s[0].off < got[0] {
				t.Fatalf("run %d: lane %d keeps in-flight bytes below the front", run, l.id)
			}
		}
		endSession(s, errClosed)
	}
}

// TestDuplicateAcksNoRetransmit_L13: a hundred identical ACKs below sNext
// trigger no retransmission (rendr has no duplicate-ACK fast retransmit;
// stream carriers are reliable).
func TestDuplicateAcksNoRetransmit_L13(t *testing.T) {
	s, ls, _ := sentSender(t, ModeSelector, 2, 1<<20)
	for i := range 100 {
		if err := sendAck(ls[i%2], 0, 300<<10, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range ls {
		fs, b := fill(l, time.Now())
		b.ReleaseRefs()
		if n := count(fs, wire.TypeData); n != 0 {
			t.Fatalf("%d DATA frames after duplicate ACKs, want 0", n)
		}
	}
	st := locked(s, func(st *stream) [3]uint64 { return [3]uint64{st.sBase, st.retxBytes, st.retx.bytes()} })
	if st != [3]uint64{300 << 10, 0, 0} {
		t.Fatalf("sBase, retxBytes, queued = %v; want %d, 0, 0", st, 300<<10)
	}
	endSession(s, errClosed)
}

// TestAckRegressionOnCarrierKills_L13 (P3): an ACK below the last one on
// the same carrier, or beyond what was sent, is a violation of that
// carrier only; the session state is unchanged and the session continues on
// another carrier.
func TestAckRegressionOnCarrierKills_L13(t *testing.T) {
	s, ls, _ := sentSender(t, ModeBond, 3, 1<<20)
	front := func() uint64 { return locked(s, func(st *stream) uint64 { return st.sBase }) }
	if err := sendAck(ls[0], 0, 500<<10, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := sendAck(ls[0], 0, 400<<10, 1<<20); !errors.Is(err, errAckRegression) {
		t.Fatalf("regression on the same carrier = %v, want the regression violation", err)
	}
	if front() != 500<<10 {
		t.Fatalf("front %d after a rejected regression, want %d", front(), 500<<10)
	}
	if err := sendAck(ls[1], 0, 400<<10, 1<<20); err != nil {
		t.Fatalf("a lower ACK from another carrier: %v", err)
	}
	if err := sendAck(ls[1], 0, 600<<10, 1<<20); err != nil || front() != 600<<10 {
		t.Fatalf("ACK 600 KiB on carrier 2 = %v, front %d", err, front())
	}
	if err := sendAck(ls[1], 0, 1<<20+10, 1<<20); !errors.Is(err, errAckBeyondSent) {
		t.Fatalf("ACK beyond sent = %v, want the violation", err)
	}
	if err := sendAck(ls[2], wire.FlagAckFinDelivered, 700<<10, 1<<20); !errors.Is(err, errFinDeliveredEarly) {
		t.Fatalf("FIN_DELIVERED without our FIN = %v, want the violation", err)
	}
	if front() != 600<<10 {
		t.Fatalf("front %d after rejected ACKs, want %d", front(), 600<<10)
	}
	// The session continues on the third carrier.
	if err := sendAck(ls[2], 0, 1<<20, 1<<20); err != nil || front() != 1<<20 {
		t.Fatalf("ACK on the surviving carrier = %v, front %d", err, front())
	}
	if u := s.env.Carrier.Budget.Used(); u != 0 {
		t.Fatalf("%d bytes of send chunks held with everything acknowledged (idle drop)", u)
	}
	endSession(s, errClosed)
}

// TestConflictingDuplicateKillsCarrier_L13: overlapping DATA is compared
// byte for byte wherever it overlaps bytes still held (the in-order queue,
// the in-order tail, out-of-order segments; copied runs and referenced
// buffers alike). A mismatch is a violation of the delivering carrier, the
// first copy stays authoritative, and the rejected frame's buffer is
// released; an agreeing overlap is trimmed and accepted.
func TestConflictingDuplicateKillsCarrier_L13(t *testing.T) {
	s := newTestSession(sopt{role: RolePassive})
	l1, _ := addLane(s, 1, false)
	l2, _ := addLane(s, 2, false)
	budget := s.env.Carrier.Budget
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 0x40
		return c
	}
	mustConflict := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, errConflict) {
			t.Fatalf("%s: %v, want the conflicting-duplicate violation", name, err)
		}
	}
	mustOK := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// In-order duplicate, small copied run.
	mustOK("[0,100)", l1.Data(nil, 0, pattern(0, 100), nil))
	used := budget.Used()
	mustConflict("duplicate [0,100) with a flipped byte", l2.Data(nil, 0, flip(pattern(0, 100), 50), nil))
	mustOK("agreeing duplicate", l2.Data(nil, 0, pattern(0, 100), nil))
	// Overlap with the in-order tail.
	mustConflict("[80,150) flipped in the overlap", l2.Data(nil, 80, flip(pattern(80, 70), 10), nil))
	mustOK("[80,150) agreeing", l2.Data(nil, 80, pattern(80, 70), nil))
	// Out-of-order overlap.
	mustOK("[300,400)", l1.Data(nil, 300, pattern(300, 100), nil))
	mustConflict("[350,450) flipped at 360", l2.Data(nil, 350, flip(pattern(350, 100), 10), nil))
	mustOK("[350,450) agreeing", l2.Data(nil, 350, pattern(350, 100), nil))
	// Referenced (≥ 16 KiB) buffers.
	big := pattern(1000, 32<<10)
	mustOK("[1000,+32K) by reference", deliverData(l1, 1000, big))
	before := budget.Used()
	mustConflict("big duplicate flipped at 20K", deliverData(l2, 1000, flip(big, 20<<10)))
	if budget.Used() != before {
		t.Fatalf("a rejected big frame kept %d bytes of buffer", budget.Used()-before)
	}
	if used > before {
		t.Fatal("budget shrank unexpectedly")
	}
	// The gap [150,300) and [450,1000) arrive: everything is contiguous.
	mustOK("[150,300)", l1.Data(nil, 150, pattern(150, 150), nil))
	mustOK("[450,1000)", l1.Data(nil, 450, pattern(450, 550), nil))
	want := pattern(0, 1000+32<<10)
	got := readN(t, s, 500)
	if !bytes.Equal(got, want[:500]) {
		t.Fatal("first copies not authoritative")
	}
	// Consumed bytes are not compared any more; held ones still are.
	mustOK("overlap of consumed bytes with a flip below rRead", l2.Data(nil, 400, flip(pattern(400, 200), 5), nil))
	mustConflict("flip in the held part", l2.Data(nil, 400, flip(pattern(400, 200), 150), nil))
	rest := readN(t, s, len(want)-500)
	if !bytes.Equal(rest, want[500:]) {
		t.Fatal("stream corrupted after rejected duplicates")
	}
	endSession(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}
