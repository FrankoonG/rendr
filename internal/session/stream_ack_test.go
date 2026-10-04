package session

import (
	"bytes"
	"errors"
	"io"
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
		s := stSession(stOpt{role: RolePassive, ackDelay: delay})
		la, pa := stAddLane(s, 1, false)
		lb, pb := stAddLane(s, 2, true)
		pa.set(func(f *stPort) { f.srtt = 10 * time.Millisecond })
		pb.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
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
				fs := stFrames(b)
				mu.Lock()
				for _, f := range fs {
					if f.typ == wire.TypeAck {
						acks = append(acks, rec{id, time.Now(), f.ack})
					}
				}
				mu.Unlock()
				if stCount(fs, wire.TypeData) > 0 && block[id].Load() {
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
		stRunWriter(&wg, la, pa, stop, sink(1))
		stRunWriter(&wg, lb, pb, stop, sink(2))
		var once [3]sync.Once
		defer func() {
			// Unblock and join every writer, also when the test fails.
			once[1].Do(func() { close(release[1]) })
			once[2].Do(func() { close(release[2]) })
			close(stop)
			wg.Wait()
			stEnd(s, errClosed)
		}()
		synctest.Wait()
		if d := stLocked(s, func(st *stream) *lane { return st.ackLane }); d != lb {
			t.Fatal("the lowest-srtt lane B does not hold the ACK duty")
		}
		// The first DATA after the attaches is acknowledged at once (L19)
		// and its delayed ACK fires: nothing is pending afterwards.
		if err := lb.Data(nil, 0, stPattern(0, 100), nil); err != nil {
			t.Fatal(err)
		}
		stReadN(t, s, 100)
		time.Sleep(2 * delay)
		synctest.Wait()

		// B's write blocks: the watchdog moves the duty to A, which sends the
		// current ACK. Then B's write returns.
		block[2].Store(true)
		if n, err := s.Write(stPattern(0, 1000)); n != 1000 || err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		pb.set(func(f *stPort) { f.blocked = true })
		lb.WriteBlocked(nil)
		synctest.Wait()
		block[2].Store(false)
		pb.set(func(f *stPort) { f.blocked = false })
		once[2].Do(func() { close(release[2]) })
		synctest.Wait()
		gen, bSent, duty := stLocked(s, func(st *stream) uint64 { return st.ackGen }), lb.ackSent, stLocked(s, func(st *stream) *lane { return st.ackLane })
		if duty != la || gen != la.ackSent || gen != bSent {
			t.Fatalf("setup: duty=%v gen=%d A.sent=%d B.sent=%d; want the duty on A and both lanes up to date", duty == la, gen, la.ackSent, bSent)
		}

		// A delivery arms the delayed ACK on the duty lane A (no bump yet).
		if err := la.Data(nil, 100, stPattern(100, 500), nil); err != nil {
			t.Fatal(err)
		}
		stReadN(t, s, 500)
		at := stLocked(s, func(st *stream) time.Time { return st.ackDelayAt })
		if at.IsZero() || at.Sub(time.Now()) != delay || stLocked(s, func(st *stream) uint64 { return st.ackGen }) != gen {
			t.Fatalf("ACK delay not armed as expected: at=%v gen moved=%v", at, stLocked(s, func(st *stream) uint64 { return st.ackGen }) != gen)
		}

		// A's carrier write blocks; PingBusy later the watchdog reports it.
		stRoute(s, la, true)
		stRoute(s, lb, false)
		block[1].Store(true)
		if n, err := s.Write(stPattern(1000, 1000)); n != 1000 || err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(5 * time.Millisecond) // inside the 20 ms delay
		before, wakes := ackCount(2), pb.wakeCount()
		pa.set(func(f *stPort) { f.blocked = true })
		la.WriteBlocked(nil)
		if stLocked(s, func(st *stream) *lane { return st.ackLane }) != lb {
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

// TestStreamAckTriggers (§4.6): the urgent ACK triggers and the
// sender-side echo fact. The first in-order DATA after an attach is
// acknowledged at once although nothing was read, later DATA is not (L19);
// a duplicate of received bytes is answered at once (the sender may have
// missed an ACK); a FIN resent over another carrier after its delivery is
// acknowledged again with FIN_DELIVERED (L05); a lane's death re-ACKs at
// once on the survivor, which is woken (L11); a delayed ACK on a duty lane
// on which Retire was called leaves in that lane's next Fill — its writer
// drops the WakeAt timer when it writes the CLOSE that follows; a dialer
// stores an echoed epoch (fact factEcho) only when it is newer than the
// stored one and not newer than the published one.
func TestStreamAckTriggers(t *testing.T) {
	acks := func(l *lane) []stFrame { // the ACKs one Fill places now
		fs, b := stFill(l, time.Now())
		b.ReleaseRefs()
		var out []stFrame
		for _, f := range fs {
			if f.typ == wire.TypeAck {
				out = append(out, f)
			}
		}
		return out
	}
	s := stSession(stOpt{role: RolePassive})
	la, pa := stAddLane(s, 1, false)
	lb, pb := stAddLane(s, 2, false)
	pa.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
	pb.set(func(f *stPort) { f.srtt = 10 * time.Millisecond })
	s.mu.Lock()
	s.refreshOrderLocked(time.Now(), true)
	s.bumpAckLocked(true)
	s.mu.Unlock()
	if d := stLocked(s, func(st *stream) *lane { return st.ackLane }); d != la {
		t.Fatal("the lowest-srtt lane does not hold the ACK duty")
	}
	acks(la)
	acks(lb)
	if err := la.Data(nil, 0, stPattern(0, 100), nil); err != nil {
		t.Fatal(err)
	}
	if a := acks(la); len(a) != 1 || a[0].ack.Delivered != 0 {
		t.Fatalf("first DATA after an attach: ACKs %v, want one at once (L19)", a)
	}
	if err := lb.Data(nil, 100, stPattern(100, 100), nil); err != nil {
		t.Fatal(err)
	}
	if a := acks(la); len(a) != 0 {
		t.Fatalf("later DATA without a delivery: ACKs %v, want none (the urgent ACK is one-shot)", a)
	}
	if err := lb.Data(nil, 50, stPattern(50, 100), nil); err != nil {
		t.Fatal(err)
	}
	if a := acks(la); len(a) != 1 {
		t.Fatalf("duplicate DATA: ACKs %v, want one at once", a)
	}
	if err := stSendFin(la, 200); err != nil {
		t.Fatal(err)
	}
	stReadN(t, s, 200)
	if a := acks(la); len(a) != 1 || a[0].flags&wire.FlagAckFinDelivered == 0 {
		t.Fatalf("FIN delivered: ACKs %v, want one with FIN_DELIVERED", a)
	}
	if err := stSendFin(lb, 200); err != nil {
		t.Fatal(err)
	}
	if a := acks(la); len(a) != 1 || a[0].flags&wire.FlagAckFinDelivered == 0 || a[0].ack.Delivered != 200 {
		t.Fatalf("FIN resent after its delivery: ACKs %v, want ACK(200) with FIN_DELIVERED again (L05)", a)
	}
	acks(lb) // lb is idle
	w := pb.wakeCount()
	stKillLane(s, la)
	if pb.wakeCount() != w+1 {
		t.Fatal("the duty lane's death did not wake the survivor")
	}
	if a := acks(lb); len(a) != 1 || a[0].ack.Delivered != 200 {
		t.Fatalf("after the duty lane died: survivor ACKs %v, want the re-ACK (L11)", a)
	}
	stEnd(s, io.EOF)

	// A delayed ACK on a retiring duty lane.
	s = stSession(stOpt{role: RolePassive})
	l, _ := stAddLane(s, 1, false)
	if err := l.Data(nil, 0, stPattern(0, 100), nil); err != nil {
		t.Fatal(err)
	}
	acks(l)
	stReadN(t, s, 100) // arms the 20 ms ACK delay
	if a := acks(l); len(a) != 0 {
		t.Fatalf("ACKs %v before the ACK delay", a)
	}
	s.mu.Lock()
	l.retireCalled = true
	s.mu.Unlock()
	if a := acks(l); len(a) != 1 || a[0].ack.Delivered != 100 {
		t.Fatalf("delayed ACK on a retiring duty lane: ACKs %v, want ACK(100) before its CLOSE", a)
	}
	stEnd(s, errClosed)

	// Echo bounds (dialer; epochs 1–5 published).
	d := stSession(stOpt{})
	dl, _ := stAddLane(d, 1, true)
	d.mu.Lock()
	d.ctl.epoch = 5
	d.mu.Unlock()
	for _, c := range []struct {
		echo, want uint32
		fact       bool
	}{{7, 0, false}, {3, 3, true}, {2, 3, false}, {5, 5, true}} {
		var p [wire.AckLen]byte
		wire.PutAck(p[:], &wire.Ack{Window: 1 << 20, EpochEcho: c.echo})
		if err := dl.Control(nil, stCtlHeader(wire.TypeAck, 0, wire.AckLen), p[:]); err != nil {
			t.Fatal(err)
		}
		d.mu.Lock()
		in, fact := d.st.echoIn, d.takeFactsLocked()&factEcho != 0
		d.mu.Unlock()
		if in != c.want || fact != c.fact {
			t.Fatalf("echo %d: stored %d (fact %v), want %d (fact %v)", c.echo, in, fact, c.want, c.fact)
		}
	}
	stEnd(d, errClosed)
}

// stSentSender returns a dialer of the given mode with n lanes (all data
// lanes in bond mode, lane 1 active otherwise) that has written and sent
// total bytes; the peer window covers them.
func stSentSender(t testing.TB, mode Mode, n, total int) (*Session, []*lane, []*stPort) {
	t.Helper()
	s := stSession(stOpt{mode: mode, window: 8 << 20})
	var ls []*lane
	var ps []*stPort
	for i := range n {
		l, p := stAddLane(s, uint32(i+1), mode == ModeBond || i == 0)
		ls, ps = append(ls, l), append(ps, p)
	}
	s.mu.Lock()
	s.peerWindowLocked(8 << 20)
	s.mu.Unlock()
	if k, err := s.Write(stPattern(0, total)); k != total || err != nil {
		t.Fatalf("Write = (%d, %v)", k, err)
	}
	for sent := 0; sent < total; {
		moved := 0
		for _, l := range ls {
			fs, b := stFill(l, time.Now())
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
	s, ls, _ := stSentSender(t, ModeBond, 8, total)
	if err := stSendAck(ls[0], 0, 5, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := stSendAck(ls[1], 0, 4, 1<<20); err != nil {
		t.Fatalf("a lower ACK on another carrier is not a violation: %v", err)
	}
	if err := stSendAck(ls[2], 0, 5, 1<<20); err != nil {
		t.Fatal(err)
	}
	if b := stLocked(s, func(st *stream) uint64 { return st.sBase }); b != 5 {
		t.Fatalf("sBase = %d after ACK 5, a late 4 and a duplicate 5; want 5", b)
	}

	for run := range 20 {
		s, ls, _ := stSentSender(t, ModeBond, 8, total)
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
					if err := stSendAck(l, 0, d, w); err != nil {
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
		got := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.sBase, st.peerLimit} })
		if got[0] != maxDel.Load() || got[1] != max(maxEdge.Load(), 8<<20) {
			t.Fatalf("run %d: front %d edge %d, want the maxima %d and %d", run, got[0], got[1], maxDel.Load(), max(maxEdge.Load(), 8<<20))
		}
		for _, l := range ls {
			if len(l.infl.s) > 0 && l.infl.s[0].off < got[0] {
				t.Fatalf("run %d: lane %d keeps in-flight bytes below the front", run, l.id)
			}
		}
		stEnd(s, errClosed)
	}
}

// TestDuplicateAcksNoRetransmit_L13: a hundred identical ACKs below sNext
// trigger no retransmission (rendr has no duplicate-ACK fast retransmit;
// stream carriers are reliable).
func TestDuplicateAcksNoRetransmit_L13(t *testing.T) {
	s, ls, _ := stSentSender(t, ModeSelector, 2, 1<<20)
	for i := range 100 {
		if err := stSendAck(ls[i%2], 0, 300<<10, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range ls {
		fs, b := stFill(l, time.Now())
		b.ReleaseRefs()
		if n := stCount(fs, wire.TypeData); n != 0 {
			t.Fatalf("%d DATA frames after duplicate ACKs, want 0", n)
		}
	}
	st := stLocked(s, func(st *stream) [3]uint64 { return [3]uint64{st.sBase, st.retxBytes, st.retx.bytes()} })
	if st != [3]uint64{300 << 10, 0, 0} {
		t.Fatalf("sBase, retxBytes, queued = %v; want %d, 0, 0", st, 300<<10)
	}
	stEnd(s, errClosed)
}

// TestAckRegressionOnCarrierKills_L13 (P3): an ACK below the last one on
// the same carrier, or beyond what was sent, is a violation of that
// carrier only; the session state is unchanged and the session continues on
// another carrier.
func TestAckRegressionOnCarrierKills_L13(t *testing.T) {
	s, ls, _ := stSentSender(t, ModeBond, 3, 1<<20)
	front := func() uint64 { return stLocked(s, func(st *stream) uint64 { return st.sBase }) }
	if err := stSendAck(ls[0], 0, 500<<10, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := stSendAck(ls[0], 0, 400<<10, 1<<20); !errors.Is(err, errAckRegression) {
		t.Fatalf("regression on the same carrier = %v, want the regression violation", err)
	}
	if front() != 500<<10 {
		t.Fatalf("front %d after a rejected regression, want %d", front(), 500<<10)
	}
	if err := stSendAck(ls[1], 0, 400<<10, 1<<20); err != nil {
		t.Fatalf("a lower ACK from another carrier: %v", err)
	}
	if err := stSendAck(ls[1], 0, 600<<10, 1<<20); err != nil || front() != 600<<10 {
		t.Fatalf("ACK 600 KiB on carrier 2 = %v, front %d", err, front())
	}
	if err := stSendAck(ls[1], 0, 1<<20+10, 1<<20); !errors.Is(err, errAckBeyondSent) {
		t.Fatalf("ACK beyond sent = %v, want the violation", err)
	}
	if err := stSendAck(ls[2], wire.FlagAckFinDelivered, 700<<10, 1<<20); !errors.Is(err, errFinDeliveredEarly) {
		t.Fatalf("FIN_DELIVERED without our FIN = %v, want the violation", err)
	}
	if front() != 600<<10 {
		t.Fatalf("front %d after rejected ACKs, want %d", front(), 600<<10)
	}
	// The session continues on the third carrier.
	if err := stSendAck(ls[2], 0, 1<<20, 1<<20); err != nil || front() != 1<<20 {
		t.Fatalf("ACK on the surviving carrier = %v, front %d", err, front())
	}
	if u := s.env.Carrier.Budget.Used(); u != 0 {
		t.Fatalf("%d bytes of send chunks held with everything acknowledged (idle drop)", u)
	}
	stEnd(s, errClosed)
}

// TestConflictingDuplicateKillsCarrier_L13: overlapping DATA is compared
// byte for byte wherever it overlaps bytes still held (the in-order queue,
// the in-order tail, out-of-order segments; copied runs and referenced
// buffers alike). A mismatch is a violation of the delivering carrier, the
// first copy stays authoritative, and the rejected frame's buffer is
// released; an agreeing overlap is trimmed and accepted.
func TestConflictingDuplicateKillsCarrier_L13(t *testing.T) {
	s := stSession(stOpt{role: RolePassive})
	l1, _ := stAddLane(s, 1, false)
	l2, _ := stAddLane(s, 2, false)
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
	mustOK("[0,100)", l1.Data(nil, 0, stPattern(0, 100), nil))
	used := budget.Used()
	mustConflict("duplicate [0,100) with a flipped byte", l2.Data(nil, 0, flip(stPattern(0, 100), 50), nil))
	mustOK("agreeing duplicate", l2.Data(nil, 0, stPattern(0, 100), nil))
	// Overlap with the in-order tail.
	mustConflict("[80,150) flipped in the overlap", l2.Data(nil, 80, flip(stPattern(80, 70), 10), nil))
	mustOK("[80,150) agreeing", l2.Data(nil, 80, stPattern(80, 70), nil))
	// Out-of-order overlap.
	mustOK("[300,400)", l1.Data(nil, 300, stPattern(300, 100), nil))
	mustConflict("[350,450) flipped at 360", l2.Data(nil, 350, flip(stPattern(350, 100), 10), nil))
	mustOK("[350,450) agreeing", l2.Data(nil, 350, stPattern(350, 100), nil))
	// Referenced (≥ 16 KiB) buffers.
	big := stPattern(1000, 32<<10)
	mustOK("[1000,+32K) by reference", stDeliverData(l1, 1000, big))
	before := budget.Used()
	mustConflict("big duplicate flipped at 20K", stDeliverData(l2, 1000, flip(big, 20<<10)))
	if budget.Used() != before {
		t.Fatalf("a rejected big frame kept %d bytes of buffer", budget.Used()-before)
	}
	if used > before {
		t.Fatal("budget shrank unexpectedly")
	}
	// The gap [150,300) and [450,1000) arrive: everything is contiguous.
	mustOK("[150,300)", l1.Data(nil, 150, stPattern(150, 150), nil))
	mustOK("[450,1000)", l1.Data(nil, 450, stPattern(450, 550), nil))
	want := stPattern(0, 1000+32<<10)
	got := stReadN(t, s, 500)
	if !bytes.Equal(got, want[:500]) {
		t.Fatal("first copies not authoritative")
	}
	// Consumed bytes are not compared any more; held ones still are.
	mustOK("overlap of consumed bytes with a flip below rRead", l2.Data(nil, 400, flip(stPattern(400, 200), 5), nil))
	mustConflict("flip in the held part", l2.Data(nil, 400, flip(stPattern(400, 200), 150), nil))
	rest := stReadN(t, s, len(want)-500)
	if !bytes.Equal(rest, want[500:]) {
		t.Fatal("stream corrupted after rejected duplicates")
	}
	stEnd(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}
