package session

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestStreamSpanList: add, trimBelow and takeFront keep the list ascending,
// coalesced and equal to a reference bitmap.
func TestStreamSpanList(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for run := range 200 {
		var l spanList
		ref := make([]bool, 512)
		check := func(what string) {
			t.Helper()
			var got []bool = make([]bool, len(ref))
			for i, sp := range l.s {
				if sp.n == 0 || (i > 0 && l.s[i-1].end() >= sp.off) {
					t.Fatalf("run %d %s: list %v not ascending and coalesced", run, what, l.s)
				}
				for x := sp.off; x < sp.end(); x++ {
					got[x] = true
				}
			}
			for i := range ref {
				if got[i] != ref[i] {
					t.Fatalf("run %d %s: list %v differs from the reference at %d", run, what, l.s, i)
				}
			}
		}
		for range 30 {
			switch rng.IntN(5) {
			case 0, 1, 2:
				off, n := uint64(rng.IntN(480)), uint64(1+rng.IntN(32))
				l.add(off, n)
				for x := off; x < off+n; x++ {
					ref[x] = true
				}
				check("add")
			case 3:
				x := uint64(rng.IntN(512))
				l.trimBelow(x)
				for i := range x {
					ref[i] = false
				}
				check("trim")
			case 4:
				if len(l.s) > 0 {
					n := 1 + uint64(rng.IntN(int(l.s[0].n)))
					for x := l.s[0].off; x < l.s[0].off+n; x++ {
						ref[x] = false
					}
					l.takeFront(n)
					check("takeFront")
				}
			}
		}
	}
}

// TestStreamReorderAndRuns: a stream cut into frames of 1 B–40 KiB is
// delivered in a random order with random duplicates and overlapping
// re-cuts, half of it after a partial Read; the reader gets exactly the
// stream, small payloads share 16 KiB runs, and every buffer returns.
func TestStreamReorderAndRuns(t *testing.T) {
	for seed := range uint64(20) {
		rng := rand.New(rand.NewPCG(seed, 99))
		s := stSession(stOpt{role: RolePassive, window: 4 << 20})
		l, _ := stAddLane(s, 1, false)
		const total = 1 << 20
		want := stPattern(0, total)
		type fr struct{ off, n int }
		var frs []fr
		for off := 0; off < total; {
			n := 1 + rng.IntN(64)
			if rng.IntN(4) == 0 {
				n = 1 + rng.IntN(40<<10)
			}
			n = min(n, total-off)
			frs = append(frs, fr{off, n})
			off += n
		}
		// duplicates and re-cut overlaps
		for range len(frs) / 4 {
			off := rng.IntN(total - 1)
			frs = append(frs, fr{off, min(1+rng.IntN(20<<10), total-off)})
		}
		rng.Shuffle(len(frs), func(i, j int) { frs[i], frs[j] = frs[j], frs[i] })
		var got []byte
		for i, f := range frs {
			if err := stDeliverData(l, uint64(f.off), want[f.off:f.off+f.n]); err != nil {
				t.Fatalf("seed %d frame %d [%d,+%d): %v", seed, i, f.off, f.n, err)
			}
			if i == len(frs)/2 {
				if n := stLocked(s, func(st *stream) int { return int(st.rTail - st.rRead) }); n > 0 {
					got = append(got, stReadN(t, s, n)...)
				}
			}
		}
		segs := stLocked(s, func(st *stream) int { return st.inq.n })
		got = append(got, stReadN(t, s, total-len(got))...)
		if !bytes.Equal(got, want) {
			t.Fatalf("seed %d: reordered stream corrupted", seed)
		}
		if segs > 2*total/carrier.BigData+64 {
			t.Fatalf("seed %d: %d in-order segments for %d bytes: small payloads are not sharing runs", seed, segs, total)
		}
		st := stLocked(s, func(st *stream) [3]uint64 { return [3]uint64{st.rxBytes, uint64(len(st.ooq.s)), uint64(st.oooCap)} })
		if st != [3]uint64{total, 0, 0} {
			t.Fatalf("seed %d: rxBytes/ooq/oooCap = %v", seed, st)
		}
		stEnd(s, io.EOF)
		if u := s.env.Carrier.Budget.Used(); u != 0 {
			t.Fatalf("seed %d: Budget.Used = %d after the end", seed, u)
		}
	}
}

// TestStreamPassiveFirstFrame: a held passive lane writes nothing — not
// even an RST — until its first response frame exists; the OPEN_ACK or
// JOIN_ACK is then the first frame, confirms the lane (fact) and makes it
// eligible for the ACK duty; nothing follows a refusal.
func TestStreamPassiveFirstFrame(t *testing.T) {
	s := stSession(stOpt{role: RolePassive})
	l, _ := stAddLane(s, 1, true)
	s.mu.Lock()
	l.firstSent = false
	s.st.ackLane = nil
	s.ctl.rst = &wire.Rst{Code: wire.RstClosed}
	s.mu.Unlock()
	if fs, b := stFill(l, time.Now()); len(fs) != 0 {
		b.ReleaseRefs()
		t.Fatalf("held lane wrote %v before its first frame", fs)
	}
	s.mu.Lock()
	s.ctl.rst = nil
	l.first = firstFrame{t: wire.TypeJoinAck, joinAck: wire.JoinAck{Status: wire.StatusOK, RxNext: 7}}
	s.st.facts = 0
	s.mu.Unlock()
	fs, b := stFill(l, time.Now())
	b.ReleaseRefs()
	if len(fs) == 0 || fs[0].typ != wire.TypeJoinAck {
		t.Fatalf("frames %v, want JOIN_ACK first", fs)
	}
	if stCount(fs, wire.TypeAck) != 1 {
		t.Fatalf("frames %v: the confirmed lane did not take the ACK duty", fs)
	}
	if f := stLocked(s, func(st *stream) uint32 { return st.facts }); f&factLaneConfirmed == 0 || !l.firstSent || l.first.t != 0 {
		t.Fatalf("facts %#x firstSent %v: the lane was not confirmed", f, l.firstSent)
	}

	// A refusal (a parked OPEN carrier's verdict) is the only frame.
	r, _ := stAddLane(s, 2, false)
	s.mu.Lock()
	r.firstSent = false
	r.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusRejected, Code: 9, Msg: []byte("no")}}
	s.st.ackLane = r // even as the duty lane
	s.mu.Unlock()
	fs, b = stFill(r, time.Now())
	b.ReleaseRefs()
	if len(fs) != 1 || fs[0].typ != wire.TypeOpenAck {
		t.Fatalf("refusal frames %v, want only the OPEN_ACK", fs)
	}
	// Nothing follows it later either: no ACK duty, no RST.
	s.mu.Lock()
	s.bumpAckLocked(true)
	duty := s.st.ackLane
	s.ctl.rst = &wire.Rst{Code: wire.RstClosed}
	s.mu.Unlock()
	if duty == r {
		t.Fatal("a refused lane took the ACK duty")
	}
	if fs, b = stFill(r, time.Now()); len(fs) != 0 {
		t.Fatalf("frames %v after the refusal", fs)
	}
	b.ReleaseRefs()
	stEnd(s, errClosed)
}

// TestStreamCopyBudget (§3.2, P17, V3): one Data call copies less than
// 16 KiB under the session lock. A 64 KiB frame whose new bytes three held
// 1-byte segments split into a 16 KiB piece and three pieces of 16 KiB − 1
// has more new bytes than one call may copy: it is kept whole by reference,
// one segment that replaces the three held runs (nothing copied), rather
// than in pieces that would each pin its buffer. The stream reads back
// intact and every buffer returns to the Budget.
func TestStreamCopyBudget(t *testing.T) {
	s := stSession(stOpt{role: RolePassive})
	copies := stWatchCopies(t, s) // every call copies fewer than 16 KiB
	l, _ := stAddLane(s, 1, false)
	for _, off := range []uint64{16 << 10, 32 << 10, 48 << 10} {
		if err := l.Data(nil, off, stPattern(off, 1), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := stDeliverData(l, 0, stPattern(0, 64<<10)); err != nil {
		t.Fatal(err)
	}
	if _, last := copies(); last != 0 {
		t.Fatalf("the 64 KiB frame's Data call copied %d bytes, want none (kept by reference)", last)
	}
	if in, out := stSegs(s); len(in) != 1 || in[0] != 64<<10 || len(out) != 0 {
		t.Fatalf("segments in order %v, out of order %v; want the whole frame as one and none held", in, out)
	}
	if u := s.env.Carrier.Budget.Used(); u != stClass(64<<10) {
		t.Fatalf("Budget charge %d, want the frame's buffer alone (%d): the held runs were not released", u, stClass(64<<10))
	}
	if got := stReadN(t, s, 64<<10); !bytes.Equal(got, stPattern(0, 64<<10)) {
		t.Fatal("the split frame reads back corrupted")
	}
	stEnd(s, errClosed)
	if u := s.env.Carrier.Budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// TestStreamRescueClock (W7, §4.11): the rescue clock lastAdvance restarts
// at the Write commit that makes data outstanding (sBase == end before it)
// and at every sBase advance (ACK, rxNext); a commit while data is already
// outstanding, or an ACK that advances nothing, leaves it. In bond mode the
// outstanding-making commit rings the actor (an idle actor arms its rescue
// check); a selector commit does not.
func TestStreamRescueClock(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeBond} {
		synctest.Test(t, func(t *testing.T) {
			s := stSession(stOpt{mode: mode})
			l, _ := stAddLane(s, 1, true)
			s.mu.Lock()
			s.peerWindowLocked(1 << 20)
			s.mu.Unlock()
			rang := func() bool {
				select {
				case <-s.mb.bell:
					return true
				default:
					return false
				}
			}
			step := func(what string, fn func(), restart, ring bool) {
				t.Helper()
				time.Sleep(10 * time.Millisecond)
				rang()
				before := stLocked(s, func(st *stream) time.Time { return st.lastAdvance })
				fn()
				got := stLocked(s, func(st *stream) time.Time { return st.lastAdvance })
				if (restart && !got.Equal(time.Now())) || (!restart && !got.Equal(before)) {
					t.Fatalf("mode %d, %s: lastAdvance %v (was %v, now %v), want restarted %v", mode, what, got, before, time.Now(), restart)
				}
				if r := rang(); r != ring {
					t.Fatalf("mode %d, %s: actor rung %v, want %v", mode, what, r, ring)
				}
			}
			write := func() {
				if n, err := s.Write(make([]byte, 1000)); n != 1000 || err != nil {
					t.Fatalf("Write = (%d, %v)", n, err)
				}
			}
			step("commit making data outstanding", write, true, mode == ModeBond)
			step("commit with data outstanding", write, false, false)
			fs, b := stFill(l, time.Now())
			b.ReleaseRefs()
			if stCount(fs, wire.TypeData) == 0 {
				t.Fatal("nothing sent")
			}
			step("ACK advance", func() { _ = stSendAck(l, 0, 500, 1<<20) }, true, false)
			step("rxNext advance", func() {
				s.mu.Lock()
				_ = s.applyRxNextLocked(1500)
				s.mu.Unlock()
			}, true, false)
			step("ACK without an advance", func() { _ = stSendAck(l, 0, 1500, 1<<20) }, false, false)
			stEnd(s, errClosed)
		})
	}
}

// TestStreamEndWithUnreadData (§4.5): after a non-local end (an RST) with
// bytes buffered and no Read in progress, every receive buffer is released
// (inq, which covers [rRead, rTail), is empty, so rTail = rRead) and Read
// returns the end error — never the stale bytes, never (0, nil).
func TestStreamEndWithUnreadData(t *testing.T) {
	s, _, _ := stBufferedReceiver(t, stOpt{})
	stEnd(s, &AbortError{Code: AbortLinger, Remote: true})
	if u := s.env.Carrier.Budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
	if st := stLocked(s, func(st *stream) [3]uint64 { return [3]uint64{st.rRead, st.rTail, uint64(st.inq.n)} }); st[1] != st[0] || st[2] != 0 {
		t.Fatalf("rRead/rTail/inq segments after the end = %v: inq no longer covers [rRead, rTail)", st)
	}
	for range 2 {
		if n, err := s.Read(make([]byte, 100)); n != 0 || !errors.Is(err, ErrAborted) {
			t.Fatalf("Read after the RST with unread bytes = (%d, %v), want (0, *AbortError)", n, err)
		}
	}
}

// TestStreamOffsetExhaustion (L14 write side): a Write that would reserve
// past the offset limit returns *AbortError{AbortExhausted} without
// reserving, records the fact for the actor (one RST), and every later
// Write fails the same way; bytes below the limit were accepted.
func TestStreamOffsetExhaustion(t *testing.T) {
	const limit = 1 << 62
	s := stSession(stOpt{first: limit - 100, limit: limit})
	if n, err := s.Write(make([]byte, 60)); n != 60 || err != nil {
		t.Fatalf("Write below the limit = (%d, %v)", n, err)
	}
	n, err := s.Write(make([]byte, 60))
	var ae *AbortError
	if n != 0 || !errors.As(err, &ae) || ae.Code != AbortExhausted || ae.Remote || !errors.Is(err, ErrAborted) {
		t.Fatalf("Write past the limit = (%d, %v), want (0, *AbortError{Exhausted})", n, err)
	}
	st := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.resEnd, uint64(st.facts & factExhausted)} })
	if st[0] != limit-40 || st[1] == 0 {
		t.Fatalf("resEnd %d facts exhausted %d, want %d and set", st[0], st[1], uint64(limit-40))
	}
	if _, err := s.Write([]byte{1}); !errors.As(err, &ae) {
		t.Fatalf("Write after exhaustion = %v", err)
	}
	stEnd(s, ae)
}

// TestStreamBondWakePolicy (§4.11): demand-limited data wakes only the
// fastest healthy member; a backlog wakes members in srtt order until
// their spare capacity covers it; write-blocked and non-data lanes are
// skipped; WriteBlocked hands pending bytes to the other members.
func TestStreamBondWakePolicy(t *testing.T) {
	s := stSession(stOpt{mode: ModeBond, window: 8 << 20})
	var ls []*lane
	var ps []*stPort
	for i, rtt := range []time.Duration{30, 10, 20} {
		l, p := stAddLane(s, uint32(i+1), true)
		p.set(func(f *stPort) { f.srtt = rtt * time.Millisecond; f.capacity = 128 << 10 })
		ls, ps = append(ls, l), append(ps, p)
	}
	s.mu.Lock()
	s.peerWindowLocked(1 << 30)
	s.refreshOrderLocked(time.Now(), true)
	for _, l := range ls {
		l.idle = true
	}
	s.mu.Unlock()
	wakes := func() [3]int { return [3]int{ps[0].wakeCount(), ps[1].wakeCount(), ps[2].wakeCount()} }
	settle := func() {
		s.mu.Lock()
		for _, l := range ls {
			l.idle = true
		}
		s.mu.Unlock()
	}

	w0 := wakes()
	if _, err := s.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	if w := wakes(); w[1] != w0[1]+1 || w[0] != w0[0] || w[2] != w0[2] {
		t.Fatalf("demand-limited write woke %v (from %v), want only the 10 ms member", w, w0)
	}
	settle()
	w0 = wakes()
	if _, err := s.Write(make([]byte, 300<<10)); err != nil { // more than two members' spare capacity
		t.Fatal(err)
	}
	if w := wakes(); w[0] != w0[0]+1 || w[1] != w0[1]+1 || w[2] != w0[2]+1 {
		t.Fatalf("backlog woke %v (from %v), want every member", w, w0)
	}
	settle()
	ps[1].set(func(f *stPort) { f.blocked = true })
	w0 = wakes()
	if _, err := s.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	if w := wakes(); w[1] != w0[1] || w[2] != w0[2]+1 {
		t.Fatalf("with the fastest member write-blocked, woke %v (from %v), want the next one (20 ms)", w, w0)
	}
	settle()
	w0 = wakes()
	ls[1].WriteBlocked(nil)
	if w := wakes(); w[2] != w0[2]+1 {
		t.Fatalf("WriteBlocked did not hand the pending bytes to another member: %v (from %v)", w, w0)
	}
	if f := stLocked(s, func(st *stream) uint32 { return st.facts }); f&factWriteBlocked == 0 {
		t.Fatal("WriteBlocked recorded no fact for the actor")
	}
	stEnd(s, errClosed)
}

// TestStreamRescue (§4.11): the lane holding the stuck head is found, a
// rescue duplicates one segment from the front on another member (never on
// the holder), the receiver deduplicates it, and the front advances.
func TestStreamRescue(t *testing.T) {
	p := stNewPair(stOpt{mode: ModeBond, window: 4 << 20}, stOpt{mode: ModeBond, window: 4 << 20}, 2)
	msg := stPattern(0, 200<<10)
	if n, err := p.a.Write(msg); n != len(msg) || err != nil {
		t.Fatal(err)
	}
	// Member 1 pulls everything; its carrier stalls (frames never arrive).
	fs, b := stFill(p.al[0], time.Now())
	b.ReleaseRefs()
	if stCount(fs, wire.TypeData) == 0 {
		t.Fatal("member 1 pulled nothing")
	}
	p.a.mu.Lock()
	holder, sp, ok := p.a.rescueHolderLocked()
	if ok {
		p.a.st.rescue = rescueSlot{set: true, sp: sp, holder: holder}
		p.a.ctl.rescuedBase = p.a.st.sBase
		p.a.routingChangedLocked()
	}
	p.a.mu.Unlock()
	if !ok || holder != p.al[0] || sp.off != 0 || sp.n != chunkSize {
		t.Fatalf("rescueHolder = (%v, %+v, %v), want member 1 and the first segment", holder == p.al[0], sp, ok)
	}
	if fs, b := stFill(p.al[0], time.Now()); stCount(fs, wire.TypeData) != 0 {
		b.ReleaseRefs()
		t.Fatal("the stuck holder sent the rescue duplicate")
	} else {
		b.ReleaseRefs()
	}
	p.stall[0] = true // member 1's write is stuck: its frames never arrive
	p.pump(true)
	var dup *stFrame
	for i := range p.traceAB {
		if f := &p.traceAB[i]; f.typ == wire.TypeData && f.off == 0 {
			dup = f
		}
	}
	if dup == nil || !dup.retx || dup.n != chunkSize {
		t.Fatalf("no rescue duplicate of the head on member 2 (trace %v)", p.traceAB)
	}
	if got := stReadN(t, p.b, chunkSize); !bytes.Equal(got, msg[:chunkSize]) {
		t.Fatal("rescued head corrupted")
	}
	p.pump(true)
	if base := stLocked(p.a, func(st *stream) uint64 { return st.sBase }); base != chunkSize {
		t.Fatalf("front %d after the rescue, want %d", base, chunkSize)
	}
	if r := stLocked(p.a, func(st *stream) rescueSlot { return st.rescue }); r.set {
		t.Fatal("rescue slot not cleared after the duplicate was sent")
	}
	p.close(t)
}

// TestStreamCloseDiscards (§4.7): Close consumes the buffered bytes (they
// are acknowledged, not reported as discarded-after-close), bytes arriving
// later are consumed on arrival and reported, and the peer's FIN is
// delivered and acknowledged without a reader.
func TestStreamCloseDiscards(t *testing.T) {
	s := stSession(stOpt{role: RolePassive})
	l, _ := stAddLane(s, 1, false)
	if err := stDeliverData(l, 0, stPattern(0, 100<<10)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	st := stLocked(s, func(st *stream) [3]uint64 {
		return [3]uint64{st.rRead, st.delivered, stB2U(st.discardedAfterClose)}
	})
	if st != [3]uint64{100 << 10, 100 << 10, 0} {
		t.Fatalf("after Close rRead/delivered/discarded = %v, want the buffered bytes consumed silently", st)
	}
	if err := stDeliverData(l, 100<<10, stPattern(100<<10, 20<<10)); err != nil {
		t.Fatal(err)
	}
	f := stLocked(s, func(st *stream) uint32 { return st.facts })
	if !stLocked(s, func(st *stream) bool { return st.discardedAfterClose }) || f&factDiscardedAfterClose == 0 {
		t.Fatal("bytes after Close not reported as discarded")
	}
	if err := stSendFin(l, 120<<10); err != nil {
		t.Fatal(err)
	}
	fs, b := stFill(l, time.Now())
	b.ReleaseRefs()
	var ack *stFrame
	for i := range fs {
		if fs[i].typ == wire.TypeAck {
			ack = &fs[i]
		}
	}
	if ack == nil || ack.ack.Delivered != 120<<10 || ack.flags&wire.FlagAckFinDelivered == 0 {
		t.Fatalf("frames %v, want an ACK(120 KiB) with FIN_DELIVERED", fs)
	}
	if u := s.env.Carrier.Budget.Used(); u != 0 {
		t.Fatalf("discarded bytes still hold %d bytes of buffers", u)
	}
	stEnd(s, errClosed)
}

// TestStreamBudgetPoll (D16): a Write refused by the Runtime budget waits
// and re-checks every 20 ms without a waiter list; it proceeds at the
// first poll after memory was freed elsewhere.
func TestStreamBudgetPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := carrier.NewBudget(64 << 20)
		s := stSession(stOpt{budget: budget})
		budget.Acquire(budget.Max()) // another session holds everything
		start := time.Now()
		done := make(chan stIO, 1)
		go func() {
			n, err := s.Write(make([]byte, 1000))
			done <- stIO{n, err}
		}()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if len(done) != 0 {
			t.Fatal("Write proceeded without budget")
		}
		budget.Release(budget.Max()) // freed elsewhere: no wake reaches us
		r := <-done
		if r.n != 1000 || r.err != nil || time.Since(start) != 60*time.Millisecond {
			t.Fatalf("Write = (%d, %v) at %v, want (1000, nil) at the 60 ms poll", r.n, r.err, time.Since(start))
		}
		stEnd(s, errClosed)
	})
}

// TestStreamWriterHysteresis (D17): a Write blocked on a full send buffer
// is woken by ACKs only once at least min(256 KiB, W/4) of room is free.
func TestStreamWriterHysteresis(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const w = 1 << 20
		s := stSession(stOpt{window: w})
		l, _ := stAddLane(s, 1, true)
		s.mu.Lock()
		s.peerWindowLocked(w)
		s.mu.Unlock()
		if n, _ := s.Write(make([]byte, w)); n != w {
			t.Fatal("first window not accepted")
		}
		for fs, b := stFill(l, time.Now()); stCount(fs, wire.TypeData) > 0; fs, b = stFill(l, time.Now()) {
			b.ReleaseRefs()
		}
		done := make(chan stIO, 1)
		go func() {
			n, err := s.Write(make([]byte, 10))
			done <- stIO{n, err}
		}()
		synctest.Wait()
		_ = stSendAck(l, 0, w/4-1, w) // room one byte below the hysteresis
		synctest.Wait()
		if len(done) != 0 || !stLocked(s, func(st *stream) bool { return st.wwaiting }) {
			t.Fatal("writer woken below the hysteresis")
		}
		_ = stSendAck(l, 0, w/4, w)
		if r := <-done; r.n != 10 || r.err != nil {
			t.Fatalf("Write after room ≥ W/4 = (%d, %v)", r.n, r.err)
		}
		stEnd(s, errClosed)
	})
}

// TestStreamControlViolations: frames the stream must reject kill only
// their carrier; the state is unchanged.
func TestStreamControlViolations(t *testing.T) {
	pending := stSession(stOpt{role: RolePassive})
	pl, _ := stAddLane(pending, 1, false)
	pending.mu.Lock()
	pending.ctl.state = StatePending
	pending.mu.Unlock()
	if err := pl.Data(nil, 0, []byte{1}, nil); !errors.Is(err, errDataBeforeOpen) {
		t.Fatalf("DATA on a pending session = %v", err)
	}
	if err := stSendAck(pl, 0, 0, 1); !errors.Is(err, errDataBeforeOpen) {
		t.Fatalf("ACK on a pending session = %v", err)
	}
	var rp [wire.RstFixedLen]byte
	wire.PutRst(rp[:], &wire.Rst{Code: wire.RstWithdrawn})
	if err := pl.Control(nil, stCtlHeader(wire.TypeRst, 0, len(rp)), rp[:]); err != nil {
		t.Fatalf("RST (withdrawal) on a pending session = %v", err)
	}
	if r := stLocked(pending, func(st *stream) *wire.Rst { return st.rstIn }); r == nil || r.Code != wire.RstWithdrawn {
		t.Fatal("withdrawal RST not recorded")
	}

	s := stSession(stOpt{role: RolePassive, window: 256 << 10})
	l, _ := stAddLane(s, 1, false)
	if err := l.Data(nil, 256<<10-1, []byte{1, 2}, nil); !errors.Is(err, errWindow) {
		t.Fatalf("DATA across the edge = %v", err)
	}
	if err := l.Data(nil, 10, stPattern(10, 10), nil); err != nil {
		t.Fatal(err)
	}
	if err := stSendFin(l, 15); !errors.Is(err, errFinBelowData) {
		t.Fatalf("FIN below received data = %v", err)
	}
	if err := stSendFin(l, 300<<10); !errors.Is(err, errFinBeyondWindow) {
		t.Fatalf("FIN beyond the window = %v", err)
	}
	if err := stSendFin(l, 100); err != nil {
		t.Fatal(err)
	}
	if err := stSendFin(l, 101); !errors.Is(err, errFinConflict) {
		t.Fatalf("a second FIN at another offset = %v", err)
	}
	if err := stSendFin(l, 100); err != nil {
		t.Fatalf("the same FIN again = %v", err)
	}
	if err := l.Data(nil, 90, stPattern(90, 20), nil); !errors.Is(err, errDataBeyondFin) {
		t.Fatalf("DATA beyond the FIN = %v", err)
	}
	if err := l.Control(nil, stCtlHeader(wire.TypeOpenAck, 0, wire.OpenAckFixedLen), make([]byte, wire.OpenAckFixedLen)); !errors.Is(err, errUnexpectedFrame) {
		t.Fatalf("OPEN_ACK after establishment = %v", err)
	}
	// SCHED: stored newest-first on the passive, a violation on the dialer.
	sched := func(l *lane, epoch uint32, cause wire.SchedCause) error {
		var p [wire.SchedFixedLen + 4]byte
		n := wire.PutSched(p[:], &wire.Sched{Epoch: epoch, N: 1, IDs: [16]uint32{7}})
		return l.Control(nil, stCtlHeader(wire.TypeSched, uint8(cause), n), p[:n])
	}
	for _, e := range []uint32{3, 1, 2} {
		if err := sched(l, e, wire.SchedQuality); err != nil {
			t.Fatal(err)
		}
	}
	got := stLocked(s, func(*stream) wire.Sched { return s.ctl.schedIn })
	if got.Epoch != 3 || s.ctl.schedInCause != wire.SchedQuality || !s.ctl.schedInSet {
		t.Fatalf("stored SCHED epoch %d, want the newest (3)", got.Epoch)
	}
	d := stSession(stOpt{})
	dl, _ := stAddLane(d, 1, false)
	if err := sched(dl, 1, wire.SchedInitial); !errors.Is(err, errSchedOnDialer) {
		t.Fatalf("SCHED on the dialer = %v", err)
	}
	for _, x := range []*Session{pending, s, d} {
		stEnd(x, errClosed)
	}
}

// TestStreamApplyRxNext (§4.0): a JOIN/JOIN_ACK rxNext beyond what was
// sent is rejected without effect; a valid one trims and frees like an ACK
// and never touches the peer's window.
func TestStreamApplyRxNext(t *testing.T) {
	s, ls, _ := stSentSender(t, ModeSelector, 1, 300<<10)
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := s.st.peerLimit
	if err := s.applyRxNextLocked(300<<10 + 1); err == nil || s.st.sBase != 0 {
		t.Fatalf("rxNext beyond sent = %v (front %d), want an error and no change", err, s.st.sBase)
	}
	if err := s.applyRxNextLocked(200 << 10); err != nil || s.st.sBase != 200<<10 {
		t.Fatalf("rxNext 200 KiB = %v, front %d", err, s.st.sBase)
	}
	if s.st.peerLimit != limit || s.st.chunks.n != 2 || ls[0].infl.s[0].off != 200<<10 {
		t.Fatalf("rxNext changed the window (%d → %d) or did not trim/free (chunks %d, infl %v)", limit, s.st.peerLimit, s.st.chunks.n, ls[0].infl.s)
	}
	if err := s.applyRxNextLocked(100 << 10); err != nil || s.st.sBase != 200<<10 {
		t.Fatal("an older rxNext moved the front back")
	}
	s.endLocked(errClosed)
}

// TestStreamAckDuty (D5, §4.6): the duty stays on its lane while it
// qualifies, is not retiring and is not write-blocked; otherwise it moves
// to the lowest-srtt lane that is neither, then to a writable retiring
// one, then to a blocked one (not retiring first). Joining (dialer),
// CLOSE-sent and dead lanes never carry it; a bump re-chooses and wakes the
// chosen lane. WriteBlocked hands the duty to a writable lane — a retiring
// one if nothing better exists — never to another blocked one.
func TestStreamAckDuty(t *testing.T) {
	s := stSession(stOpt{})
	var ls []*lane
	var ps []*stPort
	for i, rtt := range []time.Duration{5, 10, 20, 30} {
		l, p := stAddLane(s, uint32(i+1), i == 0)
		p.set(func(f *stPort) { f.srtt = rtt * time.Millisecond })
		ls, ps = append(ls, l), append(ps, p)
	}
	duty := func() *lane { return stLocked(s, func(st *stream) *lane { return st.ackLane }) }
	bump := func() {
		s.mu.Lock()
		s.refreshOrderLocked(time.Now(), true)
		s.bumpAckLocked(true)
		s.mu.Unlock()
	}
	bump()
	if duty() != ls[0] {
		t.Fatal("the duty is not on the first qualifying lane")
	}
	s.mu.Lock()
	ls[0].retireCalled = true
	ls[1].state = LaneJoining
	s.mu.Unlock()
	w := ps[2].wakeCount()
	s.mu.Lock()
	ls[2].idle = true
	s.mu.Unlock()
	bump()
	if duty() != ls[2] || ps[2].wakeCount() != w+1 {
		t.Fatal("a retiring duty lane kept the duty over a qualifying lane, or the new one was not woken (a joining lane must be skipped)")
	}
	ps[2].set(func(f *stPort) { f.blocked = true })
	bump()
	if duty() != ls[3] {
		t.Fatal("the duty stayed on a write-blocked lane while another qualifies")
	}
	ps[3].set(func(f *stPort) { f.closeSent = true })
	bump()
	if duty() != ls[0] {
		t.Fatal("with a blocked lane and a writable retiring lane left, the duty must go to the writable one")
	}
	ps[0].set(func(f *stPort) { f.blocked = true })
	bump()
	if duty() != ls[2] {
		t.Fatal("with only blocked lanes left, the duty must prefer the one that is not retiring")
	}
	ps[2].set(func(f *stPort) { f.closeSent = true })
	bump()
	if duty() != ls[0] {
		t.Fatal("with only a blocked retiring lane left, it must carry the duty")
	}
	stKillLane(s, ls[0])
	if duty() != nil {
		t.Fatal("a dead or CLOSE-sent lane holds the duty")
	}
	stEnd(s, errClosed)

	// WriteBlocked on the duty lane A with B blocked too and C writable but
	// retiring: the duty moves to C (woken: it owes the ACK), not to B.
	s = stSession(stOpt{})
	ls, ps = ls[:0], ps[:0]
	for i, rtt := range []time.Duration{5, 10, 20} {
		l, p := stAddLane(s, uint32(i+1), i == 0)
		p.set(func(f *stPort) { f.srtt = rtt * time.Millisecond })
		ls, ps = append(ls, l), append(ps, p)
	}
	bump()
	s.mu.Lock()
	ls[2].retireCalled = true
	s.mu.Unlock()
	ps[0].set(func(f *stPort) { f.blocked = true })
	ps[1].set(func(f *stPort) { f.blocked = true })
	w = ps[2].wakeCount()
	ls[0].WriteBlocked(nil)
	if duty() != ls[2] || ps[2].wakeCount() != w+1 {
		t.Fatal("WriteBlocked left the duty behind blocked carriers although a writable (retiring) lane qualifies")
	}
	stEnd(s, errClosed)
}
