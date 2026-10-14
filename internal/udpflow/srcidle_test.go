package udpflow

// The idle release of a listening socket's receive extras (M5 work item
// srcidle; plan:774; M5 design R1-4 and R1-5 rule 3 as the delegate's F-1
// decision applies them to the passive Source): the Source reads rendr's
// own socket through the dialer reader's udpsocket.Reader (here its seam,
// fakeReader, the same four-state word), and an idle Source returns its
// extra read slots and its Batch within 2 × batchIdleRelease of its last
// datagram and waits at depth 1 with slot 0 uncharged, as at M4.

import (
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// srcHold is what a seam Source of depth 32 holds while it reads: its 31
// extra slots on the Budget and its Batch in Stages (R1-4 rule 2, R1-5).
func srcHold(env *carrier.Env) (budget, stages int64) {
	return 31 * slotBytes(env, seamDgram), 32 * batchMsgBytes
}

// heldBytes names what env's accounts hold, for failure messages.
func heldBytes(env *carrier.Env) string {
	slot := slotBytes(env, seamDgram)
	b, s := env.Budget.Used(), env.Stages.Used()
	return fmt.Sprintf("Budget %d (%d read slots of %d B), Stages %d (%d Batch messages of %d B)",
		b, b/slot, slot, s, s/batchMsgBytes, batchMsgBytes)
}

// idlePeriod sets batchIdleRelease to d for the Sources a test creates and
// restores it when the test ends (no udpflow test runs in parallel).
func idlePeriod(t *testing.T, d time.Duration) {
	t.Helper()
	prev := batchIdleRelease
	batchIdleRelease = d
	t.Cleanup(func() { batchIdleRelease = prev })
}

// TestIdlePacketListenerBufferedBytesZeroSeam_plan774 (plan:774; F-1;
// R1-4, R1-5 rule 3): the seam half of the root package's
// TestIdlePacketListenerBufferedBytesZero_plan774, on every OS. A Source
// over a batching socket (depth 32) reads with its 31 extra slots and its
// Batch charged and keeps them across short parks; once its read stayed
// parked for a whole batchIdleRelease the idle release takes them by CAS
// (fakeReader.TryRelease) and returns them: BufferedBytes exactly 0 within
// 2 × batchIdleRelease of the last datagram (or of its start, if it never
// read one), with no flow open and the Source alive, and not before a
// whole period. The parked read then moves the next datagram alone, into
// slot 0, and the read after it is at depth 32 again (straight back to D:
// a burst moves in one call again); junk counts as traffic and is released
// the same way; datagrams keep their order and bytes across every release.
func TestIdlePacketListenerBufferedBytesZeroSeam_plan774(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		hb, hs := srcHold(env)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		synctest.Wait()
		rd := c.reader()
		held := func(what string) {
			t.Helper()
			if b, s := env.Budget.Used(), env.Stages.Used(); b != hb || s != hs {
				t.Fatalf("%s: %s, want the read's extras held (Budget %d, Stages %d)", what, heldBytes(env), hb, hs)
			}
		}
		idle := func(what string) {
			t.Helper()
			if u := buffered(env); u != 0 {
				t.Fatalf("%s: BufferedBytes %d, want 0 (plan:774): %s", what, u, heldBytes(env))
			}
		}
		held("stimulus: the first read waits")

		// A listening source that never read a datagram: not released
		// within a whole period, released within two.
		time.Sleep(batchIdleRelease)
		synctest.Wait()
		held("a listening source 1 × batchIdleRelease after its start")
		time.Sleep(batchIdleRelease)
		synctest.Wait()
		idle("a listening source without any datagram, 2 × batchIdleRelease after its start")
		if st := h.s.Stats(); st.Flows != 0 {
			t.Fatalf("Stats %+v: no flow expected", st)
		}
		if rd == nil {
			t.Fatal("the Source reads its socket without the reader's word (newSrcReader)")
		}
		if n, p := rd.releases.Load(), rd.Parks(); n != 1 || p != 1 || rd.Holding() {
			t.Fatalf("%d idle releases, %d parks, holding %v: want one release of a read that parked once", n, p, rd.Holding())
		}

		// Traffic: a flow's H1, then a burst of 32 PINGs.
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		fs := h.flows()
		if len(fs) != 1 {
			t.Fatalf("%d flows admitted, want 1", len(fs))
		}
		f := fs[0]
		readOne(t, f, time.Second)
		f.Admitted()
		held("after a datagram at depth 1: the read after it")
		var burst [][]byte
		for i := range 32 {
			burst = append(burst, dg(1, pingFrame(uint32(2+i))))
		}
		c.queue(from, burst...)
		synctest.Wait()
		last := time.Now()
		for i := range 32 {
			if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || pingSeq(b) != uint32(2+i) {
				t.Fatalf("burst datagram %d: event %d, seq %d", i, ev, pingSeq(b))
			}
		}
		offered, got := c.reads()
		if !slices.Equal(offered, []int{32, 32, 32}) || !slices.Equal(got, []int{1, 32}) || rd.lost.Load() != 1 {
			t.Fatalf("reads offered %v, moved %v, %d woke without their extras: want the parked read to move the H1 alone after the release, then the burst in one call at depth 32",
				offered, got, rd.lost.Load())
		}
		held("after the burst")

		// Kept across short parks: half a period later nothing went back.
		time.Sleep(batchIdleRelease / 2)
		synctest.Wait()
		held("half a batchIdleRelease after the last datagram (R1-5)")
		f.Close()
		synctest.Wait()
		time.Sleep(time.Until(last.Add(2 * batchIdleRelease)))
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != 0 {
			t.Fatalf("Stats %+v: the flow closed", st)
		}
		idle("an idle listening source with no flow, 2 × batchIdleRelease after its last datagram")

		// Junk is traffic too: the source regrows, then releases again.
		dropped := h.s.Stats().Dropped
		c.queue(from, []byte("junk"))
		synctest.Wait()
		if d := h.s.Stats().Dropped; d != dropped+1 {
			t.Fatalf("Dropped %d → %d, want the junk datagram dropped", dropped, d)
		}
		held("after a junk datagram")
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		idle("2 × batchIdleRelease after a junk datagram")

		// The source serves on: a new flow, its H1 and a PING intact.
		c.queue(from, h1(2, wire.TypeOpen, 2), dg(2, pingFrame(2)))
		synctest.Wait()
		fs = h.flows()
		if len(fs) != 2 {
			t.Fatalf("%d flows admitted, want 2", len(fs))
		}
		readOne(t, fs[1], time.Second)
		fs[1].Admitted()
		if b, _, ev := readOne(t, fs[1], time.Second); ev != carrier.ReadOK || pingSeq(b) != 2 {
			t.Fatalf("flow 2's PING: event %d, seq %d", ev, pingSeq(b))
		}
		if r := env.Dgram.ChargeRefused.Load(); r != 0 {
			t.Fatalf("ChargeRefused %d, want 0", r)
		}
		h.shutdown()
		idle("after Done")
	})
}

// TestSourceIdleReleaseNeverWhileRouting (R1-5 rule 3; srcidle's mutant
// "released while a datagram is held"): the datagrams of one read wait in
// their slots while the reader routes them — here the first, a new flow's
// H1, stops the reader in Admit for three periods. The reader holds its
// extras (no parked read), so every firing of the idle release in between
// leaves them: nothing goes back, the 31 slots still hold their PINGs, and
// once Admit returns every datagram reaches the flow in order and intact,
// also after a second burst through the next read's slots. Only after that
// does the idle source return to 0.
func TestSourceIdleReleaseNeverWhileRouting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		slot := slotBytes(env, seamDgram)
		c := newFakeSock(32)
		s := newSeamSource(env, c, c, seamDgram, Limits{})
		admitted := make(chan *Flow, 1)
		resume := make(chan struct{})
		go s.Run(func(f *Flow) {
			admitted <- f
			<-resume // the reader routes the rest of its read once the test lets it
		})
		synctest.Wait()
		from := apOf(2, 1000)
		burst := [][]byte{h1(1, wire.TypeOpen, 1)}
		for i := range 31 {
			burst = append(burst, dg(1, pingFrame(uint32(2+i))))
		}
		c.queue(from, burst...)
		synctest.Wait()
		f := <-admitted
		h1Charge := env.Budget.Used() - 31*slot
		if h1Charge <= 0 {
			t.Fatalf("stimulus: %s, want the H1 in its inbox and 31 PINGs in their slots", heldBytes(env))
		}
		time.Sleep(3 * batchIdleRelease) // three firings while the read's datagrams wait in their slots
		synctest.Wait()
		rd := c.reader()
		if b, st := env.Budget.Used(), env.Stages.Used(); b != h1Charge+31*slot || st != 32*batchMsgBytes || rd.releases.Load() != 0 {
			t.Fatalf("three periods into the routing of a read: %s, %d idle releases; want the 31 slots and the Batch held",
				heldBytes(env), rd.releases.Load())
		}
		close(resume)
		synctest.Wait()
		var second [][]byte
		for i := range 32 {
			second = append(second, dg(1, pingFrame(uint32(33+i))))
		}
		c.queue(from, second...) // read into the slots the next read took
		synctest.Wait()
		readOne(t, f, time.Second)
		f.Admitted()
		for i := range 63 {
			if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || pingSeq(b) != uint32(2+i) {
				t.Fatalf("PING %d: event %d, seq %d", 2+i, ev, pingSeq(b))
			}
		}
		f.Close()
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		if u := buffered(env); u != 0 {
			t.Fatalf("2 × batchIdleRelease after the last datagram: BufferedBytes %d, want 0: %s", u, heldBytes(env))
		}
		s.Abort()
		<-s.Done()
	})
}

// TestSourceDoneWaitsForIdleRelease (srcidle: the reader's exit against an
// idle release in flight, reader.endIdle): an idle release that took a
// parked read's extras is held between its CAS and its release function
// (fakeWord.gate). Meanwhile a junk datagram wakes the read, which moves
// it alone, into slot 0, and the next read stays at depth 1: rd refuses
// new extras while the release still runs, and the Batch the reader took
// for them goes back with its charge. When the Source then stops, its
// reader waits for the release, so Done follows only once the extras and
// their charges are back: BufferedBytes is exactly 0 at Done.
func TestSourceDoneWaitsForIdleRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		hb, hs := srcHold(env)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		synctest.Wait()
		rd := c.reader()
		gate := make(chan struct{})
		var opened sync.Once
		open := func() { opened.Do(func() { close(gate) }) }
		defer h.shutdown()
		defer open()
		rd.gate.Store(&gate)
		time.Sleep(2 * batchIdleRelease) // the release's CAS: the timer waits at the gate
		synctest.Wait()
		if b, s := env.Budget.Used(), env.Stages.Used(); rd.Holding() || rd.Held() || rd.releases.Load() != 0 || b != hb || s != hs {
			t.Fatalf("stimulus: holding %v, %d releases, %s; want a release in flight over the parked read's extras",
				rd.Holding(), rd.releases.Load(), heldBytes(env))
		}
		dropped := h.s.Stats().Dropped
		c.queue(apOf(2, 1000), []byte("junk"))
		synctest.Wait()
		offered, got := c.reads()
		if d := h.s.Stats().Dropped; d != dropped+1 || !slices.Equal(offered, []int{32, 1}) || !slices.Equal(got, []int{1}) {
			t.Fatalf("Dropped %d → %d, reads offered %v, moved %v: want the junk moved alone, then a read at depth 1 while the release runs",
				dropped, d, offered, got)
		}
		if b, s := env.Budget.Used(), env.Stages.Used(); b != hb || s != hs {
			t.Fatalf("a refused Hold kept a charge: %s, want only the extras in flight (Budget %d, Stages %d)", heldBytes(env), hb, hs)
		}
		h.s.Abort()
		synctest.Wait()
		select {
		case <-h.s.Done():
			t.Fatalf("Done before the idle release in flight returned the extras: %s", heldBytes(env))
		default:
		}
		open()
		synctest.Wait()
		<-h.s.Done()
		if u := buffered(env); u != 0 || rd.releases.Load() != 1 {
			t.Fatalf("at Done: BufferedBytes %d (%s), %d releases; want 0 after one release", u, heldBytes(env), rd.releases.Load())
		}
	})
}

// TestSourceIdleReleaseRace (R1-5 rule 3 against wakes; -race): with a
// 200-µs period the idle release races the reader's wakes on real
// goroutines — bursts of 1 … 8 PINGs with short pauses between some of
// them. Every datagram reaches the flow once, in order and intact; the
// release both won (releases) and was followed by reads that found their
// extras taken (lost); nothing stays charged after Done.
func TestSourceIdleReleaseRace(t *testing.T) {
	idlePeriod(t, 200*time.Microsecond)
	env := testEnv(1 << 30)
	c := newFakeSock(8)
	h := newFHarness(t, env, Limits{}, c, seamDgram)
	from := apOf(2, 1000)
	c.queue(from, h1(1, wire.TypeOpen, 1))
	var f *Flow
	for deadline := time.Now().Add(5 * time.Second); f == nil; time.Sleep(time.Millisecond) {
		if fs := h.flows(); len(fs) > 0 {
			f = fs[0]
		} else if time.Now().After(deadline) {
			t.Fatal("no flow admitted")
		}
	}
	readOne(t, f, 5*time.Second)
	f.Admitted()
	const rounds = 3000
	seq := uint32(2)
	for round := range rounds {
		n := 1 + round%8
		ds := make([][]byte, n)
		for i := range ds {
			ds[i] = dg(1, pingFrame(seq+uint32(i)))
		}
		c.queue(from, ds...)
		for i := range n {
			if b, _, ev := readOne(t, f, 5*time.Second); ev != carrier.ReadOK || pingSeq(b) != seq+uint32(i) {
				t.Fatalf("round %d, PING %d: event %d, seq %d", round, seq+uint32(i), ev, pingSeq(b))
			}
		}
		seq += uint32(n)
		if round%4 == 0 {
			time.Sleep(time.Duration(round%3) * 400 * time.Microsecond)
		}
	}
	rd := c.reader()
	t.Logf("%d rounds: %d idle releases, %d reads woke without their extras", rounds, rd.releases.Load(), rd.lost.Load())
	if rd.releases.Load() == 0 || rd.lost.Load() == 0 {
		t.Fatalf("stimulus: %d idle releases, %d reads that lost their extras; want both", rd.releases.Load(), rd.lost.Load())
	}
	f.Close()
	h.shutdown()
	if u := buffered(env); u != 0 {
		t.Fatalf("after Done: BufferedBytes %d: %s", u, heldBytes(env))
	}
}

// TestSourceIdleRegrowZeroAllocs (R1-5 rules 1 and 3; srcidle's mutant
// "regrow allocating"; the non-race lane asserts): an idle release and the
// regrow after it allocate nothing — the parked read's extras go back to
// the Source's pools (the Batch to s.wpool, the slots to DBufs), the read
// moves its datagram into slot 0, and the read after it at depth 32 takes
// them from those pools again.
func TestSourceIdleRegrowZeroAllocs(t *testing.T) {
	env := testEnv(1 << 30)
	hb, hs := srcHold(env)
	c := &loopSock{max: 32, from: apOf(2, 1000), ds: [][]byte{[]byte("junk")}}
	s := newSeamSource(env, c, c, seamDgram, Limits{})
	r := &reader{s: s}
	r.rd = newSrcReader(s.bio, r.releaseIdle) // no timer: the test parks and releases
	lr := r.rd.(*loopReader)
	cycle := func() {
		lr.releaseNext = true
		if !r.readOwned() || r.held { // parked a whole period: released; the datagram into slot 0
			t.Fatalf("the read after the release: held %v", r.held)
		}
		if !r.readOwned() || !r.held { // traffic: at depth 32 again
			t.Fatalf("the read after a datagram at depth 1: held %v", r.held)
		}
	}
	if !r.readOwned() || !r.held {
		t.Fatal("the first read did not hold its extras")
	}
	runtime.GC() // before the warm-up, never inside the window (pool victim caches)
	for range 10 {
		cycle()
	}
	if a := testing.AllocsPerRun(1000, cycle); a != 0 && !raceEnabled {
		t.Fatalf("%v allocations per idle release and regrow", a)
	}
	if b, st := env.Budget.Used(), env.Stages.Used(); b != hb || st != hs {
		t.Fatalf("after the regrows: %s, want the extras held once (Budget %d, Stages %d)", heldBytes(env), hb, hs)
	}
	if n := lr.releases.Load(); n < 1010 {
		t.Fatalf("stimulus: %d idle releases", n)
	}
	r.exit()
	<-s.Done()
	if u := buffered(env); u != 0 {
		t.Fatalf("after the end: BufferedBytes %d: %s", u, heldBytes(env))
	}
}

// TestFlowOwnedSocketIdleRelease_plan774 (plan:774; F-1; R1-5 rule 3):
// the real-socket row of the idle release, over rendr's own loopback
// socket and the production reader (udpsocket.Reader; batching on Linux
// amd64/arm64 — elsewhere the socket reads one datagram per call and
// holds nothing at any time). With a 200-ms period, a source that served
// a flow returns to BufferedBytes 0 within 2 × the period of its last
// datagram (plus this row's scheduling allowance), then serves the next
// datagrams intact — read at depth 1, then at D again — and returns to 0
// once more.
func TestFlowOwnedSocketIdleRelease_plan774(t *testing.T) {
	const period, slack = 200 * time.Millisecond, time.Second
	idlePeriod(t, period)
	rs := newRealSource(t, 1232)
	used := func() int64 { return rs.env.Budget.Used() + rs.env.Stages.Used() }
	zero := func(what string, last time.Time) {
		t.Helper()
		for used() != 0 {
			if time.Since(last) > 2*period+slack {
				t.Fatalf("%s: BufferedBytes %d (Budget %d, Stages %d) %v after the last datagram, want 0 within 2 × %v",
					what, used(), rs.env.Budget.Used(), rs.env.Stages.Used(), time.Since(last).Round(time.Millisecond), period)
			}
			time.Sleep(time.Millisecond)
		}
	}
	const id = 0x7a
	rs.send(h1(id, wire.TypeOpen, 1))
	f := rs.flow()
	if _, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK {
		t.Fatalf("H1: event %d", ev)
	}
	f.Admitted()
	ping := func(seq uint32) time.Time {
		t.Helper()
		rs.send(dg(id, pingFrame(seq)))
		if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || pingSeq(b) != seq {
			t.Fatalf("PING %d: event %d, seq %d", seq, ev, pingSeq(b))
		}
		return time.Now()
	}
	var last time.Time
	for i := range 8 {
		last = ping(uint32(2 + i))
	}
	zero("a source with a flow after its last datagram", last)
	for i := range 8 {
		last = ping(uint32(10 + i))
	}
	zero("the same source after more datagrams", last)
	if st := rs.s.Stats(); st.Flows != 1 || st.InboxDrops != 0 || st.Dropped != 0 {
		t.Fatalf("Stats %+v", st)
	}
	if r := rs.env.Dgram.ChargeRefused.Load(); r != 0 {
		t.Fatalf("ChargeRefused %d", r)
	}
}
