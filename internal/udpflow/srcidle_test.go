package udpflow

// The idle release of a listening socket's receive extras (M5 work item
// srcidle; plan:774; M5 design R1-4 and R1-5 rule 3 as the delegate's F-1
// decision applies them to the passive Source): the Source reads rendr's
// own socket through the dialer reader's udpsocket.Reader (here mostly its
// seam, fakeReader, the same four-state word; the production Reader in
// TestSourceIdleReleaseProductionReader and the Linux real-socket rows),
// and an idle Source returns its extra read slots and its Batch within
// 2 × batchIdleRelease of its last datagram and waits at depth 1 with
// slot 0 uncharged, as at M4.

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
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
// the Source's pools (the Batch to s.rpool, the slots to DBufs), the read
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

// TestSourceIdleShedAcrossErrors (R1-5 rule 3 as srcidle applies it;
// review mutant X1): after an idle release the Source waits at depth 1
// until a datagram arrives, also across reads that end in an error. The
// parked read that lost its extras ends in a noise error, and so does the
// depth-1 read after it: neither takes the extras back — each next read is
// offered slot 0 alone and BufferedBytes stays 0 — and only a datagram
// brings the read after it back to depth 32 with its extras, which the
// idle release then returns once more.
func TestSourceIdleShedAcrossErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		hb, hs := srcHold(env)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		synctest.Wait()
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		rd := c.reader()
		if u := buffered(env); u != 0 || rd.releases.Load() != 1 {
			t.Fatalf("stimulus: BufferedBytes %d (%s), %d idle releases; want the parked read's extras released",
				u, heldBytes(env), rd.releases.Load())
		}
		for i := range 2 {
			c.failRead(carrier.ErrNoise) // the parked read, then the depth-1 read after it
			synctest.Wait()
			time.Sleep(backoffMax) // the noise backoff, then the next read
			synctest.Wait()
			offered, _ := c.reads()
			if st := h.s.Stats(); st.ReadErrors != uint64(i+1) || len(offered) != i+2 || offered[i+1] != 1 {
				t.Fatalf("noise error %d after the idle release: ReadErrors %d, reads offered %v; want the next read at depth 1",
					i+1, st.ReadErrors, offered)
			}
			if u := buffered(env); u != 0 {
				t.Fatalf("noise error %d after the idle release: BufferedBytes %d (%s), want 0 until a datagram arrives",
					i+1, u, heldBytes(env))
			}
		}
		c.queue(apOf(2, 1000), []byte("junk"))
		synctest.Wait()
		if offered, got := c.reads(); !slices.Equal(offered, []int{32, 1, 1, 32}) || !slices.Equal(got, []int{1}) {
			t.Fatalf("reads offered %v, moved %v: want the junk moved by the depth-1 read and the read after it at depth 32",
				offered, got)
		}
		if b, s := env.Budget.Used(), env.Stages.Used(); b != hb || s != hs {
			t.Fatalf("after a datagram: %s, want the extras held again (Budget %d, Stages %d)", heldBytes(env), hb, hs)
		}
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		if u := buffered(env); u != 0 || rd.releases.Load() != 2 {
			t.Fatalf("2 × batchIdleRelease after the junk: BufferedBytes %d (%s), %d idle releases; want 0 after a second release",
				u, heldBytes(env), rd.releases.Load())
		}
	})
}

// TestSourceIdleTimerStopsWhenIdle (R1-5 rule 3: the timer is re-armed at
// a firing only while extras are held; review mutant X2): once the idle
// release returned a listening source's extras its timer stays stopped —
// no firing (fakeWord.holdings: only a firing calls Holding) in five
// periods — until a datagram brings the extras back. That re-arms it, the
// extras go back two periods later, and the timer stops again.
func TestSourceIdleTimerStopsWhenIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		hb, hs := srcHold(env)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		synctest.Wait()
		rd := c.reader()
		quiet := func(what string, releases uint64) {
			t.Helper()
			n := rd.holdings.Load()
			time.Sleep(5 * batchIdleRelease)
			synctest.Wait()
			if m := rd.holdings.Load(); m != n || rd.releases.Load() != releases || buffered(env) != 0 {
				t.Fatalf("%s: %d Holding calls (timer firings) in 5 idle periods, %d idle releases, BufferedBytes %d; want a stopped timer, %d releases and 0",
					what, m-n, rd.releases.Load(), buffered(env), releases)
			}
		}
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		if rd.releases.Load() != 1 || rd.holdings.Load() == 0 {
			t.Fatalf("stimulus: %d idle releases after %d Holding calls; want the first read's extras released by the timer",
				rd.releases.Load(), rd.holdings.Load())
		}
		quiet("an idle listening source", 1)
		c.queue(apOf(2, 1000), []byte("junk"))
		synctest.Wait()
		if b, s := env.Budget.Used(), env.Stages.Used(); b != hb || s != hs {
			t.Fatalf("after a datagram: %s, want the extras held again (Budget %d, Stages %d)", heldBytes(env), hb, hs)
		}
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		quiet("idle again after a datagram", 2)
	})
}

// TestSourceReadBatchOfDepth (R1-5 rules 1 and 4, R1-6; srcidle review):
// a Source over a socket of MaxBatch 64 reads at depth 32 — at most 32
// datagrams per call — with a Batch of 32 messages, its depth's class, not
// the socket's 64: while it reads it holds 31 extra slots on the Budget
// and 32 × batchMsgBytes in Stages, as at MaxBatch 32, and the idle
// release returns them all. A flow's writes keep the socket's class: a
// WriteDatagrams of 40 leaves in one call with the writers' Batch,
// charged for that call only.
func TestSourceReadBatchOfDepth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		hb, hs := srcHold(env)
		c := newFakeSock(64)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		synctest.Wait()
		if d := h.s.readDepth(); d != 32 {
			t.Fatalf("depth %d at MaxBatch 64, want 32 (R1-6)", d)
		}
		held := func(what string) {
			t.Helper()
			if b, s := env.Budget.Used(), env.Stages.Used(); b != hb || s != hs {
				t.Fatalf("%s: %s, want 31 slots and a Batch of 32 messages (Budget %d, Stages %d)", what, heldBytes(env), hb, hs)
			}
		}
		held("the first read waits")
		ds := [][]byte{h1(1, wire.TypeOpen, 1)}
		for i := range 39 {
			ds = append(ds, dg(1, pingFrame(uint32(2+i))))
		}
		c.queue(apOf(2, 1000), ds...)
		synctest.Wait()
		fs := h.flows()
		if len(fs) != 1 {
			t.Fatalf("%d flows admitted, want 1", len(fs))
		}
		f := fs[0]
		readOne(t, f, time.Second)
		f.Admitted()
		for i := range 39 {
			if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || pingSeq(b) != uint32(2+i) {
				t.Fatalf("PING %d: event %d, seq %d", 2+i, ev, pingSeq(b))
			}
		}
		if _, got := c.reads(); !slices.Equal(got, []int{32, 8}) {
			t.Fatalf("reads moved %v, want the 40 datagrams in two calls of at most 32", got)
		}
		held("after a burst of 40")
		out := make([][]byte, 40)
		for i := range out {
			out[i] = make([]byte, wire.FlowHeaderLen+3)
		}
		if n, err := f.WriteDatagrams(out); n != 40 || err != nil {
			t.Fatalf("WriteDatagrams of 40: %d, %v", n, err)
		}
		c.mu.Lock()
		wsizes, wbatched := slices.Clone(c.wsizes), slices.Clone(c.wbatched)
		c.mu.Unlock()
		if !slices.Equal(wsizes, []int{40}) || !slices.Equal(wbatched, []bool{true}) {
			t.Fatalf("writes of %v (batched %v), want one call of 40 with the writers' Batch", wsizes, wbatched)
		}
		held("after the write: the writer's Batch charged for its call only")
		f.Close()
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		if u := buffered(env); u != 0 {
			t.Fatalf("2 × batchIdleRelease after the last datagram: BufferedBytes %d (%s), want 0", u, heldBytes(env))
		}
	})
}

// readerBatchIO is rendr's own socket (its udpsocket.Conn) presented to
// the Source as a socket in ModeBatch on every OS and read through the
// production udpsocket.Reader: where the Conn batches (Linux amd64/arm64)
// the Reader parks in the netpoller inside recvmmsg's callback; elsewhere
// it reads one datagram per call plainly, and the extras it holds count
// as parked while that read blocks (udpsocket.Reader.readPlain, the
// branch a socket takes after a fallback). Writes go to the Conn, which
// writes plainly where it does not batch. rd records the Reader.
type readerBatchIO struct {
	*udpsocket.Conn
	rd *atomic.Pointer[udpsocket.Reader]
}

func (readerBatchIO) Mode() udpsocket.Mode { return udpsocket.ModeBatch }

func (c readerBatchIO) newReader(release func(*udpsocket.Batch)) srcReader {
	r := udpsocket.NewReader(c.Conn, release)
	c.rd.Store(r)
	return r
}

// TestSourceIdleReleaseProductionReader (plan:774; F-1; R1-5 rule 3;
// srcidle review): the idle release with the production udpsocket.Reader —
// its four-state word, not the seam's copy (fakeWord) — over rendr's own
// loopback socket, on every OS (readerBatchIO). The Source reads at depth
// 32 and holds its extras, 31 slots and a Batch of 32 messages, from its
// first read on; once its read stayed parked for a whole period (400 ms
// here) the idle release takes them — the Reader no longer holds extras
// and counted parks while it held them — and BufferedBytes is exactly 0,
// within 2 × the period of its start or of its last datagram plus this
// row's scheduling allowance. The datagrams after a release arrive intact
// and in order, the Source holds its extras again (exact charges) and
// returns to 0 once more, and Done leaves nothing charged.
func TestSourceIdleReleaseProductionReader(t *testing.T) {
	const period, slack = 400 * time.Millisecond, time.Second
	idlePeriod(t, period)
	rs := newRealSourceIO(t, seamDgram, testEnv(1<<30), Limits{}, 0)
	c, ok := rs.s.bio.(*udpsocket.Conn)
	if !ok {
		t.Fatalf("the token's socket path is %T, want its udpsocket.Conn", rs.s.bio)
	}
	var rdp atomic.Pointer[udpsocket.Reader]
	rs.s.setIO(readerBatchIO{c, &rdp})
	env := rs.env
	hb, hs := srcHold(env)
	used := func() int64 { return env.Budget.Used() + env.Stages.Used() }
	var waits []string
	// released waits until the Reader, which has parked at least minParks
	// times holding its extras (it counts parks only then), holds none and
	// BufferedBytes is 0: the idle release took them.
	released := func(what string, last time.Time, minParks uint64) {
		t.Helper()
		for {
			rd := rdp.Load()
			if rd != nil && rd.Parks() >= minParks && !rd.Holding() && used() == 0 {
				break
			}
			if time.Since(last) > 2*period+slack {
				var parks uint64
				holding := false
				if rd != nil {
					parks, holding = rd.Parks(), rd.Holding()
				}
				t.Fatalf("%s: BufferedBytes %d (%s), Reader holding %v after %d parks with its extras, %v after the last datagram; want the extras released (0) within 2 × %v",
					what, used(), heldBytes(env), holding, parks, time.Since(last).Round(time.Millisecond), period)
			}
			time.Sleep(time.Millisecond)
		}
		waits = append(waits, fmt.Sprintf("%s: %v", what, time.Since(last).Round(time.Millisecond)))
	}
	start := time.Now()
	rs.start()
	released("a listening source that never read a datagram", start, 1)

	const id = 0x7b
	rs.send(h1(id, wire.TypeOpen, 1))
	f := rs.flow()
	if _, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK {
		t.Fatalf("H1: event %d", ev)
	}
	f.Admitted()
	seq := uint32(2)
	// pings sends PINGs, each read back intact, until the Source holds its
	// extras again (the read after a datagram is at depth 32), and returns
	// the time of the last.
	pings := func(what string) time.Time {
		t.Helper()
		deadline := time.Now().Add(realWait)
		for {
			rs.send(dg(id, pingFrame(seq)))
			if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || pingSeq(b) != seq {
				t.Fatalf("%s: PING %d: event %d, seq %d", what, seq, ev, pingSeq(b))
			}
			seq++
			last := time.Now()
			if b, s := env.Budget.Used(), env.Stages.Used(); b == hb && s == hs {
				return last
			}
			if last.After(deadline) {
				t.Fatalf("stimulus, %s: %s after %d PINGs, want the read's extras held (Budget %d, Stages %d)",
					what, heldBytes(env), seq-2, hb, hs)
			}
			time.Sleep(time.Millisecond) // the reader takes them back right after a datagram
		}
	}
	released("a source with a flow after its last datagram", pings("after the first release"), 1)
	released("the same source after more datagrams", pings("after the second release"), 1)
	if st := rs.s.Stats(); st.Flows != 1 || st.InboxDrops != 0 || st.Dropped != 0 {
		t.Fatalf("Stats %+v", st)
	}
	if r := env.Dgram.ChargeRefused.Load(); r != 0 {
		t.Fatalf("ChargeRefused %d", r)
	}
	f.Close()
	rs.s.Abort()
	select {
	case <-rs.s.Done():
	case <-time.After(realWait):
		t.Fatal("the source did not end")
	}
	if u := used(); u != 0 {
		t.Fatalf("after Done: BufferedBytes %d (%s)", u, heldBytes(env))
	}
	t.Logf("BufferedBytes 0 after the last datagram (or the start): %s", strings.Join(waits, "; "))
}

// defaultIdleRelease is batchIdleRelease as the package set it, before any
// test lowered it (idlePeriod).
var defaultIdleRelease = batchIdleRelease

// TestBatchIdleReleaseShared (srcidle review): the Source's idle release
// has the dialer reader's period — internal/carrier's batchIdleRelease,
// which that package's TestBatchIdleReleaseShared pins — and the root
// package's TestIdlePacketListenerBufferedBytesZero_plan774 bounds its
// waits by 2 × that period (its idleRelease): all three are 1 s (M5
// design R1-5 rule 3). A change of one fails here or there until the
// three agree again.
func TestBatchIdleReleaseShared(t *testing.T) {
	if defaultIdleRelease != time.Second {
		t.Fatalf("batchIdleRelease %v: internal/carrier's batchIdleRelease and the root package's idleRelease are 1 s; change the three together",
			defaultIdleRelease)
	}
}
