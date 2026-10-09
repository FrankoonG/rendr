package scenario

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// failoverBound bounds how long the echo may take to carry new data again
// after a fault on the active carrier (detection DeadMin 1 s + rejoin).
const failoverBound = 4 * time.Second

func TestEchoSinglePath(t *testing.T) {
	f := newFixture(t, "p1")
	c := f.mustDial(selector, dialOpts{target: echo()})
	r := echoRun(c, 2*time.Second, 2048, nil)
	if r.err != nil {
		t.Fatal(r.err)
	}
	// both directions of the echo crossed the session carrier
	if b := f.link("p1").stats().Session.Bytes; b < 2*r.sent {
		t.Fatalf("session carriers forwarded %d bytes for %d echoed", b, r.sent)
	}
	t.Logf("sent=%d maxStall=%s", r.sent, r.maxStall)
}

func TestSelectorPrefersLowestRTT(t *testing.T) {
	f := newFixture(t, "slow", "fast", "mid")
	f.link("slow").set(80*time.Millisecond, 0, 0)
	f.link("mid").set(30*time.Millisecond, 0, 0)
	f.link("fast").set(2*time.Millisecond, 0, 0)
	c := f.mustDial(selector, dialOpts{target: echo()})
	defer c.Close()
	if p := activePath(c); p != "fast" {
		t.Fatalf("active %q, want fast", p)
	}
}

// watchReplaced reports, on the returned channel, the first active subflow
// that differs from old (0 if none appeared within 5 s).
func watchReplaced(c net.Conn, old uint32) <-chan uint32 {
	ch := make(chan uint32, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if id, _ := activeSub(c); id != 0 && id != old {
				ch <- id
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		ch <- 0
	}()
	return ch
}

// testSelectorFailure applies fail to the link of the carrier that is active
// at fault time, while the echo keeps its load. It proves that the fault hit
// a session carrier, that the session replaced the active subflow, and that
// new data flowed again within failoverBound.
func testSelectorFailure(t *testing.T, fail func(l *link), happened func(s faultCounts) bool) {
	f := newFixture(t, "p1", "p2", "p3")
	for _, l := range f.links {
		l.set(3*time.Millisecond, 0, 0)
	}
	c := f.mustDial(selector, dialOpts{target: echo()})
	if id, _ := activeSub(c); id == 0 {
		t.Fatal("no active carrier after dial")
	}
	const rate, dur = 512, 6 * time.Second
	var victim string
	var victimID uint32
	var faultAt time.Time
	var replaced <-chan uint32
	r := echoRun(c, dur, rate, func() {
		victimID, victim = activeSub(c)
		if victim == "" {
			return
		}
		faultAt = time.Now()
		fail(f.link(victim))
		replaced = watchReplaced(c, victimID)
	})
	if victim == "" {
		t.Fatal("INVALID: no active carrier at fault time")
	}
	st := f.link(victim).stats().Session
	stimulus(t, happened(st), "fault on session carriers of %s: %+v", victim, st)
	if r.err != nil {
		t.Fatalf("after failing %s: %v (maxStall %s)", victim, r.err, r.maxStall)
	}
	if id := <-replaced; id == 0 {
		t.Fatalf("active subflow %d on %s was never replaced", victimID, victim)
	}
	rec, ok := r.resumedAfter(faultAt)
	t.Logf("failed %s, recovery=%s maxStall=%s", victim, rec, r.maxStall)
	if !ok || rec > failoverBound {
		t.Fatalf("new data flowed again after %s (ok=%v), want <= %s", rec, ok, failoverBound)
	}
	offeredLoad(t, r, rate, dur)
}

func TestSelectorBlackholeActive(t *testing.T) {
	testSelectorFailure(t, func(l *link) { l.setBlackhole(true) },
		func(s faultCounts) bool { return s.Dropped > 0 })
}
func TestSelectorCutActive(t *testing.T) {
	testSelectorFailure(t, func(l *link) { l.kill(); l.setRefuse(true) },
		func(s faultCounts) bool { return s.Killed > 0 })
}

// The corrupted byte always lands in the payload of a client-to-server DATA
// frame (midway runs right after a Write), so this covers the DATA CRC path
// only; control-frame corruption needs a frame-targeted control (M1b).
func TestSelectorCorruptActive(t *testing.T) {
	testSelectorFailure(t, func(l *link) { l.corruptNext() },
		func(s faultCounts) bool { return s.Corrupted > 0 })
}

func TestSelectorMigratesOnDegradation(t *testing.T) {
	f := newFixture(t, "p1", "p2")
	f.link("p1").set(2*time.Millisecond, 0, 0)
	f.link("p2").set(5*time.Millisecond, 0, 0)
	c := f.mustDial(selector, dialOpts{target: echo()})
	if p := activePath(c); p != "p1" {
		t.Fatalf("initial active %q", p)
	}
	const rate, dur = 256, 10 * time.Second
	var mu sync.Mutex
	var moved string
	r := echoRun(c, dur, rate, func() {
		f.link("p1").set(150*time.Millisecond, 0, 0)
		go func() {
			for i := 0; i < 60; i++ {
				time.Sleep(100 * time.Millisecond)
				if p := activePath(c); p == "p2" {
					mu.Lock()
					moved = p
					mu.Unlock()
					return
				}
			}
		}()
	})
	stimulus(t, f.link("p1").stats().Session.MaxDelay >= 150*time.Millisecond,
		"no session carrier on p1 was delayed 150 ms")
	if r.err != nil {
		t.Fatal(r.err)
	}
	offeredLoad(t, r, rate, dur)
	mu.Lock()
	defer mu.Unlock()
	if moved != "p2" {
		t.Fatalf("did not migrate off degraded p1 (active %q)", activePath(c))
	}
}

func TestBondAggregatesThroughput(t *testing.T) {
	f := newFixture(t, "p1", "p2", "p3")
	for _, l := range f.links {
		l.set(5*time.Millisecond, 0, 16) // 2 MB/s each
	}
	const n = 16 << 20
	t0 := time.Now()
	single := f.mustDial(selector, dialOpts{target: gen(n / 2)})
	if d := digest(single, n/2, time.Minute); d != digest(prng(7), n/2, 0) {
		t.Fatal("single-path payload mismatch")
	}
	singleRate := float64(n/2) / time.Since(t0).Seconds()
	single.Close()
	var before [3]int64
	for i, l := range f.links {
		before[i] = l.stats().Session.Bytes
	}
	t1 := time.Now()
	c := f.mustDial(bond, dialOpts{target: gen(n)})
	if d := digest(c, n, time.Minute); d != digest(prng(7), n, 0) {
		t.Fatal("bond payload mismatch")
	}
	bondRate := float64(n) / time.Since(t1).Seconds()
	c.Close()
	t.Logf("single %.1f MB/s, bond %.1f MB/s (x%.2f)", singleRate/1e6, bondRate/1e6, bondRate/singleRate)
	for i, l := range f.links {
		stimulus(t, l.stats().Throttled > 0, "%s was never rate limited", l.name)
		if carried := l.stats().Session.Bytes - before[i]; carried < n/10 {
			t.Errorf("bond: %s carried %d bytes, want >= %d (every carrier must carry data)", l.name, carried, n/10)
		}
	}
	// The ratio is a throughput assertion: it belongs to the non-race lane.
	if raceEnabled {
		t.Log("race detector on: bond/single ratio not asserted")
		return
	}
	if bondRate < 2*singleRate {
		t.Fatalf("bond x%.2f of single path", bondRate/singleRate)
	}
}

func TestBondSurvivesPathLoss(t *testing.T) {
	f := newFixture(t, "p1", "p2", "p3")
	for _, l := range f.links {
		l.set(5*time.Millisecond, 0, 24)
	}
	const n = 24 << 20
	c := f.mustDial(bond, dialOpts{target: gen(n)})
	go func() {
		time.Sleep(2 * time.Second)
		f.link("p2").setBlackhole(true)
		time.Sleep(time.Second)
		f.link("p3").kill()
		f.link("p3").setRefuse(true)
	}()
	if d := digest(c, n, time.Minute); d != digest(prng(7), n, 0) {
		t.Fatal("payload mismatch after path loss")
	}
	c.Close()
	stimulus(t, f.link("p2").stats().Session.Dropped > 0, "p2 blackhole dropped no session bytes")
	stimulus(t, f.link("p3").stats().Session.Killed > 0, "p3 had no session carrier to kill")
}

func TestBondReorderIntegrity(t *testing.T) {
	f := newFixture(t, "p1", "p2", "p3")
	f.link("p1").set(2*time.Millisecond, 1*time.Millisecond, 20)
	f.link("p2").set(25*time.Millisecond, 10*time.Millisecond, 20)
	f.link("p3").set(60*time.Millisecond, 20*time.Millisecond, 20)
	c := f.mustDial(bond, dialOpts{target: echo()})
	r := echoRun(c, 5*time.Second, 2048, nil)
	if r.err != nil {
		t.Fatal(r.err)
	}
}

func TestAllPathsDeadAborts(t *testing.T) {
	f := newFixture(t, "p1", "p2")
	c := f.mustDial(selector, dialOpts{target: echo()})
	for _, l := range f.links {
		l.setRefuse(true)
		l.kill()
	}
	stimulus(t, f.link("p1").stats().Session.Killed+f.link("p2").stats().Session.Killed > 0,
		"no session carrier was killed")
	t0 := time.Now()
	c.SetReadDeadline(t0.Add(tun.Orphan + 10*time.Second))
	buf := make([]byte, 10)
	_, err := c.Read(buf)
	notTimeout(t, err)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("want abort error, got %v", err)
	}
	if d := time.Since(t0); d > tun.Orphan+3*time.Second {
		t.Fatalf("abort took %s", d)
	}
}

func TestTargetDialFailure(t *testing.T) {
	f := newFixture(t, "p1")
	_, err := f.dial(selector, dialOpts{target: unreachable()})
	if !isTargetDialError(err) {
		t.Fatalf("want target dial error, got %v", err)
	}
}

// Twenty sessions half-close and finish cleanly; the server releases every
// session and target connection, and once the fixture is torn down the
// goroutine count returns to its settled pre-test baseline. The baseline is
// settled before the fixture exists, so the verdict does not depend on what
// earlier tests left behind or on test order.
func TestHalfCloseAndCleanFinish(t *testing.T) {
	const slack = 2 // a per-session leak over 20 sessions is far larger
	base := settledGoroutines()
	f := newFixture(t, "p1", "p2")
	for i := 0; i < 20; i++ {
		c := f.mustDial(bond, dialOpts{target: echo()})
		msg := bytes.Repeat([]byte{byte(i)}, 100000)
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("round %d: write: %v", i, err)
		}
		c.(interface{ CloseWrite() error }).CloseWrite()
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		got, err := io.ReadAll(c)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("round %d: err=%v len=%d", i, err, len(got))
		}
		c.Close()
		select {
		case <-sessionDone(c):
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: session did not finish", i)
		}
	}
	waitFor(10*time.Second, func() bool { return f.serverSessions() == 0 && f.far.open.Load() == 0 })
	if n := f.serverSessions(); n != 0 {
		t.Fatalf("server still holds %d sessions", n)
	}
	if n := f.far.open.Load(); n != 0 {
		t.Fatalf("server still holds %d target connections", n)
	}
	f.close()
	took, ok := waitFor(15*time.Second, func() bool { return runtime.NumGoroutine() <= base+slack })
	if !ok {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutines %d > settled base %d+%d after teardown\n%s", runtime.NumGoroutine(), base, slack, buf[:n])
	}
	t.Logf("goroutines back to %d (base %d) %s after teardown", runtime.NumGoroutine(), base, took.Round(time.Millisecond))
}

func TestConcurrentSessions(t *testing.T) {
	f := newFixture(t, "p1", "p2", "p3")
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := selector
			if i%2 == 0 {
				m = bond
			}
			c, err := f.dial(m, dialOpts{target: echo()})
			if err != nil {
				errs <- err
				return
			}
			if r := echoRun(c, time.Second, 256, nil); r.err != nil {
				errs <- r.err
			}
		}(i)
	}
	go func() { time.Sleep(500 * time.Millisecond); f.link("p2").setBlackhole(true) }()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	stimulus(t, f.link("p2").stats().Session.Dropped > 0, "p2 blackhole dropped no session bytes")
}

// A fully closed session whose peer is still streaming must not keep
// pulling that stream across: the server side must end promptly.
func TestCloseResetsUnfinishedPeer(t *testing.T) {
	f := newFixture(t, "p1")
	c := f.mustDial(selector, dialOpts{target: gen(1000000000)}) // effectively endless
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64<<10)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitFor(5*time.Second, func() bool { return f.serverSessions() == 0 && f.far.open.Load() == 0 })
	if n := f.serverSessions(); n != 0 {
		t.Fatalf("server still holds %d session(s) 5 s after the client closed", n)
	}
	if n := f.far.open.Load(); n != 0 {
		t.Fatalf("server still holds %d target connection(s) 5 s after the client closed", n)
	}
}

// outageRecoveryBound bounds how long after a total stall ends the echo
// carries new data again.
const outageRecoveryBound = 4 * time.Second

// Every path stalls (QUIC under 100% loss: nothing is lost, nothing moves)
// for less than the grace while the writer keeps its load: the connection
// must come through byte-exact and resume promptly once the stall ends.
func testBriefTotalOutage(t *testing.T, m mode) {
	f := newFixture(t, "p1", "p2", "p3")
	for _, l := range f.links {
		l.set(3*time.Millisecond, 0, 0)
	}
	c := f.mustDial(m, dialOpts{target: echo(), grace: 6 * time.Second})
	const rate, dur = 256, 10 * time.Second
	ended := make(chan time.Time, 1)
	r := echoRun(c, dur, rate, func() {
		go func() { // the fault runs beside the writer, which keeps its schedule
			for _, l := range f.links {
				l.setStall(true)
			}
			time.Sleep(3 * time.Second)
			for _, l := range f.links {
				l.setStall(false)
			}
			ended <- time.Now()
		}()
	})
	var held int64
	for _, l := range f.links {
		held += l.stats().Session.Held
	}
	stimulus(t, held > 0, "no session bytes were held by the stall")
	if r.err != nil {
		t.Fatalf("3 s total outage (grace 6 s) broke the connection: %v", r.err)
	}
	offeredLoad(t, r, rate, dur)
	var end time.Time
	select {
	case end = <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("INVALID: the stall never ended")
	}
	rec, ok := r.resumedAfter(end)
	t.Logf("recovery after the stall=%s maxStall=%s", rec, r.maxStall)
	if !ok || rec > outageRecoveryBound {
		t.Fatalf("new data flowed again %s after the stall ended (ok=%v), want <= %s", rec, ok, outageRecoveryBound)
	}
}

func TestSelectorBriefTotalOutageSurvives(t *testing.T) { testBriefTotalOutage(t, selector) }
func TestBondBriefTotalOutageSurvives(t *testing.T)     { testBriefTotalOutage(t, bond) }

// Outage longer than the grace: both ends give up within the grace.
func TestGraceBoundsBothEnds(t *testing.T) {
	f := newFixture(t, "p1", "p2")
	c := f.mustDial(selector, dialOpts{target: echo(), grace: 3 * time.Second})
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	for _, l := range f.links {
		l.setRefuse(true)
		l.setStall(true)
	}
	c.SetReadDeadline(t0.Add(10 * time.Second))
	buf := make([]byte, 64)
	var err error
	for err == nil {
		_, err = c.Read(buf)
	}
	notTimeout(t, err)
	if errors.Is(err, io.EOF) {
		t.Fatalf("outage surfaced as EOF: %v", err)
	}
	// detection (DeadMin 1 s) + grace 3 s
	if d := time.Since(t0); d > 6*time.Second {
		t.Fatalf("dialer closed after %s, want ≲ 4 s", d)
	}
	waitFor(12*time.Second-time.Since(t0), func() bool { return f.serverSessions() == 0 })
	if n := f.serverSessions(); n != 0 {
		t.Fatalf("server still holds the session %s after the outage (grace 3 s + 5 s slack)", time.Since(t0))
	}
	var held int64
	for _, l := range f.links {
		held += l.stats().Session.Held
	}
	stimulus(t, held > 0, "no session bytes were held by the stall")
}

// The active path dies while the next-best candidate is stalled (a join into
// it would hang for the handshake timeout): failover must race on to the
// next candidate instead of waiting. The paths' delays are far apart so
// that the probe ranking (p1, p2, p3) holds under a loaded race lane: with
// 1, 2 and 8 ms the measured order flipped to p2 first in a Linux
// race-unit pass (M3 I1).
func TestSelectorFailoverRacesPastStalledCandidate(t *testing.T) {
	f := newFixture(t, "p1", "p2", "p3")
	f.link("p1").set(1*time.Millisecond, 0, 0)
	f.link("p2").set(10*time.Millisecond, 0, 0)
	f.link("p3").set(25*time.Millisecond, 0, 0)
	c := f.mustDial(selector, dialOpts{target: echo()})
	if p := activePath(c); p != "p1" {
		t.Fatalf("initial active %q", p)
	}
	const rate, dur = 256, 10 * time.Second
	var p3Before int64
	var p2Seq int
	var faultAt time.Time
	r := echoRun(c, dur, rate, func() {
		p3Before = f.link("p3").stats().Session.Bytes
		p2Seq = f.link("p2").nextSeq()
		faultAt = time.Now()
		f.link("p2").setStall(true)
		f.link("p1").setRefuse(true)
		f.link("p1").kill()
	})
	// the join into p2 must have been attempted and held, delivering nothing
	var joins, joinHeld, joinBytes int64
	for _, ci := range f.link("p2").carrierLog() {
		if ci.seq >= p2Seq && ci.kind == helloJoin {
			joins++
			joinHeld += ci.held
			joinBytes += ci.up + ci.down
		}
	}
	f.link("p2").setStall(false)
	stimulus(t, f.link("p1").stats().Session.Killed > 0, "p1 had no session carrier to kill")
	stimulus(t, joins > 0 && joinHeld > 0, "no join into the stalled candidate p2 was held (joins %d)", joins)
	if joinBytes != 0 {
		t.Fatalf("the stalled p2 delivered %d session bytes", joinBytes)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	offeredLoad(t, r, rate, dur)
	rec, ok := r.resumedAfter(faultAt)
	if !ok || rec > failoverBound {
		t.Fatalf("failover took %s behind a stalled candidate (ok=%v)", rec, ok)
	}
	// the race went on to p3, which then carried the session
	if got := f.link("p3").stats().Session.Bytes - p3Before; got < r.sent/4 {
		t.Fatalf("p3 carried %d session bytes after the failover, want >= %d", got, r.sent/4)
	}
	t.Logf("recovery=%s maxStall=%s", rec, r.maxStall)
}

// Pipelined open (HELLO in the carrier open request): same session
// semantics — byte-exact echo while the active carrier is cut and a rejoin
// is needed. The kill runs beside the writer, which keeps its load.
func TestPipelinedOpenFailover(t *testing.T) {
	f := newFixture(t, "p1", "p2")
	c := f.mustDial(selector, dialOpts{target: echo(), pipelined: true, noProbeWait: true})
	defer c.Close()
	type fault struct {
		victim string
		at     time.Time
	}
	faults := make(chan fault, 1)
	const rate, dur = 2048, 6 * time.Second
	r := echoRun(c, dur, rate, func() {
		go func() {
			time.Sleep(2 * time.Second)
			_, victim := activeSub(c)
			at := time.Now()
			if victim != "" {
				f.link(victim).kill()
				f.link(victim).setRefuse(true)
			}
			faults <- fault{victim, at}
		}()
	})
	var ft fault
	select {
	case ft = <-faults:
	case <-time.After(5 * time.Second):
		t.Fatal("INVALID: the fault never ran")
	}
	stimulus(t, ft.victim != "" && f.link(ft.victim).stats().Session.Killed > 0,
		"no active session carrier was killed (victim %q)", ft.victim)
	if r.err != nil {
		t.Fatal(r.err)
	}
	offeredLoad(t, r, rate, dur)
	rec, ok := r.resumedAfter(ft.at)
	t.Logf("recovery=%s maxStall=%s", rec, r.maxStall)
	if !ok || rec > failoverBound {
		t.Fatalf("new data flowed again %s after the kill (ok=%v), want <= %s", rec, ok, failoverBound)
	}
}

// A server at its session limit refuses with "at capacity" → busy.
func TestServerAtCapacityIsBusy(t *testing.T) {
	f := newFixtureCfg(t, fixtureConfig{links: []string{"p1"}, maxSessions: 1})
	o := dialOpts{target: echo(), pipelined: true, noProbeWait: true}
	c1 := f.mustDial(selector, o)
	defer c1.Close()
	_, err := f.dial(selector, o)
	if !isBusy(err) {
		t.Fatalf("second session: %v, want busy", err)
	}
}
