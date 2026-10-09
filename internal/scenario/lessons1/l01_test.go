package lessons1

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestCarrierErrorsAreDeath_L01: every way a carrier Read can fail — EOF,
// io.ErrUnexpectedEOF, a connection reset, a timeout, (0, nil), a panic
// inside Read, and bytes returned together with EOF — injected on the
// active carrier in the middle of a bidirectional transfer, on the dialer's
// and on the passive's end, is a carrier death (transport_error) and
// nothing else: the application sees no error, both streams arrive intact
// and end in io.EOF, and each end counts exactly one death migration. The
// bytes returned with EOF complete a DATA frame that the carrier applies
// before it dies (n before err): the faulted end has received it in order
// by the time the replacement carrier's JOIN is written (replay would hide
// dropped bytes from the stream check alone).
func TestCarrierErrorsAreDeath_L01(t *testing.T) {
	faults := []struct {
		name string
		f    readFault
	}{
		{"EOF", faultEOF},
		{"ErrUnexpectedEOF", faultUnexpectedEOF},
		{"reset", faultReset},
		{"timeout", faultTimeout},
		{"zero-nil", faultZeroNil},
		{"read-panic", faultPanic},
		{"bytes-with-EOF", faultDataEOF},
	}
	n := int64(8 << 20)
	if lessonsRace {
		n = 2 << 20
	}
	for _, sd := range []side{dialerSide, passiveSide} {
		for _, fc := range faults {
			t.Run(sd.String()+"/"+fc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { carrierErrorIsDeath(t, sd, fc.f, n) })
			})
		}
	}
}

func carrierErrorIsDeath(t *testing.T, sd side, fault readFault, n int64) {
	f := newFixture(t, opts{}, "a")
	f.link("a").SetDelay(time.Millisecond, 0)
	f.link("a").SetRate(64 << 20) // the transfer spans virtual time: the fault lands mid-stream
	dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
	faulted := dc
	if sd == passiveSide {
		faulted = pc
	}
	// The faulted end's in-order receive count when the replacement's JOIN
	// is written: between the death and that JOIN nothing can reach it.
	var rxAtJoin atomic.Int64
	rxAtJoin.Store(-1)
	f.wire.setHook(func(fr frame) {
		if fr.out && fr.typ == wire.TypeJoin {
			rxAtJoin.CompareAndSwap(-1, int64(faulted.Status().RxBytes))
		}
	})

	var gp gauge
	errs := make(chan error, 4)
	go func() { errs <- sendAndClose(dc, n, 1) }()
	go func() { errs <- sendAndClose(pc, n, 2) }()
	go func() { errs <- readStream(pc, n, 1, &gp) }()
	go func() { errs <- readStream(dc, n, 2, nil) }()

	reached(t, &gp, n/3, time.Minute)
	taps := f.wire.sessionTaps(sd, "a")
	if len(taps) != 1 {
		t.Fatalf("%d %v session taps before the fault, want 1", len(taps), sd)
	}
	victim := taps[0]
	victim.armRead(fault)
	for range 4 {
		if err := recv(t, errs, time.Minute, "both streams"); err != nil {
			t.Fatalf("application saw an error: %v", err)
		}
	}
	synctest.Wait() // counters settle (the passive counts at its SCHED application)

	// Stimulus: the fault was injected once, on the active carrier, and
	// killed it with transport_error on the faulted end.
	if got := victim.faults.Load(); got != 1 {
		t.Fatalf("faults injected on the active carrier: %d, want 1", got)
	}
	var cause rendr.Cause
	for _, c := range deadCarriers(faulted.Status()) {
		if uint32(c.ID) == victim.cid.Load() {
			cause = c.DeathCause
		}
	}
	if cause != rendr.CauseTransportError {
		t.Fatalf("faulted carrier %d died with %v, want transport_error: %+v", victim.cid.Load(), cause, faulted.Status().Carriers)
	}
	if sc := sessionCarriers(f.link("a")); len(sc) != 2 {
		t.Fatalf("%d session carriers on the link, want the original and one replacement", len(sc))
	}
	if fault == faultDataEOF {
		// n before err: the DATA that came with EOF was applied.
		var end uint64
		for _, fr := range victim.eofFrames() {
			if fr.typ == wire.TypeData {
				end = max(end, fr.dataEnd())
			}
		}
		if end == 0 {
			t.Fatal("the Read that returned EOF completed no DATA frame")
		}
		if rx := rxAtJoin.Load(); rx < int64(end) {
			t.Fatalf("the %v had received %d bytes in order when the replacement's JOIN was written, "+
				"but the Read that returned EOF completed DATA up to %d: the bytes returned with the error were dropped", sd, rx, end)
		}
	}
	// Load and integrity: n bytes each way, verified above; Death +1 on both ends.
	for _, c := range []*rendr.Conn{dc, pc} {
		st := c.Status()
		if st.Migrations != (rendr.MigrationCounts{Death: 1}) || st.DeliveredBytes != uint64(n) || st.TxBytes != uint64(n) {
			t.Fatalf("%v: migrations %+v, delivered %d, tx %d (want 1 death, %d bytes)", st.Role, st.Migrations, st.DeliveredBytes, st.TxBytes, n)
		}
	}
	finish(t, dc, pc)
	f.close()
}

// sendAndClose writes n bytes of PRNG(seed) and half-closes.
func sendAndClose(c *rendr.Conn, n int64, seed uint64) error {
	if _, err := writeStream(c, n, seed, 32<<10); err != nil {
		return err
	}
	return c.CloseWrite()
}

// finish closes both ends (whose directions already ended in io.EOF) and
// requires a clean end (io.EOF) on both.
func finish(t testing.TB, a, b *rendr.Conn) {
	t.Helper()
	for _, c := range []*rendr.Conn{a, b} {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for _, c := range []*rendr.Conn{a, b} {
		if st := waitEnded(t, c, 30*time.Second); st.Err != io.EOF {
			t.Fatalf("%v ended with %v, want io.EOF", st.Role, st.Err)
		}
	}
}

// swap moves n bytes of PRNG(seed) from a to b and n bytes of
// PRNG(seed+1) from b to a at the same time, without closing anything.
func swap(a, b *rendr.Conn, n int64, seed uint64) error {
	errs := make(chan error, 4)
	go func() { _, err := writeStream(a, n, seed, 16<<10); errs <- err }()
	go func() { _, err := writeStream(b, n, seed+1, 16<<10); errs <- err }()
	go func() { errs <- readN(b, n, seed) }()
	go func() { errs <- readN(a, n, seed+1) }()
	for range 4 {
		if err := <-errs; err != nil {
			return err
		}
	}
	return nil
}

// TestLocalCloseNoFailover_L01: a local close of a carrier racing a read
// failure of that same carrier never triggers a failover on the side that
// closed. Two kinds of local close are raced:
//
//   - at the session's end (conn-close: the CLOSE that follows the DONE
//     exchange; runtime-close: the GOAWAY at Runtime.Close); the read
//     failure is a Link kill (both ends read EOF, buffered bytes are lost);
//   - while the session stays open (selector-retire: the planned CLOSE of
//     the carrier a quality switch left behind); the read failure severs
//     just that carrier (its probe sibling on the same Link is untouched).
//
// The failure strikes just before the closing write is forwarded
// (before-write), right after it (after-write: inside the Write that
// forwarded it at the session's end; once that Write returned for the
// retirement), or during the drain that follows (during-drain). The closing
// side counts no migration (beyond the switch), rejoin or no-path episode,
// dials no new carrier and emits at most one CarrierDown per carrier. At the
// session's end it ends with its local result; the other side still ends
// cleanly or as the protocol prescribes. While the session stays open, a
// failure after the CLOSE was written ends the retirement (retired: no
// failed mark, no redial), one before it is the death of a carrier that
// carried nothing (transport_error: the failed mark of design §7.3 but no
// failover), and the session keeps moving data on its new carrier.
func TestLocalCloseNoFailover_L01(t *testing.T) {
	iters := 24
	if lessonsRace {
		iters = 6
	}
	for _, kind := range []string{"conn-close", "runtime-close"} {
		for _, at := range []string{"before-write", "after-write", "during-drain"} {
			t.Run(kind+"/"+at, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					hits := 0
					for i := range iters {
						hits += localCloseNoFailover(t, kind, at, i)
					}
					// Stimulus: the read failures hit live closing carriers
					// (every time before or right after the closing write).
					if hits == 0 {
						t.Fatalf("no read failure hit a live carrier in %d iterations", iters)
					}
				})
			})
		}
	}
	retires := 4
	if lessonsRace {
		retires = 2
	}
	for _, at := range []string{"before-write", "after-write", "during-drain"} {
		t.Run("selector-retire/"+at, func(t *testing.T) {
			for i := range retires {
				synctest.Test(t, func(t *testing.T) { retireNoFailover(t, at, i) })
			}
		})
	}
}

// localCloseNoFailover runs one iteration and returns how many live
// carriers the read failure hit.
func localCloseNoFailover(t *testing.T, kind, at string, i int) int {
	ov := testhooks.Overrides{
		// The passive of a lost GOAWAY retains briefly (ErrNoPath).
		NoPathGrace: time.Second, PingIdle: time.Second, DeadMin: time.Second, DeadMax: time.Second,
		WriteStall: time.Second, PingBusy: 50 * time.Millisecond, RetainSlack: 100 * time.Millisecond,
		Linger: 2 * time.Second,
	}
	f := newFixture(t, opts{ov: ov}, "a")
	l := f.link("a")
	l.SetDelay(time.Duration(i%5)*200*time.Microsecond+100*time.Microsecond, 0)
	dc, pc := f.open(f.peer("a"), rendr.DialOptions{})

	// The closing write: CLOSE at the session's end, GOAWAY at Runtime.Close.
	// The strike is armed before any data moves: a session whose FINs both
	// crossed ends by DONE on its own (X6), so its CLOSE may follow at once.
	closing := wire.TypeClose
	if kind == "runtime-close" {
		closing = wire.TypeGoAway
	}
	killed := make(chan int, 1)
	strike := func() { killed <- l.Kill() }
	drain := time.Duration(i%7) * 150 * time.Microsecond
	victim := f.wire.sessionTaps(dialerSide, "a")[0]
	fired := false
	switch at {
	case "before-write":
		victim.setPlan(func(tp *tap, fs []frame) planVerdict {
			for _, fr := range fs {
				if fr.typ == closing && !fired {
					fired = true
					strike()
				}
			}
			return planVerdict{}
		})
	default:
		f.wire.setHook(func(fr frame) {
			if fr.tap != victim || !fr.out || fr.typ != closing || fired {
				return
			}
			fired = true
			if at == "after-write" {
				strike()
				return
			}
			go func() {
				time.Sleep(drain)
				strike()
			}()
		})
	}

	// Data both ways; for Runtime.Close without FINs, so that the session
	// is still open (no DONE) when the Runtime closes it.
	if kind == "conn-close" {
		runWithin(t, time.Minute, "exchange", func() error { return exchange(dc, pc, 64<<10, uint64(i), 16<<10) })
	} else {
		runWithin(t, time.Minute, "data both ways", func() error { return swap(dc, pc, 64<<10, uint64(i)) })
	}

	dialsBefore := l.Stats().Dials
	var rtClosed chan struct{}
	switch kind {
	case "conn-close":
		finishAsync(dc, pc)
	case "runtime-close":
		rtClosed = make(chan struct{})
		go func() { f.d.Close(); close(rtClosed) }()
	}
	k := recv(t, killed, 30*time.Second, "the dialer's "+closing.String())
	if at != "during-drain" && k != 1 {
		t.Fatalf("iteration %d: the read failure hit %d carriers, want the closing one", i, k)
	}
	if rtClosed != nil {
		recv(t, rtClosed, 30*time.Second, "Runtime.Close")
	}

	// The closing side (the dialer) never failed over.
	want := error(io.EOF)
	if kind == "runtime-close" {
		want = net.ErrClosed
	}
	st := waitEnded(t, dc, 30*time.Second)
	if !errors.Is(st.Err, want) {
		t.Fatalf("iteration %d: dialer ended with %v, want %v", i, st.Err, want)
	}
	if st.Migrations != noMigrations || st.Rejoins != 0 || st.NoPathEpisodes != 0 || st.InNoPath {
		t.Fatalf("iteration %d: dialer failed over after its local close: %+v", i, st)
	}
	if n := len(f.dev.of(dc.ID(), rendr.EventMigration)) + len(f.dev.of(dc.ID(), rendr.EventNoPathStart)); n != 0 {
		t.Fatalf("iteration %d: dialer emitted %d migration/no-path events", i, n)
	}
	onePerCarrier(t, f.dev, dc)
	if d := l.Stats().Dials; d != dialsBefore || len(sessionCarriers(l)) != 1 {
		t.Fatalf("iteration %d: the dialer redialled after its local close: %d dials (was %d), %d session carriers",
			i, d, dialsBefore, len(sessionCarriers(l)))
	}

	// The passive ends as the protocol prescribes: cleanly (it already had,
	// or still gets, the dialer's DONE; else its own DONE is final after
	// Linger), or from the GOAWAY — or, when the kill destroyed the GOAWAY
	// in the Link, by its no-path retention.
	pst := waitEnded(t, pc, 30*time.Second)
	var ae *rendr.AbortError
	switch {
	case kind == "conn-close" && pst.Err == io.EOF:
	case kind == "runtime-close" && errors.As(pst.Err, &ae) && ae.Code == rendr.AbortGoingAway && ae.Remote:
	case kind == "runtime-close" && errors.Is(pst.Err, rendr.ErrNoPath):
	default:
		t.Fatalf("iteration %d: passive ended with %v", i, pst.Err)
	}
	f.close()
	return k
}

// onePerCarrier requires at most one CarrierDown event per carrier of c's
// session in log l, and returns the events by carrier.
func onePerCarrier(t testing.TB, l *evLog, c *rendr.Conn) map[rendr.CarrierID]rendr.Event {
	t.Helper()
	downs := map[rendr.CarrierID]rendr.Event{}
	for _, ev := range l.of(c.ID(), rendr.EventCarrierDown) {
		if _, dup := downs[ev.Carrier]; dup {
			t.Fatalf("carrier %d reported down twice", ev.Carrier)
		}
		downs[ev.Carrier] = ev
	}
	return downs
}

// finishAsync runs the clean end of a session whose data already
// crossed: both ends Close (their FINs went out with exchange's
// CloseWrite) and the DONE exchange runs in the background.
func finishAsync(a, b *rendr.Conn) {
	a.Close()
	b.Close()
}

// retireNoFailover runs one selector-retire iteration: a selector session
// opens on a (the faster path), a degrades, the quality switch moves the
// session to b, and the planned CLOSE of a's carrier is raced by a read
// failure of that carrier.
func retireNoFailover(t *testing.T, at string, i int) {
	ov := testhooks.Overrides{
		ProbeInterval: 50 * time.Millisecond, ProbeFresh: time.Second,
		SelectorDwell: 200 * time.Millisecond, SelectorCooldown: time.Hour,
		RetireGrace: time.Second,
	}
	// The planned CLOSE of the session's own carrier: dedicated (M3-D2).
	f := newFixture(t, opts{ov: ov, dedicated: true}, "a", "b")
	la, lb := f.link("a"), f.link("b")
	la.SetDelay(time.Millisecond, 0)
	lb.SetDelay(time.Duration(4+i%3)*time.Millisecond, 0)
	peer := f.peer("a", "b")
	dc, pc := f.open(peer, rendr.DialOptions{})
	if c, ok := carrierIn(dc.Status(), rendr.CarrierActive); !ok || c.Name != "a" {
		t.Fatalf("iteration %d: active carrier %+v, want one on a (the faster path)", i, c)
	}
	const n = 64 << 10
	seed := uint64(10 * (i + 1))
	runWithin(t, time.Minute, "data before the switch", func() error { return swap(dc, pc, n, seed) })
	eventually(t, 10*time.Second, "data acknowledged", func() bool {
		return dc.Status().AckedBytes == n && pc.Status().AckedBytes == n
	})

	// The strike: sever a's session carrier on the dialer around the
	// planned CLOSE the switch makes it write.
	victim := f.wire.sessionTaps(dialerSide, "a")[0]
	struck := make(chan struct{}, 1)
	var fired atomic.Bool
	strike := func() {
		victim.sever()
		struck <- struct{}{}
	}
	switch at {
	case "before-write":
		victim.setPlan(func(_ *tap, fs []frame) planVerdict {
			for _, fr := range fs {
				if fr.typ == wire.TypeClose && fired.CompareAndSwap(false, true) {
					strike() // the Write that carries the CLOSE then fails
				}
			}
			return planVerdict{}
		})
	default:
		// after-write: as soon as the carrier's Write of the CLOSE returned;
		// during-drain: while it waits for the peer's CLOSE (a 40 ms round
		// trip once a has degraded).
		delay := time.Nanosecond
		if at == "during-drain" {
			delay = time.Duration(1+i%4) * 7 * time.Millisecond
		}
		f.wire.setHook(func(fr frame) {
			if fr.tap == victim && fr.out && fr.typ == wire.TypeClose && fired.CompareAndSwap(false, true) {
				go func() {
					time.Sleep(delay)
					strike()
				}()
			}
		})
	}
	dialsA := la.Stats().Dials
	la.SetDelay(20*time.Millisecond, 0) // a degrades: b qualifies, and wins after the dwell
	recv(t, struck, 30*time.Second, "the strike at a's planned CLOSE")
	synctest.Wait() // the death step ran

	// The retired carrier ended once, with the cause its timing implies; the
	// failed mark follows the cause.
	cid := rendr.CarrierID(victim.cid.Load())
	var cause rendr.Cause
	for _, c := range deadCarriers(dc.Status()) {
		if c.ID == cid {
			cause = c.DeathCause
		}
	}
	want := rendr.CauseRetired
	if at == "before-write" {
		want = rendr.CauseTransportError
	}
	if cause != want {
		t.Fatalf("iteration %d: a's session carrier ended with %v, want %v: %+v", i, cause, want, dc.Status().Carriers)
	}
	if fs := peer.Status().Factories[0]; fs.Failed != (want == rendr.CauseTransportError) {
		t.Fatalf("iteration %d: factory a failed mark %v (%q) after a %v end", i, fs.Failed, fs.FailReason, cause)
	}
	if c, ok := carrierIn(dc.Status(), rendr.CarrierActive); !ok || c.Name != "b" {
		t.Fatalf("iteration %d: active carrier %+v after the switch, want one on b", i, c)
	}

	// The session stays open and keeps moving data, on b.
	runWithin(t, time.Minute, "data after the strike", func() error { return swap(dc, pc, n, seed+2) })
	synctest.Wait()
	quality := rendr.MigrationCounts{Quality: 1}
	for _, c := range []*rendr.Conn{dc, pc} {
		if st := c.Status(); st.Migrations != quality || st.Rejoins != 0 || st.NoPathEpisodes != 0 || st.InNoPath || st.State != rendr.StateOpen {
			t.Fatalf("iteration %d: %v failed over after a's retirement: %+v", i, st.Role, st)
		}
	}
	if m, np := len(f.dev.of(dc.ID(), rendr.EventMigration)), len(f.dev.of(dc.ID(), rendr.EventNoPathStart)); m != 1 || np != 0 {
		t.Fatalf("iteration %d: dialer emitted %d migration and %d no-path events, want the switch only", i, m, np)
	}
	if ev, ok := onePerCarrier(t, f.dev, dc)[cid]; !ok || ev.Cause != want {
		t.Fatalf("iteration %d: CarrierDown of a's carrier: %+v (reported %v), want one with %v", i, ev, ok, want)
	}
	// No redial: neither a session nor a probe carrier was dialled on a.
	if d := la.Stats().Dials; d != dialsA || len(sessionCarriers(la)) != 1 || len(sessionCarriers(lb)) != 1 {
		t.Fatalf("iteration %d: %d dials on a (was %d), session carriers a %d, b %d",
			i, d, dialsA, len(sessionCarriers(la)), len(sessionCarriers(lb)))
	}
	endBoth(t, dc, pc)
	f.close()
}

// endBoth ends an open session cleanly: both half-close, both read
// io.EOF, both Close and end with io.EOF.
func endBoth(t testing.TB, a, b *rendr.Conn) {
	t.Helper()
	for _, c := range []*rendr.Conn{a, b} {
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	for _, c := range []*rendr.Conn{a, b} {
		readEOF(t, c, c.Status().Role.String())
	}
	finish(t, a, b)
}
