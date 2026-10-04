package lessons1

import (
	"errors"
	"io"
	"net"
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
// and end in io.EOF, and each end counts exactly one death migration.
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

	var gp gauge
	errs := make(chan error, 4)
	go func() { errs <- sendAndClose(dc, n, 1) }()
	go func() { errs <- sendAndClose(pc, n, 2) }()
	go func() { errs <- readStream(pc, n, 1, &gp) }()
	go func() { errs <- readStream(dc, n, 2, nil) }()

	<-gp.at(n / 3)
	taps := f.wire.sessionTaps(sd, "a")
	if len(taps) != 1 {
		t.Fatalf("%d %v session taps before the fault, want 1", len(taps), sd)
	}
	victim := taps[0]
	victim.armRead(fault)
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatalf("application saw an error: %v", err)
		}
	}
	synctest.Wait() // counters settle (the passive counts at its SCHED application)

	// Stimulus: the fault was injected once, on the active carrier, and
	// killed it with transport_error on the faulted end.
	if got := victim.faults.Load(); got != 1 {
		t.Fatalf("faults injected on the active carrier: %d, want 1", got)
	}
	faulted := dc
	if sd == passiveSide {
		faulted = pc
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

// TestLocalCloseNoFailover_L01: a local close of a carrier (its CLOSE at
// the end of a session, its GOAWAY at Runtime.Close) racing a read failure
// of the same carrier never triggers a failover on the side that closed:
// the read failure is injected (the Link is killed: both ends read EOF and
// buffered bytes are lost) just before the closing write is forwarded,
// right after it, or during the drain that follows it. The closing side
// counts no migration, rejoin or no-path episode, dials no new carrier,
// emits at most one CarrierDown per carrier, and ends with its local
// result; the other side still ends cleanly or as the protocol prescribes.
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
		if err := exchange(dc, pc, 64<<10, uint64(i), 16<<10); err != nil {
			t.Fatalf("iteration %d: exchange: %v", i, err)
		}
	} else {
		errs := make(chan error, 4)
		go func() { _, err := writeStream(dc, 64<<10, uint64(i), 16<<10); errs <- err }()
		go func() { _, err := writeStream(pc, 64<<10, uint64(i)+1, 16<<10); errs <- err }()
		go func() { errs <- readN(pc, 64<<10, uint64(i)) }()
		go func() { errs <- readN(dc, 64<<10, uint64(i)+1) }()
		for range 4 {
			if err := <-errs; err != nil {
				t.Fatalf("iteration %d: data: %v", i, err)
			}
		}
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
	var k int
	select {
	case k = <-killed:
	case <-time.After(30 * time.Second):
		t.Fatalf("iteration %d: the dialer never wrote its %v", i, closing)
	}
	if at != "during-drain" && k != 1 {
		t.Fatalf("iteration %d: the read failure hit %d carriers, want the closing one", i, k)
	}
	if rtClosed != nil {
		<-rtClosed
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
	downs := map[rendr.CarrierID]int{}
	for _, ev := range f.dev.of(dc.ID(), rendr.EventCarrierDown) {
		if downs[ev.Carrier]++; downs[ev.Carrier] > 1 {
			t.Fatalf("iteration %d: carrier %d reported down twice", i, ev.Carrier)
		}
	}
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

// finishAsync runs the clean end of a session whose data already
// crossed: both ends Close (their FINs went out with exchange's
// CloseWrite) and the DONE exchange runs in the background.
func finishAsync(a, b *rendr.Conn) {
	a.Close()
	b.Close()
}
