package lessons1

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestBufferLossKillsSHA_L10_L61: a selector session moves 256 MiB (64 MiB
// under -race) from the dialer, plus a reverse stream, through a Link that
// holds up to 2 MiB per direction which every Kill loses (bytes a Write
// returned for but the far end never read: L61's buffer-loss model). The
// carrier is killed three times at a quarter, half and three quarters of
// the transfer; each time the bytes of the Link are lost, the session
// replays from the acknowledged front on a new carrier, and the SHA-256 of
// both streams is unchanged.
func TestBufferLossKillsSHA_L10_L61(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := int64(256 << 20)
		if lessonsRace {
			n = 64 << 20
		}
		back := n / 8
		f := newFixture(t, opts{}, "a")
		l := f.link("a")
		l.SetDelay(time.Millisecond, 0)
		l.SetRate(128 << 20) // the sender outruns the Link: its 2 MiB buffer stays full
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})

		type sum struct {
			d   [32]byte
			n   int64
			err error
		}
		var g gauge
		fwd, rev := make(chan sum, 1), make(chan sum, 1)
		werr := make(chan error, 2)
		go func() { werr <- sendAndClose(dc, n, 1) }()
		go func() { werr <- sendAndClose(pc, back, 2) }()
		go func() { d, k, err := shaReader(pc, &g); fwd <- sum{d, k, err} }()
		go func() { d, k, err := shaReader(dc, nil); rev <- sum{d, k, err} }()

		var lost [3]int64
		for i := range 3 {
			<-g.at(n * int64(i+1) / 4)
			before := l.Stats().Session.BufferLost
			if k := l.Kill(); k != 1 {
				t.Fatalf("kill %d hit %d carriers, want the session's", i+1, k)
			}
			lost[i] = l.Stats().Session.BufferLost - before
		}
		for range 2 {
			if err := <-werr; err != nil {
				t.Fatalf("writer: %v", err)
			}
		}
		for _, x := range []struct {
			name string
			ch   chan sum
			n    int64
			seed uint64
		}{{"dialer → passive", fwd, n, 1}, {"passive → dialer", rev, back, 2}} {
			s := <-x.ch
			if s.err != io.EOF || s.n != x.n || s.d != digest(x.n, x.seed) {
				t.Fatalf("%s: %d bytes, end %v, SHA-256 match %v (want %d bytes, io.EOF, match)", x.name, s.n, s.err, s.d == digest(x.n, x.seed), x.n)
			}
		}
		synctest.Wait()

		// Stimulus: three kills of the session's carrier, each losing what the
		// full Link held (up to its 2 MiB buffer per direction).
		for i, b := range lost {
			if b < 1<<20 {
				t.Fatalf("kill %d lost %d buffered bytes, want the Link's buffer (≈ 2 MiB)", i+1, b)
			}
		}
		if s := l.Stats().Session; s.Killed != 3 {
			t.Fatalf("session carriers killed: %d, want 3", s.Killed)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			st := c.Status()
			if st.Migrations != (rendr.MigrationCounts{Death: 3}) {
				t.Fatalf("%v migrations %+v, want 3 deaths", st.Role, st.Migrations)
			}
		}
		eventually(t, time.Second, "everything acknowledged", func() bool { return dc.Status().AckedBytes == uint64(n) })
		if st := dc.Status(); st.RetransmittedBytes < uint64(lost[0]) {
			t.Fatalf("dialer retransmitted %d bytes, want at least the %d lost at the first kill", st.RetransmittedBytes, lost[0])
		}
		if sc := sessionCarriers(l); len(sc) != 4 {
			t.Fatalf("%d session carriers, want 4", len(sc))
		}
		finish(t, dc, pc)
		f.close()
	})
}

// TestDeathAfterWriteReturnedReplays_L10_L17: the application's Write
// returns at once (decoupled from the carrier); carrier A then dies inside
// its first DATA write, which nevertheless reports success — the bytes
// never left. A carrier's successful Write is not delivery: the session
// keeps part1 until it is acknowledged, replays it on carrier B ahead of
// part2, and the passive receives exactly part1part2 and then io.EOF.
func TestDeathAfterWriteReturnedReplays_L10_L17(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			n1 = 48 << 10
			n2 = 80 << 10
		)
		f := newFixture(t, opts{}, "a")
		l := f.link("a")
		l.SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		synctest.Wait()
		a := f.wire.sessionTaps(dialerSide, "a")[0]
		var swallowed []frame
		a.setPlan(func(tp *tap, fs []frame) planVerdict {
			for _, fr := range fs {
				if fr.typ == wire.TypeData && swallowed == nil {
					swallowed = fs
					l.Kill()                          // A dies inside the Write ...
					return planVerdict{swallow: true} // ... which reports success
				}
			}
			return planVerdict{}
		})
		read := make(chan error, 1)
		go func() { read <- readStream(pc, n1+n2, 1, nil) }()

		src := rendrtest.PRNG(1)
		part1, part2 := make([]byte, n1), make([]byte, n2)
		src.Read(part1)
		src.Read(part2)
		at := time.Now()
		if k, err := dc.Write(part1); k != n1 || err != nil || time.Since(at) != 0 {
			t.Fatalf("Write(part1): (%d, %v) after %v, want (%d, nil) at once", k, err, time.Since(at), n1)
		}
		synctest.Wait()
		if a.faults.Load() != 1 {
			t.Fatalf("A's first DATA write was not intercepted (%d)", a.faults.Load())
		}
		if k, err := dc.Write(part2); k != n2 || err != nil || time.Since(at) != 0 {
			t.Fatalf("Write(part2): (%d, %v), want (%d, nil) at once", k, err, n2)
		}
		if err := dc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := <-read; err != nil {
			t.Fatalf("passive stream: %v", err)
		}
		synctest.Wait()

		// Stimulus: A's swallowed write held part1's first DATA (offset 0)
		// and A died; B carried part1 again, then part2.
		if len(swallowed) == 0 || swallowed[0].typ == 0 {
			t.Fatal("no swallowed frames")
		}
		var first *frame
		for i := range swallowed {
			if swallowed[i].typ == wire.TypeData {
				first = &swallowed[i]
				break
			}
		}
		if first == nil || first.off != 0 {
			t.Fatalf("swallowed frames %+v, want part1's DATA at offset 0", swallowed)
		}
		dt := f.wire.sessionTaps(dialerSide, "a")
		if len(dt) != 2 {
			t.Fatalf("%d dialer session carriers, want A and B", len(dt))
		}
		var next uint64
		for _, d := range dt[1].sent(wire.TypeData) {
			if d.off != next {
				t.Fatalf("B's DATA at %d, want %d (in order, part1 replayed first)", d.off, next)
			}
			next = d.dataEnd()
		}
		if next != n1+n2 {
			t.Fatalf("B carried [0, %d), want [0, %d)", next, n1+n2)
		}
		eventually(t, time.Second, "part1part2 acknowledged", func() bool { return dc.Status().AckedBytes == n1+n2 })
		st := dc.Status()
		if st.RetransmittedBytes < n1 || st.Migrations != (rendr.MigrationCounts{Death: 1}) {
			t.Fatalf("dialer: %+v", st)
		}
		if pst := pc.Status(); pst.RxBytes != n1+n2 || pst.DeliveredBytes != n1+n2 {
			t.Fatalf("passive received %d / delivered %d bytes, want exactly %d", pst.RxBytes, pst.DeliveredBytes, n1+n2)
		}
		if err := pc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if k, err := dc.Read(make([]byte, 1)); k != 0 || err != io.EOF {
			t.Fatalf("dialer Read: (%d, %v)", k, err)
		}
		finish(t, dc, pc)
		f.close()
	})
}
