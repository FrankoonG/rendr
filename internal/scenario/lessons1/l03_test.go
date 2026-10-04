package lessons1

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestCloseWriteRacesWrite_L03: 1000 sessions in which one writer streams
// PRNG bytes while four closers call Close or CloseWrite concurrently. On
// the wire there is exactly one FIN; it sits at exactly the bytes the
// writer was told were accepted, every DATA frame lies below it, the
// passive reads exactly those bytes and then io.EOF, every closer gets the
// same result (nil), and the writer stops with net.ErrClosed.
func TestCloseWriteRacesWrite_L03(t *testing.T) {
	iters := 1000
	if lessonsRace {
		iters = 200
	}
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, opts{}, "a")
		peer := f.peer("a")
		rng := rand.New(rand.NewPCG(3, 1000))
		var finsSeen, withData int
		for i := range iters {
			fins, data := closeWriteRace(t, f, peer, i, rng)
			finsSeen += fins
			if data > 0 {
				withData++
			}
		}
		// Stimulus: most closes raced a writer that had data on the wire.
		if finsSeen != iters || withData < iters/2 {
			t.Fatalf("%d FINs over %d sessions, %d of them with DATA", finsSeen, iters, withData)
		}
		f.close()
	})
}

func closeWriteRace(t *testing.T, f *fixture, peer *rendr.Peer, i int, rng *rand.Rand) (fins, data int) {
	dc, pc := f.open(peer, rendr.DialOptions{})
	seed := uint64(i + 1)
	cid := dc.Status().Carriers[0].ID

	// The writer: random sizes; the gate opens after its first k Writes.
	k := rng.IntN(3)
	sizes := make([]int, 64)
	for j := range sizes {
		sizes[j] = 1 + rng.IntN(20<<10)
	}
	kinds := [4]bool{} // true: Close, false: CloseWrite
	for j := range kinds {
		kinds[j] = rng.IntN(2) == 0
	}
	// The writer's volume is bounded whatever the scheduling: after its
	// last scripted Write it waits for the closers and writes once more,
	// which must fail. It yields between Writes so that the closers race
	// it even on a single P.
	gate, closed := make(chan struct{}), make(chan struct{})
	var accepted int64
	var werr error
	var wg, cw sync.WaitGroup
	wg.Go(func() {
		src := rendrtest.PRNG(seed)
		buf := make([]byte, 20<<10)
		for j := 0; ; j++ {
			if j == k {
				close(gate)
			}
			if j == len(sizes) {
				<-closed
			}
			b := buf[:sizes[j%len(sizes)]]
			src.Read(b)
			m, err := dc.Write(b)
			accepted += int64(m)
			if err != nil {
				werr = err
				if j < k {
					close(gate)
				}
				return
			}
			runtime.Gosched()
		}
	})
	var cerrs [4]error
	for j := range cerrs {
		cw.Go(func() {
			<-gate
			if kinds[j] {
				cerrs[j] = dc.Close()
			} else {
				cerrs[j] = dc.CloseWrite()
			}
		})
	}
	wg.Go(func() {
		cw.Wait()
		close(closed)
	})
	got, rerr := readPrefix(pc, seed)
	wg.Wait()
	synctest.Wait() // the dialer's writer has logged everything it wrote

	if !errors.Is(werr, net.ErrClosed) {
		t.Fatalf("session %d: the writer stopped with %v, want net.ErrClosed", i, werr)
	}
	for j, err := range cerrs {
		if err != cerrs[0] {
			t.Fatalf("session %d: closer %d got %v, closer 0 got %v", i, j, err, cerrs[0])
		}
	}
	if cerrs[0] != nil {
		t.Fatalf("session %d: closers got %v, want nil", i, cerrs[0])
	}
	if rerr != nil || got != accepted {
		t.Fatalf("session %d: passive read %d bytes then %v; the writer had %d accepted", i, got, rerr, accepted)
	}
	if _, err := dc.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("session %d: Write after the closers: %v", i, err)
	}

	// The wire: one FIN at the accepted end, every DATA frame below it.
	tp := f.wire.tapsOf(dialerSide, func(tp *tap) bool { return tp.cid.Load() == uint32(cid) })
	if len(tp) != 1 {
		t.Fatalf("session %d: %d taps for carrier %d", i, len(tp), cid)
	}
	fs := tp[0].sent(wire.TypeFin)
	if len(fs) != 1 || fs[0].off != uint64(accepted) {
		t.Fatalf("session %d: FINs on the wire %+v, want exactly one at %d", i, fs, accepted)
	}
	for _, d := range tp[0].sent(wire.TypeData) {
		if d.dataEnd() > fs[0].off {
			t.Fatalf("session %d: DATA [%d, %d) beyond the FIN at %d", i, d.off, d.dataEnd(), fs[0].off)
		}
		data++
	}

	// End the session cleanly before the next one.
	if err := pc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	dc.Close()
	pc.Close()
	for _, c := range []*rendr.Conn{dc, pc} {
		if st := waitEnded(t, c, 30*time.Second); st.Err != io.EOF {
			t.Fatalf("session %d: %v ended with %v", i, st.Role, st.Err)
		}
	}
	return len(fs), data
}

// readPrefix reads c to io.EOF, checking every byte against PRNG(seed); it
// returns the byte count and nil at io.EOF, else the first failure.
func readPrefix(c net.Conn, seed uint64) (int64, error) {
	src := rendrtest.PRNG(seed)
	buf := make([]byte, 32<<10)
	exp := make([]byte, 32<<10)
	var n int64
	for {
		k, err := c.Read(buf)
		if k > 0 {
			src.Read(exp[:k])
			for j := range k {
				if buf[j] != exp[j] {
					return n + int64(j), fmt.Errorf("byte mismatch at offset %d", n+int64(j))
				}
			}
			n += int64(k)
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// TestLingerBoundedBehindBlockedCarrier_L03_L52: Close returns at once even
// when the session's carrier writes block forever (a Hard block ignores
// write deadlines and Close), and the background linger is bounded: at
// Linger the session resets (RST AbortLinger), the carrier whose CLOSE can
// never be written is closed by force at the close bound (local_close),
// its writer stuck in the embedder Write is counted as abandoned after
// AbandonWait, and once the block is released every goroutine returns.
//
//   - closer-blocked: the closing (dialer) side's own writes block; the RST
//     cannot leave, the passive never sees EOF and fails with ErrNoPath at
//     its retention;
//   - peer-blocked: the passive's writes block (no ACK ever returns), so the
//     dialer's linger expires; its RST(AbortLinger) reaches the passive,
//     which then cannot write its own CLOSE.
func TestLingerBoundedBehindBlockedCarrier_L03_L52(t *testing.T) {
	const (
		linger  = 2 * time.Second
		bound   = time.Second // min(1 s, DeadMax): the end procedure's close bound (C24)
		abandon = time.Second // AbandonWait (default)
		n       = 256 << 10
	)
	ov := testhooks.Overrides{
		Linger: linger,
		// Neither stall nor ping death may end the blocked carrier before
		// the linger does: the bound under test is the linger's.
		WriteStall: 10 * time.Second, DeadMin: 10 * time.Second, DeadMax: 10 * time.Second,
		NoPathGrace: time.Second, PingIdle: time.Second, RetainSlack: 500 * time.Millisecond,
	}
	t.Run("closer-blocked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFixture(t, opts{ov: ov}, "a")
			l := f.link("a")
			dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
			if _, err := writeStream(dc, n, 1, 32<<10); err != nil {
				t.Fatal(err)
			}
			v := rendrtest.NewVerifier(1, 2*n)
			if _, err := io.CopyN(v, pc, n); err != nil {
				t.Fatalf("first half: %v", err)
			}
			synctest.Wait()
			read := make(chan error, 1)
			go func() {
				_, err := io.Copy(v, pc)
				read <- err
			}()

			l.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
			src := rendrtest.PRNG(1)
			io.CopyN(io.Discard, src, n)
			buf := make([]byte, n)
			src.Read(buf)
			if k, err := dc.Write(buf); k != n || err != nil {
				t.Fatalf("Write behind the block: (%d, %v)", k, err)
			}
			synctest.Wait()
			if got := l.Stats().Session.WritesBlocked; got != 1 {
				t.Fatalf("blocked session writes: %d, want 1", got)
			}
			closedAt := time.Now()
			if err := dc.Close(); err != nil || time.Since(closedAt) != 0 {
				t.Fatalf("Close: %v after %v, want nil at once", err, time.Since(closedAt))
			}

			st := waitEnded(t, dc, linger+time.Second)
			if el := endedAt(t, f.dev, dc).Sub(closedAt); el != linger || !errors.Is(st.Err, net.ErrClosed) {
				t.Fatalf("dialer ended %v after Close with %v, want net.ErrClosed at Linger %v", el, st.Err, linger)
			}
			// The forced close at the close bound; the stuck writer is
			// abandoned after AbandonWait.
			eventually(t, bound+abandon+100*time.Millisecond, "the stuck writer counted as abandoned", func() bool {
				return f.d.Status().Abandoned == 1
			})
			if el := time.Since(closedAt); el < linger+bound+abandon {
				t.Fatalf("writer abandoned %v after Close, before Linger + close bound + AbandonWait", el)
			}
			d := deadCarriers(dc.Status())
			if len(d) != 1 || d[0].DeathCause != rendr.CauseLocalClose {
				t.Fatalf("dialer carriers %+v, want the blocked one closed by force (local_close)", d)
			}
			if rs := f.wire.count(func(fr frame) bool { return fr.typ == wire.TypeRst && fr.fate == fateWritten }); rs != 0 {
				t.Fatalf("%d RSTs crossed a carrier whose every write blocks", rs)
			}

			// The passive never saw EOF: it fails with ErrNoPath at its retention.
			if err := <-read; !errors.Is(err, rendr.ErrNoPath) {
				t.Fatalf("passive read ended with %v, want ErrNoPath", err)
			}
			if pst := pc.Status(); pst.DeliveredBytes != n || !errors.Is(pst.Err, rendr.ErrNoPath) {
				t.Fatalf("passive: %+v", pst)
			}

			// Release: the abandoned writer returns and leaves the pool.
			l.Release()
			eventually(t, time.Second, "the abandoned writer returned", func() bool { return f.d.Status().Abandoned == 0 })
			f.close()
		})
	})
	t.Run("peer-blocked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// No PONG returns either, so the carrier's in-flight capacity
			// stays at its 128 KiB floor: n fits under it.
			const n = 64 << 10
			f := newFixture(t, opts{ov: ov}, "a")
			l := f.link("a")
			dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
			synctest.Wait()
			l.BlockWrites(rendrtest.Down, rendrtest.BlockHard)
			if _, err := writeStream(dc, n, 1, 32<<10); err != nil {
				t.Fatal(err)
			}
			closedAt := time.Now()
			if err := dc.Close(); err != nil || time.Since(closedAt) != 0 {
				t.Fatalf("Close: %v after %v, want nil at once", err, time.Since(closedAt))
			}
			// The data and the FIN reach the passive application; nothing
			// it writes (ACK, PONG, CLOSE) can leave.
			if err := readStream(pc, n, 1, nil); err != nil {
				t.Fatalf("passive stream: %v", err)
			}

			st := waitEnded(t, dc, linger+time.Second)
			if el := endedAt(t, f.dev, dc).Sub(closedAt); el != linger || !errors.Is(st.Err, net.ErrClosed) {
				t.Fatalf("dialer ended %v after Close with %v, want net.ErrClosed at Linger %v", el, st.Err, linger)
			}
			pst := waitEnded(t, pc, time.Second)
			synctest.Wait() // the dialer's writer has logged its RST
			rsts := f.wire.pick(func(fr frame) bool { return fr.typ == wire.TypeRst && fr.out && fr.fate == fateWritten })
			if len(rsts) != 1 || rsts[0].tap.side != dialerSide || rsts[0].rst != wire.RstLinger {
				t.Fatalf("RSTs written: %+v, want exactly one RST(AbortLinger) from the dialer", rsts)
			}
			var ae *rendr.AbortError
			if !errors.As(pst.Err, &ae) || ae.Code != rendr.AbortLinger || !ae.Remote {
				t.Fatalf("passive ended with %v, want the dialer's AbortLinger", pst.Err)
			}
			if got := l.Stats().Session.WritesBlocked; got < 1 {
				t.Fatalf("blocked passive writes: %d", got)
			}
			// The passive's CLOSE can never be written: its carrier ends
			// within the close bound — retired once the dialer, done
			// draining, closed its end, or by force at the bound — and the
			// writer stuck in the embedder Write is abandoned AbandonWait
			// later.
			ended := endedAt(t, f.pev, pc)
			eventually(t, bound+abandon+100*time.Millisecond, "the passive's stuck writer counted as abandoned", func() bool {
				return f.p.Status().Abandoned == 1
			})
			if el := time.Since(ended); el < abandon {
				t.Fatalf("abandoned %v after the end, before AbandonWait", el)
			}
			d := deadCarriers(pc.Status())
			if len(d) != 1 || (d[0].DeathCause != rendr.CauseLocalClose && d[0].DeathCause != rendr.CauseRetired) {
				t.Fatalf("passive carriers %+v, want the blocked one ended (retired or closed by force)", d)
			}
			if a := f.d.Status().Abandoned; a != 0 {
				t.Fatalf("dialer abandoned %d goroutines", a)
			}
			l.Release()
			eventually(t, time.Second, "the abandoned writer returned", func() bool { return f.p.Status().Abandoned == 0 })
			f.close()
		})
	})
}
