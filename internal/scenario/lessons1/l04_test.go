package lessons1

import (
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestFinReplayedOnNewCarrier_L04: carrier A dies while writing the FIN (the
// Write carrying it fails); the FIN stays in the retransmit state and
// arrives once, at the same offset, on carrier B, after every byte below
// it — the passive reads exactly the bytes written and then io.EOF.
func TestFinReplayedOnNewCarrier_L04(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 1 << 20
		f := newFixture(t, opts{}, "a")
		f.link("a").SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		a := f.wire.sessionTaps(dialerSide, "a")[0]
		var failed []frame
		a.setPlan(func(tp *tap, fs []frame) planVerdict {
			for _, fr := range fs {
				if fr.typ == wire.TypeFin && failed == nil {
					failed = fs
					return planVerdict{fail: errInjected}
				}
			}
			return planVerdict{}
		})
		read := make(chan error, 1)
		go func() { read <- readStream(pc, n, 1, nil) }()
		if _, err := writeStream(dc, n, 1, 64<<10); err != nil {
			t.Fatal(err)
		}
		for range 2 { // idempotent
			if err := dc.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
		}
		if _, err := dc.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after CloseWrite: %v, want net.ErrClosed", err)
		}
		if err := <-read; err != nil {
			t.Fatalf("passive stream: %v", err)
		}
		synctest.Wait()

		// Stimulus: A's Write carrying the FIN (at n) failed, and A died.
		if a.faults.Load() != 1 {
			t.Fatalf("FIN writes failed on A: %d, want 1", a.faults.Load())
		}
		var finA *frame
		for i := range failed {
			if failed[i].typ == wire.TypeFin {
				finA = &failed[i]
			}
		}
		if finA == nil || finA.off != n {
			t.Fatalf("A's failed batch %+v, want a FIN at %d", failed, n)
		}
		if fins := a.sent(wire.TypeFin); len(fins) != 0 {
			t.Fatalf("A wrote FINs %+v", fins)
		}
		dt := f.wire.sessionTaps(dialerSide, "a")
		if len(dt) != 2 {
			t.Fatalf("%d dialer session carriers, want A and B", len(dt))
		}
		// The FIN on B: once, same offset, after every DATA byte below it.
		b := dt[1]
		fins := b.sent(wire.TypeFin)
		if len(fins) != 1 || fins[0].off != finA.off {
			t.Fatalf("B's FINs %+v, want one at %d", fins, finA.off)
		}
		for _, d := range b.sent(wire.TypeData) {
			if d.dataEnd() > fins[0].off || d.at.After(fins[0].at) {
				t.Fatalf("B sent DATA [%d, %d) at %v, after or beyond its FIN at %v", d.off, d.dataEnd(), d.at, fins[0].at)
			}
		}
		if got := f.wire.count(func(fr frame) bool { return fr.typ == wire.TypeFin && !fr.out && fr.tap.side == passiveSide }); got != 1 {
			t.Fatalf("the passive read %d FINs, want 1", got)
		}
		if d := deadCarriers(dc.Status()); len(d) != 1 || d[0].DeathCause != rendr.CauseTransportError || uint32(d[0].ID) != a.cid.Load() {
			t.Fatalf("dialer's dead carriers %+v, want A (transport_error)", d)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := c.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) {
				t.Fatalf("%v migrations %+v, want 1 death", st.Role, st.Migrations)
			}
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

// TestHalfCloseReverse4MiB_L04: the client writes a request and half-closes
// (twice: idempotent; a later Write is net.ErrClosed); the server reads the
// request and io.EOF, writes back 4 MiB and half-closes. The carrier dies
// in the middle of the reply: the half-closed session migrates — the
// client's FIN is not sent again, its Writes stay refused — and the client
// still receives the whole reply and then io.EOF.
func TestHalfCloseReverse4MiB_L04(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			req   = 64 << 10
			reply = 4 << 20
		)
		f := newFixture(t, opts{}, "a")
		l := f.link("a")
		l.SetDelay(2*time.Millisecond, 0)
		l.SetRate(32 << 20) // the reply spans ≈ 130 ms
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		server := make(chan error, 1)
		go func() { server <- rendrtest.HalfCloseCheck(req, 1, reply)(pc) }()

		if _, err := writeStream(dc, req, 1, 16<<10); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := dc.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
		}
		if _, err := dc.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after CloseWrite: %v, want net.ErrClosed", err)
		}
		var g gauge
		client := make(chan error, 1)
		go func() { client <- readStream(dc, reply, 2, &g) }()

		<-g.at(reply / 2)
		if k := l.Kill(); k != 1 {
			t.Fatalf("Kill hit %d carriers, want 1", k)
		}
		if _, err := dc.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after CloseWrite, during the migration: %v", err)
		}
		if err := <-client; err != nil {
			t.Fatalf("client reply: %v", err)
		}
		if err := <-server; err != nil {
			t.Fatalf("server: %v", err)
		}
		synctest.Wait()

		// Stimulus and load: the reply crossed a carrier death half way.
		if s := l.Stats(); s.Session.Killed != 1 || s.Session.BufferLost == 0 {
			t.Fatalf("link stats %+v: want one killed session carrier with bytes lost", s.Session)
		}
		if got := g.get(); got != reply {
			t.Fatalf("client received %d of %d bytes", got, reply)
		}
		fins := f.wire.pick(func(fr frame) bool { return fr.typ == wire.TypeFin && fr.out && fr.fate == fateWritten })
		var df, pf int
		for _, fr := range fins {
			if fr.tap.side == dialerSide {
				df++
				if fr.off != req {
					t.Fatalf("client FIN at %d, want %d", fr.off, req)
				}
			} else {
				pf++
			}
		}
		if df != 1 || pf < 1 {
			t.Fatalf("FINs on the wire: client %d, server %d; the acknowledged client FIN must not be resent", df, pf)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := c.Status(); st.Migrations != (rendr.MigrationCounts{Death: 1}) {
				t.Fatalf("%v migrations %+v, want 1 death", st.Role, st.Migrations)
			}
		}
		// The server's behaviour already closed its end; the client closes.
		if err := dc.Close(); err != nil {
			t.Fatal(err)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := waitEnded(t, c, 30*time.Second); st.Err != io.EOF {
				t.Fatalf("%v ended with %v", st.Role, st.Err)
			}
		}
		f.close()
	})
}

// TestFinNotBeforeStuckData_L04: in a bond, member A's writes block while it
// holds DATA; the rest of the data and the FIN travel on member B. The FIN
// reaches the passive above a hole — and the passive's Read does not return
// io.EOF until the stuck bytes arrive (by rescue on B or after A's death),
// after which it returns exactly the bytes written and then io.EOF.
func TestFinNotBeforeStuckData_L04(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 1 << 20
		f := newFixture(t, opts{}, "a", "b")
		la, lb := f.link("a"), f.link("b")
		la.SetDelay(time.Millisecond, 0)
		lb.SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a", "b"), rendr.DialOptions{Mode: rendr.ModeBond})
		eventually(t, 10*time.Second, "two bond members", func() bool {
			m := 0
			for _, c := range dc.Status().Carriers {
				if c.State == rendr.CarrierMember {
					m++
				}
			}
			return m == 2
		})
		synctest.Wait()

		type result struct {
			err error
			at  time.Time
		}
		read := make(chan result, 1)
		go func() {
			err := readStream(pc, n, 1, nil)
			read <- result{err, time.Now()}
		}()
		la.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
		if _, err := writeStream(dc, n, 1, 64<<10); err != nil {
			t.Fatal(err)
		}
		if err := dc.CloseWrite(); err != nil {
			t.Fatal(err)
		}

		// The FIN arrives on B while A still holds data below it.
		fin, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
			return fr.typ == wire.TypeFin && !fr.out && fr.tap.side == passiveSide
		})
		if !ok {
			t.Fatal("no FIN reached the passive")
		}
		synctest.Wait()
		if fin.tap.link != "b" || fin.off != n {
			t.Fatalf("FIN %+v on link %q, want offset %d on b", fin, fin.tap.link, n)
		}
		if rx := pc.Status().RxBytes; rx >= n {
			t.Fatalf("the passive had all %d bytes when the FIN arrived: nothing was stuck on A", rx)
		}
		select {
		case r := <-read:
			t.Fatalf("passive Read ended (%v) with a hole below the FIN", r.err)
		default:
		}
		if s := la.Stats(); s.Session.WritesBlocked < 1 {
			t.Fatalf("A's session writes blocked: %d", s.Session.WritesBlocked)
		}

		// The stuck bytes arrive (rescued on B, or replayed after A's
		// write-stall death); io.EOF only after all of them.
		r := <-read
		if r.err != nil {
			t.Fatalf("passive stream: %v", r.err)
		}
		if !r.at.After(fin.at) {
			t.Fatalf("io.EOF at %v, not after the FIN's arrival at %v", r.at, fin.at)
		}
		if fa := f.wire.count(func(fr frame) bool {
			return fr.typ == wire.TypeFin && fr.tap.link == "a" && fr.fate == fateWritten
		}); fa != 0 {
			t.Fatalf("%d FIN frames crossed the blocked member A", fa)
		}
		la.Release()
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
