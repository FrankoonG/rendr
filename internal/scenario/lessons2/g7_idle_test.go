package lessons2

import (
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Parameters of the IdleTimeout scenarios (design §0.14 B5).
const (
	g7Idle   = 10 * time.Second       // Config.IdleTimeout (its minimum)
	g7Total  = 12 << 20               // one Write of 12 MiB
	g7Window = 8 << 20                // the default Window: what the Write commits at once
	g7Piece  = 4 << 10                // the slow reader takes 4 KiB ...
	g7Every  = 500 * time.Millisecond // ... every 500 ms (8 KiB/s)
)

// TestIdleTimeoutCountsDelivery_L19 (design §0.14 B5; L19: a session is
// judged by the delivery of application data, never by control traffic
// alone). IdleTimeout ends a session end whose application committed no
// Write or Read and none of whose sent bytes were acknowledged as delivered
// for that long.
//
// slow-reader: IdleTimeout 10 s on both ends. The dialer writes 12 MiB in
// one Write; the passive's application takes 4 KiB every 500 ms. The Write
// commits the 8 MiB window at once and then nothing for 30 s — a blocked
// Write wakes only once 256 KiB of room are free, 32 s at this rate — three
// times IdleTimeout, while the acknowledged delivery keeps moving: neither
// side times out (the stimulus: TxBytes unchanged and the Write blocked for
// 30 s, AckedBytes rising). The reader then drains the rest at full speed:
// the 12 MiB arrive intact (SHA-256), the Write returns (12 MiB, nil), the
// session ends cleanly and no RST crossed. Before B5 the dialer ended with
// ErrIdleTimeout at 10 s.
//
// reader-stops: IdleTimeout 10 s on the dialer only, PingIdle 1 s. The
// passive's application reads 4 KiB every 500 ms for 6 s, then stops. The
// dialer's blocked Write fails with ErrIdleTimeout exactly IdleTimeout after
// the last acknowledged delivery — 16 s after its last commit — although
// PINGs and PONGs kept crossing the carrier in between (carrier traffic is
// not activity), with one RST(Idle), and the passive ends with
// *AbortError{AbortIdle, Remote}.
func TestIdleTimeoutCountsDelivery_L19(t *testing.T) {
	t.Run("slow-reader", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const seed, slow = 19, 60 // 60 pieces: 30 s, 240 KiB
			cfg := rendr.Config{IdleTimeout: g7Idle}
			e := newEnv(t, cfg, cfg, nil)
			a := e.path("a", 5*time.Millisecond)
			dc, pc := e.open(e.peer(a), rendr.DialOptions{})
			src := prngBytes(seed, g7Total)
			w := goOp(func() (int, error) { return dc.Write(src) })
			synctest.Wait()
			if tx := dc.Status().TxBytes; tx != g7Window || !running(w) {
				t.Fatalf("Write committed %d bytes (running %v), want the %d-byte window and the call blocked", tx, running(w), g7Window)
			}

			h := sha256.New()
			buf := make([]byte, 64<<10)
			start := time.Now()
			for i := range slow {
				time.Sleep(g7Every)
				if _, err := io.ReadFull(pc, buf[:g7Piece]); err != nil {
					t.Fatalf("slow read %d of %d at %v: %v (dialer %v)", i+1, slow, time.Since(start), err, dc.Status().Err)
				}
				h.Write(buf[:g7Piece])
			}
			waitFor(t, time.Second, time.Millisecond, "the last piece acknowledged", func() bool {
				return dc.Status().AckedBytes == slow*g7Piece
			})
			ds, ps := dc.Status(), pc.Status()
			if ds.State != rendr.StateOpen || ps.State != rendr.StateOpen {
				t.Fatalf("after %v of slow reading: dialer %v (%v), passive %v (%v), want both open", time.Since(start), ds.State, ds.Err, ps.State, ps.Err)
			}
			if ds.TxBytes != g7Window || !running(w) {
				t.Fatalf("stimulus: the Write committed %d bytes (running %v) during %v, want none beyond the window", ds.TxBytes-g7Window, running(w), time.Since(start))
			}
			t.Logf("%v without a commit on the dialer (IdleTimeout %v); %d bytes acknowledged meanwhile", time.Since(start), g7Idle, ds.AckedBytes)

			// Drain the rest at full speed.
			for got := slow * g7Piece; got < g7Total; {
				n, err := pc.Read(buf[:min(len(buf), g7Total-got)])
				h.Write(buf[:n])
				got += n
				if err != nil && got < g7Total {
					t.Fatalf("drain after %d of %d bytes: %v", got, g7Total, err)
				}
			}
			if r := await(t, w, time.Minute, "the 12 MiB Write"); r.n != g7Total || r.err != nil {
				t.Fatalf("Write = (%d, %v), want (%d, nil)", r.n, r.err, g7Total)
			}
			if got, want := h.Sum(nil), sha256.Sum256(src); string(got) != string(want[:]) {
				t.Fatal("the 12 MiB arrived corrupted (SHA-256 mismatch)")
			}
			endClean(t, dc, pc)
			if n, m := len(a.sent(wire.TypeRst)), len(a.sentBack(wire.TypeRst)); n+m != 0 {
				t.Fatalf("%d RST from the dialer and %d from the passive, want none", n, m)
			}
			e.close()
		})
	})

	t.Run("reader-stops", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const seed, pieces = 20, 12 // 12 pieces: 6 s, 48 KiB
			e := newEnv(t, rendr.Config{IdleTimeout: g7Idle}, rendr.Config{}, &testhooks.Overrides{PingIdle: time.Second})
			a := e.path("a", 5*time.Millisecond)
			dc, pc := e.open(e.peer(a), rendr.DialOptions{})
			w := goOp(func() (int, error) { return dc.Write(prngBytes(seed, g7Total)) })
			synctest.Wait()
			committedAt := time.Now()
			if tx := dc.Status().TxBytes; tx != g7Window || !running(w) {
				t.Fatalf("Write committed %d bytes (running %v), want the %d-byte window and the call blocked", tx, running(w), g7Window)
			}

			v := prngBytes(seed, pieces*g7Piece)
			buf := make([]byte, g7Piece)
			for i := range pieces {
				time.Sleep(g7Every)
				if _, err := io.ReadFull(pc, buf); err != nil {
					t.Fatalf("read %d: %v", i+1, err)
				}
				if string(buf) != string(v[i*g7Piece:(i+1)*g7Piece]) {
					t.Fatalf("piece %d corrupted", i+1)
				}
			}
			// The reader stops. The last acknowledged delivery:
			waitFor(t, time.Second, time.Millisecond, "the last piece acknowledged", func() bool {
				return dc.Status().AckedBytes == pieces*g7Piece
			})
			ackedAt := time.Now()

			r := await(t, w, time.Minute, "the blocked Write")
			if !isTerminal(r.err, rendr.ErrIdleTimeout) || r.n != g7Window {
				t.Fatalf("blocked Write = (%d, %v), want (%d, ErrIdleTimeout)", r.n, r.err, g7Window)
			}
			if d := r.at.Sub(ackedAt); d > g7Idle || d <= g7Idle-2*time.Millisecond {
				t.Fatalf("the dialer timed out %v after the last acknowledged delivery (%v after its last commit), want IdleTimeout %v",
					d, r.at.Sub(committedAt), g7Idle)
			}
			if st := dc.Status(); st.Err != rendr.ErrIdleTimeout || st.AckedBytes != pieces*g7Piece {
				t.Fatalf("dialer ended with %v after %d bytes acknowledged, want ErrIdleTimeout after %d", st.Err, st.AckedBytes, pieces*g7Piece)
			}
			waitEnded(t, pc, 5*time.Second)
			var ae *rendr.AbortError
			if err := pc.Status().Err; !errors.As(err, &ae) || ae.Code != rendr.AbortIdle || !ae.Remote {
				t.Fatalf("passive ended with %v, want *AbortError{AbortIdle, Remote}", err)
			}
			if rs := a.sent(wire.TypeRst); len(rs) != 1 || rs[0].at.Before(r.at) {
				t.Fatalf("%d RST from the dialer, want one, sent at the timeout", len(rs))
			}
			between := func(fs []frameRec) (n int) {
				for _, f := range fs {
					if f.at.After(ackedAt) && f.at.Before(r.at) {
						n++
					}
				}
				return n
			}
			pings, pongs := between(a.sent(wire.TypePing)), between(a.sentBack(wire.TypePong))
			if pings < 5 || pongs < 5 {
				t.Fatalf("stimulus: %d PINGs and %d PONGs crossed while the session idled, want carrier traffic (≥ 5 each)", pings, pongs)
			}
			t.Logf("idle timeout %v after the last acknowledged delivery, %v after the last commit; %d PINGs and %d PONGs in between",
				r.at.Sub(ackedAt), r.at.Sub(committedAt), pings, pongs)
			e.close()
		})
	})
}
