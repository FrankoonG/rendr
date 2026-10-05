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
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// A peer that gives up waiting for our lost DONE (design §0.14 B4 extended
// to every RST code, M1c). Both ends stream to each other and our FIN is
// acknowledged; from then on nothing our side writes arrives (a path that
// fails in our direction only), so when we read the peer's stream to
// io.EOF our FIN_DELIVERED and our DONE are lost: the peer, which has
// closed, never learns that its FIN was delivered, lingers, and at its
// Linger resets the session with RST(Linger). Our exchange was complete —
// every byte and both FINs delivered — so that RST ends our session with
// io.EOF, the clean end the lost DONE would have given; before it,
// *AbortError{AbortLinger}. Before our DONE was sent (we left the peer's
// final byte unread) the same RST still ends with *AbortError (control).
// Helpers of this file start with "wpsess".

const (
	wpsessN          = 256 << 10       // bytes each way
	wpsessPeerLinger = 2 * time.Second // the waiting peer's Config.Linger
)

// wpsessTap returns side s's tap of the fixture's one session carrier.
func wpsessTap(t *testing.T, f *fixture, s side) *tap {
	t.Helper()
	taps := f.wire.sessionTaps(s, "a")
	if len(taps) != 1 {
		t.Fatalf("%d %v session carriers, want 1", len(taps), s)
	}
	return taps[0]
}

// TestWpsessLingerResetAfterLostDone_L05: the end of the waiting peer's
// linger reaches our side, which sent its DONE (dialer-waits: we are the
// dialer and the passive lingers; passive-waits: the reverse), or had not
// (before-done). Both carriers stay up (their death deadlines are 10 s, far
// beyond the 2 s linger), so the RST alone decides.
func TestWpsessLingerResetAfterLostDone_L05(t *testing.T) {
	for _, tc := range []struct {
		name     string
		usDialer bool
		done     bool
	}{
		{"dialer-waits", true, true},
		{"passive-waits", false, true},
		{"before-done", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { wpsessLingerReset(t, tc.usDialer, tc.done) })
		})
	}
}

func wpsessLingerReset(t *testing.T, usDialer, done bool) {
	o := opts{ov: testhooks.Overrides{DeadMin: 10 * time.Second, DeadMax: 10 * time.Second}}
	if usDialer {
		o.pcfg.Linger = wpsessPeerLinger
	} else {
		o.dcfg.Linger = wpsessPeerLinger
	}
	f := newFixture(t, o, "a")
	f.link("a").SetDelay(time.Millisecond, 0)
	dc, pc := f.open(f.peer("a"), rendr.DialOptions{Mode: rendr.ModeSelector})
	us, peer, usSide, peerSide, usLog, peerLog := dc, pc, dialerSide, passiveSide, f.dev, f.pev
	if !usDialer {
		us, peer, usSide, peerSide, usLog, peerLog = pc, dc, passiveSide, dialerSide, f.pev, f.dev
	}

	// Our stream and FIN; the peer reads them to io.EOF and acknowledges
	// our FIN as delivered.
	runWithin(t, time.Minute, "our stream", func() error {
		errs := make(chan error, 2)
		go func() { errs <- sendAndClose(us, wpsessN, 1) }()
		go func() { errs <- readStream(peer, wpsessN, 1, nil) }()
		return errors.Join(<-errs, <-errs)
	})
	if _, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
		return fr.finDelivered() && !fr.out && fr.tap.side == usSide
	}); !ok {
		t.Fatal("our side never read the peer's FIN_DELIVERED for our FIN")
	}

	// From our FIN_DELIVERED on, nothing we write arrives (whole writes are
	// swallowed, so the peer never sees an fseq gap): the peer's stream
	// itself is acknowledged and delivered in full first.
	ours := wpsessTap(t, f, usSide)
	var lost atomic.Bool
	ours.setPlan(func(_ *tap, fs []frame) planVerdict {
		for _, fr := range fs {
			if fr.finDelivered() {
				lost.Store(true)
			}
		}
		return planVerdict{swallow: lost.Load()}
	})

	// The peer's stream, FIN and Close (its linger starts); we read it to
	// io.EOF and Close (done), or leave its final byte unread (before-done).
	runWithin(t, time.Minute, "the peer's stream", func() error {
		if _, err := writeStream(peer, wpsessN, 2, 32<<10); err != nil {
			return err
		}
		return peer.Close()
	})
	closedAt := time.Now()
	if done {
		runWithin(t, time.Minute, "reading the peer's stream", func() error {
			if err := readStream(us, wpsessN, 2, nil); err != nil {
				return err
			}
			return us.Close()
		})
		// The writer places them after the Read that returned io.EOF.
		if _, ok := f.wire.wait(time.Second, func(fr frame) bool {
			return fr.tap == ours && fr.out && fr.done() && fr.fate == fateSwallowed
		}); !ok || !lost.Load() {
			t.Fatalf("our FIN_DELIVERED lost %v, our DONE lost %v: want both placed and lost (stimulus)", lost.Load(), ok)
		}
	} else {
		v := rendrtest.NewVerifier(2, wpsessN)
		runWithin(t, time.Minute, "reading all but the peer's final byte", func() error {
			_, err := io.CopyN(v, us, wpsessN-1)
			return err
		})
		if _, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
			return !fr.out && fr.typ == wire.TypeFin && fr.tap.side == usSide
		}); !ok {
			t.Fatal("the peer's FIN never reached our side (stimulus)")
		}
	}

	// The peer's linger expires: RST(Linger) reaches us.
	rst, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
		return !fr.out && fr.typ == wire.TypeRst && fr.tap.side == usSide
	})
	if !ok {
		t.Fatal("no RST reached our side")
	}
	if rst.rst != wire.RstLinger || rst.at.Sub(closedAt) < wpsessPeerLinger {
		t.Fatalf("RST code %d %v after the peer's Close, want RST(Linger) at its %v linger (stimulus)", rst.rst, rst.at.Sub(closedAt), wpsessPeerLinger)
	}
	st := waitEnded(t, us, 5*time.Second)
	end := endedAt(t, usLog, us)
	var ae *rendr.AbortError
	switch {
	case done && st.Err != io.EOF:
		t.Fatalf("our end %v, want io.EOF: our DONE was sent before the peer's RST(Linger)", st.Err)
	case !done && (!errors.As(st.Err, &ae) || ae.Code != rendr.AbortLinger || !ae.Remote):
		t.Fatalf("our end %v, want *AbortError{AbortLinger, Remote}", st.Err)
	}
	if d := end.Sub(rst.at); d < 0 || d > 50*time.Millisecond {
		t.Fatalf("our session ended %v after the RST arrived, want at it", d)
	}
	if st.NoPathEpisodes != 0 || st.Migrations != noMigrations {
		t.Fatalf("our side: %d no-path episodes, migrations %+v at an RST end, want none", st.NoPathEpisodes, st.Migrations)
	}
	if done {
		select {
		case <-us.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("our Done not closed after the end")
		}
	}
	if !done && lost.Load() {
		t.Fatal("our FIN_DELIVERED was placed in the before-done control (stimulus)")
	}
	if n := f.wire.count(func(fr frame) bool { return fr.done() && !fr.out && fr.tap.side == usSide }); n != 0 {
		t.Fatalf("our side read %d DONE frames: the peer had no DONE to send (stimulus)", n)
	}
	pst := waitEnded(t, peer, 5*time.Second)
	if !errors.Is(pst.Err, net.ErrClosed) {
		t.Fatalf("the peer ended with %v, want net.ErrClosed (its linger reset)", pst.Err)
	}
	if n := f.wire.count(func(fr frame) bool {
		return fr.out && fr.typ == wire.TypeRst && fr.rst == wire.RstLinger && fr.fate == fateWritten && fr.tap.side == peerSide
	}); n != 1 {
		t.Fatalf("the peer wrote %d RST(Linger) frames, want 1 (stimulus)", n)
	}
	if evs := peerLog.of(peer.ID(), rendr.EventSessionEnd); len(evs) != 1 {
		t.Fatalf("the peer: %d SessionEnd events, want 1", len(evs))
	}
	f.close()
}
