package rendr

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Conn.Done (design §0.12 AA2). Helpers of these tests start with "cd".

// cdWatch observes one Conn's Done from the moment the Conn exists: a
// goroutine blocked on the channel records the Status it reads as soon as
// Done is closed, and the virtual time.
type cdWatch struct {
	name string
	c    *Conn
	done <-chan struct{} // c.Done() when the watch started
	seen chan struct{}   // closed once st and at are recorded
	st   SessionStatus
	at   time.Time
}

func cdWatchEnd(name string, c *Conn) *cdWatch {
	w := &cdWatch{name: name, c: c, done: c.Done(), seen: make(chan struct{})}
	go func() {
		<-w.done
		w.st, w.at = c.Status(), time.Now()
		close(w.seen)
	}()
	return w
}

// cdOpen requires that none of the sessions has ended and that no Done is
// closed. It runs after synctest.Wait: every goroutine of the bubble is
// durably blocked, so a closed Done would already have woken its watcher.
func cdOpen(t *testing.T, when string, ws ...*cdWatch) {
	t.Helper()
	synctest.Wait()
	for _, w := range ws {
		if isClosed(w.seen) || isClosed(w.c.Done()) {
			t.Fatalf("%s: %s Done closed before the end (Status at Done: %v, %v)", when, w.name, w.st.State, w.st.Err)
		}
		if st := w.c.Status(); st.State == StateEnded || st.Err != nil {
			t.Fatalf("%s: %s session already %v (%v) with Done open", when, w.name, st.State, st.Err)
		}
	}
}

// cdEnded waits at most within (virtual time) for w's Done and checks the
// end it observed: the Status read when Done closed is StateEnded with an
// Err that want accepts and lists only dead carriers (no live carrier and no
// dial attempt is left); the session's one SessionEnd event in log carries
// that same error, and Done closed no earlier than the event and within the
// end phase's bound (design §4.7); Done still returns the same channel. It
// returns the end error.
func cdEnded(t *testing.T, w *cdWatch, log *eventLog, within time.Duration, want func(error) bool) error {
	t.Helper()
	select {
	case <-w.seen:
	case <-time.After(within):
		t.Fatalf("%s: Done not closed %v later: %+v", w.name, within, w.c.Status())
	}
	st := w.st
	if st.State != StateEnded || st.Err == nil || !want(st.Err) {
		t.Fatalf("%s: Status when Done closed: state %v, err %v", w.name, st.State, st.Err)
	}
	if len(st.Carriers) == 0 {
		t.Fatalf("%s: no carrier in the final Status", w.name)
	}
	for _, cs := range st.Carriers {
		if cs.State != CarrierDead {
			t.Fatalf("%s: carrier %d %v when Done closed, want every carrier dead", w.name, cs.ID, cs.State)
		}
	}
	if w.c.Done() != w.done {
		t.Fatalf("%s: Done returned another channel after the end", w.name)
	}
	synctest.Wait() // the event worker delivered what was queued
	var ends []Event
	for _, ev := range log.of(EventSessionEnd) {
		if ev.Session == w.c.ID() {
			ends = append(ends, ev)
		}
	}
	if len(ends) != 1 || ends[0].Err != st.Err {
		t.Fatalf("%s: SessionEnd events %+v, want one with the final error %v", w.name, ends, st.Err)
	}
	if lag, bound := w.at.Sub(ends[0].Time), cdEndBound(); lag < 0 || lag > bound {
		t.Fatalf("%s: Done closed %v after the end decision, want within [0, %v]", w.name, lag, bound)
	}
	return st.Err
}

// cdEndBound is the end phase's bound with the default timing (design
// §4.7, §0.9 X2): carriers whose CLOSE is unwritten are killed after
// min(1 s, DeadMax), their stuck parts abandoned AbandonWait later, dial
// attempts abandoned 2·AbandonWait after their cancellation.
func cdEndBound() time.Duration {
	eff, _ := normalize(Config{}, nil)
	return max(min(time.Second, eff.cfg.DeadMax)+eff.timing.AbandonWait, 2*eff.timing.AbandonWait)
}

// cdFinal requires that each session's Status still reports the end its
// watcher saw at Done: the end error is final, nothing later — Runtime.Close
// included — changes it.
func cdFinal(t *testing.T, ws ...*cdWatch) {
	t.Helper()
	for _, w := range ws {
		if st := w.c.Status(); st.State != StateEnded || st.Err != w.st.Err {
			t.Fatalf("%s: later Status %v, %v; want the final %v seen at Done", w.name, st.State, st.Err, w.st.Err)
		}
	}
}

// cdSessionGoroutines returns the goroutines of package session and
// package carrier still running: none once every session's Done closed
// (fully ended: its scheduler, carriers and dial attempts exited).
func cdSessionGoroutines() map[string]int {
	_, by := rendrGoroutines()
	left := map[string]int{}
	for fn, n := range by {
		if strings.Contains(fn, "/internal/session.") || strings.Contains(fn, "/internal/carrier.") {
			left[fn] = n
		}
	}
	return left
}

// cdIs returns a matcher for errors.Is(err, target).
func cdIs(target error) func(error) bool {
	return func(err error) bool { return errors.Is(err, target) }
}

// cdAbort returns a matcher for an *AbortError with code and Remote.
func cdAbort(code AbortCode, remote bool) func(error) bool {
	return func(err error) bool {
		var ae *AbortError
		return errors.As(err, &ae) && ae.Code == code && ae.Remote == remote
	}
}

// TestConnDone (design §0.12 AA2): Conn.Done is closed exactly when the
// session has fully ended — never before — for the dialer's and the
// passive's Conn: at a clean end (both FINs delivered, DONE both ways), at
// an abort (the peer's RST), at a no-path end (ErrNoPath after the grace),
// and at a Runtime.Close reset (closed by the time Close returns). A
// watcher blocked on Done reads Status the moment it closes: StateEnded
// with the session's final Err — the same error as its one SessionEnd
// event, as Write returns, and as Status still reports after both Runtimes
// closed — and only dead carriers. Done closes no earlier than the end
// decision and within the end phase's bound; at every checkpoint before the
// end it is open while Status shows the session not ended. Once every
// Done closed, no goroutine of package session or carrier is left.
func TestConnDone(t *testing.T) {
	// The documented clean-end pattern, in both modes: each side reads until
	// io.EOF, closes and waits for Done; only then do the Runtimes close. A
	// half-closed session stays open (Done open) for a minute; a passive
	// that wrote a last reply and closed while its dialer has not read that
	// reply lingers (Closing, Done open: its FIN is not delivered yet); the
	// dialer's reads up to io.EOF complete the DONE exchange. The link's
	// delay makes the carriers' CLOSE exchange outlast the end decision of
	// the side that ends first: its Done waits for them.
	for _, mode := range []Mode{ModeSelector, ModeBond} {
		t.Run("clean end "+mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var dev, pev eventLog
				e := e2eNew(t, Config{OnEvent: dev.add}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
				e.links[0].SetDelay(25*time.Millisecond, 0)
				dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{Mode: mode})
				dw, sw := cdWatchEnd("dialer", dc), cdWatchEnd("passive", sc)
				cdOpen(t, "opened", dw, sw)
				e2eExchange(t, dc, sc, 1<<20, 1)
				cdOpen(t, "after the exchange", dw, sw)

				if err := dc.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if n, err := sc.Read(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Fatalf("passive Read after the dialer's FIN: (%d, %v)", n, err)
				}
				time.Sleep(time.Minute)
				cdOpen(t, "half-closed for a minute", dw, sw)

				reply := []byte("the passive's last reply")
				if _, err := sc.Write(reply); err != nil {
					t.Fatal(err)
				}
				if err := sc.Close(); err != nil { // the passive's FIN, behind the unread reply
					t.Fatal(err)
				}
				cdOpen(t, "passive closed, its reply and FIN unread", dw, sw)
				if st := sc.Status(); st.State != StateClosing {
					t.Fatalf("passive after Close: %v, want lingering (Closing)", st.State)
				}
				passiveDone := make(chan error, 1)
				go func() { // the passive application waits for its end
					<-sc.Done()
					passiveDone <- sc.Status().Err
				}()

				if got, err := io.ReadAll(dc); err != nil || string(got) != string(reply) { // until io.EOF
					t.Fatalf("dialer read %q, %v; want the reply, then io.EOF", got, err)
				}
				if err := dc.Close(); err != nil {
					t.Fatal(err)
				}
				cdEnded(t, dw, &dev, time.Second, cdIs(io.EOF))
				cdEnded(t, sw, &pev, time.Second, cdIs(io.EOF))
				if err := <-passiveDone; err != io.EOF {
					t.Fatalf("the passive application saw %v at Done", err)
				}
				if left := cdSessionGoroutines(); len(left) != 0 {
					t.Fatalf("goroutines of the ended sessions left: %v", left)
				}
				e.close() // Runtime.Close of both, after the end
				cdFinal(t, dw, sw)
			})
		})
	}

	// An abort: the passive closes while its dialer keeps sending, so it
	// resets the session (RST(Closed)): the dialer ends with the peer's RST,
	// *AbortError{AbortClosed, Remote}, which its Write returned too, and
	// the passive with net.ErrClosed.
	t.Run("abort", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var dev, pev eventLog
			e := e2eNew(t, Config{OnEvent: dev.add}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
			dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
			dw, sw := cdWatchEnd("dialer", dc), cdWatchEnd("passive", sc)
			sendErr := make(chan error, 1)
			go func() {
				buf := make([]byte, 32<<10)
				for {
					if _, err := dc.Write(buf); err != nil {
						sendErr <- err
						return
					}
				}
			}()
			if _, err := io.ReadFull(sc, make([]byte, 64<<10)); err != nil {
				t.Fatal(err)
			}
			cdOpen(t, "the dialer sending, the window full", dw, sw)
			if err := sc.Close(); err != nil {
				t.Fatal(err)
			}
			werr := <-sendErr
			derr := cdEnded(t, dw, &dev, time.Second, cdAbort(AbortClosed, true))
			if werr != derr {
				t.Fatalf("the dialer's Write returned %v, its final Status Err is %v", werr, derr)
			}
			cdEnded(t, sw, &pev, time.Second, cdIs(net.ErrClosed))
			if left := cdSessionGoroutines(); len(left) != 0 {
				t.Fatalf("goroutines of the ended sessions left: %v", left)
			}
			e.close()
			cdFinal(t, dw, sw)
		})
	})

	// A no-path end: the only carrier dies and every redial is refused. Both
	// ends stay open (InNoPath, Done open) until their grace expires —
	// NoPathGrace on the dialer, PassiveRetain on the passive, both counted
	// from the death — and then end with ErrNoPath.
	t.Run("no path", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var dev, pev eventLog
			e := e2eNew(t, Config{OnEvent: dev.add}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
			link := e.links[0]
			dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
			dw, sw := cdWatchEnd("dialer", dc), cdWatchEnd("passive", sc)
			e2eExchange(t, dc, sc, 64<<10, 2)
			grace := e.d.eff.cfg.NoPathGrace
			retain := e.d.eff.passiveRetain(grace)
			link.SetRefuse(true)
			death := time.Now()
			if n := link.Kill(); n != 1 {
				t.Fatalf("killed %d carriers, want 1", n)
			}
			for _, x := range []struct {
				w     *cdWatch
				log   *eventLog
				grace time.Duration
			}{{dw, &dev, grace}, {sw, &pev, retain}} {
				time.Sleep(time.Until(death.Add(x.grace - time.Millisecond)))
				cdOpen(t, "1 ms before the grace expires", x.w)
				if st := x.w.c.Status(); !st.InNoPath || st.NoPathEpisodes != 1 {
					t.Fatalf("%s 1 ms before the grace: InNoPath %v, %d episodes", x.w.name, st.InNoPath, st.NoPathEpisodes)
				}
				cdEnded(t, x.w, x.log, time.Second, cdIs(ErrNoPath))
				if at := x.w.at.Sub(death); at < x.grace {
					t.Fatalf("%s Done closed %v after the death, before its grace %v", x.w.name, at, x.grace)
				}
			}
			if left := cdSessionGoroutines(); len(left) != 0 {
				t.Fatalf("goroutines of the ended sessions left: %v", left)
			}
			e.close()
			cdFinal(t, dw, sw)
		})
	})

	// A Runtime.Close reset: the dialer Runtime closes with one open session
	// and one its application closed that still lingers (Closing, waiting for
	// the passive's DONE). Both dialer Dones are closed by the time Close
	// returns, each session ended with net.ErrClosed; the passive ends get
	// the reset, *AbortError{AbortGoingAway, Remote}.
	t.Run("Runtime.Close reset", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var dev, pev eventLog
			e := e2eNew(t, Config{OnEvent: dev.add}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
			peer := e.peer()
			dc, sc := e2eOpen(t, peer, e.ln, DialOptions{})
			lc, lp := e2eOpen(t, peer, e.ln, DialOptions{})
			ws := []*cdWatch{cdWatchEnd("open dialer", dc), cdWatchEnd("closed dialer", lc),
				cdWatchEnd("open passive", sc), cdWatchEnd("passive of the closed dialer", lp)}
			e2eExchange(t, dc, sc, 64<<10, 3)
			e2eExchange(t, lc, lp, 64<<10, 4)
			if err := lc.Close(); err != nil {
				t.Fatal(err)
			}
			cdOpen(t, "before Runtime.Close", ws...)
			if st := lc.Status(); st.State != StateClosing {
				t.Fatalf("closed dialer before Runtime.Close: %v, want lingering (Closing)", st.State)
			}
			if err := e.d.Close(); err != nil {
				t.Fatal(err)
			}
			for _, c := range []*Conn{dc, lc} {
				if !isClosed(c.Done()) {
					t.Fatalf("dialer session %v: Done open when Runtime.Close returned (%+v)", c.ID(), c.Status())
				}
			}
			for _, w := range ws[:2] {
				cdEnded(t, w, &dev, time.Second, cdIs(net.ErrClosed))
			}
			for _, w := range ws[2:] {
				cdEnded(t, w, &pev, time.Second, cdAbort(AbortGoingAway, true))
			}
			if left := cdSessionGoroutines(); len(left) != 0 {
				t.Fatalf("goroutines of the ended sessions left: %v", left)
			}
			e.close()
			cdFinal(t, ws...)
		})
	})
}
