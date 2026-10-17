package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
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
	end := cdEndEvent(t, w, log)
	if lag, bound := w.at.Sub(end.Time), cdEndBound(); lag < 0 || lag > bound {
		t.Fatalf("%s: Done closed %v after the end decision, want within [0, %v]", w.name, lag, bound)
	}
	return st.Err
}

// cdEndEvent returns the one SessionEnd event of w's session in log; it
// carries the final error w's watcher read when Done closed.
func cdEndEvent(t *testing.T, w *cdWatch, log *eventLog) Event {
	t.Helper()
	synctest.Wait() // the event worker delivered what was queued
	var ends []Event
	for _, ev := range log.of(EventSessionEnd) {
		if ev.Session == w.c.ID() {
			ends = append(ends, ev)
		}
	}
	if len(ends) != 1 || ends[0].Err != w.st.Err {
		t.Fatalf("%s: SessionEnd events %+v, want one with the final error %v", w.name, ends, w.st.Err)
	}
	return ends[0]
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
// package carrier still running, by entry function. Inside the bubble,
// after synctest.Wait, it lists none once every session's Done closed
// (its scheduler, carriers and dial attempts finished) except calls stuck
// in embedder code, which were abandoned and counted in Status.Abandoned.
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

// cdCount sums the goroutine counts of by.
func cdCount(by map[string]int) int {
	n := 0
	for _, k := range by {
		n += k
	}
	return n
}

// cdJoining counts the joining carriers of st: on the dialer, every dial
// attempt in flight is one.
func cdJoining(st SessionStatus) int {
	n := 0
	for _, cs := range st.Carriers {
		if cs.State == CarrierJoining {
			n++
		}
	}
	return n
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
// an abort (the peer's RST), at a no-path end (ErrNoPath after the grace;
// with a dial attempt in flight at the end, too), at a Runtime.Close reset
// (closed by the time Close returns), and at an end with a carrier call
// stuck in embedder code. A watcher blocked on Done reads Status the moment
// it closes: StateEnded with the session's final Err — the same error as
// its one SessionEnd event, as Write returns, and as Status still reports
// after both Runtimes closed — and only dead carriers (no dial attempt
// left). Done closes no earlier than the end decision and within the end
// phase's bound, and waits for the session's carriers and dial attempts: a
// stuck carrier call is abandoned and counted in the Runtime's
// Status.Abandoned when Done closes. At every checkpoint before the end Done
// is open while Status shows the session not ended. Once every Done closed,
// no goroutine of package session or carrier is left but the abandoned
// call, until it returns.
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
				// Done joins the session's own carriers: dedicated (M3-D2;
				// with mux it joins its views, TestViewGoneJoin_L52).
				dc, sc := e2eOpen(t, e.dedicatedPeer(), e.ln, DialOptions{Mode: mode})
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

	// A no-path end: the only carrier dies and no redial succeeds. Both ends
	// stay open (InNoPath, Done open) until their grace expires —
	// NoPathGrace on the dialer, PassiveRetain on the passive, both counted
	// from the death — and then end with ErrNoPath. Redials are either
	// refused at once (no attempt is in flight at the end) or hang in the
	// factory until their attempt is cancelled: the dialer's end decision
	// then finds a dial attempt in flight (a joining carrier in Status 1 ms
	// before the grace; the first redial ran into DialTimeout, the next one
	// started at once), and Done waits for that attempt, so the Status read
	// when Done closes lists no joining carrier.
	for _, tc := range []struct {
		name     string
		redials  func(*rendrtest.Link)
		inFlight int // dial attempts in flight at the dialer's end decision
	}{
		{"no path, redials refused", func(l *rendrtest.Link) { l.SetRefuse(true) }, 0},
		{"no path, a redial in flight", func(l *rendrtest.Link) { l.SetDial(rendrtest.DialHang) }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var dev, pev eventLog
				e := e2eNew(t, Config{OnEvent: dev.add}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
				link := e.links[0]
				dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
				dw, sw := cdWatchEnd("dialer", dc), cdWatchEnd("passive", sc)
				e2eExchange(t, dc, sc, 64<<10, 2)
				grace := e.d.eff.cfg.NoPathGrace
				retain := e.d.eff.passiveRetain(grace)
				tc.redials(link)
				death := time.Now()
				if n := link.Kill(); n != 1 {
					t.Fatalf("killed %d carriers, want 1", n)
				}
				for _, x := range []struct {
					w        *cdWatch
					log      *eventLog
					grace    time.Duration
					inFlight int
				}{{dw, &dev, grace, tc.inFlight}, {sw, &pev, retain, 0}} {
					time.Sleep(time.Until(death.Add(x.grace - time.Millisecond)))
					cdOpen(t, "1 ms before the grace expires", x.w)
					st := x.w.c.Status()
					if !st.InNoPath || st.NoPathEpisodes != 1 {
						t.Fatalf("%s 1 ms before the grace: InNoPath %v, %d episodes", x.w.name, st.InNoPath, st.NoPathEpisodes)
					}
					if n := cdJoining(st); n != x.inFlight {
						t.Fatalf("stimulus: %s 1 ms before the grace: %d joining carriers (dial attempts in flight), want %d: %+v", x.w.name, n, x.inFlight, st.Carriers)
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
	}

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

	// An end with a call stuck in embedder code: the dialer's carrier writes
	// block in the embedder's Write, ignoring deadlines and Close, while its
	// application keeps writing; then the passive Runtime closes, and its
	// reset reaches the dialer the other way. The passive ends with
	// net.ErrClosed; the dialer with the peer's RST,
	// *AbortError{AbortGoingAway, Remote}, which its blocked Write returned
	// too. The dialer's Done also waits for its carrier, whose writer stays
	// stuck in the embedder's Write after the carrier died: that writer is
	// abandoned after its bound and counted in the dialer Runtime's
	// Status.Abandoned (0 before, 1 as read the moment Done closes), so Done
	// closes no earlier than AbandonWait after the end decision and within
	// the end phase's bound; the abandoned writer is the only goroutine of
	// the session left. When the embedder's Write returns, the pool empties
	// and nothing is left.
	t.Run("stuck embedder call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var dev, pev eventLog
			e := e2eNew(t, Config{OnEvent: dev.add}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
			link := e.links[0]
			dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
			dw, sw := cdWatchEnd("dialer", dc), cdWatchEnd("passive", sc)
			abandoned := make(chan int, 1)
			go func() { // the Runtime's pool the moment the dialer's Done closes
				<-dc.Done()
				abandoned <- e.d.Status().Abandoned
			}()
			e2eExchange(t, dc, sc, 64<<10, 5)
			link.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
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
			synctest.Wait()
			if n, ab := link.Stats().Session.WritesBlocked, e.d.Status().Abandoned; n != 1 || ab != 0 {
				t.Fatalf("stimulus: %d session carrier writes blocked, %d goroutines abandoned; want the dialer's writer stuck in one, not abandoned yet", n, ab)
			}
			cdOpen(t, "the dialer's carrier writer stuck in the embedder", dw, sw)
			if err := e.p.Close(); err != nil {
				t.Fatal(err)
			}
			cdEnded(t, sw, &pev, time.Second, cdIs(net.ErrClosed))
			derr := cdEnded(t, dw, &dev, cdEndBound(), cdAbort(AbortGoingAway, true))
			if werr := <-sendErr; werr != derr {
				t.Fatalf("the dialer's Write returned %v, its final Status Err is %v", werr, derr)
			}
			wait := e.d.eff.timing.AbandonWait
			if lag := dw.at.Sub(cdEndEvent(t, dw, &dev).Time); lag < wait {
				t.Fatalf("dialer Done closed %v after the end decision, before its stuck writer could be abandoned (AbandonWait %v)", lag, wait)
			}
			if n := <-abandoned; n != 1 {
				t.Fatalf("dialer Runtime abandoned %d goroutines when Done closed, want the writer stuck in the embedder's Write", n)
			}
			if left := cdSessionGoroutines(); cdCount(left) != 1 {
				t.Fatalf("goroutines of the ended sessions left: %v, want only the abandoned writer", left)
			}
			link.Release() // the embedder's Write returns
			synctest.Wait()
			if n, left := e.d.Status().Abandoned, cdSessionGoroutines(); n != 0 || len(left) != 0 {
				t.Fatalf("after the Write returned: abandoned %d, goroutines of the ended sessions left: %v", n, left)
			}
			e.close()
			cdFinal(t, dw, sw)
		})
	})
}

// TestAbortDuringOutageReachesDialer_L47 (L47, plan §5; WP13 B-1): the
// passive application aborts (code 0x5000) while the session has no
// carrier: the dialer's only link was killed and refuses new carriers.
// The RST has no lane, the session ends and its tombstone keeps the code.
// A JOIN to that tombstone — here a raw one on a second link — is answered
// JOIN_ACK(UNKNOWN_SESSION) with the code in the RxNext field when its
// PREFACE carried OptEndCode (which the PREFACE_ACK echoes), and with the
// canonical, code-free JOIN_ACK otherwise (a dialer that does not know the
// bit: M3). Once the link accepts again the dialer's own rejoin ends its
// session with *AbortError{0x5000, Remote} instead of ErrSessionLost.
func TestAbortDuringOutageReachesDialer_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const code AbortCode = 0x5000
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "raw")
		dc, pc := e2eOpen(t, e.peer(e.links[0]), e.ln, DialOptions{})
		l := e.links[0]
		l.SetRefuse(true)
		if l.Kill() == 0 {
			t.Fatal("stimulus: no carrier killed")
		}
		time.Sleep(50 * time.Millisecond)
		pc.Abort(code, "outage")
		select {
		case <-pc.Done():
		case <-time.After(time.Second):
			t.Fatal("the passive session did not end")
		}
		if st := e.p.Status(); st.Sessions.Tombstones != 1 {
			t.Fatalf("stimulus: passive %+v, want the tombstone", st.Sessions)
		}
		for _, offer := range []bool{true, false} {
			opt, wantCode := uint32(0), uint32(0)
			if offer {
				opt, wantCode = wire.OptEndCode, uint32(code)
			}
			ackOpt, payload := rawJoin(t, e, opt, dc.ID())
			want := make([]byte, wire.JoinAckLen)
			wire.PutJoinAckMux(want, &wire.JoinAck{Status: wire.StatusUnknownSession}, wantCode)
			if ackOpt != opt || !bytes.Equal(payload, want) {
				t.Errorf("JOIN offering %#x: PREFACE_ACK opt %#x, JOIN_ACK % x; want opt %#x, % x", opt, ackOpt, payload, opt, want)
			}
		}
		l.SetRefuse(false)
		var ae *AbortError
		if _, err := dc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != code || !ae.Remote {
			t.Fatalf("the dialer after the outage: %v, want *AbortError{%#x, Remote}", err, code)
		}
		synctest.Wait()
		e.close()
	})
}

// rawJoin sends PREFACE(opt) ‖ JOIN(sid) for the dialer Runtime's instance
// on e's "raw" link and returns the PREFACE_ACK's opt and the JOIN_ACK's
// payload.
func rawJoin(t *testing.T, e *e2ePair, opt uint32, sid SessionID) (uint32, []byte) {
	t.Helper()
	nc, err := e.links[1].Dial(context.Background())
	if err != nil {
		t.Fatalf("raw Dial: %v", err)
	}
	defer nc.Close()
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Opt: opt, Instance: e.d.InstanceID(), CarrierID: 0x7777})
	jp := make([]byte, wire.JoinLen)
	wire.PutJoin(jp, &wire.Join{SID: sid, Mode: 1})
	hello := wire.AppendFrame(pre, wire.Header{Type: wire.TypeJoin, Fseq: wire.PrefaceFseq(pre), Handle: wire.SessionHandle}, jp)
	if _, err := nc.Write(hello); err != nil {
		t.Fatalf("raw hello: %v", err)
	}
	ab := make([]byte, wire.PrefaceLen)
	if _, err := io.ReadFull(nc, ab); err != nil {
		t.Fatalf("PREFACE_ACK: %v", err)
	}
	ack, err := wire.ParsePrefaceAck(ab)
	if err != nil || ack.Status != wire.PrefaceOK {
		t.Fatalf("PREFACE_ACK %+v %v", ack, err)
	}
	fb := make([]byte, wire.FrameOverhead+wire.JoinAckLen)
	if _, err := io.ReadFull(nc, fb); err != nil {
		t.Fatalf("JOIN_ACK: %v", err)
	}
	f, _, err := wire.DecodeFrame(fb)
	if err != nil || f.Type != wire.TypeJoinAck || f.Handle != wire.SessionHandle {
		t.Fatalf("response %+v %v", f.Header, err)
	}
	return ack.Opt, bytes.Clone(f.Payload)
}

// TestAbortDuringOutageReachesDialerOnView_L47 (L47; WP13 B-1): the same
// outage with two sessions on one MUX trunk. The passive aborts the first
// (code 0x5001) while the trunk is dead; the second survives. When the
// link accepts again, the factory refuses every carrier whose first frame
// is the aborted session's JOIN, so only the survivor's JOIN builds the new
// trunk and the aborted session's JOIN can only take a view of it (a fast
// path or a coalesced wait never calls the factory). That view's
// JOIN_ACK(UNKNOWN_SESSION) carries the code, and the dialer ends with
// *AbortError{0x5001, Remote}, not ErrSessionLost.
func TestAbortDuringOutageReachesDialerOnView_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const code AbortCode = 0x5001
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		l := e.links[0]
		var blocked atomic.Pointer[SessionID] // the session whose handle-1 JOIN the factory refuses
		var ownJoins atomic.Int32
		dial := func(ctx context.Context, first []byte) (net.Conn, error) {
			if sid := blocked.Load(); sid != nil && len(first) >= wire.PrefaceLen+wire.HeaderLen+16 {
				f, _, err := wire.DecodeFrame(first[wire.PrefaceLen:])
				if err == nil && f.Type == wire.TypeJoin && bytes.Equal(f.Payload[:16], sid[:]) {
					ownJoins.Add(1)
					return nil, errors.New("refused: the aborted session must take a view")
				}
			}
			return l.DialEarly(ctx, first)
		}
		p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "a", Dial: l.Dial, DialEarly: dial}}})
		if err != nil {
			t.Fatal(err)
		}
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		dc2, pc2 := e2eOpen(t, p, e.ln, DialOptions{})
		if st := e.d.Status().Mux; st.Carriers != 1 || st.Views != 2 {
			t.Fatalf("stimulus: dialer mux %+v, want both sessions on one trunk", st)
		}
		sid := dc.ID()
		blocked.Store(&sid)
		l.SetRefuse(true)
		if l.Kill() == 0 {
			t.Fatal("stimulus: no carrier killed")
		}
		time.Sleep(50 * time.Millisecond)
		pc.Abort(code, "outage")
		select {
		case <-pc.Done():
		case <-time.After(time.Second):
			t.Fatal("the passive session did not end")
		}
		w := goWrite(dc2, []byte("x"))
		l.SetRefuse(false)
		var ae *AbortError
		if _, err := dc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != code || !ae.Remote {
			t.Fatalf("the aborted session's dialer after the outage: %v, want *AbortError{%#x, Remote}", err, code)
		}
		if err := <-w; err != nil {
			t.Fatalf("survivor Write: %v", err)
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(pc2, b); err != nil || b[0] != 'x' {
			t.Fatalf("survivor: %q %v", b, err)
		}
		t.Logf("the aborted session's own JOIN dials refused: %d; dialer mux %+v", ownJoins.Load(), e.d.Status().Mux)
		dc2.Close()
		pc2.Close()
		synctest.Wait()
		p.Close()
		e.close()
	})
}

// goWrite writes b to c on its own goroutine.
func goWrite(c *Conn, b []byte) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := c.Write(b)
		ch <- err
	}()
	return ch
}

// M4 WP1 (m4-design §A2.1, §A5.4, §A12.1): the root side of Conn.Abort
// and Conn.SetIdleTimeout.

// TestConnAbortReservedCode (M4-D20): an Abort code below 256 is rendr's:
// Abort returns an error and does nothing (no RST on the wire, the session
// keeps working both ways); a code of 256 or more resets the session and
// reaches the peer as *AbortError{code, msg, Remote}.
func TestConnAbortReservedCode(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		defer e.close()
		var taps mxTaps
		defer taps.close()
		p := e.mxPeer(mxTapCarrier(e.links[0], &taps))
		dc, pc := mxOpen(t, p, e.ln, DialOptions{})
		for _, code := range []AbortCode{0, AbortClosed, AbortWithdrawn, 255} {
			if err := dc.Abort(code, "reserved"); err == nil {
				t.Fatalf("Abort(%d): nil, want an error", code)
			}
		}
		e2eExchange(t, dc, pc, 64<<10, 1)
		e2eExchange(t, pc, dc, 64<<10, 2)
		synctest.Wait()
		if n := len(mxFrames(taps.tap(t, 0), rendrtest.Up, rendrtest.FrameRst, 1)); n != 0 {
			t.Fatalf("%d RST frames after refused Aborts, want none", n)
		}
		if st := dc.Status(); st.State != StateOpen {
			t.Fatalf("state %v after refused Aborts, want open", st.State)
		}
		if err := dc.Abort(256, "first application code"); err != nil {
			t.Fatalf("Abort(256): %v", err)
		}
		var b [1]byte
		_, err := pc.Read(b[:])
		var ae *AbortError
		if !errors.As(err, &ae) || ae.Code != 256 || ae.Msg != "first application code" || !ae.Remote {
			t.Fatalf("the peer's Read: %v, want *AbortError{256, msg, Remote}", err)
		}
		if _, err := dc.Write(b[:]); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after Abort: %v, want net.ErrClosed", err)
		}
		e2eDone(t, dc, 5*time.Second)
		e2eDone(t, pc, 5*time.Second)
		if n := len(mxFrames(taps.tap(t, 0), rendrtest.Up, rendrtest.FrameRst, 1)); n != 1 {
			t.Fatalf("%d RST frames, want 1", n)
		}
	})
}

// TestConnSetIdleTimeout (M4-D21): Conn.SetIdleTimeout applies the
// Runtime's clamp floor (testhooks.MinIdleTimeout lowers it) and expires
// a quiet session at the new limit: ErrIdleTimeout here, AbortIdle at the
// peer.
func TestConnSetIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := &testhooks.Overrides{MinIdleTimeout: time.Second}
		e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
		defer e.close()
		dc, pc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
		opened := time.Now()
		if err := dc.SetIdleTimeout(100 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		e2eDone(t, dc, 10*time.Second)
		if el := time.Since(opened); el < time.Second || el > 3*time.Second {
			t.Fatalf("the session ended %v after the open, want about 1 s (the lowered floor)", el)
		}
		if err := dc.Status().Err; !errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("end error %v, want ErrIdleTimeout", err)
		}
		e2eDone(t, pc, 5*time.Second)
		var ae *AbortError
		if err := pc.Status().Err; !errors.As(err, &ae) || ae.Code != AbortIdle || !ae.Remote {
			t.Fatalf("the peer's end error %v, want *AbortError{AbortIdle, Remote}", err)
		}
		if err := dc.SetIdleTimeout(time.Minute); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SetIdleTimeout after the end: %v, want net.ErrClosed", err)
		}
	})
}

// TestConnSetIdleTimeoutNegativeIsOff (M4-D21, C-2): a negative
// SetIdleTimeout turns idle expiry off, as 0 does (it is not raised to the
// 10 s floor), and it overrides the Runtime's Config.IdleTimeout: a quiet
// session is still open 25 h later (past the 24 h ceiling), and data still
// moves both ways.
func TestConnSetIdleTimeoutNegativeIsOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := Config{IdleTimeout: 10 * time.Second, PingIdle: time.Minute}
		e := e2eNew(t, cfg, Config{PingIdle: time.Minute}, nil, ListenConfig{}, "a")
		defer e.close()
		dc, pc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
		if err := dc.SetIdleTimeout(-1); err != nil {
			t.Fatal(err)
		}
		select {
		case <-dc.s.Done():
			t.Fatalf("the session ended after SetIdleTimeout(-1): %v", dc.Status().Err)
		case <-pc.s.Done():
			t.Fatalf("the peer ended after SetIdleTimeout(-1): %v", pc.Status().Err)
		case <-time.After(25 * time.Hour):
		}
		e2eExchange(t, dc, pc, 64<<10, 7)
		if err := dc.Status().Err; err != nil {
			t.Fatalf("end error %v after 25 h idle, want none", err)
		}
		e2eFinish(t, dc, pc)
	})
}

// TestPacketLogicalAddr_L38 (destination check): WriteTo accepts only nil
// or the session's remote Addr (also as a non-nil *Addr); any other
// address — another session's Addr, a typed nil *Addr, a *net.UDPAddr, a
// foreign net.Addr whose String panics — returns (0,
// ErrPacketDestinationMismatch) without calling any method of it and
// without reaching the session. (The end-to-end half — the address stable
// across migrations, the token reaching the factory — is
// TestPacketLogicalAddrE2E_L38.)
func TestPacketLogicalAddr_L38(t *testing.T) {
	remote := Addr{Instance: InstanceID(wpInst(1)), Session: SessionID(wpSID(1))}
	c := &PacketConn{remote: remote} // no session: a mismatch never reaches it
	other := remote
	other.Session[15] ^= 1
	var typedNil *Addr
	for _, tc := range []struct {
		name string
		addr net.Addr
	}{
		{"another session", other},
		{"another session by pointer", &other},
		{"typed nil *Addr", typedNil},
		{"UDP address", &net.UDPAddr{Port: 1}},
		{"foreign address whose String panics", panicAddr{}},
	} {
		if n, err := c.WriteTo([]byte("x"), tc.addr); n != 0 || !errors.Is(err, ErrPacketDestinationMismatch) {
			t.Errorf("%s: WriteTo = %d, %v", tc.name, n, err)
		}
	}
	for _, a := range []net.Addr{nil, remote, &remote} {
		if !c.isRemote(a) {
			t.Errorf("isRemote(%v) = false", a)
		}
	}
	if c.RemoteAddr() != net.Addr(remote) {
		t.Fatal("RemoteAddr")
	}
}
