package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP1 (m4-design §A7.6, §A12.1): Session.Abort and
// Session.SetIdleTimeout on two real sessions over rendrtest links inside
// synctest bubbles (the actor harness). Helpers start with "c4" (core
// API, M4).

// c4Taps wraps a link's Dial so that every carrier of a factory passes
// through a rendrtest.Tamper, whose frame log counts what went on the wire.
type c4Taps struct {
	mu  sync.Mutex
	tps []*rendrtest.Tamper
}

func (c *c4Taps) dial(l *rendrtest.Link) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		nc, err := l.Dial(ctx)
		if err != nil {
			return nil, err
		}
		a, a2 := net.Pipe()
		tp := rendrtest.NewTamper(a2, nc)
		c.mu.Lock()
		c.tps = append(c.tps, tp)
		c.mu.Unlock()
		return a, nil
	}
}

// count returns the frames of type typ forwarded in direction d by every
// tamper so far.
func (c *c4Taps) count(d rendrtest.Dir, typ rendrtest.FrameType) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, tp := range c.tps {
		for _, f := range tp.Log(d) {
			if f.Type == typ {
				n++
			}
		}
	}
	return n
}

func (c *c4Taps) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, tp := range c.tps {
		tp.Close()
	}
}

// c4Open is acWorld.open with a prepared spec.
func c4Open(w *acWorld, spec DialSpec) (dialer, passive *Session) {
	w.t.Helper()
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := w.dial(context.Background(), spec, nil)
		ch <- res{s, err}
	}()
	passive = w.confirmNext()
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.s, passive
}

// c4IsAbort reports err as the peer's RST with code.
func c4IsAbort(err error, code AbortCode) bool {
	var ae *AbortError
	return errors.As(err, &ae) && ae.Code == code && ae.Remote
}

// c4Await waits for ch within a virtual-time bound.
func c4Await[T any](t testing.TB, ch <-chan T, within time.Duration, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(within):
		t.Fatalf("%s: not within %v", what, within)
	}
	var zero T
	return zero
}

type c4IOResult struct {
	n   int
	err error
}

// TestSessionAbortSendsRst (M4-D20): Abort with blocked calls on both
// sides and undelivered data in both directions. The aborting side's
// blocked Write and its later Read, Write return net.ErrClosed; the peer's
// blocked Write and its Read (with bytes still buffered) return
// *AbortError{code, msg, Remote}; both sessions end and are done; exactly
// one RST and no FIN went to the peer, also with a CloseWrite and a Close
// right after the Abort, and nothing came back but the carrier's close.
func TestSessionAbortSendsRst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l := w.link("a")
		var taps c4Taps
		defer taps.close()
		spec := w.spec(ModeSelector, l)
		spec.Factories[0].Dial = taps.dial(l)
		d, p := c4Open(w, spec)

		// Neither side reads: each one's Write blocks once the peer's
		// window (1 MiB) is full.
		dw, pw := make(chan c4IOResult, 1), make(chan c4IOResult, 1)
		go func() { n, err := d.Write(make([]byte, 3<<20)); dw <- c4IOResult{n, err} }()
		go func() { n, err := p.Write(make([]byte, 3<<20)); pw <- c4IOResult{n, err} }()
		synctest.Wait()
		time.Sleep(time.Second) // let both windows fill
		synctest.Wait()
		if len(dw)+len(pw) != 0 {
			t.Fatal("a Write returned before the Abort: the premise (both blocked) failed")
		}
		for _, s := range []*Session{d, p} {
			if b := stLocked(s, func(st *stream) uint64 { return st.rTail - st.rRead }); b == 0 {
				t.Fatalf("the %v buffered nothing: no undelivered data", s.Role())
			}
		}

		const code = AbortCode(0x4C34_0101)
		long := string(make([]byte, 300)) // cut to 255 bytes
		if err := d.Abort(uint32(code), "bye"+long); err != nil {
			t.Fatalf("Abort: %v", err)
		}
		// At once, before the actor ended the session: the peer's bytes
		// are buffered here, and a Read no longer returns them.
		var b [8]byte
		if n, err := d.Read(b[:]); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read right after Abort: (%d, %v), want net.ErrClosed", n, err)
		}
		if err := d.Abort(uint32(code)+1, "again"); err != nil {
			t.Fatalf("a second Abort: %v", err)
		}
		if err := d.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite after Abort: %v", err)
		}
		if err := d.Close(); err != nil {
			t.Fatalf("Close after Abort: %v", err)
		}
		if r := c4Await(t, dw, time.Second, "the aborting side's blocked Write"); !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("the aborting side's blocked Write: (%d, %v), want net.ErrClosed", r.n, r.err)
		}
		if n, err := d.Read(b[:]); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after Abort: (%d, %v), want net.ErrClosed", n, err)
		}
		if n, err := d.Write(b[:]); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after Abort: (%d, %v), want net.ErrClosed", n, err)
		}
		r := c4Await(t, pw, 5*time.Second, "the peer's blocked Write")
		if !c4IsAbort(r.err, code) {
			t.Fatalf("the peer's blocked Write: (%d, %v), want *AbortError{%#x, Remote}", r.n, r.err, code)
		}
		var ae *AbortError
		errors.As(r.err, &ae)
		if len(ae.Msg) != 255 || ae.Msg[:3] != "bye" {
			t.Fatalf("the peer's AbortError message: %d bytes %q…, want 255 starting with %q", len(ae.Msg), ae.Msg[:min(3, len(ae.Msg))], "bye")
		}
		if n, err := p.Read(b[:]); n != 0 || !c4IsAbort(err, code) {
			t.Fatalf("the peer's Read with bytes buffered: (%d, %v), want the AbortError", n, err)
		}
		if n, err := p.Write(b[:]); n != 0 || !c4IsAbort(err, code) {
			t.Fatalf("the peer's Write: (%d, %v), want the AbortError", n, err)
		}
		acDone(t, d, 5*time.Second)
		acDone(t, p, 5*time.Second)
		if err := d.Status().Err; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the aborting session's end error %v, want net.ErrClosed", err)
		}
		if err := p.Status().Err; !c4IsAbort(err, code) {
			t.Fatalf("the peer's end error %v, want the AbortError", err)
		}
		if n := taps.count(rendrtest.Up, rendrtest.FrameRst); n != 1 {
			t.Fatalf("%d RST frames from the aborting side, want exactly 1", n)
		}
		if n := taps.count(rendrtest.Up, rendrtest.FrameFin); n != 0 {
			t.Fatalf("%d FIN frames from the aborting side, want none", n)
		}
		if n := taps.count(rendrtest.Down, rendrtest.FrameRst) + taps.count(rendrtest.Down, rendrtest.FrameFin); n != 0 {
			t.Fatalf("%d RST or FIN frames from the peer, want none", n)
		}
	})
}

// TestAbortAfterCloseReplacesLinger (M4-D20): a Close that lingers (the
// peer never closes, so no DONE comes) followed by an Abort ends the
// session at once with the Abort's RST, not RST(Linger) at the Linger
// deadline.
func TestAbortAfterCloseReplacesLinger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		d, p := w.open(ModeSelector, nil, w.link("a"))
		if _, err := d.Write(make([]byte, 64<<10)); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(w.a.p.Linger / 4)
		synctest.Wait()
		if st := d.State(); st == StateEnded {
			t.Fatalf("the session ended %v into its linger: the premise failed", w.a.p.Linger/4)
		}
		const code = AbortCode(0x1234)
		start := time.Now()
		if err := d.Abort(uint32(code), "reset"); err != nil {
			t.Fatal(err)
		}
		acDone(t, d, 5*time.Second)
		acDone(t, p, 5*time.Second)
		if el := time.Since(start); el >= w.a.p.Linger/2 {
			t.Fatalf("the aborted session took %v to finish, want well under the remaining linger", el)
		}
		ends := w.a.ev.of(d.ID(), EventSessionEnd)
		if len(ends) != 1 || ends[0].Time.Sub(start) > 10*time.Millisecond {
			t.Fatalf("the session-end events %+v: want one within 10 ms of the Abort", ends)
		}
		if err := p.Status().Err; !c4IsAbort(err, code) {
			t.Fatalf("the peer's end error %v, want *AbortError{%#x, Remote} (not the Linger reset)", err, code)
		}
	})
}

// TestAbortAfterEndNoop (M4-D20): Abort after a clean end changes nothing
// and sends nothing; SetIdleTimeout then returns net.ErrClosed.
func TestAbortAfterEndNoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l := w.link("a")
		var taps c4Taps
		defer taps.close()
		spec := w.spec(ModeSelector, l)
		spec.Factories[0].Dial = taps.dial(l)
		d, p := c4Open(w, spec)
		for _, s := range []*Session{d, p} {
			if err := s.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		}
		for _, s := range []*Session{d, p} {
			var b [1]byte
			if n, err := s.Read(b[:]); n != 0 || err != io.EOF {
				t.Fatalf("Read: (%d, %v), want io.EOF", n, err)
			}
			s.Close()
		}
		acDone(t, d, 5*time.Second)
		acDone(t, p, 5*time.Second)
		for _, s := range []*Session{d, p} {
			if err := s.Abort(0x777, "late"); err != nil {
				t.Fatalf("Abort after the end: %v", err)
			}
			if st := s.Status(); st.State != StateEnded || st.Err != io.EOF {
				t.Fatalf("after a late Abort: state %v, err %v, want the clean end", st.State, st.Err)
			}
			if err := s.SetIdleTimeout(time.Minute); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("SetIdleTimeout after the end: %v, want net.ErrClosed", err)
			}
		}
		synctest.Wait()
		if n := taps.count(rendrtest.Up, rendrtest.FrameRst) + taps.count(rendrtest.Down, rendrtest.FrameRst); n != 0 {
			t.Fatalf("%d RST frames, want none", n)
		}
	})
}

// TestAbortRacesCloseAndRead_L07 (M4-D20, L07): 1,000 sessions, each with
// an Abort racing a blocked Read and one of Close, CloseWrite or the
// peer's own Abort. Every call returns; each side ends once with one
// error from the allowed set: the aborting side net.ErrClosed (or the
// peer's RST when both aborted), the peer the Abort's RST — never io.EOF,
// RST(Linger) or RST(Closed). When the Abort won its race with CloseWrite
// the peer never reads io.EOF.
func TestAbortRacesCloseAndRead_L07(t *testing.T) {
	// 1,000 iterations in bubbles of perBubble: a world numbers its
	// sessions with one byte (acWorld.spec), so it opens at most 255.
	const iterations, perBubble = 1000, 50
	const dCode, pCode = AbortCode(0x5001), AbortCode(0x5002)
	for base := 0; base < iterations; base += perBubble {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			l := w.link("a")
			for i := base; i < base+perBubble; i++ {
				d, p := w.open(ModeSelector, nil, l)
				variant := i % 3
				start := make(chan struct{})
				var wg sync.WaitGroup
				read := make(chan c4IOResult, 1)
				go func() {
					var b [16]byte
					n, err := d.Read(b[:])
					read <- c4IOResult{n, err}
				}()
				if i%2 == 0 {
					synctest.Wait() // the Read is blocked before the race (else it races too)
				}
				wg.Go(func() {
					<-start
					if err := d.Abort(uint32(dCode), "race"); err != nil {
						t.Errorf("#%d Abort: %v", i, err)
					}
				})
				wg.Go(func() {
					<-start
					var err error
					switch variant {
					case 0:
						err = d.Close()
					case 1:
						err = d.CloseWrite()
					case 2:
						err = p.Abort(uint32(pCode), "race")
					}
					if err != nil {
						t.Errorf("#%d variant %d call: %v", i, variant, err)
					}
				})
				close(start)
				wg.Wait()
				r := c4Await(t, read, 5*time.Second, "the blocked Read")
				acDone(t, d, 5*time.Second)
				acDone(t, p, 5*time.Second)
				finSuppressed := stLocked(d, func(st *stream) bool { return st.fin.off == noFinOff })
				de, pe := d.Status().Err, p.Status().Err
				switch variant {
				case 0, 1:
					if !errors.Is(r.err, net.ErrClosed) || r.n != 0 {
						t.Fatalf("#%d variant %d: the blocked Read (%d, %v), want net.ErrClosed", i, variant, r.n, r.err)
					}
					if !errors.Is(de, net.ErrClosed) {
						t.Fatalf("#%d variant %d: the aborting side ended with %v, want net.ErrClosed", i, variant, de)
					}
					if !c4IsAbort(pe, dCode) {
						t.Fatalf("#%d variant %d: the peer ended with %v, want *AbortError{%#x, Remote}", i, variant, pe, dCode)
					}
				case 2:
					if r.n != 0 || !(errors.Is(r.err, net.ErrClosed) || c4IsAbort(r.err, pCode)) {
						t.Fatalf("#%d both abort: the blocked Read (%d, %v)", i, r.n, r.err)
					}
					if !(errors.Is(de, net.ErrClosed) || c4IsAbort(de, pCode)) {
						t.Fatalf("#%d both abort: the dialer ended with %v", i, de)
					}
					if !(errors.Is(pe, net.ErrClosed) || c4IsAbort(pe, dCode)) {
						t.Fatalf("#%d both abort: the passive ended with %v", i, pe)
					}
				}
				if variant != 2 {
					var b [1]byte
					n, err := p.Read(b[:])
					if err == io.EOF && finSuppressed {
						t.Fatalf("#%d variant %d: the peer read io.EOF although the Abort suppressed the FIN", i, variant)
					}
					if n != 0 || err == nil {
						t.Fatalf("#%d variant %d: the peer's Read after the end: (%d, %v)", i, variant, n, err)
					}
				}
			}
		})
	}
}

// c4EndAt waits for s to end (within, virtual time) and returns its
// SessionEnd event's time from events ev.
func c4EndAt(t testing.TB, ev *acEvents, s *Session, within time.Duration) time.Time {
	t.Helper()
	acWaitFor(t, within, "the session ends", func() bool { return s.State() == StateEnded })
	ends := ev.of(s.ID(), EventSessionEnd)
	if len(ends) != 1 {
		t.Fatalf("%d SessionEnd events, want 1", len(ends))
	}
	return ends[0].Time
}

// c4Near fails unless got is within [want − 5 ms, want + slack]: want is
// measured on the dialer once Dial returned, and a passive session opened
// one link delay (1 ms) earlier.
func c4Near(t testing.TB, what string, got, want time.Time, slack time.Duration) {
	t.Helper()
	if d := got.Sub(want); d < -5*time.Millisecond || d > slack {
		t.Fatalf("%s %v off the expected instant, want within [-5ms, +%v]", what, d, slack)
	}
}

// TestSetIdleTimeoutOverrides_L30 (M4-D21, L30): the per-session override
// replaces Params.IdleTimeout on either role, with the clock counted from
// the last activity (not restarted by the call); 0 and negative values
// turn expiry off; the clamp is [MinIdleTimeout (10 s by default), 24 h].
// The side that expires ends with ErrIdleTimeout, its peer with
// *AbortError{AbortIdle, Remote}.
func TestSetIdleTimeoutOverrides_L30(t *testing.T) {
	type row struct {
		name     string
		cfg      time.Duration // Params.IdleTimeout of the overriding side
		floor    time.Duration // its Params.MinIdleTimeout
		passive  bool          // override on the passive instead of the dialer
		set      time.Duration // SetIdleTimeout's argument
		after    time.Duration // when it is called, from the open
		expireAt time.Duration // from the open; 0: never (checked for 5 min, within the watchdog)
	}
	rows := []row{
		{name: "dialer shorter", cfg: time.Hour, set: 30 * time.Second, after: 5 * time.Second, expireAt: 30 * time.Second},
		{name: "passive shorter", cfg: time.Hour, passive: true, set: 30 * time.Second, after: 5 * time.Second, expireAt: 30 * time.Second},
		{name: "longer than config", cfg: 20 * time.Second, set: time.Minute, after: 5 * time.Second, expireAt: time.Minute},
		{name: "already past", cfg: time.Hour, set: 10 * time.Second, after: 40 * time.Second, expireAt: 40 * time.Second},
		{name: "zero turns it off", cfg: 20 * time.Second, set: 0, after: 5 * time.Second},
		{name: "negative turns it off", cfg: 20 * time.Second, passive: true, set: -time.Second, after: 5 * time.Second},
		{name: "raised to 10 s", set: time.Second, after: 0, expireAt: 10 * time.Second},
		{name: "test floor", floor: time.Second, set: 2 * time.Second, after: 0, expireAt: 2 * time.Second},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				// The overriding side has cfg; its peer has idle expiry
				// off, so only the override decides.
				onP := &w.a.p
				if r.passive {
					onP = &w.b.p
				}
				onP.IdleTimeout, onP.MinIdleTimeout = r.cfg, r.floor
				d, p := w.open(ModeSelector, nil, w.link("a"))
				opened := time.Now()
				time.Sleep(r.after)
				on, other, onEv := d, p, w.a.ev
				if r.passive {
					on, other, onEv = p, d, w.b.ev
				}
				if err := on.SetIdleTimeout(r.set); err != nil {
					t.Fatalf("SetIdleTimeout: %v", err)
				}
				if r.expireAt == 0 {
					time.Sleep(5 * time.Minute)
					synctest.Wait()
					if d.State() != StateOpen || p.State() != StateOpen {
						t.Fatalf("states %v, %v after 5 min with idle expiry off, want both open", d.State(), p.State())
					}
					if v := stLocked(on, func(st *stream) time.Duration { return st.idleOverride }); v != 0 {
						t.Fatalf("idle override %v, want 0 (off)", v)
					}
					return
				}
				at := c4EndAt(t, onEv, on, r.expireAt+time.Minute)
				c4Near(t, "idle expiry", at, opened.Add(r.expireAt), 20*time.Millisecond)
				if err := on.Status().Err; !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("the expiring side ended with %v, want ErrIdleTimeout", err)
				}
				acDone(t, other, 5*time.Second)
				if err := other.Status().Err; !c4IsAbort(err, AbortIdle) {
					t.Fatalf("its peer ended with %v, want *AbortError{AbortIdle, Remote}", err)
				}
			})
		})
	}
	t.Run("upper clamp", func(t *testing.T) {
		s := stSession(stOpt{})
		if err := s.SetIdleTimeout(48 * time.Hour); err != nil {
			t.Fatal(err)
		}
		if v := stLocked(s, func(st *stream) time.Duration { return st.idleOverride }); v != 24*time.Hour {
			t.Fatalf("48 h became %v, want 24 h", v)
		}
	})
}

// TestSetIdleTimeoutWakesParkedActor (M4-D21, M3-D42): with idle expiry
// off the quiet session's actors park (nothing to wait for); SetIdleTimeout
// rings the actor, which then expires the session at once when the new
// limit already passed, or arms the new deadline and expires it there.
func TestSetIdleTimeoutWakesParkedActor(t *testing.T) {
	for _, r := range []struct {
		name     string
		after    time.Duration
		expireAt time.Duration
	}{
		{"already past", 60 * time.Second, 60 * time.Second},
		{"in the future", 5 * time.Second, 10 * time.Second},
	} {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				var actors atomic.Int64
				w.a.p.Actors = &actors
				d, _ := w.open(ModeSelector, nil, w.link("a"))
				opened := time.Now()
				time.Sleep(r.after)
				synctest.Wait()
				if n := actors.Load(); n != 0 {
					t.Fatalf("%d dialer actors running %v after the open, want 0 (parked)", n, r.after)
				}
				if err := d.SetIdleTimeout(10 * time.Second); err != nil {
					t.Fatal(err)
				}
				at := c4EndAt(t, w.a.ev, d, time.Minute)
				c4Near(t, "idle expiry", at, opened.Add(r.expireAt), 5*time.Millisecond)
				if err := d.Status().Err; !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("end error %v, want ErrIdleTimeout", err)
				}
			})
		})
	}
}

// TestIdleTimeoutNoMigration_L30 (L30, M4-D21): an idle expiry set by
// SetIdleTimeout on a selector session with a second path ends the session
// with ErrIdleTimeout at the limit and is never taken for a path failure:
// no migration, no rejoin, no redial (the second factory is never called),
// no carrier down and no no-path episode before the end, on either side.
func TestIdleTimeoutNoMigration_L30(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		la, lb := w.link("a"), w.link("b")
		spec := w.spec(ModeSelector, la, lb)
		var dials [2]atomic.Int32
		for i, l := range []*rendrtest.Link{la, lb} {
			spec.Factories[i].Dial = func(ctx context.Context) (net.Conn, error) {
				dials[i].Add(1)
				return l.Dial(ctx)
			}
		}
		d, p := c4Open(w, spec)
		opened := time.Now()
		if _, err := d.Write(make([]byte, 32<<10)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32<<10)
		if _, err := io.ReadFull(p, buf); err != nil {
			t.Fatal(err)
		}
		lastActive := time.Now()
		if err := d.SetIdleTimeout(10 * time.Second); err != nil {
			t.Fatal(err)
		}
		at := c4EndAt(t, w.a.ev, d, time.Minute)
		if at.Before(lastActive.Add(10*time.Second)) || at.After(opened.Add(10*time.Second+time.Second)) {
			t.Fatalf("idle expiry %v after the open, want 10 s after the last activity", at.Sub(opened))
		}
		if err := d.Status().Err; !errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("end error %v, want ErrIdleTimeout", err)
		}
		acDone(t, p, 5*time.Second)
		if err := p.Status().Err; !c4IsAbort(err, AbortIdle) {
			t.Fatalf("the peer's end error %v, want *AbortError{AbortIdle, Remote}", err)
		}
		for _, s := range []struct {
			s  *Session
			ev *acEvents
		}{{d, w.a.ev}, {p, w.b.ev}} {
			st := s.s.Status()
			if st.MigDeath+st.MigQuality+st.MigExplicit+st.Rejoins+st.NoPathEpisodes != 0 {
				t.Fatalf("%v: migrations %d/%d/%d, rejoins %d, no-path episodes %d, want none",
					s.s.Role(), st.MigDeath, st.MigQuality, st.MigExplicit, st.Rejoins, st.NoPathEpisodes)
			}
			for _, k := range []EventKind{EventMigration, EventNoPathStart} {
				if evs := s.ev.of(s.s.ID(), k); len(evs) != 0 {
					t.Fatalf("%v: %d events of kind %v, want none", s.s.Role(), len(evs), k)
				}
			}
			for _, ev := range s.ev.of(s.s.ID(), EventCarrierDown) {
				if ev.Time.Before(at) {
					t.Fatalf("%v: a carrier went down at %v, before the idle expiry", s.s.Role(), ev.Time.Sub(opened))
				}
			}
		}
		if a, b := dials[0].Load(), dials[1].Load(); a != 1 || b != 0 {
			t.Fatalf("factory calls %d (a) and %d (b), want 1 and 0: the expiry looked like a path failure", a, b)
		}
	})
}

// c4HoldActors holds the actor of each session in ss between two steps
// (beforeWaitHook) from the next time it gets there until release is
// called: the session cannot end meanwhile (only its actor ends it). It
// rings each actor so that a parked one runs a step and gets held, and
// returns once every one is held.
func c4HoldActors(t *testing.T, ss ...*Session) (release func()) {
	t.Helper()
	held := make(chan *Session, len(ss))
	gate := make(chan struct{})
	var once [8]atomic.Bool
	hook := func(s *Session) {
		for i, x := range ss {
			if x == s && once[i].CompareAndSwap(false, true) {
				held <- s
				<-gate
			}
		}
	}
	beforeWaitHook.Store(&hook)
	for _, s := range ss {
		s.ringActor()
	}
	for range ss {
		c4Await(t, held, time.Second, "an actor held between steps")
	}
	var done atomic.Bool
	return func() {
		if done.CompareAndSwap(false, true) {
			beforeWaitHook.CompareAndSwap(&hook, nil)
			close(gate)
		}
	}
}

// TestAbortWakesCallsBeforeTheEndStep (M4-D20, §A7.6 "the same wakeups as
// Close"): Abort itself wakes every blocked call with net.ErrClosed, not
// the actor's terminating step, which is held here. On one session a Read
// waits for data (rwake) and a Write for window (wwake); on another a
// Write is held inside its copy (it owns the call semaphore) and a second
// Write waits for that semaphore (s.closing). All three waiting calls
// return net.ErrClosed while both actors are still held and neither
// session has ended.
func TestAbortWakesCallsBeforeTheEndStep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		dx, _ := w.open(ModeSelector, nil, w.link("x"))
		dy, _ := w.open(ModeSelector, nil, w.link("y"))

		// dx: the peer neither writes nor reads.
		rx, wx := make(chan c4IOResult, 1), make(chan c4IOResult, 1)
		go func() { var b [8]byte; n, err := dx.Read(b[:]); rx <- c4IOResult{n, err} }()
		go func() { n, err := dx.Write(make([]byte, 3<<20)); wx <- c4IOResult{n, err} }()

		// dy: the first Write stops in its copy, the second waits for wsem.
		inCopy, copyGate := make(chan struct{}, 1), make(chan struct{})
		var copies atomic.Int32
		stSetCopyHook(t, dy, func() {
			if copies.Add(1) == 1 {
				inCopy <- struct{}{}
				<-copyGate
			}
		})
		w1, w2 := make(chan c4IOResult, 1), make(chan c4IOResult, 1)
		go func() { n, err := dy.Write([]byte("one")); w1 <- c4IOResult{n, err} }()
		c4Await(t, inCopy, time.Second, "the first Write in its copy")
		go func() { n, err := dy.Write([]byte("two")); w2 <- c4IOResult{n, err} }()
		time.Sleep(time.Second) // let dx's windows fill
		synctest.Wait()
		if len(rx)+len(wx)+len(w1)+len(w2) != 0 {
			t.Fatal("a call returned before the Abort: the premise (all blocked) failed")
		}
		if ok := stLocked(dx, func(st *stream) bool { return st.rwaiting && st.wwaiting }); !ok {
			t.Fatal("dx's Read and Write do not wait on rwake and wwake: the premise failed")
		}
		if stLocked(dy, func(*stream) bool { return dy.closing == nil }) {
			t.Fatal("dy's second Write does not wait for the call semaphore: the premise failed")
		}

		openCopy := sync.OnceFunc(func() { close(copyGate) })
		defer openCopy()
		release := c4HoldActors(t, dx, dy)
		defer release()
		for _, s := range []*Session{dx, dy} {
			if err := s.Abort(0x4C34_0202, "now"); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		for _, c := range []struct {
			what string
			ch   chan c4IOResult
		}{{"dx's Read (rwake)", rx}, {"dx's Write (wwake)", wx}, {"dy's waiting Write (closing)", w2}} {
			select {
			case r := <-c.ch:
				if !errors.Is(r.err, net.ErrClosed) {
					t.Fatalf("%s: (%d, %v), want net.ErrClosed", c.what, r.n, r.err)
				}
			default:
				t.Fatalf("%s still blocked after the Abort while the actor is held", c.what)
			}
		}
		if len(w1) != 0 {
			t.Fatal("dy's first Write returned while held in its copy: the premise failed")
		}
		for _, s := range []*Session{dx, dy} {
			if stLocked(s, func(st *stream) bool { return st.ended }) {
				t.Fatal("a session ended while its actor was held: the premise failed")
			}
		}
		openCopy()
		// Its round was reserved before the Abort: it commits as it does
		// across a Close (the call returns; the RST discards the bytes).
		if r := c4Await(t, w1, time.Second, "dy's first Write after its copy"); !(r.n == 3 && r.err == nil) && !(r.n == 0 && errors.Is(r.err, net.ErrClosed)) {
			t.Fatalf("dy's first Write: (%d, %v), want (3, nil) or (0, net.ErrClosed)", r.n, r.err)
		}
		release()
		for _, s := range []*Session{dx, dy} {
			acDone(t, s, 5*time.Second)
			if err := s.Status().Err; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("end error %v, want net.ErrClosed", err)
			}
		}
	})
}

// TestPendingAfterFuncRegistrations (M4-D22, R1-8): a stopped registration
// leaves the session's list at once (stop reports true once); a kept one
// runs once at the exit from StatePending and its stop then reports false;
// one registered after the exit, by a direct call (as the context package
// may, when the session leaves pending between its Done check and its
// AfterFunc call), runs once on its own goroutine and its stop reports
// false.
func TestPendingAfterFuncRegistrations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		go func() { _, _ = w.dial(context.Background(), w.spec(ModeSelector, w.link("p")), nil) }()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		hooks := func() int { return stLocked(b, func(*stream) int { return len(b.ctl.pendingHooks) }) }

		var stoppedRan atomic.Int32
		for i := range 100 {
			stop := b.PendingAfterFunc(func() { stoppedRan.Add(1) })
			if n := hooks(); n != 1 {
				t.Fatalf("round %d: %d registrations listed, want 1", i, n)
			}
			if !stop() || stop() {
				t.Fatalf("round %d: stop: want true once, then false", i)
			}
			if n := hooks(); n != 0 {
				t.Fatalf("round %d: %d registrations listed after stop, want 0", i, n)
			}
		}
		var kept atomic.Int32
		stopKept := b.PendingAfterFunc(func() { kept.Add(1) })

		if err := b.Reject(4000, "no"); err != nil {
			t.Fatal(err)
		}
		c4Await(t, b.PendingDone(), time.Second, "the pending exit")
		synctest.Wait()
		if kept.Load() != 1 || stoppedRan.Load() != 0 {
			t.Fatalf("the kept registration ran %d times, the stopped ones %d; want 1 and 0", kept.Load(), stoppedRan.Load())
		}
		if stopKept() {
			t.Fatal("stop of a registration that ran reported true")
		}
		if n := hooks(); n != 0 {
			t.Fatalf("%d registrations listed after the exit, want 0", n)
		}

		var late atomic.Int32
		stopLate := b.PendingAfterFunc(func() { late.Add(1) })
		synctest.Wait()
		if late.Load() != 1 {
			t.Fatalf("a registration after the exit ran %d times, want 1", late.Load())
		}
		if stopLate() {
			t.Fatal("stop of a registration made after the exit reported true")
		}
		if b.PendingErr() != context.Canceled {
			t.Fatalf("PendingErr %v, want context.Canceled", b.PendingErr())
		}
	})
}
