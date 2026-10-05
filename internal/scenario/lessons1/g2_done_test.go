package lessons1

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// A finished exchange whose final DONE is lost (design §0.14 B4, extending
// D4). Both ends stream to each other, read the other's stream to io.EOF,
// half-close and Close: every byte and both FINs were delivered. The end
// that sends the final DONE holds the peer's and ends cleanly, but its DONE
// dies with its carrier, so the other end — whose DONE was sent — waits for
// a DONE that never comes. Before B4 that end failed although its exchange
// was complete: ErrNoPath at its no-path episode's expiry (with the
// defaults the dialer's NoPathGrace of 15 s, and a PassiveRetain of 29 s
// for a dialer NoPathGrace of 10 s, both expire before the 30 s Linger),
// ErrSessionLost when its redial reached a restarted peer, *AbortError on
// GOING_AWAY, GOAWAY or the RST(AbortGoingAway) the peer's Runtime.Close
// sends with its GOAWAY (either may arrive first) — so an application that
// checks Status().Err after Done saw a failure. Each of these ends is now
// the clean end (io.EOF) the lost DONE would have given; an end before our
// DONE was sent keeps its error (TestG2NoPathBeforeDone_L05). Helpers of
// this file start with "g2".

const (
	g2N      = 256 << 10        // bytes each way
	g2Grace  = 15 * time.Second // Config.NoPathGrace default
	g2Linger = 30 * time.Second // Config.Linger default
)

// g2Fixture is a fixture with one link "a" whose Accept the test can
// redirect (alt): to another passive Runtime's Listener (a restarted peer)
// or to a scripted far end, whose goroutines far joins.
type g2Fixture struct {
	*fixture
	l   *rendrtest.Link
	alt atomic.Pointer[func(net.Conn) error]
	far sync.WaitGroup
}

func g2NewFixture(t *testing.T, o opts) *g2Fixture {
	t.Helper()
	f := &g2Fixture{fixture: newFixture(t, o)}
	accept := f.accept("a")
	f.l = rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(c net.Conn) error {
		if fn := f.alt.Load(); fn != nil {
			return (*fn)(c)
		}
		return accept(c)
	}})
	f.l.SetDelay(time.Millisecond, 0)
	f.links = append(f.links, f.l)
	f.byName["a"] = f.l
	t.Cleanup(f.close) // runs before the fixture's own cleanup
	return f
}

// close closes the fixture (Runtimes, then links) and joins the far ends.
func (f *g2Fixture) close() {
	f.fixture.close()
	f.far.Wait()
}

// redirect sends every new carrier of the link to fn.
func (f *g2Fixture) redirect(fn func(net.Conn) error) { f.alt.Store(&fn) }

// g2Tap returns side s's tap of the fixture's one session carrier.
func g2Tap(t *testing.T, f *g2Fixture, s side) *tap {
	t.Helper()
	taps := f.wire.sessionTaps(s, "a")
	if len(taps) != 1 {
		t.Fatalf("%d %v session carriers, want 1", len(taps), s)
	}
	return taps[0]
}

// g2Exchange runs both directions between first (on side fs) and last:
// first's g2N bytes and FIN, which last reads to io.EOF — so last
// acknowledges first's FIN before the other way round —, then last's g2N
// bytes and FIN, of which first reads all but the final byte, so last's FIN
// is not delivered yet; last half-closes and Closes. It returns first's
// verifier, owed that byte (g2FinishFirst). When first then reads it, its
// FIN_DELIVERED and its DONE leave at one instant, and last's DONE — the
// final one — follows their arrival.
func g2Exchange(t *testing.T, f *g2Fixture, first, last *rendr.Conn, fs side) *rendrtest.Verifier {
	t.Helper()
	both := func(a, b func() error) func() error {
		return func() error {
			errs := make(chan error, 2)
			go func() { errs <- a() }()
			go func() { errs <- b() }()
			for range 2 {
				if err := <-errs; err != nil {
					return err
				}
			}
			return nil
		}
	}
	runWithin(t, time.Minute, "the first end's stream", both(
		func() error { return sendAndClose(first, g2N, 1) },
		func() error { return readStream(last, g2N, 1, nil) },
	))
	v := rendrtest.NewVerifier(2, g2N)
	runWithin(t, time.Minute, "the last end's stream", both(
		func() error {
			if err := sendAndClose(last, g2N, 2); err != nil {
				return err
			}
			return last.Close()
		},
		func() error { _, err := io.CopyN(v, first, g2N-1); return err },
	))
	if _, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
		return fr.finDelivered() && !fr.out && fr.tap.side == fs
	}); !ok {
		t.Fatal("the first end never read the last end's FIN_DELIVERED")
	}
	synctest.Wait() // applied: the first end's DONE follows its own FIN_DELIVERED
	if n := f.wire.count(func(fr frame) bool { return fr.done() }); n != 0 {
		t.Fatalf("%d DONE frames before the first end read its final byte", n)
	}
	return v
}

// g2FinishFirst reads first's final byte and io.EOF and Closes it.
func g2FinishFirst(t *testing.T, first *rendr.Conn, v *rendrtest.Verifier) {
	t.Helper()
	runWithin(t, 30*time.Second, "the final byte and io.EOF", func() error {
		if _, err := io.CopyN(v, first, 1); err != nil {
			return err
		}
		if k, err := first.Read(make([]byte, 1)); k != 0 || err != io.EOF {
			return fmt.Errorf("Read after the peer's FIN: (%d, %v)", k, err)
		}
		if err := v.Done(io.EOF); err != nil {
			return err
		}
		return first.Close()
	})
}

// g2FailFirst arms tp: the first Write carrying a frame that matches fails
// after delay (virtual time) — the carrier dies with that frame unsent —
// and from then on the link refuses new carriers until the test reopens it.
// The returned flag reports the strike.
func g2FailFirst(f *g2Fixture, tp *tap, match func(frame) bool, delay time.Duration) *atomic.Bool {
	var struck atomic.Bool
	tp.setPlan(func(_ *tap, fs []frame) planVerdict {
		for _, fr := range fs {
			if match(fr) && struck.CompareAndSwap(false, true) {
				if delay > 0 {
					time.Sleep(delay)
				}
				f.l.SetRefuse(true)
				return planVerdict{fail: errInjected}
			}
		}
		return planVerdict{}
	})
	return &struck
}

// g2LoseFinalDone arms the tap of last (on side ls) so that the Write
// carrying its DONE — the final one — fails 1 ms after it was placed: by
// then last has read the peer's DONE, which left together with the
// FIN_DELIVERED that caused last's own.
func g2LoseFinalDone(t *testing.T, f *g2Fixture, ls side) *atomic.Bool {
	t.Helper()
	return g2FailFirst(f, g2Tap(t, f, ls), frame.done, time.Millisecond)
}

// g2Ended waits for c's Done and returns its final status.
func g2Ended(t *testing.T, c *rendr.Conn, within time.Duration) rendr.SessionStatus {
	t.Helper()
	recv(t, c.Done(), within, "session "+c.ID().String()+" done")
	return c.Status()
}

// g2LastEnded checks the end on side ls that sent the final DONE: it ended
// cleanly, having read the peer's DONE, while its own died with the failed
// Write and never reached the waiting end.
func g2LastEnded(t *testing.T, f *g2Fixture, last *rendr.Conn, ls side, struck *atomic.Bool) {
	t.Helper()
	if st := g2Ended(t, last, 10*time.Second); st.Err != io.EOF {
		t.Fatalf("%v (final DONE) ended with %v, want io.EOF", ls, st.Err)
	}
	if !struck.Load() {
		t.Fatal("no Write carrying the final DONE failed (stimulus)")
	}
	if n := f.wire.count(func(fr frame) bool { return fr.done() && !fr.out && fr.tap.side == ls }); n != 1 {
		t.Fatalf("%v read %d DONE frames, want the peer's", ls, n)
	}
	if n := f.wire.count(func(fr frame) bool { return fr.done() && !fr.out && fr.tap.side != ls }); n != 0 {
		t.Fatalf("the waiting end read %d DONE frames, want none", n)
	}
}

// g2NoPathAt returns the time of the NoPathStart event of c's single no-path
// episode: the death step of its carrier, whose recorded death time the
// grace counts from (the same instant here; the session tests check the
// exact start).
func g2NoPathAt(t *testing.T, log *evLog, c *rendr.Conn) time.Time {
	t.Helper()
	evs := log.of(c.ID(), rendr.EventNoPathStart)
	if len(evs) != 1 {
		t.Fatalf("%d NoPathStart events, want 1", len(evs))
	}
	return evs[0].Time
}

// g2Expired checks that an end at end, in an episode started at start,
// came from the expiry of grace. The grace counts from the carrier's death
// time, which the death step (start) may follow by up to a second, and the
// actor arms its timer at least 1 ms ahead, so a wake just before the
// expiry (a failed redial's result) can delay it by up to 1 ms.
func g2Expired(t *testing.T, end, start time.Time, grace time.Duration, who string) {
	t.Helper()
	if d := end.Sub(start); d > grace+time.Millisecond || d < grace-time.Second {
		t.Fatalf("the %s ended %v after its no-path episode started, want its grace %v", who, d, grace)
	}
}

// g2DoneAt returns when side s wrote its DONE.
func g2DoneAt(t *testing.T, f *g2Fixture, s side) time.Time {
	t.Helper()
	fs := f.wire.pick(func(fr frame) bool { return fr.done() && fr.out && fr.fate == fateWritten && fr.tap.side == s })
	if len(fs) != 1 {
		t.Fatalf("%v wrote %d DONE frames, want 1", s, len(fs))
	}
	return fs[0].at
}

// g2CleanAfterDone checks that c, which waited for the lost DONE, ended
// with io.EOF in its single no-path episode, and returns its end time and
// the episode's start.
func g2CleanAfterDone(t *testing.T, log *evLog, c *rendr.Conn, st rendr.SessionStatus) (end, start time.Time) {
	t.Helper()
	if st.Err != io.EOF {
		t.Fatalf("%v ended with %v, want io.EOF: its DONE was sent, its FIN acknowledged and the peer's FIN delivered", st.Role, st.Err)
	}
	if st.NoPathEpisodes != 1 {
		t.Fatalf("%v: %d no-path episodes, want 1", st.Role, st.NoPathEpisodes)
	}
	return endedAt(t, log, c), g2NoPathAt(t, log, c)
}

// TestG2DoneLostPeerGone_L05: the passive sends the final DONE, which dies
// with its carrier, and its Runtime closes (the peer is gone): the dialer's
// redials reach a closed Listener. Its no-path episode expires after
// NoPathGrace (15 s), before the Linger after its DONE (30 s), and ends the
// session with io.EOF on both ends.
func TestG2DoneLostPeerGone_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := g2NewFixture(t, opts{})
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		v := g2Exchange(t, f, dc, pc, dialerSide)
		struck := g2LoseFinalDone(t, f, passiveSide)
		g2FinishFirst(t, dc, v)
		g2LastEnded(t, f, pc, passiveSide, struck)
		f.p.Close()
		f.l.SetRefuse(false) // redials reach the closed Listener, which closes them
		end, start := g2CleanAfterDone(t, f.dev, dc, g2Ended(t, dc, time.Minute))
		g2Expired(t, end, start, g2Grace, "dialer")
		if !end.Before(g2DoneAt(t, f, dialerSide).Add(g2Linger)) {
			t.Fatal("the dialer ended at the Linger after its DONE: the episode's expiry must decide")
		}
		if n := len(f.wire.tapsOf(passiveSide, nil)); n < 2 {
			t.Fatalf("%d carriers reached the passive, want redials that reached its closed Listener (stimulus)", n)
		}
		f.close()
	})
}

// TestG2DoneLostPeerRestarted_L05: as TestG2DoneLostPeerGone_L05, but the
// passive's process restarts behind the same path (a new Runtime, another
// instance). The dialer's next redial reaches it: a peer restart, which
// ends the session at once — with io.EOF, not ErrSessionLost.
func TestG2DoneLostPeerRestarted_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := g2NewFixture(t, opts{})
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		v := g2Exchange(t, f, dc, pc, dialerSide)
		struck := g2LoseFinalDone(t, f, passiveSide)
		g2FinishFirst(t, dc, v)
		g2LastEnded(t, f, pc, passiveSide, struck)
		f.p.Close()
		p2 := newRuntime(t, rendr.Config{}, &testhooks.Overrides{})
		t.Cleanup(func() { p2.Close() })
		ln2, err := p2.Listen(rendr.ListenConfig{})
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		f.redirect(func(c net.Conn) error { return ln2.Handle(f.wire.newTap("a", passiveSide, c)) })
		f.l.SetRefuse(false)
		end, start := g2CleanAfterDone(t, f.dev, dc, g2Ended(t, dc, time.Minute))
		if d := end.Sub(start); d >= g2Grace-time.Second {
			t.Fatalf("the dialer ended %v after its episode started: the restart must decide before NoPathGrace", d)
		}
		if n := f.wire.count(func(fr frame) bool { return !fr.out && fr.typ == wire.TypeJoin && fr.tap.side == passiveSide }); n == 0 {
			t.Fatal("no JOIN reached the restarted peer (stimulus)")
		}
		p2.Close()
		st := p2.Status()
		if s := st.Sessions; s.Open+s.Pending+s.Lingering+s.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} {
			t.Fatalf("restarted Runtime not empty after Close: %+v", st)
		}
		f.close()
	})
}

// TestG2DoneLostGoingAway_L05: the bound instance goes away after the
// exchange finished.
//
//   - preface-ack: the passive sends the final DONE, which dies with its
//     carrier, and its Runtime closes; the dialer's redial is answered
//     PREFACE_ACK(GOING_AWAY) naming the bound instance — what the closing
//     Runtime's handshake gate answers. A scripted far end gives that
//     answer: Runtime.Close drains handshakes still in flight, so a real
//     one leaves no deterministic window for it. Both ends end with io.EOF.
//   - goaway: nothing the dialer writes after its final read arrives, so
//     its FIN_DELIVERED and DONE are lost while its carrier stays up; the
//     passive's Runtime closes while its session still waits for them and
//     sends GOAWAY and RST(AbortGoingAway) on the live carrier. The dialer
//     ends with io.EOF; the passive with net.ErrClosed, as Runtime.Close
//     resets every session that has not ended.
//   - rst-first: as goaway, but the RST(AbortGoingAway) arrives first, as
//     when the closing passive's writer round had placed its carrier
//     controls before the Shutdown and carries the RST alone, the GOAWAY
//     following in the next round. An RST injected after the passive's next
//     PING stands in for that round; the Runtime.Close that follows sends
//     the GOAWAY. The dialer still ends with io.EOF, at the RST.
func TestG2DoneLostGoingAway_L05(t *testing.T) {
	t.Run("preface-ack", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := g2NewFixture(t, opts{})
			dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
			v := g2Exchange(t, f, dc, pc, dialerSide)
			struck := g2LoseFinalDone(t, f, passiveSide)
			g2FinishFirst(t, dc, v)
			g2LastEnded(t, f, pc, passiveSide, struck)
			f.p.Close()
			var answered atomic.Int32
			f.redirect(f.goingAway(f.p.InstanceID(), &answered))
			f.l.SetRefuse(false)
			end, start := g2CleanAfterDone(t, f.dev, dc, g2Ended(t, dc, time.Minute))
			if d := end.Sub(start); d >= g2Grace-time.Second {
				t.Fatalf("the dialer ended %v after its episode started: GOING_AWAY must decide before NoPathGrace", d)
			}
			if n := answered.Load(); n != 1 {
				t.Fatalf("%d GOING_AWAY answers, want 1 (stimulus)", n)
			}
			f.close()
		})
	})
	t.Run("goaway", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := g2NewFixture(t, opts{})
			dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
			v := g2Exchange(t, f, dc, pc, dialerSide)
			g2Tap(t, f, dialerSide).setPlan(func(*tap, []frame) planVerdict { return planVerdict{swallow: true} })
			g2FinishFirst(t, dc, v)
			if _, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
				return fr.done() && fr.out && fr.fate == fateSwallowed && fr.tap.side == dialerSide
			}); !ok {
				t.Fatal("the dialer placed no DONE")
			}
			strike := time.Now()
			f.p.Close()
			st := g2Ended(t, dc, 10*time.Second)
			if st.Err != io.EOF {
				t.Fatalf("dialer ended with %v, want io.EOF: its DONE was sent, its FIN acknowledged and the peer's FIN delivered", st.Err)
			}
			if d := endedAt(t, f.dev, dc).Sub(strike); d > time.Second {
				t.Fatalf("the dialer ended %v after the passive's Runtime closed, want at its GOAWAY", d)
			}
			if pst := g2Ended(t, pc, 10*time.Second); !errors.Is(pst.Err, net.ErrClosed) {
				t.Fatalf("passive ended with %v, want net.ErrClosed (its Runtime closed)", pst.Err)
			}
			if n := f.wire.count(func(fr frame) bool { return !fr.out && fr.typ == wire.TypeGoAway && fr.tap.side == dialerSide }); n != 1 {
				t.Fatalf("the dialer read %d GOAWAY frames, want 1 (stimulus)", n)
			}
			if n := f.wire.count(func(fr frame) bool { return fr.done() && !fr.out }); n != 0 {
				t.Fatalf("%d DONE frames were read, want none (stimulus)", n)
			}
			f.close()
		})
	})
	t.Run("rst-first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := g2NewFixture(t, opts{})
			dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
			v := g2Exchange(t, f, dc, pc, dialerSide)
			g2Tap(t, f, dialerSide).setPlan(func(*tap, []frame) planVerdict { return planVerdict{swallow: true} })
			g2FinishFirst(t, dc, v)
			if _, ok := f.wire.wait(10*time.Second, func(fr frame) bool {
				return fr.done() && fr.out && fr.fate == fateSwallowed && fr.tap.side == dialerSide
			}); !ok {
				t.Fatal("the dialer placed no DONE")
			}
			var rst [wire.RstFixedLen + len("going away")]byte
			wire.PutRst(rst[:], &wire.Rst{Code: wire.RstGoingAway, Msg: []byte("going away")})
			f.l.InjectAfterNextFrame(rendrtest.Down, rendrtest.FramePing, rendrtest.FrameRst, 0, wire.SessionHandle, rst[:])
			read := func(keep func(fr frame) bool) int {
				return f.wire.count(func(fr frame) bool { return !fr.out && fr.tap.side == dialerSide && keep(fr) })
			}
			isRst := func(fr frame) bool { return fr.typ == wire.TypeRst && fr.rst == wire.RstGoingAway }
			isGoAway := func(fr frame) bool { return fr.typ == wire.TypeGoAway }
			st := waitEnded(t, dc, time.Minute)
			if st.Err != io.EOF {
				t.Fatalf("dialer ended with %v, want io.EOF: its DONE was sent, its FIN acknowledged and the peer's FIN delivered", st.Err)
			}
			if r, g := read(isRst), read(isGoAway); r != 1 || g != 0 {
				t.Fatalf("the dialer read %d RST(AbortGoingAway) and %d GOAWAY frames by its end, want the RST alone (stimulus)", r, g)
			}
			if n := f.l.Stats().Session.FramesInjected; n != 1 {
				t.Fatalf("%d frames injected, want the RST (stimulus)", n)
			}
			f.p.Close() // the GOAWAY follows
			if pst := g2Ended(t, pc, 10*time.Second); !errors.Is(pst.Err, net.ErrClosed) {
				t.Fatalf("passive ended with %v, want net.ErrClosed (its Runtime closed)", pst.Err)
			}
			g2Ended(t, dc, 10*time.Second)
			if g := read(isGoAway); g != 1 {
				t.Fatalf("the dialer read %d GOAWAY frames after its end, want 1 (stimulus)", g)
			}
			if n := f.wire.count(func(fr frame) bool { return fr.done() && !fr.out }); n != 0 {
				t.Fatalf("%d DONE frames were read, want none (stimulus)", n)
			}
			f.close()
		})
	})
}

// goingAway returns an Accept that stands in for the instance inst while
// its Runtime closes: it reads the dialer's PREFACE, answers
// PREFACE_ACK(GOING_AWAY) naming inst, and holds the carrier until the
// dialer closes it. n counts the answers.
func (f *g2Fixture) goingAway(inst rendr.InstanceID, n *atomic.Int32) func(net.Conn) error {
	return func(nc net.Conn) error {
		c := f.wire.newTap("a", passiveSide, nc)
		f.far.Add(1)
		go func() {
			defer f.far.Done()
			defer c.Close()
			var b [wire.PrefaceLen]byte
			if _, err := io.ReadFull(c, b[:]); err != nil {
				return
			}
			p, err := wire.ParsePreface(b[:])
			if err != nil {
				return
			}
			var ab [wire.PrefaceLen]byte
			wire.PutPrefaceAck(ab[:], &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceGoingAway, Instance: [16]byte(inst), CarrierID: p.CarrierID})
			n.Add(1) // before the answer can end the session
			if _, err := c.Write(ab[:]); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, c)
		}()
		return nil
	}
}

// TestG2DoneLostPassiveRetain_L05: the mirror case on the passive. The
// dialer (NoPathGrace 10 s) sends the final DONE, which dies with its
// carrier; the passive's PassiveRetain is 10 s + PingIdle 10 s + DeadMax
// 4 s + 5 s = 29 s, shorter than Linger (30 s), and nothing attaches. Its
// episode's expiry ends it with io.EOF on both ends.
func TestG2DoneLostPassiveRetain_L05(t *testing.T) {
	const grace = 10 * time.Second
	const retain = grace + 10*time.Second + 4*time.Second + 5*time.Second
	synctest.Test(t, func(t *testing.T) {
		f := g2NewFixture(t, opts{dcfg: rendr.Config{NoPathGrace: grace}})
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		v := g2Exchange(t, f, pc, dc, passiveSide)
		struck := g2LoseFinalDone(t, f, dialerSide)
		g2FinishFirst(t, pc, v)
		g2LastEnded(t, f, dc, dialerSide, struck)
		end, start := g2CleanAfterDone(t, f.pev, pc, g2Ended(t, pc, time.Minute))
		g2Expired(t, end, start, retain, "passive")
		if !end.Before(g2DoneAt(t, f, passiveSide).Add(g2Linger)) {
			t.Fatal("the passive ended at the Linger after its DONE: the episode's expiry must decide")
		}
		f.close()
	})
}

// TestG2NoPathBeforeDone_L05 (control): as TestG2DoneLostPeerGone_L05, but
// the Write carrying the dialer's FIN_DELIVERED fails, one step earlier:
// the dialer's DONE is never placed. Its episode's expiry still ends it
// with ErrNoPath after NoPathGrace.
func TestG2NoPathBeforeDone_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := g2NewFixture(t, opts{})
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		v := g2Exchange(t, f, dc, pc, dialerSide)
		struck := g2FailFirst(f, g2Tap(t, f, dialerSide), frame.finDelivered, 0)
		g2FinishFirst(t, dc, v)
		f.p.Close()
		f.l.SetRefuse(false)
		st := g2Ended(t, dc, time.Minute)
		if !errors.Is(st.Err, rendr.ErrNoPath) {
			t.Fatalf("dialer ended with %v, want ErrNoPath: its DONE was never sent", st.Err)
		}
		g2Expired(t, endedAt(t, f.dev, dc), g2NoPathAt(t, f.dev, dc), g2Grace, "dialer")
		if !struck.Load() {
			t.Fatal("the dialer's FIN_DELIVERED was not struck (stimulus)")
		}
		if n := f.wire.count(func(fr frame) bool { return fr.done() && fr.out }); n != 0 {
			t.Fatalf("%d DONE frames were placed, want none", n)
		}
		f.close()
	})
}
