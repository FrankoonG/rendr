package session

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The end of a finished exchange whose last DONE was lost (design §0.14
// B4, extending D4). Our DONE goes out once the peer acknowledged our FIN
// as delivered and the peer's FIN reached our application; when the peer's
// DONE is then lost with a dying carrier, every end that proves the peer
// gone is the clean end that DONE would have given: the no-path episode's
// expiry (both roles), a GOING_AWAY answer (PREFACE_ACK, JOIN_ACK), a
// GOAWAY (on a lane, or answering a JOIN) — or the RST(AbortGoingAway) that
// the peer's Runtime.Close sends with it, whichever arrives first — and a
// JOIN that reached a restarted peer all end with io.EOF. The same ends
// before our DONE was sent keep their errors (the before-done controls).
// Package-level helpers of this file start with "g2".

// g2N is the size of each direction's transfer.
const g2N = 64 << 10

// g2DialerWaits finishes both directions on a selector session a (dialer),
// b (passive) whose one carrier crosses l, so that the dialer's DONE goes
// first and the passive's — the last — is dropped by the link: the passive
// ends cleanly (both DONEs), the dialer holds doneSent without the peer's
// DONE, and its carrier dies at the fseq gap of the passive's CLOSE. Arm
// whatever answers the dialer's redial before calling it: the redial may
// start before this returns.
func g2DialerWaits(t *testing.T, l *rendrtest.Link, a, b *Session, seed uint64) {
	t.Helper()
	acHalfCloseSettled(t, a, b, g2N, seed)
	l.DropNextFrame(rendrtest.Down, rendrtest.FrameAck) // the passive's next ACK is its DONE
	acReadToEOF(t, a, g2N, seed)
	acDone(t, b, 5*time.Second)
	if st := b.Status(); st.Err != io.EOF {
		t.Fatalf("passive end %v, want io.EOF (DONE both ways)", st.Err)
	}
	if n := l.Stats().Session.FramesDropped; n != 1 {
		t.Fatalf("%d frames dropped, want the passive's DONE (stimulus)", n)
	}
}

// g2PassiveWaits is g2DialerWaits mirrored: the passive's FIN is
// acknowledged first and the dialer's FIN waits unread at the passive, so
// the passive's DONE goes first and the dialer's — the last — is dropped:
// the dialer ends cleanly, the passive holds doneSent without the dialer's
// DONE, and its carrier dies at the fseq gap of the dialer's CLOSE.
func g2PassiveWaits(t *testing.T, l *rendrtest.Link, a, b *Session, seed uint64) {
	t.Helper()
	if err := acWritePRNG(b, g2N, seed+1); err != nil {
		t.Fatalf("passive Write: %v", err)
	}
	if err := b.CloseWrite(); err != nil {
		t.Fatalf("passive CloseWrite: %v", err)
	}
	if err := rendrtest.NewVerifier(seed+1, g2N).ReadAll(a); err != nil {
		t.Fatalf("dialer read: %v", err)
	}
	if err := acWritePRNG(a, g2N, seed); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	acWaitFor(t, time.Second, "the FINs exchanged", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.st.fin.acked && b.st.peerFinSet && !b.st.peerFinDelivered
	})
	time.Sleep(100 * time.Millisecond) // delayed ACKs (20 ms) have left
	synctest.Wait()
	l.DropNextFrame(rendrtest.Up, rendrtest.FrameAck) // the dialer's next ACK is its DONE
	if err := rendrtest.NewVerifier(seed, g2N).ReadAll(b); err != nil {
		t.Fatalf("passive read: %v", err)
	}
	acDone(t, a, 5*time.Second)
	if st := a.Status(); st.Err != io.EOF {
		t.Fatalf("dialer end %v, want io.EOF (DONE both ways)", st.Err)
	}
	if n := l.Stats().Session.FramesDropped; n != 1 {
		t.Fatalf("%d frames dropped, want the dialer's DONE (stimulus)", n)
	}
}

// g2Role names s's role in failure messages.
func g2Role(s *Session) string {
	if s.Role() == RoleDialer {
		return "dialer"
	}
	return "passive"
}

// g2Done reports s's DONE flags: ours placed, the peer's received.
func g2Done(s *Session) (sent, peer bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.doneSent, s.st.peerDone
}

// g2DoneSentAt returns when s placed its DONE.
func g2DoneSentAt(s *Session) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.doneSentAt
}

// g2EpisodeStart waits until s is inside a no-path episode and returns its
// start (the death time of its last carrier, from which the grace counts).
func g2EpisodeStart(t *testing.T, s *Session) time.Time {
	t.Helper()
	var at time.Time
	acWaitFor(t, 5*time.Second, "a no-path episode", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		at = s.ctl.episodeStart
		return s.ctl.inNoPath
	})
	return at
}

// g2EndAt returns the time and error of s's SessionEnd event on side.
func g2EndAt(t *testing.T, side *acSide, s *Session) (time.Time, error) {
	t.Helper()
	evs := side.ev.of(s.ID(), EventSessionEnd)
	if len(evs) != 1 {
		t.Fatalf("%v: %d SessionEnd events, want 1", g2Role(s), len(evs))
	}
	return evs[0].Time, evs[0].Err
}

// g2NoPathAt returns the time of the NoPathStart event of s's single no-path
// episode (for an ended session: the episode may have ended before a poll
// of its state could see it).
func g2NoPathAt(t *testing.T, side *acSide, s *Session) time.Time {
	t.Helper()
	evs := side.ev.of(s.ID(), EventNoPathStart)
	if len(evs) != 1 {
		t.Fatalf("%v: %d NoPathStart events, want 1", g2Role(s), len(evs))
	}
	return evs[0].Time
}

// TestG2EpisodeExpiryAfterDone_L05: the peer ended cleanly, its DONE was
// lost with the dying carrier and the waiting end gets no carrier back.
// With a grace shorter than Linger — the defaults' NoPathGrace (15 s) on
// the dialer; on the passive a PassiveRetain below Linger, i.e. a dialer
// NoPathGrace of 10 s or less — the episode expires first and ends the
// session cleanly: io.EOF at the episode start plus the grace, before the
// Linger rule after our DONE. Control (before-done): the same expiry
// before our DONE was sent still ends with ErrNoPath.
func TestG2EpisodeExpiryAfterDone_L05(t *testing.T) {
	const grace, linger = 3 * time.Second, 10 * time.Second
	t.Run("dialer", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			w.a.p.Grace, w.a.p.Linger = grace, linger
			l1 := w.link("p1")
			a, b := w.open(ModeSelector, nil, l1)
			l1.SetRefuse(true) // the peer is gone: every redial fails
			g2DialerWaits(t, l1, a, b, 31)
			start := g2EpisodeStart(t, a)
			acDone(t, a, 10*time.Second)
			g2CheckExpiry(t, w.a, a, start, grace, linger, io.EOF)
			if l1.Stats().DialFailures == 0 {
				t.Fatal("no redial was refused (stimulus)")
			}
		})
	})
	t.Run("passive", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			w.a.p.Retain = grace // the passive's grace: PassiveRetain from the OPEN
			w.b.p.Linger = linger
			l1 := w.link("p1")
			a, b := w.open(ModeSelector, nil, l1)
			g2PassiveWaits(t, l1, a, b, 41)
			start := g2EpisodeStart(t, b)
			acDone(t, b, 10*time.Second)
			g2CheckExpiry(t, w.b.acSide, b, start, grace, linger, io.EOF)
		})
	})
	t.Run("before-done", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			w.a.p.Grace, w.a.p.Linger = grace, linger
			l1 := w.link("p1")
			a, b := w.open(ModeSelector, nil, l1)
			// Our FIN is acknowledged; the passive's FIN is stored but never
			// read, so our DONE is never sent.
			acHalfCloseSettled(t, a, b, g2N, 51)
			l1.SetRefuse(true)
			if l1.Kill() != 1 {
				t.Fatal("no carrier killed (stimulus)")
			}
			start := g2EpisodeStart(t, a)
			acDone(t, a, 10*time.Second)
			g2CheckExpiry(t, w.a, a, start, grace, linger, ErrNoPath)
		})
	})
}

// g2CheckExpiry checks that s ended with want (io.EOF exactly; otherwise
// matched by errors.Is) through its single no-path episode's expiry, grace
// after the episode start and, after our DONE, before Linger since it.
func g2CheckExpiry(t *testing.T, side *acSide, s *Session, start time.Time, grace, linger time.Duration, want error) {
	t.Helper()
	st := s.Status()
	sent, peer := g2Done(s)
	switch {
	case want == io.EOF && st.Err != io.EOF:
		t.Fatalf("%v end %v, want io.EOF (our DONE sent %v, the peer's received %v)", g2Role(s), st.Err, sent, peer)
	case want != io.EOF && !errors.Is(st.Err, want):
		t.Fatalf("%v end %v, want %v", g2Role(s), st.Err, want)
	case want == io.EOF && (!sent || peer):
		t.Fatalf("%v: our DONE sent %v, the peer's received %v; want sent, not received (stimulus)", g2Role(s), sent, peer)
	case want != io.EOF && sent:
		t.Fatalf("%v: our DONE was sent in the before-done control", g2Role(s))
	}
	at, err := g2EndAt(t, side, s)
	if err != st.Err {
		t.Fatalf("SessionEnd event error %v, Status error %v", err, st.Err)
	}
	if d := at.Sub(start); d < grace || d > grace+minArm {
		// minArm: a wake just before the expiry re-arms the timer that far.
		t.Fatalf("%v ended %v after its episode started, want the grace %v", g2Role(s), d, grace)
	}
	if sent && !at.Before(g2DoneSentAt(s).Add(linger)) {
		t.Fatalf("%v ended at the Linger after its DONE: the episode's expiry must decide", g2Role(s))
	}
	if st.NoPathEpisodes != 1 {
		t.Fatalf("%v: %d no-path episodes, want 1", g2Role(s), st.NoPathEpisodes)
	}
}

// TestG2PeerRestartAfterDone_L05: the passive's DONE is lost with the dying
// carrier; the bound instance's path refuses, and the redial over the other
// factory reaches a restarted peer (another instance). That is the peer
// restart of plan §3.4, which ends the session at once — cleanly (io.EOF)
// after our DONE, with ErrSessionLost before it (before-done) — instead of
// waiting for the grace or the Linger.
func TestG2PeerRestartAfterDone_L05(t *testing.T) {
	for _, done := range []bool{true, false} {
		name := "done"
		if !done {
			name = "before-done"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				p2 := acNewPassive(t, 3, nil) // the restarted peer
				defer p2.wg.Wait()
				defer p2.joinClosing(t)
				l1 := w.link("p1")
				l2 := w.linkTo("p2", p2)
				w.a.p.Grace, w.a.p.Linger = 30*time.Second, 30*time.Second // neither may decide
				a, b := w.open(ModeSelector, nil, l1, l2)
				l1.SetRefuse(true) // the bound instance is gone from p1
				if done {
					g2DialerWaits(t, l1, a, b, 61)
				} else {
					acHalfCloseSettled(t, a, b, g2N, 61)
					l1.Kill()
				}
				acDone(t, a, 10*time.Second)
				start := g2NoPathAt(t, w.a, a)
				st := a.Status()
				switch {
				case done && st.Err != io.EOF:
					t.Fatalf("end %v, want io.EOF: our DONE was sent", st.Err)
				case !done && !errors.Is(st.Err, ErrSessionLost):
					t.Fatalf("end %v, want ErrSessionLost", st.Err)
				}
				var ee *carrier.EstablishError
				if !done && (!errors.As(st.Err, &ee) || ee.Cause != carrier.CauseInstanceMismatch) {
					t.Fatalf("end %v does not carry the instance mismatch", st.Err)
				}
				if sent, peer := g2Done(a); sent != done || peer {
					t.Fatalf("our DONE sent %v, the peer's received %v (stimulus)", sent, peer)
				}
				if at, _ := g2EndAt(t, w.a, a); at.Sub(start) > time.Second {
					t.Fatalf("ended %v after the episode started, want at the restarted peer's answer", at.Sub(start))
				}
				if l2.Stats().Dials == 0 {
					t.Fatal("the restarted instance was never dialled (stimulus)")
				}
			})
		})
	}
}

// TestG2GoingAwayAfterDone_L05: the bound instance goes away after the
// exchange finished. Five forms reach the waiting dialer: its redial is
// answered PREFACE_ACK(GOING_AWAY) or JOIN_ACK(GOING_AWAY) or GOAWAY as the
// response to its JOIN; or — while the passive still waits for our lost
// FIN_DELIVERED and DONE — the passive's Runtime closes and sends GOAWAY and
// RST(AbortGoingAway) on the live lane, the GOAWAY first (goaway) or the RST
// first (rst-first: a writer round already past its carrier controls when
// the Shutdown runs places the RST alone, and the GOAWAY follows in the next
// round; an RST(AbortGoingAway) injected ahead of the Shutdown stands in for
// that round). Each ends the session at once and notes the instance as gone
// away exactly once (D21; in rst-first through the GOAWAY that follows the
// end): cleanly (io.EOF) after our DONE, with *AbortError{AbortGoingAway,
// Remote: true} before it (before-done).
func TestG2GoingAwayAfterDone_L05(t *testing.T) {
	for _, form := range []string{"preface-ack", "join-ack", "goaway-response", "goaway", "rst-first"} {
		for _, done := range []bool{true, false} {
			name := form + "/done"
			if !done {
				name = form + "/before-done"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { g2GoingAway(t, form, done) })
			})
		}
	}
}

func g2GoingAway(t *testing.T, form string, done bool) {
	w := acNewWorld(t, nil)
	defer w.teardown()
	w.a.p.Grace, w.a.p.Linger = 30*time.Second, 30*time.Second // neither may decide
	var (
		armed    atomic.Bool  // the instance answers new carriers as going away
		answered atomic.Int32 // those answers (stimulus)
	)
	accept := w.b.accept
	switch form {
	case "preface-ack":
		w.b.gate = func(*wire.Preface) wire.PrefaceStatus {
			if armed.Load() {
				answered.Add(1)
				return wire.PrefaceGoingAway
			}
			return wire.PrefaceOK
		}
	case "join-ack":
		w.b.joinAnswer = func(*wire.Join) (wire.JoinAck, bool) {
			if armed.Load() {
				answered.Add(1)
				return wire.JoinAck{Status: wire.StatusGoingAway}, true
			}
			return wire.JoinAck{}, false
		}
	case "goaway-response":
		goAway := g2AnswerGoAway(w.b, &answered)
		accept = func(nc net.Conn) error {
			if armed.Load() {
				return goAway(nc)
			}
			return w.b.accept(nc)
		}
	}
	l1 := rendrtest.NewLink(rendrtest.LinkConfig{Name: "p1", Accept: accept})
	l1.SetDelay(acLinkDelay, 0)
	w.links = append(w.links, l1)
	noted := make(chan [16]byte, 4)
	spec := w.spec(ModeSelector, l1)
	spec.NoteGoAway = func(inst [16]byte) { noted <- inst }
	a, b := w.openSpec(spec, nil)
	a.mu.Lock()
	first := a.lanes[0].c
	a.mu.Unlock()
	var strike time.Time // the end must follow it within 2 s
	lane := form == "goaway" || form == "rst-first"
	switch {
	case lane:
		acHalfCloseSettled(t, a, b, g2N, 71)
		if done || form == "rst-first" {
			// Nothing the dialer writes from now on arrives (no fseq gap
			// ever shows): its FIN_DELIVERED and DONE are placed and
			// swallowed, so the passive keeps waiting for them; in
			// rst-first its CLOSE after the RST is swallowed too, so the
			// passive's lane is still up for the Shutdown that follows.
			swallow := make([]rendrtest.WriteResult, 64)
			for i := range swallow {
				swallow[i] = rendrtest.WriteResult{Relative: true}
			}
			l1.ScriptWrites(rendrtest.Up, swallow...)
		}
		if done {
			acReadToEOF(t, a, g2N, 71)
			acWaitFor(t, time.Second, "the dialer placed its DONE", func() bool {
				sent, _ := g2Done(a)
				return sent
			})
			if l1.Stats().Session.WritesScripted < 2 {
				t.Fatal("the dialer's FIN_DELIVERED and DONE were not swallowed (stimulus)")
			}
		}
		strike = time.Now()
		if form == "rst-first" {
			g2ResetFirst(t, l1, a, first)
		}
		b.Shutdown() // the passive Runtime closes: GOAWAY, RST(AbortGoingAway), CLOSE
	case done:
		armed.Store(true)
		g2DialerWaits(t, l1, a, b, 71)
	default:
		acHalfCloseSettled(t, a, b, g2N, 71)
		armed.Store(true)
		l1.Kill()
	}
	acDone(t, a, 10*time.Second)
	if !lane {
		strike = g2NoPathAt(t, w.a, a) // the redial follows the carrier's death
	}
	st := a.Status()
	var ae *AbortError
	switch {
	case done && st.Err != io.EOF:
		t.Fatalf("end %v, want io.EOF: our DONE was sent", st.Err)
	case !done && (!errors.As(st.Err, &ae) || ae.Code != AbortGoingAway || !ae.Remote):
		t.Fatalf("end %v, want *AbortError{AbortGoingAway, Remote}", st.Err)
	case !done && form == "rst-first" && ae.Msg != g2RstMsg:
		t.Fatalf("end %v, want the injected RST's end (message %q)", st.Err, g2RstMsg)
	}
	if sent, peer := g2Done(a); sent != done || peer {
		t.Fatalf("our DONE sent %v, the peer's received %v (stimulus)", sent, peer)
	}
	if at, _ := g2EndAt(t, w.a, a); at.Sub(strike) > 2*time.Second {
		t.Fatalf("ended %v after the strike, want at the GOING_AWAY", at.Sub(strike))
	}
	switch {
	case len(noted) != 1:
		t.Fatalf("NoteGoAway called %d times, want once (D21)", len(noted))
	default:
		if inst := <-noted; inst != w.b.cenv.Local {
			t.Fatalf("NoteGoAway(%x), want the bound instance", inst)
		}
	}
	if lane {
		if !first.PeerGoAway() {
			t.Fatal("no GOAWAY reached the live lane (stimulus)")
		}
		acDone(t, b, 5*time.Second)
		if st := b.Status(); !errors.Is(st.Err, net.ErrClosed) {
			t.Fatalf("passive end %v, want net.ErrClosed (its Runtime closed)", st.Err)
		}
	} else if n := answered.Load(); n != 1 {
		t.Fatalf("%d GOING_AWAY answers, want 1 (stimulus)", n)
	}
}

// g2AnswerGoAway returns an Accept for passive p that answers the next
// carrier's first frame with GOAWAY(shutdown) from p's instance — a peer
// may answer any first frame with CLOSE or GOAWAY (carrier.Establish) —,
// counting each answer in n.
func g2AnswerGoAway(p *acPassive, n *atomic.Int32) func(net.Conn) error {
	return func(nc net.Conn) error {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			h, err := carrier.ReadHello(p.cenv, nc, time.Now().Add(2*time.Second), p.maxMeta, nil)
			if err != nil {
				return
			}
			n.Add(1)
			h.Conn.WriteAndClose(wire.TypeGoAway, 0, 0, []byte{byte(wire.GoAwayShutdown)}, time.Time{})
			p.closed(h.Conn)
		}()
		return nil
	}
}

// g2RstMsg is the message of the injected RST(AbortGoingAway): an
// *AbortError carrying it proves that the RST ended the session, not the
// GOAWAY (whose end says "peer going away").
const g2RstMsg = "going away (injected first)"

// g2ResetFirst gives the dialer a, whose one lane is first, the passive's
// RST(AbortGoingAway) ahead of the passive's GOAWAY: it is injected after
// the passive's next PING on l, before the test calls the passive's
// Shutdown. That is the order a passive writer round produces when the
// Shutdown runs after the round placed its carrier controls and before it
// filled the lane: the round carries the RST alone, the next one the GOAWAY
// and CLOSE. It returns once the RST ended a, with no GOAWAY seen first.
func g2ResetFirst(t *testing.T, l *rendrtest.Link, a *Session, first *carrier.Conn) {
	t.Helper()
	var p [wire.RstFixedLen + len(g2RstMsg)]byte
	wire.PutRst(p[:], &wire.Rst{Code: wire.RstGoingAway, Msg: []byte(g2RstMsg)})
	l.InjectAfterNextFrame(rendrtest.Down, rendrtest.FramePing, rendrtest.FrameRst, 0, wire.SessionHandle, p[:])
	acWaitFor(t, 3*time.Second, "the injected RST ended the dialer", func() bool {
		return a.Status().State == StateEnded
	})
	if first.PeerGoAway() {
		t.Fatal("a GOAWAY reached the dialer before the RST ended it (stimulus)")
	}
	if n := l.Stats().Session.FramesInjected; n != 1 {
		t.Fatalf("%d frames injected, want the RST (stimulus)", n)
	}
}
