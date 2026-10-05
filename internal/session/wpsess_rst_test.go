package session

import (
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// A peer RST after our DONE (design §0.14 B4 extended to every RST code,
// M1c). Our DONE is placed once the peer acknowledged our FIN as delivered
// and the peer's FIN reached our application: the exchange is complete.
// When our FIN_DELIVERED and DONE are lost, the peer never learns that its
// FIN was delivered and keeps waiting; its Linger or IdleTimeout then ends
// the wait with RST(Linger) or RST(Idle) — or its Runtime closes with
// RST(GoingAway). Every such RST ends our session cleanly (io.EOF), not
// with *AbortError: the RST only says that the peer gave up waiting for a
// DONE that was lost. Before our DONE was sent an RST keeps its
// *AbortError (the before-done controls). Package-level helpers of this
// file start with "wpsess".

// wpsessN is the size of each direction's transfer.
const wpsessN = 64 << 10

// wpsessRstMsg is the message of every injected RST: an *AbortError that
// carries it proves that the injected RST ended the session.
const wpsessRstMsg = "the peer gave up waiting"

// wpsessDone reports s's DONE flags: ours placed, the peer's received.
func wpsessDone(s *Session) (sent, peer bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.doneSent, s.st.peerDone
}

// wpsessRstIn returns the RST s's stream received (nil: none).
func wpsessRstIn(s *Session) *wire.Rst {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.rstIn
}

// wpsessExchange runs a selector session a (dialer), b (passive) over l to
// the point where only the peer's view of our end is missing: both
// directions transferred and half-closed, the dialer's FIN acknowledged,
// and — when done — the dialer read the passive's data and FIN, so its
// FIN_DELIVERED and DONE were placed. From the half-close on, nothing the
// dialer writes arrives (its writes are swallowed whole, so no fseq gap
// ever shows): the passive never learns that its FIN was delivered and
// keeps waiting, its carrier stays up. Neither carrier may die of its
// unanswered PINGs meanwhile, and neither Linger may decide.
func wpsessExchange(t *testing.T, w *acWorld, done bool, seed uint64) (a, b *Session, l *rendrtest.Link) {
	t.Helper()
	for _, side := range []*acSide{w.a, w.b.acSide} {
		side.cenv.Timing.DeadMin, side.cenv.Timing.DeadMax = 10*time.Second, 10*time.Second
		side.p.Linger = 30 * time.Second
	}
	l = w.link("p1")
	a, b = w.open(ModeSelector, nil, l)
	acHalfCloseSettled(t, a, b, wpsessN, seed)
	swallow := make([]rendrtest.WriteResult, 64)
	for i := range swallow {
		swallow[i] = rendrtest.WriteResult{Relative: true}
	}
	l.ScriptWrites(rendrtest.Up, swallow...)
	if done {
		acReadToEOF(t, a, wpsessN, seed)
		acWaitFor(t, time.Second, "the dialer placed its DONE", func() bool {
			sent, _ := wpsessDone(a)
			return sent
		})
		b.mu.Lock()
		finAcked, peerDone := b.st.fin.acked, b.st.peerDone
		b.mu.Unlock()
		if n := l.Stats().Session.WritesScripted; n < 1 || finAcked || peerDone {
			t.Fatalf("%d dialer writes swallowed; the passive saw its FIN acknowledged %v, our DONE %v: want our FIN_DELIVERED and DONE lost (stimulus)", n, finAcked, peerDone)
		}
	}
	return a, b, l
}

// wpsessInjectRst makes the passive's direction of l carry RST(code) with
// wpsessRstMsg after the passive's next PING (the passive itself sent no
// RST: its session goes on).
func wpsessInjectRst(l *rendrtest.Link, code uint32) {
	var p [wire.RstFixedLen + len(wpsessRstMsg)]byte
	wire.PutRst(p[:], &wire.Rst{Code: code, Msg: []byte(wpsessRstMsg)})
	l.InjectAfterNextFrame(rendrtest.Down, rendrtest.FramePing, rendrtest.FrameRst, 0, wire.SessionHandle, p[:])
}

// wpsessCheckEnd checks the dialer's end after the injected RST(code): with
// our DONE sent, io.EOF exactly (Status, the SessionEnd event and Read);
// before it, *AbortError{code, wpsessRstMsg, Remote: true}. The RST ended
// it: the stream holds that RST, no no-path episode started, and Linger
// after our DONE had not passed.
func wpsessCheckEnd(t *testing.T, w *acWorld, a *Session, code uint32, done bool) {
	t.Helper()
	st := a.Status()
	var ae *AbortError
	switch {
	case st.State != StateEnded:
		t.Fatalf("dialer state %v, want ended", st.State)
	case done && st.Err != io.EOF:
		t.Fatalf("dialer end %v, want io.EOF: our DONE was sent before the RST (code %d)", st.Err, code)
	case !done && (!errors.As(st.Err, &ae) || ae.Code != AbortCode(code) || ae.Msg != wpsessRstMsg || !ae.Remote):
		t.Fatalf("dialer end %v, want *AbortError{%d, %q, Remote}", st.Err, code, wpsessRstMsg)
	}
	if r := wpsessRstIn(a); r == nil || r.Code != code || string(r.Msg) != wpsessRstMsg {
		t.Fatalf("the dialer's stream holds RST %+v, want the injected one (stimulus)", r)
	}
	if sent, peer := wpsessDone(a); sent != done || peer {
		t.Fatalf("our DONE sent %v, the peer's received %v; want sent %v, not received (stimulus)", sent, peer, done)
	}
	evs := w.a.ev.of(a.ID(), EventSessionEnd)
	if len(evs) != 1 || evs[0].Err != st.Err {
		t.Fatalf("SessionEnd events %+v, want one carrying %v", evs, st.Err)
	}
	if done {
		if n, err := a.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("Read after the end: (%d, %v), want (0, io.EOF)", n, err)
		}
		a.mu.Lock()
		lingerBy := a.st.doneSentAt.Add(a.p.Linger)
		a.mu.Unlock()
		if !evs[0].Time.Before(lingerBy) {
			t.Fatal("the session ended at the Linger after our DONE, not at the RST")
		}
	}
	if st.NoPathEpisodes != 0 || len(w.a.ev.of(a.ID(), EventNoPathStart)) != 0 {
		t.Fatalf("%d no-path episodes at an RST end, want none", st.NoPathEpisodes)
	}
}

// TestWpsessResetAfterDone_L05: the passive's carrier stays up and an RST of
// each code reaches the dialer after (done) or before (before-done) its
// DONE was sent. After our DONE every code ends the session with io.EOF;
// before it, with *AbortError carrying the RST's code and message.
func TestWpsessResetAfterDone_L05(t *testing.T) {
	for _, c := range []struct {
		name string
		code uint32
	}{
		{"closed", wire.RstClosed},
		{"linger", wire.RstLinger},
		{"going-away", wire.RstGoingAway},
		{"exhausted", wire.RstExhausted},
		{"idle", wire.RstIdle},
		{"withdrawn", wire.RstWithdrawn},
		{"application", 4242},
	} {
		for _, done := range []bool{true, false} {
			name := c.name + "/done"
			if !done {
				name = c.name + "/before-done"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					w := acNewWorld(t, nil)
					defer w.teardown()
					a, _, l := wpsessExchange(t, w, done, 101)
					wpsessInjectRst(l, c.code)
					acDone(t, a, 5*time.Second)
					if n := l.Stats().Session.FramesInjected; n != 1 {
						t.Fatalf("%d frames injected, want the RST (stimulus)", n)
					}
					wpsessCheckEnd(t, w, a, c.code, done)
				})
			})
		}
	}
}

// TestWpsessResetBeforeRoutingRepair_L05: the peer reset the session —
// RST(Linger): it gave up waiting for our lost DONE (done), or for our
// FIN_DELIVERED while we had not read its FIN yet (before-done) — and then
// retired and closed its carrier. The dialer's actor is held while the RST
// arrives and the carrier ends, so it finds the RST and the carrier's end
// in one step (what a peer that resets and retires in one writer round
// produces when the actor is busy). The RST ends the session before the
// step treats the carrier's end as a routing loss: io.EOF after our DONE,
// *AbortError before it, and in both cases no no-path episode, no
// NoPathStart, no redial and no migration.
func TestWpsessResetBeforeRoutingRepair_L05(t *testing.T) {
	for _, done := range []bool{true, false} {
		name := "done"
		if !done {
			name = "before-done"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				a, _, l := wpsessExchange(t, w, done, 111)
				release := wpsessHold(t, a)
				defer release()

				wpsessInjectRst(l, wire.RstLinger)
				acWaitFor(t, 3*time.Second, "the injected RST reached the dialer's stream", func() bool { return wpsessRstIn(a) != nil })
				if l.Kill() != 1 {
					t.Fatal("no carrier killed (stimulus)")
				}
				synctest.Wait()
				a.mu.Lock()
				dead := len(a.lanes) == 1 && laneEnded(a.lanes[0])
				a.mu.Unlock()
				if !dead || a.Status().State == StateEnded {
					t.Fatalf("before the held step: the carrier ended %v, session %v; want both facts pending (stimulus)", dead, a.Status().State)
				}

				release()
				acDone(t, a, 5*time.Second)
				wpsessCheckEnd(t, w, a, wire.RstLinger, done)
				if st := a.Status(); st.MigDeath+st.MigQuality+st.MigExplicit != 0 {
					t.Fatalf("migrations {death %d, quality %d, explicit %d} at an RST end, want none", st.MigDeath, st.MigQuality, st.MigExplicit)
				}
				if n := l.Stats().Dials; n != 1 {
					t.Fatalf("%d dials on the link, want only the OPEN (no redial after the RST)", n)
				}
			})
		})
	}
}
