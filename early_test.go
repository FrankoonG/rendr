package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Root EarlyReturn (M4 design §A2.1, §A4.4; WP10): the Peer.Dial branch,
// the DialPacket refusal, the EarlyDataMax clamp, the lazily bound remote
// address, SessionStatus.EarlyBytes, the end event of a failed opening and
// Runtime.Close of an unanswered session. Every row runs in a synctest
// bubble over rendrtest links.

// erDial dials p with EarlyReturn (plus o) and requires that Dial returned
// at once — before any virtual time passed — with a Conn still pending.
func erDial(t testing.TB, p *Peer, o DialOptions) *Conn {
	t.Helper()
	o.EarlyReturn = true
	start := time.Now()
	c, err := p.Dial(context.Background(), o)
	if err != nil {
		t.Fatalf("Dial with EarlyReturn: %v", err)
	}
	if d := time.Since(start); d != 0 {
		t.Fatalf("Dial with EarlyReturn took %v, want an immediate return", d)
	}
	if st := c.Status(); st.State != StatePending || st.Role != RoleDialer {
		t.Fatalf("EarlyReturn Conn after Dial: state %v role %v, want pending dialer", st.State, st.Role)
	}
	return c
}

// erPattern is n bytes of a position-dependent pattern starting at off.
func erPattern(off, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((off + i) * 7 % 251)
	}
	return b
}

// erReadN reads exactly n bytes from c and requires that they are the
// pattern from off.
func erReadN(t testing.TB, c *Conn, off, n int) {
	t.Helper()
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	if !bytes.Equal(got, erPattern(off, n)) {
		t.Fatalf("bytes [%d, %d) differ from what was written", off, off+n)
	}
}

// erWriteAsync writes p to c on its own goroutine; the channel carries the
// Write's result.
func erWriteAsync(c *Conn, p []byte) <-chan error {
	ch := make(chan error, 1)
	go func() {
		n, err := c.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		ch <- err
	}()
	return ch
}

// erAnswered waits (virtual time, at most 5 s) until the EarlyReturn
// dialer c has the peer's answer and requires that it opened.
func erAnswered(t testing.TB, c *Conn) {
	t.Helper()
	for range 500 {
		if c.Status().State != StatePending {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := c.Status().State; st != StateOpen {
		t.Fatalf("dialer state %v after the answer, want open", st)
	}
}

// erAccept accepts one pending session on ln after everything in flight
// arrived (synctest.Wait): the OPEN and its early DATA are both admitted.
func erAccept(t testing.TB, ln *Listener) *PendingConn {
	t.Helper()
	pc, err := ln.Accept(context.Background())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	synctest.Wait()
	return pc
}

// TestEarlyDataMaxClamp (M4-D16): Handshake.EarlyDataMax defaults to
// 64 KiB, is clamped to 0–64 KiB (a clamp is recorded, a negative value
// selects 0 silently, as for the other zero-able fields) and reaches the
// session template. Stimulus: an EarlyReturn session writes 80,000 bytes
// on a fresh carrier; exactly min(80,000, EarlyDataMax) of them travel as
// early data — SessionStatus.EarlyBytes on both ends — and every byte is
// delivered once the passive confirmed.
func TestEarlyDataMaxClamp(t *testing.T) {
	for _, tc := range []struct {
		in, want int
		record   string
	}{
		{0, wire.EarlyWindow, ""},
		{-1, 0, ""},
		{4096, 4096, ""},
		{wire.EarlyWindow, wire.EarlyWindow, ""},
		{1 << 20, wire.EarlyWindow, "Handshake.EarlyDataMax: 1048576 → 65536 (range 0..65536)"},
	} {
		e, adj := normalize(Config{Handshake: HandshakeLimits{EarlyDataMax: tc.in}}, nil)
		if got := e.cfg.Handshake.EarlyDataMax; got != tc.want || e.params.EarlyDataMax != tc.want {
			t.Fatalf("EarlyDataMax %d: cfg %d, session template %d, want %d", tc.in, got, e.params.EarlyDataMax, tc.want)
		}
		var want []string
		if tc.record != "" {
			want = []string{tc.record}
		}
		if strings.Join(adj, "|") != strings.Join(want, "|") {
			t.Fatalf("EarlyDataMax %d: adjustments %q, want %q", tc.in, adj, want)
		}
	}
	const total = 80000
	for _, tc := range []struct {
		name  string
		in    int
		early uint64
	}{
		{"default", 0, wire.EarlyWindow},
		{"4 KiB", 4096, 4096},
		{"clamped", 1 << 20, wire.EarlyWindow},
		{"negative selects 0", -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{Handshake: HandshakeLimits{EarlyDataMax: tc.in}}, Config{}, nil, ListenConfig{}, "a")
				dc := erDial(t, e.peer(), DialOptions{})
				wrote := erWriteAsync(dc, erPattern(0, total))
				pc := erAccept(t, e.ln)
				if dc.Status().State != StatePending {
					t.Fatal("the dialer left StatePending before Confirm")
				}
				sc, err := pc.Confirm()
				if err != nil {
					t.Fatalf("Confirm: %v", err)
				}
				erReadN(t, sc, 0, total)
				if err := <-wrote; err != nil {
					t.Fatalf("Write: %v", err)
				}
				if d, p := dc.Status().EarlyBytes, sc.Status().EarlyBytes; d != tc.early || p != tc.early {
					t.Fatalf("EarlyBytes dialer %d, passive %d, want %d on both", d, p, tc.early)
				}
				e2eFinish(t, dc, sc)
				e.close()
			})
		})
	}
}

// TestDialPacketEarlyReturnRefused (M4-D14): DialPacket refuses
// EarlyReturn with ErrProtocol in its entry checks — at once, before the
// Peer starts probing (no factory call on either link), without a
// MaxSessions unit or a session left — while Dial of the same Peer
// accepts it.
func TestDialPacketEarlyReturnRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		e.links[0].SetDelay(50*time.Millisecond, 0)
		e.links[1].SetDelay(50*time.Millisecond, 0)
		p := e.peer()
		start := time.Now()
		pc, err := p.DialPacket(context.Background(), DialOptions{EarlyReturn: true})
		if pc != nil || !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "EarlyReturn is for stream sessions") {
			t.Fatalf("DialPacket with EarlyReturn: %v, %v; want ErrProtocol for stream sessions only", pc, err)
		}
		if d := time.Since(start); d != 0 {
			t.Fatalf("the refusal took %v, want none", d)
		}
		synctest.Wait()
		for _, l := range e.links {
			if st := l.Stats(); st.Dials != 0 {
				t.Fatalf("link %s: %d factory calls after the refusal, want 0 (not even a probe)", l.Name(), st.Dials)
			}
		}
		if st := e.d.Status(); st.Sessions != (SessionCounts{}) || e.d.table.inUse() != 0 {
			t.Fatalf("dialer state after the refusal: %+v (%d MaxSessions units)", st.Sessions, e.d.table.inUse())
		}
		// The same Peer's stream Dial takes it.
		dc := erDial(t, p, DialOptions{})
		dc.Close()
		e2eDone(t, dc, time.Second)
		e.close()
	})
}

// TestEarlyReturnSkipsProbeWait (M4-D13): on a Peer with two factories
// whose probes are cold, a classic Dial waits for the first probe samples
// (Probe.DialWait, 800 ms: a probe needs about 1.2 s over these links),
// an EarlyReturn Dial returns at once. Probing still starts without any
// session byte on the links (Health.Use; the session's Health.Hold at
// session.Dial starts it as well, so the row cannot tell the two apart),
// and the session then opens with its first Write.
func TestEarlyReturnSkipsProbeWait(t *testing.T) {
	const oneWay = 300 * time.Millisecond
	newPair := func(t *testing.T) *e2ePair {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		for _, l := range e.links {
			l.SetDelay(oneWay, 0)
		}
		return e
	}
	t.Run("classic Dial waits", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newPair(t)
			ch := e2eDialAsync(context.Background(), e.peer(), DialOptions{})
			sc := e2eConfirm(t, e.ln)
			r := <-ch
			if r.err != nil {
				t.Fatalf("Dial: %v", r.err)
			}
			if r.at < 800*time.Millisecond {
				t.Fatalf("classic Dial took %v: the premise (a cold-start wait of 800 ms) does not hold", r.at)
			}
			e2eFinish(t, r.c, sc)
			e.close()
		})
	})
	t.Run("EarlyReturn does not", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newPair(t)
			dc := erDial(t, e.peer(), DialOptions{})
			time.Sleep(time.Second) // virtual: the probes run, the session does not open
			var probes int64
			for _, l := range e.links {
				st := l.Stats()
				if st.Session.Bytes != 0 {
					t.Fatalf("link %s carried %d session bytes before the first Write", l.Name(), st.Session.Bytes)
				}
				probes += st.Dials
			}
			if probes == 0 {
				t.Fatal("no probe carrier was dialled: probing did not start (Health.Use, or Hold at the session's Dial)")
			}
			msg := erPattern(0, 1000)
			if _, err := dc.Write(msg); err != nil {
				t.Fatalf("Write: %v", err)
			}
			sc := e2eConfirm(t, e.ln)
			erReadN(t, sc, 0, len(msg))
			erAnswered(t, dc)
			if dc.Status().EarlyBytes != uint64(len(msg)) {
				t.Fatalf("EarlyBytes %d, want %d", dc.Status().EarlyBytes, len(msg))
			}
			e2eFinish(t, dc, sc)
			e.close()
		})
	})
}

// erEvents collects one Runtime's events.
type erEvents struct {
	mu sync.Mutex
	ev []Event
}

func (r *erEvents) add(ev Event) {
	r.mu.Lock()
	r.ev = append(r.ev, ev)
	r.mu.Unlock()
}

// of returns the events of session sid so far.
func (r *erEvents) of(sid SessionID) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	for _, ev := range r.ev {
		if ev.Session == sid {
			out = append(out, ev)
		}
	}
	return out
}

// TestEarlyReturnEvents (§A4.4): an EarlyReturn session emits no event
// before the peer's answer; a refused opening ends it with exactly one
// EventSessionEnd carrying the Dial error (the *RejectError that Read and
// Write return), and an accepted one starts with EventCarrierUp.
func TestEarlyReturnEvents(t *testing.T) {
	t.Run("rejected", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var rec erEvents
			e := e2eNew(t, Config{OnEvent: rec.add}, Config{}, nil, ListenConfig{}, "a")
			dc := erDial(t, e.peer(), DialOptions{})
			if _, err := dc.Write([]byte("hello")); err != nil {
				t.Fatalf("Write before the answer: %v", err)
			}
			pc := erAccept(t, e.ln)
			if evs := rec.of(dc.ID()); len(evs) != 0 {
				t.Fatalf("events before the answer: %+v", evs)
			}
			if err := pc.Reject(42, "no"); err != nil {
				t.Fatalf("Reject: %v", err)
			}
			var re *RejectError
			if _, err := dc.Read(make([]byte, 8)); !errors.As(err, &re) || re.Code != 42 || !errors.Is(err, ErrRejected) {
				t.Fatalf("Read after the refusal: %v, want *RejectError 42", err)
			}
			if _, err := dc.Write([]byte("x")); !errors.As(err, &re) || re.Code != 42 {
				t.Fatalf("Write after the refusal: %v, want *RejectError 42", err)
			}
			e2eDone(t, dc, time.Second)
			synctest.Wait()
			evs := rec.of(dc.ID())
			if len(evs) != 1 || evs[0].Kind != EventSessionEnd || !errors.As(evs[0].Err, &re) || re.Code != 42 {
				t.Fatalf("events of a refused EarlyReturn session: %+v, want one EventSessionEnd with *RejectError 42", evs)
			}
			e.close()
		})
	})
	t.Run("accepted", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var rec erEvents
			e := e2eNew(t, Config{OnEvent: rec.add}, Config{}, nil, ListenConfig{}, "a")
			dc := erDial(t, e.peer(), DialOptions{})
			if _, err := dc.Write([]byte("hello")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			pc := erAccept(t, e.ln)
			if evs := rec.of(dc.ID()); len(evs) != 0 {
				t.Fatalf("events before the answer: %+v", evs)
			}
			sc, err := pc.Confirm()
			if err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			synctest.Wait()
			if evs := rec.of(dc.ID()); len(evs) == 0 || evs[0].Kind != EventCarrierUp {
				t.Fatalf("events after the answer: %+v, want EventCarrierUp first", evs)
			}
			got := make([]byte, 5)
			if _, err := io.ReadFull(sc, got); err != nil || string(got) != "hello" {
				t.Fatalf("passive read %q, %v", got, err)
			}
			e2eFinish(t, dc, sc)
			e.close()
		})
	})
}

// TestEarlyReturnRemoteAddrBinding_L38 (M4-D15, L38): an EarlyReturn
// Conn reports the zero peer InstanceID until the first OPEN_ACK(OK) binds
// the instance, then that instance for the session's life — also after a
// second instance answered OK late. The Peer's two factories reach two
// passive Runtimes (a peer that restarted behind one path): the first
// OPEN goes out at the first Write, the second after JoinStagger (1 s);
// A confirms at 2.5 s from its Accept at the latest, B 3 s after its own,
// so A always binds and B's OK comes later; the dialer withdraws B's
// session (stimulus proof: B's Conn ends with AbortWithdrawn).
func TestEarlyReturnRemoteAddrBinding_L38(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		rtB := wpTestRuntime(t, Config{}, nil)
		lnB := wpListen(t, rtB, ListenConfig{})
		linkB := rendrtest.NewLink(rendrtest.LinkConfig{Name: "b", Accept: lnB.Handle})
		t.Cleanup(linkB.Close)
		instA, instB := e.p.InstanceID(), rtB.InstanceID()

		var wg sync.WaitGroup
		var scB *Conn
		var confirmedA, confirmedB time.Time
		wg.Go(func() {
			pc, err := lnB.Accept(context.Background())
			if err != nil {
				t.Errorf("B Accept: %v", err)
				return
			}
			time.Sleep(3 * time.Second)
			if scB, err = pc.Confirm(); err != nil {
				t.Errorf("B Confirm: %v (the premise needs B's OK)", err)
			}
			confirmedB = time.Now()
		})
		var scA *Conn
		wg.Go(func() {
			pc, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Errorf("A Accept: %v", err)
				return
			}
			time.Sleep(1500 * time.Millisecond)
			if scA, err = pc.Confirm(); err != nil {
				t.Errorf("A Confirm: %v", err)
			}
			confirmedA = time.Now()
		})

		dc := erDial(t, e.peer(e.links[0], linkB), DialOptions{})
		check := func(when string, want InstanceID) {
			t.Helper()
			ra, ok := dc.RemoteAddr().(Addr)
			if !ok || ra.Instance != want || ra.Session != dc.ID() {
				t.Fatalf("%s: RemoteAddr %v, want instance %v and session %v", when, dc.RemoteAddr(), want, dc.ID())
			}
			if dc.PeerInstance() != want || dc.Status().PeerInstance != want {
				t.Fatalf("%s: PeerInstance %v, Status().PeerInstance %v, want %v", when, dc.PeerInstance(), dc.Status().PeerInstance, want)
			}
		}
		check("after Dial", InstanceID{})
		if _, err := dc.Write([]byte("hello")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		synctest.Wait()
		check("opening, unanswered", InstanceID{})
		wg.Wait()
		synctest.Wait()
		if t.Failed() {
			return
		}
		if st := dc.Status(); st.State != StateOpen {
			t.Fatalf("dialer state %v after A's OK", st.State)
		}
		if !confirmedA.Before(confirmedB) || instA == instB {
			t.Fatalf("premise: A answered at %v, B at %v; instances %v, %v", confirmedA, confirmedB, instA, instB)
		}
		check("after both answers", instA)
		e2eDone(t, scB, time.Second)
		var ae *AbortError
		if err := scB.Status().Err; !errors.As(err, &ae) || ae.Code != AbortWithdrawn {
			t.Fatalf("stimulus: B's session ended with %v, want AbortWithdrawn (B's late OK)", err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(scA, got); err != nil || string(got) != "hello" {
			t.Fatalf("A read %q, %v", got, err)
		}
		e2eFinish(t, dc, scA)
		check("after the end", instA)
		e.close()
		rtB.Close()
		wpNoState(t, rtB)
	})
}

// TestEarlyBytesStatus (M4-D18, L63): SessionStatus.EarlyBytes on both
// ends — 0 before the answer, the first Write's bytes once a fresh carrier
// carried them with the OPEN, frozen afterwards; 0 for a classic Dial and
// for an EarlyReturn session that opened on the live carrier of another
// session of the Peer (rendr mux: no early data there, M4-D17), whose bytes
// arrive all the same.
func TestEarlyBytesStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		p := e.peer()

		dc := erDial(t, p, DialOptions{})
		if _, err := dc.Write(erPattern(0, 1000)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		pc := erAccept(t, e.ln)
		if n := dc.Status().EarlyBytes; n != 0 {
			t.Fatalf("dialer EarlyBytes %d before the answer, want 0", n)
		}
		sc, err := pc.Confirm()
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		erReadN(t, sc, 0, 1000)
		if _, err := dc.Write(erPattern(1000, 5000)); err != nil {
			t.Fatalf("Write after the answer: %v", err)
		}
		erReadN(t, sc, 1000, 5000)
		if d, s := dc.Status().EarlyBytes, sc.Status().EarlyBytes; d != 1000 || s != 1000 {
			t.Fatalf("fresh carrier: EarlyBytes dialer %d, passive %d, want 1000 on both", d, s)
		}

		// A second EarlyReturn session of the Peer opens on the live trunk.
		dc2 := erDial(t, p, DialOptions{})
		if _, err := dc2.Write(erPattern(0, 700)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		sc2 := e2eConfirm(t, e.ln)
		erReadN(t, sc2, 0, 700)
		if d, s := dc2.Status().EarlyBytes, sc2.Status().EarlyBytes; d != 0 || s != 0 {
			t.Fatalf("shared carrier: EarlyBytes dialer %d, passive %d, want 0 on both", d, s)
		}
		if st := e.links[0].Stats(); st.Dials != 1 {
			t.Fatalf("premise: %d carriers dialled, want the one shared trunk", st.Dials)
		}

		// A classic Dial.
		dc3, sc3 := e2eOpen(t, p, e.ln, DialOptions{})
		e2eExchange(t, dc3, sc3, 4096, 3)
		if d, s := dc3.Status().EarlyBytes, sc3.Status().EarlyBytes; d != 0 || s != 0 {
			t.Fatalf("classic Dial: EarlyBytes dialer %d, passive %d, want 0", d, s)
		}

		for _, c := range [][2]*Conn{{dc, sc}, {dc2, sc2}, {dc3, sc3}} {
			e2eFinish(t, c[0], c[1])
		}
		e.close()
	})
}

// TestEarlyReturnRuntimeClose (§A4.4, risk 5): Runtime.Close shuts down
// an EarlyReturn session that the application holds but the peer has not
// answered. Unopened (no Write, Read or CloseWrite yet): nothing is sent —
// no factory call — and the Conn ends with net.ErrClosed. Opening (the
// OPEN and its early bytes are pending at the passive): the session
// withdraws: the passive session ends with ErrSessionLost, as one of a
// classic Dial withdrawn by Runtime.Close does (its EventSessionEnd), so
// the passive's Confirm fails and nothing is left on either side.
func TestEarlyReturnRuntimeClose(t *testing.T) {
	t.Run("unopened", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			dc := erDial(t, e.peer(), DialOptions{})
			e.d.Close()
			e2eDone(t, dc, time.Second)
			if _, err := dc.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Read after Runtime.Close: %v, want net.ErrClosed", err)
			}
			synctest.Wait()
			if st := e.links[0].Stats(); st.Dials != 0 || st.All.Bytes != 0 {
				t.Fatalf("an unopened session sent something: %d dials, %d bytes", st.Dials, st.All.Bytes)
			}
			e.close()
		})
	})
	t.Run("opening", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pev := &erEvents{}
			e := e2eNew(t, Config{}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
			dc := erDial(t, e.peer(), DialOptions{})
			if _, err := dc.Write(erPattern(0, 2000)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			pc := erAccept(t, e.ln)
			if st := e.p.Status(); st.Sessions.Pending != 1 {
				t.Fatalf("premise: passive sessions %+v, want one pending", st.Sessions)
			}
			e.d.Close()
			e2eDone(t, dc, time.Second)
			synctest.Wait()
			if c, err := pc.Confirm(); err == nil {
				t.Fatalf("Confirm after the dialer's Runtime closed: %v, want an error (withdrawn)", c)
			}
			select {
			case <-pc.Context().Done():
			default:
				t.Fatal("the pending context is not done after the withdrawal")
			}
			var ended error
			for _, ev := range pev.of(pc.ID()) {
				if ev.Kind == EventSessionEnd {
					ended = ev.Err
				}
			}
			if !errors.Is(ended, ErrSessionLost) {
				t.Fatalf("the passive session ended with %v, want ErrSessionLost (withdrawn by the dialer's Runtime.Close)", ended)
			}
			// The withdrawn carrier's reader stage is released within its
			// close bound (about 1 s), not at once.
			for range 20 {
				if e.p.Status().BufferedBytes == 0 {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if st := e.p.Status(); st.Sessions.Pending+st.Sessions.Open != 0 || st.BufferedBytes != 0 {
				t.Fatalf("passive state 2 s after the withdrawal: %+v, %d buffered", st.Sessions, st.BufferedBytes)
			}
			e.close()
		})
	})
}

// An EarlyReturn Conn that the application holds but never uses is idle
// like any other session (plan:277, plan:385; K21 candidate 1): its
// IdleTimeout counts from Dial, and at expiry it ends with ErrIdleTimeout,
// sends nothing (no OPEN was sent, so no RST either) and gives back its
// MaxSessions unit. Helpers of these tests start with "ei".

// eiIdle is the IdleTimeout of these rows: the clamp's floor.
const eiIdle = 10 * time.Second

// eiEndEvents returns the EventSessionEnd records of session sid.
func eiEndEvents(rec *erEvents, sid SessionID) []Event {
	var out []Event
	for _, ev := range rec.of(sid) {
		if ev.Kind == EventSessionEnd {
			out = append(out, ev)
		}
	}
	return out
}

// TestEarlyReturnUnusedIdleTimeout_plan277 (plan:277, plan:385; K21): an
// EarlyReturn session with no Write, Read or CloseWrite ends with
// ErrIdleTimeout exactly IdleTimeout after Dial, whether the limit comes
// from Config.IdleTimeout (no call rings the session's scheduler) or from
// Conn.SetIdleTimeout (l4.Dial's pattern), also when SetIdleTimeout comes
// later (the idle clock is not restarted). Stimulus proof: with MaxSessions
// 1 a second Dial before the deadline gets ErrCapacity (the unused session
// holds the unit). At the end: Read and Write return ErrIdleTimeout, one
// EventSessionEnd carries it, no factory was called and no byte crossed the
// link, the passive saw nothing, the dialer's table is empty, and a classic
// Dial on the same Runtime opens, exchanges and finishes cleanly.
func TestEarlyReturnUnusedIdleTimeout_plan277(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   time.Duration // Config.IdleTimeout
		set   time.Duration // SetIdleTimeout value (0: no call)
		setAt time.Duration // when SetIdleTimeout is called, after Dial
	}{
		{name: "Config.IdleTimeout", cfg: eiIdle},
		{name: "SetIdleTimeout at Dial", set: eiIdle},
		{name: "SetIdleTimeout later", set: eiIdle, setAt: 6 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var rec erEvents
				e := e2eNew(t, Config{IdleTimeout: tc.cfg, MaxSessions: 1, OnEvent: rec.add}, Config{}, nil, ListenConfig{}, "a")
				p := e.peer()
				dc := erDial(t, p, DialOptions{})
				dialed := time.Now()
				if tc.set != 0 {
					time.Sleep(tc.setAt)
					if err := dc.SetIdleTimeout(tc.set); err != nil {
						t.Fatalf("SetIdleTimeout: %v", err)
					}
				}
				deadline := dialed.Add(eiIdle)
				if _, err := p.Dial(context.Background(), DialOptions{EarlyReturn: true}); !errors.Is(err, ErrCapacity) {
					t.Fatalf("premise: a second Dial with MaxSessions 1: %v, want ErrCapacity (the unused session holds the unit)", err)
				}
				time.Sleep(time.Until(deadline) - time.Millisecond)
				synctest.Wait()
				if st := dc.Status(); st.State != StatePending || st.Err != nil {
					t.Fatalf("1 ms before the idle limit: state %v, err %v; want pending", st.State, st.Err)
				}
				e2eDone(t, dc, time.Second)
				if at := time.Now(); at.Before(deadline) || at.Sub(deadline) > 5*time.Millisecond {
					t.Fatalf("the session ended %v after Dial, want the idle limit %v", at.Sub(dialed), eiIdle)
				}
				if st := dc.Status(); st.State != StateEnded || !errors.Is(st.Err, ErrIdleTimeout) {
					t.Fatalf("end: state %v, err %v; want ended with ErrIdleTimeout", st.State, st.Err)
				}
				if n, err := dc.Read(make([]byte, 8)); n != 0 || !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("Read after the idle end = (%d, %v), want (0, ErrIdleTimeout)", n, err)
				}
				if n, err := dc.Write([]byte("late")); n != 0 || !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("Write after the idle end = (%d, %v), want (0, ErrIdleTimeout)", n, err)
				}
				synctest.Wait()
				if evs := eiEndEvents(&rec, dc.ID()); len(evs) != 1 || !errors.Is(evs[0].Err, ErrIdleTimeout) {
					t.Fatalf("SessionEnd events %+v, want one carrying ErrIdleTimeout", evs)
				}
				if st := e.links[0].Stats(); st.Dials != 0 || st.All.Bytes != 0 {
					t.Fatalf("the unused session sent something: %d factory calls, %d bytes", st.Dials, st.All.Bytes)
				}
				if st := e.p.Status(); st.Sessions != (SessionCounts{}) || st.AcceptBacklog != [2]int{} {
					t.Fatalf("the passive saw a session: %+v, backlog %v", st.Sessions, st.AcceptBacklog)
				}
				if st := e.d.Status(); st.Sessions != (SessionCounts{}) || e.d.table.inUse() != 0 || st.BufferedBytes != 0 {
					t.Fatalf("dialer after the idle end: %+v, %d MaxSessions units, %d buffered", st.Sessions, e.d.table.inUse(), st.BufferedBytes)
				}
				dc2, sc := e2eOpen(t, p, e.ln, DialOptions{})
				e2eExchange(t, dc2, sc, 64<<10, 21)
				e2eFinish(t, dc2, sc)
				e.close()
			})
		})
	}
}

// TestEarlyReturnUnusedIdleOff (plan:277; K21): without an idle limit an
// unused EarlyReturn session stays pending however long it waits — 0 in
// Config, or SetIdleTimeout(0) over a Config limit (the override counts) —
// and its first Write still opens it and delivers.
func TestEarlyReturnUnusedIdleOff(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  time.Duration
		off  bool // SetIdleTimeout(0) right after Dial
	}{
		{name: "Config 0", cfg: 0},
		{name: "SetIdleTimeout(0) over Config", cfg: eiIdle, off: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{IdleTimeout: tc.cfg}, Config{}, nil, ListenConfig{}, "a")
				dc := erDial(t, e.peer(), DialOptions{})
				if tc.off {
					if err := dc.SetIdleTimeout(0); err != nil {
						t.Fatalf("SetIdleTimeout(0): %v", err)
					}
				}
				select {
				case <-dc.s.Done():
					t.Fatalf("the unused session ended without an idle limit: %v", dc.Status().Err)
				case <-time.After(25 * time.Hour):
				}
				if st := dc.Status(); st.State != StatePending || e.links[0].Stats().Dials != 0 {
					t.Fatalf("after 25 h: state %v, %d factory calls; want pending and none", st.State, e.links[0].Stats().Dials)
				}
				msg := erPattern(0, 1000)
				if _, err := dc.Write(msg); err != nil {
					t.Fatalf("Write: %v", err)
				}
				sc := e2eConfirm(t, e.ln)
				erReadN(t, sc, 0, len(msg))
				erAnswered(t, dc)
				e2eFinish(t, dc, sc)
				e.close()
			})
		})
	}
}

// TestEarlyReturnUsedBeforeIdleLimit (plan:277; K21): the rule is for a
// session never used. A Write, or a Read, 9 s after Dial (IdleTimeout
// 10 s) opens the session; the passive confirms only at 11 s, so the
// opening spans Dial's idle mark and must survive it (an opening phase is
// bounded by NoPathGrace, never by IdleTimeout, as for a classic Dial).
// From the open on the session idles like any other: it ends
// ErrIdleTimeout (the passive *AbortError{AbortIdle}) IdleTimeout after its
// last progress, never earlier.
func TestEarlyReturnUsedBeforeIdleLimit(t *testing.T) {
	for _, read := range []bool{false, true} {
		name := "Write"
		if read {
			name = "Read"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{IdleTimeout: eiIdle}, Config{}, nil, ListenConfig{}, "a")
				dc := erDial(t, e.peer(), DialOptions{})
				dialed := time.Now()
				time.Sleep(9 * time.Second)
				msg := erPattern(0, 700)
				var rd <-chan error
				if read {
					rd = erReadAsync(dc, len(msg))
				} else if _, err := dc.Write(msg); err != nil {
					t.Fatalf("Write 9 s after Dial: %v", err)
				}
				pc := erAccept(t, e.ln)
				time.Sleep(time.Until(dialed.Add(eiIdle)) + time.Second)
				if st := dc.Status(); st.State != StatePending || st.Err != nil {
					t.Fatalf("1 s past Dial's idle mark, still opening: state %v, err %v; want pending", st.State, st.Err)
				}
				sc, err := pc.Confirm()
				if err != nil {
					t.Fatalf("Confirm at 11 s: %v", err)
				}
				if read {
					if _, err := sc.Write(msg); err != nil {
						t.Fatalf("passive Write: %v", err)
					}
					if err := <-rd; err != nil {
						t.Fatalf("dialer Read: %v", err)
					}
				} else {
					erReadN(t, sc, 0, len(msg))
				}
				erAnswered(t, dc)
				synctest.Wait()
				last := time.Now() // the last progress (a Read commit, or our bytes acknowledged within an ACK interval)
				e2eDone(t, dc, 2*eiIdle)
				if el := time.Since(last); el < eiIdle-time.Second {
					t.Fatalf("the open session ended %v after its last progress, before its idle limit %v", el, eiIdle)
				}
				if err := dc.Status().Err; !errors.Is(err, ErrIdleTimeout) {
					t.Fatalf("dialer end %v, want ErrIdleTimeout", err)
				}
				e2eDone(t, sc, 5*time.Second)
				var ae *AbortError
				if err := sc.Status().Err; !errors.As(err, &ae) || ae.Code != AbortIdle || !ae.Remote {
					t.Fatalf("passive end %v, want *AbortError{AbortIdle, Remote}", err)
				}
				e.close()
			})
		})
	}
}

// erReadAsync reads exactly n bytes of the pattern from 0 on its own
// goroutine; the channel carries the outcome.
func erReadAsync(c *Conn, n int) <-chan error {
	ch := make(chan error, 1)
	go func() {
		got := make([]byte, n)
		if _, err := io.ReadFull(c, got); err != nil {
			ch <- err
			return
		}
		if !bytes.Equal(got, erPattern(0, n)) {
			ch <- errors.New("the dialer read other bytes")
			return
		}
		ch <- nil
	}()
	return ch
}

// TestEarlyReturnStatusDuringOpen (F-8): an EarlyReturn Conn is the
// application's before its session opens (M4-D12), so the application may
// call Status, PeerInstance and RemoteAddr while the session's scheduler
// completes the open of a first Write. The open binds the peer instance
// after Dial returned; before the fix Status read it unsynchronised against
// that write (a data race the race detector reported in
// TestEarlyReturnUnusedIdleOff, 1 of 3 race passes). A poller on its own
// goroutine reads all three for the whole open: under -race the row fails
// on such a race; in every build each reading is the unbound zero or the
// passive's instance, never anything else, a Status reports the instance
// exactly when its State is no longer Pending (the peer belongs to the
// same snapshot as the state), and once seen the instance never changes.
func TestEarlyReturnStatusDuringOpen(t *testing.T) {
	for range 20 {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			want := e.p.InstanceID()
			dc := erDial(t, e.peer(), DialOptions{})
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var bad []string
			wg.Go(func() {
				var seen InstanceID
				for {
					select {
					case <-stop:
						return
					default:
					}
					st := dc.Status()
					pi := dc.PeerInstance()
					ra, _ := dc.RemoteAddr().(Addr)
					switch {
					case st.State == StatePending && st.PeerInstance != (InstanceID{}):
						bad = append(bad, "Status pending with a peer instance")
					case st.State != StatePending && st.PeerInstance != want:
						bad = append(bad, "Status "+st.State.String()+" without the passive's instance")
					case pi != (InstanceID{}) && pi != want, ra.Instance != (InstanceID{}) && ra.Instance != want:
						bad = append(bad, "PeerInstance or RemoteAddr neither zero nor the passive's")
					case seen != (InstanceID{}) && (pi != seen || ra.Instance != seen):
						bad = append(bad, "the instance changed after it was seen")
					}
					if pi != (InstanceID{}) {
						seen = pi
					}
					// Block durably between polls, so the bubble's
					// virtual time advances.
					time.Sleep(10 * time.Microsecond)
				}
			})
			msg := erPattern(0, 1000)
			if _, err := dc.Write(msg); err != nil {
				t.Fatalf("Write: %v", err)
			}
			sc := e2eConfirm(t, e.ln)
			erReadN(t, sc, 0, len(msg))
			erAnswered(t, dc)
			close(stop)
			wg.Wait()
			if len(bad) != 0 {
				t.Fatalf("%d bad readings during the open, the first: %s", len(bad), bad[0])
			}
			if st := dc.Status(); st.PeerInstance != want || dc.PeerInstance() != want {
				t.Fatalf("open: Status().PeerInstance %v PeerInstance %v, want %v", st.PeerInstance, dc.PeerInstance(), want)
			}
			e2eFinish(t, dc, sc)
			e.close()
		})
	}
}

// The passive's early data (M4 design §A5.1 … §A5.3; M4-D2, M4-D5, M4-D6,
// M4-D8; WP9b) through a real Runtime admission: scripted raw-wire dialers
// (kit_test.go) send an OPEN whose flag bit 0 (EARLY) is set and DATA
// frames before the verdict, as rendr's EarlyReturn dialer does, plus the
// violations a compliant dialer never sends.

// e9Inst is the dialer instance of these tests.
var e9Inst = wpInst(0x9b)

// e9Open encodes a stream OPEN payload with flags (wire.OpenFlagEarly or
// 0) and the dialer's receive window.
func e9Open(sid [16]byte, mode uint8, flags uint16) []byte {
	b := make([]byte, wire.OpenFixedLen)
	wire.PutOpen(b, &wire.Open{SID: sid, Kind: wire.KindStream, Mode: mode, Flags: flags, RetainMs: 30000, Window: 8 << 20})
	return b
}

// e9Data encodes a DATA payload: offset, then p.
func e9Data(off uint64, p []byte) []byte {
	b := make([]byte, wire.DataPrefixLen+len(p))
	wire.PutDataOffset(b, off)
	copy(b[wire.DataPrefixLen:], p)
	return b
}

// e9Pattern returns n bytes whose value at stream offset off+i depends on
// the offset (equal across overlapping copies, distinct across offsets).
func e9Pattern(off uint64, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		x := off + uint64(i)
		b[i] = byte(x ^ x>>8 ^ x>>17)
	}
	return b
}

// e9Opened connects a scripted dialer carrier with ID id, runs the PREFACE
// exchange and sends OPEN(sid) with flags.
func e9Opened(t testing.TB, rt *Runtime, ln *Listener, id uint32, sid [16]byte, flags uint16) *wpDialer {
	t.Helper()
	d := wpConnect(t, ln, e9Inst, id)
	d.hello(rt)
	d.send(wire.TypeOpen, 0, e9Open(sid, 1, flags))
	return d
}

// sendData sends DATA(off, p) on handle 1.
func (d *wpDialer) sendData(off uint64, p []byte) {
	d.t.Helper()
	d.send(wire.TypeData, 0, e9Data(off, p))
}

// expectKilled requires that the passive closes the carrier abruptly (a
// protocol violation: no CLOSE, no answer) within 5 s.
func (d *wpDialer) expectKilled() {
	d.t.Helper()
	d.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer d.nc.SetReadDeadline(time.Time{})
	var b [64]byte
	n, err := d.nc.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		d.t.Fatalf("read (%d bytes %x, %v), want the carrier killed (EOF)", n, b[:n], err)
	}
}

// expectSilent requires that the passive writes nothing for dur.
func (d *wpDialer) expectSilent(dur time.Duration) {
	d.t.Helper()
	d.nc.SetReadDeadline(time.Now().Add(dur))
	defer d.nc.SetReadDeadline(time.Time{})
	var b [64]byte
	if n, err := d.nc.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		d.t.Fatalf("read (%d bytes %x, %v), want nothing before the verdict", n, b[:n], err)
	}
}

// e9Accept takes the next pending stream session of ln (within 5 s).
func e9Accept(t testing.TB, ln *Listener) *PendingConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	return p
}

// e9ReadAll reads exactly n bytes from c (within 5 s).
func e9ReadAll(t testing.TB, c *Conn, n int) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	b := make([]byte, n)
	if k, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("Read: %d of %d bytes: %v", k, n, err)
	}
	return b
}

// e9Death returns the death cause of the passive lane of carrier id (the
// session's Status lists the last dead lanes), CauseNone while it lives.
func e9Death(s *session.Session, id uint32) (carrier.Cause, bool) {
	for _, cs := range s.Status().Carriers {
		if cs.ID == id {
			return cs.DeathCause, cs.State == session.LaneDead
		}
	}
	return carrier.CauseNone, false
}

// e9Early returns the passive session's EarlyBytes and state.
func e9Early(s *session.Session) (uint64, session.State) {
	st := s.Status()
	return st.EarlyBytes, st.State
}

// e9Confirm confirms p, reads the OPEN_ACK(OK) on d and returns the Conn
// and the advertised window.
func e9Confirm(t testing.TB, p *PendingConn, d *wpDialer) (*Conn, uint32) {
	t.Helper()
	c, err := p.Confirm()
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	return c, d.expectOpenAck(wire.StatusOK, 0).Window
}

// TestEarlyPassiveHolds: early DATA after an OPEN(EARLY) is held by the
// pending session — nothing is written to the dialer before the verdict,
// nothing is delivered, the bytes count in EarlyBytes — and after Confirm
// the application reads them in order from the stream's first byte
// although they arrived out of order; DATA after the verdict does not
// change EarlyBytes (frozen at the verdict, M4-D18). On a fresh MUX trunk
// the OPEN(EARLY) is handle 1, and its early DATA reaches the session
// through the view the session attached at NewPending (§A5.1).
func TestEarlyPassiveHolds(t *testing.T) {
	for _, mux := range []bool{false, true} {
		name := "dedicated"
		if mux {
			name = "mux trunk"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				ln := wpListen(t, rt, ListenConfig{})
				const half = 20000
				want := e9Pattern(0, 2*half+1000)
				d := wpConnect(t, ln, e9Inst, 1)
				pre := wpPreface(e9Inst, 1)
				if mux {
					wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Opt: wire.OptMux, Instance: e9Inst, CarrierID: 1})
				}
				if ack, ok, _ := d.sendPreface(pre); !ok || ack.Status != wire.PrefaceOK || (ack.Opt&wire.OptMux != 0) != mux {
					t.Fatalf("PREFACE_ACK %+v (answered %v), want OK with mux %v", ack, ok, mux)
				}
				d.send(wire.TypeOpen, 0, e9Open(wpSID(1), 1, wire.OpenFlagEarly))
				d.sendData(half, want[half:2*half]) // out of order first
				d.sendData(0, want[:half])
				p := e9Accept(t, ln)
				synctest.Wait()
				if eb, st := e9Early(p.s); eb != 2*half || st != session.StatePending {
					t.Fatalf("pending: EarlyBytes %d state %v, want %d and pending", eb, st, 2*half)
				}
				if st := p.s.Status(); st.DeliveredBytes != 0 || st.RxBytes != 2*half {
					t.Fatalf("pending: delivered %d received %d, want 0 and %d", st.DeliveredBytes, st.RxBytes, 2*half)
				}
				d.expectSilent(2 * time.Second) // no ACK, no response: the writer is held
				c, win := e9Confirm(t, p, d)
				if win < wire.EarlyWindow {
					t.Fatalf("OPEN_ACK window %d, want ≥ %d", win, wire.EarlyWindow)
				}
				if got := e9ReadAll(t, c, 2*half); !bytes.Equal(got, want[:2*half]) {
					t.Fatal("early bytes read after Confirm differ from those sent")
				}
				d.sendData(2*half, want[2*half:]) // after the verdict: ordinary DATA
				if got := e9ReadAll(t, c, 1000); !bytes.Equal(got, want[2*half:]) {
					t.Fatal("DATA after the verdict differs")
				}
				if st := c.Status(); st.EarlyBytes != 2*half || st.RxBytes != uint64(len(want)) {
					t.Fatalf("open: EarlyBytes %d RxBytes %d, want %d and %d", st.EarlyBytes, st.RxBytes, 2*half, len(want))
				}
				d.close()
				rt.Close()
			})
		})
	}
}

// TestEarlyBeyondWindowKillsCarrier_L44: pre-verdict DATA reaching beyond
// wire.EarlyWindow kills the carrier that delivered it with
// protocol_violation (M4-D2); the pending session survives with the bytes
// it held; a compliant retry — a duplicate OPEN(EARLY) carrying the whole
// window — opens, and the application reads every byte once. DATA ending
// exactly at the window is legal.
func TestEarlyBeyondWindowKillsCarrier_L44(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		want := e9Pattern(0, wire.EarlyWindow)
		d := e9Opened(t, rt, ln, 1, wpSID(1), wire.OpenFlagEarly)
		d.sendData(0, want[:1000])
		p := e9Accept(t, ln)
		d.sendData(wire.EarlyWindow-536, append(want[wire.EarlyWindow-536:], 0xEE)) // ends one byte beyond
		d.expectKilled()
		synctest.Wait()
		if cause, dead := e9Death(p.s, 1); !dead || cause != carrier.CauseProtocolViolation {
			t.Fatalf("carrier 1: dead %v cause %v, want protocol_violation", dead, cause)
		}
		if eb, st := e9Early(p.s); eb != 1000 || st != session.StatePending {
			t.Fatalf("after the violation: EarlyBytes %d state %v, want 1000 and pending", eb, st)
		}
		// The compliant retry: the whole window, in two frames, the second
		// ending exactly at EarlyWindow.
		d2 := e9Opened(t, rt, ln, 2, wpSID(1), wire.OpenFlagEarly)
		d2.sendData(0, want[:wire.EarlyWindow/2])
		d2.sendData(wire.EarlyWindow/2, want[wire.EarlyWindow/2:])
		synctest.Wait()
		if cause, dead := e9Death(p.s, 2); dead {
			t.Fatalf("the compliant carrier died: %v", cause)
		}
		c, win := e9Confirm(t, p, d2)
		if win < wire.EarlyWindow {
			t.Fatalf("OPEN_ACK window %d, want ≥ %d", win, wire.EarlyWindow)
		}
		if got := e9ReadAll(t, c, wire.EarlyWindow); !bytes.Equal(got, want) {
			t.Fatal("bytes read differ from the early window sent")
		}
		if st := c.Status(); st.EarlyBytes != wire.EarlyWindow || st.DupBytes != 1000 {
			t.Fatalf("EarlyBytes %d DupBytes %d, want %d and 1000", st.EarlyBytes, st.DupBytes, wire.EarlyWindow)
		}
		d2.close()
		rt.Close()
	})
}

// TestEarlyDataWithoutFlagKillsCarrier: DATA before the verdict on a
// carrier whose OPEN did not carry EARLY is a violation of that carrier
// (M4-D5, as M1): it dies with protocol_violation and the pending session
// survives. The rule is per carrier: on a session whose first OPEN was
// EARLY, a duplicate OPEN without the flag may not carry early DATA either
// (a duplicate OPEN need not repeat the flag, but then it carries none).
// A compliant retry opens.
func TestEarlyDataWithoutFlagKillsCarrier(t *testing.T) {
	t.Run("no EARLY OPEN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			want := e9Pattern(0, 3000)
			d := e9Opened(t, rt, ln, 1, wpSID(1), 0)
			p := e9Accept(t, ln)
			d.sendData(0, want)
			d.expectKilled()
			synctest.Wait()
			if cause, dead := e9Death(p.s, 1); !dead || cause != carrier.CauseProtocolViolation {
				t.Fatalf("carrier 1: dead %v cause %v, want protocol_violation", dead, cause)
			}
			if eb, st := e9Early(p.s); eb != 0 || st != session.StatePending {
				t.Fatalf("EarlyBytes %d state %v, want 0 and pending", eb, st)
			}
			d2 := e9Opened(t, rt, ln, 2, wpSID(1), wire.OpenFlagEarly)
			d2.sendData(0, want)
			c, _ := e9Confirm(t, p, d2)
			if got := e9ReadAll(t, c, len(want)); !bytes.Equal(got, want) {
				t.Fatal("bytes differ")
			}
			d2.close()
			rt.Close()
		})
	})
	t.Run("duplicate OPEN without EARLY", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			want := e9Pattern(0, 3000)
			d := e9Opened(t, rt, ln, 1, wpSID(1), wire.OpenFlagEarly)
			d.sendData(0, want)
			p := e9Accept(t, ln)
			d2 := e9Opened(t, rt, ln, 2, wpSID(1), 0) // parked: legal without the flag
			synctest.Wait()
			if cause, dead := e9Death(p.s, 2); dead {
				t.Fatalf("a duplicate OPEN without EARLY died: %v", cause)
			}
			d2.sendData(0, want) // ... but it may carry no early DATA
			d2.expectKilled()
			synctest.Wait()
			if cause, dead := e9Death(p.s, 2); !dead || cause != carrier.CauseProtocolViolation {
				t.Fatalf("carrier 2: dead %v cause %v, want protocol_violation", dead, cause)
			}
			if cause, dead := e9Death(p.s, 1); dead {
				t.Fatalf("the EARLY carrier died: %v", cause)
			}
			if eb, st := e9Early(p.s); eb != uint64(len(want)) || st != session.StatePending {
				t.Fatalf("EarlyBytes %d state %v, want %d and pending", eb, st, len(want))
			}
			c, _ := e9Confirm(t, p, d)
			if got := e9ReadAll(t, c, len(want)); !bytes.Equal(got, want) {
				t.Fatal("bytes differ")
			}
			d.close()
			rt.Close()
		})
	})
}

// TestEarlyJoinBeforeVerdictRefused: a JOIN for a pending session is
// BAD_REQUEST (P9), so its carrier never becomes a lane and the early DATA
// that follows it never reaches the session (M4-D5: DATA on a JOIN carrier
// is not early data); the pending session keeps its early bytes and opens.
// The session-level rule for a JOIN lane is TestEarlyOnJoinCarrierKills
// (internal/session).
func TestEarlyJoinBeforeVerdictRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		want := e9Pattern(0, 2000)
		d := e9Opened(t, rt, ln, 1, wpSID(1), wire.OpenFlagEarly)
		d.sendData(0, want)
		p := e9Accept(t, ln)
		j := wpConnect(t, ln, e9Inst, 2)
		j.hello(rt)
		j.send(wire.TypeJoin, 0, wpJoin(wpSID(1), 1, 0))
		late := j.sendAsync(wire.TypeData, 0, e9Data(0, bytes.Repeat([]byte{0xEE}, 2000)))
		j.expectJoinAck(wire.StatusBadRequest)
		if err := <-late; err != nil {
			t.Fatalf("the JOIN carrier's DATA was not read: %v", err)
		}
		j.expectEOF()
		synctest.Wait()
		if eb, st := e9Early(p.s); eb != uint64(len(want)) || st != session.StatePending {
			t.Fatalf("EarlyBytes %d state %v, want %d and pending", eb, st, len(want))
		}
		c, _ := e9Confirm(t, p, d)
		if got := e9ReadAll(t, c, len(want)); !bytes.Equal(got, want) {
			t.Fatal("bytes differ: the JOIN carrier's DATA reached the session")
		}
		d.close()
		rt.Close()
	})
}

// The passive's early data, continued (WP9b): the window at Confirm, the
// memory bound, refusals and duplicate copies.

// TestEarlyOpenAckWindowCoversEarly_L15: under memory pressure (the Budget
// full: the normal window is 0) an EARLY session's OPEN_ACK(OK) still
// advertises at least wire.EarlyWindow (M4-D6), so the dialer's limit
// covers the early bytes it may already have sent — also when they are
// still in flight at Confirm and arrive after it. A session without EARLY
// gets the shrunken window (the premise).
func TestEarlyOpenAckWindowCoversEarly_L15(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		full := rt.budget.Max() - rt.budget.Used()
		rt.budget.Acquire(full) // memory pressure: AdvertiseWindow gives 0
		want := e9Pattern(0, wire.EarlyWindow)

		// Premise: without EARLY the window is below the early span.
		d0 := e9Opened(t, rt, ln, 1, wpSID(1), 0)
		p0 := e9Accept(t, ln)
		if _, win := e9Confirm(t, p0, d0); win >= wire.EarlyWindow {
			t.Fatalf("premise: a non-EARLY OPEN_ACK window under pressure is %d, want < %d", win, wire.EarlyWindow)
		}

		// The early bytes arrived before Confirm.
		d1 := e9Opened(t, rt, ln, 2, wpSID(2), wire.OpenFlagEarly)
		d1.sendData(0, want[:1000])
		p1 := e9Accept(t, ln)
		c1, win := e9Confirm(t, p1, d1)
		if win < wire.EarlyWindow {
			t.Fatalf("EARLY with data held: OPEN_ACK window %d, want ≥ %d", win, wire.EarlyWindow)
		}
		if got := e9ReadAll(t, c1, 1000); !bytes.Equal(got, want[:1000]) {
			t.Fatal("bytes differ")
		}

		// The early bytes are still in flight at Confirm: they arrive
		// after it, and the window must cover all of them.
		d2 := e9Opened(t, rt, ln, 3, wpSID(3), wire.OpenFlagEarly)
		p2 := e9Accept(t, ln)
		c2, win := e9Confirm(t, p2, d2)
		if win < wire.EarlyWindow {
			t.Fatalf("EARLY with data in flight: OPEN_ACK window %d, want ≥ %d", win, wire.EarlyWindow)
		}
		d2.sendData(0, want[:wire.EarlyWindow/2])
		d2.sendData(wire.EarlyWindow/2, want[wire.EarlyWindow/2:])
		if got := e9ReadAll(t, c2, wire.EarlyWindow); !bytes.Equal(got, want) {
			t.Fatal("bytes differ")
		}
		synctest.Wait()
		if cause, dead := e9Death(p2.s, 3); dead {
			t.Fatalf("carrier 3 died: %v", cause)
		}
		rt.budget.Release(full)
		for _, d := range []*wpDialer{d0, d1, d2} {
			d.close()
		}
		rt.Close()
	})
}

// e9Charge is the receive charge of one 64 KiB early DATA frame: rendr's
// dialer sends its early span as one frame, which the reader keeps by
// reference in a buffer of the 64 KiB size class (payload + LookAhead fits
// the class slack).
const e9Charge = wire.EarlyWindow + carrier.ClassSlack

// TestEarlyPendingMemoryBounded_L48: a Listener's pending sessions hold at
// most AcceptBacklog × EarlyWindow early bytes (L48): 128 pending EARLY
// sessions with a full early window each fill the backlog and charge the
// Runtime budget at most 128 × (64 KiB + the class slack); the 129th OPEN
// gets CAPACITY(CodeBacklog) and leaves nothing behind; after
// AcceptTimeout every session answers CAPACITY(CodeAcceptTimeout) and
// BufferedBytes is back at its baseline (0). Every dialer writes its first
// flight in one Write and reads only afterwards, as rendr's dialer writes
// PREFACE ‖ OPEN(EARLY) ‖ DATA without DialEarly; the "16 KiB" variant
// (R1-5) runs over links that buffer 16 KiB per direction, less than one
// first flight: every dialer still gets its typed answer, never a
// transport error. (A synchronous conn is WP8's TestEstablishEarlySyncConn,
// M4-D58.)
func TestEarlyPendingMemoryBounded_L48(t *testing.T) {
	const backlog = 128
	for _, v := range []struct {
		name string
		buf  int // the link's buffer per direction (0: rendrtest's 2 MiB)
	}{{"link", 0}, {"link 16 KiB", 16 << 10}} {
		t.Run(v.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				const accept = 2 * time.Second
				ln := wpListen(t, rt, ListenConfig{AcceptBacklog: backlog, AcceptTimeout: accept})
				link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "early", Accept: ln.Handle, Buffer: v.buf})
				defer link.Close()
				early := e9Pattern(0, wire.EarlyWindow)
				start := time.Now()
				ds := make([]*wpDialer, backlog)
				for i := range ds {
					ds[i] = e9FirstFlight(t, link, uint32(i+1), wpSID(i), early)
				}
				synctest.Wait()
				st := rt.Status()
				if st.Sessions.Pending != backlog || st.AcceptBacklog[0] != backlog {
					t.Fatalf("pending %d backlog %d, want %d", st.Sessions.Pending, st.AcceptBacklog[0], backlog)
				}
				if u := rt.budget.Used(); u < backlog*wire.EarlyWindow || u > backlog*e9Charge {
					t.Fatalf("pending early charge %d, want within [%d, %d]", u, backlog*wire.EarlyWindow, backlog*e9Charge)
				}
				charged, buffered := rt.budget.Used(), st.BufferedBytes

				// The 129th: CAPACITY(CodeBacklog), typed, and nothing kept.
				x := e9FirstFlight(t, link, backlog+1, wpSID(backlog), early)
				x.expectOpenAck(wire.StatusCapacity, wire.CodeBacklog)
				x.drain()
				synctest.Wait()
				if u, b := rt.budget.Used(), rt.Status().BufferedBytes; u != charged || b != buffered {
					t.Fatalf("after the refusal: charge %d buffered %d, want %d and %d", u, b, charged, buffered)
				}

				// AcceptTimeout discards every held byte.
				time.Sleep(time.Until(start.Add(accept)))
				for _, d := range ds {
					d.expectOpenAck(wire.StatusCapacity, wire.CodeAcceptTimeout)
					d.drain()
				}
				synctest.Wait()
				wpNoState(t, rt)
				rt.Close()
			})
		})
	}
}

// e9FirstFlight dials link and writes PREFACE ‖ OPEN(EARLY) ‖ DATA(0,
// early) in one Write, then reads PREFACE_ACK(OK), as rendr's dialer does
// without DialEarly.
func e9FirstFlight(t testing.TB, link *rendrtest.Link, id uint32, sid [16]byte, early []byte) *wpDialer {
	t.Helper()
	nc, err := link.Dial(context.Background())
	if err != nil {
		t.Fatalf("link dial: %v", err)
	}
	t.Cleanup(func() { nc.Close() })
	d := &wpDialer{t: t, nc: nc, inst: e9Inst, id: id}
	pre := wpPreface(e9Inst, id)
	d.txFseq = wire.PrefaceFseq(pre)
	flight := append(pre, d.frame(wire.TypeOpen, 0, e9Open(sid, 1, wire.OpenFlagEarly))...)
	flight = append(flight, d.frame(wire.TypeData, 0, e9Data(0, early))...)
	if _, err := nc.Write(flight); err != nil {
		t.Fatalf("first flight of carrier %d: %v", id, err)
	}
	var b [wire.PrefaceLen]byte
	if _, err := io.ReadFull(nc, b[:]); err != nil {
		t.Fatalf("PREFACE_ACK of carrier %d: %v", id, err)
	}
	if a, err := wire.ParsePrefaceAck(b[:]); err != nil || a.Status != wire.PrefaceOK {
		t.Fatalf("PREFACE_ACK of carrier %d: %+v %v", id, a, err)
	}
	d.rxFseq = wire.PrefaceFseq(b[:])
	return d
}

// TestEarlyAcceptTimeoutDiscards: a pending EARLY session that nobody
// accepts answers CAPACITY(CodeAcceptTimeout) at AcceptTimeout and
// releases its early bytes with its receive state (M4-D8): the budget and
// BufferedBytes return to 0, the backlog is empty and a later Accept finds
// nothing.
func TestEarlyAcceptTimeoutDiscards(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{AcceptTimeout: time.Second})
		start := time.Now()
		d := e9Opened(t, rt, ln, 1, wpSID(1), wire.OpenFlagEarly)
		d.sendData(0, e9Pattern(0, 48<<10))
		synctest.Wait()
		if u := rt.budget.Used(); u < 48<<10 {
			t.Fatalf("premise: early charge %d, want ≥ %d", u, 48<<10)
		}
		d.expectOpenAck(wire.StatusCapacity, wire.CodeAcceptTimeout)
		if el := time.Since(start); el < time.Second || el > time.Second+10*time.Millisecond {
			t.Fatalf("answered after %v, want the 1 s AcceptTimeout", el)
		}
		d.drain()
		synctest.Wait()
		wpNoState(t, rt)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if p, err := ln.Accept(ctx); err == nil {
			t.Fatalf("Accept returned the timed-out session %v", p.ID())
		}
		rt.Close()
	})
}

// TestEarlyAfterVerdictDiscarded: early DATA that the dialer sent before it
// read the refusal arrives after the verdict and is discarded by the ended
// session — not a violation (M4-D8): the carrier still gets the refusal
// and retires with CLOSE (a killed carrier would end without it), and
// nothing stays charged.
func TestEarlyAfterVerdictDiscarded(t *testing.T) {
	for _, v := range []struct {
		name   string
		refuse func(p *PendingConn) error
		st     wire.AckStatus
		code   uint32
	}{
		{"reject", func(p *PendingConn) error { return p.Reject(7, "no") }, wire.StatusRejected, 7},
		{"accept timeout", func(p *PendingConn) error { time.Sleep(time.Second); return nil }, wire.StatusCapacity, wire.CodeAcceptTimeout},
	} {
		t.Run(v.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				ln := wpListen(t, rt, ListenConfig{AcceptTimeout: time.Second})
				d := e9Opened(t, rt, ln, 1, wpSID(1), wire.OpenFlagEarly)
				d.sendData(0, e9Pattern(0, 1000))
				p := e9Accept(t, ln)
				if err := v.refuse(p); err != nil {
					t.Fatalf("refusal: %v", err)
				}
				synctest.Wait()
				if _, st := e9Early(p.s); st != session.StateEnded {
					t.Fatalf("state %v, want ended", st)
				}
				late := d.sendAsync(wire.TypeData, 0, e9Data(1000, e9Pattern(1000, 30000)))
				d.expectOpenAck(v.st, v.code)
				if err := <-late; err != nil {
					t.Fatalf("the late DATA was not read: %v", err)
				}
				if seen := d.drain(); len(seen) != 1 || seen[0] != wire.TypeClose {
					t.Fatalf("after the answer: %v, want one CLOSE (a retirement, not a kill)", seen)
				}
				synctest.Wait()
				if cause, _ := e9Death(p.s, 1); cause == carrier.CauseProtocolViolation {
					t.Fatal("the late early DATA was taken as a violation")
				}
				wpNoState(t, rt)
				rt.Close()
			})
		})
	}
}

// TestEarlyWithdrawAfterFirstFlight_L49: the dialer's withdrawal RST
// follows its whole first flight, at the fseq after the DATA frame (R1-4):
// the pending session processes it as a withdrawal — no carrier is killed
// as a violation — ends, releases its early bytes, and a later Confirm
// returns ErrSessionLost.
func TestEarlyWithdrawAfterFirstFlight_L49(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		d := e9Opened(t, rt, ln, 1, wpSID(1), wire.OpenFlagEarly)
		d.sendData(0, e9Pattern(0, 20000))
		p := e9Accept(t, ln)
		d.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), "withdrawn"))
		synctest.Wait()
		if _, st := e9Early(p.s); st != session.StateEnded {
			t.Fatalf("state %v, want ended (withdrawn)", st)
		}
		if cause, _ := e9Death(p.s, 1); cause == carrier.CauseProtocolViolation {
			t.Fatal("the withdrawal RST after the early DATA was taken as a violation")
		}
		if _, err := p.Confirm(); !errors.Is(err, ErrSessionLost) {
			t.Fatalf("Confirm after the withdrawal: %v, want ErrSessionLost", err)
		}
		d.close()
		synctest.Wait()
		wpNoState(t, rt)
		rt.Close()
	})
}

// TestEarlyDuplicateCopiesOnce_L47: the dialer's attempts all carry the
// session's one early span (R1-2), so a pending session may receive it on
// several carriers: the copies are deduplicated by offset (counted in
// DupBytes, not in EarlyBytes) and delivered once; a copy that differs
// from the held bytes kills only its carrier (L13).
func TestEarlyDuplicateCopiesOnce_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		want := e9Pattern(0, 40000)
		d1 := e9Opened(t, rt, ln, 1, wpSID(1), wire.OpenFlagEarly)
		d1.sendData(0, want)
		p := e9Accept(t, ln)
		d2 := e9Opened(t, rt, ln, 2, wpSID(1), wire.OpenFlagEarly)
		d2.sendData(0, want)
		d3 := e9Opened(t, rt, ln, 3, wpSID(1), wire.OpenFlagEarly)
		bad := bytes.Clone(want[:100])
		bad[50] ^= 0xFF
		d3.sendData(0, bad)
		d3.expectKilled()
		synctest.Wait()
		if cause, dead := e9Death(p.s, 3); !dead || cause != carrier.CauseProtocolViolation {
			t.Fatalf("conflicting copy: carrier 3 dead %v cause %v, want protocol_violation", dead, cause)
		}
		if st := p.s.Status(); st.EarlyBytes != uint64(len(want)) || st.DupBytes != uint64(len(want)) {
			t.Fatalf("EarlyBytes %d DupBytes %d, want %d each", st.EarlyBytes, st.DupBytes, len(want))
		}
		c, err := p.Confirm()
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		d1.expectOpenAck(wire.StatusOK, 0)
		d2.expectOpenAck(wire.StatusOK, 0)
		if got := e9ReadAll(t, c, len(want)); !bytes.Equal(got, want) {
			t.Fatal("bytes differ")
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("a byte beyond the span: (%d, %v), want a deadline (each byte once)", n, err)
		}
		d1.close()
		d2.close()
		rt.Close()
	})
}

// esaHeld delays the bytes of its first Write after the PREFACE until the
// PREFACE_ACK was read through it, and runs onAck then: a dialer whose
// OPEN reaches the passive only after something changed between the
// passive's gate and its admission (Runtime.Close's first step).
type esaHeld struct {
	net.Conn
	once  sync.Once
	acked chan struct{}
	onAck func()
	read  int
}

func (c *esaHeld) Write(p []byte) (int, error) {
	first := false
	c.once.Do(func() { first = true })
	if !first || len(p) <= wire.PrefaceLen {
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p[:wire.PrefaceLen])
	if err != nil {
		return n, err
	}
	<-c.acked
	m, err := c.Conn.Write(p[wire.PrefaceLen:])
	return n + m, err
}

func (c *esaHeld) Read(p []byte) (int, error) {
	if c.read < wire.PrefaceLen && len(p) > wire.PrefaceLen-c.read {
		p = p[:wire.PrefaceLen-c.read]
	}
	n, err := c.Conn.Read(p)
	c.read += n
	if c.read == wire.PrefaceLen && n > 0 {
		c.onAck()
		close(c.acked)
	}
	return n, err
}

// TestEstablishEarlySyncConnAdmission (R1-5, M4-D58; the admission half of
// TestEstablishEarlySyncConn): a dialer's first flight with 64 KiB of
// early data over a raw net.Pipe to a real Runtime's Listener, whose
// admission refuses it before any session reader exists — a full backlog
// (CAPACITY CodeBacklog → ErrCapacity), MaxSessions (CAPACITY
// CodeMaxSessions → ErrCapacity), oversized metadata (BAD_REQUEST
// CodeMetadataSize → ErrMetadataTooLarge) and a Runtime whose Close began
// between the gate and the admission (GOING_AWAY → ErrCapacity): the
// dialer reads the typed OPEN_ACK at once, never a "preface" transport
// failure at the handshake deadline, because the refusal's closer drains
// the flight while it writes the answer (Hooks.Drained reports it), and no
// state is left.
func TestEstablishEarlySyncConnAdmission(t *testing.T) {
	early := bytes.Repeat([]byte{0x5a}, wire.EarlyWindow)
	dataLen := wire.FrameOverhead + wire.DataPrefixLen + len(early)
	const bigMeta = 1000
	for _, tc := range []struct {
		name    string
		cfg     Config
		lcfg    ListenConfig
		meta    int
		closing bool
		setup   func(t *testing.T, rt *Runtime, ln *Listener) (cleanup func())
		status  wire.AckStatus
		code    uint32
		drained int
	}{
		{name: "backlog full", lcfg: ListenConfig{AcceptBacklog: 1},
			setup: func(t *testing.T, rt *Runtime, ln *Listener) func() {
				if ln.reserve(kindIdxStream) != reserveOK { // the one slot: an admission in progress
					t.Fatal("reserve")
				}
				return func() { ln.unreserve(kindIdxStream) }
			}, status: wire.StatusCapacity, code: wire.CodeBacklog, drained: dataLen},
		{name: "MaxSessions", cfg: Config{MaxSessions: 1},
			setup: func(t *testing.T, rt *Runtime, ln *Listener) func() {
				if !rt.table.placeDialer(SessionID(wpSID(99))) { // the one unit
					t.Fatal("placeDialer")
				}
				return func() { rt.table.ended(dialerKey(SessionID(wpSID(99))), nil, session.Verdict{}, time.Now()) }
			}, status: wire.StatusCapacity, code: wire.CodeMaxSessions, drained: dataLen},
		{name: "oversized metadata", cfg: Config{Handshake: HandshakeLimits{MaxMetadata: 64}}, meta: bigMeta,
			status: wire.StatusBadRequest, code: wire.CodeMetadataSize, drained: wire.OpenFixedLen + bigMeta + wire.TrailerLen + dataLen},
		{name: "GOING_AWAY", closing: true, status: wire.StatusGoingAway, drained: dataLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var dmu sync.Mutex
				var drained []int
				ov := &testhooks.Overrides{Hooks: &testhooks.Hooks{Drained: func(n int) {
					dmu.Lock()
					drained = append(drained, n)
					dmu.Unlock()
				}}}
				rt := wpTestRuntime(t, tc.cfg, ov)
				ln := wpListen(t, rt, tc.lcfg)
				cleanup := func() {}
				if tc.setup != nil {
					cleanup = tc.setup(t, rt, ln)
				}
				a, b := net.Pipe()
				defer a.Close()
				if err := ln.Handle(b); err != nil {
					t.Fatalf("Handle: %v", err)
				}
				var dc net.Conn = a
				if tc.closing {
					dc = &esaHeld{Conn: a, acked: make(chan struct{}), onAck: func() {
						rt.closing.Store(true) // as between Close's first step and its drain of the handshakes
					}}
				}
				env := &carrier.Env{
					Local:   wpInst(0xe7),
					Timing:  carrier.Timing{DialTimeout: 10 * time.Second, AbandonWait: time.Second},
					IDs:     carrier.NewIDAllocator(0),
					Abandon: carrier.NewAbandonPool(16),
					Bufs:    carrier.NewBufPool(),
					Budget:  carrier.NewBudget(1 << 30),
				}
				f := carrier.Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return dc, nil }}
				start := time.Now()
				est, err := carrier.EstablishEarly(context.Background(), env, f, env.IDs.Next(), wire.TypeOpen,
					wpOpen(wpSID(1), wire.KindStream, 1, bytes.Repeat([]byte{'m'}, tc.meta)), early, nil)
				if took := time.Since(start); err != nil || took != 0 {
					t.Fatalf("EstablishEarly after %v of the handshake deadline: %v", took, err)
				}
				a2, perr := wire.ParseOpenAck(est.Payload)
				if est.Resp.Type != wire.TypeOpenAck || perr != nil || a2.Status != tc.status || a2.Code != tc.code || est.Early != len(early) {
					t.Fatalf("answer %v %+v (%v, Early %d), want OPEN_ACK %v code %d after the whole flight", est.Resp.Type, a2, perr, est.Early, tc.status, tc.code)
				}
				est.Conn.Kill(carrier.CauseLocalClose, "test end")
				<-est.Conn.Done()
				synctest.Wait()
				if tc.closing {
					rt.closing.Store(false)
				}
				cleanup()
				wpNoState(t, rt)
				dmu.Lock()
				got := append([]int(nil), drained...)
				dmu.Unlock()
				if len(got) != 1 || got[0] != tc.drained {
					t.Fatalf("Drained reports %v, want one report of %d bytes (the unread rest of the flight)", got, tc.drained)
				}
				if env.Abandon.Len() != 0 {
					t.Fatalf("dialer abandoned %d", env.Abandon.Len())
				}
				rt.Close()
			})
		})
	}
}
