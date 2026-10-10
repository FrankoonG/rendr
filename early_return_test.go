package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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
// an EarlyReturn Dial returns at once. Health.Use still runs (the probes
// start without any session byte on the links), and the session then
// opens with its first Write.
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
				t.Fatal("no probe carrier was dialled: Health.Use did not run")
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
// withdraws, so the passive's Confirm fails and nothing is left on either
// side.
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
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
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
