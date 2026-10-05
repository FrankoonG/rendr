package rendr

import (
	"context"
	"errors"
	"maps"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// g9Frame is one frame read from a scripted dialer, or the read's error.
type g9Frame struct {
	f   wire.Frame
	err error
}

// g9Answer reads the first frame the passive writes on d, on a goroutine
// of its own: a carrier parked at a pending session is answered only with
// that session's verdict.
func g9Answer(d *wpDialer) <-chan g9Frame {
	ch := make(chan g9Frame, 1)
	go func() {
		f, err := d.recv()
		ch <- g9Frame{f, err}
	}()
	return ch
}

// g9OpenAck parses the OPEN_ACK of r, failing the test on anything else.
func g9OpenAck(t testing.TB, r g9Frame) wire.OpenAck {
	t.Helper()
	if r.err != nil {
		t.Fatalf("no OPEN_ACK: %v", r.err)
	}
	if r.f.Type != wire.TypeOpenAck {
		t.Fatalf("got %v, want OPEN_ACK", r.f.Type)
	}
	a, err := wire.ParseOpenAck(r.f.Payload)
	if err != nil {
		t.Fatalf("OPEN_ACK: %v", err)
	}
	return a
}

// g9WaitFor advances virtual time in 10 ms steps until cond holds and
// fails the test after within.
func g9WaitFor(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(within); !cond(); time.Sleep(10 * time.Millisecond) {
		if !time.Now().Before(end) {
			t.Fatalf("not reached within %v: %s", within, what)
		}
	}
}

// g9Opens counts the carriers of l whose first frame was an OPEN.
func g9Opens(l *rendrtest.Link) int {
	n := 0
	for _, c := range l.Carriers() {
		if c.First == rendrtest.FrameOpen {
			n++
		}
	}
	return n
}

// g9States maps the carriers listed in st, dead ones included, to their
// states.
func g9States(st SessionStatus) map[CarrierID]CarrierState {
	m := make(map[CarrierID]CarrierState, len(st.Carriers))
	for _, c := range st.Carriers {
		m[c.ID] = c.State
	}
	return m
}

// TestRepeatedOpenBeforeCapacity_L47_L48: a repeated OPEN of a session
// that exists is routed to that session before the admission's MaxSessions
// and backlog checks (design §6.2, plan §3.5, §5; L47: an OPEN is
// idempotent; L48), so it is never answered CAPACITY for a full backlog or
// for reached MaxSessions — conditions that a new session's OPEN is refused
// for at the same moment (the stimulus). (The session's own verdict still
// applies: at its MaxCarriersPerSession it answers CAPACITY(CodeCarriers),
// which these cases do not reach.) A repeated OPEN of a pending session is
// parked: it gets no answer until the application's verdict, then
// OPEN_ACK(OK) together with the first carrier; one session is accepted.
// A repeated OPEN of an open session is adopted at once with OPEN_ACK(OK).
// Either way the session then holds both carriers attached — the first
// OPEN carrier active, the repeated one a live non-active member (selector)
// — and the repeated OPEN took no backlog slot and no MaxSessions unit.
// The last case is a real Dial over two factories whose second candidate
// OPENs one JoinStagger after the first while the session is still pending
// and holds the passive's only backlog slot and only MaxSessions unit: the
// Dial succeeds with both OPEN carriers as bond members on each end, and
// data crosses.
func TestRepeatedOpenBeforeCapacity_L47_L48(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		lc   ListenConfig
		code uint32 // the CAPACITY code a new session's OPEN gets meanwhile
		open bool   // the session is confirmed before its OPEN is repeated
	}{
		{"pending, backlog full", Config{}, ListenConfig{AcceptBacklog: 1}, wire.CodeBacklog, false},
		{"pending, MaxSessions reached", Config{MaxSessions: 1}, ListenConfig{}, wire.CodeMaxSessions, false},
		{"open, backlog full", Config{}, ListenConfig{AcceptBacklog: 1}, wire.CodeBacklog, true},
		{"open, MaxSessions reached", Config{MaxSessions: 1}, ListenConfig{}, wire.CodeMaxSessions, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, tc.cfg, nil)
				ln := wpListen(t, rt, tc.lc)
				inst, sid := wpInst(0xb1), wpSID(10)
				id := uint32(1)
				open := func(s [16]byte) *wpDialer {
					d := wpConnect(t, ln, inst, id)
					id++
					d.hello(rt)
					d.send(wire.TypeOpen, 0, wpOpen(s, wire.KindStream, 1, []byte("b10")))
					return d
				}
				accept := func() *PendingConn {
					t.Helper()
					pc, err := ln.Accept(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					return pc
				}
				// state requires the admission counters: pending and open
				// sessions, backlog slots and MaxSessions units.
				state := func(when string, pending, open, units int) {
					t.Helper()
					st := rt.Status()
					if st.Sessions.Pending != pending || st.Sessions.Open != open || st.AcceptBacklog[0] != pending || rt.table.inUse() != units || st.Handshakes != 0 {
						t.Fatalf("%s: %+v (MaxSessions units %d), want %d pending, %d open, %d units", when, st, rt.table.inUse(), pending, open, units)
					}
				}

				first := open(sid)
				var sc *Conn
				var other *wpDialer // a second session holding the only backlog slot
				pending, live := 1, 0
				if tc.open {
					pc := accept()
					c, err := pc.Confirm()
					if err != nil {
						t.Fatal(err)
					}
					sc = c
					first.expectOpenAck(wire.StatusOK, 0)
					pending, live = 0, 1
					if tc.lc.AcceptBacklog == 1 {
						other = open(wpSID(11))
						pending = 1
					}
				}
				synctest.Wait()
				state("before the repeated OPEN", pending, live, pending+live)

				// Stimulus: the capacity condition holds — a new session's OPEN
				// is refused for it now. (Closing our end at once ends the
				// refusal's drain: no virtual time passes while the raw
				// carriers of the session are not read.)
				fresh := open(wpSID(12))
				fresh.expectOpenAck(wire.StatusCapacity, tc.code)
				fresh.close()

				second := open(sid)
				ans := g9Answer(second)
				synctest.Wait()
				if tc.open {
					if a := g9OpenAck(t, <-ans); a.Status != wire.StatusOK || a.Window == 0 {
						t.Fatalf("repeated OPEN of an open session: OPEN_ACK status %d code %d (%q), want OK with a window", a.Status, a.Code, a.Msg)
					}
				} else {
					select {
					case r := <-ans:
						a := g9OpenAck(t, r)
						t.Fatalf("repeated OPEN of a pending session answered before the verdict: status %d code %d (%q)", a.Status, a.Code, a.Msg)
					default: // parked until the verdict
					}
					state("repeated OPEN parked", pending, live, pending+live)
					pc := accept()
					if pc.ID() != SessionID(sid) {
						t.Fatalf("accepted %v, want %v", pc.ID(), SessionID(sid))
					}
					if cs := sessionStatusFrom(pc.s.Status()).Carriers; len(cs) != 2 || cs[0].State != CarrierJoining || cs[1].State != CarrierJoining {
						t.Fatalf("the pending session holds %+v, want both OPEN carriers parked (joining)", cs)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
					if extra, err := ln.Accept(ctx); extra != nil || !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("a second Accept: %v, %v; want no second session", extra, err)
					}
					cancel()
					c, err := pc.Confirm()
					if err != nil {
						t.Fatal(err)
					}
					sc = c
					first.expectOpenAck(wire.StatusOK, 0)
					if a := g9OpenAck(t, <-ans); a.Status != wire.StatusOK || a.Window == 0 {
						t.Fatalf("parked OPEN after Confirm: OPEN_ACK status %d code %d (%q), want OK with a window", a.Status, a.Code, a.Msg)
					}
					pending, live = 0, 1
				}
				synctest.Wait()
				want := map[CarrierID]CarrierState{CarrierID(first.id): CarrierActive, CarrierID(second.id): CarrierMember}
				if st := sc.Status(); !maps.Equal(g9States(st), want) {
					t.Fatalf("the session holds %+v, want both OPEN carriers attached: %v", st.Carriers, want)
				}
				if other != nil {
					pending = 1 // the other session is still waiting for its verdict
				}
				state("after the repeated OPEN", pending, live, pending+live)

				for _, d := range []*wpDialer{first, second, other} {
					if d != nil {
						d.close()
					}
				}
				rt.Close()
				wpNoState(t, rt)
			})
		})
	}

	t.Run("Dial over two factories", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{MaxSessions: 1}, nil, ListenConfig{AcceptBacklog: 1}, "a", "b")
			for _, l := range e.links {
				l.SetDelay(time.Millisecond, 0) // probes need an RTT above zero (WaitFirst)
			}
			res := e2eDialAsync(context.Background(), e.peer(), DialOptions{Mode: ModeBond})
			pc, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// The second candidate OPENs one JoinStagger after the first,
			// while the session is pending: it holds the passive's only
			// backlog slot and only MaxSessions unit. Its OPEN is parked at
			// the pending session (a joining carrier) once it crossed the
			// link (1 ms) and was admitted.
			g9WaitFor(t, 5*time.Second, "the second candidate's OPEN parked at the pending session", func() bool {
				select {
				case r := <-res:
					t.Fatalf("Dial returned before Confirm: %v", r.err)
				default:
				}
				return len(sessionStatusFrom(pc.s.Status()).Carriers) == 2
			})
			if n := g9Opens(e.links[0]) + g9Opens(e.links[1]); n != 2 {
				t.Fatalf("stimulus: %d OPEN carriers, want one per factory", n)
			}
			time.Sleep(50 * time.Millisecond) // an answer to the parked OPEN would reach the dialer meanwhile
			select {
			case r := <-res:
				t.Fatalf("Dial returned before Confirm: %v", r.err)
			default:
			}
			if cs := sessionStatusFrom(pc.s.Status()).Carriers; len(cs) != 2 || cs[0].State != CarrierJoining || cs[1].State != CarrierJoining {
				t.Fatalf("the pending session holds %+v, want both OPEN carriers parked (joining)", cs)
			}
			if st := e.p.Status(); st.Sessions.Pending != 1 || st.AcceptBacklog[0] != 1 || e.p.table.inUse() != 1 {
				t.Fatalf("while both OPENs wait for the verdict: %+v (MaxSessions units %d)", st, e.p.table.inUse())
			}
			sc, err := pc.Confirm()
			if err != nil {
				t.Fatal(err)
			}
			r := <-res
			if r.err != nil {
				t.Fatalf("Dial: %v", r.err)
			}
			dc := r.c
			time.Sleep(100 * time.Millisecond) // the second member's OPEN_ACK(OK) arrives
			// Both ends list the same two carriers, one per factory, both bond
			// members: neither is left joining.
			dst, pst := dc.Status(), sc.Status()
			if cs := dst.Carriers; len(cs) != 2 || cs[0].ID == cs[1].ID || cs[0].Name == cs[1].Name {
				t.Fatalf("dialer carriers %+v, want one per factory", cs)
			}
			want := map[CarrierID]CarrierState{dst.Carriers[0].ID: CarrierMember, dst.Carriers[1].ID: CarrierMember}
			for _, st := range []SessionStatus{dst, pst} {
				if !maps.Equal(g9States(st), want) {
					t.Fatalf("%v holds %+v, want both OPEN carriers as bond members: %v", st.Role, st.Carriers, want)
				}
			}
			e2eExchange(t, dc, sc, 1<<20, 10)
			// The members are the two OPEN carriers themselves: no factory
			// dialled a session carrier again.
			for _, l := range e.links {
				var session []rendrtest.CarrierInfo
				for _, c := range l.Carriers() {
					if c.Session {
						session = append(session, c)
					}
				}
				if len(session) != 1 || session[0].First != rendrtest.FrameOpen || session[0].Closed || session[0].Down == 0 {
					t.Fatalf("link %s session carriers %+v, want its one OPEN carrier, alive and answered", l.Name(), session)
				}
			}
			e2eFinish(t, dc, sc)
			e.close()
		})
	})
}
