package rendr

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPassivePrefaceAnswers_L44_L48: the Runtime's passive handshake
// answers a PREFACE from its validation alone and allocates nothing for a
// refused one (design §5.1, §6.1; L44: incompatible versions are answered
// before any state; L48: malformed hellos reserve nothing). A foreign or
// corrupt PREFACE (v1 or msess handshake, bad CRC, wrong role or kind, zero
// instance) is closed silently; another major gets PREFACE_ACK(VERSION) and
// an unknown required bit PREFACE_ACK(FEATURE), each followed by EOF; a
// valid PREFACE gets GOING_AWAY while the Runtime closes, CAPACITY while the
// abandoned-call pool is full (D20), else OK. Every answer echoes the
// carrier ID and names this Runtime's instance, and the slot is released.
func TestPassivePrefaceAnswers_L44_L48(t *testing.T) {
	inst := wpInst(0xd1)
	good := wpPreface(inst, 5)
	edit := func(f func(b []byte)) []byte {
		b := bytes.Clone(good)
		f(b)
		return wpRecrc(b)
	}
	cases := []struct {
		name    string
		preface []byte
		setup   func(rt *Runtime) (undo func())
		answer  int // -1: silent close; else the PREFACE_ACK status
	}{
		{"v1 magic", edit(func(b []byte) { copy(b, "RND1") }), nil, -1},
		{"msess hello", []byte("MSES\x01\x00 hello from msess, not a rendr preface!"), nil, -1},
		{"corrupt CRC", func() []byte { b := bytes.Clone(good); b[39] ^= 1; return b }(), nil, -1},
		{"major 1", edit(func(b []byte) { b[4] = 1 }), nil, int(wire.PrefaceVersion)},
		{"major 3 with other fields", edit(func(b []byte) { b[4] = 3; b[6] = 9; b[20] = 7 }), nil, int(wire.PrefaceVersion)},
		{"passive role", edit(func(b []byte) { b[7] = byte(wire.RolePassive) }), nil, -1},
		{"datagram kind on a stream conn", edit(func(b []byte) { b[6] = byte(wire.KindDatagram) }), nil, -1},
		{"zero instance", edit(func(b []byte) { clear(b[16:32]) }), nil, -1},
		{"unknown required bit", edit(func(b []byte) { b[11] = 0x10 }), nil, int(wire.PrefaceFeature)},
		{"unknown optional bit", edit(func(b []byte) { b[15] = 0x10 }), nil, int(wire.PrefaceOK)},
		{"Runtime closing", good, func(rt *Runtime) func() {
			rt.closing.Store(true)
			return func() { rt.closing.Store(false) }
		}, int(wire.PrefaceGoingAway)},
		{"abandoned-call pool full", good, func(rt *Runtime) func() {
			rt.abandon.Adopt()
			return rt.abandon.Leave
		}, int(wire.PrefaceCapacity)},
		{"valid", good, nil, int(wire.PrefaceOK)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonLimit: 1})
				ln := wpListen(t, rt, ListenConfig{})
				undo := func() {}
				if tc.setup != nil {
					undo = tc.setup(rt)
				}
				d := wpConnect(t, ln, inst, 5)
				ack, ok, n := d.sendPreface(tc.preface)
				switch {
				case tc.answer < 0:
					if ok || n != 0 {
						t.Fatalf("silent close answered %d bytes (%+v)", n, ack)
					}
				case !ok:
					t.Fatalf("no PREFACE_ACK, want status %d", tc.answer)
				case int(ack.Status) != tc.answer || ack.Instance != rt.InstanceID() || ack.CarrierID != 5:
					t.Fatalf("PREFACE_ACK %+v, want status %d from %v for carrier 5", ack, tc.answer, rt.InstanceID())
				case tc.answer != int(wire.PrefaceOK):
					d.expectEOF()
				}
				if tc.answer == int(wire.PrefaceOK) {
					if rt.Status().Handshakes != 1 {
						t.Fatal("an accepted PREFACE released its slot before the first frame")
					}
					d.close() // the first frame never comes: the handshake fails and closes
				}
				synctest.Wait()
				undo()
				wpNoState(t, rt)
				if st := rt.Status(); st.Abandoned != 0 || st.HandshakeEvictions != 0 {
					t.Fatalf("status %+v", st)
				}
				d.close()
				rt.Close()
			})
		})
	}
}

// TestOpenRefusedBeforeState_L44_L48: a malformed or unsupported OPEN is
// answered OPEN_ACK(BAD_REQUEST) with its reason code before any session
// state exists (design §5.3, §6.2; L48): metadata over Handshake.MaxMetadata
// is refused unread (CodeMetadataSize → ErrMetadataTooLarge at the dialer);
// an unknown kind or the datagram kind (M2) is CodeBadKind; mode 0 or race
// (M3) is CodeBadMode; reserved flags or PMTU, a zero session ID and an
// inconsistent metadata length are CodeBadValue. The answer is the
// carrier's first frame (first fseq, session handle) followed by EOF, and
// no MaxSessions unit, backlog slot or handshake slot remains.
func TestOpenRefusedBeforeState_L44_L48(t *testing.T) {
	sid := wpSID(1)
	cases := []struct {
		name    string
		payload []byte
		code    uint32
	}{
		{"metadata over the limit", wpOpen(sid, wire.KindStream, 1, make([]byte, 5000)), wire.CodeMetadataSize},
		{"datagram kind", wpOpen(sid, wire.KindDatagram, 1, nil), wire.CodeBadKind},
		{"unknown kind", func() []byte { b := wpOpen(sid, wire.KindStream, 1, nil); b[16] = 7; return b }(), wire.CodeBadKind},
		{"race mode", wpOpen(sid, wire.KindStream, 3, nil), wire.CodeBadMode},
		{"mode 0", wpOpen(sid, wire.KindStream, 0, nil), wire.CodeBadMode},
		{"reserved flags", func() []byte { b := wpOpen(sid, wire.KindStream, 1, nil); b[19] = 1; return b }(), wire.CodeBadValue},
		{"PMTU on a stream", func() []byte { b := wpOpen(sid, wire.KindStream, 1, nil); b[29] = 1; return b }(), wire.CodeBadValue},
		{"zero session ID", wpOpen([16]byte{}, wire.KindStream, 2, nil), wire.CodeBadValue},
		{"inconsistent metadata length", func() []byte {
			b := wpOpen(sid, wire.KindStream, 1, make([]byte, 10))
			binary.BigEndian.PutUint16(b[30:32], 20)
			return b
		}(), wire.CodeBadValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				ln := wpListen(t, rt, ListenConfig{})
				d := wpConnect(t, ln, wpInst(0xd2), 9)
				d.hello(rt)
				sent := d.sendAsync(wire.TypeOpen, 0, tc.payload)
				a := d.expectOpenAck(wire.StatusBadRequest, tc.code)
				if a.Window != 0 || len(a.Msg) != 0 {
					t.Fatalf("non-canonical refusal %+v", a)
				}
				d.expectEOF()
				<-sent
				synctest.Wait()
				wpNoState(t, rt)
				d.close()
				rt.Close()
			})
		})
	}
}

// TestOpenCapacityAndGoingAway_L48: the OPEN admission order of design
// §6.2 on the wire. A tombstone is answered before any capacity check (a
// retried OPEN gets its verdict even at MaxSessions); a closing Runtime or
// Listener answers GOING_AWAY; MaxSessions (open, pending, lingering,
// orphaned and still-dialling sessions of both roles) answers
// CAPACITY(CodeMaxSessions); a full AcceptBacklog answers
// CAPACITY(CodeBacklog) and returns the MaxSessions unit it reserved. A
// JOIN is not subject to any of these (plan §3.5): on a closed Listener it
// is still routed (UNKNOWN_SESSION for an unknown session).
func TestOpenCapacityAndGoingAway_L48(t *testing.T) {
	inst := wpInst(0xd3)
	t.Run("MaxSessions", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{MaxSessions: 1}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			wpTomb(t, rt, inst, wpSID(7), session.Verdict{Status: wire.StatusRejected, Code: 42, Msg: "tomb"}, time.Hour)
			if !rt.table.placeDialer(SessionID(wpSID(99))) { // the one unit: a session of this Runtime still dialling
				t.Fatal("placeDialer")
			}
			d := wpConnect(t, ln, inst, 1)
			d.hello(rt)
			d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 1, nil))
			d.expectOpenAck(wire.StatusCapacity, wire.CodeMaxSessions)
			d.expectEOF()
			// The tombstone's verdict wins over the capacity check.
			d2 := wpConnect(t, ln, inst, 2)
			d2.hello(rt)
			d2.send(wire.TypeOpen, 0, wpOpen(wpSID(7), wire.KindStream, 1, nil))
			if a := d2.expectOpenAck(wire.StatusRejected, 42); string(a.Msg) != "tomb" {
				t.Fatalf("verdict message %q", a.Msg)
			}
			d2.expectEOF()
			synctest.Wait()
			if n := rt.table.inUse(); n != 1 {
				t.Fatalf("MaxSessions units %d, want the placeholder's 1", n)
			}
			rt.table.ended(dialerKey(SessionID(wpSID(99))), nil, session.Verdict{}, time.Now())
			wpNoState(t, rt)
			rt.Close()
		})
	})
	t.Run("AcceptBacklog", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{AcceptBacklog: 1})
			if ln.reserve() != reserveOK { // the one slot: an admission in progress
				t.Fatal("reserve")
			}
			d := wpConnect(t, ln, inst, 1)
			d.hello(rt)
			d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 2, nil))
			d.expectOpenAck(wire.StatusCapacity, wire.CodeBacklog)
			d.expectEOF()
			synctest.Wait()
			if n := rt.table.inUse(); n != 0 {
				t.Fatalf("a refused OPEN kept %d MaxSessions units", n)
			}
			ln.unreserve()
			wpNoState(t, rt)
			rt.Close()
		})
	})
	t.Run("Listener closed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			d := wpConnect(t, ln, inst, 1)
			j := wpConnect(t, ln, inst, 2)
			d.hello(rt)
			j.hello(rt)
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
			d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 1, nil))
			d.expectOpenAck(wire.StatusGoingAway, 0)
			d.expectEOF()
			j.send(wire.TypeJoin, 0, wpJoin(wpSID(2), 1, 0))
			j.expectJoinAck(wire.StatusUnknownSession)
			j.expectEOF()
			synctest.Wait()
			wpNoState(t, rt)
			rt.Close()
		})
	})
	t.Run("Runtime closing", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			d := wpConnect(t, ln, inst, 1)
			d.hello(rt)
			rt.closing.Store(true) // as between Close's first step and its drain of the handshakes
			d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 1, nil))
			d.expectOpenAck(wire.StatusGoingAway, 0)
			d.expectEOF()
			synctest.Wait()
			rt.closing.Store(false)
			wpNoState(t, rt)
			rt.Close()
		})
	})
}

// TestTombstoneRejectsReplay_L47: tombstones repeat their verdict (design
// §6.5, P8, D11; L47: an OPEN is idempotent and a session never
// resurrects). For a session that never opened, a replayed OPEN gets the
// original REJECTED(code, msg), CAPACITY(code) or GOING_AWAY again — every
// time it is retried, as after a lost answer; a session that opened, and a
// pending session the dialer withdrew, answer UNKNOWN_SESSION. A JOIN to
// any tombstone is UNKNOWN_SESSION, as is a JOIN of the same session ID from
// another dialer instance (instance binding, plan §3.4). Replays create no
// state, a verdict message longer than the format allows is truncated to
// 255 bytes, and once TombstoneTTL passed the tombstones are gone.
func TestTombstoneRejectsReplay_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		inst, other := wpInst(0xe1), wpInst(0xe2)
		const ttl = time.Hour // every refusal drains ≤ 1 s (L05): the replays take virtual seconds
		long := string(bytes.Repeat([]byte{'x'}, 300))
		tombs := []struct {
			name string
			v    session.Verdict
			st   wire.AckStatus
			code uint32
			msg  string
		}{
			{"rejected", session.Verdict{Status: wire.StatusRejected, Code: 7, Msg: "no route"}, wire.StatusRejected, 7, "no route"},
			{"rejected, long message", session.Verdict{Status: wire.StatusRejected, Code: 8, Msg: long}, wire.StatusRejected, 8, long[:wire.MaxMsg]},
			{"accept timeout", session.Verdict{Status: wire.StatusCapacity, Code: wire.CodeAcceptTimeout}, wire.StatusCapacity, wire.CodeAcceptTimeout, ""},
			{"going away", session.Verdict{Status: wire.StatusGoingAway}, wire.StatusGoingAway, 0, ""},
			{"opened", session.Verdict{Opened: true}, wire.StatusUnknownSession, 0, ""},
			{"withdrawn", session.Verdict{Status: wire.StatusUnknownSession}, wire.StatusUnknownSession, 0, ""},
		}
		start := time.Now()
		for i, tb := range tombs {
			wpTomb(t, rt, inst, wpSID(i), tb.v, ttl)
		}
		if n := rt.Status().Sessions.Tombstones; n != len(tombs) {
			t.Fatalf("%d tombstones, want %d", n, len(tombs))
		}
		id := uint32(1)
		for i, tb := range tombs {
			for retry := range 2 {
				d := wpConnect(t, ln, inst, id)
				id++
				d.hello(rt)
				d.send(wire.TypeOpen, 0, wpOpen(wpSID(i), wire.KindStream, 1, []byte("meta")))
				if a := d.expectOpenAck(tb.st, tb.code); string(a.Msg) != tb.msg {
					t.Fatalf("%s (try %d): message %q, want %q", tb.name, retry, a.Msg, tb.msg)
				}
				d.expectEOF()
			}
			j := wpConnect(t, ln, inst, id)
			id++
			j.hello(rt)
			j.send(wire.TypeJoin, 0, wpJoin(wpSID(i), 1, 0))
			j.expectJoinAck(wire.StatusUnknownSession)
			j.expectEOF()
		}
		j := wpConnect(t, ln, other, id)
		id++
		j.hello(rt)
		j.send(wire.TypeJoin, 0, wpJoin(wpSID(0), 1, 0))
		j.expectJoinAck(wire.StatusUnknownSession)
		j.expectEOF()
		synctest.Wait()
		wpNoState(t, rt)
		if n := rt.Status().Sessions.Tombstones; n != len(tombs) {
			t.Fatalf("replays changed the tombstones: %d", n)
		}

		time.Sleep(ttl - time.Since(start))
		if n := rt.Status().Sessions.Tombstones; n != 0 {
			t.Fatalf("%d tombstones after TombstoneTTL", n)
		}
		j = wpConnect(t, ln, inst, id)
		j.hello(rt)
		j.send(wire.TypeJoin, 0, wpJoin(wpSID(0), 1, 0))
		j.expectJoinAck(wire.StatusUnknownSession)
		j.expectEOF()
		synctest.Wait()
		wpNoState(t, rt)
		rt.Close()
	})

	// The tombstones of real sessions, each ended by its own verdict path:
	// Reject, AcceptTimeout, Listener.Close (GOING_AWAY), an opened session
	// reset by its dialer, and a pending session the dialer withdrew. The
	// replays arrive through another Listener of the same Runtime (the
	// table is the Runtime's, L50).
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		timed := wpListen(t, rt, ListenConfig{AcceptTimeout: 200 * time.Millisecond})
		closing := wpListen(t, rt, ListenConfig{})
		inst := wpInst(0xe4)
		id := uint32(1)
		open := func(l *Listener, sid [16]byte) *wpDialer {
			d := wpConnect(t, l, inst, id)
			id++
			d.hello(rt)
			d.send(wire.TypeOpen, 0, wpOpen(sid, wire.KindStream, 1, nil))
			return d
		}
		accept := func(l *Listener) *PendingConn {
			pc, err := l.Accept(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			return pc
		}
		var wg sync.WaitGroup
		finish := func(d *wpDialer, f func()) {
			wg.Go(func() {
				f()
				d.drain()
			})
		}

		rej := open(ln, wpSID(1))
		finish(rej, func() { rej.expectOpenAck(wire.StatusRejected, 7) })
		if err := accept(ln).Reject(7, "no route"); err != nil {
			t.Fatal(err)
		}

		late := open(timed, wpSID(2))
		finish(late, func() { late.expectOpenAck(wire.StatusCapacity, wire.CodeAcceptTimeout) })

		away := open(closing, wpSID(3))
		finish(away, func() { away.expectOpenAck(wire.StatusGoingAway, 0) })
		synctest.Wait()
		closing.Close()

		reset := open(ln, wpSID(4))
		pc := accept(ln)
		finish(reset, func() {
			reset.expectOpenAck(wire.StatusOK, 0)
			reset.send(wire.TypeRst, 0, wpRst(uint32(AbortClosed), "bye"))
		})
		sc, err := pc.Confirm()
		if err != nil {
			t.Fatal(err)
		}

		gone := open(ln, wpSID(5))
		pc = accept(ln)
		gone.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), ""))
		finish(gone, func() {})
		synctest.Wait()
		if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) {
			t.Fatalf("Confirm of a withdrawn session: %v", err)
		}
		time.Sleep(time.Second) // past the AcceptTimeout of sid 2
		wg.Wait()
		synctest.Wait()
		var ae *AbortError
		if _, err := sc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortClosed || !ae.Remote {
			t.Fatalf("the reset session's Read: %v", err)
		}
		if st := rt.Status(); st.Sessions != (SessionCounts{Tombstones: 5}) || st.AcceptBacklog[0] != 0 || rt.table.inUse() != 0 {
			t.Fatalf("after the verdicts: %+v (units %d)", st, rt.table.inUse())
		}

		replays := []struct {
			sid  int
			st   wire.AckStatus
			code uint32
			msg  string
		}{
			{1, wire.StatusRejected, 7, "no route"},
			{2, wire.StatusCapacity, wire.CodeAcceptTimeout, ""},
			{3, wire.StatusGoingAway, 0, ""},
			{4, wire.StatusUnknownSession, 0, ""},
			{5, wire.StatusUnknownSession, 0, ""},
		}
		for _, r := range replays {
			for range 2 {
				d := open(timed, wpSID(r.sid))
				if a := d.expectOpenAck(r.st, r.code); string(a.Msg) != r.msg {
					t.Fatalf("sid %d: message %q, want %q", r.sid, a.Msg, r.msg)
				}
				d.expectEOF()
				d.close()
			}
			j := wpConnect(t, ln, inst, id)
			id++
			j.hello(rt)
			j.send(wire.TypeJoin, 0, wpJoin(wpSID(r.sid), 1, 0))
			j.expectJoinAck(wire.StatusUnknownSession)
			j.expectEOF()
			j.close()
		}
		synctest.Wait()
		if st := rt.Status(); st.Sessions != (SessionCounts{Tombstones: 5}) || st.AcceptBacklog[0] != 0 || rt.table.inUse() != 0 {
			t.Fatalf("the replays changed the state: %+v", st)
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestJoinRoutingAnswers_L48: the Runtime answers a JOIN only from its
// table (design §6.3): no entry or a tombstone is UNKNOWN_SESSION; a
// malformed JOIN (zero session ID, mode outside the format) is BAD_REQUEST.
// No OPEN capacity applies: a JOIN is routed at MaxSessions and with a full
// backlog (L48: JOIN priority), and it never creates state.
func TestJoinRoutingAnswers_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{MaxSessions: 1}, nil)
		ln := wpListen(t, rt, ListenConfig{AcceptBacklog: 1})
		if !rt.table.placeDialer(SessionID(wpSID(99))) || ln.reserve() != reserveOK {
			t.Fatal("filling MaxSessions and the backlog")
		}
		inst := wpInst(0xe3)
		cases := []struct {
			name    string
			payload []byte
			st      wire.AckStatus
		}{
			{"unknown session", wpJoin(wpSID(1), 1, 0), wire.StatusUnknownSession},
			{"unknown bond session", wpJoin(wpSID(2), 2, 1<<40), wire.StatusUnknownSession},
			{"zero session ID", wpJoin([16]byte{}, 1, 0), wire.StatusBadRequest},
			{"mode 0", func() []byte { b := wpJoin(wpSID(3), 1, 0); b[16] = 0; return b }(), wire.StatusBadRequest},
		}
		for i, tc := range cases {
			d := wpConnect(t, ln, inst, uint32(i+1))
			d.hello(rt)
			d.send(wire.TypeJoin, 0, tc.payload)
			d.expectJoinAck(tc.st)
			d.expectEOF()
		}
		synctest.Wait()
		if rt.table.inUse() != 1 || rt.backlog.Load() != 0 {
			t.Fatalf("JOINs changed the admission state: units %d backlog %d", rt.table.inUse(), rt.backlog.Load())
		}
		ln.unreserve()
		rt.table.ended(dialerKey(SessionID(wpSID(99))), nil, session.Verdict{}, time.Now())
		wpNoState(t, rt)
		rt.Close()
	})
}
