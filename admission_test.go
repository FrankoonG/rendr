package rendr

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
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
// an unknown kind is CodeBadKind; mode 0 or a mode above race is
// CodeBadMode;
// reserved flags (every bit but EARLY, which is legal on stream OPENs since
// M4; EARLY on a packet OPEN) or PMTU, a zero session ID, an inconsistent metadata
// length, a packet OPEN's pmtu or window out of range and a packet OPEN
// that offers a datagram budget (window ≠ 0) on a stream carrier (M2
// §A3.5) are CodeBadValue. (A well-formed packet OPEN on a stream carrier
// is admitted as a packet session since M2: TestPacketOpenOnStreamCarrier.) The answer is the carrier's first frame (first
// fseq, session handle) followed by EOF, and no MaxSessions unit, backlog
// slot or handshake slot remains.
func TestOpenRefusedBeforeState_L44_L48(t *testing.T) {
	sid := wpSID(1)
	packetOpen := func(window uint32, pmtu uint16) []byte {
		b := wpOpen(sid, wire.KindDatagram, 1, nil)
		binary.BigEndian.PutUint32(b[24:28], window)
		binary.BigEndian.PutUint16(b[28:30], pmtu)
		return b
	}
	cases := []struct {
		name    string
		payload []byte
		code    uint32
	}{
		{"metadata over the limit", wpOpen(sid, wire.KindStream, 1, make([]byte, 5000)), wire.CodeMetadataSize},
		{"packet window on a stream carrier", packetOpen(1400, 1127), wire.CodeBadValue},
		{"packet pmtu 0", packetOpen(0, 0), wire.CodeBadValue},
		{"packet window 536", packetOpen(536, 1127), wire.CodeBadValue},
		{"unknown kind", func() []byte { b := wpOpen(sid, wire.KindStream, 1, nil); b[16] = 7; return b }(), wire.CodeBadKind},
		{"mode above race", wpOpen(sid, wire.KindStream, wire.MaxMode+1, nil), wire.CodeBadMode},
		{"mode 0", wpOpen(sid, wire.KindStream, 0, nil), wire.CodeBadMode},
		{"reserved flags", func() []byte { b := wpOpen(sid, wire.KindStream, 1, nil); b[19] = 2; return b }(), wire.CodeBadValue},
		{"EARLY on a packet OPEN", func() []byte { b := packetOpen(0, 1400); b[19] = 1; return b }(), wire.CodeBadValue},
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
// retried OPEN gets its verdict even at MaxSessions); a closing Runtime
// answers GOING_AWAY, a closed Listener of a running Runtime
// CAPACITY(CodeBacklog) — never GOING_AWAY, which would make the dialer's
// Peer give up on the whole instance (D21); MaxSessions (open, pending,
// lingering, orphaned and still-dialling sessions of both roles) answers
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
			if ln.reserve(kindIdxStream) != reserveOK { // the one slot: an admission in progress
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
			ln.unreserve(kindIdxStream)
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
			d.expectOpenAck(wire.StatusCapacity, wire.CodeBacklog)
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
	// Reject, AcceptTimeout, Listener.Close (CAPACITY backlog: the Runtime
	// runs on), an opened session reset by its dialer, and a pending session
	// the dialer withdrew. The replays arrive through another Listener of
	// the same Runtime (the table is the Runtime's, L50).
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

		shut := open(closing, wpSID(3))
		finish(shut, func() { shut.expectOpenAck(wire.StatusCapacity, wire.CodeBacklog) })
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
			{3, wire.StatusCapacity, wire.CodeBacklog, ""},
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
		if !rt.table.placeDialer(SessionID(wpSID(99))) || ln.reserve(kindIdxStream) != reserveOK {
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
		if rt.table.inUse() != 1 || rt.backlog[kindIdxStream].Load() != 0 {
			t.Fatalf("JOINs changed the admission state: units %d backlog %d", rt.table.inUse(), rt.backlog[kindIdxStream].Load())
		}
		ln.unreserve(kindIdxStream)
		rt.table.ended(dialerKey(SessionID(wpSID(99))), nil, session.Verdict{}, time.Now())
		wpNoState(t, rt)
		rt.Close()
	})
}

// TestSilentHandshakesReleased_L48: the handshake deadline (accept time +
// Handshake.Timeout) covers the PREFACE read and the PREFACE_ACK write (plan
// §3.5, L48): 64 silent conns that never send a byte and 64 conns that send
// a PREFACE but never read its PREFACE_ACK (their passive write blocks) all
// occupy a slot (load proof: 128 handshakes at once), and every one is
// closed exactly at its deadline — not earlier (no eviction: 128 < 256
// slots), not later — leaving no slot, goroutine or state behind.
func TestSilentHandshakesReleased_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 2 * time.Second
		rt := wpTestRuntime(t, Config{Handshake: HandshakeLimits{Timeout: timeout}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		const n = 128
		start := time.Now()
		released := make(chan time.Duration, n)
		var wg sync.WaitGroup
		for i := range n {
			d := wpConnect(t, ln, wpInst(0xa0), uint32(i+1))
			wg.Go(func() {
				defer d.close()
				if i%2 == 1 {
					// Write-blocked: the PREFACE is read by the passive, its
					// PREFACE_ACK is never read; this second write blocks
					// until the passive gives up and closes.
					if _, err := d.nc.Write(wpPreface(d.inst, d.id)); err != nil {
						t.Errorf("conn %d: PREFACE: %v", i, err)
					}
					if _, err := d.nc.Write([]byte{0}); !errors.Is(err, io.ErrClosedPipe) {
						t.Errorf("conn %d: blocked write ended with %v", i, err)
					}
				} else {
					var b [1]byte
					if n, err := d.nc.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
						t.Errorf("conn %d: silent conn read (%d, %v)", i, n, err)
					}
				}
				released <- time.Since(start)
			})
		}
		synctest.Wait()
		if st := rt.Status(); st.Handshakes != n {
			t.Fatalf("%d handshakes in progress, want %d", st.Handshakes, n)
		}
		wg.Wait()
		close(released)
		for d := range released {
			if d != timeout {
				t.Fatalf("a silent handshake was released after %v, want exactly %v", d, timeout)
			}
		}
		synctest.Wait()
		if st := rt.Status(); st.HandshakeEvictions != 0 || st.Abandoned != 0 {
			t.Fatalf("status %+v", st)
		}
		wpNoState(t, rt)
		rt.Close()
	})
}

// TestLegitAdmittedUnderSlowloris_L48: when every handshake slot is held
// by a silent conn, a new carrier is never refused or queued behind them:
// the oldest unfinished handshake is evicted (its conn closed at once) and
// the new one proceeds (plan §3.5, L48). 1000 silent conns fill the 256
// default slots and evict the 744 oldest (stimulus and load proof: exactly
// conns 0–743 see EOF, at once, and 256 slots stay held); then a legitimate
// probe carrier gets its PONG and a legitimate JOIN its answer within
// 100 ms (the probe evicts one more silent conn and frees its slot after
// its first frame, so the JOIN finds one free); Close releases the rest.
func TestLegitAdmittedUnderSlowloris_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		const silent, slots = 1000, 256
		evicted := make(chan int, silent)
		var wg sync.WaitGroup
		start := time.Now()
		for i := range silent {
			d := wpConnect(t, ln, wpInst(0xb0), uint32(i+1))
			wg.Go(func() {
				defer d.close()
				var b [1]byte
				if n, err := d.nc.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Errorf("silent conn %d: read (%d, %v)", i, n, err)
				}
				if time.Since(start) == 0 {
					evicted <- i
				}
			})
		}
		synctest.Wait()
		st := rt.Status()
		if st.Handshakes != slots || st.HandshakeEvictions != silent-slots {
			t.Fatalf("after %d silent conns: %d handshakes, %d evictions; want %d and %d", silent, st.Handshakes, st.HandshakeEvictions, slots, silent-slots)
		}
		if len(evicted) != silent-slots {
			t.Fatalf("%d silent conns closed at once, want %d", len(evicted), silent-slots)
		}
		for range silent - slots {
			if i := <-evicted; i >= silent-slots {
				t.Fatalf("conn %d was evicted, a newer one than the %d oldest", i, silent-slots)
			}
		}

		t0 := time.Now()
		p, f := wpProbe(t, rt, ln, wpInst(0xc0), 5000)
		if f.Type != wire.TypePong {
			t.Fatalf("legit probe answered %v, want PONG", f.Type)
		}
		if d := time.Since(t0); d > 100*time.Millisecond {
			t.Fatalf("legit probe admitted after %v", d)
		}
		j := wpConnect(t, ln, wpInst(0xc1), 5001)
		j.hello(rt)
		j.send(wire.TypeJoin, 0, wpJoin(wpSID(1), 1, 0))
		j.expectJoinAck(wire.StatusUnknownSession)
		if d := time.Since(t0); d > 100*time.Millisecond {
			t.Fatalf("legit JOIN answered after %v", d)
		}
		synctest.Wait()
		// The probe evicted one silent conn and released its slot right
		// after its first frame, so the JOIN found a free slot.
		if st := rt.Status(); st.HandshakeEvictions != silent-slots+1 || st.Handshakes != slots-1 || st.Sessionless != 1 {
			t.Fatalf("after the legit carriers: %+v", st)
		}

		// A legitimate OPEN of a real dialer Runtime reaches the application:
		// Accept returns it within 100 ms, and the session carries data.
		dl := wpTestRuntime(t, Config{}, nil)
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "legit", Accept: ln.Handle})
		peer, err := dl.NewPeer(PeerConfig{Carriers: []Carrier{e2eCarrier(link)}})
		if err != nil {
			t.Fatal(err)
		}
		t0 = time.Now()
		res := e2eDialAsync(context.Background(), peer, DialOptions{})
		pc, err := ln.Accept(context.Background())
		if err != nil || time.Since(t0) > 100*time.Millisecond {
			t.Fatalf("legit OPEN accepted after %v: %v", time.Since(t0), err)
		}
		sc, err := pc.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-res
		if r.err != nil {
			t.Fatal(r.err)
		}
		e2eExchange(t, r.c, sc, 64<<10, 48)
		synctest.Wait()
		if st := rt.Status(); st.HandshakeEvictions != silent-slots+1 || st.Handshakes != slots-1 || st.Sessions.Open != 1 {
			t.Fatalf("after the legit OPEN: %+v", st)
		}
		p.close()
		j.close()
		dl.Close()
		rt.Close()
		link.Close()
		wg.Wait()
		wpNoState(t, rt)
		wpNoState(t, dl)
		if st := rt.Status(); st.Abandoned != 0 {
			t.Fatalf("abandoned %d", st.Abandoned)
		}
	})
}

// TestSessionlessCarrierLifecycle_L48: sessionless (probe) carriers are
// capped per dialer instance and per Runtime, refused with CLOSE(capacity)
// beyond either cap without evicting the existing ones, answer every PING
// with an echoing PONG (pad included), close after Sessionless.Idle without
// a PING, answer the dialer's CLOSE with their own, free their place only
// when their carrier is done, and get GOAWAY at Runtime.Close (design §6.4,
// plan §3.5, L48).
func TestSessionlessCarrierLifecycle_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = 30 * time.Second // the default Sessionless.Idle
		rt := wpTestRuntime(t, Config{Sessionless: SessionlessLimits{PerInstance: 2, Total: 3}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		instA, instB, instC := wpInst(0xa1), wpInst(0xb1), wpInst(0xc1)
		admitted := map[*wpDialer]time.Time{} // when its first PONG came: its idle clock starts then
		probe := func(inst [16]byte, id uint32, want wire.Type) *wpDialer {
			t.Helper()
			d, f := wpProbe(t, rt, ln, inst, id)
			admitted[d] = time.Now()
			if f.Type != want {
				t.Fatalf("probe %d answered %v, want %v", id, f.Type, want)
			}
			if want == wire.TypeClose {
				if r, err := wire.ParseClose(f.Payload); err != nil || r != wire.CloseCapacity {
					t.Fatalf("probe %d refused with CLOSE %v (%v), want capacity", id, r, err)
				}
				d.expectEOF()
			}
			return d
		}
		a1 := probe(instA, 1, wire.TypePong)
		a2 := probe(instA, 2, wire.TypePong)
		probe(instA, 3, wire.TypeClose) // per-instance cap
		b1 := probe(instB, 4, wire.TypePong)
		probe(instC, 5, wire.TypeClose) // Runtime cap
		synctest.Wait()
		if n, insts := rt.slt.held(InstanceID(instA)); n != 2 || insts != 2 || rt.Status().Sessionless != 3 {
			t.Fatalf("held: %d for A over %d instances, %d in total", n, insts, rt.Status().Sessionless)
		}
		a1.pingPong(10, 0)
		a1.pingPong(11, 1000)

		// The dialer retires a1: the passive answers CLOSE, ends the carrier
		// and only then frees its place, which a new probe of A takes.
		a1.send(wire.TypeClose, 0, []byte{byte(wire.CloseRetire)})
		a1.expect(wire.TypeClose)
		a1.expectEOF()
		synctest.Wait()
		if n := rt.Status().Sessionless; n != 2 {
			t.Fatalf("%d sessionless carriers after a retirement, want 2", n)
		}
		a4 := probe(instA, 6, wire.TypePong)

		// b1 and a4 stay silent and are closed after Sessionless.Idle; a2
		// keeps PINGing and survives until it stops.
		idleClose := func(d *wpDialer) <-chan time.Duration {
			since := admitted[d]
			ch := make(chan time.Duration, 1)
			go func() {
				d.expect(wire.TypeClose)
				ch <- time.Since(since)
				d.close()
			}()
			return ch
		}
		bClosed, aClosed := idleClose(b1), idleClose(a4)
		for i := range 4 {
			time.Sleep(10 * time.Second)
			a2.pingPong(uint32(20+i), 0)
		}
		for _, ch := range []<-chan time.Duration{bClosed, aClosed} {
			if d := <-ch; d < idle || d > idle+time.Second {
				t.Fatalf("an idle probe carrier closed after %v, want %v", d, idle)
			}
		}
		synctest.Wait()
		if n := rt.Status().Sessionless; n != 1 {
			t.Fatalf("%d sessionless carriers after the idle closes, want 1 (the PINGing one)", n)
		}

		// Runtime.Close: GOAWAY, then CLOSE, on the remaining probe carrier.
		closed := make(chan error, 1)
		go func() {
			if f := a2.expect(wire.TypeGoAway); f.Handle != 0 || len(f.Payload) != 1 || f.Payload[0] != byte(wire.GoAwayShutdown) {
				closed <- errors.New("bad GOAWAY")
				return
			}
			a2.expect(wire.TypeClose)
			a2.close()
			closed <- nil
		}()
		rt.Close()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		wpNoState(t, rt)
		if n, insts := rt.slt.held(InstanceID(instA)); n != 0 || insts != 0 {
			t.Fatalf("sessionless counts left: %d over %d instances", n, insts)
		}
	})
}

// TestHandshakeClosesConnOnce_L51: an embedder conn is closed exactly once
// on every handshake path (L51), although eviction closes the conn of an
// unfinished handshake (SetDeadline(now) + Close, so that even a conn that
// ignores deadlines is released) while that handshake's ReadHello closes
// it too when its read fails: a silent conn evicted before its PREFACE, a
// conn evicted after PREFACE_ACK(OK) while it waits for its first frame, a
// sessionless carrier ended by Runtime.Close and a conn pushed after Close
// each see exactly one Close.
func TestHandshakeClosesConnOnce_L51(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{Handshake: HandshakeLimits{MaxConcurrent: 1}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		var conns []*countConn
		connect := func(id uint32) *wpDialer {
			a, b := net.Pipe()
			c := &countConn{Conn: a}
			conns = append(conns, c)
			if err := ln.Handle(c); err != nil {
				t.Fatal(err)
			}
			return &wpDialer{t: t, nc: b, inst: wpInst(0xf1), id: id, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
		}
		d1 := connect(1) // silent
		d2 := connect(2) // evicts d1
		d1.expectEOF()
		d2.hello(rt) // OK: d2 now waits for its first frame in the only slot
		p := connect(3)
		d2.expectEOF() // evicted after PREFACE_ACK(OK)
		p.hello(rt)
		ping := wire.Ping{ID: 9, Nonce: 99}
		p.send(wire.TypePing, 0, wpPing(ping))
		p.expect(wire.TypePong)
		synctest.Wait()
		if st := rt.Status(); st.HandshakeEvictions != 2 || st.Sessionless != 1 {
			t.Fatalf("status %+v", st)
		}
		go func() {
			p.expect(wire.TypeGoAway)
			p.expect(wire.TypeClose)
			p.close()
		}()
		rt.Close()
		late, _ := net.Pipe()
		lc := &countConn{Conn: late}
		conns = append(conns, lc)
		if err := ln.Handle(lc); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle after Close: %v", err)
		}
		synctest.Wait()
		for i, c := range conns {
			if n := c.closes.Load(); n != 1 {
				t.Fatalf("conn %d closed %d times, want 1", i+1, n)
			}
		}
		d1.close()
		d2.close()
		wpNoState(t, rt)
	})
}

// TestOpenModeAboveMaxBadRequest_L44: since M3 the codec accepts modes 1 to
// wire.MaxMode (3) and rejects every larger mode byte with wire.ErrValue
// (M3 design §A3.5); admission answers such an OPEN BAD_REQUEST CodeBadMode,
// as in M2, before any session state exists (the M3 rows of
// TestOpenRefusedBeforeState_L44_L48, which pins mode 0 and mode 4).
func TestOpenModeAboveMaxBadRequest_L44(t *testing.T) {
	sid := wpSID(2)
	for _, mode := range []uint8{wire.MaxMode + 1, 0xff} {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			d := wpConnect(t, ln, wpInst(0xd3), 9)
			d.hello(rt)
			sent := d.sendAsync(wire.TypeOpen, 0, wpOpen(sid, wire.KindStream, mode, nil))
			a := d.expectOpenAck(wire.StatusBadRequest, wire.CodeBadMode)
			if a.Window != 0 || len(a.Msg) != 0 {
				t.Fatalf("mode %d: non-canonical refusal %+v", mode, a)
			}
			d.expectEOF()
			<-sent
			synctest.Wait()
			wpNoState(t, rt)
			d.close()
			rt.Close()
		})
	}
}

// acceptLog accepts every session of ln on its own goroutine and hands each
// PendingConn to decide, recording how often every session ID was
// accepted. stop ends the loop and joins it.
type acceptLog struct {
	mu    sync.Mutex
	count map[SessionID]int
	conns []*Conn // confirmed passive ends
	stop  func()
}

func newAcceptLog(ln *Listener, decide func(pc *PendingConn) (*Conn, error)) *acceptLog {
	a := &acceptLog{count: make(map[SessionID]int)}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			pc, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			a.mu.Lock()
			a.count[pc.ID()]++
			a.mu.Unlock()
			if c, err := decide(pc); err == nil && c != nil {
				a.mu.Lock()
				a.conns = append(a.conns, c)
				a.mu.Unlock()
			}
		}
	})
	a.stop = func() {
		cancel()
		wg.Wait()
	}
	return a
}

// accepted returns how often sid was accepted and the number of distinct
// sessions accepted.
func (a *acceptLog) accepted(sid SessionID) (n, sessions int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.count[sid], len(a.count)
}

// TestOpenIdempotent_L47: an OPEN is idempotent (L47, design §6.2, §6.5).
// When the first OPEN_ACK(OK) is lost, the dialer's retried OPEN (same
// session ID) reaches the session the passive already confirmed: the
// application accepted exactly one session, the dialer's Conn is that
// session and carries data. When an OPEN_ACK(REJECTED) is lost, the
// retried OPEN gets REJECTED with the same code and message again from the
// tombstone — still one Accept. Stimulus proof: exactly one OPEN_ACK frame
// dropped per case on a session carrier; a replay after the end gets
// UNKNOWN_SESSION.
func TestOpenIdempotent_L47(t *testing.T) {
	t.Run("lost OPEN_ACK OK", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			link := e.links[0]
			acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
				link.DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck) // the carrier exists: it carried this OPEN
				return pc.Confirm()
			})
			start := time.Now()
			dc, err := e.peer().Dial(context.Background(), DialOptions{})
			if err != nil {
				t.Fatalf("Dial after a lost OPEN_ACK: %v", err)
			}
			synctest.Wait()
			if st := link.Stats(); st.Session.FramesDropped != 1 || st.Dials < 2 {
				t.Fatalf("stimulus: %d OPEN_ACKs dropped, %d dials", st.Session.FramesDropped, st.Dials)
			}
			if n, sessions := acc.accepted(dc.ID()); n != 1 || sessions != 1 {
				t.Fatalf("accepted %d times (%d sessions), want exactly one", n, sessions)
			}
			if ps := e.p.Status(); ps.Sessions.Open+ps.Sessions.Orphaned != 1 || e.p.table.inUse() != 1 {
				t.Fatalf("passive sessions %+v (%d units)", ps.Sessions, e.p.table.inUse())
			}
			t.Logf("Dial took %v over two carriers", time.Since(start))
			acc.mu.Lock()
			sc := acc.conns[0]
			acc.mu.Unlock()
			if sc.ID() != dc.ID() {
				t.Fatalf("confirmed %v, dialled %v", sc.ID(), dc.ID())
			}
			e2eExchange(t, dc, sc, 1<<20, 7)
			e2eFinish(t, dc, sc)
			d := wpConnect(t, e.ln, e.d.InstanceID(), 99)
			d.hello(e.p)
			d.send(wire.TypeOpen, 0, wpOpen(dc.ID(), wire.KindStream, 1, nil))
			d.expectOpenAck(wire.StatusUnknownSession, 0)
			d.expectEOF()
			d.close()
			acc.stop()
			e.close()
		})
	})
	t.Run("lost OPEN_ACK REJECTED", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			link := e.links[0]
			acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
				link.DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck)
				return nil, pc.Reject(42, "no route to host")
			})
			_, err := e.peer().Dial(context.Background(), DialOptions{})
			var re *RejectError
			if !errors.As(err, &re) || !errors.Is(err, ErrRejected) || re.Code != 42 || re.Msg != "no route to host" {
				t.Fatalf("Dial after a lost REJECTED: %v", err)
			}
			synctest.Wait()
			if st := link.Stats(); st.Session.FramesDropped != 1 || st.Dials < 2 {
				t.Fatalf("stimulus: %d OPEN_ACKs dropped, %d dials", st.Session.FramesDropped, st.Dials)
			}
			acc.mu.Lock()
			total := 0
			for _, n := range acc.count {
				total += n
			}
			acc.mu.Unlock()
			if total != 1 {
				t.Fatalf("%d Accepts, want 1", total)
			}
			if ps := e.p.Status(); ps.Sessions != (SessionCounts{Tombstones: 1}) {
				t.Fatalf("passive sessions %+v", ps.Sessions)
			}
			acc.stop()
			e.close()
		})
	})
}

// TestOpenRaceSingleSession_L47: 64 carriers of one dialer instance OPEN
// the same session ID at the same instant (L47, design §6.2 D28, C8).
// Exactly one session is created and started: one Accept, one MaxSessions
// unit, one backlog slot, no reservation left by the losers (their
// sessions were never started); every loser's carrier is attached to the
// winner (MaxCarriersPerSession raised to 64), so Confirm answers
// OPEN_ACK(OK) on all 64 carriers of the one session.
func TestOpenRaceSingleSession_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 64
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{MaxCarriersPerSession: n})
		ln := wpListen(t, rt, ListenConfig{})
		inst, sid := wpInst(0x47), wpSID(47)
		ds := make([]*wpDialer, n)
		for i := range ds {
			ds[i] = wpConnect(t, ln, inst, uint32(i+1))
			ds[i].hello(rt)
		}
		go1 := make(chan struct{})
		var wg sync.WaitGroup
		for _, d := range ds {
			wg.Go(func() {
				<-go1
				d.send(wire.TypeOpen, 0, wpOpen(sid, wire.KindStream, 1, []byte("race")))
			})
		}
		close(go1)
		wg.Wait()
		synctest.Wait()
		if units, bl := rt.table.inUse(), rt.backlog[kindIdxStream].Load(); units != 1 || bl != 1 {
			t.Fatalf("after %d racing OPENs: %d MaxSessions units, %d backlog slots", n, units, bl)
		}
		ln.mu.Lock()
		reserved, pending := ln.q[kindIdxStream].reserved, len(ln.pending)
		ln.mu.Unlock()
		if reserved != 0 || pending != 1 {
			t.Fatalf("listener: %d reservations, %d pending sessions", reserved, pending)
		}
		pc, err := ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if extra, err := ln.Accept(ctx); extra != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a second Accept: %v, %v", extra, err)
		}
		cancel()
		if pc.ID() != SessionID(sid) {
			t.Fatalf("accepted %v", pc.ID())
		}
		sc, err := pc.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		for i, d := range ds {
			wg.Go(func() {
				a := d.expectOpenAck(wire.StatusOK, 0)
				if a.Window == 0 {
					t.Errorf("carrier %d: OPEN_ACK(OK) without a window", i+1)
				}
			})
		}
		wg.Wait()
		synctest.Wait()
		if st := sc.Status(); len(st.Carriers) != n {
			t.Fatalf("the session holds %d carriers, want %d", len(st.Carriers), n)
		}
		for _, d := range ds {
			d.close()
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestRandomOpenAckLoss_L47: random OPEN_ACK loss never forks a session
// (L47 fuzz): 40 Dials over two links in selector and bond mode, a seeded
// dropper loses the next OPEN_ACK of every current carrier at random
// instants and at half of the Confirms. Each Dial produced at most one
// passive session: no session ID was accepted twice; every successful Dial
// is exactly the one session the passive application accepted for its ID,
// and carries data; Dials that failed left no session behind. Stimulus
// proof: OPEN_ACK frames were dropped on session carriers and the Dials
// retried.
func TestRandomOpenAckLoss_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rng := rand.New(rand.NewPCG(47, 4747))
		var rmu sync.Mutex
		coin := func(p float64) bool {
			rmu.Lock()
			defer rmu.Unlock()
			return rng.Float64() < p
		}
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		for _, l := range e.links {
			l.SetDelay(time.Millisecond, 0) // probes need an RTT above zero (WaitFirst)
		}
		drop := func() {
			for _, l := range e.links {
				l.DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck)
			}
		}
		acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
			if coin(0.5) {
				drop()
			}
			return pc.Confirm()
		})
		stop := make(chan struct{})
		var stopOnce sync.Once
		var wg sync.WaitGroup
		t.Cleanup(func() { // a failing test still ends the dropper before the bubble ends
			stopOnce.Do(func() { close(stop) })
			wg.Wait()
		})
		wg.Go(func() { // the dropper
			for {
				select {
				case <-stop:
					return
				case <-time.After(73 * time.Millisecond):
				}
				if coin(0.3) {
					drop()
				}
			}
		})
		peer := e.peer()
		const dials = 40
		ok := 0
		for i := range dials {
			mode := ModeSelector
			if i%2 == 1 {
				mode = ModeBond
			}
			dc, err := peer.Dial(context.Background(), DialOptions{Mode: mode})
			if err != nil {
				if !errors.Is(err, ErrNoPath) {
					t.Fatalf("Dial %d: %v", i, err)
				}
				continue
			}
			ok++
			if n, _ := acc.accepted(dc.ID()); n != 1 {
				t.Fatalf("Dial %d: its session was accepted %d times", i, n)
			}
			var sc *Conn
			acc.mu.Lock()
			for _, c := range acc.conns {
				if c.ID() == dc.ID() {
					sc = c
				}
			}
			acc.mu.Unlock()
			if sc == nil {
				t.Fatalf("Dial %d: the passive end was never confirmed", i)
			}
			e2eExchange(t, dc, sc, 64<<10, uint64(i))
			dc.Close()
			sc.Close()
		}
		stopOnce.Do(func() { close(stop) })
		wg.Wait()
		synctest.Wait()
		acc.mu.Lock()
		for sid, n := range acc.count {
			if n != 1 {
				t.Fatalf("session %v accepted %d times", sid, n)
			}
		}
		accepted := len(acc.count)
		acc.mu.Unlock()
		dropped := e.links[0].Stats().Session.FramesDropped + e.links[1].Stats().Session.FramesDropped
		dialled := e.links[0].Stats().Dials + e.links[1].Stats().Dials
		t.Logf("%d of %d Dials succeeded, %d sessions accepted, %d OPEN_ACKs dropped, %d carrier dials", ok, dials, accepted, dropped, dialled)
		if ok < dials/2 || accepted < ok || dropped < 10 {
			t.Fatalf("stimulus or load not reached: %d Dials succeeded, %d accepted, %d OPEN_ACKs dropped", ok, accepted, dropped)
		}
		if ps := e.p.Status(); ps.Sessions.Pending != 0 || ps.AcceptBacklog[0] != 0 {
			t.Fatalf("passive left %+v", ps)
		}
		acc.stop()
		e.close()
	})
}

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
