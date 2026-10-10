package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

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
