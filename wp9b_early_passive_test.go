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
)

// The passive's early data (M4 design §A5.1 … §A5.3; M4-D2, M4-D5, M4-D6,
// M4-D8; WP9b) through a real Runtime admission: scripted raw-wire dialers
// (wirepeer_test.go) send an OPEN whose flag bit 0 (EARLY) is set and DATA
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
