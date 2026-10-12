package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestJoinEndedSessionCarriesEndCode_L47 (L47; WP13 B-1 review): a JOIN
// that reaches a session after it ended but before Registry.Ended made it
// a tombstone — Join answers UNKNOWN_SESSION from StateEnded — gets the
// same end code as the tombstone would give (Session.EndCode). The
// passive aborts (code 0x5000) while the dialer's only link is dead and
// refuses carriers; its Registry.Ended is held, so the session stays in the
// admission table, ended. When the link accepts again the dialer's rejoin
// meets it and must end with *AbortError{0x5000, Remote}, not
// ErrSessionLost. EndCode itself is checked too: 0 while the session is
// open, the code once it ended by its own RST.
func TestJoinEndedSessionCarriesEndCode_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const code = 0x5000
		w := acNewWorld(t, nil)
		defer w.teardown()
		gate := make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(gate) }) }
		defer release() // before the teardown, also when the test fails
		prev := w.b.reg.onEnded
		w.b.reg.onEnded = func(s *Session, v Verdict) {
			<-gate // the session stays in the table, ended
			prev(s, v)
		}
		w.a.p.Grace = 10 * time.Second
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		if c := b.EndCode(); c != 0 {
			t.Fatalf("EndCode of an open session: %#x, want 0", c)
		}
		l1.SetRefuse(true)
		if l1.Kill() == 0 {
			t.Fatal("stimulus: no carrier killed")
		}
		time.Sleep(50 * time.Millisecond)
		if err := b.Abort(code, "outage"); err != nil {
			t.Fatalf("Abort: %v", err)
		}
		synctest.Wait() // the passive ended; its actor waits in Registry.Ended
		if c := b.EndCode(); c != code {
			t.Fatalf("EndCode of the aborted session: %#x, want %#x", c, code)
		}
		if w.b.session(b.ID()) != b {
			t.Fatal("stimulus: the ended session left the table (no tombstone may exist yet)")
		}
		l1.SetRefuse(false)
		select {
		case <-a.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the dialer did not end after its rejoin")
		}
		var ae *AbortError
		if err := a.Status().Err; !errors.As(err, &ae) || ae.Code != code || !ae.Remote {
			t.Fatalf("dialer end %v, want *AbortError{%#x, Remote}", err, code)
		}
		if joins, _ := w.b.counts(); joins[wire.StatusUnknownSession] == 0 {
			t.Fatal("stimulus: no JOIN met the ended session")
		}
		release()
		acDone(t, b, 5*time.Second)
		if v, _ := w.b.reg.endedVerdict(b); !v.Opened || v.Code != code {
			t.Fatalf("verdict %+v, want opened with code %#x", v, code)
		}
	})
}

// TestRefuseAdoptCarriesEndCode_L47 (L47; WP13 B-1 review): a JOIN that
// Join took (its adopt posted) but that the actor handles only after the
// session ended is refused by refuseAdopt with JOIN_ACK(UNKNOWN_SESSION)
// — with an opened session's end code when the carrier negotiated
// wire.OptEndCode, exactly as the tombstone answers, and the canonical,
// code-free JOIN_ACK otherwise: no bit, no code, or a session that never
// opened (its Verdict.Code is an OPEN_ACK code, never an end code).
func TestRefuseAdoptCarriesEndCode_L47(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opt      uint32
		verdict  Verdict
		wantCode uint32
	}{
		{"opened, bit negotiated", wire.OptEndCode, Verdict{Opened: true, Code: 0x5000}, 0x5000},
		{"opened, no bit", 0, Verdict{Opened: true, Code: 0x5000}, 0},
		{"opened without an RST of its own", wire.OptEndCode, Verdict{Opened: true}, 0},
		{"never opened", wire.OptEndCode, Verdict{Status: wire.StatusCapacity, Code: wire.CodeAcceptTimeout}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				side := acNewSide(2, nil)
				d, p := net.Pipe()
				defer d.Close()
				pre := make([]byte, wire.PrefaceLen)
				wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Opt: tc.opt, Instance: [16]byte{1, 0x5A, 0xC7}, CarrierID: 7})
				jp := make([]byte, wire.JoinLen)
				wire.PutJoin(jp, &wire.Join{SID: [16]byte{9}, Mode: 1})
				hello := wire.AppendFrame(pre, wire.Header{Type: wire.TypeJoin, Fseq: wire.PrefaceFseq(pre), Handle: wire.SessionHandle}, jp)
				got := make(chan []byte, 1)
				go d.Write(hello) // the passive reads the JOIN only after its PREFACE_ACK
				go func() {
					b, _ := io.ReadAll(d) // PREFACE_ACK ‖ JOIN_ACK, until the close
					got <- b
				}()
				h, err := carrier.ReadHello(side.cenv, p, time.Now().Add(time.Second), 4096, nil)
				if err != nil {
					t.Fatalf("ReadHello: %v", err)
				}
				if h.Conn.EndCodes() != (tc.opt != 0) {
					t.Fatalf("EndCodes %v for PREFACE opt %#x", h.Conn.EndCodes(), tc.opt)
				}
				a := &actor{verdict: tc.verdict}
				a.refuseAdopt(&adopt{conn: h.Conn, kind: adoptJoin})
				<-h.Conn.Done()
				b := <-got
				if len(b) < wire.PrefaceLen {
					t.Fatalf("the dialer read %d bytes", len(b))
				}
				f, _, err := wire.DecodeFrame(b[wire.PrefaceLen:])
				if err != nil || f.Type != wire.TypeJoinAck {
					t.Fatalf("response %+v %v, want a JOIN_ACK", f.Header, err)
				}
				want := make([]byte, wire.JoinAckLen)
				wire.PutJoinAckMux(want, &wire.JoinAck{Status: wire.StatusUnknownSession}, tc.wantCode)
				if !bytes.Equal(f.Payload, want) {
					t.Fatalf("JOIN_ACK % x, want % x (UNKNOWN_SESSION, code %#x)", f.Payload, want, tc.wantCode)
				}
				if len(a.gone) != 1 || a.gone[0] != h.Conn {
					t.Fatal("the refused carrier did not join the exit join")
				}
			})
		})
	}
}
