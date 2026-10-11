package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestAbortDuringOutageReachesDialer_L47 (L47, plan §5; WP13 B-1): the
// passive application aborts (code 0x5000) while the session has no
// carrier: the dialer's only link was killed and refuses new carriers.
// The RST has no lane, the session ends and its tombstone keeps the code.
// A JOIN to that tombstone — here a raw one on a second link — is answered
// JOIN_ACK(UNKNOWN_SESSION) with the code in the RxNext field when its
// PREFACE carried OptEndCode (which the PREFACE_ACK echoes), and with the
// canonical, code-free JOIN_ACK otherwise (a dialer that does not know the
// bit: M3). Once the link accepts again the dialer's own rejoin ends its
// session with *AbortError{0x5000, Remote} instead of ErrSessionLost.
func TestAbortDuringOutageReachesDialer_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const code AbortCode = 0x5000
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "raw")
		dc, pc := e2eOpen(t, e.peer(e.links[0]), e.ln, DialOptions{})
		l := e.links[0]
		l.SetRefuse(true)
		if l.Kill() == 0 {
			t.Fatal("stimulus: no carrier killed")
		}
		time.Sleep(50 * time.Millisecond)
		pc.Abort(code, "outage")
		select {
		case <-pc.Done():
		case <-time.After(time.Second):
			t.Fatal("the passive session did not end")
		}
		if st := e.p.Status(); st.Sessions.Tombstones != 1 {
			t.Fatalf("stimulus: passive %+v, want the tombstone", st.Sessions)
		}
		for _, offer := range []bool{true, false} {
			opt, wantCode := uint32(0), uint32(0)
			if offer {
				opt, wantCode = wire.OptEndCode, uint32(code)
			}
			ackOpt, payload := rawJoin(t, e, opt, dc.ID())
			want := make([]byte, wire.JoinAckLen)
			wire.PutJoinAckMux(want, &wire.JoinAck{Status: wire.StatusUnknownSession}, wantCode)
			if ackOpt != opt || !bytes.Equal(payload, want) {
				t.Errorf("JOIN offering %#x: PREFACE_ACK opt %#x, JOIN_ACK % x; want opt %#x, % x", opt, ackOpt, payload, opt, want)
			}
		}
		l.SetRefuse(false)
		var ae *AbortError
		if _, err := dc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != code || !ae.Remote {
			t.Fatalf("the dialer after the outage: %v, want *AbortError{%#x, Remote}", err, code)
		}
		synctest.Wait()
		e.close()
	})
}

// rawJoin sends PREFACE(opt) ‖ JOIN(sid) for the dialer Runtime's instance
// on e's "raw" link and returns the PREFACE_ACK's opt and the JOIN_ACK's
// payload.
func rawJoin(t *testing.T, e *e2ePair, opt uint32, sid SessionID) (uint32, []byte) {
	t.Helper()
	nc, err := e.links[1].Dial(context.Background())
	if err != nil {
		t.Fatalf("raw Dial: %v", err)
	}
	defer nc.Close()
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Opt: opt, Instance: e.d.InstanceID(), CarrierID: 0x7777})
	jp := make([]byte, wire.JoinLen)
	wire.PutJoin(jp, &wire.Join{SID: sid, Mode: 1})
	hello := wire.AppendFrame(pre, wire.Header{Type: wire.TypeJoin, Fseq: wire.PrefaceFseq(pre), Handle: wire.SessionHandle}, jp)
	if _, err := nc.Write(hello); err != nil {
		t.Fatalf("raw hello: %v", err)
	}
	ab := make([]byte, wire.PrefaceLen)
	if _, err := io.ReadFull(nc, ab); err != nil {
		t.Fatalf("PREFACE_ACK: %v", err)
	}
	ack, err := wire.ParsePrefaceAck(ab)
	if err != nil || ack.Status != wire.PrefaceOK {
		t.Fatalf("PREFACE_ACK %+v %v", ack, err)
	}
	fb := make([]byte, wire.FrameOverhead+wire.JoinAckLen)
	if _, err := io.ReadFull(nc, fb); err != nil {
		t.Fatalf("JOIN_ACK: %v", err)
	}
	f, _, err := wire.DecodeFrame(fb)
	if err != nil || f.Type != wire.TypeJoinAck || f.Handle != wire.SessionHandle {
		t.Fatalf("response %+v %v", f.Header, err)
	}
	return ack.Opt, bytes.Clone(f.Payload)
}

// TestAbortDuringOutageReachesDialerOnView_L47 (L47; WP13 B-1): the same
// outage with two sessions on one MUX trunk. The passive aborts the first
// (code 0x5001) while the trunk is dead; the second survives. When the
// link accepts again, the factory refuses every carrier whose first frame
// is the aborted session's JOIN, so only the survivor's JOIN builds the new
// trunk and the aborted session's JOIN can only take a view of it (a fast
// path or a coalesced wait never calls the factory). That view's
// JOIN_ACK(UNKNOWN_SESSION) carries the code, and the dialer ends with
// *AbortError{0x5001, Remote}, not ErrSessionLost.
func TestAbortDuringOutageReachesDialerOnView_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const code AbortCode = 0x5001
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		l := e.links[0]
		var blocked atomic.Pointer[SessionID] // the session whose handle-1 JOIN the factory refuses
		var ownJoins atomic.Int32
		dial := func(ctx context.Context, first []byte) (net.Conn, error) {
			if sid := blocked.Load(); sid != nil && len(first) >= wire.PrefaceLen+wire.HeaderLen+16 {
				f, _, err := wire.DecodeFrame(first[wire.PrefaceLen:])
				if err == nil && f.Type == wire.TypeJoin && bytes.Equal(f.Payload[:16], sid[:]) {
					ownJoins.Add(1)
					return nil, errors.New("refused: the aborted session must take a view")
				}
			}
			return l.DialEarly(ctx, first)
		}
		p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "a", Dial: l.Dial, DialEarly: dial}}})
		if err != nil {
			t.Fatal(err)
		}
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		dc2, pc2 := e2eOpen(t, p, e.ln, DialOptions{})
		if st := e.d.Status().Mux; st.Carriers != 1 || st.Views != 2 {
			t.Fatalf("stimulus: dialer mux %+v, want both sessions on one trunk", st)
		}
		sid := dc.ID()
		blocked.Store(&sid)
		l.SetRefuse(true)
		if l.Kill() == 0 {
			t.Fatal("stimulus: no carrier killed")
		}
		time.Sleep(50 * time.Millisecond)
		pc.Abort(code, "outage")
		select {
		case <-pc.Done():
		case <-time.After(time.Second):
			t.Fatal("the passive session did not end")
		}
		w := goWrite(dc2, []byte("x"))
		l.SetRefuse(false)
		var ae *AbortError
		if _, err := dc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != code || !ae.Remote {
			t.Fatalf("the aborted session's dialer after the outage: %v, want *AbortError{%#x, Remote}", err, code)
		}
		if err := <-w; err != nil {
			t.Fatalf("survivor Write: %v", err)
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(pc2, b); err != nil || b[0] != 'x' {
			t.Fatalf("survivor: %q %v", b, err)
		}
		t.Logf("the aborted session's own JOIN dials refused: %d; dialer mux %+v", ownJoins.Load(), e.d.Status().Mux)
		dc2.Close()
		pc2.Close()
		synctest.Wait()
		p.Close()
		e.close()
	})
}

// goWrite writes b to c on its own goroutine.
func goWrite(c *Conn, b []byte) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := c.Write(b)
		ch <- err
	}()
	return ch
}
