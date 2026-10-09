package carrier

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Dedicated-carrier and handshake handle rules (§A3.2, see dedicatedOK):
// since M3's wire package accepts any non-zero handle on session frames and
// knows DETACH, the carrier keeps M2's outcome for both on every carrier
// that is not a MUX trunk, and in every handshake.

// TestDedicatedStreamRejectsDetachAndHandles_L43_L14: on a sessionless,
// probe or session stream carrier, a DETACH and a session frame with a
// handle other than 1 are protocol violations (invariant 6): never a
// nil-endpoint panic, never dispatched to the endpoint; an extension frame
// with handle 2 is still skipped.
func TestDedicatedStreamRejectsDetachAndHandles_L43_L14(t *testing.T) {
	ack := make([]byte, wire.AckLen)
	wire.PutAck(ack, &wire.Ack{Delivered: 0, Window: 1 << 20})
	frames := []struct {
		name string
		f    hFrame
	}{
		{"DETACH", hFrame{t: wire.TypeDetach, payload: detachPayload(2, wire.DetachEnded)}},
		{"DETACH of handle 1", hFrame{t: wire.TypeDetach, payload: detachPayload(wire.SessionHandle, wire.DetachEnded)}},
		{"FIN handle 2", hFrame{t: wire.TypeFin, handle: 2, payload: finInner(0)}},
		{"ACK handle 7", hFrame{t: wire.TypeAck, handle: 7, payload: ack}},
		{"DATA handle 0xffffffff", hFrame{t: wire.TypeData, handle: 0xffffffff, payload: dataPayload(0, 10)}},
	}
	starts := []struct {
		name    string
		session bool
		opts    StartOptions
	}{
		{"sessionless", false, StartOptions{Sessionless: true}},
		{"probe", false, StartOptions{Probe: true}},
		{"session", true, StartOptions{}},
	}
	for _, s := range starts {
		for _, fr := range frames {
			t.Run(s.name+"/"+fr.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					c, p := hPair(t, hEnv(), nil)
					ep := &hEP{}
					if s.session {
						c.Start(ep, &hBell{}, s.opts)
					} else {
						c.Start(nil, &hBell{}, s.opts)
					}
					go p.sendFrames(fr.f)
					hWait(t, c)
					dead, cause, detail, _ := c.Death()
					if !dead || cause != CauseProtocolViolation {
						t.Fatalf("death %v %v %q, want protocol_violation", dead, cause, detail)
					}
					ep.mu.Lock()
					n, d := len(ep.ctrl), len(ep.data)
					ep.mu.Unlock()
					if n != 0 || d != 0 {
						t.Fatalf("%d control and %d data frames dispatched", n, d)
					}
					p.close()
				})
			})
		}
	}
	t.Run("extension handle 2 skipped", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, p := hPair(t, hEnv(), nil)
			p.autoPong(nil)
			c.Start(&hEP{}, &hBell{}, StartOptions{})
			go p.sendFrames(hFrame{t: wire.Type(0x80), handle: 2, payload: []byte("x")})
			synctest.Wait()
			if dead, cause, detail, _ := c.Death(); dead {
				t.Fatalf("died: %v %q", cause, detail)
			}
			p.close()
		})
	})
}

// TestDedicatedDatagramDropsBadHandle_L14: on a datagram carrier — the
// dialer's and the passive's (the FuzzMuxDispatch_L43_L14 seed "$71": a
// passive dedicated carrier and a DGRAM of handle 2) — a bare session
// frame with a handle other than 1, and a bare DETACH, drop the rest of
// their datagram and count it (M2's framing error, PA-1; dedicatedOK); the
// carrier lives and a later DGRAM of handle 1 is delivered. A REL{FIN} of
// handle 2 and a REL{DETACH} are violations ("REL: ...").
func TestDedicatedDatagramDropsBadHandle_L14(t *testing.T) {
	for _, role := range []struct {
		name   string
		dialer bool
	}{{"dialer", true}, {"passive", false}} {
		t.Run("bare frames dropped/"+role.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dedicatedBareDrops(t, role.dialer)
			})
		})
	}
	for _, tc := range []struct {
		name    string
		f       rawFrame
		session bool
	}{
		{"REL FIN handle 2", relFrame(1, wire.TypeFin, 0, 2, finInner(0)), true},
		{"REL DETACH", relFrame(1, wire.TypeDetach, 0, 0, detachPayload(2, wire.DetachEnded)), true},
		{"REL DETACH sessionless", relFrame(1, wire.TypeDetach, 0, 0, detachPayload(2, wire.DetachEnded)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, p := rawPair(t, 1200, true)
				if tc.session {
					s.start(StartOptions{})
				} else {
					s.c.Start(nil, s.bell, StartOptions{Sessionless: true})
				}
				synctest.Wait()
				p.send(tc.f)
				hWait(t, s.c)
				if _, cause, detail, _ := s.c.Death(); cause != CauseProtocolViolation || !strings.Contains(detail, "on a dedicated carrier") {
					t.Fatalf("cause %v %q, want protocol_violation on a dedicated carrier", cause, detail)
				}
				if n := len(s.ep.controls()); n != 0 {
					t.Fatalf("%d control frames dispatched", n)
				}
			})
		})
	}
}

// dedicatedBareDrops is the "bare frames dropped" row of
// TestDedicatedDatagramDropsBadHandle_L14 on a dedicated datagram carrier
// of the given role: a DGRAM of handle 2 drops the rest of its datagram (its
// handle-1 DGRAM behind it too), a bare DETACH likewise, both counted; the
// carrier lives and the next DGRAM of handle 1 is delivered.
func dedicatedBareDrops(t *testing.T, dialer bool) {
	s, p := rawPair(t, 1200, dialer)
	s.start(StartOptions{})
	synctest.Wait()
	p.read()
	bad := dgramFrame(1, 10)
	bad.handle = 2
	p.send(bad, dgramFrame(2, 10))
	synctest.Wait()
	p.send(rawFrame{t: wire.TypeDetach, payload: detachPayload(2, wire.DetachEnded)}, dgramFrame(3, 10))
	synctest.Wait()
	p.send(dgramFrame(4, 10))
	synctest.Wait()
	if dead, cause, detail, _ := s.c.Death(); dead {
		t.Fatalf("carrier died: %v %q", cause, detail)
	}
	got := s.ep.datagrams()
	if len(got) != 1 || got[0].seq != 4 {
		t.Fatalf("datagrams %+v, want only seq 4", got)
	}
	if st := s.c.Stats(); st.Dropped != 2 {
		t.Fatalf("dropped %d, want 2", st.Dropped)
	}
}

// TestDedicatedHandshakeHandle_L14: the first frame of a stream hello, the
// OPEN or JOIN of a datagram H1 and a dialer's response (stream and
// datagram: responseAllowed) carry session handle 1; any other handle is
// refused as M2's codec refused it.
func TestDedicatedHandshakeHandle_L14(t *testing.T) {
	t.Run("stream hello", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			first := frameAt(wire.TypeOpen, 0, env.Presets.firstFseq(), 2, openPayload(0))
			d := dialHello(b, hPreface(9), first)
			h, err := ReadHello(env, a, time.Now().Add(time.Second), 4096, nil)
			if err == nil || !errors.Is(err, errHelloFirst) || !strings.Contains(err.Error(), "handle 2") {
				t.Fatalf("ReadHello %+v, %v, want errHelloFirst", h, err)
			}
			<-d.done
		})
	})
	t.Run("stream response", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			f, ends := pipeFactory(3, "f3")
			id := env.IDs.Next()
			go func() {
				runPassive(<-ends, func(wire.Preface, wire.Frame) []byte {
					return append(hPrefaceAck(wire.PrefaceOK, id), frameAt(wire.TypeOpenAck, 0, env.Presets.firstFseq(), 2, okOpenAck())...)
				})
			}()
			est, err := Establish(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), nil)
			var ee *EstablishError
			if est != nil || !errors.As(err, &ee) || ee.Stage != "response" || ee.Cause != CauseProtocolViolation {
				t.Fatalf("Establish %+v, %v, want a protocol violation", est, err)
			}
		})
	})
	t.Run("datagram H1", func(t *testing.T) {
		env := hEnv()
		pre := make([]byte, wire.PrefaceLen)
		wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Instance: hDialerInst, CarrierID: 5})
		for _, tc := range []struct {
			t      wire.Type
			handle uint32
			ok     bool
		}{
			{wire.TypeOpen, wire.SessionHandle, true},
			{wire.TypeOpen, 2, false},
			{wire.TypeJoin, 0xffffffff, false},
		} {
			payload := openPayload(0)
			if tc.t == wire.TypeJoin {
				payload = make([]byte, wire.JoinLen)
				wire.PutJoin(payload, &wire.Join{SID: [16]byte{1}, Mode: 1})
			}
			rel := relPayloadOf(env.Presets.firstCseq(), tc.t, 0, tc.handle, payload)
			d := append(append([]byte(nil), pre...), frameAt(wire.TypeRel, 0, env.Presets.fseqFrom(pre), 0, rel)...)
			if _, ok, err := parseH1(env, d, 255); ok != tc.ok || err != nil {
				t.Errorf("%v handle %d: H1 ok %v %v, want %v", tc.t, tc.handle, ok, err, tc.ok)
			}
		}
	})
	t.Run("responses", func(t *testing.T) {
		for _, tc := range []struct {
			t    wire.Type
			h    wire.Header
			want bool
		}{
			{wire.TypeOpen, wire.Header{Type: wire.TypeOpenAck, Handle: wire.SessionHandle}, true},
			{wire.TypeOpen, wire.Header{Type: wire.TypeOpenAck, Handle: 2}, false},
			{wire.TypeJoin, wire.Header{Type: wire.TypeJoinAck, Handle: wire.SessionHandle}, true},
			{wire.TypeJoin, wire.Header{Type: wire.TypeJoinAck, Handle: 3}, false},
			{wire.TypeOpen, wire.Header{Type: wire.TypeDetach}, false},
			{wire.TypeOpen, wire.Header{Type: wire.TypeClose}, true},
		} {
			if got := responseAllowed(tc.t, tc.h); got != tc.want {
				t.Errorf("responseAllowed(%v, %v handle %d) = %v, want %v", tc.t, tc.h.Type, tc.h.Handle, got, tc.want)
			}
		}
	})
}
