package carrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

var hPassiveInst = [16]byte{0xcc, 15: 0xcc}

// hPrefaceAck encodes a well-formed PREFACE_ACK.
func hPrefaceAck(status wire.PrefaceStatus, id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPrefaceAck(b, &wire.PrefaceAck{Minor: wire.Minor, Status: status, Instance: hPassiveInst, CarrierID: id})
	return b
}

// scriptedPassive is the passive end of an Establish test: it reads the
// dialer's PREFACE and first frame, then writes answer, then reads until
// EOF (everything after the first frame lands in after).
type scriptedPassive struct {
	preface wire.Preface
	first   wire.Frame
	after   []byte
	err     error
	done    chan struct{}
}

func runPassive(nc net.Conn, answer func(p wire.Preface, f wire.Frame) []byte) *scriptedPassive {
	s := &scriptedPassive{done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer nc.Close()
		var pb [wire.PrefaceLen]byte
		if _, s.err = io.ReadFull(nc, pb[:]); s.err != nil {
			return
		}
		if s.preface, s.err = wire.ParsePreface(pb[:]); s.err != nil {
			return
		}
		var hb [wire.HeaderLen]byte
		if _, s.err = io.ReadFull(nc, hb[:]); s.err != nil {
			return
		}
		h, err := wire.ParseHeader(hb[:])
		if err != nil {
			s.err = err
			return
		}
		rest := make([]byte, int(h.Len)+wire.TrailerLen)
		if _, s.err = io.ReadFull(nc, rest); s.err != nil {
			return
		}
		f, _, err := wire.DecodeFrame(append(hb[:], rest...))
		if err != nil {
			s.err = err
			return
		}
		s.first = wire.Frame{Header: f.Header, Payload: bytes.Clone(f.Payload)}
		if a := answer(s.preface, s.first); a != nil {
			go nc.Write(a)
		}
		s.after, _ = io.ReadAll(nc)
	}()
	return s
}

// pipeFactory returns a factory whose conns are one end of a net.Pipe; the
// other ends are delivered on the returned channel.
func pipeFactory(index int, name string) (Factory, <-chan net.Conn) {
	ch := make(chan net.Conn, 8)
	return Factory{Index: index, Name: name, Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		ch <- b
		return a, nil
	}}, ch
}

// frameAt encodes a frame with an explicit fseq.
func frameAt(t wire.Type, flags uint8, fseq, handle uint32, payload []byte) []byte {
	return wire.AppendFrame(nil, wire.Header{Type: t, Flags: flags, Fseq: fseq, Handle: handle}, payload)
}

func okOpenAck() []byte {
	var p [wire.OpenAckFixedLen]byte
	wire.PutOpenAck(p[:], &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20})
	return p[:]
}

// TestEstablishVersionMapping_L44 (P19, design §5.1): a PREFACE_ACK of
// another major (valid magic and CRC, the rest in its own format), a
// well-formed VERSION or FEATURE status and unknown required bits all map
// to Status VERSION/FEATURE (→ ErrVersion), GOING_AWAY and CAPACITY keep
// their status; malformed answers (bad CRC, magic, role, status, zero
// instance, carrier-ID echo) are carrier errors with no status. Every
// answer is classified at once, never by a timeout.
func TestEstablishVersionMapping_L44(t *testing.T) {
	const id = 31
	good := hPrefaceAck(wire.PrefaceOK, id)
	cases := []struct {
		name   string
		ack    []byte
		status wire.PrefaceStatus
		cause  Cause
	}{
		{"major 1", recrc(edit(good, func(b []byte) { b[4] = 1 })), wire.PrefaceVersion, CauseTransportError},
		{"major 3 own format", recrc(edit(good, func(b []byte) { b[4] = 3; b[6] = 0x77; b[7] = 9; clear(b[16:36]) })), wire.PrefaceVersion, CauseTransportError},
		{"VERSION", hPrefaceAck(wire.PrefaceVersion, id), wire.PrefaceVersion, CauseTransportError},
		{"FEATURE", hPrefaceAck(wire.PrefaceFeature, id), wire.PrefaceFeature, CauseTransportError},
		{"unknown required bit", recrc(edit(good, func(b []byte) { b[8] = 0x80 })), wire.PrefaceFeature, CauseTransportError},
		{"GOING_AWAY", hPrefaceAck(wire.PrefaceGoingAway, id), wire.PrefaceGoingAway, CauseTransportError},
		{"CAPACITY", hPrefaceAck(wire.PrefaceCapacity, id), wire.PrefaceCapacity, CauseTransportError},
		{"bad crc", edit(good, func(b []byte) { b[39] ^= 1 }), wire.PrefaceOK, CauseProtocolViolation},
		{"bad magic", recrc(edit(good, func(b []byte) { b[0] = 'X' })), wire.PrefaceOK, CauseProtocolViolation},
		{"dialer role", recrc(edit(good, func(b []byte) { b[7] = byte(wire.RoleDialer) })), wire.PrefaceOK, CauseProtocolViolation},
		{"undefined status", recrc(edit(good, func(b []byte) { b[6] = 9 })), wire.PrefaceOK, CauseProtocolViolation},
		{"zero instance", recrc(edit(good, func(b []byte) { clear(b[16:32]) })), wire.PrefaceOK, CauseProtocolViolation},
		{"carrier id echo", hPrefaceAck(wire.PrefaceOK, id+1), wire.PrefaceOK, CauseProtocolViolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				f, ends := pipeFactory(0, "f0")
				go func() {
					runPassive(<-ends, func(wire.Preface, wire.Frame) []byte { return tc.ack })
				}()
				start := time.Now()
				est, err := Establish(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), nil)
				var ee *EstablishError
				if est != nil || !errors.As(err, &ee) {
					t.Fatalf("Establish: %v %v", est, err)
				}
				if ee.Stage != "preface" || ee.Status != tc.status || ee.Cause != tc.cause || ee.PrefaceOK {
					t.Fatalf("error %+v, want status %v cause %v", ee, tc.status, tc.cause)
				}
				if v2answer := tc.status != wire.PrefaceOK && tc.name != "major 1" && tc.name != "major 3 own format"; v2answer != (ee.Instance == hPassiveInst) {
					t.Fatalf("instance %v reported for %s", ee.Instance, tc.name)
				}
				if d := time.Since(start); d != 0 {
					t.Fatalf("classified after %v", d)
				}
				synctest.Wait()
				if env.IDs.inUse() != 0 {
					t.Fatal("a failed attempt kept its carrier ID")
				}
			})
		})
	}
}

// TestEstablishFirstFrameAndCounters_L14 (C10): Establish builds and stamps
// the first frame itself — PREFACE with this Runtime's instance and the
// carrier ID, OPEN or JOIN with the preset first fseq and handle 1 — and
// the Conn's counters continue after it in both directions; the response
// is validated (canonical OPEN_ACK, type matching the request, CLOSE or
// GOAWAY accepted, DATA before OPEN_ACK refused).
func TestEstablishFirstFrameAndCounters_L14(t *testing.T) {
	const first = 0xfffffffe
	t.Run("OPEN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Presets.FirstFseq = first
			f, ends := pipeFactory(3, "f3")
			id := env.IDs.Next()
			spc := make(chan *scriptedPassive, 1)
			go func() {
				spc <- runPassive(<-ends, func(wire.Preface, wire.Frame) []byte {
					return append(hPrefaceAck(wire.PrefaceOK, id), frameAt(wire.TypeOpenAck, 0, first, wire.SessionHandle, okOpenAck())...)
				})
			}()
			est, err := Establish(context.Background(), env, f, id, wire.TypeOpen, openPayload(10), nil)
			if err != nil {
				t.Fatal(err)
			}
			sp := <-spc
			if sp.preface.Instance != env.Local || sp.preface.CarrierID != id || sp.preface.Kind != wire.KindStream {
				t.Fatalf("PREFACE %+v", sp.preface)
			}
			if sp.first.Type != wire.TypeOpen || sp.first.Fseq != first || sp.first.Handle != wire.SessionHandle || !bytes.Equal(sp.first.Payload, openPayload(10)) {
				t.Fatalf("first frame %+v", sp.first.Header)
			}
			c := est.Conn
			if est.Resp.Type != wire.TypeOpenAck || !bytes.Equal(est.Payload, okOpenAck()) || est.Ack.Instance != hPassiveInst {
				t.Fatalf("established %+v", est)
			}
			if c.ID() != id || c.PeerInstance() != hPassiveInst || c.Factory() != 3 || c.Name() != "f3" {
				t.Fatalf("conn identity %d %v %d %q", c.ID(), c.PeerInstance(), c.Factory(), c.Name())
			}
			if c.wr.fseq != first+1 || c.rd.fseq != first+1 {
				t.Fatalf("counters continue at tx %#x rx %#x", c.wr.fseq, c.rd.fseq)
			}
			c.Kill(CauseLocalClose, "test end")
			hWait(t, c)
			<-sp.done
			if env.IDs.inUse() != 0 {
				t.Fatal("the carrier ID was not released at Done")
			}
		})
	})
	t.Run("JOIN and the counters after it", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Presets.FirstFseq = first
			a, b := net.Pipe()
			f := Factory{Name: "j", Dial: func(context.Context) (net.Conn, error) { return a, nil }}
			var jp [wire.JoinLen]byte
			wire.PutJoin(jp[:], &wire.Join{SID: [16]byte{3, 15: 3}, Mode: 1, RxNext: 9})
			var ja [wire.JoinAckLen]byte
			wire.PutJoinAck(ja[:], &wire.JoinAck{Status: wire.StatusOK, RxNext: 4})
			go func() {
				var buf [wire.PrefaceLen + wire.FrameOverhead + wire.JoinLen]byte
				io.ReadFull(b, buf[:])
				b.Write(append(hPrefaceAck(wire.PrefaceOK, 77), frameAt(wire.TypeJoinAck, 0, first, wire.SessionHandle, ja[:])...))
			}()
			est, err := Establish(context.Background(), env, f, 77, wire.TypeJoin, jp[:], nil)
			if err != nil || est.Resp.Type != wire.TypeJoinAck {
				t.Fatalf("Establish %+v %v", est, err)
			}
			// Started, the carrier's frames continue the counters: the
			// dialer's next frame is first+1 (wrapping to 0 next), and it
			// accepts the passive's frames from first+1 on.
			synctest.Wait()
			p := startPeer(b, first+1)
			p.autoPong(nil)
			est.Conn.Start(&hEP{}, &hBell{}, StartOptions{})
			if err := p.ping(1, false); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if dead, cause, detail, _ := est.Conn.Death(); dead {
				t.Fatalf("died: %v %s", cause, detail)
			}
			if fr := p.received(); len(fr) < 2 || fr[0].Fseq != first+1 || fr[1].Fseq != 0 {
				t.Fatalf("frames after establishment %+v", fr)
			}
			est.Conn.Kill(CauseLocalClose, "test end")
			hWait(t, est.Conn)
			p.close()
		})
	})
	for _, tc := range []struct {
		name string
		resp []byte
		ok   bool
	}{
		{"CLOSE", frameAt(wire.TypeClose, 0, first, 0, []byte{byte(wire.CloseCapacity)}), true},
		{"GOAWAY", frameAt(wire.TypeGoAway, 0, first, 0, []byte{byte(wire.GoAwayShutdown)}), true},
		{"DATA before OPEN_ACK", frameAt(wire.TypeData, 0, first, wire.SessionHandle, dataPayload(0, 4)), false},
		{"JOIN_ACK for an OPEN", frameAt(wire.TypeJoinAck, 0, first, wire.SessionHandle, make([]byte, wire.JoinAckLen)), false},
		{"non-canonical OPEN_ACK", frameAt(wire.TypeOpenAck, 0, first, wire.SessionHandle, append([]byte{0, 0, 0, 0, 1, 0, 0, 0, 5}, 0)), false},
		{"wrong fseq", frameAt(wire.TypeOpenAck, 0, first+1, wire.SessionHandle, okOpenAck()), false},
		{"crc", func() []byte {
			b := frameAt(wire.TypeOpenAck, 0, first, wire.SessionHandle, okOpenAck())
			b[len(b)-1] ^= 1
			return b
		}(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				env.Presets.FirstFseq = first
				f, ends := pipeFactory(0, "f0")
				go func() {
					runPassive(<-ends, func(wire.Preface, wire.Frame) []byte {
						return append(hPrefaceAck(wire.PrefaceOK, 5), tc.resp...)
					})
				}()
				est, err := Establish(context.Background(), env, f, 5, wire.TypeOpen, openPayload(0), nil)
				if tc.ok {
					if err != nil || est.Resp.Type != wire.Type(tc.resp[0]) {
						t.Fatalf("Establish %+v %v", est, err)
					}
					est.Conn.Kill(CauseLocalClose, "test end")
					hWait(t, est.Conn)
					return
				}
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Stage != "response" || ee.Cause != CauseProtocolViolation || !ee.PrefaceOK || ee.Instance != hPassiveInst {
					t.Fatalf("err %v (%+v)", err, ee)
				}
				synctest.Wait()
			})
		})
	}
}

// TestEstablishInstanceCheck (C9): check sees every PREFACE_ACK(OK); its
// rejection ends the attempt as instance_mismatch with the PREFACE exchange
// completed, and an OPEN is followed by a best-effort RST(withdrawn) (the
// dialer's next fseq) so that the other instance keeps no pending session;
// a rejected JOIN gets no RST (an RST would end the session).
func TestEstablishInstanceCheck(t *testing.T) {
	for _, t0 := range []wire.Type{wire.TypeOpen, wire.TypeJoin} {
		t.Run(t0.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				f, ends := pipeFactory(0, "f0")
				spc := make(chan *scriptedPassive, 1)
				go func() {
					spc <- runPassive(<-ends, func(wire.Preface, wire.Frame) []byte { return hPrefaceAck(wire.PrefaceOK, 8) })
				}()
				payload := openPayload(0)
				if t0 == wire.TypeJoin {
					payload = make([]byte, wire.JoinLen)
					wire.PutJoin(payload, &wire.Join{SID: [16]byte{9, 15: 9}, Mode: 1})
				}
				var seen [16]byte
				errOther := errors.New("not the bound instance")
				_, err := Establish(context.Background(), env, f, 8, t0, payload, func(a *wire.PrefaceAck) error {
					seen = a.Instance
					return errOther
				})
				var ee *EstablishError
				if !errors.As(err, &ee) || !errors.Is(err, errOther) || ee.Cause != CauseInstanceMismatch || !ee.PrefaceOK || ee.Instance != hPassiveInst || seen != hPassiveInst {
					t.Fatalf("err %v (%+v)", err, ee)
				}
				sp := <-spc
				<-sp.done
				if t0 == wire.TypeJoin {
					if len(sp.after) != 0 {
						t.Fatalf("%d bytes after a rejected JOIN", len(sp.after))
					}
					return
				}
				fr, n, err := wire.DecodeFrame(sp.after)
				if err != nil || n != len(sp.after) || fr.Type != wire.TypeRst || fr.Fseq != env.Presets.firstFseq()+1 {
					t.Fatalf("after the OPEN: %+v %v", fr.Header, err)
				}
				if r, err := wire.ParseRst(fr.Payload); err != nil || r.Code != wire.RstWithdrawn {
					t.Fatalf("RST %+v %v", r, err)
				}
			})
		})
	}
}

// TestEstablishWithdrawnSendsRst_L49: when the session withdraws (ctx
// cancelled with cause ErrWithdrawn) while an OPEN waits for its answer,
// Establish returns at once and the passive reads RST(withdrawn) after the
// OPEN; a plain cancellation closes without an RST; a passive that never
// answers ends the attempt at DialTimeout as a carrier error.
func TestEstablishWithdrawnSendsRst_L49(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cancel   time.Duration
		withdraw bool
		took     time.Duration
		cause    Cause
	}{
		{"withdrawn", 100 * time.Millisecond, true, 100 * time.Millisecond, CauseLocalClose},
		{"cancelled", 100 * time.Millisecond, false, 100 * time.Millisecond, CauseLocalClose},
		{"silent passive", 0, false, 10 * time.Second, CauseTransportError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				f, ends := pipeFactory(0, "f0")
				spc := make(chan *scriptedPassive, 1)
				go func() {
					spc <- runPassive(<-ends, func(wire.Preface, wire.Frame) []byte { return hPrefaceAck(wire.PrefaceOK, 4) })
				}()
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				if tc.cancel > 0 {
					cause := errors.New("dial abandoned")
					if tc.withdraw {
						cause = ErrWithdrawn
					}
					time.AfterFunc(tc.cancel, func() { cancel(cause) })
				}
				start := time.Now()
				_, err := Establish(ctx, env, f, 4, wire.TypeOpen, openPayload(0), nil)
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != tc.cause || time.Since(start) != tc.took {
					t.Fatalf("after %v: %v", time.Since(start), err)
				}
				if tc.withdraw != errors.Is(err, ErrWithdrawn) {
					t.Fatalf("err %v: withdrawn %v", err, tc.withdraw)
				}
				sp := <-spc
				<-sp.done
				if !tc.withdraw {
					if len(sp.after) != 0 {
						t.Fatalf("%d bytes after the OPEN", len(sp.after))
					}
					return
				}
				fr, _, err := wire.DecodeFrame(sp.after)
				if err != nil || fr.Type != wire.TypeRst || fr.Fseq != env.Presets.firstFseq()+1 {
					t.Fatalf("after the OPEN: %+v %v", fr.Header, err)
				}
				if r, _ := wire.ParseRst(fr.Payload); r.Code != wire.RstWithdrawn {
					t.Fatalf("RST code %d", r.Code)
				}
			})
		})
	}
}

// TestEstablishProbePing (C10, D26): a probe carrier's first frame is a
// PING with the preset first id and a nonce bound to the Conn's salt; the
// answer must be a PONG echoing both (a foreign nonce is a protocol
// violation; CLOSE(capacity) is returned as the response); the
// establishment PONG is no RTT sample, and the started carrier's next PING
// takes the next id.
func TestEstablishProbePing(t *testing.T) {
	const firstID = 0xffffffff
	for _, tc := range []struct {
		name string
		resp func(ping wire.Ping) []byte
		ok   bool
	}{
		{"PONG", func(p wire.Ping) []byte { return frameAt(wire.TypePong, 0, 1, 0, pingPayload(p)) }, true},
		{"CLOSE capacity", func(wire.Ping) []byte { return frameAt(wire.TypeClose, 0, 1, 0, []byte{byte(wire.CloseCapacity)}) }, true},
		{"foreign nonce", func(p wire.Ping) []byte { p.Nonce++; return frameAt(wire.TypePong, 0, 1, 0, pingPayload(p)) }, false},
		{"padded PONG", func(p wire.Ping) []byte { p.Pad = 4; return frameAt(wire.TypePong, 0, 1, 0, pingPayload(p)) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				env.Presets.FirstPingID = firstID
				a, b := net.Pipe()
				f := Factory{Name: "probe", Dial: func(context.Context) (net.Conn, error) { return a, nil }}
				var got wire.Ping
				go func() {
					var buf [wire.PrefaceLen + wire.FrameOverhead + wire.PingFixedLen]byte
					io.ReadFull(b, buf[:])
					fr, _, _ := wire.DecodeFrame(buf[wire.PrefaceLen:])
					got, _ = wire.ParsePing(fr.Payload)
					b.Write(append(hPrefaceAck(wire.PrefaceOK, 6), tc.resp(got)...))
				}()
				est, err := Establish(context.Background(), env, f, 6, wire.TypePing, nil, nil)
				if !tc.ok {
					var ee *EstablishError
					if !errors.As(err, &ee) || ee.Cause != CauseProtocolViolation {
						t.Fatalf("err %v", err)
					}
					b.Close()
					synctest.Wait()
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				c := est.Conn
				if got.ID != firstID || got.Nonce != c.salt^firstID {
					t.Fatalf("establishment PING %+v (salt %#x)", got, c.salt)
				}
				if est.Resp.Type == wire.TypeClose {
					c.Kill(CauseLocalClose, "capacity")
					hWait(t, c)
					b.Close()
					return
				}
				p := startPeer(b, 2)
				p.autoPong(func(uint32) time.Duration { return 5 * time.Millisecond })
				c.Start(nil, &hBell{}, StartOptions{Probe: true, Observer: &hObserver{}})
				synctest.Wait()
				if c.SRTT() != 0 {
					t.Fatal("the establishment PONG became an RTT sample")
				}
				time.Sleep(10 * time.Millisecond)
				fr := p.received()
				if len(fr) == 0 || fr[0].Type != wire.TypePing {
					t.Fatalf("frames %+v", fr)
				}
				if pg, _ := wire.ParsePing(fr[0].Payload); pg.ID != 0 || c.SRTT() != 5*time.Millisecond {
					t.Fatalf("next PING id %d (want the wrap to 0), srtt %v", pg.ID, c.SRTT())
				}
				c.Kill(CauseLocalClose, "test end")
				hWait(t, c)
				p.close()
			})
		})
	}
}

// TestEstablishDialEarly: with DialEarly the factory receives PREFACE ‖
// first frame exactly and sends them itself; Establish writes nothing more
// before it reads the answer.
func TestEstablishDialEarly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		var early []byte
		f, ends := pipeFactory(0, "early")
		f.DialEarly = func(ctx context.Context, first []byte) (net.Conn, error) {
			early = bytes.Clone(first)
			nc, err := f.Dial(ctx)
			if err == nil {
				go nc.Write(early) // the embedder's open request carries them (a copy: first is not retained)
			}
			return nc, err
		}
		spc := make(chan *scriptedPassive, 1)
		go func() {
			spc <- runPassive(<-ends, func(wire.Preface, wire.Frame) []byte {
				return append(hPrefaceAck(wire.PrefaceOK, 12), frameAt(wire.TypeOpenAck, 0, 1, wire.SessionHandle, okOpenAck())...)
			})
		}()
		est, err := Establish(context.Background(), env, f, 12, wire.TypeOpen, openPayload(3), nil)
		if err != nil {
			t.Fatal(err)
		}
		if p, err := wire.ParsePreface(early[:wire.PrefaceLen]); err != nil || p.CarrierID != 12 {
			t.Fatalf("early PREFACE %+v %v", p, err)
		}
		if fr, n, err := wire.DecodeFrame(early[wire.PrefaceLen:]); err != nil || fr.Type != wire.TypeOpen || wire.PrefaceLen+n != len(early) {
			t.Fatalf("early first frame %+v %v", fr.Header, err)
		}
		est.Conn.Kill(CauseLocalClose, "test end")
		hWait(t, est.Conn)
		sp := <-spc
		<-sp.done
		if len(sp.after) != 0 {
			t.Fatalf("Establish wrote %d more bytes after DialEarly", len(sp.after))
		}
	})
}
