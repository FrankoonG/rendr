package carrier

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP3b tests added by the review of the datagram handshakes: PREFACE-level
// refusals at the dialer, cleared handshake deadlines, the cmtu offer under
// a transport limit below the factory MTU, transport errors while answering
// a rebind challenge, the handshake reads' back-off and withdrawal races.

// TestDatagramDialRefused_L44: the dialer checks the first PREFACE_ACK in
// M1's canonical order (design §5.1; M2 design §A5.10 phase 1): a
// well-formed CAPACITY or GOING_AWAY answer, another major's answer
// (VERSION) and one with unknown required bits (FEATURE) end the attempt at
// once — no H1 copy follows — at stage preface with that Status and, from
// an answer of this major, the passive's instance; an OK answer echoing
// another carrier ID is a protocol violation. Each closes the conn once and
// releases the CarrierID (L44).
func TestDatagramDialRefused_L44(t *testing.T) {
	ackOf := func(penv *Env, a wire.PrefaceAck) []byte {
		b := make([]byte, wire.PrefaceLen)
		a.Minor, a.Instance = wire.Minor, penv.Local
		wire.PutPrefaceAck(b, &a)
		return b
	}
	for _, tc := range []struct {
		name   string
		build  func(penv *Env, id uint32) []byte
		status wire.PrefaceStatus
		cause  Cause
		inst   bool // the error names the passive's instance
	}{
		{"CAPACITY", func(penv *Env, id uint32) []byte {
			return ackOf(penv, wire.PrefaceAck{Status: wire.PrefaceCapacity, CarrierID: id})
		}, wire.PrefaceCapacity, CauseTransportError, true},
		{"GOING_AWAY", func(penv *Env, id uint32) []byte {
			return ackOf(penv, wire.PrefaceAck{Status: wire.PrefaceGoingAway, CarrierID: id})
		}, wire.PrefaceGoingAway, CauseTransportError, true},
		{"another major", func(penv *Env, id uint32) []byte {
			b := ackOf(penv, wire.PrefaceAck{Status: wire.PrefaceOK, CarrierID: id})
			b[4] = wire.Major + 1
			binary.BigEndian.PutUint32(b[36:40], wire.CRC(b[:36]))
			return b
		}, wire.PrefaceVersion, CauseTransportError, false},
		{"unknown required bits", func(penv *Env, id uint32) []byte {
			return ackOf(penv, wire.PrefaceAck{Status: wire.PrefaceOK, Req: 1 << 31, CarrierID: id})
		}, wire.PrefaceFeature, CauseTransportError, true},
		{"another carrier ID echoed", func(penv *Env, id uint32) []byte {
			return ackOf(penv, wire.PrefaceAck{Status: wire.PrefaceOK, CarrierID: id + 1})
		}, wire.PrefaceOK, CauseProtocolViolation, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				r, raws := wbRawRig(t, 1200)
				var closes atomic.Int32
				dial := r.f.DialPacket
				r.f.DialPacket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
					pc, a, err := dial(ctx)
					if pc != nil {
						pc = wbCountPC{pc, &closes}
					}
					return pc, a, err
				}
				ch := make(chan error, 1)
				start := time.Now()
				go func() {
					_, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
					ch <- err
				}()
				w := <-raws
				h1 := w.waitN(t, 1)[0].b
				pf, _ := wire.ParsePreface(h1[:wire.PrefaceLen])
				w.send(tc.build(r.penv, pf.CarrierID))
				err := <-ch
				el := time.Since(start)
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Stage != "preface" || ee.Status != tc.status || ee.Cause != tc.cause || ee.PrefaceOK {
					t.Fatalf("got %v, want stage preface, status %d, cause %v", err, tc.status, tc.cause)
				}
				var want [16]byte
				if tc.inst {
					want = r.penv.Local
				}
				if ee.Instance != want {
					t.Errorf("Instance %x, want %x", ee.Instance, want)
				}
				if el >= 300*time.Millisecond {
					t.Errorf("ended after %v, want at once", el)
				}
				synctest.Wait()
				if n := len(w.received()); n != 1 {
					t.Errorf("%d datagrams written, want H1 alone", n)
				}
				if n := closes.Load(); n != 1 {
					t.Errorf("conn closed %d times, want once", n)
				}
				if r.denv.IDs.inUse() != 0 {
					t.Errorf("the CarrierID was not released")
				}
			})
		})
	}
}

// TestDatagramHandshakeDeadlineCleared: both handshakes clear the
// transport's deadline before they hand the carrier over, so OPEN and
// probe carriers outlive the handshake deadline (10 s) on either side —
// the started reader sets no read deadline of its own.
func TestDatagramHandshakeDeadlineCleared(t *testing.T) {
	for _, typ := range []wire.Type{wire.TypeOpen, wire.TypePing} {
		t.Run(typ.String(), func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				pas := &wbPassive{}
				pas.act = wbAdmit(&dEP{}, nil)
				r := newWBRig(t, 1200, pas.run)
				var payload []byte
				if typ == wire.TypeOpen {
					payload = wbOpen(1100)
				}
				est, err := r.establish(context.Background(), typ, payload)
				if err != nil {
					t.Fatalf("Establish: %v", err)
				}
				if typ == wire.TypeOpen {
					est.Conn.Start(&dEP{}, &hBell{}, StartOptions{})
				} else {
					est.Conn.Start(nil, &hBell{}, StartOptions{Probe: true})
				}
				time.Sleep(15 * time.Second)
				synctest.Wait()
				hs := pas.helloList()
				if len(hs) != 1 {
					t.Fatalf("%d Hellos, want 1", len(hs))
				}
				for _, side := range []struct {
					name string
					c    *Conn
				}{{"dialer", est.Conn}, {"passive", hs[0].Conn}} {
					if dead, cause, detail, _ := side.c.Death(); dead {
						t.Errorf("%s carrier dead 15 s after the handshake: %v %s", side.name, cause, detail)
					}
				}
			})
		})
	}
}

// TestDatagramOfferFollowsLimit: the cmtu offer is min(factory MTU,
// transport Limit) (M2-D50): an *OwnedUDP whose MaxDatagram was clamped
// below the factory's MTU (R1-16's interface-MTU clamp) offers its Limit in
// OPEN.window and JOIN.rxNext, reads the handshake with Limit + Headroom +
// 1 bytes, and the established carrier's budget and receive limit are that
// Limit. Real loopback sockets, outside a synctest bubble.
func TestDatagramOfferFollowsLimit(t *testing.T) {
	const limit = 1000 // MaxDatagram 1009 − the flow header
	for _, typ := range []wire.Type{wire.TypeOpen, wire.TypeJoin} {
		t.Run(typ.String(), func(t *testing.T) {
			denv, penv := wbEnvs()
			pas, _ := wp5Listen(t, "udp4")
			defer pas.Close()
			f := Factory{Index: 0, Name: "owned", Kind: wire.KindDatagram, MTU: 1200, DialPacket: func(context.Context) (net.PacketConn, net.Addr, error) {
				u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					return nil, nil, err
				}
				return NewOwnedUDP(u, wp5AP(pas), wp5Flow, limit+wire.FlowHeaderLen), pas.LocalAddr(), nil
			}}
			type res struct {
				offer int
				err   error
			}
			got := make(chan res, 1)
			go func() {
				buf := make([]byte, 2048)
				_ = pas.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, src, err := pas.ReadFromUDPAddrPort(buf)
				if err != nil {
					got <- res{err: err}
					return
				}
				hdr, rb := buf[:wire.FlowHeaderLen], buf[wire.FlowHeaderLen:n]
				fs, ok := dgDecode(rb[wire.PrefaceLen:])
				if !ok || len(fs) != 1 || fs[0].Type != wire.TypeRel {
					got <- res{err: errors.New("H1 is not PREFACE ‖ REL")}
					return
				}
				_, inner, err := wire.ParseRel(fs[0].Payload)
				if err != nil {
					got <- res{err: err}
					return
				}
				F := penv.Presets.firstCseq()
				h2, nfs := wbH2(penv, rb, F)
				var offer int
				var resp []byte
				if typ == wire.TypeOpen {
					offer = int(binary.BigEndian.Uint32(inner[24:28]))
					resp = relPayloadOf(F, wire.TypeOpenAck, 0, wire.SessionHandle, wbOpenAckOK(900, limit))
				} else {
					offer = int(binary.BigEndian.Uint64(inner[17:25]))
					p := make([]byte, wire.JoinAckLen)
					wire.PutJoinAck(p, &wire.JoinAck{Status: wire.StatusOK, RxNext: limit})
					resp = relPayloadOf(F, wire.TypeJoinAck, 0, wire.SessionHandle, p)
				}
				out := append(bytes.Clone(hdr), h2...)
				out = append(out, wbFrame(wire.TypeRel, 0, nfs, 0, resp)...)
				_, err = pas.WriteToUDPAddrPort(out, src)
				got <- res{offer: offer, err: err}
			}()
			payload := wbOpen(900)
			if typ == wire.TypeJoin {
				payload = wbJoin()
			}
			est, err := Establish(context.Background(), denv, f, denv.IDs.Next(), typ, payload, nil)
			if err != nil {
				t.Fatalf("Establish: %v", err)
			}
			defer func() {
				est.Conn.Kill(CauseLocalClose, "test end")
				<-est.Conn.Done()
			}()
			p := <-got
			if p.err != nil {
				t.Fatalf("passive: %v", p.err)
			}
			c := est.Conn
			if p.offer != limit || c.MTU() != limit || c.RecvLimit() != limit {
				t.Errorf("offer %d, MTU %d, RecvLimit %d; want the transport Limit %d", p.offer, c.MTU(), c.RecvLimit(), limit)
			}
			if n := c.dg.io.ReadSize(); n != limit+wire.FlowHeaderLen+1 {
				t.Errorf("ReadSize %d, want %d", n, limit+wire.FlowHeaderLen+1)
			}
		})
	}
}

// TestEstablishChallengeWriteError: a write that fails while answering a
// rebind challenge before the response — before or after the PREFACE_ACK —
// is a transport error of the attempt, not a protocol violation.
func TestEstablishChallengeWriteError(t *testing.T) {
	errDead := errors.New("conn gone")
	for _, tc := range []struct {
		name  string
		h2    bool // the challenge follows H2 in its datagram
		stage string
	}{
		{"before the PREFACE_ACK", false, "preface"},
		{"after the PREFACE_ACK", true, "response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				denv, penv := wbEnvs()
				peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
				pc := newWBPC()
				pc.wfn = func(p []byte, _ net.Addr) (int, error) {
					if !wire.IsPreface(p) && hasType(p, wire.TypePong) {
						return 0, errDead
					}
					return len(p), nil
				}
				f := Factory{Index: 0, Name: "c", Kind: wire.KindDatagram, MTU: 1200, DialPacket: func(context.Context) (net.PacketConn, net.Addr, error) {
					return pc, peer, nil
				}}
				ch := make(chan error, 1)
				go func() {
					_, err := Establish(context.Background(), denv, f, denv.IDs.Next(), wire.TypeOpen, wbOpen(1100), nil)
					ch <- err
				}()
				synctest.Wait()
				h1 := pc.written()[0].b
				h2, fs := wbH2(penv, h1, penv.Presets.firstCseq())
				chal := wbFrame(wire.TypePing, 0, fs, 0, wbPingPayload(wire.Ping{ID: 0, Nonce: 3}))
				if tc.h2 {
					chal = append(h2, chal...)
				}
				pc.push(wbRead{b: chal, src: peer})
				err := <-ch
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != CauseTransportError || ee.Stage != tc.stage || !errors.Is(err, errDead) {
					t.Fatalf("got %v, want a transport error at stage %s", err, tc.stage)
				}
			})
		})
	}
}

// TestHandshakeReadsBackOff_R1_27: a transport that hands an endless run of
// empty datagrams to a handshake read — the dialer's and the passive's —
// is read spinIdle times at once and then at the back-off of 5 ms doubling
// to 100 ms, so no core spins until the handshake deadline (M2-D15, R1-27).
func TestHandshakeReadsBackOff_R1_27(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	const endless = 100000
	check := func(t *testing.T, pc *wbPC) {
		t.Helper()
		time.Sleep(time.Second)
		synctest.Wait()
		// spinIdle reads, then after 5+10+20+40+80 ms one each 100 ms.
		if n := pc.nreads.Load(); n < spinIdle || n > spinIdle+20 {
			t.Errorf("%d reads in the first second, want %d..%d", n, spinIdle, spinIdle+20)
		}
	}
	t.Run("dialer", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			env := dgEnv()
			pc := newWBPC()
			pc.spin, pc.spinSrc = endless, peer
			f := Factory{Index: 0, Name: "s", Kind: wire.KindDatagram, MTU: 1200, DialPacket: func(context.Context) (net.PacketConn, net.Addr, error) {
				return pc, peer, nil
			}}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = Establish(ctx, env, f, env.IDs.Next(), wire.TypeOpen, wbOpen(1100), nil)
			}()
			check(t, pc)
			cancel()
			<-done
		})
	})
	t.Run("passive", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			env := dgEnv()
			pc := newWBPC()
			pc.spin, pc.spinSrc = endless, peer
			io, err := NewPacketIO(env, pc, peer, wire.MaxDatagram)
			if err != nil {
				t.Fatal(err)
			}
			ch := wbReadHello(env, io, nil)
			check(t, pc)
			pc.Close()
			<-ch
		})
	})
}

// TestDatagramWithdrawRaces_L49: a withdrawal that lands while the
// handshake re-arms its read deadline — after the abort's SetDeadline(now)
// — still ends the attempt at once with the RST(withdrawn) datagram; one
// that lands after the response was read but before the carrier was built
// returns no carrier, with the RST (L49).
func TestDatagramWithdrawRaces_L49(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	rsts := func(pc *wbPC, F uint32) int {
		n := 0
		for _, w := range pc.written() {
			for _, h := range wbRelsIn(w.b) {
				if h.Type == wire.TypeRst && h.Cseq == F+1 {
					n++
				}
			}
		}
		return n
	}
	for _, tc := range []struct {
		name string
		at   time.Duration // the withdrawal (the second read deadline: the first H1 copy)
		resp bool          // withdrawn while the response is being read
	}{
		{"while re-arming the read deadline", 300 * time.Millisecond, false},
		{"after the response was read", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				denv, penv := wbEnvs()
				F := denv.Presets.firstCseq()
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				pc := newWBHookPC()
				withdraw := func() {
					cancel(ErrWithdrawn)
					<-pc.setNow // the abort's SetDeadline(now) took effect
				}
				if tc.resp {
					pc.afterRead = withdraw
				} else {
					pc.trigger, pc.onSetRead = 2, withdraw
				}
				var closes atomic.Int32
				f := Factory{Index: 0, Name: "w", Kind: wire.KindDatagram, MTU: 1200, DialPacket: func(context.Context) (net.PacketConn, net.Addr, error) {
					return wbCountPC{pc, &closes}, peer, nil
				}}
				type res struct {
					est *Established
					err error
					at  time.Duration
				}
				ch := make(chan res, 1)
				start := time.Now()
				go func() {
					est, err := Establish(ctx, denv, f, denv.IDs.Next(), wire.TypeOpen, wbOpen(1100), nil)
					ch <- res{est, err, time.Since(start)}
				}()
				if tc.resp {
					synctest.Wait()
					h1 := pc.written()[0].b
					h2, fs := wbH2(penv, h1, F)
					pc.push(wbRead{b: append(h2, wbFrame(wire.TypeRel, 0, fs, 0, relPayloadOf(F, wire.TypeOpenAck, 0, wire.SessionHandle, wbOpenAckOK(1100, 1200)))...), src: peer})
				}
				x := <-ch
				if x.est != nil {
					x.est.Conn.Kill(CauseLocalClose, "test end")
					<-x.est.Conn.Done()
					t.Fatalf("a withdrawn attempt returned a carrier")
				}
				var ee *EstablishError
				if !errors.As(x.err, &ee) || ee.Cause != CauseLocalClose || !errors.Is(x.err, ErrWithdrawn) {
					t.Fatalf("got %v, want the withdrawal", x.err)
				}
				if x.at != tc.at {
					t.Errorf("ended after %v, want %v", x.at, tc.at)
				}
				synctest.Wait()
				if n := rsts(pc.wbPC, F); n != 1 {
					t.Errorf("%d RST(withdrawn) datagrams, want 1", n)
				}
				if n := closes.Load(); n != 1 {
					t.Errorf("conn closed %d times, want once", n)
				}
				if denv.IDs.inUse() != 0 {
					t.Errorf("the CarrierID was not released")
				}
			})
		})
	}
}

// TestDatagramHelloMetaTooLarge: a datagram OPEN H1 whose metadata exceeds
// maxMeta is answered (H2) and handed over with MetaTooLarge and no
// payload, for the admission's BAD_REQUEST; one at maxMeta keeps its
// payload.
func TestDatagramHelloMetaTooLarge(t *testing.T) {
	for _, tc := range []struct {
		meta  int
		large bool
	}{{255, false}, {256, true}} {
		t.Run(fmt.Sprint(tc.meta), func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				denv, penv := wbEnvs()
				a, b := newFakeIOPair(1500)
				defer a.Close()
				ch := wbReadHello(penv, b, nil) // maxMeta 255
				open := make([]byte, wire.OpenFixedLen+tc.meta)
				wire.PutOpen(open, &wire.Open{SID: wbSID, Kind: wire.KindDatagram, Mode: 1, RetainMs: 30000, PMTU: 1100, Metadata: bytes.Repeat([]byte{'m'}, tc.meta)})
				_ = a.WriteDatagram(wbH1(denv, 9, wire.TypeOpen, open))
				r := <-ch
				if r.err != nil {
					t.Fatalf("meta %d: %v", tc.meta, r.err)
				}
				defer func() {
					r.h.Conn.Kill(CauseLocalClose, "test end")
					<-r.h.Conn.Done()
				}()
				if r.h.MetaTooLarge != tc.large || (tc.large && r.h.Payload != nil) || (!tc.large && !bytes.Equal(r.h.Payload, open)) {
					t.Errorf("meta %d: MetaTooLarge %v, payload %d bytes; want %v", tc.meta, r.h.MetaTooLarge, len(r.h.Payload), tc.large)
				}
				synctest.Wait()
				if d, ok := a.tryRead(); !ok || !bytes.Equal(d, r.h.Conn.dg.hs.h2()) {
					t.Errorf("meta %d: no H2", tc.meta)
				}
			})
		})
	}
}
