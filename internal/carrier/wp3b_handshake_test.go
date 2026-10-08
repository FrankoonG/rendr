package carrier

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// WP3b tests of the dialer's datagram handshake (M2 design §A5.10;
// M2-D19, M2-D20; Revision 1, R1-1, R1-3, R1-14).

// TestDatagramHandshakeResend_L12_L44: an H1 lost k times is resent
// verbatim — the same bytes, its frame a window duplicate at the passive —
// at RelRTOInit doubling, and the passive keeps one Hello; an H2 lost is
// repeated identically (the stored bytes) for the duplicate H1, with no new
// state (M2-D19; L12, L44; PA-21).
func TestDatagramHandshakeResend_L12_L44(t *testing.T) {
	t.Run("H1 lost twice", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			pas := &wbPassive{}
			pas.act = wbAdmit(&dEP{}, nil)
			r := newWBRig(t, 1200, pas.run)
			var caps []<-chan []byte
			for range 3 {
				caps = append(caps, r.link.CaptureNext(rendrtest.Up, rendrtest.FrameRel))
			}
			r.link.DropNext(rendrtest.Up, rendrtest.FrameRel, 2)
			start := time.Now()
			est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
			if err != nil {
				t.Fatalf("Establish: %v", err)
			}
			if el := time.Since(start); el < 900*time.Millisecond || el > 950*time.Millisecond {
				t.Errorf("established after %v, want the third copy's 0.9 s", el)
			}
			var copies [][]byte
			for i, ch := range caps {
				select {
				case b := <-ch:
					copies = append(copies, b)
				default:
					t.Fatalf("copy %d of H1 not captured", i)
				}
			}
			for i, c := range copies {
				if !wire.IsPreface(c) || !bytes.Equal(c, copies[0]) {
					t.Errorf("copy %d differs from the first H1:\n% x\n% x", i, c, copies[0])
				}
			}
			if n := est.Conn.Stats().Retransmits; n != 2 {
				t.Errorf("Retransmits %d, want 2 (H1 copies)", n)
			}
			if n := len(pas.helloList()); n != 1 {
				t.Errorf("%d Hellos, want 1", n)
			}
		})
	})
	t.Run("H2 lost", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			pas := &wbPassive{}
			pas.act = wbAdmit(&dEP{}, nil)
			r := newWBRig(t, 1200, pas.run)
			h2a := r.link.CaptureNext(rendrtest.Down, rendrtest.FrameRack)
			h2b := r.link.CaptureNext(rendrtest.Down, rendrtest.FrameRack)
			r.link.DropNext(rendrtest.Down, rendrtest.FrameRack, 1)
			est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
			if err != nil {
				t.Fatalf("Establish: %v", err)
			}
			a, b := <-h2a, <-h2b
			if !wire.IsPreface(a) || !bytes.Equal(a, b) {
				t.Errorf("the repeated H2 differs from the stored one:\n% x\n% x", b, a)
			}
			if !bytes.Equal(a[:wire.PrefaceLen], est.Conn.dg.hs.ack) {
				t.Errorf("the dialer kept another PREFACE_ACK")
			}
			if n := len(pas.helloList()); n != 1 {
				t.Errorf("%d Hellos, want 1: a duplicate H1 created state", n)
			}
			if n := est.Conn.Stats().Retransmits; n < 1 {
				t.Errorf("Retransmits %d: the H2 loss was not repaired by an H1 copy", n)
			}
		})
	})
}

// TestDatagramHandshakeSchedule_PA13: on a black hole the H1 copies leave
// at 0, 0.3, 0.9, 2.1, 4.1, 6.1 and 8.1 s, stop Handshake.Timeout after the
// first, and the attempt ends at DialTimeout; the next attempt's first H1
// follows at once, so two copies of a factory are never more than 2 s
// apart (PA-13's T_gap).
func TestDatagramHandshakeSchedule_PA13(t *testing.T) {
	ms := func(v ...int) []time.Duration {
		out := make([]time.Duration, len(v))
		for i, x := range v {
			out[i] = time.Duration(x) * time.Millisecond
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		handshake time.Duration
		want      []time.Duration
	}{
		{"full schedule", 10 * time.Second, ms(0, 300, 900, 2100, 4100, 6100, 8100)},
		{"stops at Handshake.Timeout", 2500 * time.Millisecond, ms(0, 300, 900, 2100)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				r, raws := wbRawRig(t, 1200)
				r.denv.Timing.HandshakeTimeout = tc.handshake
				var last time.Time
				for attempt := range 2 {
					start := time.Now()
					_, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
					var ee *EstablishError
					if !errors.As(err, &ee) || ee.Stage != "preface" || ee.Cause != CauseTransportError || !errors.Is(err, errDialTimeout) {
						t.Fatalf("attempt %d: %v, want a dial timeout at stage preface", attempt, err)
					}
					if el := time.Since(start); el != 10*time.Second {
						t.Errorf("attempt %d ended after %v, want DialTimeout 10 s", attempt, el)
					}
					w := <-raws
					synctest.Wait()
					got := w.received()
					if len(got) != len(tc.want) {
						t.Fatalf("attempt %d: %d copies, want %d", attempt, len(got), len(tc.want))
					}
					for i, g := range got {
						if at := g.at.Sub(start); at != tc.want[i] {
							t.Errorf("attempt %d copy %d at %v, want %v", attempt, i, at, tc.want[i])
						}
						if !bytes.Equal(g.b, got[0].b) {
							t.Errorf("attempt %d copy %d is not verbatim", attempt, i)
						}
					}
					if attempt == 1 {
						if gap := got[0].at.Sub(last); gap > 2*time.Second && tc.handshake == 10*time.Second {
							t.Errorf("gap across attempts %v, want ≤ 2 s", gap)
						}
					}
					last = got[len(got)-1].at
				}
			})
		})
	}
	t.Run("a RACK stops the copies", func(t *testing.T) {
		// H2's RACK covers H1's REL: its retransmission ends; while H3 is
		// delayed by 4.5 s only keepalive copies follow, verbatim, every
		// RelRTOMax after the RACK (integration 2, K5), and none counts as a
		// retransmission; H3 then establishes (§A5.10 phase 2).
		wbBubble(t, func(t *testing.T) {
			r, raws := wbRawRig(t, 1200)
			type res struct {
				est *Established
				err error
			}
			ch := make(chan res, 1)
			go func() {
				est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
				ch <- res{est, err}
			}()
			w := <-raws
			h1 := w.waitN(t, 1)[0].b
			F := r.penv.Presets.firstCseq()
			h2, fs := wbH2(r.penv, h1, F)
			rackAt := time.Now()
			w.send(h2)
			time.Sleep(4500 * time.Millisecond)
			synctest.Wait()
			got := w.received()
			if len(got) != 3 {
				t.Fatalf("%d datagrams by 4.5 s, want H1 and two keepalives: a RACK covering it ends its retransmission", len(got))
			}
			for i, g := range got[1:] {
				if at := g.at.Sub(rackAt); at != time.Duration(i+1)*2*time.Second || !bytes.Equal(g.b, got[0].b) {
					t.Errorf("keepalive %d at %v after the RACK (verbatim %v), want %v, verbatim", i, at, bytes.Equal(g.b, got[0].b), time.Duration(i+1)*2*time.Second)
				}
			}
			w.send(wbFrame(wire.TypeRel, 0, fs, 0, relPayloadOf(F, wire.TypeOpenAck, 0, wire.SessionHandle, wbOpenAckOK(1100, 1200))))
			x := <-ch
			if x.err != nil {
				t.Fatalf("Establish: %v", x.err)
			}
			if n := x.est.Conn.Stats().Retransmits; n != 0 {
				t.Errorf("Retransmits %d, want 0", n)
			}
		})
	})
}

// TestEstablishEarlyFrames_L12: before the response the dialer drops and
// counts a damaged PREFACE_ACK (PA-1), the passive's PING, PACK, DGRAM, a REL with another cseq and a
// PONG of another id — behind the PREFACE_ACK in H2 and in datagrams of
// their own — processes a RACK, answers a rebind challenge (PING id 0) at
// once with its PONG (R1-14), and the attempt succeeds on H3 (M2-D20). A
// bare control frame, DATA, a RACK naming a cseq never sent or a malformed
// response fails the attempt as a protocol violation.
func TestEstablishEarlyFrames_L12(t *testing.T) {
	type step struct {
		name  string
		build func(fs uint32, F uint32) []byte // rendr bytes of one datagram at passive fseq fs
		n     int                              // frames it uses
	}
	ping := func(id uint32) []byte { return wbPingPayload(wire.Ping{ID: id, Nonce: 77}) }
	pack := func() []byte {
		p := make([]byte, wire.PackLen)
		wire.PutPack(p, &wire.Pack{})
		return p
	}
	dgram := func() []byte {
		p := make([]byte, wire.DgramPrefixLen+10)
		wire.PutDgramSeq(p, 1)
		return p
	}
	rack := func(cum uint32) []byte {
		p := make([]byte, wire.RackLen)
		wire.PutRack(p, &wire.Rack{CumAck: cum})
		return p
	}
	t.Run("tolerated", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			r, raws := wbRawRig(t, 1200)
			type res struct {
				est *Established
				err error
			}
			ch := make(chan res, 1)
			go func() {
				est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
				ch <- res{est, err}
			}()
			w := <-raws
			h1 := w.waitN(t, 1)[0].b
			F := r.penv.Presets.firstCseq()
			h2, fs := wbH2(r.penv, h1, F)
			// A damaged copy of H2 first: a lost datagram, never the
			// attempt's end (PA-1).
			bad := bytes.Clone(h2)
			bad[20] ^= 1
			w.send(bad)
			// H2 with a PING and a PACK behind its RACK.
			d := append(h2, wbFrame(wire.TypePing, 0, fs, 0, ping(5))...)
			d = append(d, wbFrame(wire.TypePack, 0, fs+1, wire.SessionHandle, pack())...)
			fs += 2
			w.send(d)
			for _, b := range [][]byte{
				wbFrame(wire.TypeDgram, 0, fs, wire.SessionHandle, dgram()),
				wbFrame(wire.TypeRack, 0, fs+1, 0, rack(F)),
				wbFrame(wire.TypeRel, 0, fs+2, 0, relPayloadOf(F+1, wire.TypeFin, 0, wire.SessionHandle, finInner(0))),
				wbFrame(wire.TypePong, 0, fs+3, 0, ping(9)),
				wbFrame(wire.TypePing, 0, fs+4, 0, wbPingPayload(wire.Ping{ID: 0, Nonce: 0xc4a11e})),
			} {
				w.send(b)
			}
			fs += 5
			synctest.Wait()
			// The challenge's PONG left at once, through the dialer's socket.
			var chal []wire.Ping
			for _, g := range w.received()[1:] {
				chal = append(chal, pingsOf(g.b, true)...)
			}
			if len(chal) != 1 || chal[0].ID != 0 || chal[0].Nonce != 0xc4a11e {
				t.Errorf("challenge answers %+v, want one PONG id 0 with the nonce", chal)
			}
			select {
			case x := <-ch:
				t.Fatalf("attempt ended before H3: %v", x.err)
			default:
			}
			drops := r.denv.Dgram.Dropped.Load()
			w.send(wbFrame(wire.TypeRel, 0, fs, 0, relPayloadOf(F, wire.TypeOpenAck, 0, wire.SessionHandle, wbOpenAckOK(1100, 1200))))
			x := <-ch
			if x.err != nil {
				t.Fatalf("Establish: %v", x.err)
			}
			if x.est.Resp.Type != wire.TypeOpenAck {
				t.Errorf("response %v, want OPEN_ACK", x.est.Resp.Type)
			}
			if drops != 6 {
				t.Errorf("Dropped %d before H3, want 6 (the damaged H2, PING, PACK, DGRAM, REL{F+1}, PONG 9)", drops)
			}
			if dead, cause, detail, _ := x.est.Conn.Death(); dead {
				t.Errorf("established carrier dead: %v %s", cause, detail)
			}
			// H4: the RACK of the REL response, written once the response
			// arrived (best effort).
			synctest.Wait()
			var h4 []wire.Rack
			for _, g := range w.received() {
				if !wire.IsPreface(g.b) {
					h4 = append(h4, racksOf(g.b)...)
				}
			}
			if len(h4) != 1 || h4[0] != (wire.Rack{CumAck: F}) {
				t.Errorf("RACKs after the response %+v, want H4 = RACK{%d}", h4, F)
			}
		})
	})
	t.Run("challenge before the PREFACE_ACK", func(t *testing.T) {
		// The H2 went to the mapping a rebind left: the passive's challenge
		// to the new mapping arrives first and is answered at once; another
		// PING is dropped; the repeated H2 and H3 then establish (R1-14).
		wbBubble(t, func(t *testing.T) {
			r, raws := wbRawRig(t, 1200)
			type res struct {
				est *Established
				err error
			}
			ch := make(chan res, 1)
			go func() {
				est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
				ch <- res{est, err}
			}()
			w := <-raws
			h1 := w.waitN(t, 1)[0].b
			F := r.penv.Presets.firstCseq()
			h2, fs := wbH2(r.penv, h1, F)
			w.send(append(wbFrame(wire.TypePing, 0, fs, 0, ping(5)), wbFrame(wire.TypePing, 0, fs+1, 0, wbPingPayload(wire.Ping{ID: 0, Nonce: 0xc4a11e}))...))
			w.send(wbFrame(wire.TypePing, 0, fs+2, 0, ping(6)))
			synctest.Wait()
			var pongs []wire.Ping
			for _, g := range w.received()[1:] {
				pongs = append(pongs, pingsOf(g.b, true)...)
			}
			if len(pongs) != 1 || pongs[0].ID != 0 || pongs[0].Nonce != 0xc4a11e || pongs[0].Pad != 0 {
				t.Errorf("answers before the PREFACE_ACK %+v, want one PONG id 0 with the nonce", pongs)
			}
			if n := r.denv.Dgram.Dropped.Load(); n != 1 {
				t.Errorf("Dropped %d before the PREFACE_ACK, want 1 (the datagram without a challenge)", n)
			}
			select {
			case x := <-ch:
				t.Fatalf("attempt ended before H2: %v", x.err)
			default:
			}
			w.send(append(h2, wbFrame(wire.TypeRel, 0, fs+3, 0, relPayloadOf(F, wire.TypeOpenAck, 0, wire.SessionHandle, wbOpenAckOK(1100, 1200)))...))
			x := <-ch
			if x.err != nil || x.est.Resp.Type != wire.TypeOpenAck {
				t.Fatalf("Establish: %v, want OPEN_ACK", x.err)
			}
		})
	})
	for _, tc := range []struct {
		name  string
		frame func(fs, F uint32) []byte
	}{
		{"bare FIN", func(fs, F uint32) []byte {
			return wbFrame(wire.TypeFin, 0, fs, wire.SessionHandle, finInner(0))
		}},
		{"DATA", func(fs, F uint32) []byte {
			return wbFrame(wire.TypeData, 0, fs, wire.SessionHandle, make([]byte, wire.DataPrefixLen+1))
		}},
		{"RACK beyond sent", func(fs, F uint32) []byte { return wbFrame(wire.TypeRack, 0, fs, 0, rack(F+1)) }},
		{"RACK sacking a cseq never sent", func(fs, F uint32) []byte {
			p := make([]byte, wire.RackLen)
			wire.PutRack(p, &wire.Rack{CumAck: F - 1, Sack: 1}) // bit 0: cseq F + 1
			return wbFrame(wire.TypeRack, 0, fs, 0, p)
		}},
		{"JOIN_ACK answers an OPEN", func(fs, F uint32) []byte {
			p := make([]byte, wire.JoinAckLen)
			wire.PutJoinAck(p, &wire.JoinAck{Status: wire.StatusOK, RxNext: 1200})
			return wbFrame(wire.TypeRel, 0, fs, 0, relPayloadOf(F, wire.TypeJoinAck, 0, wire.SessionHandle, p))
		}},
		{"malformed OPEN_ACK", func(fs, F uint32) []byte {
			p := wbOpenAckOK(1100, 1200)
			p[0] = 0x7f // no such status
			return wbFrame(wire.TypeRel, 0, fs, 0, relPayloadOf(F, wire.TypeOpenAck, 0, wire.SessionHandle, p))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				r, raws := wbRawRig(t, 1200)
				ch := make(chan error, 1)
				go func() {
					_, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
					ch <- err
				}()
				w := <-raws
				h1 := w.waitN(t, 1)[0].b
				F := r.penv.Presets.firstCseq()
				h2, fs := wbH2(r.penv, h1, F)
				w.send(append(h2, tc.frame(fs, F)...))
				err := <-ch
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != CauseProtocolViolation || ee.Stage != "response" || !ee.PrefaceOK {
					t.Fatalf("got %v, want a protocol violation at stage response", err)
				}
				if r.denv.IDs.inUse() != 0 {
					t.Errorf("the CarrierID was not released")
				}
			})
		})
	}
}

// wbRelState reads a datagram Conn's REL sender and receiver points.
func wbRelState(c *Conn) (next, una, cum uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := &c.dg.rel
	return r.next, r.una, r.cum
}

// TestRelStartValues: every handshake variant sets R1-3's REL start values
// — dialer OPEN and JOIN send F + 1, receive F; dialer probe send F,
// receive F − 1; a dialer answered by REL{F, CLOSE} receives F; passive
// OPEN and JOIN send F, receive F; passive probe receive F − 1; the
// passive's verdict is REL{F} — with the default first cseq and a preset
// one that wraps (L14). A started probe carrier therefore dispatches the
// passive's REL{F, CLOSE(capacity)} — it retires and reports the reason —
// instead of taking it for a duplicate.
func TestRelStartValues(t *testing.T) {
	type state struct{ next, una, cum uint32 }
	for _, preset := range []uint32{0, 0xFFFFFFFF} {
		name := "default"
		if preset != 0 {
			name = "wrapping"
		}
		t.Run(name, func(t *testing.T) {
			setup := func(r *wbRig) {
				r.denv.Presets.FirstCseq, r.penv.Presets.FirstCseq = preset, preset
			}
			for _, tc := range []struct {
				name       string
				typ        wire.Type
				verdict    bool // the passive answers REL{F, CLOSE(capacity)}
				dial, pass func(F uint32) state
			}{
				{"OPEN", wire.TypeOpen, false, func(F uint32) state { return state{F + 1, F + 1, F} }, func(F uint32) state { return state{F, F, F} }},
				{"JOIN", wire.TypeJoin, false, func(F uint32) state { return state{F + 1, F + 1, F} }, func(F uint32) state { return state{F, F, F} }},
				{"probe", wire.TypePing, false, func(F uint32) state { return state{F, F, F - 1} }, func(F uint32) state { return state{F, F, F - 1} }},
				{"OPEN answered by CLOSE", wire.TypeOpen, true, func(F uint32) state { return state{F + 1, F + 1, F} }, func(F uint32) state { return state{F, F, F} }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					wbBubble(t, func(t *testing.T) {
						gotCh := make(chan state, 1)
						pas := &wbPassive{}
						pas.act = func(r *wbRig, h *Hello) {
							var got state
							got.next, got.una, got.cum = wbRelState(h.Conn)
							gotCh <- got
							if tc.verdict {
								var b [wire.ReasonLen]byte
								wire.PutReason(b[:], uint8(wire.CloseCapacity))
								h.Conn.WriteAndClose(wire.TypeClose, 0, 0, b[:], time.Now().Add(5*time.Second))
								return
							}
							wbAdmit(&dEP{}, nil)(r, h)
						}
						r := newWBRig(t, 1200, pas.run)
						setup(r)
						F := r.denv.Presets.firstCseq()
						var payload []byte
						switch tc.typ {
						case wire.TypeOpen:
							payload = wbOpen(1100)
						case wire.TypeJoin:
							payload = wbJoin()
						}
						est, err := r.establish(context.Background(), tc.typ, payload)
						if err != nil {
							t.Fatalf("Establish: %v", err)
						}
						if tc.verdict && est.Resp.Type != wire.TypeClose {
							t.Fatalf("response %v, want the CLOSE verdict", est.Resp.Type)
						}
						var d state
						d.next, d.una, d.cum = wbRelState(est.Conn)
						if want := tc.dial(F); d != want {
							t.Errorf("dialer REL state %+v, want %+v", d, want)
						}
						if got, want := <-gotCh, tc.pass(F); got != want {
							t.Errorf("passive REL state %+v, want %+v", got, want)
						}
					})
				})
			}
			t.Run("probe answered by CLOSE after its PONG", func(t *testing.T) {
				wbBubble(t, func(t *testing.T) {
					pas := &wbPassive{}
					pas.act = func(r *wbRig, h *Hello) {
						var b [wire.ReasonLen]byte
						wire.PutReason(b[:], uint8(wire.CloseCapacity))
						h.Conn.WriteAndClose(wire.TypeClose, 0, 0, b[:], time.Now().Add(5*time.Second))
					}
					r := newWBRig(t, 1200, pas.run)
					setup(r)
					est, err := r.establish(context.Background(), wire.TypePing, nil)
					if err != nil || est.Resp.Type != wire.TypePong {
						t.Fatalf("Establish: %v, %v; want the establishment PONG", est, err)
					}
					c := est.Conn
					c.Start(nil, &hBell{}, StartOptions{Probe: true})
					time.Sleep(time.Second)
					synctest.Wait()
					if reason, ok := c.PeerCloseReason(); !ok || reason != wire.CloseCapacity {
						t.Fatalf("PeerCloseReason %v %v, want capacity: the passive's REL{F, CLOSE} was not dispatched", reason, ok)
					}
					hWait(t, c)
					if cause := hCause(c); cause != CauseRetired {
						t.Errorf("probe carrier ended %v, want retired", cause)
					}
				})
			})
			t.Run("probe answered by a bare PREFACE_ACK and REL{F, CLOSE}", func(t *testing.T) {
				wbBubble(t, func(t *testing.T) {
					r, raws := wbRawRig(t, 1200)
					setup(r)
					F := r.denv.Presets.firstCseq()
					type res struct {
						est *Established
						err error
					}
					ch := make(chan res, 1)
					go func() {
						est, err := r.establish(context.Background(), wire.TypePing, nil)
						ch <- res{est, err}
					}()
					w := <-raws
					h1 := w.waitN(t, 1)[0].b
					h2, fs := wbH2(r.penv, h1, F-1) // a RACK of nothing instead of the PONG
					var b [wire.ReasonLen]byte
					wire.PutReason(b[:], uint8(wire.CloseCapacity))
					w.send(append(h2, wbFrame(wire.TypeRel, 0, fs, 0, relPayloadOf(F, wire.TypeClose, 0, 0, b[:]))...))
					x := <-ch
					if x.err != nil || x.est.Resp.Type != wire.TypeClose {
						t.Fatalf("Establish: %v; want the CLOSE response", x.err)
					}
					var d state
					d.next, d.una, d.cum = wbRelState(x.est.Conn)
					if want := (state{F, F, F}); d != want {
						t.Errorf("dialer REL state %+v, want %+v", d, want)
					}
				})
			})
		})
	}
}

// TestEstablishResponseTail: the frames the passive packed behind its first
// response in the response datagram — a DGRAM that Confirm released, or the
// first PING that follows the response of a held round — are kept as the
// dialer Conn's tail and walked by its reader before its first read: the
// DGRAM arrives (no drop counted) and the PING is answered at once, without
// the passive's PING retry (R1-1).
func TestEstablishResponseTail(t *testing.T) {
	t.Run("DGRAM", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			body := bytes.Repeat([]byte{0xd6}, 100)
			pas := &wbPassive{}
			pas.act = wbAdmit(&dEP{}, func(c *Conn, b *Batch) {
				b.AddDgram(wire.SessionHandle, 7, body, nil)
			})
			r := newWBRig(t, 1200, pas.run)
			est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
			if err != nil {
				t.Fatalf("Establish: %v", err)
			}
			if len(est.Conn.dg.tail) == 0 {
				t.Fatalf("no tail kept behind the response")
			}
			ep := &dEP{}
			est.Conn.Start(ep, &hBell{}, StartOptions{})
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
			dgs := ep.datagrams()
			if len(dgs) != 1 || dgs[0].seq != 7 || dgs[0].n != len(body) {
				t.Errorf("DGRAMs delivered %+v, want seq 7 of %d bytes", dgs, len(body))
			}
			if n := est.Conn.Stats().Dropped; n != 0 {
				t.Errorf("Dropped %d, want 0", n)
			}
		})
	})
	t.Run("first PING", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			pas := &wbPassive{}
			pas.act = wbAdmit(&dEP{}, nil)
			r := newWBRig(t, 1200, pas.run)
			r.link.SetDelay(rendrtest.Up, 10*time.Millisecond, 0)
			r.link.SetDelay(rendrtest.Down, 10*time.Millisecond, 0)
			est, err := r.establish(context.Background(), wire.TypeOpen, wbOpen(1100))
			if err != nil {
				t.Fatalf("Establish: %v", err)
			}
			if !hasType(est.Conn.dg.tail, wire.TypePing) {
				t.Fatalf("tail % x carries no PING", est.Conn.dg.tail)
			}
			est.Conn.Start(&dEP{}, &hBell{}, StartOptions{})
			time.Sleep(100 * time.Millisecond)
			synctest.Wait()
			pc := pas.helloList()[0].Conn
			if s := pc.Stats(); s.SRTT == 0 || s.SRTT > 30*time.Millisecond {
				t.Errorf("passive SRTT %v 100 ms after the response, want one 20 ms sample of the first PING", s.SRTT)
			}
			if n := est.Conn.Stats().Dropped; n != 0 {
				t.Errorf("Dropped %d, want 0", n)
			}
		})
	})
}
