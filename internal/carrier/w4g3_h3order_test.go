package carrier

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestEstablishH3BeforeH2_M2D20 (W4 REL-4; M2-D20 as amended): reordering
// delivers the passive's response datagram H3 — REL{FirstCseq, OPEN_ACK |
// JOIN_ACK} followed by a DGRAM the passive packed behind it — 1 ms before
// H2 (PREFACE_ACK ‖ RACK). The dialer keeps that one datagram and runs its
// frames once the PREFACE_ACK(OK) is read, so Establish returns as H2
// arrives (the link has no delay: within 10 ms of it) instead of waiting
// for the passive's REL resend at RelRTOInit (300 ms, no RTT sample yet).
//
// Stimulus: H3 is sent first and Establish has not returned 1 ms later.
// Load and integrity: the response's type and payload are the passive's,
// the DGRAM behind it is the carrier's tail byte for byte, H4 (RACK of
// FirstCseq) is written, nothing is counted as dropped and H1 was sent
// once. A datagram before the PREFACE_ACK whose REL has another cseq is
// still dropped and counted, never kept.
func TestEstablishH3BeforeH2_M2D20(t *testing.T) {
	for _, tc := range []struct {
		name    string
		first   wire.Type
		payload func() []byte
		resp    wire.Type
		inner   func() []byte
	}{
		{"OPEN", wire.TypeOpen, func() []byte { return wbOpen(1100) }, wire.TypeOpenAck, func() []byte { return wbOpenAckOK(1100, 1200) }},
		{"JOIN", wire.TypeJoin, wbJoin, wire.TypeJoinAck, func() []byte {
			p := make([]byte, wire.JoinAckLen)
			wire.PutJoinAck(p, &wire.JoinAck{Status: wire.StatusOK, RxNext: 1200})
			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				r, raws := wbRawRig(t, 1200)
				type res struct {
					est *Established
					err error
					at  time.Time
				}
				ch := make(chan res, 1)
				go func() {
					est, err := r.establish(context.Background(), tc.first, tc.payload())
					ch <- res{est, err, time.Now()}
				}()
				w := <-raws
				h1 := w.waitN(t, 1)[0].b
				F := r.penv.Presets.firstCseq()
				h2, fs := wbH2(r.penv, h1, F)
				dg := make([]byte, wire.DgramPrefixLen+16)
				wire.PutDgramSeq(dg, 1)
				copy(dg[wire.DgramPrefixLen:], "behind the reply")
				tail := wbFrame(wire.TypeDgram, 0, fs+1, wire.SessionHandle, dg)
				inner := tc.inner()
				h3 := append(wbFrame(wire.TypeRel, 0, fs, 0, relPayloadOf(F, tc.resp, 0, wire.SessionHandle, inner)), tail...)
				// A REL with another cseq ahead of the PREFACE_ACK is no
				// response: dropped and counted, not kept.
				w.send(wbFrame(wire.TypeRel, 0, fs+2, 0, relPayloadOf(F+1, tc.resp, 0, wire.SessionHandle, inner)))
				w.send(h3)
				time.Sleep(time.Millisecond)
				synctest.Wait()
				select {
				case x := <-ch:
					t.Fatalf("Establish returned before H2: %v", x.err)
				default:
				}
				if n := r.denv.Dgram.Dropped.Load(); n != 1 {
					t.Errorf("Dropped %d before H2, want 1 (the REL with another cseq)", n)
				}
				h2At := time.Now()
				w.send(h2)
				x := <-ch
				if x.err != nil {
					t.Fatalf("Establish: %v", x.err)
				}
				if d := x.at.Sub(h2At); d > 10*time.Millisecond {
					t.Errorf("Establish returned %v after H2, want ≤ 10 ms (no wait for a REL resend)", d)
				}
				if x.est.Resp.Type != tc.resp || !bytes.Equal(x.est.Payload, inner) {
					t.Errorf("response %v %x, want %v %x", x.est.Resp.Type, x.est.Payload, tc.resp, inner)
				}
				if !bytes.Equal(x.est.Conn.dg.tail, tail) {
					t.Errorf("tail %x, want the DGRAM behind the response %x", x.est.Conn.dg.tail, tail)
				}
				if n := r.denv.Dgram.Dropped.Load(); n != 1 {
					t.Errorf("Dropped %d after Establish, want 1: the kept response is no drop", n)
				}
				if dead, cause, detail, _ := x.est.Conn.Death(); dead {
					t.Errorf("established carrier dead: %v %s", cause, detail)
				}
				synctest.Wait()
				var h1s int
				var h4 []wire.Rack
				for _, g := range w.received() {
					if wire.IsPreface(g.b) {
						h1s++
					} else {
						h4 = append(h4, racksOf(g.b)...)
					}
				}
				if h1s != 1 {
					t.Errorf("H1 sent %d times, want once", h1s)
				}
				if len(h4) != 1 || h4[0] != (wire.Rack{CumAck: F}) {
					t.Errorf("RACKs after the response %+v, want H4 = RACK{%d}", h4, F)
				}
			})
		})
	}
}

// TestOpenPmtu (W4 L3-1): a packet OPEN's MaxPayload offer that fits its
// factory's budget (pmtu ≤ MTU − 25) is lowered to a carrier's lower cmtu
// offer − 25; an offer above the factory budget (a bond session with a
// stream factory meant larger datagrams for the stream carriers), one that
// already fits the offer, an unknown factory MTU and a result below
// MinPacketPayload keep it.
func TestOpenPmtu(t *testing.T) {
	for _, c := range []struct{ pmtu, mtu, offer, want int }{
		{3966, 3991, 1463, 1438},
		{2000, 3991, 1463, 1438},
		{1438, 3991, 1463, -1},
		{1000, 3991, 1463, -1},
		{4000, 3991, 1463, -1},
		{3966, 3991, 3991, -1},
		{3966, 0, 1463, -1},
		{1000, 3991, 536, -1},
		{1000, 3991, 537, 512},
	} {
		if got := openPmtu(c.pmtu, c.mtu, c.offer); got != c.want {
			t.Errorf("openPmtu(%d, %d, %d) = %d, want %d", c.pmtu, c.mtu, c.offer, got, c.want)
		}
	}
}
