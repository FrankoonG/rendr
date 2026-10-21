package l4

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestServerUDPFirstAboveMaxPayload_L37 (M6-D18, §A3.3, §A4.3; L37): a
// first datagram from the OPEN follows the size rule of every other
// datagram of the flow. DialUDP never lets more than 438 bytes ride, but
// an OPEN an embedder builds itself (AppendMetadata, Peer.DialPacket) may
// carry one up to Handshake.MaxMetadata; on a stream carrier with the
// passive's Packet.MaxPayload at 512 the flow's MaxPayload is 512. One of
// 1,000 bytes is not written to the target: the passive counts it
// TooLarge (FirstSent 0, ToTarget 0), confirms the flow, and the flow's
// next datagram of 100 bytes is delivered. One of exactly 512 bytes is
// written (FirstSent 1, TooLarge 0).
//
// The class seed (R1-10) counts only a written first datagram. Under the
// literal rule a second flow whose target replies once at once is a
// stream at the passive when its first datagram was written (the reply
// moves in the second direction: the flow ends at UDPIdle.Stream, 40 s,
// after it) and is not when the datagram was dropped (the reply is the
// first direction: it ends at UDPIdle.Short, 10 s).
func TestServerUDPFirstAboveMaxPayload_L37(t *testing.T) {
	const s = time.Second
	for _, tc := range []struct {
		name  string
		size  int
		write bool
	}{{"above", 1000, false}, {"at", 512, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, promoteOnReply)
				var pcfg rendr.Config
				pcfg.Packet.MaxPayload = 512
				w := newSUWorld(t, suOpts{streams: true, pcfg: pcfg})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				srv := &Server{UDP: true, Dial: ts.dial, UDPIdle: FlowIdle{Short: 10 * s, Stream: 40 * s}}
				sv := suServe(w, srv)
				first := pfData(tc.size, 0x51)
				md, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: pfTarget, First: first})
				if err != nil {
					t.Fatalf("AppendMetadata: %v", err)
				}
				pc, err := w.speer.DialPacket(context.Background(), rendr.DialOptions{Metadata: md})
				if err != nil {
					t.Fatalf("DialPacket: %v", err)
				}
				if mp := pc.MaxPayload(); mp != 512 {
					t.Fatalf("premise: the flow's MaxPayload is %d, want the passive's 512", mp)
				}
				app := ts.next(t, time.Minute)
				if tc.write {
					pfExpect(t, app, first)
				} else {
					pfNone(t, app)
				}
				u := srv.Status().UDP
				wantSent, wantLarge := uint64(0), uint64(1)
				if tc.write {
					wantSent, wantLarge = 1, 0
				}
				if u.Confirmed != 1 || u.FirstSent != wantSent || u.ToTarget != wantSent || u.TooLarge != wantLarge || u.Live != 1 {
					t.Fatalf("UDP status %+v: want one live flow, FirstSent and ToTarget %d, TooLarge %d", u, wantSent, wantLarge)
				}
				next := pfData(100, 0x52)
				if _, err := pc.WriteTo(next, nil); err != nil {
					t.Fatalf("WriteTo: %v", err)
				}
				pfExpect(t, app, next)
				if u := srv.Status().UDP; u.ToTarget != wantSent+1 || u.TooLarge != wantLarge {
					t.Fatalf("UDP status after a datagram %+v: want ToTarget %d, TooLarge %d", u, wantSent+1, wantLarge)
				}
				pc.Close()
				waitFor(t, time.Minute, "the first flow ends", func() bool { return srv.Status().UDP.Live == 0 })

				// The seed: a second flow with the same OPEN, one reply.
				pc2, err := w.speer.DialPacket(context.Background(), rendr.DialOptions{Metadata: md})
				if err != nil {
					t.Fatalf("DialPacket: %v", err)
				}
				app2 := ts.next(t, time.Minute)
				if tc.write {
					pfExpect(t, app2, first)
				}
				reply := pfData(50, 0x53)
				replied := time.Now() // the passive's idle clock moves when its session accepts the reply, after this
				pfSend(t, app2, reply)
				if b, err := pfRecvPC(t, pc2); err != nil || len(b) != len(reply) {
					t.Fatalf("the dialer read %d bytes, %v; want the %d-byte reply", len(b), err, len(reply))
				}
				waitFor(t, 2*time.Minute, "the second flow ends", func() bool { return srv.Status().UDP.Live == 0 })
				el := time.Since(replied)
				want := 10 * s // not a stream: the dropped first datagram did not seed the class
				if tc.write {
					want = 40 * s
				}
				u = srv.Status().UDP
				if el < want || el > want+s+100*time.Millisecond || u.Ended.Idle != 1 {
					t.Fatalf("the second flow ended %v after the reply (Ended %+v); want its idle limit at %v", el, u.Ended, want)
				}
				if u.FirstSent != 2*wantSent || u.TooLarge != 2*wantLarge || u.FromTarget != 1 {
					t.Fatalf("UDP status %+v: want FirstSent %d, TooLarge %d, FromTarget 1", u, 2*wantSent, 2*wantLarge)
				}
				pc2.Close()
				sv.stop(t)
				suUnits(t, srv)
				w.shutdown()
			})
		})
	}
}
