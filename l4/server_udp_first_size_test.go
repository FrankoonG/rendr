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
func TestServerUDPFirstAboveMaxPayload_L37(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int
		write bool
	}{{"above", 1000, false}, {"at", 512, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var pcfg rendr.Config
				pcfg.Packet.MaxPayload = 512
				w := newSUWorld(t, suOpts{streams: true, pcfg: pcfg})
				ts := newSUTargets(rendrtest.DatagramPipeConfig{})
				s := &Server{UDP: true, Dial: ts.dial}
				sv := suServe(w, s)
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
				u := s.Status().UDP
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
				if u := s.Status().UDP; u.ToTarget != wantSent+1 || u.TooLarge != wantLarge {
					t.Fatalf("UDP status after a datagram %+v: want ToTarget %d, TooLarge %d", u, wantSent+1, wantLarge)
				}
				pc.Close()
				sv.stop(t)
				suUnits(t, s)
				w.shutdown()
			})
		})
	}
}
