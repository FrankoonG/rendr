package mux

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestMuxPacketBesideBulk (M3 amendment KINDSPLIT to §A5.8 and M3-D17,
// M3-D24; checkpoint C-B, G6 run 20261010-074505-b27e, no_other_error_class:
// a packet session on the nat route sent 2 of 16 replies, DropAge 14): a
// selector packet session runs beside one stream session on the same
// stream factory s (a Link, 5 ms one way, rate limited: one bottleneck
// shared by every carrier of s). The stream session's sender writes
// without pause (one way: A → B only; two way: both directions); the packet
// session sends 20 datagrams/s of 200 bytes each way.
//
// Before the kind split both sessions were views of one stream trunk:
// the stream view filled the trunk's in-flight cap at every turn and room
// freed about once per round trip (≈ Cap/rate: 100 to 550 ms here), above
// Packet.MaxAge (100 ms), so the packet view's datagrams aged out before
// placement (m3 2b81de2: one-way rows lost 55-60 % of the A → B datagrams,
// two-way rows 44-78 % each way). A stream trunk now carries sessions of
// one kind: the packet session dials a trunk of its own on s.
//
// Premise: two session factory calls on s, the two sessions on distinct
// carriers of s with Shared 1 each on both ends, Status.Mux 2 carriers
// and 2 views on both Runtimes. Load: during the 8 s of packet flows the
// stream receiver(s) took at least 0.8 of the link's rate (the bulk
// stream saturates the bottleneck and so its own trunk's cap) and the
// packet session's own carrier is a carrier of s. PASS: DropAge 0 on both
// ends, no datagram lost (there is no stimulus window), PacketIntegrity,
// every stream byte verified, both sessions end cleanly.
func TestMuxPacketBesideBulk(t *testing.T) {
	for _, twoWay := range []bool{false, true} {
		for _, rate := range []float64{1 << 20, 4 << 20} {
			t.Run(fmt.Sprintf("twoway=%v/rate=%v", twoWay, rate), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					const oneWay = 5 * time.Millisecond
					warm, run := 2*time.Second, 8*time.Second
					if raceEnabled {
						warm, run = time.Second, 4*time.Second // R1-11
					}
					w := newWorld(t, worldOpts{}, linkSpec{name: "s", oneWay: oneWay, rate: rate})
					peer := w.peer("s")
					s := w.open(peer, "S0", rendr.ModeSelector)
					pf := pktFlows{s: w.openPacket(peer, "P0", rendr.ModeSelector)}
					w.identities("after the opens", []pair{s}, pf.s)

					// The kind split (Errorf: on a build without it the run goes
					// on and also shows the datagrams that aged out).
					for i, ends := range [2][2]statuser{{s.d, pf.s.d}, {s.p, pf.s.p}} {
						sc, okS := liveOf1(ends[0].Status())
						pc, okP := liveOf1(ends[1].Status())
						if !okS || !okP || sc.ID == pc.ID || sc.Shared != 1 || pc.Shared != 1 {
							t.Errorf("%s: the stream session's carrier %+v (found %v) and the packet session's %+v (found %v), want two carriers with Shared 1 each", side(i), sc, okS, pc, okP)
						}
					}
					for i, rt := range []*rendr.Runtime{w.d, w.p} {
						if m := rt.Status().Mux; m.Carriers != 2 || m.Views != 2 {
							t.Errorf("%s: Status.Mux %+v, want 2 carriers with 2 views (one trunk per session kind)", side(i), m)
						}
					}
					if got := w.dials("s"); got != 2 {
						t.Errorf("%d session factory calls on s, want 2 (one trunk per session kind)", got)
					}
					if pc, ok := liveNamed(pf.s.d.Status(), "s"); !ok {
						t.Fatalf("premise: the packet session runs on no carrier of s: %+v", pf.s.d.Status().Carriers)
					} else if pc.Kind != rendr.KindStream {
						t.Fatalf("premise: the packet session's carrier of s is %v, want a stream carrier", pc.Kind)
					}

					rx := []*receiver{startReceiver("S0 A → B", s.p, 10, openEnded)}
					tx := []*sender{w.startSender(s.d, 10, openEnded, 0)}
					size := int64(0)
					if twoWay {
						size = openEnded
					}
					rx = append(rx, startReceiver("S0 B → A", s.d, 11, size))
					tx = append(tx, w.startSender(s.p, 11, size, 0))
					time.Sleep(warm)
					from := time.Now()
					pf.up = w.startFlow(pf.s.d, pf.s.p, flowCfg{name: "P0 A → B", seed: 100, rate: 20})
					pf.down = w.startFlow(pf.s.p, pf.s.d, flowCfg{name: "P0 B → A", seed: 200, rate: 20})
					time.Sleep(run)
					to := time.Now()
					for _, x := range tx {
						x.end()
					}
					loaded := rx[:1]
					if twoWay {
						loaded = rx
					}
					for _, r := range loaded {
						got := r.bytesAt(to) - r.bytesAt(from)
						if want := 0.8 * rate * run.Seconds(); float64(got) < want {
							t.Fatalf("load: %s carried %d bytes in the %v of packet flows, want ≥ %.0f (0.8 of the link's rate)", r.name, got, run, want)
						}
					}
					for _, r := range rx {
						r.wait(t, time.Minute)
					}
					endPackets(t, pf.s, pf.up, pf.down)
					dp, pp := *pf.s.d.Status().Packet, *pf.s.p.Status().Packet
					t.Logf("dialer %+v", dp)
					t.Logf("passive %+v", pp)
					if dp.DropAge != 0 || pp.DropAge != 0 {
						t.Errorf("DropAge %d (dialer) and %d (passive), want 0: the packet session's datagrams aged out behind the stream session's in-flight cap", dp.DropAge, pp.DropAge)
					}
					judgeFlows(t, pf, nil)
					closeBoth(t, s)
					w.noViolation()
					w.close()
				})
			})
		}
	}
}

// liveOf1 returns the one live carrier of a session's status.
func liveOf1(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	l := liveOf(st)
	if len(l) != 1 {
		return rendr.CarrierStatus{}, false
	}
	return l[0], true
}
