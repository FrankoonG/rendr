package adversarial

import (
	"fmt"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// region is one region of a frame and the bit the row flips in it (bits
// count as in rendrtest.Tamper.FlipBit: bit 0 is the first header bit, −1
// the CRC trailer's last), with the checks a stream receiver may name.
type region struct {
	name string
	bit  int
	want []string // the detail names one of these (none: any check)
}

// regions are the seven regions of §A9.3's bit-flip row, the handle
// twice (to zero and to another view). The type, flags
// and length flips break whichever check meets them first (header bounds,
// the CRC over a shifted frame); the others name their check.
var regions = []region{
	{"type", 7, nil},   // the type's last bit: DATA ↔ ACK, SCHED → 0x15, DGRAM → PACK, REL → RACK
	{"flags", 15, nil}, // the flags' last bit
	{"len", 39, nil},   // the length's last bit: the frame grows or shrinks by one byte
	{"fseq", 71, []string{"fseq"}},
	{"handle", 103, []string{"handle"}}, // handle 1 → 0 on a session frame: the codec's zero-handle rule
	// handle 1 → 3: a session frame for a view a dedicated carrier does
	// not have (the trunk's routing, checked before the CRC)
	{"handle3", 102, []string{"no such view"}},
	{"payload", 8*wire.HeaderLen + 3, []string{"crc mismatch"}},
	{"crc", -1, []string{"crc mismatch"}},
}

// TestAdvBitFlipRegions_L41_L43: one bit flipped in each region (type,
// flags, len, fseq, handle, payload, CRC) of one frame of each kind. Stream
// carriers — a DATA and a SCHED of the dialer, an ACK of the passive, a
// DGRAM of a packet session on stream carriers: the receiving end kills
// exactly the carrier at that frame (protocol_violation naming the check
// that met it: header bounds, fseq, handle or CRC), the session replays
// from the ACK edge, every byte arrives once, and the dialer counts the
// row's Death migrations. Datagram carriers — a DGRAM and a REL of the
// dialer: the datagram is dropped and counted (the receiving carrier's
// Dropped), no carrier dies, the REL is retransmitted, and the verifier
// sees no damaged datagram. DETACH frames exist only on MUX trunks (the
// MUX half of the set).
func TestAdvBitFlipRegions_L41_L43(t *testing.T) {
	stream := []struct {
		name string
		dir  rendrtest.Dir
		typ  rendrtest.FrameType
	}{
		{"DATA", rendrtest.Up, rendrtest.FrameData},
		{"ACK", rendrtest.Down, rendrtest.FrameAck},
		{"SCHED", rendrtest.Up, rendrtest.FrameSched},
	}
	for _, f := range stream {
		for _, r := range regions {
			t.Run("stream/"+f.name+"/"+r.name, func(t *testing.T) {
				eachSetup(t, func(t *testing.T, s setup) {
					runStream(t, s, streamAttack{dir: f.dir, typ: f.typ, sch: f.typ == rendrtest.FrameSched,
						arm:  func(tm *rendrtest.Tamper, _ *pair) { tm.FlipBit(f.dir, rendrtest.NextOfType(f.typ), r.bit) },
						ops:  stat(func(st rendrtest.TamperStats) int { return st.Flipped }),
						want: r.want})
				})
			})
		}
	}
	for _, r := range regions {
		t.Run("stream/DGRAM/"+r.name, func(t *testing.T) {
			eachSetup(t, func(t *testing.T, s setup) { flipStreamDgram(t, s, r) })
		})
	}
	for _, typ := range []wire.Type{wire.TypeDgram, wire.TypeRel} {
		for _, r := range regions {
			t.Run("datagram/"+typ.String()+"/"+r.name, func(t *testing.T) {
				eachSetup(t, func(t *testing.T, s setup) { flipDatagram(t, s, typ, r) })
			})
		}
	}
}

// packetRate is the rows' packet rate (datagrams per second, 1000 bytes).
const packetRate = 500

// flipStreamDgram: the packet sessions on stream carriers send 500
// datagrams per second dialer → passive each; after a second one bit of
// the next DGRAM on the first session's attacked carrier is flipped; the
// passive kills that carrier and only the datagrams in flight on it are
// lost.
func flipStreamDgram(t *testing.T, s setup, r region) {
	w := newWorld(t, s, worldOpts{})
	xs := w.openPacketN(w.streamPeer())
	x := xs[0]
	ups := startPacketFlows(t, xs, 4301, packetRate)
	time.Sleep(time.Second)
	w.tamperOf(target(t, s, x.d.Status())).FlipBit(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameDgram), r.bit)
	flipped := stat(func(st rendrtest.TamperStats) int { return st.Flipped })
	waitFor(t, 5*time.Second, "the flip (stimulus)", func() bool { return w.fired(flipped) > 0 })
	hit := w.hit(t, flipped)
	violated(t, "the attacked carrier", endDead(t, "the passive", x.p.Status, hit.id), r.want...)
	time.Sleep(time.Second)
	for _, up := range ups {
		up.halt(t)
		res := up.integrity(t)
		// Load: the sessions carried on; only what was in flight on the
		// dead carrier is lost (at most its link queue and one round
		// trip: 50).
		if res.Unique < uint64(packetRate) || up.lost() > 50 {
			t.Fatalf("load: %s: %d of %d datagrams arrived (%d lost)", up.name, res.Unique, up.accepted.Load(), up.lost())
		}
	}
	deathsAre(t, s, x.d.Status, x.p.Status, 1)
	neighboursPacket(t, s, xs, 0, 1)
	endPackets(t, xs, ups)
	w.close()
}

// flipDatagram: the packet sessions on datagram carriers send 500
// datagrams per second dialer → passive each; one bit of a frame of type
// typ is flipped in one datagram the dialer writes — the next DGRAM on the
// first session's attacked carrier after a second, or the next REL of any
// session carrier from the first session's end on (its FIN). The
// receiving carrier drops the datagram's rest and counts it; nothing dies;
// a REL is retransmitted.
func flipDatagram(t *testing.T, s setup, typ wire.Type, r region) {
	w := newWorld(t, s, worldOpts{})
	xs := w.openPacketN(w.datagramPeer())
	x := xs[0]
	ups := startPacketFlows(t, xs, 4302, packetRate)
	up := ups[0]
	time.Sleep(time.Second)
	if typ == wire.TypeDgram {
		w.flip.arm(typ, r.bit, target(t, s, x.d.Status()))
		waitFor(t, 5*time.Second, "the flip (stimulus)", func() bool { _, n := w.flip.targeted(); return n > 0 })
		time.Sleep(time.Second)
	}
	for _, f := range ups {
		f.halt(t)
	}
	if typ == wire.TypeRel {
		w.flip.arm(typ, r.bit, 0) // the next REL: the first session's FIN
	}
	x.endPacket(t, up)
	id, n := w.flip.targeted()
	if n != 1 {
		t.Fatalf("stimulus: the flip fired %d times, want once", n)
	}
	res := up.integrity(t)
	w.noViolation()
	if d := w.deaths(); len(d[0])+len(d[1]) != 0 {
		t.Fatalf("carriers died: dialer %+v, passive %+v", d[0], d[1])
	}
	pc, ok := carrierOf(x.p.Status(), id)
	if !ok || pc.Dropped == 0 {
		t.Fatalf("the passive's carrier %d did not count the damaged datagram: %+v", id, pc)
	}
	if typ == wire.TypeRel {
		if dc, ok := carrierOf(x.d.Status(), id); !ok || dc.Retransmits == 0 {
			t.Fatalf("the damaged REL was not retransmitted: %+v", dc)
		}
	}
	// Only the damaged datagram can be missing (a race member's copy
	// covers it); the neighbours lose nothing.
	if lost := up.lost(); lost > 1 || res.Unique == 0 {
		t.Fatalf("load: %d lost of %d accepted (want at most the damaged one)", lost, up.accepted.Load())
	}
	for _, f := range ups[1:] {
		if f.integrity(t); f.lost() != 0 {
			t.Fatalf("load: %s lost %d datagrams", f.name, f.lost())
		}
	}
	neighboursPacket(t, s, xs, 0, 0)
	endPackets(t, xs[1:], ups[1:])
	w.close()
}

// deathsAre requires the session's Death migrations: d on the dialer; the
// passive counts the same in selector (it follows the dialer's counts) and
// none in bond and race, where it never had unacknowledged data of its
// own (the rows send dialer → passive only).
func deathsAre(t testing.TB, s setup, dst, pst func() rendr.SessionStatus, d uint64) {
	t.Helper()
	p := uint64(0)
	if s.mode == rendr.ModeSelector {
		p = d
	}
	waitFor(t, 10*time.Second, fmt.Sprintf("Death migrations %d (dialer) and %d (passive)", d, p), func() bool {
		return dst().Migrations.Death >= d && pst().Migrations.Death >= p
	})
	if dm, pm := dst().Migrations, pst().Migrations; dm.Death != d || pm.Death != p {
		t.Fatalf("Death migrations: dialer %+v, passive %+v; want Death %d and %d", dm, pm, d, p)
	}
}
