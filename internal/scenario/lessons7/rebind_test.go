package lessons7

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketNatRebind_L59 (M2 design §A8.3; M2-D27, R1-11, R1-14, A5.13):
// a packet session over a DatagramHub (the passive on FromPacketConn) with
// 100 datagrams/s each way.
//
//  1. The client's NAT mapping moves mid-flow (Rebind): the passive
//     challenges the new address, the dialer answers, the flow's reply
//     address moves — the same carrier on both ends, Rebinds 1 (carrier and
//     Runtime), no death, no migration, no dial. Up, nothing is lost; down,
//     only what the passive wrote to the old address before the commit.
//  2. The client's first 16 datagrams are replayed from foreign addresses,
//     100 ms apart: window duplicates, each frame dropped and counted (or a
//     repeated H1, answered with the stored H2 to the current address);
//     no challenge is started, nothing is written to a replay's address and
//     the reply address stays.
//  3. A forged datagram — the flow's ID, a fresh fseq and a valid CRC, from
//     a foreign address — makes the passive challenge that address. A
//     forged answer — the challenge's nonce in a PONG with id 0 — from a
//     third address is ignored (dropped and counted). Its source replaced
//     the flow's rebind candidate, so the flow refuses the challenge's
//     resends: each is a dropped datagram, never the carrier's death (a
//     wave-3 fix; the refusal used to kill the carrier). The challenge
//     expires unanswered, the reply address stays and both flows go on
//     without a loss.
//  4. The carrier dies (its conn closed under rendr); the session continues
//     on a new flow (losses only at the kill). The dead flow's H1, replayed
//     while its ID is tombstoned, is dropped without state (R1-11); replayed
//     after the tombstone TTL it
//     makes a flow whose OPEN is refused BAD_REQUEST (the carrier ID is one
//     of the session's dead lanes) — no lane either way.
func TestPacketNatRebind_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const owd = 10 * time.Millisecond
		w := newWorld(t, worldOpts{hubUp: owd, hubDown: owd})
		start := time.Now()
		dc, pc := w.open(w.peer(w.hubCarrier("h0", 0)), rendr.DialOptions{})
		up := startFlow(dc, pc, 1, 10*time.Millisecond)
		down := startFlow(pc, dc, 2, 10*time.Millisecond)
		time.Sleep(2 * time.Second)
		dcar, pcar := oneLive(t, "dialer", dc), oneLive(t, "passive", pc)
		reads, _ := w.tap.snapshot()
		flowID, oldAddr := reads[0].flow, reads[0].addr

		// 1. The NAT rebinding.
		rebindAt := time.Now()
		w.hub.Rebind(0)
		took := waitFor(t, time.Second, "the rebind to commit", func() bool {
			c, _ := carrierOf(pc.Status(), pcar.ID)
			return c.Rebinds == 1
		})
		commitAt := time.Now()
		if took > 2*owd+3*owd+20*time.Millisecond {
			t.Fatalf("the rebind committed %v after the move, want within the next datagram plus one challenge round trip", took)
		}
		if s := w.hub.Stats(); s.Rebinds != 1 || s.Dials != 1 {
			t.Fatalf("stimulus: hub rebinds %d, dials %d; want 1, 1", s.Rebinds, s.Dials)
		}
		reads, writes := w.tap.snapshot()
		newAddr := netip.AddrPort{}
		for _, d := range reads {
			if d.at.After(rebindAt) && d.flow == flowID && d.addr != oldAddr {
				newAddr = d.addr
				break
			}
		}
		chal := writesWith(writes, rebindAt, isChallenge)
		if !newAddr.IsValid() || len(chal) != 1 || chal[0].addr != newAddr || commitAt.Before(chal[0].at) {
			t.Fatalf("challenges after the move %+v; the new address %v: want exactly one, to it, before the commit", chal, newAddr)
		}
		time.Sleep(2 * time.Second)
		requireSameCarrier(t, w, dc, pc, dcar.ID, pcar.ID, 1)

		// 2. Replays of the client's first datagrams, from foreign addresses,
		// 100 ms apart: each replay is the flow's latest rebind candidate
		// for longer than a challenge takes to be written, so a challenge a
		// replay wrongly started would reach the tap (a burst would let the
		// last replay's address refuse the earlier ones' challenges).
		replayAt := time.Now()
		dropped0, spoofed0 := carrierDropped(pc, pcar.ID), w.hub.Stats().Spoofed
		for k := range 16 {
			w.hub.Replay(0, k)
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(time.Second)
		if s := w.hub.Stats(); s.Spoofed-spoofed0 != 16 {
			t.Fatalf("stimulus: %d datagrams replayed, want 16", s.Spoofed-spoofed0)
		}
		reads, writes = w.tap.snapshot()
		replayed, replayedFrames := 0, uint64(0)
		for _, d := range reads {
			if !d.at.Before(replayAt) && d.addr != newAddr {
				replayed++
				if !d.preface {
					replayedFrames += uint64(len(d.frames))
				}
			}
		}
		if replayed != 16 {
			t.Fatalf("stimulus: the passive read %d datagrams from foreign addresses, want the 16 replays", replayed)
		}
		// Each frame of the 15 non-H1 replays is a window duplicate, and
		// nothing else is dropped: no challenge was started and refused.
		if d := carrierDropped(pc, pcar.ID) - dropped0; d != replayedFrames {
			t.Fatalf("the passive carrier dropped %d frames and datagrams, want exactly the %d frames of the 15 non-H1 replays", d, replayedFrames)
		}
		for _, d := range writesWith(writes, replayAt, func(tapDgram) bool { return true }) {
			if d.addr != newAddr || isChallenge(d) {
				t.Fatalf("after the replays the passive wrote %v to %v (want only traffic to the client's address %v)", d.types(), d.addr, newAddr)
			}
		}
		requireSameCarrier(t, w, dc, pc, dcar.ID, pcar.ID, 1)

		// 3. A forged datagram from a foreign address: a fresh fseq inside
		// the window (900 ahead; fewer frames than that follow on this flow)
		// and a valid CRC, around an extension frame, which is skipped.
		top, _ := w.tap.topOf(flowID)
		forged := make([]byte, wire.FlowHeaderLen, 64)
		wire.PutFlowHeader(forged, flowID)
		forged = wire.AppendFrame(forged, wire.Header{Type: wire.Type(0x80), Fseq: top + 900}, []byte("forged"))
		forgeAt := time.Now()
		w.hub.Spoof(forged)
		time.Sleep(100 * time.Millisecond)
		_, writes = w.tap.snapshot()
		chal = writesWith(writes, forgeAt, isChallenge)
		if len(chal) == 0 || chal[0].addr == newAddr {
			t.Fatalf("stimulus: the forged datagram drew no challenge to its address: %+v", chal)
		}
		// The forged answer: the right nonce, from another foreign address.
		dropped0 = carrierDropped(pc, pcar.ID)
		var pong [wire.PingFixedLen]byte
		wire.PutPing(pong[:], &wire.Ping{ID: 0, Nonce: chal[0].frames[0].nonce})
		answer := make([]byte, wire.FlowHeaderLen, 64)
		wire.PutFlowHeader(answer, flowID)
		answer = wire.AppendFrame(answer, wire.Header{Type: wire.TypePong, Fseq: top + 901}, pong[:])
		answerAt := time.Now()
		w.hub.Spoof(answer)
		time.Sleep(3 * time.Second)
		_, writes = w.tap.snapshot()
		if late := writesWith(writes, answerAt, isChallenge); len(late) != 0 {
			t.Fatalf("challenges written after the forged answer: %+v", late)
		}
		// Dropped: the forged PONG, and each resend of the challenge within
		// its 2-s expiry, which the flow refuses — the PONG's source
		// replaced the rebind candidate — without harm to the carrier.
		if d := carrierDropped(pc, pcar.ID) - dropped0; d < 2 || d > 5 {
			t.Fatalf("after the forged challenge PONG the carrier dropped %d frames and datagrams, want the PONG and 1–4 refused challenge resends", d)
		}
		chal = writesWith(writes, forgeAt, isChallenge)
		for _, d := range chal {
			if d.addr != chal[0].addr || d.at.After(chal[0].at.Add(2*time.Second)) {
				t.Fatalf("challenge %v at %v after the first: want resends to the forged address only, within its 2-s expiry", d.addr, d.at.Sub(chal[0].at))
			}
		}
		for _, d := range writesWith(writes, forgeAt, func(tapDgram) bool { return true }) {
			if d.addr != newAddr && !isChallenge(d) {
				t.Fatalf("after the forgery the passive wrote %v to %v", d.types(), d.addr)
			}
		}
		requireSameCarrier(t, w, dc, pc, dcar.ID, pcar.ID, 1)
		t.Logf("forged datagram: %d challenges to %v; a forged answer from another address ignored; rebinds stay 1", len(chal), chal[0].addr)

		// 4. The carrier dies; replays of its H1 create no lane (R1-11).
		w.dconns.last().Close()
		killAt := time.Now()
		failover := waitFor(t, time.Second, "the failover", func() bool {
			l := liveOf(dc.Status())
			if len(l) != 1 || l[0].ID == dcar.ID {
				return false
			}
			c, ok := carrierOf(pc.Status(), l[0].ID)
			return ok && c.State == rendr.CarrierActive
		})
		failoverAt := time.Now()
		waitFor(t, 10*time.Second, "the old flow to leave", func() bool {
			c, ok := carrierOf(pc.Status(), pcar.ID)
			return ok && c.State == rendr.CarrierDead && w.p.Status().Datagram.Flows == 1
		})
		goneAt := time.Now()
		newCar := oneLive(t, "passive", pc)
		before := w.p.Status().Datagram
		replay1 := time.Now()
		w.hub.Replay(0, 0)
		time.Sleep(time.Second)
		st := w.p.Status()
		if st.Datagram.Dropped != before.Dropped+1 || st.Datagram.Flows != 1 || st.Handshakes != 0 {
			t.Fatalf("a replayed H1 of the removed flow: Dropped %d → %d, flows %d, handshakes %d; want +1, 1, 0",
				before.Dropped, st.Datagram.Dropped, st.Datagram.Flows, st.Handshakes)
		}
		_, writes = w.tap.snapshot()
		if ws := writesWith(writes, replay1, func(d tapDgram) bool { return d.flow == flowID }); len(ws) != 0 {
			t.Fatalf("the tombstoned flow was answered: %+v", ws)
		}

		// After the tombstone TTL (12 s by default) the ID attaches again:
		// the OPEN names a carrier the session already had.
		time.Sleep(goneAt.Add(12*time.Second + 500*time.Millisecond).Sub(time.Now()))
		replay2 := time.Now()
		w.hub.Replay(0, 0)
		waitFor(t, 5*time.Second, "the refused flow to leave", func() bool {
			_, writes := w.tap.snapshot()
			return len(writesWith(writes, replay2, func(d tapDgram) bool { return d.flow == flowID })) > 0 &&
				w.p.Status().Datagram.Flows == 1 && w.p.Status().Handshakes == 0
		})
		_, writes = w.tap.snapshot()
		ans := writesWith(writes, replay2, func(d tapDgram) bool { return d.flow == flowID })
		if !refusedBadRequest(ans) {
			t.Fatalf("the H1 replayed after the TTL was answered %v, want H2 then OPEN_ACK BAD_REQUEST", typesOf(ans))
		}
		if l := liveOf(pc.Status()); len(l) != 1 || l[0].ID != newCar.ID || len(w.pev.of(rendr.EventCarrierUp)) != 2 {
			t.Fatalf("the replay changed the session's carriers: %+v (%d carrier-up events)", pc.Status().Carriers, len(w.pev.of(rendr.EventCarrierUp)))
		}

		// Load and integrity: every datagram intact and at most once; up,
		// losses only at the kill; down, also between the move and the
		// commit (replies to the old address).
		time.Sleep(time.Second)
		up.halt(t, "up")
		down.halt(t, "down")
		time.Sleep(time.Second)
		endPair(t, dc, pc, up, down)
		kill := [2]time.Time{killAt.Add(-owd), failoverAt.Add(owd)}
		move := [2]time.Time{rebindAt.Add(-owd), commitAt}
		upIn, upOut := up.lostIn(kill)
		downMove, downOut := down.lostIn(move, kill)
		if len(upOut) != 0 || len(downOut) != 0 {
			t.Fatalf("losses away from the move and the kill: up %v, down %v", upOut, downOut)
		}
		if n := len(downMove); n > int((move[1].Sub(move[0])+kill[1].Sub(kill[0]))/(10*time.Millisecond))+2 {
			t.Fatalf("down: %d lost at the move and the kill, more than were written then", n)
		}
		if up.accepted.Load() < 2000 || down.accepted.Load() < 2000 {
			t.Fatalf("load: %d and %d datagrams written, want ≥ 2000 each way", up.accepted.Load(), down.accepted.Load())
		}
		w.noViolation()
		t.Logf("rebind committed %v after the move, failover %v after the kill; up %d datagrams, %d lost at the kill; down %d, %d lost at the move and the kill; old flow removed %v after the start, %v of virtual time",
			took, failover, up.accepted.Load(), len(upIn), down.accepted.Load(), len(downMove), goneAt.Sub(start), time.Since(start))
		w.close()
	})
}

// isChallenge reports a rebind challenge: a PING with id 0, alone.
func isChallenge(d tapDgram) bool {
	return len(d.frames) == 1 && d.frames[0].typ == wire.TypePing && d.frames[0].id == 0
}

// writesWith returns the datagrams in ws written at or after from that
// match.
func writesWith(ws []tapDgram, from time.Time, match func(tapDgram) bool) []tapDgram {
	var out []tapDgram
	for _, d := range ws {
		if !d.at.Before(from) && match(d) {
			out = append(out, d)
		}
	}
	return out
}

// typesOf lists the frame types of each datagram.
func typesOf(ds []tapDgram) [][]wire.Type {
	out := make([][]wire.Type, len(ds))
	for i, d := range ds {
		out[i] = d.types()
	}
	return out
}

// refusedBadRequest reports whether ds holds an H2 (a PREFACE_ACK, with
// the OPEN's address check) and an
// OPEN_ACK with status BAD_REQUEST, and nothing but repeats of those.
func refusedBadRequest(ds []tapDgram) bool {
	h2, refused := false, false
	for _, d := range ds {
		if d.preface {
			h2 = true
		}
		for _, f := range d.frames {
			switch {
			case f.typ == wire.TypeRack:
			case f.typ == wire.TypePing && f.id == 0 && d.preface: // H2's address check of an OPEN (R-C3-1)
			case f.typ == wire.TypeRel && f.inner == wire.TypeOpenAck:
				a, err := wire.ParseOpenAck(f.body)
				if err != nil || a.Status != wire.StatusBadRequest {
					return false
				}
				refused = true
			default:
				return false
			}
		}
	}
	return h2 && refused
}

// carrierDropped returns the Dropped count of carrier id.
func carrierDropped(c *rendr.PacketConn, id rendr.CarrierID) uint64 {
	cs, _ := carrierOf(c.Status(), id)
	return cs.Dropped
}

// requireSameCarrier requires that each end still has exactly the given
// carrier, with rebinds reply-address moves on the passive one, that no
// carrier went down, no migration happened and nothing was dialled again.
func requireSameCarrier(t testing.TB, w *world, dc, pc *rendr.PacketConn, did, pid rendr.CarrierID, rebinds uint64) {
	t.Helper()
	d, p := oneLive(t, "dialer", dc), oneLive(t, "passive", pc)
	ds, ps := dc.Status(), pc.Status()
	if d.ID != did || p.ID != pid || p.Rebinds != rebinds || w.p.Status().Datagram.Rebinds != rebinds {
		t.Fatalf("carriers: dialer %+v, passive %+v, Runtime rebinds %d; want IDs %d, %d and %d rebinds",
			d, p, w.p.Status().Datagram.Rebinds, did, pid, rebinds)
	}
	if ds.Migrations != (rendr.MigrationCounts{}) || ps.Migrations != (rendr.MigrationCounts{}) || ds.Rejoins != 0 ||
		len(w.dev.of(rendr.EventCarrierDown))+len(w.pev.of(rendr.EventCarrierDown)) != 0 || w.hub.Stats().Dials != 1 {
		t.Fatalf("the session changed carriers: migrations %+v/%+v, rejoins %d, carrier-down events %d/%d, dials %d",
			ds.Migrations, ps.Migrations, ds.Rejoins, len(w.dev.of(rendr.EventCarrierDown)), len(w.pev.of(rendr.EventCarrierDown)), w.hub.Stats().Dials)
	}
}
