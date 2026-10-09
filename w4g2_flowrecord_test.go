package rendr

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// pendingFlowRecord returns the flow record of the only passive packet
// session of rt: its length and how many of its flows are still live
// (not removed from their source).
func pendingFlowRecord(t testing.TB, rt *Runtime) (s *session.Session, n, live int) {
	t.Helper()
	rt.fmu.Lock()
	defer rt.fmu.Unlock()
	if len(rt.pflows) != 1 {
		t.Fatalf("%d flow records, want the pending session's alone", len(rt.pflows))
	}
	for k, fs := range rt.pflows {
		s, n = k, len(fs.flows)
		for _, fl := range fs.flows {
			if !fl.Removed() {
				live++
			}
		}
	}
	return s, n, live
}

// sendRelClose writes REL{cseq, CLOSE(retire)} at the dialer's next fseq:
// the carrier retires (no new frames follow) and ends.
func (d *wdDialer) sendRelClose(cseq uint32) {
	d.t.Helper()
	rel := make([]byte, wire.RelHeadLen+1)
	wire.PutRelHead(rel, &wire.RelHead{Cseq: cseq, Type: wire.TypeClose})
	rel[wire.RelHeadLen] = byte(wire.CloseRetire)
	b := wire.AppendFrame(nil, wire.Header{Type: wire.TypeRel, Fseq: d.tx}, rel)
	d.tx++
	if _, err := d.pc.WriteTo(b, d.peer); err != nil {
		d.t.Fatalf("writing REL{CLOSE}: %v", err)
	}
}

// ackPeerClose reads the passive's datagrams until its REL{CLOSE} (the
// answer to ours, after its RACK) and RACKs it, which completes the CLOSE
// exchange (R1-4) without waiting for the passive's resends to give up.
func (d *wdDialer) ackPeerClose() {
	d.t.Helper()
	for range 8 {
		b := d.read(time.Second)
		if b == nil {
			break
		}
		if wire.IsPreface(b) {
			continue // an H2 repeat
		}
		for _, f := range d.frames(b) {
			if f.Type != wire.TypeRel {
				continue
			}
			h, _, err := wire.ParseRel(f.Payload)
			if err != nil || h.Type != wire.TypeClose {
				continue
			}
			var rk [wire.RackLen]byte
			wire.PutRack(rk[:], &wire.Rack{CumAck: h.Cseq})
			ack := wire.AppendFrame(nil, wire.Header{Type: wire.TypeRack, Fseq: d.tx}, rk[:])
			d.tx++
			if _, err := d.pc.WriteTo(ack, d.peer); err != nil {
				d.t.Fatalf("writing the RACK of the passive's CLOSE: %v", err)
			}
			return
		}
	}
	d.t.Fatal("no REL{CLOSE} answered ours")
}

// TestPendingFlowRecordBounded_E19 (W4-L2-1; M2-D59, invariant 4): the
// flow record of a pending packet session keeps only its live OPEN
// flows. A pending session outlives its carriers, so a dialer may park a
// duplicate OPEN carrier on it, let it die and park the next one, for the
// whole AcceptTimeout. Here 200 duplicate OPEN carriers, each on a new
// FromPacketConn flow, answer the address check, are parked (the record
// then holds exactly two live flows: the first carrier's and theirs) and
// retire with REL{CLOSE} (the passive's CLOSE RACKed); each cycle ends
// with its flow removed from the source, while the session stays pending
// in the backlog, all within the AcceptTimeout. The record never exceeds
// MaxCarriersPerSession + 1 entries (before the fix it grew by one closed
// flow per cycle). The session is then rejected (the first carrier gets
// OPEN_ACK(REJECTED)), and no record, flow or state is left after
// Runtime.Close.
func TestPendingFlowRecordBounded_E19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rounds = 200
		rt := wpTestRuntime(t, Config{}, nil)
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "record"})
		defer hub.Close()
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromPacketConn(hub.PacketConn())}, AcceptTimeout: 60 * time.Second})
		bound := rt.eff.cfg.MaxCarriersPerSession + 1
		inst := wpInst(0xd2)
		sid := wpSID(1)

		a := wdHubDial(t, hub, inst, 1)
		a.sendH1(wire.TypeOpen, wdPacketOpen(sid, 1, 1223, 1198))
		a.expectH2(rt)
		a.answerCheck(0)
		synctest.Wait()
		if st := rt.Status(); st.AcceptBacklog[1] != 1 || st.Datagram.Flows != 1 || st.Datagram.Admitting != 0 {
			t.Fatalf("the pending session: %+v", st)
		}
		s0, _, _ := pendingFlowRecord(t, rt)

		start := time.Now()
		maxLen := 0
		for i := range rounds {
			d := wdHubDial(t, hub, inst, uint32(2+i))
			d.sendH1(wire.TypeOpen, wdPacketOpen(sid, 1, 1223, 1198))
			d.expectH2(rt)
			d.answerCheck(0)
			synctest.Wait()
			s, n, live := pendingFlowRecord(t, rt)
			maxLen = max(maxLen, n)
			if s != s0 || live != 2 || n > bound {
				t.Fatalf("round %d, parked: record of %d flows (%d live, want 2: the first and this one; at most %d), same session %v",
					i, n, live, bound, s == s0)
			}
			if st := rt.Status(); st.Datagram.Flows != 2 || st.AcceptBacklog[1] != 1 {
				t.Fatalf("round %d, parked: %+v", i, st)
			}
			d.sendRelClose(wire.FirstCseq + 1)
			d.ackPeerClose()
			// The retired carrier ends and its flow leaves the source
			// (a deterministic gate in virtual time, bounded).
			for range 100 {
				synctest.Wait()
				if rt.Status().Datagram.Flows == 1 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if st := rt.Status(); st.Datagram.Flows != 1 || st.AcceptBacklog[1] != 1 {
				t.Fatalf("round %d at %v, after REL{CLOSE}: %+v (the carrier's flow still live, or the session gone)", i, time.Since(start), st)
			}
			if _, n, live := pendingFlowRecord(t, rt); n > bound || live != 1 {
				t.Fatalf("round %d, after REL{CLOSE}: record of %d flows (%d live, want 1; at most %d)", i, n, live, bound)
			}
			d.close()
		}
		if el := time.Since(start); el >= 60*time.Second {
			t.Fatalf("the %d cycles took %v, past the AcceptTimeout", rounds, el)
		}
		t.Logf("%d park-and-die cycles in %v: the record held at most %d flows (bound %d)", rounds, time.Since(start), maxLen, bound)

		pp, err := ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if pp.s != s0 {
			t.Fatal("AcceptPacket returned another session than the pending one")
		}
		if err := pp.Reject(1, ""); err != nil {
			t.Fatal(err)
		}
		a.expectOpenAck(wire.StatusRejected, 1)
		time.Sleep(3 * time.Second) // the verdict's repetition window ends; the flow is removed
		synctest.Wait()
		if ds := rt.Status().Datagram; ds.Flows != 0 || ds.Admitting != 0 {
			t.Fatalf("after Reject: %+v", ds)
		}
		wdNoFlowRecords(t, rt)
		rt.Close()
		synctest.Wait()
		wpNoState(t, rt)
		wdNoFlowRecords(t, rt)
		a.close()
	})
}
