package rendr

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestListenerCloseKeepsFlows_L50: a FromPacketConn source of a Listener
// (M2-D58, M2-D59, §A5.14, §A4.6). Its flows' handshakes run in handshake
// slots and admit carriers of every kind: a probe flow becomes a
// sessionless carrier and leaves its source IP's admitting quota at once;
// a packet OPEN flow waits in the packet backlog and counts as admitting
// until Confirm writes its positive verdict (Status.Datagram.Admitting).
// Listener.Close stops admission — a new flow's H1 gets a stateless
// PREFACE_ACK(CAPACITY) and creates no flow — but never closes the shared
// socket under live flows; Runtime.Close closes it exactly once, and then
// no source, flow, handshake or buffered byte remains (L50, L52).
func TestListenerCloseKeepsFlows_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "src"})
		defer hub.Close()
		sock := &countPC{PacketConn: hub.PacketConn()}
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromPacketConn(sock)}})
		if ds := rt.Status().Datagram; ds.Sources != 1 || ds.Flows != 0 {
			t.Fatalf("after Listen: %+v", ds)
		}
		inst := wpInst(0xc1)

		probe := wdHubDial(t, hub, inst, 1)
		probe.wdProbe(rt)
		synctest.Wait()
		if st := rt.Status(); st.Sessionless != 1 || st.Datagram.Flows != 1 || st.Datagram.Admitting != 0 {
			t.Fatalf("a started probe carrier still counts as admitting: %+v", st)
		}

		open := wdHubDial(t, hub, inst, 2)
		open.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(1), 1, 1223, 1198))
		open.expectH2(rt)
		synctest.Wait()
		if st := rt.Status(); st.Datagram.Flows != 2 || st.Datagram.Admitting != 1 || st.AcceptBacklog != [2]int{0, 1} {
			t.Fatalf("a pending packet session's flow: %+v", st)
		}
		// A second OPEN carrier of the same pending session counts as well
		// (holdFlow), until Confirm's positive verdict releases both
		// (flowsOpened, which Registry.Opened calls; opening the session
		// itself needs the packet session actor: integration 2).
		dup := wdHubDial(t, hub, inst, 4)
		dup.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(1), 1, 1223, 1198))
		dup.expectH2(rt)
		synctest.Wait()
		if ds := rt.Status().Datagram; ds.Flows != 3 || ds.Admitting != 2 {
			t.Fatalf("a duplicate OPEN flow of the pending session: %+v", ds)
		}
		pp, err := ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		rt.flowsOpened(pp.s)
		if ds := rt.Status().Datagram; ds.Admitting != 0 {
			t.Fatalf("Confirm's verdict did not release the OPEN flows: %+v", ds)
		}
		late1 := wdHubDial(t, hub, inst, 5)
		late1.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(1), 1, 1223, 1198))
		late1.expectH2(rt)
		synctest.Wait()
		if ds := rt.Status().Datagram; ds.Flows != 4 || ds.Admitting != 0 {
			t.Fatalf("an OPEN flow attached after the verdict still counts: %+v", ds)
		}
		if err := pp.Reject(1, ""); err != nil {
			t.Fatal(err)
		}
		for _, d := range []*wdDialer{open, dup, late1} {
			d.expectOpenAck(wire.StatusRejected, 1)
		}
		time.Sleep(3 * time.Second) // the verdicts' repetition window ends; the flows are removed
		synctest.Wait()
		if ds := rt.Status().Datagram; ds.Flows != 1 || ds.Admitting != 0 {
			t.Fatalf("after Reject: %+v", ds)
		}

		ln.Close()
		late := wdHubDial(t, hub, inst, 3)
		late.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(2), 1, 1223, 1198))
		late.expectRefusal(wire.PrefaceCapacity)
		synctest.Wait()
		if st := rt.Status(); st.Datagram.Flows != 1 || st.Datagram.Sources != 1 || st.Sessionless != 1 || sock.closes.Load() != 0 {
			t.Fatalf("after Listener.Close: %+v, socket closed %d times", st, sock.closes.Load())
		}
		probe.wdProbePing(rt)

		rt.Close()
		synctest.Wait()
		if n := sock.closes.Load(); n != 1 {
			t.Fatalf("the shared socket was closed %d times, want once", n)
		}
		if ds := rt.Status().Datagram; ds.Sources != 0 || ds.Flows != 0 || ds.Admitting != 0 {
			t.Fatalf("after Runtime.Close: %+v", ds)
		}
		wpNoState(t, rt)
		for _, d := range []*wdDialer{probe, open, dup, late1, late} {
			d.close()
		}
	})
}
