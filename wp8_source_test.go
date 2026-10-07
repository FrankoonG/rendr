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
		wdNoFlowRecords(t, rt)

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

// TestRuntimeCloseSourcesLast: Runtime.Close closes a FromPacketConn
// socket only after the sessions whose verdicts and GOAWAYs travel over it
// ended or had the close bound (M2 design §A4.6: the sessions' REL-wrapped
// RST(GoingAway)/GOAWAY, "then every source Aborts"). A pending packet
// session over the source is answered OPEN_ACK(GOING_AWAY) on its flow
// (after the carrier's GOAWAY) before the socket closes, exactly once, and
// nothing remains. (The open
// session's RST(GoingAway) reaching the dialer as *AbortError passes at
// integration 2.)
func TestRuntimeCloseSourcesLast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "last"})
		defer hub.Close()
		sock := &countPC{PacketConn: hub.PacketConn()}
		wpListen(t, rt, ListenConfig{Sources: []Source{FromPacketConn(sock)}})
		d := wdHubDial(t, hub, wpInst(0xc3), 1)
		d.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(30), 1, 1223, 1198))
		d.expectH2(rt)
		synctest.Wait()
		if st := rt.Status(); st.AcceptBacklog != [2]int{0, 1} || st.Datagram.Flows != 1 {
			t.Fatalf("a pending packet session over the source: %+v", st)
		}
		rt.Close()
		if n := sock.closes.Load(); n != 1 {
			t.Fatalf("the socket was closed %d times by Runtime.Close, want once", n)
		}
		if a, ok := d.wdFindOpenAck(); !ok || a.Status != wire.StatusGoingAway {
			t.Fatalf("the pending session's verdict before the socket closed: %+v (found %v), want OPEN_ACK(GOING_AWAY)", a, ok)
		}
		if ds := rt.Status().Datagram; ds.Sources != 0 || ds.Flows != 0 {
			t.Fatalf("after Runtime.Close: %+v", ds)
		}
		wpNoState(t, rt)
		wdNoFlowRecords(t, rt)
		d.close()
	})
}

// TestPacketSourcesPruned: the Runtime's record of FromPacketConn sources
// stays bounded by the live ones under repeated Listen and Listener.Close
// even when Status is never read (invariant 4): a finished source (its
// socket closed, its Done closed) is dropped at the next Listen.
func TestPacketSourcesPruned(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		for i := range 4 {
			hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "prune"})
			ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromPacketConn(hub.PacketConn())}})
			rt.mu.Lock()
			n := len(rt.sources)
			rt.mu.Unlock()
			if n != 1 {
				t.Fatalf("Listen %d: %d sources recorded, want only the live one", i, n)
			}
			ln.Close()
			synctest.Wait() // the stopped source has no flow: its socket closes, its Done closes
			hub.Close()
		}
		rt.Close()
	})
}

// TestPacketSourceValidation: Listen takes FromPacketConn sources beside
// FromListener ones; a nil net.PacketConn, or one given twice (it would get
// two demux loops and two Closes, M2-D58), fails Listen, and a failed
// Listen leaves every socket with the caller, unclosed.
func TestPacketSourceValidation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "v"})
		defer hub.Close()
		sock := &countPC{PacketConn: hub.PacketConn()}
		for _, srcs := range [][]Source{
			{FromPacketConn(nil)},
			{FromPacketConn(sock), FromPacketConn(sock)},
			{FromPacketConn(sock), FromListener(nil)},
		} {
			if ln, err := rt.Listen(ListenConfig{Sources: srcs}); ln != nil || err == nil {
				t.Fatalf("Listen(%v) = %v, %v", srcs, ln, err)
			}
		}
		if n := sock.closes.Load(); n != 0 || rt.Status().Datagram.Sources != 0 {
			t.Fatalf("a failed Listen closed the socket %d times (%d sources)", n, rt.Status().Datagram.Sources)
		}
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromPacketConn(sock)}})
		if ds := rt.Status().Datagram; ds.Sources != 1 {
			t.Fatalf("sources %d, want 1", ds.Sources)
		}
		ln.Close()
		synctest.Wait()
		if n, ds := sock.closes.Load(), rt.Status().Datagram; n != 1 || ds.Sources != 0 {
			t.Fatalf("Listener.Close without flows: socket closed %d times, %d sources; want 1 and 0", n, ds.Sources)
		}
		rt.Close()
		wpNoState(t, rt)
	})
}
