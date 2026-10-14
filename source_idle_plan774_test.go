package rendr_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The idle release of rendr's own UDP sockets, seen from Status (M5 work
// item srcidle; plan:774; M5 design R1-4 and R1-5 as the delegate's F-1
// decision amends them): real loopback sockets, outside synctest bubbles.

const (
	// idleRelease is internal/udpflow's and internal/carrier's
	// batchIdleRelease (unexported, 1 s; each package's
	// TestBatchIdleReleaseShared pins it there): a batching reader returns
	// its extras within 2 × idleRelease of its last datagram.
	idleRelease = time.Second
	// idleSlack is this row's scheduling allowance on top of
	// 2 × idleRelease (a real-socket row on a loaded host; the bound
	// itself is proved exactly by internal/udpflow's
	// TestIdlePacketListenerBufferedBytesZeroSeam_plan774 and
	// internal/carrier's TestBatchMemoryBounded_L16 in synctest bubbles).
	idleSlack = time.Second
)

// idleIO is what moves on a Runtime's own UDP sockets: one changes with
// every datagram they send or read.
func idleIO(rt *rendr.Runtime) [2]uint64 {
	d := rt.Status().Datagram
	return [2]uint64{d.RecvDatagrams + d.SentDatagrams, d.RecvCalls + d.SendCalls}
}

// idleZero waits until rt's Status.BufferedBytes is exactly 0 and fails
// if it is not within 2 × idleRelease + idleSlack of the last datagram
// rt's own sockets moved (or of since, when none moved since then) — the
// I/O counters are sampled every 5 ms, and a change restarts the bound —
// or not within 30 s at all. It returns the time from the last datagram
// to 0.
func idleZero(t *testing.T, rt *rendr.Runtime, what string) time.Duration {
	t.Helper()
	start := time.Now()
	last, io := start, idleIO(rt)
	for {
		st := rt.Status()
		now := time.Now()
		if st.BufferedBytes == 0 {
			return now.Sub(last)
		}
		if n := idleIO(rt); n != io {
			last, io = now, n
		}
		if now.Sub(last) > 2*idleRelease+idleSlack || now.Sub(start) > 30*time.Second {
			t.Fatalf("%s: BufferedBytes %d %v after the last datagram (%v after the wait began), want 0 within 2 × %v (plan:774); %s",
				what, st.BufferedBytes, now.Sub(last).Round(time.Millisecond), now.Sub(start).Round(time.Millisecond), idleRelease, idleState(st))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// idleState names what a Status says is alive.
func idleState(st rendr.Status) string {
	return fmt.Sprintf("sessions %+v, sessionless %d, mux carriers %d, sources %d, flows %d, recv %d datagrams in %d calls",
		st.Sessions, st.Sessionless, st.Mux.Carriers, st.Datagram.Sources, st.Datagram.Flows, st.Datagram.RecvDatagrams, st.Datagram.RecvCalls)
}

// idleEnded waits (30 s at most) until rt has no live session, no
// sessionless carrier, no mux carrier and no raw-UDP flow.
func idleEnded(t *testing.T, rt *rendr.Runtime, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned == 0 && st.Sessionless == 0 && st.Mux.Carriers == 0 && st.Datagram.Flows == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not ended within 30 s of the sessions' end: %s", what, idleState(st))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestIdlePacketListenerBufferedBytesZero_plan774 (plan:774; F-1; M5
// design R1-4, R1-5): Status.BufferedBytes of a Runtime with no session
// open is exactly 0 within 2 × batchIdleRelease of the last datagram its
// own sockets moved, with every Listener and Peer still alive.
//
//   - Listener: a passive Runtime whose Listener adopted a carrier/udp
//     Listen socket (the default MaxBatch: a reader of depth 32 on Linux
//     amd64 and arm64) — before any datagram arrived, after junk
//     datagrams were read and dropped, and after a selector packet session
//     over that socket exchanged sioRounds verified datagrams and ended
//     (the Listener and its source stay open: Datagram.Sources 1);
//   - dialer: the session's dialer Runtime, its Peer open, once the
//     session and its datagram carrier ended (the dialer reader's extras
//     and slot 0 went back with the carrier).
//
// While datagrams arrive the batching reader holds and counts its extras
// (internal/udpflow's TestFlowOwnedSocketCharge pins the amount); this row
// pins that they do not outlive the traffic. On every other target the
// sockets read one datagram per call and the row holds at once. Runtime
// Close then leaves nothing.
func TestIdlePacketListenerBufferedBytesZero_plan774(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	d, p := sioRuntimes(t)
	ls, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(ls)}}) // owns ls
	if err != nil {
		ls.Close()
		t.Fatal(err)
	}
	listening := func(what string) {
		t.Helper()
		if st := p.Status(); st.Datagram.Sources != 1 {
			t.Fatalf("%s: %s, want the Listener's source alive", what, idleState(st))
		}
		idleZero(t, p, what)
	}
	listening("a listening socket that never read a datagram")

	// Junk read and dropped.
	junk, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer junk.Close()
	for deadline := time.Now().Add(10 * time.Second); p.Status().Datagram.Dropped < 3; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the source dropped %d junk datagrams, want 3", p.Status().Datagram.Dropped)
		}
		_, _ = junk.WriteTo([]byte("junk"), ls.LocalAddr())
	}
	listening("a listening socket after junk")

	// A packet session over the socket, then its end.
	dc, pc := sioOpen(t, d, ln, udp.Carrier("u", "udp4", ls.LocalAddr().String(), udp.Options{}))
	sioPingPong(t, dc, pc) // closes pc
	dc.Close()
	for _, ch := range []<-chan struct{}{dc.Done(), pc.Done()} {
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
			t.Fatal("a session did not end within 30 s of its Close")
		}
	}
	if st := d.Status().Datagram; st.RecvDatagrams < sioRounds {
		t.Fatalf("stimulus: the dialer read %d datagrams, want at least %d", st.RecvDatagrams, sioRounds)
	}
	idleEnded(t, d, "the dialer")
	idleEnded(t, p, "the passive")
	t.Logf("dialer: BufferedBytes 0 %v after its last datagram", idleZero(t, d, "the dialer after its session and carrier ended").Round(time.Millisecond))
	listening("a listening socket after a packet session ended")

	d.Close()
	p.Close()
	for _, rt := range []*rendr.Runtime{d, p} {
		if st := rt.Status(); st.BufferedBytes != 0 || st.Datagram.Sources != 0 {
			t.Errorf("after Runtime.Close: BufferedBytes %d; %s", st.BufferedBytes, idleState(st))
		}
	}
}
