package rendr

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
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
		// (flowsOpened, which Registry.Opened calls; through a real Confirm:
		// TestPacketAdmittingReleasedE2E_L48).
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
// nothing remains. (The open session's RST(GoingAway) reaching the dialer
// as *AbortError is TestRuntimeCloseOpenPacketSession.)
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

// The packet churn of gold/G6-mixed-nat in miniature (R-C3-1; B1.5, E19,
// M2-D59): every raw-UDP datagram of a NAT site reaches the passive from
// one source IP address, so the dialers behind it share that address's
// admitting quota. A pending session waits up to AcceptTimeout for the
// application; it must not hold the quota that later OPENs from the same
// address need, or their first datagrams are dropped silently and a
// never-accepted session ends no_path instead of ErrCapacity.

// churnSpec is one churn run over a peHub.
type churnSpec struct {
	sessions int           // dialled, one every gap
	gap      time.Duration // between two dials
	ignore   int           // every ignore-th session is never accepted (AcceptTimeout)
	dialCtx  time.Duration // each DialPacket's context (G6: 15 s)
	host     int           // the dialers' host (one source IP address)
}

// churnResult is what a churn run proved.
type churnResult struct {
	ignored, accepted int // sessions of each kind dialled
	maxIgnoring       int // the most never-accepted sessions dialling at once (the offered load)
	maxPending        int // the most passive sessions pending at once (AcceptBacklog[1])
	maxAdmitting      int // the most flows counted against the quotas at once
	failures          []string
}

// churnMeta tags a session: 'i' never accepted, 'a' accepted and echoed;
// the index follows.
func churnMeta(kind byte, i int) []byte {
	m := make([]byte, 5)
	m[0] = kind
	binary.BigEndian.PutUint32(m[1:], uint32(i))
	return m
}

// runChurn dials spec.sessions packet sessions from spec.host through two
// raw-UDP factories of that host (natu: u1, u2; selector and bond in
// turn). The passive application confirms the 'a' sessions and echoes one
// datagram, and never decides the 'i' ones. It samples the passive's
// Status every 50 ms while the churn runs.
func runChurn(t *testing.T, h *peHub, spec churnSpec) churnResult {
	t.Helper()
	p := h.peer(h.carrier("u1", spec.host, nil), h.carrier("u2", spec.host, nil))
	acceptTimeout := h.ln.cfg.AcceptTimeout

	actx, stopApp := context.WithCancel(context.Background())
	var app sync.WaitGroup
	app.Add(1)
	go func() { // the passive application
		defer app.Done()
		for {
			pp, err := h.ln.AcceptPacket(actx)
			if err != nil {
				return
			}
			md := pp.Metadata()
			if len(md) != 5 || md[0] != 'a' {
				continue // 'i': never decided; AcceptTimeout ends it with CAPACITY
			}
			pc, err := pp.Confirm()
			if err != nil {
				continue // the dialer's own failure is recorded on its side
			}
			app.Add(1)
			go func() {
				defer app.Done()
				defer pc.Close()
				buf := make([]byte, 2048)
				pc.SetReadDeadline(time.Now().Add(20 * time.Second))
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(buf[:n], nil)
				pc.SetReadDeadline(time.Now().Add(20 * time.Second))
				_, _, _ = pc.ReadFrom(buf) // until the dialer's close (io.EOF)
			}()
		}
	}()

	var (
		mu  sync.Mutex
		res churnResult
	)
	fail := func(format string, a ...any) {
		mu.Lock()
		res.failures = append(res.failures, fmt.Sprintf(format, a...))
		mu.Unlock()
	}
	sampled := make(chan struct{})
	done := make(chan struct{})
	go func() { // the Status samples
		defer close(sampled)
		for {
			st := h.p.Status()
			mu.Lock()
			res.maxPending = max(res.maxPending, st.AcceptBacklog[1])
			res.maxAdmitting = max(res.maxAdmitting, st.Datagram.Admitting)
			mu.Unlock()
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()

	var dials sync.WaitGroup
	ignoring := 0
	for i := range spec.sessions {
		kind := byte('a')
		if i%spec.ignore == 0 {
			kind = 'i'
			res.ignored++
		} else {
			res.accepted++
		}
		mode := ModeSelector
		if i%2 == 1 {
			mode = ModeBond
		}
		dials.Add(1)
		go func() {
			defer dials.Done()
			ctx, cancel := context.WithTimeout(context.Background(), spec.dialCtx)
			defer cancel()
			if kind == 'i' {
				mu.Lock()
				ignoring++
				res.maxIgnoring = max(res.maxIgnoring, ignoring)
				mu.Unlock()
				defer func() {
					mu.Lock()
					ignoring--
					mu.Unlock()
				}()
			}
			start := time.Now()
			c, err := p.DialPacket(ctx, DialOptions{Mode: mode, Metadata: churnMeta(kind, i)})
			took := time.Since(start)
			if kind == 'i' {
				switch {
				case c != nil:
					c.Close()
					fail("session %d (never accepted): DialPacket returned a session", i)
				case !errors.Is(err, ErrCapacity):
					fail("session %d (never accepted): %v after %v, want ErrCapacity", i, err, took)
				case took < acceptTimeout-100*time.Millisecond:
					fail("session %d (never accepted): ErrCapacity after %v, before AcceptTimeout %v", i, took, acceptTimeout)
				}
				return
			}
			if err != nil {
				fail("session %d (accepted): DialPacket: %v after %v", i, err, took)
				return
			}
			defer c.Close()
			want := bytes.Repeat(churnMeta('a', i), 40)
			if _, err := c.WriteTo(want, nil); err != nil {
				fail("session %d: WriteTo: %v", i, err)
				return
			}
			buf := make([]byte, 2048)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, _, err := c.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], want) {
				fail("session %d: echo %q (%v), want %d bytes of its own", i, buf[:n], err, len(want))
			}
		}()
		time.Sleep(spec.gap)
	}
	dials.Wait()
	close(done)
	<-sampled
	stopApp()
	app.Wait()
	p.Close()
	return res
}

// TestPacketChurnOneSource_E19 (R-C3-1; gold/G6-mixed-nat B1.5, E19,
// M2-D59 as amended): 80 packet sessions from one source IP address over
// two raw-UDP factories, one every 100 ms, every second one never
// accepted. The never-accepted sessions alone keep more pending sessions
// from that address than its OPEN quota (32 flows) can hold, for the whole
// AcceptTimeout of each. Every never-accepted session ends with
// ErrCapacity no earlier than the passive's AcceptTimeout, every accepted
// one opens and echoes its datagram intact, and nothing is left after the
// close.
func TestPacketChurnOneSource_E19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		res := runChurn(t, h, churnSpec{sessions: 80, gap: 100 * time.Millisecond, ignore: 2, dialCtx: 15 * time.Second})
		t.Logf("ignored %d (at most %d at once), accepted %d, max pending %d, max admitting %d, datagram %+v",
			res.ignored, res.maxIgnoring, res.accepted, res.maxPending, res.maxAdmitting, h.p.Status().Datagram)
		// Stimulus and load: more never-accepted sessions of the one
		// address dialling at once than its OPEN quota counts flows (each
		// has at least one OPEN flow), and every one of them was pending
		// at the passive at the same time: admission did not wait for the
		// quota.
		if res.maxIgnoring <= 32 {
			t.Fatalf("stimulus: at most %d never-accepted sessions at once, want more than the quota (32)", res.maxIgnoring)
		}
		for _, f := range res.failures {
			t.Error(f)
		}
		if res.maxPending < res.maxIgnoring {
			t.Errorf("at most %d sessions pending at once, below the %d never-accepted ones dialling", res.maxPending, res.maxIgnoring)
		}
		h.close()
	})
}

// TestPacketChurnBesideFlood_L58 (R-C3-1 with lesson/udp-flood's bounds,
// B1.11): a flood of valid packet OPEN and JOIN first datagrams from host
// 0's address — which never reads the passive's answers — runs while the
// churn of TestPacketChurnOneSource_E19 comes from host 1's address. The
// flood comes from four addresses (host 0's: OPENs only; three foreign
// ones: OPENs and JOINs) and the application never decides its sessions.
// Its flows stay inside those addresses' quotas — 32 OPEN flows each, and
// 32 JOIN flows on each foreign one: admitting ≤ 4·32 + 3·32 = 224 —
// counted while their sessions are pending, so the flood's pending
// sessions stay at most 4·32 = 128 and the flood's datagrams beyond them
// are dropped silently; the churn's pending sessions, whose dialers
// answered the address check, are not counted, exceed the quota, and
// every churn session gets its designed outcome. During the churn the
// churn's own unproven flows (inside their handshake, or answering a
// verdict) are bounded by host 1's OPEN quota: admitting ≤ 224 + 32. Once
// the churn ended, with the flood still running, admitting and flows are
// back inside the flood's bound (224) and its pending sessions inside 128.
func TestPacketChurnBesideFlood_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const floodAdmit, floodPending = 4*32 + 3*32, 4 * 32
		h := peNewHub(t, Config{}, ListenConfig{AcceptBacklog: 1024}, nil)
		stop := h.hub.Flood(4000, rendrtest.FloodMix{Random: 1, BadCRC: 1, Preface: 4, Join: 4})
		time.Sleep(2 * time.Second)
		st := h.p.Status()
		if st.Datagram.Admitting != floodAdmit || st.AcceptBacklog[1] != floodPending || st.Datagram.Dropped == 0 {
			t.Fatalf("stimulus: the flood fills its quotas (admitting %d, want %d; packet backlog %d, want %d; dropped %d)",
				st.Datagram.Admitting, floodAdmit, st.AcceptBacklog[1], floodPending, st.Datagram.Dropped)
		}
		dropped := st.Datagram.Dropped
		res := runChurn(t, h, churnSpec{sessions: 80, gap: 100 * time.Millisecond, ignore: 2, dialCtx: 15 * time.Second, host: 1})
		fs := h.hub.Stats()
		st = h.p.Status()
		t.Logf("ignored %d (at most %d at once), accepted %d, max pending %d, max admitting %d, datagram %+v, hub spoofed %d",
			res.ignored, res.maxIgnoring, res.accepted, res.maxPending, res.maxAdmitting, st.Datagram, fs.Spoofed)
		if res.maxIgnoring <= 32 || st.Datagram.Dropped <= dropped {
			t.Fatalf("stimulus: %d never-accepted sessions at once (want > 32), flood drops %d → %d", res.maxIgnoring, dropped, st.Datagram.Dropped)
		}
		if res.maxAdmitting > floodAdmit+32 {
			t.Errorf("admitting reached %d, want ≤ %d (the flood's quotas) + 32 (host 1's OPEN quota)", res.maxAdmitting, floodAdmit)
		}
		if res.maxPending <= floodPending+32 {
			t.Errorf("at most %d sessions pending at once, want the flood's %d plus more than 32 of the churn", res.maxPending, floodPending)
		}
		for _, f := range res.failures {
			t.Error(f)
		}
		time.Sleep(3 * time.Second) // the churn's verdicts end; the flood goes on
		synctest.Wait()
		if st := h.p.Status(); st.Datagram.Admitting > floodAdmit || st.Datagram.Flows > floodAdmit || st.AcceptBacklog[1] > floodPending {
			t.Errorf("the flood alone: admitting %d, flows %d (want ≤ %d), packet backlog %d (want ≤ %d)",
				st.Datagram.Admitting, st.Datagram.Flows, floodAdmit, st.AcceptBacklog[1], floodPending)
		}
		stop()
		time.Sleep(15 * time.Second) // the flood's pending sessions end (AcceptTimeout, verdicts, tombstones)
		h.close()
	})
}

// TestPacketSourceCheck_E19 (R-C3-1; M2-D59 as amended): the address
// check of a packet OPEN's H2 on a FromPacketConn flow. A pending
// session's OPEN flow counts against its source IP's admitting quota until
// its dialer answers the check with the nonce's PONG from the flow's own
// address; a PONG with another nonce changes nothing (a counted drop); the
// answer releases the flow once — a repeated answer, a window duplicate,
// releases nothing more, so another unanswered pending flow still counts;
// an answer from another address than the flow's (a rebind candidate)
// proves nothing; the session stays pending in the packet backlog either
// way. A JOIN's
// and a probe's H2 carry no check (the scripted dialer requires it only
// for an OPEN over a flow).
func TestPacketSourceCheck_E19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "check"})
		defer hub.Close()
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromPacketConn(hub.PacketConn())}})
		inst := wpInst(0xc5)

		a := wdHubDial(t, hub, inst, 1)
		a.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(1), 1, 1223, 1198))
		a.expectH2(rt)
		synctest.Wait()
		if st := rt.Status(); st.Datagram.Admitting != 1 || st.AcceptBacklog[1] != 1 {
			t.Fatalf("an unanswered check: %+v, packet backlog %d", st.Datagram, st.AcceptBacklog[1])
		}
		dropped := rt.Status().Datagram.Dropped
		a.answerCheck(1) // another nonce
		synctest.Wait()
		if st := rt.Status(); st.Datagram.Admitting != 1 || st.Datagram.Dropped != dropped+1 {
			t.Fatalf("a PONG with another nonce: %+v (dropped before %d)", st.Datagram, dropped)
		}
		a.answerCheck(0)
		synctest.Wait()
		if st := rt.Status(); st.Datagram.Admitting != 0 || st.Datagram.Flows != 1 || st.AcceptBacklog[1] != 1 {
			t.Fatalf("the check answered: %+v, packet backlog %d (want Admitting 0, the session pending)", st.Datagram, st.AcceptBacklog[1])
		}

		b := wdHubDial(t, hub, inst, 2)
		b.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(2), 1, 1223, 1198))
		b.expectH2(rt)
		a.answerCheck(0) // repeated: proves nothing more
		synctest.Wait()
		if st := rt.Status(); st.Datagram.Admitting != 1 || st.Datagram.Flows != 2 || st.AcceptBacklog[1] != 2 {
			t.Fatalf("a repeated answer and a second unanswered flow: %+v, packet backlog %d", st.Datagram, st.AcceptBacklog[1])
		}
		c := wdHubDial(t, hub, inst, 3)
		c.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(3), 1, 1223, 1198))
		c.expectH2(rt)
		hub.Rebind(2) // c's datagrams now come from another port: candidates
		c.answerCheck(0)
		synctest.Wait()
		if st := rt.Status(); st.Datagram.Admitting != 2 || st.Datagram.Flows != 3 || st.AcceptBacklog[1] != 3 {
			t.Fatalf("an answer from a rebind candidate: %+v, packet backlog %d (want Admitting 2)", st.Datagram, st.AcceptBacklog[1])
		}
		for range 3 {
			pp, err := ln.AcceptPacket(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := pp.Reject(1, ""); err != nil {
				t.Fatal(err)
			}
		}
		a.expectOpenAck(wire.StatusRejected, 1)
		b.expectOpenAck(wire.StatusRejected, 1)
		time.Sleep(3 * time.Second) // the verdicts' repetition window ends; the flows are removed
		synctest.Wait()
		if ds := rt.Status().Datagram; ds.Flows != 0 || ds.Admitting != 0 {
			t.Fatalf("after Reject: %+v", ds)
		}
		wdNoFlowRecords(t, rt)
		rt.Close()
		synctest.Wait()
		wpNoState(t, rt)
		a.close()
		b.close()
		c.close()
	})
}

// TestPacketSightedSourceBacklog_E19 (R-C3-1; M2-D59 as amended, L58): the
// trade-off of the address check. A source that answers it — a sighted
// host, here rendr's own dialers on one source IP address whose
// application is never accepted — is bounded like a stream listener's
// clients, not by its address's quota: its pending sessions fill the
// Listener's whole packet AcceptBacklog (40 here, above the OPEN quota of
// 32) while its flows leave the quota. Once the backlog is full every
// further packet OPEN — from that address and from another — is answered
// CAPACITY at once (not dropped silently: the dialer ends with
// ErrCapacity long before its attempt deadline), the backlog never grows
// past its bound, and Flows and Admitting stay bounded. The pending
// sessions end with ErrCapacity at AcceptTimeout, after which a session
// from the other address opens and echoes intact; nothing is left.
func TestPacketSightedSourceBacklog_E19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const backlog, extra = 40, 4
		h := peNewHub(t, Config{}, ListenConfig{AcceptBacklog: backlog}, nil)
		acceptTimeout := h.ln.cfg.AcceptTimeout
		p1 := h.peer(h.carrier("u1", 1, nil))
		p2 := h.peer(h.carrier("u2", 2, nil))

		var (
			mu         sync.Mutex
			failures   []string
			capacities int // dials ended with ErrCapacity
		)
		fail := func(format string, a ...any) {
			mu.Lock()
			failures = append(failures, fmt.Sprintf(format, a...))
			mu.Unlock()
		}
		// dial runs one DialPacket that must end with ErrCapacity within
		// [lo, hi] of its start.
		var dials sync.WaitGroup
		dial := func(p *Peer, name string, i int, lo, hi time.Duration) {
			dials.Add(1)
			go func() {
				defer dials.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				start := time.Now()
				c, err := p.DialPacket(ctx, DialOptions{Metadata: churnMeta('i', i)})
				took := time.Since(start)
				switch {
				case c != nil:
					c.Close()
					fail("%s session %d: DialPacket returned a session", name, i)
				case !errors.Is(err, ErrCapacity):
					fail("%s session %d: %v after %v, want ErrCapacity", name, i, err, took)
				case took < lo || took > hi:
					fail("%s session %d: ErrCapacity after %v, want within [%v, %v]", name, i, took, lo, hi)
				default:
					mu.Lock()
					capacities++
					mu.Unlock()
				}
			}()
		}

		for i := range backlog { // the sighted source fills the backlog
			dial(p1, "pending", i, acceptTimeout-100*time.Millisecond, acceptTimeout+2*time.Second)
			time.Sleep(20 * time.Millisecond)
		}
		peWait(t, 2*time.Second, "the full packet backlog", func() bool { return h.p.Status().AcceptBacklog[1] == backlog })
		synctest.Wait()
		st := h.p.Status()
		t.Logf("backlog full: packet backlog %d, datagram %+v", st.AcceptBacklog[1], st.Datagram)
		// Stimulus and load: more pending sessions from the one address
		// than its OPEN quota holds, every one proven and out of it.
		if st.AcceptBacklog[1] != backlog || st.Datagram.Flows != backlog || st.Datagram.Admitting != 0 {
			t.Fatalf("stimulus: packet backlog %d (want %d), flows %d (want %d), admitting %d (want 0)",
				st.AcceptBacklog[1], backlog, st.Datagram.Flows, backlog, st.Datagram.Admitting)
		}
		dropped := st.Datagram.Dropped

		over := time.Now()
		for i := range extra { // the backlog is full: CAPACITY at once, both addresses
			dial(p1, "same-address", backlog+i, 0, time.Second)
			dial(p2, "other-address", backlog+extra+i, 0, time.Second)
		}
		maxPending, maxFlows, maxAdmitting := 0, 0, 0
		for time.Since(over) < 2*time.Second {
			st := h.p.Status()
			maxPending = max(maxPending, st.AcceptBacklog[1])
			maxFlows = max(maxFlows, st.Datagram.Flows)
			maxAdmitting = max(maxAdmitting, st.Datagram.Admitting)
			time.Sleep(10 * time.Millisecond)
		}
		st = h.p.Status()
		mu.Lock()
		answered := capacities
		mu.Unlock()
		t.Logf("over the backlog: %d answered CAPACITY, max pending %d, max flows %d, max admitting %d, datagram %+v",
			answered, maxPending, maxFlows, maxAdmitting, st.Datagram)
		if answered != 2*extra {
			t.Errorf("%d of the %d OPENs over the full backlog ended with ErrCapacity within 2 s", answered, 2*extra)
		}
		if maxPending > backlog || maxFlows > backlog+2*extra || maxAdmitting > 2*extra {
			t.Errorf("over the backlog: pending %d (≤ %d), flows %d (≤ %d), admitting %d (≤ %d)",
				maxPending, backlog, maxFlows, backlog+2*extra, maxAdmitting, 2*extra)
		}
		if st.Datagram.Dropped != dropped {
			t.Errorf("over the backlog: Dropped %d → %d, want no silent drop", dropped, st.Datagram.Dropped)
		}

		dials.Wait() // the pending sessions end at AcceptTimeout
		for _, f := range failures {
			t.Error(f)
		}
		peWait(t, 5*time.Second, "an empty packet backlog", func() bool { return h.p.Status().AcceptBacklog[1] == 0 })

		// Afterwards a session from the other address opens.
		got := make(chan error, 1)
		go func() {
			pp, err := h.ln.AcceptPacket(context.Background())
			if err != nil {
				got <- err
				return
			}
			pc, err := pp.Confirm()
			if err != nil {
				got <- err
				return
			}
			defer pc.Close()
			buf := make([]byte, 2048)
			pc.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, _, err := pc.ReadFrom(buf)
			if err == nil {
				_, err = pc.WriteTo(buf[:n], nil)
			}
			got <- err
			pc.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, _, _ = pc.ReadFrom(buf) // until the dialer's close
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := p2.DialPacket(ctx, DialOptions{Metadata: churnMeta('a', 99)})
		cancel()
		if err != nil {
			t.Fatalf("a session after the backlog drained: %v", err)
		}
		want := bytes.Repeat(churnMeta('a', 99), 40)
		if _, err := c.WriteTo(want, nil); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _, err := c.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("echo %q (%v), want %d bytes of its own", buf[:n], err, len(want))
		}
		if err := <-got; err != nil {
			t.Fatalf("the passive application: %v", err)
		}
		c.Close()
		p1.Close()
		p2.Close()
		time.Sleep(15 * time.Second) // verdict repeats, flow removals and tombstones end
		h.close()
	})
}

// lossyCheckPC loses the dialer's first answers to an address check: a
// datagram that is one PONG with id 0, while lose > 0.
type lossyCheckPC struct {
	net.PacketConn
	lose atomic.Int32 // answers still to lose
	lost atomic.Int32 // answers lost
}

func (l *lossyCheckPC) WriteTo(b []byte, addr net.Addr) (int, error) {
	if f, n, err := wire.DecodeFrame(b); err == nil && n == len(b) && f.Type == wire.TypePong {
		if p, err := wire.ParsePing(f.Payload); err == nil && p.ID == 0 && l.lose.Add(-1) >= 0 {
			l.lost.Add(1)
			return len(b), nil // lost on the path
		}
	}
	return l.PacketConn.WriteTo(b, addr)
}

// TestPacketSourceCheckLostAnswer_E19 (R-C3-1; M2-D59 as amended): the
// dialer's answer to the address check is lost. The flow stays counted
// against its address's quota, and the dialer — which got H2, so it does
// not retransmit H1 — still sends its keepalive copies of H1 every
// RelRTOMax while it waits for the verdict (K5). The passive answers each
// copy with the stored H2 whose check PING moved to a fresh fseq, so the
// dialer's receive window takes it and answers again: the flow leaves the
// quota while its session is still pending, within one keepalive interval
// (2 s) plus a round trip, with exactly one answer lost. The session then
// opens and echoes intact.
func TestPacketSourceCheckLostAnswer_E19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		lossy := &lossyCheckPC{}
		lossy.lose.Store(1)
		dial := h.hub.DialFrom(1)
		p := h.peer(DatagramCarrier{Name: "lossy", MTU: 1223, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			pc, a, err := dial(ctx)
			if err != nil {
				return nil, nil, err
			}
			lossy.PacketConn = pc
			return lossy, a, nil
		}})
		type result struct {
			c   *PacketConn
			err error
		}
		res := make(chan result, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, err := p.DialPacket(ctx, DialOptions{Metadata: churnMeta('a', 1)})
			res <- result{c, err}
		}()
		peWait(t, 2*time.Second, "the pending session", func() bool { return h.p.Status().AcceptBacklog[1] == 1 })
		synctest.Wait()
		start := time.Now()
		// Stimulus: the answer was lost and the flow still counts.
		if st := h.p.Status(); lossy.lost.Load() != 1 || st.Datagram.Admitting != 1 {
			t.Fatalf("stimulus: %d answers lost (want 1), admitting %d (want 1)", lossy.lost.Load(), st.Datagram.Admitting)
		}
		peWait(t, 3*time.Second, "the flow leaving the quota", func() bool { return h.p.Status().Datagram.Admitting == 0 })
		if st := h.p.Status(); st.AcceptBacklog[1] != 1 || st.Datagram.Flows != 1 || lossy.lost.Load() != 1 {
			t.Fatalf("after the repeated check: packet backlog %d (want 1: pending), flows %d, lost %d",
				st.AcceptBacklog[1], st.Datagram.Flows, lossy.lost.Load())
		}
		t.Logf("the flow left the quota %v after the lost answer", time.Since(start))

		pp, err := h.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-res
		if r.err != nil {
			t.Fatalf("DialPacket: %v", r.err)
		}
		want := bytes.Repeat(churnMeta('a', 1), 40)
		if _, err := r.c.WriteTo(want, nil); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("the passive read %q (%v), want %d bytes of the dialer's", buf[:n], err, len(want))
		}
		peEnd(t, r.c, pc)
		p.Close()
		h.close()
	})
}

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

// wp12ClosePC records the Close calls of a FromPacketConn socket.
type wp12ClosePC struct {
	net.PacketConn
	closes atomic.Int32
}

func (c *wp12ClosePC) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

// TestRuntimeCloseAbortsSources_L50_L52 (integration 2, K7): Runtime.Close
// aborts its FromPacketConn sources at the close bound (M2 design §A4.6,
// M2-D58), so a flow that would outlive the join bound cannot keep the
// shared socket open past Close. The passive listens on a DatagramHub
// socket; the path has a 400-ms one-way delay (srtt ≈ 800 ms), and once
// the session runs the dialer → passive direction loses everything, so
// the passive's RST(GoingAway), GOAWAY and CLOSE are never acknowledged.
// Its carrier's retirement then lasts its full 2-s bound after the CLOSE
// (M2-D31), beyond the Runtime's own join bound (the passive's AbandonWait
// is 100 ms: 1 s + 100 ms + 250 ms). Without Source.Abort, Close would
// return with the flow, the source and the socket still alive.
//
// Stimulus: the passive had a live flow when Close began and the hub lost
// the dialer's datagrams meanwhile. Assertions: Close returns within the
// join bound; by then the passive session ended, no flow or source is
// left and the socket was closed exactly once; nothing is left on either
// Runtime and the bubble ends with no goroutine.
func TestRuntimeCloseAbortsSources_L50_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "hub", Queue: 8192})
		defer hub.Close()
		src := &wp12ClosePC{PacketConn: hub.PacketConn()}
		d := wpTestRuntime(t, Config{}, nil)
		const abandonWait = 100 * time.Millisecond
		p := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: abandonWait})
		ln := wpListen(t, p, ListenConfig{Sources: []Source{FromPacketConn(src)}})
		for _, dir := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
			hub.SetDelay(dir, 400*time.Millisecond, 0)
		}
		peer, err := d.NewPeer(PeerConfig{Carriers: []Carrier{DatagramCarrier{Name: "h0", Dial: hub.DialFrom(0), MTU: 1223}}})
		if err != nil {
			t.Fatal(err)
		}
		dc, pc := peOpen(t, peer, ln, DialOptions{})

		// Load both ways for 5 s: every datagram arrives, and the carriers
		// measure the 800-ms round trip.
		done := make(chan *rendrtest.PacketVerifier, 1)
		go func() { done <- peRecv(t, pc, 7, 500, 3*time.Second) }()
		peSend(t, dc, 7, 0, 500, 200)
		peWait(t, 5*time.Second, "an RTT sample of the round trip", func() bool {
			cs := peLive(pc)
			return len(cs) == 1 && cs[0].SRTT > 600*time.Millisecond
		})
		if v := <-done; v.Result().Unique != 500 {
			t.Fatalf("load: %+v", v.Result())
		}

		hub.SetLoss(rendrtest.Up, 1) // the passive never hears from the dialer again
		lost := hub.Stats().Session.Lost
		if st := p.Status().Datagram; st.Flows != 1 || st.Sources != 1 {
			t.Fatalf("stimulus: the passive has %+v, want one live flow of one source", st)
		}
		start := time.Now()
		p.Close()
		took := time.Since(start)
		st := p.Status()
		if bound := time.Second + abandonWait + 250*time.Millisecond; took > bound {
			t.Errorf("Runtime.Close took %v, beyond its join bound %v", took, bound)
		}
		select {
		case <-pc.Done():
		default:
			t.Error("the passive session had not ended when Runtime.Close returned")
		}
		if st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || src.closes.Load() != 1 {
			t.Errorf("after Runtime.Close: %+v, socket closed %d times; want no flow or source and one Close (Source.Abort)",
				st.Datagram, src.closes.Load())
		}
		if hub.Stats().Session.Lost == lost {
			t.Error("stimulus: no datagram of the dialer was lost during Close")
		}
		t.Logf("Runtime.Close took %v; passive carriers %+v", took, pc.Status().Carriers)

		d.Close()
		hub.Close()
		<-dc.Done()
		peNoState(t, d)
		peNoState(t, p)
	})
}

// TestIdleSourceBufferedBytes (R-C3-2; plan:774, gold/G6-mixed-nat's
// return_b_sessions): Status.BufferedBytes counts the MaxBufferedBytes
// budget and the reader stages of live carriers — not the read buffer a
// FromPacketConn source keeps for its socket. With a raw-UDP listener open
// and no session or carrier, BufferedBytes is 0: before any datagram, after
// junk datagrams the sources read and dropped (over real sockets:
// TestIdleUDPSourceBufferedBytes), and after a packet session whose
// datagrams were queued in its flow's inbox ended.
func TestIdleSourceBufferedBytes(t *testing.T) {
	t.Run("hub", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := peNewHub(t, Config{}, ListenConfig{}, nil)
			synctest.Wait()
			if st := h.p.Status(); st.Datagram.Sources != 1 || st.BufferedBytes != 0 {
				t.Fatalf("an idle FromPacketConn source: sources %d, BufferedBytes %d, want 1 and 0", st.Datagram.Sources, st.BufferedBytes)
			}
			// Load and integrity: a session over the source moves 200
			// datagrams each way through its flow's inbox, then ends.
			dc, pc := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
			peSend(t, dc, 1, 0, 200, 700)
			if v := peRecv(t, pc, 1, 200, time.Second); v.Result().Unique != 200 {
				t.Fatalf("dialer → passive: %+v", v.Result())
			}
			peSend(t, pc, 2, 0, 200, 700)
			if v := peRecv(t, dc, 2, 200, time.Second); v.Result().Unique != 200 {
				t.Fatalf("passive → dialer: %+v", v.Result())
			}
			if h.p.Status().BufferedBytes == 0 {
				t.Fatal("stimulus: a live carrier holds no buffered bytes")
			}
			peEnd(t, dc, pc)
			peWait(t, 5*time.Second, "the flow's removal", func() bool { return h.p.Status().Datagram.Flows == 0 })
			synctest.Wait()
			if st := h.p.Status(); st.Datagram.Sources != 1 || st.Sessions.Open+st.Sessions.Pending+st.Sessions.Lingering != 0 || st.BufferedBytes != 0 {
				t.Fatalf("after the session, the listener open: sources %d, sessions %+v, BufferedBytes %d, want 0", st.Datagram.Sources, st.Sessions, st.BufferedBytes)
			}
			h.close()
		})
	})
}

// End-to-end rows of integration 2 over a DatagramHub (FromPacketConn):
// the admitting quota, an open packet session at Runtime.Close, foreign
// and stuck sockets, and a shared socket closed once.

// TestPacketAdmittingReleasedE2E_L48 (M2-D59 as amended by R-C3-1; the
// WP8 review's surviving mutants): a packet session's raw-UDP OPEN flow
// leaves its source's admitting quota once rendr's dialer answered the
// address check of its H2 — while the session is still pending, so a
// pending session holds a backlog slot, not the quota (an unanswered
// check keeps it counted until Confirm: TestListenerCloseKeepsFlows_L50,
// TestPacketSourceCheck_E19) — and a bond member's JOIN flow leaves the
// quota at once; with every carrier attached Admitting is 0.
func TestPacketAdmittingReleasedE2E_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		ch := peDial(h.peer(h.carrier("h0", 0, nil), h.carrier("h1", 1, nil)), DialOptions{Mode: ModeBond})
		pp, err := h.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if st := h.p.Status(); st.Datagram.Admitting != 0 || st.Datagram.Flows < 1 || st.AcceptBacklog[1] != 1 {
			t.Fatalf("a pending session whose dialer answered the address check: Admitting %d (want 0), flows %d, packet backlog %d (want 1)",
				st.Datagram.Admitting, st.Datagram.Flows, st.AcceptBacklog[1])
		}
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		peWait(t, 5*time.Second, "both members", func() bool { return len(peLive(r.c)) == 2 })
		time.Sleep(100 * time.Millisecond)
		if ds := h.p.Status().Datagram; ds.Admitting != 0 || ds.Flows < 2 {
			t.Fatalf("after Confirm and the JOIN: %+v, want Admitting 0", ds)
		}
		peEnd(t, r.c, pc)
		h.close()
	})
}

// TestRuntimeCloseOpenPacketSession: the open-session half of
// TestRuntimeCloseSourcesLast. The passive Runtime closes while a packet
// session over its FromPacketConn socket is open: the session's
// RST(GoingAway) travels over the socket before it closes, so the
// dialer's ReadFrom ends with *AbortError(AbortGoingAway), within the close
// bound; nothing is left on either side.
func TestRuntimeCloseOpenPacketSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := peNewHub(t, Config{}, ListenConfig{}, nil)
		dc, _ := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
		res := make(chan error, 1)
		go func() {
			buf := make([]byte, 64)
			_, _, err := dc.ReadFrom(buf)
			res <- err
		}()
		start := time.Now()
		h.p.Close()
		var err error
		select {
		case err = <-res:
		case <-time.After(5 * time.Second):
			t.Fatal("the dialer's ReadFrom did not end within 5 s of the passive's Runtime.Close")
		}
		var ae *AbortError
		if !errors.As(err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
			t.Fatalf("the dialer's ReadFrom: %v, want *AbortError(AbortGoingAway) from the peer", err)
		}
		t.Logf("the dialer saw %v after %v", err, time.Since(start))
		<-dc.Done()
		h.close()
	})
}

// xorPC is a foreign net.PacketConn (not carrier/udp's): it XORs every
// datagram it reads and writes, so a peer that does the same can talk to
// rendr only if rendr uses the conn's own ReadFrom and WriteTo (L57).
type xorPC struct {
	net.PacketConn
	skip int         // bytes left as they are (the raw-UDP flow header on the shared socket)
	odd  chan []byte // datagrams to hand out from a non-UDPAddr source
}

func xorBytes(b []byte) {
	for i := range b {
		b[i] ^= 0x5a
	}
}

func (x *xorPC) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-x.odd:
		return copy(p, b), panicAddr{}, nil
	default:
	}
	n, a, err := x.PacketConn.ReadFrom(p)
	if n > x.skip {
		xorBytes(p[x.skip:n])
	}
	return n, a, err
}

func (x *xorPC) WriteTo(p []byte, a net.Addr) (int, error) {
	b := bytes.Clone(p)
	if len(b) > x.skip {
		xorBytes(b[x.skip:])
	}
	return x.PacketConn.WriteTo(b, a)
}

// TestFromPacketConnForeign_L57: a FromPacketConn socket that is not
// carrier/udp's is used through its methods only: an XOR wrapper on both
// ends carries a packet session (rendr reads and writes through the
// wrapper); a datagram from a source that is no *net.UDPAddr is dropped
// and counted without any method of its address being called; a Listen
// that fails (the same socket twice) never closes the caller's conn.
func TestFromPacketConnForeign_L57(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var x *xorPC
		h := peNewHub(t, Config{}, ListenConfig{}, func(pc net.PacketConn) net.PacketConn {
			x = &xorPC{PacketConn: pc, skip: wire.FlowHeaderLen, odd: make(chan []byte, 1)}
			return x
		})
		dial := h.hub.Dial
		p := h.peer(DatagramCarrier{Name: "x", MTU: 1223, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			pc, a, err := dial(ctx)
			if err != nil {
				return nil, nil, err
			}
			return &xorPC{PacketConn: pc}, a, nil
		}})
		dc, pc := peOpen(t, p, h.ln, DialOptions{})
		peSend(t, dc, 13, 0, 30, 400)
		if v := peRecv(t, pc, 13, 30, time.Second); v.Result().Unique != 30 {
			t.Fatalf("over the XOR conn: %+v", v.Result())
		}
		before := h.p.Status().Datagram.Dropped
		x.odd <- bytes.Repeat([]byte{1}, 40)
		peSend(t, dc, 13, 30, 5, 400) // a read after the odd one
		peRecv(t, pc, 13, 5, time.Second)
		if after := h.p.Status().Datagram.Dropped; after <= before {
			t.Fatalf("a datagram from a non-UDPAddr source was not dropped (Dropped %d → %d)", before, after)
		}
		peEnd(t, dc, pc)

		c := &countPC{PacketConn: h.hub.PacketConn()}
		if _, err := h.p.Listen(ListenConfig{Sources: []Source{FromPacketConn(c), FromPacketConn(c)}}); err == nil {
			t.Fatal("Listen with one socket twice succeeded")
		}
		if c.closes.Load() != 0 {
			t.Fatalf("a failed Listen closed the caller's conn %d times", c.closes.Load())
		}
		h.close()
	})
}

// stuckPC is a foreign socket whose ReadFrom ignores Close: after Close it
// blocks until release (L50: an embedder conn that does not unblock).
type stuckPC struct {
	net.PacketConn
	closed  chan struct{}
	release chan struct{}
	closes  atomic.Int32
	once    sync.Once
}

func (s *stuckPC) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		<-s.release
	}
	return n, a, err
}

func (s *stuckPC) Close() error {
	s.closes.Add(1)
	s.once.Do(func() { close(s.closed) })
	return s.PacketConn.Close()
}

// TestPacketSourceIgnoresClose_L50: Runtime.Close with an open packet
// session over a FromPacketConn socket whose ReadFrom ignores Close: the
// session ends (the dialer sees AbortGoingAway), the socket is closed
// exactly once, and Runtime.Close returns within its bound although the
// demux goroutine stays blocked in the embedder's ReadFrom: the source is
// gone (its Done closed) and the stuck read is counted in Status.Abandoned,
// still holding its Budget-charged read buffer. Once that ReadFrom
// returns, the demux goroutine leaves the abandoned pool and releases the
// buffer (L52). The source's Done is not that exit: the test waits for the
// pool and the Budget, not for Datagram.Sources, which was 0 already. A
// BufferedBytes above 0 after Close is the exception Status documents for
// buffers held by abandoned calls (M1's abandoned-call rule); it is
// required here so the drain after the release is observed, not assumed.
func TestPacketSourceIgnoresClose_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var s *stuckPC
		h := peNewHub(t, Config{}, ListenConfig{}, func(pc net.PacketConn) net.PacketConn {
			s = &stuckPC{PacketConn: pc, closed: make(chan struct{}), release: make(chan struct{})}
			return s
		})
		dc, _ := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
		start := time.Now()
		h.p.Close()
		took := time.Since(start)
		if took > 10*time.Second {
			t.Fatalf("Runtime.Close took %v with a socket that ignores Close", took)
		}
		if n := s.closes.Load(); n != 1 {
			t.Fatalf("the socket was closed %d times, want 1", n)
		}
		if st := h.p.Status(); st.Datagram.Sources != 0 || st.Abandoned != 1 || st.BufferedBytes == 0 {
			t.Fatalf("after Runtime.Close: sources %d, abandoned %d, buffered %d; want the source gone and its stuck read abandoned with its buffer",
				st.Datagram.Sources, st.Abandoned, st.BufferedBytes)
		}
		select {
		case <-dc.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the dialer session did not end")
		}
		var ae *AbortError
		if err := dc.Status().Err; !errors.As(err, &ae) || ae.Code != AbortGoingAway {
			t.Fatalf("the dialer's end: %v, want AbortGoingAway", err)
		}
		close(s.release)
		peWait(t, 5*time.Second, "the abandoned read returned", func() bool {
			st := h.p.Status()
			return st.Abandoned == 0 && st.BufferedBytes == 0
		})
		t.Logf("Runtime.Close returned after %v", took)
		h.close()
	})
}

// TestSharedSocketClosedOnceE2E_L50: Listener.Close keeps the flows of an
// open packet session (the socket stays open and the session works); the
// socket closes once its last flow ended, exactly once, and Runtime.Close
// closes nothing again.
func TestSharedSocketClosedOnceE2E_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c *countPC
		h := peNewHub(t, Config{}, ListenConfig{}, func(pc net.PacketConn) net.PacketConn {
			c = &countPC{PacketConn: pc}
			return c
		})
		dc, pc := peOpen(t, h.peer(h.carrier("h0", 0, nil)), h.ln, DialOptions{})
		h.ln.Close()
		time.Sleep(time.Second)
		if c.closes.Load() != 0 {
			t.Fatal("Listener.Close closed the socket of an open session")
		}
		peSend(t, dc, 14, 0, 20, 300)
		if v := peRecv(t, pc, 14, 20, time.Second); v.Result().Unique != 20 {
			t.Fatalf("after Listener.Close: %+v", v.Result())
		}
		peEnd(t, dc, pc)
		peWait(t, 5*time.Second, "the socket closed after the last flow", func() bool { return c.closes.Load() == 1 })
		h.close()
		if n := c.closes.Load(); n != 1 {
			t.Fatalf("the socket was closed %d times, want 1", n)
		}
	})
}
