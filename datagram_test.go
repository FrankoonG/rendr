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

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

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
