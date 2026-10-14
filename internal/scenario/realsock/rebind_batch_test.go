package realsock

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// A NAT rebind whose rebind candidate sits behind earlier datagrams of the
// same batched read (L59; M5 design §A4.4, §A4.5, R3-14; K3 of M5's second
// review wave): carrier/udp on real loopback sockets, outside synctest
// bubbles, a NAT between the dialer and the passive's listening socket
// (rbNAT). Helpers carry the rb prefix.

// rbNAT is a NAT on loopback between a dialer's carrier/udp socket and a
// passive's listening socket dst: what the dialer sends to front leaves
// toward dst from outs[cur] (the mapping in use), and what reaches an out
// socket goes back to the dialer (the latest source front saw). While hold
// is set, front's datagrams are kept (held), in order, instead.
type rbNAT struct {
	t     testing.TB
	front *net.UDPConn
	dst   netip.AddrPort
	wg    sync.WaitGroup

	mu     sync.Mutex
	outs   []*net.UDPConn
	cur    int
	client netip.AddrPort
	hold   bool
	held   [][]byte
}

// rbListen opens a socket on the IPv4 loopback address.
func rbListen(t testing.TB) *net.UDPConn {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// newRbNAT starts a NAT toward dst with one mapping.
func newRbNAT(t testing.TB, dst netip.AddrPort) *rbNAT {
	n := &rbNAT{t: t, dst: dst, front: rbListen(t)}
	n.addOut()
	n.wg.Add(1)
	go n.forward()
	return n
}

// addOut opens a mapping — an out socket and its way back — and returns it;
// it does not become the current one.
func (n *rbNAT) addOut() *net.UDPConn {
	u := rbListen(n.t)
	n.mu.Lock()
	n.outs = append(n.outs, u)
	n.mu.Unlock()
	n.wg.Add(1)
	go n.reverse(u)
	return u
}

// forward moves the dialer's datagrams toward dst (or holds them).
func (n *rbNAT) forward() {
	defer n.wg.Done()
	buf := make([]byte, 1<<16)
	for {
		k, from, err := n.front.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		d := bytes.Clone(buf[:k])
		n.mu.Lock()
		n.client = from
		if n.hold {
			n.held = append(n.held, d)
			n.mu.Unlock()
			continue
		}
		_, _ = n.outs[n.cur].WriteToUDPAddrPort(d, n.dst)
		n.mu.Unlock()
	}
}

// reverse moves the passive's datagrams that reach u back to the dialer.
func (n *rbNAT) reverse(u *net.UDPConn) {
	defer n.wg.Done()
	buf := make([]byte, 1<<16)
	for {
		k, _, err := u.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		n.mu.Lock()
		c := n.client
		n.mu.Unlock()
		_, _ = n.front.WriteToUDPAddrPort(buf[:k], c)
	}
}

// setHold makes the NAT keep what the dialer sends from now on.
func (n *rbNAT) setHold() {
	n.mu.Lock()
	n.hold = true
	n.mu.Unlock()
}

// heldNow returns copies of the held datagrams.
func (n *rbNAT) heldNow() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([][]byte(nil), n.held...)
}

// moveBurst sends the held datagrams to dst back to back — every one from
// the current mapping but the last, which leaves from a new one: the NAT
// moved — and makes the new mapping current; hold stays set, so what the
// dialer sends next waits for flow. The sends run with GOMAXPROCS 1 and no
// blocking call between them, so no goroutine of either Runtime runs before
// the last datagram is queued at the passive's socket: the passive's next
// read finds them all (one recvmmsg on Linux amd64/arm64). It returns the
// datagrams sent.
func (n *rbNAT) moveBurst() [][]byte {
	nu := n.addOut()
	n.mu.Lock()
	held, old := n.held, n.outs[n.cur]
	n.held, n.cur = nil, len(n.outs)-1
	n.mu.Unlock()
	if len(held) == 0 {
		return nil
	}
	prev := runtime.GOMAXPROCS(1)
	for _, d := range held[:len(held)-1] {
		_, _ = old.WriteToUDPAddrPort(d, n.dst)
	}
	_, _ = nu.WriteToUDPAddrPort(held[len(held)-1], n.dst)
	runtime.GOMAXPROCS(prev)
	return held
}

// flow ends the hold: the datagrams held since leave from the current
// mapping first, in order, then the NAT forwards again.
func (n *rbNAT) flow() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, d := range n.held {
		_, _ = n.outs[n.cur].WriteToUDPAddrPort(d, n.dst)
	}
	n.held, n.hold = nil, false
}

// close closes the NAT's sockets and waits for its goroutines.
func (n *rbNAT) close() {
	n.front.Close()
	n.mu.Lock()
	for _, u := range n.outs {
		u.Close()
	}
	n.mu.Unlock()
	n.wg.Wait()
}

// rbOnlyDgram reports whether d — a datagram of the raw-UDP flow — holds
// exactly one frame, a DGRAM: an application datagram, no control.
func rbOnlyDgram(d []byte) bool {
	_, rb, err := wire.ParseFlowHeader(d)
	if err != nil {
		return false
	}
	f, k, err := wire.DecodeFrame(rb)
	return err == nil && k == len(rb) && f.Type == wire.TypeDgram
}

// rbPayload is application datagram i of attempt a.
func rbPayload(a, i int) []byte {
	p := make([]byte, 64)
	binary.BigEndian.PutUint32(p, uint32(a))
	binary.BigEndian.PutUint32(p[4:], uint32(i))
	for k := 8; k < len(p); k++ {
		p[k] = byte(a*31 + i*7 + k)
	}
	return p
}

// rbReader collects what the passive's application reads.
type rbReader struct {
	mu  sync.Mutex
	got [][]byte
	err error
}

func (r *rbReader) run(c *rendr.PacketConn, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 2048)
	for {
		k, _, err := c.ReadFrom(buf)
		r.mu.Lock()
		if err != nil {
			r.err = err
			r.mu.Unlock()
			return
		}
		r.got = append(r.got, bytes.Clone(buf[:k]))
		r.mu.Unlock()
	}
}

func (r *rbReader) read() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.got...)
}

// rbLive returns the session's one live carrier.
func rbLive(t testing.TB, st rendr.SessionStatus, side string) rendr.CarrierStatus {
	t.Helper()
	var live []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State != rendr.CarrierDead {
			live = append(live, c)
		}
	}
	if len(live) != 1 {
		t.Fatalf("%s: %d live carriers, want 1: %+v", side, len(live), st.Carriers)
	}
	return live[0]
}

// rbBurst is the application datagrams of one attempt: rbBurst − 1 leave
// from the old mapping, the last from the new one, all in one read of the
// passive's socket and — at most flowReadDepth (8) — in one ReadDatagrams
// of its flow, the candidate after the others.
const rbBurst = 6

// rbSpacing is how long an attempt after the first waits: the passive
// starts a rebind challenge at most once per max(RTO, 1 s) (the carrier's
// chalSpacingMin), counted from the previous attempt's; rbSettle is the
// first attempt's wait, for the control the dialer sends after the open
// (a RACK, the first PING, its schedule). Meanwhile rbKeepEvery spaces
// datagrams that keep the passive's socket busy, so its reader keeps its
// extras (no idle release, batchIdleRelease 1 s) and the burst after the
// wait is still read at depth 32.
const (
	rbSpacing   = 1300 * time.Millisecond
	rbSettle    = 300 * time.Millisecond
	rbKeepEvery = 100 * time.Millisecond
)

// TestRealUDPRebindCandidateInBatch_L59 (L59; M5 design §A4.4, §A4.5,
// R3-14; K3 of the second review wave): a selector packet session between
// two Runtimes over carrier/udp on loopback — the passive on one
// udp.Listen socket through FromPacketConn (rendr's own socket: recvmmsg
// on Linux amd64/arm64) — through a NAT whose mapping moves. Each attempt
// holds rbBurst application datagrams of the dialer at the NAT, then sends
// them to the passive back to back, the last one from a new mapping
// (rbNAT.moveBurst): the rebind candidate sits behind five datagrams of
// the old address in one read of the socket and in one ReadDatagrams of
// the flow. Every datagram reaches the passive's application once and
// intact — the candidate's too — and the rebind commits: the passive
// challenges the new address, the dialer's answer (held at the NAT until
// the burst was read) arrives from it, and the flow's reply address moves
// — Rebinds once per attempt, the same carrier on both ends, no death.
// Before its hold an attempt waits (rbSettle, then the passive's challenge
// spacing rbSpacing) while datagrams every rbKeepEvery keep the passive's
// socket busy, so its reader keeps reading at depth 32.
//
// Stimulus: on Linux amd64/arm64 one recv call of the passive moved the
// whole burst (RecvCalls +1, RecvDatagrams +rbBurst while the NAT held
// everything else), in at least one of up to five attempts; elsewhere the
// socket reads one datagram per call and the row checks delivery and the
// commit only. Mutant (rebindloss M3, sockio.go): a candidate met in a
// batched ReadDatagrams after other results released — its datagram never
// reaches the application.
func TestRealUDPRebindCandidateInBatch_L59(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	sock, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	nat := newRbNAT(t, sock.LocalAddr().(*net.UDPAddr).AddrPort())
	t.Cleanup(nat.close)
	c := udp.Carrier("u", "udp4", nat.front.LocalAddr().String(), udp.Options{})
	// No PING, PACK cadence or probe inside the attempts: the passive reads
	// only what the NAT releases.
	ov := &testhooks.Overrides{PingIdle: time.Minute, PacketPing: time.Minute, ProbeInterval: time.Hour}
	m := newMsPair(t, rendr.Config{}, ov, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}}, []rendr.Carrier{c})
	dc, pc := m.openPacket(rendr.ModeSelector)
	var rd rbReader
	var readers sync.WaitGroup
	readers.Add(1)
	go rd.run(pc, &readers)
	dcar, pcar := rbLive(t, dc.Status(), "dialer"), rbLive(t, pc.Status(), "passive")
	wait := 5 * time.Second
	if msRace {
		wait = 15 * time.Second
	}

	attempts, batched := 5, 0
	if !beBatching {
		attempts = 2
	}
	var log []string
	written := 0 // application datagrams the dialer wrote
	for a := 1; a <= attempts && batched == 0; a++ {
		// The first attempt lets the session's control after its open pass
		// (rbSettle); a later one waits out the challenge spacing. Either
		// way the socket is kept busy meanwhile.
		pause := rbSettle
		if a > 1 {
			pause = rbSpacing
		}
		for start := time.Now(); time.Since(start) < pause; time.Sleep(rbKeepEvery) {
			if _, err := dc.WriteTo(rbPayload(1000+a, written), nil); err != nil {
				t.Fatalf("attempt %d: keep-alive WriteTo: %v", a, err)
			}
			written++
		}
		msUntil(t, wait, fmt.Sprintf("attempt %d: the passive to read the %d datagrams before it", a, written), func() bool {
			return len(rd.read()) == written
		})
		nat.setHold()
		mark := len(rd.read())
		for i := range rbBurst {
			if _, err := dc.WriteTo(rbPayload(a, i), nil); err != nil {
				t.Fatalf("attempt %d: WriteTo %d: %v", a, i, err)
			}
			written++
		}
		msUntil(t, wait, fmt.Sprintf("attempt %d: the NAT to hold the %d datagrams", a, rbBurst), func() bool {
			return len(nat.heldNow()) >= rbBurst
		})
		io0 := m.p.Status().Datagram
		sent := nat.moveBurst()
		clean := len(sent) == rbBurst
		for _, d := range sent {
			clean = clean && rbOnlyDgram(d)
		}
		msUntil(t, wait, fmt.Sprintf("attempt %d: the passive to read the burst, the candidate's datagram included (L59)", a), func() bool {
			return len(rd.read())-mark >= rbBurst
		})
		io1 := m.p.Status().Datagram
		if clean && io1.RecvCalls-io0.RecvCalls == 1 && io1.RecvDatagrams-io0.RecvDatagrams == rbBurst {
			batched = a
		}
		log = append(log, fmt.Sprintf("attempt %d: %d datagrams released (only DGRAMs: %v), read by the passive in %d calls / %d datagrams",
			a, len(sent), clean, io1.RecvCalls-io0.RecvCalls, io1.RecvDatagrams-io0.RecvDatagrams))
		nat.flow()
		msUntil(t, wait, fmt.Sprintf("attempt %d: the rebind to commit", a), func() bool {
			return m.p.Status().Datagram.Rebinds == uint64(a)
		})

		got := rd.read()[mark:]
		if len(got) != rbBurst {
			t.Fatalf("attempt %d: the passive read %d datagrams, want the %d of the burst once each", a, len(got), rbBurst)
		}
		for i, g := range got {
			if !bytes.Equal(g, rbPayload(a, i)) {
				t.Fatalf("attempt %d: datagram %d read is not the one written (the candidate is %d)", a, i, rbBurst-1)
			}
		}
		if d, p := rbLive(t, dc.Status(), "dialer"), rbLive(t, pc.Status(), "passive"); d.ID != dcar.ID || p.ID != pcar.ID || p.Rebinds != uint64(a) {
			t.Fatalf("attempt %d: live carriers %d and %d (passive Rebinds %d); want the session's first, %d, with %d rebinds",
				a, d.ID, p.ID, p.Rebinds, dcar.ID, a)
		}
	}
	for _, l := range log {
		t.Log(l)
	}
	switch {
	case beBatching && batched == 0:
		t.Fatalf("stimulus: in %d attempts no read of the passive moved a whole burst of %d (the candidate behind the old address's datagrams)", attempts, rbBurst)
	case !beBatching:
		t.Logf("%s/%s reads one datagram per call: the candidate is never behind others in one recv call here (delivery and commit checked)", runtime.GOOS, runtime.GOARCH)
	}
	if st := pc.Status(); st.Packet == nil || st.Packet.Duplicates != 0 {
		t.Fatalf("the passive's packet counters %+v: want no duplicate", st.Packet)
	}

	dc.Close()
	pc.Close()
	msDone(t, dc.Done(), "the dialer session")
	msDone(t, pc.Done(), "the passive session")
	readers.Wait()
	m.close()
}
