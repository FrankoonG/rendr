package lessons7

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketFlowMisreportedWriteSentOnce_L42 is A3 of M5's second review
// wave on the passive's raw-UDP flows (L42): the passive listens on a
// DatagramHub's socket through rendr.FromPacketConn, so its flows write
// through udpflow's foreign-conn path, and that socket misreports one
// write — a datagram holding a DGRAM, sent whole, reported as len+1. The
// flow's write returns udpflow's invalid-count error, which matches
// carrier.ErrWriteCount: the flow's carrier dies, and its writer hands the
// datagram, which left, back to no session. Before A3 that error took the
// writer's default branch: the datagram went back, the bond placed it
// again on its other member, and it reached the dialer twice — the
// dialer's session dropped the second copy as a Duplicate.
//
// A bond session over the hub (h0: a raw-UDP flow on the passive) and a
// DatagramLink (a, HandlePacket), the same one-way delay on both; the
// passive writes mcCount datagrams of mcSize bytes, one per millisecond,
// and the wrapper is armed after mcArm of them. Criteria:
//
//   - Stimulus: the wrapper misreported a write of a data datagram on the
//     hub's socket, and the passive's h0 carrier died of it
//     (transport_error, its detail naming the invalid count).
//   - Once: the dialer's application read every datagram once, intact; the
//     passive's Sent, settled, equals the datagrams and the dialer's
//     Received, with no drop on either end and no Duplicate at the dialer.
//   - On the wire: the passive's writers tried every data datagram exactly
//     once — the misreported one left on h0 and was never written again
//     (before A3: once more, on a).
//   - Integrity: no violation, a clean end, nothing left after Close.
//
// The carrier-level rules (which datagrams of a misreported call go back)
// are proven on the writer (internal/carrier) and on Flow
// (internal/udpflow's TestFlowForeignWriteCount_L42); this row shows their
// composition on the passive end to end. The dialer's embedder adapter is
// internal/scenario/packet's TestPacketMisreportedWriteSentOnce_L42.
func TestPacketFlowMisreportedWriteSentOnce_L42(t *testing.T) {
	synctest.Test(t, misreportedFlow)
}

// Schedule of the row.
const (
	mcOneWay = 5 * time.Millisecond // every path: RTT 10 ms
	mcGap    = time.Millisecond
	mcCount  = 64
	mcArm    = 10  // the wrapper is armed after this many datagrams
	mcSize   = 777 // bytes per datagram: a data datagram holds [mcSize, mcSize+mcSpan) bytes of frames
	mcSpan   = 400 // the frames a datagram may carry in front of its DGRAM; a padded PONG is larger
	mcSeed   = 0x42c
)

// miscountPC is the passive's hub socket: the tap (it decodes and records
// what it reads and writes), and once armed, the first datagram written
// that holds mcSize-byte DGRAM traffic is sent whole and reported as
// len+1 — an embedder conn that misreports its count (L42).
type miscountPC struct {
	*tapPC
	armed, fired atomic.Bool
	mu           sync.Mutex
	at           time.Time // when the misreported write returned
}

func (p *miscountPC) WriteTo(b []byte, a net.Addr) (int, error) {
	if n := len(b) - wire.FlowHeaderLen; n >= mcSize && n < mcSize+mcSpan && p.armed.Load() && p.fired.CompareAndSwap(false, true) {
		m, err := p.tapPC.WriteTo(b, a)
		if err != nil {
			return m, err
		}
		p.mu.Lock()
		p.at = time.Now()
		p.mu.Unlock()
		return m + 1, nil
	}
	return p.tapPC.WriteTo(b, a)
}

// dataTries counts, per carrier, the data datagrams a side's writers
// tried (Hooks.BeforeWrite, every attempt: the misreported one included).
type dataTries struct {
	mu   sync.Mutex
	byID map[uint32]int
}

func (d *dataTries) before(id uint32, frames, bytes int) {
	if bytes < mcSize || bytes >= mcSize+mcSpan+wire.FlowHeaderLen {
		return
	}
	d.mu.Lock()
	if d.byID == nil {
		d.byID = map[uint32]int{}
	}
	d.byID[id]++
	d.mu.Unlock()
}

func (d *dataTries) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, k := range d.byID {
		n += k
	}
	return n
}

// newMiscountWorld is newWorld with the hub's socket served to the
// passive's Listener through mc (over the tap) and the passive's own
// hooks ph: a hook keyed by a CarrierID would otherwise run on both ends,
// which share the ID.
func newMiscountWorld(t testing.TB, o worldOpts, mc *miscountPC, ph *testhooks.Hooks) *world {
	t.Helper()
	w := &world{t: t, dev: &eventLog{}, pev: &eventLog{}}
	dov, pov := o.ov, o.ov
	pov.Hooks = ph
	dcfg, pcfg := o.dcfg, o.pcfg
	dcfg.OnEvent, pcfg.OnEvent = w.dev.add, w.pev.add
	w.d = newRuntime(t, dcfg, &dov)
	w.p = newRuntime(t, pcfg, &pov)
	w.hub = rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "hub", Queue: 8192})
	w.hub.SetDelay(rendrtest.Up, o.hubUp, 0)
	w.hub.SetDelay(rendrtest.Down, o.hubDown, 0)
	t.Cleanup(w.shutdown)
	w.tap = newTap(w.hub.PacketConn())
	w.tap.flowHdr = true
	mc.tapPC = w.tap
	lc := o.lc
	lc.Sources = append(lc.Sources, rendr.FromPacketConn(mc))
	ln, err := w.p.Listen(lc)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	return w
}

func misreportedFlow(t *testing.T) {
	mc := &miscountPC{}
	tries := &dataTries{}
	w := newMiscountWorld(t, worldOpts{hubUp: mcOneWay, hubDown: mcOneWay}, mc, &testhooks.Hooks{BeforeWrite: tries.before})
	_, link := w.addLink("a", mcOneWay)
	dc, pc := w.open(w.peer(w.hubCarrier("h0", 0), link), rendr.DialOptions{Mode: rendr.ModeBond})
	waitFor(t, 2*time.Second, "two members on both ends", func() bool {
		return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
	})
	var vic rendr.CarrierStatus
	for _, c := range liveOf(dc.Status()) {
		if c.Name == "h0" {
			vic = c
		}
	}
	if vic.ID == 0 {
		t.Fatalf("premise: the hub carrier is not a member: %+v", dc.Status().Carriers)
	}

	// The dialer's reader verifies every datagram; the passive's drains
	// its side until the dialer's clean end.
	ver := rendrtest.NewPacketVerifier(mcSeed)
	rdone := make(chan error, 1)
	go func() {
		buf := make([]byte, dc.MaxPayload()+1)
		for {
			n, _, err := dc.ReadFrom(buf)
			if err != nil {
				rdone <- err
				return
			}
			if verr := ver.Add(buf[:n], time.Now()); verr != nil {
				rdone <- verr
				return
			}
		}
	}()
	pdone := make(chan error, 1)
	go func() {
		buf := make([]byte, pc.MaxPayload()+1)
		_, _, err := pc.ReadFrom(buf)
		pdone <- err
	}()

	start := time.Now()
	buf := make([]byte, mcSize)
	for seq := range uint64(mcCount) {
		sleepTo(start.Add(time.Duration(seq) * mcGap))
		if seq == mcArm {
			mc.armed.Store(true)
		}
		if _, err := pc.WriteTo(rendrtest.PacketPayload(buf, mcSeed, seq, mcSize, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo of datagram %d: %v", seq, err)
		}
	}
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ps.Sent == mcCount && ds.Received == ps.Sent && ps.PeerReceived == ds.Received && ver.Result().Unique == mcCount
	})
	ds, ps := *dc.Status().Packet, *pc.Status().Packet

	// Stimulus.
	mc.mu.Lock()
	at := mc.at
	mc.mu.Unlock()
	if !mc.fired.Load() {
		t.Fatalf("stimulus: no data datagram write on the hub's socket was misreported (the passive tried %v)", tries.byID)
	}
	if c, ok := carrierOf(pc.Status(), vic.ID); !ok || c.State != rendr.CarrierDead || c.DeathCause != rendr.CauseTransportError ||
		!strings.Contains(c.DeathDetail, "invalid count") {
		t.Fatalf("stimulus: the passive's hub carrier %d is %+v (found %v), want it dead of the invalid count (transport_error)", vic.ID, c, ok)
	}

	// Once.
	if res := ver.Result(); res.Unique != mcCount || res.Duplicates+res.Corrupt+res.BadSize != 0 || len(res.Missing) != 0 {
		t.Fatalf("the dialer's application read %+v, want each of the %d datagrams once", res, mcCount)
	}
	if ds.Duplicates != 0 {
		t.Fatalf("the dialer counted %d duplicates: the misreported datagram, which left, was sent again (dialer %+v, passive %+v)",
			ds.Duplicates, ds, ps)
	}
	if drops(&ps)+ps.DropRecvQueue+ps.DropLate+drops(&ds)+ds.DropRecvQueue+ds.DropLate != 0 {
		t.Fatalf("a drop counter moved: dialer %+v, passive %+v", ds, ps)
	}

	// On the wire: each data datagram tried once, the misreported one
	// included.
	if n := tries.total(); n != mcCount {
		t.Fatalf("the passive tried %d data datagrams (%v), want %d: each once — the misreported one left and is never written again",
			n, tries.byID, mcCount)
	}
	t.Logf("the hub's socket misreported a data datagram of carrier %d %v after the start; passive tried %v; dialer %+v; passive %+v",
		vic.ID, at.Sub(start), tries.byID, ds, ps)

	// The clean end: the dialer closes, the passive reads io.EOF and
	// closes, the dialer's reader ends with net.ErrClosed.
	dc.Close()
	select {
	case err := <-pdone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("the passive's reader ended with %v, want io.EOF", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the passive's reader did not end")
	}
	pc.Close()
	select {
	case err := <-rdone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the dialer's reader ended with %v, want net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dialer's reader did not end")
	}
	waitDone(t, 10*time.Second, dc, pc)
	w.noViolation()
	w.close()
}
