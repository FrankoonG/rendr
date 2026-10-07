//go:build !race

// Zero-allocation gates (M2 design §A8.5; L41, L54, plan:324): asserted
// in the non-race lane only — the race detector makes sync.Pool drop items
// on purpose, so pooled buffers allocate under -race.

package udpflow

import (
	"encoding/binary"
	"runtime"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestFlowRouteZeroAllocs_L41_L58 drives the demux's per-datagram step
// directly: junk, refused valid H1s (quota, tombstone, VERSION) and a known
// flow's datagram through push, pop and release allocate nothing.
func TestFlowRouteZeroAllocs_L41_L58(t *testing.T) {
	env := testEnv(1 << 30)
	c := newFakeConn()
	c.discard = true // the fake records no answers: its own copies would count
	s := NewSource(env, c, Limits{PerSource: 1})
	var flows []*Flow
	r := &reader{s: s, admit: func(f *Flow) { flows = append(flows, f) }}
	from := udpAddr(2, 1000)
	ap := from.AddrPort()
	s.route(r, h1(1, wire.TypeOpen, 1), ap, from, false)
	if len(flows) != 1 {
		t.Fatalf("%d flows", len(flows))
	}
	f := flows[0]
	f.Admitted()
	s.route(r, h1(2, wire.TypeOpen, 1), ap, from, false)
	flows[1].Close()                                     // ID 2 is tombstoned
	s.route(r, h1(4, wire.TypeOpen, 1), ap, from, false) // holds the OPEN quota of 1
	if len(flows) != 3 {
		t.Fatalf("%d flows", len(flows))
	}
	if _, _, _, err := f.ReadDatagram(nil); err != nil {
		t.Fatal(err)
	}
	f.Release()

	cases := badDatagrams()
	cases["quota"] = h1(3, wire.TypeOpen, 1)
	cases["tombstone"] = h1(2, wire.TypeOpen, 1)
	major := prefaceBytes(wire.KindDatagram, 0x55)
	major[4] = wire.Major + 1
	binary.BigEndian.PutUint32(major[36:40], wire.CRC(major[:36]))
	cases["VERSION answer"] = dg(0x11, major)
	for name, b := range cases {
		if n := testing.AllocsPerRun(200, func() { s.route(r, b, ap, from, false) }); n != 0 {
			t.Errorf("%s: %v allocations per datagram", name, n)
		}
	}
	if len(flows) != 3 {
		t.Fatalf("junk created flows: %d", len(flows))
	}
	known := dg(1, pingFrame(2))
	n := testing.AllocsPerRun(1000, func() {
		s.route(r, known, ap, from, false)
		if _, _, ev, err := f.ReadDatagram(nil); err != nil || ev != carrier.ReadOK {
			t.Fatalf("read: %v, event %d", err, ev)
		}
		f.Release()
	})
	if n != 0 {
		t.Fatalf("a known flow's datagram: %v allocations", n)
	}
	f.Close()
}

// TestFlowOwnedSocketZeroAllocs_L41_L54 is the steady state over rendr's
// own socket on loopback: read by the demux, routed into the inbox
// (zero copy), popped, released and answered through the shared socket,
// with raw MemStats.Mallocs counted process-wide (as M1's Y4).
func TestFlowOwnedSocketZeroAllocs_L41_L54(t *testing.T) {
	rs := newRealSource(t, 1232)
	const id = 0x77
	rs.send(h1(id, wire.TypeOpen, 1))
	f := rs.flow()
	if err := f.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := rs.cl.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.ReadDatagram(nil); err != nil {
		t.Fatal(err)
	}
	f.Release()
	out := dg(id, pingFrame(2))
	wb := make([]byte, wire.FlowHeaderLen+64)
	rbuf := make([]byte, 2048)
	round := func() {
		if _, err := rs.cl.WriteToUDPAddrPort(out, rs.dst); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := f.ReadDatagram(nil); err != nil {
			t.Fatal(err)
		}
		f.Release()
		if err := f.WriteDatagram(wb); err != nil {
			t.Fatal(err)
		}
		if _, _, err := rs.cl.ReadFromUDPAddrPort(rbuf); err != nil {
			t.Fatal(err)
		}
	}
	// A GC moves every sync.Pool to its victim cache: it runs before the
	// warm-up, never between the warm-up and the measurement, or the
	// window would count the pools' chains being rebuilt.
	runtime.GC()
	for range 200 {
		round()
	}
	const rounds = 4000
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for range rounds {
		round()
	}
	runtime.ReadMemStats(&m1)
	if d := m1.Mallocs - m0.Mallocs; d > 40 {
		t.Fatalf("%d allocations in %d datagram round trips, want ≤ 40", d, rounds)
	}
}
