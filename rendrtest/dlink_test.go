package rendrtest

import (
	"bytes"
	"context"
	"errors"
	"math/bits"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// dCounterNames names every datagram counter.
var dCounterNames = [nDctr]string{"Sent", "Delivered", "Lost", "Duplicated", "Reordered", "Oversize",
	"Injected", "Corrupted", "Truncated", "Foreign", "ScriptedWrites", "ReadFaults", "Held", "Killed", "Captured"}

// dExported maps DatagramCounts onto the counter order.
func dExported(c DatagramCounts) [nDctr]uint64 {
	return [nDctr]uint64{c.Sent, c.Delivered, c.Lost, c.Duplicated, c.Reordered, c.Oversize,
		c.Injected, c.Corrupted, c.Truncated, c.Foreign, c.ScriptedWrites, c.ReadFaults, c.Held, c.Killed, c.Captured}
}

// dSnap reads every counter of every class (all, session, probe).
func dSnap(n *dnet) (s [3][nDctr]uint64) {
	for c := range s {
		for k := range nDctr {
			s[c][k] = n.ctr[c][k].Load()
		}
	}
	return s
}

// dControlsRig is a link with one session carrier and one probe carrier
// whose first datagrams crossed.
type dControlsRig struct {
	r    *dRig
	s, p dCarrier
}

func newDControlsRig(t *testing.T) *dControlsRig {
	t.Helper()
	r := newDRig(t, DatagramLinkConfig{Name: "dcontrols"})
	s := r.dial()
	s.up(t, dH1Session(1, false))
	dRecv(t, s.srv)
	p := r.dial()
	p.up(t, dH1Probe(2))
	dRecv(t, p.srv)
	return &dControlsRig{r: r, s: s, p: p}
}

// sData and pData are datagrams the session and the probe carrier send.
func (g *dControlsRig) sData() []byte { return dRel(FrameFin, 2, 2, dFin()) }
func (g *dControlsRig) pData() []byte { return dFrame(FramePing, 2, pingPayload(2)) }

// TestDatagramLinkControlsCount_L60: every DatagramLink control has a
// stimulus counter in Stats, split by carrier class (session = first
// datagram PREFACE ‖ REL{OPEN or JOIN}, probe = PREFACE ‖ PING), so that a
// stimulus proof counts only what touched a session (L60, L63). Each row
// applies one control on a link carrying one session and one probe carrier
// and checks the control's effect and the exact per-class deltas of every
// counter; All = Session + Probe; Stats reports every counter of every
// class. (Needs internal/wire's REL codec: integration 1.)
func TestDatagramLinkControlsCount_L60(t *testing.T) {
	type deltas map[dctr][2]uint64 // counter → (session, probe) delta
	one := [2]uint64{1, 1}
	rows := []struct {
		name string
		act  func(t *testing.T, g *dControlsRig) deltas
	}{
		{"traffic", func(t *testing.T, g *dControlsRig) deltas {
			g.s.up(t, g.sData())
			g.p.up(t, g.pData())
			dRecv(t, g.s.srv)
			dRecv(t, g.p.srv)
			return deltas{dcSent: one, dcDelivered: one}
		}},
		{"SetDelay", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetDelay(Up, 20*time.Millisecond, 0)
			start := time.Now()
			g.s.up(t, g.sData())
			g.p.up(t, g.pData())
			dRecv(t, g.s.srv)
			dRecv(t, g.p.srv)
			if d := time.Since(start); d != 20*time.Millisecond {
				t.Fatalf("arrived after %v, want 20ms", d)
			}
			return deltas{dcSent: one, dcDelivered: one}
		}},
		{"SetRate", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetRate(Up, 10000)
			start := time.Now()
			g.s.up(t, dBytes(1000, 1))
			g.p.up(t, dBytes(1000, 2))
			dRecv(t, g.s.srv)
			if d := time.Since(start); d != 100*time.Millisecond {
				t.Fatalf("first datagram after %v, want 100ms", d)
			}
			dRecv(t, g.p.srv)
			if d := time.Since(start); d != 200*time.Millisecond {
				t.Fatalf("second datagram after %v, want 200ms (one shared bottleneck)", d)
			}
			return deltas{dcSent: one, dcDelivered: one}
		}},
		{"SetLoss", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetLoss(Up, 1)
			g.s.up(t, g.sData())
			g.p.up(t, g.pData())
			return deltas{dcSent: one, dcLost: one}
		}},
		{"SetDuplicate", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetDuplicate(Up, 1)
			for _, c := range []dCarrier{g.s, g.p} {
				b := dBytes(50, 3)
				c.up(t, b)
				for range 2 {
					if got, _ := dRecv(t, c.srv); !bytes.Equal(got, b) {
						t.Fatal("a copy differs")
					}
				}
			}
			return deltas{dcSent: one, dcDuplicated: one, dcDelivered: {2, 2}}
		}},
		{"SetReorder", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetReorder(Up, 1, 30*time.Millisecond)
			start := time.Now()
			g.s.up(t, g.sData())
			g.p.up(t, g.pData())
			dRecv(t, g.s.srv)
			dRecv(t, g.p.srv)
			if d := time.Since(start); d != 30*time.Millisecond {
				t.Fatalf("arrived after %v, want the 30ms reorder delay", d)
			}
			return deltas{dcSent: one, dcDelivered: one, dcReordered: one}
		}},
		{"SetMTU-refuse", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetMTU(100, MTURefuse)
			for _, c := range []dCarrier{g.s, g.p} {
				var tl *wire.DatagramTooLargeError
				if n, err := c.cli.WriteTo(make([]byte, 101), c.srvAddr); n != 0 || !errors.As(err, &tl) || tl.Max != 100 {
					t.Fatalf("oversize WriteTo = (%d, %v), want (0, max 100)", n, err)
				}
			}
			return deltas{dcOversize: one}
		}},
		{"SetMTU-drop", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetMTU(100, MTUDrop)
			g.s.up(t, make([]byte, 101))
			g.p.up(t, make([]byte, 101))
			return deltas{dcOversize: one, dcSent: one, dcLost: one}
		}},
		{"Blackhole", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.Blackhole(Down, true)
			g.s.down(t, g.sData())
			g.p.down(t, g.pData())
			return deltas{dcSent: one, dcLost: one}
		}},
		{"Stall", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.Stall(Up, true)
			g.s.up(t, g.sData())
			g.p.up(t, g.pData())
			dNothing(t, g.s.srv, time.Second)
			g.r.l.Stall(Up, false)
			dRecv(t, g.s.srv)
			dRecv(t, g.p.srv)
			return deltas{dcSent: one, dcDelivered: one, dcHeld: one}
		}},
		{"Kill", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.SetDelay(Up, time.Hour, 0)
			g.s.up(t, g.sData())
			g.p.up(t, g.pData())
			g.r.l.Kill()
			for _, pc := range []net.PacketConn{g.s.cli, g.s.srv, g.p.cli, g.p.srv} {
				if _, _, err := pc.ReadFrom(make([]byte, 10)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ReadFrom after Kill: %v", err)
				}
			}
			return deltas{dcSent: one, dcLost: one, dcKilled: one}
		}},
		{"DropNext", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.DropNext(Up, FrameFin, 1) // a FIN travels inside a REL
			g.s.up(t, g.sData())
			g.p.up(t, g.pData())
			dRecv(t, g.p.srv)
			second := dRel(FrameFin, 3, 3, dFin())
			g.s.up(t, second)
			if got, _ := dRecv(t, g.s.srv); !bytes.Equal(got, second) {
				t.Fatal("the dropped datagram arrived, or the next one did not")
			}
			return deltas{dcSent: {2, 1}, dcLost: {1, 0}, dcDelivered: one}
		}},
		{"CaptureNext", func(t *testing.T, g *dControlsRig) deltas {
			ch := g.r.l.CaptureNext(Up, FrameSched)
			g.p.up(t, g.pData())
			sched := dRel(FrameSched, 2, 2, dSched())
			g.s.up(t, sched)
			if got := dCaptured(t, ch); !bytes.Equal(got, sched) {
				t.Fatalf("captured %x, want the SCHED datagram", got)
			}
			dRecv(t, g.s.srv)
			dRecv(t, g.p.srv)
			return deltas{dcSent: one, dcDelivered: one, dcCaptured: {1, 0}}
		}},
		{"CorruptNext", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.CorruptNext(Up)
			g.r.l.CorruptNext(Up)
			for _, c := range []dCarrier{g.s, g.p} {
				b := dBytes(40, 4)
				c.up(t, b)
				got, _ := dRecv(t, c.srv)
				if flips := dBitDiff(got, b); flips != 1 {
					t.Fatalf("%d bits flipped, want 1", flips)
				}
			}
			return deltas{dcSent: one, dcDelivered: one, dcCorrupted: one}
		}},
		{"InjectRaw", func(t *testing.T, g *dControlsRig) deltas {
			b := dBytes(33, 5)
			g.r.l.InjectRaw(Up, b) // the newest carrier is the probe's
			if got, from := dRecv(t, g.p.srv); !bytes.Equal(got, b) || from != g.p.cliAddr {
				t.Fatalf("injected datagram %x from %v", got, from)
			}
			return deltas{dcInjected: {0, 1}, dcDelivered: {0, 1}}
		}},
		{"ScriptWrites", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.ScriptWrites(Up, WriteResult{ZeroWrite: true})
			if n, err := g.s.cli.WriteTo(g.sData(), g.s.srvAddr); n != 0 || err != nil {
				t.Fatalf("scripted WriteTo = (%d, %v), want (0, nil)", n, err)
			}
			g.r.l.ScriptWrites(Up, WriteResult{N: 1, Relative: true})
			if n, err := g.p.cli.WriteTo(g.pData(), g.p.srvAddr); n != len(g.pData())+1 || err != nil {
				t.Fatalf("scripted WriteTo = (%d, %v), want (len+1, nil)", n, err)
			}
			return deltas{dcScripted: one}
		}},
		{"ReadFaults", func(t *testing.T, g *dControlsRig) deltas {
			e1, e2 := errors.New("fault one"), errors.New("fault two")
			g.r.l.ReadFaults(Down, e1, e2)
			for i, c := range []dCarrier{g.s, g.p} {
				if _, _, err := c.srv.ReadFrom(make([]byte, 10)); err != []error{e1, e2}[i] {
					t.Fatalf("ReadFrom %d: %v", i, err)
				}
			}
			return deltas{dcReadFaults: one}
		}},
		{"TruncateNext", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.TruncateNext(Down, false)
			g.r.l.TruncateNext(Down, true)
			for i, c := range []dCarrier{g.s, g.p} {
				c.up(t, dBytes(10, 6))
				buf := make([]byte, 64)
				if n, _, err := c.srv.ReadFrom(buf); n != len(buf) || (err != nil) != (i == 1) {
					t.Fatalf("truncated ReadFrom %d = (%d, %v)", i, n, err)
				}
			}
			return deltas{dcSent: one, dcTruncated: one}
		}},
		{"ForeignNext", func(t *testing.T, g *dControlsRig) deltas {
			g.r.l.ForeignNext(Up)
			g.r.l.ForeignNext(Up)
			for _, c := range []dCarrier{g.s, g.p} {
				c.up(t, dBytes(20, 7))
				if _, from := dRecv(t, c.srv); sameAddr(from, c.cliAddr.(*net.UDPAddr)) {
					t.Fatal("the datagram came from the peer")
				}
			}
			return deltas{dcSent: one, dcDelivered: one, dcForeign: one}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newDControlsRig(t)
				defer g.r.l.Close()
				before := dSnap(g.r.l.n)
				want := row.act(t, g)
				synctest.Wait()
				after := dSnap(g.r.l.n)
				st := g.r.l.Stats()
				for c, cs := range []DatagramCounts{st.All, st.Session, st.Probe} {
					if dExported(cs) != after[c] {
						t.Errorf("class %d: Stats %v, counters %v", c, dExported(cs), after[c])
					}
				}
				for k := range nDctr {
					var d [3]uint64
					for c := range d {
						d[c] = after[c][k] - before[c][k]
					}
					w, ok := want[k]
					switch {
					case ok && (d[1] != w[0] || d[2] != w[1]):
						t.Errorf("%s: session %d, probe %d; want %d, %d", dCounterNames[k], d[1], d[2], w[0], w[1])
					case ok && w[0]+w[1] == 0:
						t.Errorf("%s: the row expects no stimulus", dCounterNames[k])
					case !ok && (d[1] != 0 || d[2] != 0):
						t.Errorf("%s moved (session %d, probe %d) without its control", dCounterNames[k], d[1], d[2])
					}
					if d[0] != d[1]+d[2] {
						t.Errorf("%s: all %d != session %d + probe %d", dCounterNames[k], d[0], d[1], d[2])
					}
				}
			})
		})
	}
}

// dBitDiff counts the bits in which a and b (of equal length) differ.
func dBitDiff(a, b []byte) int {
	if len(a) != len(b) {
		return -1
	}
	n := 0
	for i := range a {
		n += bits.OnesCount8(a[i] ^ b[i])
	}
	return n
}

// TestDatagramLinkClassifiesByFirstDatagram_L60: a carrier's class is
// fixed by the first datagram its dialer writes — whatever happens to that
// datagram (here: lost) and whatever the passive writes before it or the
// dialer writes later; every count of the carrier goes to that class. An
// unframed carrier is neither session nor probe. (Needs internal/wire's
// REL codec: integration 1.)
func TestDatagramLinkClassifiesByFirstDatagram_L60(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "classes"})
		defer r.l.Close()
		s, p, o := r.dial(), r.dial(), r.dial()
		s.down(t, dH1Probe(9)) // the passive's datagrams do not classify
		dRecv(t, s.cli)
		r.l.SetLoss(Up, 1)
		s.up(t, dH1Session(3, true))
		p.up(t, dH1Probe(4))
		o.up(t, dBytes(60, 8))
		r.l.SetLoss(Up, 0)
		s.up(t, dH1Probe(5)) // later datagrams do not reclassify
		p.up(t, dH1Session(6, false))
		o.up(t, dH1Session(7, false))
		for _, c := range []dCarrier{s, p, o} {
			dRecv(t, c.srv)
		}
		st := r.l.Stats()
		want := DatagramCounts{Sent: 2, Delivered: 1, Lost: 1}
		if st.Session != want || st.Probe != want {
			t.Fatalf("session %+v, probe %+v; want %+v each", st.Session, st.Probe, want)
		}
		// All adds the other carrier and the passive's unclassified datagram.
		if want := (DatagramCounts{Sent: 7, Delivered: 4, Lost: 3}); st.All != want {
			t.Fatalf("all %+v, want %+v", st.All, want)
		}
	})
}

// dArrival is one datagram a collector read.
type dArrival struct {
	b    []byte
	from net.Addr
	at   time.Time
}

// dCollect reads up to n datagrams from pc on a goroutine, recording when
// each arrived, until n were read or a read fails; the returned func waits
// for it.
func dCollect(pc net.PacketConn, n int) func() []dArrival {
	ch := make(chan []dArrival, 1)
	go func() {
		var out []dArrival
		buf := make([]byte, wire.MaxDatagram+1)
		for range n {
			k, from, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			out = append(out, dArrival{slices.Clone(buf[:k]), from, time.Now()})
		}
		ch <- out
	}()
	return func() []dArrival { return <-ch }
}

// TestDatagramLinkBoundaries_L36: datagrams of every size — empty to the
// 65,507-byte maximum — cross both directions whole and one by one, in
// write order without jitter, each from the address object the reader's
// end was given for its peer (the embedder adapter's pointer fast path).
// An equal *net.UDPAddr also reaches the peer; any other *net.UDPAddr is
// UDP to nowhere (lost, counted); a nil address or another address type
// fails WriteTo, as on a net.UDPConn. A reader buffer that is too short
// truncates Linux-style: n == len(p), counted.
func TestDatagramLinkBoundaries_L36(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "boundaries"})
		defer r.l.Close()
		c := r.dial()
		if c.cli.LocalAddr() != c.cliAddr || c.srv.LocalAddr() != c.srvAddr || sameAddr(c.cliAddr, c.srvAddr.(*net.UDPAddr)) {
			t.Fatalf("addresses: dialer %v (passive told %v), passive %v (dialer told %v)", c.cli.LocalAddr(), c.cliAddr, c.srv.LocalAddr(), c.srvAddr)
		}
		sizes := []int{0, 1, 5, 11, 257, 1200, wire.MaxDatagram}
		for _, dir := range []struct {
			w, r     net.PacketConn
			to, from net.Addr
		}{{c.cli, c.srv, c.srvAddr, c.cliAddr}, {c.srv, c.cli, c.cliAddr, c.srvAddr}} {
			for i, n := range sizes {
				dSend(t, dir.w, dBytes(n, i), dir.to)
			}
			for i, n := range sizes {
				if got, from := dRecv(t, dir.r); !bytes.Equal(got, dBytes(n, i)) || from != dir.from {
					t.Fatalf("datagram %d: %d bytes from %v, want %d from %v", i, len(got), from, n, dir.from)
				}
			}
		}
		equal := *c.srvAddr.(*net.UDPAddr)
		dSend(t, c.cli, []byte("equal address"), &equal)
		if got, _ := dRecv(t, c.srv); string(got) != "equal address" {
			t.Fatalf("got %q via an equal address", got)
		}
		dSend(t, c.cli, []byte("nowhere"), fakeAddr(9, 1))
		for _, a := range []net.Addr{&net.IPAddr{}, nil, (*net.UDPAddr)(nil)} {
			var op *net.OpError
			if n, err := c.cli.WriteTo([]byte("x"), a); n != 0 || !errors.As(err, &op) {
				t.Fatalf("WriteTo(%#v) = (%d, %v), want an error as net.UDPConn's", a, n, err)
			}
		}
		c.up(t, dBytes(10, 1))
		buf := make([]byte, 4)
		if n, from, err := c.srv.ReadFrom(buf); n != 4 || from != c.cliAddr || err != nil || !bytes.Equal(buf, dBytes(10, 1)[:4]) {
			t.Fatalf("short buffer: (%d, %v, %v) %x", n, from, err, buf)
		}
		dNothing(t, c.srv, time.Second)
		st := r.l.Stats()
		if want := (DatagramCounts{Sent: 17, Delivered: 15, Lost: 1, Truncated: 1}); st.All != want || st.Session != (DatagramCounts{}) || st.Probe != (DatagramCounts{}) {
			t.Fatalf("counters %+v, want all %+v and nothing classified", st, want)
		}
	})
}

// TestDatagramLinkDelayJitter: a delay is exact and per direction; with
// jitter every datagram arrives within delay ± jitter of its write, and
// datagrams overtake each other (reordering follows from jitter).
func TestDatagramLinkDelayJitter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "delay"})
		defer r.l.Close()
		c := r.dial()
		r.l.SetDelay(Up, 100*time.Millisecond, 0)
		r.l.SetDelay(Down, 7*time.Millisecond, 0)
		up, down := dCollect(c.srv, 1), dCollect(c.cli, 1)
		start := time.Now()
		c.up(t, []byte{1})
		c.down(t, []byte{2})
		if a, b := up(), down(); a[0].at.Sub(start) != 100*time.Millisecond || b[0].at.Sub(start) != 7*time.Millisecond {
			t.Fatalf("up after %v, down after %v; want 100ms and 7ms", a[0].at.Sub(start), b[0].at.Sub(start))
		}
		r.l.SetDelay(Up, 100*time.Millisecond, 50*time.Millisecond)
		got := dCollect(c.srv, 200)
		sent := make([]time.Time, 200)
		for i := range sent {
			sent[i] = time.Now()
			c.up(t, []byte{byte(i)})
			time.Sleep(time.Millisecond)
		}
		reordered, jittered, top := false, false, -1
		for _, a := range got() {
			i := int(a.b[0])
			d := a.at.Sub(sent[i])
			if d < 50*time.Millisecond || d > 150*time.Millisecond {
				t.Fatalf("datagram %d took %v, outside 100ms ± 50ms", i, d)
			}
			jittered = jittered || d != 100*time.Millisecond
			reordered = reordered || i < top
			top = max(top, i)
		}
		if !jittered || !reordered || top != 199 {
			t.Fatalf("jittered %v, reordered %v, last %d", jittered, reordered, top)
		}
	})
}

// TestDatagramLinkRateSharedBottleneck: SetRate is one bottleneck per
// direction shared by the link's carriers: datagrams of every carrier are
// transmitted one after the other in write order, each taking len/rate,
// before their delay; the other direction is not limited; a rate change
// applies to the datagrams written after it. Datagrams lost to a blackhole
// or a Kill give their bottleneck time back: the next datagram does not
// wait behind the lost backlog.
func TestDatagramLinkRateSharedBottleneck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "rate"})
		defer r.l.Close()
		a, b := r.dial(), r.dial()
		r.l.SetRate(Up, 10000)
		r.l.SetDelay(Up, 5*time.Millisecond, 0)
		ga, gb, gd := dCollect(a.srv, 2), dCollect(b.srv, 1), dCollect(a.cli, 1)
		start := time.Now()
		a.up(t, make([]byte, 1000)) // transmitted 0–100 ms
		b.up(t, make([]byte, 500))  // 100–150 ms
		a.up(t, make([]byte, 1000)) // 150–250 ms
		a.down(t, make([]byte, 5000))
		as, bs, ds := ga(), gb(), gd()
		at := func(x dArrival) time.Duration { return x.at.Sub(start) }
		if at(as[0]) != 105*time.Millisecond || at(bs[0]) != 155*time.Millisecond || at(as[1]) != 255*time.Millisecond || at(ds[0]) != 0 {
			t.Fatalf("arrivals %v, %v, %v; down %v", at(as[0]), at(bs[0]), at(as[1]), at(ds[0]))
		}
		r.l.SetRate(Up, 0)
		g := dCollect(a.srv, 1)
		start = time.Now()
		a.up(t, make([]byte, 1000))
		if d := g()[0].at.Sub(start); d != 5*time.Millisecond {
			t.Fatalf("unlimited after %v, want the 5ms delay only", d)
		}

		r.l.SetRate(Up, 10000)
		backlog := func(c dCarrier) { // 500 ms of bottleneck time, none of it arrived after 50 ms
			for range 5 {
				c.up(t, make([]byte, 1000))
			}
			time.Sleep(50 * time.Millisecond)
		}
		backlog(a)
		r.l.Blackhole(Up, true)
		r.l.Blackhole(Up, false)
		g = dCollect(a.srv, 1)
		start = time.Now()
		a.up(t, make([]byte, 1000))
		if d := g()[0].at.Sub(start); d != 105*time.Millisecond {
			t.Fatalf("after a blackhole: arrived after %v, want 105ms (the lost backlog's time given back)", d)
		}
		backlog(b)
		r.l.Kill()
		k := r.dial()
		g = dCollect(k.srv, 1)
		start = time.Now()
		k.up(t, make([]byte, 1000))
		if d := g()[0].at.Sub(start); d != 105*time.Millisecond {
			t.Fatalf("after a Kill: arrived after %v, want 105ms (the lost backlog's time given back)", d)
		}
	})
}

// TestDatagramLinkLossSeeded: SetLoss drops each datagram of its direction
// with its probability from a sequence seeded by the link's name: two
// links of one name lose the same datagrams, another name others; every
// datagram is delivered or counted lost; the other direction is lossless.
func TestDatagramLinkLossSeeded(t *testing.T) {
	lost := func(t *testing.T, name string) []int {
		var out []int
		synctest.Test(t, func(t *testing.T) {
			r := newDRig(t, DatagramLinkConfig{Name: name})
			defer r.l.Close()
			c := r.dial()
			r.l.SetLoss(Up, 0.25)
			for i := range 400 {
				c.up(t, []byte{byte(i), byte(i >> 8)})
				c.down(t, []byte{byte(i)})
			}
			st := r.l.Stats().All
			got := map[int]bool{}
			for range st.Sent - st.Lost - 400 {
				b, _ := dRecv(t, c.srv)
				got[int(b[0])|int(b[1])<<8] = true
			}
			for range 400 {
				dRecv(t, c.cli)
			}
			dNothing(t, c.srv, time.Second)
			for i := range 400 {
				if !got[i] {
					out = append(out, i)
				}
			}
			if st.Lost != uint64(len(out)) || st.Sent != 800 {
				t.Fatalf("Lost %d for %d missing, Sent %d", st.Lost, len(out), st.Sent)
			}
		})
		return out
	}
	a1, a2, b := lost(t, "loss-a"), lost(t, "loss-a"), lost(t, "loss-b")
	if !slices.Equal(a1, a2) || slices.Equal(a1, b) || len(a1) < 60 || len(a1) > 140 {
		t.Fatalf("lost %d, %d (same name), %d (other name); equal %v, %v", len(a1), len(a2), len(b), slices.Equal(a1, a2), slices.Equal(a1, b))
	}
}

// TestDatagramLinkDuplicate_L39: SetDuplicate delivers a datagram twice
// with its probability — byte-identical copies, counted — and a copy takes
// no bottleneck time.
func TestDatagramLinkDuplicate_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "dup"})
		defer r.l.Close()
		c := r.dial()
		r.l.SetDuplicate(Up, 1)
		for i := range 10 {
			c.up(t, []byte{byte(i)})
		}
		for i := range 20 {
			if b, _ := dRecv(t, c.srv); int(b[0]) != i/2 {
				t.Fatalf("datagram %d is %d: copies do not follow their originals", i, b[0])
			}
		}
		r.l.SetDuplicate(Up, 0.5)
		for i := range 200 {
			c.up(t, []byte{byte(i)})
		}
		dups := r.l.Stats().All.Duplicated - 10
		if dups < 60 || dups > 140 {
			t.Fatalf("%d duplicates of 200 at p = 0.5", dups)
		}
		for range 200 + dups {
			dRecv(t, c.srv)
		}
		dNothing(t, c.srv, time.Second)
		r.l.SetDuplicate(Up, 1)
		r.l.SetRate(Up, 1000)
		g := dCollect(c.srv, 2)
		start := time.Now()
		c.up(t, make([]byte, 100))
		if as := g(); as[0].at.Sub(start) != 100*time.Millisecond || as[1].at != as[0].at {
			t.Fatalf("original after %v, copy after %v; want both at 100ms", as[0].at.Sub(start), as[1].at.Sub(start))
		}
	})
}

// TestDatagramLinkReorder_L43: SetReorder delays a datagram of its
// direction by its extra delay with its probability (counted), so that it
// arrives after datagrams written later.
func TestDatagramLinkReorder_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "reorder"})
		defer r.l.Close()
		c := r.dial()
		r.l.SetReorder(Up, 0.3, 20*time.Millisecond)
		g := dCollect(c.srv, 100)
		sent := make([]time.Time, 100)
		for i := range sent {
			sent[i] = time.Now()
			c.up(t, []byte{byte(i)})
			time.Sleep(time.Millisecond)
		}
		late, overtaken := 0, 0
		top := -1
		for _, a := range g() {
			i := int(a.b[0])
			switch d := a.at.Sub(sent[i]); d {
			case 0:
			case 20 * time.Millisecond:
				late++
				if top > i {
					overtaken++
				}
			default:
				t.Fatalf("datagram %d took %v", i, d)
			}
			top = max(top, i)
		}
		if n := r.l.Stats().All.Reordered; n != uint64(late) || late < 15 || late > 45 || overtaken < late-1 {
			t.Fatalf("Reordered %d, late %d, overtaken %d", n, late, overtaken)
		}
	})
}

// TestDatagramLinkMTU_L37: a datagram above the MTU is refused by WriteTo
// with *wire.DatagramTooLargeError{Max: MTU} (MTURefuse, the default; the
// conn lives) or silently lost (MTUDrop); both count as Oversize, a lost
// one also as Sent and Lost. The default MTU is the UDP maximum.
func TestDatagramLinkMTU_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "mtu", MTU: 1200})
		defer r.l.Close()
		c := r.dial()
		refused := func(n, max int) {
			t.Helper()
			var tl *wire.DatagramTooLargeError
			if k, err := c.cli.WriteTo(make([]byte, n), c.srvAddr); k != 0 || !errors.Is(err, wire.ErrDatagramTooLarge) || !errors.As(err, &tl) || tl.Max != max {
				t.Fatalf("WriteTo(%d) = (%d, %v), want a refusal with Max %d", n, k, err, max)
			}
		}
		refused(1201, 1200)
		c.up(t, make([]byte, 1200))
		dRecv(t, c.srv)
		r.l.SetMTU(1000, MTUDrop)
		c.up(t, make([]byte, 1001))
		dNothing(t, c.srv, time.Second)
		c.up(t, make([]byte, 1000))
		dRecv(t, c.srv)
		r.l.SetMTU(0, MTURefuse)
		refused(wire.MaxDatagram+1, wire.MaxDatagram)
		c.up(t, make([]byte, wire.MaxDatagram))
		dRecv(t, c.srv)
		if st := r.l.Stats().All; st != (DatagramCounts{Sent: 4, Delivered: 3, Lost: 1, Oversize: 3}) {
			t.Fatalf("counters %+v", st)
		}
		defer func() {
			if recover() == nil {
				t.Fatal("an unknown MTUMode was accepted")
			}
		}()
		r.l.SetMTU(100, 0)
	})
}

// TestDatagramLinkBlackhole: a blackhole loses every datagram of its
// direction — new ones and the ones in flight or held by a stall when it
// begins — while the ones that already arrived stay readable and the other
// direction passes; off, datagrams pass again.
func TestDatagramLinkBlackhole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "blackhole"})
		defer r.l.Close()
		c := r.dial()
		c.up(t, []byte("arrived"))
		r.l.SetDelay(Up, 100*time.Millisecond, 0)
		c.up(t, []byte("in flight"))
		time.Sleep(50 * time.Millisecond)
		r.l.Blackhole(Up, true)
		c.up(t, []byte("new"))
		c.down(t, []byte("other direction"))
		if got, _ := dRecv(t, c.srv); string(got) != "arrived" {
			t.Fatalf("got %q", got)
		}
		dNothing(t, c.srv, time.Second)
		if got, _ := dRecv(t, c.cli); string(got) != "other direction" {
			t.Fatalf("got %q", got)
		}
		r.l.Stall(Up, true)
		r.l.Blackhole(Up, false)
		c.up(t, []byte("held"))
		r.l.Blackhole(Up, true)
		r.l.Stall(Up, false)
		r.l.Blackhole(Up, false)
		dNothing(t, c.srv, time.Second)
		c.up(t, []byte("after"))
		if got, _ := dRecv(t, c.srv); string(got) != "after" {
			t.Fatalf("got %q", got)
		}
		if st := r.l.Stats().All; st.Lost != 3 || st.Delivered != 3 {
			t.Fatalf("Lost %d, Delivered %d; want 3, 3", st.Lost, st.Delivered)
		}
	})
}

// TestDatagramLinkStall: a stall holds its direction — nothing that had
// not arrived when it began arrives, WriteTo keeps returning, at most Queue
// datagrams wait (the rest are lost) — and the release delivers the
// datagrams whose arrival time passed at once and transmits the waiting
// ones from then on, at the rate; the other direction is not held. Every
// datagram the stall held is counted: written while held, or on its way
// with an arrival time inside the stall. A second Stall(on) does not move
// the stall's start.
func TestDatagramLinkStall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "stall", Queue: 4})
		defer r.l.Close()
		c := r.dial()
		r.l.SetDelay(Up, 10*time.Millisecond, 0)
		start := time.Now()
		c.up(t, []byte{1}) // due at 10 ms
		time.Sleep(5 * time.Millisecond)
		r.l.Stall(Up, true)
		c.up(t, []byte{2}) // written while held
		c.down(t, []byte{9})
		if got, _ := dRecv(t, c.cli); got[0] != 9 {
			t.Fatal("the other direction was held")
		}
		time.Sleep(45 * time.Millisecond) // past datagram 1's arrival time
		dNothing(t, c.srv, 50*time.Millisecond)
		g := dCollect(c.srv, 2)
		r.l.Stall(Up, false) // at 100 ms
		as := g()
		if as[0].b[0] != 1 || as[0].at.Sub(start) != 100*time.Millisecond || as[1].b[0] != 2 || as[1].at.Sub(start) != 110*time.Millisecond {
			t.Fatalf("after the release: %d at %v, %d at %v; want 1 at 100ms, 2 at 110ms",
				as[0].b[0], as[0].at.Sub(start), as[1].b[0], as[1].at.Sub(start))
		}
		if held := r.l.Stats().All.Held; held != 2 {
			t.Fatalf("held %d, want 2: datagram 1 (on its way, due inside the stall) and datagram 2 (written while held)", held)
		}

		r.l.SetDelay(Up, 0, 0)
		r.l.SetRate(Up, 1000)
		r.l.Stall(Up, true)
		for i := range 6 {
			c.up(t, append([]byte{byte(10 + i)}, make([]byte, 99)...))
		}
		time.Sleep(time.Second)
		g = dCollect(c.srv, 4)
		release := time.Now()
		r.l.Stall(Up, false)
		for i, a := range g() {
			if a.b[0] != byte(10+i) || a.at.Sub(release) != time.Duration(i+1)*100*time.Millisecond {
				t.Fatalf("held datagram %d: %d after %v; want %d after %v", i, a.b[0], a.at.Sub(release), 10+i, time.Duration(i+1)*100*time.Millisecond)
			}
		}
		dNothing(t, c.srv, time.Second)
		if st := r.l.Stats().All; st.Lost != 2 || st.Delivered != 7 {
			t.Fatalf("Lost %d, Delivered %d; want 2 (beyond Queue), 7", st.Lost, st.Delivered)
		}

		r.l.SetRate(Up, 0)
		r.l.SetDelay(Up, 10*time.Millisecond, 0)
		c.up(t, []byte{20}) // due in 10 ms
		time.Sleep(5 * time.Millisecond)
		r.l.Stall(Up, true)
		time.Sleep(15 * time.Millisecond)
		r.l.Stall(Up, true) // again, after the datagram's arrival time: still held
		dNothing(t, c.srv, 50*time.Millisecond)
		r.l.Stall(Up, false)
		if got, _ := dRecv(t, c.srv); got[0] != 20 {
			t.Fatalf("after the release: %d, want 20", got[0])
		}
	})
}

// TestDatagramLinkKill: Kill fails every current carrier — both conns
// return net.ErrClosed from then on, a blocked ReadFrom at once, the first
// Close still succeeds — and loses the datagrams in flight; a later Dial
// creates a working carrier.
func TestDatagramLinkKill(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "kill"})
		defer r.l.Close()
		a, b := r.dial(), r.dial()
		r.l.SetDelay(Up, time.Hour, 0)
		a.up(t, []byte{1})
		b.up(t, []byte{2})
		blocked := make(chan error, 1)
		go func() {
			_, _, err := a.cli.ReadFrom(make([]byte, 10))
			blocked <- err
		}()
		synctest.Wait()
		start := time.Now()
		r.l.Kill()
		if err := <-blocked; !errors.Is(err, net.ErrClosed) || time.Since(start) != 0 {
			t.Fatalf("blocked ReadFrom after Kill: %v after %v", err, time.Since(start))
		}
		for _, pc := range []net.PacketConn{a.cli, a.srv, b.cli, b.srv} {
			var op *net.OpError
			if _, err := pc.WriteTo([]byte{1}, a.srvAddr); !errors.Is(err, net.ErrClosed) || !errors.As(err, &op) {
				t.Fatalf("WriteTo after Kill: %v", err)
			}
			if _, _, err := pc.ReadFrom(make([]byte, 10)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ReadFrom after Kill: %v", err)
			}
			if err := pc.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("SetReadDeadline after Kill: %v", err)
			}
			if err := pc.Close(); err != nil {
				t.Fatalf("first Close after Kill: %v", err)
			}
			if err := pc.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("second Close: %v", err)
			}
		}
		r.l.SetDelay(Up, 0, 0)
		c := r.dial()
		c.up(t, []byte{3})
		if got, _ := dRecv(t, c.srv); got[0] != 3 {
			t.Fatal("the new carrier does not work")
		}
		if st := r.l.Stats(); st.All.Lost != 2 || st.All.Killed != 2 || st.Carriers != 3 || st.All.Sent != 3 {
			t.Fatalf("Lost %d, Killed %d, Carriers %d, Sent %d; want 2, 2, 3, 3", st.All.Lost, st.All.Killed, st.Carriers, st.All.Sent)
		}
	})
}

// TestDatagramLinkQueueBound: each direction holds at most Queue datagrams
// that were written and not yet read, over all carriers; more are
// tail-dropped (lost, WriteTo still succeeds) and a copy that does not fit
// is not made; reading frees room.
func TestDatagramLinkQueueBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "queue", Queue: 8})
		defer r.l.Close()
		a, b := r.dial(), r.dial()
		for i := range 6 {
			a.up(t, []byte{byte(i)})
		}
		r.l.SetDuplicate(Up, 1)
		b.up(t, []byte{6}) // and its copy: 8 in the link
		b.up(t, []byte{7}) // lost
		r.l.SetDuplicate(Up, 0)
		a.down(t, []byte{9}) // the other direction has its own room
		dRecv(t, a.cli)
		for i := range 6 {
			if got, _ := dRecv(t, a.srv); got[0] != byte(i) {
				t.Fatalf("got %d, want %d", got[0], i)
			}
		}
		dRecv(t, b.srv)
		dRecv(t, b.srv)
		b.up(t, []byte{8})
		if got, _ := dRecv(t, b.srv); got[0] != 8 {
			t.Fatal("no room after reading")
		}
		r.l.SetDuplicate(Up, 1)
		for range 7 {
			a.up(t, []byte{0})
		}
		if st := r.l.Stats().All; st.Lost != 1+7-4 || st.Duplicated != 1+4 {
			t.Fatalf("Lost %d, Duplicated %d; want 4, 5 (copies only where they fit)", st.Lost, st.Duplicated)
		}
	})
}

// TestDatagramLinkClosedReceiverLoses: a datagram whose receiving conn is
// closed — on its way when the conn closes, or written afterwards, which is
// UDP to a closed port — is lost and counted and gives back, or never
// takes, its room in the queue the link's carriers share: another
// carrier's datagram still fits a queue of one.
func TestDatagramLinkClosedReceiverLoses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "closed-receiver", Queue: 1})
		defer r.l.Close()
		a, b := r.dial(), r.dial()
		r.l.SetDelay(Up, 10*time.Millisecond, 0)
		a.up(t, []byte{1}) // on its way when its receiver closes
		if err := a.srv.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		for range 3 {
			a.up(t, []byte{2}) // WriteTo succeeds, as UDP to a closed port
		}
		b.up(t, []byte{3})
		if got, _ := dRecv(t, b.srv); got[0] != 3 {
			t.Fatalf("got %d, want 3", got[0])
		}
		if st := r.l.Stats().All; st.Sent != 5 || st.Lost != 4 || st.Delivered != 1 {
			t.Fatalf("Sent %d, Lost %d, Delivered %d; want 5, 4, 1", st.Sent, st.Lost, st.Delivered)
		}
	})
}

// TestDatagramLinkAcceptFailure: when Accept fails, or is nil, the link
// closes the passive end: its reads fail with net.ErrClosed, and what the
// dialer sends to it is lost (counted) without holding room in the queue;
// with a failing Accept, a later accepted carrier's datagram still fits a
// queue of one.
func TestDatagramLinkAcceptFailure(t *testing.T) {
	for _, nilAccept := range []bool{false, true} {
		name := map[bool]string{false: "error", true: "nil"}[nilAccept]
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				acc := make(chan dAccept, 2)
				verdicts := make(chan error, 2) // Accept's results, in call order
				verdicts <- errors.New("refused")
				verdicts <- nil
				cfg := DatagramLinkConfig{Name: "accept-" + name, Queue: 1}
				if !nilAccept {
					cfg.Accept = func(pc net.PacketConn, peer net.Addr) error {
						acc <- dAccept{pc, peer}
						return <-verdicts
					}
				}
				l := NewDatagramLink(cfg)
				defer l.Close()
				cli, peer, err := l.Dial(context.Background())
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				synctest.Wait() // the Accept call returned
				if !nilAccept {
					refused := (<-acc).pc
					refused.SetReadDeadline(time.Now().Add(time.Second)) // an error once closed
					if _, _, err := refused.ReadFrom(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("the refused passive end reads: %v, want net.ErrClosed", err)
					}
				}
				for range 3 {
					dSend(t, cli, []byte{1}, peer)
				}
				if st := l.Stats().All; st.Sent != 3 || st.Lost != 3 {
					t.Fatalf("Sent %d, Lost %d; want 3, 3", st.Sent, st.Lost)
				}
				if nilAccept {
					return
				}
				cli2, peer2, err := l.Dial(context.Background())
				if err != nil {
					t.Fatalf("second Dial: %v", err)
				}
				srv2 := (<-acc).pc
				dSend(t, cli2, []byte{2}, peer2)
				if got, _ := dRecv(t, srv2); got[0] != 2 {
					t.Fatalf("got %d, want 2", got[0])
				}
			})
		})
	}
}

// TestDatagramLinkDropNext_L12: DropNext drops the next n datagrams of its
// direction that carry a frame of the type — as a frame anywhere in the
// datagram or inside a REL — on any carrier, and nothing else; FrameRel
// matches any REL; the frame's resend then passes. This is the stimulus of
// TestControlTailLoss_L12 (a lost first copy of a reliable frame). (Needs
// internal/wire's REL codec: integration 1.)
func TestDatagramLinkDropNext_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "dropnext"})
		defer r.l.Close()
		c := r.dial()
		c.up(t, dH1Session(1, false))
		dRecv(t, c.srv)
		r.l.DropNext(Down, FrameFin, 1)
		r.l.DropNext(Down, FrameSched, 2)
		r.l.DropNext(Up, FrameRel, 1)
		r.l.DropNext(Up, FramePing, 0) // nothing armed
		send := []struct {
			dir     Dir
			b       []byte
			dropped bool
		}{
			{Down, dRel(FrameFin, 1, 5, dFin()), true},
			{Down, dFrame(FramePing, 6, pingPayload(1)), false},
			{Down, dRel(FrameFin, 1, 7, dFin()), false}, // the resend
			{Down, slices.Concat(dFrame(FramePing, 8, pingPayload(2)), dRel(FrameSched, 2, 9, dSched())), true},
			{Down, dRel(FrameSched, 2, 10, dSched()), true},
			{Down, dRel(FrameSched, 2, 11, dSched()), false},
			{Up, dFrame(FramePing, 3, pingPayload(3)), false},
			{Up, dRel(FrameClose, 1, 4, dClose()), true},
			{Up, dRel(FrameClose, 1, 5, dClose()), false},
		}
		for _, s := range send {
			if s.dir == Up {
				c.up(t, s.b)
			} else {
				c.down(t, s.b)
			}
		}
		for _, s := range send {
			if s.dropped {
				continue
			}
			from := map[Dir]net.PacketConn{Up: c.srv, Down: c.cli}[s.dir]
			if got, _ := dRecv(t, from); !bytes.Equal(got, s.b) {
				t.Fatalf("got %x, want %x", got, s.b)
			}
		}
		dNothing(t, c.srv, time.Second)
		dNothing(t, c.cli, time.Second)
		if st := r.l.Stats().Session; st.Lost != 4 || st.Delivered != 6 {
			t.Fatalf("session Lost %d, Delivered %d; want 4, 6", st.Lost, st.Delivered)
		}
	})
}

// TestDatagramLinkCaptureNext_L12: CaptureNext copies the next datagram of
// its direction that carries the type (inside REL too) as the sender wrote
// it — before the path, so a DropNext of the same type drops the very
// datagram it copied — on any carrier, one armed before the carrier
// existed included; two captures receive two consecutive matching
// datagrams; the copy is the link's own. TestControlTailLoss_L12's pattern:
// capture and drop the first copy of a REL, capture its resend, compare the
// REL payloads. (Needs internal/wire's REL codec: integration 1.)
func TestDatagramLinkCaptureNext_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "capture"})
		defer r.l.Close()
		early := r.l.CaptureNext(Up, FrameOpen)
		first := r.l.CaptureNext(Down, FrameOpenAck)
		r.l.DropNext(Down, FrameOpenAck, 1)
		second := r.l.CaptureNext(Down, FrameOpenAck)
		c := r.dial()
		h1 := dH1Session(1, false)
		c.up(t, h1)
		h1[len(h1)-1] ^= 0xFF // the link's copy is not the sender's buffer
		if got := dCaptured(t, early); !bytes.Equal(got, dH1Session(1, false)) {
			t.Fatal("the capture armed before the dial did not copy the H1")
		}
		dRecv(t, c.srv)
		h3 := slices.Concat(dPrefaceAck(1), dFrame(FrameRack, 7, make([]byte, wire.RackLen)), dRel(FrameOpenAck, 1, 8, dOpenAck()))
		resend := dRel(FrameOpenAck, 1, 9, dOpenAck())
		c.down(t, h3)
		c.down(t, resend)
		a, b := dCaptured(t, first), dCaptured(t, second)
		if !bytes.Equal(a, h3) || !bytes.Equal(b, resend) {
			t.Fatalf("captures %x, %x", a, b)
		}
		if got, _ := dRecv(t, c.cli); !bytes.Equal(got, resend) {
			t.Fatal("the captured first copy was not dropped")
		}
		_, ap, _, _ := frameAt(a[len(a)-len(resend):])
		_, bp, _, _ := frameAt(b)
		if !bytes.Equal(ap, bp) {
			t.Fatal("the resent REL payload differs")
		}
		if st := r.l.Stats().Session; st.Lost != 1 || st.Captured != 3 {
			t.Fatalf("session Lost %d, Captured %d; want 1, 3", st.Lost, st.Captured)
		}
	})
}

// TestDatagramLinkCorruptNext_L43: CorruptNext flips exactly one bit of the
// next non-empty datagram a reader of its direction takes (an empty one
// passes it on); the next one arrives intact.
func TestDatagramLinkCorruptNext_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "corrupt"})
		defer r.l.Close()
		c := r.dial()
		r.l.CorruptNext(Down)
		c.down(t, nil)
		c.up(t, dBytes(30, 1)) // the other direction
		a, b := dBytes(30, 2), dBytes(30, 3)
		c.down(t, a)
		c.down(t, b)
		if got, _ := dRecv(t, c.srv); dBitDiff(got, dBytes(30, 1)) != 0 {
			t.Fatal("the other direction was corrupted")
		}
		if got, _ := dRecv(t, c.cli); len(got) != 0 {
			t.Fatal("the empty datagram changed")
		}
		if got, _ := dRecv(t, c.cli); dBitDiff(got, a) != 1 {
			t.Fatalf("%d bits differ, want 1", dBitDiff(got, a))
		}
		if got, _ := dRecv(t, c.cli); dBitDiff(got, b) != 0 {
			t.Fatal("the following datagram was corrupted")
		}
		if st := r.l.Stats().All; st.Corrupted != 1 || st.Delivered != 4 {
			t.Fatalf("Corrupted %d, Delivered %d", st.Corrupted, st.Delivered)
		}
	})
}

// TestDatagramLinkInjectRaw: InjectRaw delivers a datagram on the newest
// carrier at once, from its other end's address, untouched by the path —
// through a delay, a blackhole and a stall — and counted; without a
// carrier, or toward a receiving end that is closed, it does nothing (no
// count, no room taken in the queue).
func TestDatagramLinkInjectRaw(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "inject"})
		defer r.l.Close()
		r.l.InjectRaw(Up, []byte("no carrier"))
		a, b := r.dial(), r.dial()
		r.l.SetDelay(Up, time.Hour, 0)
		r.l.Blackhole(Down, true)
		r.l.Stall(Up, true)
		start := time.Now()
		r.l.InjectRaw(Up, []byte("up"))
		r.l.InjectRaw(Down, []byte("down"))
		if got, from := dRecv(t, b.srv); string(got) != "up" || from != b.cliAddr {
			t.Fatalf("got %q from %v", got, from)
		}
		if got, from := dRecv(t, b.cli); string(got) != "down" || from != b.srvAddr {
			t.Fatalf("got %q from %v", got, from)
		}
		if d := time.Since(start); d != 0 {
			t.Fatalf("injected datagrams took %v", d)
		}
		dNothing(t, a.srv, time.Second)
		if st := r.l.Stats().All; st.Injected != 2 || st.Delivered != 2 || st.Sent != 0 {
			t.Fatalf("Injected %d, Delivered %d, Sent %d", st.Injected, st.Delivered, st.Sent)
		}
		b.srv.Close()
		r.l.InjectRaw(Up, []byte("to a closed end"))
		r.l.InjectRaw(Down, []byte("down again")) // the other end still receives
		if got, _ := dRecv(t, b.cli); string(got) != "down again" {
			t.Fatalf("got %q", got)
		}
		r.l.n.mu.Lock()
		queued := r.l.queued
		r.l.n.mu.Unlock()
		if st := r.l.Stats().All; st.Injected != 3 || st.Lost != 0 || queued != [2]int{} {
			t.Fatalf("Injected %d, Lost %d, queued %v; want 3, 0, none", st.Injected, st.Lost, queued)
		}
	})
}

// TestDatagramLinkScriptWrites_L42: scripted WriteTo results, including
// counts a correct conn never returns, are consumed one per WriteTo by the
// conns of the scripted side only; with Transmit the reported prefix is
// sent as a datagram (a short datagram write), otherwise nothing is.
func TestDatagramLinkScriptWrites_L42(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "script"})
		defer r.l.Close()
		c := r.dial()
		e := errors.New("scripted")
		p := dBytes(20, 1)
		rows := []struct {
			r    WriteResult
			n    int
			err  error
			sent int // bytes that arrive, -1: nothing
		}{
			{WriteResult{N: -3, Relative: true}, 17, nil, -1},
			{WriteResult{N: -3, Relative: true, Transmit: true}, 17, nil, 17},
			{WriteResult{ZeroWrite: true, N: 5}, 0, nil, -1},
			{WriteResult{N: -1}, -1, nil, -1},
			{WriteResult{N: 1, Relative: true}, 21, nil, -1},
			{WriteResult{N: 0, Err: e}, 0, e, -1},
			{WriteResult{N: 2, Err: e, Transmit: true}, 2, e, 2},
		}
		for _, row := range rows {
			r.l.ScriptWrites(Up, row.r)
		}
		c.down(t, p) // the passive's side is not scripted
		if got, _ := dRecv(t, c.cli); !bytes.Equal(got, p) {
			t.Fatal("the passive's write was scripted")
		}
		for i, row := range rows {
			if n, err := c.cli.WriteTo(p, c.srvAddr); n != row.n || err != row.err {
				t.Fatalf("row %d: WriteTo = (%d, %v), want (%d, %v)", i, n, err, row.n, row.err)
			}
			if row.sent >= 0 {
				if got, _ := dRecv(t, c.srv); !bytes.Equal(got, p[:row.sent]) {
					t.Fatalf("row %d: %d bytes arrived, want %d", i, len(got), row.sent)
				}
			}
		}
		dNothing(t, c.srv, time.Second)
		c.up(t, p) // the script is used up
		dRecv(t, c.srv)
		if st := r.l.Stats().All; st.ScriptedWrites != 7 || st.Sent != 4 {
			t.Fatalf("ScriptedWrites %d, Sent %d; want 7, 4", st.ScriptedWrites, st.Sent)
		}
	})
}

// TestDatagramLinkReadFaults_L58: scripted read errors (ICMP-class or
// permanent) are returned by the next ReadFrom calls of the side's conns,
// one per call, before a datagram that is waiting; a blocked ReadFrom
// returns its fault at once.
func TestDatagramLinkReadFaults_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "faults"})
		defer r.l.Close()
		c := r.dial()
		icmp := &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED)}
		perm := errors.New("permanent")
		c.up(t, []byte("queued"))
		r.l.ReadFaults(Down, icmp, perm)
		for _, want := range []error{icmp, perm} {
			if _, _, err := c.srv.ReadFrom(make([]byte, 64)); err != want {
				t.Fatalf("ReadFrom = %v, want %v", err, want)
			}
		}
		if got, _ := dRecv(t, c.srv); string(got) != "queued" {
			t.Fatalf("got %q", got)
		}
		blocked := make(chan error, 1)
		go func() {
			_, _, err := c.cli.ReadFrom(make([]byte, 64))
			blocked <- err
		}()
		synctest.Wait()
		start := time.Now()
		r.l.ReadFaults(Up, icmp)
		if err := <-blocked; err != icmp || time.Since(start) != 0 {
			t.Fatalf("blocked ReadFrom: %v after %v", err, time.Since(start))
		}
		if n := r.l.Stats().All.ReadFaults; n != 3 {
			t.Fatalf("ReadFaults %d, want 3", n)
		}
	})
}

// TestDatagramLinkTruncation_L58: a datagram longer than the reader's
// buffer is truncated Linux-style (n == len(p), nil, the source);
// TruncateNext reports the side's next datagram truncated whatever its
// size — Linux style, or Windows style (n == len(p), no source, a
// *net.OpError wrapping errno 10040 on every OS) — and the next one
// arrives whole; each is counted.
func TestDatagramLinkTruncation_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "truncate"})
		defer r.l.Close()
		c := r.dial()
		d := dBytes(10, 1)
		c.up(t, d)
		buf := make([]byte, 4)
		if n, from, err := c.srv.ReadFrom(buf); n != 4 || from != c.cliAddr || err != nil {
			t.Fatalf("natural truncation: (%d, %v, %v)", n, from, err)
		}
		r.l.TruncateNext(Down, false)
		r.l.TruncateNext(Down, true)
		r.l.TruncateNext(Up, false) // the dialer's side
		for range 3 {
			c.up(t, d)
		}
		buf = make([]byte, 64)
		buf[63] = 0xAA
		if n, from, err := c.srv.ReadFrom(buf); n != 64 || from != c.cliAddr || err != nil || !bytes.Equal(buf[:10], d) || buf[63] != 0 {
			t.Fatalf("Linux style: (%d, %v, %v)", n, from, err)
		}
		var errno syscall.Errno
		var op *net.OpError
		if n, from, err := c.srv.ReadFrom(buf); n != 64 || from != nil || !errors.As(err, &op) || !errors.As(err, &errno) || errno != 10040 {
			t.Fatalf("Windows style: (%d, %v, %v)", n, from, err)
		}
		if got, _ := dRecv(t, c.srv); !bytes.Equal(got, d) {
			t.Fatal("the next datagram was not whole")
		}
		c.down(t, d)
		if n, _, _ := c.cli.ReadFrom(buf); n != 64 {
			t.Fatalf("the dialer's TruncateNext: n %d", n)
		}
		if st := r.l.Stats().All; st.Truncated != 4 || st.Delivered != 1 {
			t.Fatalf("Truncated %d, Delivered %d; want 4, 1", st.Truncated, st.Delivered)
		}
	})
}

// TestDatagramLinkForeignNext_L59: ForeignNext delivers the next datagram
// of its direction from a fresh address no conn of the link has; the next
// one comes from the peer again.
func TestDatagramLinkForeignNext_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "foreign"})
		defer r.l.Close()
		c, o := r.dial(), r.dial()
		r.l.ForeignNext(Down)
		r.l.ForeignNext(Down)
		var seen []net.Addr
		for range 3 {
			c.down(t, []byte{1})
			_, from := dRecv(t, c.cli)
			seen = append(seen, from)
		}
		known := []net.Addr{c.cliAddr, c.srvAddr, o.cliAddr, o.srvAddr}
		for i, from := range seen[:2] {
			u, ok := from.(*net.UDPAddr)
			if !ok || slices.ContainsFunc(known, func(a net.Addr) bool { return sameAddr(a, u) }) || (i == 1 && sameAddr(seen[0], u)) {
				t.Fatalf("foreign source %d is %v", i, from)
			}
		}
		if seen[2] != c.srvAddr {
			t.Fatalf("third datagram from %v, want the peer", seen[2])
		}
		if n := r.l.Stats().All.Foreign; n != 2 {
			t.Fatalf("Foreign %d, want 2", n)
		}
	})
}

// TestDatagramLinkDeadlines_L06: read deadlines follow net.PacketConn — a
// timeout error (Timeout, os.ErrDeadlineExceeded) exactly at the deadline,
// a deadline changed while ReadFrom waits applies at once (shortened or
// extended), a passed deadline fails even with a datagram waiting; a
// passed write deadline fails WriteTo without sending; SetDeadline sets
// both.
func TestDatagramLinkDeadlines_L06(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "deadlines"})
		defer r.l.Close()
		c := r.dial()
		read := func(pc net.PacketConn) (time.Duration, error) {
			start := time.Now()
			_, _, err := pc.ReadFrom(make([]byte, 64))
			return time.Since(start), err
		}
		timeout := func(err error) bool {
			var ne net.Error
			return errors.As(err, &ne) && ne.Timeout() && errors.Is(err, os.ErrDeadlineExceeded)
		}
		c.srv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if d, err := read(c.srv); d != 200*time.Millisecond || !timeout(err) {
			t.Fatalf("ReadFrom: %v after %v, want a timeout after 200ms", err, d)
		}
		c.srv.SetReadDeadline(time.Now().Add(time.Second))
		go func() {
			time.Sleep(100 * time.Millisecond)
			c.srv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		}()
		if d, err := read(c.srv); d != 150*time.Millisecond || !timeout(err) {
			t.Fatalf("shortened: %v after %v, want a timeout after 150ms", err, d)
		}
		r.l.SetDelay(Up, 300*time.Millisecond, 0)
		c.srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		c.up(t, []byte{1})
		go func() {
			time.Sleep(50 * time.Millisecond)
			c.srv.SetReadDeadline(time.Now().Add(time.Hour))
		}()
		if d, err := read(c.srv); d != 300*time.Millisecond || err != nil {
			t.Fatalf("extended: %v after %v, want the datagram after 300ms", err, d)
		}
		r.l.SetDelay(Up, 0, 0)
		c.up(t, []byte{2})
		c.srv.SetReadDeadline(time.Now().Add(-time.Second))
		if d, err := read(c.srv); d != 0 || !timeout(err) {
			t.Fatalf("passed deadline with a datagram waiting: %v after %v", err, d)
		}
		c.srv.SetReadDeadline(time.Time{})
		if got, _ := dRecv(t, c.srv); got[0] != 2 {
			t.Fatal("the waiting datagram was lost")
		}
		sent := r.l.Stats().All.Sent
		c.cli.SetWriteDeadline(time.Now())
		if n, err := c.cli.WriteTo([]byte{3}, c.srvAddr); n != 0 || !timeout(err) || r.l.Stats().All.Sent != sent {
			t.Fatalf("WriteTo after its deadline = (%d, %v)", n, err)
		}
		c.cli.SetDeadline(time.Now().Add(time.Second))
		c.up(t, []byte{4})
		dRecv(t, c.srv)
		time.Sleep(time.Second)
		if _, err := c.cli.WriteTo([]byte{5}, c.srvAddr); !timeout(err) {
			t.Fatalf("SetDeadline: WriteTo %v", err)
		}
		if d, err := read(c.cli); d != 0 || !timeout(err) {
			t.Fatalf("SetDeadline: ReadFrom %v after %v", err, d)
		}
	})
}

// TestDatagramLinkDialBehaviours_L51: every factory misbehaviour of L51 and
// DialNilAddr, with Refuse, Release and Close; Dials, DialFailures and
// Carriers are counted.
func TestDatagramLinkDialBehaviours_L51(t *testing.T) {
	type tc struct {
		name     string
		carriers int
		run      func(t *testing.T, r *dRig) (failed bool)
	}
	cases := []tc{
		{"normal", 1, func(t *testing.T, r *dRig) bool {
			r.dial()
			return false
		}},
		{"refuse", 0, func(t *testing.T, r *dRig) bool {
			r.l.Refuse(true)
			if pc, a, err := r.l.Dial(context.Background()); pc != nil || a != nil || !errors.Is(err, errRefused) {
				t.Fatalf("refused Dial = (%v, %v, %v)", pc, a, err)
			}
			return true
		}},
		{"error", 0, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialError)
			if pc, _, err := r.l.Dial(context.Background()); pc != nil || !errors.Is(err, errScripted) {
				t.Fatalf("Dial = (%v, %v)", pc, err)
			}
			return true
		}},
		{"hang", 0, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialHang)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			if pc, _, err := r.l.Dial(ctx); pc != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != time.Second {
				t.Fatalf("Dial = (%v, %v) after %v", pc, err, time.Since(start))
			}
			return true
		}},
		{"hang-release", 0, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialHang)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, _, err := r.l.Dial(ctx)
				done <- err
			}()
			time.Sleep(time.Hour)
			select {
			case err := <-done:
				t.Fatalf("hanging dial returned %v before Release", err)
			default:
			}
			r.l.Release()
			start := time.Now()
			if err := <-done; !errors.Is(err, errReleased) || time.Since(start) != 0 {
				t.Fatalf("released dial: %v after %v, want errReleased at once", err, time.Since(start))
			}
			return true
		}},
		{"hang-forever", 0, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialHangForever)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan error, 1)
			go func() {
				_, _, err := r.l.Dial(ctx)
				done <- err
			}()
			time.Sleep(time.Hour)
			select {
			case err := <-done:
				t.Fatalf("hanging dial returned %v before Release", err)
			default:
			}
			r.l.Release()
			if err := <-done; !errors.Is(err, errReleased) {
				t.Fatalf("released dial: %v", err)
			}
			return true
		}},
		{"nil-nil", 0, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialNilNil)
			if pc, a, err := r.l.Dial(context.Background()); pc != nil || a != nil || err != nil {
				t.Fatalf("Dial = (%v, %v, %v), want (nil, nil, nil)", pc, a, err)
			}
			return true
		}},
		{"nil-addr", 1, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialNilAddr)
			pc, a, err := r.l.Dial(context.Background())
			if pc == nil || a != nil || err != nil {
				t.Fatalf("Dial = (%v, %v, %v), want (pc, nil, nil)", pc, a, err)
			}
			<-r.acc
			if err := pc.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			return true
		}},
		{"panic", 0, func(t *testing.T, r *dRig) (failed bool) {
			r.l.SetDialBehavior(DialPanic)
			defer func() {
				if recover() == nil {
					t.Fatal("DialPanic did not panic")
				}
				failed = true
			}()
			r.l.Dial(context.Background())
			return false
		}},
		{"goexit", 0, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialGoexit)
			returned, exited := false, make(chan struct{})
			go func() {
				defer close(exited)
				r.l.Dial(context.Background())
				returned = true
			}()
			<-exited
			if returned {
				t.Fatal("DialGoexit returned")
			}
			return true
		}},
		{"late-success", 1, func(t *testing.T, r *dRig) bool {
			r.l.SetDialBehavior(DialLateSuccess)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan net.PacketConn, 1)
			go func() {
				pc, _, _ := r.l.Dial(ctx)
				done <- pc
			}()
			time.Sleep(time.Hour)
			if n := r.l.Stats().Carriers; n != 0 {
				t.Fatal("the late dial created a carrier before Release")
			}
			r.l.Release()
			pc := <-done
			if pc == nil {
				t.Fatal("the late dial failed after Release")
			}
			<-r.acc
			pc.Close()
			return false
		}},
		{"closed", 0, func(t *testing.T, r *dRig) bool {
			r.l.Close()
			if pc, _, err := r.l.Dial(context.Background()); pc != nil || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Dial after Close = (%v, %v)", pc, err)
			}
			return true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newDRig(t, DatagramLinkConfig{Name: c.name})
				defer r.l.Close()
				failed := c.run(t, r)
				st := r.l.Stats()
				want := uint64(0)
				if failed {
					want = 1
				}
				if st.Dials != 1 || st.DialFailures != want || st.Carriers != c.carriers {
					t.Fatalf("Dials %d, DialFailures %d, Carriers %d; want 1, %d, %d", st.Dials, st.DialFailures, st.Carriers, want, c.carriers)
				}
			})
		})
	}
}

// TestDatagramLinkCloseJoins: Close returns with a blocked ReadFrom, a
// hanging dial, datagrams in flight and datagrams held by a stall; the
// blocked calls return, the datagrams count as lost, later Dials fail, a
// second Close is harmless, and the bubble ends with no goroutine left
// (the Accept calls included).
func TestDatagramLinkCloseJoins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "close"})
		c := r.dial()
		r.l.SetDelay(Up, time.Hour, 0)
		c.up(t, []byte("in flight"))
		r.l.Stall(Down, true)
		c.down(t, []byte("held"))
		read := make(chan error, 1)
		go func() {
			_, _, err := c.cli.ReadFrom(make([]byte, 64))
			read <- err
		}()
		r.l.SetDialBehavior(DialHangForever)
		hung := make(chan error, 1)
		go func() {
			_, _, err := r.l.Dial(context.Background())
			hung <- err
		}()
		synctest.Wait()
		if err := r.l.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := <-read; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked ReadFrom: %v", err)
		}
		if err := <-hung; !errors.Is(err, errReleased) {
			t.Fatalf("hanging dial: %v", err)
		}
		if _, _, err := r.l.Dial(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Dial after Close: %v", err)
		}
		if err := r.l.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if st := r.l.Stats().All; st.Lost != 2 || st.Sent != 2 {
			t.Fatalf("Lost %d, Sent %d; want 2, 2", st.Lost, st.Sent)
		}
	})
}

// TestDatagramLinkCloseJoinsAccept: Close returns only after every Accept
// call the link started has returned, however long it takes.
func TestDatagramLinkCloseJoinsAccept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		returned := make(chan struct{})
		l := NewDatagramLink(DatagramLinkConfig{Name: "close-accept", Accept: func(net.PacketConn, net.Addr) error {
			time.Sleep(time.Second)
			close(returned)
			return nil
		}})
		if _, _, err := l.Dial(context.Background()); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		start := time.Now()
		l.Close()
		closed := time.Since(start)
		<-returned // a Close that did not join must still let the bubble end clean
		if closed != time.Second {
			t.Fatalf("Close returned after %v, want 1s: it must join the Accept call it started", closed)
		}
	})
}

// TestDatagramLinkAccountingIdentity: whatever the controls do, every
// datagram is accounted for exactly once per class: Sent + Duplicated +
// Injected = Delivered + Truncated + Lost once the link holds nothing
// (here after Close). The traffic mixes loss, duplication, reordering,
// jitter, a rate, a small queue, MTUDrop, blackholes, stalls, a Kill,
// injections, truncations, scripted transmitted writes and conns closed
// with datagrams waiting, on probe carriers and an unclassified one.
func TestDatagramLinkAccountingIdentity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "identity", Queue: 64})
		l := r.l
		for _, d := range []Dir{Up, Down} {
			l.SetLoss(d, 0.1)
			l.SetDuplicate(d, 0.1)
			l.SetReorder(d, 0.1, 15*time.Millisecond)
			l.SetDelay(d, 5*time.Millisecond, 3*time.Millisecond)
		}
		l.SetRate(Up, 2e6)
		l.SetMTU(1000, MTUDrop)
		var cs []dCarrier
		var readers []func() []dArrival
		add := func(first []byte) {
			c := r.dial()
			c.up(t, first)
			cs = append(cs, c)
			readers = append(readers, dCollect(c.srv, 1<<30), dCollect(c.cli, 1<<30))
		}
		add(dH1Probe(1))
		add(dH1Probe(2))
		add(dBytes(40, 3))
		for step := range 600 {
			c := cs[step%len(cs)]
			switch step % 50 {
			case 7:
				l.Blackhole(Up, true)
			case 9:
				l.Blackhole(Up, false)
			case 13:
				l.Stall(Down, true)
			case 19:
				l.Stall(Down, false)
			case 23:
				l.InjectRaw(Up, dBytes(30, step))
			case 29:
				l.TruncateNext(Down, step%2 == 0)
			case 31:
				l.ScriptWrites(Up, WriteResult{N: -5, Relative: true, Transmit: true})
			}
			if step == 300 {
				l.Kill()
				for _, f := range readers {
					f()
				}
				cs, readers = nil, nil
				add(dH1Probe(4))
				add(dBytes(40, 5))
				continue
			}
			size := 20 + step*7%1100 // some above the MTU
			c.cli.WriteTo(dBytes(size, step), c.srvAddr)
			c.srv.WriteTo(dBytes(size/2, step), c.cliAddr)
			time.Sleep(time.Millisecond)
		}
		cs[0].srv.Close() // closed with datagrams on the way
		l.Close()
		for _, f := range readers {
			f()
		}
		st := l.Stats()
		for _, cl := range []struct {
			name string
			c    DatagramCounts
		}{{"all", st.All}, {"probe", st.Probe}} {
			in := cl.c.Sent + cl.c.Duplicated + cl.c.Injected
			out := cl.c.Delivered + cl.c.Truncated + cl.c.Lost
			if in != out || cl.c.Lost == 0 || cl.c.Duplicated == 0 || cl.c.Delivered == 0 {
				t.Errorf("%s: %+v: in %d, out %d", cl.name, cl.c, in, out)
			}
		}
		if st.All.Oversize == 0 || st.All.Reordered == 0 || st.All.Injected == 0 || st.All.Truncated == 0 || st.All.ScriptedWrites == 0 {
			t.Errorf("a stimulus did not happen: %+v", st.All)
		}
	})
}

// TestDatagramLinkNoLeak_L66: on the real clock, a link with carriers,
// readers blocked in ReadFrom, datagrams in flight and a hanging dial
// leaves no goroutine behind once Close returned and the test joined its
// own goroutines (AssertNoLeak covers the link's Accept calls; the link
// starts no other goroutine: its pumps run in the callers' ReadFrom and
// WriteTo).
func TestDatagramLinkNoLeak_L66(t *testing.T) {
	check := AssertNoLeak(t)
	r := newDRig(t, DatagramLinkConfig{Name: "noleak"})
	r.l.SetDelay(Up, 2*time.Millisecond, time.Millisecond)
	cs := []dCarrier{r.dial(), r.dial()}
	var wg sync.WaitGroup
	for _, c := range cs {
		for _, pc := range []net.PacketConn{c.cli, c.srv} {
			wg.Go(func() {
				buf := make([]byte, 2048)
				for {
					if _, _, err := pc.ReadFrom(buf); err != nil {
						return
					}
				}
			})
		}
	}
	for i := range 50 {
		cs[i%2].up(t, dBytes(100, i))
	}
	r.l.SetDialBehavior(DialHangForever)
	wg.Go(func() { r.l.Dial(context.Background()) })
	r.l.SetDelay(Up, time.Hour, 0)
	cs[0].up(t, []byte("in flight at Close"))
	time.Sleep(20 * time.Millisecond)
	r.l.Close()
	wg.Wait()
	check()
}
