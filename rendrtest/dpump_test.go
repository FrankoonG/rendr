package rendrtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// dAccept is one passive end a test link's Accept received.
type dAccept struct {
	pc   net.PacketConn
	peer net.Addr
}

// dRig is a DatagramLink whose passive ends the test collects.
type dRig struct {
	t   *testing.T
	l   *DatagramLink
	acc chan dAccept
}

func newDRig(t *testing.T, cfg DatagramLinkConfig) *dRig {
	t.Helper()
	r := &dRig{t: t, acc: make(chan dAccept, 64)}
	cfg.Accept = func(pc net.PacketConn, peer net.Addr) error {
		r.acc <- dAccept{pc, peer}
		return nil
	}
	r.l = NewDatagramLink(cfg)
	return r
}

// dCarrier is one carrier of a dRig: both conns and the address each end
// was given for the other.
type dCarrier struct {
	cli, srv         net.PacketConn
	srvAddr, cliAddr net.Addr // cli's peer (from Dial), srv's peer (from Accept)
}

// dial creates one carrier.
func (r *dRig) dial() dCarrier {
	r.t.Helper()
	cli, peer, err := r.l.Dial(context.Background())
	if err != nil || cli == nil || peer == nil {
		r.t.Fatalf("Dial = (%v, %v, %v)", cli, peer, err)
	}
	a := <-r.acc
	return dCarrier{cli: cli, srv: a.pc, srvAddr: peer, cliAddr: a.peer}
}

// up and down write one datagram from the dialer's or the passive's end.
func (c dCarrier) up(t testing.TB, b []byte)   { t.Helper(); dSend(t, c.cli, b, c.srvAddr) }
func (c dCarrier) down(t testing.TB, b []byte) { t.Helper(); dSend(t, c.srv, b, c.cliAddr) }

func dSend(t testing.TB, pc net.PacketConn, b []byte, to net.Addr) {
	t.Helper()
	if n, err := pc.WriteTo(b, to); n != len(b) || err != nil {
		t.Fatalf("WriteTo(%d bytes) = (%d, %v)", len(b), n, err)
	}
}

// dRecv reads one datagram and returns a copy and its source. It waits at
// most a day of (bubble) time, so that a datagram that never comes fails
// the test by name instead of deadlocking it; it clears pc's read deadline.
func dRecv(t testing.TB, pc net.PacketConn) ([]byte, net.Addr) {
	t.Helper()
	pc.SetReadDeadline(time.Now().Add(24 * time.Hour))
	defer pc.SetReadDeadline(time.Time{})
	buf := make([]byte, wire.MaxDatagram+1)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	return slices.Clone(buf[:n]), from
}

// dCaptured receives a CaptureNext copy, failing the test after a second.
func dCaptured(t testing.TB, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(time.Second):
		t.Fatal("no datagram was captured")
		return nil
	}
}

// dNothing asserts that pc has nothing to read within d.
func dNothing(t testing.TB, pc net.PacketConn, d time.Duration) {
	t.Helper()
	pc.SetReadDeadline(time.Now().Add(d))
	defer pc.SetReadDeadline(time.Time{})
	buf := make([]byte, wire.MaxDatagram+1)
	if n, from, err := pc.ReadFrom(buf); err == nil {
		t.Fatalf("read %d bytes from %v, want nothing within %v", n, from, d)
	}
}

// dBytes returns n bytes of pattern i.
func dBytes(n, i int) []byte {
	b := make([]byte, n)
	PRNG(uint64(i) + 1000).Read(b)
	return b
}

var dInstance = [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7}

// dPreface is a PREFACE of kind datagram.
func dPreface(id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPreface(b, &wire.Preface{Kind: wire.KindDatagram, Instance: dInstance, CarrierID: id})
	return b
}

// dPrefaceAck is a PREFACE_ACK(OK).
func dPrefaceAck(id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPrefaceAck(b, &wire.PrefaceAck{Instance: dInstance, CarrierID: id})
	return b
}

// dFrame encodes one frame with the carrier-level handle rule of M2.
func dFrame(t FrameType, fseq uint32, payload []byte) []byte {
	h := wire.Header{Type: wire.Type(t), Fseq: fseq, Handle: wire.SessionHandle}
	switch t {
	case FramePing, FramePong, FrameClose, FrameGoAway, FrameRel, FrameRack:
		h.Handle = 0
	}
	return wire.AppendFrame(nil, h, payload)
}

// dRel encodes a REL frame wrapping a frame of type it.
func dRel(it FrameType, cseq, fseq uint32, inner []byte) []byte {
	p := make([]byte, wire.RelHeadLen+len(inner))
	h := wire.RelHead{Cseq: cseq, Type: wire.Type(it), Handle: wire.SessionHandle}
	if it == FrameClose || it == FrameGoAway {
		h.Handle = 0
	}
	wire.PutRelHead(p, &h)
	copy(p[wire.RelHeadLen:], inner)
	return dFrame(FrameRel, fseq, p)
}

func dOpen() []byte {
	b := make([]byte, wire.OpenFixedLen)
	wire.PutOpen(b, &wire.Open{SID: dInstance, Kind: wire.KindDatagram, Mode: 1, RetainMs: 34000, Window: 1223, PMTU: 1198})
	return b
}

func dJoin() []byte {
	b := make([]byte, wire.JoinLen)
	wire.PutJoin(b, &wire.Join{SID: dInstance, Mode: 1, RxNext: 1223})
	return b
}

func dOpenAck() []byte { return make([]byte, wire.OpenAckFixedLen) }

func dFin() []byte {
	b := make([]byte, wire.FinLen)
	wire.PutFin(b, 7)
	return b
}

func dSched() []byte {
	b := make([]byte, wire.SchedFixedLen+4)
	wire.PutSched(b, &wire.Sched{Epoch: 3, N: 1, IDs: [wire.MaxSchedIDs]uint32{9}})
	return b
}

func dClose() []byte { return []byte{1} }

// dH1Session is a session carrier's first datagram: PREFACE ‖ REL{OPEN}
// (join: REL{JOIN}).
func dH1Session(id uint32, join bool) []byte {
	pre := dPreface(id)
	it, inner := FrameOpen, dOpen()
	if join {
		it, inner = FrameJoin, dJoin()
	}
	return append(pre, dRel(it, wire.FirstCseq, wire.PrefaceFseq(pre), inner)...)
}

// dH1Probe is a probe carrier's first datagram: PREFACE ‖ PING.
func dH1Probe(id uint32) []byte {
	pre := dPreface(id)
	return append(pre, dFrame(FramePing, wire.PrefaceFseq(pre), pingPayload(1))...)
}

// TestDatagramClassification_L60: a carrier is classified by its dialer's
// first datagram — PREFACE ‖ REL{OPEN or JOIN} (or a bare OPEN or JOIN) is
// a session carrier, PREFACE ‖ PING a probe carrier, anything else other —
// and the frame-targeted controls find a type anywhere in a datagram, as a
// frame or inside a REL, after a PREFACE or PREFACE_ACK, never past the
// end of the datagram. (Needs internal/wire's REL codec: integration 1.)
func TestDatagramClassification_L60(t *testing.T) {
	pre := dPreface(5)
	f := wire.PrefaceFseq(pre)
	cat := func(parts ...[]byte) []byte { return slices.Concat(parts...) }
	classes := []struct {
		name string
		b    []byte
		want int32
	}{
		{"rel-open", dH1Session(5, false), kindSession},
		{"rel-join", dH1Session(5, true), kindSession},
		{"bare-open", cat(pre, dFrame(FrameOpen, f, dOpen())), kindSession},
		{"ping", dH1Probe(5), kindProbe},
		{"rel-close", cat(pre, dRel(FrameClose, 1, f, dClose())), kindOther},
		{"rel-malformed", cat(pre, dFrame(FrameRel, f, []byte{0, 0, 0, 1, byte(FrameOpen)})), kindOther},
		{"preface-only", pre, kindOther},
		{"frame-past-end", cat(pre, dFrame(FramePing, f, pingPayload(1))[:30]), kindOther},
		{"no-preface", dFrame(FramePing, 1, pingPayload(1)), kindOther},
		{"empty", nil, kindOther},
	}
	for _, c := range classes {
		if got := classifyDatagram(c.b); got != c.want {
			t.Errorf("%s: class %d, want %d", c.name, got, c.want)
		}
	}

	multi := cat(dFrame(FrameRack, 9, make([]byte, wire.RackLen)), dRel(FrameSched, 4, 10, dSched()),
		dFrame(FramePing, 11, pingPayload(2)), dFrame(FrameDgram, 12, make([]byte, 20)))
	carriesRows := []struct {
		name string
		b    []byte
		t    FrameType
		want bool
	}{
		{"first-frame", multi, FrameRack, true},
		{"inside-rel", multi, FrameSched, true},
		{"rel-itself", multi, FrameRel, true},
		{"third-frame", multi, FramePing, true},
		{"last-frame", multi, FrameDgram, true},
		{"absent", multi, FrameFin, false},
		{"after-preface", dH1Session(5, false), FrameOpen, true},
		{"after-preface-ack", cat(dPrefaceAck(5), dFrame(FrameRack, 3, make([]byte, wire.RackLen))), FrameRack, true},
		{"truncated-tail", multi[:len(multi)-1], FrameDgram, false},
		{"before-a-truncated-tail", multi[:len(multi)-1], FramePing, true},
	}
	for _, c := range carriesRows {
		if got := carries(c.b, c.t); got != c.want {
			t.Errorf("carries %s %#x: %v, want %v", c.name, c.t, got, c.want)
		}
	}
}

// TestDatagramConcurrentReaders: a conn serves concurrent readers, as a
// net.PacketConn must. A reader that returns hands the wake on whenever it
// leaves something behind, so that another reader blocked on the same conn
// returns it on time: a datagram still in flight after a stall's release
// (the readers had no timer for it while the direction was held), and the
// second of two read faults for two waiting readers.
func TestDatagramConcurrentReaders(t *testing.T) {
	type result struct {
		b   []byte
		err error
		at  time.Duration
	}
	show := func(rs []result) string {
		var out []string
		for _, r := range rs {
			out = append(out, fmt.Sprintf("(%x, %v) after %v", r.b, r.err, r.at))
		}
		return strings.Join(out, ", ")
	}
	// two starts two readers of pc, each blocked before the next starts,
	// with a read deadline an hour from start; the returned func waits for
	// both and returns their results in the order they returned.
	two := func(pc net.PacketConn, start time.Time) func() []result {
		pc.SetReadDeadline(start.Add(time.Hour))
		ch := make(chan result, 2)
		for range 2 {
			go func() {
				buf := make([]byte, 64)
				n, _, err := pc.ReadFrom(buf)
				ch <- result{slices.Clone(buf[:max(n, 0)]), err, time.Since(start)}
			}()
			synctest.Wait()
		}
		return func() []result { return []result{<-ch, <-ch} }
	}
	t.Run("stall-release", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newDRig(t, DatagramLinkConfig{Name: "readers"})
			defer r.l.Close()
			c := r.dial()
			r.l.SetDelay(Up, 100*time.Millisecond, 0)
			start := time.Now()
			got := two(c.srv, start)
			c.up(t, []byte{1}) // due at 100 ms
			time.Sleep(50 * time.Millisecond)
			c.up(t, []byte{2}) // due at 150 ms
			time.Sleep(10 * time.Millisecond)
			r.l.Stall(Up, true) // at 60 ms: both readers lose their timers at 100 ms
			time.Sleep(60 * time.Millisecond)
			r.l.Stall(Up, false) // at 120 ms: datagram 1 arrives at once
			rs := got()
			if rs[0].err != nil || !bytes.Equal(rs[0].b, []byte{1}) || rs[0].at != 120*time.Millisecond ||
				rs[1].err != nil || !bytes.Equal(rs[1].b, []byte{2}) || rs[1].at != 150*time.Millisecond {
				t.Fatalf("readers returned %s; want datagram 1 after 120ms and datagram 2 after 150ms", show(rs))
			}
		})
	})
	t.Run("faults", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newDRig(t, DatagramLinkConfig{Name: "readers"})
			defer r.l.Close()
			c := r.dial()
			start := time.Now()
			got := two(c.srv, start)
			e1, e2 := errors.New("fault one"), errors.New("fault two")
			r.l.ReadFaults(Down, e1, e2)
			rs := got()
			errs := []error{rs[0].err, rs[1].err}
			if !slices.Contains(errs, e1) || !slices.Contains(errs, e2) || rs[0].at != 0 || rs[1].at != 0 {
				t.Fatalf("readers returned %s; want both faults at once", show(rs))
			}
		})
	})
}

// TestDatagramQueuesOrder: an endpoint releases datagrams in arrival
// order, ties in write order: its in-flight heap and its ready FIFO
// (compactions included) keep that order for any interleaving of writes
// (each arriving no earlier than it was written), arrival checks at
// advancing times and reads.
func TestDatagramQueuesOrder(t *testing.T) {
	n := newDnet("order", 0, 0, 3)
	q := 0
	e := n.newEndpoint(fakeAddr(1, 0), 0, 0, new(int32), nil)
	rng := rand.New(rand.NewPCG(1, 2))
	now := time.Unix(0, 0)
	type key struct {
		due time.Time
		seq uint64
	}
	var written, released []key
	for range 60 {
		for range rng.IntN(400) {
			dg := n.newDgram(1)
			n.seq++
			dg.due, dg.seq, dg.q = now.Add(time.Duration(rng.IntN(50))*time.Millisecond), n.seq, &q
			written = append(written, key{dg.due, dg.seq})
			e.pushIn(dg)
		}
		e.promote(now)
		for range rng.IntN(1 + len(e.ready) - e.rhead) {
			dg := e.popReady()
			released = append(released, key{dg.due, dg.seq})
		}
		now = now.Add(time.Duration(rng.IntN(5)) * time.Millisecond)
	}
	e.promote(now.Add(time.Hour))
	for len(e.ready) > e.rhead {
		dg := e.popReady()
		released = append(released, key{dg.due, dg.seq})
	}
	slices.SortFunc(written, func(a, b key) int {
		if c := a.due.Compare(b.due); c != 0 {
			return c
		}
		return int(a.seq) - int(b.seq)
	})
	if len(written) < 5000 || !slices.Equal(released, written) {
		t.Fatalf("released %d datagrams of %d, or not in (arrival, write) order", len(released), len(written))
	}
	// A ready FIFO read slower than it fills compacts its head (no growth
	// with the total traffic) and keeps its order.
	for range 3000 {
		dg := n.newDgram(1)
		n.seq++
		dg.due, dg.seq, dg.q = now, n.seq, &q
		e.pushIn(dg)
	}
	e.promote(now)
	last := uint64(0)
	for range 2000 {
		if s := e.popReady().seq; s <= last {
			t.Fatalf("seq %d after %d", s, last)
		} else {
			last = s
		}
	}
	if e.rhead >= compactReady || len(e.ready)-e.rhead != 1000 {
		t.Fatalf("ready FIFO not compacted: head %d, length %d", e.rhead, len(e.ready))
	}
}
