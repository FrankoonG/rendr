package udpflow

// Real-socket rows (M2 design §A8.6): rendr's own listening socket
// (*carrier.OwnedUDPSocket) on loopback, outside synctest bubbles; every
// wait is bounded by a socket or flow deadline.

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

const realWait = 5 * time.Second

// loopback4 is the IPv4 loopback address, port 0.
func loopback4() *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0))
}

// realSource is a Source over an OwnedUDPSocket with a client socket.
type realSource struct {
	t        *testing.T
	env      *carrier.Env
	s        *Source
	u        *net.UDPConn
	cl       *net.UDPConn
	dst      netip.AddrPort
	admitted chan *Flow
	mu       sync.Mutex
	all      []*Flow
}

func newRealSource(t *testing.T, maxDatagram int) *realSource {
	t.Helper()
	return newRealSourceEnv(t, maxDatagram, testEnv(1<<30))
}

func newRealSourceEnv(t *testing.T, maxDatagram int, env *carrier.Env) *realSource {
	t.Helper()
	u, err := net.ListenUDP("udp4", loopback4())
	if err != nil {
		t.Fatal(err)
	}
	cl, err := net.ListenUDP("udp4", loopback4())
	if err != nil {
		u.Close()
		t.Fatal(err)
	}
	rs := &realSource{t: t, env: env, u: u, cl: cl, admitted: make(chan *Flow, 16),
		dst: u.LocalAddr().(*net.UDPAddr).AddrPort()}
	rs.s = NewSource(rs.env, carrier.NewOwnedUDPSocket(u, maxDatagram), Limits{})
	go rs.s.Run(func(f *Flow) {
		rs.mu.Lock()
		rs.all = append(rs.all, f)
		rs.mu.Unlock()
		rs.admitted <- f
	})
	t.Cleanup(func() {
		rs.s.Abort()
		rs.mu.Lock()
		all := rs.all
		rs.mu.Unlock()
		for _, f := range all {
			f.Release()
			f.Close()
		}
		select {
		case <-rs.s.Done():
		case <-time.After(realWait):
			t.Error("the source did not end")
		}
		cl.Close()
	})
	return rs
}

func (rs *realSource) send(b []byte) {
	rs.t.Helper()
	if _, err := rs.cl.WriteToUDPAddrPort(b, rs.dst); err != nil {
		rs.t.Fatal(err)
	}
}

func (rs *realSource) flow() *Flow {
	rs.t.Helper()
	select {
	case f := <-rs.admitted:
		return f
	case <-time.After(realWait):
		rs.t.Fatal("no flow admitted")
		return nil
	}
}

// recv reads one datagram at the client.
func (rs *realSource) recv() ([]byte, netip.AddrPort) {
	rs.t.Helper()
	if err := rs.cl.SetReadDeadline(time.Now().Add(realWait)); err != nil {
		rs.t.Fatal(err)
	}
	b := make([]byte, 2048)
	n, from, err := rs.cl.ReadFromUDPAddrPort(b)
	if err != nil {
		rs.t.Fatal(err)
	}
	return b[:n], from
}

func TestFlowOwnedSocket_L58(t *testing.T) {
	rs := newRealSource(t, 1232)
	const id = 0x1234
	first := h1(id, wire.TypeOpen, 5)
	rs.send(first)
	f := rs.flow()
	if f.Limit() != 1232-wire.FlowHeaderLen || f.ReadSize() != 0 {
		t.Fatalf("Limit %d, ReadSize %d", f.Limit(), f.ReadSize())
	}
	client := rs.cl.LocalAddr().(*net.UDPAddr).AddrPort()
	b, src, ev := readOne(t, f, realWait)
	if !bytes.Equal(b, first[wire.FlowHeaderLen:]) || ev != carrier.ReadOK || src.AP != client {
		t.Fatalf("H1: %d bytes, event %d, source %v (client %v)", len(b), ev, src, client)
	}

	// A datagram longer than MaxDatagram is truncated at the source; the
	// next one arrives (one socket: delivered in order on loopback).
	rs.send(make([]byte, 1233))
	rs.send(dg(id, pingFrame(2)))
	if _, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK {
		t.Fatalf("event %d", ev)
	}
	if st := rs.s.Stats(); st.Truncated != 1 || st.Dropped != 1 {
		t.Fatalf("Stats %+v, want one truncated datagram", st)
	}

	// The negotiated budget (R1-6, the OwnedUDPSocket flow row).
	f.SetLimit(600)
	rs.send(dg(id, make([]byte, 601)))
	rs.send(dg(id, make([]byte, 600)))
	if _, _, ev := readOne(t, f, realWait); ev != carrier.ReadTruncated {
		t.Fatalf("601 rendr bytes over a limit of 600: event %d", ev)
	}
	if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) != 600 {
		t.Fatalf("600 rendr bytes: event %d, %d bytes", ev, len(b))
	}

	// WriteDatagram adds the flow header and reaches the client.
	wb := make([]byte, wire.FlowHeaderLen+100)
	copy(wb[wire.FlowHeaderLen:], "payload")
	if err := f.WriteDatagram(wb); err != nil {
		t.Fatal(err)
	}
	got, from := rs.recv()
	if gid, rest, err := wire.ParseFlowHeader(got); err != nil || gid != id || !bytes.Equal(rest, wb[wire.FlowHeaderLen:]) || from != rs.dst {
		t.Fatalf("client got flow %x (%v), %d bytes from %v", gid, err, len(rest), from)
	}

	// Stop: the accepted flow keeps the socket; a new H1 gets CAPACITY.
	rs.s.Stop()
	rs.send(h1(0x999, wire.TypeJoin, 7))
	ans, _ := rs.recv()
	if aid, ack := parseAnswer(t, ans); aid != 0x999 || ack.Status != wire.PrefaceCapacity || ack.CarrierID != 7 {
		t.Fatalf("answer: flow %x, %+v", aid, ack)
	}
	rs.send(dg(id, pingFrame(3)))
	if _, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK {
		t.Fatalf("after Stop: event %d", ev)
	}
	f.Close()
	select {
	case <-rs.s.Done():
	case <-time.After(realWait):
		t.Fatal("the socket was not closed after the last flow")
	}
	if used := rs.env.Budget.Used() + rs.env.Stages.Used(); used != 0 {
		t.Fatalf("%d bytes buffered after Done", used)
	}
	if _, err := rs.u.WriteToUDPAddrPort([]byte{1}, rs.dst); err == nil {
		t.Fatal("the shared socket is still open")
	}
}

// TestFlowOwnedSocketEmpties_L58: on rendr's own socket an empty datagram
// is a real datagram the kernel received — it is dropped and counted, and
// a run of them never pauses the demux: a live flow's datagram behind
// hundreds of empties arrives at once (L58).
func TestFlowOwnedSocketEmpties_L58(t *testing.T) {
	rs := newRealSource(t, 1232)
	if err := rs.u.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
	const id = 0x4321
	rs.send(h1(id, wire.TypeOpen, 5))
	f := rs.flow()
	f.Admitted()
	readOne(t, f, realWait)
	const batches, empties = 3, 4 * emptyRun
	for i := range batches {
		before := rs.s.Stats().Dropped
		for range empties {
			rs.send(nil)
		}
		rs.send(dg(id, pingFrame(uint32(i+2))))
		// One socket on loopback delivers in order: the PING follows the
		// batch. A pause per empty run would hold it for seconds.
		if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || u32(b[5:9]) != uint32(i+2) {
			t.Fatalf("batch %d: event %d", i, ev)
		}
		// Loopback may drop a few under load; the run must have crossed
		// the spin guard's length several times to mean anything.
		if d := rs.s.Stats().Dropped - before; d < 2*emptyRun {
			t.Fatalf("batch %d: %d of %d empty datagrams counted", i, d, empties)
		}
	}
	if st := rs.s.Stats(); st.ReadErrors != 0 || st.Flows != 1 {
		t.Fatalf("Stats %+v", st)
	}
}

// waitFor polls cond every millisecond for at most realWait.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, realWait)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestFlowOwnedSocketCharge (R-C3-2; plan:774): the read buffer of rendr's
// own socket is charged to nothing while the source waits — an idle source
// whose reader runs (it read and dropped junk) holds 0 bytes in the Budget
// and in Stages — and a datagram read into it is charged to the Budget from
// the moment it is queued for a flow until the flow's reader releases it.
// When the Budget refuses that charge, a datagram without a DGRAM still
// reaches its flow through the control reserve (Stages, L16) and a DGRAM is
// dropped as an inbox drop; nothing stays charged.
func TestFlowOwnedSocketCharge(t *testing.T) {
	t.Run("budget", func(t *testing.T) {
		rs := newRealSource(t, 1232)
		used := func() int64 { return rs.env.Budget.Used() + rs.env.Stages.Used() }
		rs.send([]byte("junk"))
		waitFor(t, "the junk datagram's drop", func() bool { return rs.s.Stats().Dropped == 1 })
		if u := used(); u != 0 {
			t.Fatalf("an idle source whose reader runs: %d bytes charged, want 0", u)
		}
		const id = 0x77
		rs.send(h1(id, wire.TypeOpen, 1))
		f := rs.flow()
		if rs.env.Budget.Used() == 0 {
			t.Fatal("the H1 queued in its flow's inbox is charged to no Budget")
		}
		if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) == 0 {
			t.Fatalf("H1: event %d", ev)
		}
		f.Admitted()
		for i := range 3 {
			rs.send(dg(id, dgramFrame(uint32(2+i), 900)))
			waitFor(t, "the DGRAM's charge", func() bool { return rs.env.Budget.Used() > 0 })
			if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) < 900 {
				t.Fatalf("DGRAM %d: event %d, %d bytes", i, ev, len(b))
			}
			if u := used(); u != 0 {
				t.Fatalf("after reading DGRAM %d: %d bytes charged, want 0", i, u)
			}
		}
		if st := rs.s.Stats(); st.InboxDrops != 0 || st.Flows != 1 {
			t.Fatalf("Stats %+v", st)
		}
	})
	t.Run("refused", func(t *testing.T) {
		rs := newRealSourceEnv(t, 1232, testEnv(0)) // the Budget refuses every buffer
		const id = 0x78
		rs.send(h1(id, wire.TypeOpen, 1))
		f := rs.flow()
		if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) == 0 {
			t.Fatalf("H1 under memory pressure: event %d", ev)
		}
		rs.send(dg(id, dgramFrame(2, 100))) // dropped: carries a DGRAM
		rs.send(dg(id, pingFrame(3)))
		if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || wire.Type(b[0]) != wire.TypePing {
			t.Fatalf("got %s (event %d), want the PING through the control reserve", wire.Type(b[0]), ev)
		}
		if st := rs.s.Stats(); st.InboxDrops != 1 {
			t.Fatalf("Stats %+v, want 1 inbox drop (the DGRAM)", st)
		}
		if b, s := rs.env.Budget.Used(), rs.env.Stages.Used(); b != 0 || s != 0 {
			t.Fatalf("charged: Budget %d, Stages %d, want 0 and 0", b, s)
		}
	})
}
