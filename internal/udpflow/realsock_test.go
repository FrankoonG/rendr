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
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

const realWait = 5 * time.Second

// loopback4 is the IPv4 loopback address, port 0.
func loopback4() *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0))
}

// realSource is a Source over an OwnedUDPSocket with a client socket.
// admitted holds up to 128 flows not taken yet.
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
	return newRealSourceEnv(t, maxDatagram, testEnv(1<<30), Limits{})
}

func newRealSourceEnv(t *testing.T, maxDatagram int, env *carrier.Env, lim Limits) *realSource {
	t.Helper()
	rs := newRealSourceIO(t, maxDatagram, env, lim, defaultMaxBatch)
	rs.start()
	return rs
}

// newRealSourceIO returns a realSource, without starting Run (start),
// whose Source reads and writes the socket through: NewSource's own
// construction for maxBatch 0, and for a maxBatch that construction
// already gives (the production path once the token exposes its socket,
// M5 WP3); else a udpsocket.Conn of maxBatch counted in env.Dgram.IO; or,
// for maxBatch < 0, the token's single-datagram tokenIO.
func newRealSourceIO(t *testing.T, maxDatagram int, env *carrier.Env, lim Limits, maxBatch int) *realSource {
	t.Helper()
	return newRealSourceTok(t, maxDatagram, env, lim, maxBatch, 0)
}

// newRealSourceTok is newRealSourceIO over a token built with
// carrier/udp's Options.MaxBatch tokBatch (NewOwnedUDPSocketBatch; 0: the
// default).
func newRealSourceTok(t *testing.T, maxDatagram int, env *carrier.Env, lim Limits, maxBatch, tokBatch int) *realSource {
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
	rs := &realSource{t: t, env: env, u: u, cl: cl, admitted: make(chan *Flow, 128),
		dst: u.LocalAddr().(*net.UDPAddr).AddrPort()}
	own := carrier.NewOwnedUDPSocketBatch(u, maxDatagram, tokBatch)
	rs.s = NewSource(rs.env, own, lim)
	c, built := rs.s.bio.(*udpsocket.Conn)
	switch {
	case maxBatch < 0:
		rs.s.setIO(tokenIO{own})
	case maxBatch > 0 && !(built && c.MaxBatch() == maxBatch):
		c, err := udpsocket.New(u, maxBatch, &env.Dgram.IO)
		if err != nil {
			u.Close()
			cl.Close()
			t.Fatal(err)
		}
		rs.s.setIO(c)
	}
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

// start runs the Source's demux.
func (rs *realSource) start() {
	go rs.s.Run(func(f *Flow) {
		rs.mu.Lock()
		rs.all = append(rs.all, f)
		rs.mu.Unlock()
		rs.admitted <- f
	})
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

// idleCharge is what rs's Source holds while it waits with nothing queued
// (its slot 0 is uncharged, R-C3-2): nothing on a plain socket; on a
// socket in ModeBatch at depth D ≥ 2 (Linux amd64/arm64) its extra slots
// 1 … D−1 on the Budget — none where the Budget refuses every buffer — and
// its Batch in Stages (M5 design R1-4 rule 2, R1-5 rule 4, R3-24).
func (rs *realSource) idleCharge(maxDatagram int, budgetRefuses bool) (budget, stages int64) {
	d := rs.s.readDepth()
	if d < 2 {
		return 0, 0
	}
	if !budgetRefuses {
		budget = int64(d-1) * slotBytes(rs.env, maxDatagram)
	}
	return budget, int64(d) * batchMsgBytes
}

// TestFlowOwnedSocketCharge (R-C3-2; plan:774, as M5's R1-4 amends it for
// a batching socket): the read buffer of rendr's own socket is charged to
// nothing while the source waits — an idle source whose reader runs (it
// read and dropped junk) holds exactly its idle charge (idleCharge: 0
// bytes on a plain socket) in the Budget and in Stages — and a datagram
// read into it is charged to the Budget from the moment it is queued for a
// flow until the flow's reader releases it. When the Budget refuses that
// charge, a datagram without a DGRAM still reaches its flow through the
// control reserve (Stages, L16) and a DGRAM is dropped as an inbox drop;
// nothing stays charged beyond the idle charge. When the flow's inbox is
// full, the read buffer the Budget took (TryCharge) is returned uncharged
// for the next read: after the overflow and the drain, the idle source
// again holds exactly its idle charge.
func TestFlowOwnedSocketCharge(t *testing.T) {
	t.Run("budget", func(t *testing.T) {
		rs := newRealSource(t, 1232)
		used := func() int64 { return rs.env.Budget.Used() + rs.env.Stages.Used() }
		rs.send([]byte("junk"))
		waitFor(t, "the junk datagram's drop", func() bool { return rs.s.Stats().Dropped == 1 })
		ib, is := rs.idleCharge(1232, false)
		if b, s := rs.env.Budget.Used(), rs.env.Stages.Used(); b != ib || s != is {
			t.Fatalf("an idle source whose reader runs: Budget %d, Stages %d charged, want %d and %d", b, s, ib, is)
		}
		const id = 0x77
		rs.send(h1(id, wire.TypeOpen, 1))
		f := rs.flow()
		if rs.env.Budget.Used() == ib {
			t.Fatal("the H1 queued in its flow's inbox is charged to no Budget")
		}
		if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) == 0 {
			t.Fatalf("H1: event %d", ev)
		}
		f.Admitted()
		for i := range 3 {
			rs.send(dg(id, dgramFrame(uint32(2+i), 900)))
			waitFor(t, "the DGRAM's charge", func() bool { return rs.env.Budget.Used() > ib })
			if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) < 900 {
				t.Fatalf("DGRAM %d: event %d, %d bytes", i, ev, len(b))
			}
			if u := used(); u != ib+is {
				t.Fatalf("after reading DGRAM %d: %d bytes charged, want the idle %d", i, u, ib+is)
			}
		}
		if st := rs.s.Stats(); st.InboxDrops != 0 || st.Flows != 1 {
			t.Fatalf("Stats %+v", st)
		}
	})
	t.Run("refused", func(t *testing.T) {
		rs := newRealSourceEnv(t, 1232, testEnv(0), Limits{}) // the Budget refuses every buffer
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
		if ib, is := rs.idleCharge(1232, true); rs.env.Budget.Used() != ib || rs.env.Stages.Used() != is {
			t.Fatalf("charged: Budget %d, Stages %d, want the idle %d and %d", rs.env.Budget.Used(), rs.env.Stages.Used(), ib, is)
		}
	})
	t.Run("overflow", func(t *testing.T) {
		rs := newRealSourceEnv(t, 1232, testEnv(1<<30), Limits{Inbox: 2})
		used := func() int64 { return rs.env.Budget.Used() + rs.env.Stages.Used() }
		ib, is := rs.idleCharge(1232, false)
		// idle waits for the idle charge: after a batched read the reader
		// refills its extra slots (TryGet) when it next reads, which may
		// follow the event the test saw.
		idle := func(what string) {
			t.Helper()
			deadline := time.Now().Add(realWait)
			for used() != ib+is {
				if time.Now().After(deadline) {
					t.Fatalf("%s: %d bytes charged (Budget %d, Stages %d), want the idle %d (%d and %d)",
						what, used(), rs.env.Budget.Used(), rs.env.Stages.Used(), ib+is, ib, is)
				}
				time.Sleep(time.Millisecond)
			}
		}
		const id = 0x79
		rs.send(h1(id, wire.TypeOpen, 1))
		f := rs.flow()
		if _, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK {
			t.Fatalf("H1: event %d", ev)
		}
		f.Admitted()
		const sent, inbox = 6, 2
		for i := range sent { // nobody reads: the inbox overflows
			rs.send(dg(id, dgramFrame(uint32(2+i), 900)))
		}
		waitFor(t, "the overflow's inbox drops", func() bool { return rs.s.Stats().InboxDrops == sent-inbox })
		if rs.env.Budget.Used() <= ib {
			t.Fatal("stimulus: the queued DGRAMs are charged to no Budget")
		}
		for i := range inbox {
			if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) < 900 {
				t.Fatalf("queued DGRAM %d: event %d, %d bytes", i, ev, len(b))
			}
		}
		idle("after the overflow and the drain")
		rs.send(dg(id, dgramFrame(uint32(2+sent), 900))) // the read buffer works on
		if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || len(b) < 900 {
			t.Fatalf("a DGRAM after the overflow: event %d, %d bytes", ev, len(b))
		}
		idle("after the last DGRAM")
		if st := rs.s.Stats(); st.InboxDrops != sent-inbox || st.Flows != 1 {
			t.Fatalf("Stats %+v", st)
		}
	})
}
