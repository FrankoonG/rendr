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
	u, err := net.ListenUDP("udp4", loopback4())
	if err != nil {
		t.Fatal(err)
	}
	cl, err := net.ListenUDP("udp4", loopback4())
	if err != nil {
		u.Close()
		t.Fatal(err)
	}
	rs := &realSource{t: t, env: testEnv(1 << 30), u: u, cl: cl, admitted: make(chan *Flow, 16),
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
