package udp

// A Listen socket with a large MaxDatagram keeps M2's 512 datagrams per
// carrier (M5 work item inboxtime, F-6: the read buffer only ever raises
// the bound). The file uses no identifier inboxtime added, so the row also
// runs on the commits before it.

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestListenJumboInboxKeepsM2Bound_L40 (F-6; M2-D59; L40, L58): a Listen
// socket with the default 4-MiB read buffer and a MaxDatagram of 9,000 or
// 65,507 — whose read slots are of the 16,448- and 65,600-byte classes, so
// that the read buffer alone holds 256 and 64 of them — serves a flow
// whose reader lags while 512 datagrams of 1,000 bytes arrive. The flow
// holds every one (M2's bound, which every udp.Listen flow held before
// inboxtime), and its reader then gets them all, intact and in order, with
// no inbox drop. The client sends in bursts of 32 and waits until the
// Source has read each, so no socket buffer on loopback can overflow and
// only the inbox could lose a datagram. Mutant: the datagram floor dropped
// on rendr's own socket (256 and 64 delivered), as on inboxtime's first
// round.
func TestListenJumboInboxKeepsM2Bound_L40(t *testing.T) {
	for i, md := range []int{9000, 65507} {
		t.Run(fmt.Sprintf("MaxDatagram%d", md), func(t *testing.T) {
			defer wp5NoLeak(t)()
			lagListen(t, Options{MaxDatagram: md}, uint64(0x7a10+i), 512, 1000)
		})
	}
}

// lagListen opens a Listen socket with o and drives its udpflow Source
// directly, the test goroutine being the flow's reader: after the flow's
// H1, total datagrams of payload bytes (a sequence number first) arrive
// while the reader reads nothing, sent in bursts of 32 gated on the
// Source's receive counter; the reader then reads them all. It fails on any
// datagram lost, changed or out of order, and on any inbox drop. Its
// premise: the token's MaxDatagram class is so large that the default read
// buffer alone holds fewer than total of them.
func lagListen(t *testing.T, o Options, id uint64, total, payload int) {
	t.Helper()
	pc, err := Listen("udp4", "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	env := ibEnv()
	slot := env.DBufs.Get(pc.(*carrier.OwnedUDPSocket).MaxDatagram()+1, nil)
	class := int64(cap(slot.B))
	slot.Release()
	if byBytes := (int64(defaultReadBuffer) + class - 1) / class; o.ReadBuffer != 0 || byBytes >= int64(total) {
		pc.Close()
		t.Fatalf("premise: MaxDatagram %d, read slot class %d B: the 4-MiB read buffer alone holds %d, want fewer than the %d sent (ReadBuffer %d, want the default)",
			pc.(*carrier.OwnedUDPSocket).MaxDatagram(), class, byBytes, total, o.ReadBuffer)
	}
	src := udpflow.NewSource(env, pc, udpflow.Limits{})
	admitted := make(chan *udpflow.Flow, 1)
	go src.Run(func(f *udpflow.Flow) { admitted <- f })
	var flow *udpflow.Flow
	defer func() {
		src.Abort()
		if flow != nil {
			flow.Release()
			flow.Close()
		}
		select {
		case <-src.Done():
		case <-time.After(5 * time.Second):
			t.Error("the source did not end")
		}
	}()
	cl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	dst := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	send := func(b []byte) {
		t.Helper()
		if _, err := cl.WriteToUDPAddrPort(b, dst); err != nil {
			t.Fatal(err)
		}
	}

	send(ibH1(id))
	select {
	case flow = <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("no flow admitted")
	}
	if err := flow.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := flow.ReadDatagram(nil); err != nil {
		t.Fatalf("H1: %v", err)
	}
	flow.Release()
	flow.Admitted()

	recvd := func() uint64 { _, _, _, n, _ := env.Dgram.IO.Load(); return n }
	d := make([]byte, wire.FlowHeaderLen+payload)
	wire.PutFlowHeader(d, id)
	for i := 0; i < total; {
		for end := min(i+32, total); i < end; i++ {
			binary.BigEndian.PutUint32(d[wire.FlowHeaderLen:], uint32(i))
			send(d)
		}
		deadline := time.Now().Add(5 * time.Second)
		for recvd() < uint64(1+i) { // the H1 and the i datagrams sent so far
			if time.Now().After(deadline) {
				t.Fatalf("the Source read %d of the %d datagrams sent: loopback lost some, the row cannot judge the inbox", recvd()-1, i)
			}
			time.Sleep(100 * time.Microsecond)
		}
	}

	for i := range total {
		if err := flow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		b, _, ev, err := flow.ReadDatagram(nil)
		if err != nil {
			st := src.Stats()
			t.Fatalf("the lagging reader got %d of the %d datagrams (%v): InboxDrops %d (Env %d), want 0",
				i, total, err, st.InboxDrops, env.Dgram.InboxDrops.Load())
		}
		if ev != carrier.ReadOK || len(b) != payload || binary.BigEndian.Uint32(b) != uint32(i) {
			t.Fatalf("datagram %d: event %d, %d bytes, sequence %d", i, ev, len(b), binary.BigEndian.Uint32(b))
		}
		flow.Release()
	}
	if st := src.Stats(); st.InboxDrops != 0 || env.Dgram.InboxDrops.Load() != 0 {
		t.Fatalf("Stats %+v, Env InboxDrops %d: want no inbox drop", st, env.Dgram.InboxDrops.Load())
	}
}
