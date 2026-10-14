package udp

// A Listen socket's per-carrier queue follows its read buffer (M5 work
// item inboxtime; the delegate's F-6 decision on C-P's G3-bond-100k rows,
// whose passive dropped 17,145 and 20,484 datagrams in flow inboxes of 512
// datagrams — 5 ms at 100 kpps — with a clean kernel path and the 16-MiB
// read buffer A6.3 sizes). The rows drive the Listen socket's udpflow
// Source directly, so the test goroutine is the flow's reader and can lag.

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// ibEnv is a component Env for a udpflow Source over a Listen socket: a
// 1-GiB Budget, so that only a flow's inbox bound can drop a datagram.
func ibEnv() *carrier.Env {
	return &carrier.Env{
		Local:   [16]byte{0x1b, 2, 3},
		Timing:  carrier.Timing{AbandonWait: time.Second},
		Abandon: carrier.NewAbandonPool(256),
		Budget:  carrier.NewBudget(1 << 30),
		Stages:  carrier.NewBudget(1 << 40),
		DBufs:   carrier.NewDatagramBufPool(),
		Dgram:   &carrier.DgramStats{},
	}
}

// ibH1 returns a complete valid first datagram of flow id: the flow
// header, a PREFACE of kind datagram and REL{FirstCseq, OPEN}.
func ibH1(id uint64) []byte {
	b := make([]byte, wire.FlowHeaderLen, 256)
	wire.PutFlowHeader(b, id)
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Kind: wire.KindDatagram, Instance: [16]byte{7, 7, 7}, CarrierID: 1})
	b = append(b, pre...)
	var p [wire.RelHeadLen + wire.OpenFixedLen]byte
	n := wire.PutOpen(p[wire.RelHeadLen:], &wire.Open{SID: [16]byte{9, 9, 9}, Kind: wire.KindDatagram, Mode: 1, Window: 1223, PMTU: 1198})
	wire.PutRelHead(p[:], &wire.RelHead{Cseq: wire.FirstCseq, Type: wire.TypeOpen, Handle: wire.SessionHandle})
	return wire.AppendFrame(b, wire.Header{Type: wire.TypeRel, Fseq: wire.PrefaceFseq(pre)}, p[:wire.RelHeadLen+n])
}

// TestFlowInboxHoldsTwentyMillisAt100kpps_L40 (F-6, the failing-first row;
// A6.3; L40, L58): a Listen socket with A6.3's read buffer for 100 kpps
// (16 MiB, G3-100k's ≈ 80 ms) serves a flow whose reader lags: 2,000
// datagrams of 1,000 payload bytes — 20 ms at 100 kpps — arrive while the
// reader reads nothing. The flow's inbox holds them all, with no inbox
// drop, and the reader then gets every one, intact and in order. The
// client sends in bursts of 32 and waits until the Source has read each
// (its receive counter), so no socket buffer on loopback can overflow and
// only the inbox could lose a datagram. On m5 61c2dec, whose inbox held 512
// datagrams whatever the read buffer, the reader got 512 and the other
// 1,488 were inbox drops. Mutants: the bound back at 512 datagrams; Listen
// not recording its read buffer in the token.
func TestFlowInboxHoldsTwentyMillisAt100kpps_L40(t *testing.T) {
	defer wp5NoLeak(t)()
	const (
		total   = 2000 // 20 ms at 100,000 datagrams a second
		payload = 1000 // G3-100k's datagram payload
		burst   = 32
		id      = 0x16a1
	)
	pc, err := Listen("udp4", "127.0.0.1:0", Options{ReadBuffer: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	env := ibEnv()
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
		for end := min(i+burst, total); i < end; i++ {
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
