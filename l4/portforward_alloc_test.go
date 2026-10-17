package l4

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPortForwardZeroAllocs_L54 (M6 design §A8.2, §A16.6; L54): an open
// flow's datagrams cost no allocation at the ingress. A client socket
// sends through a PortForward on a loopback UDP socket, over a warmed
// carrier/udp loopback packet session (one dedicated carrier), to the
// passive's ForwardPacket and a target DatagramPipe, and back: at least
// 4,000 rounds of a 1000-byte datagram and 50 PacketPing intervals cost at
// most 40 allocations in total, counted raw (runtime.MemStats.Mallocs,
// every goroutine, GC off, one P), so an allocation per datagram in the
// reader, the flow goroutine, the class check or a SetIdleTimeout call
// exceeds the bound. Two legs: promoted (round trips under the reply
// rule: a stream from the warm-up) and unpromoted (the rule in force,
// promoteActive, client datagrams only: the class is checked on every
// datagram). Asserted in the non-race lane; the race lane (racebudget) runs
// the promoted leg only and logs the figure.
func TestPortForwardZeroAllocs_L54(t *testing.T) {
	t.Run("promoted", func(t *testing.T) { pwZeroAllocs(t, promoteOnReply, true) })
	if !raceEnabled {
		t.Run("unpromoted", func(t *testing.T) { pwZeroAllocs(t, promoteActive, false) })
	}
}

func pwZeroAllocs(t *testing.T, rule promoteMode, twoWay bool) {
	check := rendrtest.AssertNoLeak(t)
	pfRule(t, rule)
	ov := testhooks.Overrides{PacketPing: 10 * time.Millisecond}
	d := kitRuntime(t, rendr.Config{}, ov)
	p := kitRuntime(t, rendr.Config{}, ov)
	defer d.Close()
	defer p.Close()
	sock, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	ln, err := p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}})
	if err != nil {
		sock.Close()
		t.Fatalf("Listen: %v", err)
	}
	uc := udp.Carrier("udp", "udp4", sock.LocalAddr().String(), udp.Options{})
	uc.Props.CheapSubflow = true
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{uc}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tgtLocal, tgt := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
	out := make(chan PacketResult, 1)
	go func() {
		pend, err := ln.AcceptPacket(ctx)
		if err != nil {
			out <- PacketResult{SessionErr: err}
			return
		}
		r, err := ParseUDPMetadata(pend.Metadata())
		if err != nil {
			pend.Reject(uint32(CodeBadRequest), "test")
			out <- PacketResult{SessionErr: err}
			return
		}
		if len(r.First) > 0 {
			tgtLocal.Write(r.First)
		}
		pc, err := pend.Confirm()
		if err != nil {
			out <- PacketResult{SessionErr: err}
			return
		}
		out <- forwardPacket(context.Background(), pc, tgtLocal, FlowIdle{}, flowSeed{at: time.Now(), dir: towardLocal}, nil)
	}()

	ing, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	pf := &PortForward{Peer: peer}
	sctx, scancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- pf.ServeUDP(sctx, ing, pfTarget) }()
	cli, err := net.DialUDP("udp4", nil, ing.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	for _, c := range []interface{ SetReadDeadline(time.Time) error }{cli, tgt} {
		if err := c.SetReadDeadline(time.Now().Add(time.Minute)); err != nil { // a lost datagram fails the round instead of hanging it
			t.Fatal(err)
		}
	}
	up := rendrtest.PacketPayload(make([]byte, 1000), 54, 0, 1000, time.Now())
	down := bytes.Clone(up)
	down[0] ^= 0xff
	rbuf := make([]byte, 2048)
	round := func() {
		if _, err := cli.Write(up); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		if n, err := tgt.Read(rbuf); n != len(up) || err != nil {
			t.Fatalf("target Read = %d, %v (a datagram lost on loopback?)", n, err)
		}
		if !twoWay {
			return
		}
		if _, err := tgt.Write(down); err != nil {
			t.Fatalf("target Write: %v", err)
		}
		if n, err := cli.Read(rbuf); n != len(down) || err != nil {
			t.Fatalf("client Read = %d, %v (a datagram lost on loopback?)", n, err)
		}
	}
	const warm, maxAllocs = 256, 40
	for range warm {
		round()
	}
	runtime.GC()
	for range 16 {
		round()
	}
	minRounds, minWindow := 100*maxAllocs, 50*ov.PacketPing
	if raceEnabled {
		minRounds, minWindow = warm, 0
	}
	mallocs, rounds, el := countMallocs(minRounds, minWindow, round)
	if last := map[bool][]byte{true: down, false: up}[twoWay]; !bytes.Equal(rbuf[:len(last)], last) {
		t.Fatal("the last round delivered other bytes")
	}
	t.Logf("%d allocations in %d rounds of %d bytes (both ways: %v) through the ingress (%v)", mallocs, rounds, len(up), twoWay, el)
	if rounds < minRounds || el < minWindow {
		t.Fatalf("load: %d rounds in %v", rounds, el)
	}
	if raceEnabled {
		t.Log("race lane: not asserted")
	} else if mallocs > maxAllocs {
		t.Fatalf("%d allocations in %d steady-state rounds (both ways: %v) over %v, want at most %d", mallocs, rounds, twoWay, el, maxAllocs)
	}
	n := uint64(warm + 16 + rounds)
	st := pf.Status().UDP
	if st.Opened != 1 || st.ToSession != n || st.ToClient != map[bool]uint64{true: n, false: 0}[twoWay] {
		t.Fatalf("ingress status %+v: want one flow and %d datagrams", st, n)
	}
	if fs := pf.Flows(); len(fs) != 1 || fs[0].Stream != twoWay {
		t.Fatalf("flows %+v: want one, a stream: %v", fs, twoWay)
	}
	scancel()
	if err := <-served; err != context.Canceled {
		t.Fatalf("ServeUDP = %v", err)
	}
	<-out
	peer.Close()
	d.Close()
	p.Close()
	check()
}

// TestPortForwardMemoryPerFlow (M6 design §A12; recorded): the memory one
// open UDP flow costs at the ingress, over 200 flows (100 in the race
// lane) that each carried one exchange and stay open, and exactly one
// goroutine per flow there. Asserted: the PortForward's own live heap per
// flow — every allocation the ingress code made (its entry, done channel,
// open bound, reply buffer; profiled at rate 1, garbage collected), not
// the dialer session (DialUDP's), which the core bounds
// (TestIdleSessionMemory); the bound sits about a third above the largest
// figure observed (≈ 3.7 KiB per flow at MaxPayload 1,375, also under
// -race), so an ingress cost that grows by more than a third fails, as
// TestIdleSessionMemory. Logged: the heap allocated under the session's
// open (Peer.DialPacket), and the whole process's growth per flow (both
// ends, the kit passive included: heap plus stack spans).
func TestPortForwardMemoryPerFlow(t *testing.T) {
	const bound = 5000 // bytes per flow
	n := 200
	if raceEnabled {
		n = 100
	}
	defer func(r int) { runtime.MemProfileRate = r }(runtime.MemProfileRate)
	runtime.MemProfileRate = 1
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{})
		w.serve()
		if !pwRoundTrip(t, w.client(), pwTagged(30, 0x01, 0), time.Second) {
			t.Fatal("warm-up flow did not open")
		}
		cs := pwClients(w, n)
		sample := func() (total uint64, ingress, session int64) {
			synctest.Wait()
			runtime.GC()
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			ingress, session = pwIngressHeap()
			return m.HeapAlloc + m.StackInuse, ingress, session
		}
		total0, ing0, ses0 := sample()
		g0 := pwFlowGoroutines()
		for i, c := range cs {
			pfSend(t, c, pwTagged(30, byte(i), 1))
			time.Sleep(time.Millisecond)
		}
		for i, c := range cs {
			pfExpect(t, c, pwTagged(30, byte(i), 1))
		}
		time.Sleep(time.Second)
		total1, ing1, ses1 := sample()
		st := pwStatus(w.pf)
		if st.Flows != n+1 || st.Opened != uint64(n+1) {
			t.Fatalf("load: %s", pwDescribe(st))
		}
		if g := pwFlowGoroutines() - g0; g != n {
			t.Fatalf("%d ingress goroutines for %d flows, want one each", g, n)
		}
		per := float64(ing1-ing0) / float64(n)
		t.Logf("%d flows: the ingress's own heap %.2f KiB per flow; the session's open %.1f KiB; the process grew %.1f KiB per flow (both ends, kit passive, heap and stack spans; MaxPayload %d)",
			n, per/1024, float64(ses1-ses0)/float64(n)/1024, float64(int64(total1)-int64(total0))/float64(n)/1024, st.MaxPayload)
		if per > bound {
			t.Fatalf("the ingress's own heap %.0f bytes per flow, want at most %d", per, bound)
		}
	})
}

// pwIngressHeap sums the live heap allocated by the ingress code — the
// memory profile's in-use records whose stack holds a frame of the
// PortForward's UDP code (udpServe, ServeUDP) and none of the session's
// open (Peer.DialPacket), which is the core's — and, apart, the heap
// allocated under that open.
func pwIngressHeap() (ingress, session int64) {
	var recs []runtime.MemProfileRecord
	n, _ := runtime.MemProfile(nil, false)
	for {
		recs = make([]runtime.MemProfileRecord, n+64)
		var ok bool
		if n, ok = runtime.MemProfile(recs, false); ok {
			recs = recs[:n]
			break
		}
	}
	for _, r := range recs {
		in, ses := false, false
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			switch {
			case strings.Contains(f.Function, "/v2.(*Peer).DialPacket"):
				ses = true
			case strings.Contains(f.Function, "/l4.(*udpServe)."), strings.Contains(f.Function, "/l4.(*PortForward).ServeUDP"):
				in = true
			}
			if !more {
				break
			}
		}
		switch {
		case in && ses:
			session += r.InUseBytes()
		case in:
			ingress += r.InUseBytes()
		}
	}
	return ingress, session
}
