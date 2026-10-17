package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestForwardPacketZeroAllocs_L54 (M6 design §A16.6, M6-D14; L54):
// forwarding a datagram costs no allocation. Both forwards of a flow — the
// dialer's from a client DatagramPipe, the passive's toward a target
// DatagramPipe (which recycle their buffers) — run over a warmed
// carrier/udp loopback packet session (rendr's own UDP sockets, one
// dedicated carrier: the session's steady state allocates nothing, as the
// packet scenario's TestPacketSteadyStateZeroAllocs_L41_L54 proves). At
// least 4,000 round trips of a 1000-byte datagram each way (16,000
// datagrams through the four movers) and 50 PacketPing intervals cost at
// most 40 allocations in total, counted raw (runtime.MemStats.Mallocs,
// every goroutine, GC off, one P), so an allocation per datagram, per
// class check or per SetIdleTimeout call exceeds the bound. The flow is a
// stream from the warm-up (the reply rule, so that the window measures the
// promoted state; the tracker's pre-promotion path allocates nothing
// either, TestFlowClassRules_L72 runs it). Asserted in the non-race lane;
// the race lane logs the figure.
func TestForwardPacketZeroAllocs_L54(t *testing.T) {
	check := rendrtest.AssertNoLeak(t)
	pfRule(t, promoteOnReply)
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
	accepted := make(chan *rendr.PacketConn, 1)
	go func() {
		pend, err := ln.AcceptPacket(ctx)
		if err != nil {
			accepted <- nil
			return
		}
		c, _ := pend.Confirm()
		accepted <- c
	}()
	dc, err := peer.DialPacket(ctx, rendr.DialOptions{})
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	pc := <-accepted
	if pc == nil {
		t.Fatal("AcceptPacket/Confirm failed")
	}

	cli, cliLocal := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
	tgtLocal, tgt := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
	fctx, fcancel := context.WithCancel(context.Background())
	in := pfForward(fctx, dc, cliLocal, FlowIdle{})
	out := pfForward(fctx, pc, tgtLocal, FlowIdle{})
	for _, c := range []*rendrtest.DatagramConn{cli, tgt} {
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
	if !bytes.Equal(rbuf[:len(down)], down) {
		t.Fatal("the last round delivered other bytes")
	}
	t.Logf("%d allocations in %d round trips of %d bytes each way through both forwards (%v)", mallocs, rounds, len(up), el)
	if rounds < minRounds || el < minWindow {
		t.Fatalf("load: %d rounds in %v", rounds, el)
	}
	if raceEnabled {
		t.Log("race lane: not asserted")
	} else if mallocs > maxAllocs {
		t.Fatalf("%d allocations in %d steady-state round trips (%d datagrams forwarded) over %v, want at most %d", mallocs, rounds, 4*rounds, el, maxAllocs)
	}

	fcancel()
	n := uint64(warm + 16 + rounds)
	for name, r := range map[string]PacketResult{"dialer": <-in, "passive": <-out} {
		// Both ctxs end at once: a forward whose peer's close arrived before
		// its own ctx's halt ran ends with io.EOF.
		if r.ToSession != n || r.ToLocal != n || !r.Stream || r.LocalErr != nil || !errors.Is(r.SessionErr, context.Canceled) && !errors.Is(r.SessionErr, io.EOF) {
			t.Fatalf("%s forward %+v: want %d datagrams each way, a stream, ended by ctx", name, r, n)
		}
	}
	for _, c := range []*rendr.PacketConn{dc, pc} {
		select {
		case <-c.Done():
		case <-time.After(30 * time.Second):
			t.Fatalf("session not done: %+v", c.Status())
		}
	}
	peer.Close()
	d.Close()
	p.Close()
	check()
}
