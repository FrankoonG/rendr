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
// least 4,000 rounds of a 1000-byte datagram and 50 PacketPing intervals
// cost at most 40 allocations in total, counted raw (runtime.MemStats.Mallocs,
// every goroutine, GC off, one P), so an allocation per datagram, per
// class check or per SetIdleTimeout call exceeds the bound. Two legs:
//   - promoted: round trips under the reply rule, a stream from the
//     warm-up (16,000 datagrams through the four movers);
//   - unpromoted: the rule in force (promoteActive) with datagrams one way
//     only, so both trackers stay short and check every datagram (time and
//     lock, no allocation).
//
// Asserted in the non-race lane; the race lane logs the figure.
func TestForwardPacketZeroAllocs_L54(t *testing.T) {
	t.Run("promoted", func(t *testing.T) { pfZeroAllocs(t, promoteOnReply, true) })
	t.Run("unpromoted", func(t *testing.T) { pfZeroAllocs(t, promoteActive, false) })
}

// pfZeroAllocs is one leg of TestForwardPacketZeroAllocs_L54: rule in
// force, round trips (twoWay) or client datagrams only.
func pfZeroAllocs(t *testing.T, rule promoteMode, twoWay bool) {
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
	t.Logf("%d allocations in %d rounds of %d bytes (both ways: %v) through both forwards (%v)", mallocs, rounds, len(up), twoWay, el)
	if rounds < minRounds || el < minWindow {
		t.Fatalf("load: %d rounds in %v", rounds, el)
	}
	if raceEnabled {
		t.Log("race lane: not asserted")
	} else if mallocs > maxAllocs {
		t.Fatalf("%d allocations in %d steady-state rounds (both ways: %v) over %v, want at most %d", mallocs, rounds, twoWay, el, maxAllocs)
	}

	fcancel()
	n := uint64(warm + 16 + settleRuns(minRounds) + rounds)
	back := map[bool]uint64{true: n, false: 0}[twoWay]
	for name, r := range map[string]PacketResult{"dialer": <-in, "passive": <-out} {
		// Both ctxs end at once: a forward whose peer's close arrived before
		// its own ctx's halt ran ends with io.EOF.
		to, from := r.ToSession, r.ToLocal
		if name == "passive" {
			to, from = from, to
		}
		if to != n || from != back || r.Stream != twoWay || r.LocalErr != nil || !errors.Is(r.SessionErr, context.Canceled) && !errors.Is(r.SessionErr, io.EOF) {
			t.Fatalf("%s forward %+v: want %d datagrams toward the target, %d back, a stream: %v, ended by ctx", name, r, n, back, twoWay)
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
