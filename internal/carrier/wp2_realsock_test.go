package carrier

import (
	"bytes"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// M5 WP2 rows over real loopback sockets (both OSes; on Linux amd64/arm64
// the dialer socket batches, elsewhere it moves one datagram per call).

// wp2Env is dgEnv with the PING retry and cadence pushed past the test, so
// the datagrams written are the endpoint's frames and the first PING only.
func wp2Env() *Env {
	env := dgEnv()
	env.Timing.RelRTOInit = time.Minute
	env.Timing.RelRTOMax = time.Minute
	env.Timing.PacketPing = time.Minute
	env.Timing.DeadMin, env.Timing.DeadMax = time.Hour, time.Hour
	return env
}

// TestBatchWireIdentical (invariant 3): a raw receiver sees byte-identical
// datagram sequences — flow header and frames, the first PING's random
// nonce and clock masked — from a dialer carrier over rendr's own socket
// with MaxBatch 1 and with 32; MaxBatch 1 moves one datagram per counted
// call, and 32 batches where the platform can (Linux amd64/arm64).
func TestBatchWireIdentical(t *testing.T) {
	defer g10NoLeak(t)()
	run := func(mb int) (out [][]byte, calls, sent uint64) {
		raw, _ := wp5Listen(t, "udp4")
		defer raw.Close()
		du, _ := wp5Listen(t, "udp4")
		o := NewOwnedUDPBatch(du, wp5AP(raw), wp5Flow, wp5MaxDatagram, mb)
		env := wp2Env()
		c := dgConn(env, o, 1200, true)
		ep := &dEP{}
		var n atomic.Int32
		var seq atomic.Uint64
		n.Store(200)
		ep.setFill(burstFill(&n, &seq, func(s uint64) int { return 1 + int(s*131%1100) }, false))
		c.Start(ep, &hBell{}, StartOptions{})
		defer func() {
			c.Kill(CauseLocalClose, "test end")
			<-c.Done()
		}()
		if err := raw.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		for got := 0; got < 200; {
			k, err := raw.Read(buf)
			if err != nil {
				t.Fatalf("raw read after %d DGRAMs: %v", got, err)
			}
			d := buf[:k]
			if k < 9 || !bytes.Equal(d[:9], wp5Header(wp5Flow)) {
				t.Fatal("a datagram without the flow's header")
			}
			fs, ok := dgDecode(d[9:])
			if !ok {
				t.Fatal("a datagram does not decode")
			}
			for _, f := range fs {
				if f.Type == wire.TypeDgram {
					got++
				}
			}
			out = append(out, append(append([]byte(nil), d[:9]...), maskPings(t, d[9:])...))
		}
		// The writer counts a call when it returns, which may be after the
		// raw receiver read its datagram: wait (bounded) until every
		// datagram received is counted as sent, then snapshot.
		var sc, sd uint64
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
			sc, sd, _, _, _ = env.Dgram.IO.Load()
			if sd >= uint64(len(out)) || time.Now().After(deadline) {
				break
			}
		}
		return out, sc, sd
	}
	off, offCalls, offSent := run(1)
	on, onCalls, onSent := run(32)
	if len(off) != len(on) {
		t.Fatalf("%d datagrams with MaxBatch 1, %d with 32", len(off), len(on))
	}
	for i := range off {
		if !bytes.Equal(off[i], on[i]) {
			t.Fatalf("datagram %d differs between MaxBatch 1 and 32", i)
		}
	}
	if offCalls == 0 || offCalls != offSent || offSent < uint64(len(off)) {
		t.Fatalf("MaxBatch 1: %d calls for %d datagrams (%d received); want one per call", offCalls, offSent, len(off))
	}
	batching := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	if batching && onSent <= onCalls {
		t.Fatalf("MaxBatch 32 on %s/%s: %d datagrams in %d calls; want batched calls", runtime.GOOS, runtime.GOARCH, onSent, onCalls)
	}
	if !batching && onSent != onCalls {
		t.Fatalf("MaxBatch 32 on %s/%s: %d datagrams in %d calls; want one per call", runtime.GOOS, runtime.GOARCH, onSent, onCalls)
	}
}

// countPC counts the datagrams an embedder net.PacketConn moved, one per
// successful ReadFrom or WriteTo.
type countPC struct {
	net.PacketConn
	reads, writes atomic.Int64
}

func (p *countPC) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := p.PacketConn.ReadFrom(b)
	if err == nil {
		p.reads.Add(1)
	}
	return n, a, err
}

func (p *countPC) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := p.PacketConn.WriteTo(b, a)
	if err == nil {
		p.writes.Add(1)
	}
	return n, err
}

// wrapOwned is an embedder's wrapper around rendr's own dialer token: it
// embeds *OwnedUDP, so it even has WriteDatagrams, and counts its
// ReadFrom and WriteTo calls.
type wrapOwned struct {
	*OwnedUDP
	reads, writes atomic.Int64
}

func (p *wrapOwned) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := p.OwnedUDP.ReadFrom(b)
	if err == nil {
		p.reads.Add(1)
	}
	return n, a, err
}

func (p *wrapOwned) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := p.OwnedUDP.WriteTo(b, a)
	if err == nil {
		p.writes.Add(1)
	}
	return n, err
}

// TestEmbedderConnNeverBatched_L57: batching is a property of rendr's own
// sockets only (L57, M5-D10). An embedder *net.UDPConn and an embedder's
// wrapper around an *OwnedUDP reach a datagram carrier through NewPacketIO
// (the exact token type is never matched through a wrapper): the carrier
// sees no BatchIO, every datagram it writes is one WriteTo call and every
// datagram it reads one ReadFrom call, and the Runtime's counters of
// rendr-owned sockets stay at zero.
func TestEmbedderConnNeverBatched_L57(t *testing.T) {
	defer g10NoLeak(t)()
	for _, tc := range []string{"embedder UDPConn", "wrapped OwnedUDP"} {
		t.Run(tc, func(t *testing.T) {
			raw, _ := wp5Listen(t, "udp4")
			defer raw.Close()
			u, _ := wp5Listen(t, "udp4")
			var pc net.PacketConn
			var reads, writes *atomic.Int64
			hdr := []byte(nil)
			if tc == "embedder UDPConn" {
				p := &countPC{PacketConn: u}
				pc, reads, writes = p, &p.reads, &p.writes
			} else {
				p := &wrapOwned{OwnedUDP: NewOwnedUDP(u, wp5AP(raw), wp5Flow, wp5MaxDatagram)}
				pc, reads, writes = p, &p.reads, &p.writes
				hdr = wp5Header(wp5Flow)
			}
			env := wp2Env()
			pio, err := NewPacketIO(env, pc, raw.LocalAddr(), 1200)
			if err != nil {
				t.Fatal(err)
			}
			if bio := dgBatchOf(pio); bio != nil {
				t.Fatalf("the carrier sees a BatchIO (%T) on an embedder conn", bio)
			}
			c := dgConn(env, pio, 1200, true)
			ep := &dEP{}
			var n atomic.Int32
			var seq atomic.Uint64
			n.Store(30)
			ep.setFill(burstFill(&n, &seq, fixed(200), false))
			c.Start(ep, &hBell{}, StartOptions{})
			defer func() {
				c.Kill(CauseLocalClose, "test end")
				<-c.Done()
			}()
			waitFor(t, "30 DGRAMs written", func() bool { return seq.Load() == 30 && c.Stats().Datagrams >= 30 })
			peer := &rawPeer{fseq: env.Presets.firstFseq()}
			for i := range 20 {
				d := append(append([]byte(nil), hdr...), peer.datagram(dgramFrame(uint64(i), 100))...)
				wp5Send(t, raw, d, wp5AP(u))
			}
			waitFor(t, "20 DGRAMs read", func() bool { return c.Stats().DatagramsRx >= 20 })
			st := c.Stats()
			if w := writes.Load(); w != int64(st.Datagrams) {
				t.Fatalf("%d WriteTo calls for %d datagrams written: want one per datagram", w, st.Datagrams)
			}
			if r := reads.Load(); r != int64(st.DatagramsRx+st.Dropped) {
				t.Fatalf("%d ReadFrom calls for %d datagrams read (%d dropped): want one per datagram", r, st.DatagramsRx, st.Dropped)
			}
			if sc, sd, rc, rd, _ := env.Dgram.IO.Load(); sc|sd|rc|rd != 0 {
				t.Fatalf("rendr-owned socket counters moved: %d %d %d %d", sc, sd, rc, rd)
			}
		})
	}
}
