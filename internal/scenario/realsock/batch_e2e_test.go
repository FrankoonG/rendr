package realsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The end-to-end row of batched datagram I/O (M5 design §A10.1, WP4;
// M5-D10, M5-D16, M5-D17, R1-2): carrier/udp on real loopback sockets,
// outside synctest bubbles. Its helpers carry the be prefix; it reuses the
// package's msPair, msSide and msSize.

// beBatching reports whether this build batches rendr's own UDP sockets
// (sendmmsg/recvmmsg: Linux amd64 and arm64, M5-D8); every other target
// moves one datagram per system call.
var beBatching = runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")

// beCount is the datagrams each direction writes.
const beCount = 50000

// TestRealUDPBatchE2E (§A10.1 WP4; M5-D16, M5-D17, R1-2; L55, L57): a
// selector packet session between two Runtimes over carrier/udp on
// loopback — the dialer on udp.Carrier, the passive on one udp.Listen
// socket through FromPacketConn, both with the arm's Options.MaxBatch —
// writes 50,000 test datagrams (24 … 1,000 bytes) each way at full speed:
// both generators at once, each calling WriteTo back to back while fewer
// than beWindow of its datagrams are in flight end to end, so the
// carriers' writers always find a backlog and neither the send queue nor
// a socket buffer overflows.
//
// Stimulus: every WriteTo of both generators returned (n, nil), and each
// side's send counters account for all 50,000 (Sent plus the send-side
// drops). Load: at least beMinShare of each direction's datagrams
// arrived. Integrity per datagram: every datagram read is its generator's
// (seq, size, CRC-32C, body), none twice; what the receiving session
// accepted was read or counted as a receive-queue drop; nothing arrived
// that was not sent. Counters (Status.Datagram, both Runtimes): calls and
// datagrams moved in both directions, no batch fallback, and the final
// counts conserve datagrams (what one Runtime received the other sent, up
// to the dialer handshakes' uncounted writes, beUncounted).
// Arm "default" (MaxBatch 0 = 32): on Linux amd64/arm64 SentDatagrams/
// SendCalls > 1 on both Runtimes — sends were batched — and one datagram
// per call elsewhere. Arm "one" (MaxBatch 1): one datagram per send and
// receive call on every target, Linux included. Runtime.Close leaves
// nothing behind.
func TestRealUDPBatchE2E(t *testing.T) {
	for _, arm := range []struct {
		name     string
		maxBatch int
	}{{"default", 0}, {"one", 1}} {
		t.Run(arm.name, func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			beRun(t, arm.maxBatch)
		})
	}
}

// beMinShare is the share of each direction's datagrams that must arrive
// (load). The generators overrun neither the session's send queue nor the
// sockets' buffers (beWindow), so loopback loses next to nothing.
const beMinShare = 0.90

// beUncounted bounds the datagrams one dialer carrier writes through its
// socket before its writer and reader bind the token's counted I/O: the
// dialer's datagram handshake (H1 and its repeats, the REL) runs on the
// token's single calls before the carrier's writer and reader start, and
// those calls are not counted yet, short of DatagramStatus's godoc. Until
// that gap is closed, the dialer's SentDatagrams may fall short of what
// the passive received by at most this many per dial; once the handshake
// is counted, beUncounted is 0.
const beUncounted = 8

func beRun(t *testing.T, maxBatch int) {
	o := udp.Options{MaxBatch: maxBatch}
	sock, err := udp.Listen("udp4", "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	c := udp.Carrier("u", "udp4", sock.LocalAddr().String(), o)
	var dials atomic.Uint64 // every dial of the factory, probes included
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		dials.Add(1)
		return dial(ctx)
	}
	m := newMsPair(t, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}}, []rendr.Carrier{c})
	dc, pc := m.openPacket(rendr.ModeSelector)

	up := &msSide{v: rendrtest.NewPacketVerifier(0xb17c4)}
	down := &msSide{v: rendrtest.NewPacketVerifier(0x4c71b)}
	flows := []*beFlow{
		{name: "up", s: up, seed: 0xb17c4, tx: dc, rx: pc, rxRT: m.p},
		{name: "down", s: down, seed: 0x4c71b, tx: pc, rx: dc, rxRT: m.d},
	}
	var readers, writers sync.WaitGroup
	readers.Add(2)
	go up.receive(pc, &readers)
	go down.receive(dc, &readers)
	start := make(chan struct{})
	presumptions := make([]int, len(flows))
	writers.Add(len(flows))
	for i, f := range flows {
		go beGenerate(f, start, &writers, &presumptions[i])
	}
	began := time.Now()
	close(start)
	writers.Wait()
	t.Logf("MaxBatch %d: both generators wrote %d datagrams in %v (stall presumptions: up %d, down %d)",
		maxBatch, beCount, time.Since(began).Round(time.Millisecond), presumptions[0], presumptions[1])

	beDrain(t, flows)
	for _, f := range flows {
		beJudge(t, f)
	}
	dmid, pmid := m.d.Status().Datagram, m.p.Status().Datagram

	dc.Close()
	pc.Close()
	msDone(t, dc.Done(), "the dialer session")
	msDone(t, pc.Done(), "the passive session")
	readers.Wait()
	m.muxZero()
	m.close()

	// The final counters: every carrier and source has ended.
	ds, ps := m.d.Status().Datagram, m.p.Status().Datagram
	t.Logf("dialer   %s", beIO(ds))
	t.Logf("passive  %s", beIO(ps))
	for _, s := range []struct {
		name     string
		mid, fin rendr.DatagramStatus
	}{{"dialer", dmid, ds}, {"passive", pmid, ps}} {
		fin := s.fin
		if fin.SendCalls == 0 || fin.RecvCalls == 0 || fin.SentDatagrams < fin.SendCalls || fin.RecvDatagrams < fin.RecvCalls {
			t.Errorf("%s: I/O counters %s: want calls in both directions, each moving at least one datagram", s.name, beIO(fin))
		}
		if fin.SendCalls < s.mid.SendCalls || fin.SentDatagrams < s.mid.SentDatagrams || fin.RecvCalls < s.mid.RecvCalls || fin.RecvDatagrams < s.mid.RecvDatagrams {
			t.Errorf("%s: I/O counters went back: %s after %s", s.name, beIO(fin), beIO(s.mid))
		}
		if fin.BatchFallbacks != 0 {
			t.Errorf("%s: BatchFallbacks %d on loopback, want 0", s.name, fin.BatchFallbacks)
		}
		switch {
		case maxBatch == 1 || !beBatching:
			if fin.SendCalls != fin.SentDatagrams || fin.RecvCalls != fin.RecvDatagrams {
				t.Errorf("%s (MaxBatch %d, %s/%s): %s, want one datagram per call", s.name, maxBatch, runtime.GOOS, runtime.GOARCH, beIO(fin))
			}
		default:
			if fin.SentDatagrams <= fin.SendCalls {
				t.Errorf("%s (MaxBatch %d, %s/%s): %s, want SentDatagrams/SendCalls > 1 (sends batched)", s.name, maxBatch, runtime.GOOS, runtime.GOARCH, beIO(fin))
			}
		}
	}
	// Conservation: loopback creates no datagram, so neither Runtime
	// received more than the other sent — but for the dialer handshakes'
	// uncounted writes (beUncounted).
	if ps.RecvDatagrams > ds.SentDatagrams+beUncounted*dials.Load() || ds.RecvDatagrams > ps.SentDatagrams {
		t.Errorf("received more datagrams than were sent (%d dials): dialer %s, passive %s", dials.Load(), beIO(ds), beIO(ps))
	}
	t.Logf("%d dials; the passive received %d datagrams the dialer counted no send for", dials.Load(), int64(ps.RecvDatagrams)-int64(ds.SentDatagrams))
}

// beWindow bounds the datagrams of one direction in flight end to end:
// accepted by WriteTo and neither read by the peer's application nor
// counted lost (beFlow.losses). 256 × at most 1,000 bytes: half of a raw
// flow's inbox (udpflow.DefaultInbox, 512 datagrams, which also carries
// the other direction's control datagrams), a quarter of the session's
// default Queue and a sixteenth of the sockets' 4-MiB receive buffers, so
// no queue on the path overflows whatever the scheduler does (one P under
// -race included), and a writer that wakes always finds a backlog.
const beWindow = 256

// beStall is how long a blocked generator waits with nothing read and no
// loss counted before it presumes that the datagrams which left the
// sender vanished unseen (a socket buffer drops without a counter) and
// moves on. Every loss rendr counts is subtracted at once (beFlow.losses),
// so the presumption is a last resort that a run on loopback should never
// need; the run logs each one.
const beStall = time.Second

// beFlow is one direction of the run: its side, its seed, the sending and
// the receiving conn and the receiving Runtime.
type beFlow struct {
	name   string
	s      *msSide
	seed   uint64
	tx, rx *rendr.PacketConn
	rxRT   *rendr.Runtime
}

// losses returns the datagrams of f that rendr counted lost — the send
// side's drops, the receiving session's receive-queue and late drops and
// the receiving Runtime's flow-inbox drops (which may include the other
// direction's control datagrams: an overcount that only shrinks the
// window) — and the ones still in the sender's queue. ok is false if a
// conn reports no packet counters.
func (f *beFlow) losses() (lost, queued int64, ok bool) {
	tp, rp := f.tx.Status().Packet, f.rx.Status().Packet
	if tp == nil || rp == nil {
		return 0, 0, false
	}
	txDrops := tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge
	lost = int64(txDrops + rp.DropRecvQueue + rp.DropLate + f.rxRT.Status().Datagram.InboxDrops)
	queued = int64(f.s.accepted.Load()) - int64(tp.Sent+txDrops)
	return lost, queued, true
}

// beGenerate writes beCount test datagrams of f once start closes, as fast
// as the path takes them: WriteTo back to back while fewer than beWindow
// datagrams are in flight (f.s.read is the peer's reader of this
// direction), 50-µs pauses while beWindow are, the counted losses
// refreshed every millisecond in which nothing was read. It counts the
// accepted datagrams in f.s and the stall presumptions in *presumptions.
func beGenerate(f *beFlow, start <-chan struct{}, wg *sync.WaitGroup, presumptions *int) {
	defer wg.Done()
	s := f.s
	buf := make([]byte, 1024)
	<-start
	now := time.Now()
	var lost, presumed int64 // counted lost; presumed lost after a stall (beStall)
	inflight := func(seq int64) int64 { return seq - int64(s.read.Load()) - lost - presumed }
	for seq := range int64(beCount) {
		if inflight(seq) >= beWindow {
			last, since, polled := s.read.Load(), time.Now(), time.Now()
			for inflight(seq) >= beWindow {
				time.Sleep(50 * time.Microsecond)
				if r := s.read.Load(); r != last {
					last, since = r, time.Now()
					continue
				}
				if time.Since(polled) < time.Millisecond {
					continue
				}
				polled = time.Now()
				l, queued, ok := f.losses()
				if !ok {
					s.verr.CompareAndSwap(nil, errors.New("no packet counters"))
					return
				}
				if l != lost {
					lost, since = l, time.Now()
					continue
				}
				if time.Since(since) >= beStall {
					// Only what left the sender: in flight drops to queued.
					presumed = max(presumed, seq-int64(s.read.Load())-lost-queued)
					*presumptions++
					since = time.Now()
				}
			}
		}
		if seq%64 == 0 {
			now = time.Now()
		}
		if _, err := f.tx.WriteTo(rendrtest.PacketPayload(buf, f.seed, uint64(seq), msSize(uint64(seq)), now), nil); err != nil {
			s.verr.CompareAndSwap(nil, err)
			return
		}
		s.accepted.Add(1)
	}
}

// beDrain waits until both directions settled: the sender's counters
// account for every accepted datagram (nothing queued), the reader
// consumed what the session received (read plus DropRecvQueue equals
// Received), and the receive counters did not move for a quiet interval
// (100 ms; 300 ms under -race). It gives up after 10 s and leaves the
// verdict to beJudge.
func beDrain(t *testing.T, dirs []*beFlow) {
	t.Helper()
	quiet, limit := 100*time.Millisecond, 10*time.Second
	if msRace {
		quiet = 300 * time.Millisecond
	}
	drained := func() (bool, uint64) {
		ok, moved := true, uint64(0)
		for _, d := range dirs {
			tp, rp := d.tx.Status().Packet, d.rx.Status().Packet
			if tp == nil || rp == nil {
				return false, 0
			}
			ok = ok && tp.Sent+tp.DropQueue+tp.DropAge+tp.DropNoPath+tp.DropTooLarge == d.s.accepted.Load() &&
				d.s.read.Load()+rp.DropRecvQueue == rp.Received
			moved += rp.Received + rp.Duplicates + rp.DropLate
		}
		return ok, moved
	}
	start := time.Now()
	_, last := drained()
	since := time.Now()
	for time.Since(start) < limit {
		time.Sleep(5 * time.Millisecond)
		ok, now := drained()
		if now != last || !ok {
			last, since = now, time.Now()
			continue
		}
		if time.Since(since) >= quiet {
			t.Logf("drained in %v", time.Since(start).Round(time.Millisecond))
			return
		}
	}
	t.Logf("not drained within %v (the verdict follows)", limit)
}

// beJudge checks one direction: stimulus, load and per-datagram integrity.
func beJudge(t *testing.T, d *beFlow) {
	t.Helper()
	tp, rp := d.tx.Status().Packet, d.rx.Status().Packet
	res := d.s.v.Result()
	t.Logf("%s: accepted %d, sent %d (queue %d, age %d, no path %d, too large %d); received %d, read %d, unique %d (recv-queue %d, late %d, dup %d; the receiving Runtime's inbox drops %d)",
		d.name, d.s.accepted.Load(), tp.Sent, tp.DropQueue, tp.DropAge, tp.DropNoPath, tp.DropTooLarge,
		rp.Received, d.s.read.Load(), res.Unique, rp.DropRecvQueue, rp.DropLate, rp.Duplicates, d.rxRT.Status().Datagram.InboxDrops)
	if err, _ := d.s.verr.Load().(error); err != nil {
		t.Errorf("%s: %v", d.name, err)
	}
	if got := d.s.accepted.Load(); got != beCount {
		t.Errorf("stimulus %s: %d of %d WriteTo calls accepted", d.name, got, beCount)
	}
	if acc := tp.Sent + tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge; acc != beCount {
		t.Errorf("stimulus %s: the sender's counters account for %d of %d datagrams", d.name, acc, beCount)
	}
	if floor := uint64(beMinShare * beCount); res.Unique < floor {
		t.Errorf("load %s: %d of %d datagrams arrived, want ≥ %d", d.name, res.Unique, beCount, floor)
	}
	if res.Corrupt != 0 || res.BadSize != 0 || res.Duplicates != 0 || rp.Duplicates != 0 {
		t.Errorf("integrity %s: corrupt %d, bad size %d, read twice %d, session duplicates %d: want none",
			d.name, res.Corrupt, res.BadSize, res.Duplicates, rp.Duplicates)
	}
	if d.s.read.Load() != res.Unique {
		t.Errorf("integrity %s: %d datagrams read, %d distinct", d.name, d.s.read.Load(), res.Unique)
	}
	if d.s.read.Load()+rp.DropRecvQueue != rp.Received {
		t.Errorf("integrity %s: read %d + receive-queue drops %d ≠ Received %d", d.name, d.s.read.Load(), rp.DropRecvQueue, rp.Received)
	}
	if rp.Received > tp.Sent {
		t.Errorf("integrity %s: Received %d > the sender's Sent %d", d.name, rp.Received, tp.Sent)
	}
}

// beIO formats the I/O counters of a DatagramStatus.
func beIO(s rendr.DatagramStatus) string {
	ratio := func(n, calls uint64) string {
		if calls == 0 {
			return "-"
		}
		return fmt.Sprintf("%.2f", float64(n)/float64(calls))
	}
	return fmt.Sprintf("send %d calls / %d datagrams (%s), recv %d calls / %d datagrams (%s), fallbacks %d, charge refused %d",
		s.SendCalls, s.SentDatagrams, ratio(s.SentDatagrams, s.SendCalls), s.RecvCalls, s.RecvDatagrams,
		ratio(s.RecvDatagrams, s.RecvCalls), s.BatchFallbacks, s.ChargeRefused)
}
