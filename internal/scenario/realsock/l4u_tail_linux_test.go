//go:build linux

package realsock

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestL4UQuietTailDiag is the quiet-path tail diagnostic of the M6
// delegate decisions after wave D ("G10 criterion 7, the quiet-path tail
// (C1)"). It runs only with RENDR_TAIL_DIAG=1, on a quiet Linux host (a
// pool worker of rendr-regress, never the ordinary lanes), for
// RENDR_TAIL_SECS seconds (default 60) after a 2-s warm-up;
// RENDR_TAIL_PACE=sleep paces the bursts' groups with timers only (the
// default spins between a burst's groups, so that the burst keeps about
// 71 kpps where Go's timers round sub-millisecond sleeps up to 1 ms).
//
// Topology: one process; the dialer and the passive Runtime joined by one
// carrier/udp carrier on loopback (MaxDatagram 1,472 on both ends: the
// L4U-1472 configuration of a 1,500-byte path), one l4.PortForward on the
// dialer's Peer serving two ingress sockets and one l4.Server{UDP} with
// 4-MiB egress buffers (F86's UDPBuffer). Flow 1 carries ML-100's down
// shape from the passive's target side to the client: a frame every
// 16.667 ms of 203 datagrams of 1,408 bytes, written in groups of 46 (46,
// 46, 46, 46, 19) 46/71,000 s apart, about 71 kpps inside the burst; its
// client sends a 32-byte keepalive every 100 ms (so the flow is a stream).
// Flow 2 echoes a 48-byte datagram every 4 ms through the same Peer (one
// shared datagram trunk). The baseline is a direct loopback echo pair
// with the same schedule, 2 ms out of phase, running at the same time, so
// both see the same host.
//
// Verdict (tailJudge): FAIL when more than 0.05 % of the echoes through
// rendr were lost or came back more than 4 ms above the baseline's median
// round trip, or when rendr's p99 exceeds the baseline's by more than
// 0.5 ms. INVALID (a fatal "INVALID:" message) when the load was not
// reached: frames missed or started more than 2 ms late beyond 1 %, or
// fewer than 90 % of the video datagrams arrived. Everything else is
// logged for attribution: each echo's two legs (both clocks are the
// process's monotonic clock), the tail's phase in the frame cycle and in
// the wall-clock second (C1's once-per-second window), the worst echoes,
// rendr's counters (carrier read errors: the read back-off of
// internal/carrier and internal/udpflow takes 5 ms from the first
// transient error), the kernel's UDP counters and the Go scheduler's
// latencies and GC pauses over the window.
func TestL4UQuietTailDiag(t *testing.T) {
	cfg, err := tailDiagConfig(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.on {
		t.Skip("diagnostic (M6 wave D, C1): runs only with RENDR_TAIL_DIAG=1 on a quiet Linux host; RENDR_TAIL_SECS sets the span (default 60)")
	}
	secs, spin := cfg.secs, cfg.spin
	t.Cleanup(rendrtest.AssertNoLeak(t))

	const warm = 2 * time.Second
	span := time.Duration(secs) * time.Second
	d := &tailDiag{t: t, base: time.Now(), spin: spin, warm: warm}
	d.wall0 = d.base.UnixNano()
	echoes := int((warm+span)/tailEchoEvery) + 1000

	n := newL4uNet(t, l4uOpts{maxDatagram: 1472, srv: &l4.Server{UDP: true, UDPBuffer: 4 << 20}})
	t.Cleanup(d.stopAll) // a failed premise stops the diagnostic's goroutines first
	vt := d.newVideoTarget()
	et := d.newEchoTarget(echoes)
	bt := d.newEchoTarget(echoes)
	ingV, ingE := l4uListen(t, "udp4", "127.0.0.1:0"), l4uListen(t, "udp4", "127.0.0.1:0")
	n.serveUDP(ingV, vt.c.LocalAddr().String())
	n.serveUDP(ingE, et.c.LocalAddr().String())
	vc := d.newVideoClient(ingV.LocalAddr())
	ec := d.newEchoClient(ingE.LocalAddr(), echoes, 0)
	bc := d.newEchoClient(bt.c.LocalAddr(), echoes, tailEchoEvery/2)

	// Both flows open: the video target learns its egress socket from the
	// first keepalive, the echo flow returns its first echo.
	msUntil(t, l4uWait, "the video flow open (a keepalive at the target)", func() bool { return vt.peer.Load() != nil })
	msUntil(t, l4uWait, "the echo flow open (an echo back)", func() bool { return ec.got.Load() > 0 && bc.got.Load() > 0 })
	if v := n.d.Status().Mux; v.Carriers != 1 || v.Views != 2 {
		t.Fatalf("premise: the dialer's mux holds %d carriers and %d views, want both flows on one shared datagram trunk", v.Carriers, v.Views)
	}
	start := time.Now()
	d.opened = start.Sub(d.base)
	d.from, d.to = start.Add(warm).Sub(d.base), start.Add(warm+span).Sub(d.base)
	vt.startBursts(start)
	time.Sleep(warm)
	snapBefore := d.snapshot(n)
	time.Sleep(time.Until(start.Add(warm + span)))
	snapAfter := d.snapshot(n)
	time.Sleep(200 * time.Millisecond) // the last echoes and frames come back
	d.stopAll()

	d.report(n, vt, vc, ec, et, bc, bt, snapBefore, snapAfter)
	n.live(2)
	n.close()
}

const (
	tailEchoEvery  = 4 * time.Millisecond
	tailEchoSize   = 48
	tailKeepEvery  = 100 * time.Millisecond
	tailKeepSize   = 32
	tailShard      = 1408
	tailFrameDgram = 203
	tailGroup      = 46
	tailFrameEvery = time.Second / 60
)

// tailGroupGap spaces a burst's groups: 46 datagrams at 71 kpps.
var tailGroupGap = tailGroup * time.Second / 71000

// tailDiag is the diagnostic's shared state: the process clock's origin
// and the measuring window, as offsets from base.
type tailDiag struct {
	t        *testing.T
	base     time.Time
	wall0    int64 // base's wall clock (ns since the epoch)
	from, to time.Duration
	opened   time.Duration // both flows open: about the shared carrier's start, the origin of its PING cadence
	warm     time.Duration
	spin     bool
	stop     chan struct{}
	once     sync.Once
	stopped  sync.Once
	wg       sync.WaitGroup
	closers  []func()
}

func (d *tailDiag) now() time.Duration { return time.Since(d.base) }

// goStop runs f on a goroutine that stopAll joins; f must return when
// d.stopCh() closes or its socket closes.
func (d *tailDiag) goStop(f func()) {
	d.wg.Add(1)
	go func() { defer d.wg.Done(); f() }()
}

func (d *tailDiag) stopCh() chan struct{} {
	d.once.Do(func() { d.stop = make(chan struct{}) })
	return d.stop
}

// stopAll stops the senders, closes the diagnostic's sockets and joins
// every goroutine (before the fixture's close; once).
func (d *tailDiag) stopAll() {
	d.stopped.Do(func() {
		close(d.stopCh())
		for _, c := range d.closers {
			c()
		}
		d.wg.Wait()
	})
}

// sock opens a loopback UDP socket (connected to to when it is set) with
// the receive and send buffers asked for (SO_RCVBUFFORCE where the process
// may, else capped by the kernel's maximum) and returns it with the
// receive buffer the kernel reports.
func (d *tailDiag) sock(to net.Addr, buf int) (*net.UDPConn, int) {
	d.t.Helper()
	var c *net.UDPConn
	var err error
	if to != nil {
		c, err = net.DialUDP("udp4", nil, to.(*net.UDPAddr))
	} else {
		c, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	if err != nil {
		d.t.Fatalf("premise: a loopback UDP socket: %v", err)
	}
	got := 0
	if rc, err := c.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, buf) != nil {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, buf)
			}
			if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, buf) != nil {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, buf)
			}
			got, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		})
	}
	d.closers = append(d.closers, func() { c.Close() })
	return c, got
}

// The video target: it reads the client's keepalives (the first one names
// the flow's egress socket) and sends the frames to that socket.
type tailVideoTarget struct {
	d      *tailDiag
	c      *net.UDPConn
	rcvbuf int
	peer   atomic.Pointer[netip.AddrPort]
	keeps  atomic.Int64
	// Written by the burst goroutine; read after stopAll.
	frames, sent, errs int
	firstErr           error
	late               []time.Duration // each frame's start after its due instant
	burst              []time.Duration // each frame's first-to-last write
	starts             []time.Duration // each frame's actual start (offset from base)
}

func (d *tailDiag) newVideoTarget() *tailVideoTarget {
	c, rb := d.sock(nil, 4<<20)
	vt := &tailVideoTarget{d: d, c: c, rcvbuf: rb}
	d.goStop(func() {
		b := make([]byte, 2048)
		for {
			_, src, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if vt.peer.Load() == nil {
				vt.peer.Store(&src)
			}
			vt.keeps.Add(1)
		}
	})
	return vt
}

// startBursts sends a frame every tailFrameEvery from start until stopAll.
func (vt *tailVideoTarget) startBursts(start time.Time) {
	d := vt.d
	dst := *vt.peer.Load()
	stop := d.stopCh()
	d.goStop(func() {
		b := make([]byte, tailShard)
		var seq uint64
		for f := 0; ; f++ {
			due := start.Add(time.Duration(f) * tailFrameEvery)
			if w := time.Until(due); w > 0 {
				select {
				case <-time.After(w):
				case <-stop:
					return
				}
			}
			select {
			case <-stop:
				return
			default:
			}
			t0 := time.Now()
			vt.late = append(vt.late, t0.Sub(due))
			vt.starts = append(vt.starts, t0.Sub(d.base))
			for k := 0; k < tailFrameDgram; k++ {
				if k > 0 && k%tailGroup == 0 {
					at := t0.Add(time.Duration(k/tailGroup) * tailGroupGap)
					if d.spin {
						for time.Now().Before(at) {
							runtime.Gosched()
						}
					} else if w := time.Until(at); w > 0 {
						time.Sleep(w)
					}
				}
				binary.BigEndian.PutUint64(b, seq)
				binary.BigEndian.PutUint32(b[8:], uint32(f))
				binary.BigEndian.PutUint64(b[12:], uint64(d.now()))
				if _, err := vt.c.WriteToUDPAddrPort(b, dst); err != nil {
					if errors.Is(err, net.ErrClosed) {
						return // stopAll closed the socket during the frame
					}
					if vt.errs++; vt.firstErr == nil {
						vt.firstErr = err
					}
				} else {
					vt.sent++
				}
				seq++
			}
			vt.burst = append(vt.burst, time.Since(t0))
			vt.frames++
		}
	})
}

// The video client: a keepalive every 100 ms; every datagram's one-way
// delay and the sequence gaps.
type tailVideoClient struct {
	c                *net.UDPConn
	rcvbuf           int
	got, bad, gaps   int
	next             uint64
	delays           []time.Duration // in the window
	inWindow, sentIn int
}

func (d *tailDiag) newVideoClient(to net.Addr) *tailVideoClient {
	c, rb := d.sock(to, 8<<20)
	vc := &tailVideoClient{c: c, rcvbuf: rb}
	stop := d.stopCh()
	d.goStop(func() {
		b := make([]byte, tailKeepSize)
		tk := time.NewTicker(tailKeepEvery)
		defer tk.Stop()
		for {
			c.Write(b)
			select {
			case <-tk.C:
			case <-stop:
				return
			}
		}
	})
	d.goStop(func() {
		b := make([]byte, 64<<10)
		for {
			k, err := c.Read(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			at := d.now()
			if k != tailShard {
				vc.bad++
				continue
			}
			seq := binary.BigEndian.Uint64(b)
			sentAt := time.Duration(binary.BigEndian.Uint64(b[12:]))
			if seq != vc.next {
				vc.gaps++
			}
			vc.next = seq + 1
			vc.got++
			if sentAt >= d.from && sentAt < d.to {
				vc.inWindow++
				vc.delays = append(vc.delays, at-sentAt)
			}
		}
	})
	return vc
}

// The echo target: it stamps each echo's arrival (by seq) and returns it.
type tailEchoTarget struct {
	c      *net.UDPConn
	rcvbuf int
	at     []atomic.Int64 // arrival offset + 1 by seq (0: none)
}

func (d *tailDiag) newEchoTarget(n int) *tailEchoTarget {
	c, rb := d.sock(nil, 1<<20)
	et := &tailEchoTarget{c: c, rcvbuf: rb, at: make([]atomic.Int64, n)}
	d.goStop(func() {
		b := make([]byte, 2048)
		for {
			k, src, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if k == tailEchoSize {
				if seq := binary.BigEndian.Uint64(b); seq < uint64(len(et.at)) {
					et.at[seq].CompareAndSwap(0, int64(d.now())+1)
				}
			}
			c.WriteToUDPAddrPort(b[:k], src)
		}
	})
	return et
}

// The echo client: datagram seq every tailEchoEvery from its phase on,
// each stamped with seq and its send instant; the receive instant by seq.
type tailEchoClient struct {
	c          *net.UDPConn
	sent, recv []atomic.Int64 // offset + 1 by seq (0: none)
	got        atomic.Int64
	dups, bad  atomic.Int64
}

func (d *tailDiag) newEchoClient(to net.Addr, n int, phase time.Duration) *tailEchoClient {
	c, _ := d.sock(to, 1<<20)
	ec := &tailEchoClient{c: c, sent: make([]atomic.Int64, n), recv: make([]atomic.Int64, n)}
	stop := d.stopCh()
	d.goStop(func() {
		b := make([]byte, tailEchoSize)
		t0 := time.Now().Add(phase)
		for seq := 0; seq < n; seq++ {
			if w := time.Until(t0.Add(time.Duration(seq) * tailEchoEvery)); w > 0 {
				select {
				case <-time.After(w):
				case <-stop:
					return
				}
			}
			select {
			case <-stop:
				return
			default:
			}
			binary.BigEndian.PutUint64(b, uint64(seq))
			at := d.now()
			binary.BigEndian.PutUint64(b[8:], uint64(at))
			ec.sent[seq].Store(int64(at) + 1)
			c.Write(b)
		}
	})
	d.goStop(func() {
		b := make([]byte, 2048)
		for {
			k, err := c.Read(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			at := d.now()
			seq := binary.BigEndian.Uint64(b)
			if k != tailEchoSize || seq >= uint64(len(ec.recv)) || time.Duration(binary.BigEndian.Uint64(b[8:]))+1 != time.Duration(ec.sent[seq].Load()) {
				ec.bad.Add(1)
				continue
			}
			if !ec.recv[seq].CompareAndSwap(0, int64(at)+1) {
				ec.dups.Add(1)
				continue
			}
			ec.got.Add(1)
		}
	})
	return ec
}

// tailEcho is one echo sent in the window: its round trip and legs
// (zero rtt with lost set: it never came back).
type tailEcho struct {
	seq           int
	sent          time.Duration // offset from base
	rtt, up, down time.Duration // up: to the target's arrival; down: back to the client
	lost          bool
}

// echoes returns the echoes the client sent in the window.
func (d *tailDiag) echoes(ec *tailEchoClient, et *tailEchoTarget) []tailEcho {
	var out []tailEcho
	for seq := range ec.sent {
		s := time.Duration(ec.sent[seq].Load())
		if s == 0 || s-1 < d.from || s-1 >= d.to {
			continue
		}
		e := tailEcho{seq: seq, sent: s - 1}
		r, a := time.Duration(ec.recv[seq].Load()), time.Duration(et.at[seq].Load())
		if r == 0 {
			e.lost = true
		} else {
			e.rtt = r - s
			if a != 0 {
				e.up, e.down = a-s, r-a
			}
		}
		out = append(out, e)
	}
	return out
}

// tailSnap is the counters before and after the window.
type tailSnap struct {
	d, p     rendr.DatagramStatus
	pf       l4.UDPForwardStatus
	srv      l4.UDPServerStatus
	snmp     map[string]int64
	sched    *metrics.Float64Histogram
	gcPause  *metrics.Float64Histogram
	gcCycles uint64
}

func (d *tailDiag) snapshot(n *l4uNet) tailSnap {
	s := tailSnap{d: n.d.Status().Datagram, p: n.p.Status().Datagram, pf: n.pf.Status().UDP, srv: n.srv.Status().UDP, snmp: tailSNMP()}
	ms := []metrics.Sample{{Name: "/sched/latencies:seconds"}, {Name: "/sched/pauses/total/gc:seconds"}, {Name: "/gc/cycles/total:gc-cycles"}}
	metrics.Read(ms)
	if ms[0].Value.Kind() == metrics.KindFloat64Histogram {
		s.sched = ms[0].Value.Float64Histogram()
	}
	if ms[1].Value.Kind() == metrics.KindFloat64Histogram {
		s.gcPause = ms[1].Value.Float64Histogram()
	}
	if ms[2].Value.Kind() == metrics.KindUint64 {
		s.gcCycles = ms[2].Value.Uint64()
	}
	return s
}

// tailSNMP reads the kernel's Udp counters (/proc/net/snmp).
func tailSNMP() map[string]int64 {
	f, err := os.Open("/proc/net/snmp")
	if err != nil {
		return nil
	}
	defer f.Close()
	var names []string
	out := map[string]int64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) == 0 || fs[0] != "Udp:" {
			continue
		}
		if names == nil {
			names = fs[1:]
			continue
		}
		for i, v := range fs[1:] {
			if i < len(names) {
				out[names[i]], _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	return out
}

// histDiff returns the quantiles q of the samples a histogram gained
// between two snapshots (the bucket's upper bound) and the highest bucket
// that gained any.
func histDiff(a, b *metrics.Float64Histogram, qs ...float64) (out []time.Duration, top time.Duration, total uint64) {
	if a == nil || b == nil || len(a.Counts) != len(b.Counts) {
		return nil, 0, 0
	}
	diff := make([]uint64, len(b.Counts))
	for i := range diff {
		diff[i] = b.Counts[i] - a.Counts[i]
		total += diff[i]
		if diff[i] > 0 {
			top = histBound(b.Buckets[i+1])
		}
	}
	for _, q := range qs {
		want, acc := uint64(q*float64(total)+0.999999), uint64(0)
		v := time.Duration(0)
		for i, c := range diff {
			acc += c
			if acc >= want && c > 0 {
				v = histBound(b.Buckets[i+1])
				break
			}
		}
		out = append(out, v)
	}
	return out, top, total
}

func histBound(sec float64) time.Duration {
	if sec > 3600 {
		return time.Hour
	}
	return time.Duration(sec * float64(time.Second))
}

// q is the nearest-rank quantile of s (not sorted; empty: 0).
func q(s []time.Duration, p float64) time.Duration {
	if len(s) == 0 {
		return 0
	}
	c := slices.Clone(s)
	slices.Sort(c)
	return tailQuantile(c, p)
}

// report logs the measurement and judges it.
func (d *tailDiag) report(n *l4uNet, vt *tailVideoTarget, vc *tailVideoClient, ec *tailEchoClient, et *tailEchoTarget, bc *tailEchoClient, bt *tailEchoTarget, s0, s1 tailSnap) {
	t := d.t
	t.Logf("host: GOMAXPROCS %d, %d CPUs, %v; window %v after a %v warm-up; pacing between a burst's groups: %s",
		runtime.GOMAXPROCS(0), runtime.NumCPU(), runtime.Version(), d.to-d.from, d.warm, map[bool]string{true: "spin", false: "timers"}[d.spin])
	t.Logf("socket receive buffers (as the kernel reports them): video target %d, video client %d, echo targets %d and %d", vt.rcvbuf, vc.rcvbuf, et.rcvbuf, bt.rcvbuf)

	// The load.
	lateOver := 0
	for _, l := range vt.late {
		if l > 2*time.Millisecond {
			lateOver++
		}
	}
	due := int((d.to - d.from + 2*time.Second) / tailFrameEvery)
	var rate float64
	if b := q(vt.burst, 0.5); b > 0 {
		rate = float64(tailFrameDgram-1) / b.Seconds()
	}
	t.Logf("video: %d frames (about %d due), %d datagrams written (%d write errors, the first %v); frame start late p50 %v, p99 %v, max %v (%d over 2 ms); burst first-to-last write p50 %v (%.0f datagrams/s inside a burst), max %v",
		vt.frames, due, vt.sent, vt.errs, vt.firstErr, q(vt.late, 0.5), q(vt.late, 0.99), q(vt.late, 1), lateOver, q(vt.burst, 0.5), rate, q(vt.burst, 1))
	t.Logf("video client: %d datagrams received (%d of the window's), %d sequence gaps, %d malformed; one-way delay in the window p50 %v, p99 %v, p99.9 %v, max %v; %d keepalives at the target",
		vc.got, vc.inWindow, vc.gaps, vc.bad, q(vc.delays, 0.5), q(vc.delays, 0.99), q(vc.delays, 0.999), q(vc.delays, 1), vt.keeps.Load())

	// The echoes.
	re, be := d.echoes(ec, et), d.echoes(bc, bt)
	split := func(es []tailEcho) (rtt, up, down []time.Duration, lost int) {
		for _, e := range es {
			if e.lost {
				lost++
				continue
			}
			rtt = append(rtt, e.rtt)
			if e.up != 0 {
				up, down = append(up, e.up), append(down, e.down)
			}
		}
		return
	}
	rr, ru, rd, rl := split(re)
	br, bu, bd, bl := split(be)
	v := tailJudge(rr, rl, br)
	for _, x := range []struct {
		name          string
		rtt, up, down []time.Duration
		lost, sent    int
		dups, bad     int64
	}{{"through rendr", rr, ru, rd, rl, len(re), ec.dups.Load(), ec.bad.Load()}, {"direct baseline", br, bu, bd, bl, len(be), bc.dups.Load(), bc.bad.Load()}} {
		t.Logf("echo %s: %d sent in the window, %d lost, %d duplicates, %d malformed; round trip p50 %v, p99 %v, p99.9 %v, max %v; up p50 %v, p99 %v, max %v; down p50 %v, p99 %v, max %v",
			x.name, x.sent, x.lost, x.dups, x.bad, q(x.rtt, 0.5), q(x.rtt, 0.99), q(x.rtt, 0.999), q(x.rtt, 1),
			q(x.up, 0.5), q(x.up, 0.99), q(x.up, 1), q(x.down, 0.5), q(x.down, 0.99), q(x.down, 1))
	}
	baseOver := 0
	for _, r := range br {
		if r > v.baseMedian+tailMargin {
			baseOver++
		}
	}
	t.Logf("tail: through rendr %d of %d (%.4f %%, %d lost) more than %v above the baseline's median %v; the baseline itself %d of %d (%.4f %%); added p50 %v, p99 %v, p99.9 %v",
		v.over, v.sent, 100*v.share, v.lost, tailMargin, v.baseMedian, baseOver, len(be), 100*float64(baseOver+bl)/float64(max(len(be), 1)), v.addP50, v.addP99, v.addP999)
	d.attribute("through rendr", re, v.baseMedian, q(bu, 0.5), q(bd, 0.5), vt.starts)
	d.attribute("direct baseline", be, v.baseMedian, q(bu, 0.5), q(bd, 0.5), vt.starts)

	// rendr's counters and the host's over the window.
	t.Logf("rendr dialer datagram I/O over the window: %s", tailDgDiff(s0.d, s1.d))
	t.Logf("rendr passive datagram I/O over the window: %s", tailDgDiff(s0.p, s1.p))
	pf, srv := s1.pf, s1.srv
	pf.LastErr = nil
	t.Logf("ingress: %+v", pf)
	t.Logf("Server: %+v", srv)
	for _, fi := range n.pf.Flows() {
		if pc := fi.Session.Packet; pc != nil {
			srtt := time.Duration(0)
			if c, ok := activeCarrier(fi.Session); ok {
				srtt = c.SRTT
			}
			t.Logf("flow %v → %s: stream %v, session %v packet counters %+v, active carrier SRTT %v", fi.Client, fi.Target, fi.Stream, fi.Session.ID, *pc, srtt)
		}
	}
	if s0.snmp != nil && s1.snmp != nil {
		var parts []string
		for _, k := range []string{"InDatagrams", "NoPorts", "InErrors", "OutDatagrams", "RcvbufErrors", "SndbufErrors", "InCsumErrors", "MemErrors"} {
			if _, ok := s1.snmp[k]; ok {
				parts = append(parts, fmt.Sprintf("%s +%d", k, s1.snmp[k]-s0.snmp[k]))
			}
		}
		t.Logf("kernel Udp counters over the window (the whole host): %s", strings.Join(parts, ", "))
	}
	if qs, top, total := histDiff(s0.sched, s1.sched, 0.99, 0.999); qs != nil {
		t.Logf("Go scheduler latency over the window (runnable to running, %d samples): p99 ≤ %v, p99.9 ≤ %v, highest bucket ≤ %v", total, qs[0], qs[1], top)
	}
	if _, top, total := histDiff(s0.gcPause, s1.gcPause); total > 0 || s1.gcCycles > s0.gcCycles {
		t.Logf("GC over the window: %d cycles, %d stop-the-world pauses, the longest ≤ %v", s1.gcCycles-s0.gcCycles, total, top)
	}

	// The load proof, then the verdict.
	if vt.frames < due*99/100 || lateOver > vt.frames/100 {
		t.Fatalf("INVALID: the video generator did not keep its schedule: %d of about %d frames, %d started more than 2 ms late", vt.frames, due, lateOver)
	}
	if vc.got < vt.sent*9/10 {
		t.Fatalf("INVALID: the video flow delivered %d of %d datagrams (the load was not carried; see the counters above)", vc.got, vt.sent)
	}
	if len(v.fails) != 0 {
		t.Errorf("FAIL: %s", strings.Join(v.fails, "; "))
	} else {
		t.Logf("PASS: %.4f %% of the echoes through rendr in the tail (bound %.2f %%), added p99 %v (bound %v)", 100*v.share, 100*tailShareMax, v.addP99, tailAddedP99Max)
	}
}

// attribute logs where the echoes beyond the baseline's median + margin
// spent their excess (the leg whose time exceeds its baseline median by
// more than half the margin), their phase in the frame cycle (from the
// latest frame start before their send) and in the wall-clock second, and
// the worst ten.
func (d *tailDiag) attribute(name string, es []tailEcho, baseMedian, upMed, downMed time.Duration, starts []time.Duration) {
	var tail []tailEcho
	for _, e := range es {
		if e.lost || e.rtt > baseMedian+tailMargin {
			tail = append(tail, e)
		}
	}
	var legUp, legDown, legBoth, legNone, inBurst int
	var frame [8]int
	var wall, carrier [10]int
	for _, e := range tail {
		if !e.lost && e.up != 0 {
			u, w := e.up > upMed+tailMargin/2, e.down > downMed+tailMargin/2
			switch {
			case u && w:
				legBoth++
			case u:
				legUp++
			case w:
				legDown++
			default:
				legNone++
			}
		}
		if i, ok := slices.BinarySearch(starts, e.sent); ok || i > 0 {
			if !ok {
				i--
			}
			ph := e.sent - starts[i]
			if ph < 3*time.Millisecond {
				inBurst++
			}
			frame[min(int(ph*8/tailFrameEvery), 7)]++
		}
		wall[int((d.wall0+int64(e.sent))%int64(time.Second))/int(100*time.Millisecond)]++
		if e.sent >= d.opened {
			carrier[int((e.sent-d.opened)%time.Second/(100*time.Millisecond))]++
		}
	}
	d.t.Logf("%s tail: %d echoes (%d lost); excess on the way up %d, down %d, both %d, neither alone %d; sent within 3 ms of a frame start %d; by eighth of the frame cycle %v; by 100 ms of the wall-clock second %v; by 100 ms of the second since the flows opened (the carrier's 1-s PING cadence) %v",
		name, len(tail), len(tail)-legUp-legDown-legBoth-legNone, legUp, legDown, legBoth, legNone, inBurst, frame, wall, carrier)
	slices.SortFunc(tail, func(a, b tailEcho) int {
		if a.lost != b.lost {
			if a.lost {
				return -1
			}
			return 1
		}
		return cmp.Compare(b.rtt, a.rtt)
	})
	for i, e := range tail[:min(len(tail), 10)] {
		d.t.Logf("%s worst %d: seq %d sent at +%v (wall-second phase %v): lost %v, round trip %v, up %v, down %v",
			name, i+1, e.seq, e.sent-d.from, time.Duration((d.wall0+int64(e.sent))%int64(time.Second)), e.lost, e.rtt, e.up, e.down)
	}
}

// tailDgDiff formats the moves of a Runtime's datagram counters.
func tailDgDiff(a, b rendr.DatagramStatus) string {
	return fmt.Sprintf("ReadErrors +%d, Dropped +%d (Truncated +%d), InboxDrops +%d, sends %d datagrams in %d calls, receives %d datagrams in %d calls, ChargeRefused +%d",
		b.ReadErrors-a.ReadErrors, b.Dropped-a.Dropped, b.Truncated-a.Truncated, b.InboxDrops-a.InboxDrops,
		b.SentDatagrams-a.SentDatagrams, b.SendCalls-a.SendCalls, b.RecvDatagrams-a.RecvDatagrams, b.RecvCalls-a.RecvCalls, b.ChargeRefused-a.ChargeRefused)
}

// activeCarrier returns the active carrier of a selector session.
func activeCarrier(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}
