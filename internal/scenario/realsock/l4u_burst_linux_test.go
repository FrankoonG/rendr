//go:build linux && rendrtaildiag

package realsock

import (
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestL4UBurstDiag is rc4's burst diagnostic (M6 delegate decisions during
// wave E, "rendr's p99 under ML-100's bursts"): the one-way delay rendr adds
// to ML-100's video bursts and to the control flow that shares their
// trunk, against a direct path that carries the same schedule at the same
// time. It is built and switched like TestL4UQuietTailDiag (the build tag
// rendrtaildiag, RENDR_TAIL_DIAG=1, RENDR_TAIL_SECS, RENDR_TAIL_PACE) and
// runs on a quiet Linux pool worker; RENDR_TAIL_SHAPE picks the frames
// (ml100: ML-100's sizes and IDRs from a fixed seed, the default; fixed:
// the tail diagnostic's 203 datagrams per frame), and RENDR_TAIL_PROF=<dir>
// writes a CPU profile over the window, block and mutex profiles and a
// runtime trace of RENDR_TAIL_TRACE seconds (default 1) from the window's
// fifth second into dir (relative to the working directory: the regress
// sweep's artifacts/ comes back to the host). A profiled run is not
// judged (the profilers cost what they measure).
//
// Topology: the tail diagnostic's (one process; the dialer and the passive
// Runtime joined by one carrier/udp carrier on loopback, MaxDatagram 1,472,
// one PortForward, one l4.Server{UDP} with 4-MiB egress buffers). Through
// rendr: a video flow (the target sends each frame's 1,408-byte datagrams
// as one burst in groups of 46, 46/71,000 s apart, each group one sendmmsg
// call; the client sends a 32-byte keepalive every 100 ms) and a control
// flow (the client sends a 48-byte input every 4 ms, the target answers
// each with a 40-byte ack and sends a 256-byte feedback every 100 ms), both
// on the dialer's one shared datagram trunk, as G10's video and control.
// Direct: the same two flows between loopback sockets, the same frames and
// schedule half a frame interval later, so that the two paths' bursts do
// not overlap (an IDR's may, briefly) and both see the same host.
//
// Verdict (burstJudge, per class: video down, control down, control up):
// FAIL when rendr's p99 exceeds the direct path's by more than 0.5 ms or
// rendr lost more; INVALID when the load was not the designed one
// (burstLoadProof) or the direct path itself was not quiet. Logged for
// attribution: each class's quantiles on both paths, the video delays by
// position in the burst and for IDRs, rendr's datagram I/O counters, the
// process's CPU time, the kernel's UDP counters and the Go scheduler's
// latencies and GC pauses over the window.
func TestL4UBurstDiag(t *testing.T) {
	cfg, err := tailDiagConfig(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := burstDiagConfig(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.on {
		t.Skip("diagnostic (M6 wave E, rc4): runs only with RENDR_TAIL_DIAG=1 on a quiet Linux host; RENDR_TAIL_SECS sets the span (default 60)")
	}
	t.Cleanup(rendrtest.AssertNoLeak(t))

	const warm = 2 * time.Second
	span := time.Duration(cfg.secs) * time.Second
	d := &tailDiag{t: t, base: time.Now(), spin: cfg.spin, warm: warm}
	d.wall0 = d.base.UnixNano()
	plan, _ := burstPlan(bc.shape, int((2*l4uWait+warm+span+time.Second)/tailFrameEvery)+1)

	n := newL4uNet(t, l4uOpts{maxDatagram: 1472, srv: &l4.Server{UDP: true, UDPBuffer: 4 << 20}})
	t.Cleanup(d.stopAll)
	paths := [2]*burstPath{d.newBurstPath("rendr", 0), d.newBurstPath("direct", tailFrameEvery/2)}
	r, dp := paths[0], paths[1]
	ingV, ingC := l4uListen(t, "udp4", "127.0.0.1:0"), l4uListen(t, "udp4", "127.0.0.1:0")
	n.serveUDP(ingV, r.vt.c.LocalAddr().String())
	n.serveUDP(ingC, r.ct.c.LocalAddr().String())
	r.clients(ingV.LocalAddr(), ingC.LocalAddr())
	dp.clients(dp.vt.c.LocalAddr(), dp.ct.c.LocalAddr())

	for _, p := range paths {
		msUntil(t, l4uWait, p.name+": the video flow open (a keepalive at the target)", func() bool { return p.vt.peer.Load() != nil })
		msUntil(t, l4uWait, p.name+": the control flow open (an ack back)", func() bool { return p.cc.down.Load() > 0 })
	}
	if v := n.d.Status().Mux; v.Carriers != 1 || v.Views != 2 {
		t.Fatalf("premise: the dialer's mux holds %d carriers and %d views, want both flows on one shared datagram trunk", v.Carriers, v.Views)
	}
	start := time.Now()
	d.opened = start.Sub(d.base)
	d.from.Store(int64(start.Add(warm).Sub(d.base)))
	d.to.Store(int64(start.Add(warm + span).Sub(d.base)))
	for _, p := range paths {
		p.startVideo(start, plan)
	}
	time.Sleep(warm)
	prof := d.startProfiles(bc)
	snapBefore, cpuBefore := d.snapshot(n), burstCPU()
	time.Sleep(time.Until(start.Add(warm + span)))
	snapAfter, cpuAfter := d.snapshot(n), burstCPU()
	prof.stop()
	time.Sleep(200 * time.Millisecond) // the last frames and acks come back
	d.stopAll()

	d.burstReport(n, bc, plan, paths, snapBefore, snapAfter, cpuAfter-cpuBefore, prof.on)
	n.live(2)
	n.close()
}

// burstPath is one path's flows: video target and client, control target
// and client; phase delays its whole schedule.
type burstPath struct {
	d     *tailDiag
	name  string
	phase time.Duration
	vt    *tailVideoTarget // its burst fields are written by startVideo's goroutine
	ct    *burstCtlTarget
	vc    *burstRecv // video, at the client
	cc    *burstCtlClient
	sizes []int // each written frame's datagrams (burstLoadProof)
	inWin int   // video datagrams stamped in the window and written
}

func (d *tailDiag) newBurstPath(name string, phase time.Duration) *burstPath {
	p := &burstPath{d: d, name: name, phase: phase, vt: d.newVideoTarget()}
	p.ct = d.newBurstCtlTarget()
	return p
}

// clients opens the path's video client (toward vaddr) and control client
// (toward caddr).
func (p *burstPath) clients(vaddr, caddr net.Addr) {
	p.vc = p.d.newBurstVideoClient(vaddr)
	p.cc = p.d.newBurstCtlClient(caddr, p.phase)
}

// burstStamp writes the diagnostic's header into b.
func burstStamp(b []byte, seq uint64, at time.Duration, frame uint32, k, n int) {
	binary.BigEndian.PutUint64(b, seq)
	binary.BigEndian.PutUint64(b[8:], uint64(at))
	binary.BigEndian.PutUint32(b[16:], frame)
	binary.BigEndian.PutUint16(b[20:], uint16(k))
	binary.BigEndian.PutUint16(b[22:], uint16(n))
}

// startVideo sends frame f of plan at start + phase + f/60 s as one burst
// of groups of tailGroup datagrams, tailGroupGap apart (spinning unless
// RENDR_TAIL_PACE=sleep), each group one batched write.
func (p *burstPath) startVideo(start time.Time, plan []burstFrame) {
	d, vt := p.d, p.vt
	dst := *vt.peer.Load()
	stop := d.stopCh()
	uc, err := udpsocket.New(vt.c, tailGroup, nil)
	if err != nil {
		d.t.Fatalf("premise: the video target's batch writer: %v", err)
	}
	vt.batched = uc.Mode() == udpsocket.ModeBatch
	bt := udpsocket.NewBatch(tailGroup)
	ms := make([]udpsocket.Msg, tailGroup)
	for i := range ms {
		ms[i] = udpsocket.Msg{Buf: make([]byte, tailShard), Addr: dst}
	}
	start = start.Add(p.phase)
	d.goStop(func() {
		var seq uint64
		for f := 0; f < len(plan); f++ {
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
			fn := plan[f].n
			for g := 0; g*tailGroup < fn; g++ {
				if g > 0 {
					at := t0.Add(time.Duration(g) * tailGroupGap)
					if d.spin {
						for time.Now().Before(at) {
							runtime.Gosched()
						}
					} else if w := time.Until(at); w > 0 {
						time.Sleep(w)
					}
				}
				k := min(tailGroup, fn-g*tailGroup)
				now := d.now()
				for i := range ms[:k] {
					burstStamp(ms[i].Buf, seq, now, uint32(f), g*tailGroup+i, fn)
					seq++
				}
				sent := vt.sent
				ok := vt.write(uc, bt, ms[:k])
				if from, to := d.window(); now >= from && now < to {
					p.inWin += vt.sent - sent
				}
				if !ok {
					return // stopAll closed the socket during the frame
				}
			}
			vt.burst = append(vt.burst, time.Since(t0))
			p.sizes = append(p.sizes, fn)
			vt.frames++
		}
	})
}

// burstRec is one received datagram sent in the window: its delay and
// place (frame ^0 for control).
type burstRec struct {
	delay time.Duration
	seq   uint64
	frame uint32
	k, n  uint16
}

// burstRecv records the datagrams a socket receives that were sent in the
// window (one goroutine writes, the report reads after stopAll).
type burstRecv struct {
	recs []burstRec
	got  int // every datagram received, the window's and the others
	bad  int
}

// note records datagram b received at at.
func (r *burstRecv) note(d *tailDiag, b []byte, at time.Duration) {
	if len(b) < burstHeader {
		r.bad++
		return
	}
	r.got++
	sent := time.Duration(binary.BigEndian.Uint64(b[8:]))
	if from, to := d.window(); sent >= from && sent < to {
		r.recs = append(r.recs, burstRec{delay: at - sent, seq: binary.BigEndian.Uint64(b), frame: binary.BigEndian.Uint32(b[16:]),
			k: binary.BigEndian.Uint16(b[20:]), n: binary.BigEndian.Uint16(b[22:])})
	}
}

// newBurstVideoClient opens a video client toward to: a keepalive every
// tailKeepEvery, every datagram recorded.
func (d *tailDiag) newBurstVideoClient(to net.Addr) *burstRecv {
	c, _ := d.sock(to, 8<<20)
	r := &burstRecv{recs: make([]burstRec, 0, 1<<20)}
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
			r.note(d, b[:k], d.now())
		}
	})
	return r
}

// burstCtlTarget is the host's control end: it records each input's delay
// (control up), answers it with an ack and sends a feedback every
// burstFeedEvery to the source of the first input.
type burstCtlTarget struct {
	c    *net.UDPConn
	peer atomic.Pointer[netip.AddrPort]
	up   burstRecv
	sent atomic.Int64 // acks and feedbacks written with a send instant in the window
}

func (d *tailDiag) newBurstCtlTarget() *burstCtlTarget {
	c, _ := d.sock(nil, 1<<20)
	ct := &burstCtlTarget{c: c}
	ct.up.recs = make([]burstRec, 0, 1<<16)
	var seq atomic.Uint64
	send := func(b []byte, dst netip.AddrPort) {
		now := d.now()
		burstStamp(b, seq.Add(1), now, ^uint32(0), 0, 0)
		if from, to := d.window(); now >= from && now < to {
			ct.sent.Add(1)
		}
		c.WriteToUDPAddrPort(b, dst)
	}
	d.goStop(func() {
		b, ack := make([]byte, 2048), make([]byte, burstAckSize)
		for {
			k, src, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			at := d.now()
			if k != burstInputSize {
				continue
			}
			if ct.peer.Load() == nil {
				ct.peer.Store(&src)
			}
			ct.up.note(d, b[:k], at)
			send(ack, src)
		}
	})
	stop := d.stopCh()
	d.goStop(func() {
		b := make([]byte, burstFeedSize)
		tk := time.NewTicker(burstFeedEvery)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
			case <-stop:
				return
			}
			if dst := ct.peer.Load(); dst != nil {
				send(b, *dst)
			}
		}
	})
	return ct
}

// burstCtlClient is the client's control end: an input every
// burstInputEvery from its phase on (counted when sent in the window), the
// host's acks and feedbacks recorded (control down).
type burstCtlClient struct {
	down   atomic.Int64 // datagrams received from the host
	recv   burstRecv
	inputs int // sent in the window (written by the sender, read after stopAll)
}

func (d *tailDiag) newBurstCtlClient(to net.Addr, phase time.Duration) *burstCtlClient {
	c, _ := d.sock(to, 1<<20)
	cc := &burstCtlClient{}
	cc.recv.recs = make([]burstRec, 0, 1<<16)
	stop := d.stopCh()
	d.goStop(func() {
		b := make([]byte, burstInputSize)
		t0 := time.Now().Add(phase)
		for seq := uint64(0); ; seq++ {
			if w := time.Until(t0.Add(time.Duration(seq) * burstInputEvery)); w > 0 {
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
			now := d.now()
			burstStamp(b, seq, now, ^uint32(0), 0, 0)
			if from, to := d.window(); now >= from && now < to {
				cc.inputs++
			}
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
			cc.down.Add(1)
			cc.recv.note(d, b[:k], at)
		}
	})
	return cc
}

// burstProf is a run's profilers (on: RENDR_TAIL_PROF was set).
type burstProf struct {
	on   bool
	stop func()
}

// startProfiles starts the CPU profile, the block and mutex sampling and
// the runtime trace (after 5 s, for bc.trace) when bc.prof is set; stop
// writes them into bc.prof.
func (d *tailDiag) startProfiles(bc burstCfg) burstProf {
	if bc.prof == "" {
		return burstProf{stop: func() {}}
	}
	t := d.t
	if err := os.MkdirAll(bc.prof, 0o755); err != nil {
		t.Fatalf("RENDR_TAIL_PROF: %v", err)
	}
	create := func(name string) *os.File {
		f, err := os.Create(filepath.Join(bc.prof, name))
		if err != nil {
			t.Fatalf("RENDR_TAIL_PROF: %v", err)
		}
		return f
	}
	cpu := create("cpu.pprof")
	if err := pprof.StartCPUProfile(cpu); err != nil {
		t.Fatalf("RENDR_TAIL_PROF: %v", err)
	}
	runtime.SetBlockProfileRate(int(10 * time.Microsecond))
	runtime.SetMutexProfileFraction(10)
	traced := make(chan struct{})
	tstop := make(chan struct{})
	if bc.trace > 0 {
		go func() {
			defer close(traced)
			select {
			case <-time.After(5 * time.Second):
			case <-tstop:
				return
			}
			f := create("trace.out.gz")
			defer f.Close()
			z := gzip.NewWriter(f)
			defer z.Close()
			if err := trace.Start(z); err != nil {
				t.Errorf("RENDR_TAIL_PROF: trace: %v", err)
				return
			}
			select {
			case <-time.After(bc.trace):
			case <-tstop:
			}
			trace.Stop()
		}()
	} else {
		close(traced)
	}
	return burstProf{on: true, stop: func() {
		close(tstop)
		<-traced
		pprof.StopCPUProfile()
		cpu.Close()
		for _, name := range []string{"block", "mutex", "goroutine"} {
			f := create(name + ".pprof")
			pprof.Lookup(name).WriteTo(f, 0)
			f.Close()
		}
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
		t.Logf("profiles written to %s: cpu, block (rate 10 µs), mutex (fraction 10), goroutine, a %v runtime trace from the window's fifth second", bc.prof, bc.trace)
	}}
}

// burstCPU is the process's CPU time (user and system).
func burstCPU() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// burstReport logs every figure, then judges (an unprofiled run).
func (d *tailDiag) burstReport(n *l4uNet, bc burstCfg, plan []burstFrame, paths [2]*burstPath, s0, s1 tailSnap, cpu time.Duration, profiled bool) {
	t := d.t
	from, to := d.window()
	r, dp := paths[0], paths[1]
	t.Logf("host: GOMAXPROCS %d, %d CPUs, %v; window %v after a %v warm-up; shape %s; pacing: %s; video writes: %s; direct path %v after rendr's",
		runtime.GOMAXPROCS(0), runtime.NumCPU(), runtime.Version(), to-from, d.warm, bc.shape, map[bool]string{true: "spin", false: "timers"}[d.spin],
		map[bool]string{true: "one sendmmsg call per group", false: "one call per datagram (no batch calls here)"}[r.vt.batched], dp.phase)

	// The load, per path.
	var why []string
	for _, p := range paths {
		vt := p.vt
		due := int((to - from + d.warm) / tailFrameEvery)
		why = append(why, burstLoadProof(burstLoad{name: p.name, due: due, frames: vt.frames, late: vt.late, span: vt.burst, sizes: p.sizes})...)
		var dgs, idrs int
		for _, k := range p.sizes {
			dgs += k
		}
		for _, f := range plan[:min(len(plan), vt.frames)] {
			if f.idr {
				idrs++
			}
		}
		t.Logf("%s video: %d frames (about %d due; %d IDRs), %d datagrams written (%d write errors, the first %v); frame start late p50 %v, p99 %v, max %v; burst first-to-last write p50 %v, p99 %v, max %v; client: %d received, %d malformed",
			p.name, vt.frames, due, idrs, vt.sent, vt.errs, vt.firstErr, tailQ(vt.late, 0.5), tailQ(vt.late, 0.99), tailQ(vt.late, 1),
			tailQ(vt.burst, 0.5), tailQ(vt.burst, 0.99), tailQ(vt.burst, 1), p.vc.got, p.vc.bad)
	}

	// The classes: video (the datagrams stamped in the window), control
	// down (acks and feedbacks), control up (inputs).
	delays := func(rs []burstRec) []time.Duration {
		out := make([]time.Duration, len(rs))
		for i, x := range rs {
			out[i] = x.delay
		}
		return out
	}
	vs := [2]burstClass{{delays: delays(r.vc.recs), sent: r.inWin}, {delays: delays(dp.vc.recs), sent: dp.inWin}}
	verdicts := []burstVerdict{
		burstJudge("video down", vs[0], vs[1]),
		burstJudge("control down", burstClass{delays: delays(r.cc.recv.recs), sent: int(r.ct.sent.Load())}, burstClass{delays: delays(dp.cc.recv.recs), sent: int(dp.ct.sent.Load())}),
		burstJudge("control up", burstClass{delays: delays(r.ct.up.recs), sent: r.cc.inputs}, burstClass{delays: delays(dp.ct.up.recs), sent: dp.cc.inputs}),
	}
	for _, v := range verdicts {
		t.Logf("%s: through rendr %d of %d (%d lost) p50 %v, p99 %v, p99.9 %v, max %v; direct %d of %d (%d lost) p50 %v, p99 %v, p99.9 %v, max %v; added p50 %v, p99 %v, p99.9 %v",
			v.name, v.rSent-v.rLost, v.rSent, v.rLost, v.rP50, v.rP99, v.rP999, v.rMax, v.dSent-v.dLost, v.dSent, v.dLost, v.dP50, v.dP99, v.dP999, v.dMax, v.addP50, v.addP99, v.addP999)
	}

	// Where in a burst the delay grows: video by position in the frame and
	// for the IDRs' datagrams, both paths.
	buckets := []int{0, 46, 92, 138, 184, 276, 368, 552, 1 << 16}
	var lines []string
	for i := 0; i+1 < len(buckets); i++ {
		lo, hi := buckets[i], buckets[i+1]
		sel := func(rs []burstRec) []time.Duration {
			var out []time.Duration
			for _, x := range rs {
				if int(x.k) >= lo && int(x.k) < hi {
					out = append(out, x.delay)
				}
			}
			return out
		}
		a, b := sel(r.vc.recs), sel(dp.vc.recs)
		if len(a) == 0 && len(b) == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("[%d,%d) n %d/%d: rendr p50 %v p99 %v, direct p50 %v p99 %v", lo, hi, len(a), len(b), tailQ(a, 0.5), tailQ(a, 0.99), tailQ(b, 0.5), tailQ(b, 0.99)))
	}
	t.Logf("video delay by datagram position in its frame: %s", strings.Join(lines, "; "))
	idr := func(rs []burstRec) (all, last []time.Duration) {
		for _, x := range rs {
			if int(x.frame) < len(plan) && plan[x.frame].idr {
				all = append(all, x.delay)
				if x.k+1 == x.n {
					last = append(last, x.delay)
				}
			}
		}
		return
	}
	ra, rl := idr(r.vc.recs)
	da, dl := idr(dp.vc.recs)
	t.Logf("IDR datagrams: rendr %d, p50 %v, p99 %v, last datagram p50 %v; direct %d, p50 %v, p99 %v, last datagram p50 %v",
		len(ra), tailQ(ra, 0.5), tailQ(ra, 0.99), tailQ(rl, 0.5), len(da), tailQ(da, 0.5), tailQ(da, 0.99), tailQ(dl, 0.5))
	worst := slices.Clone(r.vc.recs)
	slices.SortFunc(worst, func(a, b burstRec) int { return int(b.delay - a.delay) })
	var ws []string
	for _, x := range worst[:min(len(worst), 10)] {
		ws = append(ws, fmt.Sprintf("%v (frame %d, %d of %d)", x.delay, x.frame, x.k, x.n))
	}
	t.Logf("rendr's worst video datagrams: %s", strings.Join(ws, ", "))

	// rendr's counters, the process's CPU and the host's over the window.
	t.Logf("rendr dialer datagram I/O over the window: %s", tailDgDiff(s0.d, s1.d))
	t.Logf("rendr passive datagram I/O over the window: %s", tailDgDiff(s0.p, s1.p))
	pf, srv := s1.pf, s1.srv
	pf.LastErr = nil
	t.Logf("ingress: %+v", pf)
	t.Logf("Server: %+v", srv)
	for _, fi := range n.pf.Flows() {
		if pc := fi.Session.Packet; pc != nil {
			t.Logf("flow %v → %s: stream %v, packet counters %+v", fi.Client, fi.Target, fi.Stream, *pc)
		}
	}
	dg := len(r.vc.recs) + len(dp.vc.recs)
	if dg > 0 {
		t.Logf("process CPU over the window: %v (%.2f cores), %.1f µs per video datagram of both paths (the generators, both paths' clients and rendr's two ends)",
			cpu, cpu.Seconds()/(to-from).Seconds(), float64(cpu.Microseconds())/float64(dg))
	}
	if s0.snmp != nil && s1.snmp != nil {
		var parts []string
		for _, k := range []string{"InDatagrams", "NoPorts", "InErrors", "OutDatagrams", "RcvbufErrors", "SndbufErrors"} {
			if _, ok := s1.snmp[k]; ok {
				parts = append(parts, fmt.Sprintf("%s +%d", k, s1.snmp[k]-s0.snmp[k]))
			}
		}
		t.Logf("kernel Udp counters over the window (the whole host): %s", strings.Join(parts, ", "))
	}
	if qs, top, total := tailHistDiff(s0.sched, s1.sched, 0.99, 0.999); qs != nil {
		t.Logf("Go scheduler latency over the window (runnable to running, %d samples): p99 ≤ %v, p99.9 ≤ %v, highest bucket ≤ %v", total, qs[0], qs[1], top)
	}
	if _, top, total := tailHistDiff(s0.gcPause, s1.gcPause); total > 0 || s1.gcCycles > s0.gcCycles {
		t.Logf("GC over the window: %d cycles, %d stop-the-world pauses, the longest ≤ %v", s1.gcCycles-s0.gcCycles, total, top)
	}

	// The verdict.
	var fails []string
	for _, v := range verdicts {
		why = append(why, v.invalid...)
		fails = append(fails, v.fails...)
	}
	judged := "PASS"
	if len(fails) != 0 {
		judged = "FAIL: " + strings.Join(fails, "; ")
	}
	switch {
	case profiled:
		t.Logf("profiled run, not judged (the profilers cost what they measure): %s", judged)
	case len(why) != 0:
		t.Fatalf("INVALID: %s (the judge alone: %s)", strings.Join(why, "; "), judged)
	case len(fails) != 0:
		t.Errorf("%s", judged)
	default:
		t.Logf("PASS: added p99 video %v, control down %v, control up %v (bound %v)", verdicts[0].addP99, verdicts[1].addP99, verdicts[2].addP99, burstAddedP99Max)
	}
}
