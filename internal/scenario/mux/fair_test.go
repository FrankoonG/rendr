package mux

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// stalledFull waits until the sender of a session whose receiving
// application stopped reading is blocked: its window is full (sent stays
// put for 1 s). It returns what the sender wrote.
func stalledFull(t testing.TB, s *sender, what string) int64 {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		before := s.sent.Load()
		time.Sleep(time.Second)
		if after := s.sent.Load(); after == before && after > 0 {
			return after
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the sender never blocked (%d bytes written)", what, s.sent.Load())
		}
	}
}

// heapInUse returns the live heap after a collection.
func heapInUse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestMuxReaderNeverBlocks_L15 (M3 design §A11.2; L15 — per-session
// credit under mux, the shared reader never blocks for one session):
// two selector sessions SA and SB share the one carrier of a one-factory
// Peer over a Link of 20 ms RTT shaped to 16 MiB/s (4 MiB/s under -race,
// R1-11), the default 8-MiB Window on both ends; each sends open-ended
// bulk A → B.
//
// Stimulus: SA's receiving application never reads: SA's sender blocks
// once SA's Window is full (its writes stop growing for 1 s) and SA's
// passive then holds every byte it wrote, undelivered. Load: SB's application keeps
// reading. PASS: over the next 4 s SB receives ≥ 0.9 of the link's rate
// (the shared carrier's reader keeps dispatching SB's frames while SA's
// buffer is full); no window violation (SA's passive never holds more
// than its Window, no carrier ends with protocol_violation, no session
// error); the live heap grows by less than 2 × (W_A + W_B) and so does
// the sum of both Runtimes' BufferedBytes (SA's bytes are held twice
// until its application reads them — in the passive's receive buffer and,
// unacknowledged, in the dialer's send buffer — and SB keeps a Window in
// flight: about 3 Windows). The Link buffers 256 KiB per direction (not
// rendrtest's 2 MiB) so that the heap measures rendr rather than the
// harness. Then SA's application reads
// again: both sessions' bytes verified with io.EOF after exactly what
// their senders wrote; a clean end and nothing left after Runtime.Close.
func TestMuxReaderNeverBlocks_L15(t *testing.T) {
	rate := float64(16 << 20)
	if raceEnabled {
		rate = 4 << 20 // R1-11
	}
	synctest.Test(t, func(t *testing.T) {
		const window = 8 << 20 // the default
		heap0 := heapInUse()
		w := newWorld(t, worldOpts{}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, rate: rate, buffer: 256 << 10})
		peer := w.peer("a")
		ps := []pair{w.open(peer, "SA", rendr.ModeSelector), w.open(peer, "SB", rendr.ModeSelector)}
		requireShared(t, ps)
		var rx []*receiver
		var tx []*sender
		for i, s := range ps {
			r := startReceiver(s.key+" A → B", s.p, uint64(1+i), openEnded)
			if i == 0 {
				w.pause(r)
			}
			rx = append(rx, r)
			tx = append(tx, w.startSender(s.d, uint64(1+i), openEnded, 0))
			startReceiver(s.key+" B → A", s.d, uint64(10+i), 0)
			w.startSender(s.p, uint64(10+i), 0, 0)
		}
		held := stalledFull(t, tx[0], "SA")
		waitFor(t, 10*time.Second, "SA's bytes in its passive's receive buffer", func() bool { return ps[0].p.Status().RxBytes == uint64(held) })
		sa := ps[0].p.Status()
		if sa.DeliveredBytes != 0 || sa.RxBytes < window/2 || sa.RxBytes > window {
			t.Fatalf("premise: SA's passive delivered %d and holds %d bytes (its sender wrote %d), want 0 delivered and between Window/2 and Window (%d)",
				sa.DeliveredBytes, sa.RxBytes, held, window)
		}

		from, b0 := time.Now(), rx[1].got.Load()
		var peakBuf int64
		var peakHeap uint64
		for k := 0; k < 4; k++ {
			time.Sleep(time.Second)
			peakBuf = max(peakBuf, w.d.Status().BufferedBytes+w.p.Status().BufferedBytes)
			if k == 1 {
				peakHeap = heapInUse()
			}
			if st := ps[0].p.Status(); st.RxBytes > window {
				t.Fatalf("SA's passive holds %d bytes, more than its Window %d", st.RxBytes, window)
			}
		}
		got := rx[1].got.Load() - b0
		share := float64(got) / (rate * time.Since(from).Seconds())
		t.Logf("SA blocked after %d bytes; SB received %d bytes in %v (%.3f of the link); BufferedBytes of both Runtimes peak %d; heap +%d",
			held, got, time.Since(from), share, peakBuf, int64(peakHeap)-int64(heap0))
		if share < 0.9 {
			t.Fatalf("SB received %.3f of the link while SA's reader was stalled, want ≥ 0.9", share)
		}
		if lim := int64(2 * 2 * window); peakBuf >= lim || int64(peakHeap)-int64(heap0) >= lim {
			t.Fatalf("BufferedBytes of both Runtimes peak %d, heap growth %d; want both < 2 × (W_A + W_B) = %d", peakBuf, int64(peakHeap)-int64(heap0), lim)
		}
		if tx[0].sent.Load() != held {
			t.Fatalf("SA's sender wrote %d bytes while blocked at %d", tx[0].sent.Load(), held)
		}

		rx[0].resume()
		for _, s := range tx {
			s.end()
		}
		for i, r := range rx {
			r.waitSent(t, tx[i], time.Minute)
		}
		closeAll(t, ps)
		w.noViolation()
		w.close()
	})
}

// TestMuxStalledReaderIsolation_L15_L16 (M3 design §A11.2; L15, L16 — a
// stalled session's full window never holds its neighbours' data or
// control frames): 16 selector sessions share the one carrier of a
// one-factory Peer over a Link of 20 ms RTT shaped to 4 MiB/s (2 MiB/s
// under -race, R1-11), with a 1-MiB Window on both ends (so the stalled
// windows fill in seconds); every session sends open-ended bulk A → B.
// Premise sizing (A11.5 rule 3): at the default 64-KiB DRR quantum an
// active session's fair share is 4 quanta per second (2 under -race), and
// at that granularity the writer's cap-limited rotation, not isolation,
// decides the per-session shares (TestMuxCapLimitedSharesFair: 0.55 of the
// fair share seen under -race); the quantum is 8 KiB on both ends
// (testhooks MuxQuantum), as in TestMuxFairness_L15.
//
// Stimulus: the receiving applications of 8 sessions stop reading for 120
// virtual s; their senders block once their windows are full. Load: the 8
// others keep reading. PASS: over 10 s from the stalled windows' filling
// the 8 active sessions receive together ≥ 0.85 of the link and each ≥ 0.6
// of its fair share (link / 8); their ACKs and FINs keep flowing while the
// stalled windows stay full: the active senders half-close, every active
// session's bytes arrive verified up to io.EOF, each sender's AckedBytes
// reaches what it wrote, and the active sessions close cleanly — all
// within the stall, the stalled senders still blocked. At 120 s the
// stalled applications read again: their bytes arrive verified with
// io.EOF after exactly what their senders wrote; a clean end and nothing
// left after Runtime.Close.
func TestMuxStalledReaderIsolation_L15_L16(t *testing.T) {
	rate := float64(4 << 20)
	if raceEnabled {
		rate = 2 << 20 // R1-11
	}
	synctest.Test(t, func(t *testing.T) {
		const window, measure, stall, quantum = 1 << 20, 10 * time.Second, 120 * time.Second, 8 << 10
		cfg := rendr.Config{Window: window}
		ov := testhooks.Overrides{MuxQuantum: quantum}
		w := newWorld(t, worldOpts{dcfg: cfg, pcfg: cfg, dov: ov, pov: ov}, linkSpec{name: "a", oneWay: 10 * time.Millisecond, rate: rate})
		peer := w.peer("a")
		ps := w.openMany(peer, "S", 16, func(int) rendr.Mode { return rendr.ModeSelector })
		requireShared(t, ps)
		var rx []*receiver
		var tx []*sender
		stallStart := time.Now()
		for i, s := range ps {
			r := startReceiver(s.key+" A → B", s.p, uint64(1+i), openEnded)
			if i < 8 {
				w.pause(r)
			}
			rx = append(rx, r)
			tx = append(tx, w.startSender(s.d, uint64(1+i), openEnded, 0))
			startReceiver(s.key+" B → A", s.d, uint64(100+i), 0)
			w.startSender(s.p, uint64(100+i), 0, 0)
		}
		held := make([]int64, 8)
		for i := range 8 {
			held[i] = stalledFull(t, tx[i], ps[i].key)
		}
		from := time.Now()
		var b0 []int64
		for _, r := range rx[8:] {
			b0 = append(b0, r.got.Load())
		}
		sleepUntil(from.Add(measure))
		var sum float64
		var each []float64
		for i, r := range rx[8:] {
			x := float64(r.got.Load() - b0[i])
			each = append(each, x)
			sum += x
		}
		link := rate * measure.Seconds()
		t.Logf("stalled windows full %v after the start; active sessions' shares of the link over %v: %.3f in all, each %v",
			from.Sub(stallStart), measure, sum/link, func() []string {
				var out []string
				for _, x := range each {
					out = append(out, fmt.Sprintf("%.3f", x/(link/8)))
				}
				return out
			}())
		if sum < 0.85*link {
			t.Fatalf("the active sessions received %.3f of the link together, want ≥ 0.85", sum/link)
		}
		if m := slices.Min(each); m < 0.6*link/8 {
			t.Fatalf("an active session received %.3f of its fair share, want ≥ 0.6", m/(link/8))
		}

		// L16: the active sessions finish (FIN, ACK, close) while the stalled
		// windows stay full.
		for _, s := range tx[8:] {
			s.end()
		}
		for i, r := range rx[8:] {
			r.waitSent(t, tx[8+i], 30*time.Second)
		}
		for i, s := range ps[8:] {
			waitFor(t, 5*time.Second, s.key+"'s last ACK", func() bool { return s.d.Status().AckedBytes == uint64(tx[8+i].sent.Load()) })
		}
		closeAll(t, ps[8:])
		if time.Since(stallStart) >= stall {
			t.Fatalf("premise: the active sessions finished %v after the stall began, not within it", time.Since(stallStart))
		}
		for i := range 8 {
			if got := tx[i].sent.Load(); got != held[i] || rx[i].got.Load() != 0 {
				t.Fatalf("stalled session %s: its sender wrote %d (blocked at %d), its application read %d", ps[i].key, got, held[i], rx[i].got.Load())
			}
		}

		sleepUntil(stallStart.Add(stall))
		for i := range 8 {
			rx[i].resume()
			tx[i].end()
		}
		for i := range 8 {
			rx[i].waitSent(t, tx[i], time.Minute)
		}
		closeAll(t, ps[:8])
		w.noViolation()
		w.close()
	})
}

// echoer measures a request/response echo on one session: the dialer
// writes a 1-KiB request every 100 ms (k-th request: bytes k + i), the
// passive application echoes everything it reads, and the dialer reads the
// echoes in order, checks each one's content and records its round trip
// (pipelined: a slow echo never delays the next request, as G2's echo).
type echoer struct {
	stop  chan struct{}
	done  chan struct{}
	rdone chan struct{}
	err   error
	rerr  error

	mu   sync.Mutex
	sent []time.Time // by request
	rtts []time.Duration
}

// samples returns the round trips measured so far.
func (e *echoer) samples() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.rtts)
}

// startEchoer runs the echo on s until halt.
func (w *world) startEchoer(s pair) *echoer {
	e := &echoer{stop: make(chan struct{}), done: make(chan struct{}), rdone: make(chan struct{})}
	w.addStop(e.stop)
	go func() { // the passive application: echo until EOF, then half-close
		buf := make([]byte, 64<<10)
		for {
			n, err := s.p.Read(buf)
			if n > 0 {
				if _, werr := s.p.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				s.p.CloseWrite()
				return
			}
		}
	}()
	go func() { // the dialer's reader: every echo in order, then EOF
		defer close(e.rdone)
		resp := make([]byte, 1<<10)
		for k := 1; ; k++ {
			if _, err := io.ReadFull(s.d, resp); err != nil {
				if err != io.EOF {
					e.rerr = fmt.Errorf("echo %d: Read: %w", k, err)
				}
				return
			}
			now := time.Now()
			for i, b := range resp {
				if b != byte(k+i) {
					e.rerr = fmt.Errorf("echo %d: byte %d is %d, want %d", k, i, b, byte(k+i))
					return
				}
			}
			e.mu.Lock()
			e.rtts = append(e.rtts, now.Sub(e.sent[k-1]))
			e.mu.Unlock()
		}
	}()
	go func() { // the dialer's writer: a request every 100 ms
		defer close(e.done)
		req := make([]byte, 1<<10)
		start := time.Now()
		for k := 1; ; k++ {
			for i := range req {
				req[i] = byte(k + i)
			}
			e.mu.Lock()
			e.sent = append(e.sent, time.Now())
			e.mu.Unlock()
			if _, err := s.d.Write(req); err != nil {
				e.err = fmt.Errorf("echo %d: Write: %w", k, err)
				return
			}
			select {
			case <-e.stop:
				return
			case <-time.After(time.Until(start.Add(time.Duration(k) * 100 * time.Millisecond))):
			}
		}
	}()
	return e
}

// halt stops the requests and half-closes the dialer; the echoes of every
// request must then arrive, followed by io.EOF.
func (e *echoer) halt(t testing.TB, s pair) {
	t.Helper()
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	<-e.done
	if e.err != nil {
		t.Fatal(e.err)
	}
	s.d.CloseWrite()
	select {
	case <-e.rdone:
	case <-time.After(30 * time.Second):
		t.Fatalf("echo: the echoes did not end within 30 s")
	}
	if e.rerr != nil {
		t.Fatal(e.rerr)
	}
	if n, m := len(e.samples()), len(e.sent); n != m {
		t.Fatalf("echo: %d echoes for %d requests", n, m)
	}
}

// p99 returns the 99th percentile of ds.
func p99(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[(len(s)*99+99)/100-1]
}

// TestMuxFairness_L15 (M3 design §A11.2, §A5.3; L15, M3-D10 DRR): 8 bulk
// sessions (4 sending A → B, 4 B → A, open-ended) and 1 echo session share
// the one carrier of a one-factory Peer over a Link of 20 ms RTT shaped to
// 4 MiB/s per direction (2 MiB/s under -race, R1-11).
//
// Premise sizing (A11.5 rule 3): fairness is measured as byte shares over
// 1-s windows, and a share is counted in DRR quanta; at the default 64-KiB
// quantum a session's 1 MiB/s is 16 quanta per window, which a direction
// that loses most of its rate (TestMuxBulkBothWaysKeepsTheLink) cuts to a
// handful. The quantum is set to 8 KiB on both ends (testhooks
// MuxQuantum) so that every window holds ≥ 25 quanta per session even
// then; the default quantum's fairness bound is WP8's unit row
// (TestMuxDRRFairness).
//
// The echo session's dialer writes a 1-KiB request every 100 ms and times
// its echo (pipelined, as G2's echo); its unloaded round trip (base) is
// measured before the bulk starts. PASS: in every 1-s window from 1 s after
// the bulk start to its end, Jain's index of the 4 bulk sessions' received
// bytes is ≥ 0.95 in each direction; the echo's P99 round trip under load
// is at most base + (Cap_A + BatchBudget)/rate + (Cap_B + BatchBudget)/rate
// + 2·RTT — the request waits behind at most the dialer end's in-flight cap
// and one writer round of the other sessions' payload (BatchBudget), the
// echo behind the passive end's (Cap_X: the largest Cap end X reported
// during the run): DRR keeps the echo a round away from the head, never
// behind the 4 × 8-MiB send backlog of its direction; every echo verified
// and every bulk byte verified with io.EOF after exactly what its sender
// wrote; a clean end and nothing left after Runtime.Close.
func TestMuxFairness_L15(t *testing.T) {
	rate := float64(4 << 20)
	if raceEnabled {
		rate = 2 << 20 // R1-11
	}
	synctest.Test(t, func(t *testing.T) {
		const oneWay, run, quantum, batch = 10 * time.Millisecond, 10 * time.Second, 8 << 10, 256 << 10
		ov := testhooks.Overrides{MuxQuantum: quantum}
		w := newWorld(t, worldOpts{dov: ov, pov: ov}, linkSpec{name: "a", oneWay: oneWay, rate: rate})
		peer := w.peer("a")
		ps := w.openMany(peer, "S", 9, func(int) rendr.Mode { return rendr.ModeSelector })
		requireShared(t, ps)
		es := ps[8]
		e := w.startEchoer(es)
		time.Sleep(2 * time.Second)
		base := slices.Max(e.samples())

		var rx []*receiver
		var tx []*sender
		for i, s := range ps[:8] {
			from, to, dir := s.d, s.p, "A → B"
			if i >= 4 {
				from, to, dir = s.p, s.d, "B → A"
			}
			rx = append(rx, startReceiver(s.key+" "+dir, to, uint64(1+i), openEnded))
			tx = append(tx, w.startSender(from, uint64(1+i), openEnded, 0))
			startReceiver(s.key+" back", from, uint64(100+i), 0)
			w.startSender(to, uint64(100+i), 0, 0)
		}
		n0 := len(e.samples())
		start := time.Now()
		var caps [2]int // the largest Cap each end of the shared carrier reported
		for k := 1; k <= int(run/(100*time.Millisecond)); k++ {
			sleepUntil(start.Add(time.Duration(k) * 100 * time.Millisecond))
			for i, c := range []*rendr.Conn{es.d, es.p} {
				if cs := liveOf(c.Status()); len(cs) == 1 {
					caps[i] = max(caps[i], cs[0].Cap)
				}
			}
		}
		end := time.Now()
		rtts := e.samples()[n0:]
		for _, s := range tx {
			s.end()
		}
		for i, r := range rx {
			r.waitSent(t, tx[i], time.Minute)
		}
		e.halt(t, es)

		for d, set := range [][]*receiver{rx[:4], rx[4:]} {
			var total int64
			worst, least := 1.0, int64(math.MaxInt64)
			for at := start.Add(time.Second); !at.Add(time.Second).After(end); at = at.Add(time.Second) {
				var xs []float64
				for _, r := range set {
					n := r.bytesAt(at.Add(time.Second)) - r.bytesAt(at)
					xs = append(xs, float64(n))
					least = min(least, n)
				}
				j := jain(xs)
				worst = min(worst, j)
				if j < 0.95 {
					t.Errorf("%s: Jain's index %.3f in the window at +%v (bytes %v), want ≥ 0.95", [2]string{"A → B", "B → A"}[d], j, at.Sub(start), xs)
				}
			}
			for _, r := range set {
				total += r.bytesAt(end) - r.bytesAt(start)
			}
			t.Logf("%s: worst Jain's index %.4f; %.3f of the link; least session window %d bytes (%d quanta)",
				[2]string{"A → B", "B → A"}[d], worst, float64(total)/(rate*run.Seconds()), least, least/quantum)
		}
		perSec := float64(time.Second) / rate
		limit := base + time.Duration(float64(caps[0]+caps[1]+2*batch)*perSec) + 2*2*oneWay
		got := p99(rtts)
		t.Logf("echo: base %v, %d samples under load, P99 %v, max %v; Cap A %d, B %d; limit %v", base, len(rtts), got, slices.Max(rtts), caps[0], caps[1], limit)
		if len(rtts) < int(run/(100*time.Millisecond))*9/10 {
			t.Errorf("echo: %d samples under load in %v, want ≥ 90 %% of one per 100 ms", len(rtts), run)
		}
		if got > limit {
			t.Errorf("echo: P99 %v under load, want ≤ base + (Cap_A + Cap_B + 2·BatchBudget)/rate + 2·RTT = %v", got, limit)
		}
		if t.Failed() {
			t.FailNow()
		}
		closeAll(t, ps)
		w.noViolation()
		w.close()
	})
}
