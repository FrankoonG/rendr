package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// pinnedRcvQueue is quic-go v0.63's receive queue (maxDatagramRcvQueueLen,
// pinned by TestQUICGoPinnedBehaviour): DATAGRAMs beyond it are dropped
// silently while nobody receives.
const pinnedRcvQueue = 128

// stallPair returns a datagram carrier pair whose receiving end (the
// passive when passiveReceives, else the dialer) counts its handled
// DATAGRAM frames in the returned tracer; both ends count drops. The
// tracer has counted every DATAGRAM the receiver got so far: the
// classifying one when the passive receives, none otherwise, so
// writeTraced's base is exact.
func stallPair(t *testing.T, passiveReceives bool) (w, r *dgramConn, ft *frameTracer, wc, rc *Counters) {
	t.Helper()
	return stallPairWith(t, passiveReceives, nil, nil)
}

// tracerFunc is quic.Config.Tracer.
type tracerFunc = func(context.Context, bool, qgo.ConnectionID) qlogwriter.Trace

// stallPairWith is stallPair whose receiver's and sender's quic-go tracers
// wrap returns for the receiver's frameTracer (nil: the frameTracer alone
// on the receiver), and paired, when not nil, runs as soon as the pair
// exists (the passive read the classifying DATAGRAM).
func stallPairWith(t *testing.T, passiveReceives bool, wrap func(ft *frameTracer) (rcv, snd tracerFunc), paired func()) (w, r *dgramConn, ft *frameTracer, wc, rc *Counters) {
	t.Helper()
	ft, wc, rc = &frameTracer{}, &Counters{}, &Counters{}
	rcvT, sndT := tracerFunc(ft.trace), tracerFunc(nil)
	if wrap != nil {
		rcvT, sndT = wrap(ft)
	}
	traced, sender := &qgo.Config{Tracer: rcvT}, (*qgo.Config)(nil)
	if sndT != nil {
		sender = &qgo.Config{Tracer: sndT}
	}
	if passiveReceives {
		w, r, _ = dgramPair(t, Options{Config: traced, Counters: rc}, Options{Config: sender, Counters: wc})
	} else {
		r, w, _ = dgramPair(t, Options{Config: sender, Counters: wc}, Options{Config: traced, Counters: rc})
	}
	if paired != nil {
		paired()
	}
	if passiveReceives {
		// quic-go records a received packet after it handled the packet's
		// frames (frameTracer), so the passive may have read the
		// classifying DATAGRAM before its tracer counted it; a base read
		// then is one short and the exact count of the next group is never
		// reached (the race lane's 5-s waits, run 20261018-050552-0937;
		// TestQUICStallPairCountsClassify_L46).
		eventually(t, "the passive's quic-go recorded the classifying DATAGRAM", func() bool { return ft.rcvDatagrams.Load() == 1 })
	}
	return w, r, ft, wc, rc
}

// lateTracer forwards a connection's qlog events to ft but holds the record
// of the received packet that carries the at-th DATAGRAM (1: the
// classifying one) until the sending side's quic-go sent its next DATAGRAM
// (sent closes; nil: never) or hold passed: quic-go's run loop descheduled
// between handling that packet's frames and recording it. It runs on that
// run loop.
type lateTracer struct {
	ft         *frameTracer
	at         int64
	sent       <-chan struct{}
	hold       time.Duration
	seen       atomic.Int64 // DATAGRAMs in the received packets so far
	held       atomic.Bool  // the record was held
	bySend     atomic.Bool  // the sender's next DATAGRAM released it (not hold)
	releasedAt atomic.Int64 // when the hold ended (UnixNano)
}

func (l *lateTracer) trace(context.Context, bool, qgo.ConnectionID) qlogwriter.Trace { return l }
func (l *lateTracer) AddProducer() qlogwriter.Recorder                               { return l }
func (l *lateTracer) SupportsSchemas(string) bool                                    { return true }
func (l *lateTracer) Close() error                                                   { return nil }

func (l *lateTracer) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.PacketReceived); ok {
		if n := datagrams(p.Frames); n > 0 && l.seen.Add(n) >= l.at && l.held.CompareAndSwap(false, true) {
			select {
			case <-l.sent:
				l.bySend.Store(true)
			case <-time.After(l.hold):
			}
			l.releasedAt.Store(time.Now().UnixNano())
		}
	}
	l.ft.RecordEvent(e)
}

// sendTracer closes sent when its connection sends its second DATAGRAM
// (the first after the classifying one).
type sendTracer struct {
	sent chan struct{}
	n    atomic.Int64
}

func (s *sendTracer) trace(context.Context, bool, qgo.ConnectionID) qlogwriter.Trace { return s }
func (s *sendTracer) AddProducer() qlogwriter.Recorder                               { return s }
func (s *sendTracer) SupportsSchemas(string) bool                                    { return true }
func (s *sendTracer) Close() error                                                   { return nil }

func (s *sendTracer) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.PacketSent); ok && datagrams(p.Frames) > 0 && s.n.Add(1) == 2 {
		close(s.sent)
	}
}

// datagrams counts the DATAGRAM frames among a packet's frames.
func datagrams(frames []qlog.Frame) int64 {
	var n int64
	for _, f := range frames {
		if _, ok := f.Frame.(*qlog.DatagramFrame); ok {
			n++
		}
	}
	return n
}

// TestQUICStallPairCountsClassify_L46 is the row of stallPair's exact base
// (TestQUICDatagramPumpStallLossCounted_L46's dialer-to-passive 5-s waits
// in the race lane, run 20261018-050552-0937; a diagnostic pool run showed
// every DATAGRAM sent and handled, no drop anywhere, and the passive's
// count one above the exact target). Stimulus: the passive's quic-go
// records the classifying DATAGRAM's packet only once the dialer sent its
// next DATAGRAM or 500 ms passed (lateTracer), after the passive read it.
// Load: one group of 32 datagrams written through writeTraced. PASS: the
// group is counted exactly (writeTraced returns), the hold happened and
// ended after the pair existed, and the passive's quic-go handled exactly
// the classifying DATAGRAM and the 32, with no drop counted at either end.
// With the base read during the hold (stallPair not waiting for the
// record), the dialer's first datagram releases the record and the count
// ends one above the target: the wait fails after 5 s.
func TestQUICStallPairCountsClassify_L46(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	sent := make(chan struct{})
	var lt *lateTracer
	var pairedAt time.Time
	w, _, ft, wc, rc := stallPairWith(t, true, func(ft *frameTracer) (tracerFunc, tracerFunc) {
		lt = &lateTracer{ft: ft, at: 1, sent: sent, hold: 500 * time.Millisecond}
		st := &sendTracer{sent: sent}
		return lt.trace, st.trace
	}, func() { pairedAt = time.Now() })
	writeTraced(t, w, ft, 0, 32)
	if !lt.held.Load() || !pairedAt.Before(time.Unix(0, lt.releasedAt.Load())) {
		t.Fatalf("stimulus: the classifying DATAGRAM's record was held %v, released at %v, the pair existed at %v: want it held past the pair",
			lt.held.Load(), time.Unix(0, lt.releasedAt.Load()), pairedAt)
	}
	if got, in, eg := ft.rcvDatagrams.Load(), rc.IngressDrops.Load(), wc.EgressDrops.Load(); got != 33 || in != 0 || eg != 0 {
		t.Fatalf("the passive's quic-go handled %d DATAGRAMs, IngressDrops %d, EgressDrops %d: want 33 (the classifying one and the group), none dropped", got, in, eg)
	}
	t.Logf("the record was released by the dialer's next DATAGRAM: %v", lt.bySend.Load())
}

// TestQUICDatagramGoldenPassiveCountsFile_L46 is the row of the golden
// passive's exact base (TestQUICDatagramGolden, KL-19): the same race as
// stallPair's, where the passive's raw client sends the file's DATAGRAMs
// untraced and the carrier delivers them before the tracer counted them.
// Stimulus: the passive's quic-go records the packet that carries the
// file's last DATAGRAM only 500 ms after it handled it (lateTracer), so the
// carrier delivers every file datagram while the tracer counts fewer.
// Load: the file's DATAGRAMs, a 200-datagram burst into a held pump and
// the trailing datagram (dgramGoldenPassive). PASS: the passive part
// completes, so its exact group waits were met and its drops counted from
// the gap; the hold happened and ended after the carrier delivered the
// file's datagrams; and the passive's quic-go handled exactly the file's,
// the burst's and the trailing DATAGRAMs. With the base read during the
// hold (no wait for the file's records) the count ends above the exact
// target of the burst's first group: the wait fails after 5 s.
func TestQUICDatagramGoldenPassiveCountsFile_L46(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	want, inner := dgramGoldenFile(t), dgramGoldenInnerBytes(t)
	var lt *lateTracer
	var readAt time.Time
	ft := dgramGoldenPassive(t, want, inner, func(ft *frameTracer) tracerFunc {
		lt = &lateTracer{ft: ft, at: int64(len(want.dgs)), hold: 500 * time.Millisecond}
		return lt.trace
	}, func() { readAt = time.Now() })
	if !lt.held.Load() || !readAt.Before(time.Unix(0, lt.releasedAt.Load())) {
		t.Fatalf("stimulus: the record of the file's last DATAGRAM was held %v, released at %v, the file's datagrams delivered at %v: want it held past the delivery",
			lt.held.Load(), time.Unix(0, lt.releasedAt.Load()), readAt)
	}
	if got, n := ft.rcvDatagrams.Load(), int64(len(want.dgs)+200+1); got != n {
		t.Fatalf("the passive's quic-go handled %d DATAGRAMs, want %d (the file's %d, the burst's 200 and the trailing one)", got, n, len(want.dgs))
	}
}

// holdPump stops r's pump before its next receive. parked returns once
// the pump stopped there and the number of datagrams it queued meanwhile
// (none, or the one it was waiting for as the hold began); release (also a
// cleanup) lets it run again.
func holdPump(t *testing.T, r *dgramConn) (parked func() int, release func()) {
	h := &pumpHold{gate: make(chan struct{}), parked: make(chan struct{}, 1)}
	r.hold.Store(h)
	done := false
	release = func() {
		if !done {
			done = true
			r.hold.Store(nil)
			close(h.gate)
		}
	}
	t.Cleanup(release)
	parked = func() int {
		t.Helper()
		select {
		case <-h.parked:
		case <-time.After(testEventuallyTime):
			t.Fatal("the pump did not stop at the hold")
		}
		return queued(r)
	}
	return parked, release
}

// writeTraced has w write the datagrams seqDatagram(from … to-1, 1000) in
// groups of 32 and waits after each group until r's quic-go handled them
// (queued or dropped by its receive queue): QUIC's congestion window never
// keeps a group in w's egress queue long enough for an age drop.
func writeTraced(t *testing.T, w *dgramConn, ft *frameTracer, from, to int) {
	t.Helper()
	base := ft.rcvDatagrams.Load() - int64(from)
	for i := from; i < to; i++ {
		if _, err := w.WriteTo(seqDatagram(i, 1000), nil); err != nil {
			t.Fatal(err)
		}
		if i%32 == 31 || i == to-1 {
			eventually(t, "the receiver's quic-go handled the group", func() bool { return ft.rcvDatagrams.Load() == base+int64(i+1) })
		}
	}
}

// rawSendTraced has the raw quic-go conn qc send each payload as one
// DATAGRAM, in groups of 32, and waits after each group until the
// receiver's quic-go (traced by ft) handled them: queued, or dropped by
// its receive queue. Every DATAGRAM sent before must have been handled.
func rawSendTraced(t *testing.T, qc *qgo.Conn, ft *frameTracer, payloads ...[]byte) {
	t.Helper()
	base := ft.rcvDatagrams.Load()
	for i, p := range payloads {
		if err := qc.SendDatagram(p); err != nil {
			t.Fatal(err)
		}
		if i%32 == 31 || i == len(payloads)-1 {
			eventually(t, "the receiver's quic-go handled the group", func() bool { return ft.rcvDatagrams.Load() == base+int64(i+1) })
		}
	}
}

// pumpWaits reports whether a carrier's pump waits in quic-go's
// ReceiveDatagram for the next DATAGRAM: it found quic-go's queue empty
// (rxSeq.empty ran) and parked. The polled probe never parks, and a held
// pump parks outside ReceiveDatagram. It reads every goroutine's stack,
// so the test must run one datagram carrier.
func pumpWaits() bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	for _, g := range strings.Split(string(buf), "\n\n") {
		head, _, _ := strings.Cut(g, "\n")
		if strings.Contains(head, "[select") && strings.Contains(g, ".(*dgramConn).pump(") && strings.Contains(g, ".ReceiveDatagram(") {
			return true
		}
	}
	return false
}

// readSeqs reads n datagrams from r and returns their seqDatagram indices,
// failing on a datagram that is not intact.
func readSeqs(t *testing.T, r *dgramConn, n int) []int {
	t.Helper()
	buf := make([]byte, DatagramBudget+1)
	seqs := make([]int, 0, n)
	for range n {
		k, _, err := r.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom after %d datagrams: %v", len(seqs), err)
		}
		i := int(binary.BigEndian.Uint32(buf))
		if !bytes.Equal(buf[:k], seqDatagram(i, 1000)) {
			t.Fatalf("datagram %d (seq %d, %d bytes) is not intact", len(seqs), i, k)
		}
		seqs = append(seqs, i)
	}
	return seqs
}

// TestQUICDatagramPumpStallLossCounted_L46 (KL-19) is the accounting row:
// quic-go keeps at most 128 received DATAGRAMs per connection and drops
// beyond silently, so a stalled pump would lose datagrams no counter sees.
// It proves the accounting path, not the production trigger (a stall of
// the whole receiving process, which no in-process row reproduces; the
// Linux pool's G3 QUIC rows are that evidence). Stimulus: per
// direction, the receiving end's pump is held (a stalled consumer: a VM or
// scheduler stall cannot be produced in process, a held pump is the same
// burst after a pause) while the peer writes a burst of 1000-byte
// datagrams that its quic-go fully handles, then released, then one more
// datagram. Load: a burst of 300 overflows quic-go's queue by 171 or 172
// (by 171 when the pump was waiting for the first datagram as the hold
// began); a burst of 100 fits. Integrity: every delivered datagram is intact and in order —
// the head of the burst, then the trailing one — and per direction
// delivered + IngressDrops + EgressDrops == written, with IngressDrops
// exactly quic-go's overflow (none for the burst that fits).
func TestQUICDatagramPumpStallLossCounted_L46(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	for _, dir := range []struct {
		name            string
		passiveReceives bool
	}{{"dialer to passive", true}, {"passive to dialer", false}} {
		for _, burst := range []int{300, 100} {
			t.Run(dir.name+"/"+map[bool]string{true: "overflow", false: "fits"}[burst > pinnedRcvQueue], func(t *testing.T) {
				w, r, ft, wc, rc := stallPair(t, dir.passiveReceives)
				parked, release := holdPump(t, r)
				writeTraced(t, w, ft, 0, burst)
				kept := min(burst, pinnedRcvQueue+parked()) // what the pump took as the hold began, and quic-go's queue
				release()
				eventually(t, "the pump drained quic-go's queue", func() bool { return queued(r) == kept })
				if _, err := w.WriteTo(seqDatagram(burst, 1000), nil); err != nil {
					t.Fatal(err)
				}
				eventually(t, "the trailing datagram arrived", func() bool { return queued(r) == kept+1 })
				seqs := readSeqs(t, r, kept+1)
				for k, s := range seqs {
					if want := map[bool]int{true: k, false: burst}[k < kept]; s != want {
						t.Fatalf("delivered %v: datagram %d is seq %d, want %d", seqs, k, s, want)
					}
				}
				in, eg := rc.IngressDrops.Load(), wc.EgressDrops.Load()
				t.Logf("written %d, delivered %d, IngressDrops %d, EgressDrops %d", burst+1, len(seqs), in, eg)
				if in != uint64(burst-kept) || eg != 0 || uint64(len(seqs))+in+eg != uint64(burst+1) {
					t.Errorf("IngressDrops %d, EgressDrops %d, delivered %d of %d written: want IngressDrops %d (quic-go's overflow), no egress drop",
						in, eg, len(seqs), burst+1, burst-kept)
				}
			})
		}
	}
}
