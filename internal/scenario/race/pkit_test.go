package race

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Packet traffic (as package packet's kit, F8): a flow writes test
// datagrams (rendrtest.PacketPayload) on one PacketConn at a fixed rate in
// 10-ms send slots and reads them on another through a
// rendrtest.PacketVerifier, recording when WriteTo accepted each seq and
// when it first arrived. The reader reads into a buffer of MaxPayload + 1
// bytes (io.ErrShortBuffer there means rendr delivered more than its own
// limit) and every ReadFrom must report the session's RemoteAddr (L38).

// flowCfg configures a flow.
type flowCfg struct {
	name  string // "A → B" or "B → A"
	seed  uint64
	rate  int // datagrams per second
	size  int // bytes per datagram (0: 1000, F4)
	limit int // stop after this many datagrams (0: until halt)
}

// flow is one direction of packet traffic.
type flow struct {
	cfg   flowCfg
	w, r  *rendr.PacketConn
	v     *rendrtest.PacketVerifier
	start time.Time

	stop         chan struct{}
	wdone, rdone chan struct{}
	accepted     atomic.Int64 // WriteTo calls that returned (len, nil)
	read         atomic.Int64 // datagrams ReadFrom returned
	werr, rerr   error
	maxCall      time.Duration // the longest WriteTo call (NonBlockingWrite)

	mu      sync.Mutex
	wrote   []time.Time // by seq: when WriteTo accepted it
	arrived []time.Time // by seq: when ReadFrom first returned it (zero: never)
	bad     error       // the first integrity failure
}

// startFlow writes on wc and reads on rc, each on its own goroutine.
func (w *world) startFlow(wc, rc *rendr.PacketConn, cfg flowCfg) *flow {
	if cfg.size == 0 {
		cfg.size = 1000
	}
	f := &flow{cfg: cfg, w: wc, r: rc, v: rendrtest.NewPacketVerifier(cfg.seed), start: time.Now(),
		stop: make(chan struct{}), wdone: make(chan struct{}), rdone: make(chan struct{})}
	w.stops = append(w.stops, f.stop)
	go f.writer()
	go f.reader()
	return f
}

func (f *flow) writer() {
	defer close(f.wdone)
	buf := make([]byte, f.cfg.size)
	seq := 0
	for k := 1; ; k++ {
		due := int(time.Since(f.start) * time.Duration(f.cfg.rate) / time.Second)
		if f.cfg.limit > 0 {
			due = min(due, f.cfg.limit)
		}
		for ; seq < due; seq++ {
			at := time.Now()
			m, err := f.w.WriteTo(rendrtest.PacketPayload(buf, f.cfg.seed, uint64(seq), f.cfg.size, at), nil)
			f.maxCall = max(f.maxCall, time.Since(at))
			if err != nil {
				f.werr = fmt.Errorf("%s: WriteTo of seq %d: %w", f.cfg.name, seq, err)
				return
			}
			if m != f.cfg.size {
				f.werr = fmt.Errorf("%s: WriteTo returned %d for a %d-byte datagram", f.cfg.name, m, f.cfg.size)
				return
			}
			f.mu.Lock()
			f.wrote = append(f.wrote, at)
			f.mu.Unlock()
			f.accepted.Add(1)
		}
		if f.cfg.limit > 0 && seq == f.cfg.limit {
			return
		}
		select {
		case <-f.stop:
			return
		case <-time.After(time.Until(f.start.Add(time.Duration(k) * slot))):
		}
	}
}

func (f *flow) reader() {
	defer close(f.rdone)
	buf := make([]byte, f.r.MaxPayload()+1)
	want := f.r.RemoteAddr()
	for {
		n, addr, err := f.r.ReadFrom(buf)
		now := time.Now()
		if errors.Is(err, io.ErrShortBuffer) {
			f.fail(fmt.Errorf("%s: ReadFrom into MaxPayload + 1 = %d bytes returned io.ErrShortBuffer", f.cfg.name, len(buf)))
			continue
		}
		if err != nil {
			f.rerr = err
			return
		}
		if addr != want {
			f.fail(fmt.Errorf("%s: ReadFrom reported %v, RemoteAddr is %v (L38)", f.cfg.name, addr, want))
		}
		if verr := f.v.Add(buf[:n], now); verr != nil {
			f.fail(fmt.Errorf("%s: %w", f.cfg.name, verr))
		} else {
			seq := int(seqOf(buf))
			f.mu.Lock()
			if seq >= len(f.arrived) {
				f.arrived = append(f.arrived, make([]time.Time, seq+1-len(f.arrived))...)
			}
			if f.arrived[seq].IsZero() {
				f.arrived[seq] = now
			}
			f.mu.Unlock()
		}
		f.read.Add(1)
	}
}

// seqOf is the seq of a test datagram.
func seqOf(b []byte) uint64 {
	var s uint64
	for _, c := range b[:8] {
		s = s<<8 | uint64(c)
	}
	return s
}

// fail records the first integrity failure.
func (f *flow) fail(err error) {
	f.mu.Lock()
	if f.bad == nil {
		f.bad = err
	}
	f.mu.Unlock()
}

// halt stops the writer and waits for it; a WriteTo error fails the test.
func (f *flow) halt(t testing.TB) {
	t.Helper()
	select {
	case <-f.stop:
	default:
		close(f.stop)
	}
	select {
	case <-f.wdone:
	case <-time.After(time.Minute):
		t.Fatalf("%s: the writer did not stop (%d accepted)", f.cfg.name, f.accepted.Load())
	}
	if f.werr != nil {
		t.Fatal(f.werr)
	}
}

// waitReader waits until the reader ended with want (io.EOF: the peer's
// clean end; net.ErrClosed: this side's Close).
func (f *flow) waitReader(t testing.TB, within time.Duration, want error) {
	t.Helper()
	select {
	case <-f.rdone:
	case <-time.After(within):
		t.Fatalf("%s: the reader did not end within %v (%d datagrams read)", f.cfg.name, within, f.read.Load())
	}
	if !errors.Is(f.rerr, want) {
		t.Fatalf("%s: the reader ended with %v, want %v", f.cfg.name, f.rerr, want)
	}
}

// integrity requires PacketIntegrity (B1.0; L36, L38, L39): every datagram
// returned intact, with its exact size and the session's address, at most
// once (0 application duplicates), never more than MaxPayload.
func (f *flow) integrity(t testing.TB) rendrtest.PacketResult {
	t.Helper()
	res := f.v.Result()
	f.mu.Lock()
	bad := f.bad
	f.mu.Unlock()
	if bad != nil || res.Corrupt+res.BadSize+res.Duplicates != 0 {
		t.Fatalf("%s: integrity (%v): %+v", f.cfg.name, bad, res)
	}
	return res
}

// nonBlocking requires that no WriteTo call took 100 ms or more (B1.0
// NonBlockingWrite, L40).
func (f *flow) nonBlocking(t testing.TB) {
	t.Helper()
	if f.maxCall >= 100*time.Millisecond {
		t.Fatalf("%s: a WriteTo call took %v, want < 100 ms", f.cfg.name, f.maxCall)
	}
}

// lost returns the accepted datagrams that never arrived.
func (f *flow) lost() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k := range f.wrote {
		if k >= len(f.arrived) || f.arrived[k].IsZero() {
			n++
		}
	}
	return n
}

// ratio is the share of accepted datagrams that arrived (DeliveryRatio).
func (f *flow) ratio() float64 {
	n := f.accepted.Load()
	if n == 0 {
		return 0
	}
	return float64(n-int64(f.lost())) / float64(n)
}

// drops is the sum of a PacketCounters' send-side drop counters.
func drops(c *rendr.PacketCounters) uint64 {
	return c.DropQueue + c.DropAge + c.DropTooLarge + c.DropNoPath
}

// endClean ends a packet session as F21: both generators stop; 1 s later,
// once every accepted datagram was sent or counted as a send-side drop and
// every datagram received was read, A (the dialer) closes; B reads until
// io.EOF, which must come after every datagram B accepted, then closes;
// both sessions end within Linger with io.EOF. up is A → B, down B → A.
func endClean(t testing.TB, dc, pc *rendr.PacketConn, up, down *flow) {
	t.Helper()
	for _, f := range []*flow{up, down} {
		select {
		case <-f.rdone:
			t.Fatalf("%s: the reader ended with %v before the clean end", f.cfg.name, f.rerr)
		default:
		}
	}
	up.halt(t)
	down.halt(t)
	time.Sleep(time.Second)
	waitFor(t, 10*time.Second, "the accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.Sent+drops(ds) == uint64(up.accepted.Load()) && ps.Sent+drops(ps) == uint64(down.accepted.Load()) &&
			ps.Received == uint64(up.read.Load()) && ds.Received == uint64(down.read.Load())
	})
	dc.Close()
	up.waitReader(t, 10*time.Second, io.EOF)
	if ps := pc.Status().Packet; ps.Received != uint64(up.read.Load()) || ps.DropRecvQueue+ps.DropLate != 0 {
		t.Fatalf("B read %d datagrams before io.EOF, accepted %+v", up.read.Load(), *ps)
	}
	pc.Close()
	down.waitReader(t, 10*time.Second, net.ErrClosed)
	timeout := time.After(30 * time.Second) // Linger
	for _, c := range []*rendr.PacketConn{dc, pc} {
		select {
		case <-c.Done():
		case <-timeout:
			t.Fatalf("a session did not end within Linger: %+v", c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || st.Err != io.EOF {
			t.Fatalf("%v session ended %v with %v, want io.EOF", st.Role, st.State, st.Err)
		}
	}
}
