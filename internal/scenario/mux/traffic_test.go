package mux

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Stream traffic. A sender writes PRNG(seed) bytes on one Conn, as fast as
// the session takes them (bulk) or paced in 10-ms slots, then half-closes;
// a receiver reads them on the other Conn through a rendrtest.Verifier
// (byte for byte, exactly size bytes, then io.EOF) and records when each
// Read returned and how many bytes it had then, so that delivery gaps and
// per-window shares can be placed in time. A receiver can be paused (its
// application stops reading) and resumed.

// slot is the paced sender's send slot.
const slot = 10 * time.Millisecond

// sender is one direction's writer.
type sender struct {
	start time.Time
	stop  chan struct{} // closed by the world's shutdown
	quit  chan struct{} // closed by end: an open-ended sender half-closes
	done  chan struct{}
	err   error
	sent  atomic.Int64
}

// openEnded is the size of a sender that writes until end is called (and
// of the receiver that reads it).
const openEnded = -1

// end makes an open-ended sender stop writing and half-close.
func (s *sender) end() {
	select {
	case <-s.quit:
	default:
		close(s.quit)
	}
}

// startSender writes size bytes of PRNG(seed) on c and then calls
// CloseWrite; rate > 0 paces it at rate bytes/s in slot-sized steps. A
// size of openEnded writes until end is called.
func (w *world) startSender(c *rendr.Conn, seed uint64, size int64, rate float64) *sender {
	s := &sender{start: time.Now(), stop: make(chan struct{}), quit: make(chan struct{}), done: make(chan struct{})}
	w.addStop(s.stop)
	limit := size
	if size == openEnded {
		limit = math.MaxInt64
	}
	go func() {
		defer close(s.done)
		src := rendrtest.PRNG(seed)
		buf := make([]byte, 64<<10)
		for k := 1; s.sent.Load() < limit; k++ {
			if size == openEnded {
				select {
				case <-s.quit:
					limit = s.sent.Load()
					continue
				default:
				}
			}
			n := min(int64(len(buf)), limit-s.sent.Load())
			if rate > 0 {
				n = min(limit, int64(rate*float64(k)*slot.Seconds())) - s.sent.Load()
			}
			for n > 0 {
				m := min(n, int64(len(buf)))
				src.Read(buf[:m])
				if _, err := c.Write(buf[:m]); err != nil {
					s.err = fmt.Errorf("Write after %d bytes: %w", s.sent.Load(), err)
					return
				}
				s.sent.Add(m)
				n -= m
			}
			if rate > 0 {
				select {
				case <-s.stop:
					s.err = fmt.Errorf("stopped after %d bytes", s.sent.Load())
					return
				case <-time.After(time.Until(s.start.Add(time.Duration(k) * slot))):
				}
			}
		}
		if err := c.CloseWrite(); err != nil {
			s.err = fmt.Errorf("CloseWrite: %w", err)
		}
	}()
	return s
}

// wait waits for the sender to finish; an error fails the test.
func (s *sender) wait(t testing.TB, within time.Duration) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(within):
		t.Fatalf("the sender did not finish within %v (%d bytes sent)", within, s.sent.Load())
	}
	if s.err != nil {
		t.Fatal(s.err)
	}
}

// finished reports whether the sender is done.
func (s *sender) finished() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// receiver is one direction's verified reader.
type receiver struct {
	name  string
	v     *rendrtest.Verifier
	size  int64
	start time.Time
	done  chan struct{}
	err   error // the verifier's verdict (nil: exactly size bytes, then io.EOF)
	got   atomic.Int64

	gate atomic.Pointer[chan struct{}] // set while paused: the reader waits for its close before its next Read
	stop chan struct{}                 // closed by the world's shutdown (pause registers it): a paused reader gives up

	mu  sync.Mutex
	at  []time.Time // when each Read that returned bytes returned
	cum []int64     // bytes received after that Read
}

// startReceiver reads c to its end through a verifier of size bytes of
// PRNG(seed). A size of openEnded checks every byte against PRNG(seed) and
// accepts io.EOF after any count (waitSent then compares the count with
// the sender's).
func startReceiver(name string, c *rendr.Conn, seed uint64, size int64) *receiver {
	want := size
	if size == openEnded {
		want = math.MaxInt64
	}
	r := &receiver{name: name, v: rendrtest.NewVerifier(seed, want), size: size, start: time.Now(), done: make(chan struct{}), stop: make(chan struct{})}
	go func() {
		defer close(r.done)
		buf := make([]byte, 64<<10)
		for {
			if g := r.gate.Load(); g != nil {
				select { // channels, not a lock: synctest sees the wait as durable
				case <-*g:
				case <-r.stop:
					r.err = fmt.Errorf("%s: stopped while paused", r.name)
					return
				}
			}
			n, err := c.Read(buf)
			if n > 0 {
				now := time.Now()
				if _, werr := r.v.Write(buf[:n]); werr != nil {
					r.err = r.v.Done(err)
					return
				}
				got := r.got.Add(int64(n))
				r.mu.Lock()
				r.at = append(r.at, now)
				r.cum = append(r.cum, got)
				r.mu.Unlock()
			}
			if err != nil {
				if r.size != openEnded || !errors.Is(err, io.EOF) {
					r.err = r.v.Done(err)
				}
				return
			}
		}
	}()
	return r
}

// pause stops the reader's application before its next Read (a Read in
// progress returns what it gets); resume lets it read again. The world's
// shutdown ends a paused reader.
func (w *world) pause(r *receiver) {
	w.addStop(r.stop)
	g := make(chan struct{})
	r.gate.Store(&g)
}

func (r *receiver) resume() {
	if g := r.gate.Swap(nil); g != nil {
		close(*g)
	}
}

// wait waits for the receiver's end; anything but exactly size verified
// bytes followed by io.EOF fails the test.
func (r *receiver) wait(t testing.TB, within time.Duration) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(within):
		t.Fatalf("%s: the receiver did not finish within %v (%d of %d bytes)", r.name, within, r.got.Load(), r.size)
	}
	if r.err != nil {
		t.Fatalf("integrity: %s: %v", r.name, r.err)
	}
}

// waitSent waits for an open-ended receiver's end, which must be io.EOF
// after exactly the bytes s sent, every one verified.
func (r *receiver) waitSent(t testing.TB, s *sender, within time.Duration) {
	t.Helper()
	r.wait(t, within)
	s.wait(t, within)
	if got, sent := r.got.Load(), s.sent.Load(); got != sent {
		t.Fatalf("integrity: %s: io.EOF after %d bytes, the sender wrote %d", r.name, got, sent)
	}
}

// finished reports whether the receiver ended.
func (r *receiver) finished() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// end returns the time of the last Read that returned bytes.
func (r *receiver) end() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.at) == 0 {
		return r.start
	}
	return r.at[len(r.at)-1]
}

// bytesAt returns the bytes received by time at.
func (r *receiver) bytesAt(at time.Time) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	i, found := slices.BinarySearchFunc(r.at, at, func(a, b time.Time) int { return a.Compare(b) })
	if found {
		for i+1 < len(r.at) && r.at[i+1].Equal(at) {
			i++
		}
		return r.cum[i]
	}
	if i == 0 {
		return 0
	}
	return r.cum[i-1]
}

// maxGap returns the longest interval in [from, to] without a Read that
// returned bytes (the ends count as Reads), and where it starts.
func (r *receiver) maxGap(from, to time.Time) (gap time.Duration, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	last := from
	for _, a := range r.at {
		if a.Before(from) || a.After(to) {
			continue
		}
		if g := a.Sub(last); g > gap {
			gap, at = g, last
		}
		last = a
	}
	if g := to.Sub(last); g > gap {
		gap, at = g, last
	}
	return gap, at
}

// firstAfter returns the first Read that returned bytes after at (zero:
// none).
func (r *receiver) firstAfter(at time.Time) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	i, _ := slices.BinarySearchFunc(r.at, at, func(a, b time.Time) int { return a.Compare(b) })
	for i < len(r.at) && !r.at[i].After(at) {
		i++
	}
	if i == len(r.at) {
		return time.Time{}
	}
	return r.at[i]
}

// closeBoth closes both ends of a session whose traffic ended and requires
// a clean end: both sessions end within Linger with io.EOF.
func closeBoth(t testing.TB, s pair) {
	t.Helper()
	s.d.Close()
	s.p.Close()
	timeout := time.After(30 * time.Second) // Linger
	for _, c := range []*rendr.Conn{s.d, s.p} {
		select {
		case <-c.Done():
		case <-timeout:
			t.Fatalf("session %s did not end within Linger: %+v", s.key, c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || !errors.Is(st.Err, io.EOF) {
			t.Fatalf("session %s: the %v ended %v with %v, want io.EOF", s.key, st.Role, st.State, st.Err)
		}
	}
}

// closeAll closes every session concurrently, each as closeBoth.
func closeAll(t testing.TB, ps []pair) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan string, 2*len(ps))
	for _, s := range ps {
		wg.Go(func() {
			s.d.Close()
			s.p.Close()
			timeout := time.After(30 * time.Second)
			for _, c := range []*rendr.Conn{s.d, s.p} {
				select {
				case <-c.Done():
				case <-timeout:
					errs <- fmt.Sprintf("session %s did not end within Linger: %+v", s.key, c.Status())
					return
				}
				if st := c.Status(); st.State != rendr.StateEnded || !errors.Is(st.Err, io.EOF) {
					errs <- fmt.Sprintf("session %s: the %v ended %v with %v, want io.EOF", s.key, st.Role, st.State, st.Err)
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if t.Failed() {
		t.FailNow()
	}
}

// echo moves n bytes of PRNG(seed) from the dialer to the passive and n
// bytes of PRNG(seed+1) back, both verified, the passive's first (a
// passive-first exchange needs the dialer's go frame on a view opened on
// a started shared carrier, M3-D8).
func echo(s pair, n int64, seed uint64) error {
	for _, dir := range []struct {
		from, to *rendr.Conn
		seed     uint64
	}{{s.p, s.d, seed + 1}, {s.d, s.p, seed}} {
		errc := make(chan error, 1)
		go func() {
			_, err := io.CopyN(struct{ io.Writer }{dir.from}, rendrtest.PRNG(dir.seed), n)
			errc <- err
		}()
		v := rendrtest.NewVerifier(dir.seed, n)
		if _, err := io.CopyN(v, dir.to, n); err != nil {
			return fmt.Errorf("session %s: reading %d bytes: %w (verifier %v)", s.key, n, err, v.Done(err))
		}
		if err := <-errc; err != nil {
			return fmt.Errorf("session %s: writing %d bytes: %w", s.key, n, err)
		}
	}
	return nil
}

// jain returns Jain's fairness index of xs: (Σx)² / (n Σx²), 1 for equal
// shares (and for no load at all).
func jain(xs []float64) float64 {
	var s, q float64
	for _, x := range xs {
		s += x
		q += x * x
	}
	if q == 0 {
		return 1
	}
	return s * s / (float64(len(xs)) * q)
}

// Packet traffic (as package race's kit, F8): a flow writes test datagrams
// (rendrtest.PacketPayload) on one PacketConn at a fixed rate in 10-ms
// send slots and reads them on another through a
// rendrtest.PacketVerifier, recording when WriteTo accepted each seq and
// when it first arrived. The reader reads into a buffer of MaxPayload + 1
// bytes (io.ErrShortBuffer there means rendr delivered more than its own
// limit) and every ReadFrom must report the session's RemoteAddr (L38).

// flowCfg configures a flow.
type flowCfg struct {
	name string // "<key> A → B" or "<key> B → A"
	seed uint64
	rate int // datagrams per second
	size int // bytes per datagram (0: 200)
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
		cfg.size = 200
	}
	f := &flow{cfg: cfg, w: wc, r: rc, v: rendrtest.NewPacketVerifier(cfg.seed), start: time.Now(),
		stop: make(chan struct{}), wdone: make(chan struct{}), rdone: make(chan struct{})}
	w.addStop(f.stop)
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

// lostOutside returns the accepted datagrams that never arrived and were
// written outside every window [from, to) of wins, and the lost ones in
// all.
func (f *flow) lostOutside(wins [][2]time.Time) (outside, lost int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, at := range f.wrote {
		if k < len(f.arrived) && !f.arrived[k].IsZero() {
			continue
		}
		lost++
		in := false
		for _, win := range wins {
			if !at.Before(win[0]) && at.Before(win[1]) {
				in = true
				break
			}
		}
		if !in {
			outside++
		}
	}
	return outside, lost
}

// firstArrivalAfter returns the arrival time of the first datagram written
// at or after at that arrived (zero: none).
func (f *flow) firstArrivalAfter(at time.Time) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, wt := range f.wrote {
		if wt.Before(at) || k >= len(f.arrived) || f.arrived[k].IsZero() {
			continue
		}
		return f.arrived[k]
	}
	return time.Time{}
}

// drops is the sum of a PacketCounters' send-side drop counters.
func drops(c *rendr.PacketCounters) uint64 {
	return c.DropQueue + c.DropAge + c.DropTooLarge + c.DropNoPath
}

// endPackets ends a packet session as F21: both flows stop; once every
// accepted datagram was sent or counted as a send-side drop and every
// datagram received was read, A (the dialer) closes; B reads until io.EOF,
// then closes; both sessions end within Linger with io.EOF. up is A → B,
// down B → A.
func endPackets(t testing.TB, s ppair, up, down *flow) {
	t.Helper()
	up.halt(t)
	down.halt(t)
	time.Sleep(time.Second)
	waitFor(t, 10*time.Second, s.key+": the accounting to settle", func() bool {
		ds, ps := s.d.Status().Packet, s.p.Status().Packet
		return ds.Sent+drops(ds) == uint64(up.accepted.Load()) && ps.Sent+drops(ps) == uint64(down.accepted.Load()) &&
			ps.Received == uint64(up.read.Load()) && ds.Received == uint64(down.read.Load())
	})
	s.d.Close()
	up.waitReader(t, 10*time.Second, io.EOF)
	s.p.Close()
	down.waitReader(t, 10*time.Second, net.ErrClosed)
	timeout := time.After(30 * time.Second) // Linger
	for _, c := range []*rendr.PacketConn{s.d, s.p} {
		select {
		case <-c.Done():
		case <-timeout:
			t.Fatalf("%s: a session did not end within Linger: %+v", s.key, c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || st.Err != io.EOF {
			t.Fatalf("%s: the %v session ended %v with %v, want io.EOF", s.key, st.Role, st.State, st.Err)
		}
	}
}
