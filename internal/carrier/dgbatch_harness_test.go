package carrier

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
)

// The batched datagram paths under the M2/M3 rows (M5 design W1.2, WP2:
// every M2/M3 datagram row green in both MaxBatch settings). The harness's
// in-memory transport (fakeIO) reaches its carriers through dgBatchOf in
// one of three settings:
//
//   - MaxBatch 32 (the default of carrier/udp): through fakeBatch — the
//     writer's flushes, the arena and the dialer reader's adaptive depth
//     with its idle release;
//   - MaxBatch 1: through fakeBatch, the batched code paths with one
//     datagram per call;
//   - off: as M2 wrote them (one ReadDatagram and one WriteDatagram per
//     datagram: the path of QUIC and embedder conns).
//
// A plain `go test` of the package runs every test in all three settings,
// one after the other (TestMain). RENDR_TEST_DGBATCH selects one: "off",
// or a MaxBatch of 1 … 64. Tests of their own transports (the WP2 rows)
// set what they need.
//
// Under -race (the race lane's 5-minute pass, M3 R1-23 lever 1 as M5 I1
// applies it) the settings after the first run only the tests that built
// the harness's transport in the first (dgNote; fuzz targets alike): every
// other test never reaches dgBatchOf's fakeIO branch, so a second and
// third run of it would repeat the first exactly. A transport built for no
// known test, or an explicit -test.run, keeps the plain behaviour, and
// TestMain says which applies. Without -race every setting runs every
// test.
var dgTestMaxBatch atomic.Int32

// dgSettings returns the settings TestMain runs: RENDR_TEST_DGBATCH's, or
// the default, 1 and off (0).
func dgSettings() []int {
	switch v := os.Getenv("RENDR_TEST_DGBATCH"); v {
	case "":
		return []int{DefaultMaxBatch, 1, 0}
	case "off":
		return []int{0}
	default:
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > udpsocket.MaxMsgs {
			panic("RENDR_TEST_DGBATCH: want off, or 1 … 64")
		}
		return []int{n}
	}
}

// dgSettingName names a setting in the output.
func dgSettingName(n int) string {
	if n == 0 {
		return "off"
	}
	return "MaxBatch " + strconv.Itoa(n)
}

// dgNoted are the top-level tests (and fuzz targets) that built the
// harness's transport during the first setting (dgNote); dgLost reports a
// build none of them is known for.
var (
	dgNotedMu sync.Mutex
	dgNoted   map[string]bool
	dgLost    atomic.Value // string: the first stack without a Test or Fuzz frame
)

// dgNote records the top-level test that builds a fakeIO pair: tb's, or
// without tb (a fuzz target's builder) the first carrier.Test… or
// carrier.Fuzz… function on the caller's stack. Only under -race and only
// while TestMain records (dgNoted non-nil); the race lane asserts no
// allocation gate.
func dgNote(tb testing.TB) {
	if !carrierRace {
		return
	}
	dgNotedMu.Lock()
	defer dgNotedMu.Unlock()
	if dgNoted == nil {
		return
	}
	if tb != nil {
		name, _, _ := strings.Cut(tb.Name(), "/")
		dgNoted[name] = true
		return
	}
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	var stack []string
	for {
		f, more := frames.Next()
		i := strings.Index(f.Function, "/internal/carrier.Test")
		if i < 0 {
			i = strings.Index(f.Function, "/internal/carrier.Fuzz")
		}
		if i >= 0 {
			name := f.Function[i+len("/internal/carrier."):]
			if j := strings.IndexByte(name, '.'); j >= 0 {
				name = name[:j]
			}
			dgNoted[name] = true
			return
		}
		stack = append(stack, f.Function)
		if !more {
			dgLost.CompareAndSwap(nil, strings.Join(stack, " < "))
			return
		}
	}
}

// dgLaterRun returns the -test.run pattern of the settings after the
// first under -race: the tests dgNote recorded; "" keeps every test, and
// why says why.
func dgLaterRun() (run, why string) {
	dgNotedMu.Lock()
	defer dgNotedMu.Unlock()
	switch lost, _ := dgLost.Load().(string); {
	case !carrierRace:
		return "", ""
	case lost != "":
		return "", "a transport built outside a Test function: " + lost
	case len(dgNoted) == 0:
		return "", "no test built the transport"
	case flag.Lookup("test.run").Value.String() != "":
		return "", "an explicit -test.run"
	}
	names := make([]string, 0, len(dgNoted))
	for n := range dgNoted {
		names = append(names, n)
	}
	slices.Sort(names)
	return "^(" + strings.Join(names, "|") + ")$", ""
}

func TestMain(m *testing.M) {
	base := dgBatchOf
	dgBatchOf = func(io PacketIO) BatchIO {
		if f, ok := io.(*fakeIO); ok {
			if n := int(dgTestMaxBatch.Load()); n > 0 {
				return newFakeBatch(f, n)
			}
		}
		return base(io)
	}
	code := 0
	for i, n := range dgSettings() {
		dgTestMaxBatch.Store(int32(n))
		switch {
		case i == 0 && carrierRace:
			dgNotedMu.Lock()
			dgNoted = map[string]bool{}
			dgNotedMu.Unlock()
		case i == 1:
			switch run, why := dgLaterRun(); {
			case run != "":
				flag.Set("test.run", run)
				fmt.Fprintf(os.Stderr, "carrier: -race: the later settings run the %d tests that built the harness's transport\n", strings.Count(run, "|")+1)
			case why != "":
				fmt.Fprintf(os.Stderr, "carrier: -race: the later settings run every test (%s)\n", why)
			}
			dgNotedMu.Lock()
			dgNoted = nil
			dgNotedMu.Unlock()
		}
		fmt.Fprintf(os.Stderr, "carrier: datagram rows with the harness transport at %s\n", dgSettingName(n))
		if c := m.Run(); c != 0 {
			fmt.Fprintf(os.Stderr, "carrier: FAIL at %s\n", dgSettingName(n))
			code = c
		}
	}
	os.Exit(code)
}

// The four states of fakeBatch.state: udpsocket.Reader's (R1-5).
const (
	fbIdle uint32 = iota
	fbHeld
	fbParked
	fbReleasing
)

// fakeBatch is a BatchIO and depthIO over a fakeIO: a batched write is one
// WriteDatagram per datagram, stopping at the first error, in one call; a
// read takes the first datagram as ReadDatagram does (waiting while the
// inbox is empty: a park while extras are held) and, at depth k, up to k−1
// more that are already queued (never waiting for them, L55), each into
// its own slot. Its ownership word follows udpsocket.Reader: held, parked
// while the first read waits, released by tryRelease only while parked;
// a read whose extras were released while it waited returns one datagram
// in slot 0.
type fakeBatch struct {
	*fakeIO
	mx atomic.Int32 // MaxBatch; setMax lowers it to 1 as a socket's fallback does (M5-D15)

	state  atomic.Uint32
	nparks atomic.Uint64
	// plainHold: at MaxBatch 1 a read that holds the extras reads slot 0
	// alone without parking, the extras left held — the weakest socket
	// fallback a transport may show (a read that started after the socket
	// stopped batching); dgReadDepth returns the extras before such a read.
	plainHold atomic.Bool
	relHdr    *ioHdr
	relFn     func(*ioHdr)
	res       [udpsocket.MaxMsgs]fbRes

	mu     sync.Mutex
	rcalls []int // the datagrams of each read call that moved any
	wcalls []int // the datagrams of each WriteDatagrams call
	parkAt []time.Time
	norec  bool // record nothing (the memory rows)
	lends  int  // successful lends of a new header

	// wfn scripts WriteDatagrams call number call (from 0): ds[:deliver]
	// are delivered, then err is returned with deliver; nil delivers all.
	// perDgram is waited before each datagram is delivered (a call's
	// duration on the fake clock).
	wfn      func(call int, ds [][]byte) (deliver int, err error)
	perDgram time.Duration
	report   func(n int) int // the count a call reports for the n it delivered (nil: n)
}

type fbRes struct {
	data []byte
	src  PeerKey
	ev   ReadEvent
}

func newFakeBatch(f *fakeIO, max int) *fakeBatch {
	a := &fakeBatch{fakeIO: f}
	a.mx.Store(int32(max))
	return a
}

func (a *fakeBatch) MaxBatch() int { return int(a.mx.Load()) }

// setMax changes MaxBatch while the carrier runs.
func (a *fakeBatch) setMax(n int) { a.mx.Store(int32(n)) }

func (a *fakeBatch) WriteDatagrams(ds [][]byte) (int, error) {
	a.mu.Lock()
	call := len(a.wcalls)
	if !a.norec {
		a.wcalls = append(a.wcalls, len(ds))
	}
	wfn, per, report := a.wfn, a.perDgram, a.report
	a.mu.Unlock()
	n, ret := len(ds), error(nil)
	if wfn != nil {
		n, ret = wfn(call, ds)
	}
	for i := range n {
		if per > 0 {
			time.Sleep(per)
		}
		if err := a.fakeIO.WriteDatagram(ds[i]); err != nil {
			return i, err
		}
	}
	if report != nil {
		return report(n), ret
	}
	return n, ret
}

// setReport sets the count lie.
func (a *fakeBatch) setReport(f func(n int) int) {
	a.mu.Lock()
	a.report = f
	a.mu.Unlock()
}

// setScript sets the write script.
func (a *fakeBatch) setScript(per time.Duration, wfn func(call int, ds [][]byte) (int, error)) {
	a.mu.Lock()
	a.perDgram, a.wfn = per, wfn
	a.mu.Unlock()
}

func (a *fakeBatch) ReadDatagrams(rs []ReadResult) (int, error) {
	data, src, ev, err := a.fakeIO.ReadDatagram(rs[0].buf.B)
	if err != nil {
		return 0, err
	}
	rs[0].Data, rs[0].Src, rs[0].Ev = data, src, ev
	return 1, nil
}

// waits reports whether a read would wait for the inbox now.
func (a *fakeBatch) waits() bool {
	f := a.fakeIO
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n == 0 && f.endless == 0 && f.hang == nil && !f.closed && (f.rdl.IsZero() || time.Until(f.rdl) > 0)
}

// queued reports whether the inbox's head is a datagram (not a scripted
// error or noise, which a batched read leaves for the next call).
func (a *fakeBatch) queued() bool {
	f := a.fakeIO
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == 0 || f.endless != 0 || f.hang != nil {
		return false
	}
	s := &f.ring[f.head]
	return s.err == nil && s.ev == ReadOK
}

func (a *fakeBatch) depthMax() int { return a.MaxBatch() }

func (a *fakeBatch) readDepth(slot0 *Buf, h *ioHdr) (int, ReadEvent, error) {
	clear(a.res[:]) // no reference to the previous call's slots
	ext := h != nil && a.state.Load() == fbHeld
	if ext && a.plainHold.Load() && a.MaxBatch() < 2 {
		ext = false // a plain read: slot 0, no park, the extras stay held
	} else if ext && a.waits() {
		a.nparks.Add(1)
		a.state.Store(fbParked)
		a.mu.Lock()
		if !a.norec {
			a.parkAt = append(a.parkAt, time.Now())
		}
		a.mu.Unlock()
	}
	data, src, ev, err := a.fakeIO.ReadDatagram(slot0.B)
	if ext && !a.state.CompareAndSwap(fbParked, fbHeld) && a.state.Load() != fbHeld {
		ext = false // released while it waited: slot 0 only
	}
	if err != nil {
		return 0, ReadOK, err
	}
	if ev == ReadNoise {
		return 0, ReadNoise, nil
	}
	a.res[0] = fbRes{data, src, ev}
	n := 1
	if ext && ev != ReadCandidate { // a call ends at its first candidate (BatchIO)
		for n < h.k && a.queued() {
			data, src, ev, err := a.fakeIO.ReadDatagram(h.slots[n].B)
			if err != nil || ev == ReadNoise {
				break // not expected: queued() saw a datagram
			}
			a.res[n] = fbRes{data, src, ev}
			n++
			if ev == ReadCandidate {
				break
			}
		}
	}
	a.mu.Lock()
	if !a.norec {
		a.rcalls = append(a.rcalls, n)
	}
	a.mu.Unlock()
	return n, ReadOK, nil
}

func (a *fakeBatch) result(i int) ([]byte, PeerKey, ReadEvent) {
	r := a.res[i]
	return r.data, r.src, r.ev
}

func (a *fakeBatch) lend(h *ioHdr) bool {
	if !a.state.CompareAndSwap(fbIdle, fbHeld) && a.state.Load() != fbHeld {
		return false
	}
	a.relHdr = h
	a.mu.Lock()
	a.lends++
	a.mu.Unlock()
	return true
}

// lendCount returns the successful lends.
func (a *fakeBatch) lendCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lends
}

func (a *fakeBatch) held() bool { return a.state.Load() == fbHeld }

func (a *fakeBatch) reclaim() bool {
	if !a.state.CompareAndSwap(fbHeld, fbIdle) {
		return false
	}
	a.relHdr = nil
	return true
}

func (a *fakeBatch) parks() uint64 { return a.nparks.Load() }

func (a *fakeBatch) holding() bool {
	s := a.state.Load()
	return s == fbHeld || s == fbParked
}

func (a *fakeBatch) tryRelease(seq uint64) bool {
	if a.nparks.Load() != seq || !a.state.CompareAndSwap(fbParked, fbReleasing) {
		return false
	}
	a.relFn(a.relHdr)
	a.relHdr = nil
	a.state.Store(fbIdle)
	return true
}

func (a *fakeBatch) onRelease(f func(*ioHdr)) { a.relFn = f }

// useBatch makes dgBatchOf return each of fbs for its fakeIO for the rest
// of the test (no carrier test runs in parallel).
func useBatch(t testing.TB, fbs ...*fakeBatch) {
	prev := dgBatchOf
	dgBatchOf = func(io PacketIO) BatchIO {
		for _, fb := range fbs {
			if f, ok := io.(*fakeIO); ok && f == fb.fakeIO {
				return fb
			}
		}
		return prev(io)
	}
	t.Cleanup(func() { dgBatchOf = prev })
}

// readCalls and writeCalls return the recorded calls.
func (a *fakeBatch) readCalls() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.rcalls...)
}

func (a *fakeBatch) writeCalls() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.wcalls...)
}

var (
	_ BatchIO = (*fakeBatch)(nil)
	_ depthIO = (*fakeBatch)(nil)
	_ depthIO = (*OwnedUDP)(nil)
)
