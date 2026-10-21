package l4u

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Test datagrams: rendrtest.PacketPayload's 24-byte header (seq, send
// instant, length, CRC-32C) and a PRNG body of the ledger's seed, so a
// PacketVerifier proves every datagram's integrity and boundaries (L36),
// and the ledger dates every loss by its send instant.

// ledger tracks one direction of one flow: what was sent, when, and what
// arrived.
type ledger struct {
	name string
	seed uint64
	v    *rendrtest.PacketVerifier

	mu   sync.Mutex
	sent []time.Time // the send instant of seq (zero: not sent)
	arr  []time.Time // the first arrival of seq (zero: none yet)
	errs []error     // the verifier's first errors
	bad  int         // datagrams the verifier refused
	got  int         // distinct datagrams that arrived
	dups int         // datagrams that arrived again (arrivedAt; the verifier counts its own)
}

func newLedger(name string, seed uint64) *ledger {
	return &ledger{name: name, seed: seed, v: rendrtest.NewPacketVerifier(seed)}
}

// next builds the ledger's next datagram of size bytes in buf (sent at
// now) and records it as sent.
func (l *ledger) next(buf []byte, size int, now time.Time) []byte {
	l.mu.Lock()
	seq := uint64(len(l.sent))
	l.sent = append(l.sent, now)
	l.mu.Unlock()
	return rendrtest.PacketPayload(buf, l.seed, seq, size, now)
}

// mark records datagram seq as sent at at (an echo's copy, sent by the
// target when the original arrived).
func (l *ledger) mark(b []byte, at time.Time) {
	if len(b) < rendrtest.PacketHeaderLen {
		return
	}
	seq := binary.BigEndian.Uint64(b)
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq >= 1<<26 {
		return
	}
	for uint64(len(l.sent)) <= seq {
		l.sent = append(l.sent, time.Time{})
	}
	if l.sent[seq].IsZero() {
		l.sent[seq] = at
	}
}

// arrive verifies one received datagram.
func (l *ledger) arrive(b []byte, at time.Time) {
	err := l.v.Add(b, at)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.bad++
		if len(l.errs) < 4 {
			l.errs = append(l.errs, err)
		}
		return
	}
	l.arriveLocked(binary.BigEndian.Uint64(b), at)
}

// arriveLocked records the first arrival of seq; a later one is a
// duplicate.
func (l *ledger) arriveLocked(seq uint64, at time.Time) {
	for uint64(len(l.arr)) <= seq {
		l.arr = append(l.arr, time.Time{})
	}
	if !l.arr[seq].IsZero() {
		l.dups++
		return
	}
	l.arr[seq] = at
	l.got++
}

// sentAt records datagram seq as sent at at (a datagram whose format is
// its flow's own, not a test datagram).
func (l *ledger) sentAt(seq uint64, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for uint64(len(l.sent)) <= seq {
		l.sent = append(l.sent, time.Time{})
	}
	l.sent[seq] = at
}

// arrivedAt records the arrival of datagram seq whose integrity its flow's
// parser checked.
func (l *ledger) arrivedAt(seq uint64, at time.Time) {
	l.mu.Lock()
	l.arriveLocked(seq, at)
	l.mu.Unlock()
}

// sentCount returns how many datagrams were sent.
func (l *ledger) sentCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, at := range l.sent {
		if !at.IsZero() {
			n++
		}
	}
	return n
}

// arrived returns how many distinct datagrams arrived intact.
func (l *ledger) arrived() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.got
}

// loss is one datagram that never arrived.
type loss struct {
	seq  int
	sent time.Time
}

// losses returns the datagrams sent before until that never arrived.
func (l *ledger) losses(until time.Time) []loss { return l.lossesIn(time.Time{}, until) }

// lossesIn returns the datagrams sent in [from, until) that never arrived.
func (l *ledger) lossesIn(from, until time.Time) []loss {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []loss
	for seq, at := range l.sent {
		if at.IsZero() || at.Before(from) || !at.Before(until) {
			continue
		}
		if seq >= len(l.arr) || l.arr[seq].IsZero() {
			out = append(out, loss{seq, at})
		}
	}
	return out
}

// delays returns the one-way delay of every datagram sent in [from, to)
// that arrived, skipping those sent inside any of the windows.
func (l *ledger) delays(from, to time.Time, skip []window) []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []time.Duration
	for seq, at := range l.sent {
		if at.IsZero() || at.Before(from) || !at.Before(to) || seq >= len(l.arr) || l.arr[seq].IsZero() || inAny(skip, at) {
			continue
		}
		out = append(out, l.arr[seq].Sub(at))
	}
	return out
}

// firstArrivalFrom returns the first arrival of a datagram sent at or
// after t (zero: none).
func (l *ledger) firstArrivalFrom(t time.Time) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	var first time.Time
	for seq, at := range l.sent {
		if at.IsZero() || at.Before(t) || seq >= len(l.arr) || l.arr[seq].IsZero() {
			continue
		}
		if a := l.arr[seq]; first.IsZero() || a.Before(first) {
			first = a
		}
	}
	return first
}

// maxGap returns the longest interval within [a, b] in which none of the
// ledger's datagrams arrived (an interval may start at a or end at b): the
// arrival gap G10's interruption is measured by.
func maxGap(l *ledger, a, b time.Time) time.Duration {
	g, _ := maxGapAt(l, a, b)
	return g
}

// maxGapAt is maxGap and the instant the longest gap began.
func maxGapAt(l *ledger, a, b time.Time) (time.Duration, time.Time) {
	l.mu.Lock()
	var ts []time.Time
	for _, at := range l.arr {
		if !at.IsZero() && !at.Before(a) && !at.After(b) {
			ts = append(ts, at)
		}
	}
	l.mu.Unlock()
	slices.SortFunc(ts, time.Time.Compare)
	var g time.Duration
	var from time.Time
	prev := a
	for _, at := range append(ts, b) {
		if d := at.Sub(prev); d > g {
			g, from = d, prev
		}
		prev = at
	}
	return g, from
}

// gapsAbove returns, in time order, every interval within [a, b] longer
// than over in which none of the ledger's datagrams arrived (maxGap's
// intervals: one may start at a or end at b).
func gapsAbove(l *ledger, a, b time.Time, over time.Duration) []window {
	l.mu.Lock()
	var ts []time.Time
	for _, at := range l.arr {
		if !at.IsZero() && !at.Before(a) && !at.After(b) {
			ts = append(ts, at)
		}
	}
	l.mu.Unlock()
	slices.SortFunc(ts, time.Time.Compare)
	var out []window
	prev := a
	for _, at := range append(ts, b) {
		if at.Sub(prev) > over {
			out = append(out, window{prev, at})
		}
		prev = at
	}
	return out
}

// integrity requires that every datagram that arrived was intact and
// arrived once (PacketIntegrity: no corruption, no merged, split or
// truncated datagram, no duplicate).
func (l *ledger) integrity(t testing.TB) {
	t.Helper()
	r := l.v.Result()
	l.mu.Lock()
	bad, errs, dups := l.bad, l.errs, l.dups
	l.mu.Unlock()
	if bad != 0 || dups != 0 || r.Corrupt != 0 || r.BadSize != 0 || r.Duplicates != 0 {
		t.Fatalf("%s: integrity: %d refused (%v), %d duplicates, %+v", l.name, bad, errs, dups, r)
	}
}

// window is a closed interval [from, to] of send instants.
type window struct{ from, to time.Time }

func (w window) has(at time.Time) bool { return !at.Before(w.from) && !at.After(w.to) }

// inAny reports whether at is inside one of the windows.
func inAny(ws []window, at time.Time) bool {
	for _, w := range ws {
		if w.has(at) {
			return true
		}
	}
	return false
}

// lossesOutside fails when a datagram sent before until that never arrived
// was sent outside every window, and returns how many were lost inside.
func (l *ledger) lossesOutside(t testing.TB, until time.Time, ws []window, origin time.Time) int {
	t.Helper()
	return l.lossesOutsideIn(t, time.Time{}, until, ws, origin)
}

// lossesOutsideIn is lossesOutside for the datagrams sent in [from,
// until).
func (l *ledger) lossesOutsideIn(t testing.TB, from, until time.Time, ws []window, origin time.Time) int {
	t.Helper()
	ls := l.lossesIn(from, until)
	for _, x := range ls {
		if !inAny(ws, x.sent) {
			t.Fatalf("%s: seq %d, sent at +%v, was lost outside every window %v (%d lost in all)",
				l.name, x.seq, x.sent.Sub(origin), fmtWindows(ws, origin), len(ls))
		}
	}
	return len(ls)
}

// fmtWindows prints windows relative to origin.
func fmtWindows(ws []window, origin time.Time) string {
	s := "["
	for i, w := range ws {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("[%v, %v]", w.from.Sub(origin), w.to.Sub(origin))
	}
	return s + "]"
}

// gen sends rate datagrams per second from the ledger to wr on an
// absolute schedule (datagram k due at start + k/rate, of size
// sizes[k % len(sizes)]; the due ones leave together at each wake-up, at
// most one wake-up per millisecond) until until or quit. It counts the
// Write errors it saw.
type gen struct {
	done chan struct{}
	errs int
	err  error
}

func startGen(wr io.Writer, l *ledger, quit <-chan struct{}, rate float64, sizes []int, until time.Time) *gen {
	g := &gen{done: make(chan struct{})}
	go func() {
		defer close(g.done)
		start := time.Now()
		buf := make([]byte, slices.Max(sizes))
		step := time.Duration(float64(time.Second) / rate)
		for k := 0; ; {
			now := time.Now()
			for ; !start.Add(time.Duration(k) * step).After(now); k++ {
				if !now.Before(until) {
					return
				}
				if _, err := wr.Write(l.next(buf, sizes[k%len(sizes)], now)); err != nil {
					if g.errs++; g.err == nil {
						g.err = err
					}
				}
			}
			at := start.Add(time.Duration(k) * step)
			if floor := now.Add(time.Millisecond); at.Before(floor) {
				at = floor
			}
			if !pace(quit, at) {
				return
			}
		}
	}()
	return g
}

// wait waits for the generator; Write errors fail the test.
func (g *gen) wait(t testing.TB, name string) {
	t.Helper()
	<-g.done
	if g.errs != 0 {
		t.Fatalf("%s: %d Writes failed (first: %v)", name, g.errs, g.err)
	}
}

// reader reads datagrams from r until it fails and hands each to fn with
// its arrival instant; done closes after the read error.
type reader struct {
	done chan struct{}
	err  error
}

func startReader(r io.Reader, fn func(b []byte, at time.Time)) *reader {
	rd := &reader{done: make(chan struct{})}
	go func() {
		defer close(rd.done)
		buf := make([]byte, 64<<10)
		for {
			n, err := r.Read(buf)
			if err != nil {
				rd.err = err
				return
			}
			fn(buf[:n], time.Now())
		}
	}()
	return rd
}

// echoApp is a target application that answers every datagram with the
// same bytes and records each in up (nil: none).
func echoApp(up func(e *egress, b []byte, at time.Time)) targetApp {
	return func(e *egress) {
		buf := make([]byte, 64<<10)
		for {
			n, err := e.conn.Read(buf)
			if err != nil {
				return
			}
			if up != nil {
				up(e, buf[:n], time.Now())
			}
			e.conn.Write(buf[:n])
		}
	}
}

// hubCfg is the configuration of ingress hub i: a loopback socket of its
// own and room for 1,024 datagrams per client and direction.
func hubCfg(i int) rendrtest.UDPSocketHubConfig {
	return rendrtest.UDPSocketHubConfig{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(40000+i)), Queue: 1024}
}

// openEcho opens an echoed flow before its load starts: it sends the up
// ledger's first datagram (size bytes) on c and waits until its echo
// arrived, so that the row's load meets an open flow (the opening stage's
// own drops, DropOpenQueue and DropOpenAge, are the l4 rows' subject).
func openEcho(t testing.TB, c io.Writer, up, down *ledger, size int) {
	t.Helper()
	if _, err := c.Write(up.next(nil, size, time.Now())); err != nil {
		t.Fatalf("the first datagram: %v", err)
	}
	waitFor(t, 15*time.Second, up.name+": the first datagram's echo", func() bool { return down.arrived() >= 1 })
}
