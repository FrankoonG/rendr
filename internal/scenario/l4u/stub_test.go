package l4u

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// One-shot query flows (G11-dns's load shape; TestL4UChurnNoResurrection_L47
// and TestL4UDNSChurnMiniature_L48_L72): each query from its own client
// socket (a stub resolver's), answered at once by the target, with a
// stub's retries at 1, 2 and 4 s on the same socket (a 7-s budget).

const (
	dnsPort      = 53
	dnsQuery     = 40  // a query's size (a test datagram)
	dnsAnswer    = 100 // an answer's size
	dnsQuerySeed = 0x5153
	dnsAnsSeed   = 0x414e
)

// dnsWaits are a stub's tries: try k is sent dnsWaits[k−1] after the first
// (the retries at 1, 2 and 4 s of G11-dns) and its answer awaited until
// dnsWaits[k] (the last until 7 s: the retry budget).
var dnsWaits = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 7 * time.Second}

// dnsStats is what an arm's stubs saw.
type dnsStats struct {
	first, retried, unanswered atomic.Int64
	bad                        atomic.Int64 // answers that were not the answer to the query
	maxTry                     atomic.Int64
}

// stub is one query: a client socket of its own sends the query, waits for
// its answer and retries (dnsWaits); it closes the socket after the answer
// or the last retry's wait.
func stub(in *ingress, src netip.AddrPort, seq uint64, st *dnsStats) {
	c := in.client(src)
	defer c.Close()
	q := rendrtest.PacketPayload(nil, dnsQuerySeed, seq, dnsQuery, time.Unix(0, int64(seq)))
	buf := make([]byte, 2048)
	start := time.Now()
	for try := range dnsWaits {
		if _, err := c.Write(q); err != nil {
			st.bad.Add(1)
			return
		}
		c.SetReadDeadline(start.Add(dnsWaits[try]))
		for {
			n, err := c.Read(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				st.bad.Add(1)
				return
			}
			if !isAnswer(buf[:n], seq) {
				st.bad.Add(1)
				continue
			}
			if try == 0 {
				st.first.Add(1)
			} else {
				st.retried.Add(1)
			}
			for m := st.maxTry.Load(); int64(try) > m && !st.maxTry.CompareAndSwap(m, int64(try)); m = st.maxTry.Load() {
			}
			return
		}
	}
	st.unanswered.Add(1)
}

// isAnswer reports whether b is the target's answer to query seq.
func isAnswer(b []byte, seq uint64) bool {
	if len(b) != dnsAnswer || binary.BigEndian.Uint64(b) != seq {
		return false
	}
	return bytes.Equal(b, rendrtest.PacketPayload(nil, dnsAnsSeed, seq, dnsAnswer, time.Unix(0, int64(seq))))
}

// dnsTarget answers every intact query at once with its answer, and
// records each flow's last datagram and the instant its egress closed.
func dnsTarget(ev *evictionLog) targetApp {
	return func(e *egress) {
		r := ev.open(e)
		buf := make([]byte, 64<<10)
		for {
			n, err := e.conn.Read(buf)
			if err != nil {
				ev.closed(r, time.Now())
				return
			}
			now := time.Now()
			ev.touch(r, now)
			if n != dnsQuery {
				continue
			}
			seq := binary.BigEndian.Uint64(buf)
			if !bytes.Equal(buf[:n], rendrtest.PacketPayload(nil, dnsQuerySeed, seq, dnsQuery, time.Unix(0, int64(seq)))) {
				continue
			}
			e.conn.Write(rendrtest.PacketPayload(nil, dnsAnsSeed, seq, dnsAnswer, time.Unix(0, int64(seq))))
			ev.touch(r, time.Now())
		}
	}
}

// evictionLog is the in-process EvictionJudge's record (R1-38): per flow
// at the target, its last datagram and its egress close.
type evictionLog struct {
	mu sync.Mutex
	rs []*egressRec
}

type egressRec struct {
	src         netip.AddrPort
	last, close time.Time
}

func (l *evictionLog) open(e *egress) *egressRec {
	r := &egressRec{src: e.src, last: time.Now()}
	l.mu.Lock()
	l.rs = append(l.rs, r)
	l.mu.Unlock()
	return r
}

func (l *evictionLog) touch(r *egressRec, at time.Time) {
	l.mu.Lock()
	r.last = at
	l.mu.Unlock()
}

func (l *evictionLog) closed(r *egressRec, at time.Time) {
	l.mu.Lock()
	r.close = at
	l.mu.Unlock()
}

// judge fails when an egress closed earlier than floor after its flow's
// last datagram, and returns how many closed before limit after it (the
// ends that preceded the idle limit: evictions, under a run that stops
// nothing). Every egress must have closed.
func (l *evictionLog) judge(t testing.TB, floor, limit time.Duration) int {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	early := 0
	for _, r := range l.rs {
		if r.close.IsZero() {
			t.Fatalf("EvictionJudge: the egress %v never closed", r.src)
		}
		d := r.close.Sub(r.last)
		if d < floor {
			t.Fatalf("EvictionJudge: the egress %v closed %v after its last datagram, want at least %v (an eviction of a flow idle less than 1 s)", r.src, d, floor)
		}
		if d < limit {
			early++
		}
	}
	return early
}
