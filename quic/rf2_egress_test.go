package quic

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	qgo "github.com/quic-go/quic-go"
)

// stalledEgress returns a dgramConn whose egress sender never runs: the
// queue behaves as behind a sender blocked in SendDatagram, which is what
// quic-go's congestion control does while a steady flow is window-limited
// (R-F2). WriteTo needs no connection.
func stalledEgress(ctr *Counters) *dgramConn {
	d := &dgramConn{sinks: []*Counters{ctr}}
	d.max.Store(DatagramBudget)
	d.out.max, d.out.wake = Options{}.norm().DatagramEgressBytes, make(chan struct{}, 1)
	return d
}

// queuedSeqs returns the sequence numbers of d's queued datagrams, oldest
// first, and the age of the oldest at now.
func queuedSeqs(d *dgramConn, now time.Time) (seqs []int, oldest time.Duration) {
	seqs, oldest, _ = queuedState(d, now)
	return seqs, oldest
}

// queuedState is queuedSeqs and whether the queue's byte count is the sum
// of its buffers' capacities.
func queuedState(d *dgramConn, now time.Time) (seqs []int, oldest time.Duration, bytesOK bool) {
	q := &d.out
	q.mu.Lock()
	defer q.mu.Unlock()
	held := 0
	for k := range q.n {
		s := q.slot(k)
		seqs = append(seqs, int(binary.BigEndian.Uint32(s.b)))
		held += cap(s.b)
		if k == 0 {
			oldest = now.Sub(s.at)
		}
	}
	return seqs, oldest, held == q.bytes
}

// TestQUICDatagramEgressHoldsAgeBound (R-F2): the egress queue holds what
// a G3-rate flow (10 kpps × 1000 bytes) writes during egressAge while its
// sender cannot send — quic-go's window-limited phases after a congestion
// cut last about a second at a rate 20–30 % short — so the age bound, not
// the count or byte bound, decides the drops. Beyond egressAge the queue
// keeps no datagram older than egressAge: WriteTo drops a stale head
// (counted), so a stalled sender holds at most egressAge of the writer's
// rate, and the queue releases its ring once drained.
func TestQUICDatagramEgressHoldsAgeBound(t *testing.T) {
	const (
		rate = 10000 // datagrams per second (G3's B → A rate)
		size = 1000
		gap  = time.Second / rate
	)
	held := int(egressAge / gap) // 2,500 datagrams written within egressAge
	synctest.Test(t, func(t *testing.T) {
		ctr := &Counters{}
		d := stalledEgress(ctr)
		write := func(seq int) {
			if n, err := d.WriteTo(seqDatagram(seq, size), nil); n != size || err != nil {
				t.Fatalf("WriteTo %d: %d, %v", seq, n, err)
			}
		}
		// Stimulus: egressAge of the G3 load, paced on the bubble's clock.
		for seq := range held {
			write(seq)
			time.Sleep(gap)
		}
		seqs, oldest := queuedSeqs(d, time.Now())
		if drops := ctr.EgressDrops.Load(); drops != 0 || len(seqs) != held {
			t.Fatalf("after %v at %d/s: %d of %d datagrams queued, %d egress drops; want all queued, 0 drops",
				egressAge, rate, len(seqs), held, drops)
		}
		for k, seq := range seqs { // integrity: every datagram once, in order
			if seq != k {
				t.Fatalf("queued datagram %d is seq %d", k, seq)
			}
		}
		if _, _, ok := queuedState(d, time.Now()); !ok || d.out.bytes < held*size || d.out.bytes > d.out.max {
			t.Fatalf("queue bytes %d: want the capacities of %d buffers of %d bytes, within %d", d.out.bytes, held, size, d.out.max)
		}
		t.Logf("%d datagrams (%d bytes) queued over %v, oldest %v", len(seqs), d.out.bytes, egressAge, oldest)

		// Load past the age bound: another egressAge of writes; the queue
		// never holds a datagram older than egressAge and stays bounded.
		for seq := held; seq < 2*held; seq++ {
			write(seq)
			time.Sleep(gap)
			if _, oldest := queuedSeqs(d, time.Now()); oldest > egressAge+gap {
				t.Fatalf("seq %d: the queue holds a datagram %v old (bound %v)", seq, oldest, egressAge)
			}
		}
		seqs, _ = queuedSeqs(d, time.Now())
		drops := ctr.EgressDrops.Load()
		if len(seqs) > held+1 || int(drops)+len(seqs) != 2*held {
			t.Fatalf("%d queued + %d dropped of %d written; want at most %d queued and every datagram counted",
				len(seqs), drops, 2*held, held+1)
		}
		for k, seq := range seqs { // the newest survive, contiguous
			if seq != 2*held-len(seqs)+k {
				t.Fatalf("queued datagram %d is seq %d; want the newest %d", k, seq, len(seqs))
			}
		}

		// Release: a drained queue gives its ring back.
		d.out.mu.Lock()
		for d.out.n > 0 {
			d.out.give(d.out.pop())
		}
		ring := len(d.out.ring)
		d.out.mu.Unlock()
		write(2 * held)
		d.out.mu.Lock()
		ring2 := len(d.out.ring)
		d.out.mu.Unlock()
		if ring2 > egressInit {
			t.Fatalf("after draining a ring of %d slots, the next datagram uses a ring of %d (want ≤ %d)", ring, ring2, egressInit)
		}
	})
}

// closableEgress is stalledEgress with what Close needs: no connection to
// release, and a pump and a sender that already exited.
func closableEgress(ctr *Counters) *dgramConn {
	d := stalledEgress(ctr)
	d.release = func(qgo.ApplicationErrorCode) {}
	d.in.wake = make(chan struct{}, 1)
	d.pumped, d.sent = make(chan struct{}), make(chan struct{})
	close(d.pumped)
	close(d.sent)
	return d
}

// TestQUICDatagramEgressCloseCounts (R-F2 review): the datagrams still
// queued when a carrier closes never reach QUIC, so Close counts them in
// EgressDrops (the loss is the close's, and the counter moves at the
// close). Stimulus: 300 datagrams queued behind a stalled sender, then
// Close. Load: every one of them counted once, nothing left queued, the
// ring released. Integrity: a WriteTo after Close fails with
// net.ErrClosed and queues nothing; a second Close counts nothing more.
func TestQUICDatagramEgressCloseCounts(t *testing.T) {
	const queued = 300
	ctr := &Counters{}
	d := closableEgress(ctr)
	for seq := range queued {
		if n, err := d.WriteTo(seqDatagram(seq, 1000), nil); n != 1000 || err != nil {
			t.Fatalf("WriteTo %d: %d, %v", seq, n, err)
		}
	}
	if seqs, _ := queuedSeqs(d, time.Now()); len(seqs) != queued || ctr.EgressDrops.Load() != 0 {
		t.Fatalf("before Close: %d queued, %d drops; want %d, 0", len(seqs), ctr.EgressDrops.Load(), queued)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if got := ctr.EgressDrops.Load(); got != queued {
		t.Fatalf("Close discarded %d queued datagrams and counted %d egress drops; want %d", queued, got, queued)
	}
	if n, err := d.WriteTo(seqDatagram(queued, 1000), nil); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close: %d, %v; want 0, net.ErrClosed", n, err)
	}
	_ = d.Close()
	d.out.mu.Lock()
	n, bytes, ring := d.out.n, d.out.bytes, len(d.out.ring)
	d.out.mu.Unlock()
	if n != 0 || bytes != 0 || ring > egressInit || ctr.EgressDrops.Load() != queued {
		t.Fatalf("after Close: %d queued (%d bytes), a ring of %d, %d drops; want an empty queue, at most %d slots, %d drops",
			n, bytes, ring, ctr.EgressDrops.Load(), egressInit, queued)
	}
}

// TestQUICDatagramEgressByteBound (R-F2 review): the egress queue's byte
// bound is the memory of its buffers, Options.DatagramEgressBytes (default
// egressBytes, clamped to at least DatagramBudget), and it binds before
// the count bound for datagrams of the full budget. Stimulus: egressMax
// writes of DatagramBudget bytes, and 200 writes of 1000 bytes under a
// 64-KiB option, at one instant (no age drop). Load: the queue holds
// exactly the buffers that fit the bound, below egressMax. Integrity: the
// newest datagrams, contiguous; queued + dropped = written; the byte count
// is the queued buffers' capacities.
func TestQUICDatagramEgressByteBound(t *testing.T) {
	for _, c := range []struct {
		opt, want int
	}{{0, egressBytes}, {-1, egressBytes}, {1, DatagramBudget}, {64 << 10, 64 << 10}} {
		if got := (Options{DatagramEgressBytes: c.opt}).norm().DatagramEgressBytes; got != c.want {
			t.Errorf("DatagramEgressBytes %d normalizes to %d, want %d", c.opt, got, c.want)
		}
	}
	for _, c := range []struct {
		name        string
		limit, size int
		writes      int
	}{
		{"default, full-budget datagrams", 0, DatagramBudget, egressMax},
		{"64 KiB option", 64 << 10, 1000, 200},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctr := &Counters{}
				d := stalledEgress(ctr)
				d.out.max = Options{DatagramEgressBytes: c.limit}.norm().DatagramEgressBytes
				for seq := range c.writes {
					if n, err := d.WriteTo(seqDatagram(seq, c.size), nil); n != c.size || err != nil {
						t.Fatalf("WriteTo %d: %d, %v", seq, n, err)
					}
				}
				seqs, _, ok := queuedState(d, time.Now())
				per := cap(append([]byte(nil), make([]byte, c.size)...)) // a buffer's capacity
				want := d.out.max / per
				drops := ctr.EgressDrops.Load()
				t.Logf("bound %d B, %d-B datagrams in %d-B buffers: %d queued (%d B), %d dropped", d.out.max, c.size, per, len(seqs), d.out.bytes, drops)
				if len(seqs) != want || want >= egressMax || !ok || d.out.bytes > d.out.max {
					t.Fatalf("%d queued (%d bytes, sum of capacities %v), want %d (< %d) within %d bytes", len(seqs), d.out.bytes, ok, want, egressMax, d.out.max)
				}
				if int(drops)+len(seqs) != c.writes {
					t.Fatalf("%d queued + %d dropped ≠ %d written", len(seqs), drops, c.writes)
				}
				for k, seq := range seqs {
					if seq != c.writes-len(seqs)+k {
						t.Fatalf("queued datagram %d is seq %d; want the newest %d", k, seq, len(seqs))
					}
				}
			})
		})
	}
}
