package quic

import (
	"encoding/binary"
	"testing"
	"testing/synctest"
	"time"
)

// stalledEgress returns a dgramConn whose egress sender never runs: the
// queue behaves as behind a sender blocked in SendDatagram, which is what
// quic-go's congestion control does while a steady flow is window-limited
// (R-F2). WriteTo needs no connection.
func stalledEgress(ctr *Counters) *dgramConn {
	d := &dgramConn{sinks: []*Counters{ctr}}
	d.max.Store(DatagramBudget)
	d.out.wake = make(chan struct{}, 1)
	return d
}

// queuedSeqs returns the sequence numbers of d's queued datagrams, oldest
// first, and the age of the oldest at now.
func queuedSeqs(d *dgramConn, now time.Time) (seqs []int, oldest time.Duration) {
	q := &d.out
	q.mu.Lock()
	defer q.mu.Unlock()
	for k := range q.n {
		s := q.slot(k)
		seqs = append(seqs, int(binary.BigEndian.Uint32(s.b)))
		if k == 0 {
			oldest = now.Sub(s.at)
		}
	}
	return seqs, oldest
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
		if d.out.bytes != held*size {
			t.Fatalf("queue bytes %d, want %d", d.out.bytes, held*size)
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
