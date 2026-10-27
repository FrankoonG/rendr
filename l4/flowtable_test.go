package l4

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// vsSock is a ServeUDP socket fed by the test: every datagram sent on in
// is one read; writes (the replies) are dropped.
type vsSock struct {
	in      chan vsDatagram
	stop    chan struct{}
	stopped sync.Once
}

type vsDatagram struct {
	b   []byte
	src netip.AddrPort
}

func newVSSock() *vsSock { return &vsSock{in: make(chan vsDatagram), stop: make(chan struct{})} }

func (s *vsSock) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	select {
	case d := <-s.in:
		return copy(b, d.b), d.src, nil
	case <-s.stop:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (s *vsSock) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) { return len(b), nil }

func (s *vsSock) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }

// SetReadDeadline: ServeUDP's stop sets one in the past; it ends the read.
func (s *vsSock) SetReadDeadline(time.Time) error {
	s.stopped.Do(func() { close(s.stop) })
	return nil
}

func (s *vsSock) Close() error { return s.SetReadDeadline(time.Time{}) }

// vsSession is a flow's session in the model of a DNS exchange: the
// query rides the OPEN, one answer comes back answerAfter after the open,
// and the flow is idle from then on until its idle limit (the flow's
// SetIdleTimeout) or a close.
type vsSession struct {
	answerAfter time.Duration
	closed      chan struct{}
	once        sync.Once
	idle        atomic.Int64
	answered    bool // the flow goroutine's
}

var vsMetadata = make([]byte, 1024) // longer than any bare metadata: the first datagram rode

func (s *vsSession) ReadFrom(b []byte) (int, net.Addr, error) {
	wait := s.answerAfter
	if s.answered {
		if wait = time.Duration(s.idle.Load()); wait <= 0 {
			<-s.closed
			return 0, nil, net.ErrClosed
		}
	}
	tm := time.NewTimer(wait)
	defer tm.Stop()
	select {
	case <-tm.C:
		if s.answered {
			return 0, nil, rendr.ErrIdleTimeout
		}
		s.answered = true
		return copy(b, "answer"), nil, nil
	case <-s.closed:
		return 0, nil, net.ErrClosed
	}
}

func (s *vsSession) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (s *vsSession) MaxPayload() int                           { return 1200 }
func (s *vsSession) SetIdleTimeout(d time.Duration) error {
	s.idle.Store(int64(d))
	return nil
}
func (s *vsSession) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}
func (s *vsSession) Done() <-chan struct{}       { return s.closed }
func (s *vsSession) Status() rendr.SessionStatus { return rendr.SessionStatus{} }
func (s *vsSession) Metadata() []byte            { return vsMetadata }

// vsSrc is the i-th client's source address (i < 2^24).
func vsSrc(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, byte(1 + i>>16), byte(i >> 8), byte(i)}), 40000)
}

// TestFlowTableVictimSampleUniform_L72 (M6-D29, O-1 (a); L72): the victim
// sample of a full table is uniform. G11-dns's burst, as measured on the
// pool: a 4,096-entry table (opening, open and held entries), about 2,000
// new one-shot flows per second, each answered once about 48 ms after its
// query (which rides the OPEN) and idle from then on, the DNS recipe's
// classes (10 s) and O-1 (a)'s 1-s floor. Every flow opened within the
// last 1.048 s is not a victim: about half the table. A uniform sample of
// 8 independent entries holds no victim with probability ≈ 0.5^8 ≈ 0.4 %,
// so at most 1 % of the newcomers that meet the full table may be
// DropFull. The first 8 entries of a Go map range from a random start are
// not independent (an evicted entry's place goes to a newcomer, never a
// victim for a second): 5.7–7.2 % on the pool, 4.9 % in a virtual-time
// model. Sessions are fakes (dialIngress), the clock synctest's: 3 s to
// fill the table, then 10 s judged (20,000 newcomers).
func TestFlowTableVictimSampleUniform_L72(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pfRule(t, promoteActive)
		const (
			table       = 4096
			perStep     = 4
			stepEvery   = 2 * time.Millisecond // 2,000 newcomers per second
			answerAfter = 48 * time.Millisecond
			fill, judge = 3 * time.Second, 10 * time.Second
			bound       = 0.01
		)
		old := dialIngress
		dialIngress = func(ctx context.Context, _ *rendr.Peer, _ string, _ []byte, _ rendr.DialOptions) (ingressSession, error) {
			return &vsSession{answerAfter: answerAfter, closed: make(chan struct{})}, nil
		}
		t.Cleanup(func() { dialIngress = old })
		sock := newVSSock()
		f := &PortForward{Peer: &rendr.Peer{}, MaxFlows: table, Idle: FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second}}
		ctx, cancel := context.WithCancel(context.Background())
		served := make(chan error, 1)
		go func() { served <- f.ServeUDP(ctx, sock, pfTarget) }()
		stopped := false
		defer func() {
			if !stopped {
				cancel()
				<-served
			}
		}()
		query := make([]byte, 40)
		next := 0
		run := func(d time.Duration) (sent int) {
			for end := time.Now().Add(d); time.Now().Before(end); {
				for range perStep {
					sock.in <- vsDatagram{b: query, src: vsSrc(next)}
					next++
					sent++
				}
				time.Sleep(stepEvery)
			}
			return sent
		}
		run(fill)
		st0 := pwStatus(f)
		n := run(judge)
		st1 := pwStatus(f)
		drops := st1.DropFull - st0.DropFull
		share := float64(drops) / float64(n)
		t.Logf("%d newcomers to the full table over %v: DropFull %d (%.2f %%), Evicted %d, ended idle %d; at the end %d open, %d opening, %d held",
			n, judge, drops, 100*share, st1.Evicted-st0.Evicted, st1.Ended.Idle-st0.Ended.Idle, st1.Flows, st1.Opening, st1.Held)
		// The premises: the table was full when the judged newcomers came,
		// and each of them opened or was DropFull (no open waited or failed).
		if entries := st0.Flows + st0.Opening + st0.Held; entries != table {
			t.Fatalf("premise: %d entries after %v, want the full table (%d): %s", entries, fill, table, pwDescribe(st0))
		}
		if st1.Opened-st0.Opened+drops != uint64(n) || st1.Failed != 0 || st1.DropOpening != 0 {
			t.Fatalf("premise: a newcomer neither opened nor met the full table: %s", pwDescribe(st1))
		}
		if share > bound {
			t.Fatalf("DropFull %d of %d newcomers (%.2f %%) with half the table evictable: the victim sample is not uniform (at most %.0f %%)",
				drops, n, 100*share, 100*bound)
		}
		pwUnits(t, f) // after about 22,000 evictions the dense entries still match the map
		cancel()
		stopped = true
		if err := <-served; err != context.Canceled {
			t.Fatalf("ServeUDP = %v", err)
		}
	})
}

// TestFlowTableVictimWholeSmallTable_L72 (M6-D29): a table of at most
// ingressSample entries is its own sample, so a full small table's victim
// is exact at every size and at every position of the entry that decides
// it. Around that entry: an open flow idle 2 s (under O-1 (a) a victim
// more recent than the wanted one), an opening flow and a stream idle 30 s
// (never victims), the rest idle 100 ms. Under O-1 (a) the least recently
// active open flow idle at least 1 s that is not a stream is the victim,
// and there is none when the deciding flow is idle just under 1 s; under
// the literal rule the held entry is, and an idle open flow is not.
// Independent draws from a table of n ≤ 8 entries would miss the wanted
// one in ((n−1)/n)^8 of the picks (34 % at 8).
func TestFlowTableVictimWholeSmallTable_L72(t *testing.T) {
	const now = time.Minute
	cases := []struct {
		name   string
		rule   promoteMode
		state  FlowState     // the deciding entry's
		idle   time.Duration // its idle time
		victim bool          // it is the victim (else there is none)
	}{
		{"O-1 (a): the least recently active idle flow", promoteActive, FlowOpen, 3 * time.Second, true},
		{"O-1 (a): idle just under 1 s", promoteActive, FlowOpen, ingressEvictIdle - time.Millisecond, false},
		{"literal: the held entry", promoteOnReply, FlowHeld, time.Millisecond, true},
		{"literal: an idle open flow", promoteOnReply, FlowOpen, 3 * time.Second, false},
	}
	for _, c := range cases {
		for n := 1; n <= ingressSample; n++ {
			for pos := range n {
				s := &udpServe{rule: c.rule}
				s.tab.m = make(map[netip.AddrPort]*ingressFlow)
				var want *ingressFlow
				for i := range n {
					e := &ingressFlow{client: vsSrc(i), state: FlowOpen}
					idle := 100 * time.Millisecond
					switch (i - pos + n) % n {
					case 0:
						e.state, idle = c.state, c.idle
						if c.victim {
							want = e
						}
					case 1:
						if c.victim {
							idle = 2 * time.Second
						}
					case 2:
						e.state, idle = FlowOpening, 30*time.Second
					case 3:
						idle = 30 * time.Second
						e.class.streamed.Store(true)
					}
					e.last.Store(int64(now - idle))
					s.tab.put(e)
				}
				for range 64 {
					if got := s.victim(now); got != want {
						t.Fatalf("%s, %d entries, the deciding one at %d: victim %v, want %v", c.name, n, pos, got, want)
					}
				}
				for _, e := range append([]*ingressFlow(nil), s.tab.all...) {
					s.tab.del(e)
				}
				if err := pwTableDense(&s.tab); err != nil || len(s.tab.m) != 0 {
					t.Fatalf("after removing every entry: %v, %d left", err, len(s.tab.m))
				}
			}
		}
	}
}
