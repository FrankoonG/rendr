package quic

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2"
	qgo "github.com/quic-go/quic-go"
)

// oversize is longer than any DATAGRAM frame quic-go accepts (16,383
// bytes): SendDatagram refuses it before queueing anything and reports its
// current limit. It is only read for its length.
var oversize [16384]byte

// datagramLimit returns the largest DATAGRAM payload quic-go accepts on qc
// now (pinned by TestDatagramLimitProbe_L37); an accepted oversize
// datagram, or a peer without DATAGRAM support, is an error.
func datagramLimit(qc *qgo.Conn) (int, error) {
	err := qc.SendDatagram(oversize[:])
	var tl *qgo.DatagramTooLargeError
	switch {
	case errors.As(err, &tl):
		return int(tl.MaxDatagramPayloadSize), nil
	case err == nil:
		return 0, errors.New("rendr/quic: an oversize DATAGRAM was accepted")
	}
	return 0, err
}

// probeLimit is the attach-time budget probe (a variable for tests).
var probeLimit = datagramLimit

// dgramConn is the DATAGRAM side of one QUIC connection as the
// net.PacketConn of a rendr datagram carrier with exactly one peer:
// ReadFrom always reports the same address value, WriteTo ignores its
// address. A pump goroutine drains quic-go's receive queue, which drops
// silently beyond 128 datagrams, into a bounded ingress queue that counts
// its drops (L46). A sender goroutine drains a bounded egress queue into
// SendDatagram, which blocks while quic-go holds 32 frames: rendr's writer
// never waits for QUIC's congestion control (R1-9).
type dgramConn struct {
	qc      *qgo.Conn
	peer    net.Addr // the value Dial returned or HandlePacket was given
	local   net.Addr
	release func(qgo.ApplicationErrorCode)
	sinks   []*Counters // Options.Counters and the Listener's
	max     atomic.Int64
	in      ingress
	out     egress
	pumped  chan struct{}
	sent    chan struct{}
	once    sync.Once
	// exitHook, set by a test before it closes the conn, runs as the pump
	// and the sender exit (the join test of Close).
	exitHook func()
}

func newDgramConn(qc *qgo.Conn, first []byte, limit int, release func(qgo.ApplicationErrorCode), o *Options, ls *Counters) *dgramConn {
	d := &dgramConn{qc: qc, peer: copyAddr(qc.RemoteAddr()), local: qc.LocalAddr(), release: release,
		pumped: make(chan struct{}), sent: make(chan struct{})}
	for _, c := range []*Counters{o.Counters, ls} {
		if c != nil {
			d.sinks = append(d.sinks, c)
		}
	}
	d.max.Store(int64(limit))
	d.in.ring, d.in.max, d.in.wake = make([][]byte, ingressInit), o.DatagramQueueBytes, make(chan struct{}, 1)
	d.out.max, d.out.wake = o.DatagramEgressBytes, make(chan struct{}, 1)
	if first != nil {
		d.in.push(first) // the datagram that classified the connection comes first
	}
	go d.pump()
	go d.send()
	return d
}

// cause returns the connection's close error when it has one, else err.
func (d *dgramConn) cause(err error) error {
	if c := context.Cause(d.qc.Context()); c != nil {
		err = c
	}
	return connErr(err)
}

func (d *dgramConn) drops(egress bool, n uint64) {
	for _, c := range d.sinks {
		if egress {
			c.EgressDrops.Add(n)
		} else {
			c.IngressDrops.Add(n)
		}
	}
}

// exit closes c, the pump's or the sender's exit signal.
func (d *dgramConn) exit(c chan struct{}) {
	if d.exitHook != nil {
		d.exitHook()
	}
	close(c)
}

func (d *dgramConn) pump() {
	defer d.exit(d.pumped)
	for {
		b, err := d.qc.ReceiveDatagram(d.qc.Context())
		if err != nil {
			d.in.fail(d.cause(err), false) // reported after the queued datagrams (L01)
			return
		}
		if !d.in.push(b) { // b moves to the queue: quic-go hands out a fresh slice
			d.drops(false, 1)
		}
	}
}

// send drains the egress queue, dropping a datagram older than egressAge;
// an error is kept for the next WriteTo: once for a too-large datagram
// (the budget shrinks), for good when the connection failed. At its exit
// the datagrams still queued are discarded and counted.
func (d *dgramConn) send() {
	defer d.exit(d.sent)
	defer d.discard()
	q, done := &d.out, d.qc.Context().Done()
	var cur []byte
	for {
		q.mu.Lock()
		q.give(cur) // the previous datagram's buffer: SendDatagram copied it, or it was dropped
		cur = nil
		for q.n == 0 && !q.closed {
			q.mu.Unlock()
			select {
			case <-q.wake:
			case <-done:
				q.setErr(d.cause(net.ErrClosed), true)
				return
			}
			q.mu.Lock()
		}
		if q.closed {
			q.mu.Unlock()
			return
		}
		at := q.slot(0).at
		cur = q.pop()
		q.mu.Unlock()
		if time.Since(at) > egressAge {
			d.drops(true, 1)
			continue
		}
		err := d.qc.SendDatagram(cur) // copies cur
		var tl *qgo.DatagramTooLargeError
		switch {
		case err == nil:
		case errors.As(err, &tl):
			if m := tl.MaxDatagramPayloadSize; m < d.max.Load() { // only the sender lowers it after attach
				d.max.Store(m)
			}
			q.setErr(&rendr.DatagramTooLargeError{Max: int(tl.MaxDatagramPayloadSize)}, false)
			d.drops(true, 1)
		default:
			q.setErr(d.cause(err), true)
			return
		}
	}
}

// ReadFrom returns the next datagram, copied (a short p truncates it like
// a Linux UDP socket; rendr reads with its budget + 1), and the peer.
func (d *dgramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	b, err := d.in.pop()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, b), d.peer, nil
}

// WriteTo queues a copy of p and returns at once (R1-9), dropping the
// queued datagrams older than egressAge and, while the queue is still full
// (egressMax datagrams or Options.DatagramEgressBytes of buffers), the
// oldest. A datagram above the connection's DATAGRAM limit is refused with
// a rendr.DatagramTooLargeError; an earlier datagram's error is returned
// instead of queueing p.
func (d *dgramConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	q, now := &d.out, time.Now()
	q.mu.Lock()
	switch err := q.err; {
	case !q.wdl.IsZero() && !now.Before(q.wdl):
		q.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	case err != nil:
		if !q.fatal {
			q.err = nil
		}
		q.mu.Unlock()
		return 0, err
	case int64(len(p)) > d.max.Load():
		q.mu.Unlock()
		return 0, &rendr.DatagramTooLargeError{Max: int(d.max.Load())}
	}
	b := append(q.take(), p...)
	var dropped uint64
	for ; q.n > 0 && (q.n == egressMax || q.bytes+cap(b) > q.max || now.Sub(q.slot(0).at) > egressAge); dropped++ {
		q.give(q.pop())
	}
	q.push(b, now)
	q.mu.Unlock()
	signal(q.wake)
	if dropped > 0 {
		d.drops(true, dropped)
	}
	return len(p), nil
}

// Close fails both queues, closes the connection once and joins the pump
// and the sender (a SendDatagram blocked in quic-go returns at the close);
// the datagrams still queued are discarded and counted in EgressDrops.
func (d *dgramConn) Close() error {
	d.once.Do(func() {
		d.in.fail(net.ErrClosed, true)
		d.out.mu.Lock()
		d.out.closed, d.out.err, d.out.fatal = true, net.ErrClosed, true
		d.out.mu.Unlock()
		signal(d.out.wake)
		d.release(codeClosed)
		<-d.pumped
		<-d.sent
		d.discard()
	})
	return nil
}

// discard drops the queued datagrams, which will never be sent (the
// sender exited), and counts them in EgressDrops: rendr counted them as
// sent. WriteTo queues nothing more: the sender exits only after Close or
// a fatal error, which every later WriteTo returns.
func (d *dgramConn) discard() {
	q := &d.out
	q.mu.Lock()
	n := uint64(q.n)
	for q.n > 0 {
		q.give(q.pop())
	}
	q.mu.Unlock()
	if n > 0 {
		d.drops(true, n)
	}
}

func (d *dgramConn) LocalAddr() net.Addr { return d.local }

func (d *dgramConn) SetDeadline(t time.Time) error {
	_ = d.SetReadDeadline(t)
	return d.SetWriteDeadline(t)
}

func (d *dgramConn) SetReadDeadline(t time.Time) error {
	d.in.mu.Lock()
	d.in.deadline = t
	d.in.mu.Unlock()
	signal(d.in.wake) // a blocked ReadFrom re-checks and passes the wake on when it returns
	return nil
}

func (d *dgramConn) SetWriteDeadline(t time.Time) error {
	d.out.mu.Lock()
	d.out.wdl = t
	d.out.mu.Unlock()
	return nil
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// egress is a connection's bounded send queue (R1-9): a ring that grows to
// egressMax slots and is released when drained, like the ingress ring. A
// slot holds a buffer only while its datagram is queued; up to egressSpare
// released buffers are kept for reuse, so a steady state copies without
// allocating and an idle queue keeps little memory. bytes counts the
// queued buffers' capacities (the memory held), bounded by max.
type egress struct {
	mu             sync.Mutex
	ring           []egressSlot // nil or a power of two of slots
	head, n, bytes int
	max            int // Options.DatagramEgressBytes
	spare          [egressSpare][]byte
	nspare         int
	wdl            time.Time
	err            error // for the next WriteTo; kept when fatal
	fatal, closed  bool
	wake           chan struct{}
}

type egressSlot struct {
	b  []byte
	at time.Time // when WriteTo queued it
}

// slot returns the k-th queued slot, oldest first (k < q.n); the ring's
// length is a power of two (egressInit, doubled).
func (q *egress) slot(k int) *egressSlot { return &q.ring[(q.head+k)&(len(q.ring)-1)] }

// push queues b, growing the ring (q.n < egressMax).
func (q *egress) push(b []byte, at time.Time) {
	if q.n == len(q.ring) {
		r := make([]egressSlot, max(2*q.n, egressInit))
		for i := range q.n {
			r[i] = *q.slot(i)
		}
		q.ring, q.head = r, 0
	}
	*q.slot(q.n) = egressSlot{b, at}
	q.n, q.bytes = q.n+1, q.bytes+cap(b)
}

// pop removes and returns the oldest datagram (q.n > 0); a drained ring
// above 4·egressInit slots is released.
func (q *egress) pop() []byte {
	s := q.slot(0)
	b := s.b
	*s = egressSlot{}
	q.head, q.n, q.bytes = (q.head+1)&(len(q.ring)-1), q.n-1, q.bytes-cap(b)
	if q.n == 0 && len(q.ring) > 4*egressInit {
		q.ring, q.head = nil, 0
	}
	return b
}

// take returns a released buffer, emptied, or nil (append allocates).
func (q *egress) take() []byte {
	if q.nspare == 0 {
		return nil
	}
	q.nspare--
	b := q.spare[q.nspare]
	q.spare[q.nspare] = nil
	return b[:0]
}

// give keeps a released buffer for reuse unless egressSpare are kept.
func (q *egress) give(b []byte) {
	if b != nil && q.nspare < egressSpare {
		q.spare[q.nspare] = b
		q.nspare++
	}
}

func (q *egress) setErr(err error, fatal bool) {
	q.mu.Lock()
	if !q.fatal {
		q.err, q.fatal = err, fatal
	}
	q.mu.Unlock()
}

// ingress is a connection's bounded receive queue (L46): tail drop by
// count and bytes, a read deadline, and a terminal error reported after
// the queued datagrams (L01).
type ingress struct {
	mu             sync.Mutex
	ring           [][]byte // grows to ingressMax; released when drained
	head, n, bytes int
	max            int
	deadline       time.Time
	err            error
	wake           chan struct{} // one waiter re-checks; one that returns passes it on
}

// push queues b unless the queue is full (false: a drop) or failed.
func (q *ingress) push(b []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch {
	case q.err != nil:
		return true // closed: discarded, not a drop
	case q.n == ingressMax || q.bytes+len(b) > q.max:
		return false
	case q.n == len(q.ring):
		r := make([][]byte, 2*q.n)
		for i := range q.n {
			r[i] = q.ring[(q.head+i)%q.n]
		}
		q.ring, q.head = r, 0
	}
	q.ring[(q.head+q.n)%len(q.ring)] = b
	q.n, q.bytes = q.n+1, q.bytes+len(b)
	signal(q.wake)
	return true
}

func (q *ingress) fail(err error, discard bool) {
	q.mu.Lock()
	if q.err == nil {
		q.err = err
	}
	if discard {
		clear(q.ring)
		q.n, q.bytes = 0, 0
	}
	q.mu.Unlock()
	signal(q.wake)
}

// pop returns the oldest datagram, else the terminal error, waiting until
// one exists or the read deadline passed. A passed deadline fails the call
// even with datagrams queued (as a socket's); the terminal error comes
// after the queued datagrams and before the deadline. Every reader shares
// the one deadline, so a waiter that returns passes the wake on.
func (q *ingress) pop() ([]byte, error) {
	var t *time.Timer
	defer func() {
		if t != nil {
			t.Stop()
		}
	}()
	for {
		q.mu.Lock()
		dl := q.deadline
		expired := !dl.IsZero() && !time.Now().Before(dl) // no clock read without a deadline
		if q.n > 0 && !expired {
			b := q.ring[q.head]
			q.ring[q.head] = nil
			q.head, q.n, q.bytes = (q.head+1)%len(q.ring), q.n-1, q.bytes-len(b)
			switch {
			case q.n > 0:
				signal(q.wake)
			case len(q.ring) > 4*ingressInit:
				q.ring, q.head = make([][]byte, ingressInit), 0 // a drained burst releases its ring
			}
			q.mu.Unlock()
			return b, nil
		}
		err := q.err
		if q.n > 0 || (err == nil && expired) { // q.n > 0: the deadline passed
			err = os.ErrDeadlineExceeded
		}
		q.mu.Unlock()
		if err != nil {
			signal(q.wake)
			return nil, err
		}
		var tc <-chan time.Time
		if !dl.IsZero() {
			if t == nil {
				t = time.NewTimer(time.Until(dl))
			} else {
				t.Reset(time.Until(dl))
			}
			tc = t.C
		}
		select {
		case <-q.wake:
		case <-tc:
		}
	}
}
