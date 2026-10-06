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
	d.in.ring, d.in.max, d.in.wake, d.out.wake = make([][]byte, 16), o.DatagramQueueBytes, make(chan struct{}, 1), make(chan struct{}, 1)
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

func (d *dgramConn) pump() {
	defer close(d.pumped)
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
// (the budget shrinks), for good when the connection failed.
func (d *dgramConn) send() {
	defer close(d.sent)
	q, done := &d.out, d.qc.Context().Done()
	var cur []byte
	for {
		q.mu.Lock()
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
		s := &q.slots[q.head]
		cur, s.b = s.b, cur[:0] // the slot keeps the sender's spare buffer
		at := s.at
		q.head, q.n, q.bytes = (q.head+1)%egressMax, q.n-1, q.bytes-len(cur)
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
// oldest queued datagram when the queue is full. A datagram above the
// connection's DATAGRAM limit is refused with a rendr.DatagramTooLargeError;
// an earlier datagram's error is returned instead of queueing p.
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
	var dropped uint64
	for ; q.n > 0 && (q.n == egressMax || q.bytes+len(p) > egressBytes); dropped++ {
		q.bytes -= len(q.slots[q.head].b)
		q.head, q.n = (q.head+1)%egressMax, q.n-1
	}
	s := &q.slots[(q.head+q.n)%egressMax]
	s.b, s.at = append(s.b[:0], p...), now
	q.n, q.bytes = q.n+1, q.bytes+len(p)
	q.mu.Unlock()
	signal(q.wake)
	if dropped > 0 {
		d.drops(true, dropped)
	}
	return len(p), nil
}

// Close fails both queues, closes the connection once and joins the pump
// and the sender (a SendDatagram blocked in quic-go returns at the close).
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
	})
	return nil
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
	signal(d.in.wake) // a blocked ReadFrom re-checks
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

// egress is a connection's bounded send queue (R1-9); slots keep their
// buffers, so a steady state copies without allocating.
type egress struct {
	mu    sync.Mutex
	slots [egressMax]struct {
		b  []byte
		at time.Time
	}
	head, n, bytes int
	wdl            time.Time
	err            error // for the next WriteTo; kept when fatal
	fatal, closed  bool
	wake           chan struct{}
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
	ring           [][]byte // grows to ingressMax
	head, n, bytes int
	max            int
	deadline       time.Time
	err            error
	wake           chan struct{}
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
// one exists or the read deadline passed. Every reader shares the one
// deadline, so a waiter that returns passes the wake on.
func (q *ingress) pop() ([]byte, error) {
	var t *time.Timer
	defer func() {
		if t != nil {
			t.Stop()
		}
	}()
	for {
		q.mu.Lock()
		if q.n > 0 {
			b := q.ring[q.head]
			q.ring[q.head] = nil
			q.head, q.n, q.bytes = (q.head+1)%len(q.ring), q.n-1, q.bytes-len(b)
			if q.n > 0 {
				signal(q.wake)
			}
			q.mu.Unlock()
			return b, nil
		}
		err, dl := q.err, q.deadline
		q.mu.Unlock()
		if err == nil && !dl.IsZero() && !time.Now().Before(dl) {
			err = os.ErrDeadlineExceeded
		}
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
