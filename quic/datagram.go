package quic

import (
	"context"
	"encoding/binary"
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

// carrierLimit is the largest datagram rendr may write on a connection
// whose DATAGRAM limit is n: the carrier's sequence number takes seqLen.
//
// quic-go's packer silently discards a queued DATAGRAM frame that does not
// fit a packet without an ACK, and SendDatagram admits by an estimate that
// never falls, while a path change resets the packet size to
// InitialPacketSize. A DATAGRAM of at most DatagramBudget+seqLen bytes
// fits a packet of that floor (1200 bytes, quicConfig) even with a 20-byte
// connection ID, so a datagram within the carrier's MTU (DatagramBudget,
// all rendr writes) is never discarded there; a larger one, admitted when
// the probed limit was higher, could be after a path change.
func carrierLimit(n int) int { return n - seqLen }

// polled is a cancelled context: ReceiveDatagram(polled) returns the head
// of quic-go's receive queue, or an error when the queue is empty - the
// pump's probe of an empty queue for rxSeq.
var polled = func() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}()

// dgramConn is the DATAGRAM side of one QUIC connection as the
// net.PacketConn of a rendr datagram carrier with exactly one peer:
// ReadFrom always reports the same address value, WriteTo ignores its
// address. A pump goroutine drains quic-go's receive queue, which drops
// silently beyond 128 datagrams, into a bounded ingress queue that counts
// its drops (L46); what quic-go's queue dropped while the pump lagged is
// counted from the gaps in the carrier's sequence numbers (KL-19, rxSeq).
// A sender goroutine drains a bounded egress queue into SendDatagram,
// which blocks while quic-go holds 32 frames: rendr's writer never waits
// for QUIC's congestion control (R1-9).
//
// Wire (versioned by the ALPN): every DATAGRAM payload is a 4-byte
// big-endian sequence number, then one datagram of rendr. Each direction
// numbers the datagrams its sender handed to quic-go, from 0 and by one
// (wrapping): one quic-go refused or the egress queue dropped takes no
// number. A DATAGRAM shorter than the sequence number violates the
// protocol and ends the connection (codeMalformed).
type dgramConn struct {
	qc      *qgo.Conn
	peer    net.Addr // the value Dial returned or HandlePacket was given
	local   net.Addr
	release func(qgo.ApplicationErrorCode)
	sinks   []*Counters // Options.Counters and the Listener's
	max     atomic.Int64
	in      ingress
	out     egress
	rx      rxSeq // the pump's (newDgramConn's before the pump starts)
	pumped  chan struct{}
	sent    chan struct{}
	once    sync.Once
	// exitHook, set by a test before it closes the conn, runs as the pump
	// and the sender exit (the join test of Close).
	exitHook func()
	// hold, set by a test, stops the pump before its next receive until
	// gate is closed or the connection ends: a stalled consumer.
	hold atomic.Pointer[pumpHold]
}

// pumpHold is a test's hold on a pump: parked is signalled when the pump
// stops at the hold, gate released.
type pumpHold struct{ gate, parked chan struct{} }

func newDgramConn(qc *qgo.Conn, first []byte, limit int, release func(qgo.ApplicationErrorCode), o *Options, ls *Counters) *dgramConn {
	d := &dgramConn{qc: qc, peer: copyAddr(qc.RemoteAddr()), local: qc.LocalAddr(), release: release,
		pumped: make(chan struct{}), sent: make(chan struct{})}
	for _, c := range []*Counters{o.Counters, ls} {
		if c != nil {
			d.sinks = append(d.sinks, c)
		}
	}
	d.max.Store(int64(limit)) // carrierLimit of quic-go's limit
	d.in.ring, d.in.max, d.in.wake = make([][]byte, ingressInit), o.DatagramQueueBytes, make(chan struct{}, 1)
	d.out.max, d.out.wake = o.DatagramEgressBytes, make(chan struct{}, 1)
	if first != nil {
		d.accept(first) // the datagram that classified the connection comes first (classify refused a short one)
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

// pump moves quic-go's received DATAGRAMs to the ingress queue. Like
// quic-go's own ReceiveDatagram, it takes the queue's head without waiting
// while there is one; it probes for an empty queue first (polled) only to
// tell rx before it waits (KL-19). rendr cannot prevent quic-go's drops:
// its 128-entry queue is fixed, and the pump never waits on rendr's
// consumer (the ingress queue drops and counts instead).
func (d *dgramConn) pump() {
	defer d.exit(d.pumped)
	ctx := d.qc.Context()
	for {
		if h := d.hold.Load(); h != nil {
			signal(h.parked)
			select {
			case <-h.gate:
			case <-ctx.Done():
			}
		}
		b, err := d.qc.ReceiveDatagram(polled)
		if err != nil { // the queue was empty (or the connection ended)
			d.rx.empty()
			b, err = d.qc.ReceiveDatagram(ctx)
		}
		if err != nil {
			d.in.fail(d.cause(err), false) // reported after the queued datagrams (L01)
			return
		}
		if !d.accept(b) {
			return
		}
	}
}

// accept takes one received DATAGRAM over: the gap its sequence number
// shows is counted when quic-go's queue may have dropped it (rxSeq), and
// the datagram moves to the ingress queue (quic-go hands out a fresh
// slice), or is dropped and counted when that queue is full. A DATAGRAM
// shorter than the sequence number fails the ingress queue after the
// datagrams already queued and closes the connection (invariant 6). Once
// the ingress queue failed (Close, or the connection ended) the carrier
// is over: nothing more is counted and the pump stops (false).
func (d *dgramConn) accept(b []byte) bool {
	if len(b) < seqLen {
		d.in.fail(errMalformed, false)
		d.release(codeMalformed)
		return false
	}
	gap := d.rx.take(binary.BigEndian.Uint32(b))
	full, closed := d.in.push(b[seqLen:])
	if closed {
		return false
	}
	if full {
		gap++
	}
	if gap > 0 {
		d.drops(false, gap)
	}
	return true
}

// rxSeq attributes the gaps in a direction's sequence numbers (KL-19).
// quic-go drops a received DATAGRAM only while its receive queue holds
// quicRcvQueue, every one of which arrived after the pump last found the
// queue empty; when DATAGRAMs arrive in order, the pump takes all of them
// before the datagram that shows the gap. So a gap shown while fewer than
// quicRcvQueue datagrams were taken since the pump last found the queue
// empty - and none since a run that reached quicRcvQueue - is no quic-go
// drop: the network lost or reordered those datagrams, which no counter
// claims. Any other gap, one shown during an overflow (lag: quic-go's
// queue may have been full), is counted in IngressDrops: a network loss
// and a quic-go drop leave the same gap. A
// datagram behind the next expected one (reordered) is delivered, counts
// nothing and leaves any lag to the datagram that shows the gap; the gap
// of a drop at the end of a burst is counted when the next datagram
// arrives.
//
// What the count means, in the words of Counters.IngressDrops and the
// README (one text): When DATAGRAMs arrive in order that count is exact,
// except that a datagram lost in the network during such an overflow
// counts too. On a path that reorders it is no bound: it can be too high
// (a datagram reordered during an overflow counts and is still delivered)
// or too low (a late datagram the full queue dropped after a later one
// was queued is missed, and once the queue has drained, a late datagram
// numbered above every one received hides the overflow's drops numbered
// above it). O(1) state cannot tell the reordered cases apart: in the
// first under-count the datagram that shows the drop's gap was taken
// before the lag began; in the second, the late datagram's own gap is
// counted, it ends the lag, and the drops numbered above it count nothing.
type rxSeq struct {
	next uint32 // the sequence number expected next
	run  int    // datagrams taken since the pump last found quic-go's queue empty
	lag  bool   // quic-go's queue may have been full since the last datagram taken in order
}

// empty records that the pump found quic-go's queue empty: a new run
// starts, and lag stays for the next datagram, which shows the gap of a
// drop at the end of the run.
func (s *rxSeq) empty() { s.run = 0 }

// take records the datagram numbered seq and returns the drops its gap
// shows.
func (s *rxSeq) take(seq uint32) uint64 {
	s.run++
	if gap := int32(seq - s.next); gap >= 0 {
		var n uint64
		if s.lag {
			n = uint64(gap)
		}
		s.next = seq + 1
		s.lag = s.run >= quicRcvQueue
		return n
	}
	s.lag = s.lag || s.run >= quicRcvQueue // a reordered datagram leaves the lag to the one that shows the gap
	return 0
}

// send drains the egress queue, dropping a datagram older than egressAge;
// an error is kept for the next WriteTo: once for a too-large datagram
// (the budget shrinks), for good when the connection failed. At its exit
// the datagrams still queued are discarded and counted. Each datagram is
// sent after its sequence number (sender.step); one dropped for its age
// is never numbered.
func (d *dgramConn) send() {
	defer d.exit(d.sent)
	defer d.discard()
	q, done := &d.out, d.qc.Context().Done()
	var cur []byte
	s := sender{framed: make([]byte, seqLen, seqLen+int(d.max.Load()))} // d.max only falls after attach
	sendDatagram := d.qc.SendDatagram
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
		switch tl, err := s.step(sendDatagram, cur); {
		case err == nil:
		case tl != nil:
			m := max(carrierLimit(int(tl.MaxDatagramPayloadSize)), 0)
			if int64(m) < d.max.Load() { // only the sender lowers it after attach
				d.max.Store(int64(m))
			}
			q.setErr(&rendr.DatagramTooLargeError{Max: m}, false)
			d.drops(true, 1)
		default:
			q.setErr(d.cause(err), true)
			return
		}
	}
}

// sender is the numbering state of a connection's send loop: the buffer
// each datagram is framed in after its sequence number (reused, since
// SendDatagram copies it), the number the next datagram quic-go accepts
// takes, and the target errors.As fills, which lives as long as the loop
// so that sending allocates nothing per datagram.
type sender struct {
	framed []byte
	seq    uint32
	tl     *qgo.DatagramTooLargeError
}

// step frames p after the next sequence number and hands it to send
// (quic-go's SendDatagram). A datagram send accepted takes the number
// (nil, nil). One it refused takes none: step returns the error, with the
// refusal when it is a quic-go DatagramTooLargeError (its limit now).
func (s *sender) step(send func([]byte) error, p []byte) (*qgo.DatagramTooLargeError, error) {
	binary.BigEndian.PutUint32(s.framed, s.seq)
	s.framed = append(s.framed[:seqLen], p...)
	switch err := send(s.framed); {
	case err == nil:
		s.seq++
		return nil, nil
	case errors.As(err, &s.tl):
		return s.tl, err
	default:
		return nil, err
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

// push queues b unless the queue is full (full: a drop) or failed
// (closed: discarded, not a drop).
func (q *ingress) push(b []byte) (full, closed bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch {
	case q.err != nil:
		return false, true
	case q.n == ingressMax || q.bytes+len(b) > q.max:
		return true, false
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
	return false, false
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
