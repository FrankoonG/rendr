package rendrtest

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Connected-datagram fakes for package l4's UDP flows and their scenario
// tests (M6 design §A2.3, M6-D36): DatagramPipe, an in-memory connected
// datagram conn pair, stands in for the passive's egress socket and for a
// local conn of ForwardPacket; UDPSocketHub (udphub.go) is an in-memory
// unconnected socket with many clients, structurally an l4.UDPSocket.
//
// Both are built from one mutex per pipe or hub, one sync.Cond per reader
// queue on that mutex, and timers created and re-armed by the reader, so a
// goroutine blocked in them is durably blocked inside a testing/synctest
// bubble (use a pipe or hub inside one bubble, or outside every bubble).
// Neither starts a goroutine: a datagram's arrival time is computed when
// it is written. A datagram is copied once, at the Write, into a buffer of
// the smallest size class that holds it (2, 16 or 64 KiB), recycled per
// pipe or hub; each class keeps up to 256 freed buffers, so steady-state
// I/O allocates nothing while no more than 256 datagrams of one class are
// buffered at once, whatever the other classes did before (the allocation
// gates of l4's forwarding run on them); a datagram above 64 KiB is
// allocated per copy. Their own errors are *net.OpError values wrapping
// net.ErrClosed, os.ErrDeadlineExceeded or ErrMsgSize, as a real socket's;
// injected errors are returned as given.

// Defaults and bounds of the datagram fakes.
const (
	defaultDpQueue = 256 // datagrams per queue
	dpRecycleMax   = 256 // freed buffers kept per size class
)

// dpClasses are the buffer sizes of the datagram copies: each copy is made
// into a buffer of the smallest class that holds it, so a burst of one
// size never leaves a free list another size cannot use.
var dpClasses = [...]int{2 << 10, 16 << 10, 64 << 10}

// dpClass returns the index of the smallest class of at least n bytes, or
// -1 above the largest.
func dpClass(n int) int {
	for k, c := range dpClasses {
		if n <= c {
			return k
		}
	}
	return -1
}

// dpNet is what a DatagramPipe or a UDPSocketHub shares: the lock over all
// of its state and the freed datagram buffers of each class.
type dpNet struct {
	mu   sync.Mutex
	free [len(dpClasses)][][]byte
}

// clone returns a copy of b in a buffer of its class, a freed one when
// there is one. n.mu held.
func (n *dpNet) clone(b []byte) []byte {
	k := dpClass(len(b))
	if k < 0 {
		return append(make([]byte, 0, len(b)), b...)
	}
	var c []byte
	if f := n.free[k]; len(f) > 0 {
		c = f[len(f)-1][:len(b)]
		f[len(f)-1] = nil
		n.free[k] = f[:len(f)-1]
	} else {
		c = make([]byte, len(b), dpClasses[k])
	}
	copy(c, b)
	return c
}

// recycle keeps b, a buffer clone returned, for a later datagram of its
// class. n.mu held.
func (n *dpNet) recycle(b []byte) {
	if k := dpClass(cap(b)); k >= 0 && cap(b) == dpClasses[k] && len(n.free[k]) < dpRecycleMax {
		n.free[k] = append(n.free[k], b[:0])
	}
}

// dpItem is one datagram in a queue.
type dpItem struct {
	b    []byte
	due  time.Time      // its arrival; zero: at once
	src  netip.AddrPort // a hub socket's queue: the client's source
	from *DatagramConn  // a hub socket's queue: the client whose bound it counts against
}

// dpQueue is the datagrams toward one reader in arrival order (a ring),
// with the reader's wake-ups: a condition on the net's lock and timers for
// the head's arrival and for the read deadline. Every method runs with the
// net's lock held, except wakeup, which takes it.
type dpQueue struct {
	ring    []dpItem
	head, n int
	cond    sync.Cond
	rdl     time.Time
	dueTm   *time.Timer
	dlTm    *time.Timer
}

func (q *dpQueue) push(it dpItem) {
	if q.n == len(q.ring) {
		r := make([]dpItem, max(8, 2*len(q.ring)))
		for i := range q.n {
			r[i] = q.ring[(q.head+i)%len(q.ring)]
		}
		q.ring, q.head = r, 0
	}
	q.ring[(q.head+q.n)%len(q.ring)] = it
	q.n++
}

func (q *dpQueue) pop() dpItem {
	it := q.ring[q.head]
	q.ring[q.head] = dpItem{}
	q.head = (q.head + 1) % len(q.ring)
	q.n--
	return it
}

// ready reports whether the head has arrived by now.
func (q *dpQueue) ready(now time.Time) bool {
	return q.n > 0 && !q.ring[q.head].due.After(now)
}

// expired reports whether the read deadline has passed at now.
func (q *dpQueue) expired(now time.Time) bool {
	return !q.rdl.IsZero() && !now.Before(q.rdl)
}

// wait blocks until something may have changed for the reader: a datagram
// or an injection, the head's arrival, the read deadline, a Close.
func (q *dpQueue) wait(now time.Time) {
	if q.n > 0 {
		if d := q.ring[q.head].due.Sub(now); d > 0 {
			q.arm(&q.dueTm, d)
		}
	}
	q.cond.Wait()
}

// setDeadline sets the read deadline and wakes the readers, so that a
// waiting read honours it at once.
func (q *dpQueue) setDeadline(t time.Time) {
	q.rdl = dpFix(t)
	stopTimer(q.dlTm)
	if !q.rdl.IsZero() {
		if d := time.Until(q.rdl); d > 0 {
			q.arm(&q.dlTm, d)
		}
	}
	q.cond.Broadcast()
}

// dpFix returns deadline t fixed against the runtime clock, as net.Conn
// fixes a deadline when it is set: a time without a monotonic reading
// (from time.Unix, Round(0), UTC, In) is turned into the same instant with
// one, so a later wall-clock step moves neither the timer nor the expiry
// check. The zero time stays zero; inside a synctest bubble, whose clock
// has no monotonic reading and no steps, t is returned as the same instant.
func dpFix(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	now := time.Now()
	return now.Add(t.Sub(now))
}

// arm makes *tm wake the readers after d; the timer is created once and
// re-armed afterwards.
func (q *dpQueue) arm(tm **time.Timer, d time.Duration) {
	if *tm == nil {
		*tm = time.AfterFunc(d, q.wakeup)
		return
	}
	(*tm).Reset(d)
}

func (q *dpQueue) wakeup() {
	q.cond.L.Lock()
	q.cond.Broadcast()
	q.cond.L.Unlock()
}

// drain discards every queued datagram and returns how many there were;
// it stops the timers and wakes the readers (the queue's owner ended).
func (q *dpQueue) drain(n *dpNet) uint64 {
	k := uint64(q.n)
	for q.n > 0 {
		it := q.pop()
		if it.from != nil {
			it.from.up--
		}
		n.recycle(it.b)
	}
	q.ring, q.head = nil, 0
	stopTimer(q.dueTm)
	stopTimer(q.dlTm)
	q.cond.Broadcast()
	return k
}

// DatagramPipeConfig configures NewDatagramPipe; zero values take defaults.
type DatagramPipeConfig struct {
	Queue        int           // datagrams buffered per direction, in flight under Delay or arrived and unread (256); more are dropped and counted, as netem's limit drops
	Trunc        TruncMode     // a Read into a shorter buffer: TruncLinux (n = len(b), the rest discarded) or TruncWindows (ErrMsgSize, buffer filled)
	Loss, Dup    float64       // per datagram and direction, from Seed
	Delay        time.Duration // one-way, both directions
	Seed         uint64        // seeds Loss and Dup (one PCG stream per direction)
	AddrA, AddrB net.Addr      // what each end reports as LocalAddr (documentation addresses by default)
}

// TruncMode is how a DatagramConn's Read reports a datagram longer than
// its buffer.
type TruncMode uint8

// Truncation modes.
const (
	TruncLinux   TruncMode = iota // n = len(b), nil error, the rest discarded (a Linux UDP socket)
	TruncWindows                  // n = len(b), ErrMsgSize, the rest discarded (a Windows UDP socket)
)

// ErrMsgSize is the running OS's "message too long" errno (EMSGSIZE;
// WSAEMSGSIZE on Windows), as TruncWindows returns it.
var ErrMsgSize error = errMsgSize

// DatagramConnCounts are a DatagramConn's counters (DatagramCounts, the
// older type, counts the carriers of a DatagramLink or DatagramHub).
type DatagramConnCounts struct {
	In        uint64 // datagrams this end's Reads returned
	Out       uint64 // datagrams this end's Writes sent
	Dropped   uint64 // datagrams toward this end dropped: a full queue, Loss, still queued at a Close
	Truncated uint64 // Reads that returned a datagram longer than their buffer
	Injected  uint64 // Reads and Writes that returned an injected error
}

func (a DatagramConnCounts) plus(b DatagramConnCounts) DatagramConnCounts {
	return DatagramConnCounts{In: a.In + b.In, Out: a.Out + b.Out, Dropped: a.Dropped + b.Dropped,
		Truncated: a.Truncated + b.Truncated, Injected: a.Injected + b.Injected}
}

// dpPipe is the shared state of a DatagramPipe's two ends.
type dpPipe struct {
	dpNet
	queue     int
	delay     time.Duration
	loss, dup float64
	shut      bool // an end was closed: every later call of both ends fails
	ends      [2]*DatagramConn
}

// Default LocalAddrs of a DatagramPipe's ends: documentation addresses.
var (
	dpAddrA = netip.MustParseAddrPort("192.0.2.1:40000")
	dpAddrB = netip.MustParseAddrPort("198.51.100.1:50000")
)

// NewDatagramPipe returns the two ends of an in-memory connected datagram
// conn: each Write is one datagram delivered whole to the other end's next
// Read; deadlines as net.Conn; Close makes both ends' later calls return
// net.ErrClosed.
//
// A Write never blocks. Each datagram is copied (the caller may reuse its
// buffer at once), then passes seeded loss and duplication (a duplicate
// arrives right behind its original; one that does not fit is never
// made), the receiving direction's Queue bound (a full queue drops it) and
// Delay; datagrams arrive in the order they were written. The bound counts
// the datagrams still in flight under Delay as well as the arrived unread
// ones, as netem's limit does, so it also bounds the memory of a fast
// writer: a reader that keeps up still loses datagrams when rate × Delay
// exceeds Queue, and a row with Delay sizes Queue ≥ rate × Delay plus the
// reader's backlog. Every datagram toward an end is either read, counted
// Dropped at that end, or still queued. A Read into an empty buffer
// returns (0, nil) at once and consumes nothing, as the net package's
// does on Unix; zero-length datagrams are delivered as such. Loss and Dup are
// drawn from two PCG streams seeded by Seed, one per direction: equal
// configurations give equal fates for equal write sequences. The default
// addresses are *net.UDPAddr values (192.0.2.1:40000 for a, 198.51.100.1:
// 50000 for b), so a check for a "udp" LocalAddr accepts the ends; each
// end's RemoteAddr is the other's LocalAddr.
func NewDatagramPipe(cfg DatagramPipeConfig) (a, b *DatagramConn) {
	p := &dpPipe{queue: cfg.Queue, delay: max(cfg.Delay, 0), loss: cfg.Loss, dup: cfg.Dup}
	if p.queue <= 0 {
		p.queue = defaultDpQueue
	}
	la, lb := cfg.AddrA, cfg.AddrB
	if la == nil {
		la = net.UDPAddrFromAddrPort(dpAddrA)
	}
	if lb == nil {
		lb = net.UDPAddrFromAddrPort(dpAddrB)
	}
	s := cfg.Seed
	a = &DatagramConn{n: &p.dpNet, pipe: p, laddr: la, raddr: lb, trunc: cfg.Trunc,
		rng: rand.New(rand.NewPCG(s, s^0x9e3779b97f4a7c15))}
	b = &DatagramConn{n: &p.dpNet, pipe: p, laddr: lb, raddr: la, trunc: cfg.Trunc,
		rng: rand.New(rand.NewPCG(s^1, s^0x7f4a7c159e3779b9))}
	a.peer, b.peer = b, a
	a.rx.cond.L, b.rx.cond.L = &p.mu, &p.mu
	p.ends = [2]*DatagramConn{a, b}
	return a, b
}

// send delivers one datagram written by end c to its peer. p.mu held.
func (p *dpPipe) send(c *DatagramConn, b []byte, now time.Time) {
	dst := c.peer
	if p.loss > 0 && c.rng.Float64() < p.loss {
		dst.ctr.Dropped++
		return
	}
	copies := 1
	if p.dup > 0 && c.rng.Float64() < p.dup {
		copies = 2
	}
	due := now.Add(p.delay)
	for i := range copies {
		if dst.rx.n >= p.queue { // tail drop; a duplicate that does not fit is never made
			if i == 0 {
				dst.ctr.Dropped++
			}
			break
		}
		dst.rx.push(dpItem{b: p.clone(b), due: due})
	}
	dst.rx.cond.Broadcast()
}

// close shuts both ends: their queued datagrams are dropped and counted,
// their readers woken. p.mu held.
func (p *dpPipe) close() {
	if p.shut {
		return
	}
	p.shut = true
	for _, e := range p.ends {
		e.ctr.Dropped += e.rx.drain(&p.dpNet)
	}
	p.free = [len(dpClasses)][][]byte{}
}

// DatagramConn is one end of a DatagramPipe, or a UDPSocketHub client: a
// connected datagram net.Conn.
type DatagramConn struct {
	n            *dpNet
	rx           dpQueue // datagrams toward this end
	laddr, raddr net.Addr
	trunc        TruncMode
	closed       bool // this end's Close was called
	wdl          time.Time
	rerr         error // the injected read error, if any
	rpersist     bool
	werr         error // the injected write error, for the next wleft Writes
	wleft        int
	ctr          DatagramConnCounts

	// A pipe end.
	pipe *dpPipe
	peer *DatagramConn
	rng  *rand.Rand // the fates of this end's datagrams

	// A hub client.
	hub *UDPSocketHub
	src netip.AddrPort
	up  int // its datagrams queued toward the hub's socket
}

var _ net.Conn = (*DatagramConn)(nil)

// ended reports whether the conn's calls fail with net.ErrClosed. n.mu
// held.
func (c *DatagramConn) ended() bool {
	return c.closed || c.pipe != nil && c.pipe.shut
}

func (c *DatagramConn) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "udp", Source: c.laddr, Addr: c.raddr, Err: err}
}

// Read returns the next datagram (TruncMode decides a shorter buffer).
// It checks, in order: Close, an empty b (0, nil at once), the read
// deadline (also when a datagram is waiting, as net.Conn), an injected
// error (which consumes no datagram), then the next arrived datagram;
// otherwise it waits for one of them.
func (c *DatagramConn) Read(b []byte) (int, error) {
	c.n.mu.Lock()
	defer c.n.mu.Unlock()
	q := &c.rx
	for {
		now := time.Now()
		switch {
		case c.ended():
			return 0, c.opErr("read", net.ErrClosed)
		case len(b) == 0:
			return 0, nil
		case q.expired(now):
			return 0, c.opErr("read", os.ErrDeadlineExceeded)
		case c.rerr != nil:
			err := c.rerr
			if !c.rpersist {
				c.rerr = nil
			}
			c.ctr.Injected++
			return 0, err
		case q.ready(now):
			it := q.pop()
			k := copy(b, it.b)
			c.ctr.In++
			var err error
			if len(it.b) > len(b) {
				c.ctr.Truncated++
				if c.trunc == TruncWindows {
					err = c.opErr("read", os.NewSyscallError("wsarecv", ErrMsgSize))
				}
			}
			c.n.recycle(it.b)
			return k, err
		}
		q.wait(now)
	}
}

// Write sends b as one datagram. It never blocks; it fails after Close,
// past the write deadline, or with an injected error (sending nothing).
func (c *DatagramConn) Write(b []byte) (int, error) {
	c.n.mu.Lock()
	defer c.n.mu.Unlock()
	now := time.Now()
	switch {
	case c.ended():
		return 0, c.opErr("write", net.ErrClosed)
	case !c.wdl.IsZero() && !now.Before(c.wdl):
		return 0, c.opErr("write", os.ErrDeadlineExceeded)
	case c.wleft > 0:
		err := c.werr
		if c.wleft--; c.wleft == 0 {
			c.werr = nil
		}
		c.ctr.Injected++
		return 0, err
	}
	c.ctr.Out++
	if c.hub != nil {
		c.hub.fromClient(c, b)
	} else {
		c.pipe.send(c, b, now)
	}
	return len(b), nil
}

// Close closes the conn; later calls of both ends return net.ErrClosed. A
// pipe end's Close shuts the pipe (the other end's own first Close still
// returns nil); a hub client's Close frees its source for a later Client
// call. The datagrams still queued toward the closed ends are counted
// Dropped. A second Close of the same end returns net.ErrClosed.
func (c *DatagramConn) Close() error {
	c.n.mu.Lock()
	defer c.n.mu.Unlock()
	if c.closed {
		return c.opErr("close", net.ErrClosed)
	}
	c.closed = true
	if c.hub != nil {
		c.hub.leave(c)
	} else {
		c.pipe.close()
	}
	return nil
}

// LocalAddr returns this end's address.
func (c *DatagramConn) LocalAddr() net.Addr { return c.laddr }

// RemoteAddr returns the other end's address.
func (c *DatagramConn) RemoteAddr() net.Addr { return c.raddr }

// SetDeadline sets both deadlines, as net.Conn.
func (c *DatagramConn) SetDeadline(t time.Time) error { return c.setDeadline(t, true, true) }

// SetReadDeadline sets the read deadline, as net.Conn; a waiting Read
// honours a new deadline at once.
func (c *DatagramConn) SetReadDeadline(t time.Time) error { return c.setDeadline(t, true, false) }

// SetWriteDeadline sets the write deadline, as net.Conn.
func (c *DatagramConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }

func (c *DatagramConn) setDeadline(t time.Time, read, write bool) error {
	c.n.mu.Lock()
	defer c.n.mu.Unlock()
	if c.ended() {
		return c.opErr("set", net.ErrClosed)
	}
	if write {
		c.wdl = dpFix(t)
	}
	if read {
		c.rx.setDeadline(t)
	}
	return nil
}

// Inject makes the next Read (every later one if persistent) return err.
// The Read returns (0, err) with the error as given, consumes no datagram
// and wakes a waiting Read (each such Read counts Injected); a nil err
// clears an earlier injection. A test that needs a count beside the error,
// as (n, io.ErrShortBuffer) or n > len(b), wraps the end.
func (c *DatagramConn) Inject(err error, persistent bool) {
	c.n.mu.Lock()
	defer c.n.mu.Unlock()
	c.rerr, c.rpersist = err, persistent && err != nil
	c.rx.cond.Broadcast()
}

// InjectWrite makes the next n Writes return err and send nothing. A nil
// err or an n below 1 clears an earlier injection.
func (c *DatagramConn) InjectWrite(err error, n int) {
	c.n.mu.Lock()
	defer c.n.mu.Unlock()
	if err == nil || n < 1 {
		err, n = nil, 0
	}
	c.werr, c.wleft = err, n
}

// Counts returns the conn's counters.
func (c *DatagramConn) Counts() DatagramConnCounts {
	c.n.mu.Lock()
	defer c.n.mu.Unlock()
	return c.ctr
}
