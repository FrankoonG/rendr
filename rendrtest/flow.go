package rendrtest

import (
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// carrier is one Dial's path: the dialer's conn ↔ a (pipe 1), b ↔ the
// passive's conn (pipe 2); the up flow pumps a → b, the down flow b → a.
type carrier struct {
	l       *Link
	seq     int
	a, b    net.Conn // link ends
	flows   [2]*flow // up, down
	kind    atomic.Int32
	first   atomic.Uint32
	done    chan struct{} // closed by shut
	once    sync.Once
	closed  atomic.Bool
	pumps   sync.WaitGroup // the four pump goroutines
	corrupt [2]atomic.Bool // CorruptNext per direction
	up      atomic.Int64
	down    atomic.Int64
	held    atomic.Int64
}

// chunk is a run of bytes due for delivery at at.
type chunk struct {
	b         []byte
	at        time.Time
	throttled bool
}

// flow is one direction of a carrier: a reader pulls what the writer wrote
// out of src (while fewer than Buffer bytes are queued), passes it through
// the frame tracker and queues timed chunks; a deliverer writes them into
// dst in order, honouring stall, blackhole and CorruptNext.
type flow struct {
	c        *carrier
	i        int // 0 up, 1 down
	src, dst net.Conn

	mu     sync.Mutex
	q      []chunk
	queued int       // bytes queued, the chunk being written included
	lastAt time.Time // delivery times never go backwards (a byte stream)
	eof    bool      // the writer's side ended: deliver the queue, then end the carrier
	tr     tracker
	wake   chan struct{} // cap 1: deliverer
	room   chan struct{} // cap 1: reader

	timer *time.Timer // deliverer only
}

// deadOpen is a dial made while the link was blackholed: it "opens" but
// nothing it writes ever arrives and nothing answers.
type deadOpen struct {
	far  net.Conn // the link's end; the dialer holds the other
	kind atomic.Int32
	done chan struct{}
	once sync.Once
	tr   tracker // classification only
}

// open creates a carrier (or, while blackholed, a dead open) and starts its
// goroutines. first (owned) goes ahead of everything the dialer writes.
func (l *Link) open(first []byte) (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		l.dialFails.Add(1)
		return nil, net.ErrClosed
	}
	l.smu.Lock()
	bh := l.blackhole
	l.smu.Unlock()
	if bh {
		cli, far := net.Pipe()
		d := &deadOpen{far: far, done: make(chan struct{})}
		l.dead = append(l.dead, d)
		l.wg.Add(1)
		l.mu.Unlock()
		if first != nil {
			d.drop(l, first)
		}
		go l.deadLoop(d)
		return newConn(l, cli, 0, &d.kind, d.done), nil
	}
	cli, a := net.Pipe()
	b, srv := net.Pipe()
	c := &carrier{l: l, seq: len(l.history), a: a, b: b, done: make(chan struct{})}
	c.flows[0] = &flow{c: c, i: 0, src: a, dst: b, wake: make(chan struct{}, 1), room: make(chan struct{}, 1)}
	c.flows[1] = &flow{c: c, i: 1, src: b, dst: a, wake: make(chan struct{}, 1), room: make(chan struct{}, 1)}
	l.history = append(l.history, c)
	l.carriers = append(l.carriers, c)
	l.wg.Add(5)
	c.pumps.Add(4)
	l.mu.Unlock()
	if first != nil {
		f := c.flows[0]
		f.mu.Lock()
		f.push(first)
		f.mu.Unlock()
	}
	for _, f := range c.flows {
		go f.readLoop()
		go f.deliverLoop()
	}
	server := newConn(l, srv, 1, &c.kind, c.done)
	go func() {
		defer l.wg.Done()
		if l.accept == nil || l.accept(server) != nil {
			server.Close()
		}
	}()
	return newConn(l, cli, 0, &c.kind, c.done), nil
}

// shut closes the carrier once: the dialer's and the passive's conns then
// read EOF and fail writes. It reports whether this call closed it.
func (c *carrier) shut() bool {
	first := false
	c.once.Do(func() {
		first = true
		close(c.done)
		c.a.Close()
		c.b.Close()
		c.closed.Store(true)
		l := c.l
		l.mu.Lock()
		if i := slices.Index(l.carriers, c); i >= 0 {
			l.carriers = slices.Delete(l.carriers, i, i+1)
		}
		l.mu.Unlock()
	})
	return first
}

// countLost counts the bytes still in the link after a Kill; the pumps have
// exited.
func (c *carrier) countLost() {
	var n int
	for _, f := range c.flows {
		f.mu.Lock()
		n += f.queued + f.tr.held()
		f.mu.Unlock()
	}
	c.l.count(c.kind.Load(), cBufferLost, int64(n))
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// readLoop moves the writer's bytes into the queue while it has room.
func (f *flow) readLoop() {
	c, l := f.c, f.c.l
	defer l.wg.Done()
	defer c.pumps.Done()
	buf := make([]byte, readSize)
	for {
		f.mu.Lock()
		for f.queued >= l.buffer {
			f.mu.Unlock()
			select {
			case <-f.room:
			case <-c.done:
				f.endSource(false)
				return
			}
			f.mu.Lock()
		}
		n := min(len(buf), l.buffer-f.queued)
		f.mu.Unlock()
		k, err := f.src.Read(buf[:n])
		if k > 0 {
			f.mu.Lock()
			f.push(buf[:k])
			f.mu.Unlock()
		}
		if err != nil {
			f.endSource(true)
			return
		}
	}
}

// endSource records that the writer's side ended. flush (the writer's conn
// failed or closed) delivers what the tracker held back; a shut carrier
// keeps it for countLost.
func (f *flow) endSource(flush bool) {
	f.mu.Lock()
	if flush {
		if out := f.tr.flush(); len(out) > 0 {
			f.enqueue(out, f.c.kind.Load())
		}
	}
	f.eof = true
	f.mu.Unlock()
	signal(f.wake)
}

// push runs p (borrowed) through the tracker and queues the output. f.mu
// held.
func (f *flow) push(p []byte) {
	var ev events
	out := f.tr.feed(p, &ev)
	c, l := f.c, f.c.l
	if f.i == 0 && c.kind.Load() == kindUnknown && f.tr.kind != kindUnknown {
		c.first.Store(uint32(f.tr.first))
		c.kind.Store(f.tr.kind)
	}
	k := c.kind.Load()
	l.count(k, cFramesCorrupted, ev.corrupted)
	l.count(k, cFramesDropped, ev.dropped)
	l.count(k, cFramesInjected, ev.injected)
	l.count(k, cCaptured, ev.captured)
	if len(out) > 0 {
		f.enqueue(out, k)
	}
}

// enqueue queues b (owned) with its delivery time: arrival, then the
// direction's shared bottleneck at the configured rate, then the one-way
// delay with jitter, never before the previous chunk. f.mu held.
func (f *flow) enqueue(b []byte, kind int32) {
	l := f.c.l
	now := time.Now()
	l.smu.Lock()
	if l.blackhole {
		l.smu.Unlock()
		l.count(kind, cDropped, int64(len(b)))
		return
	}
	d := l.delay
	if l.jitter > 0 {
		d += time.Duration(l.rng.Int64N(int64(2*l.jitter)+1)) - l.jitter
		d = max(d, 0)
	}
	at, throttled := now, false
	if l.rate > 0 {
		start := now
		if l.freeAt[f.i].After(start) {
			start = l.freeAt[f.i]
		}
		at = start.Add(time.Duration(float64(len(b)) / l.rate * float64(time.Second)))
		l.freeAt[f.i] = at
		throttled = true
	}
	l.smu.Unlock()
	l.count(kind, cMaxDelay, int64(d))
	at = at.Add(d)
	if at.Before(f.lastAt) {
		at = f.lastAt
	}
	f.lastAt = at
	f.q = append(f.q, chunk{b: b, at: at, throttled: throttled})
	f.queued += len(b)
	signal(f.wake)
}

// pop removes n delivered bytes from the head chunk. f.mu held.
func (f *flow) pop(n int) {
	f.queued -= n
	if n >= len(f.q[0].b) {
		f.q[0] = chunk{}
		f.q = f.q[1:]
	} else {
		f.q[0].b = f.q[0].b[n:]
	}
	signal(f.room)
}

// deliverLoop writes queued chunks into dst at their delivery time. When
// the writer's side ended and the queue is empty, or a write fails, it ends
// the carrier.
func (f *flow) deliverLoop() {
	c, l := f.c, f.c.l
	defer l.wg.Done()
	defer c.pumps.Done()
	for {
		f.mu.Lock()
		for len(f.q) == 0 {
			eof := f.eof
			f.mu.Unlock()
			if eof {
				c.shut()
				return
			}
			select {
			case <-f.wake:
			case <-c.done:
				return
			}
			f.mu.Lock()
		}
		ch := f.q[0]
		f.mu.Unlock()
		if !f.waitUntil(ch.at) || !f.waitStall() {
			return
		}
		kind := c.kind.Load()
		l.smu.Lock()
		bh := l.blackhole
		l.smu.Unlock()
		if bh {
			l.count(kind, cDropped, int64(len(ch.b)))
			f.mu.Lock()
			f.pop(len(ch.b))
			f.mu.Unlock()
			continue
		}
		if c.corrupt[f.i].CompareAndSwap(true, false) {
			ch.b[len(ch.b)/2] ^= 0xFF
			l.count(kind, cCorrupted, 1)
		}
		// Count first, so that whoever read the bytes sees them counted;
		// take back what a failed write did not deliver.
		f.delivered(kind, int64(len(ch.b)), ch.throttled)
		n, err := f.dst.Write(ch.b)
		if lost := len(ch.b) - n; lost > 0 {
			f.delivered(kind, -int64(lost), ch.throttled)
		}
		f.mu.Lock()
		f.pop(n)
		f.mu.Unlock()
		if err != nil {
			c.shut()
			return
		}
	}
}

// delivered counts n bytes forwarded to the far end.
func (f *flow) delivered(kind int32, n int64, throttled bool) {
	f.c.l.count(kind, cBytes, n)
	if f.i == 0 {
		f.c.up.Add(n)
	} else {
		f.c.down.Add(n)
	}
	if throttled {
		f.c.l.throttled.Add(n)
	}
}

// waitUntil sleeps until at; false if the carrier was shut meanwhile.
func (f *flow) waitUntil(at time.Time) bool {
	d := time.Until(at)
	if d <= 0 {
		select {
		case <-f.c.done:
			return false
		default:
			return true
		}
	}
	if f.timer == nil {
		f.timer = time.NewTimer(d)
	} else {
		f.timer.Reset(d)
	}
	select {
	case <-f.timer.C:
		return true
	case <-f.c.done:
		f.timer.Stop()
		return false
	}
}

// waitStall holds the head chunk while the link is stalled (counted once
// per chunk); false if the carrier was shut meanwhile.
func (f *flow) waitStall() bool {
	c, l := f.c, f.c.l
	held := false
	for {
		l.smu.Lock()
		st, ch := l.stalled, l.stallCh
		l.smu.Unlock()
		if !st {
			return true
		}
		if !held {
			held = true
			l.count(c.kind.Load(), cHeld, 1)
			c.held.Add(1)
		}
		select {
		case <-ch:
		case <-c.done:
			return false
		}
	}
}

// drop classifies b and counts it as dropped.
func (d *deadOpen) drop(l *Link, b []byte) {
	var ev events
	out := d.tr.feed(b, &ev)
	if d.kind.Load() == kindUnknown && d.tr.kind != kindUnknown {
		d.kind.Store(d.tr.kind)
	}
	l.count(d.kind.Load(), cDropped, int64(len(out)))
}

// deadLoop discards everything the dialer writes into a dead open.
func (l *Link) deadLoop(d *deadOpen) {
	defer l.wg.Done()
	buf := make([]byte, readSize)
	for {
		n, err := d.far.Read(buf)
		if n > 0 {
			d.drop(l, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (d *deadOpen) shut() {
	d.once.Do(func() {
		close(d.done)
		d.far.Close()
	})
}
