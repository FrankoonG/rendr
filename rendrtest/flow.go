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

// chunk is a run of bytes in the link: first queued at the bottleneck of
// its direction (Link.bq), then on its flow's wire (flow.q) until at.
type chunk struct {
	b       []byte
	f       *flow
	arrival time.Time // when the link accepted it
	at      time.Time // delivery time, set when it leaves the bottleneck
	held    bool      // counted as held by a stall
}

// flow is one direction of a carrier: a reader pulls what the writer wrote
// out of src (while fewer than Buffer bytes are in the link), passes it
// through the frame tracker and queues it at the direction's bottleneck
// (Link.transmit), which puts it on the flow's wire; a deliverer writes the
// wire into dst at each chunk's delivery time, honouring stall, blackhole
// and CorruptNext.
type flow struct {
	c        *carrier
	i        int // 0 up, 1 down
	src, dst net.Conn

	mu     sync.Mutex
	q      []*chunk  // on the wire, in order
	queued int       // bytes in the link: at the bottleneck, on the wire, being written
	inTx   int       // chunks at the bottleneck
	lastAt time.Time // delivery times never go backwards (a byte stream)
	eof    bool      // the writer's side ended: deliver everything, then end the carrier
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
// goroutines, and the link's bottlenecks with its first carrier. first
// (owned) goes ahead of everything the dialer writes.
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
	if !l.txOn {
		l.txOn = true
		l.wg.Add(2)
		go l.transmit(0)
		go l.transmit(1)
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
// read EOF and fail writes, and its chunks leave the bottlenecks (they take
// no more bottleneck time). It reports whether this call closed it.
func (c *carrier) shut() bool {
	first := false
	c.once.Do(func() {
		first = true
		c.closed.Store(true)
		close(c.done)
		c.a.Close()
		c.b.Close()
		l := c.l
		l.mu.Lock()
		if i := slices.Index(l.carriers, c); i >= 0 {
			l.carriers = slices.Delete(l.carriers, i, i+1)
		}
		l.mu.Unlock()
		l.smu.Lock()
		for i := range l.bq {
			l.bq[i] = slices.DeleteFunc(l.bq[i], func(ch *chunk) bool { return ch.f.c == c })
		}
		l.smu.Unlock()
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

// countHeld counts one chunk held by a stall.
func (c *carrier) countHeld() {
	c.l.count(c.kind.Load(), cHeld, 1)
	c.held.Add(1)
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// readLoop moves the writer's bytes into the link while it has room.
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

// enqueue queues b (owned) at the bottleneck of its direction, behind the
// bytes of every carrier of the link that arrived earlier; while the link
// is blackholed b vanishes instead. f.mu held.
func (f *flow) enqueue(b []byte, kind int32) {
	l := f.c.l
	l.smu.Lock()
	if l.blackhole {
		l.smu.Unlock()
		l.count(kind, cDropped, int64(len(b)))
		return
	}
	l.bq[f.i] = append(l.bq[f.i], &chunk{b: b, f: f, arrival: time.Now()})
	l.smu.Unlock()
	f.queued += len(b)
	f.inTx++
	signal(l.txWork[f.i])
}

// transmit is the bottleneck of direction i, shared by every carrier of
// the link: it moves the queued chunks onto their flows' wires in arrival
// order, each taking len/rate. Nothing is transmitted while the link is
// stalled, so a backlog drains at the rate afterwards; a rate change
// applies at once to every chunk not yet transmitted; blackholed chunks
// and chunks of ended carriers take no bottleneck time.
func (l *Link) transmit(i int) {
	defer l.wg.Done()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	var busy, start time.Time // end of the previous transmission; start of cur's
	var cur *chunk            // the chunk being transmitted
	for {
		l.smu.Lock()
		if len(l.bq[i]) == 0 {
			l.smu.Unlock()
			select {
			case <-l.txWork[i]:
			case <-l.stop:
				return
			}
			continue
		}
		ch := l.bq[i][0]
		rate, stalled, bh, ctl := l.rate, l.stalled, l.blackhole, l.ctl
		if stalled {
			for _, q := range l.bq[i] {
				if !q.held {
					q.held = true
					q.f.c.countHeld()
				}
			}
		}
		l.smu.Unlock()
		now := time.Now()
		if cur != nil && cur != ch { // lost with its carrier while being transmitted
			busy, cur = now, nil
		}
		switch {
		case bh || ch.f.c.closed.Load():
			if cur == ch {
				busy, cur = now, nil
			}
			l.discard(i, ch, bh)
			continue
		case stalled:
			cur = nil // restarts after the stall
			select {
			case <-ctl:
			case <-l.txWork[i]: // count new arrivals as held
			case <-ch.f.c.done:
			case <-l.stop:
				return
			}
			busy = maxTime(busy, time.Now())
			continue
		}
		end := now
		if rate > 0 {
			if cur != ch {
				cur, start = ch, maxTime(busy, ch.arrival)
			}
			end = start.Add(time.Duration(float64(len(ch.b)) / rate * float64(time.Second)))
			if d := end.Sub(now); d > 0 {
				timer.Reset(d)
				select {
				case <-timer.C:
				case <-ctl: // re-evaluated with the new settings
					timer.Stop()
					continue
				case <-ch.f.c.done:
					timer.Stop()
					continue
				case <-l.stop:
					return
				}
			}
			l.throttled.Add(int64(len(ch.b)))
		}
		busy, cur = end, nil
		l.toWire(i, ch, end)
	}
}

// popHead removes ch from the head of the bottleneck of direction i; false
// if it is no longer there (its carrier ended). l.smu held.
func (l *Link) popHead(i int, ch *chunk) bool {
	if len(l.bq[i]) == 0 || l.bq[i][0] != ch {
		return false
	}
	l.bq[i][0] = nil
	l.bq[i] = l.bq[i][1:]
	return true
}

// discard removes the bottleneck's head ch without transmitting it: a
// blackholed chunk is dropped (counted unless its carrier was killed, which
// counts it as lost), a chunk of an ended carrier just goes.
func (l *Link) discard(i int, ch *chunk, blackholed bool) {
	l.smu.Lock()
	ok := l.popHead(i, ch)
	l.smu.Unlock()
	if !ok {
		return
	}
	f := ch.f
	f.mu.Lock()
	if blackholed && !f.c.closed.Load() {
		l.count(f.c.kind.Load(), cDropped, int64(len(ch.b)))
		f.queued -= len(ch.b)
		f.inTx--
	}
	f.mu.Unlock()
	signal(f.room)
	signal(f.wake)
}

// toWire moves ch, transmitted at end, from the bottleneck onto its flow's
// wire: it is due one delay (with jitter) later, never before the flow's
// previous chunk.
func (l *Link) toWire(i int, ch *chunk, end time.Time) {
	l.smu.Lock()
	if !l.popHead(i, ch) {
		l.smu.Unlock()
		return
	}
	d := l.delay
	if l.jitter > 0 {
		d = max(d+time.Duration(l.rng[i].Int64N(int64(2*l.jitter)+1))-l.jitter, 0)
	}
	l.smu.Unlock()
	f := ch.f
	l.count(f.c.kind.Load(), cMaxDelay, int64(d))
	f.mu.Lock()
	ch.at = maxTime(end.Add(d), f.lastAt)
	f.lastAt = ch.at
	f.q = append(f.q, ch)
	f.inTx--
	f.mu.Unlock()
	signal(f.wake)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// pop removes n delivered bytes from the head chunk of the wire. f.mu held.
func (f *flow) pop(n int) {
	f.queued -= n
	if n >= len(f.q[0].b) {
		f.q[0] = nil
		f.q = f.q[1:]
	} else {
		f.q[0].b = f.q[0].b[n:]
	}
	signal(f.room)
}

// deliverLoop writes the wire's chunks into dst at their delivery time.
// When the writer's side ended and the link holds nothing more of this
// flow, or a write fails, it ends the carrier.
func (f *flow) deliverLoop() {
	c, l := f.c, f.c.l
	defer l.wg.Done()
	defer c.pumps.Done()
	for {
		f.mu.Lock()
		for len(f.q) == 0 {
			end := f.eof && f.inTx == 0
			f.mu.Unlock()
			if end {
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
		// Only bytes the far end has read are counted as delivered.
		n, err := f.dst.Write(ch.b)
		f.delivered(kind, int64(n))
		f.mu.Lock()
		f.pop(n)
		f.mu.Unlock()
		if err != nil {
			c.shut()
			return
		}
	}
}

// delivered counts n bytes the far end read.
func (f *flow) delivered(kind int32, n int64) {
	f.c.l.count(kind, cBytes, n)
	if f.i == 0 {
		f.c.up.Add(n)
	} else {
		f.c.down.Add(n)
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

// waitStall holds the wire while the link is stalled (every chunk on it
// counted once as held); false if the carrier was shut meanwhile.
func (f *flow) waitStall() bool {
	l := f.c.l
	for {
		l.smu.Lock()
		st, ctl := l.stalled, l.ctl
		l.smu.Unlock()
		if !st {
			return true
		}
		f.mu.Lock()
		for _, ch := range f.q {
			if !ch.held {
				ch.held = true
				f.c.countHeld()
			}
		}
		f.mu.Unlock()
		select {
		case <-ctl:
		case <-f.c.done:
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
