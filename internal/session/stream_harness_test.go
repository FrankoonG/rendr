package session

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Stream test harness (design §16.2 WP4): sessions built with
// initStreamLocked, lanes on fake ports, and the actor's few steps done by
// hand under s.mu. Fill, Data, Control and WriteBlocked are driven
// directly with real carrier Batches, Bufs and wire codecs; no carrier
// goroutine and no actor run. Every package-level helper of the stream
// tests starts with "st" (the actor's tests use their own prefix, as the
// mailbox tests use "mb"), so the two test sets never collide.

// stPort is a lane's carrier as the stream sees it.
type stPort struct {
	id   uint32
	wake chan struct{} // cap 1: Wake's token, consumed by a writer emulation

	mu        sync.Mutex
	wakes     int
	calls     int // Wake, Capacity, Inflight and WriteBlocked calls (L54)
	srtt      time.Duration
	inflight  int64
	capacity  int64
	blocked   bool
	closeSent bool
	kills     int
}

func stNewPort(id uint32) *stPort {
	return &stPort{id: id, wake: make(chan struct{}, 1), capacity: 1 << 40}
}

func (f *stPort) ID() uint32 { return f.id }

func (f *stPort) Wake() {
	f.mu.Lock()
	f.wakes++
	f.calls++
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *stPort) RequestPing() {}

func (f *stPort) Inflight() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.inflight
}

func (f *stPort) Capacity() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.capacity
}

func (f *stPort) SRTT() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.srtt
}

func (f *stPort) WriteBlocked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.blocked
}

func (f *stPort) CloseSent() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeSent
}

func (f *stPort) Kill(carrier.Cause, string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kills++
	return f.kills == 1
}

func (f *stPort) set(fn func(f *stPort)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *stPort) wakeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wakes
}

func (f *stPort) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// stOpt configures a test session; zero fields take the defaults below.
type stOpt struct {
	role     Role
	mode     Mode
	window   int64
	first    uint64
	limit    uint64
	pool     *carrier.BufPool
	budget   *carrier.Budget
	hooks    *testhooks.Hooks
	segment  int
	ackEvery int
	ackDelay time.Duration
}

// stSession returns an open session whose stream was initialized as
// Dial or NewPending would (initStreamLocked) and whose initial window was
// advertised (openWindowLocked).
func stSession(o stOpt) *Session {
	if o.role == 0 {
		o.role = RoleDialer
	}
	if o.mode == 0 {
		o.mode = ModeSelector
	}
	if o.window == 0 {
		o.window = 1 << 20
	}
	if o.pool == nil {
		o.pool = carrier.NewBufPool()
	}
	if o.budget == nil {
		o.budget = carrier.NewBudget(1 << 30)
	}
	if o.ackEvery == 0 {
		o.ackEvery = 64 << 10
	}
	if o.ackDelay == 0 {
		o.ackDelay = 20 * time.Millisecond
	}
	env := &Env{
		Carrier: &carrier.Env{
			Bufs:   o.pool,
			Budget: o.budget,
			Timing: carrier.Timing{PingBusy: 50 * time.Millisecond, BatchBudget: 256 << 10, Segment: o.segment},
		},
		Hooks: o.hooks,
	}
	s := &Session{env: env, p: Params{
		Role: o.role, Mode: o.mode, Window: o.window,
		AckEvery: o.ackEvery, AckDelay: o.ackDelay,
		FirstOffset: o.first, OffsetLimit: o.limit, FirstEpoch: 1,
	}}
	s.mb.init()
	s.mu.Lock()
	s.initStreamLocked()
	s.openWindowLocked() // the window of OPEN (dialer) or OPEN_ACK (passive)
	s.ctl.state = StateOpen
	s.mu.Unlock()
	return s
}

// stAddLane adds a lane as the actor does on an attach: confirmed (the
// passive's first response already placed), data-eligible if data (the
// selector's active lane), registered with laneAddedLocked.
func stAddLane(s *Session, id uint32, data bool) (*lane, *stPort) {
	fp := stNewPort(id)
	l := &lane{s: s, port: fp, id: id, factory: -1, since: time.Now()}
	s.mu.Lock()
	l.state = LaneMember
	l.firstSent = s.p.Role == RolePassive
	l.schedSent = s.ctl.epoch
	if data {
		l.data = true
		if s.p.Mode != ModeBond {
			l.state = LaneActive
			s.ctl.active = l
		}
	}
	s.lanes = append(s.lanes, l)
	s.laneAddedLocked(l)
	s.mu.Unlock()
	return l, fp
}

// stKillLane is the actor's death step for l (§7.3, C1).
func stKillLane(s *Session, l *lane) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.state = LaneDead
	l.data = false
	if s.ctl.active == l {
		s.ctl.active = nil
	}
	return s.laneGoneLocked(l)
}

// stRoute makes l the selector's active data lane (or a bond member) as an
// actor routing change does.
func stRoute(s *Session, l *lane, data bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.data = data
	if s.p.Mode != ModeBond {
		if data {
			l.state = LaneActive
			s.ctl.active = l
		} else if s.ctl.active == l {
			s.ctl.active = nil
		}
	}
	s.routingChangedLocked()
}

// stEnd ends the stream as the actor's end procedure does.
func stEnd(s *Session, err error) {
	s.mu.Lock()
	s.endLocked(err)
	s.mu.Unlock()
}

// stSetCopyHook makes fn run in s's Write after each round's reservation and
// before its copy (writeCopyHook) until the test ends. Tests that set it do
// not run in parallel with each other.
func stSetCopyHook(t testing.TB, s *Session, fn func()) {
	writeCopyHook.Store(&copyHook{s: s, fn: fn})
	t.Cleanup(func() { writeCopyHook.Store(nil) })
}

// stLocked runs fn under s.mu.
func stLocked[T any](s *Session, fn func(st *stream) T) T {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.st)
}

// stFrame is one recorded frame of a batch.
type stFrame struct {
	typ   wire.Type
	flags uint8
	off   uint64 // DATA, FIN: the stream offset
	n     int    // DATA: payload bytes
	retx  bool
	ack   wire.Ack
	at    time.Time
}

func (f stFrame) String() string {
	switch f.typ {
	case wire.TypeData:
		return fmt.Sprintf("DATA[%d,+%d retx=%v]", f.off, f.n, f.retx)
	case wire.TypeFin:
		return fmt.Sprintf("FIN(%d)", f.off)
	case wire.TypeAck:
		return fmt.Sprintf("ACK(%d,w=%d,f=%d)", f.ack.Delivered, f.ack.Window, f.flags)
	}
	return f.typ.String()
}

// stFrames returns the frames of b.
func stFrames(b *carrier.Batch) []stFrame {
	out := make([]stFrame, 0, b.Len())
	for i := range b.Len() {
		bf := b.Frame(i)
		f := stFrame{typ: bf.Header.Type, flags: bf.Header.Flags, at: b.Now()}
		switch f.typ {
		case wire.TypeData:
			f.off, f.n, f.retx = bf.Off, len(bf.Body), bf.Retx
		case wire.TypeFin:
			f.off, _ = wire.ParseFin(bf.Payload)
		case wire.TypeAck:
			f.ack, _ = wire.ParseAck(bf.Payload)
		}
		out = append(out, f)
	}
	return out
}

// stFill runs one Fill of l into a fresh batch at now and returns its frames
// and the batch, which still holds its chunk references: the caller
// releases them (b.ReleaseRefs, as a writer does after its write) or
// delivers the batch first.
func stFill(l *lane, now time.Time) ([]stFrame, *carrier.Batch) {
	b := carrier.NewBatch(0)
	b.Reset(now)
	l.Fill(nil, b)
	fs := stFrames(b)
	return fs, b
}

// stDeliver hands every frame of b to the endpoint to, as its carrier's
// reader would: DATA of at least 16 KiB in a reader-owned Buf of the
// receiving Runtime (reference moved), smaller DATA by a borrowed slice,
// session control frames to Control. It returns the first violation (the
// receiving carrier would be killed) and stops there.
func stDeliver(b *carrier.Batch, to *lane) error {
	for i := range b.Len() {
		f := b.Frame(i)
		var err error
		if f.Header.Type == wire.TypeData {
			err = stDeliverData(to, f.Off, f.Body)
		} else {
			err = to.Control(nil, f.Header, f.Payload)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func stDeliverData(to *lane, off uint64, body []byte) error {
	if len(body) < carrier.BigData {
		return to.Data(nil, off, body, nil)
	}
	env := to.s.env.Carrier
	buf := env.Bufs.Get(len(body)+carrier.LookAhead, env.Budget)
	n := copy(buf.B, body)
	return to.Data(nil, off, buf.B[:n], buf)
}

// stDeliverRange delivers data at off in 64 KiB frames.
func stDeliverRange(to *lane, off uint64, data []byte) error {
	for len(data) > 0 {
		n := min(len(data), 64<<10)
		if err := stDeliverData(to, off, data[:n]); err != nil {
			return err
		}
		off, data = off+uint64(n), data[n:]
	}
	return nil
}

func stCtlHeader(t wire.Type, flags uint8, n int) wire.Header {
	return wire.Header{Type: t, Flags: flags, Len: uint32(n), Handle: wire.SessionHandle}
}

// stSendAck delivers ACK{delivered, window} (flags) to l.
func stSendAck(l *lane, flags uint8, delivered uint64, window uint32) error {
	var p [wire.AckLen]byte
	wire.PutAck(p[:], &wire.Ack{Delivered: delivered, Window: window})
	return l.Control(nil, stCtlHeader(wire.TypeAck, flags, wire.AckLen), p[:])
}

// stSendFin delivers FIN(off) to l.
func stSendFin(l *lane, off uint64) error {
	var p [wire.FinLen]byte
	wire.PutFin(p[:], off)
	return l.Control(nil, stCtlHeader(wire.TypeFin, 0, wire.FinLen), p[:])
}

// stPattern returns n bytes whose value at stream offset off+i depends on
// both (consistent across overlapping frames, distinct across offsets).
func stPattern(off uint64, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		x := off + uint64(i)
		b[i] = byte(x ^ x>>8 ^ x>>17)
	}
	return b
}

// stReadN reads exactly n bytes from s (test goroutine only).
func stReadN(t testing.TB, s *Session, n int) []byte {
	t.Helper()
	out, err := stReadFull(s, n)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// stReadFull reads exactly n bytes from s; any goroutine may call it.
func stReadFull(s *Session, n int) ([]byte, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, 64<<10)
	for len(out) < n {
		k, err := s.Read(buf[:min(len(buf), n-len(out))])
		if err != nil {
			return out, fmt.Errorf("Read after %d of %d bytes: %w", len(out), n, err)
		}
		out = append(out, buf[:k]...)
	}
	return out, nil
}

type stReadResult struct {
	b   []byte
	err error
}

// stReadAsync reads exactly n bytes from s on a new goroutine.
func stReadAsync(s *Session, n int) <-chan stReadResult {
	ch := make(chan stReadResult, 1)
	go func() {
		b, err := stReadFull(s, n)
		ch <- stReadResult{b, err}
	}()
	return ch
}

// stPair is two sessions joined by links: link i connects a's lane i and b's
// lane i. a is the dialer, b the passive. trace records every frame moved,
// per direction.
type stPair struct {
	a, b    *Session
	al, bl  []*lane
	ap, bp  []*stPort
	cut     []bool // link carriers killed after a violation
	stall   []bool // a's writer on the link is stuck in a write: a → b moves nothing
	errs    []error
	traceAB []stFrame
	traceBA []stFrame
	mu      sync.Mutex // guards trace and errs in the asynchronous mode
	batch   *carrier.Batch
}

// stNewPair builds the two sessions with links lanes each; the selector's
// active (or every bond member) is data-eligible from the start, and both
// initial windows are exchanged as OPEN and OPEN_ACK would.
func stNewPair(ao, bo stOpt, links int) *stPair {
	ao.role, bo.role = RoleDialer, RolePassive
	if bo.mode == 0 {
		bo.mode = ao.mode
	}
	p := &stPair{a: stSession(ao), b: stSession(bo), batch: carrier.NewBatch(0)}
	for i := range links {
		data := i == 0 || ao.mode == ModeBond
		la, fa := stAddLane(p.a, uint32(i+1), data)
		lb, fb := stAddLane(p.b, uint32(i+1), data)
		p.al, p.ap = append(p.al, la), append(p.ap, fa)
		p.bl, p.bp = append(p.bl, lb), append(p.bp, fb)
		p.cut = append(p.cut, false)
		p.stall = append(p.stall, false)
	}
	p.a.mu.Lock()
	wa := p.a.openWindowLocked()
	p.a.mu.Unlock()
	p.b.mu.Lock()
	wb := p.b.openWindowLocked()
	p.b.peerWindowLocked(wa)
	p.b.mu.Unlock()
	p.a.mu.Lock()
	p.a.peerWindowLocked(wb)
	p.a.mu.Unlock()
	return p
}

// step runs one Fill on link i in one direction at now and delivers the
// frames; it returns the frames moved and the batch's WakeAt time.
func (p *stPair) step(i int, aToB bool, now time.Time) (int, time.Time) {
	if p.cut[i] || (aToB && p.stall[i]) {
		return 0, time.Time{}
	}
	from, to := p.al[i], p.bl[i]
	if !aToB {
		from, to = to, from
	}
	b := p.batch
	b.Reset(now)
	from.Fill(nil, b)
	n, wake := b.Len(), b.WakeTime()
	if n > 0 {
		fs := stFrames(b)
		if aToB {
			p.traceAB = append(p.traceAB, fs...)
		} else {
			p.traceBA = append(p.traceBA, fs...)
		}
		if err := stDeliver(b, to); err != nil {
			p.cut[i] = true
			p.errs = append(p.errs, err)
		}
	}
	b.ReleaseRefs()
	return n, wake
}

// pump moves frames both ways over every link until no Fill appends
// anything. With settle, a quiescent round whose Fills asked to be called
// again (the ACK delay, b.WakeAt) is repeated at that time, as the writer
// timer would; time itself does not move.
func (p *stPair) pump(settle bool) int {
	total := 0
	now := time.Now()
	for {
		moved := 0
		var wake time.Time
		for i := range p.al {
			for _, dir := range [2]bool{true, false} {
				n, w := p.step(i, dir, now)
				moved += n
				if !w.IsZero() && (wake.IsZero() || w.Before(wake)) {
					wake = w
				}
			}
		}
		total += moved
		if moved > 0 {
			continue
		}
		if !settle || wake.IsZero() || !now.Before(wake) {
			return total
		}
		now = wake
	}
}

// stCount returns the frames of type t in tr.
func stCount(tr []stFrame, t wire.Type) int {
	n := 0
	for _, f := range tr {
		if f.typ == t {
			n++
		}
	}
	return n
}

// stRunWriter emulates lane from's carrier writer inside a synctest bubble
// (§4.8): Fill on every wake or WakeAt time, self-continuing while Fill
// appends; each batch goes to sink. It exits when stop closes or sink
// fails (a violation kills the receiving carrier).
func stRunWriter(wg *sync.WaitGroup, from *lane, fp *stPort, stop <-chan struct{}, sink func(b *carrier.Batch) error) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := carrier.NewBatch(0)
		for {
			for {
				b.Reset(time.Now())
				from.Fill(nil, b)
				if b.Len() == 0 {
					break
				}
				err := sink(b)
				b.ReleaseRefs()
				if err != nil {
					return
				}
			}
			var tc <-chan time.Time
			var tm *time.Timer
			if w := b.WakeTime(); !w.IsZero() {
				tm = time.NewTimer(time.Until(w))
				tc = tm.C
			}
			select {
			case <-fp.wake:
			case <-tc:
			case <-stop:
				return
			}
			if tm != nil {
				tm.Stop()
			}
		}
	}()
}

// runPair starts writer emulations for every link of p in both directions
// (asynchronous mode); stop ends them.
func (p *stPair) runPair(wg *sync.WaitGroup, stop <-chan struct{}) {
	for i := range p.al {
		i := i
		stRunWriter(wg, p.al[i], p.ap[i], stop, func(b *carrier.Batch) error {
			p.record(true, b)
			return p.sinkErr(stDeliver(b, p.bl[i]))
		})
		stRunWriter(wg, p.bl[i], p.bp[i], stop, func(b *carrier.Batch) error {
			p.record(false, b)
			return p.sinkErr(stDeliver(b, p.al[i]))
		})
	}
}

// runLinks is runPair over links with a virtual latency lat: each batch is
// copied off the writer's batch (as bytes on a wire) and delivered by the
// link's own goroutine lat later, so virtual time — and with it the peer's
// answer — advances only once every writer emulation went idle. A producer
// that forgets to wake an idle writer therefore deadlocks the bubble
// deterministically (R1). A batch for which drop(i, aToB, b) returns true
// falls into a black hole on link i (it is recorded in neither trace).
func (p *stPair) runLinks(wg *sync.WaitGroup, stop <-chan struct{}, lat time.Duration, drop func(i int, aToB bool, b *carrier.Batch) bool) {
	type wframe struct {
		h    wire.Header
		off  uint64
		body []byte
	}
	link := func(i int, from, to *lane, fp *stPort, aToB bool) {
		q := make(chan []wframe, 1024)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case fs := <-q:
					time.Sleep(lat)
					for _, f := range fs {
						var err error
						if f.h.Type == wire.TypeData {
							err = stDeliverData(to, f.off, f.body)
						} else {
							err = to.Control(nil, f.h, f.body)
						}
						if p.sinkErr(err) != nil {
							break // the receiving carrier is killed: the rest is lost
						}
					}
				case <-stop:
					return
				}
			}
		}()
		stRunWriter(wg, from, fp, stop, func(b *carrier.Batch) error {
			if drop != nil && drop(i, aToB, b) {
				return nil
			}
			p.record(aToB, b)
			fs := make([]wframe, b.Len())
			for i := range fs {
				f := b.Frame(i)
				body := f.Payload
				if f.Header.Type == wire.TypeData {
					body = f.Body
				}
				fs[i] = wframe{f.Header, f.Off, bytes.Clone(body)}
			}
			q <- fs
			return nil
		})
	}
	for i := range p.al {
		link(i, p.al[i], p.bl[i], p.ap[i], true)
		link(i, p.bl[i], p.al[i], p.bp[i], false)
	}
}

func (p *stPair) record(aToB bool, b *carrier.Batch) {
	fs := stFrames(b)
	p.mu.Lock()
	if aToB {
		p.traceAB = append(p.traceAB, fs...)
	} else {
		p.traceBA = append(p.traceBA, fs...)
	}
	p.mu.Unlock()
}

func (p *stPair) sinkErr(err error) error {
	if err != nil {
		p.mu.Lock()
		p.errs = append(p.errs, err)
		p.mu.Unlock()
	}
	return err
}

func (p *stPair) errors() []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]error(nil), p.errs...)
}

// close ends both streams (the actors' end procedures) and checks that
// every buffer returned to its Budget.
func (p *stPair) close(t testing.TB) {
	t.Helper()
	stEnd(p.a, errClosed)
	stEnd(p.b, errClosed)
	for _, s := range []*Session{p.a, p.b} {
		if u := s.env.Carrier.Budget.Used(); u != 0 {
			t.Errorf("Budget.Used = %d after the end, want 0 (a buffer leaked)", u)
		}
	}
}

// record header used by the writer tests: [writer u16][seq u32][len u32].
const stRecHead = 10

func stPutRecord(w, seq int, body []byte) []byte {
	b := make([]byte, stRecHead+len(body))
	binary.BigEndian.PutUint16(b[0:2], uint16(w))
	binary.BigEndian.PutUint32(b[2:6], uint32(seq))
	binary.BigEndian.PutUint32(b[6:10], uint32(len(body)))
	copy(b[stRecHead:], body)
	return b
}

// stRecordBody is the deterministic body of record (w, seq).
func stRecordBody(w, seq, n int) []byte {
	return stPattern(uint64(w)<<32|uint64(seq)<<12, n)
}

func stCheckRecord(t testing.TB, b []byte) (w, seq, n int) {
	t.Helper()
	w = int(binary.BigEndian.Uint16(b[0:2]))
	seq = int(binary.BigEndian.Uint32(b[2:6]))
	n = int(binary.BigEndian.Uint32(b[6:10]))
	if len(b) < stRecHead+n {
		t.Fatalf("record (%d, %d) truncated: %d of %d bytes", w, seq, len(b)-stRecHead, n)
	}
	if !bytes.Equal(b[stRecHead:stRecHead+n], stRecordBody(w, seq, n)) {
		t.Fatalf("record (%d, %d) of %d bytes is corrupted or interleaved", w, seq, n)
	}
	return w, seq, n
}
