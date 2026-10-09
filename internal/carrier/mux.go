package carrier

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The rendr mux core (M3 design §A5.1–§A5.4, §A5.7, §A5.10): the view
// table and the last-hit dispatch cache, the reader's classification of
// session frames on a MUX trunk (§A3.3), the writer's round over several
// views (DETACHes, refusal answers and first frames in allocation order,
// then a control pass and deficit round robin over the ready views,
// R1-1), per-view wakes, the fan-outs of the trunk's death, CLOSE, GOAWAY
// and WriteBlocked to every view, and each view's Done (M3-D13). DETACH
// and the view lifecycle ends are in detach.go, passive admission, the
// refusal ring and the dialer's responses in admit.go.
//
// A trunk muxes iff both PREFACEs carried wire.OptMux (trunk.mux). Every
// path here runs only on MUX trunks; a dedicated carrier keeps M2's code.
// A MUX trunk with only view 1 (no second view was ever created) runs the
// one-view round — view 1's Fill without a quota — unless mux control is
// queued; the view table, the ready ring and the writer's scratch are
// built with the second view (M3-D1).

// ErrDead is openView's error for a trunk that takes no new view: dead,
// dying, retiring, sealed (the handle space ended or the pool closed it),
// gone away, at its view cap, not a started dialer MUX trunk, or a first
// frame a datagram trunk's REL cannot carry.
var ErrDead = errors.New("rendr/carrier: the carrier takes no new view")

// Mux defaults (M3-D12, M3-D50; Timing.withDefaults).
const (
	defMuxMaxViews         = 256
	defMuxMaxViewsDatagram = 64
	defMuxQuantum          = 64 << 10
)

// doneBit marks a view's call word (Conn.calls) closed: its Done closed and
// no endpoint call starts any more (M3-D13). The low bits count the
// reader, writer and watchdog calls in progress (R1-16).
const doneBit = 1 << 30

// muxState is the trunk's mux state beyond the fields the skeleton
// declared on trunk (trunk.go). Fields are guarded by trunk.mx unless
// marked writer (the writer goroutine only) or atomic.
type muxState struct {
	multi    atomic.Bool  // the view table exists (a second view was created): writer rounds take the ready set
	work     atomic.Bool  // mux control is queued: last frames, DETACHes, answers, first frames, retirements, a pending retirement of view 1
	started  atomic.Bool  // view 1's Start ran (join.started, readable without jmu)
	awaitAck atomic.Int32 // datagram trunks: retiring views whose DETACH waits for its RACK (relAcked)
	full     bool         // dialer: a CAPACITY CodeMuxFull answer arrived; cleared when a view's Done closes (the pool's usable rule)

	detq     []*Conn    // views whose DETACH is due (abandoned, killed, after their last frame, the peer's DETACH answered)
	lasts    []*Conn    // views with a WriteAndClose frame to place
	retiring []*Conn    // views whose DETACH was placed and whose exchange is not complete
	tol      []tolEntry // ring: handles whose late crossing frames are dropped (refused, or retired at the DETACH bound)
	tolHead  int
	opHead   int // the opens FIFO: t.opens[opHead : opHead+opN] (mod cap)
	opN      int

	// Writer.
	scratch  []*Conn  // the round's ready views (cap = the ring's)
	nextWake int64    // ns after base: the earliest per-view WakeAt; 0 = none
	detWake  int64    // ns after base: the earliest DETACH bound of a retiring view; 0 = none
	capList  []*Conn  // views with capMarked (each once): a PONG re-readies these only (L54)
	capPM    uint64   // the PONG watermark when the latest view was marked cap-blocked
	relList  []*Conn  // views with relMarked (each once)
	wakeList []*Conn  // views with a pending WakeAt (each once)
	touched  uint64   // views a round visited (ready scratch and wake lists): the cost gate's count (L54)
	post     postList // the writer's
	rpost    postList // the reader's
}

// tolEntry is one entry of the tolerance ring: a handle no view holds any
// more whose crossing frames are legal. all: every session frame and the
// DETACH (a view retired at the DETACH bound, whose peer may still be
// sending); otherwise only RST, a response and the DETACH (a refused
// handle).
type tolEntry struct {
	h   uint32
	all bool
}

// viewExt is a view's mux state beyond the fields the skeleton declared
// on Conn. Fields are guarded by trunk.mx unless marked writer or atomic.
type viewExt struct {
	own      bool        // the view has its own Done: view-scoped Kill, Retire, WriteAndClose, end record (a view of a started MUX trunk)
	fillOK   atomic.Bool // the writer may call the view's Fill (attached; not held, ended, retired or answering last)
	fin      atomic.Bool // ended: Done closes once the calls drain (M3-D13)
	peerDet  atomic.Bool // the peer's DETACH(h) was dispatched
	detSent  atomic.Bool // our DETACH(h) was placed
	needResp atomic.Bool // passive: pending or joining, the first response not yet placed (the writer looks for it)
	retireQ  atomic.Bool // a planned retirement: DETACH once a Fill places nothing (writer reads it)

	attached bool              // Start installed the session's endpoint
	dialer   bool              // a dialer view
	inTable  bool              // in the view table (view 1 of a trunk without one: implicitly)
	first    wire.Type         // OPEN or JOIN: the view's first frame (dialer) or the admitted frame (passive)
	firstP   []byte            // dialer: the first frame's payload
	queued   bool              // dialer: awaitResponse released the first frame to the opens FIFO
	sess     uintptr           // dialer: the session (one unreaped view per trunk, R1-6)
	resp     chan struct{}     // dialer: closed when the response arrived or the view ended without one
	respGot  bool              // dialer: a response arrived
	rhdr     wire.Header       // dialer: the response header
	rp       []byte            // dialer: a copy of the response payload
	reason   wire.DetachReason // our DETACH's reason
	detQ     bool              // in detq or lasts (no further Fill)
	last     *lastFrame        // a WriteAndClose frame to place
	refused  bool              // gone through a refusal response: no DETACH (M3-D7)
	lastSent bool              // a WriteAndClose frame was placed for the view (its first session frame after the response on a dialer view: it ends the passive's hold)
	onDone   Doorbell          // rung once when Done closes (OnDone)
	doneShut bool              // Done is closed (set with the close, under mx): OnDone rings at once
	ringFwd  bool              // ring the bell once at the end (killed views ring at Kill)

	// Writer.
	detAt     int64  // ns after base when our DETACH was placed
	detBound  int64  // ns after base: the DETACH bound (§A5.5)
	detCseq   uint32 // datagram trunks: the cseq of our REL{DETACH}
	relMarked bool   // its last Fill found no REL room
}

// lastFrame is a view's last session frame (WriteAndClose on a view).
type lastFrame struct {
	t     wire.Type
	flags uint8
	p     []byte
	timer *time.Timer
}

// postList collects what must run after trunk.mx is released: Done
// closes, doorbell rings and AfterDetach hooks (a hook may block).
type postList struct {
	done  []*Conn
	bells []*Conn
	hooks []detachEvent
}

type detachEvent struct {
	h    uint32
	sent bool
}

// maxViews returns the view cap of the trunk's kind (M3-D12): views and
// queued refusal answers count against it.
func (t *trunk) maxViews() int {
	if t.dg != nil {
		return t.tm.MuxMaxViewsDatagram
	}
	return t.tm.MuxMaxViews
}

// nsAt returns the ns after base of at (≥ 1).
func (t *trunk) nsAt(at time.Time) int64 { return max(int64(at.Sub(t.base)), 1) }

// The view table (M3-D9).

// lookupLocked returns the view of handle h in the table, or view 1 of a
// trunk without one; nil when there is none.
func (t *trunk) lookupLocked(h uint32) *Conn {
	if !t.ms.multi.Load() {
		if v := t.view1; v.handle == h && v.vx.inTable {
			return v
		}
		return nil
	}
	return t.views[h]
}

// routeMux is route on a MUX trunk: the last-hit cache, else the table
// under mx (a one-view trunk compares with view 1).
func (t *trunk) routeMux(h uint32) *Conn {
	if v := t.last.Load(); v != nil && v.handle == h {
		return v
	}
	if !t.ms.multi.Load() {
		if v := t.view1; v.handle == h {
			return v
		}
		return nil
	}
	t.mx.Lock()
	v := t.views[h]
	t.mx.Unlock()
	return v
}

// buildTableLocked builds the view table, the ready ring and the writer's
// scratch at the second view, and puts view 1 into the ring when it is
// fillable (a Wake it took on the one-view path is not lost).
func (t *trunk) buildTableLocked() {
	if t.ms.multi.Load() {
		return
	}
	n := t.maxViews() + 1
	t.views = make(map[uint32]*Conn, 4)
	t.readyRing = make([]*Conn, n)
	t.ms.scratch = make([]*Conn, n)
	t.ms.capList = make([]*Conn, 0, n)
	t.ms.relList = make([]*Conn, 0, n)
	t.ms.wakeList = make([]*Conn, 0, n)
	if v := t.view1; v.vx.inTable {
		t.views[v.handle] = v
		if v.vx.fillOK.Load() && v.ready.CompareAndSwap(false, true) {
			t.pushReadyLocked(v)
		}
	}
	t.ms.multi.Store(true)
}

// newViewLocked creates view h in state st on a started MUX trunk: its own
// Done, the shim endpoint until its session attaches, in the table, the
// view count raised.
func (t *trunk) newViewLocked(h uint32, st viewState) *Conn {
	t.buildTableLocked()
	v := &Conn{trunk: t, handle: h, state: st, done: make(chan struct{})}
	v.ep = &shimEndpoint{v: v}
	v.vx.own, v.vx.inTable = true, true
	t.views[h] = v
	t.nviews++
	return v
}

// removeLocked takes v out of the table (its handle is never reused), out
// of the ready ring and out of the dispatch cache.
func (t *trunk) removeLocked(v *Conn) {
	if !v.vx.inTable {
		return
	}
	v.vx.inTable = false
	if t.ms.multi.Load() {
		delete(t.views, v.handle)
	}
	t.leaveLiveLocked(v)
	t.unreadyLocked(v)
}

// leaveLiveLocked drops v from the last-hit cache: v's frames are no
// longer dispatched without the table's state check (M3-D9).
func (t *trunk) leaveLiveLocked(v *Conn) {
	t.last.CompareAndSwap(v, nil)
}

// The ready ring (R1-1): v.ready is true exactly while v is in the ring or
// in the writer's round scratch.

func (t *trunk) pushReadyLocked(v *Conn) {
	n := len(t.readyRing)
	if t.readyN >= n {
		panic("rendr/carrier: the ready ring overflowed")
	}
	t.readyRing[(t.readyHead+t.readyN)%n] = v
	t.readyN++
}

// unreadyLocked removes v from the ring (an ended view; rare, O(ring)).
func (t *trunk) unreadyLocked(v *Conn) {
	n := len(t.readyRing)
	k := 0
	for i := 0; i < t.readyN; i++ {
		w := t.readyRing[(t.readyHead+i)%n]
		if w == v {
			continue
		}
		t.readyRing[(t.readyHead+k)%n] = w
		k++
	}
	for i := k; i < t.readyN; i++ {
		t.readyRing[(t.readyHead+i)%n] = nil
	}
	if k != t.readyN {
		v.ready.Store(false)
	}
	t.readyN = k
}

// readyLocked readies v (the CAS-and-push of R1-1 rule 2).
func (t *trunk) readyLocked(v *Conn) {
	if t.ms.multi.Load() && v.vx.fillOK.Load() && v.ready.CompareAndSwap(false, true) {
		t.pushReadyLocked(v)
	}
}

// wakeView is Conn.Wake on a view of a MUX trunk (R1-1 rule 2): with a
// view table the view is readied (CAS, then the push under mx), then the
// writer's cap-1 wake always.
func (c *Conn) wakeView() {
	t := c.trunk
	if t.ms.multi.Load() && c.vx.fillOK.Load() && c.ready.CompareAndSwap(false, true) {
		t.mx.Lock()
		if c.vx.inTable && c.vx.fillOK.Load() {
			t.pushReadyLocked(c)
		} else {
			c.ready.Store(false)
		}
		t.mx.Unlock()
	}
	t.wakeWriter()
}

// markWorkLocked tells the writer that mux control is queued.
func (t *trunk) markWorkLocked() { t.ms.work.Store(true) }

// Endpoint calls into a view (M3-D13, R1-16).

// enter counts an endpoint call into v; false when v's Done closed (no
// call starts after it). A view without its own Done (a dedicated
// carrier) is not counted.
func (v *Conn) enter() bool {
	if !v.vx.own {
		return true
	}
	for {
		s := v.calls.Load()
		if s&doneBit != 0 {
			return false
		}
		if v.calls.CompareAndSwap(s, s+1) {
			return true
		}
	}
}

// exit ends a call entered with enter; the call that brings an ended
// view's count to 0 closes its Done.
func (v *Conn) exit() {
	if !v.vx.own {
		return
	}
	if v.calls.Add(-1) == 0 && v.vx.fin.Load() && v.calls.CompareAndSwap(0, doneBit) {
		v.trunk.viewDoneClosed(v)
	}
}

// finish marks v ended: its Done closes now if no call is in progress,
// else when the last one exits. It must run without trunk.mx (closing
// Done takes it); finishLocked is the variant for holders of mx.
func (t *trunk) finish(v *Conn) {
	v.vx.fin.Store(true)
	if v.calls.CompareAndSwap(0, doneBit) {
		t.viewDoneClosed(v)
	}
}

// finishLocked is finish under mx: the Done close runs at runPost.
func (t *trunk) finishLocked(v *Conn, p *postList) {
	v.vx.fin.Store(true)
	if v.calls.CompareAndSwap(0, doneBit) {
		p.done = append(p.done, v)
	}
}

// viewDoneClosed closes v's Done (once, after its last call), lowers the
// view count and runs the OnDone doorbell and the pool's view hook. The
// close and doneShut change together under mx, so an OnDone either sees
// Done closed and rings at once or registers its bell before the close
// (R1-7: no lost ring). The pool's hook runs on a goroutine of its own:
// view Kill, Retire and WriteAndClose may close Done inline and may be
// called under Session.mu or Pool.mu, while the hook takes Pool.mu.
func (t *trunk) viewDoneClosed(v *Conn) {
	t.mx.Lock()
	close(v.done)
	v.vx.doneShut = true
	t.nviews--
	t.ms.full = false
	b := v.vx.onDone
	v.vx.onDone = nil
	f := t.viewDone
	t.mx.Unlock()
	if b != nil {
		b.Ring()
	}
	if f != nil {
		go f(v)
	}
}

// runPost runs what the holder of mx collected: Done closes, view bells and
// AfterDetach hooks. The writer and the reader call it after releasing mx.
func (t *trunk) runPost(p *postList) {
	for i, v := range p.done {
		t.viewDoneClosed(v)
		p.done[i] = nil
	}
	p.done = p.done[:0]
	for i, v := range p.bells {
		v.ring()
		p.bells[i] = nil
	}
	p.bells = p.bells[:0]
	if len(p.hooks) > 0 {
		if hk := t.env.Hooks; hk != nil && hk.AfterDetach != nil {
			for _, e := range p.hooks {
				hk.AfterDetach(t.id, e.h, e.sent)
			}
		}
		p.hooks = p.hooks[:0]
	}
}

// The reader side: classification of session frames (§A3.3, §A5.4).

// muxAct is what the reader does with a session frame on a MUX trunk.
type muxAct uint8

const (
	actDispatch muxAct = iota // the view's endpoint (with its call counted)
	actAdmit                  // a new handle's OPEN or JOIN on a passive MUX trunk (admit)
	actResponse               // the response of a dialer view awaiting it (onResponse)
	actIgnore                 // legal, not delivered (after our DETACH and the view's Done; a refused handle's late frame)
	actIllegal                // a §A3.3 violation (stream) or counted drop (datagram)
)

// isFirstType reports OPEN, OPEN_ACK, JOIN and JOIN_ACK: the frames that
// open a handle or answer its opening.
func isFirstType(t wire.Type) bool {
	return t == wire.TypeOpen || t == wire.TypeOpenAck || t == wire.TypeJoin || t == wire.TypeJoinAck
}

// respTypeOf returns the response type of a first frame type.
func respTypeOf(t wire.Type) wire.Type {
	if t == wire.TypeJoin {
		return wire.TypeJoinAck
	}
	return wire.TypeOpenAck
}

// classify decides what the reader does with a session frame of type typ
// for handle h on a MUX trunk (§A3.3, §A5.4). why names the rule a frame
// broke. A frame for the cached live view is dispatched without the lock.
func (t *trunk) classify(typ wire.Type, h uint32) (act muxAct, v *Conn, why string) {
	if v := t.last.Load(); v != nil && v.handle == h && !isFirstType(typ) {
		return actDispatch, v, ""
	}
	t.mx.Lock()
	act, v, why = t.classifyLocked(typ, h)
	t.mx.Unlock()
	return act, v, why
}

func (t *trunk) classifyLocked(typ wire.Type, h uint32) (muxAct, *Conn, string) {
	v := t.lookupLocked(h)
	if v == nil {
		if typ != wire.TypeOpen && typ != wire.TypeJoin && t.toleratedLocked(h, typ, false) {
			return actIgnore, nil, ""
		}
		if !t.dialer && (typ == wire.TypeOpen || typ == wire.TypeJoin) && h > max(t.maxHandle, wire.SessionHandle) {
			return actAdmit, nil, ""
		}
		switch {
		case typ == wire.TypeOpen || typ == wire.TypeJoin:
			if t.dialer {
				return actIllegal, nil, "an OPEN or JOIN at the dialer"
			}
			return actIllegal, nil, "a handle not above every handle seen"
		case t.dialer && !t.allocatedLocked(h), !t.dialer && h > max(t.maxHandle, wire.SessionHandle):
			return actIllegal, nil, "a handle never opened"
		}
		return actIllegal, nil, "no such view (ended)"
	}
	if typ == wire.TypeOpen || typ == wire.TypeJoin {
		return actIllegal, nil, "an OPEN or JOIN for a known handle"
	}
	switch v.state {
	case viewOpening:
		return actIllegal, nil, "a frame before the view's first frame"
	case viewAwaiting:
		if typ == respTypeOf(v.vx.first) {
			return actResponse, v, ""
		}
		return actIllegal, nil, "a frame before the view's response"
	case viewAttachedPending:
		return actIllegal, nil, "a frame before the go frame (the passive broke its hold)"
	case viewPending, viewJoining:
		if isFirstType(typ) {
			return actIllegal, nil, "a response from the dialer"
		}
		if !v.vx.attached {
			return actIllegal, nil, "a frame for a view no session attached"
		}
		return actDispatch, v, ""
	case viewHeld:
		if isFirstType(typ) {
			return actIllegal, nil, "a response from the dialer"
		}
		// The dialer's go frame (or any first frame of it) ends the hold.
		v.held.Store(false)
		v.state = viewLive
		v.vx.fillOK.Store(true)
		t.readyLocked(v)
		t.last.Store(v)
		t.wakeWriter()
		return actDispatch, v, ""
	case viewLive:
		if isFirstType(typ) {
			return actIllegal, nil, "an OPEN_ACK or JOIN_ACK for a live view"
		}
		if v.needGo.Load() {
			return actIllegal, nil, "a frame before the go frame (the passive broke its hold)"
		}
		if v.vx.peerDet.Load() {
			return actIllegal, nil, "a frame after the peer's DETACH"
		}
		t.last.Store(v)
		return actDispatch, v, ""
	case viewRetiring:
		if v.vx.peerDet.Load() {
			return actIllegal, nil, "a frame after the peer's DETACH"
		}
		if isFirstType(typ) {
			if v.vx.dialer && !v.vx.respGot && typ == respTypeOf(v.vx.first) {
				return actResponse, v, "" // the response crossed our DETACH
			}
			return actIllegal, nil, "an OPEN_ACK or JOIN_ACK for a retiring view"
		}
		if v.vx.dialer && v != t.view1 && (!v.vx.attached || v.needGo.Load()) {
			if v.vx.lastSent {
				// Our last frame for the view (the RST(AbortWithdrawn) of
				// an abandoned OPEN, R1-5) ended the passive's hold: what it
				// placed for the handle meanwhile is legal; a view no
				// session attached takes none of it (WP10).
				if !v.vx.attached {
					return actIgnore, nil, ""
				}
				return actDispatch, v, ""
			}
			return actIllegal, nil, "a frame before the go frame (the passive broke its hold)"
		}
		return actDispatch, v, "" // a retiring lane (M1); dropped after the view's Done
	}
	return actIllegal, nil, "a frame for an ended view"
}

// firstHandleLocked returns the first handle the dialer allocates after
// view 1 (Presets.FirstHandle, L14).
func (t *trunk) firstHandle() uint32 {
	return max(t.env.Presets.FirstHandle, wire.SessionHandle+1)
}

// nextLocked returns the next handle the dialer allocates (the trunk is
// not sealed).
func (t *trunk) nextLocked() uint32 {
	if t.next == 0 {
		return t.firstHandle()
	}
	return t.next
}

// allocatedLocked reports whether the dialer allocated handle h.
func (t *trunk) allocatedLocked(h uint32) bool {
	switch {
	case h == wire.SessionHandle:
		return true
	case h < t.firstHandle():
		return false
	case t.sealed && t.next == 0:
		return true // the whole space up to 0xFFFFFFFF was allocated
	}
	return t.next != 0 && h < t.next
}

// countRx adds n received payload bytes to v's own counter.
func (v *Conn) countRx(n int) {
	if v.vx.own {
		v.rx.Add(uint64(n))
	}
}

// The writer side (§A5.3).

// roundData is what one MUX writer round reads under the estimator lock.
type roundData struct {
	srtt     time.Duration
	rto      time.Duration
	una      uint32 // datagram: the REL sender's oldest unacknowledged cseq
	relNext  uint32 // datagram: the next cseq (writer-owned)
	relRoom  int
	pongMark uint64
	goAway   bool
}

// muxRound appends one writer round of a MUX trunk (fillRound).
func (t *trunk) muxRound(b *Batch) {
	ms := &t.ms
	multi := ms.multi.Load()
	if !multi && !ms.work.Load() {
		t.oneViewFill(b, nil)
		return
	}
	now := b.Now()
	nowNs := t.nsAt(now)
	var rd roundData
	t.mu.Lock()
	rd.srtt, rd.pongMark, rd.goAway = t.st.srtt, t.st.pongMark, t.st.goAway
	if t.dg != nil {
		rd.rto = t.view1.relRTOLocked()
		rd.una, rd.relNext, rd.relRoom = t.dg.rel.una, t.dg.rel.next, t.dg.rel.room()
	}
	t.mu.Unlock()

	t.mx.Lock()
	t.placeControlLocked(b, &rd, nowNs, &ms.post)
	n := 0
	if multi {
		t.reReadyLocked(&rd, nowNs)
		n = t.takeReadyLocked()
	}
	t.mx.Unlock()
	t.runPost(&ms.post)

	if !multi {
		t.oneViewFill(b, &rd)
	} else if n > 0 {
		t.drrRound(b, n, &rd, nowNs)
	}
	// The cap list and the wake times are mx state: an openView that
	// builds the table, or a reader that marks a view, writes them
	// concurrently, so they are read under mx (a data race in I1's race
	// lane: TestPoolSealAtZero/open_races_the_close).
	t.mx.Lock()
	if n > 0 {
		t.returnScratchLocked(n)
	}
	capped, nextWake, detWake := len(ms.capList) > 0, ms.nextWake, ms.detWake
	t.mx.Unlock()
	if n > 0 {
		t.runPost(&ms.post)
	}
	if capped {
		// Views still wait on the shared capacity although they were not
		// called this round: the trunk stays cap-blocked, so the PONG that
		// frees capacity wakes the writer (C5) and re-readies them.
		b.capBlocked = true
	}
	if nextWake != 0 {
		b.WakeAt(t.base.Add(time.Duration(nextWake)))
	}
	if detWake != 0 {
		b.WakeAt(t.base.Add(time.Duration(detWake)))
	}
}

// oneViewFill is the round of a MUX trunk without a view table: view 1's
// Fill without a quota (M2's path), counted; with rd (mux control was
// queued) a planned retirement places view 1's DETACH once its Fill
// placed nothing.
func (t *trunk) oneViewFill(b *Batch, rd *roundData) {
	v := t.view1
	if !v.vx.fillOK.Load() || !v.enter() {
		return
	}
	nb, pb, rb := b.n, b.payload(), b.retx
	v.ep.Fill(v, b)
	v.exit()
	t.countTx(v, b, nb, pb, rb)
	if rd != nil && b.n == nb && v.vx.retireQ.Load() {
		t.mx.Lock()
		t.retireDrainedLocked(v, b, rd, t.nsAt(b.Now()), &t.ms.post)
		t.mx.Unlock()
		t.runPost(&t.ms.post)
	}
}

// countTx adds a call's frames and payload to v's own counters.
func (t *trunk) countTx(v *Conn, b *Batch, nb, pb, rb int) {
	if n := b.n - nb; n > 0 {
		v.frames.Add(uint64(n))
	}
	if n := b.payload() - pb; n > 0 {
		v.tx.Add(uint64(n))
	}
	if n := b.retx - rb; n > 0 {
		v.retx.Add(uint64(n))
	}
}

// takeReadyLocked moves the ready ring into the writer's scratch (the
// views keep ready set) and returns their number.
func (t *trunk) takeReadyLocked() int {
	n := t.readyN
	r := len(t.readyRing)
	for i := 0; i < n; i++ {
		k := (t.readyHead + i) % r
		t.ms.scratch[i] = t.readyRing[k]
		t.readyRing[k] = nil
	}
	t.readyHead, t.readyN = 0, 0
	return n
}

// returnScratchLocked puts the scratch views the round left ready back
// onto the ring in rotation order (R1-1 rule 4); views that ended
// meanwhile leave it.
func (t *trunk) returnScratchLocked(n int) {
	sc := t.ms.scratch
	for i := 0; i < n; i++ {
		v := sc[i]
		if v == nil {
			continue
		}
		sc[i] = nil
		if !v.ready.Load() {
			continue
		}
		if v.vx.inTable && v.vx.fillOK.Load() {
			t.pushReadyLocked(v)
		} else {
			v.ready.Store(false)
		}
	}
}

// drrRound runs the control pass and deficit round robin over the n
// scratch views (M3-D10, R1-1).
func (t *trunk) drrRound(b *Batch, n int, rd *roundData, nowNs int64) {
	sc := t.ms.scratch[:n]
	start := t.cursor % n
	t.cursor++
	t.ms.touched += uint64(n)
	quantum := t.tm.MuxQuantum
	// Control pass: every ready view places its control frames (ACK, FIN,
	// RST, SCHED, PACK, responses) before any view's payload (L16).
	for i := 0; i < n; i++ {
		v := sc[(start+i)%n]
		if !v.vx.fillOK.Load() || b.Full() {
			continue
		}
		b.limit(0)
		t.viewCall(v, b, rd, nowNs)
	}
	// Deficit round robin over one shared capacity.
	for {
		progressed := false
		for i := 0; i < n; i++ {
			if b.budget-b.data <= 0 || b.Full() {
				b.limit(-1)
				return
			}
			k := (start + i) % n
			v := sc[k]
			if v == nil {
				continue
			}
			if !v.vx.fillOK.Load() {
				sc[k] = nil
				v.ready.Store(false)
				continue
			}
			q := min(v.deficit+quantum, 2*quantum)
			b.limit(q)
			v.ready.Store(false) // R1-1 rule 3: cleared before the call
			appended, used := t.viewCall(v, b, rd, nowNs)
			if hk := t.env.Hooks; hk != nil && hk.AfterViewFill != nil {
				hk.AfterViewFill(t.id, v.handle)
			}
			if used > 0 {
				v.deficit = max(q-used, 0)
			} else {
				v.deficit = 0
			}
			if appended == 0 && v.vx.retireQ.Load() {
				t.mx.Lock()
				t.retireDrainedLocked(v, b, rd, nowNs, &t.ms.post)
				t.mx.Unlock()
				t.runPost(&t.ms.post)
			}
			switch {
			case appended == 0 && b.nearFull(), appended > 0 && used == 0:
				// The view stays ready for the next round, which the writer
				// runs by itself (M2's self-continuation, per view; WP10):
				// a call that placed control frames only, or nothing because
				// the batch had no room left for what the view owes (a
				// control frame that did not fit), did not decide that the
				// view is idle — its endpoint marks itself idle only after a
				// call that placed nothing, and its producers wake only idle
				// lanes, so dropping it here lost its next data until an
				// unrelated wakeup. It goes back onto the ring at once (not
				// called again in this round): its next call is in the next
				// round, whose control pass places what a producer added
				// meanwhile before any payload (L16).
				sc[k] = nil
				if v.ready.CompareAndSwap(false, true) {
					t.mx.Lock()
					if v.vx.inTable && v.vx.fillOK.Load() {
						t.pushReadyLocked(v)
					} else {
						v.ready.Store(false)
					}
					t.mx.Unlock()
				}
			case used == 0:
				sc[k] = nil // a Wake during or after the call pushed it again
			case !v.ready.CompareAndSwap(false, true):
				sc[k] = nil // a Wake pushed it: the ring carries it
			default:
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	b.limit(-1)
}

// viewCall makes one Fill call of view v (quota set by the caller) and
// keeps the view's state: per-view WakeAt, cap and REL marks, counters,
// the go frame and the passive's first response. It returns the frames and
// payload bytes the call appended.
func (t *trunk) viewCall(v *Conn, b *Batch, rd *roundData, nowNs int64) (appended, used int) {
	if !v.enter() {
		return 0, 0
	}
	nb, pb, rb := b.n, b.payload(), b.retx
	wake, capB, relB := b.wake, b.capBlocked, b.relBlocked
	b.wake, b.capBlocked, b.relBlocked = time.Time{}, false, false
	needResp := v.vx.needResp.Load()
	if needResp {
		b.holdH = v.handle // nothing after its OK response (M3-D8)
	}
	v.ep.Fill(v, b)
	v.exit()
	b.holdH, b.holdOn = 0, false
	ms := &t.ms
	if b.capBlocked && !v.capMarked {
		v.capMarked = true
		ms.capList = append(ms.capList, v)
		ms.capPM = rd.pongMark
	}
	if b.relBlocked && !v.vx.relMarked {
		v.vx.relMarked = true
		ms.relList = append(ms.relList, v)
	}
	if w := b.wake; !w.IsZero() {
		if at := t.nsAt(w); at > nowNs && (v.wakeAt == 0 || at < v.wakeAt) {
			if v.wakeAt == 0 {
				ms.wakeList = append(ms.wakeList, v)
			}
			v.wakeAt = at
			if ms.nextWake == 0 || at < ms.nextWake {
				ms.nextWake = at
			}
		}
		if wake.IsZero() || w.Before(wake) {
			wake = w
		}
	}
	b.wake, b.capBlocked, b.relBlocked = wake, capB || b.capBlocked, relB || b.relBlocked
	appended, used = b.n-nb, b.payload()-pb
	t.countTx(v, b, nb, pb, rb)
	if appended == 0 {
		return 0, used
	}
	if v.needGo.Load() {
		v.needGo.Store(false) // the go frame is the lane's first frame (M3-D8)
	}
	if needResp {
		if typ, st, ok := b.responseIn(nb, v.handle); ok {
			t.mx.Lock()
			t.responsePlacedLocked(v, typ, st, &ms.post)
			t.mx.Unlock()
			t.runPost(&ms.post)
		}
	}
	return appended, used
}

// reReadyLocked readies the views whose wake came (§A4.3): the views a
// PONG freed capacity for (cap-marked, once the PONG watermark moved), the
// views a RACK freed REL room for, and the views whose WakeAt is due. It
// visits the marked views only, never the idle ones (L54).
func (t *trunk) reReadyLocked(rd *roundData, nowNs int64) {
	ms := &t.ms
	if len(ms.capList) > 0 && rd.pongMark != ms.capPM {
		for i, v := range ms.capList {
			ms.touched++
			v.capMarked = false
			t.readyLocked(v)
			ms.capList[i] = nil
		}
		ms.capList = ms.capList[:0]
	}
	if len(ms.relList) > 0 && rd.relRoom > 0 {
		for i, v := range ms.relList {
			ms.touched++
			v.vx.relMarked = false
			t.readyLocked(v)
			ms.relList[i] = nil
		}
		ms.relList = ms.relList[:0]
	}
	if ms.nextWake == 0 || nowNs < ms.nextWake {
		return
	}
	ms.nextWake = 0
	k := 0
	for i, v := range ms.wakeList {
		ms.touched++
		ms.wakeList[i] = nil
		switch {
		case v.wakeAt == 0:
		case v.wakeAt <= nowNs:
			v.wakeAt = 0
			t.readyLocked(v)
		default:
			ms.wakeList[k] = v
			k++
			if ms.nextWake == 0 || v.wakeAt < ms.nextWake {
				ms.nextWake = v.wakeAt
			}
		}
	}
	ms.wakeList = ms.wakeList[:k]
}

// Fan-outs (M3-D14, §A4.3).

// viewsSnapshot returns the views of the trunk (the table's, or view 1).
func (t *trunk) viewsSnapshot() []*Conn {
	if !t.ms.multi.Load() {
		return []*Conn{t.view1}
	}
	t.mx.Lock()
	out := make([]*Conn, 0, len(t.views))
	for _, v := range t.views {
		out = append(out, v)
	}
	t.mx.Unlock()
	return out
}

// ringAll rings the doorbell of every view: the trunk's death, the peer's
// CLOSE and GOAWAY concern all of them (M3-D14).
func (t *trunk) ringAll() {
	if !t.ms.multi.Load() {
		t.view1.ring()
		return
	}
	for _, v := range t.viewsSnapshot() {
		v.ring()
	}
}

// writeBlockedAll reports a blocked batch write to every attached view's
// endpoint (M3-D14; each call counted, R1-16; views whose Done closed are
// skipped).
func (t *trunk) writeBlockedAll() {
	for _, v := range t.viewsSnapshot() {
		if !v.vx.fillOK.Load() || !v.enter() {
			continue
		}
		v.ep.WriteBlocked(v)
		v.exit()
	}
}

// finishAll ends every view of a trunk whose Done closed: every view not
// yet gone becomes dead (§A5.4), and each view's Done closes once its
// calls drained (M3-D13).
func (t *trunk) finishAll() {
	vs := t.viewsSnapshot()
	t.mx.Lock()
	for _, v := range vs {
		if v.vx.own && v.state != viewGone {
			v.state = viewDead
		}
	}
	t.mx.Unlock()
	for _, v := range vs {
		if v.vx.own {
			t.finish(v)
		}
	}
	// Views that left the table but whose Done is still open (a killed
	// view waiting for its calls) close at their last call.
}

// Starting views.

// startMux runs inside view 1's Start on a MUX trunk, before the goroutines
// start: view 1 gets its own Done (a view of a MUX trunk retires without
// ending the trunk, M3-D13) and becomes live.
func (c *Conn) startMux() {
	c.done = make(chan struct{})
	c.vx.own, c.vx.inTable, c.vx.attached, c.vx.dialer = true, true, true, c.dialer
	c.state = viewLive
	c.vx.fillOK.Store(true)
	c.ms.started.Store(true)
}

// startView is Start on a view created on a started MUX trunk (§A5.1): the
// session's endpoint replaces the shim; a dialer view goes live with its
// go frame owed (M3-D8), a passive view is readied so that its Fill places
// the first response. A view that already ended rings bell and starts
// nothing.
func (c *Conn) startView(ep Endpoint, bell Doorbell, o StartOptions) {
	t := c.trunk
	if bell != nil {
		c.bell.Store(&ringer{bell})
	}
	t.mx.Lock()
	if c.vx.attached || !c.vx.inTable || c.vx.detQ || c.vx.fin.Load() || t.death.Load() != nil ||
		(c.state != viewAttachedPending && c.state != viewPending && c.state != viewJoining) {
		t.mx.Unlock()
		if bell != nil {
			bell.Ring()
		}
		return
	}
	c.ep = ep
	c.pep, _ = ep.(PacketEndpoint)
	c.vx.attached = true
	if c.state == viewAttachedPending {
		c.state = viewLive
		c.needGo.Store(true)
	}
	c.vx.fillOK.Store(true)
	t.readyLocked(c)
	t.mx.Unlock()
	t.wakeWriter()
}

// The dialer's views (§A5.4, §A5.8).

// openViewMux allocates the next handle on a started dialer MUX trunk
// (M3-D4): the view in state opening, its first frame copied and queued in
// the opens FIFO behind every earlier handle (awaitResponse releases it),
// the view count raised. At the end of the handle space the trunk seals.
func (t *trunk) openViewMux(kind wire.Type, payload []byte, sess uintptr) (*Conn, error) {
	if kind != wire.TypeOpen && kind != wire.TypeJoin {
		return nil, fmt.Errorf("rendr/carrier: openView of %v", kind)
	}
	if !t.mux || !t.dialer || !t.ms.started.Load() || t.death.Load() != nil {
		return nil, ErrDead
	}
	if t.dg != nil && wire.RelHeadLen+len(payload) > wire.RelMaxPayload {
		return nil, ErrDead // a REL slot cannot carry it: the attempt dials
	}
	t.mx.Lock()
	defer t.mx.Unlock()
	if t.sealed || t.nviews+t.refN >= t.maxViews() {
		return nil, ErrDead
	}
	h := t.nextLocked()
	t.next = h + 1 // never reused (M3-D4)
	if t.next == 0 {
		t.sealed = true // the handle space ended: no new view (M3-D4, PA-37)
	}
	if t.opens == nil {
		t.opens = make([]*Conn, t.maxViews()+1)
	}
	if t.ms.opN >= len(t.opens) {
		return nil, ErrDead
	}
	v := t.newViewLocked(h, viewOpening)
	v.vx.dialer, v.vx.first, v.vx.sess = true, kind, sess
	v.vx.firstP = append([]byte(nil), payload...)
	if t.dg != nil {
		patchViewOffer(kind, v.vx.firstP, int(t.dg.budget.Load())) // the trunk's current budget (§A3.3)
	}
	v.vx.resp = make(chan struct{})
	t.opens[(t.ms.opHead+t.ms.opN)%len(t.opens)] = v
	t.ms.opN++
	return v, nil
}

// awaitResponseMux releases view c's first frame to the writer (after the
// BeforeOpenView hook), then waits for its response, bounded by ctx and the
// trunk's death. An OK response runs check on the trunk's PREFACE_ACK; a
// failed check ends the view (Kill on the view), never the trunk. A
// refusal ends the handle (M3-D7) and is returned like Establish returns
// one. ctx ending abandons the view (Kill: DETACH once its first frame was
// placed).
func (c *Conn) awaitResponseMux(ctx context.Context, check func(*wire.PrefaceAck) error) (*Established, error) {
	t := c.trunk
	if hk := t.env.Hooks; hk != nil && hk.BeforeOpenView != nil {
		hk.BeforeOpenView(t.id, c.handle)
	}
	t.mx.Lock()
	if c.state == viewOpening && !c.vx.queued {
		c.vx.queued = true
		t.markWorkLocked()
	}
	resp := c.vx.resp
	t.mx.Unlock()
	t.wakeWriter()
	select {
	case <-resp:
	case <-ctx.Done():
	case <-t.dying:
	}
	ack := wire.PrefaceAck{Status: wire.PrefaceOK, Opt: wire.OptMux, Instance: t.peer, CarrierID: t.id}
	t.mx.Lock()
	got, hdr, p := c.vx.respGot, c.vx.rhdr, c.vx.rp
	t.mx.Unlock()
	if got {
		st := wire.AckStatus(0)
		if len(p) > 0 {
			st = wire.AckStatus(p[0])
		}
		if st == wire.StatusOK && check != nil {
			if err := check(&ack); err != nil {
				c.Kill(CauseInstanceMismatch, "check: "+err.Error())
				return nil, &EstablishError{Stage: "preface", Cause: CauseInstanceMismatch, PrefaceOK: true, Instance: t.peer, Err: err}
			}
		}
		return &Established{Conn: c, Ack: ack, Resp: hdr, Payload: p}, nil
	}
	if err := ctx.Err(); err != nil {
		if c.vx.first == wire.TypeOpen && errors.Is(context.Cause(ctx), ErrWithdrawn) {
			// A withdrawn OPEN (its session never opened): RST(AbortWithdrawn)
			// for the handle, then DETACH(ended), so the passive's pending
			// session withdraws at once (R1-5 rule 1, L49) — as Establish's
			// withdrawal RST on a dedicated carrier. A first frame never
			// placed leaves a handle gap and places nothing.
			c.WriteAndClose(wire.TypeRst, 0, c.handle, rstWithdrawnPayload, time.Time{})
		} else {
			c.Kill(CauseLocalClose, "attempt ended before the response")
		}
		return nil, &EstablishError{Stage: "response", Cause: CauseLocalClose, PrefaceOK: true, Instance: t.peer, Err: context.Cause(ctx)}
	}
	c.Kill(CauseTransportError, "the carrier ended before the response")
	return nil, &EstablishError{Stage: "response", Cause: CauseTransportError, PrefaceOK: true, Instance: t.peer, Err: errors.New("rendr/carrier: the carrier ended before the view's response")}
}

// usableForMux is the trunk half of the pool's usable rule (M3-D17).
// kind is the session's data frame type — wire.TypeData for a stream
// session, wire.TypeDgram for a packet session — and inst is the bound
// instance of a JOIN (zero for an OPEN).
func (t *trunk) usableForMux(kind wire.Type, inst [16]byte, sess uintptr) bool {
	if !t.mux || !t.dialer || !t.ms.started.Load() || t.death.Load() != nil {
		return false
	}
	if t.peerClosed.Load() || t.peerGoAway.Load() || t.closeSent.Load() || t.wstate.Load()&1 != 0 {
		return false
	}
	if kind == wire.TypeData && t.dg != nil {
		return false // a stream session needs a stream trunk (M3-D24)
	}
	if inst != ([16]byte{}) && inst != t.peer {
		return false
	}
	t.mu.Lock()
	retiring := t.st.retiring || t.st.goAway
	t.mu.Unlock()
	if retiring {
		return false
	}
	t.mx.Lock()
	defer t.mx.Unlock()
	if t.sealed || t.ms.full || t.nviews >= t.maxViews() || (inst == ([16]byte{}) && t.openFull) {
		return false
	}
	if sess != 0 {
		// One unreaped view per session (R1-6): a view of the session that
		// has not ended keeps its lane in the session.
		if v := t.view1; v.vx.inTable && v.vx.sess == sess && !v.vx.fin.Load() {
			return false
		}
		for _, v := range t.views {
			if v.vx.sess == sess && !v.vx.fin.Load() {
				return false
			}
		}
	}
	return true
}

// bindSession records the session a dialer view belongs to (the pool sets
// it on view 1 of a fresh trunk when it publishes it; openView records it
// on later views) for the one-view-per-session rule (R1-6).
func (c *Conn) bindSession(sess uintptr) {
	if c.trunk == nil {
		return
	}
	c.mx.Lock()
	c.vx.sess = sess
	c.mx.Unlock()
}

// retireTrunk retires the physical carrier with CLOSE(r) (M2's Retire on
// a dedicated carrier): the pool's close at the last view (§A5.9).
func (t *trunk) retireTrunk(r wire.CloseReason) {
	t.mu.Lock()
	if t.st.retiring {
		t.mu.Unlock()
		return
	}
	t.st.retiring, t.st.reason = true, r
	t.mu.Unlock()
	t.wakeWriter()
}
