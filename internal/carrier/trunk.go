package carrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// rendr mux (M3 design §A5; M3-D1). Every carrier is a trunk — the
// physical carrier: socket, reader, writer, fseq, CRC, estimator, PING,
// death, REL — carrying one or more views, one per session: handle,
// endpoint, retirement state. Conn is the view and embeds *trunk; a
// dedicated carrier is a trunk with exactly one view (handle 1), so M2's
// data path is the one-view case and a one-view trunk never builds the
// view table.
//
// The trunk holds every physical field of a carrier — the embedder conn,
// the reader and writer state, fseq, the estimator and PING records, the
// death record, the joins, the datagram half — and the mux state of a
// carrier that negotiated wire.OptMux (a MUX trunk). Every view of a trunk
// reads the physical fields through the embedded pointer. Every carrier
// built by the handshakes (Establish, ReadHello and the datagram
// handshakes) is a trunk with its view 1 (newConn). A Conn whose trunk is
// nil is a bare identity that no carrier code runs on (component tests of
// the session build such Conns); its accessors report zero values.
//
// The reader and writer goroutines run as methods of view 1 but reach a
// view's endpoint only through route (reader) and fillRound (writer), so a
// one-view trunk is M2's data path with one handle compare.
//
// Locks: mx is a leaf (view table, ready ring, opens FIFO, last-hit cache
// writes, view count, refusal ring). It is taken by Conn.Wake (often under
// the session lock: Session.mu → trunk.mx), by the writer between
// endpoint calls (never across an Endpoint.Fill), by the reader on a cache
// miss and by view attach and detach; Pool.mu → trunk.mx when a view is
// allocated. The estimator lock (mu, M2's Conn.mu) is another leaf: the
// two never nest. admit releases mx before it calls Env.Admit (R1-17).
//
// Concurrency of the physical fields (M2): the death record, the write
// state (generation and WriteBlocked), the peer CLOSE/GOAWAY and CLOSE-sent
// flags and a few counters are atomics; the estimator, the PING records
// and carrier-level control live under mu (a leaf lock: session.mu →
// trunk.mu); the goroutine join bookkeeping lives under jmu (a leaf). The
// reader and writer state is owned by those goroutines. No endpoint is
// ever called with mu held.
type trunk struct {
	// Immutable from construction.
	env     *Env
	tm      Timing // env.Timing with defaults for zero fields
	nc      net.Conn
	ncClose closeOnce // closes nc (a datagram carrier: its dg.io, R1-7) exactly once: the closer, or the last resort of its abandonment (V2)
	owned   *OwnedTCP // nc itself when it is rendr's ownership token (D3, L57); nil otherwise
	id      uint32    // the CarrierID: every view of the trunk reports it (§A5.1)
	peer    [16]byte
	factory int    // -1 on the passive side
	name    string // "" on the passive side
	dialer  bool   // id was allocated from env.IDs and is released when Done closes
	salt    uint64 // per-carrier random PING nonce salt (D14)
	base    time.Time

	wake  chan struct{} // cap 1: the writer's coalescing wakeup
	dying chan struct{} // closed when the death record is set
	tdone chan struct{} // closed when every goroutine of the carrier finished or was abandoned (view 1's Done; a view's Done is its own on a MUX trunk, M3-D13)

	death      atomic.Pointer[deathRecord]
	wstate     atomic.Uint64 // write generation << 1 | WriteBlocked (C6)
	peerClosed atomic.Bool   // the peer's CLOSE (handle 0) arrived
	peerGoAway atomic.Bool
	closeSent  atomic.Bool // our CLOSE (handle 0) was written
	capBlocked atomic.Bool // the writer's last round was cap-blocked (C5)
	rxData     atomic.Bool // DATA arrived since the previous PING was encoded (P12)
	rxBytes    atomic.Uint64
	lastRx     atomic.Int64 // nanoseconds after base when the last frame arrived; 0 = none

	// Set by view 1's Start under mu before the goroutines run; read by
	// them.
	opts StartOptions

	mu sync.Mutex
	st carrierState // guarded by mu

	jmu  sync.Mutex
	join joinState // guarded by jmu

	rd reader // reader goroutine (and ReadHello before Start)
	wr writer // writer goroutine (and the handshake writers before Start)

	// dg is the datagram half of a datagram carrier (M2-D3), set by the
	// datagram handshakes before the Conn is returned; nil on stream
	// carriers.
	dg *dgState

	// Two-stage write watchdog (design §4.8, C6): reused AfterFunc timers
	// whose callbacks act only for the write generation they were armed for.
	wd1, wd2       *time.Timer
	wd1Gen, wd2Gen atomic.Uint64
	wd1At, wd2At   atomic.Int64 // nanoseconds after base when each stage is due

	// The mux state (M3-D1 … M3-D13).
	mux   bool  // OptMux negotiated: both PREFACE and PREFACE_ACK carried it (M3-D3); immutable after the handshake
	owner *Pool // dialer MUX trunks: the pool that publishes and closes it; nil on the passive side
	// kinds is the session kind a dialer MUX trunk carries, as the data
	// frame type (wire.TypeData: stream sessions, wire.TypeDgram: packet
	// sessions): its claimant's, set by the pool under Pool.mu before the
	// trunk is published and read under Pool.mu (KINDSPLIT). Zero on a
	// trunk no pool owns: no kind restriction beyond M3-D24.
	kinds wire.Type

	// last is the last-hit dispatch cache (M3-D9): the reader tries it
	// before the view table. Written under mx, read lock-free.
	last atomic.Pointer[Conn]

	mx        sync.Mutex
	views     map[uint32]*Conn // live and retiring views by handle; built at the second view (a one-view trunk compares with view 1)
	view1     *Conn            // the view of handle 1 (the handshake's); immutable from newTrunk, read without mx (route, fillRound)
	nviews    int              // views not yet gone (opening, awaiting, attached-pending, live, retiring; pending, joining, held on the passive)
	next      uint32           // dialer: the next handle to allocate (from Presets.FirstHandle, never reused)
	maxHandle uint32           // passive: the largest handle seen (a new handle must exceed it)
	sealed    bool             // no new view: the handle space ended (M3-D4) or the pool closed the trunk at its last view (M3-D20)
	openFull  bool             // dialer: the peer answered CAPACITY CodeListenerClosed: no further OPEN on this trunk (R1-10); JOINs stay
	readyRing []*Conn          // the writer's ready ring of views (fixed, MuxMaxViews entries; a view is in it or in the writer's round scratch exactly while its ready flag is set, R1-1)
	readyHead int              // ring position of the oldest ready view
	readyN    int              // ready views in the ring
	opens     []*Conn          // dialer: views whose first frame (OPEN or JOIN) is not yet placed, in allocation order (§A3.2)
	refusals  []refusal        // passive: queued refusal answers for handles that never became views (R1-4)
	refHead   int              // ring position of the oldest queued answer
	refN      int              // queued answers (counted with the views against MuxMaxViews)
	listener  any              // passive: the root's record of the Listener that accepted the trunk (opaque here; admission uses its queues, §A5.6)
	viewDone  func(*Conn)      // dialer: the pool's view-count hook, called once per view at its Done (onViewDone)

	ms muxState // the rest of the mux state (mux.go)
}

// viewState is a view's handle lifecycle state (M3 design §A5.4). Its
// transitions run under trunk.mx unless the table says otherwise.
type viewState uint8

// View states. Gone and dead are terminal.
const (
	viewNone viewState = iota // a dedicated carrier's view: M2's lifecycle
	// Dialer.
	viewOpening         // handle allocated, first frame (OPEN/JOIN) queued in the opens FIFO
	viewAwaiting        // first frame placed, waiting for OPEN_ACK/JOIN_ACK
	viewAttachedPending // OK response read; the attempt returned the view; the session has not started it
	// Passive.
	viewPending // an admitted OPEN, waiting for its verdict
	viewJoining // an admitted JOIN or duplicate OPEN, waiting for its session's answer
	viewHeld    // OK response placed on a started trunk; nothing else placed until the dialer's go frame (M3-D8)
	// Both.
	viewLive     // carrying the session's frames
	viewRetiring // DETACH placed or received, the exchange not complete (M3-D6)
	viewGone     // ended without a trunk death: refused, abandoned or retired
	viewDead     // the trunk died
)

// refusal is one queued refusal answer of the refusal ring: the handle it
// answers and the answer (a fixed-size record, no allocation).
type refusal struct {
	handle uint32
	a      Answer
}

// Answer is a fixed-size refusal record (M3-D12, R1-4): the response a
// passive MUX trunk places for a handle that never becomes a view —
// OPEN_ACK or JOIN_ACK with a status other than OK. Window and RxNext are
// the response's window (OPEN_ACK) and receive point (JOIN_ACK) fields.
type Answer struct {
	Type   wire.Type      // wire.TypeOpenAck or wire.TypeJoinAck
	Status wire.AckStatus // never wire.StatusOK
	Code   uint32
	Window uint32
	RxNext uint64
}

// newTrunk returns the physical carrier over nc with its view 1 (handle
// wire.SessionHandle), unstarted (§A5.1): the handshake code sets the first
// fseq and PING id it used, and the datagram handshakes its dg half. View
// 1's Done is the trunk's: a one-view trunk is M2's carrier. The view
// table is not built (a one-view trunk never builds it, M3-D1).
func newTrunk(env *Env, nc net.Conn, id uint32, peer [16]byte, factory int, name string, dialer bool) *trunk {
	t := &trunk{
		env:     env,
		tm:      env.Timing.withDefaults(),
		nc:      nc,
		ncClose: closeOnce{nc: nc},
		id:      id,
		peer:    peer,
		factory: factory,
		name:    name,
		dialer:  dialer,
		base:    time.Now(),
		wake:    make(chan struct{}, 1),
		dying:   make(chan struct{}),
		tdone:   make(chan struct{}),
		nviews:  1,
	}
	if o, ok := nc.(*OwnedTCP); ok { // the exact token type: a wrapper is never bypassed (L41, L57)
		t.owned = o
	}
	var s [8]byte
	_, _ = rand.Read(s[:]) // crypto/rand never fails (it crashes the program instead)
	t.salt = binary.LittleEndian.Uint64(s[:])
	first := env.Presets.firstFseq()
	t.rd.fseq, t.wr.fseq = first, first
	t.st.nextPingID = env.Presets.firstPingID()
	t.view1 = &Conn{trunk: t, handle: wire.SessionHandle, done: t.tdone}
	return t
}

// route returns the view of handle h, or nil (M3-D9). A one-view trunk
// compares h with view 1's handle only: no view table, no last-hit cache,
// no lock (M3-D1, TestTrunkOneViewHotPath). The multi-view case (the
// last-hit cache, else the view table under mx) is WP8's. The reader calls
// route for every session frame.
func (t *trunk) route(h uint32) *Conn {
	if t.mux {
		return t.routeMux(h) // mux.go
	}
	if v := t.view1; v.handle == h {
		return v
	}
	return nil
}

// fillRound appends one writer round of endpoint frames to b (M3-D10,
// §A5.3). With one view it is view 1's Fill without a quota (M2's path);
// a carrier without a session (probe, sessionless) has no endpoint and
// appends nothing. The multi-view round (the opens FIFO, the control pass
// over the ready views with quota 0, then deficit round robin with a
// payload quota per call over one shared capacity) is WP8's.
func (t *trunk) fillRound(b *Batch) {
	if t.mux {
		t.muxRound(b) // mux.go
		return
	}
	if v := t.view1; v.ep != nil {
		v.ep.Fill(v, b)
	}
}

// wakeWriter makes the writer run a round soon: the cap-1 coalescing
// wakeup (M2's Conn.Wake). The trunk's own work — a PONG due, a PING
// requested, CLOSE or GOAWAY queued, a death, capacity a PONG freed — wakes
// the writer through it; a session's wakeup goes through Conn.Wake, which
// on a view of a MUX trunk also readies the view (R1-1, WP8).
func (t *trunk) wakeWriter() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// ringViews rings the owner of every view of the trunk: its death, the
// peer's CLOSE and GOAWAY concern all of them (§A4.3; M3-D14's fan-out on
// a MUX trunk is WP8's). A one-view trunk rings view 1's doorbell.
func (t *trunk) ringViews() {
	if t.mux {
		t.ringAll() // mux.go
		return
	}
	t.view1.ring()
}

// admit handles an OPEN or JOIN for a new handle h on a started passive
// MUX trunk (M3-D21, §A5.6), on the reader: the view cap (views plus
// queued answers), the payload decode and our GOAWAY are checked here and
// refused through the refusal ring; otherwise a new view (pending or
// joining, shim endpoint) is inserted under mx and, with mx released,
// handed to Env.Admit. It never blocks; a full refusal ring kills the
// trunk ("mux flood").
func (t *trunk) admit(h uint32, hdr wire.Header, p []byte) {
	t.admitMux(h, hdr, p) // admit.go
}

// openView allocates the next handle on a started dialer MUX trunk and
// returns its new view in state opening, its first frame (OPEN or JOIN of
// kind kind, payload copied into the view's fixed slot) queued in the
// opens FIFO, the view count raised (M3-D4, §A5.4). sess identifies the
// session for the one-view-per-trunk rule. It fails with ErrDead on a dead
// or sealed trunk; at the end of the handle space it seals the trunk.
func (t *trunk) openView(kind wire.Type, payload []byte, sess uintptr) (*Conn, error) {
	return t.openViewMux(kind, payload, sess, false) // mux.go
}

// viewCount returns the views that are not gone (the pool's close rule,
// M3-D20).
func (t *trunk) viewCount() int {
	t.mx.Lock()
	defer t.mx.Unlock()
	return t.nviews
}

// seal makes the trunk take no new view (handle exhaustion, or the pool's
// close at the last view). Idempotent.
func (t *trunk) seal() {
	t.mx.Lock()
	t.sealed = true
	t.mx.Unlock()
}

// onViewDone registers the hook the trunk calls once for each view whose
// Done closed (the pool's view-count transition, §A5.9).
func (t *trunk) onViewDone(f func(*Conn)) {
	t.mx.Lock()
	t.viewDone = f
	t.mx.Unlock()
}

// usableFor reports whether a new view of a session sess of kind kind may
// be opened on the trunk (M3-D17): OptMux negotiated; started; not dying,
// retiring, peer-closed, gone-away, write-blocked or sealed; fewer views
// than MuxMaxViews; a stream session needs a stream trunk, and a pooled
// trunk takes sessions of its own kind only (KINDSPLIT); for a JOIN
// (inst not zero) the trunk's peer instance is inst; sess holds no view on
// the trunk that is not yet reaped (R1-6). The caller holds Pool.mu.
func (t *trunk) usableFor(kind wire.Type, inst [16]byte, sess uintptr) bool {
	return t.usableForMux(kind, inst, sess) // mux.go
}

// awaitResponse waits, bounded by ctx, for the OPEN_ACK or JOIN_ACK of a
// view opened on a started trunk (fast path, §A5.8), runs check on the
// trunk's PREFACE_ACK as Establish does and returns the view as an
// Established. A check failure ends the view (Kill on the view), never the
// trunk; a refusal response ends the handle (M3-D7).
func (c *Conn) awaitResponse(ctx context.Context, check func(*wire.PrefaceAck) error) (*Established, error) {
	return c.awaitResponseMux(ctx, check) // mux.go
}

// shimEndpoint is the endpoint of a view whose session has not attached it
// yet (M3-D9): on the dialer it completes the waiting attempt with the
// view's response and keeps the view dark; on the passive it holds an
// admitted view's frames until its session's Join or Confirm swaps in the
// session's endpoint.
type shimEndpoint struct{ v *Conn }

var _ PacketEndpoint = (*shimEndpoint)(nil)

// Handle returns the view's handle.
func (e *shimEndpoint) Handle() uint32 { return e.v.Handle() }

// Fill places nothing: a view without its session has no session frames.
func (e *shimEndpoint) Fill(c *Conn, b *Batch) { e.fill(c, b) }

// Data reports DATA for a view without its session (a violation unless the
// view's state allows it, §A3.3).
func (e *shimEndpoint) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	return e.data(c, off, p, buf)
}

// Control completes the waiting attempt with the view's response (dialer)
// or reports a frame the state table does not allow.
func (e *shimEndpoint) Control(c *Conn, h wire.Header, p []byte) error {
	return e.control(c, h, p)
}

// WriteBlocked has no duties to move.
func (e *shimEndpoint) WriteBlocked(c *Conn) {}

// Datagram reports a DGRAM for a view without its session.
func (e *shimEndpoint) Datagram(c *Conn, seq uint64, p []byte, buf *Buf) error {
	return e.dgram(c, seq, p, buf)
}
