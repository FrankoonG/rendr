package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// This file is the session's internal layout (design §4.0): the contract
// between the stream (the data path: application Read and Write, the lanes'
// carrier.Endpoint methods, ACK, FIN) and the actor (the session's control
// goroutine). It declares every shared type and nothing executable. Methods
// live with their only writer: the stream owns the spans, rings, segments
// and deadlines, the lane's carrier.Endpoint methods (lane_ep.go) and the
// helpers the actor calls (helpers.go); the actor owns the mailbox
// (mailbox.go) and the status snapshot (status.go).
//
// Field ownership: (S) is written only by stream code, (A) only by actor
// code; both are read under Session.mu. Immutable fields are set before the
// session becomes visible to any other goroutine.

// Session is one stream session: its stream state, its lanes and its actor.
// All exported methods are safe for concurrent use.
//
// Lock order (design §3.2): wmu / rmu → mu → carrier.Conn's own lock. wmu and
// rmu serialize application Writes and Reads and are held across the
// application copy; mu guards st, ctl, lanes and every lane's mutable fields
// and is never held across I/O, an embedder call, a callback, a blocking
// channel operation or a payload copy of 16 KiB or more.
type Session struct {
	env  *Env     // immutable
	p    Params   // immutable
	id   [16]byte // immutable: the session ID (dialer-chosen)
	meta []byte   // immutable: the OPEN metadata, owned by the session

	// peer is the bound peer instance. Passive: set at NewPending (the
	// dialer's InstanceID). Dialer: written once by the actor at the first
	// OPEN_ACK(OK), right before bound is set.
	peer [16]byte
	// bound (A) dialer: set right after peer; attempt check closures read
	// peer only after observing bound (design §6.6).
	bound atomic.Bool

	mu, wmu, rmu sync.Mutex

	st    stream                     // (S)
	ctl   control                    // (A)
	lanes []*lane                    // (A) membership, attach order
	snap  atomic.Pointer[statusSnap] // (A) published under mu with every control change
	mb    mailbox                    // (A) the actor's mailbox; ringActor rings its doorbell
	done  chan struct{}              // (A) closed at actor exit
}

// port is the set of *carrier.Conn methods the stream uses on a lane's
// carrier; a fake implements it in the stream's unit tests (design §4.0).
type port interface {
	ID() uint32
	Wake()
	RequestPing()
	Inflight() int64
	Capacity() int64
	SRTT() time.Duration
	WriteBlocked() bool
	CloseSent() bool
	Kill(cause carrier.Cause, detail string) bool
}

// The real carrier is a port.
var _ port = (*carrier.Conn)(nil)

// lane is one carrier incarnation of a session (design §4.0, §7.1). It
// implements carrier.Endpoint; its methods live in lane_ep.go. The first
// group is immutable; the other fields are guarded by Session.mu.
type lane struct {
	s       *Session      // immutable
	c       *carrier.Conn // immutable: the carrier incarnation
	port    port          // immutable: the stream's view of c (a fake in stream unit tests)
	id      uint32        // immutable: the CarrierID
	factory int           // immutable: the dialer factory index (-1 on the passive side)
	gen     uint32        // immutable: dialer: incarnation number of the factory slot; passive: attach order
	since   time.Time     // immutable: when the lane was created

	state        LaneState  // (A); LaneDead is set (with data = false) before laneGoneLocked: Fill then appends nothing
	data         bool       // (A) may pull DATA (routing)
	first        firstFrame // (A) sets the pending OPEN_ACK/JOIN_ACK; (S) Fill emits it first and clears it
	firstSent    bool       // (S)
	retireAt     time.Time  // (A)
	retireMark   uint64     // (A) sNext when retirement began
	retireCalled bool       // (A) Conn.Retire was called: never data-eligible or a fallback again (§7.3)
	infl         spanList   // (S) DATA spans sent here, not yet acknowledged or requeued
	lastAck      uint64     // (S) highest Delivered received on this lane (per-lane monotonic, L13)
	ackSent      uint64     // (S) ackGen last carried
	schedSent    uint32     // (S) SCHED epoch last carried; (A) initializes it to ctl.epoch and sets it to ctl.epoch−1 to request a resend on this lane
	rstSent      bool       // (S)
	finHere      bool       // (S) our unacknowledged FIN went out here
	idle         bool       // (S) the writer found nothing in its last Fill
}

// stream is the session's data-path state (design §4.2–§4.12): (S) as a
// whole, written only by stream code (the actor changes it through the
// helpers in helpers.go) except where a field says otherwise. Offsets are u64
// stream offsets from Params.FirstOffset; C is carrier.ChunkSize and W is
// Params.Window.
type stream struct {
	// Send buffer (§4.2): reserve under mu, copy outside it, commit under it.
	chunks    chunkRing // send chunks (refcounted 64 KiB Bufs); a chunk is freed only when acknowledged and unreferenced
	cbase     uint64    // start offset of the ring's first chunk (⌊resEnd/C⌋·C after an idle drop)
	sBase     uint64    // acknowledged front: the peer delivered every byte below it (ACK = delivered)
	sNext     uint64    // first never-sent offset: every offset ever sent is below it
	end       uint64    // committed end: bytes below it are immutable and visible to carrier writers
	resEnd    uint64    // reserved end: above end only while one Write copies [end, resEnd) outside mu
	peerLimit uint64    // max over received Delivered + Window and the initial window: the largest edge the peer advertised
	retx      spanList  // requeued spans, resent lowest first before new data, FIN and retirement (L10)

	rescue rescueSlot // (A) sets {span, excluded lane}; (S) Fill consumes and clears
	fin    finState   // requested, off, lane, acked (§4.3 step 6, §4.7)

	wcopying     bool // a Write copies into [end, resEnd) outside mu: teardown must not release chunks
	wfreePending bool // endLocked ran during that copy: the copier releases the chunks after it

	// Receive side (§4.4, §4.5, §4.12).
	rRead      uint64  // delivered to the application (consumed by Read)
	rTail      uint64  // end of the contiguous received bytes
	rightEdge  uint64  // the largest right edge ever advertised; never retracts (P10); the receiver's fatal threshold
	inq        segRing // in-order segments covering [rRead, rTail)
	ooq        segList // out-of-order segments beyond rTail: ascending, non-overlapping
	oooCap     int64   // size-class capacity held by inq and ooq together: exactly the Budget charge of the receive buffers (one segment per buffer); out-of-order data may fill it to 2·W (D13, V3)
	oooDropped uint64  // out-of-order DATA payload bytes dropped at the 2·W receive cap or shed by later in-order data (counted, never a violation: §4.4 step 6, D13, V3)

	peerFin          uint64 // the peer's FIN offset (valid when peerFinSet)
	peerFinSet       bool   // a FIN arrived
	peerFinDelivered bool   // rRead reached peerFin: the FIN is delivered (an ACK with FIN_DELIVERED follows)

	discard             bool // after local Close: in-order bytes are consumed on arrival
	discardedAfterClose bool // in-order bytes arrived and were discarded after Close (fact)
	rcopying            bool // a Read copies from inq outside mu: Close and teardown must not release segments
	rfreePending        bool // Close or endLocked ran during that copy: the reader releases at its commit

	// ACK (§4.6).
	ackGen     uint64    // incremented by every bump; a lane whose ackSent differs owes an ACK
	ackBumped  uint64    // rRead at the last bump (AckEvery cadence)
	ackFlags   uint8     // header flags the next ACK carries (FIN_DELIVERED, DONE)
	ackDelayAt time.Time // armed ACK delay (zero: none); fired by the duty lane's writer timer, never by the actor
	ackLane    *lane     // the ACK duty lane (D5); nil when no lane qualifies
	lastWin    int64     // the window last advertised: W at init, then OPEN/OPEN_ACK (openWindowLocked) and every ACK placed; below 64 KiB the actor re-advertises (D18, readvertiseLocked)
	ackOnData  bool      // the next in-order DATA bumps an urgent ACK (a lane attached, L19)

	// Application waiters (§3.5) and deadlines (§3.6).
	rwaiting bool          // a Read waits on rwake
	wwaiting bool          // a Write waits on wwake
	rwake    chan struct{} // cap 1
	wwake    chan struct{} // cap 1
	rdl      deadline      // read deadline
	wdl      deadline      // write deadline

	// Close and termination (§4.7).
	closed   bool      // the application called Close
	closedAt time.Time // when (the linger clock)
	ended    bool      // terminal: endLocked ran
	endErr   error     // the end error (io.EOF after a clean finish)

	finDelivSent bool      // an ACK with FIN_DELIVERED was placed
	doneQueued   bool      // the final ACK with FIN_DELIVERED|DONE is queued
	doneSent     bool      // that ACK was placed in a batch (fact)
	peerDone     bool      // the peer's DONE arrived (fact)
	doneSentAt   time.Time // when doneSent was set (the actor's DONE wait)

	lastAdvance time.Time // rescue clock, read by the actor: the last sBase advance, or the Write commit that made data outstanding (sBase == end before it)
	echoIn      uint32    // dialer: highest EpochEcho received (fact factEcho); the actor copies it into ctl.echoed

	rstIn     *wire.Rst // the RST received (fact factRst)
	exhausted bool      // a Write would have passed Params.OffsetLimit (fact factExhausted)
	facts     uint32    // fact bits (fact*) not yet taken by the actor (takeFactsLocked)
	lastData  time.Time // last application Write or Read commit (the IdleTimeout clock)

	// Counters (Status).
	txBytes   uint64 // bytes committed by application Writes
	rxBytes   uint64 // in-order bytes received
	delivered uint64 // bytes delivered to the application (discarded ones included)
	retxBytes uint64 // DATA payload bytes retransmitted

	order   []*lane   // lanes by srtt; refreshed when older than PingBusy or on lane changes
	orderAt time.Time // when order was last refreshed
}

// control is the session's control state (design §4.0, §7): (A) as a whole,
// written only by actor code except the received-SCHED fields, which the
// stream stores for the actor to apply.
type control struct {
	state  State // (A) lifecycle
	active *lane // (A) selector: the data lane; nil while there is none (failover race, no-path episode)

	epoch  uint32          // (A) dialer: published; passive: applied
	echoed uint32          // (A) dialer: highest epoch echoed by the passive (copied from st.echoIn)
	cause  wire.SchedCause // (A) dialer: published; passive: applied
	set    wire.Sched      // (A) dialer: published; passive: applied

	schedIn      wire.Sched      // (S) stores the newest received SCHED (passive); (A) applies it
	schedInCause wire.SchedCause // (S) its cause bits; (A) applies them
	schedInSet   bool            // (S) a SCHED was stored in schedIn

	rst *wire.Rst // (A) RST to place on every live lane

	inNoPath     bool      // (A) inside a no-path episode (no live lane)
	episodeStart time.Time // (A) death time of the last live lane
	episodeGen   uint64    // (A) incremented per episode; expiry acts only if unchanged (L18)

	rescuedBase uint64    // (A) sBase at the last rescue (one rescue per sBase value)
	adopting    int       // (A) adopts posted by Join/AttachOpen, not yet handled; count toward MaxCarriers (§6.3)
	closeBy     time.Time // (A) end/shutdown: Kill lanes whose CLOSE is unwritten by then (§4.7)

	migDeath, migQuality, migExplicit uint64 // (A) migration counters (§7.6)
	rejoins, episodes                 uint64 // (A) Rejoins (dialer only), NoPathEpisodes
}

// span is the half-open stream range [off, off+n).
type span struct{ off, n uint64 }

// spanList is an ascending, coalesced list of spans; the backing array grows
// and never shrinks during a session (no steady-state allocation).
type spanList struct{ s []span }

// chunkRing holds the send chunks: chunk i covers [cbase + i·C, cbase +
// (i+1)·C); capacity W/C + 2.
type chunkRing struct {
	b       []*carrier.Buf
	head, n int
}

// seg is one received segment; b is a tail slice of buf.B, so every
// segment may grow at its end into the rest of its buffer (V3).
type seg struct {
	off uint64
	b   []byte
	buf *carrier.Buf
	run bool // a 16 KiB copy run starting at its buffer's first byte (payloads < 16 KiB, P17)
}

// segRing is the in-order receive queue: inq covers [rRead, rTail).
type segRing struct {
	s       []seg
	head, n int
}

// segList is the out-of-order receive set: ooq is ascending, non-overlapping
// and beyond rTail.
type segList struct{ s []seg }

// rescueSlot is a pending bond rescue (§4.11): the actor sets it, the first
// data lane other than holder that has capacity sends sp, and Fill clears it.
type rescueSlot struct {
	set    bool
	sp     span
	holder *lane // the lane that must not send the duplicate
}

// finState is our FIN (§4.3 step 6, §4.7): requested at the first
// CloseWrite or Close with off = resEnd; lane is the lane it went out on
// (cleared when that lane's carrier ends, so it is re-sent at the same
// offset); acked once the peer reported FIN_DELIVERED.
type finState struct {
	requested, acked bool
	off              uint64
	lane             *lane
}

// deadline is one direction's application deadline (§3.6): t, a generation
// that invalidates older timer firings, and the AfterFunc timer.
type deadline struct {
	t     time.Time
	gen   uint64
	timer *time.Timer
}

// firstFrame is a lane's pending first response frame; t is 0 (none),
// wire.TypeOpenAck or wire.TypeJoinAck.
type firstFrame struct {
	t       wire.Type
	openAck wire.OpenAck
	joinAck wire.JoinAck
}

// Stream facts (S → A, design §3.4, §4.0): bits the data path sets in
// st.facts under mu before it calls ringActor. The actor takes them with
// takeFactsLocked and re-reads the state they point at, so a fact is never
// lost or applied twice.
//
// Two conditions have no fact bit: they only arm actor deadlines, and the
// actor re-reads them in every step. The data path still rings the actor
// (under mu) when one arises, so an idle actor arms the deadline at once:
//
//   - Window pressure (D18): Fill places an ACK that takes lastWin from
//     64 KiB or more to below it. The actor keeps its
//     Params.WindowReadvertise deadline armed for as long as
//     readvertiseLocked returns true, which it does until an ACK carrying
//     at least 64 KiB has been placed; an ACK that leaves lastWin below
//     64 KiB therefore needs no ring.
//   - Bond data outstanding (§4.11): a Write commit makes data outstanding
//     (sBase == end before it). That commit restarts the rescue clock
//     lastAdvance (in either mode) and, in bond mode, rings the actor. In
//     bond mode the actor keeps a rescue check armed while sBase < end: at
//     lastAdvance + sched.RescueWait, or RescueWait after the current step
//     once that time has passed without a rescue (none possible, or already
//     done at this sBase), so a stuck head is rescued without waiting for
//     an unrelated wake.
const (
	factClose               uint32 = 1 << iota // the application called Close (closed, closedAt)
	factCloseWrite                             // the application called CloseWrite (fin.requested)
	factFinAcked                               // the peer acknowledged our FIN (fin.acked)
	factPeerFinDelivered                       // the peer's FIN reached the application (peerFinDelivered)
	factDoneSent                               // the ACK carrying DONE was placed in a batch (doneSent, doneSentAt)
	factPeerDone                               // the peer's DONE arrived (peerDone)
	factRst                                    // an RST arrived (rstIn)
	factSched                                  // passive: a SCHED was stored in ctl.schedIn
	factEcho                                   // dialer: the echoed epoch advanced; its value is st.echoIn
	factDiscardedAfterClose                    // data arrived after Close and was discarded (discardedAfterClose)
	factExhausted                              // a Write reached Params.OffsetLimit (exhausted)
	factLaneConfirmed                          // Fill placed a lane's first response frame (firstSent)
	factWriteBlocked                           // a lane's carrier reported WriteBlocked (duties move off it)
)
