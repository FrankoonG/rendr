package carrier

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Endpoint is a session's view of one carrier (M1: one per carrier; M3: one
// per handle of a mux carrier). A Conn calls it only from its own writer
// (Fill, WriteBlocked via the watchdog) and reader (Data, Control)
// goroutines, never concurrently for the same method kind, and never while
// holding its own lock. Implementations take the session lock.
type Endpoint interface {
	// Handle returns the session handle this endpoint uses on the carrier.
	Handle() uint32
	// Fill appends this endpoint's frames to b: while the carrier is held
	// (StartOptions.Hold) the first response frame (OPEN_ACK or JOIN_ACK)
	// before anything else; then session control (RST, SCHED, ACK, FIN) and
	// then DATA (rescue span, retransmissions, new data) within b.Room() and
	// the carrier's capacity: c.Inflight() counts only batches already
	// written, so Fill stops pulling DATA once c.Inflight() plus the DATA
	// bytes it appended in this round reach c.Capacity(). It appends
	// nothing when it has nothing to send; it may call b.WakeAt to be
	// called again at a time (ACK delay) and b.MarkCapBlocked when data
	// waits on the capacity cap. The writer never
	// calls Fill again after its own Kill or after it saw the death record
	// (it exits); a Fill that was already running when another goroutine
	// killed the carrier may still complete, so the endpoint's owner must
	// requeue whatever such a Fill pulled (design §4.3, §7.3).
	Fill(c *Conn, b *Batch)
	// Data delivers one CRC-verified DATA frame at stream offset off. When
	// buf is non-nil, p aliases buf.B and ownership of buf's reference moves
	// to the endpoint (it keeps or releases it, also on error). When buf is
	// nil, p is valid only during the call. A non-nil error kills the
	// carrier with CauseProtocolViolation; the session is unaffected.
	Data(c *Conn, off uint64, p []byte, buf *Buf) error
	// Control delivers one CRC-verified session control frame (ACK, FIN,
	// RST, SCHED). p is valid only during the call. Any other session type
	// after establishment is a violation reported by returning an error.
	Control(c *Conn, h wire.Header, p []byte) error
	// WriteBlocked reports that c's current batch write has been in progress
	// for PingBusy. The endpoint moves duties held by c (ACK duty, SCHED
	// resend) to another carrier and wakes it (L08). It is called on the
	// watchdog's goroutine, at most once per batch write and only while that
	// same write is still in progress (the watchdog's generation check,
	// design §4.8), and must not block.
	WriteBlocked(c *Conn)
}

// PacketEndpoint is the Endpoint of a packet session's lane (M2-D2). The
// carrier asserts it once at Start: a stream session's Endpoint does not
// implement it, and a DGRAM frame delivered to it is a violation of the
// delivering carrier. Packet session control (PACK, FIN, RST, SCHED)
// arrives through Control.
type PacketEndpoint interface {
	Endpoint
	// Datagram delivers one CRC-verified DGRAM frame carrying session seq
	// seq. When buf is non-nil, p aliases buf.B and ownership of buf's
	// reference moves to the endpoint (kept or released, also on error);
	// when buf is nil, p is valid only during the call. A non-nil error
	// kills the carrier with CauseProtocolViolation; the session is
	// unaffected.
	Datagram(c *Conn, seq uint64, p []byte, buf *Buf) error
}

// Doorbell is a non-blocking, coalescing notification (the session actor's
// mailbox signal or the health layer's). Ring may be called from any
// goroutine, with or without locks held.
type Doorbell interface{ Ring() }

// PingObserver receives probe-carrier PING commits and PONGs (health layer).
// It is called from the carrier's writer (PingCommitted) and reader (Pong)
// goroutines and must not block.
type PingObserver interface {
	// PingCommitted: the write carrying PING id returned successfully at at.
	PingCommitted(c *Conn, id uint32, at time.Time)
	// Pong: PONG id matched a committed PING of this incarnation; rtt is
	// measured from the PING's write commit (L23).
	Pong(c *Conn, id uint32, rtt time.Duration, at time.Time)
}

// StartOptions select the carrier's role.
type StartOptions struct {
	// Hold (passive session carriers): the writer writes nothing — not even
	// PING or PONG — until the endpoint's Fill placed its first frame
	// (OPEN_ACK or JOIN_ACK), which is then the first frame on the wire.
	Hold bool
	// Gauge (dialer session carriers of a multi-factory Peer): the self-load
	// gauge of the carrier's factory (§8). nil: no self-load accounting.
	Gauge *Gauge
	// Observer (dialer probe carriers): receives PING commits and PONGs.
	Observer PingObserver
	// Probe (dialer probe carriers): PING every Timing.ProbeInterval instead
	// of the busy/idle cadence.
	Probe bool
	// Sessionless (passive probe carriers): never PING; answer PONGs; close
	// after Timing.SessionlessIdle without a PING.
	Sessionless bool
}

// Conn is one carrier incarnation: immutable from construction to death
// (L42). It owns the embedder net.Conn, one reader goroutine, one writer
// goroutine, the estimator and PING records, and the death record. Conns are
// created unstarted by Establish (dialer) and ReadHello (passive).
//
// Concurrency: the death record, the write state (generation and
// WriteBlocked), the peer CLOSE/GOAWAY and CLOSE-sent flags and a few
// counters are atomics; the estimator, the PING records and carrier-level
// control live under mu (a leaf lock: session.mu → Conn.mu); the goroutine
// join bookkeeping lives under jmu (a leaf). The reader and writer state is
// owned by those goroutines. The Endpoint is never called with mu held.
type Conn struct {
	// Immutable from construction.
	env     *Env
	tm      Timing // env.Timing with defaults for zero fields
	nc      net.Conn
	ncClose closeOnce // closes nc (a datagram carrier: its dg.io, R1-7) exactly once: the closer, or the last resort of its abandonment (V2)
	owned   *OwnedTCP // nc itself when it is rendr's ownership token (D3, L57); nil otherwise
	id      uint32
	peer    [16]byte
	factory int    // -1 on the passive side
	name    string // "" on the passive side
	dialer  bool   // id was allocated from env.IDs and is released when Done closes
	salt    uint64 // per-carrier random PING nonce salt (D14)
	base    time.Time

	wake  chan struct{} // cap 1: the writer's coalescing wakeup
	dying chan struct{} // closed when the death record is set
	done  chan struct{} // closed when every goroutine of the carrier finished or was abandoned

	death      atomic.Pointer[deathRecord]
	wstate     atomic.Uint64 // write generation << 1 | WriteBlocked (C6)
	peerClosed atomic.Bool
	peerGoAway atomic.Bool
	closeSent  atomic.Bool
	capBlocked atomic.Bool // the writer's last round was cap-blocked (C5)
	rxData     atomic.Bool // DATA arrived since the previous PING was encoded (P12)
	rxBytes    atomic.Uint64
	lastRx     atomic.Int64 // nanoseconds after base when the last frame arrived; 0 = none
	bell       atomic.Pointer[ringer]

	// Set by Start under mu before the goroutines run; read by them.
	ep   Endpoint
	pep  PacketEndpoint // ep when it is a packet session's (asserted once at Start, M2-D2); nil otherwise
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
}

// deathRecord is the first cause that ended the carrier.
type deathRecord struct {
	cause  Cause
	detail string
	at     time.Time
}

type ringer struct{ b Doorbell }

// Goroutine parts of a carrier, joined by Done.
const (
	partReader uint8 = 1 << iota
	partWriter
	partCloser
	partDeadline // the closer's SetDeadline(now), run beside its Close (closeConn)
)

// joinState joins the carrier's goroutines (design §3.1): Done closes once
// the closer started (the conn is being closed) and every running part
// finished or was abandoned AbandonWait after the closer started (L52).
type joinState struct {
	started    bool
	running    uint8
	abandoned  uint8
	closing    bool
	doneClosed bool
	timer      *time.Timer // abandons stuck parts
	drain      *time.Timer // retirement drain bound (stopped at Done)
	// readerExit, when set, is closed as the reader part finishes: the
	// closer of a drain-bound retirement waits on it (closeRetiredDrain).
	readerExit chan struct{}
}

// newConn returns an unstarted carrier over nc. The handshake code sets the
// first fseq and PING id it used.
func newConn(env *Env, nc net.Conn, id uint32, peer [16]byte, factory int, name string, dialer bool) *Conn {
	c := &Conn{
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
		done:    make(chan struct{}),
	}
	if o, ok := nc.(*OwnedTCP); ok { // the exact token type: a wrapper is never bypassed (L41, L57)
		c.owned = o
	}
	var s [8]byte
	_, _ = rand.Read(s[:]) // crypto/rand never fails (it crashes the program instead)
	c.salt = binary.LittleEndian.Uint64(s[:])
	first := env.Presets.firstFseq()
	c.rd.fseq, c.wr.fseq = first, first
	c.st.nextPingID = env.Presets.firstPingID()
	return c
}

// ID returns the CarrierID (dialer-assigned, echoed in PREFACE_ACK).
func (c *Conn) ID() uint32 { return c.id }

// Kind returns the carrier kind: wire.KindDatagram for a datagram carrier,
// else wire.KindStream. Immutable.
func (c *Conn) Kind() wire.CarrierKind {
	if c.dg != nil {
		return wire.KindDatagram
	}
	return wire.KindStream
}

// MTU returns a datagram carrier's current send frame budget — bytes of
// frames per datagram, the flow header excluded: the negotiated cmtu,
// lowered (never raised) by wire.DatagramTooLargeError (M2-D25). 0 on
// stream carriers. Lock-free.
func (c *Conn) MTU() int {
	if c.dg == nil {
		return 0
	}
	return int(c.dg.budget.Load())
}

// RecvLimit returns a datagram carrier's negotiated cmtu (its reader accepts
// datagrams of up to that many rendr bytes); 0 on stream carriers.
func (c *Conn) RecvLimit() int {
	if c.dg == nil {
		return 0
	}
	return c.dg.recvLimit
}

// TransportLimit returns the largest datagram a datagram carrier's transport
// receives (its PacketIO's Limit, the passive's cmtu_acc bound, M2-D50; 0
// when the transport does not know it, as HandlePacket's); 0 on stream
// carriers.
func (c *Conn) TransportLimit() int {
	if c.dg == nil {
		return 0
	}
	return c.dg.io.Limit()
}

// DgramMax returns the largest application datagram this carrier takes now:
// MTU() − wire.DgramOverhead on a datagram carrier, wire.MaxPacketPayload on
// a stream carrier (a DGRAM is an ordinary frame there).
func (c *Conn) DgramMax() int {
	if c.dg == nil {
		return wire.MaxPacketPayload
	}
	return c.MTU() - wire.DgramOverhead
}

// SetBudget fixes the negotiated cmtu of an unstarted datagram carrier
// (M2-D50): on the passive the admission's min(the dialer's offer, the
// transport's Limit), on the dialer the value the OPEN_ACK or JOIN_ACK
// returned (≤ its offer). It sets the send budget and the receive limit,
// and lowers the transport's receive limit to it (PacketIO.SetLimit, M2
// design Revision 1, R1-6), so the started reader's buffer is cmtu +
// Headroom + 1 and a longer datagram is ReadTruncated. A no-op on stream
// carriers; it panics after Start.
func (c *Conn) SetBudget(cmtu int) {
	if c.dg == nil {
		return
	}
	c.jmu.Lock()
	started := c.join.started
	c.jmu.Unlock()
	if started {
		panic("rendr/carrier: SetBudget after Start")
	}
	c.dg.recvLimit = cmtu
	c.dg.budget.Store(int32(cmtu))
	c.dg.io.SetLimit(cmtu)
}

// PeerInstance returns the remote Runtime's InstanceID from the handshake.
func (c *Conn) PeerInstance() [16]byte { return c.peer }

// Factory returns the dialer factory index (-1 on the passive side).
func (c *Conn) Factory() int { return c.factory }

// Name returns the factory name ("" on the passive side).
func (c *Conn) Name() string { return c.name }

// Start launches the reader and writer. ep is nil for probe and sessionless
// carriers (any session frame is then a violation). bell is rung on death,
// peer CLOSE and peer GOAWAY. Start is called exactly once; the first PING
// is sent immediately (L23) unless o.Hold or o.Sessionless.
//
// A carrier that is never started is discarded with Kill (its Done then
// closes once the conn is closed). Start on a carrier that was already
// killed starts nothing and rings bell, so the owner reconciles it.
func (c *Conn) Start(ep Endpoint, bell Doorbell, o StartOptions) {
	c.jmu.Lock()
	if c.join.started || c.join.closing || c.death.Load() != nil {
		c.jmu.Unlock()
		if bell != nil && c.death.Load() != nil {
			bell.Ring()
		}
		return
	}
	c.join.started = true
	c.join.running |= partReader | partWriter
	c.jmu.Unlock()

	if bell != nil {
		c.bell.Store(&ringer{bell})
		if c.death.Load() != nil {
			bell.Ring() // a Kill that raced this Start may have missed the bell
		}
	}
	now := time.Now()
	c.mu.Lock()
	c.ep, c.opts = ep, o
	c.pep, _ = ep.(PacketEndpoint)
	st := &c.st
	st.gauge = o.Gauge
	if c.dg != nil {
		st.gauge = nil // no self-load gauge on datagram carriers (M2-D26)
	}
	st.rateAt, st.rateCommitAt, st.rxAt, st.intervalStart, st.lastPingRx = now, now, now, now, now
	c.mu.Unlock()
	c.wr.held = o.Hold
	if c.dg != nil {
		c.dg.held.Store(o.Hold)
		go c.dgReadLoop()
	} else {
		go c.readLoop()
	}
	go c.writeLoop()
}

// Wake makes the writer run Fill again soon (cap-1 channel; non-blocking,
// coalescing; never lost: a token sent while the writer is busy makes it
// re-run Fill once more). Besides session producers, the Conn wakes its own
// writer for carrier-level work: a PONG due, a PING requested, CLOSE or
// GOAWAY queued, Kill, and a matched PONG that advanced the PONG watermark
// while the writer's last round was cap-blocked (design §3.5, §4.10).
func (c *Conn) Wake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// RequestPing asks for one PING as soon as no other PING is queued and
// uncommitted (cap-hit PING, BUSY flag change). Coalescing (L08).
func (c *Conn) RequestPing() {
	c.mu.Lock()
	c.st.pingReq = true
	c.mu.Unlock()
	c.Wake()
}

// Kill records the first death cause (idempotent CAS: later calls return
// false and change nothing), wakes the writer, rings the bell, and closes
// the embedder conn on guarded goroutines (SetDeadline(now) and Close, the
// Close not waiting for the SetDeadline; abandoned after
// Timing.AbandonWait). It never blocks and takes no session lock, so it may
// be called from anywhere, including under the session lock.
func (c *Conn) Kill(cause Cause, detail string) bool {
	if !c.setDeath(cause, detail) {
		return false
	}
	c.startCloser(closeKill, nil, time.Time{})
	return true
}

// setDeath publishes the death record once (L01: one CAS, one ring) and
// announces it: the writer's dying channel closes (an idle writer exits),
// the self-load contribution is withdrawn and the owner's bell rings. The
// caller that won starts the closer.
func (c *Conn) setDeath(cause Cause, detail string) bool {
	if c.death.Load() != nil {
		return false
	}
	if !c.death.CompareAndSwap(nil, &deathRecord{cause: cause, detail: detail, at: time.Now()}) {
		return false
	}
	close(c.dying)
	c.Wake()
	c.mu.Lock()
	c.endGaugeLocked()
	c.mu.Unlock()
	c.ring()
	return true
}

func (c *Conn) ring() {
	if r := c.bell.Load(); r != nil {
		r.b.Ring()
	}
}

// Retire starts the planned teardown (L05): the writer writes what the
// endpoint still has, then CLOSE(reason), then stops writing; the reader
// keeps delivering until the peer's CLOSE, EOF or min(2·srtt + 100 ms, 1 s)
// after our CLOSE; then CloseWrite (OwnedTCP only) and Close. The death
// record becomes CauseRetired unless a death happened first. Idempotent and
// irreversible: CLOSE follows as soon as a round appends no endpoint frame,
// so an owner never makes the endpoint data-eligible again after calling
// Retire (design §7.3). Retire itself does not bound how long CLOSE takes
// to be written behind a blocked embedder Write; owners bound it by Kill
// (design §4.7: min(1 s, DeadMax) at session end and Runtime.Close).
//
// A held carrier whose endpoint never placed a first frame writes its
// CLOSE (after a GOAWAY, if requested) as its first frame.
func (c *Conn) Retire(reason wire.CloseReason) {
	c.mu.Lock()
	if c.st.retiring {
		c.mu.Unlock()
		return
	}
	c.st.retiring, c.st.reason = true, reason
	c.mu.Unlock()
	c.Wake()
}

// GoAway queues GOAWAY(shutdown) ahead of any further frame and then
// retires the carrier (Runtime.Close).
func (c *Conn) GoAway() {
	c.mu.Lock()
	c.st.goAway = true
	if !c.st.retiring {
		c.st.retiring, c.st.reason = true, wire.CloseRetire
	}
	c.mu.Unlock()
	c.Wake()
}

// Death returns the death record (lock-free): whether the carrier ended,
// the first cause, a diagnostic detail and when it was recorded.
func (c *Conn) Death() (dead bool, cause Cause, detail string, at time.Time) {
	r := c.death.Load()
	if r == nil {
		return false, CauseNone, "", time.Time{}
	}
	return true, r.cause, r.detail, r.at
}

// Done is closed when the reader and writer exited (or were abandoned
// after Timing.AbandonWait) and the embedder conn was closed — its Close
// and SetDeadline(now) returned — or its close abandoned. Before it closes,
// the CarrierID is released and every abandoned goroutine is counted in
// Env.Abandon, so a joiner woken by Done sees the final state; a closer
// abandoned before its Close has had its conn's last-resort close started
// (design §0.8 V2).
func (c *Conn) Done() <-chan struct{} { return c.done }

// PeerClosed reports that the peer sent CLOSE on this carrier.
func (c *Conn) PeerClosed() bool { return c.peerClosed.Load() }

// PeerGoAway reports that the peer sent GOAWAY on this carrier.
func (c *Conn) PeerGoAway() bool { return c.peerGoAway.Load() }

// CloseSent reports that this side has written CLOSE (no new frames follow).
func (c *Conn) CloseSent() bool { return c.closeSent.Load() }

// WriteBlocked reports that the current batch write has been in progress for
// at least PingBusy (lock-free). The flag lives in one atomic word with the
// write generation: the watchdog sets it only by a compare-and-swap against
// the generation it was armed with, and the writer bumps the generation and
// clears it when the write returns, so a late watchdog callback can never
// leave it set on an idle carrier (design §4.8).
func (c *Conn) WriteBlocked() bool { return c.wstate.Load()&1 != 0 }

// SRTT returns the smoothed RTT (0 before the first PONG).
func (c *Conn) SRTT() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.srtt
}

// Inflight returns DATA payload bytes written and not yet proven received by
// a PONG watermark (submitted − pongMark). Bytes join it when the write of
// their batch returned: the batch being filled or written is not included
// (Fill adds what it appended itself, see Endpoint.Fill).
func (c *Conn) Inflight() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.inflight()
}

// Capacity returns the current in-flight cap (sched.Capacity).
func (c *Conn) Capacity() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capacityLocked()
}

func (c *Conn) capacityLocked() int64 {
	return sched.Capacity(c.st.rate, c.st.minRTT, c.tm.PingBusy, c.tm.CapFloor, c.tm.Window)
}

// Stats returns a point-in-time copy of the estimator and counters.
func (c *Conn) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := &c.st
	s := Stats{
		Kind:       c.Kind(),
		SRTT:       st.srtt,
		MinRTT:     st.minRTT,
		Rate:       st.rate,
		RxRate:     st.rxRate,
		Inflight:   st.inflight(),
		Cap:        c.capacityLocked(),
		Backlogged: st.lastBusy,
		PeerBusy:   st.peerBusy,
		TxBytes:    st.txBytes,
		RxBytes:    c.rxBytes.Load(),
		RetxBytes:  st.retxBytes,
		Frames:     st.frames,
	}
	if n := c.lastRx.Load(); n != 0 {
		s.LastRx = c.base.Add(time.Duration(n))
	}
	if dg := c.dg; dg != nil {
		s.MTU = int(dg.budget.Load())
		s.Datagrams = dg.ctr.datagrams.Load()
		s.DatagramsRx = dg.ctr.datagramsRx.Load()
		s.Dropped = dg.ctr.dropped.Load()
		s.Truncated = dg.ctr.truncated.Load()
		s.Refused = dg.ctr.refused.Load()
		s.Retransmits = dg.ctr.retransmits.Load()
		s.Rebinds = dg.ctr.rebinds.Load()
	}
	return s
}

// Stats is a point-in-time view of one carrier.
type Stats struct {
	Kind              wire.CarrierKind // the carrier's kind (Conn.Kind)
	SRTT, MinRTT      time.Duration
	Rate              float64   // bytes/s proven by PONG watermarks (decaying max, backlog-gated)
	RxRate            float64   // DATA payload bytes/s received (decaying max)
	Inflight, Cap     int64     // submitted − pongMark; capacity cap
	Backlogged        bool      // this side's writer was send-backlogged in the latest backlog interval a PING judged (≥ 5 ms)
	PeerBusy          bool      // the peer's latest PING carried BUSY
	TxBytes, RxBytes  uint64    // DATA payload bytes sent / received on this carrier
	RetxBytes, Frames uint64    // retransmitted DATA payload bytes; frames written
	LastRx            time.Time // last frame received

	// M2. TxBytes and RxBytes also count DGRAM payload bytes on every
	// carrier; the fields below are zero on stream carriers.
	MTU                    int    // current send frame budget (Conn.MTU)
	Datagrams, DatagramsRx uint64 // datagrams written / read and handed over
	Dropped                uint64 // datagrams and frames dropped (M2-D14), Truncated included
	Truncated              uint64 // truncated or oversize datagrams read
	Refused                uint64 // DGRAMs lost in datagrams the transport refused as too large (the session adds them to PacketCounters.DropTooLarge)
	Retransmits            uint64 // REL and H1 retransmissions (L12)
	Rebinds                uint64 // committed rebinds of a passive raw-UDP flow (L59)
}

// Closing and joining.

// closeMode selects what the closer goroutine does.
type closeMode uint8

const (
	closeKill         closeMode = iota // abrupt: SetDeadline(now) and Close (closeConn)
	closeRetired                       // planned: CloseWrite (OwnedTCP only), then SetDeadline(now) and Close
	closeWriteOne                      // WriteAndClose: write one frame, CloseWrite (OwnedTCP), bounded drain, then SetDeadline(now) and Close
	closeRetiredDrain                  // planned, an OwnedTCP carrier past the drain bound: CloseWrite, the reader ends (awaitReader, ≤ drainMax), then SetDeadline(now) and Close
)

// drainMax bounds the drain of a planned close and of WriteAndClose.
const drainMax = time.Second

// startCloser starts the carrier's single closer goroutine (the caller set
// the death record; the closer starts the deadline part, closeConn) and
// arms the abandonment of parts still stuck in embedder code AbandonWait
// after the close (plus the bounded write and drain of WriteAndClose).
func (c *Conn) startCloser(mode closeMode, frame []byte, deadline time.Time) {
	wait := c.tm.AbandonWait
	switch mode {
	case closeWriteOne:
		if d := time.Until(deadline); d > 0 {
			wait += d
		}
		wait += drainMax
	case closeRetiredDrain:
		wait += drainMax
	}
	c.jmu.Lock()
	c.join.running |= partCloser
	c.join.closing = true
	c.join.timer = time.AfterFunc(wait, c.abandonParts)
	c.jmu.Unlock()
	go c.closer(mode, frame, deadline)
}

func (c *Conn) closer(mode closeMode, frame []byte, deadline time.Time) {
	defer c.partDone(partCloser) // also on runtime.Goexit inside an embedder call
	// Deferred, so the conn is closed exactly once also when one of the
	// embedder calls below (CloseWrite, the verdict write, the drain) calls
	// runtime.Goexit (L51); skipped when the abandonment's last resort
	// closed it first under a call that ignored its deadline (V2).
	defer c.closeConn()
	switch mode {
	case closeRetired:
		if c.owned != nil {
			_ = callCloseWrite(c.owned)
		}
	case closeRetiredDrain:
		_ = callCloseWrite(c.owned)
		c.awaitReader(drainMax)
	case closeWriteOne:
		_ = callSetWriteDeadline(c.nc, deadline)
		if writeFull(c.nc, frame) == nil {
			if c.owned != nil {
				_ = callCloseWrite(c.owned)
			}
			drain(c.nc, time.Now().Add(drainMax))
		}
	}
}

// awaitReader waits, at most d, until the reader part finished. The reader
// owns Read (no second reader drains the conn): after a drain-bound
// retirement it keeps reading — the peer's late frames are dispatched as
// before the bound — and ends at the peer's CLOSE (no frame follows it),
// at EOF or at a read error, so the conn is closed with nothing unread and
// no late frame of the peer meets a closed socket and draws a TCP RST
// (L05; W4-K11, TestLoopbackDrainBoundNoReset_L05). A peer that sends
// nothing more is cut off by closeConn after d. A later Kill does not cut
// the wait short (the death is already recorded, so it starts no closer):
// Done and the join may come up to d later, inside the closer's
// abandonment wait (AbandonWait + drainMax). No owner kills a carrier
// whose CLOSE was written (the end phase and Runtime.Close kill only those
// whose CLOSE is unwritten), and only such a carrier reaches this wait.
func (c *Conn) awaitReader(d time.Duration) {
	c.jmu.Lock()
	if c.join.running&partReader == 0 {
		c.jmu.Unlock()
		return
	}
	if c.join.readerExit == nil {
		c.join.readerExit = make(chan struct{})
	}
	exit := c.join.readerExit
	c.jmu.Unlock()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-exit:
	case <-t.C:
	}
}

// closeConn ends the closer: SetDeadline(now) on a part of its own, the
// deadline part, started first so that a conn that honours deadlines
// unblocks the reader and the writer (L52), then Close on the closer
// itself, which does not wait for the SetDeadline (design §0.14 B3). The
// reader of a started carrier reads with no deadline; on a conn whose
// deadline setters wait for a pending Read and whose Close ends it, a Close
// called only after SetDeadline returned would wait for the peer on a
// silent path, with the reader and the closer counted in the abandoned-call
// pool. A step started already — by the last resort under a call that
// ignored its deadline — is skipped (closeOnce). The deadline part is
// joined by Done like the others and counted by abandonParts when it is
// stuck in the embedder's SetDeadline; it is registered under jmu, where
// the abandonment runs, and never after Done closed.
func (c *Conn) closeConn() {
	k := &c.ncClose
	c.jmu.Lock()
	set := !c.join.doneClosed && k.startDeadline()
	if set {
		c.join.running |= partDeadline
	}
	c.jmu.Unlock()
	if set {
		go func() {
			defer c.partDone(partDeadline) // also on runtime.Goexit inside the embedder's SetDeadline
			_ = callSetDeadline(k.nc, time.Now())
		}()
	}
	if k.startClose() {
		_ = callClose(k.nc) // the net.Conn, or a datagram carrier's PacketIO (R1-7)
	}
}

// drain reads and discards until EOF, an error or the time until (L05:
// closing a socket with unread data could reset the peer before it read our
// last frame).
func drain(nc net.Conn, until time.Time) {
	_ = callSetReadDeadline(nc, until)
	var buf [512]byte
	for i := 0; i < 1<<12; i++ { // bounded even for a conn that ignores deadlines but keeps returning data
		n, err := callRead(nc, buf[:])
		if err != nil || n <= 0 || n > len(buf) {
			return
		}
	}
}

// partDone records that one goroutine of the carrier exited.
func (c *Conn) partDone(p uint8) {
	c.jmu.Lock()
	c.join.running &^= p
	if p == partReader && c.join.readerExit != nil {
		close(c.join.readerExit)
		c.join.readerExit = nil
	}
	left := c.join.abandoned&p != 0
	c.join.abandoned &^= p
	c.maybeDoneLocked()
	c.jmu.Unlock()
	if left && c.env.Abandon != nil {
		c.env.Abandon.Leave()
	}
}

// abandonParts counts every part still running AbandonWait after the close
// as abandoned (L52) and lets Done close; each leaves the pool when its
// embedder call finally returns. The parts enter the pool before Done
// closes (Adopt is an atomic add, safe under the leaf lock), so a joiner
// woken by Done already sees them in Status.Abandoned and in the Full
// fail-fast gate; partDone reads the abandoned bits under the same lock, so
// a part's Leave always follows its Adopt.
//
// A closer adopted here is still inside an embedder call before its Close
// — the verdict write or the drain of WriteAndClose on a conn that ignores
// its deadline — or inside the Close itself. In the first case its conn is
// then closed once as a last resort (design §0.8 V2), which unblocks the
// call on a conn that honours Close; a closer stuck inside the Close
// itself is never closed a second time (closeOnce). The last resort
// (closeOnce.last) calls Close directly and only starts a guarded
// goroutine, so it may run under the leaf lock. A deadline part stuck in
// the embedder's SetDeadline is counted like the others; the Close beside
// it was called already.
func (c *Conn) abandonParts() {
	c.jmu.Lock()
	defer c.jmu.Unlock()
	stuck := c.join.running &^ c.join.abandoned
	c.join.abandoned |= stuck
	if c.env.Abandon != nil {
		for p := partReader; p <= partDeadline; p <<= 1 {
			if stuck&p != 0 {
				c.env.Abandon.Adopt()
			}
		}
	}
	if stuck&partCloser != 0 {
		c.ncClose.last(c.env) // the last resort
	}
	c.maybeDoneLocked()
}

// maybeDoneLocked closes Done once the closer started and every part
// finished or was abandoned. Every account settles before Done closes —
// the abandoned parts are counted (abandonParts) and the CarrierID is
// released here — so a joiner woken by Done never sees a stale state.
func (c *Conn) maybeDoneLocked() {
	j := &c.join
	if !j.closing || j.doneClosed || j.running&^j.abandoned != 0 {
		return
	}
	j.doneClosed = true
	if j.timer != nil {
		j.timer.Stop()
	}
	if j.drain != nil {
		j.drain.Stop()
	}
	if c.dialer && c.env.IDs != nil {
		c.env.IDs.Release(c.id) // the allocator's lock is a leaf
	}
	close(c.done)
}

// finishRetire ends a planned retirement (both CLOSEs exchanged, EOF or
// read error after a CLOSE, or the drain bound): the death record becomes
// CauseRetired unless a death came first, and the conn is closed in the
// L05 order. At the drain bound (drained) a carrier over rendr's own TCP
// (OwnedTCP) half-closes and still consumes what the peer sends until its
// CLOSE or EOF, bounded by drainMax, before the socket is closed
// (closeRetiredDrain): a frame of a stalled peer that arrived after the
// bound would otherwise meet a closed socket and draw a TCP RST (W4-K11).
// Every other conn — an embedder's net.Conn, which rendr cannot
// half-close, or a datagram carrier's PacketIO (R1-7) — is closed at the
// bound.
func (c *Conn) finishRetire(detail string) { c.retire(detail, false) }

func (c *Conn) retire(detail string, drained bool) {
	if c.setDeath(CauseRetired, detail) {
		mode := closeRetired
		if drained && c.owned != nil && c.dg == nil {
			mode = closeRetiredDrain
		}
		c.startCloser(mode, nil, time.Time{})
	}
}

// endIfPeerClosed ends the planned retirement instead of a death when the
// peer already sent CLOSE, and reports whether it did. The peer sends
// nothing after its CLOSE — no PONG either — and closes the conn after its
// bounded drain, so a failed or stalled write and an unanswered PING after
// it are the end of that retirement, not evidence against the path (as a
// read error after a CLOSE, readFailed). The cause then stays retired: no
// failed mark, no immediate redial, no death migration (design §7.3).
func (c *Conn) endIfPeerClosed(detail string) bool {
	if !c.peerClosed.Load() {
		return false
	}
	c.finishRetire("retired: " + detail + " after the peer's CLOSE")
	return true
}

// closeWritten runs on the writer right after the batch carrying our CLOSE
// was written (closeSent is already set): the retirement ends at once if
// the peer's CLOSE already arrived, else when it arrives, at EOF, or after
// the drain bound min(2·srtt + 100 ms, 1 s).
func (c *Conn) closeWritten() {
	if c.peerClosed.Load() {
		c.finishRetire("retired: CLOSE exchange complete")
		return
	}
	c.mu.Lock()
	bound := 2*c.st.srtt + 100*time.Millisecond
	c.mu.Unlock()
	if bound > drainMax {
		bound = drainMax
	}
	c.jmu.Lock()
	if !c.join.doneClosed {
		c.join.drain = time.AfterFunc(bound, func() { c.retire("retired: drain bound after CLOSE", true) })
	}
	c.jmu.Unlock()
}

// WriteAndClose writes one frame (the next tx fseq) on an unstarted Conn —
// an admission verdict such as OPEN_ACK(CAPACITY), JOIN_ACK(UNKNOWN_SESSION)
// or CLOSE(capacity) — bounded by deadline, then closes it in the L05 order
// (CloseWrite on OwnedTCP only, bounded drain, Close). A zero deadline
// means now + 1 s (the drain bound): the write is never unbounded, so the
// conn is closed once the write gave up. It returns at once; the work runs
// on a guarded goroutine. The death record becomes CauseLocalClose. On a
// started or already dead Conn it only kills it.
//
// On a conn that ignores the write (or the drain's read) deadline, the
// closer is adopted by the abandoned-call pool AbandonWait after the
// deadline and the drain bound, and its conn is then closed exactly once
// as a last resort (design §0.8 V2): a conn that honours Close unblocks,
// and the closer leaves the pool.
func (c *Conn) WriteAndClose(t wire.Type, flags uint8, handle uint32, payload []byte, deadline time.Time) {
	c.jmu.Lock()
	started := c.join.started
	c.jmu.Unlock()
	if started {
		c.Kill(CauseLocalClose, "WriteAndClose on a started carrier")
		return
	}
	if deadline.IsZero() {
		deadline = time.Now().Add(drainMax)
	}
	if c.dg != nil {
		// A datagram verdict is a REL retransmitted until RACKed (M2-D21).
		c.dgWriteAndClose(t, flags, handle, payload, deadline)
		return
	}
	frame := wire.AppendFrame(nil, wire.Header{Type: t, Flags: flags, Fseq: c.wr.fseq, Handle: handle}, payload)
	if !c.setDeath(CauseLocalClose, "closed after a "+t.String()) {
		return
	}
	c.wr.fseq++
	c.startCloser(closeWriteOne, frame, deadline)
}
