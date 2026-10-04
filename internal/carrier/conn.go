package carrier

import (
	"time"

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
	// the carrier's capacity. It appends nothing when it has nothing to send;
	// it may call b.WakeAt to be called again at a time (ACK delay) and
	// b.MarkCapBlocked when data waits on the capacity cap. The writer never
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
type Conn struct {
	_ struct{} // unexported state is defined by the implementation
}

// ID returns the CarrierID (dialer-assigned, echoed in PREFACE_ACK).
func (c *Conn) ID() uint32 {
	panic("unimplemented: M1b")
}

// PeerInstance returns the remote Runtime's InstanceID from the handshake.
func (c *Conn) PeerInstance() [16]byte {
	panic("unimplemented: M1b")
}

// Factory returns the dialer factory index (-1 on the passive side).
func (c *Conn) Factory() int {
	panic("unimplemented: M1b")
}

// Name returns the factory name ("" on the passive side).
func (c *Conn) Name() string {
	panic("unimplemented: M1b")
}

// Start launches the reader and writer. ep is nil for probe and sessionless
// carriers (any session frame is then a violation). bell is rung on death,
// peer CLOSE and peer GOAWAY. Start is called exactly once; the first PING
// is sent immediately (L23) unless o.Hold or o.Sessionless.
func (c *Conn) Start(ep Endpoint, bell Doorbell, o StartOptions) {
	panic("unimplemented: M1b")
}

// Wake makes the writer run Fill again soon (cap-1 channel; non-blocking,
// coalescing; never lost: a token sent while the writer is busy makes it
// re-run Fill once more). Besides session producers, the Conn wakes its own
// writer for carrier-level work: a PONG due, a PING requested, CLOSE or
// GOAWAY queued, Kill, and a matched PONG that advanced the PONG watermark
// while the writer's last round was cap-blocked (design §3.5, §4.10).
func (c *Conn) Wake() {
	panic("unimplemented: M1b")
}

// RequestPing asks for one PING as soon as no other PING is queued and
// uncommitted (cap-hit PING, BUSY flag change). Coalescing (L08).
func (c *Conn) RequestPing() {
	panic("unimplemented: M1b")
}

// Kill records the first death cause (idempotent CAS: later calls return
// false and change nothing), wakes the writer, rings the bell, and closes
// the embedder conn on a guarded goroutine (SetDeadline(now), then Close;
// abandoned after Timing.AbandonWait). It never blocks and takes no session
// lock, so it may be called from anywhere, including under the session lock.
func (c *Conn) Kill(cause Cause, detail string) bool {
	panic("unimplemented: M1b")
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
func (c *Conn) Retire(reason wire.CloseReason) {
	panic("unimplemented: M1b")
}

// GoAway queues GOAWAY(shutdown) ahead of any further frame and then
// retires the carrier (Runtime.Close).
func (c *Conn) GoAway() {
	panic("unimplemented: M1b")
}

// Death returns the death record (lock-free): whether the carrier ended,
// the first cause, a diagnostic detail and when it was recorded.
func (c *Conn) Death() (dead bool, cause Cause, detail string, at time.Time) {
	panic("unimplemented: M1b")
}

// Done is closed when the reader and writer exited (or were abandoned
// after Timing.AbandonWait) and the embedder conn was closed or its close
// abandoned. The CarrierID is released then.
func (c *Conn) Done() <-chan struct{} {
	panic("unimplemented: M1b")
}

// PeerClosed reports that the peer sent CLOSE on this carrier.
func (c *Conn) PeerClosed() bool {
	panic("unimplemented: M1b")
}

// PeerGoAway reports that the peer sent GOAWAY on this carrier.
func (c *Conn) PeerGoAway() bool {
	panic("unimplemented: M1b")
}

// CloseSent reports that this side has written CLOSE (no new frames follow).
func (c *Conn) CloseSent() bool {
	panic("unimplemented: M1b")
}

// WriteBlocked reports that the current batch write has been in progress for
// at least PingBusy (lock-free). The flag lives in one atomic word with the
// write generation: the watchdog sets it only by a compare-and-swap against
// the generation it was armed with, and the writer bumps the generation and
// clears it when the write returns, so a late watchdog callback can never
// leave it set on an idle carrier (design §4.8).
func (c *Conn) WriteBlocked() bool {
	panic("unimplemented: M1b")
}

// SRTT returns the smoothed RTT (0 before the first PONG).
func (c *Conn) SRTT() time.Duration {
	panic("unimplemented: M1b")
}

// Inflight returns DATA payload bytes written and not yet proven received by
// a PONG watermark (submitted − pongMark).
func (c *Conn) Inflight() int64 {
	panic("unimplemented: M1b")
}

// Capacity returns the current in-flight cap (sched.Capacity).
func (c *Conn) Capacity() int64 {
	panic("unimplemented: M1b")
}

// Stats returns a point-in-time copy of the estimator and counters.
func (c *Conn) Stats() Stats {
	panic("unimplemented: M1b")
}

// Stats is a point-in-time view of one carrier.
type Stats struct {
	SRTT, MinRTT      time.Duration
	Rate              float64   // bytes/s proven by PONG watermarks (decaying max, backlog-gated)
	RxRate            float64   // DATA payload bytes/s received (decaying max)
	Inflight, Cap     int64     // submitted − pongMark; capacity cap
	Backlogged        bool      // this side's writer was send-backlogged in the last PING interval
	PeerBusy          bool      // the peer's latest PING carried BUSY
	TxBytes, RxBytes  uint64    // DATA payload bytes sent / received on this carrier
	RetxBytes, Frames uint64    // retransmitted DATA payload bytes; frames written
	LastRx            time.Time // last frame received
}
