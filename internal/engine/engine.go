package engine

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// MaxPayload caps an engine-issued data frame payload. Combined with
// the 8-byte header it stays under the TCP adapter's 65535-byte
// frame max. A smaller value would just increase per-byte overhead;
// a larger one would not fit in 16-bit length-prefix.
const MaxPayload = 32 * 1024

// Side indicates whether this engine is the dialing (client) side or
// the listening (server) side. The only behavioural difference in M1
// is who issues HELLO first.
type Side uint8

const (
	SideClient Side = 0
	SideServer Side = 1
)

// Engine is the per-Conn migration engine. One Engine backs one
// application-visible rendr.Conn.
type Engine struct {
	side    Side
	flowID  [16]byte
	limits  Limits
	state   atomic.Uint32 // BridgeState
	created time.Time

	// Mode is the dispatcher selector: 1=prime, 2=bond, 3=race.
	// Loaded by dispatch() to decide single-path vs all-paths send.
	mode atomic.Uint32

	// bondCursor is the round-robin index for bond dispatch.
	// bondPinLeft is how many more consecutive frames must stay on
	// the current path before bondCursor advances. Path pinning is
	// the M8 mitigation for reorder-window blow-up under RTT skew
	// (docs/modes.md "1. path pinning"). When bondPinLeft hits 0 we
	// bump bondCursor and refill bondPinLeft from bondPinSize.
	bondCursor  uint64
	bondPinLeft int
	bondPinSize int // 0 = use defaultBondPinSize

	// Path management. activeID == 0 means "no active path".
	pathsMu    sync.RWMutex
	paths      map[uint32]*pathSlot
	nextPathID uint32
	activeID   uint32

	// Send state: one global SEQ counter, plus a single-flight
	// serialise so frames go out in SEQ order on whatever path is
	// active at the time.
	sendMu  sync.Mutex
	sendSeq uint64

	// Recv state: reorder buffer keyed by SEQ. expectedRecvSeq is the
	// next SEQ the application should observe.
	recvMu          sync.Mutex
	recvCond        *sync.Cond
	recvQueue       map[uint64]recvItem
	expectedRecvSeq uint64
	recvDeliver     []byte // pending bytes for the next Read

	// recvQueueHWM is the maximum size the reorder buffer reached
	// during this Conn's lifetime. Exposed for diagnostics so race-
	// mode chaos / bond tests can spot 'dedup window overflow' that
	// docs/modes.md flags as a hard race-mode bug. Pure observer;
	// the engine does not act on it.
	recvQueueHWM int

	// Zombie state. The counter decrements on each migration that
	// completes (death -> new active path) and resets on payload
	// arrival OR if the cooldown window has elapsed since the last
	// migration (CLAUDE.md hard rule #5).
	zombieMu      sync.Mutex
	zombieLeft    int
	zombieLastMig time.Time

	// Prime-mode scheduler. nil until StartPrime is called.
	primeMu sync.Mutex
	prime   *prime

	// Per-path RTT probe state. Keys are probe_id, values are the
	// monotonic time at issue. handlePathProbeReply consumes them.
	probeMu               sync.Mutex
	probeOutstanding      map[uint64]time.Time
	probeNextID           uint64
	probeIntervalOverride time.Duration // 0 = default 1s; tests can shorten

	// Lifecycle.
	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
	closeMu   sync.Mutex
}

// pathSlot tracks one attached path and its reader goroutine.
type pathSlot struct {
	id       uint32
	conn     transport.PathConn
	spec     transport.PathSpec
	attached time.Time

	quit     chan struct{}
	quitOnce sync.Once
	doneR    chan struct{} // closed when reader goroutine exits
}

// closeQuit is idempotent: multiple paths into the engine
// (Engine.Close, onPathDeath, an explicit migration tear-down) can
// all signal a slot to exit without panicking on a double close.
func (s *pathSlot) closeQuit() {
	s.quitOnce.Do(func() { close(s.quit) })
}

// New constructs an engine. flowID is the connection identifier; on
// the client side it should be a fresh 16 random bytes, on the
// server side it should be copied from the inbound HELLO.
func New(side Side, flowID [16]byte, limits Limits) *Engine {
	e := &Engine{
		side:             side,
		flowID:           flowID,
		limits:           limits.Clamp(),
		created:          time.Now(),
		paths:            make(map[uint32]*pathSlot),
		recvQueue:        make(map[uint64]recvItem),
		zombieLeft:       limits.Clamp().ZombieMaxMigrations,
		probeOutstanding: make(map[uint64]time.Time),
		closed:           make(chan struct{}),
	}
	e.recvCond = sync.NewCond(&e.recvMu)
	e.state.Store(uint32(BridgeInit))
	return e
}

// NewClientFlowID returns a fresh random flow_id for use by the
// client side of a dial.
func NewClientFlowID() [16]byte {
	var f [16]byte
	if _, err := rand.Read(f[:]); err != nil {
		// rand.Read on Go's crypto/rand is documented infallible on
		// supported platforms; fall back to a time-derived value
		// just to avoid an ergonomic panic in pathological cases.
		t := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			f[i] = byte(t >> (i * 8))
		}
	}
	return f
}

// FlowID returns the engine's flow identifier.
func (e *Engine) FlowID() [16]byte { return e.flowID }

// State returns the current bridge state.
func (e *Engine) State() BridgeState { return BridgeState(e.state.Load()) }

func (e *Engine) setState(s BridgeState) { e.state.Store(uint32(s)) }

// AttachPath registers a freshly-dialed PathConn with the engine.
// If no path was previously active, the new path becomes active.
// AttachPath spawns the per-path reader goroutine.
func (e *Engine) AttachPath(pc transport.PathConn, spec transport.PathSpec) (uint32, error) {
	if pc == nil {
		return 0, errors.New("engine: nil PathConn")
	}
	e.pathsMu.Lock()
	defer e.pathsMu.Unlock()

	if e.isClosed() {
		_ = pc.Close()
		return 0, net.ErrClosed
	}

	e.nextPathID++
	id := e.nextPathID
	if id == 0 {
		// 0 reserved for "no active path"; skip on wrap.
		e.nextPathID++
		id = e.nextPathID
	}
	slot := &pathSlot{
		id:       id,
		conn:     pc,
		spec:     spec,
		attached: time.Now(),
		quit:     make(chan struct{}),
		doneR:    make(chan struct{}),
	}
	e.paths[id] = slot

	pc.OnDeath(func(cause transport.DeathCause, err error) {
		e.onPathDeath(id, cause, err)
	})

	if e.activeID == 0 {
		e.activeID = id
		if e.State() == BridgeInit || e.State() == BridgeMigrating {
			e.setState(BridgeActive)
		}
	}

	go e.readerLoop(slot)
	go e.proberLoop(slot)
	return id, nil
}

// proberLoop sends a CtrlPathProbe on slot.conn every 1s and
// records the issue time so handlePathProbeReply can compute RTT.
//
// Per CLAUDE.md hard rule #3 ("默认不安装主动迁移触发器"), the
// prober only OBSERVES quality - it does not itself trigger
// migration. Prime-mode scoring decides migration via the
// independent scheduler in prime.go.
func (e *Engine) proberLoop(slot *pathSlot) {
	t := time.NewTicker(e.probeInterval())
	defer t.Stop()
	for {
		select {
		case <-slot.quit:
			return
		case <-e.closed:
			return
		case <-t.C:
			e.probeMu.Lock()
			e.probeNextID++
			id := e.probeNextID
			e.probeOutstanding[id] = nowFn()
			e.probeMu.Unlock()

			payload := proto.ProbePayload{
				TS: uint64(nowFn().UnixNano()),
				ID: id,
			}.Encode()
			hdr := proto.Header{
				Version: proto.Version,
				Type:    proto.FrameCtrl,
				Flags:   proto.FlagsForCtrl(proto.CtrlPathProbe),
				Seq:     0,
			}
			frame := make([]byte, proto.HeaderSize+len(payload))
			_ = hdr.Encode(frame[:proto.HeaderSize])
			copy(frame[proto.HeaderSize:], payload)
			// Best-effort write; failure means the path is dying and
			// OnDeath will fire from the read side soon enough.
			_, _ = slot.conn.Write(frame)

			// GC stale probes older than 30 s so the map cannot grow.
			e.probeMu.Lock()
			cutoff := nowFn().Add(-30 * time.Second)
			for k, t := range e.probeOutstanding {
				if t.Before(cutoff) {
					delete(e.probeOutstanding, k)
				}
			}
			e.probeMu.Unlock()
		}
	}
}

// ActivePath returns the currently-active path id, or 0 if none.
func (e *Engine) ActivePath() uint32 {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return e.activeID
}

// Paths returns a snapshot of all attached paths. Reads / Writes
// counters are populated when the path adapter implements the
// optional `interface{ Reads() uint64; Writes() uint64 }` shape
// (all in-tree adapters do).
func (e *Engine) Paths() []transport.PathInfo {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	out := make([]transport.PathInfo, 0, len(e.paths))
	for _, s := range e.paths {
		pi := transport.PathInfo{
			ID:      s.id,
			Spec:    s.spec,
			Quality: s.conn.Quality(),
			Since:   s.attached,
			Active:  s.id == e.activeID,
		}
		if rw, ok := s.conn.(interface {
			Reads() uint64
			Writes() uint64
		}); ok {
			pi.Reads = rw.Reads()
			pi.Writes = rw.Writes()
		}
		out = append(out, pi)
	}
	return out
}

// Migrate switches the active path to id. Returns an error if id is
// unknown or already dead. The new path becomes the destination of
// all subsequent sends. In-flight frames on the previous path are
// not retransmitted here; loss-tolerant paths (e.g. mid-stream
// migrations on G4) are handled by the recv-side reorder buffer
// requesting any missing SEQs separately (M1 leaves that to a future
// commit; the test harness uses planned migration which is
// loss-safe).
func (e *Engine) Migrate(id uint32) error {
	e.pathsMu.Lock()
	defer e.pathsMu.Unlock()

	slot, ok := e.paths[id]
	if !ok {
		return fmt.Errorf("engine: migrate to unknown path %d", id)
	}
	if e.activeID == id {
		return nil
	}
	e.activeID = id
	e.setState(BridgeActive)

	// Issue MIGRATE_NOTIFY on the new path so the peer can update its
	// own view. Send is best-effort; if it fails, onPathDeath will
	// trigger another migration.
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlMigrateNotify),
		Seq:     atomic.AddUint64(&e.sendSeq, 1) - 1,
	}
	payload := proto.MigrateNotifyPayload{NewPathID: id}.Encode()
	frame := make([]byte, proto.HeaderSize+len(payload))
	_ = hdr.Encode(frame[:proto.HeaderSize])
	copy(frame[proto.HeaderSize:], payload)
	// Write without holding pathsMu's full lock: the slot ref is captured.
	go func() {
		_, _ = slot.conn.Write(frame)
	}()
	return nil
}

// isClosed checks the lifecycle.
func (e *Engine) isClosed() bool {
	select {
	case <-e.closed:
		return true
	default:
		return false
	}
}

// IsClosed is the exported form of isClosed for the public Conn
// wrapper, which uses it to gate the BYE on local Close.
func (e *Engine) IsClosed() bool { return e.isClosed() }

// ModeRace / ModeBond / ModePrime values used by SetMode. These
// mirror the public rendr.Mode values; the engine duplicates them
// to avoid an import cycle.
const (
	dispatchPrime uint32 = 1
	dispatchBond  uint32 = 2
	dispatchRace  uint32 = 3
)

// SetMode updates the dispatcher mode. Called by the public
// engineBackedConn wrapper after the application-level SetMode
// validates the transition.
func (e *Engine) SetMode(mode uint32) {
	e.mode.Store(mode)
}

// Mode returns the current dispatcher mode.
func (e *Engine) Mode() uint32 { return e.mode.Load() }

// defaultBondPinSize is the number of consecutive frames bond
// dispatch keeps on one path before moving to the next. 8 is a
// trade-off between "small enough to keep aggregate bandwidth ~
// sum-of-paths" and "large enough to amortise the reorder cost
// from RTT skew between paths".
const defaultBondPinSize = 8

// SetBondPinSizeForTest is a backdoor for tests that want to
// observe pinning without sending 64+ frames. Not part of the API.
func (e *Engine) SetBondPinSizeForTest(n int) {
	if n <= 0 {
		return
	}
	e.pathsMu.Lock()
	e.bondPinSize = n
	// Reset the current pin so the change takes effect on the next
	// frame rather than waiting out the residual count.
	e.bondPinLeft = 0
	e.pathsMu.Unlock()
}

// probeInterval lets tests override the prober cadence. Default 1s.
func (e *Engine) probeInterval() time.Duration {
	if e.probeIntervalOverride > 0 {
		return e.probeIntervalOverride
	}
	return 1 * time.Second
}

// SetProbeIntervalForTest is a backdoor for tests that want a
// shorter prober cadence; not part of the API.
func (e *Engine) SetProbeIntervalForTest(d time.Duration) {
	e.probeIntervalOverride = d
}

// Close tears down the engine, closing all attached paths.
func (e *Engine) Close() error {
	var firstErr error
	e.closeOnce.Do(func() {
		e.setState(BridgeClosing)
		e.pathsMu.Lock()
		for _, s := range e.paths {
			s.closeQuit()
			if err := s.conn.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		e.pathsMu.Unlock()
		close(e.closed)
		// Wake any Read goroutine waiting on data.
		e.recvMu.Lock()
		e.recvCond.Broadcast()
		e.recvMu.Unlock()
		e.setState(BridgeDead)
	})
	return firstErr
}

// CloseErr returns the recorded close cause once the engine is dead;
// returns nil while still alive or on a clean close.
func (e *Engine) CloseErr() error {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	return e.closeErr
}

// Closed returns a channel that is closed when the engine has fully
// shut down. Useful for downstream cleanup goroutines.
func (e *Engine) Closed() <-chan struct{} { return e.closed }

// RecvQueueHighWaterMark returns the maximum reorder-buffer size
// the engine has ever observed for this Conn. Useful for race-mode
// chaos to verify the dedup window does not grow without bound
// when paths have RTT skew.
func (e *Engine) RecvQueueHighWaterMark() int {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	return e.recvQueueHWM
}

// RecvQueueLen returns the current reorder-buffer size.
func (e *Engine) RecvQueueLen() int {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	return len(e.recvQueue)
}

// WalkPathsForTest invokes fn for every attached path. fn receives
// the path id and the underlying PathConn as a bare any so tests can
// type-assert to transport-specific diagnostic interfaces (e.g.
// tcp.PathConn.Writes()).
func (e *Engine) WalkPathsForTest(fn func(id uint32, pc interface{})) {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	for id, s := range e.paths {
		fn(id, s.conn)
	}
}

// RemovePath gracefully detaches path id from the engine. The
// underlying socket is closed and a clean-close OnDeath fires, which
// (since CauseCleanClose on a non-last path is a no-op) just drops
// the slot from the path set. If id was the active path the engine
// failovers to any other attached path before returning.
//
// Returns ErrLastPath if id is the only attached path; in that case
// callers who want full teardown should call Close on the rendr.Conn
// instead. Returns a generic "unknown path" error if id is not in
// the engine's path set.
func (e *Engine) RemovePath(id uint32) error {
	e.pathsMu.Lock()
	slot, ok := e.paths[id]
	if !ok {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: remove unknown path %d", id)
	}
	if len(e.paths) <= 1 {
		e.pathsMu.Unlock()
		return ErrLastPath
	}
	e.pathsMu.Unlock()
	// Close the socket so the per-path reader exits, then synthesise
	// a clean-close OnDeath. We avoid relying on the transport's own
	// OnDeath firing because some adapters (e.g. udpflow ServerPathConn)
	// route death through the listener fanout and only emit it on
	// hard transport errors, not on local close.
	_ = slot.conn.Close()
	e.onPathDeath(id, transport.CauseCleanClose, nil)
	return nil
}

// ForceKillPathForTest is a backdoor for tests that need to simulate
// a sudden network death on a specific attached path. It closes the
// socket AND synthesises an onPathDeath(TransportError) so the
// engine's normal migration / budget machinery fires; without the
// second step, local PathConn.Close would silently leave the engine
// thinking the path is still attached.
//
// Not part of the API; gated by an obvious name to discourage misuse.
func (e *Engine) ForceKillPathForTest(id uint32) error {
	e.pathsMu.RLock()
	slot, ok := e.paths[id]
	e.pathsMu.RUnlock()
	if !ok {
		return fmt.Errorf("engine: kill unknown path %d", id)
	}
	err := slot.conn.Close()
	e.onPathDeath(id, transport.CauseTransportError, err)
	return err
}

func (e *Engine) setCloseErr(err error) {
	e.closeMu.Lock()
	if e.closeErr == nil {
		e.closeErr = err
	}
	e.closeMu.Unlock()
}
