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
	side     Side
	flowID   [16]byte
	limits   Limits
	peerCaps atomic.Uint32
	state    atomic.Uint32 // BridgeState
	created  time.Time

	// Mode is the dispatcher selector: 1=prime, 2=bond, 3=race.
	// Loaded by dispatch() to decide single-path vs all-paths send.
	mode atomic.Uint32

	// bondCursor is the round-robin index for bond dispatch.
	// bondPinLeft is how many more consecutive frames must stay on
	// the current path before bondCursor advances. Path pinning is
	// the M8 mitigation for reorder-window blow-up under RTT skew
	// (path pinning, see dispatchBond). When bondPinLeft hits 0 we
	// bump bondCursor and refill bondPinLeft from bondPinSize.
	bondCursor     uint64
	bondPinLeft    int
	bondPinSize    int    // 0 = use defaultBondPinSize
	bondStuckSkips uint64 // count of round-robin slots bypassed for RTT

	// migrationCount tracks the number of active-path changes that
	// happened AFTER the engine first became Active. The initial
	// assignment of activeID at AttachPath time is not counted.
	// Both explicit Migrate() and death-driven failover via
	// onPathDeath increment it. Read under pathsMu.
	migrationCount uint64

	// migrateHooks is the list of subscriber callbacks invoked
	// (each in its own goroutine) when activeID changes. Registered
	// via OnMigrate; cancelled via the returned cancel function.
	// Held under pathsMu - same as migrationCount.
	migrateHooks  map[uint64]func(oldID, newID uint32, cause string)
	migrateHookID uint64

	// Path management. activeID == 0 means "no active path".
	pathsMu     sync.RWMutex
	paths       map[uint32]*pathSlot
	nextPathID  uint32
	nextPathGen uint64
	activeID    uint32
	// dispatchScope optionally limits race/bond dispatch and death
	// failover to a policy-selected target group. nil means all paths.
	dispatchScope map[uint32]bool

	// Send state: one global SEQ counter, plus a single-flight
	// serialise so frames go out in SEQ order on whatever path is
	// active at the time.
	sendMu      sync.Mutex
	sendSeq     uint64
	sendAckNext atomic.Uint64

	// Recv state: reorder buffer keyed by SEQ. expectedRecvSeq is the
	// next SEQ the application should observe.
	recvMu          sync.Mutex
	recvCond        *sync.Cond
	recvPacketCh    chan []byte
	recvPacketWake  chan struct{}
	recvWake        chan struct{}
	recvQueue       map[uint64]recvItem
	expectedRecvSeq uint64
	recvAckSent     uint64
	recvDeliver     []byte // pending bytes for the next Read (stream)
	packetized      bool   // when true, drainer routes payload to recvPacketCh
	recvPathCursor  uint64
	recvSeenBits    []uint64
	recvSeenHead    uint64
	recvPacketMarks int

	// recvDeadline is the application-set read deadline (zero = none).
	// When non-zero, Recv / RecvPacket return a timeout error if no
	// payload is available by the deadline. recvDeadlineTimer wakes
	// the recvCond at deadline expiry.
	recvDeadline      time.Time
	recvDeadlineTimer *time.Timer

	// recvQueueHWM is the maximum size the reorder buffer reached
	// during this Conn's lifetime. Exposed for diagnostics so race-
	// mode chaos / bond tests can spot 'dedup window overflow' that
	// is a hard race-mode bug to detect. Pure observer;
	// the engine does not act on it.
	recvQueueHWM int

	// recvDups counts incoming frames whose SEQ has already been
	// delivered (race-mode duplicates, retransmits-on-redistribute).
	// Pure observability hook so users can verify race is actually
	// reaping duplicates rather than racing one path only.
	recvDups uint64

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
	gen      uint64
	conn     transport.PathConn
	spec     transport.PathSpec
	attached time.Time
	// maintenance marks a slot as being intentionally torn down and
	// replaced (e.g. TCP_REPAIR rebuild). Death callbacks from the old
	// socket are ignored while this is true.
	maintenance atomic.Bool

	// recvDups counts inbound frames on THIS path whose SEQ had
	// already been delivered or buffered. Used per-path so monitoring
	// can identify which path is contributing duplicates under race
	// or accidental retransmits. Atomic - touched from the receive
	// path under recvMu, but readers via Paths() may run concurrently.
	recvDups atomic.Uint64
	recvQ    chan recvFrame

	// lastRecvUnixNano is the most recent wall-clock instant
	// (UnixNano) at which a frame was received on this path. Zero
	// before the first frame. Atomic for the same reason as recvDups.
	lastRecvUnixNano atomic.Int64

	// lastSendUnixNano mirrors lastRecvUnixNano on the send side:
	// stamped after a successful dispatch write to this slot's
	// socket. Engine-level (not probe-level): both data and ctrl
	// writes bump it.
	lastSendUnixNano atomic.Int64

	// bondSendHistory keeps a bounded ring of fully encoded frames
	// successfully written through this path in bond mode. If the
	// path dies asynchronously, the engine can replay these exact
	// SEQs on surviving paths; recv-side dedup makes already-arrived
	// frames harmless while filling gaps left on the dead path.
	bondSendMu   sync.Mutex
	bondSendRing [][]byte
	bondSendNext int
	bondSendFull bool

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
		recvPacketCh:     make(chan []byte, 16384),
		recvPacketWake:   make(chan struct{}, 1),
		recvWake:         make(chan struct{}, 1),
		recvQueue:        make(map[uint64]recvItem),
		zombieLeft:       limits.Clamp().ZombieMaxMigrations,
		probeOutstanding: make(map[uint64]time.Time),
		closed:           make(chan struct{}),
	}
	e.recvCond = sync.NewCond(&e.recvMu)
	e.state.Store(uint32(BridgeInit))
	go e.recvLoop()
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

// SetPeerCaps records capability bits advertised by the peer's HELLO.
func (e *Engine) SetPeerCaps(caps uint32) { e.peerCaps.Store(caps) }

// PeerCaps returns the capability bits advertised by the peer's HELLO.
func (e *Engine) PeerCaps() uint32 { return e.peerCaps.Load() }

// CreatedAt returns the monotonic wall-clock time at which this
// engine was constructed. Production monitoring uses this to compute
// connection age without polling Stats() at known intervals.
func (e *Engine) CreatedAt() time.Time { return e.created }

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
	recvQSize := 64
	if e.Packetized() {
		recvQSize = 1024
	}
	slot := &pathSlot{
		id:       id,
		gen:      e.nextPathGenerationLocked(),
		conn:     pc,
		spec:     spec,
		attached: time.Now(),
		recvQ:    make(chan recvFrame, recvQSize),
		quit:     make(chan struct{}),
		doneR:    make(chan struct{}),
	}
	e.paths[id] = slot

	gen := slot.gen
	pc.OnDeath(func(cause transport.DeathCause, err error) {
		e.onPathDeath(id, gen, cause, err)
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

func (e *Engine) nextPathGenerationLocked() uint64 {
	e.nextPathGen++
	return e.nextPathGen
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
		pi.RecvDups = s.recvDups.Load()
		if ns := s.lastRecvUnixNano.Load(); ns > 0 {
			pi.LastRecvAt = time.Unix(0, ns)
		}
		if ns := s.lastSendUnixNano.Load(); ns > 0 {
			pi.LastSendAt = time.Unix(0, ns)
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
	return e.migrate(id, true, "explicit")
}

func (e *Engine) migrate(id uint32, clearScope bool, cause string) error {
	e.pathsMu.Lock()
	slot, ok := e.paths[id]
	if !ok {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: migrate to unknown path %d", id)
	}
	if e.activeID == id {
		e.pathsMu.Unlock()
		return nil
	}
	oldID := e.activeID
	e.activeID = id
	if clearScope {
		e.dispatchScope = nil
	}
	e.migrationCount++
	e.setState(BridgeActive)

	// Build the MIGRATE_NOTIFY frame while still under the lock so
	// sendSeq is serialised consistently with other ctrl emissions.
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
	pc := slot.conn
	e.pathsMu.Unlock()

	// Hook fan-out and the MIGRATE_NOTIFY send happen AFTER unlock so
	// fireMigrateHooks can safely RLock pathsMu and hook callbacks
	// can call back into AdminConn methods without deadlocking. If
	// the captured pc has closed concurrently, the Write fails and
	// onPathDeath will pick up the slack.
	if cause == "" {
		cause = "explicit"
	}
	e.fireMigrateHooks(oldID, id, cause)
	go func() {
		_, _ = pc.Write(frame)
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
	e.pathsMu.Lock()
	e.dispatchScope = nil
	e.pathsMu.Unlock()
	e.mode.Store(mode)
}

// Mode returns the current dispatcher mode.
func (e *Engine) Mode() uint32 { return e.mode.Load() }

// SetDispatchPolicy updates the sender's mode and optionally limits
// dispatch to a policy-selected path group. It is used by the policy
// graph layer for selector -> bond/race target changes.
func (e *Engine) SetDispatchPolicy(mode uint32, active uint32, scope []uint32, cause string) error {
	if mode != dispatchPrime && mode != dispatchBond && mode != dispatchRace {
		mode = dispatchPrime
	}
	e.pathsMu.Lock()
	if len(scope) > 0 {
		for _, id := range scope {
			if _, ok := e.paths[id]; !ok {
				e.pathsMu.Unlock()
				return fmt.Errorf("engine: policy references unknown path %d", id)
			}
		}
	}
	if active != 0 {
		if _, ok := e.paths[active]; !ok {
			e.pathsMu.Unlock()
			return fmt.Errorf("engine: policy activates unknown path %d", active)
		}
	}
	oldID := e.activeID
	if active == 0 {
		active = e.pickAnyActiveFromScopeLocked(scope)
	}
	if active != 0 {
		e.activeID = active
		e.setState(BridgeActive)
	}
	if len(scope) == 0 {
		e.dispatchScope = nil
	} else {
		next := make(map[uint32]bool, len(scope))
		for _, id := range scope {
			next[id] = true
		}
		e.dispatchScope = next
	}
	changed := oldID != e.activeID && e.activeID != 0
	if changed {
		e.migrationCount++
	}
	e.mode.Store(mode)
	newID := e.activeID
	e.pathsMu.Unlock()
	if changed {
		if cause == "" {
			cause = "policy"
		}
		e.fireMigrateHooks(oldID, newID, cause)
	}
	return nil
}

// SetDispatchPolicyByName is the peer-control counterpart to
// SetDispatchPolicy. Receive-side selectors send target/path names because path
// ids are local to each peer; this method resolves those names against the
// local path slots and then applies the ordinary sender policy.
func (e *Engine) SetDispatchPolicyByName(mode uint32, activeName string, scopeNames []string, cause string) error {
	e.pathsMu.RLock()
	byName := make(map[string]uint32, len(e.paths))
	for id, slot := range e.paths {
		if name := pathSlotName(slot); name != "" {
			byName[name] = id
		}
	}
	e.pathsMu.RUnlock()

	scope := make([]uint32, 0, len(scopeNames))
	for _, name := range scopeNames {
		id, ok := byName[name]
		if !ok {
			return fmt.Errorf("engine: policy references unknown path name %q", name)
		}
		scope = append(scope, id)
	}
	var active uint32
	if activeName != "" {
		id, ok := byName[activeName]
		if !ok {
			return fmt.Errorf("engine: policy activates unknown path name %q", activeName)
		}
		active = id
	}
	return e.SetDispatchPolicy(mode, active, scope, cause)
}

func pathSlotName(slot *pathSlot) string {
	if slot == nil || slot.spec.Opts == nil {
		return ""
	}
	return slot.spec.Opts["name"]
}

// SetReadDeadline sets a deadline after which a blocked Recv/RecvPacket
// returns a timeout error (net.Error with Timeout()==true). The zero
// time clears the deadline. Replaces any previously-set deadline.
//
// Hard rule #1 still applies: a timeout from a deadline is an
// application-level error surface, not a migration-class error. The
// engine's path machinery is unaffected.
func (e *Engine) SetReadDeadline(t time.Time) error {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	if e.recvDeadlineTimer != nil {
		e.recvDeadlineTimer.Stop()
		e.recvDeadlineTimer = nil
	}
	e.recvDeadline = t
	if t.IsZero() {
		select {
		case e.recvPacketWake <- struct{}{}:
		default:
		}
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		e.recvCond.Broadcast()
		select {
		case e.recvPacketWake <- struct{}{}:
		default:
		}
		return nil
	}
	e.recvDeadlineTimer = time.AfterFunc(d, func() {
		e.recvMu.Lock()
		e.recvCond.Broadcast()
		e.recvMu.Unlock()
		select {
		case e.recvPacketWake <- struct{}{}:
		default:
		}
	})
	select {
	case e.recvPacketWake <- struct{}{}:
	default:
	}
	return nil
}

// timeoutError implements net.Error with Timeout()==true.
type timeoutError struct{}

func (timeoutError) Error() string   { return "rendr: read deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ErrReadDeadlineExceeded is the sentinel returned by Recv/RecvPacket
// when SetReadDeadline's deadline elapses before payload is ready.
// Implements net.Error.
var ErrReadDeadlineExceeded net.Error = timeoutError{}

// recvDeadlineExceededLocked reports whether the read deadline has
// elapsed. Caller holds recvMu.
func (e *Engine) recvDeadlineExceededLocked() bool {
	return !e.recvDeadline.IsZero() && !time.Now().Before(e.recvDeadline)
}

// SetPacketMode flips the engine's receive drainer to packet-boundary
// delivery. Each DATA frame becomes one entry on the packet queue
// drained by RecvPacket; SendPacket emits exactly one frame per call
// (no chunking). Must be called BEFORE any frames flow on the engine;
// once called, the engine is in packet mode for the rest of its life.
// Stream and packet modes share the same wire format - the choice is
// purely about receive-side semantics - so a stream-mode peer can
// talk to a packet-mode peer as long as both agree at HELLO time
// (negotiated via proto.CapsPacketMode).
func (e *Engine) SetPacketMode() {
	e.recvMu.Lock()
	e.packetized = true
	if e.recvSeenBits == nil {
		e.recvSeenBits = make([]uint64, packetRecvWindowBits/64)
	}
	e.recvMu.Unlock()
}

// Packetized reports whether the engine is in packet-boundary mode.
func (e *Engine) Packetized() bool {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	return e.packetized
}

// defaultBondPinSize is the number of consecutive frames bond
// dispatch keeps on one path before moving to the next. 8 is a
// trade-off between "small enough to keep aggregate bandwidth ~
// sum-of-paths" and "large enough to amortise the reorder cost
// from RTT skew between paths".
const defaultBondPinSize = 8

// BondStuckSkips returns the cumulative number of times bond
// dispatch bypassed a path because its probe-measured RTT exceeded
// best_path_rtt * BondStuckRTTMultiplier. Pure observability counter;
// useful for verifying that the stuck-skip protection is actually
// firing in production.
func (e *Engine) BondStuckSkips() uint64 {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return e.bondStuckSkips
}

// MigrationCount returns the cumulative number of active-path
// changes since this engine was created, excluding the initial
// active-path assignment. Both explicit Migrate() calls and
// death-driven failover via onPathDeath contribute. Production
// dashboards can use this to gauge churn on a flow.
func (e *Engine) MigrationCount() uint64 {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return e.migrationCount
}

// OnMigrate registers fn to be invoked (in a fresh goroutine) every
// time the engine's active path changes. cause is one of "explicit"
// (Migrate called by app) or "death" (onPathDeath promoting another
// path). The returned function cancels the subscription.
//
// Hooks run after pathsMu has been released, so fn may safely call
// back into AdminConn methods.
func (e *Engine) OnMigrate(fn func(oldID, newID uint32, cause string)) (cancel func()) {
	if fn == nil {
		return func() {}
	}
	e.pathsMu.Lock()
	if e.migrateHooks == nil {
		e.migrateHooks = make(map[uint64]func(uint32, uint32, string))
	}
	e.migrateHookID++
	id := e.migrateHookID
	e.migrateHooks[id] = fn
	e.pathsMu.Unlock()
	return func() {
		e.pathsMu.Lock()
		delete(e.migrateHooks, id)
		e.pathsMu.Unlock()
	}
}

// fireMigrateHooks snapshots the hook set and invokes each fn in its
// own goroutine. Caller must NOT hold pathsMu.
func (e *Engine) fireMigrateHooks(oldID, newID uint32, cause string) {
	e.pathsMu.RLock()
	if len(e.migrateHooks) == 0 {
		e.pathsMu.RUnlock()
		return
	}
	hooks := make([]func(uint32, uint32, string), 0, len(e.migrateHooks))
	for _, fn := range e.migrateHooks {
		hooks = append(hooks, fn)
	}
	e.pathsMu.RUnlock()
	for _, fn := range hooks {
		go fn(oldID, newID, cause)
	}
}

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

// QuiesceActivePath half-closes the active transport, when supported,
// after the local side has sent BYE. This gives TCP peers a chance to
// read the BYE as an orderly FIN path instead of racing a full socket
// close that can turn into RST when local control frames are unread.
func (e *Engine) QuiesceActivePath() {
	e.pathsMu.RLock()
	slot := e.paths[e.activeID]
	e.pathsMu.RUnlock()
	if slot == nil {
		return
	}
	if q, ok := slot.conn.(interface{ MarkQuiesced() }); ok {
		q.MarkQuiesced()
	}
	if cw, ok := slot.conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

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
	return len(e.recvQueue) + e.recvPacketMarks
}

// RecvDups returns the cumulative count of incoming frames whose
// SEQ had already been delivered (or was already in the reorder
// buffer). For race mode this is the duplicate-frames-reaped
// counter; for any mode it surfaces accidental retransmits.
func (e *Engine) RecvDups() uint64 {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	return e.recvDups
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
	e.onPathDeath(id, slot.gen, transport.CauseCleanClose, nil)
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
	e.onPathDeath(id, slot.gen, transport.CauseTransportError, err)
	return err
}

func (e *Engine) setCloseErr(err error) {
	e.closeMu.Lock()
	if e.closeErr == nil {
		e.closeErr = err
	}
	e.closeMu.Unlock()
}
