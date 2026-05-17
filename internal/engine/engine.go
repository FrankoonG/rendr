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
	recvQueue       map[uint64][]byte
	expectedRecvSeq uint64
	recvDeliver     []byte // pending bytes for the next Read

	// Zombie state.
	zombieMu             sync.Mutex
	zombieMigrationsLeft int
	lastPayloadAt        time.Time
	zombieCooldownUntil  time.Time

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
		side:                 side,
		flowID:               flowID,
		limits:               limits.Clamp(),
		created:              time.Now(),
		paths:                make(map[uint32]*pathSlot),
		recvQueue:            make(map[uint64][]byte),
		zombieMigrationsLeft: limits.Clamp().ZombieMaxMigrations,
		lastPayloadAt:        time.Now(),
		closed:               make(chan struct{}),
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
	return id, nil
}

// ActivePath returns the currently-active path id, or 0 if none.
func (e *Engine) ActivePath() uint32 {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return e.activeID
}

// Paths returns a snapshot of all attached paths.
func (e *Engine) Paths() []transport.PathInfo {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	out := make([]transport.PathInfo, 0, len(e.paths))
	for _, s := range e.paths {
		out = append(out, transport.PathInfo{
			ID:      s.id,
			Spec:    s.spec,
			Quality: s.conn.Quality(),
			Since:   s.attached,
		})
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

func (e *Engine) setCloseErr(err error) {
	e.closeMu.Lock()
	if e.closeErr == nil {
		e.closeErr = err
	}
	e.closeMu.Unlock()
}
