package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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

const maxSessionPaths = 64
const maxSeenAttachIDs = 1024
const pathCloseTimeout = 250 * time.Millisecond

// Side indicates whether this engine is the dialing (client) side or
// the listening (server) side. The only behavioural difference in M1
// is who issues HELLO first.
type Side uint8

const (
	SideClient Side = 0
	SideServer Side = 1
)

type PeerKind uint32

const (
	PeerUnknown PeerKind = iota
	PeerNative
	PeerRendr
)

// Engine is the per-Conn migration engine. One Engine backs one
// application-visible rendr.Conn.
type Engine struct {
	side               Side
	flowID             [16]byte
	limits             Limits
	peerCaps           atomic.Uint32
	localInstance      proto.InstanceID
	peerInstance       proto.InstanceID
	peerKind           atomic.Uint32
	state              atomic.Uint32 // BridgeState
	graphMu            sync.RWMutex
	localGraph         graphBinding
	peerGraph          graphBinding
	localExec          *executionRuntime
	peerNegotiation    proto.Negotiation
	peerNegotiationSet bool
	attachMu           sync.Mutex
	seenAttach         map[[16]byte]struct{}
	seenAttachFIFO     [][16]byte
	created            time.Time

	// Mode is the dispatcher selector: 1=selector, 2=bond, 3=race.
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
	migrateHooks         map[uint64]func(oldID, newID uint32, cause string)
	migrateHookID        uint64
	pathDeathHooks       map[uint64]func(PathDeathEvent)
	pathDeathSerialHooks map[uint64]func(PathDeathEvent)
	pathDeathHookID      uint64

	// Path management. activeID == 0 means "no active path".
	pathsMu      sync.RWMutex
	paths        map[uint32]*pathSlot
	pendingPaths map[uint32]*pathSlot
	stagedPaths  map[uint32]*pathSlot
	// retainedPaths remain receive-capable while a staged admission is
	// finalized. They are excluded from every TX dispatcher and provide a
	// bounded rollback target if the successor dies before confirmation.
	retainedPaths           map[uint32]*pathSlot
	pathPredecessors        map[uint32][]uint32
	pathAdmissionByLeaf     map[pathAdmissionLeafKey]pathAdmissionReservation
	pathAdmissionByPath     map[uint32]pathAdmissionLeafKey
	completedPathAdmissions map[proto.PathAdmissionBinding]*completedPathAdmission
	pathLeafGeneration      map[pathAdmissionLeafKey]uint64
	nextPathID              uint32
	nextPathGen             uint64
	activeID                uint32
	// dispatchScope optionally limits race/bond dispatch and death
	// failover to a policy-selected target group. nil means all paths.
	dispatchScope map[uint32]bool

	// Send state: one global SEQ counter, plus a single-flight
	// serialise so frames go out in SEQ order on whatever path is
	// active at the time.
	sendMu            sync.Mutex
	sendSeq           uint64
	sendAckNext       atomic.Uint64
	sendPublishedNext atomic.Uint64
	sendProof         proto.AckProof
	sendAckProof      proto.AckProof
	sendHistMu        sync.Mutex
	sendHist          sendHistory
	sendSlots         chan struct{}
	sendControlSlots  chan struct{}
	sendClosing       atomic.Bool
	terminalOnce      sync.Once
	terminalDone      chan struct{}
	terminalErr       error
	replayRequests    chan uint64
	ackMu             sync.Mutex
	ackPending        *ackRequest
	ackWake           chan struct{}

	// Recv state: reorder buffer keyed by SEQ. expectedRecvSeq is the
	// next SEQ the application should observe.
	recvMu              sync.Mutex
	recvCond            *sync.Cond
	recvPacketCh        chan []byte
	recvPacketWake      chan struct{}
	recvWake            chan struct{}
	recvQueue           map[uint64]recvItem
	expectedRecvSeq     uint64
	recvAckSent         uint64
	recvDeliver         []byte // pending bytes for the next Read (stream)
	recvDeliverFrames   []int  // remaining bytes per admitted stream DATA frame
	packetized          bool   // when true, drainer routes payload to recvPacketCh
	recvPathCursor      uint64
	recvSeenBits        []uint64
	recvSeenHead        uint64
	recvPacketMarks     int
	recvFinalErr        error
	recvTerminal        bool
	recvFinalHandled    bool
	recvProof           proto.AckProof
	recvFrameProofs     map[uint64]proto.FrameDigest
	policyReplayDigests map[uint64]proto.FrameDigest
	policyReplayOrder   []uint64
	recvDroppedThrough  uint64

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

	// Selector-mode scheduler. nil until StartSelector is called.
	selectorMu sync.Mutex
	selector   *selector

	// Directional policy transactions are serialized independently from the
	// data sequencer. The inbox preserves receive order while network writes
	// and path-death failover remain outside policyStateMu.
	policySendGate       chan struct{}
	policyOwnerMu        sync.Mutex
	policyStateMu        sync.Mutex
	policyGeneration     uint64
	policyPeerGeneration uint64
	policyOutgoing       *outgoingPolicyTransaction
	policyIncoming       *incomingPolicyTransaction
	policySelections     map[proto.TargetID]proto.TargetID
	policyCompleted      map[[16]byte]completedPolicyTransaction
	policyCompletedOrder [][16]byte
	policyInbox          chan policyMessage
	policyQueueMu        sync.Mutex
	policyQueued         map[policyMessageKey]struct{}
	policyAdmissionMu    sync.RWMutex
	policyAdmission      func(selectorID, targetID proto.TargetID, cause string) error

	// Per-path RTT probe state. Keys are probe_id, values are the
	// monotonic time at issue. handlePathProbeReply consumes them.
	probeMu               sync.Mutex
	probeOutstanding      map[uint64]time.Time
	probeNextID           uint64
	probeIntervalOverride time.Duration // 0 = default 1s; tests can shorten

	// Lifecycle.
	closing      atomic.Bool
	closeOnce    sync.Once
	closed       chan struct{} // internal cancellation
	quiesced     chan struct{} // public completion after owned loops stop
	coreWG       sync.WaitGroup
	closeResult  error
	closeErr     error
	closeMu      sync.Mutex
	gracefulOnce sync.Once
	gracefulDone chan struct{}
	gracefulErr  error
}

// PathDeathEvent is an internal immutable snapshot emitted after one path is
// removed from the engine. Root wrappers use it to redial the same frozen leaf.
type PathDeathEvent struct {
	ID             uint32
	Owner          uint64
	Spec           transport.PathSpec
	Binding        PathBinding
	Cause          transport.DeathCause
	Err            error
	Administrative bool
}

// PathRef names one physical generation of a logical path ID.
type PathRef struct {
	ID    uint32
	Owner uint64
}

// TopologySnapshot captures fields that must agree on one path-set epoch.
// Per-path counters remain atomic observations, but membership, active path,
// lifecycle state, and migration count are read under one pathsMu hold.
type TopologySnapshot struct {
	State          BridgeState
	ActivePath     uint32
	Paths          []transport.PathInfo
	MigrationCount uint64
}

var ErrPathAttachInProgress = errors.New("engine: path attach already in progress for leaf")
var ErrPathTXFenced = fmt.Errorf("%w: engine path is TX-fenced", net.ErrClosed)

// pathSlot tracks one attached path and its reader goroutine.
type pathSlot struct {
	id              uint32
	gen             uint64
	owner           uint64
	conn            transport.PathConn
	spec            transport.PathSpec
	localTXTargetID proto.TargetID
	peerTXTargetID  proto.TargetID
	attached        time.Time
	// maintenance marks a slot as being intentionally torn down and
	// replaced (e.g. TCP_REPAIR rebuild). Death callbacks from the old
	// socket are ignored while this is true.
	maintenance   atomic.Bool
	deathPending  atomic.Bool
	deathMu       sync.Mutex
	deathCause    transport.DeathCause
	deathErr      error
	removeWaiters atomic.Int32
	txEnabled     atomic.Bool
	writePermit   chan struct{}
	ackMu         sync.Mutex
	ackPending    *pathAckWrite
	ackRunning    bool
	ackClosed     bool
	ackWG         sync.WaitGroup

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
	lastSendUnixNano    atomic.Int64
	dataWrites          atomic.Uint64
	controlWrites       atomic.Uint64
	dataDispatches      atomic.Uint64
	firstDataDispatches atomic.Uint64

	dispatchMu      sync.Mutex
	dispatchQ       chan pathDispatchJob
	dispatchDead    bool
	dispatchFenced  bool
	dispatchStalled atomic.Bool

	quit              chan struct{}
	quitOnce          sync.Once
	doneR             chan struct{} // closed when reader goroutine exits
	doneW             chan struct{} // closed when data writer goroutine exits
	admissionInbox    chan pathAdmissionMessage
	admissionDone     chan struct{}
	admissionOnce     sync.Once
	admissionRollback atomic.Bool
	readerStarted     atomic.Bool
	writerStarted     atomic.Bool
	proberStarted     atomic.Bool
	doneP             chan struct{}
}

type pathAckWrite struct {
	frame    []byte
	terminal bool
	result   chan<- bool
}

func (s *pathSlot) writeFrame(frame []byte) (int, error) {
	if err := s.acquireWrite(context.Background()); err != nil {
		return 0, err
	}
	defer s.releaseWrite()
	return s.writeFrameOwned(frame)
}

func (s *pathSlot) writeFrameOwned(frame []byte) (int, error) {
	n, err := s.conn.Write(frame)
	if err == nil && n == len(frame) && len(frame) >= proto.HeaderSize {
		if header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize]); decodeErr == nil {
			if header.Type == proto.FrameData {
				s.dataWrites.Add(1)
			} else {
				s.controlWrites.Add(1)
			}
		}
	}
	return n, err
}

func (s *pathSlot) writeDispatchedFrame(frame []byte) (int, error) {
	if err := s.acquireWrite(context.Background()); err != nil {
		return 0, err
	}
	defer s.releaseWrite()
	if !s.txEnabled.Load() {
		return 0, ErrPathTXFenced
	}
	return s.writeFrameOwned(frame)
}

func (s *pathSlot) acquireWrite(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.writePermit:
		return nil
	case <-s.quit:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *pathSlot) releaseWrite() {
	s.writePermit <- struct{}{}
}

func (s *pathSlot) waitWriteIdle(ctx context.Context) error {
	if err := s.acquireWrite(ctx); err != nil {
		return err
	}
	s.releaseWrite()
	return nil

}

func (s *pathSlot) recordPendingDeath(cause transport.DeathCause, err error) {
	s.deathMu.Lock()
	s.deathCause = cause
	s.deathErr = err
	s.deathMu.Unlock()
	s.deathPending.Store(true)
}

func (s *pathSlot) takePendingDeath() (transport.DeathCause, error, bool) {
	if !s.deathPending.CompareAndSwap(true, false) {
		return transport.CauseUnknown, nil, false
	}
	s.deathMu.Lock()
	cause, err := s.deathCause, s.deathErr
	s.deathCause, s.deathErr = transport.CauseUnknown, nil
	s.deathMu.Unlock()
	if cause == transport.CauseUnknown {
		cause = transport.CauseTransportError
	}
	return cause, err, true
}

func (s *pathSlot) fenceDispatch() {
	s.dispatchMu.Lock()
	s.dispatchFenced = true
	s.txEnabled.Store(false)
	s.dispatchMu.Unlock()
}

func (s *pathSlot) unfenceDispatch() {
	s.dispatchMu.Lock()
	if !s.dispatchDead {
		s.txEnabled.Store(true)
		s.dispatchFenced = false
	}
	s.dispatchMu.Unlock()
}

func (s *pathSlot) recordDispatch(frame []byte, firstPublication bool) {
	if len(frame) < proto.HeaderSize {
		return
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err == nil && header.Type == proto.FrameData {
		s.dataDispatches.Add(1)
		if firstPublication {
			s.firstDataDispatches.Add(1)
		}
	}
}

func (s *pathSlot) noteRecv(at time.Time) {
	next := at.UnixNano()
	for {
		previous := s.lastRecvUnixNano.Load()
		if next <= previous {
			next = previous + 1
		}
		if s.lastRecvUnixNano.CompareAndSwap(previous, next) {
			return
		}
	}
}

// closeQuit is idempotent: multiple paths into the engine
// (Engine.Close, onPathDeath, an explicit migration tear-down) can
// all signal a slot to exit without panicking on a double close.
func (s *pathSlot) closeQuit() {
	s.quitOnce.Do(func() {
		s.completeAdmission()
		s.ackMu.Lock()
		s.ackClosed = true
		if s.ackPending != nil && s.ackPending.result != nil {
			select {
			case s.ackPending.result <- false:
			default:
			}
		}
		s.ackPending = nil
		s.ackMu.Unlock()
		s.dispatchMu.Lock()
		s.dispatchDead = true
		s.dispatchFenced = true
		s.txEnabled.Store(false)
		s.dispatchMu.Unlock()
		close(s.quit)
	})
}

func (s *pathSlot) completeAdmission() {
	if s != nil {
		s.admissionOnce.Do(func() { close(s.admissionDone) })
	}
}

// New constructs an engine. flowID is the connection identifier; on
// the client side it should be a fresh 16 random bytes, on the
// server side it should be copied from the inbound HELLO.
func New(side Side, flowID [16]byte, limits Limits) *Engine {
	e := &Engine{
		side:                    side,
		flowID:                  flowID,
		limits:                  limits.Clamp(),
		created:                 time.Now(),
		paths:                   make(map[uint32]*pathSlot),
		pendingPaths:            make(map[uint32]*pathSlot),
		stagedPaths:             make(map[uint32]*pathSlot),
		retainedPaths:           make(map[uint32]*pathSlot),
		pathPredecessors:        make(map[uint32][]uint32),
		pathAdmissionByLeaf:     make(map[pathAdmissionLeafKey]pathAdmissionReservation),
		pathAdmissionByPath:     make(map[uint32]pathAdmissionLeafKey),
		completedPathAdmissions: make(map[proto.PathAdmissionBinding]*completedPathAdmission),
		pathLeafGeneration:      make(map[pathAdmissionLeafKey]uint64),
		seenAttach:              make(map[[16]byte]struct{}),
		recvPacketCh:            make(chan []byte, 16384),
		recvPacketWake:          make(chan struct{}, 1),
		recvWake:                make(chan struct{}, 1),
		recvQueue:               make(map[uint64]recvItem),
		recvFrameProofs:         make(map[uint64]proto.FrameDigest),
		policyReplayDigests:     make(map[uint64]proto.FrameDigest),
		sendSlots:               make(chan struct{}, sendHistoryWindow),
		sendControlSlots:        make(chan struct{}, sendControlReserve),
		replayRequests:          make(chan uint64, 1),
		ackWake:                 make(chan struct{}, 1),
		policyInbox:             make(chan policyMessage, 64),
		policySendGate:          make(chan struct{}, 1),
		policySelections:        make(map[proto.TargetID]proto.TargetID),
		policyCompleted:         make(map[[16]byte]completedPolicyTransaction),
		policyQueued:            make(map[policyMessageKey]struct{}),
		zombieLeft:              limits.Clamp().ZombieMaxMigrations,
		probeOutstanding:        make(map[uint64]time.Time),
		closed:                  make(chan struct{}),
		quiesced:                make(chan struct{}),
		gracefulDone:            make(chan struct{}),
		terminalDone:            make(chan struct{}),
	}
	e.recvCond = sync.NewCond(&e.recvMu)
	e.state.Store(uint32(BridgeInit))
	e.localGraph = graphBinding{revision: 1}
	e.peerGraph = graphBinding{revision: 1}
	e.sendProof = proto.InitialAckProof(proto.SessionEpoch(flowID), senderDirection(side), 1, proto.GraphDigest{})
	e.sendAckProof = e.sendProof
	e.recvProof = proto.InitialAckProof(proto.SessionEpoch(flowID), peerSenderDirection(side), 1, proto.GraphDigest{})
	e.startCoreLoop(e.recvLoop)
	e.startCoreLoop(e.replayLoop)
	e.startCoreLoop(e.ackLoop)
	e.startCoreLoop(e.ackWriterLoop)
	e.startCoreLoop(e.policyLoop)
	return e
}

func (e *Engine) startCoreLoop(loop func()) {
	e.coreWG.Add(1)
	go func() {
		defer e.coreWG.Done()
		loop()
	}()
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

func NewInstanceID() proto.InstanceID {
	var id proto.InstanceID
	if _, err := rand.Read(id[:]); err != nil {
		t := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			id[i] = byte(t >> (i * 8))
		}
	}
	return id
}

// FlowID returns the engine's flow identifier.
func (e *Engine) FlowID() [16]byte { return e.flowID }

func (e *Engine) SetLocalInstanceID(id proto.InstanceID) { e.localInstance = id }

func (e *Engine) LocalInstanceID() proto.InstanceID { return e.localInstance }

func (e *Engine) SetPeerInstanceID(id proto.InstanceID) { e.peerInstance = id }

func (e *Engine) PeerInstanceID() proto.InstanceID { return e.peerInstance }

func (e *Engine) SetPeerKind(kind PeerKind) { e.peerKind.Store(uint32(kind)) }

func (e *Engine) PeerKind() PeerKind { return PeerKind(e.peerKind.Load()) }

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
	binding, err := e.InferPathBinding(spec)
	if err != nil {
		if pc != nil {
			_ = pc.Close()
		}
		return 0, err
	}
	return e.AttachPathBound(pc, spec, binding)
}

// AttachPathBound registers a path with its independently negotiated sender
// graph leaves. Binding validation happens before any path ID, callback, or
// goroutine is allocated.
func (e *Engine) AttachPathBound(pc transport.PathConn, spec transport.PathSpec, binding PathBinding) (uint32, error) {
	id, err := e.PreparePathBound(pc, spec, binding)
	if err != nil {
		return 0, err
	}
	if err := e.CommitPathAttach(id); err != nil {
		e.AbortPathAttach(id, err)
		return 0, err
	}
	return id, nil
}

// PreparePathBound validates and reserves a path without making it visible to
// DATA dispatch. The server uses this phase while BRIDGE_ACK still owns the
// carrier exclusively.
func (e *Engine) PreparePathBound(pc transport.PathConn, spec transport.PathSpec, binding PathBinding) (uint32, error) {
	if pc == nil {
		return 0, errors.New("engine: nil PathConn")
	}
	if err := e.validatePathBinding(binding); err != nil {
		_ = pc.Close()
		return 0, err
	}
	e.pathsMu.Lock()
	var (
		completedKey     pathAdmissionLeafKey
		completedKeyOK   bool
		completedOverlap []*pathSlot
		superseded       map[uint32]struct{}
	)
	rejectLocked := func(err error) (uint32, error) {
		e.pathsMu.Unlock()
		e.retirePathSet(completedOverlap)
		_ = pc.Close()
		return 0, err
	}

	if e.isClosed() || e.sendClosing.Load() {
		return rejectLocked(net.ErrClosed)
	}
	if completedKey, completedKeyOK = pathAdmissionKey(e.side, binding); completedKeyOK {
		superseded = e.completedAdmissionPredecessorsLocked(completedKey)
	}
	pathCount := len(e.paths) + len(e.pendingPaths) + len(e.stagedPaths) + len(e.retainedPaths) - len(superseded)
	if pathCount >= maxSessionPaths {
		return rejectLocked(fmt.Errorf("engine: session path limit %d reached", maxSessionPaths))
	}
	for _, inFlight := range []map[uint32]*pathSlot{e.pendingPaths, e.stagedPaths} {
		for _, existing := range inFlight {
			if binding.LocalTXTargetID != (proto.TargetID{}) &&
				binding.PeerTXTargetID != (proto.TargetID{}) &&
				existing.localTXTargetID == binding.LocalTXTargetID &&
				existing.peerTXTargetID == binding.PeerTXTargetID {
				return rejectLocked(ErrPathAttachInProgress)
			}
		}
	}
	all := make([]*pathSlot, 0, len(e.paths)+len(e.pendingPaths)+len(e.stagedPaths)+len(e.retainedPaths))
	for _, existing := range e.paths {
		all = append(all, existing)
	}
	for _, existing := range e.pendingPaths {
		all = append(all, existing)
	}
	for _, existing := range e.stagedPaths {
		all = append(all, existing)
	}
	for _, existing := range e.retainedPaths {
		all = append(all, existing)
	}
	for _, existing := range all {
		if _, replaceable := superseded[existing.id]; replaceable {
			continue
		}
		sameLocal := binding.LocalTXTargetID != (proto.TargetID{}) && existing.localTXTargetID == binding.LocalTXTargetID
		samePeer := binding.PeerTXTargetID != (proto.TargetID{}) && existing.peerTXTargetID == binding.PeerTXTargetID
		if sameLocal && samePeer {
			if existing.maintenance.Load() {
				return rejectLocked(ErrPathAttachInProgress)
			}
			// Make-before-break recovery may briefly attach two physical
			// carriers for the same logical directional leaf pair.
			continue
		}
		if sameLocal {
			return rejectLocked(fmt.Errorf("engine: local TX target is already paired with another peer target"))
		}
		if samePeer {
			return rejectLocked(fmt.Errorf("engine: peer TX target is already paired with another local target"))
		}
	}

	e.nextPathID++
	id := e.nextPathID
	if id == 0 {
		// 0 reserved for "no active path"; skip on wrap.
		e.nextPathID++
		id = e.nextPathID
	}
	if err := e.reservePathAdmissionLocked(id, binding); err != nil {
		return rejectLocked(err)
	}
	recvQSize := 64
	if e.Packetized() {
		recvQSize = 1024
	}
	generation := e.nextPathGenerationLocked()
	slot := &pathSlot{
		id:              id,
		gen:             generation,
		owner:           generation,
		conn:            pc,
		spec:            spec.Clone(),
		localTXTargetID: binding.LocalTXTargetID,
		peerTXTargetID:  binding.PeerTXTargetID,
		attached:        time.Now(),
		recvQ:           make(chan recvFrame, recvQSize),
		dispatchQ:       make(chan pathDispatchJob, pathDispatchQueueSize),
		writePermit:     newPathWritePermit(),
		quit:            make(chan struct{}),
		doneR:           make(chan struct{}),
		doneW:           make(chan struct{}),
		doneP:           make(chan struct{}),
		admissionInbox:  make(chan pathAdmissionMessage, pathAdmissionInboxSize),
		admissionDone:   make(chan struct{}),
	}
	if completedKeyOK {
		completedOverlap = e.retireCompletedAdmissionPredecessorsLocked(completedKey)
	}
	e.pendingPaths[id] = slot
	e.pathsMu.Unlock()
	e.retirePathSet(completedOverlap)
	return id, nil
}

func newPathWritePermit() chan struct{} {
	permit := make(chan struct{}, 1)
	permit <- struct{}{}
	return permit
}

// CommitPathAttach preserves the original one-call attach contract. Admission
// handshakes use StagePathAttach and ActivateStagedPath separately so the new
// carrier can receive confirmation without becoming a TX route prematurely.
func (e *Engine) CommitPathAttach(id uint32) error {
	if err := e.StagePathAttach(id); err != nil {
		return err
	}
	return e.ActivateStagedPath(id, false)
}

// StagePathAttach starts only the receive side of a prepared carrier. The
// path is deliberately absent from Paths, activeID, and every TX dispatcher.
func (e *Engine) StagePathAttach(id uint32) error {
	e.pathsMu.Lock()
	slot := e.pendingPaths[id]
	if slot == nil {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: stage unknown pending path %d", id)
	}
	if e.isClosed() || e.sendClosing.Load() {
		delete(e.pendingPaths, id)
		e.pathsMu.Unlock()
		_ = slot.conn.Close()
		return net.ErrClosed
	}
	delete(e.pendingPaths, id)
	slot.readerStarted.Store(true)
	e.stagedPaths[id] = slot
	e.pathsMu.Unlock()

	owner := slot.owner
	slot.conn.OnDeath(func(cause transport.DeathCause, err error) {
		e.onPathDeath(id, owner, cause, err)
	})
	go e.readerLoop(slot)
	return nil
}

// ActivateStagedPath publishes an RX-ready staged path as the TX successor.
// When retainPredecessor is true, one previous generation remains RX-capable
// for at most the migration budget so a lost final admission message cannot
// strand the two peers on disjoint generations.
func (e *Engine) ActivateStagedPath(id uint32, retainPredecessor bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), e.limits.MigrationBudget)
	defer cancel()
	return e.activateStagedPathContext(ctx, id, retainPredecessor, retainPredecessor)
}

// activateStagedPath publishes a staged path after draining any application
// write already in progress on its predecessor. rollbackAllowed is false once
// the peer has proved it already activated this generation: from that point a
// successor failure is an uncertain distributed outcome and must not revive a
// predecessor the peer may have retired.
func (e *Engine) activateStagedPathContext(ctx context.Context, id uint32, retainPredecessor, rollbackAllowed bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		retired           []*pathSlot
		fenced            []*pathSlot
		oldActive         uint32
		recoveryEvent     bool
		superseded        bool
		admissionDeadline time.Time
	)
	e.pathsMu.Lock()
	slot := e.stagedPaths[id]
	if slot == nil {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: activate unknown staged path %d", id)
	}
	if e.isClosed() || e.sendClosing.Load() {
		delete(e.stagedPaths, id)
		e.pathsMu.Unlock()
		slot.closeQuit()
		_ = slot.conn.Close()
		return net.ErrClosed
	}
	// Fence new application dispatches while pathsMu still protects the active
	// set. Drain writes outside pathsMu: transports may synchronously report
	// OnDeath from Write, and that callback also needs pathsMu.
	for _, existing := range e.paths {
		if !sameBoundLeaf(slot, existing) {
			continue
		}
		existing.maintenance.Store(true)
		existing.fenceDispatch()
		fenced = append(fenced, existing)
	}
	e.pathsMu.Unlock()

	for _, existing := range fenced {
		if err := existing.waitWriteIdle(ctx); err != nil {
			e.pathsMu.Lock()
			deaths := e.unwindFencedPathsLocked(fenced)
			e.pathsMu.Unlock()
			e.processDeferredPathDeaths(deaths)
			return fmt.Errorf("engine: predecessor write fence: %w", err)
		}
	}

	e.pathsMu.Lock()
	slot = e.stagedPaths[id]
	if slot == nil || e.isClosed() || e.sendClosing.Load() {
		deaths := e.unwindFencedPathsLocked(fenced)
		e.pathsMu.Unlock()
		e.processDeferredPathDeaths(deaths)
		if slot == nil {
			return fmt.Errorf("engine: staged path %d changed during activation", id)
		}
		return net.ErrClosed
	}
	for _, existing := range fenced {
		if current := e.paths[existing.id]; current != existing || !sameBoundLeaf(slot, existing) {
			deaths := e.unwindFencedPathsLocked(fenced)
			e.pathsMu.Unlock()
			e.processDeferredPathDeaths(deaths)
			return fmt.Errorf("engine: predecessor changed during path activation")
		}
	}
	// A native in-place repair may have advanced the generation while this
	// admission waited for its peer. Rebase under the same lock that publishes
	// the successor; no competing staged attach for this leaf is permitted.
	for _, existing := range e.paths {
		if sameBoundLeaf(slot, existing) && existing.gen >= slot.gen {
			slot.gen = e.nextPathGenerationLocked()
			break
		}
	}
	if _, err := e.advancePathAdmissionLocked(id); err != nil {
		deaths := e.unwindFencedPathsLocked(fenced)
		e.pathsMu.Unlock()
		e.processDeferredPathDeaths(deaths)
		return err
	}
	// Keep at most one older receive generation per logical leaf.
	for retainedID, existing := range e.retainedPaths {
		if !sameBoundLeaf(slot, existing) {
			continue
		}
		delete(e.retainedPaths, retainedID)
		existing.closeQuit()
		retired = append(retired, existing)
	}
	for _, existing := range fenced {
		existingID := existing.id
		superseded = true
		delete(e.paths, existingID)
		if e.dispatchScope[existingID] {
			delete(e.dispatchScope, existingID)
			e.dispatchScope[id] = true
		}
		if retainPredecessor && !existing.deathPending.Load() {
			e.retainedPaths[existingID] = existing
			e.pathPredecessors[id] = append(e.pathPredecessors[id], existingID)
		} else {
			existing.closeQuit()
			retired = append(retired, existing)
		}
	}
	delete(e.stagedPaths, id)
	oldActive = e.activeID
	slot.unfenceDispatch()
	slot.admissionRollback.Store(rollbackAllowed)
	slot.writerStarted.Store(true)
	slot.proberStarted.Store(true)
	e.paths[id] = slot
	if e.activeID == 0 {
		e.activeID = id
		recoveryEvent = e.State() == BridgeMigrating
		if e.State() == BridgeInit || e.State() == BridgeMigrating {
			e.setState(BridgeActive)
		}
	} else if _, activeStillPresent := e.paths[e.activeID]; !activeStillPresent {
		e.activeID = id
		recoveryEvent = true
	}
	if recoveryEvent {
		e.migrationCount++
	}
	if !retainPredecessor {
		e.releasePathAdmissionLocked(id)
		slot.completeAdmission()
	} else {
		admissionDeadline = e.ensurePathAdmissionDeadlineLocked(id)
	}
	e.pathsMu.Unlock()

	go e.pathWriterLoop(slot)
	go e.proberLoop(slot)
	for _, existing := range retired {
		go e.retireSupersededPath(existing)
	}
	if recoveryEvent {
		e.fireMigrateHooks(oldActive, id, "recovery")
		e.recordMigration()
	}
	if superseded {
		e.requestReplay(e.sendAckNext.Load())
	}
	if retainPredecessor {
		gen := slot.gen
		go func() {
			delay := time.Until(admissionDeadline)
			if delay < 0 {
				delay = 0
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
				e.completePathAdmissionGeneration(id, gen)
			case <-slot.admissionDone:
			case <-e.closed:
			}
		}()
	}
	return nil
}

// ReleasePathPredecessors ends the overlap window after peer confirmation.
func (e *Engine) ReleasePathPredecessors(successorID uint32) {
	e.pathsMu.Lock()
	successor := e.paths[successorID]
	if successor == nil {
		e.pathsMu.Unlock()
		return
	}
	retired := e.releasePathPredecessorsLocked(successorID, successor.gen)
	e.pathsMu.Unlock()
	e.retirePathSet(retired)
}

// DisablePathAdmissionRollback records that the peer may already have made
// the successor generation durable. A later successor failure must use normal
// recovery or fail closed; reviving the predecessor could split the peers.
func (e *Engine) DisablePathAdmissionRollback(pathID uint32) error {
	e.pathsMu.RLock()
	slot := e.pathSlotForAdmissionLocked(pathID)
	e.pathsMu.RUnlock()
	if slot == nil {
		return fmt.Errorf("engine: admission path %d is unavailable", pathID)
	}
	slot.admissionRollback.Store(false)
	return nil
}

func (e *Engine) releasePathPredecessors(successorID uint32, successorGen uint64) {
	e.pathsMu.Lock()
	retired := e.releasePathPredecessorsLocked(successorID, successorGen)
	e.pathsMu.Unlock()
	e.retirePathSet(retired)
}

func (e *Engine) releasePathPredecessorsLocked(successorID uint32, successorGen uint64) []*pathSlot {
	successor := e.paths[successorID]
	if successor == nil || successor.gen != successorGen {
		return nil
	}
	successor.completeAdmission()
	ids := e.pathPredecessors[successorID]
	delete(e.pathPredecessors, successorID)
	retired := make([]*pathSlot, 0, len(ids))
	for _, predecessorID := range ids {
		if predecessor := e.retainedPaths[predecessorID]; predecessor != nil {
			delete(e.retainedPaths, predecessorID)
			predecessor.closeQuit()
			retired = append(retired, predecessor)
		}
	}
	return retired
}

func (e *Engine) retirePathSet(retired []*pathSlot) {
	for _, predecessor := range retired {
		go e.retireSupersededPath(predecessor)
	}
}

func sameBoundLeaf(a, b *pathSlot) bool {
	if a == nil || b == nil || a.localTXTargetID == (proto.TargetID{}) || a.peerTXTargetID == (proto.TargetID{}) {
		return false
	}
	return a.localTXTargetID == b.localTXTargetID && a.peerTXTargetID == b.peerTXTargetID
}

func (e *Engine) retireSupersededPath(slot *pathSlot) {
	_ = slot.conn.Close()
	timer := time.NewTimer(pathCloseTimeout)
	defer timer.Stop()
	select {
	case <-slot.doneR:
	case <-timer.C:
		// Never race a final reader enqueue. A conforming PathConn.Close
		// unblocks Read promptly; if it does not, keep cleanup detached until
		// the reader eventually exits instead of stranding a late frame.
		go func() {
			<-slot.doneR
			e.drainDeadSlot(slot)
		}()
		return
	}
	if slot.writerStarted.Load() {
		select {
		case <-slot.doneW:
		case <-timer.C:
		}
	}
	if slot.proberStarted.Load() {
		select {
		case <-slot.doneP:
		case <-timer.C:
		}
	}
	e.drainDeadSlot(slot)
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
// migration. Selector-mode scoring decides migration via the
// independent scheduler in selector.go.
func (e *Engine) proberLoop(slot *pathSlot) {
	defer close(slot.doneP)
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
			_, _ = slot.writeFrame(frame)

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
	activeID := e.activeID
	slots := e.pathSlotsLocked()
	e.pathsMu.RUnlock()
	return pathInfos(slots, activeID)
}

// TopologySnapshot returns one coherent public-observation epoch.
func (e *Engine) TopologySnapshot() TopologySnapshot {
	e.pathsMu.RLock()
	activeID := e.activeID
	slots := e.pathSlotsLocked()
	snapshot := TopologySnapshot{
		State:          BridgeState(e.state.Load()),
		ActivePath:     activeID,
		MigrationCount: e.migrationCount,
	}
	e.pathsMu.RUnlock()
	snapshot.Paths = pathInfos(slots, activeID)
	return snapshot
}

func (e *Engine) pathSlotsLocked() []*pathSlot {
	slots := make([]*pathSlot, 0, len(e.paths))
	for _, s := range e.paths {
		slots = append(slots, s)
	}
	return slots
}

func pathInfos(slots []*pathSlot, activeID uint32) []transport.PathInfo {
	out := make([]transport.PathInfo, 0, len(slots))
	for _, s := range slots {
		pi := transport.PathInfo{
			ID:      s.id,
			Spec:    s.spec.Clone(),
			Quality: s.conn.Quality(),
			Since:   s.attached,
			Active:  s.id == activeID,
		}
		if rw, ok := s.conn.(interface {
			Reads() uint64
			Writes() uint64
		}); ok {
			pi.Reads = rw.Reads()
			pi.Writes = rw.Writes()
		}
		if observer, ok := s.conn.(transport.IngressQueueObserver); ok {
			pi.IngressQueue = observer.IngressQueueStats()
		}
		pi.RecvDups = s.recvDups.Load()
		pi.DataWrites = s.dataWrites.Load()
		pi.ControlWrites = s.controlWrites.Load()
		pi.DataDispatches = s.dataDispatches.Load()
		pi.FirstDataDispatches = s.firstDataDispatches.Load()
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
// all subsequent sends. Unacked frames from the bounded send history
// are replayed on the new active path; recv-side dedup makes already
// delivered frames harmless while filling gaps left on the old path.
func (e *Engine) Migrate(id uint32) error {
	if runtime := e.localExecutionRuntime(); runtime != nil {
		return e.migrateRecursiveSelectorPath(id, runtime)
	}
	return e.migrateOwnerDecision(id, true, "explicit")
}

func (e *Engine) migrateRecursiveSelectorPath(id uint32, runtime *executionRuntime) error {
	e.pathsMu.RLock()
	slot := e.paths[id]
	targetID := proto.TargetID{}
	if slot != nil {
		targetID = slot.localTXTargetID
	}
	e.pathsMu.RUnlock()
	if slot == nil {
		return fmt.Errorf("engine: migrate to unknown path %d", id)
	}
	root, ok := runtime.plan.root()
	if !ok || root.kind != proto.GraphNodeKindSelector {
		return fmt.Errorf("engine: path migration requires a selector root")
	}
	if err := runtime.plan.validateImmediateChild(root.targetID, targetID); err != nil {
		return fmt.Errorf("engine: path %d is not a directly selectable root target: %w", id, err)
	}
	if err := e.SelectLocalTarget(root.targetID, targetID, "explicit"); err != nil {
		return err
	}
	return e.redistributeFrames(e.sendHistorySnapshot(e.sendAckNext.Load()))
}

func (e *Engine) migrateOwnerDecision(id uint32, clearScope bool, cause string) error {
	e.policyOwnerMu.Lock()
	defer e.policyOwnerMu.Unlock()
	if err := e.migrate(id, clearScope, cause); err != nil {
		return err
	}
	e.recordPathPolicyDecision(id)
	return nil
}

func (e *Engine) recordPathPolicyDecision(id uint32) {
	binding := e.localGraphBinding()
	root, ok := binding.manifest.Node(binding.manifest.RootID)
	if !ok || root.Kind != proto.GraphNodeKindSelector {
		return
	}
	e.pathsMu.RLock()
	slot := e.paths[id]
	targetID := proto.TargetID{}
	if slot != nil {
		targetID = slot.localTXTargetID
	}
	e.pathsMu.RUnlock()
	node, ok := binding.manifest.Node(targetID)
	if !ok || node.Kind != proto.GraphNodeKindPath {
		return
	}
	immediate := false
	for _, childID := range root.Children {
		if childID == node.ID {
			immediate = true
			break
		}
	}
	if !immediate {
		return
	}
	e.policyStateMu.Lock()
	defer e.policyStateMu.Unlock()
	if e.policySelections[root.ID] == node.ID {
		return
	}
	if e.policyGeneration != ^uint64(0) {
		e.policyGeneration++
	}
	e.policySelections[root.ID] = node.ID
}

func (e *Engine) migrate(id uint32, clearScope bool, cause string) error {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	if e.isClosed() {
		return net.ErrClosed
	}

	e.pathsMu.RLock()
	slot, ok := e.paths[id]
	if !ok {
		e.pathsMu.RUnlock()
		return fmt.Errorf("engine: migrate to unknown path %d", id)
	}
	if e.activeID == id {
		e.pathsMu.RUnlock()
		return nil
	}
	gen := slot.gen
	e.pathsMu.RUnlock()

	replay := e.sendHistorySnapshot(e.sendAckNext.Load())
	for _, frame := range replay {
		n, err := slot.writeDispatchedFrame(frame)
		if err != nil {
			return err
		}
		if n != len(frame) {
			return io.ErrShortWrite
		}
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
	}

	e.pathsMu.Lock()
	current, ok := e.paths[id]
	if !ok || current != slot || current.gen != gen {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: migration target %d changed during replay", id)
	}
	oldID := e.activeID
	e.activeID = id
	if clearScope {
		e.dispatchScope = nil
	}
	e.migrationCount++
	e.setState(BridgeActive)
	e.pathsMu.Unlock()

	if cause == "" {
		cause = "explicit"
	}
	e.fireMigrateHooks(oldID, id, cause)
	return nil
}

// isClosed checks the lifecycle.
func (e *Engine) isClosed() bool {
	if e.closing.Load() {
		return true
	}
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

// WaitForSendDrain waits for the peer's cumulative ACK to cover every frame
// published before the call. It is used only during explicit local close.
func (e *Engine) WaitForSendDrain() bool {
	target := e.sendPublishedNext.Load()
	if e.sendAckNext.Load() >= target {
		return true
	}
	wait := e.limits.MigrationBudget
	if wait > 2*time.Second {
		wait = 2 * time.Second
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if e.sendAckNext.Load() >= target {
			return true
		}
		select {
		case <-e.closed:
			return false
		case <-timer.C:
			return false
		case <-ticker.C:
		}
	}
}

// GracefulClose linearizes the local send side, emits exactly one final BYE,
// waits briefly for cumulative acknowledgement, and then tears down paths.
// Concurrent callers observe the same result. A broken PathConn cannot hold
// the public Close call forever; timeout returns ErrGracefulCloseTimeout.
func (e *Engine) GracefulClose(reason proto.ByeReason) error {
	e.gracefulOnce.Do(func() {
		e.gracefulErr = e.runGracefulClose(reason)
		close(e.gracefulDone)
	})
	<-e.gracefulDone
	return e.gracefulErr
}

func (e *Engine) runGracefulClose(reason proto.ByeReason) error {
	if e.isClosed() {
		return nil
	}
	e.sendClosing.Store(true)
	timeout := e.limits.MigrationBudget
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	sent := make(chan error, 1)
	go func() { sent <- e.SendBye(reason) }()
	timer := time.NewTimer(timeout)
	var closeErr error
	select {
	case err := <-sent:
		if err != nil {
			closeErr = err
		} else if !e.WaitForSendDrain() {
			closeErr = ErrGracefulCloseTimeout
		}
	case <-timer.C:
		closeErr = ErrGracefulCloseTimeout
	case <-e.closed:
		return nil
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	e.QuiesceActivePath()
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case err := <-closed:
		if closeErr == nil {
			closeErr = err
		}
	case <-time.After(250 * time.Millisecond):
		if closeErr == nil {
			closeErr = ErrGracefulCloseTimeout
		}
	}
	return closeErr
}

// Internal dispatch identifiers are deliberately separate from both the
// public API mode and the wire-level proto.ExecutionKind.
const (
	dispatchSelector uint32 = 1
	dispatchBond     uint32 = 2
	dispatchRace     uint32 = 3
)

// ConfigureExecution sets the initial sender executor using an explicit wire
// mapping. Runtime policy transitions use SetDispatchPolicy.
func (e *Engine) ConfigureExecution(kind proto.ExecutionKind) error {
	mode, ok := dispatchForExecutionKind(kind)
	if !ok {
		return fmt.Errorf("engine: invalid execution kind %d", kind)
	}
	e.pathsMu.Lock()
	e.dispatchScope = nil
	e.pathsMu.Unlock()
	e.mode.Store(mode)
	return nil
}

// Mode returns the current dispatcher mode.
func (e *Engine) Mode() uint32 { return e.mode.Load() }

// setDispatchPolicy updates the temporary flat dispatcher at one sender
// boundary. Callers must own policyOwnerMu when this is a runtime decision;
// initialization runs before the engine is exposed to the application.
func (e *Engine) setDispatchPolicy(kind proto.ExecutionKind, active uint32, scope []uint32, cause string) error {
	return e.setDispatchPolicyAndSelection(kind, active, scope, cause, nil, proto.TargetID{}, proto.TargetID{})
}

func (e *Engine) setDispatchPolicyAndSelection(
	kind proto.ExecutionKind,
	active uint32,
	scope []uint32,
	cause string,
	runtime *executionRuntime,
	selectorID proto.TargetID,
	targetID proto.TargetID,
) error {
	mode, ok := dispatchForExecutionKind(kind)
	if !ok {
		return fmt.Errorf("engine: invalid execution kind %d", kind)
	}
	// Serialize the policy boundary with sequenced DATA/CTRL publication. Once
	// this returns, every later frame observes the new mode, scope, and active
	// path as one state transition.
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	if e.isClosed() || e.sendClosing.Load() {
		return net.ErrClosed
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
	if runtime != nil {
		if err := runtime.selectChild(selectorID, targetID); err != nil {
			e.pathsMu.Unlock()
			return err
		}
		effectiveKind, projectedActive, projectedScope, err := e.projectRecursiveDispatchLocked(runtime)
		if err != nil {
			e.pathsMu.Unlock()
			return err
		}
		mode, ok = dispatchForExecutionKind(effectiveKind)
		if !ok {
			e.pathsMu.Unlock()
			return fmt.Errorf("engine: invalid effective execution kind %d", effectiveKind)
		}
		active = projectedActive
		scope = projectedScope
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

// projectRecursiveDispatchLocked maps the root's effective target subtree to
// the transitional flat observability fields. Caller must hold pathsMu.
func (e *Engine) projectRecursiveDispatchLocked(runtime *executionRuntime) (proto.ExecutionKind, uint32, []uint32, error) {
	attached := make(map[proto.TargetID]bool, len(e.paths))
	for _, slot := range e.paths {
		attached[slot.localTXTargetID] = true
	}
	leafTargets, kind, err := runtime.activeLeafTargets(attached)
	if err != nil {
		return 0, 0, nil, err
	}
	leafSet := make(map[proto.TargetID]bool, len(leafTargets))
	for _, leafID := range leafTargets {
		leafSet[leafID] = true
	}
	scope := make([]uint32, 0, len(leafTargets))
	for pathID, slot := range e.paths {
		if leafSet[slot.localTXTargetID] {
			scope = append(scope, pathID)
		}
	}
	for i := 1; i < len(scope); i++ {
		for j := i; j > 0 && scope[j] < scope[j-1]; j-- {
			scope[j], scope[j-1] = scope[j-1], scope[j]
		}
	}
	active := uint32(0)
	for _, pathID := range scope {
		if pathID == e.activeID {
			active = pathID
			break
		}
	}
	if active == 0 && len(scope) > 0 {
		active = scope[0]
	}
	return kind, active, scope, nil
}

// SetPeerPolicyAdmission installs a bounded, local sender-side admission
// check for advisory peer selection requests. A nil function clears it.
func (e *Engine) SetPeerPolicyAdmission(fn func(selectorID, targetID proto.TargetID, cause string) error) {
	e.policyAdmissionMu.Lock()
	e.policyAdmission = fn
	e.policyAdmissionMu.Unlock()
}

func (e *Engine) admitPeerPolicy(selectorID, targetID proto.TargetID, cause string) error {
	e.policyAdmissionMu.RLock()
	fn := e.policyAdmission
	e.policyAdmissionMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(selectorID, targetID, cause)
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

// BondStuckSkips returns the cumulative number of path writer stalls that
// caused recursive dispatch to retry the immutable frame on another route.
// RTT by itself never increments this counter or excludes a bond child.
func (e *Engine) BondStuckSkips() uint64 {
	e.pathsMu.RLock()
	legacy := e.bondStuckSkips
	e.pathsMu.RUnlock()
	if runtime := e.localExecutionRuntime(); runtime != nil {
		return legacy + runtime.stuckSkips.Load()
	}
	return legacy
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
// back into the root package's narrow control interfaces.
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

// OnPathDeath registers an internal lifecycle subscriber. Callbacks run in
// fresh goroutines after pathsMu is released.
func (e *Engine) OnPathDeath(fn func(PathDeathEvent)) (cancel func()) {
	if fn == nil {
		return func() {}
	}
	e.pathsMu.Lock()
	e.pathDeathHookID++
	id := e.pathDeathHookID
	if e.pathDeathHooks == nil {
		e.pathDeathHooks = make(map[uint64]func(PathDeathEvent))
	}
	e.pathDeathHooks[id] = fn
	e.pathsMu.Unlock()
	return func() {
		e.pathsMu.Lock()
		delete(e.pathDeathHooks, id)
		e.pathsMu.Unlock()
	}
}

// OnPathDeathSerial registers an internal, nonblocking lifecycle subscriber
// that is invoked in topology-commit order before the departure operation
// returns. It is reserved for state-machine queues such as recovery; callbacks
// must only enqueue bounded immutable work.
func (e *Engine) OnPathDeathSerial(fn func(PathDeathEvent)) (cancel func()) {
	if fn == nil {
		return func() {}
	}
	e.pathsMu.Lock()
	e.pathDeathHookID++
	id := e.pathDeathHookID
	if e.pathDeathSerialHooks == nil {
		e.pathDeathSerialHooks = make(map[uint64]func(PathDeathEvent))
	}
	e.pathDeathSerialHooks[id] = fn
	e.pathsMu.Unlock()
	return func() {
		e.pathsMu.Lock()
		delete(e.pathDeathSerialHooks, id)
		e.pathsMu.Unlock()
	}
}

func (e *Engine) firePathDeathHooks(event PathDeathEvent) {
	e.pathsMu.RLock()
	hooks := make([]func(PathDeathEvent), 0, len(e.pathDeathHooks))
	for _, hook := range e.pathDeathHooks {
		hooks = append(hooks, hook)
	}
	serialHooks := make([]func(PathDeathEvent), 0, len(e.pathDeathSerialHooks))
	for _, hook := range e.pathDeathSerialHooks {
		serialHooks = append(serialHooks, hook)
	}
	e.pathsMu.RUnlock()
	for _, hook := range serialHooks {
		snapshot := event
		snapshot.Spec = event.Spec.Clone()
		hook(snapshot)
	}
	for _, hook := range hooks {
		snapshot := event
		snapshot.Spec = event.Spec.Clone()
		go hook(snapshot)
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
	e.closeOnce.Do(func() {
		var firstErr error
		recordErr := func(err error) {
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		e.closing.Store(true)
		e.setState(BridgeClosing)
		e.pathsMu.Lock()
		slots := make([]*pathSlot, 0, len(e.paths)+len(e.pendingPaths)+len(e.stagedPaths)+len(e.retainedPaths))
		for _, s := range e.paths {
			s.closeQuit()
			slots = append(slots, s)
		}
		for _, s := range e.pendingPaths {
			s.closeQuit()
			slots = append(slots, s)
		}
		for _, s := range e.stagedPaths {
			s.closeQuit()
			slots = append(slots, s)
		}
		for _, s := range e.retainedPaths {
			s.closeQuit()
			slots = append(slots, s)
		}
		e.paths = make(map[uint32]*pathSlot)
		e.pendingPaths = make(map[uint32]*pathSlot)
		e.stagedPaths = make(map[uint32]*pathSlot)
		e.retainedPaths = make(map[uint32]*pathSlot)
		e.pathPredecessors = make(map[uint32][]uint32)
		e.pathAdmissionByLeaf = make(map[pathAdmissionLeafKey]pathAdmissionReservation)
		e.pathAdmissionByPath = make(map[uint32]pathAdmissionLeafKey)
		e.completedPathAdmissions = make(map[proto.PathAdmissionBinding]*completedPathAdmission)
		e.pathLeafGeneration = make(map[pathAdmissionLeafKey]uint64)
		e.activeID = 0
		e.dispatchScope = nil
		e.pathsMu.Unlock()
		close(e.closed)
		// Wake any Read goroutine waiting on data.
		e.recvMu.Lock()
		e.recvCond.Broadcast()
		e.recvMu.Unlock()
		results := make(chan error, len(slots))
		for _, s := range slots {
			go func(slot *pathSlot) { results <- slot.conn.Close() }(s)
		}
		reaped := make(chan error, 1)
		go func() {
			var reapErr error
			for range slots {
				if err := <-results; err != nil && reapErr == nil {
					reapErr = err
				}
			}
			for _, slot := range slots {
				if slot.readerStarted.Load() {
					<-slot.doneR
				}
				if slot.writerStarted.Load() {
					<-slot.doneW
				}
				if slot.proberStarted.Load() {
					<-slot.doneP
				}
				slot.ackWG.Wait()
			}
			e.coreWG.Wait()
			e.selectorMu.Lock()
			selector := e.selector
			e.selectorMu.Unlock()
			if selector != nil {
				<-selector.done
			}
			e.setState(BridgeDead)
			close(e.quiesced)
			reaped <- reapErr
		}()
		timer := time.NewTimer(pathCloseTimeout)
		defer timer.Stop()
		select {
		case err := <-reaped:
			recordErr(err)
		case <-timer.C:
			recordErr(fmt.Errorf("engine: shutdown did not quiesce after %s", pathCloseTimeout))
		}
		e.closeResult = firstErr
	})
	return e.closeResult
}

func (e *Engine) requestClose() {
	go e.Close()
}

// CloseErr returns the recorded close cause once the engine is dead;
// returns nil while still alive or on a clean close.
func (e *Engine) CloseErr() error {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	return e.closeErr
}

// Closed returns a channel that is closed only after engine-owned path and
// core loops have actually quiesced. Close itself may return a timeout first;
// the asynchronous reaper keeps ownership until this channel closes.
func (e *Engine) Closed() <-chan struct{} { return e.quiesced }

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
	timer := time.NewTimer(e.limits.MigrationBudget)
	defer timer.Stop()

	for {
		e.pathsMu.RLock()
		slot := e.paths[id]
		if slot == nil {
			e.pathsMu.RUnlock()
			return fmt.Errorf("engine: remove unknown path %d", id)
		}
		owner := slot.owner
		admissionDone := slot.admissionDone
		e.pathsMu.RUnlock()

		slot.removeWaiters.Add(1)
		select {
		case <-admissionDone:
		case <-e.closed:
			slot.removeWaiters.Add(-1)
			if err := e.CloseErr(); err != nil {
				return err
			}
			return net.ErrClosed
		case <-timer.C:
			slot.removeWaiters.Add(-1)
			return fmt.Errorf("engine: path %d admission did not complete within migration budget", id)
		}

		// Native repair uses the same outer lock order. Whichever operation
		// acquires sendMu first commits; the loser revalidates the physical owner
		// and can never resurrect or remove a stale generation.
		e.sendMu.Lock()
		slot.removeWaiters.Add(-1)
		runtime := e.localExecutionRuntime()
		e.pathsMu.Lock()
		current := e.paths[id]
		if current != slot || current.owner != owner {
			e.pathsMu.Unlock()
			e.sendMu.Unlock()
			continue
		}
		if current.maintenance.Load() {
			e.pathsMu.Unlock()
			e.sendMu.Unlock()
			return ErrPathAttachInProgress
		}
		if len(e.paths) <= 1 {
			e.pathsMu.Unlock()
			e.sendMu.Unlock()
			return ErrLastPath
		}
		departure := e.detachPathLocked(current, runtime, transport.CauseCleanClose, nil, true)
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		e.finishPathDeparture(departure)
		return nil
	}
}

// PathRef returns the current physical generation for id.
func (e *Engine) PathRef(id uint32) (PathRef, bool) {
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	if slot == nil {
		return PathRef{}, false
	}
	return PathRef{ID: id, Owner: slot.owner}, true
}

// RetirePath removes one exact stale physical generation as an administrative
// cleanup. Unlike RemovePath it may retire the last path; the engine then
// enters its migration budget instead of manufacturing EOF. Lifecycle
// subscribers see a clean administrative departure and must not redial it.
func (e *Engine) RetirePath(ref PathRef, reason error) error {
	if ref.ID == 0 || ref.Owner == 0 {
		return fmt.Errorf("engine: invalid stale path reference")
	}
	e.sendMu.Lock()
	runtime := e.localExecutionRuntime()
	e.pathsMu.Lock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner {
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		return fmt.Errorf("engine: stale path generation is unavailable")
	}
	departure := e.detachPathLocked(slot, runtime, transport.CauseCleanClose, reason, true)
	e.pathsMu.Unlock()
	e.sendMu.Unlock()
	e.finishPathDeparture(departure)
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
	e.onPathDeath(id, slot.owner, transport.CauseTransportError, err)
	return err
}

// AbortPathAttach rolls back a path that was locally attached but whose
// handshake acknowledgement could not be delivered. The generation check in
// onPathDeath makes this safe against a concurrent transport callback.
func (e *Engine) AbortPathAttach(id uint32, cause error) {
	e.pathsMu.Lock()
	pending := e.pendingPaths[id]
	if pending != nil {
		delete(e.pendingPaths, id)
	}
	staged := e.stagedPaths[id]
	if staged != nil {
		delete(e.stagedPaths, id)
		staged.closeQuit()
	}
	if pending != nil || staged != nil {
		e.releasePathAdmissionLocked(id)
	}
	slot := e.paths[id]
	e.pathsMu.Unlock()
	if pending != nil {
		_ = pending.conn.Close()
		return
	}
	if staged != nil {
		_ = staged.conn.Close()
		e.drainDeadSlot(staged)
		return
	}
	if slot != nil {
		e.onPathDeath(id, slot.owner, transport.CauseTransportError, cause)
	}
}

func (e *Engine) setCloseErr(err error) {
	e.closeMu.Lock()
	if e.closeErr == nil {
		e.closeErr = err
		if debugPathDeath {
			fmt.Printf("[rendr-engine] closeErr side=%v flow=%x err=%v\n", e.side, e.flowID, err)
		}
	}
	e.closeMu.Unlock()
}
