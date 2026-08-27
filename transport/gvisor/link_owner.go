package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

const (
	outerControlRetry       = 50 * time.Millisecond
	outerWriteBound         = time.Second
	outerPeerPendingTTL     = 90 * time.Second
	outerPredecessorDrain   = 50 * time.Millisecond
	outerRoutePollInterval  = 30 * time.Second
	outerRouteRecheck       = 250 * time.Millisecond
	outerMTURecoveryBudget  = 90 * time.Second
	outerLivenessTick       = 250 * time.Millisecond
	outerLivenessInterval   = 500 * time.Millisecond
	outerLivenessFailure    = 4 * time.Second
	outerReplayNoProgress   = 500 * time.Millisecond
	outerRefreshCallbackMax = 250 * time.Millisecond
	outerWriteRetryInterval = 20 * time.Millisecond
	outerQualificationRate  = 10 * time.Millisecond
	maxPeerReplayEntries    = 64
	maxLivenessPending      = 16
	maxPacketReplayBytes    = 32 << 20
	maxPacketReplayEntries  = 32768
	maxReplayDomainBytes    = 128 << 20
	maxReplayDomainEntries  = 131072
	maxRefreshCallbacks     = 32
	maxReceiveAheadEntries  = 8192
	dataAckEveryPackets     = 16
	duplicateDataAckTrigger = 3
	maxCurrentReplayPackets = 64
	maxReplayNoProgress     = 8
)

var (
	errPacketReplayAdmission = errors.New("gvisor: packet-link replay owner budget exhausted")
	errPacketLivenessTimeout = errors.New("gvisor: active outer packet link stopped acknowledging liveness")
	errPacketReplayStalled   = errors.New("gvisor: packet-link replay made no peer frontier progress")
	errRefreshCallbackStall  = errors.New("gvisor: packet-link mobility refresh callback stalled")
	errRefreshCallbackBudget = errors.New("gvisor: packet-link mobility refresh callback budget exhausted")
	errRefreshQueueFull      = errors.New("gvisor: packet-link mobility refresh queue exhausted")
)

type packetReplayBudget struct {
	mu sync.Mutex

	maxOwners  int
	maxBytes   int
	maxEntries int
	owners     int
	bytes      int
	entries    int
	changed    chan struct{}
}

type packetReplayLease struct {
	budget  *packetReplayBudget
	closed  bool
	bytes   int
	entries int
}

type packetReplayBudgetSnapshot struct {
	Owners     int
	Bytes      int
	Entries    int
	MaxOwners  int
	MaxBytes   int
	MaxEntries int
}

func newPacketReplayBudget(maxOwners, maxBytes, maxEntries int) *packetReplayBudget {
	if maxOwners <= 0 {
		maxOwners = 1
	}
	if maxBytes <= 0 {
		maxBytes = maxPacketReplayBytes
	}
	if maxEntries <= 0 {
		maxEntries = maxPacketReplayEntries
	}
	return &packetReplayBudget{
		maxOwners: maxOwners, maxBytes: maxBytes, maxEntries: maxEntries, changed: make(chan struct{}),
	}
}

func newDefaultPacketReplayBudget() *packetReplayBudget {
	return newPacketReplayBudget(maxPacketLinks, maxReplayDomainBytes, maxReplayDomainEntries)
}

func (budget *packetReplayBudget) acquire() (*packetReplayLease, error) {
	if budget == nil {
		return nil, errors.New("gvisor: packet-link replay budget is unavailable")
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.owners >= budget.maxOwners {
		return nil, errPacketReplayAdmission
	}
	budget.owners++
	return &packetReplayLease{budget: budget}, nil
}

func (lease *packetReplayLease) reserve(bytes, entries int) (bool, <-chan struct{}) {
	if lease == nil || lease.budget == nil || bytes < 0 || entries <= 0 {
		return false, nil
	}
	budget := lease.budget
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if lease.closed {
		return false, budget.changed
	}
	if budget.bytes+bytes > budget.maxBytes || budget.entries+entries > budget.maxEntries {
		return false, budget.changed
	}
	budget.bytes += bytes
	budget.entries += entries
	lease.bytes += bytes
	lease.entries += entries
	return true, nil
}

func (lease *packetReplayLease) release(bytes, entries int) {
	if lease == nil || lease.budget == nil || bytes < 0 || entries <= 0 {
		return
	}
	budget := lease.budget
	budget.mu.Lock()
	if lease.closed {
		budget.mu.Unlock()
		return
	}
	if bytes > lease.bytes {
		bytes = lease.bytes
	}
	if entries > lease.entries {
		entries = lease.entries
	}
	lease.bytes -= bytes
	lease.entries -= entries
	budget.bytes -= bytes
	budget.entries -= entries
	budget.signalChangedLocked()
	budget.mu.Unlock()
}

func (lease *packetReplayLease) close() {
	if lease == nil || lease.budget == nil {
		return
	}
	budget := lease.budget
	budget.mu.Lock()
	if !lease.closed {
		lease.closed = true
		budget.bytes -= lease.bytes
		budget.entries -= lease.entries
		budget.owners--
		lease.bytes = 0
		lease.entries = 0
		budget.signalChangedLocked()
	}
	budget.mu.Unlock()
}

func (budget *packetReplayBudget) signalChangedLocked() {
	close(budget.changed)
	budget.changed = make(chan struct{})
}

func (budget *packetReplayBudget) snapshot() packetReplayBudgetSnapshot {
	if budget == nil {
		return packetReplayBudgetSnapshot{}
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return packetReplayBudgetSnapshot{
		Owners: budget.owners, Bytes: budget.bytes, Entries: budget.entries,
		MaxOwners: budget.maxOwners, MaxBytes: budget.maxBytes, MaxEntries: budget.maxEntries,
	}
}

type refreshCallbackBudget struct {
	permits  chan struct{}
	mu       sync.Mutex
	active   int
	rejected uint64
}

type refreshCallbackBudgetSnapshot struct {
	Active   int
	Limit    int
	Rejected uint64
}

var processRefreshCallbackBudget = newRefreshCallbackBudget(maxRefreshCallbacks)

func newRefreshCallbackBudget(limit int) *refreshCallbackBudget {
	if limit <= 0 {
		limit = 1
	}
	return &refreshCallbackBudget{permits: make(chan struct{}, limit)}
}

func (budget *refreshCallbackBudget) acquire() (func(), bool) {
	if budget == nil {
		return nil, false
	}
	select {
	case budget.permits <- struct{}{}:
		budget.mu.Lock()
		budget.active++
		budget.mu.Unlock()
		var once sync.Once
		return func() {
			once.Do(func() {
				<-budget.permits
				budget.mu.Lock()
				budget.active--
				budget.mu.Unlock()
			})
		}, true
	default:
		budget.mu.Lock()
		budget.rejected++
		budget.mu.Unlock()
		return nil, false
	}
}

func (budget *refreshCallbackBudget) snapshot() refreshCallbackBudgetSnapshot {
	if budget == nil {
		return refreshCallbackBudgetSnapshot{}
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return refreshCallbackBudgetSnapshot{Active: budget.active, Limit: cap(budget.permits), Rejected: budget.rejected}
}

type packetWire struct {
	conn      net.PacketConn
	shared    bool
	socket    outerSocketContext
	socketErr error
	bindMode  outerUDPMode
	bindLocal *net.UDPAddr
	bindKnown bool
	writeMu   sync.RWMutex
	writer    packetWriter
	writeGate chan struct{}

	closeOnce sync.Once
	readOnce  sync.Once
	receiving atomic.Bool
	done      chan struct{}

	errMu sync.RWMutex
	err   error

	socketReleaseOnce sync.Once
}

type packetWriter interface {
	WriteTo([]byte, net.Addr) (int, error)
	SetWriteDeadline(time.Time) error
}

func newPacketWire(conn net.PacketConn, shared bool) *packetWire {
	socket, socketErr := platformCaptureOuterSocketContext(conn)
	return newPacketWireWithSocketContextError(conn, shared, socket, socketErr)
}

func newPacketWireWithSocketContext(
	conn net.PacketConn,
	shared bool,
	socket outerSocketContext,
) *packetWire {
	return newPacketWireWithSocketContextError(conn, shared, socket, nil)
}

func newPacketWireWithSocketContextError(
	conn net.PacketConn,
	shared bool,
	socket outerSocketContext,
	socketErr error,
) *packetWire {
	return &packetWire{
		conn: conn, shared: shared, writer: conn, writeGate: make(chan struct{}, 1), done: make(chan struct{}),
		socket: socket, socketErr: socketErr,
	}
}

func (wire *packetWire) releaseSocketContext() {
	if wire == nil {
		return
	}
	wire.socketReleaseOnce.Do(func() { platformReleaseOuterSocketContext(&wire.socket) })
}

func (wire *packetWire) writeTo(ctx context.Context, payload []byte, remote net.Addr) (int, error) {
	if wire == nil {
		return 0, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case wire.writeGate <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-wire.writeGate }()
	wire.writeMu.RLock()
	writer := wire.writer
	wire.writeMu.RUnlock()
	if writer == nil {
		return 0, net.ErrClosed
	}
	deadline := time.Now().Add(outerWriteBound)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := writer.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	var stopWatch chan struct{}
	var watchDone chan struct{}
	if ctx.Done() != nil {
		stopWatch = make(chan struct{})
		watchDone = make(chan struct{})
		go func() {
			defer close(watchDone)
			select {
			case <-ctx.Done():
				_ = writer.SetWriteDeadline(time.Now())
			case <-stopWatch:
			}
		}()
	}
	n, writeErr := writer.WriteTo(payload, remote)
	if stopWatch != nil {
		close(stopWatch)
		<-watchDone
	}
	clearErr := writer.SetWriteDeadline(time.Time{})
	if writeErr == nil && clearErr != nil {
		writeErr = clearErr
	}
	writeErr = classifyOuterMTUError(len(payload), writeErr)
	if writeErr != nil && ctx.Err() != nil && n == 0 && !errors.Is(writeErr, ErrOuterMTU) {
		writeErr = ctx.Err()
	}
	return n, writeErr
}

func (wire *packetWire) replaceWriter(writer packetWriter) error {
	if wire == nil || writer == nil {
		return errors.New("gvisor: invalid packet-link writer")
	}
	wire.writeMu.Lock()
	wire.writer = writer
	wire.writeMu.Unlock()
	return nil
}

func (wire *packetWire) close() {
	if wire == nil {
		return
	}
	wire.closeOnce.Do(func() {
		wire.writeMu.RLock()
		writer := wire.writer
		wire.writeMu.RUnlock()
		if writer != nil {
			_ = writer.SetWriteDeadline(time.Now())
		}
		if wire.conn != nil {
			_ = wire.conn.Close()
		}
		wire.releaseSocketContext()
	})
}

func (wire *packetWire) setError(err error) {
	if wire == nil || err == nil {
		return
	}
	wire.errMu.Lock()
	if wire.err == nil {
		wire.err = err
	}
	wire.errMu.Unlock()
}

func (wire *packetWire) error() error {
	if wire == nil {
		return net.ErrClosed
	}
	wire.errMu.RLock()
	err := wire.err
	wire.errMu.RUnlock()
	return err
}

type peerCandidate struct {
	generation         uint64
	control            outerControl
	qualificationRound uint32
	wire               *packetWire
	remote             net.Addr
	route              routeObservation
	qualified          bool
	expires            time.Time
}

type committedPeer struct {
	generation uint64
	control    outerControl
	remote     net.Addr
}

type peerQualification struct {
	purpose       outerQualificationPurpose
	generation    uint64
	qualification outerQualification
	wire          *packetWire
	remote        net.Addr
	route         routeObservation
	confirmed     bool
	confirming    bool
	expires       time.Time
}

type localRefreshCommit struct {
	wire            *packetWire
	localGeneration uint64
	peerGeneration  uint64
	control         outerControl
	remote          net.Addr
	route           routeObservation
}

type controlKey struct {
	typ        outerType
	generation uint64
	control    outerControl
}

type peerReplayKey struct {
	generation uint64
	control    outerControl
	remote     string
}

type controlEvent struct {
	remote net.Addr
	wire   *packetWire
}

type qualificationWaiterKey struct {
	typ            outerType
	generation     uint64
	purpose        outerQualificationPurpose
	round          uint32
	initiatorNonce linkNonce
	context        [outerQualificationContextSize]byte
	binding        linkAgreement
}

type qualificationEvent struct {
	qualification outerQualification
	remote        net.Addr
	wire          *packetWire
}

type peerQualificationFloor struct {
	purpose    outerQualificationPurpose
	generation uint64
	round      uint32
}

type livenessProbe struct {
	generation uint64
	sent       time.Time
}

type packetReplay struct {
	sequence uint64
	packet   []byte
}

type outerMTURecoveryEpisode struct {
	deadline      time.Time
	cause         error
	datagramBytes int
	frameworkSet  bool
	expired       bool
	timer         *time.Timer
}

type outerRouteObserver func(context.Context, *packetWire, net.Addr) (routeObservation, error)

type linkOwner struct {
	id                 linkID
	secret             linkSecret
	admissionClientKey linkPublicKey
	admissionNonce     linkNonce
	admissionAck       []byte
	admissionQualified bool
	role               leafmobility.Role
	virtualIP          [4]byte
	listener           *Listener
	inject             func([]byte)

	sendMu sync.Mutex
	mu     sync.Mutex

	incarnation            uint64
	localGeneration        uint64
	peerGeneration         uint64
	active                 *packetWire
	predecessor            *packetWire
	predecessorUntil       time.Time
	peerRemote             net.Addr
	previousRemote         net.Addr
	previousPeerGen        uint64
	previousPeerUntil      time.Time
	activationPending      bool
	maintenance            bool
	closed                 bool
	closing                bool
	change                 chan struct{}
	done                   chan struct{}
	wires                  map[*packetWire]struct{}
	waiters                map[controlKey]chan controlEvent
	qualificationWaiters   map[qualificationWaiterKey]chan qualificationEvent
	qualificationSequence  atomic.Uint64
	outbound               chan []byte
	outboundOnce           sync.Once
	pendingPeer            *peerCandidate
	peerQualification      *peerQualification
	peerQualificationFloor peerQualificationFloor
	qualificationRequestAt time.Time
	qualificationConfirmAt time.Time
	peerReplay             map[peerReplayKey]struct{}
	committedPeer          *committedPeer
	livenessPending        map[linkNonce]livenessProbe
	livenessLastAck        time.Time
	livenessLastProbe      time.Time
	replayPackets          []packetReplay
	replayBytes            int
	replaySequence         uint64
	replayActivations      uint64
	replayTransmitted      uint64
	replayTXBytes          uint64
	replayLimit            int
	replayEntryLimit       int
	replayLease            *packetReplayLease
	replayRequestGen       uint64
	replayRequestPeer      uint64
	replayRequestNext      uint64
	replayRequestAt        time.Time
	replayRequestRuns      uint8
	replayExhausted        bool
	receiveNext            uint64
	receiveAhead           map[uint64]struct{}
	receiveSinceAck        uint32
	peerReceiveNext        uint64
	duplicateDataAcks      uint8
	dataAckWake            chan struct{}
	dataReplayWake         chan struct{}
	endpoint               net.Conn
	cleanup                func()
	cleanupOnce            sync.Once
	admissionTimer         *time.Timer
	wireFault              bool
	wireFaultReason        leafmobility.RefreshReason
	mtuRecovery            *outerMTURecoveryEpisode
	mtuRecoveryBudget      time.Duration
	terminalErr            error

	claim               *leafmobility.Claim
	refreshState        *leafmobility.RefreshSourceState
	refreshEmitter      *leafmobility.RefreshEmitter
	refreshStateMu      sync.Mutex
	refreshMu           sync.Mutex
	refreshCancel       context.CancelFunc
	refreshDone         chan struct{}
	refreshDispatchDone chan struct{}
	refreshFn           func(leafmobility.RefreshEvidence)
	refreshEvents       chan leafmobility.RefreshEvidence
	refreshEpoch        uint64
	routeBaseline       [sha256.Size]byte
	refreshSent         [sha256.Size]byte
	refreshCircuit      bool
	refreshTrips        uint64
	refreshCallbacks    *refreshCallbackBudget
	refreshCallbackLive bool
	refreshCallbackGen  uint64
	pendingRefresh      *localRefreshCommit

	// Initialized before publication; runtime reads and writes must hold mu.
	openCandidate func(context.Context, net.Addr) (*packetWire, routeObservation, error)
	openWire      func(outerUDPMode, *net.UDPAddr, bool) (*packetWire, error)
	observeRoute  outerRouteObserver
	lifetimeCtx   context.Context
	lifetimeStop  context.CancelFunc
}

func newLinkOwner(
	id linkID,
	secret linkSecret,
	role leafmobility.Role,
	virtualIP [4]byte,
	active *packetWire,
	remote net.Addr,
	listener *Listener,
	inject func([]byte),
) (*linkOwner, error) {
	return newLinkOwnerWithReplayBudget(
		id, secret, role, virtualIP, active, remote, listener, inject,
		newPacketReplayBudget(1, maxPacketReplayBytes, maxPacketReplayEntries),
	)
}

func newLinkOwnerWithReplayBudget(
	id linkID,
	secret linkSecret,
	role leafmobility.Role,
	virtualIP [4]byte,
	active *packetWire,
	remote net.Addr,
	listener *Listener,
	inject func([]byte),
	replayBudget *packetReplayBudget,
) (*linkOwner, error) {
	if id == (linkID{}) || secret == (linkSecret{}) || virtualIP == ([4]byte{}) ||
		active == nil || active.conn == nil || remote == nil || inject == nil {
		return nil, errors.New("gvisor: invalid logical packet link owner")
	}
	replayLease, err := replayBudget.acquire()
	if err != nil {
		return nil, err
	}
	lifetimeCtx, lifetimeStop := context.WithCancel(context.Background())
	owner := &linkOwner{
		id: id, secret: secret, role: role, virtualIP: virtualIP,
		listener: listener, inject: inject, active: active, peerRemote: cloneAddr(remote),
		incarnation: 1, localGeneration: 1, peerGeneration: 1,
		admissionQualified: true,
		change:             make(chan struct{}), done: make(chan struct{}),
		wires: make(map[*packetWire]struct{}), waiters: make(map[controlKey]chan controlEvent),
		qualificationWaiters: make(map[qualificationWaiterKey]chan qualificationEvent),
		peerReplay:           make(map[peerReplayKey]struct{}),
		livenessPending:      make(map[linkNonce]livenessProbe), livenessLastAck: time.Now(),
		replayLimit: maxPacketReplayBytes, replayEntryLimit: maxPacketReplayEntries, replayLease: replayLease,
		receiveNext: 1, receiveAhead: make(map[uint64]struct{}),
		peerReceiveNext: 1,
		outbound:        make(chan []byte, packetOutboundQueued), dataAckWake: make(chan struct{}, 1),
		dataReplayWake:    make(chan struct{}, 1),
		refreshCallbacks:  processRefreshCallbackBudget,
		mtuRecoveryBudget: outerMTURecoveryBudget,
		lifetimeCtx:       lifetimeCtx, lifetimeStop: lifetimeStop,
	}
	owner.wires[active] = struct{}{}
	owner.openCandidate = owner.openUDPCandidate
	owner.observeRoute = observeUDPRouteForWire
	return owner, nil
}

func (owner *linkOwner) startOutbound() {
	if owner == nil {
		return
	}
	owner.outboundOnce.Do(func() {
		go func() {
			for {
				select {
				case packet := <-owner.outbound:
					if err := owner.sendPacket(packet); err != nil {
						if !errors.Is(err, net.ErrClosed) {
							owner.failClosed(err)
						}
						return
					}
				case <-owner.done:
					return
				}
			}
		}()
		go owner.dataAckLoop()
		go owner.dataReplayLoop()
		go owner.livenessLoop()
	})
}

func (owner *linkOwner) enqueuePacket(packet []byte) error {
	if owner == nil || len(packet) == 0 || len(packet) > packetMTU {
		return errors.New("gvisor: invalid packet-link outbound packet")
	}
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case owner.outbound <- copyOfPacket:
		return nil
	case <-owner.done:
		return net.ErrClosed
	}
}

func (owner *linkOwner) enqueueSharedPacket(packet []byte) bool {
	if owner == nil || len(packet) == 0 || len(packet) > packetMTU {
		return false
	}
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case owner.outbound <- copyOfPacket:
		return true
	case <-owner.done:
		return false
	default:
		// A shared NIC must keep demultiplexing sibling endpoints. Dropping one
		// inner packet here is ordinary link loss; the owning gVisor TCP
		// endpoint retains and retransmits the application bytes.
		return false
	}
}

func (owner *linkOwner) attachClaim(claim *leafmobility.Claim) error {
	if owner == nil || claim == nil {
		return errors.New("gvisor: cannot attach nil mobility claim")
	}
	state := leafmobility.NewRefreshSourceState()
	emitter, err := leafmobility.NewRefreshEmitterWithSourceState(claim, state)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	if owner.closed || owner.closing {
		owner.mu.Unlock()
		return net.ErrClosed
	}
	if owner.claim != nil {
		owner.mu.Unlock()
		return errors.New("gvisor: mobility claim already attached")
	}
	owner.claim = claim
	owner.refreshState = state
	owner.refreshEmitter = emitter
	owner.mu.Unlock()
	return nil
}

func (owner *linkOwner) LeafMobilityIncarnation() uint64 {
	if owner == nil {
		return 0
	}
	owner.mu.Lock()
	incarnation := owner.incarnation
	if owner.closed {
		incarnation = 0
	}
	owner.mu.Unlock()
	return incarnation
}

func (owner *linkOwner) bindEndpoint(endpoint net.Conn, cleanup func()) error {
	if owner == nil || endpoint == nil {
		return errors.New("gvisor: cannot bind nil endpoint")
	}
	if cleanup == nil {
		cleanup = func() {}
	}
	owner.mu.Lock()
	if owner.closed || owner.closing {
		owner.mu.Unlock()
		return net.ErrClosed
	}
	if owner.endpoint != nil {
		owner.mu.Unlock()
		return errors.New("gvisor: logical packet link already owns an endpoint")
	}
	if !owner.admissionQualified {
		owner.mu.Unlock()
		return errors.New("gvisor: packet-link admission is not maximum-DATA qualified")
	}
	owner.endpoint = endpoint
	owner.cleanup = cleanup
	if owner.peerQualification != nil &&
		owner.peerQualification.purpose == outerQualificationAdmission &&
		owner.peerQualification.confirmed {
		owner.peerQualification = nil
	}
	timer := owner.admissionTimer
	owner.admissionTimer = nil
	owner.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	return nil
}

func (owner *linkOwner) armAdmissionTimeout(ttl time.Duration) {
	if owner == nil || ttl <= 0 {
		return
	}
	timer := time.AfterFunc(ttl, owner.expireUnboundAdmission)
	owner.mu.Lock()
	if owner.closed || owner.closing || owner.endpoint != nil {
		owner.mu.Unlock()
		timer.Stop()
		return
	}
	previous := owner.admissionTimer
	owner.admissionTimer = timer
	owner.mu.Unlock()
	if previous != nil {
		previous.Stop()
	}
}

func (owner *linkOwner) expireUnboundAdmission() {
	owner.failClosedInternal(errors.New("gvisor: packet-link admission expired"), true)
}

func (owner *linkOwner) startReceiver(wire *packetWire) {
	if owner == nil || wire == nil || wire.shared || wire.conn == nil {
		return
	}
	wire.readOnce.Do(func() {
		wire.receiving.Store(true)
		go func() {
			defer close(wire.done)
			buf := make([]byte, outerMaxDatagramSize+1)
			for {
				n, remote, err := wire.conn.ReadFrom(buf)
				if err != nil {
					wire.setError(err)
					owner.onWireReadError(wire, err)
					return
				}
				if n > outerMaxDatagramSize {
					continue
				}
				owner.handleDatagram(wire, remote, buf[:n])
			}
		}()
	})
}

func (owner *linkOwner) onWireReadError(wire *packetWire, err error) {
	owner.mu.Lock()
	active := !owner.closed && owner.active == wire
	owner.mu.Unlock()
	if active && !errors.Is(err, net.ErrClosed) {
		if !owner.publishWireFailure(leafmobility.RefreshReasonLocalReadFailure) {
			owner.failClosed(err)
		}
	}
}

func (owner *linkOwner) sendPacket(packet []byte) error {
	if owner == nil || len(packet) == 0 || len(packet) > packetMTU || !owner.validInnerPacket(packet, true) {
		return errors.New("gvisor: invalid outbound inner packet")
	}
	var replay packetReplay
	for {
		owner.sendMu.Lock()
		owner.mu.Lock()
		if owner.closed || owner.closing {
			owner.mu.Unlock()
			owner.sendMu.Unlock()
			return net.ErrClosed
		}
		if owner.activationPending {
			changed, done := owner.change, owner.done
			owner.mu.Unlock()
			owner.sendMu.Unlock()
			select {
			case <-changed:
			case <-done:
				return net.ErrClosed
			}
			continue
		}
		if replay.sequence == 0 {
			if owner.replayLimit < len(packet) || owner.replayEntryLimit < 1 {
				owner.mu.Unlock()
				owner.sendMu.Unlock()
				return errors.New("gvisor: packet exceeds packet-link replay budget")
			}
			if owner.replayBytes+len(packet) > owner.replayLimit ||
				len(owner.replayPackets) >= owner.replayEntryLimit {
				changed, done := owner.change, owner.done
				owner.mu.Unlock()
				owner.sendMu.Unlock()
				select {
				case <-changed:
				case <-done:
					return net.ErrClosed
				}
				continue
			}
			var retained bool
			var budgetChanged <-chan struct{}
			replay, budgetChanged, retained = owner.retainReplayLocked(packet)
			if !retained {
				changed, done := owner.change, owner.done
				owner.mu.Unlock()
				owner.sendMu.Unlock()
				select {
				case <-changed:
				case <-budgetChanged:
				case <-done:
					return net.ErrClosed
				}
				continue
			}
		}
		wire := owner.active
		remote := cloneAddr(owner.peerRemote)
		generation := owner.localGeneration
		changed, done := owner.change, owner.done
		owner.mu.Unlock()
		encoded, err := encodeOuterData(
			owner.id, generation, replay.sequence, replay.packet, owner.secret, owner.role,
		)
		if err != nil {
			owner.sendMu.Unlock()
			return err
		}
		n, writeErr := wire.writeTo(owner.lifetimeCtx, encoded, remote)
		owner.sendMu.Unlock()
		if writeErr == nil && n == len(encoded) {
			if err := owner.completeOuterMTURecovery(len(encoded)); err != nil {
				return err
			}
			return nil
		}
		if n != 0 {
			ambiguous := fmt.Errorf("gvisor: ambiguous outer UDP write %d/%d: %w", n, len(encoded), writeErr)
			go owner.failClosed(ambiguous)
			return ambiguous
		}
		if writeErr == nil {
			writeErr = errors.New("gvisor: zero-byte outer UDP write")
		}
		var recovery *outerMTURecoveryEpisode
		if errors.Is(writeErr, ErrOuterMTU) {
			recovery = owner.noteOuterMTUFailure(writeErr)
		}
		faultReason := leafmobility.RefreshReasonLocalWriteFailure
		if recovery != nil {
			faultReason = leafmobility.RefreshReasonOuterMTUFailure
		}
		if !owner.publishWireFailure(faultReason) {
			go owner.failClosed(writeErr)
			return writeErr
		}
		if recovery != nil {
			if err := owner.waitForOuterRouteChange(wire, remote, generation, recovery); err != nil {
				return err
			}
			continue
		}
		timer := time.NewTimer(outerWriteRetryInterval)
		select {
		case <-changed:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		case <-done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return net.ErrClosed
		}
	}
}

func (owner *linkOwner) waitForOuterRouteChange(
	wire *packetWire,
	remote net.Addr,
	generation uint64,
	recovery *outerMTURecoveryEpisode,
) error {
	if recovery == nil {
		return errors.New("gvisor: outer MTU recovery episode is unavailable")
	}
	owner.mu.Lock()
	failedRouteDeadline := recovery.deadline
	owner.mu.Unlock()
	probeCtx, cancelProbe := owner.outerRouteProbeContext(failedRouteDeadline)
	failedRoute, failedRouteErr := owner.observeOuterRoute(probeCtx, wire, remote)
	cancelProbe()
	ticker := time.NewTicker(outerRouteRecheck)
	defer ticker.Stop()
	unknownRoutePolled := false
	for {
		owner.mu.Lock()
		if owner.closed || owner.closing {
			terminalErr := owner.terminalErr
			owner.mu.Unlock()
			if terminalErr != nil {
				return terminalErr
			}
			return net.ErrClosed
		}
		if owner.mtuRecovery != recovery {
			owner.mu.Unlock()
			return nil
		}
		currentWire := owner.active
		currentRemote := cloneAddr(owner.peerRemote)
		currentGeneration := owner.localGeneration
		deadline := recovery.deadline
		cause := recovery.cause
		changed, done := owner.change, owner.done
		owner.mu.Unlock()
		if !time.Now().Before(deadline) {
			return cause
		}
		probeCtx, cancelProbe = owner.outerRouteProbeContext(deadline)
		currentRoute, currentRouteErr := owner.observeOuterRoute(probeCtx, currentWire, currentRemote)
		cancelProbe()
		if currentRouteErr == nil && currentRoute.qualifiesMaximumData() {
			identityChanged := currentWire != wire || currentGeneration != generation ||
				!addrEqualOnWire(currentWire, currentRemote, remote)
			if failedRouteErr == nil && currentRoute.digest != failedRoute.digest ||
				failedRouteErr != nil && (identityChanged || unknownRoutePolled) {
				return nil
			}
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return cause
		}
		deadlineTimer := time.NewTimer(wait)
		select {
		case <-changed:
			if !deadlineTimer.Stop() {
				<-deadlineTimer.C
			}
		case <-ticker.C:
			unknownRoutePolled = true
			if !deadlineTimer.Stop() {
				<-deadlineTimer.C
			}
		case <-deadlineTimer.C:
			return cause
		case <-done:
			if !deadlineTimer.Stop() {
				select {
				case <-deadlineTimer.C:
				default:
				}
			}
			if terminalErr := owner.terminalError(); terminalErr != nil {
				return terminalErr
			}
			return net.ErrClosed
		case <-owner.lifetimeCtx.Done():
			if !deadlineTimer.Stop() {
				select {
				case <-deadlineTimer.C:
				default:
				}
			}
			if terminalErr := owner.terminalError(); terminalErr != nil {
				return terminalErr
			}
			return context.Cause(owner.lifetimeCtx)
		}
	}
}

func (owner *linkOwner) observeOuterRoute(
	ctx context.Context,
	wire *packetWire,
	remote net.Addr,
) (routeObservation, error) {
	if owner == nil {
		return routeObservation{}, net.ErrClosed
	}
	observer := owner.observeRoute
	if observer == nil {
		observer = observeUDPRouteForWire
	}
	return observer(ctx, wire, remote)
}

func (owner *linkOwner) outerRouteProbeContext(deadline time.Time) (context.Context, context.CancelFunc) {
	probeDeadline := time.Now().Add(outerWriteBound)
	if !deadline.IsZero() && deadline.Before(probeDeadline) {
		probeDeadline = deadline
	}
	return context.WithDeadline(owner.lifetimeCtx, probeDeadline)
}

func (owner *linkOwner) noteOuterMTUFailure(cause error) *outerMTURecoveryEpisode {
	if owner == nil || !errors.Is(cause, ErrOuterMTU) {
		return nil
	}
	datagramBytes := outerMaxDatagramSize
	var typed *OuterMTUError
	if errors.As(cause, &typed) && typed.DatagramBytes > 0 {
		datagramBytes = typed.DatagramBytes
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.closing {
		return owner.mtuRecovery
	}
	if owner.mtuRecovery != nil {
		if datagramBytes > owner.mtuRecovery.datagramBytes {
			owner.mtuRecovery.datagramBytes = datagramBytes
		}
		return owner.mtuRecovery
	}
	budget := owner.mtuRecoveryBudget
	if budget <= 0 || budget > outerMTURecoveryBudget {
		budget = outerMTURecoveryBudget
	}
	recovery := &outerMTURecoveryEpisode{
		deadline: time.Now().Add(budget), cause: cause, datagramBytes: datagramBytes,
	}
	owner.mtuRecovery = recovery
	owner.armOuterMTURecoveryLocked(recovery)
	return recovery
}

func (owner *linkOwner) bindOuterMTURecoveryDeadline(deadline time.Time) {
	if owner == nil {
		return
	}
	owner.mu.Lock()
	recovery := owner.mtuRecovery
	if recovery == nil || recovery.frameworkSet {
		owner.mu.Unlock()
		return
	}
	recovery.frameworkSet = true
	if !deadline.IsZero() && deadline.Before(recovery.deadline) {
		recovery.deadline = deadline
		owner.armOuterMTURecoveryLocked(recovery)
		owner.signalChangedLocked()
	}
	owner.mu.Unlock()
}

func (owner *linkOwner) armOuterMTURecoveryLocked(recovery *outerMTURecoveryEpisode) {
	if recovery == nil || recovery.expired {
		return
	}
	wait := time.Until(recovery.deadline)
	if wait < 0 {
		wait = 0
	}
	if recovery.timer == nil {
		recovery.timer = time.AfterFunc(wait, func() { owner.expireOuterMTURecovery(recovery) })
		return
	}
	recovery.timer.Stop()
	recovery.timer.Reset(wait)
}

func (owner *linkOwner) expireOuterMTURecovery(recovery *outerMTURecoveryEpisode) {
	owner.mu.Lock()
	if owner.mtuRecovery != recovery || recovery == nil || recovery.expired || owner.closed || owner.closing {
		owner.mu.Unlock()
		return
	}
	if wait := time.Until(recovery.deadline); wait > 0 {
		recovery.timer.Reset(wait)
		owner.mu.Unlock()
		return
	}
	recovery.expired = true
	cause := recovery.cause
	owner.mu.Unlock()
	owner.failClosed(cause)
}

func (owner *linkOwner) completeOuterMTURecovery(datagramBytes int) error {
	if owner == nil {
		return net.ErrClosed
	}
	owner.mu.Lock()
	recovery := owner.mtuRecovery
	if recovery == nil || datagramBytes < recovery.datagramBytes {
		owner.mu.Unlock()
		return nil
	}
	if recovery.expired || !time.Now().Before(recovery.deadline) {
		recovery.expired = true
		cause := recovery.cause
		owner.mu.Unlock()
		owner.failClosed(cause)
		return cause
	}
	owner.mtuRecovery = nil
	timer := recovery.timer
	recovery.timer = nil
	owner.signalChangedLocked()
	owner.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	return nil
}

func (owner *linkOwner) terminalError() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	err := owner.terminalErr
	owner.mu.Unlock()
	return err
}

func (owner *linkOwner) noteActiveOuterMTUFailure(wire *packetWire, cause error) {
	if owner == nil || wire == nil || !errors.Is(cause, ErrOuterMTU) {
		return
	}
	owner.mu.Lock()
	active := !owner.closed && !owner.closing && owner.active == wire
	owner.mu.Unlock()
	if active {
		owner.noteOuterMTUFailure(cause)
	}
}

func (owner *linkOwner) handleDatagram(wire *packetWire, remote net.Addr, datagram []byte) {
	header, err := decodeOuterHeader(datagram)
	if err != nil || header.LinkID != owner.id {
		return
	}
	frame, err := decodeOuter(datagram, owner.secret, peerOuterRole(owner.role))
	if err != nil {
		return
	}
	switch frame.Type {
	case outerTypeData:
		owner.handleData(wire, remote, frame)
	case outerTypePathChallenge:
		owner.handlePathChallenge(wire, remote, frame)
	case outerTypePathCommit:
		owner.handlePathCommit(wire, remote, frame)
	case outerTypePathAbort:
		owner.handlePathAbort(wire, remote, frame)
	case outerTypePathResponse, outerTypePathCommitAck, outerTypePathAbortAck:
		owner.deliverControl(wire, remote, frame)
	case outerTypeLivenessChallenge:
		owner.handleLivenessChallenge(wire, remote, frame)
	case outerTypeLivenessAck:
		owner.handleLivenessAck(wire, remote, frame)
	case outerTypeDataAck:
		owner.handleDataAck(wire, remote, frame)
	case outerTypeQualificationRequest, outerTypeQualificationConfirm:
		owner.handleMaximumDataQualification(wire, remote, frame)
	case outerTypeQualificationResponse, outerTypeQualificationDone:
		owner.deliverMaximumDataQualification(wire, remote, frame)
	}
}

func (owner *linkOwner) handleData(wire *packetWire, remote net.Addr, frame outerFrame) {
	data, err := parseOuterData(frame.Payload)
	if err != nil {
		return
	}
	now := time.Now()
	owner.mu.Lock()
	wireAllowed := owner.wireAllowedLocked(wire, now)
	peerAllowed := frame.Generation == owner.peerGeneration && addrEqualOnWire(wire, remote, owner.peerRemote)
	if !peerAllowed && frame.Generation == owner.previousPeerGen && now.Before(owner.previousPeerUntil) {
		peerAllowed = addrEqualOnWire(wire, remote, owner.previousRemote)
	}
	closed := owner.closed || owner.closing
	accept, acknowledge := false, false
	if !closed && owner.admissionQualified && wireAllowed && peerAllowed && owner.validInnerPacket(data.Packet, false) {
		accept, acknowledge = owner.recordReceiveSequenceLocked(data.Sequence)
	}
	owner.mu.Unlock()
	if accept {
		owner.inject(data.Packet)
	}
	if acknowledge {
		owner.queueDataAck()
	}
}

func (owner *linkOwner) handleDataAck(wire *packetWire, remote net.Addr, frame outerFrame) {
	receiveNext, err := parseOuterDataAck(frame.Payload)
	if err != nil {
		return
	}
	now := time.Now()
	owner.mu.Lock()
	replayNeeded := false
	replayExhausted := false
	if !owner.closed && !owner.closing && owner.wireAllowedLocked(wire, now) &&
		frame.Generation == owner.peerGeneration && addrEqualOnWire(wire, remote, owner.peerRemote) {
		valid, progressed := owner.observePeerReceiveNextLocked(receiveNext)
		switch {
		case !valid:
		case progressed:
		case receiveNext == owner.peerReceiveNext && len(owner.replayPackets) != 0:
			if owner.duplicateDataAcks < duplicateDataAckTrigger {
				owner.duplicateDataAcks++
			}
			if owner.duplicateDataAcks >= duplicateDataAckTrigger {
				replayNeeded, replayExhausted = owner.scheduleCurrentReplayLocked(now)
			}
		}
	}
	owner.mu.Unlock()
	if replayExhausted {
		owner.failReplayStall()
		return
	}
	if replayNeeded {
		owner.queueDataReplay()
	}
}

func (owner *linkOwner) handleMaximumDataQualification(
	wire *packetWire,
	remote net.Addr,
	frame outerFrame,
) {
	qualification, err := parseOuterQualification(frame.Type, frame.Payload)
	if err != nil {
		return
	}
	if !owner.allowMaximumDataQualificationFrame(frame.Type) {
		return
	}
	probeCtx, cancel := context.WithTimeout(owner.lifetimeCtx, outerWriteBound)
	observation, observeErr := owner.observeOuterRoute(probeCtx, wire, remote)
	cancel()
	if observeErr != nil || observation.maximumDataError() != nil {
		return
	}
	switch frame.Type {
	case outerTypeQualificationRequest:
		response, accepted := owner.acceptMaximumDataQualificationRequest(
			wire, remote, frame.Generation, qualification, observation,
		)
		if accepted {
			_ = owner.sendMaximumDataQualification(
				owner.lifetimeCtx, wire, remote, outerTypeQualificationResponse, frame.Generation, response,
			)
		}
	case outerTypeQualificationConfirm:
		done, confirmation, accepted := owner.confirmMaximumDataQualification(
			wire, remote, frame.Generation, qualification, observation,
		)
		if !accepted {
			return
		}
		if err := owner.sendMaximumDataQualification(
			owner.lifetimeCtx, wire, remote, outerTypeQualificationDone, frame.Generation, done,
		); err != nil {
			owner.finishMaximumDataQualification(confirmation, false)
			return
		}
		if owner.finishMaximumDataQualification(confirmation, true) {
			owner.startOutbound()
		}
	}
}

func maximumDataQualificationWaiterKey(
	typ outerType,
	generation uint64,
	qualification outerQualification,
) qualificationWaiterKey {
	return qualificationWaiterKey{
		typ: typ, generation: generation, purpose: qualification.Purpose,
		round: qualification.Round, initiatorNonce: qualification.InitiatorNonce, context: qualification.Context,
		binding: qualification.Binding,
	}
}

func (owner *linkOwner) deliverMaximumDataQualification(
	wire *packetWire,
	remote net.Addr,
	frame outerFrame,
) {
	qualification, err := parseOuterQualification(frame.Type, frame.Payload)
	if err != nil {
		return
	}
	key := maximumDataQualificationWaiterKey(frame.Type, frame.Generation, qualification)
	owner.mu.Lock()
	waiter := owner.qualificationWaiters[key]
	owner.mu.Unlock()
	if waiter != nil {
		select {
		case waiter <- qualificationEvent{
			qualification: qualification, remote: cloneAddr(remote), wire: wire,
		}:
		default:
		}
	}
}

func (owner *linkOwner) allowMaximumDataQualificationFrame(typ outerType) bool {
	now := time.Now()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.closing {
		return false
	}
	var previous *time.Time
	switch typ {
	case outerTypeQualificationRequest:
		previous = &owner.qualificationRequestAt
	case outerTypeQualificationConfirm:
		previous = &owner.qualificationConfirmAt
	default:
		return false
	}
	if !previous.IsZero() && now.Sub(*previous) < outerQualificationRate {
		return false
	}
	*previous = now
	return true
}

func (owner *linkOwner) acceptMaximumDataQualificationRequest(
	wire *packetWire,
	remote net.Addr,
	generation uint64,
	qualification outerQualification,
	observation routeObservation,
) (outerQualification, bool) {
	if owner == nil || wire == nil || remote == nil || generation == 0 {
		return outerQualification{}, false
	}
	expectedBinding := computeOuterQualificationBinding(
		owner.secret, owner.id, generation, qualification.Purpose,
		qualification.Round, qualification.InitiatorNonce, qualification.Context,
	)
	if qualification.Binding != expectedBinding {
		return outerQualification{}, false
	}
	now := time.Now()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.closing || !owner.wireAllowedLocked(wire, now) {
		return outerQualification{}, false
	}
	var control outerControl
	switch qualification.Purpose {
	case outerQualificationAdmission:
		context, err := qualificationAdmissionContext(owner.admissionNonce)
		if err != nil || generation != 1 || qualification.Context != context ||
			!addrEqualOnWire(wire, remote, owner.peerRemote) {
			return outerQualification{}, false
		}
	case outerQualificationRebind:
		var err error
		control, err = parseQualificationRebindContext(qualification.Context)
		if err != nil || generation != owner.peerGeneration+1 ||
			control.ReceiveNext > owner.replaySequence+1 ||
			owner.peerReplayContainsLocked(generation, control, remote) {
			return outerQualification{}, false
		}
	default:
		return outerQualification{}, false
	}
	floor := owner.peerQualificationFloor
	sameFloor := floor.purpose == qualification.Purpose && floor.generation == generation
	if sameFloor && qualification.Round < floor.round {
		return outerQualification{}, false
	}
	current := owner.peerQualification
	if sameFloor && qualification.Round == floor.round {
		if current == nil || !now.Before(current.expires) {
			return outerQualification{}, false
		}
		exact := current.purpose == qualification.Purpose && current.generation == generation &&
			current.qualification.Round == qualification.Round &&
			current.qualification.InitiatorNonce == qualification.InitiatorNonce &&
			current.qualification.Context == qualification.Context &&
			current.qualification.Binding == qualification.Binding &&
			current.wire == wire && addrEqualOnWire(wire, current.remote, remote)
		if exact {
			return current.qualification, true
		}
		return outerQualification{}, false
	}
	if current != nil && now.Before(current.expires) &&
		(current.purpose != qualification.Purpose || current.generation != generation) {
		return outerQualification{}, false
	}
	if sameFloor && qualification.Round > floor.round && current != nil && now.Before(current.expires) &&
		(current.qualification.Context != qualification.Context ||
			!addrEqualOnWire(wire, current.remote, remote)) {
		return outerQualification{}, false
	}
	if sameFloor && qualification.Round > floor.round && owner.pendingPeer != nil &&
		owner.pendingPeer.generation == generation && owner.pendingPeer.control == control &&
		owner.pendingPeer.qualificationRound < qualification.Round {
		owner.pendingPeer = nil
	}
	responderNonce, err := newLinkNonce()
	if err != nil {
		return outerQualification{}, false
	}
	response := qualification
	response.ResponderNonce = responderNonce
	owner.peerQualification = &peerQualification{
		purpose: qualification.Purpose, generation: generation, qualification: response,
		wire: wire, remote: cloneAddr(remote), route: observation,
		expires: now.Add(outerPeerPendingTTL),
	}
	owner.peerQualificationFloor = peerQualificationFloor{
		purpose: qualification.Purpose, generation: generation, round: qualification.Round,
	}
	return response, true
}

func (owner *linkOwner) confirmMaximumDataQualification(
	wire *packetWire,
	remote net.Addr,
	generation uint64,
	qualification outerQualification,
	observation routeObservation,
) (outerQualification, *peerQualification, bool) {
	now := time.Now()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	state := owner.peerQualification
	if owner.closed || owner.closing || state == nil || !now.Before(state.expires) ||
		!owner.wireAllowedLocked(wire, now) || state.wire != wire ||
		state.generation != generation || state.qualification != qualification ||
		!addrEqualOnWire(wire, state.remote, remote) || state.route.digest != observation.digest {
		return outerQualification{}, nil, false
	}
	if state.confirmed {
		return qualification, nil, true
	}
	if state.confirming {
		return outerQualification{}, nil, false
	}
	switch state.purpose {
	case outerQualificationAdmission:
		if generation != 1 || !addrEqualOnWire(wire, remote, owner.peerRemote) {
			return outerQualification{}, nil, false
		}
	case outerQualificationRebind:
		control, err := parseQualificationRebindContext(state.qualification.Context)
		if err != nil || generation != owner.peerGeneration+1 ||
			control.ReceiveNext > owner.replaySequence+1 {
			return outerQualification{}, nil, false
		}
	default:
		return outerQualification{}, nil, false
	}
	state.confirming = true
	state.route = observation
	return qualification, state, true
}

func (owner *linkOwner) finishMaximumDataQualification(state *peerQualification, sent bool) bool {
	if state == nil {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.peerQualification != state || !state.confirming || state.confirmed {
		return false
	}
	state.confirming = false
	if !sent || owner.closed || owner.closing || !time.Now().Before(state.expires) {
		owner.peerQualification = nil
		if owner.pendingPeer != nil && owner.pendingPeer.generation == state.generation &&
			addrEqualOnWire(state.wire, owner.pendingPeer.remote, state.remote) {
			owner.pendingPeer = nil
		}
		return false
	}
	state.confirmed = true
	switch state.purpose {
	case outerQualificationAdmission:
		startOutbound := !owner.admissionQualified
		owner.admissionQualified = true
		return startOutbound
	case outerQualificationRebind:
		control, err := parseQualificationRebindContext(state.qualification.Context)
		if err != nil || state.generation != owner.peerGeneration+1 ||
			control.ReceiveNext > owner.replaySequence+1 {
			state.confirmed = false
			owner.peerQualification = nil
			return false
		}
		owner.pendingPeer = &peerCandidate{
			generation: state.generation, control: control,
			qualificationRound: state.qualification.Round, wire: state.wire,
			remote: cloneAddr(state.remote), route: state.route, qualified: true, expires: state.expires,
		}
	}
	return false
}

func (owner *linkOwner) sendMaximumDataQualification(
	ctx context.Context,
	wire *packetWire,
	remote net.Addr,
	typ outerType,
	generation uint64,
	qualification outerQualification,
) error {
	if wire == nil || wire.conn == nil || remote == nil {
		return net.ErrClosed
	}
	payload, err := marshalOuterQualification(typ, qualification)
	if err != nil {
		return err
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: typ, Sender: owner.role, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		return err
	}
	if len(datagram) != outerMaxDatagramSize {
		return fmt.Errorf("gvisor: maximum-DATA qualification size=%d want %d", len(datagram), outerMaxDatagramSize)
	}
	n, err := wire.writeTo(ctx, datagram, remote)
	if err != nil {
		owner.noteActiveOuterMTUFailure(wire, err)
		return err
	}
	if n != len(datagram) {
		return fmt.Errorf("gvisor: short maximum-DATA qualification write %d/%d", n, len(datagram))
	}
	return nil
}

func (owner *linkOwner) handlePathChallenge(wire *packetWire, remote net.Addr, frame outerFrame) {
	control, err := parseOuterControl(frame.Payload)
	if err != nil {
		return
	}
	now := time.Now()
	accepted := false
	owner.mu.Lock()
	wireAllowed := owner.wireAllowedLocked(wire, now)
	if !owner.closed && !owner.closing && wireAllowed {
		replayed := owner.peerReplayContainsLocked(frame.Generation, control, remote)
		if owner.committedPeer != nil && owner.committedPeer.generation == frame.Generation &&
			owner.committedPeer.control == control && addrEqualOnWire(wire, owner.committedPeer.remote, remote) {
			accepted = true
		} else if !replayed && frame.Generation == owner.peerGeneration+1 &&
			control.ReceiveNext <= owner.replaySequence+1 {
			if owner.pendingPeer == nil || now.After(owner.pendingPeer.expires) ||
				owner.pendingPeer.generation == frame.Generation && owner.pendingPeer.control == control &&
					owner.pendingPeer.wire == wire && addrEqualOnWire(wire, owner.pendingPeer.remote, remote) {
				owner.pendingPeer = &peerCandidate{
					generation: frame.Generation, control: control, wire: wire,
					remote: cloneAddr(remote), qualified: false, expires: now.Add(outerPeerPendingTTL),
				}
				accepted = true
			}
		}
	}
	owner.mu.Unlock()
	if accepted {
		_ = owner.sendControl(owner.lifetimeCtx, wire, remote, outerTypePathResponse, frame.Generation, control)
	}
}

func (owner *linkOwner) handlePathAbort(wire *packetWire, remote net.Addr, frame outerFrame) {
	control, err := parseOuterControl(frame.Payload)
	if err != nil {
		return
	}
	now := time.Now()
	accepted := false
	owner.mu.Lock()
	wireAllowed := owner.wireAllowedLocked(wire, now)
	if !owner.closed && !owner.closing && wireAllowed && frame.Generation == owner.peerGeneration+1 {
		exactPending := owner.pendingPeer != nil && now.Before(owner.pendingPeer.expires) && owner.pendingPeer.wire == wire &&
			owner.pendingPeer.generation == frame.Generation && owner.pendingPeer.control == control &&
			addrEqualOnWire(wire, owner.pendingPeer.remote, remote)
		exactReplay := owner.peerReplayContainsLocked(frame.Generation, control, remote)
		if exactReplay {
			accepted = true
		} else if exactPending || owner.pendingPeer == nil {
			if owner.peerReplayAddLocked(frame.Generation, control, remote) {
				owner.pendingPeer = nil
				if owner.peerQualification != nil && owner.peerQualification.generation == frame.Generation &&
					owner.peerQualification.wire == wire &&
					addrEqualOnWire(wire, owner.peerQualification.remote, remote) {
					owner.peerQualification = nil
				}
				accepted = true
			}
		}
	}
	owner.mu.Unlock()
	if accepted {
		_ = owner.sendControl(owner.lifetimeCtx, wire, remote, outerTypePathAbortAck, frame.Generation, control)
	}
}

func (owner *linkOwner) acceptPredecessorCommitLocked(peer outerControl) bool {
	if owner == nil || !owner.activationPending || owner.pendingRefresh == nil ||
		owner.pendingRefresh.wire != owner.active || owner.pendingRefresh.localGeneration != owner.localGeneration ||
		owner.pendingRefresh.peerGeneration != owner.peerGeneration ||
		owner.pendingRefresh.control == (outerControl{}) {
		return false
	}
	local := owner.pendingRefresh.control
	if comparison := compareOuterControl(local, peer); comparison != 0 {
		// Exactly one endpoint yields: the lexicographically earlier transaction
		// commits first, and the later transaction then requalifies active-to-active.
		return comparison > 0
	}
	// A mirrored transaction still needs a deterministic side. Proper packet
	// links always have one dialer and one acceptor, so the acceptor yields to
	// the dialer's local commit.
	return owner.role == leafmobility.RoleAcceptor
}

func compareOuterControl(left, right outerControl) int {
	if comparison := bytes.Compare(left.Transaction[:], right.Transaction[:]); comparison != 0 {
		return comparison
	}
	if comparison := bytes.Compare(left.Agreement[:], right.Agreement[:]); comparison != 0 {
		return comparison
	}
	if comparison := bytes.Compare(left.Nonce[:], right.Nonce[:]); comparison != 0 {
		return comparison
	}
	switch {
	case left.ReceiveNext < right.ReceiveNext:
		return -1
	case left.ReceiveNext > right.ReceiveNext:
		return 1
	default:
		return 0
	}
}

func (owner *linkOwner) handlePathCommit(wire *packetWire, remote net.Addr, frame outerFrame) {
	control, err := parseOuterControl(frame.Payload)
	if err != nil {
		return
	}
	now := time.Now()
	owner.mu.Lock()
	replayed := !owner.closed && !owner.closing && owner.wireAllowedLocked(wire, now) &&
		owner.committedPeer != nil && owner.committedPeer.generation == frame.Generation &&
		owner.committedPeer.control == control && addrEqualOnWire(wire, owner.committedPeer.remote, remote)
	owner.mu.Unlock()
	var observed routeObservation
	if !replayed {
		probeCtx, cancel := owner.outerRouteProbeContext(time.Now().Add(outerWriteBound))
		observed, err = owner.observeOuterRoute(probeCtx, wire, remote)
		cancel()
		if err != nil || validateMaximumDataRoute(observed) != nil {
			return
		}
	}
	accepted := false
	newCommit := false
	deferSourceUpdate := false
	var committedRoute routeObservation
	replayNeeded := false
	replayExhausted := false
	owner.sendMu.Lock()
	owner.refreshStateMu.Lock()
	owner.mu.Lock()
	now = time.Now()
	wireAllowed := owner.wireAllowedLocked(wire, now)
	if !owner.closed && !owner.closing && wireAllowed {
		if owner.committedPeer != nil && owner.committedPeer.generation == frame.Generation &&
			owner.committedPeer.control == control && addrEqualOnWire(wire, owner.committedPeer.remote, remote) {
			accepted = true
		} else if owner.pendingPeer != nil && now.Before(owner.pendingPeer.expires) &&
			owner.pendingPeer.generation == frame.Generation && owner.pendingPeer.control == control &&
			owner.pendingPeer.wire == wire && addrEqualOnWire(wire, owner.pendingPeer.remote, remote) &&
			owner.pendingPeer.route.digest == observed.digest && frame.Generation == owner.peerGeneration+1 &&
			owner.pendingPeer.qualified && control.ReceiveNext <= owner.replaySequence+1 &&
			(wire == owner.active || owner.acceptPredecessorCommitLocked(control)) {
			routeIsActive := wire == owner.active
			owner.previousRemote = cloneAddr(owner.peerRemote)
			owner.previousPeerGen = owner.peerGeneration
			owner.previousPeerUntil = now.Add(outerPredecessorDrain)
			owner.peerRemote = cloneAddr(remote)
			owner.peerGeneration = frame.Generation
			if routeIsActive {
				committedRoute = observed
				owner.routeBaseline = observed.digest
				owner.refreshSent = [sha256.Size]byte{}
			}
			if owner.pendingRefresh != nil && owner.pendingRefresh.wire == owner.active &&
				owner.pendingRefresh.localGeneration == owner.localGeneration {
				owner.pendingRefresh.peerGeneration = owner.peerGeneration
				owner.pendingRefresh.remote = cloneAddr(remote)
				if routeIsActive {
					owner.pendingRefresh.route = observed
				} else {
					owner.pendingRefresh.route = routeObservation{}
				}
				deferSourceUpdate = true
			}
			owner.committedPeer = &committedPeer{
				generation: frame.Generation, control: control, remote: cloneAddr(remote),
			}
			owner.pendingPeer = nil
			owner.peerQualification = nil
			owner.peerReplayGCLocked()
			owner.signalChangedLocked()
			accepted = true
			newCommit = true
		}
		if accepted {
			// An authenticated commit from the current/new peer tuple is a
			// positive reachability proof for this outer link. Retaining an
			// earlier one-way blackhole fault suppresses liveness and replay
			// after the peer has already recovered.
			owner.wireFault = false
			owner.wireFaultReason = leafmobility.RefreshReasonInvalid
			owner.resetLivenessLocked(now)
			valid, _ := owner.observePeerReceiveNextLocked(control.ReceiveNext)
			if valid {
				replayNeeded, replayExhausted = owner.scheduleCurrentReplayLocked(now)
			}
		}
	}
	if newCommit && !deferSourceUpdate && owner.refreshState != nil {
		digest := owner.refreshSourceDigestLocked(committedRoute)
		if _, updateErr := owner.refreshState.Update(digest); updateErr != nil {
			owner.refreshState.Invalidate()
		}
	}
	owner.mu.Unlock()
	owner.refreshStateMu.Unlock()
	owner.sendMu.Unlock()
	if accepted {
		_ = owner.sendControl(owner.lifetimeCtx, wire, remote, outerTypePathCommitAck, frame.Generation, control)
		if replayExhausted {
			owner.failReplayStall()
			return
		}
		if replayNeeded {
			owner.queueDataReplay()
		}
	}
}

func (owner *linkOwner) deliverControl(wire *packetWire, remote net.Addr, frame outerFrame) {
	control, err := parseOuterControl(frame.Payload)
	if err != nil {
		return
	}
	key := controlKey{typ: frame.Type, generation: frame.Generation, control: control}
	owner.mu.Lock()
	waiter := owner.waiters[key]
	owner.mu.Unlock()
	if waiter != nil {
		select {
		case waiter <- controlEvent{remote: cloneAddr(remote), wire: wire}:
		default:
		}
	}
}

func (owner *linkOwner) handleLivenessChallenge(wire *packetWire, remote net.Addr, frame outerFrame) {
	liveness, err := parseOuterLiveness(frame.Payload)
	if err != nil {
		return
	}
	now := time.Now()
	owner.mu.Lock()
	accepted := !owner.closed && !owner.closing && owner.wireAllowedLocked(wire, now) &&
		frame.Generation == owner.peerGeneration && addrEqualOnWire(wire, remote, owner.peerRemote)
	receiveNext := owner.receiveNext
	replayNeeded := false
	replayExhausted := false
	if accepted {
		valid, _ := owner.observePeerReceiveNextLocked(liveness.ReceiveNext)
		accepted = valid
		if valid {
			replayNeeded, replayExhausted = owner.scheduleCurrentReplayLocked(now)
		}
	}
	owner.mu.Unlock()
	if accepted {
		_ = owner.sendLiveness(
			owner.lifetimeCtx, wire, remote, outerTypeLivenessAck, frame.Generation,
			outerLiveness{Nonce: liveness.Nonce, ReceiveNext: receiveNext},
		)
		if replayExhausted {
			owner.failReplayStall()
			return
		}
		if replayNeeded {
			owner.queueDataReplay()
		}
	}
}

func (owner *linkOwner) handleLivenessAck(wire *packetWire, remote net.Addr, frame outerFrame) {
	liveness, err := parseOuterLiveness(frame.Payload)
	if err != nil {
		return
	}
	now := time.Now()
	owner.mu.Lock()
	probe, exists := owner.livenessPending[liveness.Nonce]
	accepted := exists && !owner.closed && !owner.closing && owner.wireAllowedLocked(wire, now) &&
		probe.generation == frame.Generation && frame.Generation == owner.localGeneration &&
		addrEqualOnWire(wire, remote, owner.peerRemote) && liveness.ReceiveNext <= owner.replaySequence+1
	if accepted {
		delete(owner.livenessPending, liveness.Nonce)
		owner.livenessLastAck = now
		owner.observePeerReceiveNextLocked(liveness.ReceiveNext)
	}
	replayNeeded, replayExhausted := false, false
	if accepted {
		replayNeeded, replayExhausted = owner.scheduleCurrentReplayLocked(now)
	}
	owner.mu.Unlock()
	if replayExhausted {
		owner.failReplayStall()
		return
	}
	if accepted && replayNeeded {
		owner.queueDataReplay()
	}
}

func (owner *linkOwner) failReplayStall() {
	if owner == nil {
		return
	}
	if !owner.publishWireFailure(leafmobility.RefreshReasonReplayStalled) {
		owner.failClosed(errPacketReplayStalled)
	}
}

func (owner *linkOwner) sendLiveness(
	ctx context.Context,
	wire *packetWire,
	remote net.Addr,
	typ outerType,
	generation uint64,
	liveness outerLiveness,
) error {
	if typ != outerTypeLivenessChallenge && typ != outerTypeLivenessAck {
		return errors.New("gvisor: invalid liveness frame type")
	}
	payload, err := marshalOuterLiveness(liveness)
	if err != nil {
		return err
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: typ, Sender: owner.role, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		return err
	}
	n, err := wire.writeTo(ctx, datagram, remote)
	if err != nil {
		owner.noteActiveOuterMTUFailure(wire, err)
		return err
	}
	if n != len(datagram) {
		return fmt.Errorf("gvisor: short liveness write %d/%d", n, len(datagram))
	}
	return nil
}

func (owner *linkOwner) wireAllowedLocked(wire *packetWire, now time.Time) bool {
	return wire != nil && (wire == owner.active ||
		wire == owner.predecessor && (owner.activationPending || now.Before(owner.predecessorUntil)))
}

func (owner *linkOwner) peerReplayContainsLocked(
	generation uint64,
	control outerControl,
	remote net.Addr,
) bool {
	_, exists := owner.peerReplay[peerReplayKey{
		generation: generation, control: control, remote: canonicalAddr(remote),
	}]
	return exists
}

func (owner *linkOwner) peerReplayAddLocked(
	generation uint64,
	control outerControl,
	remote net.Addr,
) bool {
	key := peerReplayKey{generation: generation, control: control, remote: canonicalAddr(remote)}
	if _, exists := owner.peerReplay[key]; exists {
		return true
	}
	owner.peerReplayGCLocked()
	if len(owner.peerReplay) >= maxPeerReplayEntries {
		return false
	}
	owner.peerReplay[key] = struct{}{}
	return true
}

func (owner *linkOwner) peerReplayGCLocked() {
	for key := range owner.peerReplay {
		if key.generation <= owner.peerGeneration {
			delete(owner.peerReplay, key)
		}
	}
}

func canonicalAddr(value net.Addr) string {
	if value == nil {
		return ""
	}
	return value.Network() + "\x00" + value.String()
}

func (owner *linkOwner) sendControl(
	ctx context.Context,
	wire *packetWire,
	remote net.Addr,
	typ outerType,
	generation uint64,
	control outerControl,
) error {
	if wire == nil || wire.conn == nil || remote == nil {
		return net.ErrClosed
	}
	payload, err := marshalOuterControl(control)
	if err != nil {
		return err
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: typ, Sender: owner.role, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		return err
	}
	n, err := wire.writeTo(ctx, datagram, remote)
	if err != nil {
		owner.noteActiveOuterMTUFailure(wire, err)
		return err
	}
	if n != len(datagram) {
		return fmt.Errorf("gvisor: short outer control write %d/%d", n, len(datagram))
	}
	return nil
}

func (owner *linkOwner) registerWaiter(key controlKey) (<-chan controlEvent, func(), error) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.closing {
		return nil, nil, net.ErrClosed
	}
	if _, exists := owner.waiters[key]; exists {
		return nil, nil, errors.New("gvisor: duplicate outer control waiter")
	}
	ch := make(chan controlEvent, 1)
	owner.waiters[key] = ch
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			owner.mu.Lock()
			if owner.waiters[key] == ch {
				delete(owner.waiters, key)
			}
			owner.mu.Unlock()
		})
	}, nil
}

func (owner *linkOwner) registerQualificationWaiter(
	key qualificationWaiterKey,
) (<-chan qualificationEvent, func(), error) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.closing {
		return nil, nil, net.ErrClosed
	}
	if _, exists := owner.qualificationWaiters[key]; exists {
		return nil, nil, errors.New("gvisor: duplicate maximum-DATA qualification waiter")
	}
	ch := make(chan qualificationEvent, 1)
	owner.qualificationWaiters[key] = ch
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			owner.mu.Lock()
			if owner.qualificationWaiters[key] == ch {
				delete(owner.qualificationWaiters, key)
			}
			owner.mu.Unlock()
		})
	}, nil
}

func (owner *linkOwner) validInnerPacket(packet []byte, outbound bool) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	var source, destination [4]byte
	copy(source[:], packet[12:16])
	copy(destination[:], packet[16:20])
	if owner.role == leafmobility.RoleDialer {
		if outbound {
			return source == owner.virtualIP && destination == serverIPv4
		}
		return source == serverIPv4 && destination == owner.virtualIP
	}
	if outbound {
		return source == serverIPv4 && destination == owner.virtualIP
	}
	return source == owner.virtualIP && destination == serverIPv4
}

func (owner *linkOwner) beginMaintenance(ctx context.Context, incarnation uint64) (*linkMaintenance, error) {
	if owner == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.closing {
		return nil, net.ErrClosed
	}
	if owner.maintenance || owner.incarnation != incarnation || incarnation == 0 {
		return nil, errors.New("gvisor: stale or busy packet-link owner")
	}
	owner.maintenance = true
	return &linkMaintenance{owner: owner, incarnation: incarnation}, nil
}

func (owner *linkOwner) stageCandidate(
	ctx context.Context,
	maintenance *linkMaintenance,
	control outerControl,
	source linkAttemptOwnerSnapshot,
) (*packetWire, uint64, routeObservation, error) {
	if maintenance == nil || maintenance.owner != owner {
		return nil, 0, routeObservation{}, errors.New("gvisor: invalid packet-link maintenance lease")
	}
	owner.mu.Lock()
	if !owner.maintenance || owner.incarnation != maintenance.incarnation || !source.currentLocked(owner) {
		owner.mu.Unlock()
		return nil, 0, routeObservation{}, errors.New("gvisor: stale packet-link source before staging")
	}
	remote := cloneAddr(source.remote)
	proposedGeneration := source.localGeneration + 1
	openCandidate := owner.openCandidate
	owner.mu.Unlock()
	if proposedGeneration == 0 {
		return nil, 0, routeObservation{}, errors.New("gvisor: packet-link generation exhausted")
	}
	if openCandidate == nil {
		return nil, 0, routeObservation{}, errors.New("gvisor: packet-link candidate opener unavailable")
	}
	stageCtx, stopSourceWatch := source.watch(ctx, owner)
	defer stopSourceWatch()
	candidate, observation, err := openCandidate(stageCtx, remote)
	if err != nil {
		if errors.Is(context.Cause(stageCtx), errLinkAttemptSourceChanged) {
			return nil, 0, routeObservation{}, errLinkAttemptSourceChanged
		}
		return nil, 0, routeObservation{}, err
	}
	if candidate == nil || candidate.conn == nil || candidate.shared {
		if candidate != nil {
			candidate.close()
		}
		return nil, 0, routeObservation{}, errors.New("gvisor: invalid private packet-link candidate")
	}
	if err := validateMaximumDataRoute(observation); err != nil {
		candidate.close()
		return nil, 0, routeObservation{}, fmt.Errorf("gvisor: qualify packet-link successor: %w", err)
	}
	challengeSent, challengeErr := owner.challengeCandidate(stageCtx, candidate, remote, proposedGeneration, control)
	if errors.Is(context.Cause(stageCtx), errLinkAttemptSourceChanged) {
		if challengeSent {
			return candidate, proposedGeneration, observation, errLinkAttemptSourceChanged
		}
		candidate.close()
		return nil, 0, routeObservation{}, errLinkAttemptSourceChanged
	}
	if challengeErr != nil && !challengeSent {
		candidate.close()
		return nil, 0, routeObservation{}, challengeErr
	}
	owner.mu.Lock()
	if !owner.maintenance || owner.incarnation != maintenance.incarnation || !source.currentLocked(owner) {
		owner.mu.Unlock()
		if challengeSent {
			return candidate, proposedGeneration, observation, errLinkAttemptSourceChanged
		}
		candidate.close()
		return nil, 0, routeObservation{}, errLinkAttemptSourceChanged
	}
	owner.wires[candidate] = struct{}{}
	owner.mu.Unlock()
	_ = candidate.conn.SetReadDeadline(time.Time{})
	return candidate, proposedGeneration, observation, challengeErr
}

func validateMaximumDataRoute(observation routeObservation) error {
	return observation.maximumDataError()
}

func (owner *linkOwner) challengeCandidate(
	ctx context.Context,
	candidate *packetWire,
	remote net.Addr,
	generation uint64,
	control outerControl,
) (bool, error) {
	context, err := qualificationRebindContext(control)
	if err != nil {
		return false, err
	}
	return owner.runMaximumDataQualification(
		ctx, candidate, remote, generation, outerQualificationRebind, context,
	)
}

func (owner *linkOwner) runMaximumDataQualification(
	ctx context.Context,
	candidate *packetWire,
	remote net.Addr,
	generation uint64,
	purpose outerQualificationPurpose,
	qualificationContext [outerQualificationContextSize]byte,
) (bool, error) {
	if owner == nil || candidate == nil || candidate.conn == nil || remote == nil || generation == 0 ||
		!purpose.valid() || qualificationContext == ([outerQualificationContextSize]byte{}) {
		return false, errors.New("gvisor: invalid bilateral maximum-DATA qualification")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sequence := owner.qualificationSequence.Add(1)
	if sequence > uint64(^uint32(0)) {
		return false, errors.New("gvisor: maximum-DATA qualification round exhausted")
	}
	round := uint32(sequence)
	initiatorNonce, err := newLinkNonce()
	if err != nil {
		return false, err
	}
	request := outerQualification{
		Purpose: purpose, Round: round, InitiatorNonce: initiatorNonce, Context: qualificationContext,
		Binding: computeOuterQualificationBinding(
			owner.secret, owner.id, generation, purpose, round, initiatorNonce, qualificationContext,
		),
	}
	defer candidate.conn.SetReadDeadline(time.Time{})
	response, sent, err := owner.exchangeMaximumDataQualification(
		ctx, candidate, remote, generation,
		outerTypeQualificationRequest, request,
		outerTypeQualificationResponse,
	)
	if err != nil {
		return sent, err
	}
	confirm := response
	done, confirmSent, err := owner.exchangeMaximumDataQualification(
		ctx, candidate, remote, generation,
		outerTypeQualificationConfirm, confirm,
		outerTypeQualificationDone,
	)
	sent = sent || confirmSent
	if err != nil {
		return sent, err
	}
	if done != confirm {
		return sent, errors.New("gvisor: maximum-DATA DONE does not match confirmation")
	}
	return sent, nil
}

func (owner *linkOwner) exchangeMaximumDataQualification(
	ctx context.Context,
	candidate *packetWire,
	remote net.Addr,
	generation uint64,
	requestType outerType,
	request outerQualification,
	responseType outerType,
) (outerQualification, bool, error) {
	payload, err := marshalOuterQualification(requestType, request)
	if err != nil {
		return outerQualification{}, false, err
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: requestType, Sender: owner.role, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		return outerQualification{}, false, err
	}
	if len(datagram) != outerMaxDatagramSize {
		return outerQualification{}, false, fmt.Errorf(
			"gvisor: maximum-DATA request size=%d want %d", len(datagram), outerMaxDatagramSize,
		)
	}
	if candidate.receiving.Load() {
		return owner.exchangeMaximumDataQualificationRouted(
			ctx, candidate, remote, generation, requestType, request, responseType, datagram,
		)
	}
	buffer := make([]byte, outerMaxDatagramSize+1)
	sent := false
	for {
		if err := ctx.Err(); err != nil {
			return outerQualification{}, sent, contextCause(ctx)
		}
		n, writeErr := candidate.writeTo(ctx, datagram, remote)
		if writeErr != nil || n != len(datagram) {
			if writeErr == nil {
				writeErr = fmt.Errorf("short write %d/%d", n, len(datagram))
			}
			return outerQualification{}, sent, fmt.Errorf(
				"gvisor: send maximum-DATA qualification type=%d: %w", requestType, writeErr,
			)
		}
		sent = true
		deadline := time.Now().Add(outerControlRetry)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := candidate.conn.SetReadDeadline(deadline); err != nil {
			return outerQualification{}, sent, err
		}
		for {
			n, source, readErr := candidate.conn.ReadFrom(buffer)
			if readErr != nil {
				if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() && ctx.Err() == nil {
					break
				}
				if ctx.Err() != nil && !errors.Is(readErr, ErrOuterMTU) {
					return outerQualification{}, sent, contextCause(ctx)
				}
				return outerQualification{}, sent, readErr
			}
			if n != outerMaxDatagramSize || !addrEqualOnWire(candidate, source, remote) {
				continue
			}
			frame, decodeErr := decodeOuter(buffer[:n], owner.secret, peerOuterRole(owner.role))
			if decodeErr != nil || frame.Type != responseType || frame.LinkID != owner.id ||
				frame.Generation != generation {
				continue
			}
			response, parseErr := parseOuterQualification(frame.Type, frame.Payload)
			if parseErr != nil || response.Purpose != request.Purpose ||
				response.InitiatorNonce != request.InitiatorNonce ||
				response.Context != request.Context || response.Binding != request.Binding {
				continue
			}
			if requestType == outerTypeQualificationConfirm && response != request {
				continue
			}
			return response, sent, nil
		}
	}
}

func (owner *linkOwner) exchangeMaximumDataQualificationRouted(
	ctx context.Context,
	candidate *packetWire,
	remote net.Addr,
	generation uint64,
	requestType outerType,
	request outerQualification,
	responseType outerType,
	datagram []byte,
) (outerQualification, bool, error) {
	key := maximumDataQualificationWaiterKey(responseType, generation, request)
	waiter, cancelWaiter, err := owner.registerQualificationWaiter(key)
	if err != nil {
		return outerQualification{}, false, err
	}
	defer cancelWaiter()
	sent := false
	for {
		if err := ctx.Err(); err != nil {
			return outerQualification{}, sent, contextCause(ctx)
		}
		n, writeErr := candidate.writeTo(ctx, datagram, remote)
		if writeErr != nil || n != len(datagram) {
			if writeErr == nil {
				writeErr = fmt.Errorf("short write %d/%d", n, len(datagram))
			}
			return outerQualification{}, sent, fmt.Errorf(
				"gvisor: send routed maximum-DATA qualification type=%d: %w", requestType, writeErr,
			)
		}
		sent = true
		timer := time.NewTimer(outerControlRetry)
		select {
		case event := <-waiter:
			if !timer.Stop() {
				<-timer.C
			}
			response := event.qualification
			if event.wire != candidate || !addrEqualOnWire(candidate, event.remote, remote) ||
				response.Purpose != request.Purpose || response.InitiatorNonce != request.InitiatorNonce ||
				response.Context != request.Context || response.Binding != request.Binding ||
				requestType == outerTypeQualificationConfirm && response != request {
				continue
			}
			return response, sent, nil
		case <-timer.C:
			continue
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return outerQualification{}, sent, contextCause(ctx)
		case <-owner.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return outerQualification{}, sent, net.ErrClosed
		}
	}
}

func (owner *linkOwner) publishCandidate(
	ctx context.Context,
	maintenance *linkMaintenance,
	candidate *packetWire,
	generation uint64,
	control outerControl,
	expectedRoute routeObservation,
	source linkAttemptOwnerSnapshot,
) error {
	if owner == nil || maintenance == nil || maintenance.owner != owner || candidate == nil ||
		control == (outerControl{}) {
		return errors.New("gvisor: invalid packet-link publish")
	}
	owner.mu.Lock()
	sourceCurrent := source.currentLocked(owner)
	valid := owner.maintenance && owner.incarnation == maintenance.incarnation && sourceCurrent &&
		owner.localGeneration+1 == generation &&
		candidate.error() == nil
	remote := cloneAddr(source.remote)
	_, staged := owner.wires[candidate]
	private := staged && owner.active != candidate && !owner.activationPending
	owner.mu.Unlock()
	if !sourceCurrent {
		return errors.New("gvisor: packet-link source changed before publication")
	}
	if !valid || !private {
		return errors.New("gvisor: packet-link publish state changed")
	}
	observation, err := owner.observeOuterRoute(ctx, candidate, remote)
	if err != nil {
		return fmt.Errorf("gvisor: observe packet-link successor before publication: %w", err)
	}
	if observation.digest != expectedRoute.digest {
		return errors.New("gvisor: packet-link successor route changed before publication")
	}
	if err := validateMaximumDataRoute(observation); err != nil {
		return fmt.Errorf("gvisor: requalify packet-link successor before publication: %w", err)
	}
	if _, err := owner.challengeCandidate(ctx, candidate, remote, generation, control); err != nil {
		return fmt.Errorf("gvisor: peer-receipt requalification before publication: %w", err)
	}
	_ = candidate.conn.SetReadDeadline(time.Time{})
	owner.startReceiver(candidate)
	owner.sendMu.Lock()
	defer owner.sendMu.Unlock()
	owner.refreshStateMu.Lock()
	defer owner.refreshStateMu.Unlock()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !source.currentLocked(owner) {
		return errors.New("gvisor: packet-link source changed during publication")
	}
	if !owner.maintenance || owner.incarnation != maintenance.incarnation ||
		owner.localGeneration+1 != generation || candidate.error() != nil {
		return errors.New("gvisor: packet-link publish state changed")
	}
	if _, exists := owner.wires[candidate]; !exists || owner.active == candidate || owner.activationPending {
		return errors.New("gvisor: packet-link candidate is not privately staged")
	}
	owner.predecessor = owner.active
	owner.predecessorUntil = time.Time{}
	owner.active = candidate
	owner.localGeneration = generation
	owner.incarnation++
	if owner.incarnation == 0 {
		owner.incarnation++
	}
	owner.activationPending = true
	owner.pendingRefresh = &localRefreshCommit{
		wire: candidate, localGeneration: generation, peerGeneration: owner.peerGeneration,
		control: control, remote: cloneAddr(remote), route: observation,
	}
	owner.signalChangedLocked()
	return nil
}

func (owner *linkOwner) activateCandidate(
	ctx context.Context,
	maintenance *linkMaintenance,
	candidate *packetWire,
	generation uint64,
	control outerControl,
) error {
	key := controlKey{typ: outerTypePathCommitAck, generation: generation, control: control}
	waiter, cancelWaiter, err := owner.registerWaiter(key)
	if err != nil {
		return err
	}
	defer cancelWaiter()
	for {
		owner.mu.Lock()
		if owner.closed || owner.closing || owner.active != candidate || !owner.activationPending ||
			!owner.maintenance || maintenance == nil || maintenance.owner != owner {
			owner.mu.Unlock()
			return errors.New("gvisor: packet-link activation state changed")
		}
		remote := cloneAddr(owner.peerRemote)
		owner.mu.Unlock()
		observation, err := owner.observeOuterRoute(ctx, candidate, remote)
		if err != nil {
			return fmt.Errorf("gvisor: observe final packet-link route: %w", err)
		}
		if err := validateMaximumDataRoute(observation); err != nil {
			return fmt.Errorf("gvisor: qualify final packet-link route: %w", err)
		}
		if _, err := owner.challengeCandidate(ctx, candidate, remote, generation, control); err != nil {
			return fmt.Errorf("gvisor: qualify final packet-link tuple: %w", err)
		}
		owner.mu.Lock()
		currentRemote := addrEqualOnWire(candidate, owner.peerRemote, remote)
		current := !owner.closed && !owner.closing && owner.active == candidate && owner.activationPending &&
			owner.maintenance && owner.localGeneration == generation
		owner.mu.Unlock()
		if !current {
			return errors.New("gvisor: packet-link activation state changed")
		}
		if !currentRemote {
			continue
		}
		if err := owner.sendControl(ctx, candidate, remote, outerTypePathCommit, generation, control); err != nil {
			return err
		}
		timer := time.NewTimer(outerControlRetry)
		select {
		case event := <-waiter:
			if !timer.Stop() {
				<-timer.C
			}
			if event.wire != candidate || !addrEqualOnWire(candidate, event.remote, remote) {
				continue
			}
			owner.refreshStateMu.Lock()
			owner.mu.Lock()
			current = !owner.closed && !owner.closing && owner.active == candidate && owner.activationPending &&
				owner.maintenance && owner.localGeneration == generation &&
				addrEqualOnWire(candidate, owner.peerRemote, remote)
			if current && owner.pendingRefresh != nil && owner.pendingRefresh.wire == candidate &&
				owner.pendingRefresh.localGeneration == generation {
				owner.pendingRefresh.peerGeneration = owner.peerGeneration
				owner.pendingRefresh.remote = cloneAddr(remote)
				owner.pendingRefresh.route = observation
			}
			owner.mu.Unlock()
			owner.refreshStateMu.Unlock()
			if !current {
				continue
			}
			if err := owner.replayOnCandidate(ctx, candidate, remote, generation); err != nil {
				return fmt.Errorf("gvisor: replay packet-link predecessor window: %w", err)
			}
			return owner.finishActivation(ctx, maintenance, candidate)
		case <-timer.C:
			continue
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-owner.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return net.ErrClosed
		}
	}
}

func (owner *linkOwner) finishActivation(
	ctx context.Context,
	maintenance *linkMaintenance,
	candidate *packetWire,
) error {
	owner.mu.Lock()
	if owner.closed || owner.closing || owner.active != candidate || !owner.activationPending {
		owner.mu.Unlock()
		return errors.New("gvisor: packet-link activation is no longer current")
	}
	owner.activationPending = false
	predecessor := owner.predecessor
	owner.predecessorUntil = time.Now().Add(outerPredecessorDrain)
	owner.resetLivenessLocked(time.Now())
	owner.signalChangedLocked()
	owner.mu.Unlock()

	timer := time.NewTimer(outerPredecessorDrain)
	select {
	case <-timer.C:
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	owner.mu.Lock()
	if owner.predecessor == predecessor {
		owner.predecessor = nil
		owner.predecessorUntil = time.Time{}
		if predecessor != nil && !predecessor.shared {
			delete(owner.wires, predecessor)
		}
	}
	owner.mu.Unlock()
	if predecessor != nil && !predecessor.shared {
		predecessor.close()
	}
	maintenance.release()
	return nil
}

func (owner *linkOwner) rollbackCandidate(
	ctx context.Context,
	maintenance *linkMaintenance,
	candidate *packetWire,
	generation uint64,
	control outerControl,
	remote net.Addr,
) error {
	if owner == nil || maintenance == nil || maintenance.owner != owner {
		return errors.New("gvisor: invalid packet-link rollback")
	}
	owner.mu.Lock()
	if owner.active == candidate || owner.activationPending {
		owner.mu.Unlock()
		return errors.New("gvisor: packet-link rollback after publication")
	}
	owner.mu.Unlock()
	if candidate != nil {
		if err := owner.cancelPeerCandidate(ctx, candidate, generation, control, remote); err != nil {
			return err
		}
		owner.mu.Lock()
		delete(owner.wires, candidate)
		owner.mu.Unlock()
		candidate.close()
	}
	maintenance.release()
	return nil
}

func (owner *linkOwner) cancelPeerCandidate(
	ctx context.Context,
	candidate *packetWire,
	generation uint64,
	control outerControl,
	remote net.Addr,
) error {
	if candidate == nil || generation == 0 || control == (outerControl{}) || remote == nil {
		return errors.New("gvisor: invalid peer candidate cancellation")
	}
	remote = cloneAddr(remote)
	if !candidate.receiving.Load() {
		return owner.cancelPeerCandidateDirect(ctx, candidate, generation, control, remote)
	}
	key := controlKey{typ: outerTypePathAbortAck, generation: generation, control: control}
	waiter, cancelWaiter, err := owner.registerWaiter(key)
	if err != nil {
		return err
	}
	defer cancelWaiter()
	for {
		owner.mu.Lock()
		if owner.closed || owner.closing || !owner.maintenance {
			owner.mu.Unlock()
			return net.ErrClosed
		}
		owner.mu.Unlock()
		if err := owner.sendControl(ctx, candidate, remote, outerTypePathAbort, generation, control); err != nil {
			return err
		}
		timer := time.NewTimer(outerControlRetry)
		select {
		case event := <-waiter:
			if !timer.Stop() {
				<-timer.C
			}
			if event.wire == candidate && addrEqualOnWire(candidate, event.remote, remote) {
				return nil
			}
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-owner.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return net.ErrClosed
		}
	}
}

func (owner *linkOwner) cancelPeerCandidateDirect(
	ctx context.Context,
	candidate *packetWire,
	generation uint64,
	control outerControl,
	remote net.Addr,
) error {
	if remote == nil {
		return errors.New("gvisor: packet-link rollback has no qualified peer remote")
	}
	remote = cloneAddr(remote)
	payload, err := marshalOuterControl(control)
	if err != nil {
		return err
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: outerTypePathAbort, Sender: owner.role, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		return err
	}
	buffer := make([]byte, outerHeaderSize+outerControlPayloadSize+outerAuthTagSize+1)
	defer candidate.conn.SetReadDeadline(time.Time{})
	for {
		if err := ctx.Err(); err != nil {
			return contextCause(ctx)
		}
		owner.mu.Lock()
		if owner.closed || owner.closing || !owner.maintenance {
			owner.mu.Unlock()
			return net.ErrClosed
		}
		owner.mu.Unlock()
		n, writeErr := candidate.writeTo(ctx, datagram, remote)
		if writeErr != nil || n != len(datagram) {
			if writeErr == nil {
				writeErr = fmt.Errorf("short write %d/%d", n, len(datagram))
			}
			return fmt.Errorf("gvisor: send direct packet-link abort: %w", writeErr)
		}
		deadline := time.Now().Add(outerControlRetry)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := candidate.conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		for {
			n, source, readErr := candidate.conn.ReadFrom(buffer)
			if readErr != nil {
				if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() && ctx.Err() == nil {
					break
				}
				if ctx.Err() != nil {
					return contextCause(ctx)
				}
				return readErr
			}
			frame, decodeErr := decodeOuter(buffer[:n], owner.secret, peerOuterRole(owner.role))
			if decodeErr != nil || frame.Type != outerTypePathAbortAck || frame.LinkID != owner.id ||
				frame.Generation != generation || !addrEqualOnWire(candidate, source, remote) {
				continue
			}
			ack, parseErr := parseOuterControl(frame.Payload)
			if parseErr == nil && ack == control {
				return nil
			}
		}
	}
}

func (owner *linkOwner) failClosed(cause error) {
	owner.failClosedInternal(cause, false)
}

func (owner *linkOwner) failClosedInternal(cause error, requireUnbound bool) {
	if owner == nil {
		return
	}
	if cause == nil {
		cause = net.ErrClosed
	}
	owner.mu.Lock()
	if owner.closed || owner.closing || (requireUnbound && owner.endpoint != nil) {
		if requireUnbound {
			owner.admissionTimer = nil
		}
		owner.mu.Unlock()
		return
	}
	if owner.mtuRecovery != nil && !errors.Is(cause, ErrOuterMTU) && !errors.Is(cause, net.ErrClosed) {
		cause = errors.Join(owner.mtuRecovery.cause, cause)
	}
	owner.closing = true
	if owner.terminalErr == nil {
		owner.terminalErr = cause
	}
	owner.activationPending = false
	owner.signalChangedLocked()
	endpoint := owner.endpoint
	admissionTimer := owner.admissionTimer
	owner.admissionTimer = nil
	var recoveryTimer *time.Timer
	if owner.mtuRecovery != nil {
		owner.mtuRecovery.expired = true
		recoveryTimer = owner.mtuRecovery.timer
		owner.mtuRecovery.timer = nil
	}
	wires := make([]*packetWire, 0, len(owner.wires))
	for wire := range owner.wires {
		if !wire.shared {
			wires = append(wires, wire)
		}
	}
	owner.mu.Unlock()
	owner.lifetimeStop()
	if admissionTimer != nil {
		admissionTimer.Stop()
	}
	if recoveryTimer != nil {
		recoveryTimer.Stop()
	}

	for _, wire := range wires {
		wire.close()
	}
	if endpoint != nil {
		_ = endpoint.Close()
	}
	owner.finishClose(cause)
}

func (owner *linkOwner) close() {
	if owner == nil {
		return
	}
	owner.failClosed(net.ErrClosed)
	// Another fault path may already own teardown. Join it instead of making
	// PathConn.Close report completion while the listener, replay lease, and
	// owner endpoint are still live.
	<-owner.done
}

func (owner *linkOwner) finishClose(_ error) {
	owner.refreshMu.Lock()
	cancelRefresh := owner.refreshCancel
	owner.refreshFn = nil
	owner.refreshEvents = nil
	owner.refreshMu.Unlock()
	if cancelRefresh != nil {
		cancelRefresh()
	}

	owner.cleanupOnce.Do(func() {
		owner.mu.Lock()
		cleanup := owner.cleanup
		owner.mu.Unlock()
		if owner.listener != nil {
			owner.listener.unregisterPacketLink(owner)
		}
		if cleanup != nil {
			cleanup()
		}
	})
	owner.mu.Lock()
	if !owner.closed {
		if owner.mtuRecovery != nil && owner.mtuRecovery.timer != nil {
			owner.mtuRecovery.timer.Stop()
			owner.mtuRecovery.timer = nil
		}
		for index := range owner.replayPackets {
			owner.replayPackets[index].packet = nil
		}
		owner.replayPackets = nil
		owner.replayBytes = 0
		owner.replayLease.close()
		owner.closed = true
		owner.closing = false
		close(owner.done)
	}
	owner.mu.Unlock()
}

func (owner *linkOwner) signalChangedLocked() {
	close(owner.change)
	owner.change = make(chan struct{})
}

type linkMaintenance struct {
	once        sync.Once
	owner       *linkOwner
	incarnation uint64
}

func (maintenance *linkMaintenance) release() {
	if maintenance == nil || maintenance.owner == nil {
		return
	}
	maintenance.once.Do(func() {
		maintenance.owner.mu.Lock()
		maintenance.owner.maintenance = false
		maintenance.owner.signalChangedLocked()
		maintenance.owner.mu.Unlock()
	})
}

func (owner *linkOwner) openUDPCandidate(
	ctx context.Context,
	remote net.Addr,
) (*packetWire, routeObservation, error) {
	owner.mu.Lock()
	active := owner.active
	owner.mu.Unlock()
	activeRoute, err := owner.observeOuterRoute(ctx, active, remote)
	if err != nil {
		return nil, routeObservation{}, fmt.Errorf("gvisor: observe active packet-link source: %w", err)
	}
	udpRemote, err := resolveOuterUDPAddress(remote)
	if err != nil {
		return nil, routeObservation{}, err
	}
	mode, err := outerUDPRemoteMode(udpRemote)
	if err != nil {
		return nil, routeObservation{}, err
	}
	local, err := active.successorBindAddress(mode, activeRoute.local)
	if err != nil {
		return nil, routeObservation{}, fmt.Errorf("gvisor: preserve packet-link bind intent: %w", err)
	}
	openWire := owner.openWire
	var candidate *packetWire
	if openWire != nil {
		candidate, err = openWire(mode, local, false)
	} else {
		candidate, err = platformOpenOuterSuccessorWire(ctx, active, mode, local)
	}
	if err != nil {
		return nil, routeObservation{}, fmt.Errorf("gvisor: open packet-link successor: %w", err)
	}
	candidateObservation, err := owner.observeOuterRoute(ctx, candidate, remote)
	if err != nil {
		candidate.close()
		return nil, routeObservation{}, fmt.Errorf("gvisor: observe packet-link successor route: %w", err)
	}
	return candidate, candidateObservation, nil
}

func (owner *linkOwner) subscribeRefresh(
	ctx context.Context,
	fn func(leafmobility.RefreshEvidence),
) (func(), error) {
	if owner == nil || fn == nil || owner.refreshEmitter == nil || owner.refreshState == nil {
		return nil, errors.New("gvisor: packet-link mobility refresh is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owner.mu.Lock()
	if owner.closed || owner.closing {
		owner.mu.Unlock()
		return nil, net.ErrClosed
	}
	sourceRoute := outerRefreshRouteSnapshot{
		active: owner.active, remote: cloneAddr(owner.peerRemote),
		localGeneration: owner.localGeneration, peerGeneration: owner.peerGeneration,
		incarnation: owner.incarnation,
	}
	owner.mu.Unlock()
	observation, err := owner.observeOuterRoute(ctx, sourceRoute.active, sourceRoute.remote)
	if err != nil {
		return nil, err
	}
	owner.refreshStateMu.Lock()
	defer owner.refreshStateMu.Unlock()
	owner.mu.Lock()
	if !owner.refreshRouteSnapshotCurrentLocked(sourceRoute) {
		owner.mu.Unlock()
		return nil, errors.New("gvisor: packet-link changed during refresh subscription")
	}
	if _, err := owner.refreshState.Update(owner.refreshSourceDigestLocked(observation)); err != nil {
		owner.mu.Unlock()
		return nil, err
	}
	monitorCtx, cancel := context.WithCancel(ctx)
	owner.resetLivenessLocked(time.Now())
	owner.refreshMu.Lock()
	if owner.refreshCancel != nil || owner.refreshCallbackLive {
		owner.refreshMu.Unlock()
		owner.mu.Unlock()
		cancel()
		return nil, errors.New("gvisor: packet-link mobility refresh subscriber or callback is still active")
	}
	owner.refreshCancel = cancel
	owner.refreshDone = make(chan struct{})
	owner.refreshDispatchDone = make(chan struct{})
	owner.refreshFn = fn
	owner.refreshEvents = make(chan leafmobility.RefreshEvidence, 16)
	owner.refreshCircuit = false
	owner.refreshEpoch++
	if owner.refreshEpoch == 0 {
		owner.refreshEpoch++
	}
	epoch := owner.refreshEpoch
	owner.routeBaseline = observation.digest
	owner.refreshSent = [sha256.Size]byte{}
	done := owner.refreshDone
	dispatchDone := owner.refreshDispatchDone
	events := owner.refreshEvents
	owner.refreshMu.Unlock()
	owner.mu.Unlock()
	go owner.refreshDispatchLoop(monitorCtx, epoch, fn, events, dispatchDone)
	go owner.refreshLoop(monitorCtx, done)
	var once sync.Once
	return func() {
		once.Do(func() {
			owner.cancelRefreshSubscription(epoch, cancel)
		})
	}, nil
}

func (owner *linkOwner) refreshDispatchLoop(
	ctx context.Context,
	epoch uint64,
	fn func(leafmobility.RefreshEvidence),
	events <-chan leafmobility.RefreshEvidence,
	done chan struct{},
) {
	defer func() {
		owner.cancelRefreshSubscription(epoch, nil)
		close(done)
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case evidence := <-events:
			owner.refreshMu.Lock()
			current := ctx.Err() == nil && owner.refreshEpoch == epoch && owner.refreshFn != nil &&
				owner.refreshEvents == events && !owner.refreshCircuit && !owner.refreshCallbackLive
			owner.refreshMu.Unlock()
			if !current {
				return
			}
			budget := owner.refreshCallbacks
			if budget == nil {
				budget = processRefreshCallbackBudget
			}
			release, ok := budget.acquire()
			if !ok {
				owner.tripRefreshCircuit(epoch, errRefreshCallbackBudget)
				return
			}
			completed := make(chan bool, 1)
			started := make(chan struct{})
			owner.refreshMu.Lock()
			if ctx.Err() != nil || owner.refreshEpoch != epoch || owner.refreshFn == nil ||
				owner.refreshEvents != events || owner.refreshCircuit || owner.refreshCallbackLive {
				owner.refreshMu.Unlock()
				release()
				return
			}
			owner.refreshCallbackLive = true
			owner.refreshCallbackGen = epoch
			go func() {
				close(started)
				panicked := false
				func() {
					defer func() {
						if recover() != nil {
							panicked = true
						}
					}()
					fn(evidence)
				}()
				release()
				owner.finishRefreshCallback(epoch)
				completed <- panicked
			}()
			// Cancellation clears the subscriber under refreshMu. Waiting for
			// this handshake while holding the same lock guarantees a callback
			// either started before cancellation linearized or never starts.
			<-started
			owner.refreshMu.Unlock()
			timer := time.NewTimer(outerRefreshCallbackMax)
			select {
			case panicked := <-completed:
				if !timer.Stop() {
					<-timer.C
				}
				if panicked {
					owner.tripRefreshCircuit(epoch, errors.New("gvisor: packet-link mobility refresh callback panicked"))
					return
				}
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
				owner.tripRefreshCircuit(epoch, errRefreshCallbackStall)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (owner *linkOwner) finishRefreshCallback(epoch uint64) {
	owner.refreshMu.Lock()
	if owner.refreshCallbackLive && owner.refreshCallbackGen == epoch {
		owner.refreshCallbackLive = false
		owner.refreshCallbackGen = 0
	}
	owner.refreshMu.Unlock()
}

func (owner *linkOwner) cancelRefreshSubscription(epoch uint64, cancel context.CancelFunc) {
	owner.refreshMu.Lock()
	if owner.refreshEpoch == epoch {
		if cancel == nil {
			cancel = owner.refreshCancel
		}
		owner.refreshCancel = nil
		owner.refreshFn = nil
		owner.refreshEvents = nil
	}
	owner.refreshMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (owner *linkOwner) tripRefreshCircuit(epoch uint64, cause error) {
	owner.refreshMu.Lock()
	if owner.refreshEpoch != epoch || owner.refreshFn == nil {
		owner.refreshMu.Unlock()
		return
	}
	owner.refreshCircuit = true
	owner.refreshTrips++
	owner.refreshFn = nil
	owner.refreshEvents = nil
	cancel := owner.refreshCancel
	owner.refreshMu.Unlock()
	if cancel != nil {
		cancel()
	}
	go owner.failClosed(cause)
}

func (owner *linkOwner) refreshLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	routeTicker := time.NewTicker(outerRoutePollInterval)
	defer routeTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-routeTicker.C:
			owner.observeRefresh(ctx)
		}
	}
}

func (owner *linkOwner) livenessLoop() {
	ticker := time.NewTicker(outerLivenessTick)
	defer ticker.Stop()
	for {
		select {
		case <-owner.lifetimeCtx.Done():
			return
		case <-ticker.C:
			owner.probeLiveness(owner.lifetimeCtx)
		}
	}
}

func (owner *linkOwner) probeLiveness(ctx context.Context) {
	now := time.Now()
	owner.mu.Lock()
	if owner.closed || owner.closing || owner.maintenance || owner.activationPending || owner.wireFault {
		owner.mu.Unlock()
		return
	}
	if now.Sub(owner.livenessLastAck) >= owner.livenessFailureThreshold() && len(owner.replayPackets) != 0 {
		owner.mu.Unlock()
		if !owner.publishWireFailure(leafmobility.RefreshReasonLinkUnresponsive) {
			owner.failClosed(errPacketLivenessTimeout)
		}
		return
	}
	if now.Sub(owner.livenessLastProbe) < outerLivenessInterval {
		owner.mu.Unlock()
		return
	}
	for nonce, probe := range owner.livenessPending {
		if now.Sub(probe.sent) >= outerLivenessFailure {
			delete(owner.livenessPending, nonce)
		}
	}
	if len(owner.livenessPending) >= maxLivenessPending {
		owner.mu.Unlock()
		return
	}
	wire := owner.active
	remote := cloneAddr(owner.peerRemote)
	generation := owner.localGeneration
	receiveNext := owner.receiveNext
	owner.livenessLastProbe = now
	owner.mu.Unlock()

	nonce, err := newLinkNonce()
	if err != nil {
		owner.publishWireFailure(leafmobility.RefreshReasonLivenessProbeFailure)
		return
	}
	owner.mu.Lock()
	if owner.closed || owner.closing || owner.maintenance || owner.activationPending || owner.active != wire ||
		owner.localGeneration != generation || !addrEqualOnWire(wire, owner.peerRemote, remote) {
		owner.mu.Unlock()
		return
	}
	owner.livenessPending[nonce] = livenessProbe{
		generation: generation, sent: now,
	}
	owner.mu.Unlock()
	if err := owner.sendLiveness(ctx, wire, remote, outerTypeLivenessChallenge, generation, outerLiveness{
		Nonce: nonce, ReceiveNext: receiveNext,
	}); err != nil {
		owner.mu.Lock()
		delete(owner.livenessPending, nonce)
		owner.mu.Unlock()
		owner.publishWireFailure(leafmobility.RefreshReasonLocalWriteFailure)
	}
}

func (owner *linkOwner) livenessFailureThreshold() time.Duration {
	if owner != nil && owner.role == leafmobility.RoleAcceptor {
		// Both endpoints observe a silent shared-link blackhole. Give the
		// dialer one monitor tick to publish the protocol's client-priority
		// transaction before the acceptor starts a redundant server actor.
		// Asymmetric route/read/write failures bypass this liveness threshold.
		return outerLivenessFailure + outerLivenessTick
	}
	return outerLivenessFailure
}

func (owner *linkOwner) resetLivenessLocked(now time.Time) {
	clear(owner.livenessPending)
	owner.livenessLastAck = now
	owner.livenessLastProbe = time.Time{}
}

func (owner *linkOwner) retainReplayLocked(packet []byte) (packetReplay, <-chan struct{}, bool) {
	if len(packet) == 0 || owner.replayLease == nil || owner.replayBytes+len(packet) > owner.replayLimit ||
		len(owner.replayPackets) >= owner.replayEntryLimit {
		return packetReplay{}, nil, false
	}
	reserved, changed := owner.replayLease.reserve(len(packet), 1)
	if !reserved {
		return packetReplay{}, changed, false
	}
	copyOfPacket := append([]byte(nil), packet...)
	owner.replaySequence++
	if owner.replaySequence == 0 {
		owner.replaySequence++
	}
	replay := packetReplay{
		sequence: owner.replaySequence, packet: copyOfPacket,
	}
	owner.replayPackets = append(owner.replayPackets, replay)
	owner.replayBytes += len(copyOfPacket)
	return replay, nil, true
}

func (owner *linkOwner) ackReplayLocked(receiveNext uint64) bool {
	firstRetained := 0
	releasedBytes := 0
	for firstRetained < len(owner.replayPackets) && owner.replayPackets[firstRetained].sequence < receiveNext {
		releasedBytes += len(owner.replayPackets[firstRetained].packet)
		owner.replayPackets[firstRetained].packet = nil
		firstRetained++
	}
	if firstRetained != 0 {
		remaining := copy(owner.replayPackets, owner.replayPackets[firstRetained:])
		clear(owner.replayPackets[remaining:])
		if remaining == 0 {
			owner.replayPackets = nil
		} else {
			owner.replayPackets = owner.replayPackets[:remaining]
		}
		owner.replayBytes -= releasedBytes
		owner.replayLease.release(releasedBytes, firstRetained)
		if len(owner.replayPackets) == 0 {
			owner.replayRequestGen = 0
			owner.replayRequestPeer = 0
			owner.replayRequestNext = 0
			owner.replayRequestAt = time.Time{}
			owner.replayRequestRuns = 0
			owner.replayExhausted = false
		}
		owner.signalChangedLocked()
		return true
	}
	return false
}

func (owner *linkOwner) observePeerReceiveNextLocked(receiveNext uint64) (valid, progressed bool) {
	if receiveNext == 0 || receiveNext > owner.replaySequence+1 {
		return false, false
	}
	if receiveNext <= owner.peerReceiveNext {
		return true, false
	}
	owner.peerReceiveNext = receiveNext
	owner.duplicateDataAcks = 0
	owner.replayRequestRuns = 0
	owner.replayExhausted = false
	owner.ackReplayLocked(receiveNext)
	return true, true
}

func (owner *linkOwner) scheduleCurrentReplayLocked(now time.Time) (replay, exhausted bool) {
	if len(owner.replayPackets) == 0 || owner.wireFault {
		return false, false
	}
	changedFrontier := owner.replayRequestGen != owner.localGeneration ||
		owner.replayRequestPeer != owner.peerGeneration ||
		owner.replayRequestNext != owner.peerReceiveNext
	if changedFrontier {
		owner.replayRequestRuns = 0
		owner.replayExhausted = false
	}
	if owner.replayExhausted {
		return false, false
	}
	if !changedFrontier && !owner.replayRequestAt.IsZero() &&
		now.Sub(owner.replayRequestAt) < outerReplayNoProgress {
		return false, false
	}
	if owner.replayRequestRuns >= maxReplayNoProgress {
		owner.replayExhausted = true
		return false, true
	}
	owner.replayRequestGen = owner.localGeneration
	owner.replayRequestPeer = owner.peerGeneration
	owner.replayRequestNext = owner.peerReceiveNext
	owner.replayRequestAt = now
	owner.replayRequestRuns++
	return true, false
}

func (owner *linkOwner) recordReceiveSequenceLocked(sequence uint64) (accept, acknowledge bool) {
	if sequence < owner.receiveNext {
		return false, true
	}
	if sequence-owner.receiveNext >= maxReceiveAheadEntries {
		return false, true
	}
	if sequence > owner.receiveNext {
		if _, exists := owner.receiveAhead[sequence]; exists {
			return false, true
		}
		if len(owner.receiveAhead) >= maxReceiveAheadEntries {
			return false, true
		}
		owner.receiveAhead[sequence] = struct{}{}
		owner.receiveSinceAck++
		return true, true
	}
	owner.receiveNext++
	for {
		if _, exists := owner.receiveAhead[owner.receiveNext]; !exists {
			break
		}
		delete(owner.receiveAhead, owner.receiveNext)
		owner.receiveNext++
	}
	owner.receiveSinceAck++
	acknowledge = owner.receiveSinceAck >= dataAckEveryPackets
	if acknowledge {
		owner.receiveSinceAck = 0
	}
	return true, acknowledge
}

func (owner *linkOwner) queueDataAck() {
	select {
	case owner.dataAckWake <- struct{}{}:
	default:
	}
}

func (owner *linkOwner) dataAckLoop() {
	for {
		select {
		case <-owner.dataAckWake:
			if err := owner.sendDataAck(owner.lifetimeCtx); err != nil && !errors.Is(err, context.Canceled) &&
				!errors.Is(err, net.ErrClosed) {
				faultReason := leafmobility.RefreshReasonLocalWriteFailure
				if errors.Is(err, ErrOuterMTU) {
					faultReason = leafmobility.RefreshReasonOuterMTUFailure
				}
				if !owner.publishWireFailure(faultReason) {
					owner.failClosed(err)
				}
			}
		case <-owner.done:
			return
		}
	}
}

func (owner *linkOwner) sendDataAck(ctx context.Context) error {
	owner.mu.Lock()
	if owner.closed || owner.closing {
		owner.mu.Unlock()
		return net.ErrClosed
	}
	wire := owner.active
	remote := cloneAddr(owner.peerRemote)
	generation := owner.localGeneration
	receiveNext := owner.receiveNext
	owner.receiveSinceAck = 0
	owner.mu.Unlock()
	payload, err := marshalOuterDataAck(receiveNext)
	if err != nil {
		return err
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: outerTypeDataAck, Sender: owner.role, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		return err
	}
	n, err := wire.writeTo(ctx, datagram, remote)
	if err != nil {
		owner.noteActiveOuterMTUFailure(wire, err)
		return err
	}
	if n != len(datagram) {
		return fmt.Errorf("gvisor: short packet-link DATA_ACK write %d/%d", n, len(datagram))
	}
	return nil
}

func (owner *linkOwner) queueDataReplay() {
	select {
	case owner.dataReplayWake <- struct{}{}:
	default:
	}
}

func (owner *linkOwner) dataReplayLoop() {
	for {
		select {
		case <-owner.dataReplayWake:
			if err := owner.replayOnCurrent(owner.lifetimeCtx); err != nil && !errors.Is(err, context.Canceled) &&
				!errors.Is(err, net.ErrClosed) {
				faultReason := leafmobility.RefreshReasonReplayFailure
				if errors.Is(err, ErrOuterMTU) {
					faultReason = leafmobility.RefreshReasonOuterMTUFailure
				}
				if !owner.publishWireFailure(faultReason) {
					owner.failClosed(err)
				}
			}
		case <-owner.done:
			return
		}
	}
}

func (owner *linkOwner) replayOnCurrent(ctx context.Context) error {
	owner.mu.Lock()
	packetCount := len(owner.replayPackets)
	if packetCount > maxCurrentReplayPackets {
		packetCount = maxCurrentReplayPackets
	}
	packets := make([]packetReplay, packetCount)
	for index, replay := range owner.replayPackets[:packetCount] {
		packets[index] = packetReplay{sequence: replay.sequence, packet: append([]byte(nil), replay.packet...)}
	}
	owner.replayActivations++
	owner.replayTransmitted += uint64(len(packets))
	for _, replay := range packets {
		owner.replayTXBytes += uint64(len(replay.packet))
	}
	owner.mu.Unlock()
	for _, replay := range packets {
		owner.sendMu.Lock()
		owner.mu.Lock()
		if owner.closed || owner.closing {
			owner.mu.Unlock()
			owner.sendMu.Unlock()
			return net.ErrClosed
		}
		if owner.activationPending {
			changed, done := owner.change, owner.done
			owner.mu.Unlock()
			owner.sendMu.Unlock()
			select {
			case <-changed:
				owner.queueDataReplay()
			case <-done:
				return net.ErrClosed
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}
		wire := owner.active
		remote := cloneAddr(owner.peerRemote)
		generation := owner.localGeneration
		owner.mu.Unlock()
		encoded, err := encodeOuterData(
			owner.id, generation, replay.sequence, replay.packet, owner.secret, owner.role,
		)
		if err == nil {
			var n int
			n, err = wire.writeTo(ctx, encoded, remote)
			if err == nil && n != len(encoded) {
				err = fmt.Errorf("gvisor: short current replay write %d/%d", n, len(encoded))
			}
		}
		owner.sendMu.Unlock()
		if err != nil {
			owner.noteActiveOuterMTUFailure(wire, err)
			return err
		}
		if err := owner.completeOuterMTURecovery(len(encoded)); err != nil {
			return err
		}
	}
	return nil
}

func (owner *linkOwner) replayOnCandidate(
	ctx context.Context,
	candidate *packetWire,
	remote net.Addr,
	generation uint64,
) error {
	owner.mu.Lock()
	packets := make([]packetReplay, len(owner.replayPackets))
	for index, replay := range owner.replayPackets {
		packets[index] = packetReplay{sequence: replay.sequence, packet: append([]byte(nil), replay.packet...)}
	}
	owner.replayActivations++
	owner.replayTransmitted += uint64(len(packets))
	for _, replay := range packets {
		owner.replayTXBytes += uint64(len(replay.packet))
	}
	owner.mu.Unlock()
	for _, replay := range packets {
		encoded, err := encodeOuterData(
			owner.id, generation, replay.sequence, replay.packet, owner.secret, owner.role,
		)
		if err != nil {
			return err
		}
		n, err := candidate.writeTo(ctx, encoded, remote)
		if err != nil {
			owner.noteActiveOuterMTUFailure(candidate, err)
			return err
		}
		if n != len(encoded) {
			return fmt.Errorf("gvisor: short replay write %d/%d", n, len(encoded))
		}
		if err := owner.completeOuterMTURecovery(len(encoded)); err != nil {
			return err
		}
	}
	return nil
}

func (owner *linkOwner) observeRefresh(ctx context.Context) bool {
	owner.mu.Lock()
	if owner.closed || owner.closing {
		owner.mu.Unlock()
		return false
	}
	source := outerRefreshRouteSnapshot{
		active: owner.active, remote: cloneAddr(owner.peerRemote),
		localGeneration: owner.localGeneration, peerGeneration: owner.peerGeneration,
		incarnation: owner.incarnation,
	}
	owner.mu.Unlock()
	observation, err := owner.observeOuterRoute(ctx, source.active, source.remote)
	owner.refreshStateMu.Lock()
	owner.mu.Lock()
	if !owner.refreshRouteSnapshotCurrentLocked(source) {
		owner.mu.Unlock()
		owner.refreshStateMu.Unlock()
		return true
	}
	if owner.pendingRefresh != nil {
		owner.mu.Unlock()
		owner.refreshStateMu.Unlock()
		return true
	}
	if err != nil {
		snapshot, changed, stateErr := owner.refreshState.MarkUnavailable()
		owner.mu.Unlock()
		owner.refreshStateMu.Unlock()
		if stateErr == nil && changed {
			return owner.emitRefresh(leafmobility.RefreshReasonRouteSourceUnavailable, snapshot)
		}
		return stateErr == nil
	}
	snapshot, stateErr := owner.refreshState.Update(owner.refreshSourceDigestLocked(observation))
	if stateErr != nil {
		owner.mu.Unlock()
		owner.refreshStateMu.Unlock()
		return false
	}
	fault := owner.wireFault
	faultReason := owner.wireFaultReason
	base := owner.routeBaseline
	sent := owner.refreshSent
	if fault && observation.digest != sent {
		owner.refreshSent = observation.digest
		owner.mu.Unlock()
		owner.refreshStateMu.Unlock()
		return owner.emitRefresh(faultReason, snapshot)
	}
	if !fault && observation.digest != base && observation.digest != sent {
		owner.refreshSent = observation.digest
		owner.mu.Unlock()
		owner.refreshStateMu.Unlock()
		return owner.emitRefresh(leafmobility.RefreshReasonRouteSourceChanged, snapshot)
	}
	if !fault && observation.digest == base && sent != ([sha256.Size]byte{}) {
		owner.refreshSent = [sha256.Size]byte{}
		owner.mu.Unlock()
		owner.refreshStateMu.Unlock()
		return owner.emitRefresh(leafmobility.RefreshReasonRouteSourceRestored, snapshot)
	}
	owner.mu.Unlock()
	owner.refreshStateMu.Unlock()
	return !fault || sent != ([sha256.Size]byte{})
}

type outerRefreshRouteSnapshot struct {
	active                          *packetWire
	remote                          net.Addr
	localGeneration, peerGeneration uint64
	incarnation                     uint64
}

// refreshSourceDigestLocked binds route evidence to the exact packet-link
// owner generation. A relay can preserve the server-visible UDP tuple while a
// peer commit advances generation, so route evidence alone cannot revoke an
// already-minted mobility attempt.
func (owner *linkOwner) refreshSourceDigestLocked(observation routeObservation) [sha256.Size]byte {
	if owner == nil || observation.digest == ([sha256.Size]byte{}) || owner.id == (linkID{}) ||
		owner.incarnation == 0 || owner.localGeneration == 0 || owner.peerGeneration == 0 {
		return [sha256.Size]byte{}
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("GVRS1"))
	_, _ = hash.Write(owner.id[:])
	_, _ = hash.Write(owner.virtualIP[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], owner.incarnation)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], owner.localGeneration)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], owner.peerGeneration)
	_, _ = hash.Write(scalar[:])
	_, _ = hash.Write(observation.digest[:])
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func (owner *linkOwner) refreshRouteSnapshotCurrentLocked(source outerRefreshRouteSnapshot) bool {
	return owner != nil && !owner.closed && !owner.closing && owner.active == source.active &&
		owner.localGeneration == source.localGeneration && owner.peerGeneration == source.peerGeneration &&
		owner.incarnation == source.incarnation && addrEqualOnWire(source.active, owner.peerRemote, source.remote)
}

func (owner *linkOwner) publishWireFailure(reason leafmobility.RefreshReason) bool {
	switch reason {
	case leafmobility.RefreshReasonLinkUnresponsive,
		leafmobility.RefreshReasonLocalReadFailure,
		leafmobility.RefreshReasonLocalWriteFailure,
		leafmobility.RefreshReasonOuterMTUFailure,
		leafmobility.RefreshReasonReplayStalled,
		leafmobility.RefreshReasonReplayFailure,
		leafmobility.RefreshReasonLivenessProbeFailure:
	default:
		return false
	}
	owner.mu.Lock()
	if !owner.wireFault {
		owner.wireFault = true
		owner.wireFaultReason = reason
	}
	owner.mu.Unlock()
	owner.refreshMu.Lock()
	available := owner.refreshEmitter != nil && owner.refreshFn != nil
	owner.refreshMu.Unlock()
	if !available {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), outerWriteBound)
	handled := owner.observeRefresh(ctx)
	cancel()
	return handled
}

func (owner *linkOwner) emitRefresh(reason leafmobility.RefreshReason, source leafmobility.RefreshSourceSnapshot) bool {
	if owner == nil || owner.refreshEmitter == nil {
		return false
	}
	evidence, err := owner.refreshEmitter.Observe(reason, source)
	if err != nil {
		return false
	}
	owner.refreshMu.Lock()
	if owner.refreshFn == nil || owner.refreshEvents == nil {
		owner.refreshMu.Unlock()
		return false
	}
	epoch := owner.refreshEpoch
	queued := false
	select {
	case owner.refreshEvents <- evidence:
		queued = true
	default:
	}
	owner.refreshMu.Unlock()
	if !queued {
		owner.tripRefreshCircuit(epoch, errRefreshQueueFull)
	}
	return queued
}

func (owner *linkOwner) commitRefresh(evidence leafmobility.RefreshEvidence) error {
	if owner == nil || owner.refreshState == nil {
		return errors.New("gvisor: packet-link mobility refresh is unavailable")
	}
	owner.refreshStateMu.Lock()
	defer owner.refreshStateMu.Unlock()
	if _, err := owner.refreshState.DigestForCommit(evidence); err != nil {
		return err
	}
	owner.mu.Lock()
	pending := owner.pendingRefresh
	if owner.closed || owner.closing || pending == nil || pending.wire != owner.active ||
		pending.localGeneration != owner.localGeneration || pending.peerGeneration != owner.peerGeneration ||
		!addrEqualOnWire(owner.active, pending.remote, owner.peerRemote) || pending.route.digest == ([sha256.Size]byte{}) {
		owner.mu.Unlock()
		return errors.New("gvisor: staged packet-link refresh baseline is no longer current")
	}
	routeDigest := pending.route.digest
	owner.routeBaseline = routeDigest
	owner.refreshSent = [sha256.Size]byte{}
	owner.wireFault = false
	owner.wireFaultReason = leafmobility.RefreshReasonInvalid
	owner.pendingRefresh = nil
	owner.resetLivenessLocked(time.Now())
	_, err := owner.refreshState.Update(owner.refreshSourceDigestLocked(pending.route))
	owner.mu.Unlock()
	return err
}

func addrEqual(left, right net.Addr) bool {
	if left == nil || right == nil || left.Network() != right.Network() {
		return false
	}
	leftUDP, leftOK := left.(*net.UDPAddr)
	rightUDP, rightOK := right.(*net.UDPAddr)
	if leftOK && rightOK {
		return leftUDP.Port == rightUDP.Port && outerUDPZonesEqual(leftUDP.Zone, rightUDP.Zone) &&
			leftUDP.IP.Equal(rightUDP.IP)
	}
	return left.String() == right.String()
}

func cloneAddr(value net.Addr) net.Addr {
	if value == nil {
		return nil
	}
	if udp, ok := value.(*net.UDPAddr); ok {
		return &net.UDPAddr{IP: append(net.IP(nil), udp.IP...), Port: udp.Port, Zone: udp.Zone}
	}
	return value
}
