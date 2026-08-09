package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
)

const (
	leafMobilityRetryInterval             = 200 * time.Millisecond
	leafMobilityExecutionWatchdogInterval = 10 * time.Millisecond
	leafMobilityExecutionCleanupMaxDelay  = 5 * time.Second
	leafMobilityFailClosedStepTimeout     = 5 * time.Second
	leafMobilityRecordLimit               = sendHistoryWindow + sendControlReserve
	leafMobilityOOBRecordLimit            = leafMobilityRecordLimit * 6
)

var (
	ErrLeafMobilityAuthorityBusy         = errors.New("engine: leaf mobility authority is busy")
	ErrLeafMobilityAdmissionBusy         = errors.New("engine: leaf admission overlaps mobility authority")
	ErrLeafMobilityRejected              = errors.New("engine: peer rejected leaf mobility transaction")
	ErrLeafMobilityOutcomeUnknown        = errors.New("engine: leaf mobility transaction outcome is unknown")
	errLeafMobilityResponseUnavailable   = errors.New("engine: leaf mobility response route is unavailable")
	errLeafMobilityResolutionUnpublished = errors.New("engine: leaf mobility resolution was not published")
)

type leafMobilityMessageKind uint8

const (
	leafMobilityMessagePrepare leafMobilityMessageKind = iota + 1
	leafMobilityMessageAck
	leafMobilityMessageCommit
)

type leafMobilityMessage struct {
	kind     leafMobilityMessageKind
	source   PathRef
	seq      uint64
	replayed bool
	prepare  proto.LeafMobilityPeerPlanPrepare
	ack      proto.LeafMobilityPeerPlanAck
	commit   proto.LeafMobilityPeerPlanCommit
}

type leafMobilityMessageKey struct {
	kind          leafMobilityMessageKind
	phase         proto.LeafMobilityPeerPlanAckPhase
	stage         proto.LeafMobilityPeerPlanCommitStage
	transactionID [16]byte
	digest        proto.LeafMobilityProposalDigest
	source        PathRef
	seq           uint64
}

type leafMobilityOOBKey struct {
	source PathRef
	seq    uint64
}

type leafMobilityOOBRecord struct {
	digest      proto.FrameDigest
	retireAfter time.Time
}

type leafMobilityAckEvent struct {
	source PathRef
	seq    uint64
	ack    proto.LeafMobilityPeerPlanAck
}

type outgoingLeafMobilityTransaction struct {
	source            PathRef
	sourceSlot        *pathSlot
	prepare           proto.LeafMobilityPeerPlanPrepare
	digest            proto.LeafMobilityProposalDigest
	resourceTx        *leafmobility.ResourceTransaction
	claim             *leafmobility.Claim
	commit            proto.LeafMobilityPeerPlanCommit
	commitFrame       []byte
	resolution        proto.LeafMobilityPeerPlanCommit
	resolutionFrame   []byte
	preparedSeq       uint64
	finalSeq          uint64
	releasedSeq       uint64
	preparedAck       proto.LeafMobilityPeerPlanAck
	finalAck          proto.LeafMobilityPeerPlanAck
	releasedAck       proto.LeafMobilityPeerPlanAck
	preparedDelivered bool
	finalDelivered    bool
	releasedDelivered bool
	prepared          chan leafMobilityAckEvent
	final             chan leafMobilityAckEvent
	released          chan leafMobilityAckEvent
	preempt           chan error
	deadline          time.Time
	gateHeld          atomic.Bool
	commitIssued      atomic.Bool
	resolutionIntent  atomic.Uint32
	abandoned         atomic.Bool
	recoveryOwned     atomic.Bool
	authority         *leafMobilityAuthorityToken
	recoveryOnce      sync.Once
	recoveryWriteMu   sync.Mutex
	recoveryWrite     <-chan leafMobilityFrameResult
}

type outgoingLeafMobilityRecoveryPhase uint8

const (
	outgoingLeafMobilityRecoveryFinal outgoingLeafMobilityRecoveryPhase = iota + 1
	outgoingLeafMobilityRecoveryRollbackPublication
	outgoingLeafMobilityRecoveryReleased
)

type incomingLeafMobilityState uint8

const (
	incomingLeafMobilityPlanning incomingLeafMobilityState = iota + 1
	incomingLeafMobilityPrepared
	incomingLeafMobilitySuperseded
	incomingLeafMobilityCommitted
	incomingLeafMobilityTerminalPending
	incomingLeafMobilityOutcomeUnknown
)

type incomingLeafMobilityTransaction struct {
	source        PathRef
	sourceSlot    *pathSlot
	prepare       proto.LeafMobilityPeerPlanPrepare
	prepareSeq    uint64
	digest        proto.LeafMobilityProposalDigest
	ledger        leafMobilityPeerGenerationReservation
	ledgerActive  bool
	plan          leafmobility.Plan
	claim         *leafmobility.Claim
	hold          *leafmobility.AdmissionReservation
	prepared      proto.LeafMobilityPeerPlanAck
	preparedFrame []byte
	commit        proto.LeafMobilityPeerPlanCommit
	commitSeq     uint64
	final         proto.LeafMobilityPeerPlanAck
	finalFrame    []byte
	resolution    proto.LeafMobilityPeerPlanCommit
	resolutionSeq uint64
	released      proto.LeafMobilityPeerPlanAck
	releasedFrame []byte
	deadline      time.Time
	retireAfter   time.Time
	state         incomingLeafMobilityState
}

type completedLeafMobilityTransaction struct {
	source        PathRef
	sourceSlot    *pathSlot
	prepare       proto.LeafMobilityPeerPlanPrepare
	prepareSeq    uint64
	digest        proto.LeafMobilityProposalDigest
	prepared      proto.LeafMobilityPeerPlanAck
	preparedFrame []byte
	commit        proto.LeafMobilityPeerPlanCommit
	commitSeq     uint64
	final         proto.LeafMobilityPeerPlanAck
	finalFrame    []byte
	resolution    proto.LeafMobilityPeerPlanCommit
	resolutionSeq uint64
	released      proto.LeafMobilityPeerPlanAck
	releasedFrame []byte
	retireAfter   time.Time
}

type rejectedLeafMobilityTransaction struct {
	source      PathRef
	prepare     proto.LeafMobilityPeerPlanPrepare
	prepareSeq  uint64
	digest      proto.LeafMobilityProposalDigest
	ack         proto.LeafMobilityPeerPlanAck
	frame       []byte
	retireAfter time.Time
}

type actorLeafMobilityTombstone struct {
	source      PathRef
	digest      proto.LeafMobilityProposalDigest
	prepare     proto.LeafMobilityPeerPlanPrepare
	commit      proto.LeafMobilityPeerPlanCommit
	resolution  proto.LeafMobilityPeerPlanCommit
	preparedSeq uint64
	finalSeq    uint64
	releasedSeq uint64
	preparedAck proto.LeafMobilityPeerPlanAck
	finalAck    proto.LeafMobilityPeerPlanAck
	releasedAck proto.LeafMobilityPeerPlanAck
	retireAfter time.Time
}

type leafMobilityRuntime struct {
	sendGate       chan struct{}
	responseGate   chan struct{}
	mu             sync.Mutex
	outgoing       *outgoingLeafMobilityTransaction
	incoming       map[[16]byte]*incomingLeafMobilityTransaction
	completed      map[[16]byte]completedLeafMobilityTransaction
	rejected       map[[16]byte]rejectedLeafMobilityTransaction
	actorTerminal  map[[16]byte]actorLeafMobilityTombstone
	peerLedger     *LeafMobilityPeerLedger
	sessionLedger  *LeafMobilityPeerLedger
	sessionPeer    proto.InstanceID
	sessionEpoch   proto.SessionEpoch
	messageSeq     atomic.Uint64
	inbox          chan leafMobilityMessage
	queueMu        sync.Mutex
	queued         map[leafMobilityMessageKey]struct{}
	oobMu          sync.Mutex
	oobSeen        map[leafMobilityOOBKey]leafMobilityOOBRecord
	controlWriteMu sync.Mutex
	controlWrites  map[PathRef]map[*pathSlot]uint32
	writerMu       sync.Mutex
	writerClosing  bool
	writerWG       sync.WaitGroup
	asyncWG        sync.WaitGroup
}

func newLeafMobilityRuntime() *leafMobilityRuntime {
	return &leafMobilityRuntime{
		sendGate:      make(chan struct{}, 1),
		responseGate:  make(chan struct{}, 1),
		incoming:      make(map[[16]byte]*incomingLeafMobilityTransaction),
		completed:     make(map[[16]byte]completedLeafMobilityTransaction),
		rejected:      make(map[[16]byte]rejectedLeafMobilityTransaction),
		actorTerminal: make(map[[16]byte]actorLeafMobilityTombstone),
		peerLedger:    NewLeafMobilityPeerLedger(),
		inbox:         make(chan leafMobilityMessage, 64),
		queued:        make(map[leafMobilityMessageKey]struct{}),
		oobSeen:       make(map[leafMobilityOOBKey]leafMobilityOOBRecord),
		controlWrites: make(map[PathRef]map[*pathSlot]uint32),
	}
}

// LeafMobilityAuthority remains bound to the engine route ledger and peer
// reservation. It cannot be completed by manipulating leafmobility or proto
// values directly; only a correlated RELEASED receipt releases both sides.
type LeafMobilityAuthority struct {
	token *leafMobilityAuthorityToken
}

type leafMobilityAuthorityToken struct {
	engine           *Engine
	outgoing         *outgoingLeafMobilityTransaction
	expiry           *time.Timer
	expiryGeneration uint64
	expiryMu         sync.Mutex
	resolveMu        sync.Mutex
	consumed         bool
	execution        *leafmobility.Execution
	done             chan struct{}
	once             sync.Once
	dispatchMu       sync.Mutex
	dispatchSlot     *pathSlot
	dispatchFenced   bool
	localCleanupOnce sync.Once
}

type LeafMobilityPermit struct {
	token     *leafMobilityAuthorityToken
	execution *leafmobility.Execution
}

func (a *LeafMobilityAuthority) State() leafmobility.ResourceTransactionState {
	if a == nil || a.token == nil || a.token.outgoing == nil || a.token.outgoing.resourceTx == nil {
		return leafmobility.ResourceTransactionInvalid
	}
	return a.token.outgoing.resourceTx.State()
}

func (a *LeafMobilityAuthority) Consume() (*LeafMobilityPermit, error) {
	if a == nil || a.token == nil || a.token.engine == nil || a.token.outgoing == nil || a.token.outgoing.resourceTx == nil {
		return nil, leafmobility.ErrAuthorityStale
	}
	token := a.token
	token.resolveMu.Lock()
	select {
	case <-token.done:
		token.resolveMu.Unlock()
		return nil, leafmobility.ErrAuthorityStale
	default:
	}
	if token.consumed {
		token.resolveMu.Unlock()
		return nil, leafmobility.ErrAuthorityConsumed
	}
	token.engine.pathsMu.RLock()
	if token.engine.isClosed() || token.engine.sendClosing.Load() {
		token.engine.pathsMu.RUnlock()
		token.outcomeUnknown(fmt.Errorf("engine is closing"))
		token.resolveMu.Unlock()
		return nil, net.ErrClosed
	}
	if err := token.engine.validateLeafMobilityAuthoritySourceLocked(token.outgoing); err != nil {
		token.engine.pathsMu.RUnlock()
		token.outcomeUnknown(err)
		token.resolveMu.Unlock()
		return nil, err
	}
	plan := token.outgoing.resourceTx.Snapshot().Plan
	prepared := token.outgoing.preparedAck
	agreement := leafmobility.PeerAgreement{
		Binding:                 token.outgoing.prepare.LeafMobilityPeerPlanBinding,
		Generation:              prepared.Generation,
		ActorEndpointGeneration: prepared.ActorEndpointGeneration,
		PeerEndpointGeneration:  prepared.PeerEndpointGeneration,
		ActorPlanDigest:         token.outgoing.prepare.ActorPlanDigest,
		ProposalDigest:          prepared.ProposalDigest,
		PeerPlanDigest:          prepared.PeerPlanDigest,
		AgreementDigest:         prepared.AgreementDigest,
		ReservationID:           prepared.ReservationID,
	}
	execution, err := token.engine.leafIssuer.ConsumeExecution(
		token.outgoing.claim, token.outgoing.resourceTx, plan, agreement,
	)
	token.engine.pathsMu.RUnlock()
	if err != nil {
		token.resolveMu.Unlock()
		return nil, err
	}
	token.consumed = true
	token.execution = execution
	token.resolveMu.Unlock()
	permit := &LeafMobilityPermit{token: token, execution: execution}
	permit.armExecutionWatchdog()
	return permit, nil
}

func (p *LeafMobilityPermit) armExecutionWatchdog() {
	if p == nil || p.token == nil || p.token.engine == nil || p.execution == nil {
		return
	}
	watch := func() { p.watchExecutionTerminal() }
	if !p.token.engine.startLeafMobilityAsync(watch) {
		watch()
	}
}

func (p *LeafMobilityPermit) watchExecutionTerminal() {
	forwardDeadline := p.execution.ForwardDeadline()
	if forwardDeadline.IsZero() {
		return
	}
	timer := time.NewTimer(max(time.Until(forwardDeadline), 0))
	defer timer.Stop()
	select {
	case <-p.token.done:
		p.forceLocalExecutionClosed()
		return
	case <-p.token.engine.closed:
		p.forceLocalExecutionClosed()
		return
	case <-timer.C:
	}

	cleanupCtx, cancel := context.WithDeadline(context.Background(), p.token.outgoing.deadline)
	defer cancel()
	ticker := time.NewTicker(leafMobilityExecutionWatchdogInterval)
	defer ticker.Stop()
	for {
		var err error
		activated := false
		switch p.execution.State() {
		case leafmobility.ExecutionActivated:
			err = p.Complete(cleanupCtx)
		case leafmobility.ExecutionPublished, leafmobility.ExecutionActivationRequired:
			err = p.ActivateDriver(cleanupCtx)
			activated = err == nil
		case leafmobility.ExecutionFailClosedRequired:
			_ = p.failClosedAfterUnprovenCommit(leafmobility.ErrIncarnationUnproven)
			return
		case leafmobility.ExecutionAuthorized, leafmobility.ExecutionPrepared,
			leafmobility.ExecutionStaged, leafmobility.ExecutionPublishAuthorized,
			leafmobility.ExecutionRollbackRequired,
			leafmobility.ExecutionRolledBack:
			err = p.RolledBack(cleanupCtx)
		case leafmobility.ExecutionFailedClosed, leafmobility.ExecutionInvalid:
			p.token.outcomeUnknownSerialized(leafmobility.ErrExecutionState)
			return
		}
		if activated {
			continue
		}
		if err == nil {
			return
		}
		if errors.Is(err, ErrLeafMobilityOutcomeUnknown) || errors.Is(err, leafmobility.ErrAuthorityStale) {
			return
		}
		select {
		case <-p.token.done:
			p.forceLocalExecutionClosed()
			return
		case <-p.token.engine.closed:
			p.forceLocalExecutionClosed()
			return
		case <-cleanupCtx.Done():
			p.forceLocalExecutionClosed()
			p.token.outcomeUnknownSerialized(cleanupCtx.Err())
			return
		case <-ticker.C:
		}
	}
}

func (p *LeafMobilityPermit) forceLocalExecutionClosed() {
	if p == nil || p.token == nil || p.execution == nil {
		return
	}
	p.token.localCleanupOnce.Do(func() { p.forceLocalExecutionClosedOnce() })
}

func (p *LeafMobilityPermit) forceLocalExecutionClosedOnce() {
	p.execution.CancelForward()
	retryDelay := leafMobilityExecutionWatchdogInterval
	retry := func() {
		time.Sleep(retryDelay)
		if retryDelay < leafMobilityExecutionCleanupMaxDelay {
			retryDelay *= 2
			if retryDelay > leafMobilityExecutionCleanupMaxDelay {
				retryDelay = leafMobilityExecutionCleanupMaxDelay
			}
		}
	}
	for {
		switch p.execution.State() {
		case leafmobility.ExecutionActivated:
			if err := p.execution.FinalizePublished(); err == nil {
				p.token.releaseExecutionDispatch()
				return
			}
			retry()
			continue
		case leafmobility.ExecutionRolledBack:
			if err := p.execution.FinalizeRolledBack(); err == nil {
				p.token.releaseExecutionDispatch()
				return
			}
			retry()
			continue
		case leafmobility.ExecutionFailedClosed, leafmobility.ExecutionInvalid:
			p.token.releaseExecutionDispatch()
			return
		}
		if err := p.execution.Rollback(context.Background()); err == nil {
			if err := p.execution.FinalizeRolledBack(); err == nil {
				p.token.releaseExecutionDispatch()
				return
			}
		} else if !errors.Is(err, leafmobility.ErrExecutionBusy) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), leafMobilityFailClosedStepTimeout)
			cleanupErr := p.execution.FailClosed(cleanupCtx)
			cancel()
			if cleanupErr == nil {
				p.token.releaseExecutionDispatch()
				return
			}
		}
		retry()
	}
}

func (p *LeafMobilityPermit) startLocalExecutionCleanup() {
	if p == nil || p.token == nil || p.token.engine == nil || p.execution == nil {
		return
	}
	cleanup := func() { p.forceLocalExecutionClosed() }
	if !p.token.engine.startLeafMobilityAsync(cleanup) {
		cleanup()
	}
}

func (p *LeafMobilityPermit) failClosedAfterUnprovenCommit(cause error) error {
	if p == nil || p.token == nil || p.token.engine == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	terminalErr := fmt.Errorf("%w: irreversible driver commit is unproven: %w", ErrLeafMobilityOutcomeUnknown, cause)
	p.token.engine.sendClosing.Store(true)
	p.token.engine.setCloseErr(terminalErr)
	p.token.outcomeUnknownSerialized(terminalErr)
	p.startLocalExecutionCleanup()
	go p.token.engine.Close()
	return terminalErr
}

// Rollback resolves an authority that was never consumed by a destructive
// driver. It still requires a peer RELEASED receipt because FINAL already
// advanced the transaction generation.
func (a *LeafMobilityAuthority) Rollback(ctx context.Context) error {
	if a == nil || a.token == nil || a.token.outgoing == nil || a.token.outgoing.resourceTx == nil {
		return leafmobility.ErrAuthorityStale
	}
	return a.token.resolve(ctx, leafmobility.ResolutionAbort, false)
}

func (p *LeafMobilityPermit) State() leafmobility.ResourceTransactionState {
	if p == nil || p.token == nil || p.token.outgoing == nil || p.token.outgoing.resourceTx == nil {
		return leafmobility.ResourceTransactionInvalid
	}
	return p.token.outgoing.resourceTx.State()
}

func (p *LeafMobilityPermit) ExecutionState() leafmobility.ExecutionState {
	if p == nil || p.execution == nil {
		return leafmobility.ExecutionInvalid
	}
	return p.execution.State()
}

func (p *LeafMobilityPermit) Prepare(ctx context.Context) error {
	if p == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	if err := p.validateExecutionSource(); err != nil {
		return err
	}
	if err := p.token.fenceExecutionDispatch(); err != nil {
		return err
	}
	if err := p.execution.Prepare(ctx); err != nil {
		return err
	}
	return p.validateExecutionSource()
}

func (t *leafMobilityAuthorityToken) fenceExecutionDispatch() error {
	if t == nil || t.outgoing == nil || t.outgoing.sourceSlot == nil {
		return leafmobility.ErrAuthorityStale
	}
	t.dispatchMu.Lock()
	defer t.dispatchMu.Unlock()
	if t.dispatchFenced {
		return nil
	}
	slot := t.outgoing.sourceSlot
	if slot.id != t.outgoing.source.ID || slot.owner != t.outgoing.source.Owner || !slot.tryFenceDispatch() {
		return ErrPathTXFenced
	}
	t.dispatchSlot = slot
	t.dispatchFenced = true
	return nil
}

func (t *leafMobilityAuthorityToken) releaseExecutionDispatch() {
	if t == nil {
		return
	}
	t.dispatchMu.Lock()
	if !t.dispatchFenced {
		t.dispatchMu.Unlock()
		return
	}
	slot := t.dispatchSlot
	t.dispatchSlot = nil
	t.dispatchFenced = false
	t.dispatchMu.Unlock()
	if slot != nil {
		slot.unfenceDispatch()
	}
}

func (p *LeafMobilityPermit) Stage(ctx context.Context) error {
	if p == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	if err := p.validateExecutionSource(); err != nil {
		return err
	}
	if err := p.execution.Stage(ctx); err != nil {
		return err
	}
	return p.validateExecutionSource()
}

func (p *LeafMobilityPermit) PublishDriver(ctx context.Context) error {
	if p == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	if err := p.validateExecutionSource(); err != nil {
		return err
	}
	if err := p.execution.Publish(ctx); err != nil {
		return err
	}
	return nil
}

func (p *LeafMobilityPermit) ActivateDriver(ctx context.Context) error {
	if p == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	return p.execution.Activate(ctx)
}

// authorizePublish sends COMMIT_INTENT only after the driver has produced a
// private successor. Correlated FINAL authorizes the exact Execution to cross
// its owner-swap boundary; it does not itself publish anything locally.
func (t *leafMobilityAuthorityToken) authorizePublish(ctx context.Context) error {
	if t == nil || t.engine == nil || t.outgoing == nil || t.outgoing.resourceTx == nil || t.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.resolveMu.Lock()
	rearmExpiry := true
	defer func() {
		if rearmExpiry {
			t.armExpiry()
		}
		t.resolveMu.Unlock()
	}()
	select {
	case <-t.done:
		rearmExpiry = false
		return leafmobility.ErrAuthorityStale
	default:
	}
	if !t.consumed || t.execution.State() != leafmobility.ExecutionStaged {
		return leafmobility.ErrExecutionState
	}
	if err := t.engine.validateLeafMobilityAuthoritySource(t.outgoing); err != nil {
		return err
	}
	publicationDigest, err := t.execution.PublicationDigest()
	if err != nil {
		return err
	}
	prepared := t.outgoing.preparedAck
	t.outgoing.commit = proto.LeafMobilityPeerPlanCommit{
		LeafMobilityPeerPlanBinding: t.outgoing.prepare.LeafMobilityPeerPlanBinding,
		Stage:                       proto.LeafMobilityPeerPlanCommitStageCommit,
		Generation:                  prepared.Generation,
		ActorEndpointGeneration:     prepared.ActorEndpointGeneration,
		PeerEndpointGeneration:      prepared.PeerEndpointGeneration,
		ProposalDigest:              prepared.ProposalDigest,
		PeerPlanDigest:              prepared.PeerPlanDigest,
		AgreementDigest:             prepared.AgreementDigest,
		ReservationID:               prepared.ReservationID,
		PublicationDigest:           publicationDigest,
	}
	t.stopExpiry()
	txCtx, cancel := context.WithDeadline(ctx, t.outgoing.deadline)
	defer cancel()
	_, sendErr, pending := t.engine.sendLeafMobilityFrameWithContext(txCtx, func(writeCtx context.Context) ([]byte, error) {
		return t.engine.sendLeafMobilityCommitForOutgoingContext(writeCtx, t.outgoing, t.outgoing.commit, func(frame []byte) error {
			t.engine.leafTx.mu.Lock()
			defer t.engine.leafTx.mu.Unlock()
			if t.engine.leafTx.outgoing != t.outgoing {
				return leafmobility.ErrAuthorityStale
			}
			if err := t.outgoing.resourceTx.MarkCommitPublished(); err != nil {
				return err
			}
			t.outgoing.commitFrame = append([]byte(nil), frame...)
			t.outgoing.commitIssued.Store(true)
			return nil
		})
	})
	commitPublished := t.outgoing.commitIssued.Load()
	if pending != nil {
		rearmExpiry = false
		t.outgoing.abandoned.Store(true)
		finish := func() { t.engine.finishAbandonedLeafMobilityCommitWrite(t.outgoing, pending) }
		if !t.engine.startLeafMobilityAsync(finish) {
			finish()
		}
		return fmt.Errorf("%w: commit publication pending: %v", ErrLeafMobilityOutcomeUnknown, sendErr)
	}
	if sendErr != nil {
		if commitPublished {
			rearmExpiry = false
			_ = t.outgoing.resourceTx.MarkOutcomeUnknown()
			t.engine.startOutgoingLeafMobilityRecovery(t.outgoing, outgoingLeafMobilityRecoveryFinal)
			return fmt.Errorf("%w: commit publication: %v", ErrLeafMobilityOutcomeUnknown, sendErr)
		}
		return sendErr
	}

	retry := time.NewTicker(leafMobilityRetryInterval)
	defer retry.Stop()
	frame := t.engine.outgoingCommitFrame(t.outgoing)
	for {
		select {
		case <-t.done:
			rearmExpiry = false
			return ErrLeafMobilityOutcomeUnknown
		case <-t.engine.closed:
			rearmExpiry = false
			t.outcomeUnknown(net.ErrClosed)
			return net.ErrClosed
		case <-txCtx.Done():
			rearmExpiry = false
			_ = t.outgoing.resourceTx.MarkOutcomeUnknown()
			t.engine.startOutgoingLeafMobilityRecovery(t.outgoing, outgoingLeafMobilityRecoveryFinal)
			return fmt.Errorf("%w: %v", ErrLeafMobilityOutcomeUnknown, txCtx.Err())
		case <-retry.C:
			_, retryErr, retryPending := t.engine.sendLeafMobilityFrameWithContext(txCtx, func(writeCtx context.Context) ([]byte, error) {
				return frame, t.engine.replayLeafMobilityFrameForOutgoingContext(writeCtx, t.outgoing, frame)
			})
			if retryPending != nil {
				rearmExpiry = false
				t.outgoing.abandoned.Store(true)
				finish := func() { t.engine.finishAbandonedLeafMobilityCommitWrite(t.outgoing, retryPending) }
				if !t.engine.startLeafMobilityAsync(finish) {
					finish()
				}
				return fmt.Errorf("%w: commit retry pending: %v", ErrLeafMobilityOutcomeUnknown, retryErr)
			}
			if retryErr != nil {
				rearmExpiry = false
				_ = t.outgoing.resourceTx.MarkOutcomeUnknown()
				t.engine.startOutgoingLeafMobilityRecovery(t.outgoing, outgoingLeafMobilityRecoveryFinal)
				return fmt.Errorf("%w: commit retry: %v", ErrLeafMobilityOutcomeUnknown, retryErr)
			}
		case event := <-t.outgoing.final:
			if event.source != t.outgoing.source {
				return t.engine.leafMobilityProtocolError(fmt.Errorf("FINAL changed route"))
			}
			if err := event.ack.ValidateForCommit(t.outgoing.commit); err != nil {
				return t.engine.leafMobilityProtocolError(err)
			}
			if event.ack.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
				if rollbackErr := t.execution.Rollback(context.WithoutCancel(txCtx)); rollbackErr != nil {
					rearmExpiry = false
					t.outcomeUnknown(rollbackErr)
					return errors.Join(fmt.Errorf("%w: %s", ErrLeafMobilityRejected, event.ack.Reason), rollbackErr)
				}
				if _, err := reconcileLeafMobilityFinalRejected(t.outgoing.resourceTx); err != nil {
					rearmExpiry = false
					t.outcomeUnknown(err)
					return err
				}
				t.finish()
				rearmExpiry = false
				return fmt.Errorf("%w: %s", ErrLeafMobilityRejected, event.ack.Reason)
			}
			disposition, err := t.execution.ResolveFinalAcceptance(true)
			if err != nil {
				if errors.Is(err, leafmobility.ErrExecutionBusy) {
					rearmExpiry = false
					eventCopy := event
					t.engine.startOutgoingLeafMobilityRecoveryWithFinal(
						t.outgoing, outgoingLeafMobilityRecoveryFinal, &eventCopy,
					)
					return fmt.Errorf("%w: FINAL raced local rollback", ErrLeafMobilityOutcomeUnknown)
				}
				return err
			}
			switch disposition {
			case leafmobility.FinalAcceptanceRollbackOnly:
				rearmExpiry = false
				t.engine.startOutgoingLeafMobilityRecovery(
					t.outgoing, outgoingLeafMobilityRecoveryRollbackPublication,
				)
				return fmt.Errorf("%w: FINAL arrived after COMMIT outcome became unknown", ErrLeafMobilityOutcomeUnknown)
			case leafmobility.FinalAcceptancePublishAllowed:
				return nil
			default:
				return leafmobility.ErrExecutionState
			}
		}
	}
}

func reconcileLeafMobilityFinalRejected(tx *leafmobility.ResourceTransaction) (bool, error) {
	if tx == nil {
		return false, leafmobility.ErrResourceTransactionState
	}
	if err := tx.MarkFinalRejected(); err == nil {
		return false, nil
	} else {
		snapshot := tx.Snapshot()
		if snapshot.State != leafmobility.ResourceTransactionOutcomeUnknown ||
			snapshot.UnknownFrom != leafmobility.ResourceTransactionCommitPublished {
			return false, err
		}
		if reconcileErr := tx.ReconcileFinalRejected(); reconcileErr != nil {
			return false, errors.Join(err, reconcileErr)
		}
		return true, nil
	}
}

func (p *LeafMobilityPermit) validateExecutionSource() error {
	if p == nil || p.token == nil || p.token.engine == nil || p.token.outgoing == nil {
		return leafmobility.ErrAuthorityStale
	}
	p.token.engine.pathsMu.RLock()
	err := p.token.engine.validateLeafMobilityAuthoritySourceLocked(p.token.outgoing)
	p.token.engine.pathsMu.RUnlock()
	return err
}

func (p *LeafMobilityPermit) Complete(ctx context.Context) error {
	if p == nil || p.token == nil || p.token.outgoing == nil || p.token.outgoing.resourceTx == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	if p.execution.State() != leafmobility.ExecutionActivated {
		return leafmobility.ErrExecutionState
	}
	return p.token.resolveCommitted(ctx)
}

func (p *LeafMobilityPermit) RolledBack(ctx context.Context) error {
	if p == nil || p.token == nil || p.token.outgoing == nil || p.token.outgoing.resourceTx == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	if err := p.execution.Rollback(ctx); err != nil {
		return err
	}
	return p.token.resolve(ctx, leafmobility.ResolutionRolledBack, true)
}

// Execute runs the complete local driver transaction, then publishes the
// matching peer resolution. A local failure is never reported as ROLLED_BACK
// until the driver has actually restored its endpoint ownership.
func (p *LeafMobilityPermit) Execute(ctx context.Context) error {
	if p == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	if err := p.Prepare(ctx); err != nil {
		return p.rollbackAfterFailure(ctx, err)
	}
	if err := p.Stage(ctx); err != nil {
		return p.rollbackAfterFailure(ctx, err)
	}
	if err := p.token.authorizePublish(ctx); err != nil {
		select {
		case <-p.token.done:
			return err
		default:
		}
		return p.rollbackAfterFailure(ctx, err)
	}
	if err := p.PublishDriver(ctx); err != nil {
		if p.execution.State() == leafmobility.ExecutionFailClosedRequired {
			return p.failClosedAfterUnprovenCommit(err)
		}
		return p.rollbackAfterFailure(ctx, err)
	}
	if err := p.activateUntilDeadline(ctx); err != nil {
		return p.failClosedAfterUnprovenCommit(err)
	}
	return p.Complete(ctx)
}

func (p *LeafMobilityPermit) activateUntilDeadline(ctx context.Context) error {
	if p == nil || p.execution == nil {
		return leafmobility.ErrAuthorityStale
	}
	parent := context.Background()
	if ctx != nil {
		parent = context.WithoutCancel(ctx)
	}
	activationCtx, cancel := context.WithDeadline(parent, p.execution.Deadline())
	defer cancel()
	delay := leafMobilityExecutionWatchdogInterval
	for {
		if err := p.ActivateDriver(activationCtx); err == nil {
			return nil
		} else if errors.Is(err, leafmobility.ErrExecutionState) || errors.Is(err, leafmobility.ErrAuthorityStale) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-activationCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return activationCtx.Err()
		}
		if delay < leafMobilityExecutionCleanupMaxDelay {
			delay *= 2
			if delay > leafMobilityExecutionCleanupMaxDelay {
				delay = leafMobilityExecutionCleanupMaxDelay
			}
		}
	}
}

func (p *LeafMobilityPermit) rollbackAfterFailure(ctx context.Context, cause error) error {
	if p != nil && p.execution != nil && p.execution.State() == leafmobility.ExecutionFailClosedRequired {
		return p.failClosedAfterUnprovenCommit(cause)
	}
	cleanupParent := context.Background()
	if ctx != nil {
		cleanupParent = context.WithoutCancel(ctx)
	}
	deadline := time.Now()
	if p != nil && p.token != nil && p.token.outgoing != nil {
		deadline = p.token.outgoing.deadline
	}
	cleanupCtx, cancel := context.WithDeadline(cleanupParent, deadline)
	defer cancel()
	return errors.Join(cause, p.RolledBack(cleanupCtx))
}

// NegotiateLeafMobilityAuthority runs PREPARE/PREPARED/COMMIT/FINAL over the
// exact path. The returned authority still owns the session transaction; the
// caller must Rollback it unconsumed, or Consume and then Execute (or complete
// the equivalent phased driver sequence) before its deadline.
func (e *Engine) NegotiateLeafMobilityAuthority(
	ctx context.Context,
	ref PathRef,
	plan leafmobility.Plan,
) (*LeafMobilityAuthority, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if plan.Operation == 0 {
		return nil, leafmobility.ErrBaselinePlan
	}
	claim, sourceSlot, err := e.validateLeafMobilitySource(ref, plan)
	if err != nil {
		return nil, err
	}
	select {
	case e.leafTx.sendGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.closed:
		return nil, net.ErrClosed
	}

	lease := time.Until(plan.Deadline)
	if lease <= 0 {
		<-e.leafTx.sendGate
		return nil, leafmobility.ErrPlanExpired
	}
	if lease > leafmobility.MaxPlanHorizon {
		lease = leafmobility.MaxPlanHorizon
	}
	leaseMillis := uint32(lease / time.Millisecond)
	if leaseMillis == 0 {
		leaseMillis = 1
	}
	binding := e.canonicalLeafMobilityBinding(plan, leaseMillis)
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest(plan.LocalDigest),
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		<-e.leafTx.sendGate
		return nil, err
	}
	outgoing := &outgoingLeafMobilityTransaction{
		source: ref, sourceSlot: sourceSlot, prepare: prepare, digest: digest, deadline: plan.Deadline,
		prepared: make(chan leafMobilityAckEvent, 1), final: make(chan leafMobilityAckEvent, 1),
		released: make(chan leafMobilityAckEvent, 1), preempt: make(chan error, 1),
	}
	outgoing.gateHeld.Store(true)

	e.leafTx.mu.Lock()
	e.pruneLeafMobilityRecordsLocked(time.Now())
	if len(e.leafTx.actorTerminal) >= leafMobilityRecordLimit {
		e.leafTx.mu.Unlock()
		e.releaseLeafMobilityOutgoingGate(outgoing)
		return nil, ErrLeafMobilityAuthorityBusy
	}
	if err := e.arbitrateOutgoingLeafMobilityLocked(protocolActorSide(e.side)); err != nil {
		e.leafTx.mu.Unlock()
		e.releaseLeafMobilityOutgoingGate(outgoing)
		return nil, err
	}
	resourceTx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		e.leafTx.mu.Unlock()
		e.releaseLeafMobilityOutgoingGate(outgoing)
		return nil, err
	}
	outgoing.resourceTx = resourceTx
	outgoing.claim = claim
	e.leafTx.outgoing = outgoing
	e.leafTx.mu.Unlock()

	txCtx, cancel := context.WithDeadline(ctx, plan.Deadline)
	defer cancel()
	if err := resourceTx.MarkProposalPublished(); err != nil {
		_ = resourceTx.Abort()
		e.finishOutgoingLeafMobility(outgoing)
		return nil, err
	}
	prepareFrame, err, pending := e.sendLeafMobilityFrameWithContext(txCtx, func(writeCtx context.Context) ([]byte, error) {
		return e.sendLeafMobilityPrepareContext(writeCtx, ref, prepare)
	})
	if pending != nil {
		outgoing.abandoned.Store(true)
		// The peer may already have observed PREPARE even though the local
		// PathConn has not returned. Keep the resource reservation until its
		// immutable lease expires; caller cancellation only stops waiting.
		finish := func() { e.finishAbandonedLeafMobilityWrite(outgoing, pending) }
		if !e.startLeafMobilityAsync(finish) {
			finish()
		}
		return nil, err
	}
	if err != nil {
		_ = resourceTx.Abort()
		e.finishOutgoingLeafMobility(outgoing)
		return nil, err
	}

	retry := time.NewTicker(leafMobilityRetryInterval)
	defer retry.Stop()
	for {
		select {
		case <-e.closed:
			return nil, e.failOutgoingLeafMobility(outgoing, false, net.ErrClosed)
		case <-txCtx.Done():
			return nil, e.failOutgoingLeafMobility(outgoing, false, txCtx.Err())
		case err := <-outgoing.preempt:
			return nil, e.failOutgoingLeafMobility(outgoing, false, err)
		case <-retry.C:
			_, retryErr, retryPending := e.sendLeafMobilityFrameWithContext(txCtx, func(writeCtx context.Context) ([]byte, error) {
				return prepareFrame, e.replayLeafMobilityFrameContext(writeCtx, ref, prepareFrame)
			})
			if retryPending != nil {
				outgoing.abandoned.Store(true)
				finish := func() { e.finishAbandonedLeafMobilityWrite(outgoing, retryPending) }
				if !e.startLeafMobilityAsync(finish) {
					finish()
				}
				return nil, retryErr
			}
		case event := <-outgoing.prepared:
			if event.source != ref {
				return nil, e.failOutgoingLeafMobility(outgoing, false, e.leafMobilityProtocolError(
					fmt.Errorf("PREPARED arrived on path %+v, want %+v", event.source, ref)))
			}
			if err := event.ack.ValidateForPrepare(prepare); err != nil {
				return nil, e.failOutgoingLeafMobility(outgoing, false, e.leafMobilityProtocolError(err))
			}
			if event.ack.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
				_ = resourceTx.Abort()
				e.finishOutgoingLeafMobility(outgoing)
				return nil, fmt.Errorf("%w: %s", ErrLeafMobilityRejected, event.ack.Reason)
			}
			deadline := time.Now().Add(time.Duration(binding.LeaseMillis) * time.Millisecond)
			if plan.Deadline.Before(deadline) {
				deadline = plan.Deadline
			}
			if err := resourceTx.MarkPrepared(event.ack.Generation, deadline); err != nil {
				return nil, e.failOutgoingLeafMobility(outgoing, false, err)
			}
			outgoing.deadline = deadline
			token := &leafMobilityAuthorityToken{
				engine: e, outgoing: outgoing, done: make(chan struct{}),
			}
			token.armExpiry()
			e.leafTx.mu.Lock()
			if e.leafTx.outgoing == outgoing {
				outgoing.authority = token
			}
			e.leafTx.mu.Unlock()
			return &LeafMobilityAuthority{token: token}, nil
		case <-outgoing.final:
			return nil, e.failOutgoingLeafMobility(outgoing, false, e.leafMobilityProtocolError(
				fmt.Errorf("FINAL arrived before local staging and COMMIT publication")))
		}
	}
}

func (t *leafMobilityAuthorityToken) resolve(
	ctx context.Context,
	resolution leafmobility.Resolution,
	permitOwned bool,
) error {
	if t == nil || t.engine == nil || t.outgoing == nil || t.outgoing.resourceTx == nil {
		return leafmobility.ErrAuthorityStale
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.resolveMu.Lock()
	rearmExpiry := true
	defer func() {
		if rearmExpiry {
			t.armExpiry()
		}
		t.resolveMu.Unlock()
	}()
	select {
	case <-t.done:
		rearmExpiry = false
		return leafmobility.ErrAuthorityStale
	default:
	}
	if t.consumed != permitOwned {
		if t.consumed {
			return leafmobility.ErrAuthorityConsumed
		}
		return leafmobility.ErrAuthorityStale
	}
	if t.outgoing.recoveryOwned.Load() || t.outgoing.abandoned.Load() {
		rearmExpiry = false
		return ErrLeafMobilityOutcomeUnknown
	}
	t.outgoing.resolutionIntent.Store(uint32(resolution))
	t.stopExpiry()
	stage := proto.LeafMobilityPeerPlanCommitStageComplete
	if resolution == leafmobility.ResolutionRolledBack {
		stage = proto.LeafMobilityPeerPlanCommitStageRolledBack
	} else if resolution == leafmobility.ResolutionAbort {
		stage = proto.LeafMobilityPeerPlanCommitStageAbort
	}
	message := t.outgoing.commit
	if !t.outgoing.commitIssued.Load() || t.outgoing.commit == (proto.LeafMobilityPeerPlanCommit{}) {
		prepared := t.outgoing.preparedAck
		message = proto.LeafMobilityPeerPlanCommit{
			LeafMobilityPeerPlanBinding: t.outgoing.prepare.LeafMobilityPeerPlanBinding,
			Generation:                  prepared.Generation,
			ActorEndpointGeneration:     prepared.ActorEndpointGeneration,
			PeerEndpointGeneration:      prepared.PeerEndpointGeneration,
			ProposalDigest:              prepared.ProposalDigest,
			PeerPlanDigest:              prepared.PeerPlanDigest,
			AgreementDigest:             prepared.AgreementDigest,
			ReservationID:               prepared.ReservationID,
		}
	}
	message.Stage = stage
	txCtx, cancel := context.WithDeadline(ctx, t.outgoing.deadline)
	defer cancel()
	frame, err, pending := t.engine.sendLeafMobilityFrameWithContext(txCtx, func(writeCtx context.Context) ([]byte, error) {
		return t.engine.sendLeafMobilityCommitForOutgoingContext(writeCtx, t.outgoing, message, func(frame []byte) error {
			t.engine.leafTx.mu.Lock()
			defer t.engine.leafTx.mu.Unlock()
			if t.engine.leafTx.outgoing != t.outgoing {
				return leafmobility.ErrAuthorityStale
			}
			if err := t.outgoing.resourceTx.BeginResolution(resolution); err != nil {
				return err
			}
			t.outgoing.resolution = message
			t.outgoing.resolutionFrame = append([]byte(nil), frame...)
			return nil
		})
	})
	if pending != nil {
		rearmExpiry = false
		t.outgoing.abandoned.Store(true)
		finish := func() {
			t.engine.finishAbandonedLeafMobilityResolutionWrite(t.outgoing, pending)
		}
		if !t.engine.startLeafMobilityAsync(finish) {
			finish()
		}
		return fmt.Errorf("%w: resolution publication: %v", ErrLeafMobilityOutcomeUnknown, err)
	}
	if err != nil {
		if len(frame) == 0 {
			return fmt.Errorf("%w: %w", errLeafMobilityResolutionUnpublished, err)
		}
		rearmExpiry = false
		_ = t.outgoing.resourceTx.MarkOutcomeUnknown()
		t.engine.startOutgoingLeafMobilityRecovery(t.outgoing, outgoingLeafMobilityRecoveryReleased)
		return fmt.Errorf("%w: resolution publication: %v", ErrLeafMobilityOutcomeUnknown, err)
	}
	if len(frame) == 0 {
		frame = t.engine.outgoingResolutionFrame(t.outgoing)
	}
	rearmExpiry = false
	retry := time.NewTicker(leafMobilityRetryInterval)
	defer retry.Stop()
	for {
		select {
		case <-t.done:
			return ErrLeafMobilityOutcomeUnknown
		case <-t.engine.closed:
			t.outcomeUnknown(net.ErrClosed)
			return net.ErrClosed
		case <-txCtx.Done():
			_ = t.outgoing.resourceTx.MarkOutcomeUnknown()
			t.engine.startOutgoingLeafMobilityRecovery(t.outgoing, outgoingLeafMobilityRecoveryReleased)
			return fmt.Errorf("%w: %v", ErrLeafMobilityOutcomeUnknown, txCtx.Err())
		case <-retry.C:
			_, retryErr, retryPending := t.engine.sendLeafMobilityFrameWithContext(txCtx, func(writeCtx context.Context) ([]byte, error) {
				return frame, t.engine.replayLeafMobilityFrameForOutgoingContext(writeCtx, t.outgoing, frame)
			})
			if retryPending != nil {
				t.outgoing.abandoned.Store(true)
				finish := func() {
					t.engine.finishAbandonedLeafMobilityResolutionWrite(t.outgoing, retryPending)
				}
				if !t.engine.startLeafMobilityAsync(finish) {
					finish()
				}
				return fmt.Errorf("%w: resolution retry: %v", ErrLeafMobilityOutcomeUnknown, retryErr)
			}
			if retryErr != nil {
				_ = t.outgoing.resourceTx.MarkOutcomeUnknown()
				t.engine.startOutgoingLeafMobilityRecovery(t.outgoing, outgoingLeafMobilityRecoveryReleased)
				return fmt.Errorf("%w: resolution retry: %v", ErrLeafMobilityOutcomeUnknown, retryErr)
			}
		case event := <-t.outgoing.released:
			if event.source != t.outgoing.source {
				err := t.engine.leafMobilityProtocolError(fmt.Errorf("RELEASED changed route"))
				t.outcomeUnknown(err)
				return err
			}
			if err := event.ack.ValidateForCommit(message); err != nil ||
				event.ack.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
				if err == nil {
					err = fmt.Errorf("peer rejected resolution: %s", event.ack.Reason)
				}
				err = t.engine.leafMobilityProtocolError(err)
				t.outcomeUnknown(err)
				return err
			}
			if err := t.outgoing.resourceTx.FinishResolution(resolution); err != nil {
				t.outcomeUnknown(err)
				return err
			}
			t.finish()
			return nil
		}
	}
}

// resolveCommitted owns terminal publication after the driver has committed.
// Caller cancellation cannot strand a locally committed endpoint. A failure
// known to have published zero bytes is retried until the immutable plan
// deadline; uncertain publication is handed to the existing recovery path.
func (t *leafMobilityAuthorityToken) resolveCommitted(ctx context.Context) error {
	if t == nil || t.outgoing == nil {
		return leafmobility.ErrAuthorityStale
	}
	parent := context.Background()
	if ctx != nil {
		parent = context.WithoutCancel(ctx)
	}
	terminalCtx, cancel := context.WithDeadline(parent, t.outgoing.deadline)
	defer cancel()

	for {
		if err := terminalCtx.Err(); err != nil {
			t.outcomeUnknownSerialized(err)
			return fmt.Errorf("%w: committed resolution deadline: %w", ErrLeafMobilityOutcomeUnknown, err)
		}
		err := t.resolve(terminalCtx, leafmobility.ResolutionComplete, true)
		if !errors.Is(err, errLeafMobilityResolutionUnpublished) {
			return err
		}
		timer := time.NewTimer(leafMobilityRetryInterval)
		select {
		case <-timer.C:
		case <-terminalCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			t.outcomeUnknownSerialized(terminalCtx.Err())
			return fmt.Errorf("%w: committed resolution deadline: %w", ErrLeafMobilityOutcomeUnknown, terminalCtx.Err())
		case <-t.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ErrLeafMobilityOutcomeUnknown
		}
	}
}

func (t *leafMobilityAuthorityToken) finish() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		t.stopExpiry()
		t.releaseTerminalExecution()
		t.releaseExecutionDispatch()
		close(t.done)
		t.engine.finishOutgoingLeafMobility(t.outgoing)
	})
}

func (t *leafMobilityAuthorityToken) outcomeUnknown(cause error) {
	if t == nil {
		return
	}
	t.once.Do(func() {
		t.stopExpiry()
		_ = t.outgoing.resourceTx.MarkOutcomeUnknown()
		t.releaseTerminalExecution()
		if t.executionAllowsOutcomeUnknownDispatchRelease() {
			t.releaseExecutionDispatch()
		}
		close(t.done)
		t.engine.finishOutgoingLeafMobility(t.outgoing)
	})
}

func (t *leafMobilityAuthorityToken) executionAllowsOutcomeUnknownDispatchRelease() bool {
	if t == nil || t.execution == nil {
		return true
	}
	switch t.execution.State() {
	case leafmobility.ExecutionActivated, leafmobility.ExecutionRolledBack,
		leafmobility.ExecutionFailedClosed, leafmobility.ExecutionInvalid:
		return true
	default:
		return false
	}
}

func (t *leafMobilityAuthorityToken) releaseTerminalExecution() {
	if t == nil || t.execution == nil {
		return
	}
	switch t.execution.State() {
	case leafmobility.ExecutionActivated:
		_ = t.execution.FinalizePublished()
	case leafmobility.ExecutionRolledBack:
		_ = t.execution.FinalizeRolledBack()
	}
}

func (t *leafMobilityAuthorityToken) finishSerialized() {
	if t == nil {
		return
	}
	t.resolveMu.Lock()
	t.finish()
	t.resolveMu.Unlock()
}

func (t *leafMobilityAuthorityToken) outcomeUnknownSerialized(cause error) {
	if t == nil {
		return
	}
	t.resolveMu.Lock()
	t.outcomeUnknown(cause)
	t.resolveMu.Unlock()
}

func (t *leafMobilityAuthorityToken) stopExpiry() {
	if t == nil {
		return
	}
	t.expiryMu.Lock()
	t.expiryGeneration++
	if t.expiry != nil {
		t.expiry.Stop()
		t.expiry = nil
	}
	t.expiryMu.Unlock()
}

func (t *leafMobilityAuthorityToken) armExpiry() {
	if t == nil || t.outgoing == nil {
		return
	}
	select {
	case <-t.done:
		return
	default:
	}
	remaining := time.Until(t.outgoing.deadline)
	if remaining < 0 {
		remaining = 0
	}
	t.expiryMu.Lock()
	select {
	case <-t.done:
		t.expiryMu.Unlock()
		return
	default:
	}
	if t.expiry != nil {
		t.expiry.Stop()
	}
	t.expiryGeneration++
	generation := t.expiryGeneration
	t.expiry = time.AfterFunc(remaining, func() {
		t.engine.startLeafMobilityAsync(func() { t.expireGeneration(generation) })
	})
	t.expiryMu.Unlock()
}

func (t *leafMobilityAuthorityToken) expireGeneration(generation uint64) {
	if t == nil {
		return
	}
	t.resolveMu.Lock()
	defer t.resolveMu.Unlock()
	t.expiryMu.Lock()
	if t.expiry == nil || t.expiryGeneration != generation {
		t.expiryMu.Unlock()
		return
	}
	t.expiry = nil
	t.expiryGeneration++
	t.expiryMu.Unlock()
	select {
	case <-t.done:
		return
	default:
	}
	t.outcomeUnknown(leafmobility.ErrAuthorityExpired)
	if t.execution != nil {
		permit := &LeafMobilityPermit{token: t, execution: t.execution}
		permit.startLocalExecutionCleanup()
	}
}

type leafMobilityFrameResult struct {
	frame []byte
	err   error
}

func (e *Engine) sendLeafMobilityFrameWithContext(
	ctx context.Context,
	send func(context.Context) ([]byte, error),
) ([]byte, error, <-chan leafMobilityFrameResult) {
	e.leafTx.writerMu.Lock()
	if e.leafTx.writerClosing {
		e.leafTx.writerMu.Unlock()
		return nil, net.ErrClosed, nil
	}
	e.leafTx.writerWG.Add(1)
	e.leafTx.writerMu.Unlock()
	result := make(chan leafMobilityFrameResult, 1)
	go func() {
		defer e.leafTx.writerWG.Done()
		frame, err := send(ctx)
		result <- leafMobilityFrameResult{frame: frame, err: err}
	}()
	select {
	case outcome := <-result:
		return outcome.frame, outcome.err, nil
	case <-ctx.Done():
		return nil, ctx.Err(), result
	case <-e.closed:
		return nil, net.ErrClosed, result
	}
}

func (e *Engine) startLeafMobilityAsync(fn func()) bool {
	if e == nil || fn == nil {
		return false
	}
	e.leafTx.writerMu.Lock()
	if e.leafTx.writerClosing {
		e.leafTx.writerMu.Unlock()
		return false
	}
	e.leafTx.asyncWG.Add(1)
	e.leafTx.writerMu.Unlock()
	go func() {
		defer e.leafTx.asyncWG.Done()
		fn()
	}()
	return true
}

func (e *Engine) finishAbandonedLeafMobilityWrite(outgoing *outgoingLeafMobilityTransaction, result <-chan leafMobilityFrameResult) {
	<-result
	e.finishOutgoingLeafMobility(outgoing)
}

func (e *Engine) finishAbandonedLeafMobilityCommitWrite(
	outgoing *outgoingLeafMobilityTransaction,
	result <-chan leafMobilityFrameResult,
) {
	<-result
	outgoing.abandoned.Store(false)
	if outgoing.commitIssued.Load() {
		e.startOutgoingLeafMobilityRecovery(outgoing, outgoingLeafMobilityRecoveryFinal)
		return
	}
	e.leafTx.mu.Lock()
	authority := outgoing.authority
	e.leafTx.mu.Unlock()
	if authority != nil {
		authority.resolveMu.Lock()
		resolution, permitOwned, retry := knownLeafMobilityResolution(authority, outgoing)
		if !retry {
			authority.armExpiry()
		}
		authority.resolveMu.Unlock()
		if retry {
			e.retryKnownLeafMobilityResolution(authority, resolution, permitOwned)
		}
		return
	}
	_ = outgoing.resourceTx.Abort()
	e.finishOutgoingLeafMobility(outgoing)
}

func (e *Engine) finishAbandonedLeafMobilityResolutionWrite(
	outgoing *outgoingLeafMobilityTransaction,
	result <-chan leafMobilityFrameResult,
) {
	<-result
	published := len(e.outgoingResolutionFrame(outgoing)) != 0
	e.leafTx.mu.Lock()
	current := e.leafTx.outgoing == outgoing
	authority := outgoing.authority
	e.leafTx.mu.Unlock()
	if !current {
		outgoing.abandoned.Store(false)
		return
	}
	var retryResolution leafmobility.Resolution
	var retryPermitOwned, retry bool
	if authority != nil {
		authority.resolveMu.Lock()
		select {
		case <-authority.done:
			outgoing.abandoned.Store(false)
			authority.resolveMu.Unlock()
			return
		default:
		}
		if published {
			outgoing.recoveryOwned.Store(true)
		}
		outgoing.abandoned.Store(false)
		if !published {
			retryResolution, retryPermitOwned, retry = knownLeafMobilityResolution(authority, outgoing)
			if !retry {
				authority.armExpiry()
			}
		}
		authority.resolveMu.Unlock()
	} else {
		if published {
			outgoing.recoveryOwned.Store(true)
		}
		outgoing.abandoned.Store(false)
	}
	if published {
		_ = outgoing.resourceTx.MarkOutcomeUnknown()
		e.startOutgoingLeafMobilityRecovery(outgoing, outgoingLeafMobilityRecoveryReleased)
	} else if retry {
		e.retryKnownLeafMobilityResolution(authority, retryResolution, retryPermitOwned)
	}
}

func knownLeafMobilityResolution(
	authority *leafMobilityAuthorityToken,
	outgoing *outgoingLeafMobilityTransaction,
) (leafmobility.Resolution, bool, bool) {
	if authority == nil || outgoing == nil {
		return leafmobility.ResolutionInvalid, false, false
	}
	permitOwned := authority.consumed
	resolution := leafmobility.Resolution(outgoing.resolutionIntent.Load())
	if !permitOwned {
		if resolution == leafmobility.ResolutionInvalid {
			resolution = leafmobility.ResolutionAbort
		}
		return resolution, false, resolution == leafmobility.ResolutionAbort
	}
	if authority.execution == nil {
		return leafmobility.ResolutionInvalid, true, false
	}
	switch authority.execution.State() {
	case leafmobility.ExecutionRolledBack:
		if resolution == leafmobility.ResolutionInvalid {
			resolution = leafmobility.ResolutionRolledBack
		}
		return resolution, true, resolution == leafmobility.ResolutionRolledBack
	case leafmobility.ExecutionActivated:
		if resolution == leafmobility.ResolutionInvalid {
			resolution = leafmobility.ResolutionComplete
		}
		return resolution, true, resolution == leafmobility.ResolutionComplete
	default:
		return leafmobility.ResolutionInvalid, true, false
	}
}

func (e *Engine) retryKnownLeafMobilityResolution(
	authority *leafMobilityAuthorityToken,
	resolution leafmobility.Resolution,
	permitOwned bool,
) {
	if e == nil || authority == nil || authority.outgoing == nil || resolution == leafmobility.ResolutionInvalid {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), authority.outgoing.deadline)
	defer cancel()
	for {
		err := authority.resolve(ctx, resolution, permitOwned)
		if !errors.Is(err, errLeafMobilityResolutionUnpublished) {
			return
		}
		timer := time.NewTimer(leafMobilityRetryInterval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-authority.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
	}
}

func (e *Engine) failOutgoingLeafMobility(outgoing *outgoingLeafMobilityTransaction, committed bool, cause error) error {
	if committed {
		_ = outgoing.resourceTx.MarkOutcomeUnknown()
		e.startOutgoingLeafMobilityRecovery(outgoing, outgoingLeafMobilityRecoveryFinal)
		return fmt.Errorf("%w: %v", ErrLeafMobilityOutcomeUnknown, cause)
	}
	_ = outgoing.resourceTx.Abort()
	e.finishOutgoingLeafMobility(outgoing)
	return cause
}

func (e *Engine) startOutgoingLeafMobilityRecovery(
	outgoing *outgoingLeafMobilityTransaction,
	phase outgoingLeafMobilityRecoveryPhase,
) {
	e.startOutgoingLeafMobilityRecoveryWithFinal(outgoing, phase, nil)
}

func (e *Engine) startOutgoingLeafMobilityRecoveryWithFinal(
	outgoing *outgoingLeafMobilityTransaction,
	phase outgoingLeafMobilityRecoveryPhase,
	initialFinal *leafMobilityAckEvent,
) {
	if outgoing == nil || outgoing.resourceTx == nil {
		return
	}
	outgoing.recoveryOwned.Store(true)
	switch phase {
	case outgoingLeafMobilityRecoveryFinal, outgoingLeafMobilityRecoveryRollbackPublication:
		if initialFinal == nil {
			e.enqueuePinnedLeafMobilityAck(outgoing, proto.LeafMobilityPeerPlanAckPhaseFinal)
		}
	case outgoingLeafMobilityRecoveryReleased:
		e.enqueuePinnedLeafMobilityAck(outgoing, proto.LeafMobilityPeerPlanAckPhaseReleased)
	}
	outgoing.recoveryOnce.Do(func() {
		_ = outgoing.resourceTx.MarkOutcomeUnknown()
		deadline := time.Now().Add(e.leafMobilityRecordRetention())
		if !e.startLeafMobilityAsync(func() { e.recoverOutgoingLeafMobility(outgoing, phase, deadline, initialFinal) }) {
			e.finishRecoveredOutgoingLeafMobility(outgoing, net.ErrClosed)
		}
	})
}

func (e *Engine) enqueuePinnedLeafMobilityAck(
	outgoing *outgoingLeafMobilityTransaction,
	phase proto.LeafMobilityPeerPlanAckPhase,
) bool {
	if e == nil || outgoing == nil {
		return false
	}
	e.leafTx.mu.Lock()
	defer e.leafTx.mu.Unlock()
	if e.leafTx.outgoing != outgoing {
		return false
	}
	return enqueuePinnedLeafMobilityAckLocked(outgoing, phase)
}

func enqueuePinnedLeafMobilityAckLocked(
	outgoing *outgoingLeafMobilityTransaction,
	phase proto.LeafMobilityPeerPlanAckPhase,
) bool {
	var (
		seq         uint64
		ack         proto.LeafMobilityPeerPlanAck
		destination chan leafMobilityAckEvent
		delivered   *bool
	)
	switch phase {
	case proto.LeafMobilityPeerPlanAckPhasePrepared:
		seq, ack, destination, delivered = outgoing.preparedSeq, outgoing.preparedAck, outgoing.prepared, &outgoing.preparedDelivered
	case proto.LeafMobilityPeerPlanAckPhaseFinal:
		seq, ack, destination, delivered = outgoing.finalSeq, outgoing.finalAck, outgoing.final, &outgoing.finalDelivered
	case proto.LeafMobilityPeerPlanAckPhaseReleased:
		seq, ack, destination, delivered = outgoing.releasedSeq, outgoing.releasedAck, outgoing.released, &outgoing.releasedDelivered
	default:
		return false
	}
	if seq == 0 || ack == (proto.LeafMobilityPeerPlanAck{}) || *delivered || destination == nil {
		return false
	}
	select {
	case destination <- leafMobilityAckEvent{source: outgoing.source, seq: seq, ack: ack}:
		*delivered = true
		return true
	default:
		return false
	}
}

func (e *Engine) recoverOutgoingLeafMobility(
	outgoing *outgoingLeafMobilityTransaction,
	phase outgoingLeafMobilityRecoveryPhase,
	deadline time.Time,
	pendingFinal *leafMobilityAckEvent,
) {
	retry := time.NewTicker(leafMobilityRetryInterval)
	defer retry.Stop()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		e.finishRecoveredOutgoingLeafMobility(outgoing, ErrLeafMobilityOutcomeUnknown)
		return
	}
	recoveryDeadline := time.NewTimer(remaining)
	defer recoveryDeadline.Stop()
	for {
		switch phase {
		case outgoingLeafMobilityRecoveryFinal:
			if pendingFinal != nil {
				event := *pendingFinal
				err := e.reconcileRecoveredLeafMobilityFinal(outgoing, event)
				if errors.Is(err, leafmobility.ErrExecutionBusy) {
					select {
					case <-e.closed:
						e.finishRecoveredOutgoingLeafMobility(outgoing, net.ErrClosed)
						return
					case <-recoveryDeadline.C:
						_ = outgoing.resourceTx.MarkOutcomeUnknown()
						e.waitOutgoingLeafMobilityRecoveryWrite(outgoing)
						e.finishRecoveredOutgoingLeafMobility(outgoing, ErrLeafMobilityOutcomeUnknown)
						return
					case <-retry.C:
					}
					continue
				}
				pendingFinal = nil
				if err != nil {
					e.finishRecoveredOutgoingLeafMobility(outgoing, err)
					return
				}
				if event.ack.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
					e.finishRecoveredOutgoingLeafMobility(outgoing, nil)
					return
				}
				phase = outgoingLeafMobilityRecoveryRollbackPublication
				if err := e.publishRecoveredLeafMobilityRollback(outgoing, deadline); err == nil ||
					len(e.outgoingResolutionFrame(outgoing)) != 0 {
					phase = outgoingLeafMobilityRecoveryReleased
				}
				continue
			}
			select {
			case <-e.closed:
				e.finishRecoveredOutgoingLeafMobility(outgoing, net.ErrClosed)
				return
			case <-recoveryDeadline.C:
				_ = outgoing.resourceTx.MarkOutcomeUnknown()
				e.waitOutgoingLeafMobilityRecoveryWrite(outgoing)
				e.finishRecoveredOutgoingLeafMobility(outgoing, ErrLeafMobilityOutcomeUnknown)
				return
			case event := <-outgoing.final:
				pendingFinal = &event
			case <-retry.C:
				e.replayOutgoingLeafMobilityRecovery(outgoing, phase, deadline)
			}
		case outgoingLeafMobilityRecoveryRollbackPublication:
			select {
			case <-e.closed:
				e.finishRecoveredOutgoingLeafMobility(outgoing, net.ErrClosed)
				return
			case <-recoveryDeadline.C:
				_ = outgoing.resourceTx.MarkOutcomeUnknown()
				e.waitOutgoingLeafMobilityRecoveryWrite(outgoing)
				e.finishRecoveredOutgoingLeafMobility(outgoing, ErrLeafMobilityOutcomeUnknown)
				return
			case event := <-outgoing.final:
				if event.source != outgoing.source {
					e.finishRecoveredOutgoingLeafMobility(outgoing, e.leafMobilityProtocolError(
						fmt.Errorf("recovered FINAL changed route")))
					return
				}
				if err := event.ack.ValidateForCommit(outgoing.commit); err != nil ||
					event.ack.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
					if err == nil {
						err = fmt.Errorf("recovered FINAL changed decision: %s", event.ack.Reason)
					}
					e.finishRecoveredOutgoingLeafMobility(outgoing, e.leafMobilityProtocolError(err))
					return
				}
			case <-retry.C:
				if err := e.publishRecoveredLeafMobilityRollback(outgoing, deadline); err == nil ||
					len(e.outgoingResolutionFrame(outgoing)) != 0 {
					phase = outgoingLeafMobilityRecoveryReleased
				}
			}
		case outgoingLeafMobilityRecoveryReleased:
			select {
			case <-e.closed:
				e.finishRecoveredOutgoingLeafMobility(outgoing, net.ErrClosed)
				return
			case <-recoveryDeadline.C:
				_ = outgoing.resourceTx.MarkOutcomeUnknown()
				e.waitOutgoingLeafMobilityRecoveryWrite(outgoing)
				e.finishRecoveredOutgoingLeafMobility(outgoing, ErrLeafMobilityOutcomeUnknown)
				return
			case event := <-outgoing.released:
				resolution := e.outgoingResolution(outgoing)
				if event.source != outgoing.source {
					e.finishRecoveredOutgoingLeafMobility(outgoing, e.leafMobilityProtocolError(
						fmt.Errorf("recovered RELEASED changed route")))
					return
				}
				if err := event.ack.ValidateForCommit(resolution); err != nil ||
					event.ack.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
					if err == nil {
						err = fmt.Errorf("peer rejected recovered resolution: %s", event.ack.Reason)
					}
					e.finishRecoveredOutgoingLeafMobility(outgoing, e.leafMobilityProtocolError(err))
					return
				}
				localResolution := leafmobility.ResolutionComplete
				if resolution.Stage == proto.LeafMobilityPeerPlanCommitStageRolledBack {
					localResolution = leafmobility.ResolutionRolledBack
				} else if resolution.Stage == proto.LeafMobilityPeerPlanCommitStageAbort {
					localResolution = leafmobility.ResolutionAbort
				}
				if err := outgoing.resourceTx.FinishResolution(localResolution); err != nil {
					e.finishRecoveredOutgoingLeafMobility(outgoing, err)
					return
				}
				e.finishRecoveredOutgoingLeafMobility(outgoing, nil)
				return
			case <-retry.C:
				e.replayOutgoingLeafMobilityRecovery(outgoing, phase, deadline)
			}
		default:
			e.finishRecoveredOutgoingLeafMobility(outgoing, leafmobility.ErrResourceTransactionState)
			return
		}
	}
}

func (e *Engine) reconcileRecoveredLeafMobilityFinal(
	outgoing *outgoingLeafMobilityTransaction,
	event leafMobilityAckEvent,
) error {
	if event.source != outgoing.source {
		return e.leafMobilityProtocolError(fmt.Errorf("recovered FINAL changed route"))
	}
	if err := event.ack.ValidateForCommit(outgoing.commit); err != nil {
		return e.leafMobilityProtocolError(err)
	}
	if event.ack.Code == proto.LeafMobilityPeerPlanAckCodeAccept {
		e.leafTx.mu.Lock()
		authority := outgoing.authority
		e.leafTx.mu.Unlock()
		if authority == nil || authority.execution == nil {
			return leafmobility.ErrExecutionState
		}
		disposition, err := authority.execution.ResolveFinalAcceptance(false)
		if err != nil {
			return err
		}
		if disposition != leafmobility.FinalAcceptanceRollbackOnly {
			return leafmobility.ErrExecutionState
		}
		return nil
	}
	snapshot := outgoing.resourceTx.Snapshot()
	e.leafTx.mu.Lock()
	authority := outgoing.authority
	e.leafTx.mu.Unlock()
	if authority != nil && authority.execution != nil {
		if err := authority.execution.Rollback(context.Background()); err != nil {
			return err
		}
	}
	switch snapshot.State {
	case leafmobility.ResourceTransactionCommitPublished:
		_, err := reconcileLeafMobilityFinalRejected(outgoing.resourceTx)
		return err
	case leafmobility.ResourceTransactionOutcomeUnknown:
		return outgoing.resourceTx.ReconcileFinalRejected()
	default:
		return leafmobility.ErrResourceTransactionState
	}
}

func (e *Engine) publishRecoveredLeafMobilityRollback(
	outgoing *outgoingLeafMobilityTransaction,
	deadline time.Time,
) error {
	if !e.pollOutgoingLeafMobilityRecoveryWrite(outgoing) {
		return errLeafMobilityResponseUnavailable
	}
	if len(e.outgoingResolutionFrame(outgoing)) != 0 {
		return nil
	}
	e.leafTx.mu.Lock()
	authority := outgoing.authority
	e.leafTx.mu.Unlock()
	if authority != nil && authority.execution != nil {
		if err := authority.execution.Rollback(context.Background()); err != nil {
			return err
		}
	}
	message := outgoing.commit
	message.Stage = proto.LeafMobilityPeerPlanCommitStageRolledBack
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	_, err, pending := e.sendLeafMobilityFrameWithContext(ctx, func(writeCtx context.Context) ([]byte, error) {
		return e.sendLeafMobilityCommitForOutgoingContext(writeCtx, outgoing, message, func(frame []byte) error {
			e.leafTx.mu.Lock()
			defer e.leafTx.mu.Unlock()
			if e.leafTx.outgoing != outgoing {
				return leafmobility.ErrAuthorityStale
			}
			if err := outgoing.resourceTx.BeginResolution(leafmobility.ResolutionRolledBack); err != nil {
				return err
			}
			outgoing.resolution = message
			outgoing.resolutionFrame = append([]byte(nil), frame...)
			return nil
		})
	})
	if pending != nil {
		e.setOutgoingLeafMobilityRecoveryWrite(outgoing, pending)
		return err
	}
	return err
}

func (e *Engine) replayOutgoingLeafMobilityRecovery(
	outgoing *outgoingLeafMobilityTransaction,
	phase outgoingLeafMobilityRecoveryPhase,
	deadline time.Time,
) {
	if !e.pollOutgoingLeafMobilityRecoveryWrite(outgoing) {
		return
	}
	frame := e.outgoingCommitFrame(outgoing)
	if phase == outgoingLeafMobilityRecoveryReleased {
		frame = e.outgoingResolutionFrame(outgoing)
	}
	if len(frame) == 0 {
		return
	}
	attemptDeadline := time.Now().Add(leafMobilityRetryInterval)
	if deadline.Before(attemptDeadline) {
		attemptDeadline = deadline
	}
	ctx, cancel := context.WithDeadline(context.Background(), attemptDeadline)
	defer cancel()
	_, _, pending := e.sendLeafMobilityFrameWithContext(ctx, func(writeCtx context.Context) ([]byte, error) {
		return frame, e.replayLeafMobilityFrameForOutgoingContext(writeCtx, outgoing, frame)
	})
	if pending != nil {
		e.setOutgoingLeafMobilityRecoveryWrite(outgoing, pending)
	}
}

func (e *Engine) setOutgoingLeafMobilityRecoveryWrite(
	outgoing *outgoingLeafMobilityTransaction,
	pending <-chan leafMobilityFrameResult,
) {
	if outgoing == nil || pending == nil {
		return
	}
	outgoing.recoveryWriteMu.Lock()
	if outgoing.recoveryWrite == nil {
		outgoing.recoveryWrite = pending
	}
	outgoing.recoveryWriteMu.Unlock()
}

func (e *Engine) pollOutgoingLeafMobilityRecoveryWrite(outgoing *outgoingLeafMobilityTransaction) bool {
	if outgoing == nil {
		return true
	}
	outgoing.recoveryWriteMu.Lock()
	pending := outgoing.recoveryWrite
	if pending == nil {
		outgoing.recoveryWriteMu.Unlock()
		return true
	}
	select {
	case <-pending:
		outgoing.recoveryWrite = nil
		outgoing.recoveryWriteMu.Unlock()
		return true
	default:
		outgoing.recoveryWriteMu.Unlock()
		return false
	}
}

func (e *Engine) waitOutgoingLeafMobilityRecoveryWrite(outgoing *outgoingLeafMobilityTransaction) {
	if outgoing == nil {
		return
	}
	outgoing.recoveryWriteMu.Lock()
	pending := outgoing.recoveryWrite
	outgoing.recoveryWriteMu.Unlock()
	if pending == nil {
		return
	}
	<-pending
	outgoing.recoveryWriteMu.Lock()
	if outgoing.recoveryWrite == pending {
		outgoing.recoveryWrite = nil
	}
	outgoing.recoveryWriteMu.Unlock()
}

func (e *Engine) finishRecoveredOutgoingLeafMobility(outgoing *outgoingLeafMobilityTransaction, cause error) {
	e.waitOutgoingLeafMobilityRecoveryWrite(outgoing)
	e.leafTx.mu.Lock()
	authority := outgoing.authority
	e.leafTx.mu.Unlock()
	if cause != nil {
		_ = outgoing.resourceTx.MarkOutcomeUnknown()
	}
	if authority != nil {
		if cause == nil {
			authority.finishSerialized()
		} else {
			authority.outcomeUnknownSerialized(cause)
			permit := &LeafMobilityPermit{token: authority, execution: authority.execution}
			permit.startLocalExecutionCleanup()
		}
		return
	}
	e.finishOutgoingLeafMobility(outgoing)
}

func (e *Engine) finishOutgoingLeafMobility(outgoing *outgoingLeafMobilityTransaction) {
	if outgoing == nil {
		return
	}
	e.leafTx.mu.Lock()
	if e.leafTx.outgoing == outgoing {
		e.leafTx.outgoing = nil
		e.leafTx.actorTerminal[outgoing.prepare.TransactionID] = actorLeafMobilityTombstone{
			source: outgoing.source, digest: outgoing.digest,
			prepare: outgoing.prepare, commit: outgoing.commit, resolution: outgoing.resolution,
			preparedSeq: outgoing.preparedSeq, finalSeq: outgoing.finalSeq, releasedSeq: outgoing.releasedSeq,
			preparedAck: outgoing.preparedAck, finalAck: outgoing.finalAck, releasedAck: outgoing.releasedAck,
			retireAfter: time.Now().Add(e.leafMobilityRecordRetention()),
		}
	}
	e.pruneLeafMobilityRecordsLocked(time.Now())
	e.leafTx.mu.Unlock()
	e.releaseLeafMobilityOutgoingGate(outgoing)
}

func (e *Engine) leafMobilityRecordRetention() time.Duration {
	retention := e.limits.MigrationBudget
	if retention < time.Second {
		retention = time.Second
	}
	if retention > leafmobility.MaxPlanHorizon {
		retention = leafmobility.MaxPlanHorizon
	}
	return retention
}

func (e *Engine) releaseLeafMobilityOutgoingGate(outgoing *outgoingLeafMobilityTransaction) {
	if outgoing != nil && outgoing.gateHeld.CompareAndSwap(true, false) {
		<-e.leafTx.sendGate
	}
}

func (e *Engine) outgoingCommitFrame(outgoing *outgoingLeafMobilityTransaction) []byte {
	e.leafTx.mu.Lock()
	defer e.leafTx.mu.Unlock()
	if e.leafTx.outgoing != outgoing {
		return nil
	}
	return append([]byte(nil), outgoing.commitFrame...)
}

func (e *Engine) outgoingResolutionFrame(outgoing *outgoingLeafMobilityTransaction) []byte {
	e.leafTx.mu.Lock()
	defer e.leafTx.mu.Unlock()
	if e.leafTx.outgoing != outgoing {
		return nil
	}
	return append([]byte(nil), outgoing.resolutionFrame...)
}

func (e *Engine) outgoingResolution(outgoing *outgoingLeafMobilityTransaction) proto.LeafMobilityPeerPlanCommit {
	e.leafTx.mu.Lock()
	defer e.leafTx.mu.Unlock()
	if e.leafTx.outgoing != outgoing {
		return proto.LeafMobilityPeerPlanCommit{}
	}
	return outgoing.resolution
}

func (e *Engine) setOutgoingCommitFrame(outgoing *outgoingLeafMobilityTransaction, frame []byte) {
	e.leafTx.mu.Lock()
	if e.leafTx.outgoing == outgoing {
		outgoing.commitFrame = append([]byte(nil), frame...)
	}
	e.leafTx.mu.Unlock()
}

func (e *Engine) leafMobilityLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			e.closeOutgoingLeafMobilityTransaction()
			e.releaseIncomingLeafMobilityTransactions()
			return
		case now := <-ticker.C:
			e.expireIncomingLeafMobilityTransactions(now)
		case message := <-e.leafTx.inbox:
			e.releaseLeafMobilityMessageKey(leafMobilityKey(message))
			var err error
			switch message.kind {
			case leafMobilityMessagePrepare:
				err = e.handleLeafMobilityPrepare(message.source, message.seq, message.replayed, message.prepare)
			case leafMobilityMessageAck:
				err = e.handleLeafMobilityAck(message.source, message.seq, message.replayed, message.ack)
			case leafMobilityMessageCommit:
				err = e.handleLeafMobilityCommit(message.source, message.seq, message.replayed, message.commit)
			default:
				err = fmt.Errorf("unknown leaf mobility message kind %d", message.kind)
			}
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errLeafMobilityResponseUnavailable) {
				_ = e.leafMobilityProtocolError(err)
			}
		}
	}
}

func (e *Engine) closeOutgoingLeafMobilityTransaction() {
	e.leafTx.mu.Lock()
	outgoing := e.leafTx.outgoing
	if outgoing == nil {
		e.leafTx.mu.Unlock()
		return
	}
	authority := outgoing.authority
	if authority != nil {
		e.leafTx.mu.Unlock()
		authority.outcomeUnknownSerialized(net.ErrClosed)
		if authority.execution != nil {
			permit := &LeafMobilityPermit{token: authority, execution: authority.execution}
			permit.startLocalExecutionCleanup()
		}
		return
	}
	if outgoing.commitIssued.Load() {
		_ = outgoing.resourceTx.MarkOutcomeUnknown()
	} else {
		if err := outgoing.resourceTx.Abort(); errors.Is(err, leafmobility.ErrTransactionOutcomeUnknown) {
			_ = outgoing.resourceTx.MarkOutcomeUnknown()
		}
	}
	abandoned := outgoing.abandoned.Load()
	e.leafTx.mu.Unlock()
	if !abandoned {
		e.finishOutgoingLeafMobility(outgoing)
	}
}

func (e *Engine) enqueueLeafMobilityMessageLocked(message leafMobilityMessage) bool {
	key := leafMobilityKey(message)
	e.leafTx.queueMu.Lock()
	if _, exists := e.leafTx.queued[key]; exists {
		e.leafTx.queueMu.Unlock()
		return true
	}
	e.leafTx.queued[key] = struct{}{}
	e.leafTx.queueMu.Unlock()
	select {
	case e.leafTx.inbox <- message:
		return true
	default:
		e.releaseLeafMobilityMessageKey(key)
		return false
	}
}

func leafMobilityKey(message leafMobilityMessage) leafMobilityMessageKey {
	key := leafMobilityMessageKey{kind: message.kind, source: message.source, seq: message.seq}
	switch message.kind {
	case leafMobilityMessagePrepare:
		key.transactionID = message.prepare.TransactionID
		key.digest, _ = message.prepare.ProposalDigest()
	case leafMobilityMessageAck:
		key.phase = message.ack.Phase
		key.stage = message.ack.Stage
		key.transactionID = message.ack.TransactionID
		key.digest = message.ack.ProposalDigest
	case leafMobilityMessageCommit:
		key.stage = message.commit.Stage
		key.transactionID = message.commit.TransactionID
		key.digest = message.commit.ProposalDigest
	}
	return key
}

func (e *Engine) releaseLeafMobilityMessageKey(key leafMobilityMessageKey) {
	e.leafTx.queueMu.Lock()
	delete(e.leafTx.queued, key)
	e.leafTx.queueMu.Unlock()
}

func (e *Engine) handleLeafMobilityAck(source PathRef, seq uint64, replayed bool, ack proto.LeafMobilityPeerPlanAck) error {
	if seq == 0 {
		return fmt.Errorf("leaf mobility ACK has zero OOB message sequence")
	}
	e.leafTx.mu.Lock()
	outgoing := e.leafTx.outgoing
	if outgoing == nil || outgoing.prepare.TransactionID != ack.TransactionID || outgoing.digest != ack.ProposalDigest {
		terminal, known := e.leafTx.actorTerminal[ack.TransactionID]
		if known && terminal.source == source && terminal.digest == ack.ProposalDigest {
			var wantSeq uint64
			var wantAck proto.LeafMobilityPeerPlanAck
			var validateErr error
			switch ack.Phase {
			case proto.LeafMobilityPeerPlanAckPhasePrepared:
				wantSeq, wantAck = terminal.preparedSeq, terminal.preparedAck
				validateErr = ack.ValidateForPrepare(terminal.prepare)
			case proto.LeafMobilityPeerPlanAckPhaseFinal:
				wantSeq, wantAck = terminal.finalSeq, terminal.finalAck
				if terminal.commit == (proto.LeafMobilityPeerPlanCommit{}) {
					validateErr = fmt.Errorf("terminal transaction never published COMMIT")
				} else {
					validateErr = ack.ValidateForCommit(terminal.commit)
				}
			case proto.LeafMobilityPeerPlanAckPhaseReleased:
				wantSeq, wantAck = terminal.releasedSeq, terminal.releasedAck
				if terminal.resolution == (proto.LeafMobilityPeerPlanCommit{}) {
					validateErr = fmt.Errorf("terminal transaction never published resolution")
				} else {
					validateErr = ack.ValidateForCommit(terminal.resolution)
				}
			default:
				e.leafTx.mu.Unlock()
				return fmt.Errorf("terminal leaf mobility ACK has invalid phase %d", ack.Phase)
			}
			if validateErr != nil {
				e.leafTx.mu.Unlock()
				return fmt.Errorf("terminal leaf mobility ACK is not correlated: %w", validateErr)
			}
			if wantSeq == 0 {
				switch ack.Phase {
				case proto.LeafMobilityPeerPlanAckPhasePrepared:
					terminal.preparedSeq, terminal.preparedAck = seq, ack
				case proto.LeafMobilityPeerPlanAckPhaseFinal:
					terminal.finalSeq, terminal.finalAck = seq, ack
				case proto.LeafMobilityPeerPlanAckPhaseReleased:
					terminal.releasedSeq, terminal.releasedAck = seq, ack
				}
				e.leafTx.actorTerminal[ack.TransactionID] = terminal
				e.leafTx.mu.Unlock()
				return nil
			}
			e.leafTx.mu.Unlock()
			if wantSeq != seq || wantAck != ack {
				return fmt.Errorf("terminal leaf mobility ACK changed transaction evidence")
			}
			return nil
		}
		e.leafTx.mu.Unlock()
		if replayed {
			return nil
		}
		return fmt.Errorf("leaf mobility ACK has no matching outgoing transaction")
	}
	if source != outgoing.source {
		e.leafTx.mu.Unlock()
		if replayed {
			return nil
		}
		return fmt.Errorf("leaf mobility ACK changed route from %+v to %+v", outgoing.source, source)
	}
	var destination chan leafMobilityAckEvent
	var acceptedSeq *uint64
	var acceptedAck *proto.LeafMobilityPeerPlanAck
	var delivered *bool
	switch ack.Phase {
	case proto.LeafMobilityPeerPlanAckPhasePrepared:
		destination = outgoing.prepared
		acceptedSeq = &outgoing.preparedSeq
		acceptedAck = &outgoing.preparedAck
		delivered = &outgoing.preparedDelivered
		if err := ack.ValidateForPrepare(outgoing.prepare); err != nil {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility PREPARED ACK is not correlated: %w", err)
		}
	case proto.LeafMobilityPeerPlanAckPhaseFinal:
		destination = outgoing.final
		acceptedSeq = &outgoing.finalSeq
		acceptedAck = &outgoing.finalAck
		delivered = &outgoing.finalDelivered
		if outgoing.commit == (proto.LeafMobilityPeerPlanCommit{}) {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility FINAL arrived before COMMIT evidence")
		}
		if err := ack.ValidateForCommit(outgoing.commit); err != nil {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility FINAL ACK is not correlated: %w", err)
		}
	case proto.LeafMobilityPeerPlanAckPhaseReleased:
		destination = outgoing.released
		acceptedSeq = &outgoing.releasedSeq
		acceptedAck = &outgoing.releasedAck
		delivered = &outgoing.releasedDelivered
		if outgoing.resolution == (proto.LeafMobilityPeerPlanCommit{}) {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility RELEASED arrived before resolution evidence")
		}
		if err := ack.ValidateForCommit(outgoing.resolution); err != nil {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility RELEASED ACK is not correlated: %w", err)
		}
	default:
		e.leafTx.mu.Unlock()
		return fmt.Errorf("invalid leaf mobility ACK phase %d", ack.Phase)
	}
	if *acceptedSeq != 0 && (*acceptedSeq != seq || *acceptedAck != ack) {
		e.leafTx.mu.Unlock()
		return fmt.Errorf("leaf mobility ACK retry changed transaction evidence")
	}
	if *acceptedSeq == 0 {
		*acceptedSeq = seq
		*acceptedAck = ack
	}
	if outgoing.abandoned.Load() || *delivered {
		e.leafTx.mu.Unlock()
		return nil
	}
	select {
	case destination <- leafMobilityAckEvent{source: source, seq: seq, ack: ack}:
		*delivered = true
	default:
	}
	e.leafTx.mu.Unlock()
	return nil
}

func (e *Engine) pruneLeafMobilityRecordsLocked(now time.Time) {
	for id, rejected := range e.leafTx.rejected {
		if !rejected.retireAfter.IsZero() && !now.Before(rejected.retireAfter) {
			delete(e.leafTx.rejected, id)
		}
	}
	for id, completed := range e.leafTx.completed {
		if !completed.retireAfter.IsZero() && !now.Before(completed.retireAfter) {
			delete(e.leafTx.completed, id)
		}
	}
	for id, terminal := range e.leafTx.actorTerminal {
		if !terminal.retireAfter.IsZero() && !now.Before(terminal.retireAfter) {
			delete(e.leafTx.actorTerminal, id)
		}
	}
}

func (e *Engine) leafMobilityProtocolError(err error) error {
	if err == nil {
		return nil
	}
	wrapped := fmt.Errorf("%w: leaf mobility transaction: %v", ErrPeerProtocol, err)
	e.setCloseErr(wrapped)
	go e.Close()
	return wrapped
}
