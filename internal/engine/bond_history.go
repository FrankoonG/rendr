package engine

import (
	"errors"
	"math"
	"net"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

const (
	// sendHistoryWindow bounds the number of unacknowledged application
	// frames. The former 256-frame limit capped a 1 KiB packet stream at only
	// 256 KiB in flight, regardless of the path BDP.
	sendHistoryWindow = 8 * 1024
	// sendHistoryByteLimit independently bounds the immutable replay payload.
	// A frame limit alone lets large frames consume excessive memory, while a
	// byte limit alone lets zero/small packet floods allocate unbounded entry
	// metadata. Both credits must be available before publication.
	sendHistoryByteLimit = 64 << 20
)
const (
	sendControlReserve = 8
	// One FINAL can sit immediately beyond an already-ACKed PREPARE while a
	// preceding DATA gap blocks cumulative ACK. Every later committed policy
	// transaction necessarily retains one PREPARE response in the ordinary
	// control reserve, so that reserve plus the first FINAL is the exact bounded
	// emergency cardinality. Keep this coupled to the causal credit, not the
	// independent completed-transaction cache size.
	sendPolicyFinalReserve = sendControlReserve + 1
)
const unknownApplicationBytes = ^uint64(0)

const (
	selectorGoodputMinimumWindow = 250 * time.Millisecond
	selectorGoodputMinimumBytes  = 32 << 10
)

type sendHistory struct {
	entries []sendHistoryEntry
	// reservedFrames counts acquired application-frame credits, including a
	// writer that is still waiting for byte credit or sendMu publication.
	reservedFrames int
	// reservedBytes includes application-frame credits acquired by writers
	// that have not yet appended their ledger entry. This closes the race where
	// concurrent writers could all pass the byte check before sendMu orders
	// publication.
	reservedBytes  int
	frameHighWater int
	byteHighWater  int
	creditWaiters  int
	backpressure   uint64
	generation     uint64
	// ackedApplicationBytes is the cumulative unique DATA payload proven by
	// the peer's contiguous ACK frontier. Socket writes, replay attempts, and
	// control frames never advance it.
	ackedApplicationBytes uint64
	rootCohort            rootDeliveryCohort
	rootAckedBytes        uint64
	rootPublishedBytes    uint64
	rootDemandAckedBytes  uint64
	rootEvidenceEpoch     uint64
	rootTopologyEpoch     uint64
	rootAttributable      bool
	// rootPendingDispatches counts ACK-retired batch receipts whose physical
	// result can still invalidate the current generation.
	rootPendingDispatches      uint64
	rootCommitted              bool
	targetDelivery             map[proto.TargetID]targetDeliveryEvidence
	targetDeliveryScratch      map[proto.TargetID]uint64
	targetDeliveryTouched      []proto.TargetID
	targetDeliveryScratchEpoch uint64
}

// targetDeliveryEvidence is sender-owned, ACK-confirmed telemetry for one
// logical graph target. The fixed graph bounds the map cardinality. One frame
// is credited once to the deepest target containing every attempted route and
// to each ancestor, so race copies remain unique and bond parents see their
// actual aggregate goodput.
type targetDeliveryEvidence struct {
	topologyEpoch uint64
	totalAcked    uint64
	windowAcked   uint64
	windowStart   time.Time
	estimate      speedEstimate
}

type rootDeliveryCohort struct {
	selectorID proto.TargetID
	targetID   proto.TargetID
	generation uint64
}

// ReplayStats is a coherent read-only snapshot of the bounded application
// replay-credit domain. Control-frame reserve is intentionally separate.
type ReplayStats struct {
	FrameLimit         uint64
	ByteLimit          uint64
	FramesInUse        uint64
	BytesInUse         uint64
	FramesHighWater    uint64
	BytesHighWater     uint64
	PublishedNext      uint64
	AckNext            uint64
	CreditWaiters      uint64
	BackpressureEvents uint64
	Generation         uint64
}

// ApplicationDeliverySnapshot is a coherent view of unique application DATA
// at the replay-ledger boundary. PublishedPayloadBytes includes payload at or
// below PublishedNext even when it is still awaiting peer acknowledgement.
// AckedPayloadBytes advances only after a proof-valid cumulative peer ACK.
type ApplicationDeliverySnapshot struct {
	PublishedNext         uint64
	AckNext               uint64
	PublishedPayloadBytes uint64
	AckedPayloadBytes     uint64
	PendingPayloadBytes   uint64
	Generation            uint64
}

// TargetDeliverySnapshot binds peer-confirmed unique payload to one root
// selector immediate child at the frame's original publication boundary.
type TargetDeliverySnapshot struct {
	TargetID           proto.TargetID
	SelectorID         proto.TargetID
	TargetName         string
	SelectorName       string
	SelectorGeneration uint64
	EvidenceEpoch      uint64
	Attributable       bool
	DemandBytes        uint64
	PublishedBytes     uint64
	AckedBytes         uint64
}

// ConnectionObservationSnapshot binds topology membership to one replay/root
// evidence epoch. Monotonic receive and scheduler counters are point
// observations sampled after the structural locks are released.
type ConnectionObservationSnapshot struct {
	Topology       TopologySnapshot
	Replay         ReplayStats
	RootDelivery   TargetDeliverySnapshot
	RecvQueueHWM   int
	RecvDups       uint64
	BondStuckSkips uint64
}

type sendHistoryEntry struct {
	seq                   uint64
	frame                 []byte
	application           bool
	control               bool
	policyFinal           bool
	terminal              bool
	priorProof            proto.AckProof
	proof                 proto.AckProof
	tailRoute             tailReplayPublicationRoute
	rootCohort            rootDeliveryCohort
	rootCommitted         bool
	rootDemand            bool
	rootRouteSeen         bool
	rootRouteTarget       proto.TargetID
	rootEvidenceEpoch     uint64
	rootTopologyEpoch     uint64
	rootAttributable      bool
	deliveryRouteSeen     bool
	deliveryRouteTarget   proto.TargetID
	deliveryTopologyEpoch uint64
	deliveryAttributable  bool
	batchAttribution      *batchDispatchAttributionRecord
	applicationBytes      uint64
}

type applicationDispatchRouteState struct {
	topologyEpoch        uint64
	rootRouteSeen        bool
	rootRouteTarget      proto.TargetID
	rootAttributable     bool
	deliveryRouteSeen    bool
	deliveryRouteTarget  proto.TargetID
	deliveryAttributable bool
}

// batchDispatchAttributionRecord outlives a replay-ledger entry when a valid
// peer ACK arrives before FrameBatchWriter returns its completed prefix. All
// provisional attempts for the same SEQ share one record and settle exactly
// once after every physical result is known.
type batchDispatchAttributionRecord struct {
	seq      uint64
	pending  int
	detached bool
	acked    bool
	ackedAt  time.Time
	state    applicationDispatchRouteState
	binding  graphBinding

	applicationBytes   uint64
	rootCohort         rootDeliveryCohort
	rootCommitted      bool
	rootDemand         bool
	rootEvidenceEpoch  uint64
	rootTopologyEpoch  uint64
	rootPendingTracked bool
	routeStarted       time.Time
}

type batchDispatchAttributionReceipt struct {
	record        *batchDispatchAttributionRecord
	targetID      proto.TargetID
	topologyEpoch uint64
	started       time.Time
	resolved      bool
}

// reserveSendFrame gives a sequence number a replay owner before any path can
// observe it. Caller holds sendMu, while ACK processing owns sendHistMu so it
// can release backpressure without waiting behind an in-flight path write.
func (e *Engine) reserveSendFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, false, false, false, false, rootDataAttribution{}, unknownApplicationBytes)
}

func (e *Engine) reserveTerminalFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, true, false, false, false, rootDataAttribution{}, unknownApplicationBytes)
}

// reserveOwnedSendFrame transfers an otherwise-unaliased frame to the replay
// ledger. PathConn.Write follows io.Writer and may neither retain nor mutate
// the borrowed bytes, so dispatch can read the ledger-owned frame directly.
func (e *Engine) reserveOwnedSendFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, false, true, false, false, rootDataAttribution{}, unknownApplicationBytes)
}

func (e *Engine) reserveAndPublishOwnedSendFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, false, true, true, false, rootDataAttribution{}, unknownApplicationBytes)
}

func (e *Engine) reserveAndPublishOwnedPolicyFinalFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, false, true, true, true, rootDataAttribution{}, unknownApplicationBytes)
}

func (e *Engine) reserveOwnedApplicationFrame(
	frame []byte,
	attribution rootDataAttribution,
	applicationBytes int,
) error {
	if applicationBytes < 0 {
		return errors.New("engine: negative application payload size")
	}
	return e.reserveSendFrameClass(frame, false, true, false, false, attribution, uint64(applicationBytes))
}

func (e *Engine) reserveAndPublishOwnedApplicationFrame(
	frame []byte,
	attribution rootDataAttribution,
	applicationBytes int,
) error {
	if applicationBytes < 0 {
		return errors.New("engine: negative application payload size")
	}
	return e.reserveSendFrameClass(frame, false, true, true, false, attribution, uint64(applicationBytes))
}

func (e *Engine) reserveOwnedTerminalFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, true, true, false, false, rootDataAttribution{}, unknownApplicationBytes)
}

func (e *Engine) reserveAndPublishOwnedTerminalFrame(frame []byte) error {
	return e.reserveSendFrameClass(frame, true, true, true, false, rootDataAttribution{}, unknownApplicationBytes)
}

func (e *Engine) reserveSendFrameClass(
	frame []byte,
	terminal, takeOwnership, publish, policyFinal bool,
	attribution rootDataAttribution,
	applicationBytes uint64,
) error {
	if len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return err
	}
	ledgerFrame := frame
	if !takeOwnership {
		ledgerFrame = append([]byte(nil), frame...)
	}
	entry := sendHistoryEntry{
		seq:           hdr.Seq,
		frame:         ledgerFrame,
		control:       hdr.Type == proto.FrameCtrl,
		policyFinal:   policyFinal,
		terminal:      terminal,
		priorProof:    e.sendProof,
		rootCohort:    attribution.cohort,
		rootCommitted: attribution.committed,
		rootDemand:    attribution.demand,
	}
	if hdr.Type == proto.FrameData {
		if applicationBytes == unknownApplicationBytes {
			entry.applicationBytes = uint64(len(frame) - proto.HeaderSize)
		} else {
			entry.applicationBytes = applicationBytes
		}
		entry.application = entry.applicationBytes != 0
	}
	entry.proof = proto.AdvanceAckProof(e.sendProof, proto.DigestFrame(frame))

	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	if e.closing.Load() {
		return net.ErrClosed
	}
	if policyFinal && !entry.control {
		return errors.New("engine: policy FINAL replay credit used by non-control frame")
	}
	limit := sendHistoryWindow + sendControlReserve + sendPolicyFinalReserve
	if terminal {
		limit++
	}
	if len(e.sendHist.entries) >= limit {
		return errors.New("engine: replay ledger capacity invariant violated")
	}
	e.sendHist.entries = append(e.sendHist.entries, entry)
	e.sendProof = entry.proof
	if publish {
		e.publishSendSeqLocked(hdr.Seq + 1)
	}
	return nil
}

func (e *Engine) publishRootAttributionLocked(entry *sendHistoryEntry) {
	if entry == nil || entry.rootCohort.targetID == (proto.TargetID{}) {
		return
	}
	topologyEpoch := e.currentPathTopologyEpoch()
	if e.sendHist.rootCohort != entry.rootCohort ||
		e.sendHist.rootCommitted != entry.rootCommitted ||
		e.sendHist.rootTopologyEpoch != topologyEpoch ||
		(entry.rootCommitted && !e.sendHist.rootAttributable) {
		e.sendHist.beginRootEvidenceEpochLocked(entry.rootCohort, entry.rootCommitted, topologyEpoch)
	}
	entry.rootEvidenceEpoch = e.sendHist.rootEvidenceEpoch
	entry.rootTopologyEpoch = e.sendHist.rootTopologyEpoch
	entry.rootAttributable = entry.rootCommitted && e.sendHist.rootAttributable
	if entry.rootAttributable {
		e.sendHist.rootPublishedBytes = saturatingAddUint64(
			e.sendHist.rootPublishedBytes, entry.applicationBytes,
		)
	}
}

func (h *sendHistory) beginRootEvidenceEpochLocked(
	cohort rootDeliveryCohort,
	committed bool,
	topologyEpoch uint64,
) {
	h.rootCohort = cohort
	h.rootAckedBytes = 0
	h.rootPublishedBytes = 0
	h.rootDemandAckedBytes = 0
	h.rootCommitted = committed
	h.rootTopologyEpoch = topologyEpoch
	h.rootAttributable = committed
	h.rootPendingDispatches = 0
	h.rootEvidenceEpoch++
	if h.rootEvidenceEpoch == 0 {
		h.rootEvidenceEpoch++
	}
}

func (h *sendHistory) invalidateRootEvidenceEpochLocked(epoch uint64) {
	if epoch == 0 || epoch != h.rootEvidenceEpoch {
		return
	}
	h.rootAckedBytes = 0
	h.rootPublishedBytes = 0
	h.rootDemandAckedBytes = 0
	h.rootAttributable = false
	h.rootPendingDispatches = 0
	h.rootEvidenceEpoch++
	if h.rootEvidenceEpoch == 0 {
		h.rootEvidenceEpoch++
	}
}

// rollbackReservedSendFrame removes the unpublished tail entry. It is valid
// only while sendMu is held and before publishSendSeq makes the SEQ observable.
func (e *Engine) rollbackReservedSendFrame(seq uint64) bool {
	e.sendHistMu.Lock()
	if len(e.sendHist.entries) == 0 {
		e.sendHistMu.Unlock()
		return false
	}
	last := len(e.sendHist.entries) - 1
	entry := e.sendHist.entries[last]
	if entry.seq != seq || e.sendPublishedNext.Load() > seq {
		e.sendHistMu.Unlock()
		return false
	}
	e.sendProof = entry.priorProof
	e.sendHist.entries[last] = sendHistoryEntry{}
	e.sendHist.entries = e.sendHist.entries[:last]
	e.sendHistMu.Unlock()
	if !entry.terminal {
		e.releaseSendCredit(entry.control, entry.policyFinal, len(entry.frame))
	}
	return true
}

func (e *Engine) acquireSendSlot(control bool, frameBytes int) error {
	slots := e.sendSlots
	if control {
		slots = e.sendControlSlots
	}
	if control {
		select {
		case slots <- struct{}{}:
			return nil
		case <-e.closed:
			return net.ErrClosed
		}
	}
	if frameBytes <= 0 || frameBytes > sendHistoryByteLimit {
		return errors.New("engine: invalid replay byte credit request")
	}
	waiting := false
	markWaiting := func() {
		if waiting {
			return
		}
		waiting = true
		e.sendHistMu.Lock()
		e.sendHist.creditWaiters++
		e.sendHist.backpressure++
		e.sendHist.generation++
		e.sendHistMu.Unlock()
	}
	defer func() {
		if !waiting {
			return
		}
		e.sendHistMu.Lock()
		if e.sendHist.creditWaiters > 0 {
			e.sendHist.creditWaiters--
		}
		e.sendHist.generation++
		e.sendHistMu.Unlock()
	}()
	select {
	case slots <- struct{}{}:
	default:
		markWaiting()
		select {
		case slots <- struct{}{}:
		case <-e.closed:
			return net.ErrClosed
		}
	}
	e.sendHistMu.Lock()
	if e.closing.Load() {
		e.sendHistMu.Unlock()
		select {
		case <-slots:
		default:
		}
		return net.ErrClosed
	}
	e.sendHist.reservedFrames++
	if e.sendHist.reservedFrames > e.sendHist.frameHighWater {
		e.sendHist.frameHighWater = e.sendHist.reservedFrames
	}
	e.sendHist.generation++
	e.sendHistMu.Unlock()
	for {
		e.sendHistMu.Lock()
		if e.closing.Load() {
			if e.sendHist.reservedFrames > 0 {
				e.sendHist.reservedFrames--
				e.sendHist.generation++
			}
			e.sendHistMu.Unlock()
			select {
			case <-slots:
			default:
			}
			return net.ErrClosed
		}
		if e.sendHist.reservedBytes <= sendHistoryByteLimit-frameBytes {
			e.sendHist.reservedBytes += frameBytes
			if e.sendHist.reservedBytes > e.sendHist.byteHighWater {
				e.sendHist.byteHighWater = e.sendHist.reservedBytes
			}
			e.sendHist.generation++
			e.sendHistMu.Unlock()
			return nil
		}
		wake := e.sendCreditWake
		e.sendHistMu.Unlock()
		markWaiting()
		select {
		case <-wake:
		case <-e.closed:
			e.sendHistMu.Lock()
			if e.sendHist.reservedFrames > 0 {
				e.sendHist.reservedFrames--
				e.sendHist.generation++
			}
			e.sendHistMu.Unlock()
			select {
			case <-slots:
			default:
			}
			return net.ErrClosed
		}
	}
}

func (e *Engine) acquirePolicyFinalSlot() error {
	select {
	case e.sendPolicyFinalSlots <- struct{}{}:
		return nil
	case <-e.closed:
		return net.ErrClosed
	}
}

func (e *Engine) releaseSendSlot(control bool, frameBytes int) {
	e.releaseSendCredit(control, false, frameBytes)
}

func (e *Engine) releaseSendCredit(control, policyFinal bool, frameBytes int) {
	if policyFinal {
		e.sendHistMu.Lock()
		select {
		case <-e.sendPolicyFinalSlots:
		default:
			if !e.closing.Load() {
				e.sendHistMu.Unlock()
				panic("engine: policy FINAL replay credit invariant violated")
			}
		}
		e.sendHistMu.Unlock()
		return
	}
	if control {
		e.sendHistMu.Lock()
		select {
		case <-e.sendControlSlots:
		default:
			if !e.closing.Load() {
				e.sendHistMu.Unlock()
				panic("engine: control replay credit invariant violated")
			}
		}
		e.sendHistMu.Unlock()
		return
	}
	e.sendHistMu.Lock()
	if frameBytes <= 0 || frameBytes > e.sendHist.reservedBytes || e.sendHist.reservedFrames <= 0 {
		closing := e.closing.Load()
		e.sendHistMu.Unlock()
		if !closing {
			panic("engine: replay byte credit invariant violated")
		}
		select {
		case <-e.sendSlots:
		default:
		}
		return
	}
	e.sendHist.reservedFrames--
	e.sendHist.reservedBytes -= frameBytes
	select {
	case <-e.sendSlots:
	default:
		if !e.closing.Load() {
			e.sendHistMu.Unlock()
			panic("engine: replay frame token invariant violated")
		}
	}
	e.sendHist.generation++
	wake := e.sendCreditWake
	e.sendCreditWake = make(chan struct{})
	close(wake)
	e.sendHistMu.Unlock()
}

// ReplayStats returns the current bounded application replay-credit state.
func (e *Engine) ReplayStats() ReplayStats {
	if e == nil {
		return ReplayStats{FrameLimit: sendHistoryWindow, ByteLimit: sendHistoryByteLimit}
	}
	e.sendHistMu.Lock()
	stats := e.replayStatsLocked()
	e.sendHistMu.Unlock()
	if hook := e.replayStatsAfterCreditSnapshot; hook != nil {
		hook()
	}
	return stats
}

func (e *Engine) replayStatsLocked() ReplayStats {
	return ReplayStats{
		FrameLimit:         sendHistoryWindow,
		ByteLimit:          sendHistoryByteLimit,
		FramesInUse:        uint64(e.sendHist.reservedFrames),
		BytesInUse:         uint64(e.sendHist.reservedBytes),
		FramesHighWater:    uint64(e.sendHist.frameHighWater),
		BytesHighWater:     uint64(e.sendHist.byteHighWater),
		CreditWaiters:      uint64(e.sendHist.creditWaiters),
		BackpressureEvents: e.sendHist.backpressure,
		Generation:         e.sendHist.generation,
		PublishedNext:      e.sendPublishedNext.Load(),
		AckNext:            e.sendAckNext.Load(),
	}
}

// ApplicationDelivery returns unique peer-confirmed payload progress without
// exposing replay entries or transport-local write completion. The snapshot is
// used by policy telemetry; it grants no send or migration authority.
func (e *Engine) ApplicationDelivery() ApplicationDeliverySnapshot {
	if e == nil {
		return ApplicationDeliverySnapshot{}
	}
	e.sendHistMu.Lock()
	publishedNext := e.sendPublishedNext.Load()
	ackNext := e.sendAckNext.Load()
	acked := e.sendHist.ackedApplicationBytes
	pending := uint64(0)
	for _, entry := range e.sendHist.entries {
		if entry.seq >= publishedNext || !entry.application {
			continue
		}
		pending = saturatingAddUint64(pending, sendHistoryApplicationBytes(entry))
	}
	snapshot := ApplicationDeliverySnapshot{
		PublishedNext:         publishedNext,
		AckNext:               ackNext,
		PublishedPayloadBytes: saturatingAddUint64(acked, pending),
		AckedPayloadBytes:     acked,
		PendingPayloadBytes:   pending,
		Generation:            e.sendHist.generation,
	}
	e.sendHistMu.Unlock()
	return snapshot
}

// TargetApplicationDelivery reports unique DATA progress for one root child.
// It never attributes replay attempts or socket-local completion as delivery.
func (e *Engine) TargetApplicationDelivery(targetID proto.TargetID) TargetDeliverySnapshot {
	topologyEpoch := e.currentPathTopologyEpoch()
	binding := e.localGraphBinding()
	e.sendHistMu.Lock()
	snapshot := e.targetApplicationDeliveryLocked(targetID, topologyEpoch, binding)
	e.sendHistMu.Unlock()
	if e.currentPathTopologyEpoch() != topologyEpoch {
		clearTargetDeliveryAttribution(&snapshot)
	}
	return snapshot
}

func (e *Engine) targetApplicationDeliveryLocked(
	targetID proto.TargetID,
	topologyEpoch uint64,
	binding graphBinding,
) TargetDeliverySnapshot {
	cohort := e.sendHist.rootCohort
	snapshot := TargetDeliverySnapshot{
		TargetID:           targetID,
		SelectorID:         cohort.selectorID,
		SelectorGeneration: cohort.generation,
		EvidenceEpoch:      e.sendHist.rootEvidenceEpoch,
		Attributable: e.sendHist.rootAttributable && e.sendHist.rootPendingDispatches == 0 &&
			e.sendHist.rootTopologyEpoch == topologyEpoch,
		DemandBytes: e.sendHist.rootDemandAckedBytes,
	}
	if targetID == (proto.TargetID{}) {
		snapshot.TargetID = cohort.targetID
		targetID = cohort.targetID
	}
	snapshot.SelectorName, _ = binding.targetName(snapshot.SelectorID)
	snapshot.TargetName, _ = binding.targetName(snapshot.TargetID)
	if cohort.targetID == targetID && snapshot.Attributable {
		snapshot.PublishedBytes = e.sendHist.rootPublishedBytes
		snapshot.AckedBytes = e.sendHist.rootAckedBytes
	} else {
		snapshot.Attributable = false
		snapshot.DemandBytes = 0
	}
	return snapshot
}

func clearTargetDeliveryAttribution(snapshot *TargetDeliverySnapshot) {
	snapshot.Attributable = false
	snapshot.PublishedBytes = 0
	snapshot.AckedBytes = 0
	snapshot.DemandBytes = 0
}

const connectionObservationOptimisticRetries = 3

// ConnectionObservation returns topology, replay occupancy, and root-delivery
// evidence from one stable physical topology and policy epoch. It first uses a
// bounded optimistic path. If churn invalidates every attempt, the fallback
// holds pathsMu while taking sendHistMu, matching the engine's path-to-replay
// lock order and preventing topology or selector commits from splitting the
// structural and delivery snapshots. Transport-local metrics and monotonic
// counters are sampled only after that structural boundary is released.
func (e *Engine) ConnectionObservation() ConnectionObservationSnapshot {
	if e == nil {
		return ConnectionObservationSnapshot{
			Replay: ReplayStats{FrameLimit: sendHistoryWindow, ByteLimit: sendHistoryByteLimit},
		}
	}
	binding := e.localGraphBinding()
	for attempt := 0; attempt < connectionObservationOptimisticRetries; attempt++ {
		topology := e.TopologySnapshot()
		if hook := e.connectionObservationAfterTopology; hook != nil {
			hook()
		}
		e.sendHistMu.Lock()
		replay := e.replayStatsLocked()
		root := e.targetApplicationDeliveryLocked(proto.TargetID{}, topology.Epoch, binding)
		e.sendHistMu.Unlock()
		snapshot := ConnectionObservationSnapshot{
			Topology:     topology,
			Replay:       replay,
			RootDelivery: root,
		}
		if e.topologyObservationStable(topology) {
			e.populateConnectionObservationPointCounters(&snapshot)
			return snapshot
		}
		runtime.Gosched()
	}
	return e.connectionObservationCoherentFallback(binding)
}

func (e *Engine) connectionObservationCoherentFallback(binding graphBinding) ConnectionObservationSnapshot {
	runtime := e.localExecutionRuntime()
	e.pathsMu.RLock()
	topology, slots := e.topologySnapshotLocked(runtime)
	if hook := e.connectionObservationFallbackLocked; hook != nil {
		hook()
	}
	e.sendHistMu.Lock()
	replay := e.replayStatsLocked()
	root := e.targetApplicationDeliveryLocked(proto.TargetID{}, topology.Epoch, binding)
	e.sendHistMu.Unlock()
	snapshot := ConnectionObservationSnapshot{
		Topology:     topology,
		Replay:       replay,
		RootDelivery: root,
	}
	e.pathsMu.RUnlock()
	snapshot.Topology.Paths = pathInfos(slots, topology.ActivePath, e.limits.ProbeInterval)
	e.populateConnectionObservationPointCounters(&snapshot)
	return snapshot
}

func (e *Engine) populateConnectionObservationPointCounters(snapshot *ConnectionObservationSnapshot) {
	if snapshot == nil {
		return
	}
	snapshot.RecvQueueHWM = e.RecvQueueHighWaterMark()
	snapshot.RecvDups = e.RecvDups()
	snapshot.BondStuckSkips = e.BondStuckSkips()
}

func (e *Engine) localRootSelection() (proto.TargetID, bool) {
	_, targetID, _, ok := e.localRootSelectionSnapshot()
	return targetID, ok
}

func (e *Engine) localRootSelectionSnapshot() (selectorID, targetID proto.TargetID, generation uint64, ok bool) {
	runtime := e.localExecutionRuntime()
	selectorID, desired, _, generation, ok := runtime.rootPublicationAttribution()
	return selectorID, desired, generation, ok
}

func sendHistoryApplicationBytes(entry sendHistoryEntry) uint64 {
	if !entry.application {
		return 0
	}
	return entry.applicationBytes
}

// sendHistoryEntryLocked resolves one sequenced frame in constant time. The
// replay ledger owns every unpublished/acknowledged prefix as one contiguous,
// monotonically ordered interval; an unexpected hole is an invariant failure,
// not a reason to scan the entire hot-path ledger.
func (e *Engine) sendHistoryEntryLocked(seq uint64) *sendHistoryEntry {
	if len(e.sendHist.entries) == 0 {
		return nil
	}
	first := e.sendHist.entries[0].seq
	if seq < first {
		return nil
	}
	offset := seq - first
	if offset >= uint64(len(e.sendHist.entries)) {
		return nil
	}
	entry := &e.sendHist.entries[int(offset)]
	if entry.seq != seq {
		return nil
	}
	return entry
}

// noteApplicationDispatchRoute records the physical root child attempted for
// one immutable DATA frame. Peer ACK still supplies the delivery proof; this
// route fact only prevents bytes replayed across root children from becoming
// capacity evidence.
func (e *Engine) noteApplicationDispatchRoute(frame []byte, slot *pathSlot) {
	e.noteApplicationDispatchRouteAtEpoch(frame, slot, e.currentPathTopologyEpoch())
}

func (e *Engine) noteApplicationDispatchRouteAtEpoch(
	frame []byte,
	slot *pathSlot,
	topologyEpoch uint64,
) {
	if slot == nil || len(frame) < proto.HeaderSize {
		return
	}
	e.noteApplicationDispatchTargets(frame, nil, slot.localTXTargetID, topologyEpoch)
}

// noteApplicationDispatchPlan records a recursive ticket before any child
// writer can produce an ACK. A ticket with several leaves is intentional
// fanout; its deepest common target receives one unique-delivery credit.
func (e *Engine) noteApplicationDispatchPlan(frame []byte, routes []dispatchRoute) {
	e.noteApplicationDispatchPlanAtEpoch(frame, routes, e.currentPathTopologyEpoch())
}

func (e *Engine) noteApplicationDispatchPlanAtEpoch(
	frame []byte,
	routes []dispatchRoute,
	topologyEpoch uint64,
) {
	if len(routes) == 0 {
		return
	}
	e.noteApplicationDispatchTargets(frame, routes, proto.TargetID{}, topologyEpoch)
}

func (e *Engine) noteApplicationDispatchTargets(
	frame []byte,
	routes []dispatchRoute,
	single proto.TargetID,
	topologyEpoch uint64,
) {
	if (len(routes) == 0 && single == (proto.TargetID{})) || len(frame) < proto.HeaderSize {
		return
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || hdr.Type != proto.FrameData {
		return
	}
	binding := e.localGraphBinding()
	now := nowFn()
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	entry := e.sendHistoryEntryLocked(hdr.Seq)
	if entry == nil {
		return
	}
	record := entry.batchAttribution
	state := applicationDispatchRouteStateFromEntry(entry)
	rootCohort, rootCommitted := entry.rootCohort, entry.rootCommitted
	if record != nil {
		state = record.state
		rootCohort, rootCommitted = record.rootCohort, record.rootCommitted
	}
	noteTarget := func(routeTarget proto.TargetID) {
		noteApplicationDispatchTarget(
			&state, binding, routeTarget, topologyEpoch,
			rootCohort, rootCommitted, entry.rootTopologyEpoch,
		)
	}
	if single != (proto.TargetID{}) {
		noteTarget(single)
	} else {
		for _, route := range routes {
			noteTarget(route.targetID)
		}
	}
	if record != nil {
		record.state = state
		if record.routeStarted.IsZero() || now.Before(record.routeStarted) {
			record.routeStarted = now
		}
		if state.rootRouteSeen && !state.rootAttributable {
			e.sendHist.invalidateRootEvidenceEpochLocked(record.rootEvidenceEpoch)
		}
		return
	}
	applyApplicationDispatchRouteState(entry, state)
	if state.deliveryAttributable {
		e.beginTargetDeliveryWindowsLocked(
			binding, state.deliveryRouteTarget, state.topologyEpoch, now,
		)
	}
	if state.rootRouteSeen && !state.rootAttributable {
		e.sendHist.invalidateRootEvidenceEpochLocked(entry.rootEvidenceEpoch)
	}
}

func (e *Engine) beginApplicationBatchDispatch(
	frame []byte,
	slot *pathSlot,
	topologyEpoch uint64,
) *batchDispatchAttributionReceipt {
	if slot == nil || len(frame) < proto.HeaderSize {
		return nil
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameData {
		return nil
	}
	binding := e.localGraphBinding()
	if !binding.containsLeaf(slot.localTXTargetID) {
		return nil
	}
	started := nowFn()
	e.sendHistMu.Lock()
	entry := e.sendHistoryEntryLocked(header.Seq)
	if entry == nil {
		e.sendHistMu.Unlock()
		return nil
	}
	record := entry.batchAttribution
	if record == nil {
		record = &batchDispatchAttributionRecord{
			seq: header.Seq, state: applicationDispatchRouteStateFromEntry(entry), binding: binding,
			applicationBytes: entry.applicationBytes, rootCohort: entry.rootCohort,
			rootCommitted: entry.rootCommitted, rootDemand: entry.rootDemand,
			rootEvidenceEpoch: entry.rootEvidenceEpoch,
			rootTopologyEpoch: entry.rootTopologyEpoch,
		}
		entry.batchAttribution = record
	}
	record.pending++
	e.sendHistMu.Unlock()
	return &batchDispatchAttributionReceipt{
		record: record, targetID: slot.localTXTargetID,
		topologyEpoch: topologyEpoch, started: started,
	}
}

func (e *Engine) resolveApplicationBatchDispatch(
	receipts []*batchDispatchAttributionReceipt,
	completed int,
) {
	if len(receipts) == 0 {
		return
	}
	e.sendHistMu.Lock()
	e.resetTargetDeliveryScratchLocked()
	for index, receipt := range receipts {
		if receipt == nil || receipt.record == nil || receipt.resolved {
			continue
		}
		receipt.resolved = true
		record := receipt.record
		if record.pending <= 0 {
			e.sendHistMu.Unlock()
			panic("engine: batch attribution receipt resolved more than once")
		}
		record.pending--
		if index < completed {
			noteApplicationDispatchTarget(
				&record.state, record.binding, receipt.targetID, receipt.topologyEpoch,
				record.rootCohort, record.rootCommitted, record.rootTopologyEpoch,
			)
			if record.routeStarted.IsZero() || receipt.started.Before(record.routeStarted) {
				record.routeStarted = receipt.started
			}
		}
		if record.pending != 0 {
			continue
		}
		if record.rootPendingTracked {
			record.rootPendingTracked = false
			if record.rootEvidenceEpoch == e.sendHist.rootEvidenceEpoch &&
				e.sendHist.rootPendingDispatches != 0 {
				e.sendHist.rootPendingDispatches--
			}
		}
		if record.detached {
			if record.acked && !e.closing.Load() {
				e.settleAcknowledgedDispatchStateLocked(
					record.binding, record.state, record.applicationBytes,
					record.rootCohort, record.rootDemand, record.rootEvidenceEpoch,
					record.rootTopologyEpoch,
					record.routeStarted, record.ackedAt,
				)
			}
			continue
		}
		entry := e.sendHistoryEntryLocked(record.seq)
		if entry == nil || entry.batchAttribution != record {
			continue
		}
		applyApplicationDispatchRouteState(entry, record.state)
		entry.batchAttribution = nil
		if record.state.deliveryAttributable && !record.routeStarted.IsZero() {
			e.beginTargetDeliveryWindowsLocked(
				record.binding, record.state.deliveryRouteTarget,
				record.state.topologyEpoch, record.routeStarted,
			)
		}
		if record.state.rootRouteSeen && !record.state.rootAttributable {
			e.sendHist.invalidateRootEvidenceEpochLocked(record.rootEvidenceEpoch)
		}
	}
	e.flushTargetDeliveryScratchLocked(nowFn())
	e.sendHistMu.Unlock()
}

func applicationDispatchRouteStateFromEntry(entry *sendHistoryEntry) applicationDispatchRouteState {
	if entry == nil {
		return applicationDispatchRouteState{}
	}
	return applicationDispatchRouteState{
		topologyEpoch: entry.deliveryTopologyEpoch,
		rootRouteSeen: entry.rootRouteSeen, rootRouteTarget: entry.rootRouteTarget,
		rootAttributable:  entry.rootAttributable,
		deliveryRouteSeen: entry.deliveryRouteSeen, deliveryRouteTarget: entry.deliveryRouteTarget,
		deliveryAttributable: entry.deliveryAttributable,
	}
}

func applyApplicationDispatchRouteState(entry *sendHistoryEntry, state applicationDispatchRouteState) {
	entry.rootRouteSeen = state.rootRouteSeen
	entry.rootRouteTarget = state.rootRouteTarget
	entry.rootAttributable = state.rootAttributable
	entry.deliveryRouteSeen = state.deliveryRouteSeen
	entry.deliveryRouteTarget = state.deliveryRouteTarget
	entry.deliveryTopologyEpoch = state.topologyEpoch
	entry.deliveryAttributable = state.deliveryAttributable
}

func noteApplicationDispatchTarget(
	state *applicationDispatchRouteState,
	binding graphBinding,
	routeTarget proto.TargetID,
	topologyEpoch uint64,
	rootCohort rootDeliveryCohort,
	rootCommitted bool,
	rootTopologyEpoch uint64,
) {
	if state == nil {
		return
	}
	if topologyEpoch == 0 {
		state.deliveryRouteSeen = true
		state.deliveryAttributable = false
		state.rootAttributable = false
	} else if state.topologyEpoch == 0 {
		state.topologyEpoch = topologyEpoch
	} else if state.topologyEpoch != topologyEpoch {
		state.deliveryRouteSeen = true
		state.deliveryAttributable = false
		state.rootAttributable = false
	}
	if !binding.containsLeaf(routeTarget) {
		state.deliveryRouteSeen = true
		state.deliveryAttributable = false
	} else if !state.deliveryRouteSeen {
		state.deliveryRouteSeen = true
		state.deliveryRouteTarget = routeTarget
		state.deliveryAttributable = true
	} else if state.deliveryAttributable {
		common, ok := binding.commonTargetAncestor(state.deliveryRouteTarget, routeTarget)
		if !ok {
			state.deliveryAttributable = false
		} else {
			state.deliveryRouteTarget = common
		}
	}
	if rootCohort.targetID == (proto.TargetID{}) {
		return
	}
	rootTarget, ok := binding.rootTargetForLeaf(routeTarget)
	if !state.rootRouteSeen {
		state.rootRouteSeen = true
		state.rootRouteTarget = rootTarget
	} else if state.rootRouteTarget != rootTarget {
		state.rootAttributable = false
	}
	if !ok || !rootCommitted || rootTarget != rootCohort.targetID ||
		topologyEpoch == 0 || topologyEpoch != rootTopologyEpoch {
		state.rootAttributable = false
	}
}

func (e *Engine) beginTargetDeliveryWindowsLocked(
	binding graphBinding,
	targetID proto.TargetID,
	topologyEpoch uint64,
	now time.Time,
) {
	ancestors, ok := binding.targetAncestors(targetID)
	if !ok {
		return
	}
	for _, ancestorID := range ancestors {
		if kind, ok := binding.targetKind(ancestorID); !ok || kind == proto.GraphNodeKindSelector {
			continue
		}
		e.beginTargetDeliveryWindowLocked(ancestorID, topologyEpoch, now)
	}
}

func (e *Engine) resetTargetDeliveryScratchLocked() {
	if e.sendHist.targetDeliveryScratch == nil {
		e.sendHist.targetDeliveryScratch = make(map[proto.TargetID]uint64)
	}
	for _, targetID := range e.sendHist.targetDeliveryTouched {
		delete(e.sendHist.targetDeliveryScratch, targetID)
	}
	e.sendHist.targetDeliveryTouched = e.sendHist.targetDeliveryTouched[:0]
	e.sendHist.targetDeliveryScratchEpoch = e.currentPathTopologyEpoch()
}

func (e *Engine) addAcknowledgedTargetDeliveryLocked(
	binding graphBinding,
	state applicationDispatchRouteState,
	applicationBytes uint64,
	routeStarted, acknowledgedAt time.Time,
) {
	if applicationBytes == 0 || !state.deliveryRouteSeen || !state.deliveryAttributable {
		return
	}
	if state.topologyEpoch == 0 ||
		state.topologyEpoch != e.sendHist.targetDeliveryScratchEpoch ||
		state.topologyEpoch != e.currentPathTopologyEpoch() {
		return
	}
	if routeStarted.IsZero() || acknowledgedAt.Before(routeStarted) {
		routeStarted = acknowledgedAt
	}
	e.beginTargetDeliveryWindowsLocked(
		binding, state.deliveryRouteTarget, state.topologyEpoch, routeStarted,
	)
	ancestors, ok := binding.targetAncestors(state.deliveryRouteTarget)
	if !ok {
		return
	}
	for _, targetID := range ancestors {
		if kind, exists := binding.targetKind(targetID); !exists || kind == proto.GraphNodeKindSelector {
			continue
		}
		if _, touched := e.sendHist.targetDeliveryScratch[targetID]; !touched {
			e.sendHist.targetDeliveryTouched = append(e.sendHist.targetDeliveryTouched, targetID)
		}
		e.sendHist.targetDeliveryScratch[targetID] = saturatingAddUint64(
			e.sendHist.targetDeliveryScratch[targetID], applicationBytes,
		)
	}
}

func (e *Engine) settleAcknowledgedDispatchStateLocked(
	binding graphBinding,
	state applicationDispatchRouteState,
	applicationBytes uint64,
	rootCohort rootDeliveryCohort,
	rootDemand bool,
	rootEvidenceEpoch uint64,
	rootTopologyEpoch uint64,
	routeStarted, acknowledgedAt time.Time,
) {
	e.addAcknowledgedTargetDeliveryLocked(
		binding, state, applicationBytes, routeStarted, acknowledgedAt,
	)
	if applicationBytes == 0 || rootCohort.targetID == (proto.TargetID{}) {
		return
	}
	currentTopologyEpoch := e.currentPathTopologyEpoch()
	if !state.rootRouteSeen || !state.rootAttributable {
		e.sendHist.invalidateRootEvidenceEpochLocked(rootEvidenceEpoch)
		return
	}
	if rootCohort != e.sendHist.rootCohort ||
		rootEvidenceEpoch != e.sendHist.rootEvidenceEpoch ||
		rootTopologyEpoch == 0 || rootTopologyEpoch != currentTopologyEpoch ||
		state.topologyEpoch != currentTopologyEpoch ||
		e.sendHist.rootTopologyEpoch != currentTopologyEpoch ||
		!e.sendHist.rootAttributable {
		return
	}
	e.sendHist.rootAckedBytes = saturatingAddUint64(e.sendHist.rootAckedBytes, applicationBytes)
	if rootDemand {
		e.sendHist.rootDemandAckedBytes = saturatingAddUint64(
			e.sendHist.rootDemandAckedBytes, applicationBytes,
		)
	}
}

func (e *Engine) flushTargetDeliveryScratchLocked(now time.Time) {
	topologyEpoch := e.currentPathTopologyEpoch()
	if topologyEpoch != e.sendHist.targetDeliveryScratchEpoch {
		for _, targetID := range e.sendHist.targetDeliveryTouched {
			delete(e.sendHist.targetDeliveryScratch, targetID)
		}
		e.sendHist.targetDeliveryTouched = e.sendHist.targetDeliveryTouched[:0]
		return
	}
	for _, targetID := range e.sendHist.targetDeliveryTouched {
		e.addTargetDeliveryLocked(
			targetID, topologyEpoch, e.sendHist.targetDeliveryScratch[targetID], now,
		)
		e.sampleTargetDeliveryLocked(targetID, now)
	}
}

func (e *Engine) beginTargetDeliveryWindowLocked(
	targetID proto.TargetID,
	topologyEpoch uint64,
	now time.Time,
) {
	if topologyEpoch == 0 || topologyEpoch != e.currentPathTopologyEpoch() {
		return
	}
	if e.sendHist.targetDelivery == nil {
		e.sendHist.targetDelivery = make(map[proto.TargetID]targetDeliveryEvidence)
	}
	state := e.sendHist.targetDelivery[targetID]
	if state.topologyEpoch != topologyEpoch {
		state = targetDeliveryEvidence{topologyEpoch: topologyEpoch, windowStart: now}
		e.sendHist.targetDelivery[targetID] = state
		return
	}
	if state.windowStart.IsZero() || now.Before(state.windowStart) ||
		now.Sub(state.windowStart) > selectorEvidenceFreshFor {
		state.windowStart = now
		state.windowAcked = state.totalAcked
		if !state.estimate.sampleTime.IsZero() && now.Before(state.estimate.sampleTime) {
			state.estimate = speedEstimate{}
		}
		e.sendHist.targetDelivery[targetID] = state
	}
}

func (e *Engine) addTargetDeliveryLocked(
	targetID proto.TargetID,
	topologyEpoch uint64,
	bytes uint64,
	now time.Time,
) {
	if targetID == (proto.TargetID{}) || topologyEpoch == 0 || bytes == 0 {
		return
	}
	if e.sendHist.targetDelivery == nil {
		e.sendHist.targetDelivery = make(map[proto.TargetID]targetDeliveryEvidence)
	}
	state := e.sendHist.targetDelivery[targetID]
	if state.topologyEpoch != topologyEpoch {
		state = targetDeliveryEvidence{topologyEpoch: topologyEpoch, windowStart: now}
	}
	if state.windowStart.IsZero() || now.Before(state.windowStart) {
		state.windowStart = now
		state.windowAcked = state.totalAcked
		if !state.estimate.sampleTime.IsZero() && now.Before(state.estimate.sampleTime) {
			state.estimate = speedEstimate{}
		}
	}
	state.totalAcked = saturatingAddUint64(state.totalAcked, bytes)
	e.sendHist.targetDelivery[targetID] = state
}

func (e *Engine) sampleTargetDeliveryLocked(targetID proto.TargetID, now time.Time) {
	state := e.sendHist.targetDelivery[targetID]
	elapsed := now.Sub(state.windowStart)
	delta := state.totalAcked - state.windowAcked
	if elapsed >= selectorGoodputMinimumWindow && delta >= selectorGoodputMinimumBytes {
		rate := bytesPerSecond(delta, elapsed)
		if rate != 0 {
			if state.estimate.sampleCount != 0 {
				rate = smoothGoodput(state.estimate.bytesPerSecond, rate)
			}
			state.estimate = speedEstimate{
				state: qualityStateFresh, bytesPerSecond: rate,
				confidence: goodputConfidence(delta, elapsed), source: speedSourceDelivered,
				sampleTime: now, sampleCount: saturatingAddUint64(state.estimate.sampleCount, 1),
			}
		}
		state.windowStart = now
		state.windowAcked = state.totalAcked
	}
	e.sendHist.targetDelivery[targetID] = state
}

func (e *Engine) targetDeliverySpeeds(now time.Time) map[proto.TargetID]speedEstimate {
	out, _ := e.targetDeliverySpeedsAtEpoch(now, e.currentPathTopologyEpoch())
	return out
}

func (e *Engine) targetDeliverySpeedsAtEpoch(
	now time.Time,
	topologyEpoch uint64,
) (map[proto.TargetID]speedEstimate, bool) {
	if topologyEpoch == 0 || e.currentPathTopologyEpoch() != topologyEpoch {
		return nil, false
	}
	e.sendHistMu.Lock()
	if len(e.sendHist.targetDelivery) == 0 {
		e.sendHistMu.Unlock()
		return nil, e.currentPathTopologyEpoch() == topologyEpoch
	}
	out := make(map[proto.TargetID]speedEstimate, len(e.sendHist.targetDelivery))
	for targetID, state := range e.sendHist.targetDelivery {
		if state.topologyEpoch != topologyEpoch {
			continue
		}
		estimate := state.estimate
		if !estimate.sampleTime.IsZero() {
			switch {
			case now.Before(estimate.sampleTime):
				state.estimate = speedEstimate{}
				state.windowStart = now
				state.windowAcked = state.totalAcked
				e.sendHist.targetDelivery[targetID] = state
				continue
			case now.Sub(estimate.sampleTime) > selectorEvidenceFreshFor:
				estimate.state = qualityStateStale
			}
		}
		if estimate.observed() {
			out[targetID] = estimate
		}
	}
	valid := e.currentPathTopologyEpoch() == topologyEpoch
	e.sendHistMu.Unlock()
	if !valid {
		return nil, false
	}
	return out, true
}

func bytesPerSecond(bytes uint64, elapsed time.Duration) uint64 {
	if bytes == 0 || elapsed <= 0 {
		return 0
	}
	nanos := uint64(elapsed)
	if bytes > math.MaxUint64/uint64(time.Second) {
		return math.MaxUint64
	}
	return bytes * uint64(time.Second) / nanos
}

func smoothGoodput(previous, sample uint64) uint64 {
	if sample >= previous {
		return previous + (sample-previous)/4
	}
	return previous - (previous-sample)/4
}

func goodputConfidence(bytes uint64, elapsed time.Duration) evidenceConfidence {
	const fullBytes = 256 << 10
	byteConfidence := uint64(evidenceConfidenceFull)
	if bytes < fullBytes {
		byteConfidence = bytes * uint64(evidenceConfidenceFull) / fullBytes
	}
	timeConfidence := uint64(evidenceConfidenceFull)
	if elapsed < time.Second {
		timeConfidence = uint64(elapsed) * uint64(evidenceConfidenceFull) / uint64(time.Second)
	}
	if timeConfidence < byteConfidence {
		byteConfidence = timeConfidence
	}
	if byteConfidence == 0 {
		byteConfidence = 1
	}
	return evidenceConfidence(byteConfidence)
}

// releaseReplayStateOnClose discards every replay owner after lifecycle
// cancellation has made future publication impossible. Waiting writers wake
// through both closed and the byte-credit generation channel; late releases
// are idempotent because close owns every remaining channel token.
func (e *Engine) releaseReplayStateOnClose() {
	e.cancelTailReplay()
	e.sendHistMu.Lock()
	for i := range e.sendHist.entries {
		e.sendHist.entries[i] = sendHistoryEntry{}
	}
	e.sendHist.entries = nil
	e.sendHist.reservedFrames = 0
	e.sendHist.reservedBytes = 0
	e.sendHist.targetDelivery = nil
	e.sendHist.targetDeliveryScratch = nil
	e.sendHist.targetDeliveryTouched = nil
	e.sendHist.generation++
	wake := e.sendCreditWake
	e.sendCreditWake = make(chan struct{})
	close(wake)
	for {
		select {
		case <-e.sendSlots:
		default:
			goto control
		}
	}

control:
	for {
		select {
		case <-e.sendControlSlots:
		default:
			goto policyFinal
		}
	}

policyFinal:
	for {
		select {
		case <-e.sendPolicyFinalSlots:
		default:
			e.sendHistMu.Unlock()
			return
		}
	}
}

func (e *Engine) sendHistorySnapshot(ackNext uint64) [][]byte {
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()

	if len(e.sendHist.entries) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(e.sendHist.entries))
	for _, entry := range e.sendHist.entries {
		if entry.seq >= ackNext {
			out = append(out, append([]byte(nil), entry.frame...))
		}
	}
	return out
}

func (e *Engine) sendHistoryRange(nextSeq, target uint64) [][]byte {
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	if len(e.sendHist.entries) == 0 || target <= nextSeq {
		return nil
	}
	out := make([][]byte, 0, len(e.sendHist.entries))
	for _, entry := range e.sendHist.entries {
		if entry.seq < nextSeq {
			continue
		}
		if entry.seq >= target {
			break
		}
		out = append(out, append([]byte(nil), entry.frame...))
	}
	return out
}

func (e *Engine) sendHistoryFrame(seq uint64) []byte {
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	entry := e.sendHistoryEntryLocked(seq)
	if entry != nil {
		return append([]byte(nil), entry.frame...)
	}
	return nil
}

func (e *Engine) sendAcknowledgementSnapshot(target uint64) (bool, <-chan struct{}) {
	e.sendHistMu.Lock()
	acked := e.sendAckNext.Load() >= target
	wake := e.sendCreditWake
	e.sendHistMu.Unlock()
	return acked, wake
}

func (e *Engine) applicationDispatchAcknowledged(target uint64) bool {
	if target == 0 {
		return false
	}
	acknowledged, _ := e.sendAcknowledgementSnapshot(target)
	return acknowledged
}

// acknowledgeSendFrames releases every contiguous replay entry below nextSeq.
// It reports whether the ACK proves delivery of application payload; control
// progress alone must not refresh zombie protection.
func (e *Engine) acknowledgeSendFrames(nextSeq uint64, proof proto.AckProof) (valid bool, application bool) {
	return e.acknowledgeSendFramesAt(nextSeq, proof, nowFn())
}

func (e *Engine) acknowledgeSendFramesAt(
	nextSeq uint64,
	proof proto.AckProof,
	receivedAt time.Time,
) (valid bool, application bool) {
	if receivedAt.IsZero() {
		receivedAt = nowFn()
	}
	// The local graph is immutable before any DATA publication. Snapshot it
	// outside the replay hot lock so ACK processing never nests graphMu below
	// sendHistMu.
	binding := e.localGraphBinding()
	e.sendHistMu.Lock()
	current := e.sendAckNext.Load()
	if nextSeq < current {
		e.sendHistMu.Unlock()
		return false, false
	}
	if nextSeq == current {
		valid = proof == e.sendAckProof
		e.sendHistMu.Unlock()
		return valid, false
	}

	if nextSeq == 0 {
		e.sendHistMu.Unlock()
		return false, false
	}
	proofEntry := e.sendHistoryEntryLocked(nextSeq - 1)
	if proofEntry == nil || proof != proofEntry.proof {
		e.sendHistMu.Unlock()
		return false, false
	}

	firstSeq := e.sendHist.entries[0].seq
	if nextSeq < firstSeq || nextSeq-firstSeq > uint64(len(e.sendHist.entries)) {
		e.sendHistMu.Unlock()
		return false, false
	}
	cut := int(nextSeq - firstSeq)
	if cut == 0 {
		e.sendHistMu.Unlock()
		return false, application
	}
	e.sendAckProof = proof
	now := receivedAt
	e.resetTargetDeliveryScratchLocked()
	for i := 0; i < cut; i++ {
		entry := e.sendHist.entries[i]
		application = application || entry.application
		if entry.terminal {
			e.sendHist.entries[i] = sendHistoryEntry{}
			continue
		}
		if entry.control {
			if entry.policyFinal {
				<-e.sendPolicyFinalSlots
			} else {
				<-e.sendControlSlots
			}
			e.sendHist.entries[i] = sendHistoryEntry{}
			continue
		}
		if len(entry.frame) <= 0 || len(entry.frame) > e.sendHist.reservedBytes || e.sendHist.reservedFrames <= 0 {
			e.sendHistMu.Unlock()
			panic("engine: acknowledged replay credit invariant violated")
		}
		applicationBytes := sendHistoryApplicationBytes(entry)
		e.sendHist.ackedApplicationBytes = saturatingAddUint64(e.sendHist.ackedApplicationBytes, applicationBytes)
		if record := entry.batchAttribution; record != nil {
			record.detached = true
			record.acked = true
			record.ackedAt = now
			if record.pending != 0 && !record.rootPendingTracked && entry.rootAttributable &&
				record.rootEvidenceEpoch != 0 && record.rootEvidenceEpoch == e.sendHist.rootEvidenceEpoch &&
				record.rootCohort == e.sendHist.rootCohort {
				e.sendHist.rootPendingDispatches++
				record.rootPendingTracked = true
			}
			if record.pending == 0 {
				e.settleAcknowledgedDispatchStateLocked(
					record.binding, record.state, record.applicationBytes,
					record.rootCohort, record.rootDemand, record.rootEvidenceEpoch,
					record.rootTopologyEpoch,
					record.routeStarted, now,
				)
			}
		} else {
			state := applicationDispatchRouteStateFromEntry(&entry)
			e.settleAcknowledgedDispatchStateLocked(
				binding, state, applicationBytes,
				entry.rootCohort, entry.rootDemand, entry.rootEvidenceEpoch,
				entry.rootTopologyEpoch,
				now, now,
			)
		}
		e.sendHist.reservedFrames--
		e.sendHist.reservedBytes -= len(entry.frame)
		<-e.sendSlots
		e.sendHist.entries[i] = sendHistoryEntry{}
	}
	e.flushTargetDeliveryScratchLocked(now)
	// Reslicing avoids copying every still-unacknowledged frame on each
	// cumulative ACK. Append occasionally compacts through Go's amortized
	// growth, so retirement cost is proportional only to the released prefix.
	e.sendHist.entries = e.sendHist.entries[cut:]
	e.sendAckNext.Store(nextSeq)
	e.sendACKProgress.Store(&sendACKProgressObservation{next: nextSeq, at: now})
	e.sendHist.generation++
	wake := e.sendCreditWake
	e.sendCreditWake = make(chan struct{})
	close(wake)
	e.sendHistMu.Unlock()
	e.completeReplayPublicationBarrier(nextSeq)
	return true, application
}
