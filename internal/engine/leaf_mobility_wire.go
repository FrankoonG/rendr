package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
)

// ErrLeafMobilityControlRouteUnavailable means no path is independent from
// the mobility subject and currently eligible to carry its OOB control frame.
var ErrLeafMobilityControlRouteUnavailable = errors.New("engine: leaf mobility control route unavailable")

const (
	leafMobilityControlRouteAttemptLimit = time.Second
	leafMobilityResponseRetryInterval    = 5 * time.Millisecond
)

type leafMobilityControlCandidate struct {
	ref                  PathRef
	slot                 *pathSlot
	subject              *pathSlot
	allowDetachedSubject bool
}

func (e *Engine) routeLeafMobilityOOB(slot *pathSlot, header proto.Header, payload []byte) error {
	control := pathRefForSlot(slot)
	if control.ID == 0 {
		return nil
	}
	message := leafMobilityMessage{seq: header.Seq}
	var binding proto.LeafMobilityPeerPlanBinding
	switch code := proto.CtrlCodeFromFlags(header.Flags); code {
	case proto.CtrlLeafMobilityPrepare:
		prepare, err := proto.DecodeLeafMobilityPeerPlanPrepare(payload)
		if err != nil {
			return fmt.Errorf("malformed LEAF_MOBILITY_PREPARE: %w", err)
		}
		message.kind, message.prepare = leafMobilityMessagePrepare, prepare
		binding = prepare.LeafMobilityPeerPlanBinding
	case proto.CtrlLeafMobilityAck:
		ack, err := proto.DecodeLeafMobilityPeerPlanAck(payload)
		if err != nil {
			return fmt.Errorf("malformed LEAF_MOBILITY_ACK: %w", err)
		}
		message.kind, message.ack = leafMobilityMessageAck, ack
		binding = ack.LeafMobilityPeerPlanBinding
	case proto.CtrlLeafMobilityCommit:
		commit, err := proto.DecodeLeafMobilityPeerPlanCommit(payload)
		if err != nil {
			return fmt.Errorf("malformed LEAF_MOBILITY_COMMIT: %w", err)
		}
		message.kind, message.commit = leafMobilityMessageCommit, commit
		binding = commit.LeafMobilityPeerPlanBinding
	default:
		return fmt.Errorf("unknown leaf mobility control %s", code)
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	if binding.SessionEpoch != proto.SessionEpoch(e.FlowID()) {
		return nil
	}
	subject, subjectSlot, ok := e.resolveLeafMobilitySubject(binding)
	if !ok {
		return nil
	}
	conflictsBinding := e.leafMobilityControlConflictsWithBinding(slot, binding)
	conflictsSubject := e.leafMobilityControlConflictsWithSubject(slot, subject)
	if control == subject || conflictsBinding || conflictsSubject {
		// A stale exact frame can legitimately arrive after its former path was
		// replaced. It is not an independent control route, so drop it without
		// authorizing state or turning a harmless replay into a session close.
		return nil
	}
	message.source = subject
	message.sourceSlot = subjectSlot
	key := leafMobilityOOBKey{source: subject, seq: header.Seq}
	digest := recvFrameDigest(header, payload)
	now := time.Now()
	e.leafTx.oobMu.Lock()
	for seenKey, record := range e.leafTx.oobSeen {
		if !now.Before(record.retireAfter) {
			delete(e.leafTx.oobSeen, seenKey)
		}
	}
	if record, seen := e.leafTx.oobSeen[key]; seen {
		if record.digest != digest {
			e.leafTx.oobMu.Unlock()
			return fmt.Errorf("altered leaf mobility OOB frame reused message sequence %d", header.Seq)
		}
		message.replayed = true
	} else {
		if len(e.leafTx.oobSeen) >= leafMobilityOOBRecordLimit {
			e.leafTx.oobMu.Unlock()
			// Exact replay protection cannot be weakened by admitting an
			// unrecorded frame. Drop it and let the actor retry after bounded
			// records retire; capacity pressure is not a peer protocol error.
			return nil
		}
		e.leafTx.oobSeen[key] = leafMobilityOOBRecord{
			digest: digest, retireAfter: now.Add(e.leafMobilityRecordRetention()),
		}
	}
	e.leafTx.oobMu.Unlock()
	if !e.enqueueLeafMobilityMessageLocked(message) {
		return fmt.Errorf("leaf mobility inbox capacity exceeded")
	}
	return nil
}

func (e *Engine) leafMobilityControlConflictsWithSubject(control *pathSlot, subject PathRef) bool {
	e.pathsMu.RLock()
	subjectSlot := e.leafMobilitySubjectSlotLocked(subject)
	conflicts := subjectSlot != nil && subjectSlot.owner == subject.Owner && control != nil &&
		(control.localTXTargetID == subjectSlot.localTXTargetID && control.peerTXTargetID == subjectSlot.peerTXTargetID)
	if !conflicts && subjectSlot != nil && subjectSlot.owner == subject.Owner && control != nil &&
		subjectSlot.mobilityClaim != nil && control.mobilityClaim != nil {
		subjectResource := subjectSlot.mobilityClaim.Snapshot().ResourceID
		conflicts = subjectResource != (leafmobility.ResourceID{}) && subjectResource == control.mobilityClaim.Snapshot().ResourceID
	}
	e.pathsMu.RUnlock()
	return conflicts
}

func (e *Engine) leafMobilityControlConflictsWithBinding(
	control *pathSlot,
	binding proto.LeafMobilityPeerPlanBinding,
) bool {
	if control == nil {
		return false
	}
	localTarget, peerTarget := binding.SubjectClientTargetID, binding.SubjectServerTargetID
	if e.side == SideServer {
		localTarget, peerTarget = peerTarget, localTarget
	}
	if control.localTXTargetID == localTarget && control.peerTXTargetID == peerTarget {
		return true
	}
	if control.mobilityClaim == nil || binding.ResourceID == (proto.LeafMobilityResourceID{}) {
		return false
	}
	resourceID := control.mobilityClaim.Snapshot().ResourceID
	return resourceID != (leafmobility.ResourceID{}) &&
		proto.LeafMobilityResourceID(resourceID) == binding.ResourceID
}

func (e *Engine) resolveLeafMobilitySubject(binding proto.LeafMobilityPeerPlanBinding) (PathRef, *pathSlot, bool) {
	localTarget, peerTarget := binding.SubjectClientTargetID, binding.SubjectServerTargetID
	if e.side == SideServer {
		localTarget, peerTarget = peerTarget, localTarget
	}
	e.pathsMu.RLock()
	var subject PathRef
	var subjectSlot *pathSlot
	for _, slots := range []map[uint32]*pathSlot{e.paths, e.retainedPaths, e.stagedPaths} {
		for _, candidate := range slots {
			if candidate.localTXTargetID != localTarget || candidate.peerTXTargetID != peerTarget ||
				candidate.routeGeneration.Load() != binding.SubjectRouteGeneration {
				continue
			}
			if subject.ID != 0 && subject != pathRefForSlot(candidate) {
				e.pathsMu.RUnlock()
				return PathRef{}, nil, false
			}
			subject = pathRefForSlot(candidate)
			subjectSlot = candidate
		}
	}
	e.pathsMu.RUnlock()
	if subject.ID != 0 {
		return subject, subjectSlot, true
	}

	// A transaction keeps its exact subject owner after administrative
	// topology retirement so FINAL/RELEASED can still arrive over a sibling
	// control route. This is lookup evidence only; it never reactivates the
	// retired subject for DATA.
	e.leafTx.mu.Lock()
	defer e.leafTx.mu.Unlock()
	if outgoing := e.leafTx.outgoing; outgoing != nil &&
		outgoing.prepare.LeafMobilityPeerPlanBinding == binding {
		return outgoing.source, outgoing.sourceSlot, true
	}
	if incoming := e.leafTx.incoming[binding.TransactionID]; incoming != nil &&
		incoming.prepare.LeafMobilityPeerPlanBinding == binding {
		return incoming.source, incoming.sourceSlot, true
	}
	if completed, ok := e.leafTx.completed[binding.TransactionID]; ok &&
		completed.prepare.LeafMobilityPeerPlanBinding == binding {
		return completed.source, completed.sourceSlot, true
	}
	if rejected, ok := e.leafTx.rejected[binding.TransactionID]; ok &&
		rejected.prepare.LeafMobilityPeerPlanBinding == binding {
		return rejected.source, rejected.sourceSlot, true
	}
	if terminal, ok := e.leafTx.actorTerminal[binding.TransactionID]; ok &&
		terminal.prepare.LeafMobilityPeerPlanBinding == binding {
		return terminal.source, terminal.sourceSlot, true
	}
	if source, slot, ok := e.leafTx.activeClientWinnerForServerPrepareLocked(binding); ok {
		return source, slot, true
	}
	// A client-priority transaction can finish and advance the subject route
	// generation before the crossed server PREPARE is dispatched from the
	// sibling control path. Keep destructive lookup generation-exact, but let
	// the completed client tombstone identify that one stale proposal so the
	// responder can publish its immutable Busy decision.
	if source, slot, ok := e.leafTx.completedClientWinnerForServerPrepareLocked(binding); ok {
		return source, slot, true
	}
	return PathRef{}, nil, false
}

func (e *Engine) validateLeafMobilitySource(ref PathRef, plan leafmobility.Plan) (*leafmobility.Claim, *pathSlot, error) {
	if e == nil || ref.ID == 0 || ref.Owner == 0 || e.isClosed() || e.sendClosing.Load() {
		return nil, nil, net.ErrClosed
	}
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner || slot.mobilityClaim == nil || slot.maintenance.Load() ||
		slot.routeGeneration.Load() == 0 || plan.Binding.PathID != ref.ID || plan.Binding.Owner != ref.Owner {
		e.pathsMu.RUnlock()
		return nil, nil, ErrStalePathRef
	}
	key, valid := pathAdmissionKey(e.side, PathBinding{
		LocalTXTargetID: slot.localTXTargetID, PeerTXTargetID: slot.peerTXTargetID,
	})
	_, admission := e.pathAdmissionByLeaf[key]
	predecessors := len(e.pathPredecessors[ref.ID])
	claim := slot.mobilityClaim
	e.pathsMu.RUnlock()
	if !valid || admission || predecessors != 0 {
		return nil, nil, ErrLeafMobilityAdmissionBusy
	}
	if err := claim.ValidatePlanCurrent(plan); err != nil {
		return nil, nil, err
	}
	return claim, slot, nil
}

func (e *Engine) leafClaimForRef(ref PathRef) (*leafmobility.Claim, *pathSlot, bool) {
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner || slot.mobilityClaim == nil || slot.maintenance.Load() {
		e.pathsMu.RUnlock()
		return nil, nil, false
	}
	claim := slot.mobilityClaim
	e.pathsMu.RUnlock()
	return claim, slot, true
}

func (e *Engine) leafSourceCurrent(ref PathRef, claim *leafmobility.Claim) bool {
	e.pathsMu.RLock()
	ok := e.leafSourceCurrentLocked(ref, claim)
	e.pathsMu.RUnlock()
	return ok
}

func (e *Engine) leafSourceCurrentLocked(ref PathRef, claim *leafmobility.Claim) bool {
	slot := e.paths[ref.ID]
	return slot != nil && slot.owner == ref.Owner && slot.mobilityClaim == claim && !slot.maintenance.Load()
}

func (e *Engine) validateLeafMobilityAuthoritySource(outgoing *outgoingLeafMobilityTransaction) error {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	return e.validateLeafMobilityAuthoritySourceLocked(outgoing)
}

// validateLeafMobilityAuthoritySourceLocked is the final ownership check used
// at execution-authority consumption. The caller keeps pathsMu read-locked
// through the resource state transition so path retirement and Engine.Close
// cannot land between validation and consumption.
func (e *Engine) validateLeafMobilityAuthoritySourceLocked(outgoing *outgoingLeafMobilityTransaction) error {
	if outgoing == nil || outgoing.claim == nil || e.isClosed() || e.sendClosing.Load() {
		return net.ErrClosed
	}
	slot := e.paths[outgoing.source.ID]
	if slot == nil || slot.owner != outgoing.source.Owner || slot.mobilityClaim != outgoing.claim || slot.maintenance.Load() ||
		slot.routeGeneration.Load() == 0 || slot.routeGeneration.Load() != outgoing.prepare.SubjectRouteGeneration {
		return ErrStalePathRef
	}
	plan := outgoing.resourceTx.Snapshot().Plan
	state := outgoing.claim.State()
	if state.Retired || !state.Bound || state.Binding != plan.Binding ||
		state.Facts.Generation != plan.EndpointGeneration || state.Facts.Kind != plan.Kind ||
		state.Facts.Role != plan.Role || state.Facts.Scope != plan.Scope ||
		state.Facts.ResourceID != plan.ResourceID || !state.Facts.Operations.Has(plan.Operation) {
		return leafmobility.ErrAuthorityStale
	}
	return nil
}

func (e *Engine) validateIncomingLeafMobilityBinding(ref PathRef, binding proto.LeafMobilityPeerPlanBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if binding.ActorSide == protocolActorSide(e.side) {
		return fmt.Errorf("local endpoint cannot receive its own actor transaction")
	}
	if binding.SessionEpoch != proto.SessionEpoch(e.FlowID()) || binding.SessionKind != e.protocolLeafSession() {
		return fmt.Errorf("leaf mobility session binding mismatch")
	}
	e.graphMu.RLock()
	localGraph, peerGraph := e.localGraph, e.peerGraph
	localNegotiation, peerNegotiation := e.localNegotiation, e.peerNegotiation
	localSet, peerSet := e.localNegotiationSet, e.peerNegotiationSet
	e.graphMu.RUnlock()
	if !localSet || !peerSet {
		return ErrLeafMobilityNotNegotiated
	}
	wireOperation := leafMobilitySetForOperation(binding.Operation)
	if !localNegotiation.MobilitySupported.Has(wireOperation) || !peerNegotiation.MobilitySupported.Has(wireOperation) {
		return fmt.Errorf("leaf mobility operation is not bilaterally negotiated")
	}
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner || slot.routeGeneration.Load() == 0 ||
		binding.SubjectRouteGeneration != slot.routeGeneration.Load() {
		e.pathsMu.RUnlock()
		return ErrStalePathRef
	}
	localTarget, peerTarget := slot.localTXTargetID, slot.peerTXTargetID
	e.pathsMu.RUnlock()
	clientGraph := proto.GraphBinding{Revision: localGraph.revision, Digest: localGraph.digest}
	serverGraph := proto.GraphBinding{Revision: peerGraph.revision, Digest: peerGraph.digest}
	clientTarget, serverTarget := localTarget, peerTarget
	if e.side == SideServer {
		clientGraph, serverGraph = serverGraph, clientGraph
		clientTarget, serverTarget = peerTarget, localTarget
	}
	if binding.ClientGraph != clientGraph || binding.ServerGraph != serverGraph ||
		binding.SubjectClientTargetID != clientTarget || binding.SubjectServerTargetID != serverTarget {
		return fmt.Errorf("leaf mobility graph or target binding mismatch")
	}
	return nil
}

func (e *Engine) canonicalLeafMobilityBinding(plan leafmobility.Plan, leaseMillis uint32) proto.LeafMobilityPeerPlanBinding {
	e.graphMu.RLock()
	localGraph, peerGraph := e.localGraph, e.peerGraph
	e.graphMu.RUnlock()
	e.pathsMu.RLock()
	slot := e.paths[plan.Binding.PathID]
	var routeGeneration uint64
	if slot != nil && slot.owner == plan.Binding.Owner {
		routeGeneration = slot.routeGeneration.Load()
	}
	e.pathsMu.RUnlock()
	binding := proto.LeafMobilityPeerPlanBinding{
		CoordinatorSide:        proto.LeafMobilityActorClient,
		ActorSide:              protocolActorSide(e.side),
		Direction:              plan.Direction,
		SessionKind:            protocolLeafSession(plan.Session),
		Operation:              protocolLeafOperation(plan.Operation),
		Fallback:               proto.LeafMobilityFallbackRedialAttach,
		LeaseMillis:            leaseMillis,
		SessionEpoch:           proto.SessionEpoch(plan.Binding.FlowID),
		TransactionID:          [16]byte(plan.TransactionID),
		BaseGeneration:         plan.BaseGeneration,
		ResourceScope:          protocolLeafScope(plan.Scope),
		ResourceID:             proto.LeafMobilityResourceID(plan.ResourceID),
		SubjectRouteGeneration: routeGeneration,
	}
	if e.side == SideClient {
		binding.ClientGraph = proto.GraphBinding{Revision: localGraph.revision, Digest: localGraph.digest}
		binding.ServerGraph = proto.GraphBinding{Revision: peerGraph.revision, Digest: peerGraph.digest}
		binding.SubjectClientTargetID = proto.TargetID(plan.Binding.LocalTargetID)
		binding.SubjectServerTargetID = proto.TargetID(plan.Binding.PeerTargetID)
	} else {
		binding.ClientGraph = proto.GraphBinding{Revision: peerGraph.revision, Digest: peerGraph.digest}
		binding.ServerGraph = proto.GraphBinding{Revision: localGraph.revision, Digest: localGraph.digest}
		binding.SubjectClientTargetID = proto.TargetID(plan.Binding.PeerTargetID)
		binding.SubjectServerTargetID = proto.TargetID(plan.Binding.LocalTargetID)
	}
	return binding
}

func protocolActorSide(side Side) proto.LeafMobilityActorSide {
	if side == SideClient {
		return proto.LeafMobilityActorClient
	}
	return proto.LeafMobilityActorServer
}

func (e *Engine) protocolLeafSession() proto.LeafMobilitySessionKind {
	if e.Packetized() {
		return proto.LeafMobilitySessionPacket
	}
	return proto.LeafMobilitySessionStream
}

func protocolLeafSession(session leafmobility.Session) proto.LeafMobilitySessionKind {
	switch session {
	case leafmobility.SessionStream:
		return proto.LeafMobilitySessionStream
	case leafmobility.SessionPacket:
		return proto.LeafMobilitySessionPacket
	default:
		return proto.LeafMobilitySessionInvalid
	}
}

func protocolLeafOperation(operation leafmobility.Operation) proto.LeafMobilityOperation {
	switch operation {
	case leafmobility.OperationTCPRepair:
		return proto.LeafMobilityOperationTCPRepair
	case leafmobility.OperationQUICCIDRebind:
		return proto.LeafMobilityOperationQUICCIDRebind
	case leafmobility.OperationUDPFlowRebind:
		return proto.LeafMobilityOperationUDPFlowRebind
	case leafmobility.OperationGVisorLinkRebind:
		return proto.LeafMobilityOperationGVisorLinkRebind
	default:
		return proto.LeafMobilityOperationInvalid
	}
}

func protocolLeafScope(scope leafmobility.Scope) proto.LeafMobilityResourceScope {
	switch scope {
	case leafmobility.ScopeEndpoint:
		return proto.LeafMobilityResourceEndpoint
	case leafmobility.ScopeSharedLink:
		return proto.LeafMobilityResourceSharedLink
	case leafmobility.ScopeProcessLocal:
		return proto.LeafMobilityResourceProcessLocal
	default:
		return proto.LeafMobilityResourceInvalid
	}
}

func leafMobilitySetForOperation(operation proto.LeafMobilityOperation) proto.LeafMobilitySet {
	switch operation {
	case proto.LeafMobilityOperationTCPRepair:
		return proto.LeafMobilityTCPRepair
	case proto.LeafMobilityOperationQUICCIDRebind:
		return proto.LeafMobilityQUICCIDRebind
	case proto.LeafMobilityOperationUDPFlowRebind:
		return proto.LeafMobilityUDPFlowRebind
	case proto.LeafMobilityOperationGVisorLinkRebind:
		return proto.LeafMobilityGVisorLinkRebind
	default:
		return 0
	}
}

func newLeafMobilityReservationID() (proto.LeafMobilityReservationID, error) {
	var id proto.LeafMobilityReservationID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	if id == (proto.LeafMobilityReservationID{}) {
		return id, fmt.Errorf("generated zero leaf mobility reservation")
	}
	return id, nil
}

func (e *Engine) sendLeafMobilityPrepare(
	ref PathRef,
	prepare proto.LeafMobilityPeerPlanPrepare,
) ([]byte, error) {
	return e.sendLeafMobilityPrepareContext(context.Background(), ref, prepare)
}

func (e *Engine) sendLeafMobilityPrepareContext(
	ctx context.Context,
	ref PathRef,
	prepare proto.LeafMobilityPeerPlanPrepare,
) ([]byte, error) {
	payload, err := prepare.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendLeafMobilityFrameAtContext(ctx, ref, proto.CtrlLeafMobilityPrepare, payload, nil)
}

func (e *Engine) sendLeafMobilityCommitAt(
	ref PathRef,
	commit proto.LeafMobilityPeerPlanCommit,
	onPublish func([]byte) error,
) ([]byte, error) {
	return e.sendLeafMobilityCommitAtContext(context.Background(), ref, commit, onPublish)
}

func (e *Engine) sendLeafMobilityCommitAtContext(
	ctx context.Context,
	ref PathRef,
	commit proto.LeafMobilityPeerPlanCommit,
	onPublish func([]byte) error,
) ([]byte, error) {
	payload, err := commit.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendLeafMobilityFrameAtContext(ctx, ref, proto.CtrlLeafMobilityCommit, payload, onPublish)
}

func (e *Engine) sendLeafMobilityCommitForOutgoing(
	outgoing *outgoingLeafMobilityTransaction,
	commit proto.LeafMobilityPeerPlanCommit,
	onPublish func([]byte) error,
) ([]byte, error) {
	return e.sendLeafMobilityCommitForOutgoingContext(context.Background(), outgoing, commit, onPublish)
}

func (e *Engine) sendLeafMobilityCommitForOutgoingContext(
	ctx context.Context,
	outgoing *outgoingLeafMobilityTransaction,
	commit proto.LeafMobilityPeerPlanCommit,
	onPublish func([]byte) error,
) ([]byte, error) {
	if outgoing == nil {
		return nil, ErrStalePathRef
	}
	payload, err := commit.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendLeafMobilityFrameOnSlotContext(
		ctx,
		outgoing.source, outgoing.sourceSlot, proto.CtrlLeafMobilityCommit, payload, onPublish,
	)
}

func (e *Engine) sendLeafMobilityAckBounded(
	ref PathRef,
	ack proto.LeafMobilityPeerPlanAck,
	deadline time.Time,
	onPublish func([]byte),
) ([]byte, error) {
	return e.sendLeafMobilityAckBoundedOnSlot(ref, nil, ack, deadline, onPublish)
}

func (e *Engine) sendLeafMobilityAckBoundedOnSlot(
	ref PathRef,
	sourceSlot *pathSlot,
	ack proto.LeafMobilityPeerPlanAck,
	deadline time.Time,
	onPublish func([]byte),
) ([]byte, error) {
	payload, err := ack.Encode()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	select {
	case e.leafTx.responseGate <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", errLeafMobilityResponseUnavailable, ctx.Err())
	case <-e.closed:
		return nil, net.ErrClosed
	}
	routeRetryUntil := time.Now().Add(leafMobilityControlRouteAttemptLimit)
	if deadline.Before(routeRetryUntil) {
		routeRetryUntil = deadline
	}
	var frame []byte
	for {
		retryWake := e.leafMobilityRetryChannel()
		attemptFrame, sendErr, pending := e.sendLeafMobilityFrameWithContext(ctx, func(writeCtx context.Context) ([]byte, error) {
			if len(frame) != 0 {
				controlRoutes, routeErr := e.leafMobilityControlRoutesWithSubject(ref, sourceSlot)
				if routeErr != nil {
					return frame, routeErr
				}
				return frame, e.writeLeafMobilityFrameOnControlRoutes(writeCtx, ref, controlRoutes, frame)
			}
			return e.sendLeafMobilityFrameOnSlotContext(writeCtx, ref, sourceSlot, proto.CtrlLeafMobilityAck, payload, func(published []byte) error {
				if onPublish != nil {
					onPublish(published)
				}
				return nil
			})
		})
		if len(frame) == 0 && len(attemptFrame) != 0 {
			frame = attemptFrame
		}
		if pending != nil {
			select {
			case outcome := <-pending:
				if len(frame) == 0 && len(outcome.frame) != 0 {
					frame = outcome.frame
				}
				<-e.leafTx.responseGate
				return frame, leafMobilityResponseWriteError(outcome.err)
			case <-time.After(time.Second):
				cleanup := func() {
					<-pending
					<-e.leafTx.responseGate
				}
				if !e.startLeafMobilityAsync(cleanup) {
					cleanup()
				}
				return frame, leafMobilityResponseWriteError(sendErr)
			}
		}
		if sendErr == nil {
			<-e.leafTx.responseGate
			return frame, nil
		}
		if !leafMobilityResponseRouteRetryable(sendErr) {
			<-e.leafTx.responseGate
			return frame, leafMobilityResponseWriteError(sendErr)
		}
		retryDelay := time.Until(routeRetryUntil)
		if retryDelay <= 0 {
			<-e.leafTx.responseGate
			return frame, leafMobilityResponseWriteError(sendErr)
		}
		if retryDelay > leafMobilityResponseRetryInterval {
			retryDelay = leafMobilityResponseRetryInterval
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-retryWake:
			stopLeafMobilityResponseTimer(timer)
		case <-timer.C:
		case <-ctx.Done():
			stopLeafMobilityResponseTimer(timer)
			<-e.leafTx.responseGate
			return frame, leafMobilityResponseWriteError(ctx.Err())
		case <-e.closed:
			stopLeafMobilityResponseTimer(timer)
			<-e.leafTx.responseGate
			return frame, net.ErrClosed
		}
	}
}

func leafMobilityResponseRouteRetryable(err error) bool {
	return err == ErrLeafMobilityControlRouteUnavailable || err == ErrStalePathRef
}

func stopLeafMobilityResponseTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (e *Engine) replayLeafMobilityResponse(ref PathRef, frame []byte, deadline time.Time) error {
	return e.replayLeafMobilityResponseOnSlot(ref, nil, frame, deadline)
}

func (e *Engine) replayLeafMobilityResponseOnSlot(ref PathRef, sourceSlot *pathSlot, frame []byte, deadline time.Time) error {
	if len(frame) == 0 {
		return fmt.Errorf("%w: empty cached response frame", errLeafMobilityResponseUnavailable)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	select {
	case e.leafTx.responseGate <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", errLeafMobilityResponseUnavailable, ctx.Err())
	case <-e.closed:
		return net.ErrClosed
	}
	_, err, pending := e.sendLeafMobilityFrameWithContext(ctx, func(writeCtx context.Context) ([]byte, error) {
		if sourceSlot == nil {
			return frame, e.replayLeafMobilityFrameContext(writeCtx, ref, frame)
		}
		if len(frame) < proto.HeaderSize {
			return frame, proto.ErrBadHeader
		}
		header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr != nil || header.Type != proto.FrameCtrl || !isLeafMobilityCtrl(proto.CtrlCodeFromFlags(header.Flags)) ||
			header.Seq == 0 || header.Last {
			return frame, proto.ErrBadHeader
		}
		controlRoutes, routeErr := e.leafMobilityControlRoutesWithSubject(ref, sourceSlot)
		if routeErr != nil {
			return frame, routeErr
		}
		return frame, e.writeLeafMobilityFrameOnControlRoutes(writeCtx, ref, controlRoutes, frame)
	})
	if pending == nil {
		<-e.leafTx.responseGate
		return leafMobilityResponseWriteError(err)
	}
	cleanup := func() {
		<-pending
		<-e.leafTx.responseGate
	}
	if !e.startLeafMobilityAsync(cleanup) {
		cleanup()
	}
	return leafMobilityResponseWriteError(err)
}

func leafMobilityResponseWriteError(err error) error {
	if err == nil || errors.Is(err, proto.ErrBadHeader) {
		return err
	}
	return fmt.Errorf("%w: %v", errLeafMobilityResponseUnavailable, err)
}

func (e *Engine) leafMobilityReceiptDeadline(original time.Time) time.Time {
	if original.After(time.Now()) {
		return original
	}
	grace := e.limits.MigrationBudget
	if grace <= 0 || grace > time.Second {
		grace = time.Second
	}
	return time.Now().Add(grace)
}

func (e *Engine) sendLeafMobilityFrameAt(
	ref PathRef,
	code proto.CtrlCode,
	payload []byte,
	onPublish func([]byte) error,
) ([]byte, error) {
	return e.sendLeafMobilityFrameAtContext(context.Background(), ref, code, payload, onPublish)
}

func (e *Engine) sendLeafMobilityFrameAtContext(
	ctx context.Context,
	ref PathRef,
	code proto.CtrlCode,
	payload []byte,
	onPublish func([]byte) error,
) ([]byte, error) {
	return e.sendLeafMobilityFrameOnSlotContext(ctx, ref, nil, code, payload, onPublish)
}

func (e *Engine) sendLeafMobilityFrameOnSlot(
	ref PathRef,
	sourceSlot *pathSlot,
	code proto.CtrlCode,
	payload []byte,
	onPublish func([]byte) error,
) ([]byte, error) {
	return e.sendLeafMobilityFrameOnSlotContext(context.Background(), ref, sourceSlot, code, payload, onPublish)
}

func (e *Engine) sendLeafMobilityFrameOnSlotContext(
	ctx context.Context,
	ref PathRef,
	sourceSlot *pathSlot,
	code proto.CtrlCode,
	payload []byte,
	onPublish func([]byte) error,
) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.isClosed() || e.sendClosing.Load() {
		return nil, net.ErrClosed
	}
	controlRoutes, err := e.leafMobilityControlRoutesWithSubject(ref, sourceSlot)
	if err != nil {
		return nil, err
	}
	seq := e.leafTx.messageSeq.Add(1)
	if seq == 0 || seq > proto.MaxSeq {
		return nil, fmt.Errorf("leaf mobility message sequence exhausted")
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	header := proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Flags: proto.FlagsForCtrl(code), Seq: seq}
	if err := header.Encode(frame[:proto.HeaderSize]); err != nil {
		return nil, err
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if onPublish != nil {
		if err := onPublish(frame); err != nil {
			return nil, err
		}
	}
	writeErr := e.writeLeafMobilityFrameOnControlRoutes(ctx, ref, controlRoutes, frame)
	if writeErr != nil {
		return frame, writeErr
	}
	return frame, nil
}

func (e *Engine) replayLeafMobilityFrameForOutgoing(outgoing *outgoingLeafMobilityTransaction, frame []byte) error {
	return e.replayLeafMobilityFrameForOutgoingContext(context.Background(), outgoing, frame)
}

func (e *Engine) replayLeafMobilityFrameForOutgoingContext(
	ctx context.Context,
	outgoing *outgoingLeafMobilityTransaction,
	frame []byte,
) error {
	if outgoing == nil || len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	if e.isClosed() || e.sendClosing.Load() {
		return net.ErrClosed
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl || !isLeafMobilityCtrl(proto.CtrlCodeFromFlags(header.Flags)) ||
		header.Seq == 0 || header.Last {
		return proto.ErrBadHeader
	}
	controlRoutes, err := e.leafMobilityControlRoutesWithSubject(outgoing.source, outgoing.sourceSlot)
	if err != nil {
		return err
	}
	return e.writeLeafMobilityFrameOnControlRoutes(ctx, outgoing.source, controlRoutes, frame)
}

func (e *Engine) replayLeafMobilityFrame(ref PathRef, frame []byte) error {
	return e.replayLeafMobilityFrameContext(context.Background(), ref, frame)
}

func (e *Engine) replayLeafMobilityFrameContext(ctx context.Context, ref PathRef, frame []byte) error {
	if len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	if e.isClosed() || e.sendClosing.Load() {
		return net.ErrClosed
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl || !isLeafMobilityCtrl(proto.CtrlCodeFromFlags(header.Flags)) ||
		header.Seq == 0 || header.Last {
		return proto.ErrBadHeader
	}
	// Transaction state owns the exact frame, but not its control route. The
	// replay stays outside the application DATA replay/ACK domain.
	return e.writeLeafMobilityFrame(ctx, ref, frame)
}

func (e *Engine) writeLeafMobilityFrame(ctx context.Context, ref PathRef, frame []byte) error {
	controlRoutes, err := e.leafMobilityControlRoutes(ref)
	if err != nil {
		return err
	}
	return e.writeLeafMobilityFrameOnControlRoutes(ctx, ref, controlRoutes, frame)
}

func (e *Engine) leafMobilityControlRoutes(subject PathRef) ([]leafMobilityControlCandidate, error) {
	return e.leafMobilityControlRoutesWithSubject(subject, nil)
}

func (e *Engine) leafMobilityControlRoutesWithSubject(
	subject PathRef,
	subjectHint *pathSlot,
) ([]leafMobilityControlCandidate, error) {
	e.pathsMu.RLock()
	subjectSlot := e.leafMobilitySubjectSlotLocked(subject)
	allowDetachedSubject := false
	if subjectSlot == nil && subjectHint != nil && subjectHint.id == subject.ID && subjectHint.owner == subject.Owner {
		subjectSlot = subjectHint
		allowDetachedSubject = true
	}
	if subjectSlot == nil {
		e.pathsMu.RUnlock()
		return nil, ErrStalePathRef
	}
	candidateCapacity := len(e.paths)
	if candidateCapacity > 0 {
		candidateCapacity--
	}
	candidates := make([]leafMobilityControlCandidate, 0, candidateCapacity)
	for _, slot := range e.paths {
		if !e.leafMobilityControlSlotEligibleLocked(subjectSlot, slot) {
			continue
		}
		candidates = append(candidates, leafMobilityControlCandidate{
			ref: pathRefForSlot(slot), slot: slot, subject: subjectSlot,
			allowDetachedSubject: allowDetachedSubject,
		})
	}
	e.pathsMu.RUnlock()
	if len(candidates) == 0 {
		return nil, ErrLeafMobilityControlRouteUnavailable
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ref.ID < candidates[j].ref.ID })
	return candidates, nil
}

func (e *Engine) leafMobilitySubjectSlotLocked(subject PathRef) *pathSlot {
	for _, slots := range []map[uint32]*pathSlot{e.paths, e.retainedPaths, e.stagedPaths} {
		if slot := slots[subject.ID]; slot != nil && slot.owner == subject.Owner {
			return slot
		}
	}
	return nil
}

func (e *Engine) leafMobilityControlSlotEligibleLocked(subject, control *pathSlot) bool {
	if subject == nil || control == nil || control == subject || e.paths[control.id] != control ||
		control.maintenance.Load() || control.routeGeneration.Load() == 0 ||
		(control.localTXTargetID == subject.localTXTargetID && control.peerTXTargetID == subject.peerTXTargetID) {
		return false
	}
	if subject.mobilityClaim != nil && control.mobilityClaim != nil {
		subjectResource := subject.mobilityClaim.Snapshot().ResourceID
		if subjectResource != (leafmobility.ResourceID{}) && subjectResource == control.mobilityClaim.Snapshot().ResourceID {
			return false
		}
	}
	control.dispatchMu.Lock()
	eligible := !control.dispatchDead && !control.dispatchFenced && !control.dispatchStalled.Load() && control.txEnabled.Load()
	control.dispatchMu.Unlock()
	return eligible
}

func (e *Engine) writeLeafMobilityFrameOnControlRoutes(
	ctx context.Context,
	subject PathRef,
	candidates []leafMobilityControlCandidate,
	frame []byte,
) error {
	var lastErr error
	for index, candidate := range candidates {
		attemptCtx, cancel := leafMobilityControlRouteAttemptContext(ctx, len(candidates)-index)
		err := e.writeLeafMobilityFrameToControlSlot(
			attemptCtx, subject, candidate, frame,
		)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if lastErr == nil || errors.Is(lastErr, ErrLeafMobilityControlRouteUnavailable) || errors.Is(lastErr, ErrStalePathRef) {
		return ErrLeafMobilityControlRouteUnavailable
	}
	return errors.Join(ErrLeafMobilityControlRouteUnavailable, lastErr)
}

func leafMobilityControlRouteAttemptContext(parent context.Context, remainingCandidates int) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if remainingCandidates <= 1 {
		return context.WithCancel(parent)
	}
	budget := leafMobilityControlRouteAttemptLimit
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline)
		if remainingCandidates > 0 {
			remaining /= time.Duration(remainingCandidates)
		}
		if remaining < budget {
			budget = remaining
		}
	}
	if budget <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}
	}
	return context.WithTimeout(parent, budget)
}

func (e *Engine) writeLeafMobilityFrameToControlSlot(
	ctx context.Context,
	subject PathRef,
	candidate leafMobilityControlCandidate,
	frame []byte,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	e.registerLeafMobilityControlWrite(subject, candidate.slot)
	defer e.unregisterLeafMobilityControlWrite(subject, candidate.slot)
	if err := candidate.slot.acquireWrite(ctx); err != nil {
		return err
	}
	defer candidate.slot.releaseWrite()

	e.pathsMu.RLock()
	currentSubject := e.leafMobilitySubjectSlotLocked(subject)
	subjectCurrent := currentSubject == candidate.subject ||
		(candidate.allowDetachedSubject && currentSubject == nil && candidate.subject != nil &&
			candidate.subject.id == subject.ID && candidate.subject.owner == subject.Owner)
	current := subjectCurrent && e.leafMobilityControlSlotEligibleLocked(candidate.subject, candidate.slot)
	e.pathsMu.RUnlock()
	if !current {
		return ErrLeafMobilityControlRouteUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan pathCallbackWriteResult, 1)
	go candidate.slot.writeFrameOwnedResult(frame, result)
	var outcome pathCallbackWriteResult
	select {
	case outcome = <-result:
	case <-ctx.Done():
		select {
		case outcome = <-result:
			// Prefer an already observable write completion at the deadline.
		default:
			// PathConn.Close must promptly unblock Write. Await that exact
			// invocation before releasing the write permit or reporting the
			// outcome as unknown to the transaction owner.
			_ = candidate.slot.closeConn()
			outcome = <-result
			e.failPathControlWrite(candidate.slot, ctx.Err())
			return ctx.Err()
		}
	}
	if outcome.err != nil {
		e.failPathControlWrite(candidate.slot, outcome.err)
		return outcome.err
	}
	if outcome.n != len(frame) {
		e.failPathControlWrite(candidate.slot, io.ErrShortWrite)
		return io.ErrShortWrite
	}
	candidate.slot.lastSendUnixNano.Store(nowFn().UnixNano())
	return nil
}

func (e *Engine) registerLeafMobilityControlWrite(subject PathRef, slot *pathSlot) {
	e.leafTx.controlWriteMu.Lock()
	slots := e.leafTx.controlWrites[subject]
	if slots == nil {
		slots = make(map[*pathSlot]uint32)
		e.leafTx.controlWrites[subject] = slots
	}
	slots[slot]++
	e.leafTx.controlWriteMu.Unlock()
}

func (e *Engine) unregisterLeafMobilityControlWrite(subject PathRef, slot *pathSlot) {
	e.leafTx.controlWriteMu.Lock()
	if slots := e.leafTx.controlWrites[subject]; slots != nil {
		if slots[slot] <= 1 {
			delete(slots, slot)
		} else {
			slots[slot]--
		}
		if len(slots) == 0 {
			delete(e.leafTx.controlWrites, subject)
		}
	}
	e.leafTx.controlWriteMu.Unlock()
}

func (e *Engine) activeLeafMobilityControlWrites(subject PathRef) []*pathSlot {
	e.leafTx.controlWriteMu.Lock()
	slots := make([]*pathSlot, 0, len(e.leafTx.controlWrites[subject]))
	for slot := range e.leafTx.controlWrites[subject] {
		slots = append(slots, slot)
	}
	e.leafTx.controlWriteMu.Unlock()
	sort.Slice(slots, func(i, j int) bool { return slots[i].id < slots[j].id })
	return slots
}

func writeLeafMobilityFrameToSlot(ref PathRef, slot *pathSlot, frame []byte) error {
	if slot == nil || slot.id != ref.ID || slot.owner != ref.Owner {
		return ErrStalePathRef
	}
	n, err := slot.writeFrame(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	slot.lastSendUnixNano.Store(nowFn().UnixNano())
	return nil
}
