package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
)

func (e *Engine) routeLeafMobilityOOB(slot *pathSlot, header proto.Header, payload []byte) error {
	source := pathRefForSlot(slot)
	routeGeneration := slot.routeGeneration.Load()
	if source.ID == 0 || routeGeneration == 0 {
		return nil
	}
	message := leafMobilityMessage{source: source, seq: header.Seq}
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
	clientTarget, serverTarget := slot.localTXTargetID, slot.peerTXTargetID
	if e.side == SideServer {
		clientTarget, serverTarget = slot.peerTXTargetID, slot.localTXTargetID
	}
	if binding.SessionEpoch != proto.SessionEpoch(e.FlowID()) ||
		binding.ClientTargetID != clientTarget || binding.ServerTargetID != serverTarget ||
		binding.RouteGeneration != routeGeneration {
		// A byte-exact old-route frame may surface on a replacement carrier.
		// It cannot authorize that carrier and is benign stale replay.
		return nil
	}
	key := leafMobilityOOBKey{source: source, seq: header.Seq}
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

func (e *Engine) validateLeafMobilitySource(ref PathRef, plan leafmobility.Plan) (*leafmobility.Claim, error) {
	if e == nil || ref.ID == 0 || ref.Owner == 0 || e.isClosed() || e.sendClosing.Load() {
		return nil, net.ErrClosed
	}
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner || slot.mobilityClaim == nil || slot.maintenance.Load() ||
		slot.routeGeneration.Load() == 0 || plan.Binding.PathID != ref.ID || plan.Binding.Owner != ref.Owner {
		e.pathsMu.RUnlock()
		return nil, ErrStalePathRef
	}
	key, valid := pathAdmissionKey(e.side, PathBinding{
		LocalTXTargetID: slot.localTXTargetID, PeerTXTargetID: slot.peerTXTargetID,
	})
	_, admission := e.pathAdmissionByLeaf[key]
	predecessors := len(e.pathPredecessors[ref.ID])
	claim := slot.mobilityClaim
	e.pathsMu.RUnlock()
	if !valid || admission || predecessors != 0 {
		return nil, ErrLeafMobilityAdmissionBusy
	}
	if err := claim.ValidatePlanCurrent(plan); err != nil {
		return nil, err
	}
	return claim, nil
}

func (e *Engine) leafClaimForRef(ref PathRef) (*leafmobility.Claim, bool) {
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner || slot.mobilityClaim == nil || slot.maintenance.Load() {
		e.pathsMu.RUnlock()
		return nil, false
	}
	claim := slot.mobilityClaim
	e.pathsMu.RUnlock()
	return claim, true
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
	if slot == nil || slot.owner != outgoing.source.Owner || slot.mobilityClaim != outgoing.claim || slot.maintenance.Load() {
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
		binding.RouteGeneration != slot.routeGeneration.Load() {
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
		binding.ClientTargetID != clientTarget || binding.ServerTargetID != serverTarget {
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
		CoordinatorSide: proto.LeafMobilityActorClient,
		ActorSide:       protocolActorSide(e.side),
		Direction:       plan.Direction,
		SessionKind:     protocolLeafSession(plan.Session),
		Operation:       protocolLeafOperation(plan.Operation),
		Fallback:        proto.LeafMobilityFallbackRedialAttach,
		LeaseMillis:     leaseMillis,
		SessionEpoch:    proto.SessionEpoch(plan.Binding.FlowID),
		TransactionID:   [16]byte(plan.TransactionID),
		BaseGeneration:  plan.BaseGeneration,
		ResourceScope:   protocolLeafScope(plan.Scope),
		ResourceID:      proto.LeafMobilityResourceID(plan.ResourceID),
		RouteGeneration: routeGeneration,
	}
	if e.side == SideClient {
		binding.ClientGraph = proto.GraphBinding{Revision: localGraph.revision, Digest: localGraph.digest}
		binding.ServerGraph = proto.GraphBinding{Revision: peerGraph.revision, Digest: peerGraph.digest}
		binding.ClientTargetID = proto.TargetID(plan.Binding.LocalTargetID)
		binding.ServerTargetID = proto.TargetID(plan.Binding.PeerTargetID)
	} else {
		binding.ClientGraph = proto.GraphBinding{Revision: peerGraph.revision, Digest: peerGraph.digest}
		binding.ServerGraph = proto.GraphBinding{Revision: localGraph.revision, Digest: localGraph.digest}
		binding.ClientTargetID = proto.TargetID(plan.Binding.PeerTargetID)
		binding.ServerTargetID = proto.TargetID(plan.Binding.LocalTargetID)
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

func (e *Engine) sendLeafMobilityPrepare(ref PathRef, prepare proto.LeafMobilityPeerPlanPrepare) ([]byte, error) {
	payload, err := prepare.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendLeafMobilityFrameAt(ref, proto.CtrlLeafMobilityPrepare, payload, nil)
}

func (e *Engine) sendLeafMobilityCommitAt(
	ref PathRef,
	commit proto.LeafMobilityPeerPlanCommit,
	onPublish func([]byte) error,
) ([]byte, error) {
	payload, err := commit.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendLeafMobilityFrameAt(ref, proto.CtrlLeafMobilityCommit, payload, onPublish)
}

func (e *Engine) sendLeafMobilityAckBounded(
	ref PathRef,
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
	frame, sendErr, pending := e.sendLeafMobilityFrameWithContext(ctx, func() ([]byte, error) {
		return e.sendLeafMobilityFrameAt(ref, proto.CtrlLeafMobilityAck, payload, func(frame []byte) error {
			if onPublish != nil {
				onPublish(frame)
			}
			return nil
		})
	})
	if pending == nil {
		<-e.leafTx.responseGate
		return frame, leafMobilityResponseWriteError(sendErr)
	}
	e.abortLeafMobilityPathWrite(ref)
	select {
	case outcome := <-pending:
		<-e.leafTx.responseGate
		return outcome.frame, leafMobilityResponseWriteError(outcome.err)
	case <-time.After(time.Second):
		cleanup := func() {
			<-pending
			<-e.leafTx.responseGate
		}
		if !e.startLeafMobilityAsync(cleanup) {
			cleanup()
		}
		return nil, leafMobilityResponseWriteError(sendErr)
	}
}

func (e *Engine) replayLeafMobilityResponse(ref PathRef, frame []byte, deadline time.Time) error {
	if len(frame) == 0 {
		return nil
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
	_, err, pending := e.sendLeafMobilityFrameWithContext(ctx, func() ([]byte, error) {
		return frame, e.replayLeafMobilityFrame(ref, frame)
	})
	if pending == nil {
		<-e.leafTx.responseGate
		return leafMobilityResponseWriteError(err)
	}
	e.abortLeafMobilityPathWrite(ref)
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
	if e.isClosed() || e.sendClosing.Load() {
		return nil, net.ErrClosed
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
	if onPublish != nil {
		if err := onPublish(frame); err != nil {
			return nil, err
		}
	}
	if err := e.writeLeafMobilityFrame(ref, frame); err != nil {
		return frame, err
	}
	return frame, nil
}

func (e *Engine) replayLeafMobilityFrame(ref PathRef, frame []byte) error {
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
	// Transaction state owns the exact frame. It stays pinned to the original
	// route and never enters the application DATA replay/ACK domain.
	return e.writeLeafMobilityFrame(ref, frame)
}

func (e *Engine) writeLeafMobilityFrame(ref PathRef, frame []byte) error {
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil {
		slot = e.retainedPaths[ref.ID]
	}
	if slot == nil {
		slot = e.stagedPaths[ref.ID]
	}
	if slot == nil || slot.owner != ref.Owner {
		e.pathsMu.RUnlock()
		return ErrStalePathRef
	}
	e.pathsMu.RUnlock()
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

func (e *Engine) abortLeafMobilityPathWrite(ref PathRef) {
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil {
		slot = e.retainedPaths[ref.ID]
	}
	if slot == nil {
		slot = e.stagedPaths[ref.ID]
	}
	if slot == nil || slot.owner != ref.Owner {
		e.pathsMu.RUnlock()
		return
	}
	conn := slot.conn
	e.pathsMu.RUnlock()
	if !e.startLeafMobilityAsync(func() { _ = conn.Close() }) {
		_ = conn.Close()
	}
}
