package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
)

func (e *Engine) arbitrateOutgoingLeafMobilityLocked(localActor proto.LeafMobilityActorSide) error {
	if e.leafTx.outgoing != nil {
		return ErrLeafMobilityAuthorityBusy
	}
	for _, incoming := range e.leafTx.incoming {
		switch incoming.state {
		case incomingLeafMobilityCommitted, incomingLeafMobilityTerminalPending, incomingLeafMobilityOutcomeUnknown:
			return ErrLeafMobilityAuthorityBusy
		}
		if localActor == proto.LeafMobilityActorServer && incoming.prepare.ActorSide == proto.LeafMobilityActorClient {
			return ErrLeafMobilityAuthorityBusy
		}
		if localActor == proto.LeafMobilityActorClient && incoming.prepare.ActorSide == proto.LeafMobilityActorServer {
			incoming.state = incomingLeafMobilitySuperseded
			if incoming.hold != nil {
				incoming.hold.Release()
				incoming.hold = nil
			}
		}
	}
	return nil
}

func (e *Engine) handleLeafMobilityPrepare(source PathRef, seq uint64, replayed bool, prepare proto.LeafMobilityPeerPlanPrepare) error {
	if seq == 0 {
		return fmt.Errorf("leaf mobility PREPARE has zero OOB message sequence")
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		return err
	}
	now := time.Now()
	deadline := now.Add(time.Duration(prepare.LeaseMillis) * time.Millisecond)
	e.leafTx.mu.Lock()
	e.pruneLeafMobilityRecordsLocked(now)
	if rejected, ok := e.leafTx.rejected[prepare.TransactionID]; ok {
		e.leafTx.mu.Unlock()
		if rejected.prepare != prepare || rejected.digest != digest || rejected.prepareSeq != seq {
			return fmt.Errorf("rejected leaf mobility transaction was replayed with altered prepare")
		}
		if source != rejected.source {
			return nil
		}
		return e.replayLeafMobilityResponse(source, rejected.frame, rejected.retireAfter)
	}
	if completed, ok := e.leafTx.completed[prepare.TransactionID]; ok {
		e.leafTx.mu.Unlock()
		if completed.prepare != prepare || completed.digest != digest || completed.prepareSeq != seq {
			return fmt.Errorf("completed leaf mobility transaction was replayed with altered prepare")
		}
		if source != completed.source {
			if replayed {
				return nil
			}
			return fmt.Errorf("completed leaf mobility prepare changed route")
		}
		return e.replayLeafMobilityResponse(source, completed.preparedFrame, now.Add(e.limits.MigrationBudget))
	}
	if incoming := e.leafTx.incoming[prepare.TransactionID]; incoming != nil {
		frame := append([]byte(nil), incoming.preparedFrame...)
		deadline := incoming.deadline
		e.leafTx.mu.Unlock()
		if incoming.prepare != prepare || incoming.digest != digest || incoming.prepareSeq != seq {
			return fmt.Errorf("active leaf mobility transaction was replayed with altered prepare")
		}
		if source != incoming.source {
			if replayed {
				return nil
			}
			return fmt.Errorf("active leaf mobility prepare changed route")
		}
		return e.replayLeafMobilityResponse(source, frame, deadline)
	}
	if len(e.leafTx.incoming)+len(e.leafTx.completed)+len(e.leafTx.rejected) >= leafMobilityRecordLimit {
		e.leafTx.mu.Unlock()
		// A response that cannot be cached cannot be replayed exactly. Drop the
		// request and let the actor retry after bounded records retire.
		return nil
	}
	if outgoing := e.leafTx.outgoing; outgoing != nil {
		localActor := outgoing.prepare.ActorSide
		if localActor == proto.LeafMobilityActorClient || outgoing.commitIssued.Load() {
			e.leafTx.mu.Unlock()
			return e.rejectLeafMobilityPrepare(source, seq, prepare, digest, proto.LeafMobilityPeerPlanAckCodeBusy, "simultaneous transaction lost arbitration", now.Add(time.Second))
		}
		if prepare.ActorSide == proto.LeafMobilityActorClient {
			select {
			case outgoing.preempt <- ErrLeafMobilityAuthorityBusy:
			default:
			}
			// The client is the deterministic winner. Keep one Planning record
			// while the local server proposal observes preemption; do not emit a
			// transient Busy that could later change to Accept for the same ID.
		}
	}
	incoming := &incomingLeafMobilityTransaction{
		source: source, prepare: prepare, prepareSeq: seq, digest: digest, deadline: deadline,
		retireAfter: deadline.Add(e.leafMobilityRecordRetention()), state: incomingLeafMobilityPlanning,
	}
	e.leafTx.incoming[prepare.TransactionID] = incoming
	e.leafTx.mu.Unlock()

	installed := false
	defer func() {
		if installed {
			return
		}
		e.leafTx.mu.Lock()
		if e.leafTx.incoming[prepare.TransactionID] == incoming {
			delete(e.leafTx.incoming, prepare.TransactionID)
		}
		e.leafTx.mu.Unlock()
	}()
	reject := func(code proto.LeafMobilityPeerPlanAckCode, reason string) error {
		return e.rejectLeafMobilityPrepare(source, seq, prepare, digest, code, reason, deadline)
	}
	if err := e.validateIncomingLeafMobilityBinding(source, prepare.LeafMobilityPeerPlanBinding); err != nil {
		return reject(proto.LeafMobilityPeerPlanAckCodeReject, err.Error())
	}
	claim, ok := e.leafClaimForRef(source)
	if !ok {
		return reject(proto.LeafMobilityPeerPlanAckCodeSuperseded, "bound peer leaf is unavailable")
	}
	planCtx, cancel := context.WithDeadline(context.Background(), deadline)
	peerPlan, planErr := e.PlanLeafMobilityCandidate(planCtx, source, leafmobility.TransactionID(prepare.TransactionID), prepare.Direction)
	cancel()
	staleDuringClientArbitration := planErr == nil && prepare.ActorSide == proto.LeafMobilityActorClient &&
		peerPlan.Operation == 0 && peerPlan.Reason == leafmobility.ReasonStaleGeneration
	if planErr != nil || (!staleDuringClientArbitration &&
		(peerPlan.Operation == 0 || protocolLeafOperation(peerPlan.Operation) != prepare.Operation)) {
		reason := "peer leaf has no matching factual mobility plan"
		if planErr != nil {
			reason = planErr.Error()
		}
		return reject(proto.LeafMobilityPeerPlanAckCodeReject, reason)
	}
	var hold *leafmobility.AdmissionReservation
	for {
		if !deadline.After(time.Now()) {
			return reject(proto.LeafMobilityPeerPlanAckCodeSuperseded, "leaf mobility reservation expired during arbitration")
		}
		e.leafTx.mu.Lock()
		if e.leafTx.incoming[prepare.TransactionID] != incoming ||
			incoming.state != incomingLeafMobilityPlanning || e.leafTx.outgoingBlocksIncomingLocked(prepare.ActorSide) {
			e.leafTx.mu.Unlock()
			return reject(proto.LeafMobilityPeerPlanAckCodeBusy, "leaf mobility arbitration changed before resource reservation")
		}
		hold, err = leafmobility.ReserveAdmissions(claim)
		if err == nil {
			incoming.hold = hold
			e.leafTx.mu.Unlock()
			break
		}
		outgoing := e.leafTx.outgoing
		waitForClientPreemption := errors.Is(err, leafmobility.ErrAuthorityActive) &&
			prepare.ActorSide == proto.LeafMobilityActorClient && outgoing != nil &&
			outgoing.prepare.ActorSide == proto.LeafMobilityActorServer && !outgoing.commitIssued.Load()
		e.leafTx.mu.Unlock()
		if !waitForClientPreemption {
			return reject(proto.LeafMobilityPeerPlanAckCodeBusy, err.Error())
		}
		wait := time.NewTimer(time.Millisecond)
		select {
		case <-wait.C:
		case <-e.closed:
			if !wait.Stop() {
				<-wait.C
			}
			return net.ErrClosed
		}
	}
	if err := claim.ValidatePlanCurrent(peerPlan); err != nil {
		planCtx, cancel := context.WithDeadline(context.Background(), deadline)
		refreshed, refreshErr := e.PlanLeafMobilityCandidate(
			planCtx, source, leafmobility.TransactionID(prepare.TransactionID), prepare.Direction,
		)
		cancel()
		if refreshErr != nil || refreshed.Operation == 0 || protocolLeafOperation(refreshed.Operation) != prepare.Operation {
			hold.Release()
			reason := "peer leaf changed during transaction arbitration"
			if refreshErr != nil {
				reason = refreshErr.Error()
			}
			return reject(proto.LeafMobilityPeerPlanAckCodeReject, reason)
		}
		peerPlan = refreshed
	}
	reservation, err := newLeafMobilityReservationID()
	if err != nil {
		hold.Release()
		return err
	}
	generation, err := prepare.ReservedGeneration()
	if err != nil {
		hold.Release()
		return err
	}
	peerDigest := proto.LeafMobilityPeerDigest(peerPlan.LocalDigest)
	agreementDigest, err := proto.ComputeLeafMobilityAgreementDigest(
		prepare.LeafMobilityPeerPlanBinding, generation, prepare.ActorEndpointGeneration,
		peerPlan.EndpointGeneration, digest, peerDigest, reservation,
	)
	if err != nil {
		hold.Release()
		return err
	}
	prepared := proto.LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       proto.LeafMobilityPeerPlanAckPhasePrepared,
		Code:                        proto.LeafMobilityPeerPlanAckCodeAccept,
		CurrentGeneration:           prepare.BaseGeneration,
		Generation:                  generation,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		PeerEndpointGeneration:      peerPlan.EndpointGeneration,
		ProposalDigest:              digest,
		PeerPlanDigest:              peerDigest,
		AgreementDigest:             agreementDigest,
		ReservationID:               reservation,
	}
	e.pathsMu.RLock()
	sourceCurrent := e.leafSourceCurrentLocked(source, claim)
	planCurrentErr := claim.ValidatePlanCurrent(peerPlan)
	e.leafTx.mu.Lock()
	if existing := e.leafTx.incoming[prepare.TransactionID]; existing != incoming ||
		incoming.state != incomingLeafMobilityPlanning || e.leafTx.outgoingBlocksIncomingLocked(prepare.ActorSide) ||
		!sourceCurrent || planCurrentErr != nil {
		e.leafTx.mu.Unlock()
		e.pathsMu.RUnlock()
		hold.Release()
		return reject(proto.LeafMobilityPeerPlanAckCodeBusy, "leaf mobility arbitration changed during preflight")
	}
	resourceKey := e.peerLeafLedgerKey(prepare.ActorSide, prepare.ResourceID)
	ledgerReservation, ledgerErr := e.leafTx.peerLedger.installValidated(
		resourceKey, prepare.TransactionID, prepare.BaseGeneration,
	)
	if ledgerErr != nil {
		e.leafTx.mu.Unlock()
		e.pathsMu.RUnlock()
		hold.Release()
		code := proto.LeafMobilityPeerPlanAckCodeStale
		if errors.Is(ledgerErr, ErrLeafMobilityAuthorityBusy) {
			code = proto.LeafMobilityPeerPlanAckCodeBusy
		}
		return reject(code, ledgerErr.Error())
	}
	incoming.ledger = ledgerReservation
	incoming.ledgerActive = true
	incoming.plan = peerPlan
	incoming.claim = claim
	incoming.prepared = prepared
	incoming.state = incomingLeafMobilityPrepared
	installed = true
	e.leafTx.mu.Unlock()
	e.pathsMu.RUnlock()
	_, err = e.sendLeafMobilityAckBounded(source, prepared, deadline, func(frame []byte) {
		e.leafTx.mu.Lock()
		if e.leafTx.incoming[prepare.TransactionID] == incoming {
			incoming.preparedFrame = append([]byte(nil), frame...)
		}
		e.leafTx.mu.Unlock()
	})
	return err
}

func (r *leafMobilityRuntime) outgoingBlocksIncomingLocked(remoteActor proto.LeafMobilityActorSide) bool {
	outgoing := r.outgoing
	if outgoing == nil {
		return false
	}
	localActor := outgoing.prepare.ActorSide
	if outgoing.commitIssued.Load() {
		return true
	}
	return localActor == proto.LeafMobilityActorClient || remoteActor != proto.LeafMobilityActorClient
}

func (e *Engine) rejectLeafMobilityPrepare(
	source PathRef,
	seq uint64,
	prepare proto.LeafMobilityPeerPlanPrepare,
	digest proto.LeafMobilityProposalDigest,
	code proto.LeafMobilityPeerPlanAckCode,
	reason string,
	deadline time.Time,
) error {
	ack := proto.LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       proto.LeafMobilityPeerPlanAckPhasePrepared,
		Code:                        code,
		CurrentGeneration:           prepare.BaseGeneration,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		ProposalDigest:              digest,
		Reason:                      reason,
	}
	if !deadline.After(time.Now()) {
		deadline = time.Now().Add(time.Second)
	}
	retireAfter := deadline.Add(e.leafMobilityRecordRetention())
	e.leafTx.mu.Lock()
	if existing, ok := e.leafTx.rejected[prepare.TransactionID]; ok {
		frame := append([]byte(nil), existing.frame...)
		e.leafTx.mu.Unlock()
		if existing.prepare != prepare || existing.digest != digest || existing.prepareSeq != seq {
			return fmt.Errorf("leaf mobility rejection replay changed transaction evidence")
		}
		if existing.source != source {
			return nil
		}
		if len(frame) == 0 {
			_, err := e.sendLeafMobilityAckBounded(source, existing.ack, deadline, func(published []byte) {
				e.leafTx.mu.Lock()
				if rejected, ok := e.leafTx.rejected[prepare.TransactionID]; ok &&
					rejected.prepare == prepare && rejected.prepareSeq == seq && rejected.digest == digest && rejected.source == source &&
					len(rejected.frame) == 0 {
					rejected.frame = append([]byte(nil), published...)
					e.leafTx.rejected[prepare.TransactionID] = rejected
				}
				e.leafTx.mu.Unlock()
			})
			return err
		}
		return e.replayLeafMobilityResponse(source, frame, existing.retireAfter)
	}
	if len(e.leafTx.incoming)+len(e.leafTx.completed)+len(e.leafTx.rejected) >= leafMobilityRecordLimit {
		e.leafTx.mu.Unlock()
		return nil
	}
	delete(e.leafTx.incoming, prepare.TransactionID)
	e.leafTx.rejected[prepare.TransactionID] = rejectedLeafMobilityTransaction{
		source: source, prepare: prepare, prepareSeq: seq, digest: digest, ack: ack, retireAfter: retireAfter,
	}
	e.leafTx.mu.Unlock()
	_, err := e.sendLeafMobilityAckBounded(source, ack, deadline, func(frame []byte) {
		e.leafTx.mu.Lock()
		if rejected, ok := e.leafTx.rejected[prepare.TransactionID]; ok &&
			rejected.prepare == prepare && rejected.prepareSeq == seq && rejected.digest == digest && rejected.source == source {
			rejected.frame = append([]byte(nil), frame...)
			e.leafTx.rejected[prepare.TransactionID] = rejected
		}
		e.leafTx.mu.Unlock()
	})
	return err
}

func (e *Engine) handleLeafMobilityCommit(source PathRef, seq uint64, replayed bool, message proto.LeafMobilityPeerPlanCommit) error {
	if seq == 0 {
		return fmt.Errorf("leaf mobility COMMIT has zero OOB message sequence")
	}
	e.leafTx.mu.Lock()
	e.pruneLeafMobilityRecordsLocked(time.Now())
	if completed, ok := e.leafTx.completed[message.TransactionID]; ok {
		e.leafTx.mu.Unlock()
		return e.replayCompletedLeafMobility(source, seq, replayed, message, completed)
	}
	incoming := e.leafTx.incoming[message.TransactionID]
	peerGeneration, _ := e.leafTx.peerLedger.current(
		e.peerLeafLedgerKey(message.ActorSide, message.ResourceID),
	)
	e.leafTx.mu.Unlock()
	if incoming == nil {
		if message.BaseGeneration < peerGeneration {
			return nil
		}
		return fmt.Errorf("leaf mobility commit has no prepared reservation")
	}
	if incoming.source != source {
		if replayed {
			return nil
		}
		return fmt.Errorf("leaf mobility commit changed route from %+v to %+v", incoming.source, source)
	}
	if err := message.ValidateForPrepared(incoming.prepare, incoming.prepared); err != nil {
		return err
	}
	switch message.Stage {
	case proto.LeafMobilityPeerPlanCommitStageCommit:
		return e.handleLeafMobilityCommitIntent(incoming, seq, message)
	case proto.LeafMobilityPeerPlanCommitStageComplete,
		proto.LeafMobilityPeerPlanCommitStageRolledBack,
		proto.LeafMobilityPeerPlanCommitStageAbort:
		return e.handleLeafMobilityResolution(incoming, seq, message)
	default:
		return fmt.Errorf("invalid leaf mobility commit stage %d", message.Stage)
	}
}

func (e *Engine) handleLeafMobilityCommitIntent(incoming *incomingLeafMobilityTransaction, seq uint64, commit proto.LeafMobilityPeerPlanCommit) error {
	e.pathsMu.RLock()
	e.leafTx.mu.Lock()
	if incoming.commit == commit {
		if incoming.commitSeq != seq {
			e.leafTx.mu.Unlock()
			e.pathsMu.RUnlock()
			return fmt.Errorf("leaf mobility COMMIT retry changed OOB message sequence")
		}
		frame := append([]byte(nil), incoming.finalFrame...)
		final := incoming.final
		deadline := incoming.deadline
		source := incoming.source
		e.leafTx.mu.Unlock()
		e.pathsMu.RUnlock()
		if len(frame) != 0 {
			return e.replayLeafMobilityResponse(source, frame, deadline)
		}
		if final != (proto.LeafMobilityPeerPlanAck{}) {
			return e.publishLeafMobilityFinal(incoming, commit, final)
		}
		return nil
	}
	if incoming.commit != (proto.LeafMobilityPeerPlanCommit{}) ||
		(incoming.state != incomingLeafMobilityPrepared && incoming.state != incomingLeafMobilitySuperseded) {
		e.leafTx.mu.Unlock()
		e.pathsMu.RUnlock()
		return fmt.Errorf("leaf mobility COMMIT conflicts with responder state")
	}
	final := incoming.prepared
	final.Phase = proto.LeafMobilityPeerPlanAckPhaseFinal
	final.Stage = proto.LeafMobilityPeerPlanCommitStageCommit
	final.CurrentGeneration = final.Generation
	accept := incoming.state == incomingLeafMobilityPrepared && incoming.deadline.After(time.Now())
	if accept {
		if err := incoming.claim.ValidatePlanCurrent(incoming.plan); err != nil ||
			!e.leafSourceCurrentLocked(incoming.source, incoming.claim) {
			accept = false
		}
	}
	if !accept {
		final.Code = proto.LeafMobilityPeerPlanAckCodeSuperseded
		final.Reason = "peer reservation or leaf expired before commit"
	}
	if !incoming.ledgerActive {
		e.leafTx.mu.Unlock()
		e.pathsMu.RUnlock()
		return fmt.Errorf("peer generation reservation missing during leaf mobility commit")
	}
	if err := e.leafTx.peerLedger.compareAndAdvance(incoming.ledger); err != nil {
		e.leafTx.mu.Unlock()
		e.pathsMu.RUnlock()
		return err
	}
	incoming.ledgerActive = false
	incoming.commit = commit
	incoming.commitSeq = seq
	incoming.final = final
	if accept {
		incoming.state = incomingLeafMobilityCommitted
	} else {
		incoming.state = incomingLeafMobilityTerminalPending
		if incoming.hold != nil {
			incoming.hold.Release()
			incoming.hold = nil
		}
	}
	e.leafTx.mu.Unlock()
	e.pathsMu.RUnlock()
	return e.publishLeafMobilityFinal(incoming, commit, final)
}

func (e *Engine) publishLeafMobilityFinal(
	incoming *incomingLeafMobilityTransaction,
	commit proto.LeafMobilityPeerPlanCommit,
	final proto.LeafMobilityPeerPlanAck,
) error {
	accept := final.Code == proto.LeafMobilityPeerPlanAckCodeAccept
	_, err := e.sendLeafMobilityAckBounded(incoming.source, final, e.leafMobilityReceiptDeadline(incoming.deadline), func(frame []byte) {
		e.leafTx.mu.Lock()
		if e.leafTx.incoming[commit.TransactionID] != incoming {
			e.leafTx.mu.Unlock()
			return
		}
		incoming.finalFrame = append([]byte(nil), frame...)
		if accept {
			e.leafTx.mu.Unlock()
			return
		}
		e.completeIncomingLeafMobilityLocked(incoming)
		e.leafTx.mu.Unlock()
	})
	return err
}

func (e *Engine) handleLeafMobilityResolution(incoming *incomingLeafMobilityTransaction, seq uint64, resolution proto.LeafMobilityPeerPlanCommit) error {
	e.leafTx.mu.Lock()
	if incoming.resolution == resolution {
		if incoming.resolutionSeq != seq {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility resolution retry changed OOB message sequence")
		}
		frame := append([]byte(nil), incoming.releasedFrame...)
		released := incoming.released
		deadline := incoming.deadline
		source := incoming.source
		e.leafTx.mu.Unlock()
		if len(frame) != 0 {
			return e.replayLeafMobilityResponse(source, frame, deadline)
		}
		if released != (proto.LeafMobilityPeerPlanAck{}) {
			return e.publishLeafMobilityReleased(incoming, resolution, released)
		}
		return nil
	}
	if incoming.resolution != (proto.LeafMobilityPeerPlanCommit{}) {
		e.leafTx.mu.Unlock()
		return fmt.Errorf("leaf mobility resolution changed terminal evidence")
	}
	preCommitAbort := resolution.Stage == proto.LeafMobilityPeerPlanCommitStageAbort
	if preCommitAbort {
		if incoming.state != incomingLeafMobilityPrepared && incoming.state != incomingLeafMobilitySuperseded {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility abort arrived after commit")
		}
	} else if incoming.state != incomingLeafMobilityCommitted && incoming.state != incomingLeafMobilityOutcomeUnknown {
		e.leafTx.mu.Unlock()
		return fmt.Errorf("leaf mobility resolution arrived without committed reservation")
	}
	if !preCommitAbort {
		commitEvidence := resolution
		commitEvidence.Stage = proto.LeafMobilityPeerPlanCommitStageCommit
		if incoming.commit != commitEvidence || incoming.final.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
			e.leafTx.mu.Unlock()
			return fmt.Errorf("leaf mobility resolution does not match accepted commit")
		}
	} else if incoming.ledgerActive {
		if err := e.leafTx.peerLedger.release(incoming.ledger); err != nil {
			e.leafTx.mu.Unlock()
			return err
		}
		incoming.ledgerActive = false
	}
	released := incoming.prepared
	released.Phase = proto.LeafMobilityPeerPlanAckPhaseReleased
	released.Stage = resolution.Stage
	released.CurrentGeneration = released.Generation
	incoming.resolution = resolution
	incoming.resolutionSeq = seq
	incoming.released = released
	incoming.state = incomingLeafMobilityTerminalPending
	if incoming.hold != nil {
		if !incoming.hold.ReconcilePoison() {
			incoming.hold.Release()
		}
		incoming.hold = nil
	}
	e.leafTx.mu.Unlock()
	return e.publishLeafMobilityReleased(incoming, resolution, released)
}

func (e *Engine) publishLeafMobilityReleased(
	incoming *incomingLeafMobilityTransaction,
	resolution proto.LeafMobilityPeerPlanCommit,
	released proto.LeafMobilityPeerPlanAck,
) error {
	_, err := e.sendLeafMobilityAckBounded(incoming.source, released, e.leafMobilityReceiptDeadline(incoming.deadline), func(frame []byte) {
		e.leafTx.mu.Lock()
		if e.leafTx.incoming[resolution.TransactionID] == incoming {
			incoming.releasedFrame = append([]byte(nil), frame...)
			e.completeIncomingLeafMobilityLocked(incoming)
		}
		e.leafTx.mu.Unlock()
	})
	return err
}

func (e *Engine) completeIncomingLeafMobilityLocked(incoming *incomingLeafMobilityTransaction) {
	delete(e.leafTx.incoming, incoming.prepare.TransactionID)
	e.leafTx.completed[incoming.prepare.TransactionID] = completedLeafMobilityTransaction{
		source: incoming.source, prepare: incoming.prepare, prepareSeq: incoming.prepareSeq, digest: incoming.digest,
		prepared: incoming.prepared, preparedFrame: append([]byte(nil), incoming.preparedFrame...),
		commit: incoming.commit, commitSeq: incoming.commitSeq, final: incoming.final, finalFrame: append([]byte(nil), incoming.finalFrame...),
		resolution: incoming.resolution, resolutionSeq: incoming.resolutionSeq, released: incoming.released,
		releasedFrame: append([]byte(nil), incoming.releasedFrame...),
		retireAfter:   time.Now().Add(e.leafMobilityRecordRetention()),
	}
	e.pruneLeafMobilityRecordsLocked(time.Now())
}

func (e *Engine) replayCompletedLeafMobility(
	source PathRef,
	seq uint64,
	replayed bool,
	message proto.LeafMobilityPeerPlanCommit,
	completed completedLeafMobilityTransaction,
) error {
	if source != completed.source {
		if replayed {
			return nil
		}
		return fmt.Errorf("completed leaf mobility transaction changed route")
	}
	var want proto.LeafMobilityPeerPlanCommit
	var frame []byte
	var wantSeq uint64
	switch message.Stage {
	case proto.LeafMobilityPeerPlanCommitStageCommit:
		want, frame, wantSeq = completed.commit, completed.finalFrame, completed.commitSeq
	default:
		want, frame, wantSeq = completed.resolution, completed.releasedFrame, completed.resolutionSeq
	}
	if want != message || wantSeq != seq {
		return fmt.Errorf("completed leaf mobility transaction changed evidence")
	}
	return e.replayLeafMobilityResponse(source, frame, time.Now().Add(e.limits.MigrationBudget))
}

func (e *Engine) expireIncomingLeafMobilityTransactions(now time.Time) {
	var release []*leafmobility.AdmissionReservation
	var poison []*leafmobility.AdmissionReservation
	closeSession := false
	e.leafTx.mu.Lock()
	e.pruneLeafMobilityRecordsLocked(now)
	for id, incoming := range e.leafTx.incoming {
		if now.Before(incoming.deadline) {
			continue
		}
		switch incoming.state {
		case incomingLeafMobilityPlanning:
			if incoming.ledgerActive {
				if err := e.leafTx.peerLedger.release(incoming.ledger); err != nil {
					closeSession = true
					continue
				}
				incoming.ledgerActive = false
			}
			if incoming.hold != nil {
				release = append(release, incoming.hold)
				incoming.hold = nil
			}
			delete(e.leafTx.incoming, id)
		case incomingLeafMobilityPrepared:
			incoming.state = incomingLeafMobilitySuperseded
			if incoming.hold != nil {
				release = append(release, incoming.hold)
				incoming.hold = nil
			}
		case incomingLeafMobilityCommitted:
			incoming.state = incomingLeafMobilityOutcomeUnknown
			if incoming.hold != nil {
				poison = append(poison, incoming.hold)
			}
		case incomingLeafMobilityOutcomeUnknown:
			if !now.Before(incoming.retireAfter) {
				incoming.hold = nil
				delete(e.leafTx.incoming, id)
			}
		case incomingLeafMobilityTerminalPending:
			if !now.Before(incoming.retireAfter) {
				if incoming.hold != nil {
					release = append(release, incoming.hold)
					incoming.hold = nil
				}
				delete(e.leafTx.incoming, id)
			}
		case incomingLeafMobilitySuperseded:
			if !now.Before(incoming.retireAfter) {
				if incoming.ledgerActive {
					if err := e.leafTx.peerLedger.release(incoming.ledger); err != nil {
						closeSession = true
						continue
					}
					incoming.ledgerActive = false
				}
				delete(e.leafTx.incoming, id)
			}
		}
	}
	e.leafTx.mu.Unlock()
	for _, hold := range release {
		hold.Release()
	}
	for _, hold := range poison {
		hold.Poison()
	}
	if closeSession && !e.isClosed() {
		e.setCloseErr(ErrLeafMobilityOutcomeUnknown)
		go e.Close()
	}
}

func (e *Engine) releaseIncomingLeafMobilityTransactions() {
	var release []*leafmobility.AdmissionReservation
	var poison []*leafmobility.AdmissionReservation
	e.leafTx.mu.Lock()
	for id, incoming := range e.leafTx.incoming {
		delete(e.leafTx.incoming, id)
		if incoming.ledgerActive {
			if err := e.leafTx.peerLedger.release(incoming.ledger); err == nil {
				incoming.ledgerActive = false
			}
		}
		if incoming.hold == nil {
			continue
		}
		switch incoming.state {
		case incomingLeafMobilityCommitted, incomingLeafMobilityOutcomeUnknown:
			poison = append(poison, incoming.hold)
		default:
			release = append(release, incoming.hold)
		}
		incoming.hold = nil
	}
	e.leafTx.mu.Unlock()
	for _, hold := range release {
		hold.Release()
	}
	for _, hold := range poison {
		hold.Poison()
	}
}
