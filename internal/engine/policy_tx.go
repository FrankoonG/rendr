package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"
	"unicode/utf8"

	"github.com/FrankoonG/rendr/proto"
)

const (
	policyRetryInterval  = 200 * time.Millisecond
	policyTransactionTTL = 5 * time.Second
	policyCompletedLimit = 8
)

type outgoingPolicyTransaction struct {
	prepare     proto.PolicyPrepare
	digest      proto.PolicyProposalDigest
	prepareAcks chan proto.PolicyAck
	finalAcks   chan proto.PolicyAck
}

type incomingPolicyTransaction struct {
	prepare      proto.PolicyPrepare
	digest       proto.PolicyProposalDigest
	graph        graphBinding
	generation   uint64
	expires      time.Time
	prepareAck   proto.PolicyAck
	prepareFrame []byte
}

type completedPolicyTransaction struct {
	prepare      proto.PolicyPrepare
	digest       proto.PolicyProposalDigest
	prepareAck   proto.PolicyAck
	finalAck     proto.PolicyAck
	prepareFrame []byte
	finalFrame   []byte
}

type policyMessageKind uint8

const (
	policyMessagePrepare policyMessageKind = iota + 1
	policyMessageAck
	policyMessageCommit
)

type policyMessage struct {
	kind    policyMessageKind
	prepare proto.PolicyPrepare
	ack     proto.PolicyAck
	commit  proto.PolicyCommit
}

type policyProtocolViolation struct{ err error }

func (e *policyProtocolViolation) Error() string { return e.err.Error() }

func policyViolation(err error) error {
	return &policyProtocolViolation{err: err}
}

// RequestPeerSelection asks the peer, which owns the opposite sender, to
// atomically select one immediate child of one selector. The owner assigns the
// generation; the requester never chooses it. One outgoing transaction is
// allowed at a time, independently from an incoming transaction.
func (e *Engine) RequestPeerSelection(ctx context.Context, selectorID, targetID proto.TargetID, cause string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	peer := e.peerGraphBinding()
	if !peer.configured {
		return fmt.Errorf("engine: peer graph is not configured")
	}
	if err := validatePolicySelection(peer.manifest, selectorID, targetID); err != nil {
		return err
	}

	select {
	case e.policySendGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-e.closed:
		return net.ErrClosed
	}
	releaseGate := true
	defer func() {
		if releaseGate {
			<-e.policySendGate
		}
	}()

	txID, err := newPolicyTransactionID()
	if err != nil {
		return err
	}
	e.policyStateMu.Lock()
	base := e.policyPeerGeneration
	prepare := proto.PolicyPrepare{
		PolicyTransactionBinding: proto.PolicyTransactionBinding{
			SessionEpoch:  proto.SessionEpoch(e.flowID),
			Direction:     peerSenderDirection(e.side),
			GraphBinding:  proto.GraphBinding{Revision: peer.revision, Digest: peer.digest},
			TransactionID: txID,
		},
		BaseGeneration: base,
		Action:         proto.PolicyActionSelectChild,
		SelectorID:     selectorID,
		TargetID:       targetID,
		Cause:          cause,
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		e.policyStateMu.Unlock()
		return err
	}
	tx := &outgoingPolicyTransaction{
		prepare:     prepare,
		digest:      digest,
		prepareAcks: make(chan proto.PolicyAck, 1),
		finalAcks:   make(chan proto.PolicyAck, 1),
	}
	if e.policyOutgoing != nil {
		e.policyStateMu.Unlock()
		return fmt.Errorf("engine: outgoing policy transaction invariant violated")
	}
	e.policyOutgoing = tx
	e.policyStateMu.Unlock()
	defer func() {
		e.policyStateMu.Lock()
		if e.policyOutgoing == tx {
			e.policyOutgoing = nil
		}
		e.policyStateMu.Unlock()
	}()

	txCtx, cancel := context.WithTimeout(ctx, policyTransactionTTL)
	defer cancel()
	prepareFrame, err, pending := e.sendPolicyFrameWithContext(txCtx, func() ([]byte, error) {
		return e.sendPolicyPrepare(tx.prepare)
	})
	if pending != nil {
		releaseGate = false
		go e.releasePolicySendGateAfter(pending)
		return err
	}
	if err != nil {
		return err
	}

	retry := time.NewTicker(policyRetryInterval)
	defer retry.Stop()
	commitSent := false
	var generation uint64
	var commitFrame []byte
	ackChannel := (<-chan proto.PolicyAck)(tx.prepareAcks)
	for {
		select {
		case <-e.closed:
			if commitSent {
				return fmt.Errorf("%w: connection closed before COMMIT_ACK", ErrPolicyOutcomeUnknown)
			}
			return net.ErrClosed
		case <-txCtx.Done():
			if commitSent {
				return fmt.Errorf("%w: %v", ErrPolicyOutcomeUnknown, txCtx.Err())
			}
			return txCtx.Err()
		case <-retry.C:
			frame := prepareFrame
			if commitSent {
				frame = commitFrame
			}
			_, err, pending = e.sendPolicyFrameWithContext(txCtx, func() ([]byte, error) {
				return frame, e.replaySequencedFrame(frame)
			})
			if pending != nil {
				releaseGate = false
				go e.releasePolicySendGateAfter(pending)
				if commitSent {
					return fmt.Errorf("%w: retry COMMIT: %v", ErrPolicyOutcomeUnknown, err)
				}
				return err
			}
			if err != nil {
				if commitSent {
					return fmt.Errorf("%w: retry COMMIT: %v", ErrPolicyOutcomeUnknown, err)
				}
				return err
			}
		case ack := <-ackChannel:
			if ack.ProposalDigest != digest {
				return e.policyProtocolError(fmt.Errorf("policy ACK proposal digest mismatch"))
			}
			if !commitSent {
				if ack.Phase != proto.PolicyAckPhasePrepare {
					return e.policyProtocolError(fmt.Errorf("unexpected final ACK before prepare ACK"))
				}
				if ack.Code != proto.PolicyAckCodeAccept {
					e.recordPeerPolicyGeneration(ack.CurrentGeneration)
					return fmt.Errorf("%w: %s", ErrPolicyRejected, ack.Reason)
				}
				if base == ^uint64(0) || ack.Generation != base+1 || ack.CurrentGeneration != base {
					return e.policyProtocolError(fmt.Errorf("owner assigned invalid generation %d from base %d", ack.Generation, base))
				}
				generation = ack.Generation
				commit := proto.PolicyCommit{
					PolicyTransactionBinding: tx.prepare.PolicyTransactionBinding,
					Generation:               generation,
					ProposalDigest:           digest,
				}
				commitFrame, err, pending = e.sendPolicyFrameWithContext(txCtx, func() ([]byte, error) {
					return e.sendPolicyCommit(commit)
				})
				if pending != nil {
					releaseGate = false
					go e.releasePolicySendGateAfter(pending)
					return fmt.Errorf("%w: send COMMIT: %v", ErrPolicyOutcomeUnknown, err)
				}
				if err != nil {
					return fmt.Errorf("%w: send COMMIT: %v", ErrPolicyOutcomeUnknown, err)
				}
				commitSent = true
				ackChannel = tx.finalAcks
				continue
			}
			if ack.Phase != proto.PolicyAckPhaseFinal {
				return e.policyProtocolError(fmt.Errorf("invalid policy ACK phase %d", ack.Phase))
			}
			if ack.Code != proto.PolicyAckCodeAccept {
				e.recordPeerPolicyGeneration(ack.CurrentGeneration)
				return fmt.Errorf("%w: %s", ErrPolicyRejected, ack.Reason)
			}
			if ack.Generation != generation || ack.CurrentGeneration != generation || ack.CurrentTargetID != targetID {
				return e.policyProtocolError(fmt.Errorf("COMMIT_ACK does not prove requested policy state"))
			}
			e.recordPeerPolicyGeneration(generation)
			return nil
		}
	}
}

type policyFrameResult struct {
	frame []byte
	err   error
}

// sendPolicyFrameWithContext bounds the caller while retaining ownership of a
// possibly blocked publication. The transaction gate remains held until that
// one send exits, so repeated requests cannot accumulate blocked goroutines.
func (e *Engine) sendPolicyFrameWithContext(ctx context.Context, send func() ([]byte, error)) ([]byte, error, <-chan policyFrameResult) {
	result := make(chan policyFrameResult, 1)
	go func() {
		frame, err := send()
		result <- policyFrameResult{frame: frame, err: err}
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

func (e *Engine) releasePolicySendGateAfter(result <-chan policyFrameResult) {
	<-result
	<-e.policySendGate
}

func (e *Engine) sendPolicyPrepare(p proto.PolicyPrepare) ([]byte, error) {
	payload, err := p.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendFrameTracked(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPolicyPrepare), payload)
}

func (e *Engine) sendPolicyAck(p proto.PolicyAck) ([]byte, error) {
	payload, err := p.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendFrameTracked(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPolicyAck), payload)
}

func (e *Engine) sendPolicyCommit(p proto.PolicyCommit) ([]byte, error) {
	payload, err := p.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendFrameTracked(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPolicyCommit), payload)
}

func (e *Engine) enqueuePolicyMessageLocked(message policyMessage) bool {
	select {
	case e.policyInbox <- message:
		return true
	default:
		e.recvFinalErr = fmt.Errorf("%w: policy inbox capacity exceeded", ErrPeerProtocol)
		e.recvTerminal = true
		return false
	}
}

func (e *Engine) policyLoop() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case now := <-ticker.C:
			e.policyStateMu.Lock()
			if e.policyIncoming != nil && !now.Before(e.policyIncoming.expires) {
				e.expirePolicyIncomingLocked(e.policyIncoming)
			}
			e.policyStateMu.Unlock()
		case message := <-e.policyInbox:
			var err error
			switch message.kind {
			case policyMessagePrepare:
				err = e.handlePolicyPrepare(message.prepare)
			case policyMessageAck:
				err = e.handlePolicyAck(message.ack)
			case policyMessageCommit:
				err = e.handlePolicyCommit(message.commit)
			default:
				err = policyViolation(fmt.Errorf("unknown policy message kind %d", message.kind))
			}
			if err != nil && !errors.Is(err, net.ErrClosed) {
				var violation *policyProtocolViolation
				if errors.As(err, &violation) {
					_ = e.policyProtocolError(violation.err)
				}
			}
		}
	}
}

func (e *Engine) handlePolicyPrepare(prepare proto.PolicyPrepare) error {
	if err := e.validateIncomingPolicyBinding(prepare.PolicyTransactionBinding); err != nil {
		return policyViolation(err)
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		return policyViolation(err)
	}
	graph := e.localGraphBinding()
	e.policyStateMu.Lock()
	if completed, ok := e.policyCompleted[prepare.TransactionID]; ok {
		if completed.prepare != prepare || completed.digest != digest {
			e.policyStateMu.Unlock()
			return policyViolation(fmt.Errorf("policy transaction id reused with different PREPARE"))
		}
		ack, frame := completed.prepareAck, completed.prepareFrame
		e.policyStateMu.Unlock()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, frame)
	}
	if pending := e.policyIncoming; pending != nil {
		if pending.prepare.TransactionID == prepare.TransactionID {
			if pending.prepare != prepare || pending.digest != digest {
				e.policyStateMu.Unlock()
				return policyViolation(fmt.Errorf("policy transaction id reused while pending"))
			}
			ack, frame := pending.prepareAck, pending.prepareFrame
			e.policyStateMu.Unlock()
			return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, frame)
		}
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeBusy, 0, prepare.SelectorID, "another policy transaction is pending")
		e.policyStateMu.Unlock()
		_, err := e.sendPolicyAck(ack)
		return err
	}
	if err := validatePolicySelection(graph.manifest, prepare.SelectorID, prepare.TargetID); err != nil {
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeReject, 0, prepare.SelectorID, err.Error())
		e.rememberPolicyCompletedLocked(completedPolicyTransaction{prepare: prepare, digest: digest, prepareAck: ack})
		e.policyStateMu.Unlock()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
	}
	if prepare.BaseGeneration != e.policyGeneration {
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeStale, 0, prepare.SelectorID, "base generation is stale")
		e.rememberPolicyCompletedLocked(completedPolicyTransaction{prepare: prepare, digest: digest, prepareAck: ack})
		e.policyStateMu.Unlock()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
	}
	if e.policyGeneration == ^uint64(0) {
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeReject, 0, prepare.SelectorID, "generation space exhausted")
		e.rememberPolicyCompletedLocked(completedPolicyTransaction{prepare: prepare, digest: digest, prepareAck: ack})
		e.policyStateMu.Unlock()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
	}
	generation := e.policyGeneration + 1
	ack := proto.PolicyAck{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Phase:                    proto.PolicyAckPhasePrepare,
		Code:                     proto.PolicyAckCodeAccept,
		Generation:               generation,
		CurrentGeneration:        e.policyGeneration,
		CurrentTargetID:          e.policySelections[prepare.SelectorID],
		ProposalDigest:           digest,
	}
	e.policyIncoming = &incomingPolicyTransaction{
		prepare:    prepare,
		digest:     digest,
		graph:      graph,
		generation: generation,
		expires:    time.Now().Add(policyTransactionTTL),
		prepareAck: ack,
	}
	e.policyStateMu.Unlock()
	return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
}

func (e *Engine) handlePolicyAck(ack proto.PolicyAck) error {
	if err := e.validateOutgoingPolicyBinding(ack.PolicyTransactionBinding); err != nil {
		return policyViolation(err)
	}
	e.policyStateMu.Lock()
	tx := e.policyOutgoing
	if tx == nil || tx.prepare.TransactionID != ack.TransactionID {
		e.policyStateMu.Unlock()
		return nil
	}
	if tx.prepare.PolicyTransactionBinding != ack.PolicyTransactionBinding {
		e.policyStateMu.Unlock()
		return policyViolation(fmt.Errorf("policy ACK binding changed within transaction"))
	}
	if tx.digest != ack.ProposalDigest {
		e.policyStateMu.Unlock()
		return policyViolation(fmt.Errorf("policy ACK proposal digest changed within transaction"))
	}
	var channel chan proto.PolicyAck
	switch ack.Phase {
	case proto.PolicyAckPhasePrepare:
		channel = tx.prepareAcks
	case proto.PolicyAckPhaseFinal:
		channel = tx.finalAcks
	default:
		e.policyStateMu.Unlock()
		return policyViolation(fmt.Errorf("invalid policy ACK phase %d", ack.Phase))
	}
	select {
	case channel <- ack:
	default:
		// Each phase has an independent one-entry mailbox. Duplicates can
		// never displace the other phase's ACK.
	}
	e.policyStateMu.Unlock()
	return nil
}

func (e *Engine) handlePolicyCommit(commit proto.PolicyCommit) error {
	if err := e.validateIncomingPolicyBinding(commit.PolicyTransactionBinding); err != nil {
		return policyViolation(err)
	}

	e.policyStateMu.Lock()
	if completed, ok := e.policyCompleted[commit.TransactionID]; ok {
		if completed.finalAck.Phase == proto.PolicyAckPhaseInvalid {
			e.policyStateMu.Unlock()
			return policyViolation(fmt.Errorf("COMMIT followed a rejected PREPARE"))
		}
		if completed.digest != commit.ProposalDigest || completed.finalAck.Generation != commit.Generation {
			e.policyStateMu.Unlock()
			return policyViolation(fmt.Errorf("policy transaction id reused with different COMMIT"))
		}
		ack, frame := completed.finalAck, completed.finalFrame
		e.policyStateMu.Unlock()
		return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, frame)
	}
	pending := e.policyIncoming
	if pending == nil {
		ack := e.policyRejectLocked(commit.PolicyTransactionBinding, commit.ProposalDigest, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeSuperseded, commit.Generation, proto.TargetID{}, "prepared transaction is no longer pending")
		e.policyStateMu.Unlock()
		_, err := e.sendPolicyAck(ack)
		return err
	}
	if pending.prepare.TransactionID != commit.TransactionID {
		ack := e.policyRejectLocked(commit.PolicyTransactionBinding, commit.ProposalDigest, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeBusy, commit.Generation, proto.TargetID{}, "another policy transaction is pending")
		e.policyStateMu.Unlock()
		_, err := e.sendPolicyAck(ack)
		return err
	}
	if pending.generation != commit.Generation || pending.digest != commit.ProposalDigest {
		e.policyStateMu.Unlock()
		return policyViolation(fmt.Errorf("policy transaction id reused with different COMMIT proposal"))
	}
	if !time.Now().Before(pending.expires) {
		completed := e.expirePolicyIncomingLocked(pending)
		ack := completed.finalAck
		e.policyStateMu.Unlock()
		return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, completed.finalFrame)
	}
	prepare := pending.prepare
	e.policyStateMu.Unlock()

	e.policyOwnerMu.Lock()
	defer e.policyOwnerMu.Unlock()
	e.policyStateMu.Lock()
	if e.policyIncoming != pending || e.policyGeneration != prepare.BaseGeneration || e.sendClosing.Load() || e.isClosed() {
		if e.policyIncoming == pending {
			e.policyIncoming = nil
		}
		ack := e.policyRejectLocked(commit.PolicyTransactionBinding, pending.digest, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeStale, commit.Generation, prepare.SelectorID, "owner state changed after PREPARE")
		completed := completedPolicyTransaction{prepare: prepare, digest: pending.digest, prepareAck: pending.prepareAck, prepareFrame: pending.prepareFrame, finalAck: ack}
		e.rememberPolicyCompletedLocked(completed)
		e.policyStateMu.Unlock()
		return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, nil)
	}
	e.policyStateMu.Unlock()

	applyErr := e.applyPolicySelectionFromGraph(pending.graph, prepare.SelectorID, prepare.TargetID, prepare.Cause)

	e.policyStateMu.Lock()
	if e.policyIncoming != pending || e.policyGeneration != prepare.BaseGeneration {
		e.policyStateMu.Unlock()
		return policyViolation(fmt.Errorf("prepared policy transaction lost ownership during commit"))
	}
	var ack proto.PolicyAck
	if applyErr != nil {
		ack = e.policyRejectLocked(commit.PolicyTransactionBinding, pending.digest, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeReject, commit.Generation, prepare.SelectorID, applyErr.Error())
	} else {
		e.policyGeneration = commit.Generation
		e.policySelections[prepare.SelectorID] = prepare.TargetID
		ack = proto.PolicyAck{
			PolicyTransactionBinding: commit.PolicyTransactionBinding,
			Phase:                    proto.PolicyAckPhaseFinal,
			Code:                     proto.PolicyAckCodeAccept,
			Generation:               commit.Generation,
			CurrentGeneration:        commit.Generation,
			CurrentTargetID:          prepare.TargetID,
			ProposalDigest:           pending.digest,
		}
	}
	e.policyIncoming = nil
	e.rememberPolicyCompletedLocked(completedPolicyTransaction{
		prepare:      prepare,
		digest:       pending.digest,
		prepareAck:   pending.prepareAck,
		prepareFrame: pending.prepareFrame,
		finalAck:     ack,
	})
	e.policyStateMu.Unlock()
	return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, nil)
}

func (e *Engine) policyReject(binding proto.PolicyTransactionBinding, digest proto.PolicyProposalDigest, phase proto.PolicyAckPhase, code proto.PolicyAckCode, generation uint64, selectorID proto.TargetID, reason string) proto.PolicyAck {
	e.policyStateMu.Lock()
	ack := e.policyRejectLocked(binding, digest, phase, code, generation, selectorID, reason)
	e.policyStateMu.Unlock()
	return ack
}

func (e *Engine) policyRejectLocked(binding proto.PolicyTransactionBinding, digest proto.PolicyProposalDigest, phase proto.PolicyAckPhase, code proto.PolicyAckCode, generation uint64, selectorID proto.TargetID, reason string) proto.PolicyAck {
	if len(reason) > proto.PolicyMaxReasonBytes {
		reason = reason[:proto.PolicyMaxReasonBytes]
		for !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
	}
	return proto.PolicyAck{
		PolicyTransactionBinding: binding,
		Phase:                    phase,
		Code:                     code,
		Generation:               generation,
		CurrentGeneration:        e.policyGeneration,
		CurrentTargetID:          e.policySelections[selectorID],
		ProposalDigest:           digest,
		Reason:                   reason,
	}
}

func (e *Engine) publishPolicyAck(transactionID [16]byte, phase proto.PolicyAckPhase, ack proto.PolicyAck, replay []byte) error {
	if len(replay) != 0 {
		return e.replaySequencedFrame(replay)
	}
	frame, err := e.sendPolicyAck(ack)
	if len(frame) == 0 {
		return err
	}
	e.policyStateMu.Lock()
	if pending := e.policyIncoming; pending != nil && pending.prepare.TransactionID == transactionID && phase == proto.PolicyAckPhasePrepare {
		pending.prepareFrame = append([]byte(nil), frame...)
	}
	if completed, ok := e.policyCompleted[transactionID]; ok {
		if phase == proto.PolicyAckPhasePrepare {
			completed.prepareFrame = append([]byte(nil), frame...)
		} else {
			completed.finalFrame = append([]byte(nil), frame...)
		}
		e.policyCompleted[transactionID] = completed
	}
	e.policyStateMu.Unlock()
	return err
}

func (e *Engine) expirePolicyIncomingLocked(pending *incomingPolicyTransaction) completedPolicyTransaction {
	ack := e.policyRejectLocked(
		pending.prepare.PolicyTransactionBinding,
		pending.digest,
		proto.PolicyAckPhaseFinal,
		proto.PolicyAckCodeSuperseded,
		pending.generation,
		pending.prepare.SelectorID,
		"prepared transaction expired",
	)
	completed := completedPolicyTransaction{
		prepare:      pending.prepare,
		digest:       pending.digest,
		prepareAck:   pending.prepareAck,
		prepareFrame: pending.prepareFrame,
		finalAck:     ack,
	}
	e.policyIncoming = nil
	e.rememberPolicyCompletedLocked(completed)
	return completed
}

func (e *Engine) rememberPolicyCompletedLocked(completed completedPolicyTransaction) {
	id := completed.prepare.TransactionID
	if _, exists := e.policyCompleted[id]; !exists {
		e.policyCompletedOrder = append(e.policyCompletedOrder, id)
	}
	e.policyCompleted[id] = completed
	for len(e.policyCompletedOrder) > policyCompletedLimit {
		oldest := e.policyCompletedOrder[0]
		e.policyCompletedOrder = e.policyCompletedOrder[1:]
		delete(e.policyCompleted, oldest)
	}
}

func (e *Engine) recordPeerPolicyGeneration(generation uint64) {
	e.policyStateMu.Lock()
	if generation > e.policyPeerGeneration {
		e.policyPeerGeneration = generation
	}
	e.policyStateMu.Unlock()
}

func (e *Engine) validateIncomingPolicyBinding(binding proto.PolicyTransactionBinding) error {
	local := e.localGraphBinding()
	if !local.configured {
		return fmt.Errorf("local policy graph is not configured")
	}
	want := proto.PolicyTransactionBinding{
		SessionEpoch: proto.SessionEpoch(e.flowID),
		Direction:    senderDirection(e.side),
		GraphBinding: proto.GraphBinding{Revision: local.revision, Digest: local.digest},
	}
	if binding.SessionEpoch != want.SessionEpoch || binding.Direction != want.Direction || binding.GraphBinding != want.GraphBinding {
		return fmt.Errorf("incoming policy binding does not match local sender graph")
	}
	return nil
}

func (e *Engine) validateOutgoingPolicyBinding(binding proto.PolicyTransactionBinding) error {
	peer := e.peerGraphBinding()
	if !peer.configured {
		return fmt.Errorf("peer policy graph is not configured")
	}
	if binding.SessionEpoch != proto.SessionEpoch(e.flowID) || binding.Direction != peerSenderDirection(e.side) ||
		binding.GraphBinding != (proto.GraphBinding{Revision: peer.revision, Digest: peer.digest}) {
		return fmt.Errorf("policy ACK binding does not match peer sender graph")
	}
	return nil
}

func validatePolicySelection(manifest proto.GraphManifest, selectorID, targetID proto.TargetID) error {
	selector, ok := manifest.Node(selectorID)
	if !ok || selector.Kind != proto.GraphNodeKindSelector {
		return fmt.Errorf("engine: policy selector is not a selector in the bound graph")
	}
	for _, childID := range selector.Children {
		if childID == targetID {
			return nil
		}
	}
	return fmt.Errorf("engine: policy target is not an immediate selector child")
}

// InitializePolicySelection installs generation zero before the connection is
// exposed to application traffic. It records the selector child without
// consuming a runtime generation, matching the initial graph negotiation.
func (e *Engine) InitializePolicySelection(selectorID, targetID proto.TargetID, cause string) error {
	e.policyOwnerMu.Lock()
	defer e.policyOwnerMu.Unlock()
	binding := e.localGraphBinding()
	if err := validatePolicySelection(binding.manifest, selectorID, targetID); err != nil {
		return err
	}
	e.policyStateMu.Lock()
	if e.policyGeneration != 0 {
		e.policyStateMu.Unlock()
		return fmt.Errorf("engine: initial policy selection follows a runtime generation")
	}
	if current := e.policySelections[selectorID]; current != (proto.TargetID{}) && current != targetID {
		e.policyStateMu.Unlock()
		return fmt.Errorf("engine: initial policy selection is already configured")
	}
	e.policyStateMu.Unlock()
	if err := e.applyPolicySelectionFromGraph(binding, selectorID, targetID, cause); err != nil {
		return err
	}
	e.policyStateMu.Lock()
	e.policySelections[selectorID] = targetID
	e.policyStateMu.Unlock()
	return nil
}

// SelectLocalTarget is the only non-death runtime path for a sender-owner
// selector decision. It shares policyOwnerMu and the same monotonic generation
// with peer-requested commits, so a local decision after PREPARE supersedes the
// reservation instead of being overwritten by a stale COMMIT.
func (e *Engine) SelectLocalTarget(selectorID, targetID proto.TargetID, cause string) error {
	e.policyOwnerMu.Lock()
	defer e.policyOwnerMu.Unlock()
	if e.sendClosing.Load() || e.isClosed() {
		return net.ErrClosed
	}
	binding := e.localGraphBinding()
	if err := validatePolicySelection(binding.manifest, selectorID, targetID); err != nil {
		return err
	}
	e.policyStateMu.Lock()
	if e.policySelections[selectorID] == targetID {
		e.policyStateMu.Unlock()
		return nil
	}
	if e.policyGeneration == ^uint64(0) {
		e.policyStateMu.Unlock()
		return fmt.Errorf("engine: policy generation space exhausted")
	}
	base := e.policyGeneration
	e.policyStateMu.Unlock()
	if err := e.applyPolicySelectionFromGraph(binding, selectorID, targetID, cause); err != nil {
		return err
	}
	e.policyStateMu.Lock()
	if e.policyGeneration != base {
		e.policyStateMu.Unlock()
		return fmt.Errorf("engine: local policy generation changed during selection")
	}
	e.policyGeneration = base + 1
	e.policySelections[selectorID] = targetID
	e.policyStateMu.Unlock()
	return nil
}

func (e *Engine) applyPolicySelectionFromGraph(binding graphBinding, selectorID, targetID proto.TargetID, cause string) error {
	if !binding.configured {
		return fmt.Errorf("engine: local graph is not configured")
	}
	if err := validatePolicySelection(binding.manifest, selectorID, targetID); err != nil {
		return err
	}
	target, _ := binding.manifest.Node(targetID)
	kind := proto.ExecutionKindSelector
	switch target.Kind {
	case proto.GraphNodeKindPath, proto.GraphNodeKindSelector:
		kind = proto.ExecutionKindSelector
	case proto.GraphNodeKindBond:
		kind = proto.ExecutionKindBond
	case proto.GraphNodeKindRace:
		kind = proto.ExecutionKindRace
	default:
		return fmt.Errorf("engine: unsupported policy target kind %s", target.Kind)
	}

	leafNames := make([]string, 0)
	if err := collectGraphLeafNames(binding.manifest, targetID, &leafNames); err != nil {
		return err
	}
	e.pathsMu.RLock()
	byName := make(map[string]uint32, len(e.paths))
	for id, slot := range e.paths {
		name := pathSlotName(slot)
		if name != "" {
			byName[name] = id
		}
	}
	e.pathsMu.RUnlock()
	scope := make([]uint32, 0, len(leafNames))
	for _, name := range leafNames {
		if id := byName[name]; id != 0 {
			scope = append(scope, id)
		}
	}
	if len(scope) == 0 {
		return fmt.Errorf("engine: selected target has no attached path")
	}
	return e.setDispatchPolicy(kind, scope[0], scope, cause)
}

func collectGraphLeafNames(manifest proto.GraphManifest, id proto.TargetID, names *[]string) error {
	node, ok := manifest.Node(id)
	if !ok {
		return fmt.Errorf("engine: graph target is missing")
	}
	if node.Kind == proto.GraphNodeKindPath {
		*names = append(*names, node.Name)
		return nil
	}
	for _, childID := range node.Children {
		if err := collectGraphLeafNames(manifest, childID, names); err != nil {
			return err
		}
	}
	return nil
}

func newPolicyTransactionID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("engine: generate policy transaction id: %w", err)
	}
	if id == ([16]byte{}) {
		id[0] = 1
	}
	return id, nil
}

func (e *Engine) policyProtocolError(err error) error {
	if err == nil {
		return nil
	}
	wrapped := fmt.Errorf("%w: %v", ErrPeerProtocol, err)
	e.setCloseErr(wrapped)
	_ = e.Close()
	return wrapped
}
