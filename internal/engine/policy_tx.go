package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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
	prepare          proto.PolicyPrepare
	digest           proto.PolicyProposalDigest
	commitChallenge  proto.PolicyCommitChallenge
	commitDispatched bool
	prepareAcks      chan proto.PolicyAck
	finalAcks        chan proto.PolicyAck
}

type incomingPolicyTransaction struct {
	prepare                 proto.PolicyPrepare
	resolved                proto.TargetID
	decisionTopologyEpoch   uint64
	decisionEvidence        selectorEvidenceCommit
	decisionRequiresCutover bool
	digest                  proto.PolicyProposalDigest
	reservation             proto.PolicyReservationID
	graph                   graphBinding
	generation              uint64
	expires                 time.Time
	committed               bool
	prepareAck              proto.PolicyAck
	prepareFrame            []byte
}

type completedPolicyTransaction struct {
	prepare             proto.PolicyPrepare
	digest              proto.PolicyProposalDigest
	prepareAck          proto.PolicyAck
	finalAck            proto.PolicyAck
	finalNeedsChallenge bool
	prepareFrame        []byte
	finalFrame          []byte
}

type policyMessageKind uint8

const (
	policyMessagePrepare policyMessageKind = iota + 1
	policyMessageAck
	policyMessageCommit
)

type policyMessage struct {
	kind    policyMessageKind
	key     policyMessageKey
	prepare proto.PolicyPrepare
	ack     proto.PolicyAck
	commit  proto.PolicyCommit
	done    chan error
}

type policyMessageKey struct {
	kind        policyMessageKind
	seq         uint64
	frameDigest proto.FrameDigest
}

type policyProtocolViolation struct{ err error }

func (e *policyProtocolViolation) Error() string { return e.err.Error() }

func policyViolation(err error) error {
	return &policyProtocolViolation{err: err}
}

// lockPolicyMutation admits one policy-state mutation after taking
// policyStateMu. Receive-terminal publication takes policyTerminalMu without
// policyStateMu, so a queued worker blocked on policy state cannot prevent BYE
// from winning this boundary. Network writes and target resolution never hold
// policyTerminalMu.
func (e *Engine) lockPolicyMutation() bool {
	e.policyStateMu.Lock()
	e.policyTerminalMu.Lock()
	if e.policyTerminal.Load() || e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
		e.policyTerminalMu.Unlock()
		e.policyStateMu.Unlock()
		return false
	}
	return true
}

func (e *Engine) unlockPolicyMutation() {
	e.policyStateMu.Unlock()
	e.policyTerminalMu.Unlock()
}

// RequestPeerSelection asks the peer, which owns the opposite sender, to
// atomically select one immediate child of one selector. The owner assigns the
// generation; the requester never chooses it. One outgoing transaction is
// allowed at a time, independently from an incoming transaction.
func (e *Engine) RequestPeerSelection(ctx context.Context, selectorID, targetID proto.TargetID, cause string) error {
	return e.requestPeerSelection(ctx, proto.PolicyActionSelectChild, selectorID, targetID, cause, nil)
}

// RequestPeerSelectionClass asks the opposite sender owner to resolve its best
// fresh normal or peak child. PREPARE freezes the resolved target, and the
// returned ID is valid only after the owner's FINAL proves that exact commit.
func (e *Engine) RequestPeerSelectionClass(ctx context.Context, selectorID proto.TargetID, peak bool, cause string) (proto.TargetID, error) {
	action := proto.PolicyActionSelectBestNormal
	if peak {
		action = proto.PolicyActionSelectBestPeak
	}
	var resolved proto.TargetID
	err := e.requestPeerSelection(ctx, action, selectorID, proto.TargetID{}, cause, func(targetID proto.TargetID) {
		resolved = targetID
	})
	return resolved, err
}

func (e *Engine) requestPeerSelection(
	ctx context.Context,
	action proto.PolicyAction,
	selectorID, targetID proto.TargetID,
	cause string,
	committed func(proto.TargetID),
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	peer := e.peerGraphBinding()
	if !peer.configured {
		return fmt.Errorf("engine: peer graph is not configured")
	}
	prepareShape := proto.PolicyPrepare{Action: action, SelectorID: selectorID, TargetID: targetID}
	if err := validatePolicyPrepareTarget(peer.manifest, prepareShape); err != nil {
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
			SessionEpoch:  proto.SessionEpoch(e.FlowID()),
			Direction:     peerSenderDirection(e.side),
			GraphBinding:  proto.GraphBinding{Revision: peer.revision, Digest: peer.digest},
			TransactionID: txID,
		},
		BaseGeneration: base,
		Action:         action,
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
	var reservation proto.PolicyReservationID
	var resolvedTarget proto.TargetID
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
				if err := validatePolicyResolvedTarget(peer.manifest, tx.prepare, ack.ResolvedTargetID); err != nil {
					return e.policyProtocolError(fmt.Errorf("owner resolved invalid policy target: %w", err))
				}
				generation = ack.Generation
				reservation = ack.ReservationID
				resolvedTarget = ack.ResolvedTargetID
				challenge, challengeErr := newPolicyCommitChallenge()
				if challengeErr != nil {
					return challengeErr
				}
				commit := proto.PolicyCommit{
					PolicyTransactionBinding: tx.prepare.PolicyTransactionBinding,
					Generation:               generation,
					ProposalDigest:           digest,
					ReservationID:            reservation,
					CommitChallenge:          challenge,
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
				e.policyStateMu.Lock()
				if e.policyOutgoing != tx {
					e.policyStateMu.Unlock()
					return fmt.Errorf("engine: outgoing policy transaction changed during COMMIT")
				}
				tx.commitChallenge = challenge
				tx.commitDispatched = true
				e.policyStateMu.Unlock()
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
			if ack.Generation != generation || ack.CurrentGeneration != generation || ack.CurrentTargetID != resolvedTarget ||
				ack.ResolvedTargetID != resolvedTarget || ack.ReservationID != reservation ||
				ack.CommitChallenge != tx.commitChallenge {
				return e.policyProtocolError(fmt.Errorf("COMMIT_ACK does not prove requested policy state"))
			}
			e.recordPeerPolicyGeneration(generation)
			if committed != nil {
				committed(resolvedTarget)
			}
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

func (e *Engine) sendPolicyAckPreemptingReplay(p proto.PolicyAck) ([]byte, error) {
	payload, err := p.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendFrameTrackedPreemptingReplay(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPolicyAck), payload)
}

func (e *Engine) sendPolicyCommit(p proto.PolicyCommit) ([]byte, error) {
	payload, err := p.Encode()
	if err != nil {
		return nil, err
	}
	return e.sendFrameTracked(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPolicyCommit), payload)
}

func (e *Engine) enqueuePolicyMessageLocked(message policyMessage) bool {
	e.policyLifecycleMu.Lock()
	if e.closing.Load() || e.sendClosing.Load() || e.isClosed() || e.recvTerminal {
		e.policyLifecycleMu.Unlock()
		return false
	}
	e.policyQueueMu.Lock()
	if _, exists := e.policyQueued[message.key]; exists {
		e.policyQueueMu.Unlock()
		e.policyLifecycleMu.Unlock()
		return true
	}
	e.policyQueued[message.key] = struct{}{}
	e.policyQueueMu.Unlock()
	select {
	case e.policyInbox <- message:
		e.policyLifecycleMu.Unlock()
		return true
	default:
		e.releasePolicyMessageKey(message.key)
		e.policyLifecycleMu.Unlock()
		e.publishRecvTerminalLocked(fmt.Errorf("%w: policy inbox capacity exceeded", ErrPeerProtocol))
		return false
	}
}

func (e *Engine) releasePolicyMessageKey(key policyMessageKey) {
	e.policyQueueMu.Lock()
	delete(e.policyQueued, key)
	e.policyQueueMu.Unlock()
}

func (e *Engine) policyLoop() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case now := <-ticker.C:
			e.expirePreparedPolicy(now)
		case message := <-e.policyInbox:
			e.releasePolicyMessageKey(message.key)
			if e.closing.Load() || e.isClosed() {
				return
			}
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
			if message.done != nil {
				message.done <- err
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
	if e.policyTerminal.Load() || e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
		return net.ErrClosed
	}
	if err := e.validateIncomingPolicyBinding(prepare.PolicyTransactionBinding); err != nil {
		return policyViolation(err)
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		return policyViolation(err)
	}
	graph := e.localGraphBinding()
	e.policyStateMu.Lock()
	if e.policyTerminal.Load() || e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
		e.policyStateMu.Unlock()
		return net.ErrClosed
	}
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
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyReservationID{}, proto.PolicyCommitChallenge{}, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeBusy, 0, prepare.SelectorID, "another policy transaction is pending")
		e.policyStateMu.Unlock()
		_, err := e.sendPolicyAck(ack)
		return err
	}
	e.policyStateMu.Unlock()

	resolvedTarget, decisionEvidence, decisionRequiresCutover, resolveErr :=
		e.resolveIncomingPolicyTarget(prepare, graph.manifest)

	// Target resolution reads path evidence and may invoke admission callbacks,
	// so it runs outside policyStateMu. Recheck every owner invariant before
	// installing the reservation; a concurrent owner move makes this PREPARE
	// stale rather than allowing evidence from one generation into another.
	if !e.lockPolicyMutation() {
		return net.ErrClosed
	}
	if completed, ok := e.policyCompleted[prepare.TransactionID]; ok {
		if completed.prepare != prepare || completed.digest != digest {
			e.unlockPolicyMutation()
			return policyViolation(fmt.Errorf("policy transaction id reused with different PREPARE"))
		}
		ack, frame := completed.prepareAck, completed.prepareFrame
		e.unlockPolicyMutation()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, frame)
	}
	if pending := e.policyIncoming; pending != nil {
		if pending.prepare.TransactionID == prepare.TransactionID {
			if pending.prepare != prepare || pending.digest != digest {
				e.unlockPolicyMutation()
				return policyViolation(fmt.Errorf("policy transaction id reused while pending"))
			}
			ack, frame := pending.prepareAck, pending.prepareFrame
			e.unlockPolicyMutation()
			return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, frame)
		}
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyReservationID{}, proto.PolicyCommitChallenge{}, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeBusy, 0, prepare.SelectorID, "another policy transaction is pending")
		e.unlockPolicyMutation()
		_, err := e.sendPolicyAck(ack)
		return err
	}
	if prepare.BaseGeneration != e.policyGeneration {
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyReservationID{}, proto.PolicyCommitChallenge{}, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeStale, 0, prepare.SelectorID, "base generation is stale")
		e.rememberPolicyCompletedLocked(completedPolicyTransaction{prepare: prepare, digest: digest, prepareAck: ack})
		e.unlockPolicyMutation()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
	}
	if resolveErr != nil {
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyReservationID{}, proto.PolicyCommitChallenge{}, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeReject, 0, prepare.SelectorID, resolveErr.Error())
		e.rememberPolicyCompletedLocked(completedPolicyTransaction{prepare: prepare, digest: digest, prepareAck: ack})
		e.unlockPolicyMutation()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
	}
	if e.policyGeneration == ^uint64(0) {
		ack := e.policyRejectLocked(prepare.PolicyTransactionBinding, digest, proto.PolicyReservationID{}, proto.PolicyCommitChallenge{}, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeReject, 0, prepare.SelectorID, "generation space exhausted")
		e.rememberPolicyCompletedLocked(completedPolicyTransaction{prepare: prepare, digest: digest, prepareAck: ack})
		e.unlockPolicyMutation()
		return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
	}
	reservation, err := newPolicyReservationID()
	if err != nil {
		e.unlockPolicyMutation()
		return err
	}
	generation := e.policyGeneration + 1
	ack := proto.PolicyAck{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Phase:                    proto.PolicyAckPhasePrepare,
		Code:                     proto.PolicyAckCodeAccept,
		Generation:               generation,
		CurrentGeneration:        e.policyGeneration,
		CurrentTargetID:          e.policySelections[prepare.SelectorID],
		ResolvedTargetID:         resolvedTarget,
		ProposalDigest:           digest,
		ReservationID:            reservation,
	}
	e.policyIncoming = &incomingPolicyTransaction{
		prepare:                 prepare,
		resolved:                resolvedTarget,
		decisionTopologyEpoch:   decisionEvidence.topologyEpoch,
		decisionEvidence:        decisionEvidence,
		decisionRequiresCutover: decisionRequiresCutover,
		digest:                  digest,
		reservation:             reservation,
		graph:                   graph,
		generation:              generation,
		expires:                 time.Now().Add(policyTransactionTTL),
		prepareAck:              ack,
	}
	e.unlockPolicyMutation()
	return e.publishPolicyAck(prepare.TransactionID, proto.PolicyAckPhasePrepare, ack, nil)
}

func (e *Engine) handlePolicyAck(ack proto.PolicyAck) error {
	if e.policyTerminal.Load() || e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
		return net.ErrClosed
	}
	if err := e.validateOutgoingPolicyBinding(ack.PolicyTransactionBinding); err != nil {
		return policyViolation(err)
	}
	if !e.lockPolicyMutation() {
		return net.ErrClosed
	}
	tx := e.policyOutgoing
	if tx == nil || tx.prepare.TransactionID != ack.TransactionID {
		e.unlockPolicyMutation()
		return nil
	}
	if tx.prepare.PolicyTransactionBinding != ack.PolicyTransactionBinding {
		e.unlockPolicyMutation()
		return policyViolation(fmt.Errorf("policy ACK binding changed within transaction"))
	}
	if tx.digest != ack.ProposalDigest {
		e.unlockPolicyMutation()
		return policyViolation(fmt.Errorf("policy ACK proposal digest changed within transaction"))
	}
	var channel chan proto.PolicyAck
	switch ack.Phase {
	case proto.PolicyAckPhasePrepare:
		if ack.CommitChallenge != (proto.PolicyCommitChallenge{}) {
			e.unlockPolicyMutation()
			return policyViolation(fmt.Errorf("prepare policy ACK carried a commit challenge"))
		}
		channel = tx.prepareAcks
	case proto.PolicyAckPhaseFinal:
		// A FINAL may race the return of the COMMIT write on an in-memory or
		// otherwise synchronous carrier. Ignore it until the requester has
		// published its local COMMIT boundary; retry then elicits an exact replay.
		// The unpredictable challenge proves the peer received that COMMIT.
		if !tx.commitDispatched {
			e.unlockPolicyMutation()
			return nil
		}
		if ack.CommitChallenge != tx.commitChallenge {
			e.unlockPolicyMutation()
			return policyViolation(fmt.Errorf("final policy ACK commit challenge mismatch"))
		}
		channel = tx.finalAcks
	default:
		e.unlockPolicyMutation()
		return policyViolation(fmt.Errorf("invalid policy ACK phase %d", ack.Phase))
	}
	select {
	case channel <- ack:
	default:
		// Each phase has an independent one-entry mailbox. Duplicates can
		// never displace the other phase's ACK.
	}
	e.unlockPolicyMutation()
	return nil
}

func (e *Engine) handlePolicyCommit(commit proto.PolicyCommit) error {
	if e.policyTerminal.Load() || e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
		return net.ErrClosed
	}
	if err := e.validateIncomingPolicyBinding(commit.PolicyTransactionBinding); err != nil {
		return policyViolation(err)
	}

	if !e.lockPolicyMutation() {
		return net.ErrClosed
	}
	if completed, ok := e.policyCompleted[commit.TransactionID]; ok {
		if completed.finalAck.Phase == proto.PolicyAckPhaseInvalid {
			e.unlockPolicyMutation()
			return policyViolation(fmt.Errorf("COMMIT followed a rejected PREPARE"))
		}
		if completed.digest != commit.ProposalDigest || completed.finalAck.Generation != commit.Generation ||
			completed.finalAck.ReservationID != commit.ReservationID ||
			completed.prepare.PolicyTransactionBinding != commit.PolicyTransactionBinding {
			e.unlockPolicyMutation()
			return policyViolation(fmt.Errorf("policy transaction id reused with different COMMIT"))
		}
		if completed.finalNeedsChallenge {
			completed.finalAck.CommitChallenge = commit.CommitChallenge
			completed.finalNeedsChallenge = false
			completed.finalFrame = nil
			e.policyCompleted[commit.TransactionID] = completed
		} else if completed.finalAck.CommitChallenge != commit.CommitChallenge {
			e.unlockPolicyMutation()
			return policyViolation(fmt.Errorf("policy transaction id reused with different COMMIT challenge"))
		}
		ack, frame := completed.finalAck, completed.finalFrame
		e.unlockPolicyMutation()
		return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, frame)
	}
	pending := e.policyIncoming
	if pending == nil {
		ack := e.policyRejectLocked(commit.PolicyTransactionBinding, commit.ProposalDigest, commit.ReservationID, commit.CommitChallenge, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeSuperseded, commit.Generation, proto.TargetID{}, "prepared transaction is no longer pending")
		e.unlockPolicyMutation()
		_, err := e.sendPolicyAck(ack)
		return err
	}
	if pending.prepare.TransactionID != commit.TransactionID {
		ack := e.policyRejectLocked(commit.PolicyTransactionBinding, commit.ProposalDigest, commit.ReservationID, commit.CommitChallenge, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeBusy, commit.Generation, proto.TargetID{}, "another policy transaction is pending")
		e.unlockPolicyMutation()
		_, err := e.sendPolicyAck(ack)
		return err
	}
	if pending.generation != commit.Generation || pending.digest != commit.ProposalDigest || pending.reservation != commit.ReservationID {
		e.unlockPolicyMutation()
		return policyViolation(fmt.Errorf("policy transaction id reused with different COMMIT proposal"))
	}
	if !pending.committed && !time.Now().Before(pending.expires) {
		completed := e.expirePolicyIncomingLocked(pending)
		completed.finalAck.CommitChallenge = commit.CommitChallenge
		completed.finalNeedsChallenge = false
		e.policyCompleted[commit.TransactionID] = completed
		ack := completed.finalAck
		e.unlockPolicyMutation()
		return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, completed.finalFrame)
	}
	prepare := pending.prepare
	e.unlockPolicyMutation()
	validationTopologyEpoch := e.currentPathTopologyEpoch()
	commitEvidence, applyErr := e.validateIncomingPolicyCommitTarget(prepare, pending.resolved)
	if applyErr == nil && pending.decisionEvidence.physicallyBound() &&
		!pending.decisionEvidence.physicalEqual(commitEvidence) {
		applyErr = errStaleSelectorEvidence
	}
	origin := policyOriginForAction(prepare.Action)
	decisionEvidence := commitEvidence
	if !decisionEvidence.bound() {
		decisionEvidence = pending.decisionEvidence
	}
	if !decisionEvidence.bound() {
		decisionEvidence = selectorEvidenceCommit{topologyEpoch: validationTopologyEpoch}
	}
	requiresCutover := origin.requiresSelectorCutover()
	if prepare.Action == proto.PolicyActionSelectChild {
		requiresCutover = pending.decisionRequiresCutover
		if applyErr == nil && !requiresCutover &&
			e.currentPathTopologyEpoch() != pending.decisionEvidence.topologyEpoch {
			applyErr = errStaleSelectorEvidence
		}
	}
	if applyErr != nil {
		return e.rejectIncomingPolicyCommitAfterValidation(commit, pending, applyErr)
	}

	if hook := e.policyCommitBeforeOwnerLock; hook != nil {
		hook()
	}
	e.policyCutoverMu.Lock()
	defer e.policyCutoverMu.Unlock()
	e.policyOwnerMu.Lock()
	ownerHeld := true
	releaseOwner := func() {
		if ownerHeld {
			ownerHeld = false
			e.policyOwnerMu.Unlock()
		}
	}
	defer releaseOwner()
	if !e.lockPolicyMutation() {
		return net.ErrClosed
	}
	if e.policyIncoming != pending || e.policyGeneration != prepare.BaseGeneration || e.sendClosing.Load() || e.isClosed() {
		if e.policyIncoming == pending {
			e.policyIncoming = nil
		}
		ack := e.policyRejectLocked(commit.PolicyTransactionBinding, pending.digest, pending.reservation, commit.CommitChallenge, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeStale, commit.Generation, prepare.SelectorID, "owner state changed after PREPARE")
		completed := completedPolicyTransaction{prepare: prepare, digest: pending.digest, prepareAck: pending.prepareAck, prepareFrame: pending.prepareFrame, finalAck: ack}
		e.rememberPolicyCompletedLocked(completed)
		e.unlockPolicyMutation()
		return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, nil)
	}
	if !pending.committed && !time.Now().Before(pending.expires) {
		completed := e.expirePolicyIncomingLocked(pending)
		completed.finalAck.CommitChallenge = commit.CommitChallenge
		completed.finalNeedsChallenge = false
		e.policyCompleted[commit.TransactionID] = completed
		ack := completed.finalAck
		e.unlockPolicyMutation()
		return e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, completed.finalFrame)
	}
	e.unlockPolicyMutation()

	cutoverGeneration := uint64(0)
	if requiresCutover {
		if prepare.Action == proto.PolicyActionSelectChild &&
			!pending.decisionEvidence.physicallyBound() {
			decisionEvidence = selectorEvidenceCommit{}
		}
		cutoverGeneration = e.beginSelectorCutover()
		defer func() {
			if cutoverGeneration != 0 {
				e.finishSelectorCutoverWithReplay(cutoverGeneration)
			}
		}()
	}

	committed := false
	commitPolicy := func(publishRoute func()) error {
		if !e.lockPolicyMutation() {
			return net.ErrClosed
		}
		if e.policyIncoming != pending || e.policyGeneration != prepare.BaseGeneration {
			e.unlockPolicyMutation()
			panic("engine: prepared policy ownership changed while owner lock was held")
		}
		if !time.Now().Before(pending.expires) {
			e.unlockPolicyMutation()
			return fmt.Errorf("engine: prepared policy transaction expired before commit")
		}
		if err := e.validateSelectorEvidenceCommitLocked(decisionEvidence); err != nil {
			e.unlockPolicyMutation()
			return err
		}
		e.policyGeneration = commit.Generation
		e.policySelections[prepare.SelectorID] = pending.resolved
		pending.committed = true
		publishRoute()
		e.policyObservationGen.Store(commit.Generation)
		committed = true
		e.unlockPolicyMutation()
		releaseOwner()
		return nil
	}
	if applyErr == nil {
		applyErr = e.applyPolicySelectionFromGraphOriginCommittedEvidence(
			pending.graph,
			prepare.SelectorID,
			pending.resolved,
			prepare.Cause,
			origin,
			cutoverGeneration,
			decisionEvidence,
			commitPolicy,
		)
	}
	if committed {
		e.observePeakPolicy(prepare.SelectorID, pending.resolved, origin, prepare.Cause)
	}
	if cutoverGeneration != 0 {
		e.finishSelectorCutoverWithReplay(cutoverGeneration)
		cutoverGeneration = 0
	}

	if !e.lockPolicyMutation() {
		releaseOwner()
		return net.ErrClosed
	}
	wantGeneration := prepare.BaseGeneration
	if committed {
		wantGeneration = commit.Generation
	}
	if e.policyIncoming != pending || e.policyGeneration != wantGeneration {
		e.unlockPolicyMutation()
		return policyViolation(fmt.Errorf("prepared policy transaction lost ownership during commit"))
	}
	var ack proto.PolicyAck
	if !committed {
		ack = e.policyRejectLocked(commit.PolicyTransactionBinding, pending.digest, pending.reservation, commit.CommitChallenge, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeReject, commit.Generation, prepare.SelectorID, applyErr.Error())
	} else {
		ack = proto.PolicyAck{
			PolicyTransactionBinding: commit.PolicyTransactionBinding,
			Phase:                    proto.PolicyAckPhaseFinal,
			Code:                     proto.PolicyAckCodeAccept,
			Generation:               commit.Generation,
			CurrentGeneration:        commit.Generation,
			CurrentTargetID:          pending.resolved,
			ResolvedTargetID:         pending.resolved,
			ProposalDigest:           pending.digest,
			ReservationID:            pending.reservation,
			CommitChallenge:          commit.CommitChallenge,
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
	e.unlockPolicyMutation()
	releaseOwner()
	ackErr := e.publishPolicyAck(commit.TransactionID, proto.PolicyAckPhaseFinal, ack, nil)
	if committed && applyErr != nil {
		return errors.Join(ackErr, fmt.Errorf("%w: committed policy replay: %v", ErrPolicyOutcomeUnknown, applyErr))
	}
	return ackErr
}

func (e *Engine) rejectIncomingPolicyCommitAfterValidation(
	commit proto.PolicyCommit,
	pending *incomingPolicyTransaction,
	reason error,
) error {
	if !e.lockPolicyMutation() {
		return net.ErrClosed
	}
	prepare := pending.prepare
	if e.policyIncoming != pending || e.policyGeneration != prepare.BaseGeneration ||
		e.sendClosing.Load() || e.isClosed() {
		if e.policyIncoming == pending {
			e.policyIncoming = nil
		}
		ack := e.policyRejectLocked(
			commit.PolicyTransactionBinding, pending.digest, pending.reservation,
			commit.CommitChallenge, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeReject,
			commit.Generation, prepare.SelectorID, reason.Error(),
		)
		completed := completedPolicyTransaction{
			prepare: prepare, digest: pending.digest, prepareAck: pending.prepareAck,
			prepareFrame: pending.prepareFrame, finalAck: ack,
		}
		e.rememberPolicyCompletedLocked(completed)
		e.unlockPolicyMutation()
		return e.publishPolicyAckPreemptingReplay(commit.TransactionID, proto.PolicyAckPhaseFinal, ack)
	}
	if !pending.committed && !time.Now().Before(pending.expires) {
		completed := e.expirePolicyIncomingLocked(pending)
		completed.finalAck.CommitChallenge = commit.CommitChallenge
		completed.finalNeedsChallenge = false
		e.policyCompleted[commit.TransactionID] = completed
		ack := completed.finalAck
		e.unlockPolicyMutation()
		return e.publishPolicyAckPreemptingReplay(commit.TransactionID, proto.PolicyAckPhaseFinal, ack)
	}
	ack := e.policyRejectLocked(
		commit.PolicyTransactionBinding, pending.digest, pending.reservation,
		commit.CommitChallenge, proto.PolicyAckPhaseFinal, proto.PolicyAckCodeReject,
		commit.Generation, prepare.SelectorID, reason.Error(),
	)
	e.policyIncoming = nil
	e.rememberPolicyCompletedLocked(completedPolicyTransaction{
		prepare: prepare, digest: pending.digest, prepareAck: pending.prepareAck,
		prepareFrame: pending.prepareFrame, finalAck: ack,
	})
	e.unlockPolicyMutation()
	return e.publishPolicyAckPreemptingReplay(commit.TransactionID, proto.PolicyAckPhaseFinal, ack)
}

func (e *Engine) policyRejectLocked(binding proto.PolicyTransactionBinding, digest proto.PolicyProposalDigest, reservation proto.PolicyReservationID, challenge proto.PolicyCommitChallenge, phase proto.PolicyAckPhase, code proto.PolicyAckCode, generation uint64, selectorID proto.TargetID, reason string) proto.PolicyAck {
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
		ReservationID:            reservation,
		CommitChallenge:          challenge,
		Reason:                   reason,
	}
}

func (e *Engine) publishPolicyAck(transactionID [16]byte, phase proto.PolicyAckPhase, ack proto.PolicyAck, replay []byte) error {
	if len(replay) != 0 {
		return e.replaySequencedFrame(replay)
	}
	frame, err := e.sendPolicyAck(ack)
	return e.recordPublishedPolicyAck(transactionID, phase, frame, err)
}

func (e *Engine) publishPolicyAckPreemptingReplay(transactionID [16]byte, phase proto.PolicyAckPhase, ack proto.PolicyAck) error {
	frame, err := e.sendPolicyAckPreemptingReplay(ack)
	return e.recordPublishedPolicyAck(transactionID, phase, frame, err)
}

func (e *Engine) recordPublishedPolicyAck(transactionID [16]byte, phase proto.PolicyAckPhase, frame []byte, err error) error {
	if len(frame) == 0 {
		return err
	}
	if !e.lockPolicyMutation() {
		return errors.Join(err, net.ErrClosed)
	}
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
	e.unlockPolicyMutation()
	return err
}

func (e *Engine) expirePolicyIncomingLocked(pending *incomingPolicyTransaction) completedPolicyTransaction {
	if pending.committed {
		panic("engine: committed policy transaction cannot expire")
	}
	ack := e.policyRejectLocked(
		pending.prepare.PolicyTransactionBinding,
		pending.digest,
		pending.reservation,
		proto.PolicyCommitChallenge{},
		proto.PolicyAckPhaseFinal,
		proto.PolicyAckCodeSuperseded,
		pending.generation,
		pending.prepare.SelectorID,
		"prepared transaction expired",
	)
	completed := completedPolicyTransaction{
		prepare:             pending.prepare,
		digest:              pending.digest,
		prepareAck:          pending.prepareAck,
		prepareFrame:        pending.prepareFrame,
		finalAck:            ack,
		finalNeedsChallenge: true,
	}
	e.policyIncoming = nil
	e.rememberPolicyCompletedLocked(completed)
	return completed
}

func (e *Engine) expirePreparedPolicy(now time.Time) {
	if e.policyTerminal.Load() {
		return
	}
	e.policyLifecycleMu.Lock()
	defer e.policyLifecycleMu.Unlock()
	if e.policyTerminal.Load() || e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
		return
	}
	if !e.lockPolicyMutation() {
		return
	}
	pending := e.policyIncoming
	if pending != nil && !pending.committed && !now.Before(pending.expires) {
		e.expirePolicyIncomingLocked(pending)
	}
	e.unlockPolicyMutation()
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
	if !e.lockPolicyMutation() {
		return
	}
	if generation > e.policyPeerGeneration {
		e.policyPeerGeneration = generation
	}
	e.unlockPolicyMutation()
}

func (e *Engine) validateIncomingPolicyBinding(binding proto.PolicyTransactionBinding) error {
	local := e.localGraphBinding()
	if !local.configured {
		return fmt.Errorf("local policy graph is not configured")
	}
	want := proto.PolicyTransactionBinding{
		SessionEpoch: proto.SessionEpoch(e.FlowID()),
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
	if binding.SessionEpoch != proto.SessionEpoch(e.FlowID()) || binding.Direction != peerSenderDirection(e.side) ||
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

func validatePolicyPrepareTarget(manifest proto.GraphManifest, prepare proto.PolicyPrepare) error {
	selector, ok := manifest.Node(prepare.SelectorID)
	if !ok || selector.Kind != proto.GraphNodeKindSelector {
		return fmt.Errorf("engine: policy selector is not a selector in the bound graph")
	}
	switch prepare.Action {
	case proto.PolicyActionSelectChild:
		return validatePolicySelection(manifest, prepare.SelectorID, prepare.TargetID)
	case proto.PolicyActionSelectBestNormal, proto.PolicyActionSelectBestPeak:
		if prepare.TargetID != (proto.TargetID{}) {
			return fmt.Errorf("engine: selector-class policy must not specify a target")
		}
		wantPeak := prepare.Action == proto.PolicyActionSelectBestPeak
		for _, childID := range selector.Children {
			isPeak := false
			for _, peakID := range selector.PeakCandidates {
				if peakID == childID {
					isPeak = true
					break
				}
			}
			if isPeak == wantPeak {
				return nil
			}
		}
		return fmt.Errorf("engine: selector has no target in the requested class")
	default:
		return fmt.Errorf("engine: unsupported policy action %d", prepare.Action)
	}
}

func validatePolicyResolvedTarget(manifest proto.GraphManifest, prepare proto.PolicyPrepare, targetID proto.TargetID) error {
	if targetID == (proto.TargetID{}) {
		return fmt.Errorf("engine: policy owner resolved a zero target")
	}
	if err := validatePolicySelection(manifest, prepare.SelectorID, targetID); err != nil {
		return err
	}
	if prepare.Action == proto.PolicyActionSelectChild {
		if targetID != prepare.TargetID {
			return fmt.Errorf("engine: policy owner changed an explicit target")
		}
		return nil
	}
	selector, _ := manifest.Node(prepare.SelectorID)
	isPeak := false
	for _, peakID := range selector.PeakCandidates {
		if peakID == targetID {
			isPeak = true
			break
		}
	}
	wantPeak := prepare.Action == proto.PolicyActionSelectBestPeak
	if (prepare.Action != proto.PolicyActionSelectBestNormal && !wantPeak) || isPeak != wantPeak {
		return fmt.Errorf("engine: policy owner resolved a target from the wrong selector class")
	}
	return nil
}

func (e *Engine) resolveIncomingPolicyTarget(
	prepare proto.PolicyPrepare,
	manifest proto.GraphManifest,
) (proto.TargetID, selectorEvidenceCommit, bool, error) {
	if err := validatePolicyPrepareTarget(manifest, prepare); err != nil {
		return proto.TargetID{}, selectorEvidenceCommit{}, false, err
	}
	if prepare.Action == proto.PolicyActionSelectChild {
		if err := e.admitPeerPolicy(prepare.SelectorID, prepare.TargetID, prepare.Cause); err != nil {
			return proto.TargetID{}, selectorEvidenceCommit{}, false, err
		}
		var evidence selectorEvidenceCommit
		if policyTargetIsPeak(manifest, prepare.SelectorID, prepare.TargetID) {
			ranked, view, err := e.rankLocalSelectorClass(prepare.SelectorID, true, nil, true)
			if err != nil || !selectorTargetRanked(ranked, prepare.TargetID) {
				return proto.TargetID{}, selectorEvidenceCommit{}, false, fmt.Errorf("engine: explicit peak target has no fresh admissible evidence")
			}
			evidence = view.commitEvidence()
		}
		requiresCutover, topologyEpoch, err := e.policySelectionCutoverSnapshot(
			prepare.SelectorID, prepare.TargetID,
		)
		if err != nil {
			return proto.TargetID{}, selectorEvidenceCommit{}, false, err
		}
		if evidence.bound() && evidence.topologyEpoch != topologyEpoch {
			return proto.TargetID{}, selectorEvidenceCommit{}, false, errStaleSelectorEvidence
		}
		if !evidence.bound() {
			evidence = selectorEvidenceCommit{topologyEpoch: topologyEpoch}
		}
		return prepare.TargetID, evidence, requiresCutover, nil
	}
	peak := prepare.Action == proto.PolicyActionSelectBestPeak
	excluded := make(map[proto.TargetID]struct{})
	for _, targetID := range policySelectorClassTargets(manifest, prepare.SelectorID, peak) {
		if err := e.admitPeerPolicy(prepare.SelectorID, targetID, prepare.Cause); err != nil {
			excluded[targetID] = struct{}{}
		}
	}
	ranked, view, err := e.rankLocalSelectorClass(prepare.SelectorID, peak, excluded, peak)
	if err != nil {
		return proto.TargetID{}, selectorEvidenceCommit{}, false, err
	}
	if len(ranked) == 0 {
		return proto.TargetID{}, selectorEvidenceCommit{}, false, fmt.Errorf("engine: no sender-owned target in the requested class passed admission")
	}
	return ranked[0], view.commitEvidence(), true, nil
}

func (e *Engine) policySelectionCutoverSnapshot(
	selectorID, targetID proto.TargetID,
) (bool, uint64, error) {
	runtime := e.localExecutionRuntime()
	if runtime == nil || runtime.plan == nil {
		return false, 0, errExecutionRuntimeNotConfigured
	}
	e.pathsMu.RLock()
	attached := e.attachedLeafTargetsLocked()
	requiresCutover := runtime.policySelectionChangesEffectiveRoute(selectorID, targetID, attached)
	topologyEpoch := e.currentPathTopologyEpoch()
	e.pathsMu.RUnlock()
	return requiresCutover, topologyEpoch, nil
}

func (e *Engine) validateIncomingPolicyCommitTarget(
	prepare proto.PolicyPrepare,
	targetID proto.TargetID,
) (selectorEvidenceCommit, error) {
	if err := validatePolicyResolvedTarget(e.localGraphBinding().manifest, prepare, targetID); err != nil {
		return selectorEvidenceCommit{}, err
	}
	var evidence selectorEvidenceCommit
	if prepare.Action == proto.PolicyActionSelectBestPeak ||
		(prepare.Action == proto.PolicyActionSelectChild && policyTargetIsPeak(
			e.localGraphBinding().manifest, prepare.SelectorID, targetID,
		)) {
		ranked, view, err := e.rankLocalSelectorClass(prepare.SelectorID, true, nil, true)
		if err != nil || !selectorTargetRanked(ranked, targetID) {
			return selectorEvidenceCommit{}, fmt.Errorf("engine: resolved peak target is no longer fresh and admissible")
		}
		evidence = view.commitEvidence()
	} else if prepare.Action != proto.PolicyActionSelectChild {
		peak := prepare.Action == proto.PolicyActionSelectBestPeak
		ranked, view, err := e.rankLocalSelectorClass(prepare.SelectorID, peak, nil, false)
		if err != nil || !selectorTargetRanked(ranked, targetID) {
			return selectorEvidenceCommit{}, fmt.Errorf("engine: resolved selector-class target is no longer fresh and healthy")
		}
		evidence = view.commitEvidence()
	}
	if err := e.admitPeerPolicy(prepare.SelectorID, targetID, prepare.Cause); err != nil {
		return selectorEvidenceCommit{}, err
	}
	return evidence, nil
}

func selectorTargetRanked(ranked []proto.TargetID, targetID proto.TargetID) bool {
	for _, candidate := range ranked {
		if candidate == targetID {
			return true
		}
	}
	return false
}

func policySelectorClassTargets(
	manifest proto.GraphManifest,
	selectorID proto.TargetID,
	peak bool,
) []proto.TargetID {
	selector, ok := manifest.Node(selectorID)
	if !ok || selector.Kind != proto.GraphNodeKindSelector {
		return nil
	}
	peakSet := make(map[proto.TargetID]struct{}, len(selector.PeakCandidates))
	for _, targetID := range selector.PeakCandidates {
		peakSet[targetID] = struct{}{}
	}
	targets := make([]proto.TargetID, 0, len(selector.Children))
	for _, targetID := range selector.Children {
		_, isPeak := peakSet[targetID]
		if isPeak == peak {
			targets = append(targets, targetID)
		}
	}
	return targets
}

func policyTargetIsPeak(
	manifest proto.GraphManifest,
	selectorID, targetID proto.TargetID,
) bool {
	selector, ok := manifest.Node(selectorID)
	if !ok || selector.Kind != proto.GraphNodeKindSelector {
		return false
	}
	for _, peakID := range selector.PeakCandidates {
		if peakID == targetID {
			return true
		}
	}
	return false
}

func policyOriginForAction(action proto.PolicyAction) policySelectionOrigin {
	switch action {
	case proto.PolicyActionSelectBestPeak:
		return policySelectionPeakPromote
	case proto.PolicyActionSelectBestNormal:
		return policySelectionPeakReturn
	default:
		return policySelectionExternal
	}
}

// InitializePolicySelection installs generation zero before the connection is
// exposed to application traffic. It records the selector child without
// consuming a runtime generation, matching the initial graph negotiation.
func (e *Engine) InitializePolicySelection(selectorID, targetID proto.TargetID, cause string) error {
	e.policyCutoverMu.Lock()
	defer e.policyCutoverMu.Unlock()
	e.policyOwnerMu.Lock()
	defer e.policyOwnerMu.Unlock()
	binding := e.localGraphBinding()
	if err := validatePolicySelection(binding.manifest, selectorID, targetID); err != nil {
		return err
	}
	commitInitial := func(publishRoute func()) error {
		e.policyStateMu.Lock()
		defer e.policyStateMu.Unlock()
		if e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
			return net.ErrClosed
		}
		if e.policyGeneration != 0 {
			return fmt.Errorf("engine: initial policy selection follows a runtime generation")
		}
		if current := e.policySelections[selectorID]; current != (proto.TargetID{}) && current != targetID {
			return fmt.Errorf("engine: initial policy selection is already configured")
		}
		e.policySelections[selectorID] = targetID
		publishRoute()
		return nil
	}
	return e.applyPolicySelectionFromGraphOriginCommitted(
		binding, selectorID, targetID, cause, policySelectionExternal, 0, 0, commitInitial,
	)
}

// SelectLocalTarget is the only non-death runtime path for a sender-owner
// selector decision. It shares policyOwnerMu and the same monotonic generation
// with peer-requested commits, so a local decision after PREPARE supersedes the
// reservation instead of being overwritten by a stale COMMIT.
func (e *Engine) SelectLocalTarget(selectorID, targetID proto.TargetID, cause string) error {
	return e.selectLocalTarget(selectorID, targetID, cause, policySelectionExternal)
}

// SelectPeakTransferTarget commits a local PeakTransfer phase change. The
// explicit phase is retained by the recursive selector runtime so ordinary
// quality scheduling cannot undo a healthy promotion.
func (e *Engine) SelectPeakTransferTarget(selectorID, targetID proto.TargetID, peak bool, cause string) error {
	origin := policySelectionPeakReturn
	if peak {
		origin = policySelectionPeakPromote
	}
	return e.selectLocalTarget(selectorID, targetID, cause, origin)
}

// SelectExplicitTarget applies an embedder-requested logical target change and
// replays the frozen unacknowledged prefix on the new route before later
// publications can overtake it. Scheduler and peer-policy selections use
// SelectLocalTarget because a healthy former route can finish its own prefix.
func (e *Engine) SelectExplicitTarget(selectorID, targetID proto.TargetID, cause string) error {
	return e.selectLocalTarget(selectorID, targetID, cause, policySelectionExplicit)
}

func (e *Engine) selectLocalTarget(selectorID, targetID proto.TargetID, cause string, origin policySelectionOrigin) error {
	return e.selectLocalTargetCommitted(selectorID, targetID, cause, origin, nil)
}

func (e *Engine) selectLocalTargetCommitted(
	selectorID, targetID proto.TargetID,
	cause string,
	origin policySelectionOrigin,
	afterCommit func(),
) error {
	return e.selectLocalTargetCommittedAtTopology(
		selectorID, targetID, cause, origin, 0, afterCommit,
	)
}

func (e *Engine) selectLocalTargetCommittedAtTopology(
	selectorID, targetID proto.TargetID,
	cause string,
	origin policySelectionOrigin,
	expectedTopologyEpoch uint64,
	afterCommit func(),
) error {
	return e.selectLocalTargetCommittedAtEvidence(
		selectorID, targetID, cause, origin,
		selectorEvidenceCommit{topologyEpoch: expectedTopologyEpoch}, afterCommit,
	)
}

func (e *Engine) selectLocalTargetCommittedAtEvidence(
	selectorID, targetID proto.TargetID,
	cause string,
	origin policySelectionOrigin,
	expectedEvidence selectorEvidenceCommit,
	afterCommit func(),
) error {
	e.policyCutoverMu.Lock()
	defer e.policyCutoverMu.Unlock()
	e.policyOwnerMu.Lock()
	ownerHeld := true
	releaseOwner := func() {
		if ownerHeld {
			ownerHeld = false
			e.policyOwnerMu.Unlock()
		}
	}
	defer releaseOwner()
	if e.sendClosing.Load() || e.isClosed() {
		return net.ErrClosed
	}
	binding := e.localGraphBinding()
	if err := validatePolicySelection(binding.manifest, selectorID, targetID); err != nil {
		return err
	}
	if e.policySelectionHeldByLeafMobility(selectorID, targetID, origin) {
		return errPolicySelectionLeafMobilityHeld
	}
	cutoverGeneration := uint64(0)
	requiresCutover := origin.requiresSelectorCutover()
	if requiresCutover && origin == policySelectionExplicit {
		runtime := e.localExecutionRuntime()
		e.pathsMu.RLock()
		attached := e.attachedLeafTargetsLocked()
		e.pathsMu.RUnlock()
		requiresCutover = runtime != nil && runtime.selectorIsEffective(selectorID, attached)
	}
	if requiresCutover {
		cutoverGeneration = e.beginSelectorCutover()
		defer func() { e.finishSelectorCutoverWithReplay(cutoverGeneration) }()
	}
	e.policyStateMu.Lock()
	sameTarget := e.policySelections[selectorID] == targetID
	pendingSameSelector := e.policyIncoming != nil && e.policyIncoming.prepare.SelectorID == selectorID
	if sameTarget && !pendingSameSelector {
		e.policyStateMu.Unlock()
		// The logical target can remain selected while its former physical
		// incarnation dies and later reattaches with a new path ID. Re-project
		// the same selection against current attachments so explicit migration
		// and G5 recovery can activate that incarnation without inventing a new
		// policy generation. If the physical projection is unchanged,
		// commitRecursiveSelection remains a true no-op.
		if err := e.applyPolicySelectionFromGraphOriginCommittedEvidence(
			binding, selectorID, targetID, cause, origin, cutoverGeneration,
			expectedEvidence, nil,
		); err != nil {
			return err
		}
		if afterCommit != nil {
			afterCommit()
		}
		e.observePeakPolicy(selectorID, targetID, origin, cause)
		return nil
	}
	if e.policyGeneration == ^uint64(0) {
		e.policyStateMu.Unlock()
		return fmt.Errorf("engine: policy generation space exhausted")
	}
	base := e.policyGeneration
	e.policyStateMu.Unlock()
	committed := false
	commitPolicy := func(publishRoute func()) error {
		e.policyStateMu.Lock()
		if e.closing.Load() || e.sendClosing.Load() || e.isClosed() {
			e.policyStateMu.Unlock()
			return net.ErrClosed
		}
		if e.policyGeneration != base {
			e.policyStateMu.Unlock()
			panic("engine: policy generation changed while owner lock was held")
		}
		e.policyGeneration = base + 1
		e.policySelections[selectorID] = targetID
		publishRoute()
		e.policyObservationGen.Store(base + 1)
		committed = true
		e.policyStateMu.Unlock()
		releaseOwner()
		return nil
	}
	err := e.applyPolicySelectionFromGraphOriginCommittedEvidence(
		binding, selectorID, targetID, cause, origin, cutoverGeneration,
		expectedEvidence, commitPolicy,
	)
	if err != nil {
		if committed {
			if afterCommit != nil {
				afterCommit()
			}
			// The recursive route and policy generation are already factual at
			// this point. Replay failure makes the call outcome unsafe to report as
			// success, but suppressing the observer would leave the policy owner
			// permanently projecting the pre-commit target.
			e.observePeakPolicy(selectorID, targetID, origin, cause)
			return fmt.Errorf("%w: committed policy replay: %v", ErrPolicyOutcomeUnknown, err)
		}
		return err
	}
	if !committed {
		return fmt.Errorf("engine: selector target returned without committing policy generation")
	}
	if afterCommit != nil {
		afterCommit()
	}
	e.observePeakPolicy(selectorID, targetID, origin, cause)
	return nil
}

func (e *Engine) applyPolicySelectionFromGraph(binding graphBinding, selectorID, targetID proto.TargetID, cause string) error {
	return e.applyPolicySelectionFromGraphOrigin(binding, selectorID, targetID, cause, policySelectionExternal, 0)
}

func (e *Engine) applyPolicySelectionFromGraphOrigin(
	binding graphBinding,
	selectorID, targetID proto.TargetID,
	cause string,
	origin policySelectionOrigin,
	cutoverGeneration uint64,
) error {
	return e.applyPolicySelectionFromGraphOriginCommitted(
		binding, selectorID, targetID, cause, origin, cutoverGeneration, 0, nil,
	)
}

func (e *Engine) applyPolicySelectionFromGraphOriginCommitted(
	binding graphBinding,
	selectorID, targetID proto.TargetID,
	cause string,
	origin policySelectionOrigin,
	cutoverGeneration uint64,
	expectedTopologyEpoch uint64,
	committed func(publishRoute func()) error,
) error {
	return e.applyPolicySelectionFromGraphOriginCommittedEvidence(
		binding, selectorID, targetID, cause, origin, cutoverGeneration,
		selectorEvidenceCommit{topologyEpoch: expectedTopologyEpoch}, committed,
	)
}

func (e *Engine) applyPolicySelectionFromGraphOriginCommittedEvidence(
	binding graphBinding,
	selectorID, targetID proto.TargetID,
	cause string,
	origin policySelectionOrigin,
	cutoverGeneration uint64,
	expectedEvidence selectorEvidenceCommit,
	committed func(publishRoute func()) error,
) error {
	if !binding.configured {
		return fmt.Errorf("engine: local graph is not configured")
	}
	if err := validatePolicySelection(binding.manifest, selectorID, targetID); err != nil {
		return err
	}
	runtime := e.localExecutionRuntime()
	if runtime == nil || runtime.plan == nil {
		return fmt.Errorf("engine: local execution runtime is not configured")
	}
	if err := runtime.plan.validateImmediateChild(selectorID, targetID); err != nil {
		return err
	}
	if e.policySelectionHeldByLeafMobility(selectorID, targetID, origin) {
		return errPolicySelectionLeafMobilityHeld
	}
	return e.commitRecursiveSelection(
		cause, runtime, selectorID, targetID, origin, cutoverGeneration,
		expectedEvidence, committed,
	)
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

func newPolicyReservationID() (proto.PolicyReservationID, error) {
	var id proto.PolicyReservationID
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("engine: generate policy reservation id: %w", err)
	}
	if id == (proto.PolicyReservationID{}) {
		id[0] = 1
	}
	return id, nil
}

func newPolicyCommitChallenge() (proto.PolicyCommitChallenge, error) {
	return readPolicyCommitChallenge(rand.Reader)
}

func readPolicyCommitChallenge(reader io.Reader) (proto.PolicyCommitChallenge, error) {
	var challenge proto.PolicyCommitChallenge
	if reader == nil {
		return challenge, errors.New("engine: policy commit challenge entropy source is nil")
	}
	if _, err := io.ReadFull(reader, challenge[:]); err != nil {
		return challenge, fmt.Errorf("engine: generate policy commit challenge: %w", err)
	}
	if challenge == (proto.PolicyCommitChallenge{}) {
		return challenge, errors.New("engine: policy commit challenge entropy was all zero")
	}
	return challenge, nil
}

func (e *Engine) policyProtocolError(err error) error {
	if err == nil {
		return nil
	}
	wrapped := fmt.Errorf("%w: %v", ErrPeerProtocol, err)
	e.setCloseErr(wrapped)
	go e.Close()
	return wrapped
}
