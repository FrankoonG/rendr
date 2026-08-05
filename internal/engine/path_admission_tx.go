package engine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const (
	pathAdmissionRetryInterval = 200 * time.Millisecond
	pathAdmissionTimeout       = 10 * time.Second
)

type ClientHelloAdmission struct {
	Ack    proto.HelloAckPayload
	PathID uint32
}

type ClientBridgeAdmission struct {
	Ack    proto.BridgeAckPayload
	PathID uint32
}

func PerformClientHelloAdmissionContext(
	ctx context.Context,
	pc transport.PathConn,
	e *Engine,
	instanceID proto.InstanceID,
	caps uint32,
	name string,
	spec transport.PathSpec,
) (ClientHelloAdmission, error) {
	ctx, cancel := boundedAdmissionContext(ctx)
	defer cancel()
	if pc == nil || e == nil {
		return ClientHelloAdmission{}, errors.New("engine: nil hello admission participant")
	}
	localTargetID, err := e.LocalPathTargetID(name)
	if err != nil {
		return ClientHelloAdmission{}, err
	}
	hello := proto.HelloPayload{
		Negotiation:     e.LocalNegotiation(),
		FlowID:          e.FlowID(),
		InstanceID:      instanceID,
		Caps:            caps,
		InitialTargetID: localTargetID,
		LocalTXManifest: e.LocalGraphManifest(),
	}
	proposalWire, err := hello.Encode()
	if err != nil {
		return ClientHelloAdmission{}, err
	}
	responseWire, err := sendProposalReadResponse(ctx, pc, proto.CtrlHello, proposalWire, proto.CtrlHelloAck)
	if err != nil {
		return ClientHelloAdmission{}, err
	}
	ack, err := proto.DecodeHelloAck(responseWire)
	if err != nil {
		return ClientHelloAdmission{}, err
	}
	if err := validateClientHelloAck(e, hello, ack); err != nil {
		return ClientHelloAdmission{}, err
	}
	if peerPacket := ack.Caps&proto.CapsPacketMode != 0; peerPacket != (caps&proto.CapsPacketMode != 0) {
		return ClientHelloAdmission{}, fmt.Errorf("engine: peer session kind mismatch: packet=%t", peerPacket)
	}
	if err := e.AcceptPeerNegotiation(ack.Negotiation, ack.LocalTXManifest); err != nil {
		return ClientHelloAdmission{}, err
	}
	pathID, err := e.PreparePathBound(pc, spec, PathBinding{
		LocalTXTargetID: localTargetID,
		PeerTXTargetID:  ack.InitialTargetID,
	})
	if err != nil {
		return ClientHelloAdmission{}, err
	}
	success := false
	commitSent := false
	defer func() {
		if success {
			return
		}
		if commitSent {
			e.setCloseErr(ErrPathAdmissionOutcomeUnknown)
			_ = e.Close()
			return
		}
		e.AbortPathAttach(pathID, nil)
	}()
	commit, err := readAndBindPrepared(ctx, pc, e, pathID, proto.PathAdmissionKindHello,
		hello.SessionEpoch, proto.PathAdmissionID(hello.FlowID), senderDirection(SideClient),
		hello.GraphRevision, hello.GraphDigest, hello.InitialTargetID, ack.InitialTargetID,
		proposalWire, responseWire, proto.CtrlHello, proto.CtrlHelloAck)
	if err != nil {
		return ClientHelloAdmission{}, err
	}
	if err := e.StagePathAttach(pathID); err != nil {
		return ClientHelloAdmission{}, err
	}
	commitSent = true
	if err := performClientAdmission(e, pathID, commit); err != nil {
		return ClientHelloAdmission{}, pathAdmissionOutcomeUnknown(err)
	}
	success = true
	return ClientHelloAdmission{Ack: ack, PathID: pathID}, nil
}

func PerformClientBridgeAdmissionContext(
	ctx context.Context,
	pc transport.PathConn,
	e *Engine,
	name string,
	spec transport.PathSpec,
) (ClientBridgeAdmission, error) {
	ctx, cancel := boundedAdmissionContext(ctx)
	defer cancel()
	if pc == nil || e == nil {
		return ClientBridgeAdmission{}, errors.New("engine: nil bridge admission participant")
	}
	localTargetID, err := e.LocalPathTargetID(name)
	if err != nil {
		return ClientBridgeAdmission{}, err
	}
	tag := newBridgeTagPayload(e, localTargetID)
	proposalWire := tag.Encode()
	responseWire, err := sendProposalReadResponse(ctx, pc, proto.CtrlBridgeTag, proposalWire, proto.CtrlBridgeAck)
	if err != nil {
		return ClientBridgeAdmission{}, err
	}
	ack, err := proto.DecodeBridgeAck(responseWire)
	if err != nil {
		return ClientBridgeAdmission{}, err
	}
	if err := validateClientBridgeAck(e, tag, ack); err != nil {
		return ClientBridgeAdmission{}, err
	}
	pathID, err := e.PreparePathBound(pc, spec, PathBinding{
		LocalTXTargetID: localTargetID,
		PeerTXTargetID:  ack.ResponderTargetID,
	})
	if err != nil {
		return ClientBridgeAdmission{}, err
	}
	success := false
	commitSent := false
	defer func() {
		if success {
			return
		}
		if commitSent {
			e.setCloseErr(ErrPathAdmissionOutcomeUnknown)
			_ = e.Close()
			return
		}
		e.AbortPathAttach(pathID, nil)
	}()
	commit, err := readAndBindPrepared(ctx, pc, e, pathID, proto.PathAdmissionKindBridge,
		tag.SessionEpoch, proto.PathAdmissionID(tag.AttachID), tag.Direction,
		tag.GraphRevision, tag.GraphDigest, tag.TargetID, ack.ResponderTargetID,
		proposalWire, responseWire, proto.CtrlBridgeTag, proto.CtrlBridgeAck)
	if err != nil {
		return ClientBridgeAdmission{}, err
	}
	if err := e.StagePathAttach(pathID); err != nil {
		return ClientBridgeAdmission{}, err
	}
	commitSent = true
	if err := performClientAdmission(e, pathID, commit); err != nil {
		return ClientBridgeAdmission{}, pathAdmissionOutcomeUnknown(err)
	}
	success = true
	return ClientBridgeAdmission{Ack: ack, PathID: pathID}, nil
}

func PerformServerHelloAdmission(
	ctx context.Context,
	pc transport.PathConn,
	e *Engine,
	pathID uint32,
	instanceID proto.InstanceID,
	caps uint32,
	localTargetID, peerTargetID proto.TargetID,
	hello proto.HelloPayload,
	proposalWire []byte,
) error {
	ack := proto.HelloAckPayload{
		Negotiation:          e.LocalNegotiation(),
		FlowID:               e.FlowID(),
		InstanceID:           instanceID,
		Caps:                 caps,
		InitialTargetID:      localTargetID,
		AcceptedPeerBinding:  proto.GraphBinding{Revision: hello.GraphRevision, Digest: hello.GraphDigest},
		AcceptedPeerTargetID: peerTargetID,
		LocalTXManifest:      e.LocalGraphManifest(),
	}
	responseWire, err := ack.Encode()
	if err != nil {
		return err
	}
	return performServerAdmission(ctx, pc, e, pathID, proto.PathAdmissionKindHello,
		hello.SessionEpoch, proto.PathAdmissionID(hello.FlowID), senderDirection(SideClient),
		hello.GraphRevision, hello.GraphDigest, hello.InitialTargetID, localTargetID,
		proto.CtrlHello, proposalWire, proto.CtrlHelloAck, responseWire)
}

func PerformServerBridgeAdmission(
	ctx context.Context,
	pc transport.PathConn,
	e *Engine,
	pathID uint32,
	instanceID proto.InstanceID,
	localTargetID proto.TargetID,
	tag proto.BridgeTagPayload,
	proposalWire []byte,
) error {
	ack := proto.BridgeAckPayload{
		BridgeID:          tag.BridgeID,
		AttachID:          tag.AttachID,
		InstanceID:        instanceID,
		SessionEpoch:      tag.SessionEpoch,
		Direction:         tag.Direction,
		GraphRevision:     tag.GraphRevision,
		GraphDigest:       tag.GraphDigest,
		TargetID:          tag.TargetID,
		ResponderTargetID: localTargetID,
		Code:              proto.AckOK,
	}
	responseWire := ack.Encode()
	return performServerAdmission(ctx, pc, e, pathID, proto.PathAdmissionKindBridge,
		tag.SessionEpoch, proto.PathAdmissionID(tag.AttachID), tag.Direction,
		tag.GraphRevision, tag.GraphDigest, tag.TargetID, localTargetID,
		proto.CtrlBridgeTag, proposalWire, proto.CtrlBridgeAck, responseWire)
}

func performClientAdmission(e *Engine, pathID uint32, commit proto.PathAdmissionCommit) error {
	ctx, cancel := context.WithTimeout(context.Background(), e.limits.MigrationBudget)
	defer cancel()
	commitWire, err := commit.Encode()
	if err != nil {
		return err
	}
	if err := e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionCommit, commitWire); err != nil {
		return err
	}
	if err := waitForAdmissionAck(ctx, e, pathID, commit, proto.PathAdmissionPhaseCommitted, func() error {
		return e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionCommit, commitWire)
	}); err != nil {
		return err
	}
	confirm := proto.PathAdmissionConfirm{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		CommittedGeneration:  commit.BaseLeafGeneration + 1,
	}
	confirmWire, err := confirm.Encode()
	if err != nil {
		return err
	}
	if err := e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionConfirm, confirmWire); err != nil {
		return err
	}
	if err := waitForAdmissionAck(ctx, e, pathID, commit, proto.PathAdmissionPhaseFinal, func() error {
		return e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionConfirm, confirmWire)
	}); err != nil {
		return err
	}
	if err := e.activateStagedPathContext(ctx, pathID, true, true); err != nil {
		return err
	}
	// Sending FINAL receipt can make the responder activate. From this point
	// the predecessor is not a safe unilateral rollback target.
	if err := e.DisablePathAdmissionRollback(pathID); err != nil {
		return err
	}
	receipt := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseFinal,
		Code:                 proto.AckOK,
	}
	receiptWire, err := receipt.Encode()
	if err != nil {
		return err
	}
	if err := e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, receiptWire); err != nil {
		return err
	}
	if err := waitForAdmissionAck(ctx, e, pathID, commit, proto.PathAdmissionPhaseActivated, func() error {
		return e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, receiptWire)
	}); err != nil {
		return err
	}
	activatedReceipt := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseActivated,
		Code:                 proto.AckOK,
	}
	activatedReceiptWire, err := activatedReceipt.Encode()
	if err != nil {
		return err
	}
	// Install replay state before releasing the live reservation. If the first
	// terminal receipt is lost, duplicate ACTIVATED messages are answered by
	// the bounded completed-admission path.
	if err := e.rememberCompletedPathAdmission(pathID, commit.PathAdmissionBinding, proto.PathAdmissionPhaseActivated, activatedReceiptWire); err != nil {
		return err
	}
	if err := e.CompletePathAdmissionBinding(pathID, commit.PathAdmissionBinding); err != nil {
		return err
	}
	return e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, activatedReceiptWire)
}

func performServerAdmission(
	ctx context.Context,
	pc transport.PathConn,
	e *Engine,
	pathID uint32,
	kind proto.PathAdmissionKind,
	epoch proto.SessionEpoch,
	admissionID proto.PathAdmissionID,
	direction proto.SenderDirection,
	revision uint64,
	graphDigest proto.GraphDigest,
	initiatorTargetID, responderTargetID proto.TargetID,
	proposalCode proto.CtrlCode,
	proposalWire []byte,
	responseCode proto.CtrlCode,
	responseWire []byte,
) (retErr error) {
	ctx, cancel := boundedAdmissionContext(ctx)
	defer cancel()
	postCommit := false
	completed := false
	defer func() {
		if retErr == nil || !postCommit || completed {
			return
		}
		e.setCloseErr(ErrPathAdmissionOutcomeUnknown)
		_ = e.Close()
		retErr = pathAdmissionOutcomeUnknown(retErr)
	}()
	base, err := e.PathAdmissionBaseGeneration(pathID)
	if err != nil {
		return err
	}
	commit := admissionCommit(kind, epoch, admissionID, direction, revision, graphDigest,
		initiatorTargetID, responderTargetID, base, proposalWire, responseWire)
	if err := e.BindPathAdmission(pathID, commit.PathAdmissionBinding); err != nil {
		return err
	}
	prepared := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhasePrepared,
		Code:                 proto.AckOK,
	}
	preparedWire, err := prepared.Encode()
	if err != nil {
		return err
	}
	writePrepared := func() error {
		if err := writeAdmissionCtrlContext(ctx, pc, responseCode, responseWire); err != nil {
			return err
		}
		return writeAdmissionCtrlContext(ctx, pc, proto.CtrlPathAdmissionAck, preparedWire)
	}
	if err := writePrepared(); err != nil {
		return err
	}
	commitWire, err := waitRawCommit(ctx, pc, proposalCode, proposalWire, writePrepared, commit)
	if err != nil {
		return err
	}
	postCommit = true
	if err := e.StagePathAttach(pathID); err != nil {
		return err
	}
	postCommitCtx, postCommitCancel := context.WithTimeout(context.Background(), e.limits.MigrationBudget)
	defer postCommitCancel()
	committed := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseCommitted,
		Code:                 proto.AckOK,
	}
	committedWire, err := committed.Encode()
	if err != nil {
		return err
	}
	if err := e.WritePathAdmissionControlContext(postCommitCtx, pathID, proto.CtrlPathAdmissionAck, committedWire); err != nil {
		return err
	}
	confirm, confirmWire, err := waitForAdmissionConfirm(postCommitCtx, e, pathID, commit, commitWire, committedWire)
	if err != nil {
		e.setCloseErr(ErrPathAdmissionOutcomeUnknown)
		_ = e.Close()
		return err
	}
	finalAck := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseFinal,
		Code:                 proto.AckOK,
	}
	finalWire, err := finalAck.Encode()
	if err != nil {
		return err
	}
	if err := e.WritePathAdmissionControlContext(postCommitCtx, pathID, proto.CtrlPathAdmissionAck, finalWire); err != nil {
		return err
	}
	if err := waitForFinalReceipt(postCommitCtx, e, pathID, commit, confirm, confirmWire, finalWire); err != nil {
		e.setCloseErr(ErrPathAdmissionOutcomeUnknown)
		_ = e.Close()
		return err
	}
	if err := e.activateStagedPathContext(postCommitCtx, pathID, true, false); err != nil {
		return err
	}
	activated := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseActivated,
		Code:                 proto.AckOK,
	}
	activatedWire, err := activated.Encode()
	if err != nil {
		return err
	}
	if err := e.WritePathAdmissionControlContext(postCommitCtx, pathID, proto.CtrlPathAdmissionAck, activatedWire); err != nil {
		return err
	}
	if err := waitForActivatedReceipt(postCommitCtx, e, pathID, commit, finalWire, activatedWire); err != nil {
		return err
	}
	if err := e.CompletePathAdmissionBinding(pathID, commit.PathAdmissionBinding); err != nil {
		return err
	}
	completed = true
	return nil
}

func readAndBindPrepared(
	ctx context.Context,
	pc transport.PathConn,
	e *Engine,
	pathID uint32,
	kind proto.PathAdmissionKind,
	epoch proto.SessionEpoch,
	admissionID proto.PathAdmissionID,
	direction proto.SenderDirection,
	revision uint64,
	graphDigest proto.GraphDigest,
	initiatorTargetID, responderTargetID proto.TargetID,
	proposalWire, responseWire []byte,
	proposalCode, responseCode proto.CtrlCode,
) (proto.PathAdmissionCommit, error) {
	resend := func() error { return writeAdmissionCtrlContext(ctx, pc, proposalCode, proposalWire) }
	for {
		hdr, payload, err := readRawAdmission(ctx, pc, resend)
		if err != nil {
			return proto.PathAdmissionCommit{}, err
		}
		code := proto.CtrlCodeFromFlags(hdr.Flags)
		if err := validateAdmissionHeader(hdr, code); err != nil {
			return proto.PathAdmissionCommit{}, err
		}
		if code == proto.CtrlBye {
			return proto.PathAdmissionCommit{}, admissionByeError(payload)
		}
		if code == responseCode {
			if !equalBytes(payload, responseWire) {
				return proto.PathAdmissionCommit{}, fmt.Errorf("engine: mutated duplicate prepared response")
			}
			continue
		}
		if code != proto.CtrlPathAdmissionAck {
			continue
		}
		prepared, err := proto.DecodePathAdmissionAck(payload)
		if err != nil {
			return proto.PathAdmissionCommit{}, err
		}
		if prepared.Phase != proto.PathAdmissionPhasePrepared || !prepared.Code.OK() {
			return proto.PathAdmissionCommit{}, fmt.Errorf("engine: invalid path admission PREPARED")
		}
		expected := admissionCommit(kind, epoch, admissionID, direction, revision, graphDigest,
			initiatorTargetID, responderTargetID, prepared.BaseLeafGeneration, proposalWire, responseWire)
		if err := prepared.ValidateForCommit(expected); err != nil {
			return proto.PathAdmissionCommit{}, err
		}
		if err := e.AdoptPathAdmissionBase(pathID, prepared.BaseLeafGeneration); err != nil {
			return proto.PathAdmissionCommit{}, err
		}
		if err := e.BindPathAdmission(pathID, expected.PathAdmissionBinding); err != nil {
			return proto.PathAdmissionCommit{}, err
		}
		return expected, nil
	}
}

func sendProposalReadResponse(ctx context.Context, pc transport.PathConn, proposalCode proto.CtrlCode, proposal []byte, responseCode proto.CtrlCode) ([]byte, error) {
	resend := func() error { return writeAdmissionCtrlContext(ctx, pc, proposalCode, proposal) }
	if err := resend(); err != nil {
		return nil, err
	}
	for {
		hdr, payload, err := readRawAdmission(ctx, pc, resend)
		if err != nil {
			return nil, err
		}
		if err := validateAdmissionHeader(hdr, proto.CtrlCodeFromFlags(hdr.Flags)); err != nil {
			return nil, err
		}
		code := proto.CtrlCodeFromFlags(hdr.Flags)
		if code == proto.CtrlBye {
			return nil, admissionByeError(payload)
		}
		if code == responseCode {
			return payload, nil
		}
	}
}

func waitRawCommit(
	ctx context.Context,
	pc transport.PathConn,
	proposalCode proto.CtrlCode,
	proposalWire []byte,
	writePrepared func() error,
	want proto.PathAdmissionCommit,
) ([]byte, error) {
	for {
		hdr, payload, err := readRawAdmission(ctx, pc, writePrepared)
		if err != nil {
			return nil, err
		}
		code := proto.CtrlCodeFromFlags(hdr.Flags)
		if err := validateAdmissionHeader(hdr, code); err != nil {
			return nil, err
		}
		if code == proposalCode {
			if !equalBytes(payload, proposalWire) {
				return nil, fmt.Errorf("engine: mutated duplicate admission proposal")
			}
			if err := writePrepared(); err != nil {
				return nil, err
			}
			continue
		}
		if code != proto.CtrlPathAdmissionCommit {
			continue
		}
		got, err := proto.DecodePathAdmissionCommit(payload)
		if err != nil {
			return nil, err
		}
		if got != want {
			return nil, fmt.Errorf("engine: path admission COMMIT identity mismatch")
		}
		return append([]byte(nil), payload...), nil
	}
}

func waitForAdmissionAck(
	ctx context.Context,
	e *Engine,
	pathID uint32,
	commit proto.PathAdmissionCommit,
	phase proto.PathAdmissionPhase,
	resend func() error,
) error {
	for {
		code, payload, err := waitStagedAdmission(ctx, e, pathID, resend)
		if err != nil {
			return err
		}
		if code != proto.CtrlPathAdmissionAck {
			continue
		}
		ack, err := proto.DecodePathAdmissionAck(payload)
		if err != nil {
			return err
		}
		if ack.Phase != phase {
			continue
		}
		if err := ack.ValidateForCommit(commit); err != nil {
			return err
		}
		if !ack.Code.OK() {
			return fmt.Errorf("engine: path admission rejected: %s: %s", ack.Code, ack.Reason)
		}
		return nil
	}
}

func waitForAdmissionConfirm(
	ctx context.Context,
	e *Engine,
	pathID uint32,
	commit proto.PathAdmissionCommit,
	commitWire, committedWire []byte,
) (proto.PathAdmissionConfirm, []byte, error) {
	for {
		code, payload, err := waitStagedAdmission(ctx, e, pathID, func() error {
			return e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, committedWire)
		})
		if err != nil {
			return proto.PathAdmissionConfirm{}, nil, err
		}
		switch code {
		case proto.CtrlPathAdmissionCommit:
			if !equalBytes(payload, commitWire) {
				return proto.PathAdmissionConfirm{}, nil, fmt.Errorf("engine: mutated duplicate path admission COMMIT")
			}
			if err := e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, committedWire); err != nil {
				return proto.PathAdmissionConfirm{}, nil, err
			}
		case proto.CtrlPathAdmissionConfirm:
			confirm, err := proto.DecodePathAdmissionConfirm(payload)
			if err != nil {
				return proto.PathAdmissionConfirm{}, nil, err
			}
			if err := confirm.ValidateForCommit(commit); err != nil {
				return proto.PathAdmissionConfirm{}, nil, err
			}
			return confirm, append([]byte(nil), payload...), nil
		}
	}
}

func waitForFinalReceipt(
	ctx context.Context,
	e *Engine,
	pathID uint32,
	commit proto.PathAdmissionCommit,
	confirm proto.PathAdmissionConfirm,
	confirmWire, finalWire []byte,
) error {
	for {
		code, payload, err := waitStagedAdmission(ctx, e, pathID, func() error {
			return e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, finalWire)
		})
		if err != nil {
			return err
		}
		switch code {
		case proto.CtrlPathAdmissionConfirm:
			got, err := proto.DecodePathAdmissionConfirm(payload)
			if err != nil || got != confirm || !equalBytes(payload, confirmWire) {
				continue
			}
			if err := e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, finalWire); err != nil {
				return err
			}
		case proto.CtrlPathAdmissionAck:
			receipt, err := proto.DecodePathAdmissionAck(payload)
			if err != nil {
				return err
			}
			if receipt.Phase != proto.PathAdmissionPhaseFinal {
				continue
			}
			if err := receipt.ValidateForCommit(commit); err != nil || !receipt.Code.OK() {
				if err != nil {
					return err
				}
				return fmt.Errorf("engine: path admission receipt rejected")
			}
			return nil
		}
	}
}

func waitForActivatedReceipt(
	ctx context.Context,
	e *Engine,
	pathID uint32,
	commit proto.PathAdmissionCommit,
	finalReceiptWire, activatedWire []byte,
) error {
	for {
		code, payload, err := waitStagedAdmission(ctx, e, pathID, func() error {
			return e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, activatedWire)
		})
		if err != nil {
			return err
		}
		if code != proto.CtrlPathAdmissionAck {
			continue
		}
		receipt, err := proto.DecodePathAdmissionAck(payload)
		if err != nil {
			return err
		}
		if receipt.Phase == proto.PathAdmissionPhaseFinal {
			if !equalBytes(payload, finalReceiptWire) || receipt.ValidateForCommit(commit) != nil || !receipt.Code.OK() {
				return fmt.Errorf("engine: invalid duplicate FINAL receipt")
			}
			if err := e.WritePathAdmissionControlContext(ctx, pathID, proto.CtrlPathAdmissionAck, activatedWire); err != nil {
				return err
			}
			continue
		}
		if receipt.Phase != proto.PathAdmissionPhaseActivated {
			continue
		}
		if err := receipt.ValidateForCommit(commit); err != nil {
			return err
		}
		if !receipt.Code.OK() {
			return fmt.Errorf("engine: path admission ACTIVATED receipt rejected")
		}
		return nil
	}
}

func admissionCommit(
	kind proto.PathAdmissionKind,
	epoch proto.SessionEpoch,
	id proto.PathAdmissionID,
	direction proto.SenderDirection,
	revision uint64,
	graphDigest proto.GraphDigest,
	initiatorTargetID, responderTargetID proto.TargetID,
	base uint64,
	proposalWire, responseWire []byte,
) proto.PathAdmissionCommit {
	proposalHash := sha256.Sum256(proposalWire)
	responseHash := sha256.Sum256(responseWire)
	return proto.PathAdmissionCommit{
		PathAdmissionBinding: proto.PathAdmissionBinding{
			Kind:                   kind,
			Direction:              direction,
			SessionEpoch:           epoch,
			AdmissionID:            id,
			InitiatorGraphRevision: revision,
			InitiatorGraphDigest:   graphDigest,
			InitiatorTargetID:      initiatorTargetID,
			ResponderTargetID:      responderTargetID,
			BaseLeafGeneration:     base,
			ProposalDigest:         proto.PathAdmissionProposalDigest(proposalHash),
			ResponderPlanDigest:    proto.PathAdmissionPlanDigest(responseHash),
		},
		Phase: proto.PathAdmissionPhaseCommit,
	}
}

func validateClientHelloAck(e *Engine, hello proto.HelloPayload, ack proto.HelloAckPayload) error {
	if ack.FlowID != hello.FlowID {
		return fmt.Errorf("engine: HELLO_ACK flow mismatch")
	}
	local := e.localGraphBinding()
	if ack.AcceptedPeerBinding.Revision != local.revision || ack.AcceptedPeerBinding.Digest != local.digest {
		return fmt.Errorf("engine: HELLO_ACK did not accept local graph binding")
	}
	if ack.AcceptedPeerTargetID != hello.InitialTargetID {
		return fmt.Errorf("engine: HELLO_ACK accepted a different local target")
	}
	return nil
}

func validateClientBridgeAck(e *Engine, tag proto.BridgeTagPayload, ack proto.BridgeAckPayload) error {
	if ack.BridgeID != e.FlowID() || ack.InstanceID != e.PeerInstanceID() {
		return fmt.Errorf("engine: BRIDGE_ACK session or instance mismatch")
	}
	if ack.SessionEpoch != tag.SessionEpoch || ack.GraphRevision != tag.GraphRevision ||
		ack.GraphDigest != tag.GraphDigest || ack.TargetID != tag.TargetID ||
		ack.AttachID != tag.AttachID || ack.Direction != tag.Direction {
		return fmt.Errorf("engine: BRIDGE_ACK binding mismatch")
	}
	if !ack.Code.OK() {
		return fmt.Errorf("engine: bridge rejected: %s: %s", ack.Code, ack.Reason)
	}
	if _, err := e.PeerPathName(ack.ResponderTargetID); err != nil {
		return fmt.Errorf("engine: BRIDGE_ACK responder target: %w", err)
	}
	return nil
}

type rawAdmissionResult struct {
	hdr     proto.Header
	payload []byte
	err     error
}

func writeAdmissionCtrlContext(ctx context.Context, pc transport.PathConn, code proto.CtrlCode, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	result := make(chan error, 1)
	go func() {
		result <- writeCtrl(pc, code, 0, payload, 0)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		select {
		case err := <-result:
			return err
		default:
		}
		go func() { _ = pc.Close() }()
		return ctx.Err()
	}
}

func readRawAdmission(ctx context.Context, pc transport.PathConn, resend func() error) (proto.Header, []byte, error) {
	result := make(chan rawAdmissionResult, 1)
	go func() {
		hdr, payload, err := ReadFirstFrame(pc)
		result <- rawAdmissionResult{hdr: hdr, payload: payload, err: err}
	}()
	ticker := time.NewTicker(pathAdmissionRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case got := <-result:
			return got.hdr, got.payload, got.err
		case <-ticker.C:
			if resend != nil {
				if err := resend(); err != nil {
					_ = pc.Close()
					return proto.Header{}, nil, err
				}
			}
		case <-ctx.Done():
			_ = pc.Close()
			return proto.Header{}, nil, ctx.Err()
		}
	}
}

func waitStagedAdmission(ctx context.Context, e *Engine, pathID uint32, resend func() error) (proto.CtrlCode, []byte, error) {
	for {
		attempt, cancel := context.WithTimeout(ctx, pathAdmissionRetryInterval)
		code, payload, err := e.WaitPathAdmissionControl(attempt, pathID)
		cancel()
		if err == nil {
			return code, payload, nil
		}
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return 0, nil, err
		}
		if resend != nil {
			if err := resend(); err != nil {
				return 0, nil, err
			}
		}
	}
}

func boundedAdmissionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pathAdmissionTimeout)
}

func validateAdmissionHeader(hdr proto.Header, code proto.CtrlCode) error {
	if hdr.Version != proto.Version || hdr.Type != proto.FrameCtrl || hdr.Last || hdr.Seq != 0 ||
		hdr.Flags != proto.FlagsForCtrl(code) {
		return fmt.Errorf("engine: non-canonical admission control header")
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func pathAdmissionOutcomeUnknown(err error) error {
	if err == nil {
		return ErrPathAdmissionOutcomeUnknown
	}
	if errors.Is(err, ErrPathAdmissionOutcomeUnknown) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrPathAdmissionOutcomeUnknown, err)
}

func admissionByeError(payload []byte) error {
	bye, err := proto.DecodeBye(payload)
	if err != nil {
		return fmt.Errorf("%w: malformed BYE: %v", ErrPeerProtocol, err)
	}
	if bye.Reason == proto.ByeProtoVer {
		return ErrPeerProtoVersion
	}
	return fmt.Errorf("%w: %d", ErrPeerClosed, bye.Reason)
}
