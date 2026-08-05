package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const pathAdmissionInboxSize = 16

type pathAdmissionMessage struct {
	Code    proto.CtrlCode
	Payload []byte
	Source  PathRef
}

func isPathAdmissionCtrl(code proto.CtrlCode) bool {
	return code == proto.CtrlPathAdmissionCommit ||
		code == proto.CtrlPathAdmissionAck ||
		code == proto.CtrlPathAdmissionConfirm
}

func isPathAdmissionHandshakeCtrl(code proto.CtrlCode) bool {
	return code == proto.CtrlHello || code == proto.CtrlHelloAck ||
		code == proto.CtrlBridgeTag || code == proto.CtrlBridgeAck
}

func (e *Engine) routePathAdmissionControl(slot *pathSlot, code proto.CtrlCode, payload []byte) bool {
	if !isPathAdmissionCtrl(code) && !isPathAdmissionHandshakeCtrl(code) {
		return false
	}
	if isPathAdmissionCtrl(code) {
		if err := validatePathAdmissionControl(code, payload); err != nil {
			e.setCloseErr(fmt.Errorf("%w: malformed %s: %v", ErrPeerProtocol, code, err))
			go e.Close()
			return true
		}
	}
	if isPathAdmissionHandshakeCtrl(code) {
		e.pathsMu.RLock()
		_, live := e.pathAdmissionByPath[slot.id]
		e.pathsMu.RUnlock()
		if live {
			e.enqueuePathAdmissionMessage(slot, PathRef{ID: slot.id, Owner: slot.owner}, code, payload)
		}
		return true
	}
	binding, err := pathAdmissionControlBinding(code, payload)
	if err != nil {
		return true
	}
	incomingKey, incomingBound := pathAdmissionKey(e.side, PathBinding{
		LocalTXTargetID: slot.localTXTargetID,
		PeerTXTargetID:  slot.peerTXTargetID,
	})
	var (
		replay         *completedPathAdmission
		replayResponse []byte
		replayExpires  time.Time
		promotion      completedPathAdmissionPromotion
	)
	source := PathRef{ID: slot.id, Owner: slot.owner}
	e.pathsMu.Lock()
	key, _, target, live := e.pathAdmissionRouteLocked(binding)
	if live && incomingBound && incomingKey == key {
		e.pathsMu.Unlock()
		e.enqueuePathAdmissionMessage(target, PathRef{ID: slot.id, Owner: slot.owner}, code, payload)
		return true
	}
	if entry := e.completedPathAdmissions[binding]; entry != nil {
		if !nowFn().Before(entry.expires) {
			delete(e.completedPathAdmissions, binding)
		} else if incomingBound && incomingKey == entry.key && code == proto.CtrlPathAdmissionAck {
			receipt, decodeErr := proto.DecodePathAdmissionAck(payload)
			if decodeErr == nil && receipt.Phase == entry.requestPhase && receipt.Code.OK() &&
				receipt.PathAdmissionBinding == entry.binding && !entry.replayPending {
				if committed, accepted := e.promoteCompletedPathAdmissionRouteLocked(entry, source); accepted {
					entry.replayPending = true
					replay = entry
					replayResponse = append([]byte(nil), entry.response...)
					replayExpires = entry.expires
					promotion = committed
				}
			}
		}
	}
	e.pathsMu.Unlock()
	e.finishCompletedPathAdmissionPromotion(promotion)
	if replay != nil {
		go func() {
			defer e.finishCompletedPathAdmissionReplay(binding, replay)
			ctx, cancel := context.WithDeadline(context.Background(), replayExpires)
			defer cancel()
			_ = e.WritePathAdmissionControlContext(ctx, source.ID, proto.CtrlPathAdmissionAck, replayResponse)
		}()
	}
	// Handshake controls are always unsequenced. Once admission completes,
	// delayed copies are tombstoned by dropping them, never by feeding SEQ 0
	// into the application reorder window.
	return true
}

func pathAdmissionControlBinding(code proto.CtrlCode, payload []byte) (proto.PathAdmissionBinding, error) {
	switch code {
	case proto.CtrlPathAdmissionCommit:
		value, err := proto.DecodePathAdmissionCommit(payload)
		return value.PathAdmissionBinding, err
	case proto.CtrlPathAdmissionAck:
		value, err := proto.DecodePathAdmissionAck(payload)
		return value.PathAdmissionBinding, err
	case proto.CtrlPathAdmissionConfirm:
		value, err := proto.DecodePathAdmissionConfirm(payload)
		return value.PathAdmissionBinding, err
	default:
		return proto.PathAdmissionBinding{}, fmt.Errorf("unsupported admission control %s", code)
	}
}

func validatePathAdmissionControl(code proto.CtrlCode, payload []byte) error {
	switch code {
	case proto.CtrlPathAdmissionCommit:
		_, err := proto.DecodePathAdmissionCommit(payload)
		return err
	case proto.CtrlPathAdmissionAck:
		_, err := proto.DecodePathAdmissionAck(payload)
		return err
	case proto.CtrlPathAdmissionConfirm:
		_, err := proto.DecodePathAdmissionConfirm(payload)
		return err
	default:
		return fmt.Errorf("unsupported admission control %s", code)
	}
}

func (e *Engine) enqueuePathAdmissionMessage(slot *pathSlot, source PathRef, code proto.CtrlCode, payload []byte) {
	if slot == nil || (!isPathAdmissionCtrl(code) && !isPathAdmissionHandshakeCtrl(code)) {
		return
	}
	message := pathAdmissionMessage{Code: code, Payload: append([]byte(nil), payload...), Source: source}
	select {
	case slot.admissionInbox <- message:
	default:
		// Admission retransmissions are byte-identical and bounded by the
		// caller's retry timer. Dropping overflow is safer than allowing an
		// unauthenticated duplicate flood to stall the path reader.
	}
}

// WaitPathAdmissionControl waits for one out-of-band admission control from
// an RX-ready staged or active path. These controls never consume DATA SEQ.
func (e *Engine) WaitPathAdmissionControl(ctx context.Context, pathID uint32) (proto.CtrlCode, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.pathsMu.RLock()
	slot := e.pathSlotForAdmissionLocked(pathID)
	e.pathsMu.RUnlock()
	if slot == nil {
		return 0, nil, fmt.Errorf("engine: admission path %d is not receive-ready", pathID)
	}
	select {
	case message := <-slot.admissionInbox:
		return message.Code, message.Payload, nil
	case <-slot.quit:
		return 0, nil, net.ErrClosed
	case <-e.closed:
		return 0, nil, net.ErrClosed
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

// WaitPathAdmissionControlBinding follows a live transaction if successor
// death atomically moves it onto a retained predecessor.
func (e *Engine) WaitPathAdmissionControlBinding(ctx context.Context, binding proto.PathAdmissionBinding) (proto.CtrlCode, []byte, PathRef, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		e.pathsMu.RLock()
		_, _, slot, live := e.pathAdmissionRouteLocked(binding)
		e.pathsMu.RUnlock()
		if !live || slot == nil {
			return 0, nil, PathRef{}, net.ErrClosed
		}
		select {
		case message := <-slot.admissionInbox:
			return message.Code, message.Payload, message.Source, nil
		case <-slot.quit:
			// onPathDeath transfers the reservation under pathsMu. Resolve it
			// again instead of treating successor shutdown as transaction loss.
			continue
		case <-e.closed:
			return 0, nil, PathRef{}, net.ErrClosed
		case <-ctx.Done():
			return 0, nil, PathRef{}, ctx.Err()
		}
	}
}

// WritePathAdmissionControl serializes a handshake control with all writes on
// the selected path. It is valid for staged, active, or retained paths.
func (e *Engine) WritePathAdmissionControl(pathID uint32, code proto.CtrlCode, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), e.limits.MigrationBudget)
	defer cancel()
	return e.WritePathAdmissionControlContext(ctx, pathID, code, payload)
}

// WritePathAdmissionControlContext bounds both lock acquisition and the
// transport write. On cancellation the carrier is closed so conforming
// PathConn implementations unblock their in-flight Write.
func (e *Engine) WritePathAdmissionControlContext(ctx context.Context, pathID uint32, code proto.CtrlCode, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !isPathAdmissionCtrl(code) {
		return fmt.Errorf("engine: %s is not a path admission control", code)
	}
	e.pathsMu.RLock()
	slot := e.pathSlotForAdmissionLocked(pathID)
	e.pathsMu.RUnlock()
	if slot == nil {
		return fmt.Errorf("engine: admission path %d is unavailable", pathID)
	}
	frame, err := pathAdmissionControlFrame(code, payload)
	if err != nil {
		return err
	}
	n, err := e.writePathFrameContext(ctx, slot, frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

func (e *Engine) WritePathAdmissionControlBindingContext(ctx context.Context, binding proto.PathAdmissionBinding, code proto.CtrlCode, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !isPathAdmissionCtrl(code) {
		return fmt.Errorf("engine: %s is not a path admission control", code)
	}
	frame, err := pathAdmissionControlFrame(code, payload)
	if err != nil {
		return err
	}
	for {
		e.pathsMu.RLock()
		_, _, slot, live := e.pathAdmissionRouteLocked(binding)
		e.pathsMu.RUnlock()
		if !live || slot == nil {
			return net.ErrClosed
		}
		n, writeErr := e.writePathFrameContext(ctx, slot, frame)
		if writeErr == nil && n == len(frame) {
			return nil
		}
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.onPathDeath(slot.id, slot.owner, transport.CauseTransportError, writeErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.closed:
			return net.ErrClosed
		case <-time.After(time.Millisecond):
		}
	}
}

func pathAdmissionControlFrame(code proto.CtrlCode, payload []byte) ([]byte, error) {
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(code),
		Seq:     0,
	}).Encode(frame[:proto.HeaderSize]); err != nil {
		return nil, err
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame, nil
}

type pathAdmissionWriteResult struct {
	n   int
	err error
}

func (e *Engine) writePathFrameContext(ctx context.Context, slot *pathSlot, frame []byte) (int, error) {
	if err := slot.acquireWrite(ctx); err != nil {
		return 0, err
	}
	result := make(chan pathAdmissionWriteResult, 1)
	go func() {
		defer slot.releaseWrite()
		n, err := slot.writeFrameOwned(frame)
		result <- pathAdmissionWriteResult{n: n, err: err}
	}()
	select {
	case got := <-result:
		return got.n, got.err
	case <-ctx.Done():
		select {
		case got := <-result:
			return got.n, got.err
		default:
		}
		go e.onPathDeath(slot.id, slot.owner, transport.CauseTransportError, ctx.Err())
		return 0, ctx.Err()
	}
}

func (e *Engine) pathSlotForAdmissionLocked(pathID uint32) *pathSlot {
	if slot := e.stagedPaths[pathID]; slot != nil {
		return slot
	}
	if slot := e.paths[pathID]; slot != nil {
		return slot
	}
	return e.retainedPaths[pathID]
}
