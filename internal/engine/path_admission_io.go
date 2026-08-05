package engine

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const pathAdmissionInboxSize = 16

type pathAdmissionMessage struct {
	Code    proto.CtrlCode
	Payload []byte
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
	e.pathsMu.RLock()
	_, live := e.pathAdmissionByPath[slot.id]
	e.pathsMu.RUnlock()
	if live {
		e.enqueuePathAdmissionMessage(slot, code, payload)
		return true
	}
	if completed, ok := e.completedPathAdmission(slot.id); ok && code == proto.CtrlPathAdmissionAck {
		receipt, err := proto.DecodePathAdmissionAck(payload)
		if err == nil && receipt.Phase == completed.requestPhase && receipt.Code.OK() &&
			receipt.PathAdmissionBinding == completed.binding && slot.admissionReplayPending.CompareAndSwap(false, true) {
			go func() {
				defer slot.admissionReplayPending.Store(false)
				ctx, cancel := context.WithDeadline(context.Background(), completed.expires)
				defer cancel()
				_ = e.WritePathAdmissionControlContext(ctx, slot.id, proto.CtrlPathAdmissionAck, completed.response)
			}()
		}
	}
	// Handshake controls are always unsequenced. Once admission completes,
	// delayed copies are tombstoned by dropping them, never by feeding SEQ 0
	// into the application reorder window.
	return true
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

func (e *Engine) enqueuePathAdmissionMessage(slot *pathSlot, code proto.CtrlCode, payload []byte) {
	if slot == nil || (!isPathAdmissionCtrl(code) && !isPathAdmissionHandshakeCtrl(code)) {
		return
	}
	message := pathAdmissionMessage{Code: code, Payload: append([]byte(nil), payload...)}
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
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(code),
		Seq:     0,
	}).Encode(frame[:proto.HeaderSize]); err != nil {
		return err
	}
	copy(frame[proto.HeaderSize:], payload)
	n, err := e.writePathFrameContext(ctx, slot, frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
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
