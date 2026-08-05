package engine

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

// SendData splits buf into ≤MaxPayload frames, assigns SEQ, encodes
// them, and writes to the currently-active path. It blocks while the
// engine is in BridgeMigrating, but never returns a migration-class
// error to the caller (hard rule #1). Migration-budget exhaustion
// returns rendr.ErrMigrationBudgetExceeded.
func (e *Engine) SendData(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	sent := 0
	for sent < len(buf) {
		end := sent + MaxPayload
		if end > len(buf) {
			end = len(buf)
		}
		chunk := buf[sent:end]
		if err := e.sendFrame(proto.FrameData, 0, chunk); err != nil {
			return sent, err
		}
		sent = end
	}
	return sent, nil
}

// SendPacket emits exactly one DATA frame carrying buf as payload.
// Returns ErrPacketTooLarge if len(buf) > MaxPayload. Unlike SendData,
// this never fragments: packet-boundary semantics require the receiver
// see the same byte boundary the sender drew. Zero-length buf is
// legal and produces a zero-payload DATA frame (keepalive shape).
//
// Hard rule #1 still applies: a migration in flight blocks SendPacket
// but never surfaces a migration-class error.
func (e *Engine) SendPacket(buf []byte) error {
	if len(buf) > MaxPayload {
		return ErrPacketTooLarge
	}
	return e.sendFrame(proto.FrameData, 0, buf)
}

// SendBye emits the final sequenced frame. It shares the same sequencer as
// DATA so a concurrent successful Write is always ordered before the final
// sequence number and the receiver cannot observe an early clean EOF.
func (e *Engine) SendBye(reason proto.ByeReason) error {
	e.sendClosing.Store(true)
	e.terminalOnce.Do(func() {
		e.terminalErr = e.sendTerminalFrame(reason)
		close(e.terminalDone)
	})
	<-e.terminalDone
	return e.terminalErr
}

// sendFrame builds a single rendr frame and pushes it on the active
// path. Frame type may be Data or Ctrl; for Ctrl, flags encodes the
// CtrlCode in its low 8 bits.
func (e *Engine) sendFrame(t proto.FrameType, flags uint16, payload []byte) error {
	_, err := e.sendFrameTracked(t, flags, payload)
	return err
}

// sendFrameTracked publishes one new sequenced frame and returns the exact
// immutable bytes owned by the replay ledger. Transaction retries can
// redispatch these bytes without allocating another SEQ or control slot.
func (e *Engine) sendFrameTracked(t proto.FrameType, flags uint16, payload []byte) ([]byte, error) {
	if e.sendClosing.Load() {
		return nil, net.ErrClosed
	}
	control := t == proto.FrameCtrl
	if err := e.acquireSendSlot(control); err != nil {
		return nil, err
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	if e.isClosed() || e.sendClosing.Load() {
		e.releaseSendSlot(control)
		return nil, net.ErrClosed
	}

	seq := atomic.AddUint64(&e.sendSeq, 1) - 1
	hdr := proto.Header{
		Version: proto.Version,
		Type:    t,
		Flags:   flags,
		Seq:     seq,
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		e.releaseSendSlot(control)
		return nil, err
	}
	copy(frame[proto.HeaderSize:], payload)

	if err := e.reserveSendFrame(frame); err != nil {
		e.releaseSendSlot(control)
		return nil, err
	}
	// Publication means the SEQ has a replay owner and may now be observed by
	// any path. Advancing before dispatch lets a fast race child ACK while a
	// slower sibling is still inside Write without having that ACK rejected.
	e.publishSendSeq(seq + 1)
	err := e.dispatch(frame, true)
	return frame, err
}

func (e *Engine) replaySequencedFrame(frame []byte) error {
	if len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	if e.isClosed() || e.sendClosing.Load() {
		return net.ErrClosed
	}
	return e.dispatch(frame, false)
}

func (e *Engine) sendTerminalFrame(reason proto.ByeReason) error {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	if e.isClosed() {
		return net.ErrClosed
	}
	seq := atomic.AddUint64(&e.sendSeq, 1) - 1
	payload := proto.ByePayload{Reason: reason}.Encode()
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlBye),
		Seq:     seq,
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return err
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := e.reserveTerminalFrame(frame); err != nil {
		return err
	}
	e.publishSendSeq(seq + 1)
	return e.dispatch(frame, true)
}

func (e *Engine) publishSendSeq(next uint64) {
	for {
		cur := e.sendPublishedNext.Load()
		if next <= cur || e.sendPublishedNext.CompareAndSwap(cur, next) {
			return
		}
	}
}

// dispatch writes a fully-built frame on the path(s) appropriate to
// the current Mode:
//
//	selector / 0 (default) - write on the single active path
//	race                - write on every attached path
//	bond                - round-robin frame-level across all paths
//
// The race path returns nil as long as at least one path succeeded
// (receiver dedup handles duplicates). It returns
// ErrMigrationBudgetExceeded only when there are no usable paths
// after the budget.
func (e *Engine) dispatch(frame []byte, firstPublication bool) error {
	if runtime := e.localExecutionRuntime(); runtime != nil {
		return e.dispatchRecursive(frame, runtime, firstPublication)
	}
	switch e.mode.Load() {
	case dispatchRace:
		return e.dispatchRace(frame, firstPublication)
	case dispatchBond:
		return e.dispatchBond(frame, firstPublication)
	default:
		return e.dispatchSingle(frame, firstPublication)
	}
}

func (e *Engine) dispatchSingle(frame []byte, firstPublication bool) error {
	for {
		if e.isClosed() {
			return net.ErrClosed
		}
		e.pathsMu.RLock()
		id := e.activeID
		var slot *pathSlot
		if id != 0 {
			if s, ok := e.paths[id]; ok {
				slot = s
			}
		}
		e.pathsMu.RUnlock()

		if slot == nil {
			if err := e.waitForPath(); err != nil {
				return err
			}
			continue
		}

		n, err := slot.writeDispatchedFrame(frame)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				continue
			}
			return err
		}
		if n != len(frame) {
			return io.ErrShortWrite
		}
		if slot != nil {
			slot.lastSendUnixNano.Store(nowFn().UnixNano())
			slot.recordDispatch(frame, firstPublication)
		}
		return nil
	}
}

// dispatchBond writes one frame to one path, with path-pinning:
// after picking a path, the next bondPinSize-1 frames stay on it
// before bondCursor advances. This bounds reorder-window growth
// under RTT skew between paths.
//
// A path whose latest probe RTT exceeds best_rtt *
// BondStuckRTTMultiplier (default 3x) is skipped on round-robin;
// if the currently-pinned path goes stuck mid-window, the pin is
// broken early and the cursor advances. Paths with zero RTT
// (unmeasured: fresh attach, no probe reply yet) are never
// considered stuck.
//
// PathSpec.Weight controls each path's share of pin windows. A zero
// weight means 1. Redistribute-on-death replays only frames newer
// than the peer's latest cumulative ACK, with the bounded recent
// window as the conservative fallback when no ACK has arrived yet.
func (e *Engine) dispatchBond(frame []byte, firstPublication bool) error {
	for {
		if e.isClosed() {
			return net.ErrClosed
		}
		e.pathsMu.Lock()
		if len(e.paths) == 0 {
			e.pathsMu.Unlock()
			if err := e.waitForPath(); err != nil {
				return err
			}
			continue
		}
		// Stable order so round-robin is deterministic across paths.
		ids := make([]uint32, 0, len(e.paths))
		for id := range e.paths {
			if !e.dispatchScopeAllowsLocked(id) {
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			e.pathsMu.Unlock()
			if err := e.waitForPath(); err != nil {
				return err
			}
			continue
		}
		for i := 1; i < len(ids); i++ {
			for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
				ids[j-1], ids[j] = ids[j], ids[j-1]
			}
		}
		weights, totalWeight := e.bondWeightsLocked(ids)
		stuck := e.computeBondStuckMask(ids)

		// If pin window still has frames AND current path is not
		// stuck, keep using it.
		idx := -1
		if e.bondPinLeft > 0 {
			cur := bondWeightedIndex(weights, totalWeight, e.bondCursor)
			if !stuck[cur] {
				idx = cur
			} else {
				// Mid-pin: pinned path went stuck, force re-pick.
				e.bondStuckSkips++
			}
		}
		if idx < 0 {
			// Pin expired OR current went stuck. Advance until we
			// land on a non-stuck path, or give up after one full
			// rotation (all paths stuck).
			pin := e.bondPinSize
			if pin <= 0 {
				pin = defaultBondPinSize
			}
			if e.Packetized() {
				// Packet-mode bond on QUIC DATAGRAM is the G3 hot
				// path: per-path 8-frame pinning creates avoidable
				// microbursts that can overflow datagram queues and
				// manifest as one missing SEQ that stalls the strict
				// reorder window behind it. Stream-mode keeps the
				// default pinning; packet-mode smooths to frame-by-
				// frame round-robin.
				pin = 1
			}
			chosen := -1
			for i := uint64(0); i < totalWeight; i++ {
				e.bondCursor++
				j := bondWeightedIndex(weights, totalWeight, e.bondCursor)
				if !stuck[j] {
					chosen = j
					break
				}
				// Path skipped because it is stuck.
				e.bondStuckSkips++
			}
			if chosen < 0 {
				chosen = bondWeightedIndex(weights, totalWeight, e.bondCursor)
			}
			idx = chosen
			e.bondPinLeft = pin
		}
		e.bondPinLeft--
		slot := e.paths[ids[idx]]
		e.pathsMu.Unlock()

		n, err := slot.writeDispatchedFrame(frame)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// Path died mid-write; pick again.
				continue
			}
			return err
		}
		if n != len(frame) {
			return io.ErrShortWrite
		}
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		slot.recordDispatch(frame, firstPublication)
		return nil
	}
}

func (e *Engine) redistributeFrames(frames [][]byte) error {
	if len(frames) == 0 || e.isClosed() {
		return nil
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	return e.redistributeFramesLocked(frames)
}

func (e *Engine) redistributeFramesLocked(frames [][]byte) error {
	for _, frame := range frames {
		if e.isClosed() {
			return net.ErrClosed
		}
		if err := e.dispatch(frame, false); err != nil {
			return err
		}
		if len(frame) >= proto.HeaderSize {
			if hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil {
				e.publishSendSeq(hdr.Seq + 1)
			}
		}
	}
	return nil
}

func (e *Engine) requestReplay(nextSeq uint64) {
	select {
	case e.replayRequests <- nextSeq:
	default:
	}
}

func (e *Engine) replayLoop() {
	for {
		select {
		case <-e.closed:
			return
		case nextSeq := <-e.replayRequests:
			e.replayUntilSent(nextSeq)
		}
	}
}

func (e *Engine) replayUntilSent(nextSeq uint64) {
	backoff := 10 * time.Millisecond
	for {
		if acked := e.sendAckNext.Load(); nextSeq < acked {
			nextSeq = acked
		}
		frames := e.sendHistorySnapshot(nextSeq)
		if len(frames) == 0 {
			return
		}
		if err := e.redistributeFrames(frames); err == nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-e.closed:
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
		if backoff < 200*time.Millisecond {
			backoff *= 2
		}
	}
}

func (e *Engine) bondWeightsLocked(ids []uint32) ([]uint16, uint64) {
	weights := make([]uint16, len(ids))
	var total uint64
	for i, id := range ids {
		w := uint16(1)
		if s, ok := e.paths[id]; ok && s.spec.Weight > 0 {
			w = s.spec.Weight
		}
		weights[i] = w
		total += uint64(w)
	}
	if total == 0 {
		return weights, uint64(len(ids))
	}
	return weights, total
}

func bondWeightedIndex(weights []uint16, total uint64, cursor uint64) int {
	if len(weights) == 0 {
		return 0
	}
	if total == 0 {
		return int(cursor % uint64(len(weights)))
	}
	slot := cursor % total
	var acc uint64
	for i, w := range weights {
		acc += uint64(w)
		if slot < acc {
			return i
		}
	}
	return len(weights) - 1
}

// computeBondStuckMask is retained for the transitional flat dispatcher.
// Latency alone cannot exclude a bond member; recursive dispatch performs
// evidence-based writer-stall quarantine instead.
func (e *Engine) computeBondStuckMask(ids []uint32) []bool {
	return make([]bool, len(ids))
}

// dispatchRace writes the same frame on every attached path.
// At least one success is required; if every path errors, the
// engine waits inside the migration budget for a fresh path.
func (e *Engine) dispatchRace(frame []byte, firstPublication bool) error {
	for {
		if e.isClosed() {
			return net.ErrClosed
		}
		e.pathsMu.RLock()
		slots := make([]*pathSlot, 0, len(e.paths))
		for _, s := range e.paths {
			if !e.dispatchScopeAllowsLocked(s.id) {
				continue
			}
			slots = append(slots, s)
		}
		e.pathsMu.RUnlock()

		if len(slots) == 0 {
			if err := e.waitForPath(); err != nil {
				return err
			}
			continue
		}

		anyOk := false
		now := nowFn().UnixNano()
		for _, s := range slots {
			if n, err := s.writeDispatchedFrame(frame); err == nil && n == len(frame) {
				anyOk = true
				s.lastSendUnixNano.Store(now)
				s.recordDispatch(frame, firstPublication)
			}
		}
		if anyOk {
			return nil
		}
		// All paths failed. Loop and let waitForPath enforce budget.
	}
}

func (e *Engine) dispatchScopeAllowsLocked(id uint32) bool {
	return len(e.dispatchScope) == 0 || e.dispatchScope[id]
}
