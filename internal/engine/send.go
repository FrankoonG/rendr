package engine

import (
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
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
	return e.sendFrameWithHistory(proto.FrameData, 0, buf, false)
}

// SendPolicyRequest asks the peer to update its sender policy for this flow.
// It is intentionally just another sequenced control frame: the peer applies
// it after earlier DATA/CTRL frames reach the reorder head.
func (e *Engine) SendPolicyRequest(mode uint32, activeName string, scopeNames []string, cause string) error {
	names := append([]string(nil), scopeNames...)
	return e.sendFrame(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPolicyRequest), proto.PolicyRequestPayload{
		Mode:       uint8(mode),
		ActiveName: activeName,
		ScopeNames: names,
		Cause:      cause,
	}.Encode())
}

// SendBye emits a CTRL_BYE frame on the active path. Best-effort
// and explicitly non-retrying: if the active path is dead or
// missing, the call returns immediately with net.ErrClosed instead
// of engaging the migration budget. That's intentional - BYE is the
// local-Close convention, and Close should not block 90 s on a
// failing peer.
func (e *Engine) SendBye(reason proto.ByeReason) error {
	payload := proto.ByePayload{Reason: reason}.Encode()

	if !e.sendMu.TryLock() {
		return net.ErrClosed
	}
	defer e.sendMu.Unlock()

	if e.isClosed() {
		return net.ErrClosed
	}

	e.pathsMu.RLock()
	id := e.activeID
	var pc transport.PathConn
	if id != 0 {
		if s, ok := e.paths[id]; ok {
			pc = s.conn
		}
	}
	e.pathsMu.RUnlock()
	if pc == nil {
		return net.ErrClosed
	}

	seq := atomic.AddUint64(&e.sendSeq, 1) - 1
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
	_, err := pc.Write(frame)
	return err
}

// sendFrame builds a single rendr frame and pushes it on the active
// path. Frame type may be Data or Ctrl; for Ctrl, flags encodes the
// CtrlCode in its low 8 bits.
func (e *Engine) sendFrame(t proto.FrameType, flags uint16, payload []byte) error {
	return e.sendFrameWithHistory(t, flags, payload, true)
}

func (e *Engine) sendFrameWithHistory(t proto.FrameType, flags uint16, payload []byte, remember bool) error {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	if e.isClosed() {
		return net.ErrClosed
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
		return err
	}
	copy(frame[proto.HeaderSize:], payload)

	if err := e.dispatch(frame); err != nil {
		return err
	}
	if remember {
		e.rememberSendFrame(frame)
	}
	return nil
}

// dispatch writes a fully-built frame on the path(s) appropriate to
// the current Mode:
//
//	prime / 0 (default) - write on the single active path
//	race                - write on every attached path
//	bond                - round-robin frame-level across all paths
//
// The race path returns nil as long as at least one path succeeded
// (receiver dedup handles duplicates). It returns
// ErrMigrationBudgetExceeded only when there are no usable paths
// after the budget.
func (e *Engine) dispatch(frame []byte) error {
	switch e.mode.Load() {
	case dispatchRace:
		return e.dispatchRace(frame)
	case dispatchBond:
		return e.dispatchBond(frame)
	default:
		return e.dispatchSingle(frame)
	}
}

func (e *Engine) dispatchSingle(frame []byte) error {
	for {
		if e.isClosed() {
			return net.ErrClosed
		}
		e.pathsMu.RLock()
		id := e.activeID
		var pc transport.PathConn
		var slot *pathSlot
		if id != 0 {
			if s, ok := e.paths[id]; ok {
				pc = s.conn
				slot = s
			}
		}
		e.pathsMu.RUnlock()

		if pc == nil {
			if err := e.waitForPath(); err != nil {
				return err
			}
			continue
		}

		if _, err := pc.Write(frame); err != nil {
			if errors.Is(err, net.ErrClosed) {
				continue
			}
			return err
		}
		if slot != nil {
			slot.lastSendUnixNano.Store(nowFn().UnixNano())
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
func (e *Engine) dispatchBond(frame []byte) error {
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
		pc := slot.conn
		e.pathsMu.Unlock()

		if _, err := pc.Write(frame); err != nil {
			if errors.Is(err, net.ErrClosed) {
				// Path died mid-write; pick again.
				continue
			}
			return err
		}
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		slot.rememberBondFrame(frame)
		return nil
	}
}

func (e *Engine) redistributeFrames(frames [][]byte) {
	if len(frames) == 0 || e.isClosed() {
		return
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	for _, frame := range frames {
		if e.isClosed() {
			return
		}
		_ = e.dispatchRedistributedBondFrame(frame)
	}
}

func (e *Engine) redistributeBondFrames(frames [][]byte) {
	e.redistributeFrames(frames)
}

func (e *Engine) dispatchRedistributedBondFrame(frame []byte) error {
	for {
		e.pathsMu.Lock()
		if len(e.paths) == 0 {
			e.pathsMu.Unlock()
			return net.ErrClosed
		}
		activeID := e.activeID
		ids := make([]uint32, 0, len(e.paths))
		for id := range e.paths {
			if !e.dispatchScopeAllowsLocked(id) {
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			e.pathsMu.Unlock()
			return net.ErrClosed
		}
		for i := 1; i < len(ids); i++ {
			for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
				ids[j-1], ids[j] = ids[j], ids[j-1]
			}
		}
		if activeID != 0 {
			for i, id := range ids {
				if id == activeID {
					copy(ids[1:i+1], ids[:i])
					ids[0] = id
					break
				}
			}
		}
		slots := make([]*pathSlot, 0, len(ids))
		for _, id := range ids {
			slots = append(slots, e.paths[id])
		}
		e.pathsMu.Unlock()

		now := nowFn().UnixNano()
		for _, slot := range slots {
			if _, err := slot.conn.Write(frame); err == nil {
				slot.lastSendUnixNano.Store(now)
				return nil
			}
		}
		return net.ErrClosed
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

// computeBondStuckMask returns, for each id in ids (in order), true
// if that path's latest probe RTT exceeds best_rtt * multiplier.
// Caller must hold e.pathsMu in read or write mode.
//
// Paths with zero RTT (no probe reply yet) are never stuck; if no
// path has any positive RTT reading the mask is all-false.
func (e *Engine) computeBondStuckMask(ids []uint32) []bool {
	mask := make([]bool, len(ids))
	var best time.Duration
	rtts := make([]time.Duration, len(ids))
	for i, id := range ids {
		if s, ok := e.paths[id]; ok {
			rtts[i] = s.conn.Quality().RTT
			if rtts[i] > 0 && (best == 0 || rtts[i] < best) {
				best = rtts[i]
			}
		}
	}
	if best == 0 {
		return mask
	}
	mult := e.limits.BondStuckRTTMultiplier
	if mult >= 1_000_000 {
		return mask
	}
	if mult <= 1.0 {
		mult = 3.0
	}
	threshold := time.Duration(float64(best) * mult)
	for i, r := range rtts {
		if r > 0 && r > threshold {
			mask[i] = true
		}
	}
	return mask
}

// dispatchRace writes the same frame on every attached path.
// At least one success is required; if every path errors, the
// engine waits inside the migration budget for a fresh path.
func (e *Engine) dispatchRace(frame []byte) error {
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
			if _, err := s.conn.Write(frame); err == nil {
				anyOk = true
				s.lastSendUnixNano.Store(now)
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
