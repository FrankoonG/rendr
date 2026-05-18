package engine

import (
	"errors"
	"net"
	"sync/atomic"

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

// SendBye emits a CTRL_BYE frame on the active path. Best-effort
// and explicitly non-retrying: if the active path is dead or
// missing, the call returns immediately with net.ErrClosed instead
// of engaging the migration budget. That's intentional - BYE is the
// local-Close convention, and Close should not block 90 s on a
// failing peer.
func (e *Engine) SendBye(reason proto.ByeReason) error {
	payload := proto.ByePayload{Reason: reason}.Encode()

	e.sendMu.Lock()
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

	return e.dispatch(frame)
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
		if id != 0 {
			if s, ok := e.paths[id]; ok {
				pc = s.conn
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
		return nil
	}
}

// dispatchBond writes one frame to one path, with path-pinning:
// after picking a path, the next bondPinSize-1 frames stay on it
// before bondCursor advances. This bounds reorder-window growth
// under RTT skew between paths (docs/modes.md "path pinning").
//
// Minimum-viable: deterministic id-sorted round-robin, no weighted
// distribution, no stuck-path bypass, no redistribute-on-death.
// Those are M8(3..n) follow-ups.
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
			ids = append(ids, id)
		}
		// Insertion sort on small N - cheaper than sort.Slice for
		// the typical <= 8 paths bond cares about.
		for i := 1; i < len(ids); i++ {
			for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
				ids[j-1], ids[j] = ids[j], ids[j-1]
			}
		}
		// Refill the pin window when it runs out, then advance the
		// cursor. Cursor advances on the FIRST frame of a window,
		// not in the middle, so all frames in a window land on the
		// same path id.
		if e.bondPinLeft <= 0 {
			pin := e.bondPinSize
			if pin <= 0 {
				pin = defaultBondPinSize
			}
			e.bondPinLeft = pin
			e.bondCursor++
		}
		e.bondPinLeft--
		idx := int(e.bondCursor % uint64(len(ids)))
		pc := e.paths[ids[idx]].conn
		e.pathsMu.Unlock()

		if _, err := pc.Write(frame); err != nil {
			if errors.Is(err, net.ErrClosed) {
				// Path died mid-write; pick again.
				continue
			}
			return err
		}
		return nil
	}
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
		conns := make([]transport.PathConn, 0, len(e.paths))
		for _, s := range e.paths {
			conns = append(conns, s.conn)
		}
		e.pathsMu.RUnlock()

		if len(conns) == 0 {
			if err := e.waitForPath(); err != nil {
				return err
			}
			continue
		}

		anyOk := false
		for _, pc := range conns {
			if _, err := pc.Write(frame); err == nil {
				anyOk = true
			}
		}
		if anyOk {
			return nil
		}
		// All paths failed. Loop and let waitForPath enforce budget.
	}
}
