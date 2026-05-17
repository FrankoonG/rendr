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

// dispatch writes a fully-built frame on the currently-active path,
// reselecting if the active one dies mid-write.
func (e *Engine) dispatch(frame []byte) error {
	for {
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
			// No active path. Wait inside the migration budget for a
			// new path to attach, or surface ErrMigrationBudgetExceeded.
			if err := e.waitForPath(); err != nil {
				return err
			}
			continue
		}

		if _, err := pc.Write(frame); err != nil {
			// Path is dying; the path's OnDeath callback will mark it
			// inactive. Retry on the next active path.
			if errors.Is(err, net.ErrClosed) {
				continue
			}
			return err
		}
		return nil
	}
}
