package engine

import (
	"io"
	"net"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// Recv reads up to len(buf) bytes from the engine into buf, blocking
// until at least one byte is available or the engine is dead.
//
// Hard rule #1: a migration in flight may block Recv but never
// returns an error caused by the migration. Recv returns:
//   - io.EOF if the peer issued BYE
//   - rendr.ErrMigrationBudgetExceeded if the budget tripped
//   - rendr.ErrZombie if zombie protection tripped
//   - net.ErrClosed if the engine itself was Close()d locally
func (e *Engine) Recv(buf []byte) (int, error) {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	for {
		if len(e.recvDeliver) > 0 {
			n := copy(buf, e.recvDeliver)
			e.recvDeliver = e.recvDeliver[n:]
			return n, nil
		}
		if e.isClosed() {
			if err := e.CloseErr(); err != nil {
				return 0, err
			}
			return 0, net.ErrClosed
		}
		e.recvCond.Wait()
	}
}

// readerLoop is one goroutine per attached PathConn. It pulls
// length-prefixed framed units off the path (the transport adapter
// gives us complete header+payload buffers via Read), decodes the
// header, and dispatches data to the reorder buffer or hands a
// control frame to the engine.
func (e *Engine) readerLoop(slot *pathSlot) {
	defer close(slot.doneR)

	buf := make([]byte, MaxPayload+proto.HeaderSize)
	for {
		select {
		case <-slot.quit:
			return
		default:
		}

		n, err := slot.conn.Read(buf)
		if err != nil {
			// Path adapter has already invoked OnDeath; just exit.
			return
		}
		if n < proto.HeaderSize {
			// Malformed; treat as path death (transport adapter
			// already classified; OnDeath fires elsewhere).
			return
		}
		hdr, err := proto.DecodeHeader(buf[:proto.HeaderSize])
		if err != nil {
			return
		}
		if hdr.Version != proto.Version {
			e.setCloseErr(errVersionMismatch)
			_ = e.Close()
			return
		}
		payload := append([]byte(nil), buf[proto.HeaderSize:n]...)

		switch hdr.Type {
		case proto.FrameData:
			e.deliverData(hdr.Seq, payload)
		case proto.FrameCtrl:
			e.handleCtrl(slot, hdr, payload)
		}
	}
}

// deliverData places a data frame into the reorder buffer and
// flushes any in-order suffix into recvDeliver.
func (e *Engine) deliverData(seq uint64, payload []byte) {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()

	if seq < e.expectedRecvSeq {
		// Duplicate from race/redistribute; drop.
		return
	}
	if seq == e.expectedRecvSeq {
		e.recvDeliver = append(e.recvDeliver, payload...)
		e.expectedRecvSeq++
		// Drain any cached contiguous suffix.
		for {
			p, ok := e.recvQueue[e.expectedRecvSeq]
			if !ok {
				break
			}
			delete(e.recvQueue, e.expectedRecvSeq)
			e.recvDeliver = append(e.recvDeliver, p...)
			e.expectedRecvSeq++
		}
		e.markPayload()
		e.recvCond.Broadcast()
		return
	}
	// Future SEQ: cache.
	e.recvQueue[seq] = payload
}

// handleCtrl processes a control frame on the receiver side.
func (e *Engine) handleCtrl(slot *pathSlot, hdr proto.Header, payload []byte) {
	code := proto.CtrlCodeFromFlags(hdr.Flags)
	switch code {
	case proto.CtrlBye:
		// Peer-initiated teardown: mark the path so EOF maps to
		// CleanClose, then surface EOF to the application.
		if pc, ok := slot.conn.(interface{ MarkByeSeen() }); ok {
			pc.MarkByeSeen()
		}
		e.recvMu.Lock()
		e.recvCond.Broadcast()
		e.recvMu.Unlock()
		e.setCloseErr(io.EOF)
		_ = e.Close()

	case proto.CtrlMigrateNotify:
		// Peer told us its new active path. M1 single-active-path
		// engines just record the fact; the reorder buffer doesn't
		// care which path delivered which SEQ.
		_ = payload

	case proto.CtrlHeartbeat,
		proto.CtrlPathQuality,
		proto.CtrlBridgeTag,
		proto.CtrlHello:
		// M1 ignores these on the read side; handshake / quality
		// flows are wired up in subsequent commits.
		_ = payload
	}
}

func (e *Engine) markPayload() {
	e.zombieMu.Lock()
	// Reset zombie budget on successful payload arrival.
	e.zombieMigrationsLeft = e.limits.ZombieMaxMigrations
	e.lastPayloadAt = nowFn()
	e.zombieMu.Unlock()
}

// errVersionMismatch is the internal close cause for a peer
// announcing an incompatible proto.Version.
var errVersionMismatch = &engineError{msg: "rendr: peer protocol version mismatch"}

type engineError struct{ msg string }

func (e *engineError) Error() string { return e.msg }

// Wire it to the public sentinel: rendr.ErrPeerProtoVersion via
// errors.Is when called from the outside.
func (e *engineError) Is(target error) bool {
	if target == nil {
		return false
	}
	return target.Error() == "rendr: incompatible protocol version"
}

// Ensure unused-import elimination if transport ends up unused later.
var _ transport.DeathCause = transport.CauseUnknown
