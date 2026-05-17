package engine

import (
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// recvItem is one frame waiting in the reorder buffer. Data frames
// hold the payload bytes; ctrl frames hold the flags so the in-order
// drainer can dispatch them after the SEQ space catches up.
type recvItem struct {
	isCtrl  bool
	flags   uint16
	payload []byte
}

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

// readerLoop is one goroutine per attached PathConn.
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
			return
		}
		if n < proto.HeaderSize {
			return
		}
		hdr, err := proto.DecodeHeader(buf[:proto.HeaderSize])
		if err != nil {
			return
		}
		if hdr.Version != proto.Version {
			e.setCloseErr(ErrPeerProtoVersion)
			_ = e.Close()
			return
		}
		payload := append([]byte(nil), buf[proto.HeaderSize:n]...)

		// Per-path probes are handled before the SEQ-aware reorder
		// path so they never stall the application stream. Probe
		// frames intentionally do not consume a SEQ slot - the peer
		// can pick any value (we use 0) and we filter on type+code.
		if hdr.Type == proto.FrameCtrl {
			code := proto.CtrlCodeFromFlags(hdr.Flags)
			if code == proto.CtrlPathProbe {
				e.handlePathProbeRequest(slot, payload)
				continue
			}
			if code == proto.CtrlPathProbeReply {
				e.handlePathProbeReply(slot, payload)
				continue
			}
		}

		e.onFrameRecv(slot, hdr, payload)
	}
}

// handlePathProbeRequest echoes the probe back on the same path so
// the peer can compute its RTT. Best-effort; a failed write just
// degrades quality measurement, it does not affect the application.
func (e *Engine) handlePathProbeRequest(slot *pathSlot, payload []byte) {
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathProbeReply),
		Seq:     0, // probes are out-of-band of the SEQ stream
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return
	}
	copy(frame[proto.HeaderSize:], payload)
	_, _ = slot.conn.Write(frame)
}

// handlePathProbeReply matches the reply against an outstanding
// probe and, if found, updates the path's quality with the measured
// RTT.
func (e *Engine) handlePathProbeReply(slot *pathSlot, payload []byte) {
	p, err := proto.DecodeProbe(payload)
	if err != nil {
		return
	}
	e.probeMu.Lock()
	t0, ok := e.probeOutstanding[p.ID]
	if ok {
		delete(e.probeOutstanding, p.ID)
	}
	e.probeMu.Unlock()
	if !ok {
		return
	}
	rtt := nowFn().Sub(t0)
	if setter, ok := slot.conn.(interface {
		SetQuality(transport.PathQuality)
		Quality() transport.PathQuality
	}); ok {
		prev := setter.Quality()
		// Light jitter estimate: |new - prev| smoothed.
		jit := prev.Jitter
		if prev.RTT != 0 {
			diff := rtt - prev.RTT
			if diff < 0 {
				diff = -diff
			}
			jit = (jit*3 + diff) / 4
		}
		setter.SetQuality(transport.PathQuality{
			RTT:    rtt,
			Jitter: jit,
			LossPP: prev.LossPP,
			At:     nowFn(),
		})
	}
}

// onFrameRecv inserts a frame into the reorder buffer and drains
// any in-order suffix.
//
// The SEQ namespace is shared between data and ctrl frames (see
// docs/architecture.md "不变量 #2"); both consume one SEQ. The
// drainer dispatches each in turn so the application stream remains
// contiguous regardless of how ctrl frames are interleaved.
func (e *Engine) onFrameRecv(slot *pathSlot, hdr proto.Header, payload []byte) {
	e.recvMu.Lock()
	defer e.recvMu.Unlock()

	if hdr.Seq < e.expectedRecvSeq {
		// Duplicate (race / redistribute) or out-of-window.
		return
	}

	e.recvQueue[hdr.Seq] = recvItem{
		isCtrl:  hdr.Type == proto.FrameCtrl,
		flags:   hdr.Flags,
		payload: payload,
	}

	wokeReader := false
	for {
		item, ok := e.recvQueue[e.expectedRecvSeq]
		if !ok {
			break
		}
		delete(e.recvQueue, e.expectedRecvSeq)
		e.expectedRecvSeq++
		if item.isCtrl {
			e.applyCtrlLocked(slot, item.flags, item.payload)
		} else {
			e.recvDeliver = append(e.recvDeliver, item.payload...)
			wokeReader = true
			e.markPayloadLocked()
		}
	}
	if wokeReader || e.isClosed() {
		e.recvCond.Broadcast()
	}
}

// applyCtrlLocked dispatches a control frame whose SEQ has reached
// the head of the reorder window. Caller holds recvMu.
//
// To avoid deadlocks against Close (which itself broadcasts the recv
// cond), heavyweight teardown work fires in a goroutine.
func (e *Engine) applyCtrlLocked(slot *pathSlot, flags uint16, payload []byte) {
	code := proto.CtrlCodeFromFlags(flags)
	switch code {
	case proto.CtrlBye:
		// Peer-initiated teardown -> clean close. Record io.EOF as the
		// close cause so the local application's Read picks up EOF.
		if pc, ok := slot.conn.(interface{ MarkByeSeen() }); ok {
			pc.MarkByeSeen()
		}
		// Schedule Close in a goroutine so we do not re-enter recvMu.
		go func() {
			e.setCloseErr(io.EOF)
			_ = e.Close()
		}()

	case proto.CtrlMigrateNotify,
		proto.CtrlHeartbeat,
		proto.CtrlPathQuality,
		proto.CtrlBridgeTag,
		proto.CtrlHello:
		// M1 ignores these on the read side; they consume a SEQ slot
		// purely to keep the reorder window contiguous.
		_ = payload
	}
}

// markPayloadLocked refreshes the zombie counter when payload makes
// it through. Caller holds recvMu (and we serialise zombie counter
// access via zombieMu separately).
//
// Resetting zombieLastMig to zero is intentional: after payload, the
// NEXT migration will compute "cooldown expired" as false and start
// from a fresh full counter.
func (e *Engine) markPayloadLocked() {
	e.zombieMu.Lock()
	e.zombieLeft = e.limits.ZombieMaxMigrations
	e.zombieLastMig = time.Time{}
	e.zombieMu.Unlock()
}
