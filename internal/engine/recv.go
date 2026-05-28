package engine

import (
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const recvBatchSize = 64

// packetRecvWindowBits bounds the amount of out-of-order packet-mode
// state we keep as a bitmap instead of one map entry per SEQ. 4 Mi
// bits ≈ 512 KiB and covers ~42 s at 100k pps, which is comfortably
// above G3-T4's 30 s runtime.
const packetRecvWindowBits = 4 << 20

// recvItem is one frame waiting in the reorder buffer. Data frames
// hold the payload bytes; ctrl frames hold the flags so the in-order
// drainer can dispatch them after the SEQ space catches up.
type recvItem struct {
	isCtrl  bool
	flags   uint16
	payload []byte
	// packet-mode data may be delivered as soon as the first copy
	// arrives; delivered tracks that early handoff so later SEQ-floor
	// advancement can retire the slot without delivering twice.
	delivered bool
}

// recvFrame is one decoded frame handed off by a path reader to the
// single recvLoop aggregator. Readers stay out of recvMu entirely;
// the aggregator batches reorder/dedup work so G3-scale fan-in no
// longer serialises four path goroutines on one mutex per frame.
type recvFrame struct {
	slot    *pathSlot
	hdr     proto.Header
	payload []byte
}

func (e *Engine) packetSeenCapLocked() uint64 {
	return uint64(len(e.recvSeenBits)) * 64
}

func (e *Engine) packetSeenIndexLocked(seq uint64) uint64 {
	cap := e.packetSeenCapLocked()
	if cap == 0 {
		return 0
	}
	return (e.recvSeenHead + (seq - e.expectedRecvSeq)) % cap
}

func (e *Engine) packetSeenLocked(seq uint64) bool {
	idx := e.packetSeenIndexLocked(seq)
	word := idx / 64
	bit := idx % 64
	return e.recvSeenBits[word]&(uint64(1)<<bit) != 0
}

func (e *Engine) packetMarkSeenLocked(seq uint64) {
	idx := e.packetSeenIndexLocked(seq)
	word := idx / 64
	bit := idx % 64
	e.recvSeenBits[word] |= uint64(1) << bit
}

func (e *Engine) packetHeadSeenLocked() bool {
	if len(e.recvSeenBits) == 0 {
		return false
	}
	idx := e.recvSeenHead
	word := idx / 64
	bit := idx % 64
	return e.recvSeenBits[word]&(uint64(1)<<bit) != 0
}

func (e *Engine) packetAdvanceHeadLocked() {
	cap := e.packetSeenCapLocked()
	if cap == 0 {
		return
	}
	e.recvSeenHead = (e.recvSeenHead + 1) % cap
}

func (e *Engine) packetConsumeHeadLocked() {
	if len(e.recvSeenBits) == 0 {
		return
	}
	idx := e.recvSeenHead
	word := idx / 64
	bit := idx % 64
	e.recvSeenBits[word] &^= uint64(1) << bit
	if e.recvPacketMarks > 0 {
		e.recvPacketMarks--
	}
	e.packetAdvanceHeadLocked()
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
		if e.recvDeadlineExceededLocked() {
			return 0, ErrReadDeadlineExceeded
		}
		e.recvCond.Wait()
	}
}

// RecvPacket pops the oldest pending packet from the engine's packet
// queue. Blocks until at least one packet is available or the engine
// is dead. Only valid when SetPacketMode was called; callers using
// Recv on a packet-mode engine will deadlock because the drainer
// never appends to recvDeliver.
//
// If the engine closes during the wait, RecvPacket returns
// (nil, io.EOF) for a peer BYE or (nil, ErrMigrationBudgetExceeded)
// for a budget exhaustion - same shape as Recv.
func (e *Engine) RecvPacket() ([]byte, error) {
	for {
		e.recvMu.Lock()
		deadline := e.recvDeadline
		e.recvMu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, ErrReadDeadlineExceeded
		}
		var (
			timer  *time.Timer
			timerC <-chan time.Time
		)
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}
		select {
		case p := <-e.recvPacketCh:
			if timer != nil {
				timer.Stop()
			}
			return p, nil
		case <-e.recvPacketWake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-e.closed:
			if timer != nil {
				timer.Stop()
			}
			if err := e.CloseErr(); err != nil {
				return nil, err
			}
			return nil, net.ErrClosed
		case <-timerC:
			return nil, ErrReadDeadlineExceeded
		}
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
		// Stamp last-recv after a successful read but before any
		// version / framing rejection: from the path's perspective,
		// "something arrived" is the signal monitoring cares about.
		slot.lastRecvUnixNano.Store(nowFn().UnixNano())
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
			if code == proto.CtrlBye {
				// BYE is still delivered through the SEQ-aware reorder
				// path below, but mark the transport immediately. A peer
				// can close its TCP write side right after sending BYE; if
				// the resulting EOF wins the race against recvLoop draining
				// slot.recvQ, OnDeath must still classify it as clean.
				if pc, ok := slot.conn.(interface{ MarkByeSeen() }); ok {
					pc.MarkByeSeen()
				}
			}
		}

		if !e.enqueueRecvFrame(slot, hdr, payload) {
			return
		}
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
	if ack, ok := proto.DecodeAck(payload); ok {
		e.notePeerAck(ack.NextSeq)
		return
	}
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

func (e *Engine) notePeerAck(nextSeq uint64) {
	for {
		cur := e.sendAckNext.Load()
		if nextSeq <= cur {
			return
		}
		if e.sendAckNext.CompareAndSwap(cur, nextSeq) {
			return
		}
	}
}

func (e *Engine) sendAck(nextSeq uint64) {
	if nextSeq == 0 || e.isClosed() {
		return
	}
	payload := proto.AckPayload{NextSeq: nextSeq}.Encode()
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathProbeReply),
		Seq:     0,
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return
	}
	copy(frame[proto.HeaderSize:], payload)

	e.pathsMu.RLock()
	slot := e.paths[e.activeID]
	e.pathsMu.RUnlock()
	if slot == nil {
		return
	}
	_, _ = slot.conn.Write(frame)
}

// enqueueRecvFrame hands one fully-decoded frame to the per-path recv
// queue. The queue is intentionally small so one fast path cannot run
// arbitrarily far ahead of a slower path and explode the reorder
// window. Returning false means the engine is closing and the caller
// should stop reading.
func (e *Engine) enqueueRecvFrame(slot *pathSlot, hdr proto.Header, payload []byte) bool {
	select {
	case slot.recvQ <- recvFrame{slot: slot, hdr: hdr, payload: payload}:
		select {
		case e.recvWake <- struct{}{}:
		default:
		}
		return true
	case <-slot.quit:
		return false
	case <-e.closed:
		return false
	}
}

// recvLoop is the sole mutator of the reorder buffer. It drains the
// per-path recv queues in a round-robin sweep so one path cannot
// monopolise ingress and strand lower SEQs behind hundreds of
// thousands of later frames.
func (e *Engine) recvLoop() {
	batch := make([]recvFrame, 0, recvBatchSize)
	for {
		if e.fillRecvBatch(&batch) {
			e.onRecvBatch(batch)
			batch = batch[:0]
			continue
		}
		select {
		case <-e.closed:
			return
		case <-e.recvWake:
		}
	}
}

func (e *Engine) fillRecvBatch(batch *[]recvFrame) bool {
	slots := e.recvSlotsSnapshot()
	if len(slots) == 0 {
		return false
	}
	start := int(e.recvPathCursor % uint64(len(slots)))
	progressed := false
	for len(*batch) < cap(*batch) {
		roundProgress := false
		for i := 0; i < len(slots) && len(*batch) < cap(*batch); i++ {
			slot := slots[(start+i)%len(slots)]
			select {
			case frame := <-slot.recvQ:
				*batch = append(*batch, frame)
				roundProgress = true
				progressed = true
			default:
			}
		}
		if !roundProgress {
			break
		}
		start = (start + 1) % len(slots)
	}
	if progressed {
		e.recvPathCursor = uint64(start)
	}
	return progressed
}

func (e *Engine) recvSlotsSnapshot() []*pathSlot {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	if len(e.paths) == 0 {
		return nil
	}
	ids := make([]uint32, 0, len(e.paths))
	for id := range e.paths {
		ids = append(ids, id)
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	slots := make([]*pathSlot, 0, len(ids))
	for _, id := range ids {
		slots = append(slots, e.paths[id])
	}
	return slots
}

// onRecvBatch inserts frames into the reorder buffer and drains any
// in-order suffix. Caller guarantees all work in batch belongs to the
// same Engine instance; the function takes recvMu once for the whole
// batch to amortise dedup/reorder cost at high packet rates.
func (e *Engine) onRecvBatch(batch []recvFrame) {
	if len(batch) == 0 {
		return
	}
	deliverPackets := make([][]byte, 0, len(batch))
	e.recvMu.Lock()
	wokeReader := false
	for _, frame := range batch {
		if e.onFrameRecvLocked(frame.slot, frame.hdr, frame.payload, &deliverPackets) {
			wokeReader = true
		}
	}
	ackNext := uint64(0)
	if e.expectedRecvSeq > e.recvAckSent {
		e.recvAckSent = e.expectedRecvSeq
		ackNext = e.expectedRecvSeq
	}
	if wokeReader || e.isClosed() {
		e.recvCond.Broadcast()
	}
	e.recvMu.Unlock()
	if ackNext != 0 {
		e.sendAck(ackNext)
	}
	for _, pkt := range deliverPackets {
		select {
		case e.recvPacketCh <- pkt:
		case <-e.closed:
			return
		}
	}
}

// onFrameRecvLocked inserts a frame into the reorder buffer and drains
// any now-contiguous suffix. Returns true if payload became readable
// by the application.
//
// The SEQ namespace is shared between data and ctrl frames (see
// each consumes one SEQ for the contiguous-stream invariant). The
// drainer dispatches each in turn so the application stream remains
// contiguous regardless of how ctrl frames are interleaved.
func (e *Engine) onFrameRecvLocked(slot *pathSlot, hdr proto.Header, payload []byte, deliverPackets *[][]byte) bool {
	if hdr.Seq < e.expectedRecvSeq {
		// Duplicate (race / redistribute) or out-of-window.
		e.recvDups++
		if slot != nil {
			slot.recvDups.Add(1)
		}
		return false
	}

	if e.packetized && hdr.Type != proto.FrameCtrl {
		cap := e.packetSeenCapLocked()
		if cap > 0 {
			delta := hdr.Seq - e.expectedRecvSeq
			if delta < cap {
				if e.packetSeenLocked(hdr.Seq) {
					e.recvDups++
					if slot != nil {
						slot.recvDups.Add(1)
					}
					return false
				}
				if _, exists := e.recvQueue[hdr.Seq]; exists {
					e.recvDups++
					if slot != nil {
						slot.recvDups.Add(1)
					}
					return false
				}
				e.packetMarkSeenLocked(hdr.Seq)
				e.recvPacketMarks++
				*deliverPackets = append(*deliverPackets, payload)
				e.markPayloadLocked()
				if n := len(e.recvQueue) + e.recvPacketMarks; n > e.recvQueueHWM {
					e.recvQueueHWM = n
				}

				for {
					if item, ok := e.recvQueue[e.expectedRecvSeq]; ok {
						delete(e.recvQueue, e.expectedRecvSeq)
						e.expectedRecvSeq++
						e.packetAdvanceHeadLocked()
						if item.isCtrl {
							e.applyCtrlLocked(slot, item.flags, item.payload)
						} else if !item.delivered {
							*deliverPackets = append(*deliverPackets, item.payload)
							e.markPayloadLocked()
						}
						continue
					}
					if !e.packetHeadSeenLocked() {
						break
					}
					e.packetConsumeHeadLocked()
					e.expectedRecvSeq++
				}
				return true
			}
		}
	}

	if _, exists := e.recvQueue[hdr.Seq]; exists {
		// Same SEQ already buffered (race-mode in-flight duplicate):
		// keep the first copy, count the second.
		e.recvDups++
		if slot != nil {
			slot.recvDups.Add(1)
		}
		return false
	}

	e.recvQueue[hdr.Seq] = recvItem{
		isCtrl:  hdr.Type == proto.FrameCtrl,
		flags:   hdr.Flags,
		payload: payload,
	}
	if e.packetized && hdr.Type != proto.FrameCtrl {
		// Packet mode follows datagram semantics: preserve packet
		// boundaries, dedupe by SEQ, but do not block application
		// delivery behind an unrelated missing earlier SEQ. Keep a
		// lightweight marker in recvQueue so control-frame ordering and
		// duplicate suppression still have a shared SEQ view.
		item := e.recvQueue[hdr.Seq]
		*deliverPackets = append(*deliverPackets, item.payload)
		item.payload = nil
		item.delivered = true
		e.recvQueue[hdr.Seq] = item
		e.markPayloadLocked()
	}
	if n := len(e.recvQueue) + e.recvPacketMarks; n > e.recvQueueHWM {
		e.recvQueueHWM = n
	}

	wokeReader := false
	for {
		item, ok := e.recvQueue[e.expectedRecvSeq]
		if !ok {
			if e.packetized && e.packetHeadSeenLocked() {
				e.packetConsumeHeadLocked()
				e.expectedRecvSeq++
				continue
			}
			break
		}
		delete(e.recvQueue, e.expectedRecvSeq)
		e.expectedRecvSeq++
		if e.packetized {
			e.packetAdvanceHeadLocked()
		}
		if item.isCtrl {
			e.applyCtrlLocked(slot, item.flags, item.payload)
		} else {
			if e.packetized {
				if !item.delivered {
					// DATA at the SEQ head may still be pending if it
					// arrived in-order; preserve boundaries 1:1.
					*deliverPackets = append(*deliverPackets, item.payload)
					e.markPayloadLocked()
				}
			} else {
				e.recvDeliver = append(e.recvDeliver, item.payload...)
				e.markPayloadLocked()
			}
			wokeReader = true
		}
	}
	return wokeReader
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

	case proto.CtrlPolicyRequest:
		if p, err := proto.DecodePolicyRequest(payload); err == nil {
			go func() {
				_ = e.SetDispatchPolicyByName(uint32(p.Mode), p.ActiveName, p.ScopeNames, p.Cause)
			}()
		}

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
