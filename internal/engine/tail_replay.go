package engine

import (
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const (
	// Tail replay is deliberately quicker than the periodic cumulative ACK.
	// A healthy low-latency carrier therefore repairs a silently lost final
	// frame without waiting for a later sequence number to expose a gap.
	defaultTailReplayInitialDelay = 100 * time.Millisecond
	defaultTailReplayMaxBackoff   = time.Second
	maximumTailReplayInitialDelay = 4 * time.Second
)

// tailReplayLease is the single engine-owned timer lease for the latest
// immutable publication frontier. It is protected by replayMu. The lease never
// owns frame bytes: the bounded replay ledger remains their only owner.
type tailReplayLease struct {
	target   uint64
	ackNext  uint64
	due      time.Time
	deadline time.Time
	backoff  time.Duration
	armed    bool
}

func (e *Engine) tailReplayTiming() (time.Duration, time.Duration) {
	initial := e.tailReplayInitialDelay
	if initial <= 0 {
		initial = defaultTailReplayInitialDelay
	}
	if observed := e.tailReplayObservedDelay(); observed > initial {
		initial = observed
	}
	maximum := e.tailReplayMaxBackoff
	if maximum < initial {
		maximum = initial
	}
	return initial, maximum
}

func (e *Engine) tailReplayObservedDelay() time.Duration {
	mode := e.mode.Load()
	e.pathsMu.RLock()
	slots := make([]*pathSlot, 0, len(e.paths))
	for id, slot := range e.paths {
		if mode == dispatchSelector && id != e.activeID {
			continue
		}
		if mode != dispatchSelector && len(e.dispatchScope) != 0 && !e.dispatchScope[id] {
			continue
		}
		slots = append(slots, slot)
	}
	e.pathsMu.RUnlock()

	observed := time.Duration(0)
	for _, slot := range slots {
		delay := boundedTailReplayQualityDelay(tailReplayProbeQuality(slot))
		if delay == 0 {
			continue
		}
		if mode == dispatchRace {
			if observed == 0 || delay < observed {
				observed = delay
			}
			continue
		}
		// A bond frame may have used any eligible child, while a selector has
		// exactly one active child. The conservative maximum prevents either
		// mode from retransmitting before its healthy carrier can ACK.
		if delay > observed {
			observed = delay
		}
	}
	return observed
}

func tailReplayProbeQuality(slot *pathSlot) transport.PathQuality {
	if slot == nil {
		return transport.PathQuality{}
	}
	evidence := slot.probeEvidence.Load()
	if evidence == nil || evidence.generation != pathProbeGenerationForSlot(slot) ||
		evidence.succeeded == 0 || evidence.lastSuccess.IsZero() {
		return transport.PathQuality{}
	}
	return evidence.quality
}

func boundedTailReplayQualityDelay(quality transport.PathQuality) time.Duration {
	if quality.RTT <= 0 {
		return 0
	}
	delay := time.Duration(0)
	for _, component := range []time.Duration{quality.RTT, quality.RTT, quality.Jitter, quality.Jitter} {
		if component <= 0 {
			continue
		}
		if component >= maximumTailReplayInitialDelay-delay {
			return maximumTailReplayInitialDelay
		}
		delay += component
	}
	if delay > maximumTailReplayInitialDelay {
		return maximumTailReplayInitialDelay
	}
	return delay
}

// armTailReplay publishes no new work. It only gives the existing replay
// worker a bounded lease over [ackNext,target), resetting the idle timer when a
// newer frame is published. Consequently a busy stream relies on normal
// cumulative gap repair, while its final unacknowledged frame gets an explicit
// recovery trigger once publication becomes idle.
func (e *Engine) armTailReplay(target uint64) {
	if target == 0 || e.isClosed() {
		return
	}
	ackNext := e.sendAckNext.Load()
	if ackNext >= target {
		return
	}
	now := nowFn()
	initial, _ := e.tailReplayTiming()
	deadline := now.Add(e.limits.MigrationBudget)
	due := now.Add(initial)
	if due.After(deadline) {
		due = deadline
	}

	e.replayMu.Lock()
	if !e.tailReplay.armed || target > e.tailReplay.target {
		e.tailReplay = tailReplayLease{
			target:   target,
			ackNext:  ackNext,
			due:      due,
			deadline: deadline,
			backoff:  initial,
			armed:    true,
		}
	}
	e.replayMu.Unlock()
	e.wakeReplayWorker()
}

func (e *Engine) armTailReplayForFrame(frame []byte, target uint64) {
	if len(frame) < proto.HeaderSize {
		return
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return
	}
	// A stream PathConn already promises reliable ordered bytes. Speculative
	// DATA replay on a healthy stream can only create framed duplicates; real
	// carrier failure is repaired from the ledger during migration. Packet
	// sessions still need tail repair, while sequenced control convergence is
	// required for both session kinds.
	if header.Type == proto.FrameData && !e.Packetized() {
		return
	}
	e.armTailReplay(target)
}

// noteTailReplayAck cancels a completed lease and restarts pacing only when the
// cumulative ACK actually advances. Duplicate/stale ACKs cannot indefinitely
// postpone recovery of a still-unacknowledged tail.
func (e *Engine) noteTailReplayAck(nextSeq uint64) {
	now := nowFn()
	initial, _ := e.tailReplayTiming()
	changed := false
	e.replayMu.Lock()
	if e.tailReplay.armed {
		switch {
		case nextSeq >= e.tailReplay.target:
			e.tailReplay = tailReplayLease{}
			changed = true
		case nextSeq > e.tailReplay.ackNext:
			e.tailReplay.ackNext = nextSeq
			e.tailReplay.backoff = initial
			e.tailReplay.due = now.Add(initial)
			if e.tailReplay.due.After(e.tailReplay.deadline) {
				e.tailReplay.due = e.tailReplay.deadline
			}
			changed = true
		}
	}
	e.replayMu.Unlock()
	if changed {
		e.wakeReplayWorker()
	}
}

func (e *Engine) wakeReplayWorker() {
	select {
	case e.replayWake <- struct{}{}:
	default:
	}
}

func (e *Engine) cancelTailReplay() {
	e.replayMu.Lock()
	e.tailReplay = tailReplayLease{}
	e.replayMu.Unlock()
}

// tailReplayDue returns the sole timer deadline. Expiry is intentionally
// silent: it neither fabricates a migration nor turns a healthy carrier's
// missing application ACK into an application-visible error.
func (e *Engine) tailReplayDue(now time.Time) (time.Time, bool) {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	if !e.tailReplay.armed {
		return time.Time{}, false
	}
	if e.sendAckNext.Load() >= e.tailReplay.target || !now.Before(e.tailReplay.deadline) {
		e.tailReplay = tailReplayLease{}
		return time.Time{}, false
	}
	return e.tailReplay.due, true
}

// takeTailReplayAttempt advances the one timer lease before dispatch. At most
// one attempt can therefore exist, even if thousands of publications coalesce
// while the worker is busy.
func (e *Engine) takeTailReplayAttempt(now time.Time) (uint64, bool) {
	initial, maximum := e.tailReplayTiming()
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	lease := &e.tailReplay
	if !lease.armed || e.sendAckNext.Load() >= lease.target || !now.Before(lease.deadline) {
		*lease = tailReplayLease{}
		return 0, false
	}
	if now.Before(lease.due) {
		return 0, false
	}
	backoff := lease.backoff
	if backoff <= 0 {
		backoff = initial
	}
	nextBackoff := backoff * 2
	if nextBackoff < backoff || nextBackoff > maximum {
		nextBackoff = maximum
	}
	lease.backoff = nextBackoff
	lease.due = now.Add(nextBackoff)
	if lease.due.After(lease.deadline) {
		lease.due = lease.deadline
	}
	return lease.target, true
}

func (e *Engine) tailReplayAttemptCurrent(target uint64) bool {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	return e.tailReplay.armed && e.tailReplay.target == target &&
		e.sendAckNext.Load() < target && nowFn().Before(e.tailReplay.deadline)
}

// replayTailFrame retransmits only target-1, not the whole unacknowledged
// window. If an earlier frame is missing, this final frame elicits the normal
// cumulative gap repair; if the final frame itself was lost, it repairs it
// directly. This bounds duplicate traffic to one immutable ledger frame per
// backoff interval.
func (e *Engine) replayTailFrame(target uint64) {
	if target == 0 {
		return
	}
	seq := target - 1
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	if e.isClosed() || !e.tailReplayAttemptCurrent(target) {
		return
	}
	frame := e.sendHistoryFrame(seq)
	if len(frame) == 0 {
		return
	}
	if hook := e.tailReplayBeforeDispatch; hook != nil {
		hook(seq, target)
	}
	// ACK processing does not take sendMu. Recheck after the deterministic hook
	// and immediately before dispatch so an already-advanced ACK suppresses a
	// stale retry. A truly concurrent ACK may still race the carrier write; the
	// receive sequencer's normal duplicate filter makes that harmless.
	if e.isClosed() || !e.tailReplayAttemptCurrent(target) {
		return
	}
	// Every retry remains policy-neutral. Existing path ownership and
	// migration-budget handling decide whether a real transport failure is
	// terminal; this worker never publishes its own application error.
	_ = e.dispatchReplayFrameLocked(frame)
}
