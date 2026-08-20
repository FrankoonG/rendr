package engine

import (
	"errors"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

const (
	policyReplayRecordLimit = 2 * (policyCompletedLimit + 1)
	policyReplayByteLimit   = policyReplayRecordLimit * (proto.HeaderSize + MaxPayload)
)

type policyReplayKey struct {
	transactionID [16]byte
	phase         proto.PolicyAckPhase
}

// policyReplayRecord is the explicit post-ACK owner of one immutable policy
// response. Its separate bounded credit lets the ordinary replay ledger retire
// without turning completed-transaction bytes into unaccounted storage.
type policyReplayRecord struct {
	key                   policyReplayKey
	reserved              int
	frame                 []byte
	seq                   uint64
	digest                proto.FrameDigest
	lastTry               time.Time
	inFlight              bool
	deferred              bool
	deferredRunning       bool
	deferredWake          chan struct{}
	deferredStop          chan struct{}
	deferredDone          chan struct{}
	deferredWait          policyReplayWaitFactory
	deferredBeforeCleanup func()
	retired               bool
	released              bool
}

type policyReplayLease struct {
	record *policyReplayRecord
	frame  []byte
}

type policyReplayWait struct {
	ready <-chan time.Time
	stop  func() bool
}

type policyReplayWaitFactory func(time.Duration) policyReplayWait

func newPolicyReplayWait(delay time.Duration) policyReplayWait {
	timer := time.NewTimer(delay)
	return policyReplayWait{ready: timer.C, stop: timer.Stop}
}

func (e *Engine) reservePolicyReplayRecord(
	transactionID [16]byte,
	phase proto.PolicyAckPhase,
	frameBytes int,
) (*policyReplayRecord, error) {
	if phase != proto.PolicyAckPhasePrepare && phase != proto.PolicyAckPhaseFinal {
		return nil, fmt.Errorf("engine: invalid policy replay phase %d", phase)
	}
	if frameBytes <= proto.HeaderSize || frameBytes > proto.HeaderSize+MaxPayload {
		return nil, errors.New("engine: invalid policy replay byte credit request")
	}
	key := policyReplayKey{transactionID: transactionID, phase: phase}
	e.policyReplayMu.Lock()
	defer e.policyReplayMu.Unlock()
	if existing := e.policyReplayRecords[key]; existing != nil && !existing.retired {
		return nil, errors.New("engine: policy replay owner already exists")
	}
	if e.policyReplayCount >= policyReplayRecordLimit ||
		e.policyReplayBytes > policyReplayByteLimit-frameBytes {
		return nil, errors.New("engine: policy replay cache capacity exceeded")
	}
	record := &policyReplayRecord{
		key:          key,
		reserved:     frameBytes,
		deferredWake: make(chan struct{}, 1),
		deferredStop: make(chan struct{}),
	}
	e.policyReplayRecords[key] = record
	e.policyReplayCount++
	e.policyReplayBytes += frameBytes
	return record, nil
}

func (e *Engine) bindPolicyReplayRecord(record *policyReplayRecord, frame []byte) error {
	if record == nil || len(frame) != record.reserved {
		return errors.New("engine: policy replay frame does not match reserved credit")
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return err
	}
	if header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlPolicyAck {
		return errors.New("engine: policy replay owner bound to non-ACK frame")
	}
	ack, err := proto.DecodePolicyAck(frame[proto.HeaderSize:])
	if err != nil {
		return err
	}
	if ack.TransactionID != record.key.transactionID || ack.Phase != record.key.phase {
		return errors.New("engine: policy replay owner identity mismatch")
	}
	e.policyReplayMu.Lock()
	defer e.policyReplayMu.Unlock()
	if record.retired || e.policyReplayRecords[record.key] != record {
		return errors.New("engine: policy replay owner retired before publication")
	}
	if len(record.frame) != 0 {
		return errors.New("engine: policy replay owner bound more than once")
	}
	record.frame = append([]byte(nil), frame...)
	record.seq = header.Seq
	record.digest = proto.DigestFrame(frame)
	return nil
}

func (e *Engine) markPolicyReplayPublished(record *policyReplayRecord, at time.Time) {
	if record == nil {
		return
	}
	e.policyReplayMu.Lock()
	if !record.retired && len(record.frame) != 0 {
		record.lastTry = at
	}
	e.policyReplayMu.Unlock()
}

func (e *Engine) acquirePolicyReplay(record *policyReplayRecord, now time.Time) (policyReplayLease, bool) {
	if record == nil {
		return policyReplayLease{}, false
	}
	e.policyReplayMu.Lock()
	defer e.policyReplayMu.Unlock()
	if record.retired || len(record.frame) == 0 ||
		e.policyReplayRecords[record.key] != record {
		return policyReplayLease{}, false
	}
	if record.inFlight || !policyReplayEligible(record, now) {
		e.deferPolicyReplayLocked(record)
		return policyReplayLease{}, false
	}
	record.deferred = false
	notifyPolicyReplayWorkerLocked(record)
	record.inFlight = true
	record.lastTry = now
	return policyReplayLease{record: record, frame: record.frame}, true
}

func policyReplayEligible(record *policyReplayRecord, now time.Time) bool {
	return record.lastTry.IsZero() || !now.Before(record.lastTry.Add(policyRetryInterval))
}

func (e *Engine) deferPolicyReplayLocked(record *policyReplayRecord) {
	if record == nil || record.retired || e.policyReplayRecords[record.key] != record {
		return
	}
	record.deferred = true
	if !record.deferredRunning {
		record.deferredRunning = true
		record.deferredDone = make(chan struct{})
		done := record.deferredDone
		e.coreWG.Add(1)
		go e.runDeferredPolicyReplay(record, done)
		return
	}
	notifyPolicyReplayWorkerLocked(record)
}

func notifyPolicyReplayWorkerLocked(record *policyReplayRecord) {
	if record == nil || record.deferredWake == nil {
		return
	}
	select {
	case record.deferredWake <- struct{}{}:
	default:
	}
}

func (e *Engine) runDeferredPolicyReplay(record *policyReplayRecord, done chan struct{}) {
	defer e.coreWG.Done()
	defer close(done)
	defer func() {
		e.policyReplayMu.Lock()
		if record.deferredDone == done {
			record.deferredRunning = false
			record.deferredDone = nil
		}
		if record.retired && !record.inFlight {
			e.releasePolicyReplayCreditLocked(record)
		}
		e.policyReplayMu.Unlock()
	}()

	for {
		now := e.policyReplayTime()
		e.policyReplayMu.Lock()
		if record.retired || e.policyReplayRecords[record.key] != record {
			e.policyReplayMu.Unlock()
			return
		}
		if !record.deferred {
			beforeCleanup := record.deferredBeforeCleanup
			record.deferredBeforeCleanup = nil
			e.policyReplayMu.Unlock()
			if beforeCleanup != nil {
				beforeCleanup()
			}
			// A duplicate can arrive after the empty check while this worker still
			// owns deferredRunning. Recheck before relinquishing that ownership.
			if e.continueDeferredPolicyReplayBeforeCleanup(record, done) {
				continue
			}
			return
		}
		wake, stop := record.deferredWake, record.deferredStop
		drainPolicyReplayWakeLocked(record)
		if record.inFlight {
			e.policyReplayMu.Unlock()
			select {
			case <-wake:
			case <-stop:
				return
			case <-e.closed:
				return
			}
			continue
		}
		if policyReplayEligible(record, now) {
			record.deferred = false
			record.inFlight = true
			record.lastTry = now
			lease := policyReplayLease{record: record, frame: record.frame}
			e.policyReplayMu.Unlock()
			_ = e.replaySequencedFrame(lease.frame)
			e.finishPolicyReplay(lease)
			continue
		}
		delay := record.lastTry.Add(policyRetryInterval).Sub(now)
		waitFactory := record.deferredWait
		e.policyReplayMu.Unlock()

		var wait policyReplayWait
		if waitFactory == nil {
			wait = newPolicyReplayWait(delay)
		} else {
			wait = waitFactory(delay)
		}
		select {
		case <-wait.ready:
		case <-wake:
		case <-stop:
			if wait.stop != nil {
				wait.stop()
			}
			return
		case <-e.closed:
			if wait.stop != nil {
				wait.stop()
			}
			return
		}
		if wait.stop != nil {
			wait.stop()
		}
	}
}

func (e *Engine) continueDeferredPolicyReplayBeforeCleanup(
	record *policyReplayRecord,
	done chan struct{},
) bool {
	e.policyReplayMu.Lock()
	defer e.policyReplayMu.Unlock()
	if record.deferredDone != done {
		return false
	}
	if !record.retired && e.policyReplayRecords[record.key] == record && record.deferred {
		return true
	}
	record.deferredRunning = false
	record.deferredDone = nil
	if record.retired && !record.inFlight {
		e.releasePolicyReplayCreditLocked(record)
	}
	return false
}

func drainPolicyReplayWakeLocked(record *policyReplayRecord) {
	if record == nil || record.deferredWake == nil {
		return
	}
	select {
	case <-record.deferredWake:
	default:
	}
}

func (e *Engine) finishPolicyReplay(lease policyReplayLease) {
	if lease.record == nil {
		return
	}
	e.policyReplayMu.Lock()
	if !lease.record.inFlight {
		e.policyReplayMu.Unlock()
		panic("engine: policy replay lease finished without ownership")
	}
	lease.record.inFlight = false
	if lease.record.deferred {
		notifyPolicyReplayWorkerLocked(lease.record)
	}
	if lease.record.retired && !lease.record.deferredRunning {
		e.releasePolicyReplayCreditLocked(lease.record)
	}
	e.policyReplayMu.Unlock()
}

func (e *Engine) replayPolicyRecord(record *policyReplayRecord) error {
	lease, ok := e.acquirePolicyReplay(record, e.policyReplayTime())
	if !ok {
		return nil
	}
	defer e.finishPolicyReplay(lease)
	return e.replaySequencedFrame(lease.frame)
}

func (e *Engine) policyReplayTime() time.Time {
	if e != nil && e.policyReplayNow != nil {
		return e.policyReplayNow()
	}
	return nowFn()
}

func (e *Engine) retirePolicyReplayRecord(record *policyReplayRecord) {
	if record == nil {
		return
	}
	e.policyReplayMu.Lock()
	if record.retired {
		e.policyReplayMu.Unlock()
		return
	}
	record.retired = true
	record.deferred = false
	close(record.deferredStop)
	if e.policyReplayRecords[record.key] == record {
		delete(e.policyReplayRecords, record.key)
	}
	if !record.inFlight && !record.deferredRunning {
		e.releasePolicyReplayCreditLocked(record)
	}
	e.policyReplayMu.Unlock()
}

func (e *Engine) releasePolicyReplayCreditLocked(record *policyReplayRecord) {
	if record == nil || record.released {
		return
	}
	if e.policyReplayCount <= 0 || record.reserved <= 0 || record.reserved > e.policyReplayBytes {
		panic("engine: policy replay credit invariant violated")
	}
	record.released = true
	e.policyReplayCount--
	e.policyReplayBytes -= record.reserved
}

func (e *Engine) releasePolicyReplayStateOnClose() {
	e.policyReplayMu.Lock()
	for key, record := range e.policyReplayRecords {
		delete(e.policyReplayRecords, key)
		record.retired = true
		record.deferred = false
		close(record.deferredStop)
		if !record.inFlight && !record.deferredRunning {
			e.releasePolicyReplayCreditLocked(record)
		}
	}
	e.policyReplayMu.Unlock()
}
