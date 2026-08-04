package engine

import (
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const pathDispatchQueueSize = 64

type pathDispatchJob struct {
	frame  []byte
	bonded bool
	result chan<- pathDispatchResult
}

type pathDispatchResult struct {
	slot *pathSlot
	err  error
}

func (s *pathSlot) submitDispatch(job pathDispatchJob) bool {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if s.dispatchDead {
		return false
	}
	select {
	case s.dispatchQ <- job:
		return true
	default:
		return false
	}
}

func (e *Engine) pathWriterLoop(slot *pathSlot) {
	defer close(slot.doneW)
	for {
		select {
		case job := <-slot.dispatchQ:
			e.executePathDispatch(slot, job)
		case <-slot.quit:
			e.rejectQueuedDispatches(slot)
			return
		case <-e.closed:
			e.rejectQueuedDispatches(slot)
			return
		}
	}
}

func (e *Engine) executePathDispatch(slot *pathSlot, job pathDispatchJob) {
	n, err := slot.writeFrame(job.frame)
	if err == nil && n != len(job.frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		slot.recordDispatch(job.frame)
		if job.bonded {
			slot.rememberBondFrame(job.frame)
		}
	} else {
		// Some third-party PathConn implementations cannot reliably invoke
		// OnDeath after a failed Write. The generation check makes this
		// synthetic report idempotent with a concurrent transport callback.
		e.onPathDeath(slot.id, slot.gen, transport.CauseTransportError, err)
	}
	job.result <- pathDispatchResult{slot: slot, err: err}
}

func (e *Engine) rejectQueuedDispatches(slot *pathSlot) {
	for {
		select {
		case job := <-slot.dispatchQ:
			job.result <- pathDispatchResult{slot: slot, err: net.ErrClosed}
		default:
			return
		}
	}
}

func (e *Engine) dispatchRecursive(frame []byte, runtime *executionRuntime) error {
	deadline := nowFn().Add(e.limits.MigrationBudget)
	for {
		if e.isClosed() {
			return net.ErrClosed
		}
		e.pathsMu.RLock()
		attached := make(map[proto.TargetID]bool, len(e.paths))
		latest := make(map[proto.TargetID]*pathSlot, len(e.paths))
		qualities := make(map[proto.TargetID]transport.PathQuality, len(e.paths))
		for _, slot := range e.paths {
			if slot.localTXTargetID == (proto.TargetID{}) {
				continue
			}
			attached[slot.localTXTargetID] = true
			if previous := latest[slot.localTXTargetID]; previous == nil || slot.gen > previous.gen {
				latest[slot.localTXTargetID] = slot
				qualities[slot.localTXTargetID] = slot.conn.Quality()
			}
		}
		e.pathsMu.RUnlock()

		ticket, err := runtime.buildTicketObserved(attached, qualities, e.Packetized(), e.bondPinSize, e.limits.BondStuckRTTMultiplier)
		if err != nil {
			if err != errNoExecutionRoute {
				return err
			}
			if err := e.waitForExecutionProgress(deadline); err != nil {
				return err
			}
			continue
		}

		results := make(chan pathDispatchResult, len(ticket.routes))
		submitted := 0
		for _, route := range ticket.routes {
			slot := latest[route.targetID]
			if slot == nil {
				continue
			}
			if slot.submitDispatch(pathDispatchJob{frame: frame, bonded: route.bonded, result: results}) {
				submitted++
			}
		}
		if submitted == 0 {
			if err := e.waitForExecutionProgress(deadline); err != nil {
				return err
			}
			continue
		}

		remainingBudget := deadline.Sub(nowFn())
		if remainingBudget <= 0 {
			return e.executionBudgetExceeded()
		}
		budgetTimer := time.NewTimer(remainingBudget)
		for remaining := submitted; remaining > 0; remaining-- {
			select {
			case result := <-results:
				if result.err == nil {
					if !budgetTimer.Stop() {
						select {
						case <-budgetTimer.C:
						default:
						}
					}
					return nil
				}
			case <-e.closed:
				budgetTimer.Stop()
				return net.ErrClosed
			case <-budgetTimer.C:
				return e.executionBudgetExceeded()
			}
		}
		budgetTimer.Stop()
		if err := e.waitForExecutionProgress(deadline); err != nil {
			return err
		}
	}
}

func (e *Engine) waitForExecutionProgress(deadline time.Time) error {
	if !nowFn().Before(deadline) {
		return e.executionBudgetExceeded()
	}
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-e.closed:
		if err := e.CloseErr(); err != nil {
			return err
		}
		return net.ErrClosed
	case <-timer.C:
		return nil
	}
}

func (e *Engine) executionBudgetExceeded() error {
	e.setCloseErr(ErrMigrationBudgetExceeded)
	go e.Close()
	return ErrMigrationBudgetExceeded
}
