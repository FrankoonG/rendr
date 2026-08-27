package engine

import (
	"errors"
	"sync"
	"sync/atomic"
)

const (
	externalPathRetirementOperation   = "PathConn.Retirement"
	externalPathRetirementWorkerLimit = externalPathDurableCallbackWorkerLimit
	externalPathRetirementPermitLimit = externalPathDurableCallbackClassLimit
)

type externalPathRetirementPermit struct {
	executor *externalPathRetirementExecutor
	once     sync.Once
	active   atomic.Bool
}

type externalPathRetirementJob struct {
	engine *Engine
	slot   *pathSlot
	permit *externalPathRetirementPermit
	next   *externalPathRetirementJob
}

// externalPathRetirementExecutor bounds trusted retirement continuations that
// may wait for hostile carrier callbacks or per-path reader/writer/prober
// shutdown. A path reserves its independent retirement permit before admission
// and keeps it through the entire reaper job. Cleanup callback completion can
// therefore never recycle the authority that bounds this queue.
type externalPathRetirementExecutor struct {
	mu          sync.Mutex
	head        *externalPathRetirementJob
	tail        *externalPathRetirementJob
	queued      int
	inflight    int
	permitLimit int
	workerLimit chan struct{}
	stopOnce    sync.Once
	stopped     bool
	running     bool
}

var externalPathRetirements = newExternalPathRetirementExecutor(
	externalPathRetirementPermitLimit,
	externalPathRetirementWorkerLimit,
)

func newExternalPathRetirementExecutor(permitLimit, workerLimit int) *externalPathRetirementExecutor {
	return &externalPathRetirementExecutor{
		permitLimit: permitLimit,
		workerLimit: make(chan struct{}, workerLimit),
	}
}

func (executor *externalPathRetirementExecutor) reserve() (*externalPathRetirementPermit, error) {
	if executor == nil || executor.permitLimit <= 0 {
		return nil, errors.New("engine: invalid external path retirement executor")
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.stopped {
		return nil, errors.New("engine: external path retirement executor is stopped")
	}
	if executor.inflight >= executor.permitLimit {
		return nil, &pathDispatchCallbackCapacityError{operation: externalPathRetirementOperation}
	}
	executor.inflight++
	permit := &externalPathRetirementPermit{executor: executor}
	permit.active.Store(true)
	return permit, nil
}

func (permit *externalPathRetirementPermit) release() {
	if permit == nil || permit.executor == nil {
		return
	}
	permit.once.Do(func() {
		permit.active.Store(false)
		permit.executor.mu.Lock()
		if permit.executor.inflight <= 0 {
			permit.executor.mu.Unlock()
			panic("engine: external path retirement permit underflow")
		}
		permit.executor.inflight--
		permit.executor.mu.Unlock()
	})
}

func (executor *externalPathRetirementExecutor) owns(permit *externalPathRetirementPermit) bool {
	return executor != nil && permit != nil && permit.executor == executor && permit.active.Load()
}

func (executor *externalPathRetirementExecutor) enqueue(engine *Engine, slot *pathSlot) error {
	if executor == nil || engine == nil || slot == nil {
		return errors.New("engine: invalid external path retirement job")
	}
	if !slot.retireTracked.Load() || !slot.retireStarted.Load() {
		return errors.New("engine: external path retirement lacks a tracked ticket")
	}
	permit := slot.retirementPermit
	if !executor.owns(permit) {
		return errors.New("engine: external path retirement lacks an active process permit")
	}
	job := &externalPathRetirementJob{engine: engine, slot: slot, permit: permit}
	executor.mu.Lock()
	if !executor.owns(permit) {
		executor.mu.Unlock()
		return errors.New("engine: external path retirement permit was released before queue admission")
	}
	if executor.queued >= executor.inflight {
		executor.mu.Unlock()
		return errors.New("engine: external path retirement queue exceeded active permits")
	}
	if executor.stopped {
		executor.mu.Unlock()
		permit.release()
		return errors.New("engine: external path retirement executor is stopped")
	}
	if executor.tail == nil {
		executor.head = job
	} else {
		executor.tail.next = job
	}
	executor.tail = job
	executor.queued++
	startDispatcher := !executor.running
	if startDispatcher {
		executor.running = true
	}
	executor.mu.Unlock()
	if startDispatcher {
		go executor.dispatch()
	}
	return nil
}

func (executor *externalPathRetirementExecutor) activePermits() int {
	if executor == nil {
		return 0
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.inflight
}

func (executor *externalPathRetirementExecutor) shutdown() {
	if executor == nil {
		return
	}
	executor.stopOnce.Do(func() {
		executor.mu.Lock()
		executor.stopped = true
		executor.mu.Unlock()
	})
}

func (executor *externalPathRetirementExecutor) dispatch() {
	for {
		job := executor.dequeue()
		if job == nil {
			return
		}
		executor.workerLimit <- struct{}{}
		go func() {
			defer func() { <-executor.workerLimit }()
			job.run()
		}()
	}
}

func (executor *externalPathRetirementExecutor) dequeue() *externalPathRetirementJob {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	job := executor.head
	if job == nil {
		executor.running = false
		return nil
	}
	executor.head = job.next
	job.next = nil
	executor.queued--
	if executor.head == nil {
		executor.tail = nil
	}
	return job
}

func (job *externalPathRetirementJob) run() {
	defer func() {
		job.engine.retireDebugMu.Lock()
		delete(job.engine.retireDebug, job.slot)
		job.engine.retireDebugMu.Unlock()
		job.permit.release()
		job.engine.retireWG.Done()
	}()
	job.engine.retireSupersededPath(job.slot)
}
