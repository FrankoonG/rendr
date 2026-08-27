package engine

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

const (
	externalPathValueCallbackTimeout        = 50 * time.Millisecond
	externalPathErrorCallbackTimeout        = pathCloseTimeout
	externalPathCloseOperation              = "PathConn.Close"
	externalPathReadOperation               = "PathConn.Read"
	externalPathWriteOperation              = "PathConn.Write"
	externalPathCallbackClassLimit          = 64
	externalPathAdmissionCallbackClassLimit = 2 * externalPathCallbackClassLimit
	externalPathDurableCallbackWorkerLimit  = externalPathCallbackClassLimit
	// A runtime may own DefaultBridgeTableCapacity sessions. Make-before-break
	// admission permits one transient generation beyond maxSessionPaths. Durable
	// authority therefore cannot share the much smaller execution pool. The
	// reservation limit also bounds each durable execution queue.
	externalPathDurableCallbackClassLimit = DefaultBridgeTableCapacity * (maxSessionPaths + 1)
	externalPathDurableEventClassLimit    = 2 * externalPathDurableCallbackClassLimit
)

type externalPathCallbackClass uint8

const (
	externalPathCallbackOptional externalPathCallbackClass = iota
	externalPathCallbackLifecycle
	externalPathCallbackCleanup
	externalPathCallbackAdmission
	externalPathCallbackClassCount
)

var externalPathCallbackClassLimits = [externalPathCallbackClassCount]int{
	externalPathCallbackOptional:  externalPathCallbackClassLimit,
	externalPathCallbackLifecycle: externalPathCallbackClassLimit,
	externalPathCallbackCleanup:   externalPathCallbackClassLimit,
	externalPathCallbackAdmission: externalPathAdmissionCallbackClassLimit,
}

type externalPathCallbackKey struct {
	operation  string
	targetType reflect.Type
	target     any
	invocation uint64
}

type externalPathCallbackLease struct {
	key   externalPathCallbackKey
	class externalPathCallbackClass
	once  sync.Once
	done  chan struct{}
	owner *externalPathCallbackOwner
}

// externalPathCallbackOwner is the lifetime authority for callbacks started by
// one exact path generation. Retirement closes admission before waiting, so a
// callback observed under pathsMu either joins this owner or is rejected after
// the generation leaves the topology.
type externalPathCallbackOwner struct {
	marker byte

	mu           sync.Mutex
	active       int
	retired      bool
	drained      chan struct{}
	drainedClose bool
	drainHooks   []func()
}

func (owner *externalPathCallbackOwner) ensureDrainedLocked() chan struct{} {
	if owner.drained == nil {
		owner.drained = make(chan struct{})
	}
	return owner.drained
}

func (owner *externalPathCallbackOwner) acquire(operation string) error {
	if owner == nil {
		return &externalPathDurableCallbackStateError{
			operation: operation,
			action:    "invoke without exact-generation callback authority",
			state:     externalPathDurableCallbackReleased,
		}
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.ensureDrainedLocked()
	if owner.retired {
		return &externalPathDurableCallbackStateError{
			operation: operation,
			action:    "invoke after exact-generation retirement",
			state:     externalPathDurableCallbackReleased,
		}
	}
	owner.active++
	return nil
}

func (owner *externalPathCallbackOwner) release() {
	if owner == nil {
		return
	}
	var hooks []func()
	owner.mu.Lock()
	if owner.active <= 0 {
		owner.mu.Unlock()
		panic("engine: exact-generation callback authority underflow")
	}
	owner.active--
	if owner.retired && owner.active == 0 && !owner.drainedClose {
		owner.drainedClose = true
		close(owner.ensureDrainedLocked())
		hooks = append(hooks, owner.drainHooks...)
		owner.drainHooks = nil
	}
	owner.mu.Unlock()
	for _, hook := range hooks {
		hook()
	}
}

func (owner *externalPathCallbackOwner) onDrained(hook func()) {
	if owner == nil || hook == nil {
		return
	}
	owner.mu.Lock()
	owner.ensureDrainedLocked()
	if owner.retired && owner.active == 0 {
		owner.mu.Unlock()
		hook()
		return
	}
	owner.drainHooks = append(owner.drainHooks, hook)
	owner.mu.Unlock()
}

func (owner *externalPathCallbackOwner) retire() {
	if owner == nil {
		return
	}
	var hooks []func()
	owner.mu.Lock()
	owner.ensureDrainedLocked()
	owner.retired = true
	if owner.active == 0 && !owner.drainedClose {
		owner.drainedClose = true
		close(owner.drained)
		hooks = append(hooks, owner.drainHooks...)
		owner.drainHooks = nil
	}
	owner.mu.Unlock()
	for _, hook := range hooks {
		hook()
	}
}

func (owner *externalPathCallbackOwner) waitRetired() {
	if owner == nil {
		return
	}
	owner.retire()
	owner.mu.Lock()
	drained := owner.ensureDrainedLocked()
	owner.mu.Unlock()
	<-drained
}

var externalPathCallbacks = struct {
	sync.Mutex
	inflight      map[externalPathCallbackKey]*externalPathCallbackLease
	classInflight [externalPathCallbackClassCount]int
}{inflight: make(map[externalPathCallbackKey]*externalPathCallbackLease)}

var externalPathCallbackInvocation atomic.Uint64

type externalPathDurableCallbackReservation struct {
	operation       string
	key             externalPathCallbackKey
	class           externalPathDurableCallbackClass
	state           atomic.Uint32
	done            chan struct{}
	completionMu    sync.Mutex
	terminalErr     error
	terminalSet     bool
	boundedDeadline bool
	finalized       bool
	hooks           []externalPathDurableCallbackCompletionHook
	released        atomic.Bool
	deadlineSet     atomic.Bool
}

type externalPathDurableCallbackJob struct {
	reservation *externalPathDurableCallbackReservation
	callback    func() error
	next        *externalPathDurableCallbackJob
}

type externalPathDurableCallbackState uint32

const (
	externalPathDurableCallbackReserved externalPathDurableCallbackState = iota
	externalPathDurableCallbackQueued
	externalPathDurableCallbackCompleted
	externalPathDurableCallbackReleased
)

func (state externalPathDurableCallbackState) String() string {
	switch state {
	case externalPathDurableCallbackReserved:
		return "reserved"
	case externalPathDurableCallbackQueued:
		return "queued"
	case externalPathDurableCallbackCompleted:
		return "completed"
	case externalPathDurableCallbackReleased:
		return "released"
	default:
		return fmt.Sprintf("unknown(%d)", state)
	}
}

type externalPathDurableCallbackStateError struct {
	operation string
	action    string
	state     externalPathDurableCallbackState
}

func (err *externalPathDurableCallbackStateError) Error() string {
	return fmt.Sprintf("engine: external callback %s cannot %s from %s state",
		err.operation, err.action, err.state)
}

type externalPathDurableCallbackCompletion struct {
	State    externalPathDurableCallbackState
	Terminal error
}

type externalPathDurableCallbackCompletionHook func(externalPathDurableCallbackCompletion)

// externalPathDurableCallbackExecutor separates durable ownership from actual
// execution. Its linked queue can grow only as large as the corresponding
// pre-reserved authority class, while one dispatcher admits at most workerLimit
// hostile callbacks concurrently. A callback that calls runtime.Goexit exits
// only its bounded worker. The dispatcher exits when the queue is empty and is
// restarted atomically by the next enqueue.
type externalPathDurableCallbackExecutor struct {
	mu          sync.Mutex
	head        *externalPathDurableCallbackJob
	tail        *externalPathDurableCallbackJob
	queued      int
	queueLimit  int
	workerLimit chan struct{}
	running     bool
}

type externalPathDurableCallbackDeadline struct {
	at          time.Time
	sequence    uint64
	index       int
	reservation *externalPathDurableCallbackReservation
	report      func(error)
}

type externalPathDurableCallbackDeadlineHeap []*externalPathDurableCallbackDeadline

func (deadlines externalPathDurableCallbackDeadlineHeap) Len() int { return len(deadlines) }
func (deadlines externalPathDurableCallbackDeadlineHeap) Less(i, j int) bool {
	if deadlines[i].at.Equal(deadlines[j].at) {
		return deadlines[i].sequence < deadlines[j].sequence
	}
	return deadlines[i].at.Before(deadlines[j].at)
}
func (deadlines externalPathDurableCallbackDeadlineHeap) Swap(i, j int) {
	deadlines[i], deadlines[j] = deadlines[j], deadlines[i]
	deadlines[i].index = i
	deadlines[j].index = j
}
func (deadlines *externalPathDurableCallbackDeadlineHeap) Push(value any) {
	entry := value.(*externalPathDurableCallbackDeadline)
	entry.index = len(*deadlines)
	*deadlines = append(*deadlines, entry)
}
func (deadlines *externalPathDurableCallbackDeadlineHeap) Pop() any {
	old := *deadlines
	last := old[len(old)-1]
	old[len(old)-1] = nil
	*deadlines = old[:len(old)-1]
	last.index = -1
	return last
}

type externalPathDurableCallbackDeadlineScheduler struct {
	mu            sync.Mutex
	entries       externalPathDurableCallbackDeadlineHeap
	byReservation map[*externalPathDurableCallbackReservation]*externalPathDurableCallbackDeadline
	wake          chan struct{}
	running       bool
	sequence      atomic.Uint64
}

// pathAdmissionCleanupTicket owns the interval between accepting a durable
// cleanup reservation and publishing its pathSlot. Close crosses
// sessionEpochMu before waiting on this ticket set, so Add and Wait cannot race.
type pathAdmissionCleanupTicket struct {
	engine            *Engine
	reservation       *externalPathDurableCallbackReservation
	retirementPermit  *externalPathRetirementPermit
	callbackAuthority *externalPathCallbackOwner
	once              sync.Once
}

type externalPathDurableCallbackClass uint8

const (
	externalPathDurableCleanup externalPathDurableCallbackClass = iota
	externalPathDurableCancellation
	externalPathDurableEvent
	externalPathDurableCallbackClassCount
)

var externalPathDurableCallbacks = struct {
	sync.Mutex
	inflight      int
	classInflight [externalPathDurableCallbackClassCount]int
	classLimit    [externalPathDurableCallbackClassCount]int
	owners        map[externalPathCallbackKey]*externalPathDurableCallbackReservation
}{
	classLimit: [externalPathDurableCallbackClassCount]int{
		externalPathDurableCleanup:      externalPathDurableCallbackClassLimit,
		externalPathDurableCancellation: externalPathDurableCallbackClassLimit,
		externalPathDurableEvent:        externalPathDurableEventClassLimit,
	},
	owners: make(map[externalPathCallbackKey]*externalPathDurableCallbackReservation),
}

var externalPathDurableCallbackExecutors = [externalPathDurableCallbackClassCount]*externalPathDurableCallbackExecutor{
	externalPathDurableCleanup: newExternalPathDurableCallbackExecutor(
		externalPathDurableCallbackClassLimit, externalPathDurableCallbackWorkerLimit,
	),
	externalPathDurableCancellation: newExternalPathDurableCallbackExecutor(
		externalPathDurableCallbackClassLimit, externalPathDurableCallbackWorkerLimit,
	),
	externalPathDurableEvent: newExternalPathDurableCallbackExecutor(
		externalPathDurableEventClassLimit, externalPathDurableCallbackWorkerLimit,
	),
}

var externalPathDurableCallbackDeadlines = &externalPathDurableCallbackDeadlineScheduler{
	byReservation: make(map[*externalPathDurableCallbackReservation]*externalPathDurableCallbackDeadline),
	wake:          make(chan struct{}, 1),
}

func newExternalPathDurableCallbackExecutor(
	queueLimit int,
	workerLimit int,
) *externalPathDurableCallbackExecutor {
	return &externalPathDurableCallbackExecutor{
		queueLimit:  queueLimit,
		workerLimit: make(chan struct{}, workerLimit),
	}
}

func (executor *externalPathDurableCallbackExecutor) enqueue(job *externalPathDurableCallbackJob) error {
	if executor == nil || job == nil {
		return &externalPathDurableCallbackStateError{
			operation: "unknown", action: "enqueue a nil executor job",
		}
	}
	if err := job.reservation.validateQueuedAuthority(); err != nil {
		return err
	}
	executor.mu.Lock()
	if executor.queued >= executor.queueLimit {
		executor.mu.Unlock()
		return &externalPathDurableCallbackStateError{
			operation: job.reservation.operation,
			action:    "enqueue beyond the pre-reserved execution bound",
			state:     job.reservation.lifecycleState(),
		}
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

func (executor *externalPathDurableCallbackExecutor) dispatch() {
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

func (executor *externalPathDurableCallbackExecutor) dequeue() *externalPathDurableCallbackJob {
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

func (job *externalPathDurableCallbackJob) run() {
	var terminal error
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			terminal = newPathDispatchCallbackPanicError(job.reservation.operation, recovered)
		} else if !returned {
			terminal = &pathDispatchCallbackGoexitError{operation: job.reservation.operation}
		}
		job.reservation.completeQueued(terminal)
	}()
	terminal = job.callback()
	returned = true
}

func (scheduler *externalPathDurableCallbackDeadlineScheduler) schedule(
	reservation *externalPathDurableCallbackReservation,
	after time.Duration,
	report func(error),
) error {
	if scheduler == nil || reservation == nil || report == nil {
		return &externalPathDurableCallbackStateError{
			operation: "unknown", action: "schedule a nil durable deadline",
			state: externalPathDurableCallbackReleased,
		}
	}
	state := reservation.lifecycleState()
	if state == externalPathDurableCallbackCompleted {
		return nil
	}
	if state != externalPathDurableCallbackQueued {
		return &externalPathDurableCallbackStateError{
			operation: reservation.operation, action: "schedule a deadline", state: state,
		}
	}
	if !reservation.deadlineSet.CompareAndSwap(false, true) {
		return &externalPathDurableCallbackStateError{
			operation: reservation.operation,
			action:    "schedule more than one deadline",
			state:     reservation.lifecycleState(),
		}
	}
	if after <= 0 {
		after = externalPathValueCallbackTimeout
	}
	entry := &externalPathDurableCallbackDeadline{
		at:          time.Now().Add(after),
		sequence:    scheduler.sequence.Add(1),
		index:       -1,
		reservation: reservation,
		report:      report,
	}
	scheduler.mu.Lock()
	if scheduler.byReservation == nil {
		scheduler.byReservation = make(map[*externalPathDurableCallbackReservation]*externalPathDurableCallbackDeadline)
	}
	if _, exists := scheduler.byReservation[reservation]; exists {
		scheduler.mu.Unlock()
		return &externalPathDurableCallbackStateError{
			operation: reservation.operation,
			action:    "schedule more than one deadline",
			state:     reservation.lifecycleState(),
		}
	}
	heap.Push(&scheduler.entries, entry)
	scheduler.byReservation[reservation] = entry
	scheduler.mu.Unlock()
	if err := reservation.onCompletion(func(externalPathDurableCallbackCompletion) {
		scheduler.remove(entry)
	}); err != nil {
		scheduler.remove(entry)
		return err
	}
	scheduler.mu.Lock()
	startDispatcher := len(scheduler.entries) != 0 && !scheduler.running
	if startDispatcher {
		scheduler.running = true
	}
	scheduler.mu.Unlock()
	if startDispatcher {
		go scheduler.dispatch()
	}
	select {
	case scheduler.wake <- struct{}{}:
	default:
	}
	return nil
}

func (scheduler *externalPathDurableCallbackDeadlineScheduler) remove(
	entry *externalPathDurableCallbackDeadline,
) {
	if scheduler == nil || entry == nil {
		return
	}
	scheduler.mu.Lock()
	current := scheduler.byReservation[entry.reservation]
	if current == entry {
		delete(scheduler.byReservation, entry.reservation)
		if entry.index >= 0 {
			heap.Remove(&scheduler.entries, entry.index)
		}
	}
	scheduler.mu.Unlock()
	select {
	case scheduler.wake <- struct{}{}:
	default:
	}
}

func (scheduler *externalPathDurableCallbackDeadlineScheduler) entryCount() int {
	if scheduler == nil {
		return 0
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return len(scheduler.entries)
}

func (scheduler *externalPathDurableCallbackDeadlineScheduler) dispatch() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}
	for {
		scheduler.mu.Lock()
		if len(scheduler.entries) == 0 {
			scheduler.running = false
			scheduler.mu.Unlock()
			return
		}
		next := scheduler.entries[0].at
		scheduler.mu.Unlock()
		wait := time.Until(next)
		if wait > 0 {
			timer.Reset(wait)
			select {
			case <-timer.C:
			case <-scheduler.wake:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			continue
		}
		now := time.Now()
		var due []*externalPathDurableCallbackDeadline
		scheduler.mu.Lock()
		for len(scheduler.entries) > 0 && !scheduler.entries[0].at.After(now) {
			entry := heap.Pop(&scheduler.entries).(*externalPathDurableCallbackDeadline)
			if scheduler.byReservation[entry.reservation] == entry {
				delete(scheduler.byReservation, entry.reservation)
			}
			due = append(due, entry)
		}
		scheduler.mu.Unlock()
		for _, entry := range due {
			if entry.reservation.markBoundedDeadlineIfQueued() {
				entry.report(&pathDispatchCallbackDeadlineError{
					operation: entry.reservation.operation,
					cause:     context.DeadlineExceeded,
				})
			}
		}
	}
}

func classifyExternalPathDurableCallback(operation string) externalPathDurableCallbackClass {
	if operation == leafMobilityRefreshEventOp {
		return externalPathDurableEvent
	}
	if operation == leafMobilityRefreshCancelOp {
		return externalPathDurableCancellation
	}
	return externalPathDurableCleanup
}

func reserveExternalPathDurableCallback(operation string, target any) (*externalPathDurableCallbackReservation, error) {
	key, _ := makeExternalPathCallbackKey(operation, target)
	class := classifyExternalPathDurableCallback(operation)
	externalPathDurableCallbacks.Lock()
	defer externalPathDurableCallbacks.Unlock()
	if _, exists := externalPathDurableCallbacks.owners[key]; exists {
		return nil, &pathDispatchCallbackBusyError{operation: operation}
	}
	if externalPathDurableCallbacks.classInflight[class] >= externalPathDurableCallbacks.classLimit[class] {
		return nil, &pathDispatchCallbackCapacityError{operation: operation}
	}
	externalPathDurableCallbacks.inflight++
	externalPathDurableCallbacks.classInflight[class]++
	reservation := &externalPathDurableCallbackReservation{
		operation: operation, key: key, class: class, done: make(chan struct{}),
	}
	reservation.state.Store(uint32(externalPathDurableCallbackReserved))
	externalPathDurableCallbacks.owners[key] = reservation
	return reservation, nil
}

func reserveExternalPathDurableCallbackAuthority(
	operation string,
	owner *externalPathCallbackOwner,
) (*externalPathDurableCallbackReservation, error) {
	return reserveExternalPathDurableCallbackTargetAuthority(operation, owner, owner)
}

func reserveExternalPathDurableCallbackTargetAuthority(
	operation string,
	target any,
	owner *externalPathCallbackOwner,
) (*externalPathDurableCallbackReservation, error) {
	if err := owner.acquire(operation); err != nil {
		return nil, err
	}
	reservation, err := reserveExternalPathDurableCallback(operation, target)
	if err != nil {
		owner.release()
		return nil, err
	}
	if err := reservation.onCompletion(func(externalPathDurableCallbackCompletion) {
		owner.release()
	}); err != nil {
		_ = reservation.releaseReservation()
		owner.release()
		return nil, err
	}
	return reservation, nil
}

func (reservation *externalPathDurableCallbackReservation) lifecycleState() externalPathDurableCallbackState {
	if reservation == nil {
		return externalPathDurableCallbackReleased
	}
	return externalPathDurableCallbackState(reservation.state.Load())
}

func (reservation *externalPathDurableCallbackReservation) validateQueuedAuthority() error {
	return reservation.validateCountedAuthority(
		externalPathDurableCallbackQueued,
		"enqueue without counted authority",
	)
}

func (reservation *externalPathDurableCallbackReservation) validateReservedAuthority() error {
	return reservation.validateCountedAuthority(
		externalPathDurableCallbackReserved,
		"retire without counted cleanup authority",
	)
}

func (reservation *externalPathDurableCallbackReservation) validateCountedAuthority(
	want externalPathDurableCallbackState,
	action string,
) error {
	if reservation == nil {
		return &externalPathDurableCallbackStateError{
			operation: "unknown", action: "validate nil queued authority",
			state: externalPathDurableCallbackReleased,
		}
	}
	state := reservation.lifecycleState()
	externalPathDurableCallbacks.Lock()
	counted := reservation.class < externalPathDurableCallbackClassCount &&
		externalPathDurableCallbacks.owners[reservation.key] == reservation &&
		externalPathDurableCallbacks.classInflight[reservation.class] > 0
	externalPathDurableCallbacks.Unlock()
	if state != want || !counted {
		return &externalPathDurableCallbackStateError{
			operation: reservation.operation,
			action:    action,
			state:     state,
		}
	}
	return nil
}

func (reservation *externalPathDurableCallbackReservation) releaseReservation() error {
	if reservation == nil {
		return nil
	}
	for {
		state := reservation.lifecycleState()
		switch state {
		case externalPathDurableCallbackReserved:
			if !reservation.state.CompareAndSwap(
				uint32(externalPathDurableCallbackReserved), uint32(externalPathDurableCallbackReleased),
			) {
				continue
			}
			reservation.finalize(externalPathDurableCallbackReleased, nil)
			return nil
		case externalPathDurableCallbackReleased, externalPathDurableCallbackCompleted:
			return nil
		default:
			return &externalPathDurableCallbackStateError{
				operation: reservation.operation, action: "release", state: state,
			}
		}
	}
}

func (reservation *externalPathDurableCallbackReservation) completeQueued(terminal error) bool {
	if reservation == nil || !reservation.state.CompareAndSwap(
		uint32(externalPathDurableCallbackQueued), uint32(externalPathDurableCallbackCompleted),
	) {
		return false
	}
	reservation.finalize(externalPathDurableCallbackCompleted, terminal)
	return true
}

func (reservation *externalPathDurableCallbackReservation) finalize(
	state externalPathDurableCallbackState,
	terminal error,
) {
	reservation.completionMu.Lock()
	if reservation.finalized {
		reservation.completionMu.Unlock()
		return
	}
	reservation.terminalErr = terminal
	reservation.terminalSet = state == externalPathDurableCallbackCompleted
	reservation.finalized = true
	hooks := append([]externalPathDurableCallbackCompletionHook(nil), reservation.hooks...)
	reservation.hooks = nil
	reservation.completionMu.Unlock()

	reservation.released.Store(true)
	externalPathDurableCallbacks.Lock()
	if externalPathDurableCallbacks.owners[reservation.key] == reservation {
		delete(externalPathDurableCallbacks.owners, reservation.key)
		externalPathDurableCallbacks.inflight--
		externalPathDurableCallbacks.classInflight[reservation.class]--
	}
	externalPathDurableCallbacks.Unlock()
	close(reservation.done)
	completion := externalPathDurableCallbackCompletion{State: state, Terminal: terminal}
	for _, hook := range hooks {
		hook(completion)
	}
}

func (reservation *externalPathDurableCallbackReservation) onCompletion(
	hook externalPathDurableCallbackCompletionHook,
) error {
	if reservation == nil || hook == nil {
		return &externalPathDurableCallbackStateError{
			operation: "unknown", action: "register a nil completion hook",
			state: externalPathDurableCallbackReleased,
		}
	}
	reservation.completionMu.Lock()
	if !reservation.finalized {
		reservation.hooks = append(reservation.hooks, hook)
		reservation.completionMu.Unlock()
		return nil
	}
	completion := externalPathDurableCallbackCompletion{
		State: reservation.lifecycleState(), Terminal: reservation.terminalErr,
	}
	reservation.completionMu.Unlock()
	hook(completion)
	return nil
}

func (reservation *externalPathDurableCallbackReservation) completion() <-chan struct{} {
	if reservation == nil || reservation.done == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return reservation.done
}

// lateTerminalError reports a callback error that became known only after the
// bounded invocation had already returned a deadline. Callers wait for
// completion first, so terminalSet is immutable at observation time.
func (reservation *externalPathDurableCallbackReservation) lateTerminalError() error {
	if reservation == nil {
		return nil
	}
	reservation.completionMu.Lock()
	defer reservation.completionMu.Unlock()
	if !reservation.boundedDeadline || !reservation.terminalSet {
		return nil
	}
	return reservation.terminalErr
}

func (reservation *externalPathDurableCallbackReservation) invoke(
	ctx context.Context,
	callback func() error,
) error {
	if reservation == nil {
		return &externalPathDurableCallbackStateError{
			operation: "unknown", action: "invoke nil authority",
			state: externalPathDurableCallbackReleased,
		}
	}
	if err := reservation.start(callback); err != nil {
		return err
	}
	return reservation.wait(ctx)
}

func (reservation *externalPathDurableCallbackReservation) start(callback func() error) error {
	if reservation == nil {
		return &externalPathDurableCallbackStateError{
			operation: "unknown", action: "start nil authority",
			state: externalPathDurableCallbackReleased,
		}
	}
	if !reservation.state.CompareAndSwap(
		uint32(externalPathDurableCallbackReserved), uint32(externalPathDurableCallbackQueued),
	) {
		return &externalPathDurableCallbackStateError{
			operation: reservation.operation,
			action:    "invoke",
			state:     reservation.lifecycleState(),
		}
	}
	err := externalPathDurableCallbackExecutors[reservation.class].enqueue(
		&externalPathDurableCallbackJob{reservation: reservation, callback: callback},
	)
	if err != nil {
		reservation.completeQueued(err)
	}
	return err
}

func (reservation *externalPathDurableCallbackReservation) wait(ctx context.Context) error {
	if reservation == nil {
		return &externalPathDurableCallbackStateError{
			operation: "unknown", action: "wait for nil authority",
			state: externalPathDurableCallbackReleased,
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state := reservation.lifecycleState()
	if state == externalPathDurableCallbackReserved || state == externalPathDurableCallbackReleased {
		return &externalPathDurableCallbackStateError{
			operation: reservation.operation, action: "wait", state: state,
		}
	}
	select {
	case <-reservation.done:
		reservation.completionMu.Lock()
		terminal := reservation.terminalErr
		reservation.completionMu.Unlock()
		return terminal
	case <-ctx.Done():
		select {
		case <-reservation.done:
			reservation.completionMu.Lock()
			terminal := reservation.terminalErr
			reservation.completionMu.Unlock()
			return terminal
		default:
		}
		reservation.completionMu.Lock()
		reservation.boundedDeadline = true
		reservation.completionMu.Unlock()
		return &pathDispatchCallbackDeadlineError{
			operation: reservation.operation,
			cause:     ctx.Err(),
		}
	}
}

func (reservation *externalPathDurableCallbackReservation) markBoundedDeadlineIfQueued() bool {
	if reservation == nil || reservation.lifecycleState() != externalPathDurableCallbackQueued {
		return false
	}
	reservation.completionMu.Lock()
	defer reservation.completionMu.Unlock()
	if reservation.finalized || reservation.lifecycleState() != externalPathDurableCallbackQueued {
		return false
	}
	reservation.boundedDeadline = true
	return true
}

func reserveExternalPathCleanup(conn transport.PathConn) (*externalPathDurableCallbackReservation, error) {
	return reserveExternalPathDurableCallback(externalPathCloseOperation, conn)
}

func (e *Engine) reservePathAdmissionCleanup(
	conn transport.PathConn,
) (*externalPathDurableCallbackReservation, *pathAdmissionCleanupTicket, error) {
	e.sessionEpochMu.Lock()
	defer e.sessionEpochMu.Unlock()
	if e.closing.Load() {
		return nil, nil, net.ErrClosed
	}
	retirementPermit, err := externalPathRetirements.reserve()
	if err != nil {
		return nil, nil, err
	}
	callbackAuthority := &externalPathCallbackOwner{}
	reservation, err := reserveExternalPathDurableCallback(externalPathCloseOperation, callbackAuthority)
	if err != nil {
		retirementPermit.release()
		return nil, nil, err
	}
	e.pathAdmissionCleanupWG.Add(1)
	return reservation, &pathAdmissionCleanupTicket{
		engine: e, reservation: reservation, retirementPermit: retirementPermit,
		callbackAuthority: callbackAuthority,
	}, nil
}

func (ticket *pathAdmissionCleanupTicket) transferToSlot(slot *pathSlot) {
	if ticket == nil || ticket.engine == nil {
		return
	}
	ticket.once.Do(func() {
		if slot == nil {
			ticket.retirementPermit.release()
			ticket.engine.pathAdmissionCleanupWG.Done()
			return
		}
		slot.retirementPermit = ticket.retirementPermit
		slot.callbackAuthority = ticket.callbackAuthority
		ticket.engine.pathAdmissionCleanupWG.Done()
	})
}

func (ticket *pathAdmissionCleanupTicket) reject(conn transport.PathConn) {
	if ticket == nil || ticket.engine == nil {
		return
	}
	ticket.once.Do(func() {
		if err := ticket.reservation.onCompletion(func(completion externalPathDurableCallbackCompletion) {
			ticket.engine.recordTeardownErr(completion.Terminal)
			ticket.retirementPermit.release()
			ticket.engine.pathAdmissionCleanupWG.Done()
		}); err != nil {
			ticket.engine.recordTeardownErr(err)
			ticket.retirementPermit.release()
			ticket.engine.pathAdmissionCleanupWG.Done()
			ticket.callbackAuthority.retire()
			return
		}
		startClose := func() {
			err := closeExternalPathConnReserved(conn, ticket.reservation)
			var deadlineErr *pathDispatchCallbackDeadlineError
			var stateErr *externalPathDurableCallbackStateError
			if errors.As(err, &deadlineErr) || errors.As(err, &stateErr) {
				ticket.engine.recordTeardownErr(err)
			}
		}
		// A timed-out lifecycle callback still owns external code. Do not close
		// its carrier or release retirement capacity until that exact callback
		// has returned; the callback-class bound contains a hostile implementation.
		ticket.callbackAuthority.onDrained(startClose)
		ticket.callbackAuthority.retire()
	})
}

func closeExternalPathConnReserved(
	conn transport.PathConn,
	reservation *externalPathDurableCallbackReservation,
) error {
	if conn == nil {
		if reservation != nil {
			reservation.releaseReservation()
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), externalPathErrorCallbackTimeout)
	defer cancel()
	return reservation.invoke(ctx, conn.Close)
}

func classifyExternalPathCallback(operation string) externalPathCallbackClass {
	switch operation {
	case externalPathCloseOperation:
		return externalPathCallbackCleanup
	case externalPathReadOperation, externalPathWriteOperation:
		return externalPathCallbackAdmission
	case leafMobilityRefreshSubscribeOp, leafMobilityRefreshEventOp, leafMobilityRefreshCommitOp, leafMobilityRefreshCancelOp,
		"PathConn.OnDeath", "PathConn.MarkByeSeen":
		return externalPathCallbackLifecycle
	default:
		return externalPathCallbackOptional
	}
}

func makeExternalPathCallbackKey(operation string, target any) (externalPathCallbackKey, bool) {
	key := externalPathCallbackKey{operation: operation}
	if target == nil {
		return key, true
	}
	targetType := reflect.TypeOf(target)
	key.targetType = targetType
	if targetType.Comparable() {
		key.target = target
		return key, true
	}
	key.invocation = externalPathCallbackInvocation.Add(1)
	return key, false
}

func acquireExternalPathCallbackLease(operation string, target any) (*externalPathCallbackLease, error) {
	key, _ := makeExternalPathCallbackKey(operation, target)
	class := classifyExternalPathCallback(operation)
	externalPathCallbacks.Lock()
	defer externalPathCallbacks.Unlock()
	if _, exists := externalPathCallbacks.inflight[key]; exists {
		return nil, &pathDispatchCallbackBusyError{operation: operation}
	}
	if externalPathCallbacks.classInflight[class] >= externalPathCallbackClassLimits[class] {
		return nil, &pathDispatchCallbackCapacityError{operation: operation}
	}
	lease := &externalPathCallbackLease{key: key, class: class, done: make(chan struct{})}
	externalPathCallbacks.inflight[key] = lease
	externalPathCallbacks.classInflight[class]++
	return lease, nil
}

func acquireExternalPathCallbackLeaseAuthority(
	operation string,
	owner *externalPathCallbackOwner,
) (*externalPathCallbackLease, error) {
	return acquireExternalPathCallbackLeaseTargetAuthority(operation, owner, owner)
}

func acquireExternalPathCallbackLeaseTargetAuthority(
	operation string,
	target any,
	owner *externalPathCallbackOwner,
) (*externalPathCallbackLease, error) {
	if err := owner.acquire(operation); err != nil {
		return nil, err
	}
	lease, err := acquireExternalPathCallbackLease(operation, target)
	if err != nil {
		owner.release()
		return nil, err
	}
	lease.owner = owner
	return lease, nil
}

func externalPathCallbackInFlight(operation string, target any) bool {
	key, stable := makeExternalPathCallbackKey(operation, target)
	if !stable {
		return false
	}
	externalPathCallbacks.Lock()
	_, exists := externalPathCallbacks.inflight[key]
	externalPathCallbacks.Unlock()
	return exists
}

func (lease *externalPathCallbackLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		externalPathCallbacks.Lock()
		if externalPathCallbacks.inflight[lease.key] == lease {
			delete(externalPathCallbacks.inflight, lease.key)
			externalPathCallbacks.classInflight[lease.class]--
		}
		externalPathCallbacks.Unlock()
		close(lease.done)
		lease.owner.release()
	})
}

func (lease *externalPathCallbackLease) completion() <-chan struct{} {
	if lease == nil || lease.done == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return lease.done
}

type externalPathValueResult[T any] struct {
	value T
	err   error
}

func invokeExternalPathValueCallback[T any](operation string, callback func() T) (T, error) {
	return invokeExternalPathValueCallbackForTarget(operation, nil, callback)
}

func invokeExternalPathValueCallbackForTarget[T any](operation string, target any, callback func() T) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), externalPathValueCallbackTimeout)
	defer cancel()
	return invokeExternalPathValueCallbackContext(ctx, operation, target, callback)
}

func invokeExternalPathValueCallbackAuthority[T any](
	ctx context.Context,
	operation string,
	target any,
	authority *externalPathCallbackOwner,
	callback func() T,
) (T, error) {
	var zero T
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, &pathDispatchCallbackDeadlineError{operation: operation, cause: err}
	}
	lease, err := acquireExternalPathCallbackLeaseTargetAuthority(operation, target, authority)
	if err != nil {
		return zero, err
	}
	return invokeExternalPathValueCallbackWithLease(ctx, operation, lease, callback)
}

func invokeExternalPathValueCallbackContext[T any](
	ctx context.Context,
	operation string,
	target any,
	callback func() T,
) (T, error) {
	var zero T
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, &pathDispatchCallbackDeadlineError{operation: operation, cause: err}
	}
	lease, err := acquireExternalPathCallbackLease(operation, target)
	if err != nil {
		return zero, err
	}
	return invokeExternalPathValueCallbackWithLease(ctx, operation, lease, callback)
}

func invokeExternalPathValueCallbackWithLease[T any](
	ctx context.Context,
	operation string,
	lease *externalPathCallbackLease,
	callback func() T,
) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		lease.release()
		return zero, &pathDispatchCallbackDeadlineError{operation: operation, cause: err}
	}
	result := make(chan externalPathValueResult[T], 1)
	go func() {
		var terminal externalPathValueResult[T]
		returned := false
		defer func() {
			if recovered := recover(); recovered != nil {
				terminal.err = newPathDispatchCallbackPanicError(operation, recovered)
			} else if !returned {
				terminal.err = &pathDispatchCallbackGoexitError{operation: operation}
			}
			lease.release()
			result <- terminal
		}()
		terminal.value = callback()
		returned = true
	}()
	select {
	case terminal := <-result:
		return terminal.value, terminal.err
	case <-ctx.Done():
		select {
		case terminal := <-result:
			return terminal.value, terminal.err
		default:
		}
		return zero, &pathDispatchCallbackDeadlineError{operation: operation, cause: ctx.Err()}
	}
}

func invokeExternalPathErrorCallbackContext(
	ctx context.Context,
	operation string,
	target any,
	callback func() error,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return &pathDispatchCallbackDeadlineError{operation: operation, cause: err}
	}
	lease, err := acquireExternalPathCallbackLease(operation, target)
	if err != nil {
		return err
	}
	return invokeExternalPathErrorCallbackWithLease(ctx, operation, lease, callback)
}

func invokeExternalPathErrorCallbackAuthority(
	ctx context.Context,
	operation string,
	authority *externalPathCallbackOwner,
	callback func() error,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return &pathDispatchCallbackDeadlineError{operation: operation, cause: err}
	}
	lease, err := acquireExternalPathCallbackLeaseAuthority(operation, authority)
	if err != nil {
		return err
	}
	return invokeExternalPathErrorCallbackWithLease(ctx, operation, lease, callback)
}

func invokeExternalPathErrorCallbackWithLease(
	ctx context.Context,
	operation string,
	lease *externalPathCallbackLease,
	callback func() error,
) error {
	if err := ctx.Err(); err != nil {
		lease.release()
		return &pathDispatchCallbackDeadlineError{operation: operation, cause: err}
	}
	result := make(chan error, 1)
	go func() {
		returned := false
		defer func() {
			if recovered := recover(); recovered != nil {
				lease.release()
				result <- newPathDispatchCallbackPanicError(operation, recovered)
			} else if !returned {
				lease.release()
				result <- &pathDispatchCallbackGoexitError{operation: operation}
			}
		}()
		err := callback()
		returned = true
		lease.release()
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		select {
		case err := <-result:
			return err
		default:
		}
		return &pathDispatchCallbackDeadlineError{operation: operation, cause: ctx.Err()}
	}
}

func closeExternalPathConn(conn transport.PathConn) error {
	if conn == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), externalPathErrorCallbackTimeout)
	defer cancel()
	return invokeExternalPathErrorCallbackContext(ctx, externalPathCloseOperation, conn, conn.Close)
}

func registerExternalPathDeath(
	conn transport.PathConn,
	callback func(transport.DeathCause, error),
) error {
	if conn == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), externalPathErrorCallbackTimeout)
	defer cancel()
	return invokeExternalPathErrorCallbackContext(ctx, "PathConn.OnDeath", conn, func() error {
		conn.OnDeath(callback)
		return nil
	})
}

func registerExternalPathDeathAuthority(
	conn transport.PathConn,
	authority *externalPathCallbackOwner,
	callback func(transport.DeathCause, error),
) error {
	if conn == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), externalPathErrorCallbackTimeout)
	defer cancel()
	return invokeExternalPathErrorCallbackAuthority(ctx, "PathConn.OnDeath", authority, func() error {
		conn.OnDeath(callback)
		return nil
	})
}

func externalPathCallbackBoundaryError(err error) bool {
	if err == nil {
		return false
	}
	var panicErr *pathDispatchCallbackPanicError
	var goexitErr *pathDispatchCallbackGoexitError
	var deadlineErr *pathDispatchCallbackDeadlineError
	var busyErr *pathDispatchCallbackBusyError
	var capacityErr *pathDispatchCallbackCapacityError
	var readCountErr *pathDispatchCallbackReadCountError
	return errors.As(err, &panicErr) || errors.As(err, &goexitErr) ||
		errors.As(err, &deadlineErr) || errors.As(err, &busyErr) ||
		errors.As(err, &capacityErr) || errors.As(err, &readCountErr)
}

func readExternalPathConnGuarded(
	conn transport.PathConn,
	buffer []byte,
	guard *pathDispatchCallbackGuard,
) (n int, err error) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			n = 0
			err = newPathDispatchCallbackPanicError("PathConn.Read", recovered)
		} else if !returned {
			guard.recordGoexit("PathConn.Read")
		}
	}()
	n, err = conn.Read(buffer)
	returned = true
	if n < 0 || n > len(buffer) {
		return 0, &pathDispatchCallbackReadCountError{
			operation:  externalPathReadOperation,
			count:      n,
			bufferSize: len(buffer),
			cause:      err,
		}
	}
	return n, err
}

func readExternalOwnedFrameGuarded(
	reader transport.OwnedFrameReader,
	guard *pathDispatchCallbackGuard,
) (frame []byte, err error) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			frame = nil
			err = newPathDispatchCallbackPanicError("OwnedFrameReader.ReadOwnedFrame", recovered)
		} else if !returned {
			guard.recordGoexit("OwnedFrameReader.ReadOwnedFrame")
		}
	}()
	frame, err = reader.ReadOwnedFrame()
	returned = true
	return frame, err
}
