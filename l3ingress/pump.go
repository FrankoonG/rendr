package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/virtualif"
)

const (
	defaultReadBufferSize = 64 << 10
	// DefaultPacketHandlerTimeout bounds a state-authoritative packet handler
	// even when Run's caller did not install a deadline.
	DefaultPacketHandlerTimeout = 30 * time.Second
)

// PacketEvent is emitted after one raw IP packet has been parsed and
// optionally passed through an external routing decision hook.
type PacketEvent struct {
	Packet   []byte
	Meta     PacketMeta
	Flow     FlowMeta
	Ref      FlowRef
	Decision FlowDecision
	Decided  bool
}

// PacketHandler consumes parsed packet events. Later TUN flow adapters
// plug in here to create rendr Conn / PacketConn sessions.
type PacketHandler interface {
	HandlePacket(context.Context, PacketEvent) error
}

// PacketHandlerFunc adapts a function into PacketHandler.
type PacketHandlerFunc func(context.Context, PacketEvent) error

func (f PacketHandlerFunc) HandlePacket(ctx context.Context, ev PacketEvent) error {
	return f(ctx, ev)
}

// ParseErrorHandler observes packets that cannot become a flow.
type ParseErrorHandler func(packet []byte, err error)

// PacketFailureStage identifies which packet-local Pump operation failed.
type PacketFailureStage string

const (
	// PacketFailureResolve means routing or flow-table admission failed.
	PacketFailureResolve PacketFailureStage = "resolve"
	// PacketFailureHandle means PacketHandler.HandlePacket rejected the packet
	// or failed its flow-local work.
	PacketFailureHandle PacketFailureStage = "handle"
)

// PacketFailure is bounded evidence for one packet-local failure. Event owns
// its Packet bytes and may be retained by the caller.
type PacketFailure struct {
	Stage PacketFailureStage
	Event PacketEvent
	Err   error
}

// PacketFailureHandler observes packet-local failures. Delivery is best
// effort: Pump permits at most one callback invocation at a time and records
// skipped or panicking callbacks in Status. Status counts every failure and
// retains the latest evidence even when callback delivery is skipped.
type PacketFailureHandler func(PacketFailure)

// PumpStatus is a concurrency-safe snapshot of packet-local failure evidence.
type PumpStatus struct {
	PacketFailures  uint64
	ObserverDrops   uint64
	ObserverPanics  uint64
	ObserverGoexits uint64
	FailureObserver CallbackStatus
	ParseObserver   CallbackStatus
	LastFailure     PacketFailure
	HasLastFailure  bool
}

// Pump connects a raw virtual interface to the l3ingress classifier.
// It owns no routing policy and starts no rendr flows by itself.
type Pump struct {
	Device       virtualif.CancellableDevice
	Direction    Direction
	FlowTable    *FlowTable
	Router       FlowDecisionFunc
	Handler      PacketHandler
	OnParseError ParseErrorHandler
	// OnPacketFailure is optional and must not be used as the authoritative
	// failure record; Status counts every failure even when this callback is
	// blocked, skipped, or panics, and retains the latest evidence.
	OnPacketFailure PacketFailureHandler
	BufferSize      int
	Now             func() time.Time
	// HandlerTimeout bounds PacketHandler.HandlePacket. ObserverTimeout bounds
	// the formerly synchronous OnParseError hook. Zero selects package defaults.
	HandlerTimeout  time.Duration
	ObserverTimeout time.Duration

	statusMu          sync.Mutex
	status            PumpStatus
	handlerBusy       atomic.Bool
	observerBusy      atomic.Bool
	parseObserverBusy atomic.Bool
}

// Status returns bounded packet-local failure evidence accumulated by Pump.
func (p *Pump) Status() PumpStatus {
	if p == nil {
		return PumpStatus{}
	}
	p.statusMu.Lock()
	status := p.status
	p.statusMu.Unlock()
	if status.HasLastFailure {
		status.LastFailure = clonePacketFailure(status.LastFailure)
	}
	return status
}

// Run reads packets until the context is canceled or the device reaches a
// terminal read result. Ordinary routing and handler errors reject only their
// packet. A handler timeout or saturated executor terminates Run because the
// late state-authoritative callback can no longer safely overlap new flows.
func (p *Pump) Run(ctx context.Context) error {
	if p.Device == nil {
		return errors.New("l3ingress: nil device")
	}
	if p.Handler == nil {
		return errors.New("l3ingress: nil packet handler")
	}
	if p.HandlerTimeout < 0 {
		return errors.New("l3ingress: packet handler timeout must not be negative")
	}
	if p.ObserverTimeout < 0 {
		return errors.New("l3ingress: observer timeout must not be negative")
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	bufSize := p.BufferSize
	if bufSize <= 0 {
		bufSize = p.Device.MTU()
	}
	if bufSize <= 0 {
		bufSize = defaultReadBufferSize
	}
	if bufSize < 1 {
		return fmt.Errorf("l3ingress: invalid buffer size %d", bufSize)
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	onPacketFailure := p.OnPacketFailure
	onParseError := p.OnParseError
	handler := p.Handler
	handlerExecutor := newPacketHandlerExecutor(handler, &p.handlerBusy)
	defer handlerExecutor.Close()
	handlerTimeout := p.HandlerTimeout
	if handlerTimeout == 0 {
		handlerTimeout = DefaultPacketHandlerTimeout
	}
	observerTimeout := p.ObserverTimeout
	if observerTimeout == 0 {
		observerTimeout = DefaultFlowObserverTimeout
	}
	direction := p.Direction
	if direction == 0 {
		direction = DirectionIngress
	}
	table := p.FlowTable
	if table == nil && p.Router != nil {
		table = NewFlowTable(p.Router, FlowTableOptions{Now: now})
	}
	buf := make([]byte, bufSize)
	for {
		select {
		case <-runCtx.Done():
			return runCtx.Err()
		default:
		}
		n, err := p.Device.ReadContext(runCtx, buf)
		if err != nil {
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			if errors.Is(err, io.ErrShortBuffer) && len(buf) < defaultReadBufferSize {
				buf = make([]byte, defaultReadBufferSize)
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		meta, err := ParsePacket(packet)
		if err != nil {
			p.observeParseError(onParseError, packet, err, observerTimeout)
			continue
		}
		flow := FlowMeta{
			L3Identity: meta.Identity,
			Direction:  direction,
			CreatedAt:  now(),
		}
		ev := PacketEvent{
			Packet: packet,
			Meta:   meta,
			Flow:   flow,
		}
		if table != nil {
			decision, _, snapshot, err := table.Resolve(runCtx, flow, len(packet))
			if err != nil {
				if ctxErr := runCtx.Err(); ctxErr != nil {
					return ctxErr
				}
				p.recordPacketFailure(onPacketFailure, PacketFailure{
					Stage: PacketFailureResolve,
					Event: ev,
					Err:   err,
				})
				continue
			}
			ev.Decision = decision
			ev.Decided = snapshot.Decided
			ev.Flow = snapshot.Flow
			ev.Ref = snapshot.Ref
		}
		if ev.Decision.Deny {
			if table != nil {
				if reason, ok := TCPFlowCloseReason(meta); ok {
					closePacketFlow(table, ev.Ref, meta.Identity, reason)
				}
			}
			continue
		}
		handlerErr := p.invokePacketHandler(runCtx, handlerExecutor, ev, handlerTimeout)
		if table != nil {
			if reason, ok := TCPFlowCloseReason(meta); ok {
				closePacketFlow(table, ev.Ref, meta.Identity, reason)
			}
		}
		if handlerErr != nil {
			if ctxErr := runCtx.Err(); ctxErr != nil {
				return ctxErr
			}
			p.recordPacketFailure(onPacketFailure, PacketFailure{
				Stage: PacketFailureHandle,
				Event: ev,
				Err:   handlerErr,
			})
			if callbackFailureIsTerminal(handlerErr) {
				return handlerErr
			}
		}
	}
}

func callbackFailureIsTerminal(err error) bool {
	var callbackErr *CallbackError
	if !errors.As(err, &callbackErr) {
		return false
	}
	return callbackErr.Reason == CallbackFailureTimeout || callbackErr.Reason == CallbackFailureSaturated
}

type packetHandlerResult struct {
	id  uint64
	err error
}

type packetHandlerRequest struct {
	id             uint64
	ctx            context.Context
	event          PacketEvent
	releaseProcess func()
}

type packetHandlerExecutor struct {
	handler  PacketHandler
	busy     *atomic.Bool
	requests chan packetHandlerRequest
	results  chan packetHandlerResult
	stop     chan struct{}
	closed   atomic.Bool
	nextID   atomic.Uint64
	workers  sync.WaitGroup
}

func newPacketHandlerExecutor(handler PacketHandler, busy *atomic.Bool) *packetHandlerExecutor {
	executor := &packetHandlerExecutor{
		handler:  handler,
		busy:     busy,
		requests: make(chan packetHandlerRequest),
		results:  make(chan packetHandlerResult, 1),
		stop:     make(chan struct{}),
	}
	executor.startWorker()
	return executor
}

func (e *packetHandlerExecutor) startWorker() {
	e.workers.Add(1)
	go e.runWorker()
}

func (e *packetHandlerExecutor) runWorker() {
	normalExit := false
	defer func() {
		if !normalExit && !e.closed.Load() {
			e.startWorker()
		}
		e.workers.Done()
	}()
	for {
		select {
		case <-e.stop:
			normalExit = true
			return
		case request := <-e.requests:
			e.execute(request)
		}
	}
}

func (e *packetHandlerExecutor) execute(request packetHandlerRequest) {
	result := packetHandlerResult{
		id: request.id,
		err: &CallbackError{
			Callback: "PacketHandler.HandlePacket",
			Reason:   CallbackFailureGoexit,
		},
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.err = callbackPanicError("PacketHandler.HandlePacket", recovered)
		}
		request.releaseProcess()
		e.busy.Store(false)
		select {
		case e.results <- result:
		case <-e.stop:
		}
	}()
	// PacketHandler may retain ctx as the flow lifetime (for example, a UDP
	// reply loop). A per-call derived context would cancel valid async work as
	// soon as HandlePacket returns, so the timeout only bounds Pump's wait.
	result.err = e.handler.HandlePacket(request.ctx, request.event)
}

func (e *packetHandlerExecutor) Close() {
	if e == nil || !e.closed.CompareAndSwap(false, true) {
		return
	}
	close(e.stop)
	if !e.busy.Load() {
		e.workers.Wait()
	}
}

func (p *Pump) invokePacketHandler(
	ctx context.Context,
	executor *packetHandlerExecutor,
	event PacketEvent,
	timeout time.Duration,
) error {
	if !p.handlerBusy.CompareAndSwap(false, true) {
		return &CallbackError{
			Callback: "PacketHandler.HandlePacket",
			Reason:   CallbackFailureSaturated,
		}
	}
	releaseProcess, ok := tryAcquireL3IngressCallback(l3IngressCallbackAuthoritative)
	if !ok {
		p.handlerBusy.Store(false)
		return &CallbackError{
			Callback: "PacketHandler.HandlePacket",
			Reason:   CallbackFailureSaturated,
		}
	}
	request := packetHandlerRequest{
		id:             executor.nextID.Add(1),
		ctx:            ctx,
		event:          clonePacketEvent(event),
		releaseProcess: releaseProcess,
	}
	select {
	case executor.requests <- request:
	case <-ctx.Done():
		p.handlerBusy.Store(false)
		releaseProcess()
		return ctx.Err()
	case <-executor.stop:
		p.handlerBusy.Store(false)
		releaseProcess()
		return netClosedCallbackError("PacketHandler.HandlePacket")
	}
	timer := time.NewTimer(timeout)
	defer stopFlowCallbackTimer(timer)
	for {
		select {
		case result := <-executor.results:
			if result.id == request.id {
				return result.err
			}
		case <-ctx.Done():
			select {
			case result := <-executor.results:
				if result.id == request.id {
					return result.err
				}
			default:
			}
			return ctx.Err()
		case <-timer.C:
			select {
			case result := <-executor.results:
				if result.id == request.id {
					return result.err
				}
			default:
			}
			return &CallbackError{
				Callback: "PacketHandler.HandlePacket",
				Reason:   CallbackFailureTimeout,
			}
		case <-executor.stop:
			return netClosedCallbackError("PacketHandler.HandlePacket")
		}
	}
}

func netClosedCallbackError(callback string) error {
	return errors.New("l3ingress: " + callback + " executor closed")
}

func (p *Pump) observeParseError(
	observer ParseErrorHandler,
	packet []byte,
	parseErr error,
	timeout time.Duration,
) {
	if observer == nil {
		return
	}
	if !p.parseObserverBusy.CompareAndSwap(false, true) {
		p.recordOptionalCallbackFailure(false, &CallbackError{
			Callback: "ParseErrorHandler",
			Reason:   CallbackFailureSaturated,
		})
		return
	}
	releaseProcess, ok := tryAcquireL3IngressCallback(l3IngressCallbackOptional)
	if !ok {
		p.parseObserverBusy.Store(false)
		p.recordOptionalCallbackFailure(false, &CallbackError{
			Callback: "ParseErrorHandler",
			Reason:   CallbackFailureSaturated,
		})
		return
	}
	done := make(chan struct{})
	ownedPacket := append([]byte(nil), packet...)
	go func() {
		returned := false
		defer func() {
			if recovered := recover(); recovered != nil {
				p.recordOptionalCallbackFailure(false, callbackPanicError("ParseErrorHandler", recovered))
			} else if !returned {
				p.recordOptionalCallbackFailure(false, &CallbackError{
					Callback: "ParseErrorHandler",
					Reason:   CallbackFailureGoexit,
				})
			}
			releaseProcess()
			p.parseObserverBusy.Store(false)
			close(done)
		}()
		observer(ownedPacket, parseErr)
		returned = true
	}()
	timer := time.NewTimer(timeout)
	defer stopFlowCallbackTimer(timer)
	select {
	case <-done:
	case <-timer.C:
		select {
		case <-done:
		default:
			p.recordOptionalCallbackFailure(false, &CallbackError{
				Callback: "ParseErrorHandler",
				Reason:   CallbackFailureTimeout,
			})
		}
	}
}

func closePacketFlow(table *FlowTable, ref FlowRef, id L3Identity, reason FlowCloseReason) {
	if ref != (FlowRef{}) {
		table.CloseRef(ref, reason)
		return
	}
	table.Close(id, reason)
}

func (p *Pump) recordPacketFailure(observer PacketFailureHandler, failure PacketFailure) {
	retained := clonePacketFailure(failure)
	p.statusMu.Lock()
	p.status.PacketFailures++
	p.status.LastFailure = retained
	p.status.HasLastFailure = true
	p.statusMu.Unlock()

	if observer == nil {
		return
	}
	if !p.observerBusy.CompareAndSwap(false, true) {
		p.recordOptionalCallbackFailure(true, &CallbackError{
			Callback: "PacketFailureHandler",
			Reason:   CallbackFailureSaturated,
		})
		return
	}
	releaseProcess, ok := tryAcquireL3IngressCallback(l3IngressCallbackOptional)
	if !ok {
		p.observerBusy.Store(false)
		p.recordOptionalCallbackFailure(true, &CallbackError{
			Callback: "PacketFailureHandler",
			Reason:   CallbackFailureSaturated,
		})
		return
	}
	observed := clonePacketFailure(retained)
	go func() {
		returned := false
		defer func() {
			if recovered := recover(); recovered != nil {
				p.recordOptionalCallbackFailure(true, callbackPanicError("PacketFailureHandler", recovered))
			} else if !returned {
				p.recordOptionalCallbackFailure(true, &CallbackError{
					Callback: "PacketFailureHandler",
					Reason:   CallbackFailureGoexit,
				})
			}
			releaseProcess()
			p.observerBusy.Store(false)
		}()
		observer(observed)
		returned = true
	}()
}

func (p *Pump) recordOptionalCallbackFailure(failureObserver bool, failure *CallbackError) {
	if p == nil || failure == nil {
		return
	}
	p.statusMu.Lock()
	status := &p.status.ParseObserver
	if failureObserver {
		status = &p.status.FailureObserver
	}
	switch failure.Reason {
	case CallbackFailurePanic:
		status.Panics++
		if failureObserver {
			p.status.ObserverPanics++
		}
	case CallbackFailureGoexit:
		status.Goexits++
		if failureObserver {
			p.status.ObserverGoexits++
		}
	case CallbackFailureTimeout:
		status.Timeouts++
	case CallbackFailureSaturated:
		status.Drops++
		if failureObserver {
			p.status.ObserverDrops++
		}
	}
	status.LastFailure = *failure
	status.HasFailure = true
	p.statusMu.Unlock()
}

func clonePacketFailure(failure PacketFailure) PacketFailure {
	failure.Event = clonePacketEvent(failure.Event)
	return failure
}

func clonePacketEvent(event PacketEvent) PacketEvent {
	event.Packet = append([]byte(nil), event.Packet...)
	event.Flow = cloneFlowMeta(event.Flow)
	event.Decision = cloneDecision(event.Decision)
	return event
}
