package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
	uflow "github.com/FrankoonG/rendr/transport/udpflow"
)

const (
	runtimeAcceptQueueSize         = 16
	runtimeHandshakeLimit          = 64
	runtimeHandshakeTimeout        = 10 * time.Second
	runtimeBridgeAwaitTimeout      = 10 * time.Second
	runtimeListenerCallLimit       = 64
	runtimeListenerProcessLimit    = 2 * runtimeListenerCallLimit
	runtimeListenerCallTimeout     = time.Second
	runtimeListenerWorkerJoinGrace = 100 * time.Millisecond
	runtimeListenerTerminalLimit   = runtimeListenerProcessLimit
	runtimeListenerErrorNodeLimit  = 128
	runtimeListenerErrorDepthLimit = 32
)

// ListenerCallbackOperation identifies caller-owned listener code invoked by
// a Runtime. It is stable diagnostic data for ListenerCallbackError.
type ListenerCallbackOperation string

const (
	ListenerCallbackSessionKind     ListenerCallbackOperation = "SessionKind"
	ListenerCallbackAddr            ListenerCallbackOperation = "Addr"
	ListenerCallbackAccept          ListenerCallbackOperation = "Accept"
	ListenerCallbackAcceptPath      ListenerCallbackOperation = "AcceptPath"
	ListenerCallbackPacketAccept    ListenerCallbackOperation = "udpflow.Listener.Accept"
	ListenerCallbackSetDeadline     ListenerCallbackOperation = "net.Conn.SetDeadline"
	ListenerCallbackClearDeadline   ListenerCallbackOperation = "net.Conn.ClearDeadline"
	ListenerCallbackPacketRead      ListenerCallbackOperation = "net.PacketConn.ReadFrom"
	ListenerCallbackPacketWrite     ListenerCallbackOperation = "net.PacketConn.WriteTo"
	ListenerCallbackPacketControl   ListenerCallbackOperation = "net.PacketConn.Control"
	ListenerCallbackPacketLocalAddr ListenerCallbackOperation = "net.PacketConn.LocalAddr"
	ListenerCallbackPacketListen    ListenerCallbackOperation = "udpflow.NewListenerFromPacketConn"
	ListenerCallbackPacketClose     ListenerCallbackOperation = "net.PacketConn.Close"
	ListenerCallbackClose           ListenerCallbackOperation = "Close"
	ListenerCallbackLocalAddr       ListenerCallbackOperation = "PathConn.LocalAddr"
	ListenerCallbackRemoteAddr      ListenerCallbackOperation = "PathConn.RemoteAddr"
	ListenerCallbackPathClose       ListenerCallbackOperation = "PathConn.Close"
)

// ListenerCallbackFailure classifies an abnormal caller-owned listener exit.
type ListenerCallbackFailure string

const (
	ListenerCallbackPanic           ListenerCallbackFailure = "panic"
	ListenerCallbackAbnormalExit    ListenerCallbackFailure = "abnormal_exit"
	ListenerCallbackTimeout         ListenerCallbackFailure = "timeout"
	ListenerCallbackResourceLimited ListenerCallbackFailure = "resource_limited"
	ListenerCallbackInvalidResult   ListenerCallbackFailure = "invalid_result"
)

// ListenerCallbackError reports that caller-owned listener code did not obey
// its lifecycle contract. Recovered panic values are deliberately not exposed
// or unwrapped; PanicType is sufficient for diagnostics without allowing a
// panic value to masquerade as an internal sentinel error.
type ListenerCallbackError struct {
	Source    string
	Operation ListenerCallbackOperation
	Reason    ListenerCallbackFailure
	PanicType string
}

func (e *ListenerCallbackError) Error() string {
	if e == nil {
		return "rendr: listener callback failed"
	}
	message := fmt.Sprintf("rendr: inbound source %q %s callback %s", e.Source, e.Operation, e.Reason)
	if e.PanicType != "" {
		message += " (" + e.PanicType + ")"
	}
	return message
}

type runtimeListenerCallbackPermits struct {
	acceptCalls        chan struct{}
	metadataCalls      chan struct{}
	pathMetadataCalls  chan struct{}
	packetReadCalls    chan struct{}
	packetWriteCalls   chan struct{}
	packetControlCalls chan struct{}
	packetCloseCalls   chan struct{}
	sourceCloseCalls   chan struct{}
	pathCloseCalls     chan struct{}
}

func newRuntimeListenerCallbackPermits(limit int) *runtimeListenerCallbackPermits {
	return &runtimeListenerCallbackPermits{
		acceptCalls:        make(chan struct{}, limit),
		metadataCalls:      make(chan struct{}, limit),
		pathMetadataCalls:  make(chan struct{}, limit),
		packetReadCalls:    make(chan struct{}, limit),
		packetWriteCalls:   make(chan struct{}, limit),
		packetControlCalls: make(chan struct{}, limit),
		packetCloseCalls:   make(chan struct{}, limit),
		sourceCloseCalls:   make(chan struct{}, limit),
		pathCloseCalls:     make(chan struct{}, limit),
	}
}

func (permits *runtimeListenerCallbackPermits) forOperation(operation ListenerCallbackOperation) chan struct{} {
	switch operation {
	case ListenerCallbackAccept, ListenerCallbackAcceptPath:
		return permits.acceptCalls
	case ListenerCallbackClose:
		return permits.sourceCloseCalls
	case ListenerCallbackPacketClose:
		return permits.packetCloseCalls
	case ListenerCallbackLocalAddr, ListenerCallbackRemoteAddr,
		ListenerCallbackSetDeadline, ListenerCallbackClearDeadline:
		return permits.pathMetadataCalls
	case ListenerCallbackPacketRead:
		return permits.packetReadCalls
	case ListenerCallbackPacketWrite:
		return permits.packetWriteCalls
	case ListenerCallbackPacketControl:
		return permits.packetControlCalls
	case ListenerCallbackPathClose:
		return permits.pathCloseCalls
	default:
		return permits.metadataCalls
	}
}

type runtimeListenerCallbackScope struct {
	runtime    *Runtime
	permits    *runtimeListenerCallbackPermits
	owners     int
	calls      int
	generation uint64
}

var runtimeListenerCallbackScopes = struct {
	sync.Mutex
	byRuntime map[*Runtime]*runtimeListenerCallbackScope
}{byRuntime: make(map[*Runtime]*runtimeListenerCallbackScope)}

// A Runtime can consume at most half of each process-wide callback class.
// Separate source/path cleanup classes remain available when normal callback
// classes are saturated.
var runtimeListenerProcessCallbackPermits = newRuntimeListenerCallbackPermits(runtimeListenerProcessLimit)

func retainRuntimeListenerCallbackScope(runtime *Runtime) *runtimeListenerCallbackScope {
	if runtime == nil {
		return nil
	}
	runtimeListenerCallbackScopes.Lock()
	defer runtimeListenerCallbackScopes.Unlock()
	scope := runtimeListenerCallbackScopes.byRuntime[runtime]
	if scope == nil {
		scope = &runtimeListenerCallbackScope{
			runtime: runtime,
			permits: newRuntimeListenerCallbackPermits(runtimeListenerCallLimit),
		}
		runtimeListenerCallbackScopes.byRuntime[runtime] = scope
	}
	scope.owners++
	return scope
}

func (scope *runtimeListenerCallbackScope) retainCall() {
	if scope == nil {
		return
	}
	runtimeListenerCallbackScopes.Lock()
	scope.calls++
	runtimeListenerCallbackScopes.Unlock()
}

func (scope *runtimeListenerCallbackScope) releaseCall() {
	if scope == nil {
		return
	}
	runtimeListenerCallbackScopes.Lock()
	if scope.calls > 0 {
		scope.calls--
	}
	releaseRuntimeListenerCallbackScopeLocked(scope)
	runtimeListenerCallbackScopes.Unlock()
}

func releaseRuntimeListenerCallbackScopeLocked(scope *runtimeListenerCallbackScope) {
	if scope == nil || scope.owners != 0 || scope.calls != 0 {
		return
	}
	if runtimeListenerCallbackScopes.byRuntime[scope.runtime] == scope {
		delete(runtimeListenerCallbackScopes.byRuntime, scope.runtime)
	}
}

type runtimeListenerCallbackOwner struct {
	permits *runtimeListenerCallbackPermits
	scope   *runtimeListenerCallbackScope

	releaseOnce sync.Once
	generation  uint64

	terminalMu      sync.Mutex
	terminalErrs    []error
	terminalDropped bool
}

func newRuntimeListenerCallbackOwner() *runtimeListenerCallbackOwner {
	return &runtimeListenerCallbackOwner{
		permits: newRuntimeListenerCallbackPermits(runtimeListenerCallLimit),
	}
}

func newRuntimeListenerCallbackOwnerForRuntime(runtime *Runtime) *runtimeListenerCallbackOwner {
	owner := newRuntimeListenerCallbackOwner()
	owner.scope = retainRuntimeListenerCallbackScope(runtime)
	return owner
}

func (owner *runtimeListenerCallbackOwner) release() {
	if owner == nil || owner.scope == nil {
		return
	}
	owner.releaseOnce.Do(func() {
		runtimeListenerCallbackScopes.Lock()
		if owner.scope.owners > 0 {
			owner.scope.owners--
		}
		releaseRuntimeListenerCallbackScopeLocked(owner.scope)
		runtimeListenerCallbackScopes.Unlock()
	})
}

func (owner *runtimeListenerCallbackOwner) activateGeneration() uint64 {
	if owner == nil || owner.scope == nil {
		return 0
	}
	runtimeListenerCallbackScopes.Lock()
	owner.scope.generation++
	if owner.scope.generation == 0 {
		owner.scope.generation++
	}
	owner.generation = owner.scope.generation
	runtimeListenerCallbackScopes.Unlock()
	return owner.generation
}

func (owner *runtimeListenerCallbackOwner) generationActive(generation uint64) bool {
	if owner == nil || owner.scope == nil || generation == 0 {
		return true
	}
	runtimeListenerCallbackScopes.Lock()
	active := owner.scope.generation == generation
	runtimeListenerCallbackScopes.Unlock()
	return active
}

func (owner *runtimeListenerCallbackOwner) recordTerminalDiagnostic(err error) {
	err = runtimeListenerTerminalDiagnostic(err)
	if owner == nil || err == nil {
		return
	}
	owner.terminalMu.Lock()
	defer owner.terminalMu.Unlock()
	if len(owner.terminalErrs) < runtimeListenerTerminalLimit {
		owner.terminalErrs = append(owner.terminalErrs, err)
		return
	}
	owner.terminalDropped = true
}

func runtimeListenerTerminalDiagnostic(err error) error {
	walk := runtimeListenerErrorWalk{remaining: runtimeListenerErrorNodeLimit}
	diagnostic, _, invalid := walk.prune(err, 0)
	if invalid {
		return runtimeListenerInvalidTerminalDiagnostic()
	}
	return diagnostic
}

type runtimeListenerErrorWalk struct {
	remaining int
}

func (walk *runtimeListenerErrorWalk) prune(err error, depth int) (diagnostic error, pruned, invalid bool) {
	if err == nil {
		return nil, false, false
	}
	if depth >= runtimeListenerErrorDepthLimit || walk.remaining <= 0 {
		return nil, false, true
	}
	walk.remaining--

	if children, joined, malformed := runtimeListenerUnwrapMany(err); malformed {
		return nil, false, true
	} else if joined {
		if len(children) > walk.remaining {
			return nil, false, true
		}
		retained := make([]error, 0, len(children))
		changed := false
		for _, child := range children {
			if child == nil {
				return nil, false, true
			}
			childDiagnostic, childPruned, childInvalid := walk.prune(child, depth+1)
			if childInvalid {
				return nil, false, true
			}
			changed = changed || childPruned
			if childDiagnostic != nil {
				retained = append(retained, childDiagnostic)
			}
		}
		if !changed {
			return err, false, false
		}
		return errors.Join(retained...), true, false
	}

	child, wrapped, malformed := runtimeListenerUnwrapOne(err)
	if malformed {
		return nil, false, true
	}
	expected, malformed := runtimeListenerMatchesExpected(err)
	if malformed {
		return nil, false, true
	}
	if !wrapped {
		if expected {
			return nil, true, false
		}
		return err, false, false
	}
	childDiagnostic, childPruned, childInvalid := walk.prune(child, depth+1)
	if childInvalid {
		return nil, false, true
	}
	if expected || childPruned {
		// A wrapper containing an expected branch cannot be safely rebuilt
		// after pruning because error wrappers have no general constructor.
		return childDiagnostic, true, false
	}
	return err, false, false
}

func runtimeListenerUnwrapMany(err error) (children []error, joined, malformed bool) {
	unwrap, joined := err.(interface{ Unwrap() []error })
	if !joined {
		return nil, false, false
	}
	defer func() {
		if recover() != nil {
			children = nil
			malformed = true
		}
	}()
	return unwrap.Unwrap(), true, false
}

func runtimeListenerUnwrapOne(err error) (child error, wrapped, malformed bool) {
	unwrap, wrapped := err.(interface{ Unwrap() error })
	if !wrapped {
		return nil, false, false
	}
	defer func() {
		if recover() != nil {
			child = nil
			malformed = true
		}
	}()
	return unwrap.Unwrap(), true, false
}

func runtimeListenerMatchesExpected(err error) (matched, malformed bool) {
	defer func() {
		if recover() != nil {
			matched = false
			malformed = true
		}
	}()
	if err == net.ErrClosed || err == context.Canceled {
		return true, false
	}
	if matcher, ok := err.(interface{ Is(error) bool }); ok {
		return matcher.Is(net.ErrClosed) || matcher.Is(context.Canceled), false
	}
	return false, false
}

func runtimeListenerInvalidTerminalDiagnostic() error {
	return &ListenerCallbackError{
		Source: "session-listener-diagnostics", Operation: ListenerCallbackClose, Reason: ListenerCallbackInvalidResult,
	}
}

func (owner *runtimeListenerCallbackOwner) terminalDiagnostics() error {
	if owner == nil {
		return nil
	}
	owner.terminalMu.Lock()
	defer owner.terminalMu.Unlock()
	if !owner.terminalDropped {
		return errors.Join(owner.terminalErrs...)
	}
	dropped := &ListenerCallbackError{
		Source: "session-listener-diagnostics", Operation: ListenerCallbackClose, Reason: ListenerCallbackResourceLimited,
	}
	return errors.Join(errors.Join(owner.terminalErrs...), dropped)
}

type runtimeListenerCloser struct {
	source  string
	close   func() error
	lease   *runtimeListenerCallbackLease
	timeout time.Duration
}

type runtimeListenerCallResult[T any] struct {
	value T
	err   error
}

type runtimeListenerCallbackLease struct {
	owner    *runtimeListenerCallbackOwner
	scope    *runtimeListenerCallbackScope
	acquired []chan struct{}
	once     sync.Once
}

func (lease *runtimeListenerCallbackLease) recordTerminalDiagnostic(err error) {
	if lease != nil {
		lease.owner.recordTerminalDiagnostic(err)
	}
}

func (lease *runtimeListenerCallbackLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		for index := len(lease.acquired) - 1; index >= 0; index-- {
			<-lease.acquired[index]
		}
		if lease.scope != nil {
			lease.scope.releaseCall()
		}
	})
}

type runtimeListenerPathClose struct {
	source     string
	path       transport.PathConn
	lease      *runtimeListenerCallbackLease
	reserveErr error
	timeout    time.Duration

	startOnce sync.Once
	done      chan struct{}
	err       error
}

type runtimeListenerNetConnCleanup struct{ conn net.Conn }

func (cleanup *runtimeListenerNetConnCleanup) Read([]byte) (int, error) {
	return 0, net.ErrClosed
}
func (cleanup *runtimeListenerNetConnCleanup) Write([]byte) (int, error) {
	return 0, net.ErrClosed
}
func (cleanup *runtimeListenerNetConnCleanup) Close() error {
	if cleanup == nil || isNilNetworkSource(cleanup.conn) {
		return nil
	}
	return cleanup.conn.Close()
}
func (*runtimeListenerNetConnCleanup) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (*runtimeListenerNetConnCleanup) OnDeath(func(transport.DeathCause, error)) {}
func (cleanup *runtimeListenerNetConnCleanup) LocalAddr() string {
	if cleanup == nil || isNilNetworkSource(cleanup.conn) || cleanup.conn.LocalAddr() == nil {
		return ""
	}
	return cleanup.conn.LocalAddr().String()
}
func (cleanup *runtimeListenerNetConnCleanup) RemoteAddr() string {
	if cleanup == nil || isNilNetworkSource(cleanup.conn) || cleanup.conn.RemoteAddr() == nil {
		return ""
	}
	return cleanup.conn.RemoteAddr().String()
}

func newRuntimeListenerPathClose(source string, path transport.PathConn, lease *runtimeListenerCallbackLease, reserveErr error) *runtimeListenerPathClose {
	return &runtimeListenerPathClose{
		source:     source,
		path:       path,
		lease:      lease,
		reserveErr: reserveErr,
		timeout:    runtimeListenerCallTimeout,
		done:       make(chan struct{}),
	}
}

func reserveRuntimeListenerPathClose(ctx context.Context, source string, owner *runtimeListenerCallbackOwner) (*runtimeListenerCallbackLease, error) {
	return acquireRuntimeListenerCallbackLease(ctx, owner, source, ListenerCallbackPathClose)
}

func (closeCall *runtimeListenerPathClose) start() {
	if closeCall == nil {
		return
	}
	closeCall.startOnce.Do(func() {
		if closeCall.reserveErr != nil {
			closeCall.err = closeCall.reserveErr
			close(closeCall.done)
			return
		}
		if closeCall.path == nil {
			closeCall.lease.release()
			close(closeCall.done)
			return
		}
		go func() {
			result := make(chan error)
			abandoned := make(chan struct{})
			deliver := func(err error) {
				select {
				case result <- err:
				case <-abandoned:
					closeCall.lease.recordTerminalDiagnostic(err)
				}
			}
			go func() {
				defer closeCall.lease.release()
				completed := false
				defer func() {
					if completed {
						return
					}
					recovered := recover()
					failure := &ListenerCallbackError{Source: closeCall.source, Operation: ListenerCallbackPathClose, Reason: ListenerCallbackAbnormalExit}
					if recovered != nil {
						failure.Reason = ListenerCallbackPanic
						failure.PanicType = reflect.TypeOf(recovered).String()
					}
					deliver(failure)
				}()
				err := closeCall.path.Close()
				completed = true
				deliver(err)
			}()
			timeout := closeCall.timeout
			if timeout <= 0 {
				timeout = runtimeListenerCallTimeout
			}
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			select {
			case closeCall.err = <-result:
			case <-timer.C:
				// Prefer a callback result that became ready at the timeout edge.
				// Otherwise mark delivery abandoned before returning the factual
				// timeout; the callback records its eventual terminal result.
				select {
				case closeCall.err = <-result:
				default:
					close(abandoned)
					closeCall.err = &ListenerCallbackError{Source: closeCall.source, Operation: ListenerCallbackPathClose, Reason: ListenerCallbackTimeout}
				}
			}
			close(closeCall.done)
		}()
	})
}

func (closeCall *runtimeListenerPathClose) releaseToEngine() {
	if closeCall == nil {
		return
	}
	closeCall.startOnce.Do(func() {
		closeCall.lease.release()
		close(closeCall.done)
	})
}

func (closeCall *runtimeListenerPathClose) wait() error {
	if closeCall == nil {
		return nil
	}
	closeCall.start()
	<-closeCall.done
	return closeCall.err
}

type runtimeListenerInflightClaim struct {
	listener  *SessionListener
	id        uint64
	source    string
	path      transport.PathConn
	close     *runtimeListenerPathClose
	engine    *engine.Engine
	pathID    uint32
	attaching bool
	canceled  bool

	handshakeOnce sync.Once
}

func (claim *runtimeListenerInflightClaim) active() bool {
	if claim == nil || claim.listener == nil {
		return false
	}
	if !claim.listener.generationActive() {
		return false
	}
	claim.listener.inflightMu.Lock()
	defer claim.listener.inflightMu.Unlock()
	return !claim.listener.closing && claim.listener.inflight[claim.id] == claim
}

func (claim *runtimeListenerInflightClaim) cancel() bool {
	if claim == nil || claim.listener == nil {
		return false
	}
	claim.listener.inflightMu.Lock()
	active := claim.listener.inflight[claim.id] == claim
	if active {
		delete(claim.listener.inflight, claim.id)
		claim.canceled = true
	}
	e := claim.engine
	pathID := claim.pathID
	closeCall := claim.close
	attaching := claim.attaching
	claim.listener.inflightMu.Unlock()
	if active {
		claim.releaseHandshake()
		if e != nil {
			if pathID != 0 {
				e.AbortPathAttach(pathID, net.ErrClosed)
			}
		} else if !attaching {
			closeCall.start()
		}
	}
	return active
}

func (claim *runtimeListenerInflightClaim) beginEngineAttach(e *engine.Engine) bool {
	if claim == nil || claim.listener == nil || e == nil {
		return false
	}
	claim.listener.inflightMu.Lock()
	active := !claim.listener.closing && claim.listener.inflight[claim.id] == claim && claim.listener.generationActive()
	if active {
		claim.attaching = true
		claim.engine = e
	}
	claim.listener.inflightMu.Unlock()
	return active
}

func (claim *runtimeListenerInflightClaim) resolveEngineAttach(e *engine.Engine, pathID uint32, adopted bool) bool {
	if claim == nil || claim.listener == nil || e == nil {
		return false
	}
	claim.listener.inflightMu.Lock()
	if !claim.attaching || claim.engine != e {
		claim.listener.inflightMu.Unlock()
		return false
	}
	claim.attaching = false
	if adopted {
		claim.pathID = pathID
	} else {
		// Reservation rejection precedes engine ownership. Restore listener
		// authority before cancellation can choose the cleanup owner.
		claim.engine = nil
	}
	active := !claim.canceled && !claim.listener.closing && claim.listener.inflight[claim.id] == claim && claim.listener.generationActive()
	closeCall := claim.close
	claim.listener.inflightMu.Unlock()

	if adopted {
		closeCall.releaseToEngine()
	} else if !active {
		closeCall.start()
	}
	if adopted && pathID != 0 && !active {
		e.AbortPathAttach(pathID, net.ErrClosed)
	}
	return active
}

func (claim *runtimeListenerInflightClaim) releaseHandshake() {
	if claim == nil || claim.listener == nil {
		return
	}
	claim.handshakeOnce.Do(func() { <-claim.listener.handshakes })
}

func (claim *runtimeListenerInflightClaim) finish(owned bool) {
	if claim == nil {
		return
	}
	if !owned {
		claim.cancel()
		claim.releaseHandshake()
		return
	}
	claim.listener.inflightMu.Lock()
	if claim.listener.inflight[claim.id] == claim {
		delete(claim.listener.inflight, claim.id)
	}
	claim.listener.inflightMu.Unlock()
	claim.releaseHandshake()
	claim.close.releaseToEngine()
}

func (claim *runtimeListenerInflightClaim) listenerCleanup() *runtimeListenerPathClose {
	if claim == nil || claim.listener == nil {
		return nil
	}
	claim.listener.inflightMu.Lock()
	defer claim.listener.inflightMu.Unlock()
	if claim.engine != nil {
		return nil
	}
	return claim.close
}

func invokeRuntimeListenerCallback[T any](
	ctx context.Context,
	owner *runtimeListenerCallbackOwner,
	source string,
	operation ListenerCallbackOperation,
	invoke func() (T, error),
) (zero T, err error) {
	value, callErr, _ := invokeRuntimeListenerCallbackWithCleanup(ctx, owner, source, operation, invoke, nil)
	return value, callErr
}

func invokeRuntimeListenerCallbackWithCleanup[T any](
	ctx context.Context,
	owner *runtimeListenerCallbackOwner,
	source string,
	operation ListenerCallbackOperation,
	invoke func() (T, error),
	cleanup func(T),
) (zero T, err error, abandoned bool) {
	lease, err := acquireRuntimeListenerCallbackLease(ctx, owner, source, operation)
	if err != nil {
		return zero, err, false
	}
	return invokeRuntimeListenerCallbackWithLeaseAndCleanup(ctx, lease, source, operation, invoke, cleanup)
}

func acquireRuntimeListenerCallbackLease(
	ctx context.Context,
	owner *runtimeListenerCallbackOwner,
	source string,
	operation ListenerCallbackOperation,
) (*runtimeListenerCallbackLease, error) {
	if owner == nil {
		owner = newRuntimeListenerCallbackOwner()
	}
	permitSets := []*runtimeListenerCallbackPermits{owner.permits}
	if owner.scope != nil {
		// The per-Runtime scope also covers concurrent pre-claim Listen calls,
		// which do not yet have a SessionListener to own their resource budget.
		permitSets = append(permitSets, owner.scope.permits)
		owner.scope.retainCall()
	}
	permitSets = append(permitSets, runtimeListenerProcessCallbackPermits)
	acquireTimer := time.NewTimer(runtimeListenerCallTimeout)
	defer acquireTimer.Stop()
	acquired := make([]chan struct{}, 0, len(permitSets))
	releaseAcquired := func() {
		for index := len(acquired) - 1; index >= 0; index-- {
			<-acquired[index]
		}
	}
	for _, permitSet := range permitSets {
		permits := permitSet.forOperation(operation)
		select {
		case permits <- struct{}{}:
			acquired = append(acquired, permits)
		case <-ctx.Done():
			releaseAcquired()
			if owner.scope != nil {
				owner.scope.releaseCall()
			}
			if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
				return nil, &ListenerCallbackError{
					Source: source, Operation: operation, Reason: ListenerCallbackResourceLimited,
				}
			}
			return nil, ctx.Err()
		case <-acquireTimer.C:
			releaseAcquired()
			if owner.scope != nil {
				owner.scope.releaseCall()
			}
			return nil, &ListenerCallbackError{
				Source: source, Operation: operation, Reason: ListenerCallbackResourceLimited,
			}
		}
	}
	return &runtimeListenerCallbackLease{owner: owner, scope: owner.scope, acquired: acquired}, nil
}

func invokeRuntimeListenerCallbackWithLeaseAndCleanup[T any](
	ctx context.Context,
	lease *runtimeListenerCallbackLease,
	source string,
	operation ListenerCallbackOperation,
	invoke func() (T, error),
	cleanup func(T),
) (zero T, err error, abandoned bool) {
	type callbackState struct {
		sync.Mutex
		result    runtimeListenerCallResult[T]
		completed bool
		abandoned bool
	}
	state := new(callbackState)
	done := make(chan struct{})
	deliver := func(call runtimeListenerCallResult[T]) {
		state.Lock()
		if state.abandoned {
			state.Unlock()
			lease.recordTerminalDiagnostic(call.err)
			if cleanup != nil {
				cleanup(call.value)
			}
			lease.release()
			return
		}
		// Publish completion only after capacity is returned. A waiter which
		// wakes on done therefore observes the callback as fully handed back.
		lease.release()
		state.result = call
		state.completed = true
		close(done)
		state.Unlock()
	}
	go func() {
		completed := false
		defer func() {
			if completed {
				return
			}
			recovered := recover()
			failure := &ListenerCallbackError{
				Source: source, Operation: operation, Reason: ListenerCallbackAbnormalExit,
			}
			if recovered != nil {
				failure.Reason = ListenerCallbackPanic
				failure.PanicType = reflect.TypeOf(recovered).String()
			}
			deliver(runtimeListenerCallResult[T]{err: failure})
		}()
		value, callErr := invoke()
		completed = true
		deliver(runtimeListenerCallResult[T]{value: value, err: callErr})
	}()

	select {
	case <-done:
		state.Lock()
		call := state.result
		state.Unlock()
		return call.value, call.err, false
	case <-ctx.Done():
		state.Lock()
		if state.completed {
			call := state.result
			state.Unlock()
			return call.value, call.err, false
		}
		state.abandoned = true
		state.Unlock()
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			return zero, &ListenerCallbackError{
				Source: source, Operation: operation, Reason: ListenerCallbackTimeout,
			}, true
		}
		return zero, ctx.Err(), true
	}
}

func invokeRuntimeListenerAcceptedPath[T any](
	ctx context.Context,
	owner *runtimeListenerCallbackOwner,
	source string,
	operation ListenerCallbackOperation,
	invoke func() (T, error),
	path func(T) transport.PathConn,
) (zero T, closeCall *runtimeListenerPathClose, err error) {
	cleanupLease, reserveErr := reserveRuntimeListenerPathClose(ctx, source, owner)
	if reserveErr != nil {
		var callbackErr *ListenerCallbackError
		if errors.As(reserveErr, &callbackErr) {
			callbackErr.Operation = operation
		}
		return zero, nil, reserveErr
	}
	cleanupLate := func(value T) {
		owned := path(value)
		if isNilNetworkSource(owned) {
			cleanupLease.release()
			return
		}
		newRuntimeListenerPathClose(source, owned, cleanupLease, nil).start()
	}
	value, callErr, abandoned := invokeRuntimeListenerCallbackWithCleanup(
		ctx, owner, source, operation, invoke, cleanupLate,
	)
	if abandoned {
		return zero, nil, callErr
	}
	owned := path(value)
	if isNilNetworkSource(owned) {
		cleanupLease.release()
		return value, nil, callErr
	}
	return value, newRuntimeListenerPathClose(source, owned, cleanupLease, nil), callErr
}

func invokeRuntimeListenerMetadata[T any](owner *runtimeListenerCallbackOwner, source string, operation ListenerCallbackOperation, invoke func() T) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	defer cancel()
	return invokeRuntimeListenerCallback(ctx, owner, source, operation, func() (T, error) {
		return invoke(), nil
	})
}

// StreamSource contributes one embedder-owned stream listener to a Runtime
// ingress domain. SessionListener.Close closes Listener; already accepted
// rendr sessions own independent connections and remain usable.
type StreamSource struct {
	Name     string
	Carrier  CarrierFamily
	Listener net.Listener
}

// PacketSource contributes one embedder-owned packet socket to a Runtime
// ingress domain. The socket is demultiplexed by rendr flow ID. Closing the
// SessionListener stops new flows but keeps the shared socket alive until all
// accepted sessions release their virtual paths.
type PacketSource struct {
	Name            string
	Carrier         CarrierFamily
	Conn            net.PacketConn
	MaxDatagramSize int
}

type runtimeListenerPacketReadResult struct {
	n    int
	addr net.Addr
	err  error
}

type runtimeListenerPacketReadRequest struct {
	payload []byte
	result  chan runtimeListenerPacketReadResult
}

type runtimeListenerPacketWriteRequest struct {
	payload []byte
	addr    net.Addr
	result  chan runtimeListenerCallResult[int]
}

// runtimeListenerPacketConn contains caller-owned PacketConn methods without
// putting one goroutine allocation on every datagram. Read and write each use
// one fixed worker and one process/runtime/listener callback lease.
type runtimeListenerPacketConn struct {
	source     string
	raw        net.PacketConn
	owner      *runtimeListenerCallbackOwner
	closeLease *runtimeListenerCallbackLease

	closed chan struct{}

	readOnce     sync.Once
	readStarted  atomic.Bool
	readDone     chan struct{}
	readReq      chan runtimeListenerPacketReadRequest
	writeOnce    sync.Once
	writeStarted atomic.Bool
	writeDone    chan struct{}
	writeReq     chan runtimeListenerPacketWriteRequest

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error

	scopeReleaseOnce sync.Once
}

func newRuntimeListenerPacketConn(source string, raw net.PacketConn, owner *runtimeListenerCallbackOwner, closeLeases ...*runtimeListenerCallbackLease) *runtimeListenerPacketConn {
	if owner == nil {
		owner = newRuntimeListenerCallbackOwner()
	}
	conn := &runtimeListenerPacketConn{
		source:    source,
		raw:       raw,
		owner:     owner,
		closed:    make(chan struct{}),
		readDone:  make(chan struct{}),
		readReq:   make(chan runtimeListenerPacketReadRequest),
		writeDone: make(chan struct{}),
		writeReq:  make(chan runtimeListenerPacketWriteRequest),
		closeDone: make(chan struct{}),
	}
	if len(closeLeases) != 0 {
		conn.closeLease = closeLeases[0]
	}
	if owner.scope != nil {
		runtimeListenerCallbackScopes.Lock()
		owner.scope.owners++
		runtimeListenerCallbackScopes.Unlock()
	}
	return conn
}

func (conn *runtimeListenerPacketConn) releaseScope() {
	if conn == nil || conn.owner == nil || conn.owner.scope == nil {
		return
	}
	conn.scopeReleaseOnce.Do(func() {
		runtimeListenerCallbackScopes.Lock()
		if conn.owner.scope.owners > 0 {
			conn.owner.scope.owners--
		}
		releaseRuntimeListenerCallbackScopeLocked(conn.owner.scope)
		runtimeListenerCallbackScopes.Unlock()
	})
}

func (conn *runtimeListenerPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	if conn == nil {
		return 0, nil, net.ErrClosed
	}
	conn.readOnce.Do(func() {
		conn.readStarted.Store(true)
		go func() {
			defer close(conn.readDone)
			conn.readWorker()
		}()
	})
	request := runtimeListenerPacketReadRequest{payload: payload, result: make(chan runtimeListenerPacketReadResult, 1)}
	select {
	case <-conn.closed:
		return 0, nil, net.ErrClosed
	case conn.readReq <- request:
	}
	// Once the caller's buffer is handed to the worker, retain ownership until
	// the exact raw ReadFrom returns. Close may be bounded even for a hostile
	// callback, but it must not let the caller reuse a buffer still being
	// mutated by that callback.
	result := <-request.result
	return result.n, result.addr, result.err
}

func (conn *runtimeListenerPacketConn) readWorker() {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	lease, err := acquireRuntimeListenerCallbackLease(ctx, conn.owner, conn.source, ListenerCallbackPacketRead)
	cancel()
	if err != nil {
		select {
		case request := <-conn.readReq:
			conn.startClose()
			request.result <- runtimeListenerPacketReadResult{err: err}
		case <-conn.closed:
		}
		return
	}
	defer lease.release()
	var current *runtimeListenerPacketReadRequest
	completed := false
	defer func() {
		if completed {
			return
		}
		recovered := recover()
		failure := &ListenerCallbackError{Source: conn.source, Operation: ListenerCallbackPacketRead, Reason: ListenerCallbackAbnormalExit}
		if recovered != nil {
			failure.Reason = ListenerCallbackPanic
			failure.PanicType = reflect.TypeOf(recovered).String()
		}
		conn.startClose()
		if current != nil {
			current.result <- runtimeListenerPacketReadResult{err: failure}
		}
	}()
	for {
		select {
		case <-conn.closed:
			completed = true
			return
		case request := <-conn.readReq:
			current = &request
			result, abnormal := conn.readPacket(request.payload)
			current = nil
			request.result <- result
			if abnormal {
				conn.startClose()
				completed = true
				return
			}
		}
	}
}

func (conn *runtimeListenerPacketConn) readPacket(payload []byte) (result runtimeListenerPacketReadResult, abnormal bool) {
	completed := false
	defer func() {
		if completed {
			return
		}
		abnormal = true
		recovered := recover()
		failure := &ListenerCallbackError{Source: conn.source, Operation: ListenerCallbackPacketRead, Reason: ListenerCallbackAbnormalExit}
		if recovered != nil {
			failure.Reason = ListenerCallbackPanic
			failure.PanicType = reflect.TypeOf(recovered).String()
		}
		result.err = failure
	}()
	result.n, result.addr, result.err = conn.raw.ReadFrom(payload)
	if result.n < 0 || result.n > len(payload) {
		result.n = 0
		result.addr = nil
		result.err = &ListenerCallbackError{
			Source: conn.source, Operation: ListenerCallbackPacketRead, Reason: ListenerCallbackInvalidResult,
		}
		completed = true
		return result, true
	}
	completed = true
	return result, false
}

func (conn *runtimeListenerPacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	if conn == nil {
		return 0, net.ErrClosed
	}
	conn.writeOnce.Do(func() {
		conn.writeStarted.Store(true)
		go func() {
			defer close(conn.writeDone)
			conn.writeWorker()
		}()
	})
	request := runtimeListenerPacketWriteRequest{payload: payload, addr: addr, result: make(chan runtimeListenerCallResult[int], 1)}
	select {
	case <-conn.closed:
		return 0, net.ErrClosed
	case conn.writeReq <- request:
	}
	// Keep the caller's payload borrowed until the exact raw WriteTo completes;
	// a concurrent Close cannot make it safe to mutate the slice early.
	result := <-request.result
	return result.value, result.err
}

func (conn *runtimeListenerPacketConn) writeWorker() {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	lease, err := acquireRuntimeListenerCallbackLease(ctx, conn.owner, conn.source, ListenerCallbackPacketWrite)
	cancel()
	if err != nil {
		select {
		case request := <-conn.writeReq:
			conn.startClose()
			request.result <- runtimeListenerCallResult[int]{err: err}
		case <-conn.closed:
		}
		return
	}
	defer lease.release()
	var current *runtimeListenerPacketWriteRequest
	completed := false
	defer func() {
		if completed {
			return
		}
		recovered := recover()
		failure := &ListenerCallbackError{Source: conn.source, Operation: ListenerCallbackPacketWrite, Reason: ListenerCallbackAbnormalExit}
		if recovered != nil {
			failure.Reason = ListenerCallbackPanic
			failure.PanicType = reflect.TypeOf(recovered).String()
		}
		conn.startClose()
		if current != nil {
			current.result <- runtimeListenerCallResult[int]{err: failure}
		}
	}()
	for {
		select {
		case <-conn.closed:
			completed = true
			return
		case request := <-conn.writeReq:
			current = &request
			result, abnormal := conn.writePacket(request.payload, request.addr)
			current = nil
			request.result <- result
			if abnormal {
				conn.startClose()
				completed = true
				return
			}
		}
	}
}

func (conn *runtimeListenerPacketConn) writePacket(payload []byte, addr net.Addr) (result runtimeListenerCallResult[int], abnormal bool) {
	completed := false
	defer func() {
		if completed {
			return
		}
		abnormal = true
		recovered := recover()
		failure := &ListenerCallbackError{Source: conn.source, Operation: ListenerCallbackPacketWrite, Reason: ListenerCallbackAbnormalExit}
		if recovered != nil {
			failure.Reason = ListenerCallbackPanic
			failure.PanicType = reflect.TypeOf(recovered).String()
		}
		result.err = failure
	}()
	result.value, result.err = conn.raw.WriteTo(payload, addr)
	if result.value < 0 || result.value > len(payload) {
		result.value = 0
		result.err = &ListenerCallbackError{
			Source: conn.source, Operation: ListenerCallbackPacketWrite, Reason: ListenerCallbackInvalidResult,
		}
		completed = true
		return result, true
	}
	completed = true
	return result, false
}

func (conn *runtimeListenerPacketConn) startClose() {
	if conn == nil {
		return
	}
	conn.closeOnce.Do(func() {
		close(conn.closed)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
			defer cancel()
			invoke := func() (struct{}, error) {
				defer conn.releaseScope()
				return struct{}{}, conn.raw.Close()
			}
			var closeErr error
			var abandoned bool
			if conn.closeLease != nil {
				_, closeErr, abandoned = invokeRuntimeListenerCallbackWithLeaseAndCleanup(
					ctx, conn.closeLease, conn.source, ListenerCallbackPacketClose, invoke, nil,
				)
			} else {
				_, closeErr, abandoned = invokeRuntimeListenerCallbackWithCleanup(
					ctx, conn.owner, conn.source, ListenerCallbackPacketClose, invoke, nil,
				)
			}
			conn.closeErr = closeErr
			if !abandoned {
				conn.releaseScope()
			}
			close(conn.closeDone)
		}()
	})
}

func (conn *runtimeListenerPacketConn) Close() error {
	if conn == nil {
		return nil
	}
	conn.startClose()
	<-conn.closeDone
	return errors.Join(conn.closeErr, conn.waitWorkers())
}

func (conn *runtimeListenerPacketConn) waitWorkers() error {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	defer cancel()
	var errs []error
	wait := func(started bool, done <-chan struct{}, operation ListenerCallbackOperation) {
		if !started {
			return
		}
		select {
		case <-done:
		case <-ctx.Done():
			errs = append(errs, &ListenerCallbackError{
				Source: conn.source, Operation: operation, Reason: ListenerCallbackTimeout,
			})
		}
	}
	wait(conn.readStarted.Load(), conn.readDone, ListenerCallbackPacketRead)
	wait(conn.writeStarted.Load(), conn.writeDone, ListenerCallbackPacketWrite)
	return errors.Join(errs...)
}

func (conn *runtimeListenerPacketConn) localAddr() (net.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	defer cancel()
	return invokeRuntimeListenerCallback(ctx, conn.owner, conn.source, ListenerCallbackPacketLocalAddr, func() (net.Addr, error) {
		return conn.raw.LocalAddr(), nil
	})
}

func (conn *runtimeListenerPacketConn) LocalAddr() net.Addr {
	addr, _ := conn.localAddr()
	return addr
}

func (conn *runtimeListenerPacketConn) SetDeadline(deadline time.Time) error {
	return conn.packetControl(func() error { return conn.raw.SetDeadline(deadline) })
}

func (conn *runtimeListenerPacketConn) SetReadDeadline(deadline time.Time) error {
	return conn.packetControl(func() error { return conn.raw.SetReadDeadline(deadline) })
}

func (conn *runtimeListenerPacketConn) SetWriteDeadline(deadline time.Time) error {
	return conn.packetControl(func() error { return conn.raw.SetWriteDeadline(deadline) })
}

func (conn *runtimeListenerPacketConn) packetControl(invoke func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	defer cancel()
	_, err := invokeRuntimeListenerCallback(ctx, conn.owner, conn.source, ListenerCallbackPacketControl, func() (struct{}, error) {
		return struct{}{}, invoke()
	})
	return err
}

func runtimeListenerChannelClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// normalizeRuntimeUDPFlowError translates udpflow's containment boundary back
// into the public Runtime callback vocabulary. The wrapped PacketConn has its
// own bounded workers, so when udpflow times out waiting for Close we can name
// the caller callback that is actually still retaining that Close.
func normalizeRuntimeUDPFlowError(
	source string,
	conn *runtimeListenerPacketConn,
	err error,
) error {
	if err == nil {
		return nil
	}
	var udpErr *uflow.ListenerCallbackError
	if !errors.As(err, &udpErr) {
		return err
	}
	reason := ListenerCallbackAbnormalExit
	switch udpErr.Reason {
	case uflow.ListenerCallbackFailurePanic:
		reason = ListenerCallbackPanic
	case uflow.ListenerCallbackFailureGoexit:
		reason = ListenerCallbackAbnormalExit
	case uflow.ListenerCallbackFailureTimeout:
		reason = ListenerCallbackTimeout
	case uflow.ListenerCallbackFailureSaturated:
		reason = ListenerCallbackResourceLimited
	}
	operation := ListenerCallbackPacketClose
	switch udpErr.Callback {
	case "PacketConn.ReadFrom":
		operation = ListenerCallbackPacketRead
	case "PacketConn.Close":
		if reason == ListenerCallbackTimeout && conn != nil &&
			runtimeListenerChannelClosed(conn.closeDone) {
			switch {
			case conn.readStarted.Load() && !runtimeListenerChannelClosed(conn.readDone):
				operation = ListenerCallbackPacketRead
			case conn.writeStarted.Load() && !runtimeListenerChannelClosed(conn.writeDone):
				operation = ListenerCallbackPacketWrite
			}
		}
	}
	diagnostic := &ListenerCallbackError{
		Source: source, Operation: operation, Reason: reason, PanicType: udpErr.PanicType,
	}
	return errors.Join(diagnostic, err)
}

// FramedSource contributes an optional transport listener that already
// produces rendr PathConn framing and lifecycle signals. It is the ingress
// boundary for transports such as QUIC and gVisor; Runtime owns admission,
// bridge identity, limits, and accepted-session publication after AcceptPath.
// SessionListener.Close closes Listener; accepted paths are independently
// owned by their sessions.
type FramedSource struct {
	Name     string
	Carrier  CarrierFamily
	Listener transport.PathListener
}

// ListenConfig describes the inbound carrier sources that share one Runtime
// identity and bridge namespace.
type ListenConfig struct {
	Streams []StreamSource
	Packets []PacketSource
	Framed  []FramedSource

	// AcceptL3Identity declares that accepted sessions are consumed by a
	// peer-side L3 relay which validates the versioned identity envelope and
	// dispatches an egress. It is a local fact, not an echo of the dialer's
	// request; leaving it false makes PreserveL3Identity dials fail closed.
	AcceptL3Identity bool
}

// acceptedStreamConn restricts the dynamic method set to capabilities an
// inbound session can actually honor. The peer owns the frozen graph and
// factory resolver, so an accepted session cannot initiate AddPath.
type acceptedStreamConn struct {
	Conn
	MigrationController
	ConnectionObserver
	engine        *engine.Engine
	peakAdmission *listenerPeakTransferAdmission
}

// CloseWrite preserves the optional stream half-close surface across the
// inbound capability wrapper. Embedding Conn alone would restrict the dynamic
// method set to the base interface and silently turn a peer FIN into a no-op.
func (c *acceptedStreamConn) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	half, ok := c.Conn.(StreamHalfCloser)
	if !ok {
		return net.ErrClosed
	}
	return half.CloseWrite()
}

type acceptedPacketConn struct {
	PacketConn
	MigrationController
	ConnectionObserver
	engine *engine.Engine
}

// RemoteAddr is an optional convenience exposed by rendr-owned packet
// sessions. The required net.PacketConn contract continues to surface the
// same logical peer through ReadFrom, so external PacketConn implementations
// are not forced to grow a non-standard method.
func (c *acceptedPacketConn) RemoteAddr() net.Addr {
	remote, ok := c.PacketConn.(interface{ RemoteAddr() net.Addr })
	if !ok {
		return nil
	}
	return remote.RemoteAddr()
}

// SessionListener accepts application sessions assembled from all sources in
// one ListenConfig. It implements net.Listener for stream sessions and also
// provides a context-aware, strongly typed AcceptStream method.
type SessionListener struct {
	runtime    *Runtime
	generation uint64

	callbackOnce sync.Once
	callbacks    *runtimeListenerCallbackOwner

	streamAccept chan *acceptedStreamConn
	packetAccept chan *acceptedPacketConn
	streamSlots  chan struct{}
	packetSlots  chan struct{}
	handshakes   chan struct{}

	addrs    []net.Addr
	closers  []runtimeListenerCloser
	carriers map[string]CarrierFamily
	kinds    map[string]transport.PathSessionKind

	streamMobility   []leafmobility.Capability
	packetMobility   []leafmobility.Capability
	acceptL3Identity bool

	sourceMu     sync.Mutex
	activeSource int
	sourceErr    error
	acceptErr    error

	inflightMu   sync.Mutex
	inflight     map[uint64]*runtimeListenerInflightClaim
	nextInflight atomic.Uint64
	closing      bool
	workers      sync.WaitGroup

	admissionMu        sync.Mutex
	bridgeReservations map[engine.BridgeReservation]struct{}

	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}
	closeDone chan struct{}
}

func (l *SessionListener) generationActive() bool {
	if l == nil || l.generation == 0 {
		return true
	}
	return l.callbackOwner().generationActive(l.generation)
}

func (l *SessionListener) reserveBridge(claim *runtimeListenerInflightClaim, flowID [16]byte) (engine.BridgeReservation, error) {
	l.admissionMu.Lock()
	defer l.admissionMu.Unlock()
	if !claim.active() {
		return engine.BridgeReservation{}, net.ErrClosed
	}
	reservation, err := l.runtime.bridges.Reserve(flowID)
	if err != nil {
		return engine.BridgeReservation{}, err
	}
	if l.bridgeReservations == nil {
		l.bridgeReservations = make(map[engine.BridgeReservation]struct{})
	}
	l.bridgeReservations[reservation] = struct{}{}
	return reservation, nil
}

func (l *SessionListener) abortBridge(reservation engine.BridgeReservation) {
	l.admissionMu.Lock()
	delete(l.bridgeReservations, reservation)
	l.runtime.bridges.Abort(reservation)
	l.admissionMu.Unlock()
}

func (l *SessionListener) activateBridge(
	claim *runtimeListenerInflightClaim,
	reservation engine.BridgeReservation,
	sessionID [16]byte,
	e *engine.Engine,
) error {
	l.admissionMu.Lock()
	defer l.admissionMu.Unlock()
	if !claim.active() {
		delete(l.bridgeReservations, reservation)
		l.runtime.bridges.Abort(reservation)
		return net.ErrClosed
	}
	err := l.runtime.bridges.ActivateSession(reservation, sessionID, e)
	delete(l.bridgeReservations, reservation)
	if err != nil {
		l.runtime.bridges.Abort(reservation)
	}
	return err
}

func (l *SessionListener) closeAdmissionFence() []engine.BridgeReservation {
	l.admissionMu.Lock()
	l.inflightMu.Lock()
	l.closing = true
	l.inflightMu.Unlock()
	reservations := make([]engine.BridgeReservation, 0, len(l.bridgeReservations))
	for reservation := range l.bridgeReservations {
		reservations = append(reservations, reservation)
		delete(l.bridgeReservations, reservation)
	}
	l.admissionMu.Unlock()
	return reservations
}

// Listen starts one Runtime-owned ingress domain. All sources use the
// Runtime's stable instance ID and bridge table, so an initial path accepted
// on one source can be joined by a BRIDGE path accepted on another.
func (r *Runtime) Listen(config ListenConfig) (*SessionListener, error) {
	if r == nil {
		return nil, fmt.Errorf("rendr: nil Runtime")
	}
	sourceCount := len(config.Streams) + len(config.Packets) + len(config.Framed)
	if sourceCount == 0 {
		return nil, fmt.Errorf("rendr: ListenConfig requires at least one source")
	}
	if sourceCount > runtimeListenerCallLimit {
		return nil, fmt.Errorf("rendr: ListenConfig has %d sources, limit is %d", sourceCount, runtimeListenerCallLimit)
	}
	callbacks := newRuntimeListenerCallbackOwnerForRuntime(r)
	callbacksTransferred := false
	defer func() {
		if !callbacksTransferred {
			callbacks.release()
		}
	}()
	seen := make(map[string]struct{}, len(config.Streams)+len(config.Packets)+len(config.Framed))
	seenObjects := make(map[uintptr]string, len(config.Streams)+len(config.Packets)+len(config.Framed))
	framedKinds := make(map[string]transport.PathSessionKind, len(config.Framed))
	var streamMobility, packetMobility mobilityCapabilitySet
	for index, source := range config.Streams {
		if source.Name == "" {
			return nil, fmt.Errorf("rendr: StreamSource[%d] has an empty name", index)
		}
		if _, duplicate := seen[source.Name]; duplicate {
			return nil, fmt.Errorf("rendr: duplicate inbound source %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if !source.Carrier.valid() {
			return nil, fmt.Errorf("rendr: StreamSource %q has invalid carrier %d", source.Name, source.Carrier)
		}
		if isNilNetworkSource(source.Listener) {
			return nil, fmt.Errorf("rendr: StreamSource %q has a nil Listener", source.Name)
		}
		if pointer := networkSourcePointer(source.Listener); pointer != 0 {
			if previous := seenObjects[pointer]; previous != "" {
				return nil, fmt.Errorf("rendr: inbound sources %q and %q share one network object", previous, source.Name)
			}
			seenObjects[pointer] = source.Name
		}
	}
	for index, source := range config.Packets {
		if source.Name == "" {
			return nil, fmt.Errorf("rendr: PacketSource[%d] has an empty name", index)
		}
		if _, duplicate := seen[source.Name]; duplicate {
			return nil, fmt.Errorf("rendr: duplicate inbound source %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if !source.Carrier.valid() {
			return nil, fmt.Errorf("rendr: PacketSource %q has invalid carrier %d", source.Name, source.Carrier)
		}
		if isNilNetworkSource(source.Conn) {
			return nil, fmt.Errorf("rendr: PacketSource %q has a nil Conn", source.Name)
		}
		if pointer := networkSourcePointer(source.Conn); pointer != 0 {
			if previous := seenObjects[pointer]; previous != "" {
				return nil, fmt.Errorf("rendr: inbound sources %q and %q share one network object", previous, source.Name)
			}
			seenObjects[pointer] = source.Name
		}
	}
	for index, source := range config.Framed {
		if source.Name == "" {
			return nil, fmt.Errorf("rendr: FramedSource[%d] has an empty name", index)
		}
		if _, duplicate := seen[source.Name]; duplicate {
			return nil, fmt.Errorf("rendr: duplicate inbound source %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if !source.Carrier.valid() {
			return nil, fmt.Errorf("rendr: FramedSource %q has invalid carrier %d", source.Name, source.Carrier)
		}
		if isNilNetworkSource(source.Listener) {
			return nil, fmt.Errorf("rendr: FramedSource %q has a nil Listener", source.Name)
		}
		kind, err := invokeRuntimeListenerMetadata(callbacks, source.Name, ListenerCallbackSessionKind, source.Listener.SessionKind)
		if err != nil {
			return nil, err
		}
		if kind > transport.PathSessionPacket {
			return nil, fmt.Errorf("rendr: FramedSource %q has invalid session kind %d", source.Name, kind)
		}
		framedKinds[source.Name] = kind
		if pointer := networkSourcePointer(source.Listener); pointer != 0 {
			if previous := seenObjects[pointer]; previous != "" {
				return nil, fmt.Errorf("rendr: inbound sources %q and %q share one network object", previous, source.Name)
			}
			seenObjects[pointer] = source.Name
		}
	}
	framedByName := make(map[string]FramedSource, len(config.Framed))
	framedNames := make([]string, 0, len(config.Framed))
	for _, source := range config.Framed {
		framedByName[source.Name] = source
		framedNames = append(framedNames, source.Name)
	}
	sort.Strings(framedNames)
	for _, name := range framedNames {
		source := framedByName[name]
		var sourceMobility mobilityCapabilitySet
		if err := sourceMobility.addImplementation(source.Listener); err != nil {
			return nil, fmt.Errorf("rendr: FramedSource %q has invalid leaf mobility evidence: %w", source.Name, err)
		}
		capabilities := sourceMobility.snapshotAll()
		kind := framedKinds[name]
		if kind == transport.PathSessionAny || kind == transport.PathSessionStream {
			if err := streamMobility.add(capabilities...); err != nil {
				return nil, err
			}
		}
		if kind == transport.PathSessionAny || kind == transport.PathSessionPacket {
			if err := packetMobility.add(capabilities...); err != nil {
				return nil, err
			}
		}
	}
	streamCapabilities, err := streamMobility.snapshotForSession(leafmobility.SessionStream)
	if err != nil {
		return nil, err
	}
	packetCapabilities, err := packetMobility.snapshotForSession(leafmobility.SessionPacket)
	if err != nil {
		return nil, err
	}
	streamAddrs := make(map[string]net.Addr, len(config.Streams))
	for _, source := range config.Streams {
		addr, err := invokeRuntimeListenerMetadata(callbacks, source.Name, ListenerCallbackAddr, source.Listener.Addr)
		if err != nil {
			return nil, err
		}
		streamAddrs[source.Name] = addr
	}
	framedAddrs := make(map[string]net.Addr, len(config.Framed))
	for _, source := range config.Framed {
		addr, err := invokeRuntimeListenerMetadata(callbacks, source.Name, ListenerCallbackAddr, source.Listener.Addr)
		if err != nil {
			return nil, err
		}
		framedAddrs[source.Name] = addr
	}
	sourceCloseLeases := make(map[string]*runtimeListenerCallbackLease, sourceCount)
	packetCloseLeases := make(map[string]*runtimeListenerCallbackLease, len(config.Packets))
	allCleanupLeases := make([]*runtimeListenerCallbackLease, 0, sourceCount+len(config.Packets))
	cleanupTransferred := false
	defer func() {
		if cleanupTransferred {
			return
		}
		for _, lease := range allCleanupLeases {
			lease.release()
		}
	}()
	reserveCleanup := func(source string, operation ListenerCallbackOperation) (*runtimeListenerCallbackLease, error) {
		ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
		defer cancel()
		return acquireRuntimeListenerCallbackLease(ctx, callbacks, source, operation)
	}
	for _, source := range config.Streams {
		lease, err := reserveCleanup(source.Name, ListenerCallbackClose)
		if err != nil {
			return nil, err
		}
		sourceCloseLeases[source.Name] = lease
		allCleanupLeases = append(allCleanupLeases, lease)
	}
	for _, source := range config.Packets {
		lease, err := reserveCleanup(source.Name, ListenerCallbackClose)
		if err != nil {
			return nil, err
		}
		sourceCloseLeases[source.Name] = lease
		allCleanupLeases = append(allCleanupLeases, lease)
		packetLease, err := reserveCleanup(source.Name, ListenerCallbackPacketClose)
		if err != nil {
			return nil, err
		}
		packetCloseLeases[source.Name] = packetLease
		allCleanupLeases = append(allCleanupLeases, packetLease)
	}
	for _, source := range config.Framed {
		lease, err := reserveCleanup(source.Name, ListenerCallbackClose)
		if err != nil {
			return nil, err
		}
		sourceCloseLeases[source.Name] = lease
		allCleanupLeases = append(allCleanupLeases, lease)
	}

	l := &SessionListener{
		runtime:            r,
		callbacks:          callbacks,
		streamAccept:       make(chan *acceptedStreamConn, runtimeAcceptQueueSize),
		packetAccept:       make(chan *acceptedPacketConn, runtimeAcceptQueueSize),
		streamSlots:        make(chan struct{}, runtimeAcceptQueueSize),
		packetSlots:        make(chan struct{}, runtimeAcceptQueueSize),
		handshakes:         make(chan struct{}, runtimeHandshakeLimit),
		activeSource:       len(config.Streams) + len(config.Packets) + len(config.Framed),
		inflight:           make(map[uint64]*runtimeListenerInflightClaim),
		bridgeReservations: make(map[engine.BridgeReservation]struct{}),
		closed:             make(chan struct{}),
		closeDone:          make(chan struct{}),
		carriers:           make(map[string]CarrierFamily, len(config.Streams)+len(config.Packets)+len(config.Framed)),
		kinds:              make(map[string]transport.PathSessionKind, len(config.Streams)+len(config.Packets)+len(config.Framed)),
		streamMobility:     streamCapabilities,
		packetMobility:     packetCapabilities,
		acceptL3Identity:   config.AcceptL3Identity,
	}
	if err := r.claimListener(l); err != nil {
		return nil, err
	}
	l.generation = callbacks.activateGeneration()
	type preparedPacketSource struct {
		source   PacketSource
		listener *uflow.Listener
		conn     *runtimeListenerPacketConn
		addr     net.Addr
	}
	preparedPackets := make([]preparedPacketSource, 0, len(config.Packets))
	for _, source := range config.Packets {
		wrapped := newRuntimeListenerPacketConn(source.Name, source.Conn, callbacks, packetCloseLeases[source.Name])
		packetListener, err := uflow.NewListenerFromPacketConn(wrapped, source.MaxDatagramSize)
		if err != nil {
			_ = wrapped.Close()
			return nil, l.abortListenStart(err)
		}
		addr, err := wrapped.localAddr()
		if err != nil {
			closeErr := packetListener.Close()
			return nil, l.abortListenStart(errors.Join(err, closeErr))
		}
		l.closers = append(l.closers, runtimeListenerCloser{
			source: source.Name, close: func() error {
				return normalizeRuntimeUDPFlowError(source.Name, wrapped, packetListener.Close())
			}, lease: sourceCloseLeases[source.Name],
			timeout: 3 * runtimeListenerCallTimeout,
		})
		preparedPackets = append(preparedPackets, preparedPacketSource{
			source: source, listener: packetListener, conn: wrapped, addr: addr,
		})
	}
	for _, source := range config.Streams {
		l.carriers[source.Name] = source.Carrier
		l.kinds[source.Name] = transport.PathSessionAny
		l.addrs = append(l.addrs, streamAddrs[source.Name])
		l.closers = append(l.closers, runtimeListenerCloser{
			source: source.Name, close: source.Listener.Close, lease: sourceCloseLeases[source.Name],
		})
		l.workers.Add(1)
		go func(source StreamSource) {
			defer l.workers.Done()
			l.acceptStreamSource(source)
		}(source)
	}
	for _, prepared := range preparedPackets {
		l.carriers[prepared.source.Name] = prepared.source.Carrier
		l.kinds[prepared.source.Name] = transport.PathSessionAny
		l.addrs = append(l.addrs, prepared.addr)
		l.workers.Add(1)
		go func(source PacketSource, packetListener *uflow.Listener, conn *runtimeListenerPacketConn) {
			defer l.workers.Done()
			l.acceptPacketSource(source, packetListener, conn)
		}(prepared.source, prepared.listener, prepared.conn)
	}
	for _, source := range config.Framed {
		l.carriers[source.Name] = source.Carrier
		l.kinds[source.Name] = framedKinds[source.Name]
		l.addrs = append(l.addrs, framedAddrs[source.Name])
		l.closers = append(l.closers, runtimeListenerCloser{
			source: source.Name, close: source.Listener.Close, lease: sourceCloseLeases[source.Name],
		})
		l.workers.Add(1)
		go func(source FramedSource) {
			defer l.workers.Done()
			l.acceptFramedSource(source)
		}(source)
	}
	cleanupTransferred = true
	callbacksTransferred = true
	return l, nil
}

func (l *SessionListener) abortListenStart(cause error) error {
	if l == nil {
		return cause
	}
	reservations := l.closeAdmissionFence()
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	for _, reservation := range reservations {
		l.runtime.bridges.Abort(reservation)
	}
	l.runtime.releaseListener(l)
	cleanupErr := closeRuntimeListenerCallbacks(l.closers, l.callbackOwner())
	return errors.Join(cause, cleanupErr, l.callbackOwner().terminalDiagnostics())
}

// Accept implements net.Listener. Packet-mode sessions are delivered only by
// AcceptPacket and never appear here.
func (l *SessionListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (l *SessionListener) AcceptStream(ctx context.Context) (Conn, error) {
	if l == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-l.closed:
		return nil, l.listenerError()
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, l.listenerError()
	case conn := <-l.streamAccept:
		l.inflightMu.Lock()
		closing := l.closing
		l.inflightMu.Unlock()
		l.releaseAcceptSlot(false)
		if closing {
			_ = conn.Close()
			return nil, l.listenerError()
		}
		return conn, nil
	}
}

func (l *SessionListener) AcceptPacket(ctx context.Context) (PacketConn, error) {
	if l == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-l.closed:
		return nil, l.listenerError()
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, l.listenerError()
	case conn := <-l.packetAccept:
		l.inflightMu.Lock()
		closing := l.closing
		l.inflightMu.Unlock()
		l.releaseAcceptSlot(true)
		if closing {
			_ = conn.Close()
			return nil, l.listenerError()
		}
		return conn, nil
	}
}

func (l *SessionListener) Close() error {
	if l == nil {
		return nil
	}
	l.shutdown(net.ErrClosed)
	return errors.Join(l.closeErr, l.callbackOwner().terminalDiagnostics())
}

func (l *SessionListener) Addr() net.Addr {
	if l == nil || len(l.addrs) == 0 {
		return nil
	}
	return l.addrs[0]
}

func (l *SessionListener) Addrs() []net.Addr {
	if l == nil {
		return nil
	}
	return append([]net.Addr(nil), l.addrs...)
}

// FlowIDs returns the active flow set for the whole Runtime ingress domain,
// including sessions accepted by another SessionListener on the same Runtime.
func (l *SessionListener) FlowIDs() [][16]byte {
	if l == nil || l.runtime == nil || l.runtime.bridges == nil {
		return nil
	}
	return l.runtime.bridges.Snapshot()
}

func (l *SessionListener) acceptStreamSource(source StreamSource) {
	ctx, cancel := l.listenerSourceContext()
	defer cancel()
	terminalErr := error(net.ErrClosed)
	defer func() { l.sourceEnded(terminalErr) }()
	for {
		raw, closeCall, err := invokeRuntimeListenerAcceptedPath(
			ctx,
			l.callbackOwner(),
			source.Name,
			ListenerCallbackAccept,
			func() (net.Conn, error) { return source.Listener.Accept() },
			func(conn net.Conn) transport.PathConn {
				if isNilNetworkSource(conn) {
					return nil
				}
				return &runtimeListenerNetConnCleanup{conn: conn}
			},
		)
		if err != nil {
			if closeCall != nil {
				closeCall.start()
			}
			terminalErr = err
			return
		}
		if isNilNetworkSource(raw) {
			terminalErr = fmt.Errorf("rendr: StreamSource %q returned a nil connection", source.Name)
			return
		}
		pc := tcp.Wrap(raw)
		if !l.acquireHandshake() {
			closeCall.start()
			return
		}
		claim, ok := l.trackInflight(source.Name, pc, closeCall)
		if !ok {
			<-l.handshakes
			closeCall.start()
			return
		}
		if err := l.setClaimedStreamDeadline(claim, raw, time.Now().Add(runtimeHandshakeTimeout), ListenerCallbackSetDeadline); err != nil {
			claim.finish(false)
			continue
		}
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			l.serveIncoming(claim, source.Carrier, func() error {
				return l.setClaimedStreamDeadline(claim, raw, time.Time{}, ListenerCallbackClearDeadline)
			})
		}()
	}
}

func (l *SessionListener) acceptPacketSource(
	source PacketSource,
	listener *uflow.Listener,
	conn *runtimeListenerPacketConn,
) {
	ctx, cancel := l.listenerSourceContext()
	defer cancel()
	terminalErr := error(net.ErrClosed)
	defer func() { l.sourceEnded(terminalErr) }()
	for {
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, runtimeListenerCallTimeout)
		cleanupLease, reserveErr := reserveRuntimeListenerPathClose(cleanupCtx, source.Name, l.callbackOwner())
		cleanupCancel()
		if reserveErr != nil {
			var callbackErr *ListenerCallbackError
			if errors.As(reserveErr, &callbackErr) {
				callbackErr.Operation = ListenerCallbackPacketAccept
			}
			terminalErr = reserveErr
			return
		}
		pc, err := listener.Accept(ctx)
		if err != nil {
			cleanupLease.release()
			terminalErr = normalizeRuntimeUDPFlowError(source.Name, conn, err)
			return
		}
		closeCall := newRuntimeListenerPathClose(source.Name, pc, cleanupLease, nil)
		if !l.acquireHandshake() {
			closeCall.start()
			return
		}
		claim, ok := l.trackInflight(source.Name, pc, closeCall)
		if !ok {
			<-l.handshakes
			closeCall.start()
			return
		}
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			l.serveIncoming(claim, source.Carrier, func() error { return nil })
		}()
	}
}

func (l *SessionListener) acceptFramedSource(source FramedSource) {
	ctx, cancel := l.listenerSourceContext()
	defer cancel()
	terminalErr := error(net.ErrClosed)
	defer func() { l.sourceEnded(terminalErr) }()
	for {
		pc, closeCall, acceptTimedOut, err := invokeRuntimeListenerFramedAccept(
			ctx, l.callbackOwner(), source, runtimeHandshakeTimeout,
		)
		if err != nil {
			if closeCall != nil {
				closeCall.start()
			}
			var callbackErr *ListenerCallbackError
			if errors.As(err, &callbackErr) && callbackErr.Reason == ListenerCallbackTimeout {
				l.callbackOwner().recordTerminalDiagnostic(err)
			}
			if acceptTimedOut && ctx.Err() == nil {
				continue
			}
			terminalErr = err
			return
		}
		if isNilNetworkSource(pc) {
			terminalErr = fmt.Errorf("rendr: FramedSource %q returned a nil PathConn", source.Name)
			return
		}
		if !l.acquireHandshake() {
			closeCall.start()
			return
		}
		claim, ok := l.trackInflight(source.Name, pc, closeCall)
		if !ok {
			<-l.handshakes
			closeCall.start()
			return
		}
		clearDeadline := armClaimedPathHandshakeDeadline(claim, runtimeHandshakeTimeout)
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			l.serveIncoming(claim, source.Carrier, func() error {
				clearDeadline()
				return nil
			})
		}()
	}
}

func invokeRuntimeListenerFramedAccept(
	sourceCtx context.Context,
	owner *runtimeListenerCallbackOwner,
	source FramedSource,
	acceptTimeout time.Duration,
) (transport.PathConn, *runtimeListenerPathClose, bool, error) {
	if sourceCtx == nil || acceptTimeout <= 0 {
		return nil, nil, false, &ListenerCallbackError{
			Source: source.Name, Operation: ListenerCallbackAcceptPath, Reason: ListenerCallbackInvalidResult,
		}
	}
	acceptCtx, acceptCancel := context.WithTimeout(sourceCtx, acceptTimeout)
	defer acceptCancel()

	// Admission and hand-back are separate stages. Once either the admission
	// deadline or listener shutdown fires, an already-started callback gets one
	// independent listener-call budget to return. The source Close callback is
	// still responsible for unblocking work which ignores its context.
	waitCtx, waitCancel := context.WithCancelCause(context.Background())
	defer waitCancel(context.Canceled)
	returned := make(chan struct{})
	defer close(returned)
	go func() {
		select {
		case <-acceptCtx.Done():
		case <-sourceCtx.Done():
		case <-returned:
			return
		}
		timer := time.NewTimer(runtimeListenerCallTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			waitCancel(context.DeadlineExceeded)
		case <-returned:
		}
	}()
	pc, closeCall, err := invokeRuntimeListenerAcceptedPath(
		waitCtx,
		owner,
		source.Name,
		ListenerCallbackAcceptPath,
		func() (transport.PathConn, error) { return source.Listener.AcceptPath(acceptCtx) },
		func(path transport.PathConn) transport.PathConn { return path },
	)
	pureDeadline := isNilNetworkSource(pc) && acceptCtx.Err() == context.DeadlineExceeded && err == context.DeadlineExceeded
	return pc, closeCall, pureDeadline, err
}

func (l *SessionListener) setClaimedStreamDeadline(
	claim *runtimeListenerInflightClaim,
	conn net.Conn,
	deadline time.Time,
	operation ListenerCallbackOperation,
) error {
	if !claim.active() {
		return net.ErrClosed
	}
	sourceCtx, cancelSource := l.listenerSourceContext()
	defer cancelSource()
	ctx, cancel := context.WithTimeout(sourceCtx, runtimeListenerCallTimeout)
	defer cancel()
	_, err := invokeRuntimeListenerCallback(ctx, l.callbackOwner(), claim.source, operation, func() (struct{}, error) {
		return struct{}{}, conn.SetDeadline(deadline)
	})
	if !claim.active() {
		return net.ErrClosed
	}
	return err
}

func (l *SessionListener) listenerSourceContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-l.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (l *SessionListener) callbackOwner() *runtimeListenerCallbackOwner {
	if l == nil {
		return newRuntimeListenerCallbackOwner()
	}
	l.callbackOnce.Do(func() {
		if l.callbacks == nil {
			l.callbacks = newRuntimeListenerCallbackOwner()
		}
	})
	return l.callbacks
}

func armPathHandshakeDeadline(pc transport.PathConn) func() {
	return armPathHandshakeDeadlineAfter(pc, runtimeHandshakeTimeout)
}

func armPathHandshakeDeadlineAfter(pc transport.PathConn, timeout time.Duration) func() {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	lease, err := reserveRuntimeListenerPathClose(ctx, "handshake", nil)
	cancel()
	closeCall := newRuntimeListenerPathClose("handshake", pc, lease, err)
	clearTimer := armRuntimePathHandshakeDeadline(timeout, func() {
		closeCall.start()
	})
	return func() {
		clearTimer()
		// If timeout already won, startOnce keeps ownership with the close
		// callback until it exits. Otherwise clearing the timer returns the
		// reservation to the caller that still owns the live path.
		closeCall.releaseToEngine()
	}
}

func armClaimedPathHandshakeDeadline(claim *runtimeListenerInflightClaim, timeout time.Duration) func() {
	return armRuntimePathHandshakeDeadline(timeout, func() {
		claim.cancel()
	})
}

func armRuntimePathHandshakeDeadline(timeout time.Duration, expire func()) func() {
	var active atomic.Bool
	active.Store(true)
	timer := time.AfterFunc(timeout, func() {
		if active.CompareAndSwap(true, false) {
			expire()
		}
	})
	return func() {
		if active.CompareAndSwap(true, false) {
			timer.Stop()
		}
	}
}

func (l *SessionListener) acquireHandshake() bool {
	select {
	case <-l.closed:
		return false
	case l.handshakes <- struct{}{}:
		return true
	}
}

func (l *SessionListener) serveIncoming(claim *runtimeListenerInflightClaim, _ CarrierFamily, clearDeadline func() error) {
	owned := false
	var clearDeadlineOnce sync.Once
	var clearDeadlineErr error
	clearHandshakeDeadline := func() error {
		clearDeadlineOnce.Do(func() { clearDeadlineErr = clearDeadline() })
		return clearDeadlineErr
	}
	defer func() {
		_ = clearHandshakeDeadline()
		claim.finish(owned)
	}()

	pc := claim.path
	hdr, payload, err := engine.ReadFirstFrame(pc)
	if err != nil {
		return
	}
	if !claim.active() {
		return
	}
	code, ok := canonicalFirstControlCode(hdr)
	if !ok {
		return
	}
	switch code {
	case proto.CtrlHello:
		owned = l.handleRuntimeHello(claim, payload, clearHandshakeDeadline)
	case proto.CtrlBridgeTag:
		// The first-frame deadline has done its job. Bridge admission owns its
		// own bounded context; retaining the socket deadline would truncate it.
		if clearHandshakeDeadline() == nil {
			owned = l.handleRuntimeBridge(claim, payload)
		}
	}
}

func (l *SessionListener) pathAddress(claim *runtimeListenerInflightClaim, operation ListenerCallbackOperation) (string, bool) {
	if !claim.active() {
		return "", false
	}
	sourceCtx, cancelSource := l.listenerSourceContext()
	defer cancelSource()
	ctx, cancel := context.WithTimeout(sourceCtx, runtimeListenerCallTimeout)
	defer cancel()
	address, err := invokeRuntimeListenerCallback(
		ctx,
		l.callbackOwner(),
		claim.source,
		operation,
		func() (string, error) {
			switch operation {
			case ListenerCallbackLocalAddr:
				return claim.path.LocalAddr(), nil
			case ListenerCallbackRemoteAddr:
				return claim.path.RemoteAddr(), nil
			default:
				return "", fmt.Errorf("rendr: unsupported PathConn metadata callback %q", operation)
			}
		},
	)
	if !claim.active() {
		return "", false
	}
	if err != nil {
		// PathConn addresses are advisory. A malformed diagnostic callback
		// cannot control admission while the physical claim remains live.
		return "", true
	}
	return address, true
}

func attachClaimedServerPath(
	claim *runtimeListenerInflightClaim,
	e *engine.Engine,
	pc transport.PathConn,
	spec PathSpec,
	peerTargetID proto.TargetID,
	peerReceiveFrameCapacity uint32,
) (uint32, proto.TargetID, error) {
	peerName, err := e.PeerPathName(peerTargetID)
	if err != nil {
		return 0, proto.TargetID{}, err
	}
	localTargetID, err := e.LocalPathTargetID(peerName)
	if err != nil {
		return 0, proto.TargetID{}, err
	}
	localReceiveFrameCapacity, err := e.InspectPacketPathFrameCapacity(pc)
	if err != nil {
		return 0, proto.TargetID{}, err
	}
	if !claim.beginEngineAttach(e) {
		return 0, proto.TargetID{}, net.ErrClosed
	}
	id, adopted, err := e.PreparePathBoundWithOwnership(pc, spec, engine.PathBinding{
		LocalTXTargetID:           localTargetID,
		PeerTXTargetID:            peerTargetID,
		LocalReceiveFrameCapacity: localReceiveFrameCapacity,
		PeerReceiveFrameCapacity:  peerReceiveFrameCapacity,
	})
	active := claim.resolveEngineAttach(e, id, adopted)
	if err != nil {
		return 0, proto.TargetID{}, err
	}
	if !active {
		return 0, proto.TargetID{}, net.ErrClosed
	}
	return id, localTargetID, nil
}

func (l *SessionListener) handleRuntimeHello(
	claim *runtimeListenerInflightClaim,
	payload []byte,
	clearHandshakeDeadline func() error,
) bool {
	pc := claim.path
	sourceName := claim.source
	hello, err := decodeHelloForAdmission(pc, payload)
	if err != nil {
		return false
	}
	if hello.FlowID == ([16]byte{}) || hello.InstanceID == (proto.InstanceID{}) {
		return false
	}
	packetMode := hello.Caps&proto.CapsPacketMode != 0
	if !l.sourceAllowsSession(sourceName, packetMode) {
		return false
	}
	// PreserveL3Identity is a bilateral requirement, not an advisory feature.
	// Reject before reserving bridge/admission resources so packet transports
	// cannot leave a 10-second COMMIT waiter after the caller fails closed.
	if hello.Caps&proto.CapsL3Identity != 0 && !l.acceptL3Identity {
		_ = engine.PerformBye(pc, proto.ByeAppRequest, 0)
		return false
	}
	remoteAddress, ok := l.pathAddress(claim, ListenerCallbackRemoteAddr)
	if !ok {
		return false
	}
	localAddress, ok := l.pathAddress(claim, ListenerCallbackLocalAddr)
	if !ok {
		return false
	}
	// HELLO admission owns separate pre-COMMIT and migration-budget contexts.
	// Keep the first-frame deadline armed through every immediate rejection so
	// a peer that stops reading cannot pin a handshake slot in the BYE write.
	if err := clearHandshakeDeadline(); err != nil {
		return false
	}
	var reservation engine.BridgeReservation
	for {
		reservation, err = l.reserveBridge(claim, hello.FlowID)
		if err == nil {
			break
		}
		if !errors.Is(err, engine.ErrBridgeDuplicate) {
			return false
		}
		e, state, waitErr := l.awaitRuntimeEngine(hello.FlowID)
		if waitErr != nil {
			return false
		}
		if state == engine.BridgeEntryAbsent {
			continue
		}
		if state != engine.BridgeEntryActive || e == nil {
			return false
		}
		return l.handleDuplicateRuntimeHello(claim, remoteAddress, hello, payload, e)
	}
	if !l.acquireAcceptSlot(packetMode) {
		l.abortBridge(reservation)
		return false
	}
	slotHeld := true
	defer func() {
		if slotHeld {
			l.releaseAcceptSlot(packetMode)
		}
	}()

	activated := false
	defer func() {
		if !activated {
			l.abortBridge(reservation)
		}
	}()

	var sessionID [16]byte
	for {
		sessionID = engine.NewClientFlowID()
		if sessionID == ([16]byte{}) || sessionID == hello.FlowID {
			continue
		}
		err = l.runtime.bridges.AssignSession(reservation, sessionID)
		if err == nil {
			break
		}
		if !errors.Is(err, engine.ErrBridgeSessionConflict) {
			return false
		}
	}

	e := engine.New(engine.SideServer, sessionID, l.runtime.engineLimits())
	e.SetLeafMobilityPeerLedger(l.runtime.mobilityLedger)
	mobilityCapabilities := l.streamMobility
	if packetMode {
		mobilityCapabilities = l.packetMobility
	}
	if err := e.ConfigureLocalMobilityCapabilities(mobilityCapabilities...); err != nil {
		_ = e.Close()
		return false
	}
	engineOwnsPath := false
	defer func() {
		if !activated {
			_ = e.Close()
		}
	}()
	peerNegotiation := hello.Negotiation
	peerNegotiation.SessionEpoch = proto.SessionEpoch(sessionID)
	if err := e.AcceptPeerNegotiation(peerNegotiation, hello.LocalTXManifest); err != nil {
		rejectIncompatibleNegotiation(pc, err)
		return false
	}
	if err := e.MirrorPeerGraphForLocal(); err != nil {
		return false
	}
	peakAdmission := installPeakTransferPeerAdmission(e)
	e.SetLocalInstanceID(l.runtime.instanceID)
	e.SetPeerKind(engine.PeerRendr)
	if err := e.SetPeerInstanceID(hello.InstanceID); err != nil {
		return false
	}
	e.SetPeerCaps(hello.Caps)
	if packetMode {
		e.SetPacketMode()
	}

	spec := specWithTargetName(PathSpec{Transport: sourceName, Address: remoteAddress}, helloPathName(hello))
	pathID, localTargetID, err := attachClaimedServerPath(claim, e, pc, spec, hello.InitialTargetID, hello.ReceiveFrameCapacity)
	if err != nil {
		return false
	}
	engineOwnsPath = true
	localCaps := eLocalCaps(e, l.acceptL3Identity)
	admissionCtx, cancelAdmission := l.listenerSourceContext()
	defer cancelAdmission()
	if err := acknowledgeInitialServerPath(admissionCtx, e, pathID, pc, l.runtime.instanceID, localCaps, localTargetID, hello, payload); err != nil {
		return false
	}
	if !claim.active() {
		e.AbortPathAttach(pathID, net.ErrClosed)
		return false
	}
	if err := l.activateBridge(claim, reservation, sessionID, e); err != nil {
		_ = e.Close()
		return engineOwnsPath
	}
	activated = true
	go func() {
		<-e.Closed()
		l.runtime.bridges.RemoveActive(reservation, e)
	}()

	laddr := addrFromString(localAddress)
	if packetMode {
		base := newEnginePacketConn(e, laddr)
		base.localStatus = l.runtime.LocalStatus
		base.carriers = l.carriers
		conn := &acceptedPacketConn{
			PacketConn:          base,
			MigrationController: base,
			ConnectionObserver:  base,
			engine:              e,
		}
		if l.publishPacket(claim, conn) {
			slotHeld = false
		} else {
			// The application never acquired this session, so there is no
			// graceful-close obligation. A graceful BYE can wait the full
			// migration budget after listener shutdown has already removed every
			// route, pinning the worker that shutdown is joining.
			_ = e.Close()
		}
		return true
	}
	raddr := addrFromString(remoteAddress)
	base := newEngineBackedConn(e, &engine.Conn{E: e, LAddr: laddr, RAddr: raddr})
	base.localStatus = l.runtime.LocalStatus
	base.carriers = l.carriers
	conn := &acceptedStreamConn{
		Conn:                base,
		MigrationController: base,
		ConnectionObserver:  base,
		engine:              e,
		peakAdmission:       peakAdmission,
	}
	if l.publishStream(claim, conn) {
		slotHeld = false
	} else {
		_ = e.Close()
	}
	return true
}

func (l *SessionListener) handleDuplicateRuntimeHello(claim *runtimeListenerInflightClaim, remoteAddress string, hello proto.HelloPayload, proposalWire []byte, e *engine.Engine) bool {
	pc := claim.path
	if e.PeerKind() != engine.PeerRendr || e.PeerInstanceID() != hello.InstanceID || e.PeerCaps() != hello.Caps {
		return false
	}
	if e.Packetized() != (hello.Caps&proto.CapsPacketMode != 0) {
		return false
	}
	peerNegotiation := hello.Negotiation
	peerNegotiation.SessionEpoch = proto.SessionEpoch(e.FlowID())
	if err := e.ValidatePeerNegotiation(peerNegotiation, hello.LocalTXManifest); err != nil {
		rejectIncompatibleNegotiation(pc, err)
		return false
	}
	name, err := e.PeerPathName(hello.InitialTargetID)
	if err != nil || name != helloPathName(hello) {
		return false
	}
	spec := specWithTargetName(PathSpec{Transport: claim.source, Address: remoteAddress}, name)
	pathID, localTargetID, err := attachClaimedServerPath(claim, e, pc, spec, hello.InitialTargetID, hello.ReceiveFrameCapacity)
	if err != nil {
		return false
	}
	admissionCtx, cancelAdmission := l.listenerSourceContext()
	defer cancelAdmission()
	if err := acknowledgeInitialServerPath(admissionCtx, e, pathID, pc, l.runtime.instanceID, eLocalCaps(e, l.acceptL3Identity), localTargetID, hello, proposalWire); err != nil {
		return false
	}
	if !claim.active() {
		e.AbortPathAttach(pathID, net.ErrClosed)
		return false
	}
	return true
}

func (l *SessionListener) handleRuntimeBridge(claim *runtimeListenerInflightClaim, payload []byte) bool {
	pc := claim.path
	tag, err := proto.DecodeBridgeTag(payload)
	if err != nil {
		return false
	}
	if tag.ExpectedPeerInstanceID != l.runtime.instanceID {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, proto.AckRejectInstance, "peer instance mismatch")
		return false
	}
	e, state, err := l.awaitRuntimeEngine(tag.BridgeID)
	if err != nil || state != engine.BridgeEntryActive || e == nil {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, proto.AckRejectUnknown, "unknown flow")
		return false
	}
	if !l.sourceAllowsSession(claim.source, e.Packetized()) {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, proto.AckRejectAttach, "source session kind mismatch")
		return false
	}
	select {
	case <-l.closed:
		return false
	default:
	}
	if err := e.ValidateBridgeBinding(tag); err != nil {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, bridgeValidationAckCode(err), err.Error())
		return false
	}
	remoteAddress, ok := l.pathAddress(claim, ListenerCallbackRemoteAddr)
	if !ok {
		return false
	}
	spec := specWithTargetName(PathSpec{Transport: claim.source, Address: remoteAddress}, bridgePathName(e, tag))
	pathID, localTargetID, err := attachClaimedServerPath(claim, e, pc, spec, tag.TargetID, tag.ReceiveFrameCapacity)
	if err != nil {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, proto.AckRejectAttach, err.Error())
		return false
	}
	admissionCtx, cancelAdmission := l.listenerSourceContext()
	defer cancelAdmission()
	if err := acknowledgeServerPath(admissionCtx, e, pathID, pc, tag, payload, l.runtime.instanceID, localTargetID); err != nil {
		return false
	}
	if !claim.active() {
		e.AbortPathAttach(pathID, net.ErrClosed)
		return false
	}
	return true
}

func (l *SessionListener) awaitRuntimeEngine(flowID [16]byte) (*engine.Engine, engine.BridgeEntryState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeBridgeAwaitTimeout)
	stopCloseWatch := make(chan struct{})
	go func() {
		select {
		case <-l.closed:
			cancel()
		case <-ctx.Done():
		case <-stopCloseWatch:
		}
	}()
	defer close(stopCloseWatch)
	defer cancel()
	return l.runtime.bridges.WaitActive(ctx, flowID)
}

func (l *SessionListener) sourceAllowsSession(sourceName string, packetMode bool) bool {
	kind, known := l.kinds[sourceName]
	if !known {
		return false
	}
	switch kind {
	case transport.PathSessionAny:
		return true
	case transport.PathSessionStream:
		return !packetMode
	case transport.PathSessionPacket:
		return packetMode
	default:
		return false
	}
}

func (l *SessionListener) acquireAcceptSlot(packet bool) bool {
	slots := l.streamSlots
	if packet {
		slots = l.packetSlots
	}
	timer := time.NewTimer(runtimeHandshakeTimeout)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		return true
	case <-l.closed:
		return false
	case <-timer.C:
		return false
	}
}

func (l *SessionListener) releaseAcceptSlot(packet bool) {
	slots := l.streamSlots
	if packet {
		slots = l.packetSlots
	}
	select {
	case <-slots:
	default:
	}
}

func (l *SessionListener) sourceEnded(err error) {
	l.sourceMu.Lock()
	closed := false
	select {
	case <-l.closed:
		closed = true
	default:
	}
	if !closed && l.sourceErr == nil {
		l.sourceErr = err
	}
	if l.activeSource > 0 {
		l.activeSource--
	}
	last := l.activeSource == 0
	cause := l.sourceErr
	l.sourceMu.Unlock()
	if last && !closed {
		// sourceEnded runs inside a counted source worker. Shutdown joins all
		// workers, so transfer ownership to another goroutine before returning.
		go l.shutdown(cause)
	}
}

func (l *SessionListener) shutdown(cause error) {
	l.closeOnce.Do(func() {
		l.sourceMu.Lock()
		if l.acceptErr == nil {
			l.acceptErr = cause
		}
		l.sourceMu.Unlock()
		reservations := l.closeAdmissionFence()
		close(l.closed)
		for _, reservation := range reservations {
			l.runtime.bridges.Abort(reservation)
		}
		go l.finishShutdown()
	})
	<-l.closeDone
}

func (l *SessionListener) finishShutdown() {
	completed := false
	callbacksReleased := false
	defer func() {
		if !completed {
			recovered := recover()
			failure := &ListenerCallbackError{
				Source: "session-listener", Operation: ListenerCallbackClose, Reason: ListenerCallbackAbnormalExit,
			}
			if recovered != nil {
				failure.Reason = ListenerCallbackPanic
				failure.PanicType = reflect.TypeOf(recovered).String()
			}
			l.closeErr = errors.Join(l.closeErr, failure)
		}
		if !callbacksReleased {
			l.callbackOwner().release()
		}
		l.runtime.releaseListener(l)
		close(l.closeDone)
	}()

	l.closeErr = errors.Join(l.closeErr, closeRuntimeListenerCallbacks(l.closers, l.callbackOwner()))
	l.closeErr = errors.Join(l.closeErr, l.closeInflight())
	workersDone := make(chan struct{})
	go func() {
		l.workers.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
		l.callbackOwner().release()
		callbacksReleased = true
	case <-time.After(runtimeListenerCallTimeout + runtimeListenerWorkerJoinGrace):
		l.closeErr = errors.Join(l.closeErr, &ListenerCallbackError{
			Source: "session-listener-workers", Operation: ListenerCallbackClose, Reason: ListenerCallbackTimeout,
		})
		go func() {
			<-workersDone
			l.callbackOwner().release()
		}()
		callbacksReleased = true
	}
	l.closeErr = errors.Join(l.closeErr, l.drainQueuedSessions())
	completed = true
}

func (l *SessionListener) listenerError() error {
	l.sourceMu.Lock()
	defer l.sourceMu.Unlock()
	if l.acceptErr != nil {
		return l.acceptErr
	}
	return net.ErrClosed
}

func (l *SessionListener) trackInflight(source string, pc transport.PathConn, closeCall *runtimeListenerPathClose) (*runtimeListenerInflightClaim, bool) {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	if l.closing || !l.generationActive() || closeCall == nil || closeCall.lease == nil {
		return nil, false
	}
	id := l.nextInflight.Add(1)
	claim := &runtimeListenerInflightClaim{
		listener: l,
		id:       id,
		source:   source,
		path:     pc,
		close:    closeCall,
	}
	l.inflight[id] = claim
	return claim, true
}

func (l *SessionListener) closeInflight() error {
	l.inflightMu.Lock()
	l.closing = true
	claims := make([]*runtimeListenerInflightClaim, 0, len(l.inflight))
	for _, claim := range l.inflight {
		claims = append(claims, claim)
	}
	l.inflightMu.Unlock()
	for _, claim := range claims {
		claim.cancel()
	}
	errs := make([]error, len(claims))
	for index, claim := range claims {
		closeCall := claim.listenerCleanup()
		if closeCall == nil {
			continue
		}
		if err := closeCall.wait(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs[index] = err
		}
	}
	return errors.Join(errs...)
}

func closeRuntimeListenerPath(source string, path transport.PathConn, owner *runtimeListenerCallbackOwner) error {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	defer cancel()
	lease, err := reserveRuntimeListenerPathClose(ctx, source, owner)
	return newRuntimeListenerPathClose(source, path, lease, err).wait()
}

func closeLateRuntimeNetConn(source string, conn net.Conn, owner *runtimeListenerCallbackOwner) {
	if isNilNetworkSource(conn) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	defer cancel()
	lease, err := reserveRuntimeListenerPathClose(ctx, source, owner)
	newRuntimeListenerPathClose(source, tcp.Wrap(conn), lease, err).start()
}

func closeLateRuntimePath(source string, path transport.PathConn, owner *runtimeListenerCallbackOwner) {
	if isNilNetworkSource(path) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtimeListenerCallTimeout)
	defer cancel()
	lease, err := reserveRuntimeListenerPathClose(ctx, source, owner)
	newRuntimeListenerPathClose(source, path, lease, err).start()
}

func closeRuntimeListenerCallbacks(closers []runtimeListenerCloser, owner *runtimeListenerCallbackOwner) error {
	if len(closers) == 0 {
		return nil
	}
	type closeResult struct {
		index int
		err   error
	}
	results := make(chan closeResult, len(closers))
	for index, closer := range closers {
		go func(index int, closer runtimeListenerCloser) {
			timeout := closer.timeout
			if timeout <= 0 {
				timeout = runtimeListenerCallTimeout
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			invoke := func() (struct{}, error) { return struct{}{}, closer.close() }
			var err error
			if closer.lease != nil {
				_, err, _ = invokeRuntimeListenerCallbackWithLeaseAndCleanup(
					ctx, closer.lease, closer.source, ListenerCallbackClose, invoke, nil,
				)
			} else {
				_, err = invokeRuntimeListenerCallback(ctx, owner, closer.source, ListenerCallbackClose, invoke)
			}
			results <- closeResult{index: index, err: err}
		}(index, closer)
	}
	errs := make([]error, len(closers))
	for range closers {
		result := <-results
		if result.err != nil && !errors.Is(result.err, net.ErrClosed) {
			errs[result.index] = result.err
		}
	}
	return errors.Join(errs...)
}

func (l *SessionListener) publishStream(claim *runtimeListenerInflightClaim, conn *acceptedStreamConn) bool {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	if l.closing || l.inflight[claim.id] != claim {
		return false
	}
	select {
	case l.streamAccept <- conn:
		delete(l.inflight, claim.id)
		return true
	default:
		return false
	}
}

func (l *SessionListener) publishPacket(claim *runtimeListenerInflightClaim, conn *acceptedPacketConn) bool {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	if l.closing || l.inflight[claim.id] != claim {
		return false
	}
	select {
	case l.packetAccept <- conn:
		delete(l.inflight, claim.id)
		return true
	default:
		return false
	}
}

func isNilNetworkSource(source any) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func networkSourcePointer(source any) uintptr {
	if isNilNetworkSource(source) {
		return 0
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return value.Pointer()
	default:
		return 0
	}
}

func (l *SessionListener) drainQueuedSessions() error {
	var engines []*engine.Engine
	for {
		select {
		case conn := <-l.streamAccept:
			l.releaseAcceptSlot(false)
			engines = append(engines, conn.engine)
		default:
			goto packets
		}
	}

packets:
	for {
		select {
		case conn := <-l.packetAccept:
			l.releaseAcceptSlot(true)
			engines = append(engines, conn.engine)
		default:
			goto closeEngines
		}
	}

closeEngines:
	results := make(chan error, len(engines))
	for _, e := range engines {
		go func(e *engine.Engine) {
			if e == nil {
				results <- nil
				return
			}
			results <- e.Close()
		}(e)
	}
	errs := make([]error, 0, len(engines))
	for range engines {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
